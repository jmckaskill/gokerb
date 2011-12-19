package khttp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/jmckaskill/gokerb"
	"io"
	"net/http"
	"strings"
	"time"
)

type Transport struct {
	Credential *kerb.Credential
	Next       http.RoundTripper
}

var TicketLifetime = time.Hour * 8
var TicketFlags = 0

var (
	ErrNoAuth       = errors.New("kerb http: no or invalid authorization header")
	negotiate       = "Negotiate "
	basic           = "Basic "
	authorization   = "Authorization"
	wwwAuthenticate = "Www-Authenticate"
)

type ErrInvalidUser string

func (s ErrInvalidUser) Error() string {
	return fmt.Sprintf("kerb: invalid user '%s'", string(s))
}

type gss struct {
	// Warning: the use of []byte rather than string here only works
	// because the gss algorithms don't modify the buffers they write
	// after calling Write
	togss    chan []byte
	fromgss  chan []byte
	done     chan error
	username string
	realm    string
	buf      []byte
}

func splitAuth(h string) (string, []byte, error) {
	i := strings.Index(h, " ")
	if i < 0 {
		return "", nil, ErrNoAuth
	}

	data, err := base64.StdEncoding.DecodeString(h[i+1:])
	return h[:i+1], data, err
}

func (g *gss) Read(data []byte) (int, error) {
	if len(g.buf) == 0 {
		ok := false
		if g.togss != nil {
			g.buf, ok = <-g.togss
		}
		if !ok {
			g.togss = nil
			return 0, io.EOF
		}
	}

	n := copy(data, g.buf)
	g.buf = g.buf[n:]
	return n, nil
}

func (g *gss) Write(data []byte) (int, error) {
	g.fromgss <- data
	// For both the connect and accept algorithms we should always send at most one PDU
	close(g.fromgss)
	g.fromgss = nil
	return len(data), nil
}

func (g *gss) connect(t *kerb.Ticket) {
	g.done <- t.Connect(g, kerb.MutualAuth)
	if g.fromgss != nil {
		close(g.fromgss)
	}
}

func acceptThread(c *kerb.Credential, ch chan *gss) {
	var err error
	for g := range ch {
		g.username, g.realm, err = c.Accept(g)
		if g.fromgss != nil {
			close(g.fromgss)
		}
		g.done <- err
	}
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	service, err := kerb.ResolveService("HTTP", req.URL.Host)
	if err != nil {
		return nil, err
	}

	tkt, err := t.Credential.GetTicket(service, "", time.Now().Add(TicketLifetime), TicketFlags)
	if err != nil {
		return nil, err
	}

	// Make togss async so the send doesn't block when the connector
	// doesn't want the reply. Make done async, so the connect thread will
	// finish if we error out early and don't service it.
	g := &gss{fromgss: make(chan []byte), togss: make(chan []byte, 1), done: make(chan error, 1)}
	go g.connect(tkt)
	defer close(g.togss)

	// Get the request auth header from the connect thread
	select {
	case auth := <-g.fromgss:
		req.Header.Set(wwwAuthenticate, negotiate+base64.StdEncoding.EncodeToString(auth))
	case err := <-g.done:
		return nil, err
	}

	resp, err := t.Next.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if auth, data, err := splitAuth(resp.Header.Get(wwwAuthenticate)); auth == negotiate && err == nil {
		g.togss <- data
	}

	return resp, <-g.done
}

type UserLookup func(username string) (user, realm string, err error)

type Authenticator struct {
	BasicLookup UserLookup
	BasicRealm  string
	Negotiate   bool
	accept      chan *gss
	cred        *kerb.Credential
}

func NewAuthenticator(c *kerb.Credential) *Authenticator {
	a := &Authenticator{
		accept:    make(chan *gss),
		cred:      c,
		Negotiate: false,
	}

	go acceptThread(c, a.accept)
	return a
}

func (a *Authenticator) Close() {
	close(a.accept)
}

func (a *Authenticator) fail(w http.ResponseWriter, r *http.Request, err error) (user, realm string, rerr error) {
	// Filter out negotiate on failure so that the user can retry with basic auth
	if a.Negotiate && !strings.HasPrefix(r.Header.Get(authorization), negotiate) {
		w.Header().Add(wwwAuthenticate, negotiate)
	}

	if a.BasicLookup != nil {
		w.Header().Add(wwwAuthenticate, fmt.Sprintf("Basic realm=\"%s\"", a.BasicRealm))
	}

	w.WriteHeader(http.StatusUnauthorized)
	return "", "", err
}

func (a *Authenticator) doNegotiate(w http.ResponseWriter, r *http.Request, auth []byte) (user, realm string, err error) {
	g := &gss{fromgss: make(chan []byte), done: make(chan error), buf: auth}
	a.accept <- g

	reply, rok := <-g.fromgss

	if err := <-g.done; err != nil {
		return a.fail(w, r, err)
	}

	if rok {
		// The auth succeeded and requested that the server authenticate back
		w.Header().Add(wwwAuthenticate, negotiate+base64.StdEncoding.EncodeToString(reply))
	}

	return g.username, g.realm, nil
}

func (a *Authenticator) doBasicAuth(w http.ResponseWriter, r *http.Request, auth []byte) (user, realm string, err error) {
	i := bytes.IndexRune(auth, ':')
	if i < 0 {
		return a.fail(w, r, ErrNoAuth)
	}

	user, realm, err = a.BasicLookup(string(auth[:i]))
	if err != nil {
		return a.fail(w, r, err)
	} else if user == "" || realm == "" {
		return a.fail(w, r, ErrInvalidUser(string(auth[:i])))
	}

	cred := kerb.NewCredential(user, realm, string(auth[i+1:]))
	tkt, err := cred.GetTicket(a.cred.Principal(), a.cred.Realm(), time.Now().Add(TicketLifetime), TicketFlags)
	if err != nil {
		return a.fail(w, r, err)
	}

	// We now run the accept and connect algorithms in two threads and
	// join them directly up. This has the effect of double checking the
	// ticket returned by the dc. Make togss and fromgss buffered in case
	// one of the threads errors out before servicing its input.
	gc := &gss{fromgss: make(chan []byte, 1), togss: make(chan []byte, 1), done: make(chan error)}
	ga := &gss{togss: gc.fromgss, fromgss: gc.togss, done: gc.done}

	go gc.connect(tkt)
	a.accept <- ga
	errc := <-gc.done
	erra := <-ga.done

	if errc != nil {
		return a.fail(w, r, errc)
	}

	if erra != nil {
		return a.fail(w, r, erra)
	}

	return user, realm, nil
}

func (a *Authenticator) Authenticate(w http.ResponseWriter, r *http.Request) (user, realm string, err error) {
	auth, data, err := splitAuth(r.Header.Get(authorization))

	if err != nil {
		return a.fail(w, r, err)
	}

	// Remove the auth header so its not seen by reverse proxies, logs, etc
	r.Header.Del(authorization)

	switch {
	case a.Negotiate && auth == negotiate:
		return a.doNegotiate(w, r, data)

	case a.BasicLookup != nil && auth == basic:
		return a.doBasicAuth(w, r, data)
	}

	return a.fail(w, r, ErrNoAuth)
}
