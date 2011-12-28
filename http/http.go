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

type readwriter struct {
	io.Reader
	io.Writer
}

func connectThread(t *kerb.Ticket, rw readwriter, done chan error) {
	_, err := t.Connect(rw, 0)
	done <- err
}

func splitAuth(h string) (string, []byte, error) {
	i := strings.Index(h, " ")
	if i < 0 {
		return "", nil, ErrNoAuth
	}

	data, err := base64.StdEncoding.DecodeString(h[i+1:])
	return h[:i+1], data, err
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

	rreq, wreq := io.Pipe()
	rrep, wrep := io.Pipe()
	done := make(chan error, 1)
	go connectThread(tkt, readwriter{rrep, wreq}, done)
	defer wrep.Close()

	// Get the request auth header from the connect thread
	breq := [4096]byte{}
	n, err := rreq.Read(breq[:])
	if err != nil {
		return nil, err
	}

	req.Header.Set(wwwAuthenticate, negotiate+base64.StdEncoding.EncodeToString(breq[:n]))

	resp, err := t.Next.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if auth, data, err := splitAuth(resp.Header.Get(wwwAuthenticate)); auth == negotiate && err == nil {
		wrep.Write(data)
	}

	if err := <-done; err != nil {
		return nil, err
	}

	return resp, nil
}

type UserLookup func(username string) (user, realm string, err error)

type AuthConfig struct {
	BasicLookup UserLookup
	BasicRealm  string
	Negotiate   bool
}

type Authenticator struct {
	AuthConfig
	cred        *kerb.Credential
}

func NewAuthenticator(c *kerb.Credential, cfg *AuthConfig) *Authenticator {
	a := &Authenticator{
		AuthConfig: *cfg,
		cred:      c,
	}

	return a
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
	rbuf := bytes.NewBuffer(auth)
	wbuf := new(bytes.Buffer)

	_, user, realm, err = a.cred.Accept(readwriter{rbuf, wbuf}, 0)
	if err != nil {
		return a.fail(w, r, err)
	}

	if wbuf.Len() > 0 {
		// The auth succeeded and requested that the server authenticate back
		w.Header().Add(wwwAuthenticate, negotiate+base64.StdEncoding.EncodeToString(wbuf.Bytes()))
	}

	return user, realm, nil
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

	// We now run the accept and connect algorithms and join them directly
	// up. This has the effect of double checking the ticket returned by
	// the dc.
	rreq, wreq := io.Pipe()
	rrep, wrep := io.Pipe()
	done := make(chan error, 1)

	go connectThread(tkt, readwriter{rrep, wreq}, done)

	_, user, realm, err = cred.Accept(readwriter{rreq, wrep}, 0)
	if err != nil {
		return a.fail(w, r, err)
	}

	if err := <-done; err != nil {
		return a.fail(w, r, err)
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
