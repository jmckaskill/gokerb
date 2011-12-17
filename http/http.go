package khttp

import (
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
	Next http.RoundTripper
}

var TicketLifetime = time.Hour * 8
var TicketFlags = 0

var (
	ErrNoAuth = errors.New("kerb http: no www-authorization")
)

type gss struct {
	togss chan string
	fromgss chan string
	done chan error
}

var negHeader = "Negotiate "

func (g *gss) Read(data []byte) (int, error) {
	enc, ok := <-g.togss
	if !ok {
		return 0, io.EOF
	}

	if !strings.HasPrefix(enc, negHeader) {
		return 0, kerb.ErrProtocol
	}

	return base64.StdEncoding.Decode(data, []byte(enc[len(negHeader):]))
}

func (g *gss) Write(data []byte) (int, error) {
	enc := make([]byte, len(negHeader) + base64.StdEncoding.EncodedLen(len(data)))
	copy(enc, negHeader)
	base64.StdEncoding.Encode(enc[len(negHeader):], data)
	g.fromgss <- string(enc)
	return len(data), nil
}

func (g *gss) connect(t *kerb.Ticket) {
	g.done <- t.Connect(g, kerb.MutualAuth)
}

func (g *gss) accept(c *kerb.Credential) {
	g.done <- c.Accept(g)
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

	g := gss{make(chan string), make(chan string), make(chan error, 1)}
	go g.connect(tkt)

	// Get the request auth header from the connect thread
	select {
	case auth := <-g.fromgss:
		req.Header.Set("WWW-Authorization", auth)
	case err := <-g.done:
		return nil, err
	}

	resp, err := t.Next.RoundTrip(req)
	if err != nil {
		// Make sure the connect thread finishes
		close(g.togss)
		return nil, err
	}

	// Try and send the reply auth header to the connect thread
	select {
	case g.togss <- req.Header.Get("WWW-Authorization"):
	case err := <-g.done:
		return nil, err
	}

	// Finally get the final result of the kerberos connect
	close(g.togss)
	return resp, <-g.done
}

type Authenticator struct {
	BasicAuthRealm string
	Credential *kerb.Credential

	// List of windows 2000 style realm aliases. This allows use to login
	// with Domain\User. The key is the alias, value is the kerberos realm.
	Realms map[string]string
}

func (a *Authenticator) writeFailure(w http.ResponseWriter, failed string) {
	if failed != "Negotiate" && a.Credential != nil {
		w.Header().Add("WWW-Authorization", "Negotiate")
	}

	if a.BasicAuthRealm != "" {
		w.Header().Add("WWW-Authorization", fmt.Sprintf("Basic realm \"%a\"", a.BasicAuthRealm))
	}

	w.WriteHeader(http.StatusUnauthorized)
}

func (a *Authenticator) doNegotiate(w http.ResponseWriter, r *http.Request, auth string) error {
	g := gss{make(chan string), make(chan string), make(chan error, 1)}
	go g.accept(a.Credential)

	g.togss <- auth
	close(g.togss)

	var err error
	select {
	case reply := <-g.fromgss:
		err = <-g.done
		if err != nil && reply != "" {
			w.Header().Add("WWW-Authorization", reply)
		}
	case err = <-g.done:
	}

	if err != nil {
		a.writeFailure(w, "Negotiate")
		return err
	}

	return nil
}

func (a *Authenticator) splitBasicAuth(auth string) (user string, realm string, pass string, err error) {
	i := strings.Index(auth, ":")
	if i < 0 {
		err = ErrNoAuth
		return
	}

	user = auth[:i]
	pass = auth[i+1:]

	if i := strings.Index(user, "@"); i >= 0 {
		realm = user[i+1:]
		user = user[:i]
		return
	}

	if i := strings.Index(user, "\\"); i >= 0 {
		realm = user[:i]
		user = user[i+1:]
	} else if i := strings.Index(user, "/"); i >= 0 {
		realm = user[:i]
		user = user[i+1:]
	}

	realm, ok := a.Realms[realm]
	if !ok {
		err = ErrNoAuth
		return
	}

	return
}

func (a *Authenticator) doBasicAuth(w http.ResponseWriter, r *http.Request, auth string) error {
	dec, err := base64.StdEncoding.DecodeString(auth[len("Basic "):])
	if err != nil {
		a.writeFailure(w, "Basic")
		return err
	}

	user, realm, pass, err := a.splitBasicAuth(string(dec))
	if err != nil {
		a.writeFailure(w, "Basic")
		return err
	}

	realm = strings.ToUpper(realm)

	c := kerb.NewCredential(user, realm, pass)
	_, err = c.GetTicket("krbtgt/" + realm, realm, time.Now().Add(TicketLifetime), TicketFlags)

	if err != nil {
		a.writeFailure(w, "Basic")
		return err
	}

	return nil
}

func (a *Authenticator) Authenticate(w http.ResponseWriter, r *http.Request) error {
	auth := r.Header.Get("WWW-Authorization")

	switch {
	case a.Credential != nil && strings.HasPrefix(auth, "Negotiate "):
		return a.doNegotiate(w, r, auth)

	case a.BasicAuthRealm != "" && strings.HasPrefix(auth, "Basic "):
		return a.doBasicAuth(w, r, auth)
	}

	a.writeFailure(w, "")
	return ErrNoAuth
}


