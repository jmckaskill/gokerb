// Package khttp provides HTTP client/server functions that allow you to
// authenticate HTTP using kerberos.
package khttp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/jmckaskill/gokerb"
	"io"
	"net"
	"net/http"
	"strings"
)

// Transport is a HTTP client transport that authenticates all outgoing
// requests using the Negotiate WWW auth mechanism.
type Transport struct {
	// Credential to use to authenticate outgoing requests
	Credential *kerb.Credential
	// Next specifies the next transport to be used or http.DefaultTransport if nil.
	Next           http.RoundTripper
	// Flags to pass to ticket.Connect. Use kerb.MutualAuth to authenticate the server.
	ConnectFlags int
}

var (
	// Error returned from Authenticate
	ErrNoAuth = errors.New("khttp: no or invalid authorization header")

	negotiate       = "Negotiate "
	basic           = "Basic "
	authorization   = "Authorization"
	wwwAuthenticate = "Www-Authenticate"
)

// Error returned from Authenticate when the BasicLookup callback returns no
// user/realm, but no specific error.
type ErrInvalidUser string

func (s ErrInvalidUser) Error() string {
	return fmt.Sprintf("khttp: invalid user '%s'", string(s))
}

type readwriter struct {
	io.Reader
	io.Writer
}

func connectThread(t *kerb.Ticket, rw readwriter, done chan error, flags int) {
	_, err := t.Connect(rw, flags)
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
	// TODO this should use the same lookup as the request
	addr, err := net.LookupHost(req.URL.Host)
	if err != nil {
		return nil, err
	}

	service, err := kerb.ResolveService("HTTP", addr[0])
	if err != nil {
		return nil, err
	}

	tkt, err := t.Credential.GetTicket(service, nil)
	if err != nil {
		return nil, err
	}

	rreq, wreq := io.Pipe()
	rrep, wrep := io.Pipe()
	done := make(chan error, 1)
	go connectThread(tkt, readwriter{rrep, wreq}, done, t.ConnectFlags)
	defer wrep.Close()

	// Get the request auth header from the connect thread
	breq := [4096]byte{}
	n, err := rreq.Read(breq[:])
	if err != nil {
		return nil, err
	}

	req.Header.Set(wwwAuthenticate, negotiate+base64.StdEncoding.EncodeToString(breq[:n]))

	tr := t.Next
	if tr == nil {
		tr = http.DefaultTransport
		if tr == nil {
			return nil, errors.New("khttp: no Next transport or DefaultTransport")
		}
	}

	resp, err := tr.RoundTrip(req)
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

type AuthConfig struct {
	// BasicLookup is a mapping function used for incoming basic auth
	// requests to map from the username to the kerberos user and realm.
	// If set to nil then basic auth is disabled. If the username is
	// invalid the callback can return either an error or an empty
	// user/realm. If an error is returned this is handed back from
	// Authenticate.
	BasicLookup func(username string) (user, realm string, err error)
	// BasicRealm is the basic auth realm sent to the client if any.
	BasicRealm          string
	// Negotiate enables/disables the Negotiate WWW auth mechanism which
	// allows a browser to send a kerberos ticket directly.
	Negotiate bool
}

// Authenticator is a handler for checking an incoming request.
// It supports both the Negotiate and Basic auth mechanisms
type Authenticator struct {
	cfg  *AuthConfig
	cred *kerb.Credential
}

func NewAuthenticator(c *kerb.Credential, cfg *AuthConfig) *Authenticator {
	a := &Authenticator{
		cfg:  cfg,
		cred: c,
	}

	return a
}

// SetAuthHeader writes the auth header in a response.
func (a *Authenticator) SetAuthHeader(w http.ResponseWriter) {
	if a.cfg.Negotiate {
		w.Header().Add(wwwAuthenticate, negotiate)
	}

	if a.cfg.BasicLookup != nil {
		w.Header().Add(wwwAuthenticate, fmt.Sprintf("Basic realm=\"%s\"", a.cfg.BasicRealm))
	}
}

func (a *Authenticator) doNegotiate(w http.ResponseWriter, auth []byte) (user, realm string, err error) {
	rbuf := bytes.NewBuffer(auth)
	wbuf := new(bytes.Buffer)

	_, user, realm, err = a.cred.Accept(readwriter{rbuf, wbuf}, 0)
	if err != nil {
		return "", "", err
	}

	if wbuf.Len() > 0 {
		// The auth succeeded and requested that the server authenticate back
		w.Header().Add(wwwAuthenticate, negotiate+base64.StdEncoding.EncodeToString(wbuf.Bytes()))
	}

	return user, realm, nil
}

func (a *Authenticator) doBasicAuth(auth []byte) (user, realm string, err error) {
	i := bytes.IndexRune(auth, ':')
	if i < 0 {
		return "", "", ErrNoAuth
	}

	user, realm, err = a.cfg.BasicLookup(string(auth[:i]))
	if err != nil {
		return "", "", err
	} else if user == "" || realm == "" {
		return "", "", ErrInvalidUser(string(auth[:i]))
	}

	cred, err := kerb.NewCredential(user, realm, string(auth[i+1:]), nil)
	if err != nil {
		return "", "", err
	}

	tkt, err := cred.GetTicket(a.cred.Principal(), nil)
	if err != nil {
		return "", "", err
	}

	// We now run the accept and connect algorithms and join them directly
	// up. This has the effect of double checking the ticket returned by
	// the dc.
	rreq, wreq := io.Pipe()
	rrep, wrep := io.Pipe()
	done := make(chan error, 1)

	go connectThread(tkt, readwriter{rrep, wreq}, done, 0)

	_, user, realm, err = cred.Accept(readwriter{rreq, wrep}, 0)
	if err != nil {
		return "", "", err
	}

	if err := <-done; err != nil {
		return "", "", err
	}

	return user, realm, nil
}

// Authenticate checks that a given requests is correctly authenticated.
//
// If the request authentication succeeds then this returns the user and realm
// that were authenticated. Note this does not check authorization for a given
// service.
//
// Note if basic auth is being used with a reverse proxy then you may want to
// remove the WWW-Authorization header so that the user password doesn't leak
// to the backend server.
//
// If the authenticator is the only auth source then you should call
// SetAuthHeader and return http.StatusUnauthorized so that the client can
// re-request with the correct auth header.
//
// Returns an ErrNoAuth error when no or invalid authorization is provided.
func (a *Authenticator) Authenticate(w http.ResponseWriter, r *http.Request) (user, realm string, err error) {
	auth, data, err := splitAuth(r.Header.Get(authorization))

	if err != nil {
		return "", "", err
	}

	switch {
	case a.cfg.Negotiate && auth == negotiate:
		return a.doNegotiate(w, data)

	case a.cfg.BasicLookup != nil && auth == basic:
		return a.doBasicAuth(data)
	}

	return "", "", ErrNoAuth
}
