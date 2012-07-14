package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/jmckaskill/gokerb"
	"github.com/jmckaskill/gokerb/khttp"
	"github.com/jmckaskill/goldap"
	"github.com/jmckaskill/goldap/ad"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func die(args ...interface{}) {
	a := []interface{}{"fatal: ", args}
	log.Print(a...)
	os.Exit(256)
}

func check(err error) {
	if err != nil {
		die(err)
	}
}

type bitset []uint32

func newBitset(i int) bitset {
	var b bitset
	b.Set(i)
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (b1 bitset) HasIntersection(b2 bitset) bool {
	for i := 0; i < min(len(b1), len(b2)); i++ {
		if b1[i]&b2[i] != 0 {
			return true
		}
	}
	return false
}

func (b bitset) Test(i int) bool {
	o := i >> 5
	return o < len(b) && (b[o]&(1<<(uint(i)&31))) != 0
}

func (b bitset) Clone() bitset {
	b2 := make(bitset, len(b))
	copy(b2, b)
	return b2
}

func (b *bitset) Set(i int) {
	o := i >> 5
	if o >= cap(*b) {
		b2 := make(bitset, o)
		copy(b2, *b)
		*b = b2
	} else if o >= len(*b) {
		*b = (*b)[:o]
	}
	(*b)[o] |= 1 << (uint(i) & 31)
}

func (b *bitset) SetMulti(v bitset) {
	if len(v) >= cap(*b) {
		b2 := make(bitset, len(v))
		copy(b2, *b)
		*b = b2
	} else if len(v) >= len(*b) {
		*b = (*b)[:len(v)]
	}
	for i, v2 := range v {
		(*b)[i] |= v2
	}
}

type ruleGroup struct {
	gid  int
	name string
	dn   ldap.ObjectDN
}

type rule struct {
	path        string
	host        string
	gmask       bitset
	groups      []ruleGroup
	hook        string
	cgi         string
	cgicwd      string
	proxy       *url.URL
	stripPrefix string
	handler     http.Handler
}

type user struct {
	*ad.User
	gmask bitset
}

var groups []ldap.ObjectDN
var groupmap = make(map[ldap.ObjectDN]int)
var rules []rule
var configFile string
var cred *kerb.Credential
var cookieKey []byte
var sslCert tls.Certificate
var runas string

func init() {
	flag.StringVar(&configFile, "config", "/etc/khttp-proxy.conf", "config file")
}

func dial(proto, realm string) (io.ReadWriteCloser, error) {
	if realm == "CTCT.NET" {
		return net.Dial(proto, "10.1.46.195:88")
	}

	return kerb.DefaultDial(proto, realm)
}

func parseConfigFile() {
	f, err := os.Open(configFile)
	check(err)
	defer f.Close()

	r := bufio.NewReader(f)
	var p rule
	var sslCrtFile, sslKeyFile string

	for err != nil {
		s, err := r.ReadString('\n')
		if s == "" || s[0] == '#' {
			continue
		}

		s = strings.TrimSpace(s)
		cmdi := strings.Index(s, " ")
		if cmdi < 0 {
			cmdi = len(s)
		}
		cmd := strings.TrimSpace(s[:cmdi])
		args := strings.TrimSpace(s[cmdi:])

		switch cmd {
		case "path":
			if len(p.path) > 0 {
				rules = append(rules, p)
			}
			p = rule{path: args}
		case "host":
			p.host = args
			_, err = path.Match(args, "")
			if err != nil {
				die(err, args)
			}
		case "group":
			a := strings.SplitN(args, " ", 2)
			if len(a) < 2 {
				die("invalid group should be group name dn")
			}
			dn := ldap.ObjectDN(a[1])
			gidx, ok := groupmap[dn]
			if !ok {
				groupmap[dn] = len(groups)
				gidx = len(groups)
				groups = append(groups, dn)
			}
			p.groups = append(p.groups, ruleGroup{gidx, a[0], dn})
			p.gmask.Set(gidx)
		case "hook":
			p.hook = args
		case "cgi":
			p.cgi = args
		case "cgi-cwd":
			p.cgicwd = args
		case "filesystem":
			p.handler = http.FileServer(http.Dir(args))
		case "strip-prefix":
			p.stripPrefix = args
		case "proxy":
			u, err := url.Parse(args)
			check(err)
			p.handler = httputil.NewSingleHostReverseProxy(u)
		case "ssl-crt":
			sslCrtFile = args
		case "ssl-key":
			sslKeyFile = args
		case "krb-key":
			file, err := os.Open(args)
			check(err)
			creds, err := kerb.ReadKeytab(file, &kerb.CredConfig{Dial: dial})
			file.Close()
			check(err)
			if len(creds) < 1 {
				die("invalid keytab ", args)
			}
			cred = creds[0]
			_, err = cred.GetTicket("krbtgt/CTCT.NET", nil)
			check(err)
		case "cookie-key":
			cookieKey, err = ioutil.ReadFile("cookie_key")
			check(err)
		case "run-as":
			runas = args
		}
	}

	if err != nil && err != io.EOF {
		die(err)
	}

	if len(p.path) > 0 {
		rules = append(rules, p)
	}

	for _, p := range rules {
		if len(p.cgi) > 0 {
			p.handler = &cgi.Handler{
				Path: p.cgi,
				Dir:  p.cgicwd,
			}
		}

		if p.handler == nil {
			die("no handler defined for ", p.path)
		}

		if len(p.stripPrefix) > 0 {
			p.handler = http.StripPrefix(p.stripPrefix, p.handler)
		}
	}

	if sslCrtFile != "" {
		sslCert, err = tls.LoadX509KeyPair(sslCrtFile, sslKeyFile)
		check(err)
	}

}

func resolveUsers(db *ad.DB, dn ldap.ObjectDN, users map[string]user, depth int, gmask bitset) error {
	if depth == 0 {
		return errors.New("reached max group depth")
	}

	log.Print("LookupDN", dn)
	obj, err := db.LookupDN(dn)
	if err != nil {
		return err
	}

	switch u := obj.(type) {
	case *ad.User:
		log.Print("user", u)
		pr := fmt.Sprintf("%s@%s", strings.ToLower(u.SAMAccountName), u.Realm)
		if u2, ok := users[pr]; ok {
			u2.gmask.SetMulti(gmask)
		} else {
			users[pr] = user{u, gmask.Clone()}
		}

	case *ad.Group:
		log.Print("group", u)
		if _, ok := groupmap[u.DN]; !ok {
			gidx := len(groups)
			groupmap[u.DN] = gidx
			groups = append(groups, u.DN)
			mask := gmask.Clone()
			mask.Set(gidx)
			for _, dn := range u.Member {
				err := resolveUsers(db, dn, users, depth-1, mask)
				if err == ldap.ErrNotFound {
					continue
				} else if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func getUsers(db *ad.DB) (map[string]user, error) {
	users := make(map[string]user)

	// If we encounter any errors collecting the user list from LDAP, we
	// error out and leave the users map in its current state. This is to
	// avoid temporary glitches from deactivating accounts.
	for i, g := range groups {
		err := resolveUsers(db, g, users, 5, newBitset(i))
		if err != nil {
			return nil, err
		}
	}

	return users, nil
}

func logLines(pfx string, r io.Reader) error {
	b := bufio.NewReaderSize(r, 512)
	for {
		line, isPrefix, err := b.ReadLine()
		if len(line) > 0 {
			log.Print(pfx, string(line))
		}
		if err != nil {
			return err
		}
		// Consume the rest of the overlong line
		for isPrefix {
			_, isPrefix, err = b.ReadLine()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func runHooks(users map[string]user) error {
	for _, r := range rules {
		if r.hook == "" {
			continue
		}

		h := exec.Command(r.hook)
		w, err := h.StdinPipe()
		if err != nil {
			return err
		}
		stderr, err := h.StderrPipe()
		if err != nil {
			return err
		}

		go logLines(fmt.Sprintf("hook %s: ", r.hook), stderr)

		err = h.Start()
		if err != nil {
			return err
		}

		for pr, u := range users {
			if !u.gmask.HasIntersection(r.gmask) {
				continue
			}

			fmt.Fprintf(w, "user %s\n", pr)
			fmt.Fprintf(w, "dn %s\n", u.DN)
			fmt.Fprintf(w, "sid %s\n", u.ObjectSID)
			fmt.Fprintf(w, "name %s\n", u.DisplayName)
			fmt.Fprintf(w, "email %s\n", u.Mail)
			for _, g := range r.groups {
				if u.gmask.Test(g.gid) {
					fmt.Fprintf(w, "group %s %s\n", g.name, g.dn)
				}
			}
			fmt.Fprint(w, "\n")
		}

		fmt.Print(w, "\n")
		w.Close()
		err = h.Wait()
		if err != nil {
			return err
		}
	}

	return nil
}

func authCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie("kerb")
	if err != nil {
		return "", khttp.ErrNoAuth
	}

	val, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", err
	}

	sig := hmac.New(md5.New, cookieKey)
	sig.Write(val[:len(val)-md5.Size])

	if subtle.ConstantTimeCompare(sig.Sum(nil), val[len(val)-md5.Size:]) != 1 {
		return "", khttp.ErrNoAuth
	}

	vals := strings.SplitN(string(val[:len(val)-md5.Size]), " ", 2)
	if len(vals) < 2 {
		return "", khttp.ErrNoAuth
	}

	ts, err := time.Parse(time.RFC3339, vals[0])
	if err != nil || time.Now().Sub(ts) > 5*time.Minute || ts.Sub(time.Now()) > 5*time.Minute {
		return "", khttp.ErrNoAuth
	}

	return vals[1], nil
}

func writeCookie(w http.ResponseWriter, user string) {
	val := append([]byte(nil), time.Now().Format(time.RFC3339)...)
	val = append(val, " "...)
	val = append(val, user...)

	sig := hmac.New(md5.New, cookieKey)
	sig.Write(val)
	val = sig.Sum(val)

	http.SetCookie(w, &http.Cookie{
		Name:     "kerb",
		Secure:   true,
		HttpOnly: true,
		Value:    base64.StdEncoding.EncodeToString(val),
		Path:     "/",
		MaxAge:   600,
	})
}

type loggedResponse struct {
	w    http.ResponseWriter
	r    *http.Request
	url  string
	user string
}

func (w *loggedResponse) Header() http.Header         { return w.w.Header() }
func (w *loggedResponse) Write(d []byte) (int, error) { return w.w.Write(d) }

func (w *loggedResponse) WriteHeader(status int) {
	log.Printf("%s %s \"%s %s %s\" %d", w.r.RemoteAddr, w.user, w.r.Method, w.url, w.r.Proto, status)
	w.w.WriteHeader(status)
}

func main() {
	var userlk sync.Mutex
	var users map[string]user
	var db *ad.DB

	slog, err := syslog.New(syslog.LOG_INFO, "khttp-proxy")
	check(err)
	log.SetFlags(0)
	log.SetOutput(slog)

	flag.Parse()
	parseConfigFile()

	httpServer := http.Server{
		Addr: ":80",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := new(url.URL)
			*u = *r.URL
			if u.Host == "" && r.Host != "" {
				u.Host = r.Host
			}
			u.Scheme = "https"
			http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
		}),
	}

	auth := khttp.NewAuthenticator(cred, &khttp.AuthConfig{
		BasicLookup: func(u string) (string, string, error) {
			userlk.Lock()
			d := db
			userlk.Unlock()
			if d == nil {
				return "", "", errors.New("no database")
			}
			return d.ResolvePrincipal(u)
		},
		BasicRealm: "Windows Domain Logon (e.g. AM\\User)",
		Negotiate:  true,
	})

	httpsServer := http.Server{
		Addr: ":443",
		TLSConfig: &tls.Config{
			NextProtos:   []string{"http/1.1"},
			Certificates: []tls.Certificate{sslCert},
		},
		Handler: http.HandlerFunc(func(w2 http.ResponseWriter, r *http.Request) {
			var err error
			var u user
			var uok bool

			w := &loggedResponse{w2, r, r.URL.String(), ""}

			w.user, err = authCookie(r)
			if err != nil {
				user, realm, err := auth.Authenticate(w, r)
				if err != nil {
					goto authFailed
				}

				w.user = fmt.Sprintf("%s@%s", user, realm)
				writeCookie(w, w.user)
			}

			userlk.Lock()
			u, uok = users[w.user]
			userlk.Unlock()

			if !uok {
				goto authFailed
			}

			for _, p := range rules {
				if p.host != "" && r.URL.Host != p.host && r.Host != p.host {
					continue
				}

				if ok, _ := path.Match(p.path, r.URL.Path); !ok {
					continue
				}

				if !u.gmask.HasIntersection(p.gmask) {
					continue
				}

				r.Header.Set("Remote-User", w.user)
				p.handler.ServeHTTP(w, r)
				return
			}

		authFailed:
			auth.SetAuthHeader(w)
			w.WriteHeader(http.StatusUnauthorized)
		}),
	}

	httpConn, err := net.Listen("tcp", ":80")
	check(err)

	httpsConn, err := net.Listen("tcp", ":443")
	check(err)

	if runas != "" {
		uid, err := strconv.Atoi(runas)
		check(err)
		err = syscall.Setuid(uid)
		check(err)
	}

	go httpServer.Serve(httpConn)
	go httpsServer.Serve(tls.NewListener(httpsConn, httpsServer.TLSConfig))

	for {
		newdb := ad.New(cred, cred.Realm())
		newusers, err := getUsers(newdb)
		if err != nil {
			log.Print("LDAP failed:", err)
			goto sleep
		}

		err = runHooks(newusers)
		if err != nil {
			log.Print("Hook failed:", err)
			goto sleep
		}

		userlk.Lock()
		db = newdb
		users = newusers
		userlk.Unlock()

	sleep:
		time.Sleep(time.Hour)
	}
}
