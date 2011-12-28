package kerb

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ResolveService resolves the canonical service principal for a given service
// on a given host.
//
// Host will be converted to the canonical FQDN and appended to service as
// <service>/<canon fqdn> to create the principal.
func ResolveService(service, host string) (string, error) {
	if hpart, _, err := net.SplitHostPort(host); err == nil {
		host = hpart
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", err
	}

	names, err := net.LookupAddr(addrs[0])
	if err != nil {
		return "", err
	}

	// Strip any trailing dot
	name := names[0]
	if strings.HasSuffix(name, ".") {
		name = name[:len(name)-1]
	}

	return fmt.Sprintf("%s/%s", service, name), nil
}

type Credential struct {
	key       cipher
	kvno      int
	principal principalName
	realm     string

	lk              sync.Mutex
	cache           map[string]*Ticket
	tgt             map[string]*Ticket
	replay          map[replayKey]bool
	lastReplayPurge time.Time
}

// NewCredential creates a new client credential that can be used to get
// tickets. The credential uses the specified UTF8 user, realm, and plaintext
// password.
//
// This does not check if the password is valid. To do that request the
// krbtgt/<realm> service ticket.
func NewCredential(user, realm, password string) *Credential {
	// Due to use of rc4HmacKey, the key should always be valid
	key, err := loadKey(rc4HmacAlgorithm, rc4HmacKey(password))
	if err != nil {
		panic(err)
	}

	return &Credential{
		key:       key,
		principal: principalName{principalNameType, []string{user}},
		realm:     strings.ToUpper(realm),
	}
}

// lookupCache looks up a ticket in the tbl cache and returns it if it exists
// and meets the specified expiry and flags.
func (c *Credential) lookupCache(tbl map[string]*Ticket, key string, till time.Time, flags int) *Ticket {
	tkt := tbl[key]

	if tkt == nil {
		return nil
	}

	// Check to see if the ticket has expired or is about to expire
	if tkt.till.Before(till) {
		delete(tbl, key)
		return nil
	}

	// Check that it has all the flags we want
	if (tkt.flags & flags) != flags {
		return nil
	}

	return tkt
}

// getTgt tries to find the closest valid ticket for requesting new tickets in
// realm. It will send an AS_REQ to get the initial ticket in the credential's
// realm if no valid tgt ticket in the cache can be found.
func (c *Credential) getTgt(realm string, ctill time.Time) (*Ticket, string, error) {
	// TGS_REQ using the remote realm
	if tgt := c.lookupCache(c.tgt, realm, ctill, 0); tgt != nil {
		return tgt, realm, nil
	}

	// TGS_REQ using the local realm
	if tgt := c.lookupCache(c.tgt, c.realm, ctill, 0); tgt != nil {
		return tgt, c.realm, nil
	}

	// Credentials created with ReadCredentialCache don't know the client password
	if c.key == nil {
		return nil, "", ErrPassword
	}

	// AS_REQ login
	r := request{
		ckey:    c.key,
		ckvno:   c.kvno,
		flags:   defaultLoginFlags,
		till:    time.Now().Add(defaultLoginDuration),
		crealm:  c.realm,
		srealm:  c.realm,
		client:  c.principal,
		service: principalName{serviceInstanceType, []string{"krbtgt", c.realm}},
	}

	tgt, err := r.do()
	if r.sock != nil {
		r.sock.Close()
	}
	if err != nil {
		return nil, "", err
	}

	c.kvno = r.ckvno
	c.tgt[c.realm] = tgt
	c.cache["krbtgt/"+c.realm] = tgt

	return tgt, c.realm, nil
}

func (c *Credential) GetLoginTicket(till time.Time, flags int) (*Ticket, error) {
	return c.GetTicket("krbtgt/"+c.realm, c.realm, till, flags)
}

// GetTicket returns a valid ticket for the given service and realm.
//
// The ticket will be pulled from the cache if possible, but if not GetTicket
// will go out to the KDC(s) and get a new ticket.
//
// Till is used as a hint for when the ticket should expire, but may not be
// met due to a cached ticket being used or the KDC limiting the lifetime of
// tickets (use ticket.GetExpireTime to see when the returned ticket actually
// expires).
//
// Cached entries will not be used if they don't meet all the flags, but the
// returned ticket may not have all the flags if the domain policy forbids
// some of them.
//
// The realm if specified is used as a hint for which KDC to use if no cached
// ticket is found.
func (c *Credential) GetTicket(service, realm string, till time.Time, flags int) (*Ticket, error) {
	// One of a number of possiblities:
	// 1. Init state (no keys) user is requesting service key. Send AS_REQ then send TGS_REQ.
	// 2. Init state (no keys) user is requesting krbtgt key. Send AS_REQ, find krbtgt key in cache.
	// 3. Have krbtgt key for local realm, but not for the requested realm. Use local realm krbtgt key to send TGS_REQ and then follow the trail.
	// 4. Have krbtgt key for service realm. Use to send TGS_REQ.

	// The algorithm is thus:
	// 1. Lookup ticket in cache. Return if found.
	// 2. Lookup service realm tgt key in cache. Use with TGS_REQ to get ticket if found.
	// 3. Lookup local realm tgt key in cache. Use with TGS_REQ to get ticket if found and follow trail.
	// 4. Send AS_REQ to get local realm tgt key. Then send TGS_REQ and follow trail.

	// We require that cached entries have at least 10 minutes left to use
	ctill := time.Now().Add(time.Minute * 10)

	if realm == "" {
		realm = c.realm
	} else {
		// Realms are case-insensitive, but kerberos is
		// case-sensitive. The RFC recommends always using upper case.
		realm = strings.ToUpper(realm)
	}

	c.lk.Lock()
	defer c.lk.Unlock()

	if c.cache == nil {
		c.cache = make(map[string]*Ticket)
		c.tgt = make(map[string]*Ticket)
	}

	if tkt := c.lookupCache(c.cache, service, ctill, flags); tkt != nil {
		return tkt, nil
	}

	tgt, tgtrealm, err := c.getTgt(realm, till)
	if err != nil {
		return nil, err
	}

	// Lookup in the cache again to handle the corner case where the
	// requested ticket was the krbtgt login ticket, which getTgt requested.
	if tkt := c.lookupCache(c.cache, service, ctill, flags); tkt != nil {
		return tkt, nil
	}

	// Loop around the ticket granting services that get returned until we
	// either get our service or we cancel due to a loop in the auth path
	for i := 0; i < 10; i++ {
		r := request{
			client:  c.principal,
			crealm:  c.realm,
			service: splitPrincipal(service),
			srealm:  tgtrealm,
			flags:   flags,
			till:    till,
			tgt:     tgt,
		}

		tkt, err := r.do()
		if r.sock != nil {
			r.sock.Close()
		}
		if err != nil {
			return nil, err
		}

		tktserv := composePrincipal(tkt.service)
		c.cache[tktserv] = tkt

		// Did we get the service we wanted
		if service == tktserv {
			return tkt, nil
		}

		// If we got a different service, then we may have a ticket to
		// a next hop ticket granting service.
		if s := tkt.service; len(s.Parts) == 2 && s.Parts[0] == "krbtgt" {
			tgtrealm = s.Parts[1]
			tgt = tkt
			c.tgt[tgtrealm] = tkt
			continue
		}

		// We can validly get a different service back if we set the
		// canon flag
		if (flags & Canonicalize) != 0 {
			c.cache[service] = tkt
			return tkt, nil
		}

		return nil, ErrProtocol
	}

	return nil, ErrAuthLoop
}

func (c *Credential) Principal() string {
	return composePrincipal(c.principal)
}

func (c *Credential) Realm() string {
	return c.realm
}
