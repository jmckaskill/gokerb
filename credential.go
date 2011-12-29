/*
Package kerb implements a kerberos V5 ticket and credential manager.

Kerberos is a network authentication system that allows users to authenticate
to servers and vice versa without the user or server revealing their password.
It does this by acquiring a ticket from a trusted third party and then
presenting this ticket to the server.

Glossary:

Principal:
	A user ID that can be authenticated in a given realm. User principals
	are normally a single word. Service principals are of the form
	service/<FQDN>.

Realm:
	Set of users IDs that are controlled by one key database. Realms can
	have trust chains between them such that a user ID in one realm can
	authenticate to a user ID from another. Similar to the domain in an
	email address.

Keytab:
	File used to store a service principal along with its private key.
	With this a server can authenticate an incoming request without
	checking with the key server.

Credential Cache:
	File used by MIT and heimdal kerberos to store the local users cached
	tickets. On unix systems `klist` will list the tickets in a cache.

Ticket:
	Chunk of data acquired from the key server that allows a given
	principal to authenticate to a given service for a specified period of
	time. Can also include a number of further restrictions/extensions (EG
	ability to forward the ticket).
*/
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

// Credential is a wrapper for a locally owned user or service principal. It
// can be used to authenticate to other services or to check incoming requests
// against. A credential can be created from a user, realm, password triple, a
// credential cache created by MIT or heimdal kerberos, or a keytab created
// for a service principal.
//
// It will store the password in hashed form if created from a keytab or
// plaintext password so that we can renew tickets.  This is not possible if
// created from a credential cache as the cache doesn't store the user
// password in any form.
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
//
// TODO: Check that UTF8 usernames actually work.
func NewCredential(user, realm, password string) *Credential {
	return &Credential{
		key:       mustLoadKey(rc4HmacAlgorithm, rc4HmacKey(password)),
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

// Flag values for GetTicket
const (
	TicketForwardable                 = 1 << 30
	TicketForwarded                   = 1 << 29
	TicketProxiable                   = 1 << 28
	TicketProxy                       = 1 << 27
	TicketAllowPostdate               = 1 << 26
	TicketPostdated                   = 1 << 25
	TicketRenewable                   = 1 << 23
	TicketCanonicalize                = 1 << 16
	TicketDisableTransitedCheck       = 1 << 5
	TicketRenewableOk                 = 1 << 4
	TicketEncryptedTicketInSessionKey = 1 << 3
	TicketRenew                       = 1 << 1
	TicketValidate                    = 1 << 0

	defaultLoginFlags = 0
)

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
// some of them. Valid flag values are of the form Ticket*.
func (c *Credential) GetTicket(service string, till time.Time, flags int) (*Ticket, error) {
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

	c.lk.Lock()
	defer c.lk.Unlock()

	if c.cache == nil {
		c.cache = make(map[string]*Ticket)
		c.tgt = make(map[string]*Ticket)
	}

	if tkt := c.lookupCache(c.cache, service, ctill, flags); tkt != nil {
		return tkt, nil
	}

	tgt, tgtrealm, err := c.getTgt(c.realm, till)
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
		if (flags & TicketCanonicalize) != 0 {
			c.cache[service] = tkt
			return tkt, nil
		}

		return nil, ErrProtocol
	}

	return nil, ErrAuthLoop
}

// Principal returns the credential's associated principal
func (c *Credential) Principal() string {
	return composePrincipal(c.principal)
}

// Realm returns the credential's associated realm
func (c *Credential) Realm() string {
	return c.realm
}
