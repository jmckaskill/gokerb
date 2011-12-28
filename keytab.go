package kerb

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"time"
)

const (
	keytabVersion = 0x502
	cacheVersion  = 0x504
	deltaTimeTag  = 1
)

func read(file io.Reader, p *int64, buf []byte) []byte {
	n, err := io.ReadFull(file, buf)
	*p += int64(n)
	if err != nil {
		panic(err)
	}
	return buf
}

func skip(file io.Reader, p *int64, n int) {
	m, err := io.CopyN(ioutil.Discard, file, int64(n))
	*p += m
	if err != nil {
		panic(err)
	}
}

func readU8(file io.Reader, p *int64) uint8 {
	buf := [1]byte{}
	read(file, p, buf[:])
	return buf[0]
}

func readU16(file io.Reader, p *int64) uint16 {
	buf := [2]byte{}
	read(file, p, buf[:])
	return binary.BigEndian.Uint16(buf[:])
}

func readU32(file io.Reader, p *int64) uint32 {
	buf := [4]byte{}
	read(file, p, buf[:])
	return binary.BigEndian.Uint32(buf[:])
}

func tryRead32(file io.Reader, p *int64, v *int) bool {
	buf := [4]byte{}
	n, err := io.ReadFull(file, buf[:])
	*p += int64(n)

	if n == 0 && err == io.EOF {
		return false
	} else if err != nil {
		panic(err)
	}

	*v = int(binary.BigEndian.Uint32(buf[:]))
	return true
}

func readPrincipal(file io.Reader, p *int64) (n principalName, realm string) {
	return readPrincipal2(file, p, int(readU32(file, p)))
}

func readPrincipal2(file io.Reader, p *int64, ntype int) (n principalName, realm string) {
	n.Type = ntype
	parts := make([]string, int(readU32(file, p))+1)
	for i := 0; i < len(parts); i++ {
		sz := int(readU32(file, p))
		buf := read(file, p, make([]byte, sz))
		parts[i] = string(buf)
	}

	realm = parts[0]
	n.Parts = parts[1:]
	return
}

// ReadKeytab reads a MIT kerberos keytab file returning all credentials found
// within.
//
// These are produced by MIT, heimdal, and the ktpass utility on windows.
func ReadKeytab(file io.Reader) (creds []*Credential, rerr error) {
	n := int64(0)

	defer func() {
		if err, ok := recover().(error); err != nil && ok {
			rerr = err
			creds = nil
		}
	}()

	if readU16(file, &n) != keytabVersion {
		return nil, ErrParse
	}

	size := 0
	for tryRead32(file, &n, &size) {

		// Negative sizes are used for deleted entries, skip over it
		if size < 0 {
			skip(file, &n, -size)
			continue
		}

		// Get an extra octet_string for the realm
		parts := make([]string, int(readU16(file, &n))+1)
		size -= 2

		for i := 0; i < len(parts); i++ {
			psz := int(readU16(file, &n))
			size -= 2

			parts[i] = string(read(file, &n, make([]byte, psz)))
			size -= psz
		}

		nametype := int(readU32(file, &n))
		size -= 4

		// timestamp unused
		_ = time.Unix(int64(readU32(file, &n)), 0)
		size -= 4

		kvno := int(readU8(file, &n))
		size -= 1

		keytype := int(readU16(file, &n))
		size -= 2

		keysize := int(readU16(file, &n))
		size -= 2

		keydata := read(file, &n, make([]byte, keysize))
		size -= keysize

		if size < 0 {
			return nil, ErrParse
		}

		if size >= 4 {
			kvno = int(readU32(file, &n))
			size -= 4
		}

		key, err := loadKey(keytype, keydata)
		if err != nil {
			return nil, err
		}

		creds = append(creds, &Credential{
			key:       key,
			kvno:      kvno,
			realm:     parts[0],
			principal: principalName{nametype, parts[1:]},
		})
	}

	return creds, nil
}

func appendU16(d []byte, v uint16) []byte {
	return append(d, byte(v>>8), byte(v))
}

func appendU32(d []byte, v uint32) []byte {
	return append(d, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// appendPrincipal append a principal and realm to d in the credential cache
// format. Keytab uses a different format with 2 byte lengths.
func appendPrincipal(d []byte, princ principalName, realm string) []byte {
	d = appendU32(d, uint32(princ.Type))
	d = appendU32(d, uint32(len(princ.Parts)))
	d = appendU32(d, uint32(len(realm)))
	d = append(d, realm...)
	for _, p := range princ.Parts {
		d = appendU32(d, uint32(len(p)))
		d = append(d, p...)
	}
	return d
}

func (c *Credential) WriteTo(file io.Writer) (int64, error) {
	now := time.Now()
	n := int64(0)
	d := make([]byte, 0)

	d = appendU16(d, cacheVersion)
	d = appendU16(d, 0) // headerlen
	d = appendPrincipal(d, c.principal, c.realm)

	if m, err := file.Write(d); err != nil {
		return n + int64(m), err
	}
	n += int64(len(d))

	for k, t := range c.cache {
		if now.After(t.till) {
			delete(c.cache, k)
			continue
		}

		d = d[:0]

		d = appendPrincipal(d, t.client, t.crealm)
		d = appendPrincipal(d, t.service, t.srealm)

		key := t.key.Key()
		d = appendU16(d, uint16(t.key.EncryptAlgo(asReplyClientKey)))
		d = appendU16(d, 0) // etype - not used
		d = appendU16(d, uint16(len(key)))
		d = append(d, key...)

		d = appendU32(d, uint32(t.authTime.Unix()))
		d = appendU32(d, uint32(t.startTime.Unix()))
		d = appendU32(d, uint32(t.till.Unix()))
		d = appendU32(d, uint32(t.renewTill.Unix()))

		d = append(d, 0) // is_skey
		d = appendU32(d, uint32(t.flags))
		d = appendU32(d, 0) // num_address
		d = appendU32(d, 0) // num_authdata
		d = appendU32(d, uint32(len(t.ticket)))
		d = append(d, t.ticket...)
		d = appendU32(d, 0) // second ticket

		if m, err := file.Write(d); err != nil {
			return n + int64(m), err
		}

		n += int64(len(d))
	}

	return n, nil
}

type ErrWrongPrincipal struct {
	expectedUser  string
	expectedRealm string
	User          string
	Realm         string
}

func (s ErrWrongPrincipal) Error() string {
	return fmt.Sprintf("kerb: cache has wrong principal, expected %s@%s, got %s@%s", s.expectedUser, s.expectedRealm, s.User, s.Realm)
}

func (c *Credential) readTickets(file io.Reader) (n int64, err error) {
	now := time.Now()
	ctype := 0

	for tryRead32(file, &n, &ctype) {

		client, crealm := readPrincipal2(file, &n, ctype)
		service, srealm := readPrincipal(file, &n)

		algorithm := int(readU16(file, &n))
		_ = readU16(file, &n) // etype not used
		keysize := int(readU16(file, &n))
		keydata := read(file, &n, make([]byte, keysize))

		key, err := loadKey(algorithm, keydata)
		if err != nil {
			return n, err
		}

		auth := time.Unix(int64(readU32(file, &n)), 0)
		start := time.Unix(int64(readU32(file, &n)), 0)
		till := time.Unix(int64(readU32(file, &n)), 0)
		renew := time.Unix(int64(readU32(file, &n)), 0)

		_ = readU8(file, &n) // is_skey not used
		flags := int(readU32(file, &n))

		// addresses
		for i, num := 0, int(readU32(file, &n)); i < num; i++ {
			_ = readU16(file, &n) // type
			sz := int(readU32(file, &n))
			skip(file, &n, sz)
		}

		// authdata
		for i, num := 0, int(readU32(file, &n)); i < num; i++ {
			_ = readU16(file, &n) // type
			sz := int(readU32(file, &n))
			skip(file, &n, sz)
		}

		tktsz := int(readU32(file, &n))
		tktdata := read(file, &n, make([]byte, tktsz))

		// second ticket
		tktsz = int(readU32(file, &n))
		skip(file, &n, tktsz)

		// Ignore expired tickets
		// TODO: handle renewable tickets.
		if now.After(till) {
			continue
		}

		tkt := &Ticket{
			client:    client,
			crealm:    crealm,
			service:   service,
			srealm:    srealm,
			ticket:    tktdata,
			till:      till,
			renewTill: renew,
			authTime:  auth,
			startTime: start,
			flags:     flags,
			key:       key,
		}

		if len(service.Parts) == 2 && service.Parts[0] == "krbtgt" {
			c.tgt[service.Parts[1]] = tkt
		}

		name := composePrincipal(service)
		c.cache[name] = tkt
	}

	return n, nil
}

// ReadFrom reads a MIT kerberos credential cache file.
//
// These are normally found at /tmp/krb5cc_<uid> on unix.
//
// This will error if the principal within the cache is different.
//
// All the tickets will be put into the credential's ticket cache (and can
// be subsequently retrieved using GetTicket).
func (c *Credential) ReadFrom(file io.Reader) (n int64, rerr error) {
	defer func() {
		if err, ok := recover().(error); ok && err != nil {
			rerr = err
		}
	}()

	if readU16(file, &n) != cacheVersion {
		return n, ErrParse
	}

	hlen := int(readU16(file, &n))
	skip(file, &n, hlen)

	princ, realm := readPrincipal(file, &n)
	if !nameEquals(princ, c.principal) || realm != c.realm {
		return n, ErrParse
	}

	m, err := c.readTickets(file)
	n += m
	return n, err
}

func ReadCredentialCache(file io.Reader) (rc *Credential, rerr error) {
	n := int64(0)

	defer func() {
		if err, ok := recover().(error); ok && err != nil {
			rerr = err
		}
	}()

	if readU16(file, &n) != cacheVersion {
		return nil, ErrParse
	}

	hlen := int(readU16(file, &n))
	skip(file, &n, hlen)

	princ, realm := readPrincipal(file, &n)

	c := &Credential{
		principal: princ,
		realm:     realm,
	}

	if _, err := c.readTickets(file); err != nil {
		return nil, err
	}

	return c, nil
}

func WriteKeytab(file io.Writer, creds []*Credential) error {
	d := []byte{}

	d = appendU16(d, keytabVersion)
	if _, err := file.Write(d); err != nil {
		return err
	}

	for _, c := range creds {
		d = d[:0]
		d = appendU32(d, 0) // size gets set at the end

		d = appendU16(d, uint16(len(c.principal.Parts)))
		d = appendU16(d, uint16(len(c.realm)))
		d = append(d, c.realm...)

		for _, p := range c.principal.Parts {
			d = appendU16(d, uint16(len(p)))
			d = append(d, p...)
		}

		d = appendU32(d, uint32(c.principal.Type))
		d = appendU32(d, 0) // timestamp unused

		if c.key == nil {
			return ErrPassword
		}

		key := c.key.Key()
		d = append(d, uint8(c.kvno))
		d = appendU16(d, uint16(c.key.EncryptAlgo(asReplyClientKey)))
		d = appendU16(d, uint16(len(key)))
		d = append(d, key...)
		d = appendU32(d, uint32(c.kvno))

		binary.BigEndian.PutUint32(d[:4], uint32(len(d)))

		if _, err := file.Write(d); err != nil {
			return err
		}
	}

	return nil
}
