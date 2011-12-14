package kerb

import (
	"crypto/hmac"
	"crypto/md4"
	"crypto/rand"
	"crypto/rc4"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf16"
)

// KDC request flags
const (
	_ = 1 << iota // reserved
	Forwardable
	Forwarded
	Proxiable
	Proxy
	AllowPostdate
	Postdated
	_ // reserved
	Renewable
)
const (
	// reserved to 25
	DisableTransitedCheck = 1 << (iota + 26)
	RenewableOk
	EncryptedTicketInSessionKey
	_ // reserved
	Renew
	Validate
)

// App request flags
const (
	_ = 1 << iota // reserved
	useSessionKey
	mutualRequired
)

// Key usage
const (
	asReqPreauthTimestamp = iota
	kdcReplyTicket
	kdcReplyEncryptedPart
)

// Address type
const (
	ipv4 = 2
	ipv6 = 24
)

// Message types
const (
	asRequestType = 10 + iota
	asReplyType
	tgsRequestType
	tgsReplyType
	appRequestType
	appReplyType
	errorType = 30
)

// Name types
const (
	principalNameType = 1 + iota
	serviceNameType
)

// Preauth types
const (
	paTgsRequest = 1 + iota
	paEncryptedTimestamp
)

// Encryption algorithms
const (
	rc4HmacAlgorithm = 23
	defaultAlgorithm = rc4HmacAlgorithm
)

// Key usage values
const (
	paEncryptedTimestampKey = iota + 1
	ticketKey
	asReplyClientKey
	tgsRequestAuthSessionKey
	tgsRequestAuthSubKey
	paTgsRequestChecksumKey
	paTgsRequestKey
	tgsReplySessionKey
	tgsReplySubKey
	apRequestAuthChecksumKey
	apRequestAuthKey
	apReplyEncryptedKey
)

const (
	kerberosVersion  = 5
	applicationClass = 0x40
	udpReadTimeout   = 3e9
)

var (
	ErrParse    = errors.New("kerb: parse error")
	ErrProtocol = errors.New("kerb: protocol error")

	supportedAlgorithms = []int{18, 17, 16, rc4HmacAlgorithm}
)

type principalName struct {
	Type  int      `asn1:"explicit,tag:0"`
	Parts []string `asn1:"general,explicit,tag:1"`
}

type encryptedData struct {
	Algorithm  int    `asn1:"explicit,tag:0"`
	KeyVersion int    `asn1:"optional,explicit,tag:1"`
	Data       []byte `asn1:"explicit,tag:2"`
}

type encryptionKey struct {
	Algorithm int    `asn1:"explicit,tag:0"`
	Key       []byte `asn1:"explicit,tag:1"`
}

/* Tickets are wrapped as
 * 1. Context-sensitive tag
 * 2. Application tag 1
 * 3. Universal tag 0 (sequence of)
 *
 * In order to do this:
 * 1. ticket is included as a member with the context sensitive tag, but not
 * explicit. This generates the context-sensitive tag, but nothing else.
 * 2. ticketInner has the application tag which provides #2
 * 3. ticketInner2 then provides #3
 *
 * We also catch the raw bytes with #2 and #3 in the Raw member so that when
 * we serialise the ticket back out in an app request we can use the original
 * data exactly as it was sent to us by the ticket generating service.
 */
type ticket struct {
	Raw         asn1.RawContent
	ticketInner `asn1:"application,tag:1"`
}

type ticketInner struct {
	ticketInner2
}

type ticketInner2 struct {
	KeyVersion    int           `asn1:"explicit,tag:0"`
	Realm         string        `asn1:"general,explicit,tag:1"`
	Service       principalName `asn1:"explicit,tag:2"`
	EncryptedData encryptedData `asn1:"explicit,tag:3"`
}

type transitedEncoding struct {
	Type     int    `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}

type authorization struct {
	Type int    `asn1:"explicit,tag:0"`
	Data []byte `asn1:"explicit,tag:1"`
}

type address struct {
	Type    int    `asn1:"explicit,tag:0"`
	Address []byte `asn1:"explicit,tag:1"`
}

type preauth struct {
	Type int    `asn1:"explicit,tag:1"`
	Data []byte `asn1:"explicit,tag:2"`
}

type checksum struct {
	Type     int    `asn1:"explicit,tag:0"`
	Checksum []byte `asn1:"explicit,tag:1"`
}

type encryptedTimestamp struct {
	Time         time.Time `asn1:"generalized,explicit,tag:0"`
	Microseconds int       `asn1:"optional,explicit,tag:1"`
}

type encryptedTicket struct {
	Flags         int               `asn1:"explicit,tag:0"`
	Key           encryptionKey     `asn1:"explicit,tag:1"`
	Realm         string            `asn1:"general,explicit,tag:2"`
	Client        principalName     `asn1:"explicit,tag:3"`
	Transited     transitedEncoding `asn1:"explicit,tag:4"`
	AuthTime      time.Time         `asn1:"generalized,explicit,tag:5"`
	From          time.Time         `asn1:"generalized,optional,explicit,tag:6"`
	Till          time.Time         `asn1:"generalized,explicit,tag:7"`
	RenewTill     time.Time         `asn1:"generalized,optional,explicit,tag:8"`
	Addresses     []address         `asn1:"optional,explicit,tag:9"`
	Authorization []authorization   `asn1:"optional,explicit,tag:10"`
}

type kdcRequest struct {
	ProtoVersion   int       `asn1:"explicit,tag:1"`
	MsgType        int       `asn1:"explicit,tag:2"`
	Preauth        []preauth `asn1:"optional,explicit,tag:3"`
	kdcRequestBody `asn1:"explicit,tag:4"`
}

type kdcRequestBody struct {
	// Todo: does work with < 32 bits?
	Flags             asn1.BitString `asn1:"explicit,tag:0"`
	Client            principalName  `asn1:"optional,explicit,tag:1"`
	Realm             string         `asn1:"general,explicit,tag:2"`
	Service           principalName  `asn1:"optional,explicit,tag:3"`
	From              time.Time      `asn1:"generalized,optional,explicit,tag:4"`
	Till              time.Time      `asn1:"generalized,explicit,tag:5"`
	RenewTill         time.Time      `asn1:"generalized,optional,explicit,tag:6"`
	Nonce             uint32         `asn1:"explicit,tag:7"`
	Algorithms        []int          `asn1:"explicit,tag:8"`
	Addresses         []address      `asn1:"optional,explicit,tag:9"`
	Authorization     encryptedData  `asn1:"optional,explicit,tag:10"`
	AdditionalTickets []ticket       `asn1:"optional,explicit,tag:11"`
}

type kdcReply struct {
	ProtoVersion int           `asn1:"explicit,tag:0"`
	MsgType      int           `asn1:"explicit,tag:1"`
	Preauth      []preauth     `asn1:"optional,explicit,tag:2"`
	Realm        string        `asn1:"general,explicit,tag:3"`
	Client       principalName `asn1:"explicit,tag:4"`
	Ticket       ticket        `asn1:"tag:5"`
	Encrypted    encryptedData `asn1:"explicit,tag:6"`
}

type lastRequest struct {
	Type int       `asn1:"explicit,tag:0"`
	Time time.Time `asn1:"generalized,explicit,tag:1"`
}

type encryptedKdcReply struct {
	Key          encryptionKey  `asn1:"explicit,tag:0"`
	LastRequests []lastRequest  `asn1:"explicit,tag:1"`
	Nonce        uint32         `asn1:"explicit,tag:2"`
	ExpiryTime   time.Time      `asn1:"generalized,optional,explicit,tag:3"`
	Flags        asn1.BitString `asn1:"explicit,tag:4"`
	AuthTime     time.Time      `asn1:"generalized,explicit,tag:5"`
	From         time.Time      `asn1:"generalized,optional,explicit,tag:6"`
	Till         time.Time      `asn1:"generalized,explicit,tag:7"`
	RenewTill    time.Time      `asn1:"generalized,optional,explicit,tag:8"`
	Realm        string         `asn1:"general,explicit,tag:9"`
	Service      principalName  `asn1:"explicit,tag:10"`
	Addresses    []address      `asn1:"optional,explicit,tag:11"`
}

type appRequest struct {
	ProtoVersion  int            `asn1:"explicit,tag:0"`
	MsgType       int            `asn1:"explicit,tag:1"`
	Flags         asn1.BitString `asn1:"explicit,tag:2"`
	Ticket        ticket         `asn1:"explicit,tag:3"`
	Authenticator encryptedData  `asn1:"explicit,tag:4"`
}

type authenticator struct {
	ProtoVersion   int           `asn1:"explicit,tag:0"`
	Realm          string        `asn1:"general,explicit,tag:1"`
	Client         principalName `asn1:"explicit,tag:2"`
	Checksum       checksum      `asn1:"optional,explicit,tag:3"`
	Microseconds   int           `asn1:"explicit,tag:4"`
	Time           time.Time     `asn1:"generalized,explicit,tag:5"`
	SubKey         encryptionKey `asn1:"optional,explicit,tag:6"`
	SequenceNumber uint32        `asn1:"optional,explicit,tag:7"`
	Authorization  authorization `asn1:"optional,explicit,tag:8"`
}

type appReply struct {
	ProtoVersion int           `asn1:"explicit,tag:0"`
	MsgType      int           `asn1:"explicit,tag:1"`
	Encrypted    encryptedData `asn1:"explicit,tag:2"`
}

type encryptedAppReply struct {
	Time           time.Time     `asn1:"generalized,explicit,tag:0"`
	Microseconds   int           `asn1:"explicit,tag:1"`
	SubKey         encryptionKey `asn1:"optional,explicit,tag:2"`
	SequenceNumber uint32        `asn1:"optional,explicit,tag:3"`
}

type errorMessage struct {
	ProtoVersion       int           `asn1:"explicit,tag:0"`
	MsgType            int           `asn1:"explicit,tag:1"`
	ClientTime         time.Time     `asn1:"generalized,explicit,tag:2"`
	ClientMicroseconds int           `asn1:"explicit,tag:3"`
	ServerTime         time.Time     `asn1:"generalized,explicit,tag:4"`
	ServerMicroseconds int           `asn1:"explicit,tag:5"`
	ErrorCode          int           `asn1:"explicit,tag:6"`
	ClientRealm        string        `asn1:"general,optional,explicit,tag:7"`
	Client             principalName `asn1:"optional,explicit,tag:8"`
	ServiceRealm       string        `asn1:"general,explicit,tag:9"`
	Service            principalName `asn1:"explicit,tag:10"`
	ErrorText          string        `asn1:"general,optional,explicit,tag:11"`
	ErrorData          []byte        `asn1:"optional,explicit,tag:12"`
}

func (e *errorMessage) Error() string {
	return fmt.Sprintf("kerb: remote error %d", e.ErrorCode)
}

type ErrInvalidPrincipal struct {
	str string
}

func (e ErrInvalidPrincipal) Error() string {
	return fmt.Sprintf("kerb: invalid principal '%s'", e.str)
}

func mustMarshal(val interface{}, params string) []byte {
	data, err := asn1.MarshalWithParams(val, params)
	if err != nil {
		panic(err)
	}
	return data
}

type cipher interface {
	encrypt(d []byte, usage int) encryptedData
	decrypt(d encryptedData, usage int) ([]byte, error)
}

type rc4HmacCipher struct {
	key  []byte
	kvno int
}

func rc4HmacKey(password string) []byte {
	// Convert password from UTF8 to UTF16-LE
	s := make([]byte, 0)
	for _, r := range password {
		if r > 0x10000 {
			a, b := utf16.EncodeRune(r)
			s = append(s, byte(a), byte(a>>8), byte(b), byte(b>>8))
		} else {
			s = append(s, byte(r), byte(r>>8))
		}
	}

	h := md4.New()
	h.Write(s)
	return h.Sum(nil)
}

// RC4-HMAC has a few slight differences in the used usage values
func rc4HmacUsage(usage int) uint32 {
	switch usage {
	case asReplyClientKey:
		return 8
	case tgsReplySubKey:
		return 8
	}

	return uint32(usage)
}

func (c *rc4HmacCipher) encrypt(data []byte, usage int) encryptedData {
	// Create the output vector, layout is 0-15 checksum, 16-23 random data, 24- actual data
	out := make([]byte, len(data)+24)
	io.ReadFull(rand.Reader, out[16:24])

	// Hash the key and usage together to get the HMAC-MD5 key
	h1 := hmac.NewMD5(c.key)
	binary.Write(h1, binary.LittleEndian, rc4HmacUsage(usage))
	K1 := h1.Sum(nil)

	// Fill in out[:16] with the checksum
	ch := hmac.NewMD5(K1)
	ch.Write(out[16:24])
	ch.Write(data)
	ch.Sum(out[:0])

	// Calculate the RC4 key using the checksum
	h3 := hmac.NewMD5(K1)
	h3.Write(out[:16])
	K3 := h3.Sum(nil)

	// Encrypt out[16:] with 16:24 being random data and 24: being the
	// encrypted data
	r, _ := rc4.NewCipher(K3)
	r.XORKeyStream(out[16:24], out[16:24])
	r.XORKeyStream(out[24:], data)

	return encryptedData{
		Algorithm:  rc4HmacAlgorithm,
		KeyVersion: c.kvno,
		Data:       out,
	}
}

func (c *rc4HmacCipher) decrypt(d encryptedData, usage int) ([]byte, error) {
	if d.Algorithm != rc4HmacAlgorithm || (d.KeyVersion != 0 && c.kvno != 0 && d.KeyVersion != c.kvno) || len(d.Data) < 24 {
		return nil, ErrProtocol
	}

	// Hash the key and usage together to get the HMAC-MD5 key
	h1 := hmac.NewMD5(c.key)
	binary.Write(h1, binary.LittleEndian, rc4HmacUsage(usage))
	K1 := h1.Sum(nil)

	// Calculate the RC4 key using the checksum
	h3 := hmac.NewMD5(K1)
	h3.Write(d.Data[:16])
	K3 := h3.Sum(nil)

	// Decrypt d.Data[16:] in place with 16:24 being random data and 24:
	// being the encrypted data
	r, _ := rc4.NewCipher(K3)
	r.XORKeyStream(d.Data[16:], d.Data[16:])

	// Recalculate the checksum using the decrypted data
	ch := hmac.NewMD5(K1)
	ch.Write(d.Data[16:])
	chk := ch.Sum(nil)

	// Check the input checksum
	if subtle.ConstantTimeCompare(chk, d.Data[:16]) != 1 {
		return nil, ErrProtocol
	}

	return d.Data[24:], nil
}

func loadKey(algorithm int, key []byte, kvno int) (cipher, error) {
	switch algorithm {
	case rc4HmacAlgorithm:
		return &rc4HmacCipher{key, kvno}, nil
	}
	return nil, ErrProtocol
}

func bitStringToFlags(s asn1.BitString) int {
	x := s.RightAlign()
	y := [4]byte{}
	for i := 0; i < len(x); i++ {
		y[i] = x[i]
	}
	return int(binary.LittleEndian.Uint32(y[:]))
}

func flagsToBitString(flags int) (s asn1.BitString) {
	s.Bytes = make([]byte, 4)
	s.BitLength = 32
	binary.LittleEndian.PutUint32(s.Bytes, uint32(flags))
	return
}

// To ensure the authenticator is unique we use the microseconds field as a
// sequence number as its required anyways
var usSequenceNumber uint32

func nextSequenceNumber() int {
	return int(atomic.AddUint32(&usSequenceNumber, 1) % 1000000)
}

func (r *appRequest) init(t *Ticket, flags int) {
	r.ProtoVersion = kerberosVersion
	r.MsgType = appRequestType
	r.Flags = flagsToBitString(flags)
	r.Ticket = t.ticket

	auth := authenticator{
		ProtoVersion: kerberosVersion,
		Realm:        t.realm,
		Client:       splitPrincipal(t.principal),
		Microseconds: nextSequenceNumber(),
		Time:         time.Now(),
	}

	data := mustMarshal(auth, "application,explicit,tag:2")
	r.Authenticator = t.cipher.encrypt(data, paTgsRequestKey)
}

type request struct {
	principal string // sans realm
	realm     string
	cipher    cipher
	service   string // sans realm
	till      time.Time
	flags     int
	parent    *Ticket
	nonce     uint32
	time      time.Time
	seqnum    int
}

// splitPrincipal splits the principal (sans realm) in p into the split on
// wire format.
func splitPrincipal(p string) (r principalName) {
	parts := strings.Split(p, "/")

	switch len(parts) {
	case 1:
		r.Type = principalNameType
		r.Parts = parts
	case 2:
		r.Type = serviceNameType
		r.Parts = parts
	default:
		panic("invalid principal")
	}

	return
}

// composePrincipal converts the on wire principal format to a composed
// string. It returns an error if it can't understand the split version.
func composePrincipal(n principalName) (string, error) {
	switch n.Type {
	case principalNameType:
		if len(n.Parts) != 1 {
			return "", ErrParse
		}
		return n.Parts[0], nil

	case serviceNameType:
		if len(n.Parts) != 2 {
			return "", ErrParse
		}

		return strings.Join(n.Parts, "/"), nil
	}

	return "", ErrParse
}

// send sends a single ticket request down the sock writer. If r.parent is set
// this is a ticket granting service request, otherwise its an authentication
// service request. Note this does not use any random data, so resending will
// generate the exact same byte stream. This is needed with UDP connections
// such that if the remote receives multiple retries it discards the latters
// as replays.
func (r *request) send(sock io.Writer) error {
	var err error
	var params string

	req := kdcRequest{
		ProtoVersion: kerberosVersion,
		kdcRequestBody: kdcRequestBody{
			Realm:      r.realm,
			Client:     splitPrincipal(r.principal),
			Service:    splitPrincipal(r.service),
			Flags:      flagsToBitString(r.flags),
			Till:       r.till,
			Nonce:      r.nonce,
			Algorithms: supportedAlgorithms,
		},
	}

	if r.parent != nil {
		// For TGS requests we stash an AP_REQ for the ticket granting
		// service (using the krbtgt) as a preauth.
		params = "application,explicit,tag:12"
		req.MsgType = tgsRequestType
		app := appRequest{}
		app.init(r.parent, 0)
		req.Preauth = make([]preauth, 1)
		req.Preauth[0].Type = paTgsRequest
		req.Preauth[0].Data = mustMarshal(app, "application,explicit,tag:14")
	} else {
		// For AS requests we add a PA-ENC-TIMESTAMP preauth, even if
		// its always required rather than trying to handle the
		// preauth error return.
		params = "application,explicit,tag:10"
		req.MsgType = asRequestType
		ts := encryptedTimestamp{r.time, r.seqnum}
		enc := r.cipher.encrypt(mustMarshal(ts, ""), paEncryptedTimestampKey)
		req.Preauth = make([]preauth, 1)
		req.Preauth[0].Type = paEncryptedTimestamp
		req.Preauth[0].Data = mustMarshal(enc, "")
	}

	data, err := asn1.MarshalWithParams(req, params)
	if err != nil {
		return err
	}

	if _, err := sock.Write(data); err != nil {
		return err
	}

	return nil
}

func (r *request) recvReply(sock io.Reader, stream bool) (*Ticket, error) {
	buf := [4096]byte{}
	read := 0
	hsz := 2

	// Decode the message asn1 header so we can figure out which message
	// we have and also the message length (needed for stream
	// connections).

	if n, err := io.ReadAtLeast(sock, buf[read:], hsz-read); err != nil {
		return nil, err
	} else {
		read += n
	}

	fmt.Println(hex.EncodeToString(buf[:hsz]))

	// We are expecting an outer asn1 wrapper with a constructed definite
	// length and an application tag
	if class := buf[0] & 0xC0; class != applicationClass {
		return nil, ErrParse
	}

	// Check that we have a constructed length
	if (buf[0] & 0x20) == 0 {
		return nil, ErrParse
	}

	msgtype := int(buf[0] & 0x1F)
	sz := int(buf[1])

	// Check that we don't have an indefinite length or a long form thats too long
	if sz == 0x80 || sz > 0x83 {
		return nil, ErrParse
	}

	// Handle the long form
	if sz > 0x80 {
		hsz += sz & 0x7F

		if n, err := io.ReadAtLeast(sock, buf[read:], hsz-read); err != nil {
			return nil, err
		} else {
			read += n
		}

		sb := [4]byte{}
		for i, j := hsz-1, 0; i >= 2; i, j = i-1, j+1 {
			sb[j] = buf[i]
		}
		ulen := binary.LittleEndian.Uint32(sb[:])
		sz = int(ulen)
	}

	fmt.Println(hex.EncodeToString(buf[:hsz]))

	if n, err := io.ReadAtLeast(sock, buf[read:], hsz+sz-read); err != nil {
		return nil, err
	} else {
		read += n
	}

	data := buf[hsz : hsz+sz]
	rep := kdcReply{}
	keyusage := 0

	fmt.Println(hex.EncodeToString(data))

	switch msgtype {
	case asReplyType:
		if r.parent != nil {
			return nil, ErrParse
		}

		keyusage = asReplyClientKey

	case tgsReplyType:
		if r.parent == nil {
			return nil, ErrParse
		}

		// We don't use sub keys
		keyusage = tgsReplySessionKey

	case errorType:
		errmsg := errorMessage{}
		if _, err := asn1.Unmarshal(data, &errmsg); err != nil {
			return nil, err
		}

		return nil, &errmsg

	default:
		return nil, ErrParse
	}

	if _, err := asn1.Unmarshal(data, &rep); err != nil {
		return nil, err
	}

	fmt.Printf("request %+v %+v\n\n", r, r.cipher)
	fmt.Printf("reply %+v\n\n", rep)

	if rep.ProtoVersion != kerberosVersion {
		return nil, ErrProtocol
	}

	if n, err := composePrincipal(rep.Client); err != nil {
		return nil, err
	} else if n != r.principal {
		return nil, ErrProtocol
	}

	if rep.MsgType != msgtype || rep.Realm != r.realm {
		return nil, ErrProtocol
	}

	dec, err := r.cipher.decrypt(rep.Encrypted, keyusage)
	if err != nil {
		return nil, err
	}

	enc := encryptedKdcReply{}

	switch msgtype {
	case asReplyType:
		if _, err := asn1.UnmarshalWithParams(dec, &enc, "application,explicit,tag:25"); err != nil {
			return nil, err
		}
	case tgsReplyType:
		if _, err := asn1.UnmarshalWithParams(dec, &enc, "application,explicit,tag:26"); err != nil {
			return nil, err
		}
	default:
		panic("")
	}

	fmt.Printf("encrypted reply %+v\n\n", enc)

	if enc.Nonce != r.nonce || enc.Realm != r.realm {
		return nil, ErrProtocol
	}

	// The returned service may be different from the request. This
	// happens when we get a tgt of the next server to try.
	service, err := composePrincipal(enc.Service)
	if err != nil {
		return nil, err
	}

	cipher, err := loadKey(enc.Key.Algorithm, enc.Key.Key, rep.Ticket.KeyVersion)
	if err != nil {
		return nil, err
	}

	return &Ticket{
		service:    service,
		principal:  r.principal,
		realm:      r.realm,
		ticket:     rep.Ticket,
		till:       enc.Till,
		renewTill:  enc.RenewTill,
		flags:      bitStringToFlags(enc.Flags),
		expiryTime: enc.ExpiryTime,
		cipher:     cipher,
	}, nil
}

type Ticket struct {
	service    string
	principal  string
	realm      string
	ticket     ticket
	till       time.Time
	renewTill  time.Time
	flags      int
	expiryTime time.Time
	cipher     cipher
	sock       net.Conn
	stream     bool
}

type timeoutError interface {
	Timeout() bool
}

func (r *request) do(sock net.Conn, stream bool) (tkt *Ticket, err error) {
	if err = binary.Read(rand.Reader, binary.BigEndian, &r.nonce); err != nil {
		return nil, err
	}

	// Reduce the entropy of the nonce to 31 bits to ensure it fits in a 4
	// byte asn.1 value. Active directory seems to need this.
	r.nonce >>= 1
	r.time = time.Now()
	r.seqnum = nextSequenceNumber()

	for i := 0; i < 3; i++ {
		if err := r.send(sock); err != nil {
			return nil, err
		}

		tkt, err = r.recvReply(sock, stream)

		if err == nil {
			tkt.sock = sock
			tkt.stream = stream
			return
		} else if e, ok := err.(timeoutError); !(!stream && ok && e.Timeout()) {
			return
		}
	}

	return
}

func open(realm string) (net.Conn, bool, error) {
	stream := false
	proto := "udp"
	_, addrs, err := net.LookupSRV("kerberos", "udp", realm)
	if err != nil {
		return nil, false, err
	}

	var sock net.Conn

	for _, a := range addrs {
		addr := net.JoinHostPort(a.Target, strconv.Itoa(int(a.Port)))
		sock, err = net.Dial(proto, addr)
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, false, err
	}

	if !stream {
		// For datagram connections, retry up to three times, then give up
		sock.SetReadTimeout(udpReadTimeout)
	}

	return sock, stream, nil
}

func NewTicket(principal string, password string, service string, till time.Time, flags int) (*Ticket, error) {
	pparts := strings.Split(principal, "@")
	if len(pparts) != 2 {
		return nil, ErrInvalidPrincipal{principal}
	}

	sparts := strings.Split(service, "@")
	if len(sparts) > 2 {
		return nil, ErrInvalidPrincipal{service}
	}

	if len(sparts) == 2 && len(pparts) == 2 && sparts[1] != pparts[1] {
		return nil, ErrInvalidPrincipal{service}
	}

	cipher, err := loadKey(defaultAlgorithm, rc4HmacKey(password), 0)
	if err != nil {
		return nil, err
	}

	r := request{
		cipher:    cipher,
		flags:     flags,
		till:      till,
		realm:     pparts[1],
		principal: pparts[0],
	}

	if service == "" {
		r.service = fmt.Sprintf("krbtgt/%s", r.realm)
	} else {
		r.service = sparts[0]
	}

	sock, stream, err := open(r.realm)
	if err != nil {
		return nil, err
	}

	tkt, err := r.do(sock, stream)
	if err != nil {
		sock.Close()
		return nil, err
	}

	tkt.sock = sock
	tkt.stream = stream
	return tkt, nil
}

// GetSubTicket uses this ticket generating ticket to get a valid ticket for
// the requested service. The sub ticket may be pulled from the cache if there
// is valid ticket that has not expired in it. The till argument indicates how
// long the ticket should last but the returned ticket may and quite often
// will be for a much shorted period. Use ticket.GetExpiryTime to see when a
// new ticket should be requested.
func (t *Ticket) GetSubTicket(service string, till time.Time, flags int) (*Ticket, error) {
	sparts := strings.Split(service, "@")
	if len(sparts) > 2 {
		return nil, ErrInvalidPrincipal{service}
	}

	r := request{
		principal: t.principal,
		cipher:    t.cipher,
		flags:     flags,
		till:      till,
		service:   sparts[0],
	}

	// Default to using the parent's realm
	if len(sparts) == 2 {
		r.realm = sparts[1]
	} else {
		r.realm = t.realm
	}

	tkt := t

	// Loop around the ticket granting services that get returned until we
	// either get our service or we cancel due to a loop in the auth path
	for i := 0; i < 10; i++ {
		var err error
		tkt, err = r.do(tkt.sock, tkt.stream)
		if err != nil {
			return nil, err
		}

		// Did we get the service we wanted
		if tkt.service != r.service {
			return tkt, nil
		}

		// If we got a different service, then we have ticket to a next hop
		// ticket granting service
		sparts := strings.Split(tkt.service, "/")
		if len(sparts) != 2 {
			return nil, ErrProtocol
		}

		if r.realm == t.realm {
			r.realm = sparts[1]
		}

		tkt.sock, tkt.stream, err = open(sparts[1])
		if err != nil {
			return nil, err
		}

		// Loop around to try our request with the next ticket service
	}

	return nil, ErrProtocol
}

func (t *Ticket) GenerateReply(r []byte) ([]byte, error) {
	panic("todo")
}

func (t *Ticket) LocalPrincipal() string {
	return fmt.Sprintf("%s@%s", t.principal, t.realm)
}

func (t *Ticket) RemotePrincipal() string {
	return fmt.Sprintf("%s@%s", t.service, t.realm)
}

func (t *Ticket) ExpiryTime() time.Time {
	return t.till
}

func LoadKeytab(file string) ([]*Ticket, error) {
	panic("todo")
}
