package kerb

import (
	"crypto/hmac"
	"crypto/md4"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/binary"
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
	Forwardable                 = 1 << 30
	Forwarded                   = 1 << 29
	Proxiable                   = 1 << 28
	Proxy                       = 1 << 27
	AllowPostdate               = 1 << 26
	Postdated                   = 1 << 25
	Renewable                   = 1 << 23
	canonicalize                = 1 << 16
	DisableTransitedCheck       = 1 << 5
	RenewableOk                 = 1 << 4
	EncryptedTicketInSessionKey = 1 << 3
	Renew                       = 1 << 1
	Validate                    = 1 << 0

	defaultLoginFlags = 0
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
	rc4HmacChecksum  = -138
	md5Checksum      = 7
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
	appRequestAuthChecksumKey
	appRequestAuthKey
	appReplyEncryptedKey
)

const (
	kerberosVersion      = 5
	applicationClass     = 0x40
	udpReadTimeout       = 3e9
	defaultLoginDuration = time.Hour * 24
)

var (
	ErrParse    = errors.New("kerb: parse error")
	ErrProtocol = errors.New("kerb: protocol error")

	supportedAlgorithms = []int{rc4HmacAlgorithm}

	asRequestParam     = "application,explicit,tag:10"
	tgsRequestParam    = "application,explicit,tag:12"
	asReplyParam       = "application,explicit,tag:11"
	tgsReplyParam      = "application,explicit,tag:13"
	encAsReplyParam    = "application,explicit,tag:25"
	encTgsReplyParam   = "application,explicit,tag:26"
	ticketParam        = "application,explicit,tag:1"
	encTicketParam     = "application,explicit,tag:3"
	appRequestParam    = "application,explicit,tag:14"
	authenticatorParam = "application,explicit,tag:2"
	appReplyParam      = "application,explicit,tag:15"
	encAppReplyParam   = "application,explicit,tag:27"
	errorParam         = "application,explicit,tag:30"
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

type ticket struct {
	KeyVersion    int           `asn1:"explicit,tag:0"`
	Realm         string        `asn1:"general,explicit,tag:1"`
	Service       principalName `asn1:"explicit,tag:2"`
	EncryptedData encryptedData `asn1:"explicit,tag:3"`
}

type transitedEncoding struct {
	Type     int    `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}

// Known as authorization in the RFCs
type restriction struct {
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

type checksumData struct {
	Type int    `asn1:"explicit,tag:0"`
	Data []byte `asn1:"explicit,tag:1"`
}

type encryptedTimestamp struct {
	Time         time.Time `asn1:"generalized,explicit,tag:0"`
	Microseconds int       `asn1:"optional,explicit,tag:1"`
}

type encryptedTicket struct {
	Flags        int               `asn1:"explicit,tag:0"`
	Key          encryptionKey     `asn1:"explicit,tag:1"`
	ClientRealm  string            `asn1:"general,explicit,tag:2"`
	Client       principalName     `asn1:"explicit,tag:3"`
	Transited    transitedEncoding `asn1:"explicit,tag:4"`
	AuthTime     time.Time         `asn1:"generalized,explicit,tag:5"`
	From         time.Time         `asn1:"generalized,optional,explicit,tag:6"`
	Till         time.Time         `asn1:"generalized,explicit,tag:7"`
	RenewTill    time.Time         `asn1:"generalized,optional,explicit,tag:8"`
	Addresses    []address         `asn1:"optional,explicit,tag:9"`
	Restrictions []restriction     `asn1:"optional,explicit,tag:10"`
}

type kdcRequest struct {
	ProtoVersion int           `asn1:"explicit,tag:1"`
	MsgType      int           `asn1:"explicit,tag:2"`
	Preauth      []preauth     `asn1:"optional,explicit,tag:3"`
	Body         asn1.RawValue `asn1:"explicit,tag:4"`
}

type kdcRequestBody struct {
	Flags             asn1.BitString  `asn1:"explicit,tag:0"`
	Client            principalName   `asn1:"optional,explicit,tag:1"`
	ServiceRealm      string          `asn1:"general,explicit,tag:2"`
	Service           principalName   `asn1:"optional,explicit,tag:3"`
	From              time.Time       `asn1:"generalized,optional,explicit,tag:4"`
	Till              time.Time       `asn1:"generalized,explicit,tag:5"`
	RenewTill         time.Time       `asn1:"generalized,optional,explicit,tag:6"`
	Nonce             uint32          `asn1:"explicit,tag:7"`
	Algorithms        []int           `asn1:"explicit,tag:8"`
	Addresses         []address       `asn1:"optional,explicit,tag:9"`
	Authorization     encryptedData   `asn1:"optional,explicit,tag:10"`
	AdditionalTickets []asn1.RawValue `asn1:"optional,explicit,tag:11"`
}

type kdcReply struct {
	ProtoVersion int           `asn1:"explicit,tag:0"`
	MsgType      int           `asn1:"explicit,tag:1"`
	Preauth      []preauth     `asn1:"optional,explicit,tag:2"`
	ClientRealm  string        `asn1:"general,explicit,tag:3"`
	Client       principalName `asn1:"explicit,tag:4"`
	Ticket       asn1.RawValue `asn1:"explicit,tag:5"`
	Encrypted    encryptedData `asn1:"explicit,tag:6"`
}

type lastRequest struct {
	Type int       `asn1:"explicit,tag:0"`
	Time time.Time `asn1:"generalized,explicit,tag:1"`
}

type encryptedKdcReply struct {
	Key             encryptionKey  `asn1:"explicit,tag:0"`
	LastRequests    []lastRequest  `asn1:"explicit,tag:1"`
	Nonce           uint32         `asn1:"explicit,tag:2"`
	ClientKeyExpiry time.Time      `asn1:"generalized,optional,explicit,tag:3"`
	Flags           asn1.BitString `asn1:"explicit,tag:4"`
	AuthTime        time.Time      `asn1:"generalized,explicit,tag:5"`
	From            time.Time      `asn1:"generalized,optional,explicit,tag:6"`
	Till            time.Time      `asn1:"generalized,explicit,tag:7"`
	RenewTill       time.Time      `asn1:"generalized,optional,explicit,tag:8"`
	ServiceRealm    string         `asn1:"general,explicit,tag:9"`
	Service         principalName  `asn1:"explicit,tag:10"`
	Addresses       []address      `asn1:"optional,explicit,tag:11"`
}

type appRequest struct {
	ProtoVersion  int            `asn1:"explicit,tag:0"`
	MsgType       int            `asn1:"explicit,tag:1"`
	Flags         asn1.BitString `asn1:"explicit,tag:2"`
	Ticket        asn1.RawValue  `asn1:"explicit,tag:3"`
	Authenticator encryptedData  `asn1:"explicit,tag:4"`
}

type authenticator struct {
	ProtoVersion   int           `asn1:"explicit,tag:0"`
	ClientRealm    string        `asn1:"general,explicit,tag:1"`
	Client         principalName `asn1:"explicit,tag:2"`
	Checksum       checksumData  `asn1:"optional,explicit,tag:3"`
	Microseconds   int           `asn1:"explicit,tag:4"`
	Time           time.Time     `asn1:"generalized,explicit,tag:5"`
	SubKey         encryptionKey `asn1:"optional,explicit,tag:6"`
	SequenceNumber uint32        `asn1:"optional,explicit,tag:7"`
	Restrictions   []restriction `asn1:"optional,explicit,tag:8"`
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
	ClientTime         time.Time     `asn1:"generalized,optional,explicit,tag:2"`
	ClientMicroseconds int           `asn1:"optional,explicit,tag:3"`
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

type cipher interface {
	encrypt(d []byte, usage int) encryptedData
	decrypt(d encryptedData, usage int) ([]byte, error)
	checksum(d []byte, usage int) checksumData
}

type rc4HmacCipher struct {
	key  []byte
	kvno int
}

// rc4HmacKey converts a UTF8 password into a key suitable for use with the
// rc4HmacCipher.
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

// RC4-HMAC has a few slight differences in the key usage values
func rc4HmacUsage(usage int) uint32 {
	switch usage {
	case asReplyClientKey:
		return 8
	}

	return uint32(usage)
}

func (c *rc4HmacCipher) checksum(data []byte, usage int) checksumData {
	// TODO: replace with RC4-HMAC checksum algorithm. For now we are
	// using the unkeyed RSA-MD5 checksum algorithm
	h := md5.New()
	h.Write(data)
	return checksumData{
		Type: md5Checksum,
		Data: h.Sum(nil),
	}
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
	y := [4]byte{}
	for i, b := range s.Bytes {
		y[i] = b
	}
	return int(binary.BigEndian.Uint32(y[:]))
}

func flagsToBitString(flags int) (s asn1.BitString) {
	s.Bytes = make([]byte, 4)
	s.BitLength = 32
	binary.BigEndian.PutUint32(s.Bytes, uint32(flags))
	return
}

func initSequenceNumber() (ret uint32) {
	if err := binary.Read(rand.Reader, binary.BigEndian, &ret); err != nil {
		panic(err)
	}
	return
}

// To ensure the authenticator is unique we use the microseconds field as a
// sequence number as its required anyways
var usSequenceNumber uint32 = initSequenceNumber()

func nextSequenceNumber() int {
	return int(atomic.AddUint32(&usSequenceNumber, 1))
}

type request struct {
	client  principalName
	crealm  string
	cipher  cipher
	service principalName
	srealm  string
	till    time.Time
	flags   int
	parent  *Ticket
	nonce   uint32
	time    time.Time
	seqnum  int
}

func nameEquals(a, b principalName) bool {
	if a.Type != b.Type || len(a.Parts) != len(b.Parts) {
		return false
	}

	for i, ap := range a.Parts {
		if ap != b.Parts[i] {
			return false
		}
	}

	return true
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
// string.
func composePrincipal(n principalName) string {
	return strings.Join(n.Parts, "/")
}

// send sends a single ticket request down the sock writer. If r.parent is set
// this is a ticket granting service request, otherwise its an authentication
// service request. Note this does not use any random data, so resending will
// generate the exact same byte stream. This is needed with UDP connections
// such that if the remote receives multiple retries it discards the latters
// as replays.
func (r *request) send(sock io.Writer) error {
	body := kdcRequestBody{
		Client:       r.client,
		ServiceRealm: r.srealm,
		Service:      r.service,
		Flags:        flagsToBitString(r.flags),
		Till:         r.till,
		Nonce:        r.nonce,
		Algorithms:   supportedAlgorithms,
	}

	bodyData, err := asn1.Marshal(body)
	if err != nil {
		return err
	}

	reqParam := ""
	req := kdcRequest{
		ProtoVersion: kerberosVersion,
		Body:         asn1.RawValue{FullBytes: bodyData},
		// MsgType and Preauth filled out below
	}

	if r.parent != nil {
		// For TGS requests we stash an AP_REQ for the ticket granting
		// service (using the krbtgt) as a preauth.
		reqParam = tgsRequestParam
		req.MsgType = tgsRequestType

		auth := authenticator{
			ProtoVersion: kerberosVersion,
			ClientRealm:  r.crealm,
			Client:       r.client,
			Microseconds: r.seqnum % 1000000,
			Time:         r.time,
			Checksum:     r.cipher.checksum(bodyData, paTgsRequestChecksumKey),
		}

		authData, err := asn1.MarshalWithParams(auth, authenticatorParam)
		if err != nil {
			return err
		}

		app := appRequest{
			ProtoVersion:  kerberosVersion,
			MsgType:       appRequestType,
			Flags:         flagsToBitString(0),
			Ticket:        asn1.RawValue{FullBytes: r.parent.ticket},
			Authenticator: r.cipher.encrypt(authData, paTgsRequestKey),
		}

		appData, err := asn1.MarshalWithParams(app, appRequestParam)
		if err != nil {
			return err
		}

		req.Preauth = []preauth{{paTgsRequest, appData}}
	} else {
		// For AS requests we add a PA-ENC-TIMESTAMP preauth, even if
		// its always required rather than trying to handle the
		// preauth error return.
		reqParam = asRequestParam
		req.MsgType = asRequestType

		ts, err := asn1.Marshal(encryptedTimestamp{r.time, r.seqnum % 1000000})
		if err != nil {
			return err
		}

		enc, err := asn1.Marshal(r.cipher.encrypt(ts, paEncryptedTimestampKey))
		if err != nil {
			return err
		}

		req.Preauth = []preauth{{paEncryptedTimestamp, enc}}
	}

	data, err := asn1.MarshalWithParams(req, reqParam)
	if err != nil {
		return err
	}

	if _, err := sock.Write(data); err != nil {
		return err
	}

	return nil
}

func readMessage(r io.Reader) (msgtype int, data []byte, err error) {
	buf := [4096]byte{}
	read := 0
	hsz := 2

	// Decode the message asn1 header so we can figure out which message
	// we have and also the message length (needed for stream
	// connections).

	n, err := io.ReadAtLeast(r, buf[read:], hsz-read)
	if err != nil {
		return
	}
	read += n

	// We are expecting an outer asn1 wrapper with a constructed definite
	// length and an application tag
	if class := buf[0] & 0xC0; class != applicationClass {
		err = ErrParse
		return
	}

	// Check that we have a constructed length
	if (buf[0] & 0x20) == 0 {
		err = ErrParse
		return
	}

	sz := int(buf[1])

	// Check that we don't have an indefinite length or a long form thats too long
	if sz == 0x80 || sz > 0x83 {
		err = ErrParse
		return
	}

	// Handle the long form
	if sz > 0x80 {
		hsz += sz & 0x7F

		n, err = io.ReadAtLeast(r, buf[read:], hsz-read)
		if err != nil {
			return
		}
		read += n

		sb := [4]byte{}
		for i, j := hsz-1, 0; i >= 2; i, j = i-1, j+1 {
			sb[j] = buf[i]
		}
		ulen := binary.LittleEndian.Uint32(sb[:])
		sz = int(ulen)
	}

	n, err = io.ReadAtLeast(r, buf[read:], hsz+sz-read)
	if err != nil {
		return
	}
	read += n

	msgtype = int(buf[0] & 0x1F)
	data = buf[hsz : hsz+sz]
	return
}

func (r *request) recvReply(sock io.Reader, stream bool) (*Ticket, error) {
	rep := kdcReply{}
	keyusage := 0
	encparam := ""

	msgtype, data, err := readMessage(sock)
	if err != nil {
		return nil, err
	}

	switch msgtype {
	case asReplyType:
		if r.parent != nil {
			return nil, ErrParse
		}

		keyusage = asReplyClientKey
		encparam = encAsReplyParam

	case tgsReplyType:
		if r.parent == nil {
			return nil, ErrParse
		}

		// We don't use sub keys
		keyusage = tgsReplySessionKey
		encparam = encTgsReplyParam

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

	if rep.ProtoVersion != kerberosVersion {
		return nil, ErrProtocol
	}

	if rep.MsgType != msgtype || !nameEquals(rep.Client, r.client) || rep.ClientRealm != r.crealm {
		return nil, ErrProtocol
	}

	// Decrypt the embedded data

	dec, err := r.cipher.decrypt(rep.Encrypted, keyusage)
	if err != nil {
		return nil, err
	}

	enc := encryptedKdcReply{}
	if _, err := asn1.UnmarshalWithParams(dec, &enc, encparam); err != nil {
		return nil, err
	}

	// The returned service may be different from the request. This
	// happens when we get a tgt of the next server to try.
	if enc.Nonce != r.nonce || enc.ServiceRealm != r.srealm {
		return nil, ErrProtocol
	}

	ticket := ticket{}
	if _, err := asn1.UnmarshalWithParams(rep.Ticket.FullBytes, &ticket, ticketParam); err != nil {
		return nil, err
	}

	cipher, err := loadKey(enc.Key.Algorithm, enc.Key.Key, ticket.KeyVersion)
	if err != nil {
		return nil, err
	}

	// TODO use enc.Flags to mask out flags which the server refused
	return &Ticket{
		service:   enc.Service,
		client:    r.client,
		srealm:    enc.ServiceRealm,
		crealm:    r.crealm,
		ticket:    rep.Ticket.FullBytes,
		till:      enc.Till,
		renewTill: enc.RenewTill,
		flags:     r.flags,
		cipher:    cipher,
	}, nil
}

type Ticket struct {
	service   principalName
	client    principalName
	crealm    string
	srealm    string
	ticket    []byte
	till      time.Time
	renewTill time.Time
	flags     int
	cipher    cipher
	sock      net.Conn
	stream    bool
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
			return tkt, err
		} else if e, ok := err.(timeoutError); !stream && ok && e.Timeout() {
			// Try again for UDP timeouts
			continue
		} else {
			return nil, err
		}
	}

	return nil, err
}

func open(realm string) (net.Conn, bool, error) {
	proto := "udp"
	stream := proto == "tcp"
	_, addrs, err := net.LookupSRV("kerberos", proto, realm)
	if err != nil {
		_, addrs, err = net.LookupSRV("kerberos-master", proto, realm)
		if err != nil {
			return nil, false, err
		}
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

// ResolveService resolves the canonical service principal for a given service
// on a given host.
//
// Host will be converted to the canonical FQDN and appended to service as
// <service>/<canon fqdn> to create the principal.
func ResolveService(service, host string) (string, error) {
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
	cipher    cipher
	principal principalName
	realm     string
	cache     map[string]*Ticket
	tgt       map[string]*Ticket
}

// NewCredential creates a new client credential that can be used to get
// tickets. The credential uses the specified UTF8 user, realm, and plaintext
// password.
//
// This does not check if the password is valid. To do that request the
// krbtgt/<realm> service ticket.
func NewCredential(user, realm, password string) *Credential {
	// Due to use of rc4HmacKey, the key should always be valid
	cipher, err := loadKey(rc4HmacAlgorithm, rc4HmacKey(password), 0)
	if err != nil {
		panic(err)
	}

	return &Credential{
		cipher:    cipher,
		principal: principalName{principalNameType, []string{user}},
		realm:     strings.ToUpper(realm),
		cache:     make(map[string]*Ticket),
		tgt:       make(map[string]*Ticket),
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

	// AS_REQ login
	r := request{
		cipher:  c.cipher,
		flags:   defaultLoginFlags,
		till:    time.Now().Add(defaultLoginDuration),
		crealm:  c.realm,
		srealm:  c.realm,
		client:  c.principal,
		service: principalName{serviceNameType, []string{"krbtgt", c.realm}},
	}

	sock, stream, err := open(r.srealm)
	if err != nil {
		return nil, "", err
	}

	tgt, err := r.do(sock, stream)
	if err != nil {
		sock.Close()
		return nil, "", err
	}

	tgt.sock = sock
	tgt.stream = stream

	c.tgt[c.realm] = tgt
	c.cache[fmt.Sprintf("krbtgt/%s", c.realm)] = tgt

	return tgt, c.realm, nil
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

	r := request{
		client:  tgt.client,
		crealm:  tgt.crealm,
		service: splitPrincipal(service),
		srealm:  tgtrealm,
		flags:   flags | canonicalize,
		till:    till,
		parent:  tgt,
	}

	// Loop around the ticket granting services that get returned until we
	// either get our service or we cancel due to a loop in the auth path
	for i := 0; i < 10; i++ {
		r.cipher = r.parent.cipher

		tkt, err := r.do(r.parent.sock, r.parent.stream)
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
		s := tkt.service
		if s.Type != serviceNameType || len(s.Parts) != 2 || s.Parts[0] != "krbtgt" {
			return tkt, nil
		}
		r.srealm = s.Parts[1]
		r.parent = tkt

		tkt.sock, tkt.stream, err = open(r.srealm)
		if err != nil {
			return nil, err
		}

		c.tgt[r.srealm] = tkt

		// Loop around to try our request with the next ticket service
	}

	return nil, ErrProtocol
}

func (t *Ticket) Connect(sock io.ReadWriter, flags int) error {
	/*
		req := appRequest{
			ProtoVersion: kerberosVersion,
			MsgType: appRequestType,
			Flags: flagsToBitString(flags),
			Ticket: t.ticket,
			Authenticator: t.cipher.encrypt(appData, appRequestAuthKey),
		}
	*/
	panic("todo")
}

func (t *Ticket) Accept(sock io.ReadWriter, flags int) error {
	panic("todo")
}

func (c *Credential) Principal() string {
	return composePrincipal(c.principal)
}

func (c *Credential) Realm() string {
	return c.realm
}

func (t *Ticket) Principal() string {
	return composePrincipal(t.service)
}

func (t *Ticket) Realm() string {
	return t.srealm
}

func (t *Ticket) ExpiryTime() time.Time {
	return t.till
}

type keytabEntry struct {
	size          int32
	numComponents uint16
}

const (
	keytabVersion = 0x502
)

// ReadKeytab reads a MIT kerberos keytab file returning all credentials found
// within.
//
// These are produced by MIT, heimdal, and the ktpass utility on windows.
func ReadKeytab(file io.Reader) (retcreds []*Credential, err error) {
	var creds []*Credential
	var version uint16
	if err = binary.Read(file, binary.BigEndian, &version); err != nil {
		return
	}
	if version != keytabVersion {
		err = ErrParse
		return
	}

	for {
		var size int32
		err = binary.Read(file, binary.BigEndian, &size)
		if err == io.EOF {
			break
		} else if err != nil {
			return
		}

		// Negative sizes are used for deleted entries, skip over it
		if size < 0 {
			size *= -1
			buf := [4096]byte{}
			for size-4096 > 0 {
				size -= 4096
				if _, err = io.ReadFull(file, buf[:]); err != nil {
					return
				}
			}
			if _, err = io.ReadFull(file, buf[:size]); err != nil {
				return
			}
			continue
		}

		var numComponents uint16
		size -= 2
		if err = binary.Read(file, binary.BigEndian, &numComponents); err != nil {
			return
		}

		// Get an extra octet_string for the realm
		var components []string
		for i := 0; i < int(numComponents+1); i++ {
			var csize uint16
			size -= 2
			if err = binary.Read(file, binary.BigEndian, &csize); err != nil {
				return
			}

			cbuf := make([]byte, csize)
			size -= int32(csize)
			if _, err = io.ReadFull(file, cbuf); err != nil {
				return
			}

			components = append(components, string(cbuf))
		}

		// unused
		var nameType uint32
		size -= 4
		if err = binary.Read(file, binary.BigEndian, &nameType); err != nil {
			return
		}

		// unused
		var timestamp uint32
		size -= 4
		if err = binary.Read(file, binary.BigEndian, &timestamp); err != nil {
			return
		}

		var vno8 uint8
		size -= 1
		if err = binary.Read(file, binary.BigEndian, &vno8); err != nil {
			return
		}

		var keytype uint16
		size -= 2
		if err = binary.Read(file, binary.BigEndian, &keytype); err != nil {
			return
		}

		var keysize uint16
		size -= 2
		if err = binary.Read(file, binary.BigEndian, &keysize); err != nil {
			return
		}

		key := make([]byte, keysize)
		size -= int32(keysize)
		if _, err = io.ReadFull(file, key); err != nil {
			return
		}

		if size < 0 {
			err = ErrParse
			return
		}

		keyversion := int(vno8)
		if size >= 4 {
			var vno32 uint32
			size -= 4
			if err = binary.Read(file, binary.BigEndian, &vno32); err != nil {
				return
			}
			keyversion = int(vno32)
		}

		var cipher cipher
		if cipher, err = loadKey(int(keytype), key, keyversion); err != nil {
			return
		}

		cred := &Credential{
			cipher:    cipher,
			realm:     components[0],
			principal: principalName{int(nameType), components[1:]},
			cache:     make(map[string]*Ticket),
			tgt:       make(map[string]*Ticket),
		}

		creds = append(creds, cred)
	}

	return creds, nil
}

// ReadCredentialCache reads a MIT kerberos credential cache file.
//
// These are normally found at /tmp/krb5cc_<uid> on unix.
//
// The returned credential will be populated with the principal found within
// the file and all the tickets will be put into the credential's ticket cache
// (and can be subsequently retrieved using GetTicket).
func ReadCredentialCache(file io.Reader) (*Credential, error) {
	panic("todo")
}

func WriteKeytab(file io.Writer, c []*Credential) error {
	panic("todo")
}

func WriteCredentialCache(file io.Writer, c *Credential) error {
	panic("todo")
}
