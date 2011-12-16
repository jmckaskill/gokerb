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
	Canonicalize                = 1 << 16
	DisableTransitedCheck       = 1 << 5
	RenewableOk                 = 1 << 4
	EncryptedTicketInSessionKey = 1 << 3
	Renew                       = 1 << 1
	Validate                    = 1 << 0

	defaultLoginFlags = 0
)

// Remote error codes
const (
	KDC_ERR_NONE                 = iota // No error
	KDC_ERR_NAME_EXP                    // Client's entry in database has expired
	KDC_ERR_SERVICE_EXP                 // Server's entry in database has expired
	KDC_ERR_BAD_PVNO                    // Requested protocol version number not supported
	KDC_ERR_C_OLD_MAST_KVNO             // Client's key encrypted in old master key
	KDC_ERR_S_OLD_MAST_KVNO             // Server's key encrypted in old master key
	KDC_ERR_C_PRINCIPAL_UNKNOWN         // Client not found in Kerberos database
	KDC_ERR_S_PRINCIPAL_UNKNOWN         // Server not found in Kerberos database
	KDC_ERR_PRINCIPAL_NOT_UNIQUE        // Multiple principal entries in database
	KDC_ERR_NULL_KEY                    // The client or server has a null key
	KDC_ERR_CANNOT_POSTDATE             // Ticket not eligible for postdating
	KDC_ERR_NEVER_VALID                 // Requested starttime is later than end time
	KDC_ERR_POLICY                      // KDC policy rejects request
	KDC_ERR_BADOPTION                   // KDC cannot accommodate requested option
	KDC_ERR_ETYPE_NOSUPP                // KDC has no support for encryption type
	KDC_ERR_SUMTYPE_NOSUPP              // KDC has no support for checksum type
	KDC_ERR_PADATA_TYPE_NOSUPP          // KDC has no support for padata type
	KDC_ERR_TRTYPE_NOSUPP               // KDC has no support for transited type
	KDC_ERR_CLIENT_REVOKED              // Clients credentials have been revoked
	KDC_ERR_SERVICE_REVOKED             // Credentials for server have been revoked
	KDC_ERR_TGT_REVOKED                 // TGT has been revoked
	KDC_ERR_CLIENT_NOTYET               // Client not yet valid; try again later
	KDC_ERR_SERVICE_NOTYET              // Server not yet valid; try again later
	KDC_ERR_KEY_EXPIRED                 // Password has expired; change password to reset
	KDC_ERR_PREAUTH_FAILED              // Pre-authentication information was invalid
	KDC_ERR_PREAUTH_REQUIRED            // Additional pre-authentication required
	KDC_ERR_SERVER_NOMATCH              // Requested server and ticket don't match
	KDC_ERR_MUST_USE_USER2USER          // Server principal valid for user2user only
	KDC_ERR_PATH_NOT_ACCEPTED           // KDC Policy rejects transited path
	KDC_ERR_SVC_UNAVAILABLE             // A service is not available
	_
	KRB_AP_ERR_BAD_INTEGRITY // Integrity check on decrypted field failed
	KRB_AP_ERR_TKT_EXPIRED   // Ticket expired
	KRB_AP_ERR_TKT_NYV       // Ticket not yet valid
	KRB_AP_ERR_REPEAT        // Request is a replay
	KRB_AP_ERR_NOT_US        // The ticket isn't for us
	KRB_AP_ERR_BADMATCH      // Ticket and authenticator don't match
	KRB_AP_ERR_SKEW          // Clock skew too great
	KRB_AP_ERR_BADADDR       // Incorrect net address
	KRB_AP_ERR_BADVERSION    // Protocol version mismatch
	KRB_AP_ERR_MSG_TYPE      // Invalid msg type
	KRB_AP_ERR_MODIFIED      // Message stream modified
	KRB_AP_ERR_BADORDER      // Message out of order
	_
	KRB_AP_ERR_BADKEYVER     // Specified version of key is not available
	KRB_AP_ERR_NOKEY         // Service key not available
	KRB_AP_ERR_MUT_FAIL      // Mutual authentication failed
	KRB_AP_ERR_BADDIRECTION  // Incorrect message direction
	KRB_AP_ERR_METHOD        // Alternative authentication method required
	KRB_AP_ERR_BADSEQ        // Incorrect sequence number in message
	KRB_AP_ERR_INAPP_CKSUM   // Inappropriate type of checksum in message
	KRB_AP_PATH_NOT_ACCEPTED // Policy rejects transited path
	KRB_ERR_RESPONSE_TOO_BIG // Response too big for UDP; retry with TCP
	_
	_
	_
	_
	_
	_
	_
	KRB_ERR_GENERIC                       // Generic error (description in e-text)
	KRB_ERR_FIELD_TOOLONG                 // Field is too long for this implementation
	KDC_ERROR_CLIENT_NOT_TRUSTED          // Reserved for PKINIT
	KDC_ERROR_KDC_NOT_TRUSTED             // Reserved for PKINIT
	KDC_ERROR_INVALID_SIG                 // Reserved for PKINIT
	KDC_ERR_KEY_TOO_WEAK                  // Reserved for PKINIT
	KDC_ERR_CERTIFICATE_MISMATCH          // Reserved for PKINIT
	KRB_AP_ERR_NO_TGT                     // No TGT available to validate USER-TO-USER
	KDC_ERR_WRONG_REALM                   // Reserved for future use
	KRB_AP_ERR_USER_TO_USER_REQUIRED      // Ticket must be for USER-TO-USER
	KDC_ERR_CANT_VERIFY_CERTIFICATE       // Reserved for PKINIT
	KDC_ERR_INVALID_CERTIFICATE           // Reserved for PKINIT
	KDC_ERR_REVOKED_CERTIFICATE           // Reserved for PKINIT
	KDC_ERR_REVOCATION_STATUS_UNKNOWN     // Reserved for PKINIT
	KDC_ERR_REVOCATION_STATUS_UNAVAILABLE // Reserved for PKINIT
	KDC_ERR_CLIENT_NAME_MISMATCH          // Reserved for PKINIT
	KDC_ERR_KDC_NAME_MISMATCH             // Reserved for PKINIT
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
	maxUdpWrite          = 1400 // TODO: figure out better way of doing this
)

var (
	ErrParse    = errors.New("kerb: parse error")
	ErrProtocol = errors.New("kerb: protocol error")
	ErrAuthLoop = errors.New("kerb: auth loop")

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

type RemoteError struct {
	msg *errorMessage
}

func (e RemoteError) ErrorCode() int {
	return e.msg.ErrorCode
}

func (e RemoteError) Error() string {
	return fmt.Sprintf("kerb: remote error %d", e.msg.ErrorCode)
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
	ckey    cipher // only needed for AS requests when tgt == nil
	service principalName
	srealm  string
	till    time.Time
	flags   int
	tgt     *Ticket

	// Setup by request.do()
	nonce  uint32
	time   time.Time
	seqnum int
	sock   net.Conn
	proto  string
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

// send sends a single ticket request down the sock writer. If r.tgt is set
// this is a ticket granting service request, otherwise its an authentication
// service request. Note this does not use any random data, so resending will
// generate the exact same byte stream. This is needed with UDP connections
// such that if the remote receives multiple retries it discards the latters
// as replays.
func (r *request) sendRequest() error {
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

	if r.tgt != nil {
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
			Checksum:     r.tgt.key.checksum(bodyData, paTgsRequestChecksumKey),
		}

		authData, err := asn1.MarshalWithParams(auth, authenticatorParam)
		if err != nil {
			return err
		}

		app := appRequest{
			ProtoVersion:  kerberosVersion,
			MsgType:       appRequestType,
			Flags:         flagsToBitString(0),
			Ticket:        asn1.RawValue{FullBytes: r.tgt.ticket},
			Authenticator: r.tgt.key.encrypt(authData, paTgsRequestKey),
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

		enc, err := asn1.Marshal(r.ckey.encrypt(ts, paEncryptedTimestampKey))
		if err != nil {
			return err
		}

		req.Preauth = []preauth{{paEncryptedTimestamp, enc}}
	}

	data, err := asn1.MarshalWithParams(req, reqParam)
	if err != nil {
		return err
	}

	if r.proto == "tcp" {
		if err := binary.Write(r.sock, binary.BigEndian, uint32(len(data))); err != nil {
			return err
		}
	}

	if r.proto == "udp" && len(data) > maxUdpWrite {
		return io.ErrShortWrite
	}

	if _, err := r.sock.Write(data); err != nil {
		return err
	}

	return nil
}

func (r *request) recvReply() (*Ticket, error) {
	var data []byte

	switch r.proto {
	case "tcp":
		// TCP streams prepend a 32bit big endian size before each PDU
		var size uint32
		if err := binary.Read(r.sock, binary.BigEndian, &size); err != nil {
			return nil, err
		}

		data = make([]byte, size)

		if _, err := io.ReadFull(r.sock, data); err != nil {
			return nil, err
		}

	case "udp":
		// UDP PDUs are packed in individual frames
		data = make([]byte, 4096)

		n, err := r.sock.Read(data)
		if err != nil {
			return nil, err
		}

		data = data[:n]

	default:
		panic("")
	}

	if len(data) == 0 {
		return nil, ErrParse
	}

	if (data[0] & 0x1F) == errorType {
		errmsg := errorMessage{}
		if _, err := asn1.UnmarshalWithParams(data, &errmsg, errorParam); err != nil {
			return nil, err
		}
		return nil, RemoteError{&errmsg}
	}

	var msgtype, usage int
	var repparam, encparam string
	var key cipher

	if r.tgt != nil {
		repparam = tgsReplyParam
		msgtype = tgsReplyType
		key = r.tgt.key
		usage = tgsReplySessionKey
		encparam = encTgsReplyParam
	} else {
		repparam = asReplyParam
		msgtype = asReplyType
		key = r.ckey
		usage = asReplyClientKey
		encparam = encAsReplyParam
	}

	// Decode reply body

	rep := kdcReply{}
	if _, err := asn1.UnmarshalWithParams(data, &rep, repparam); err != nil {
		return nil, err
	}

	if rep.MsgType != msgtype || rep.ProtoVersion != kerberosVersion || !nameEquals(rep.Client, r.client) || rep.ClientRealm != r.crealm {
		return nil, ErrProtocol
	}

	// Decode encrypted part

	enc := encryptedKdcReply{}
	if edata, err := key.decrypt(rep.Encrypted, usage); err != nil {
		return nil, err
	} else if _, err := asn1.UnmarshalWithParams(edata, &enc, encparam); err != nil {
		return nil, err
	}

	// The returned service may be different from the request. This
	// happens when we get a tgt of the next server to try.
	if enc.Nonce != r.nonce || enc.ServiceRealm != r.srealm {
		return nil, ErrProtocol
	}

	// Decode ticket

	tkt := ticket{}
	if _, err := asn1.UnmarshalWithParams(rep.Ticket.FullBytes, &tkt, ticketParam); err != nil {
		return nil, err
	}

	key, err := loadKey(enc.Key.Algorithm, enc.Key.Key, tkt.KeyVersion)
	if err != nil {
		return nil, err
	}

	// TODO use enc.Flags to mask out flags which the server refused
	return &Ticket{
		service:   enc.Service,
		srealm:    enc.ServiceRealm,
		ticket:    rep.Ticket.FullBytes,
		till:      enc.Till,
		renewTill: enc.RenewTill,
		flags:     r.flags,
		key:       key,
	}, nil
}

type Ticket struct {
	service   principalName
	srealm    string
	ticket    []byte
	till      time.Time
	renewTill time.Time
	flags     int
	key       cipher
	sock      net.Conn
	proto     string
}

func open(proto, realm string) (net.Conn, error) {
	if proto != "tcp" && proto != "udp" {
		panic("invalid protocol: " + proto)
	}

	_, addrs, err := net.LookupSRV("kerberos", proto, realm)

	if err != nil {
		_, addrs, err = net.LookupSRV("kerberos-master", proto, realm)
		if err != nil {
			return nil, err
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
		return nil, err
	}

	if proto == "udp" {
		// For datagram connections, we retry up to three times, then give up
		sock.SetReadTimeout(udpReadTimeout)
	}

	return sock, nil
}

type timeoutError interface {
	Timeout() bool
}

func (r *request) do() (tkt *Ticket, err error) {
	r.nonce = 0

	if r.proto == "" {
		r.proto = "udp"
	}

	// Limit the number of retries before we give up and error out with
	// the last error
	for i := 0; i < 3; i++ {
		if r.sock == nil {
			if r.sock, err = open(r.proto, r.srealm); err != nil {
				break
			}
		}

		if r.nonce == 0 {
			// Reduce the entropy of the nonce to 31 bits to ensure it fits in a 4
			// byte asn.1 value. Active directory seems to need this.
			if err = binary.Read(rand.Reader, binary.BigEndian, &r.nonce); err != nil {
				return nil, err
			}
			r.nonce >>= 1
			r.time = time.Now()
			r.seqnum = nextSequenceNumber()
		}

		// TODO what error do we get if the tcp socket has been closed underneath us
		err = r.sendRequest()

		if r.proto == "udp" && err == io.ErrShortWrite {
			r.nonce = 0
			r.proto = "tcp"
			r.sock.Close()
			r.sock = nil
			continue
		} else if err != nil {
			break
		}

		tkt, err = r.recvReply()

		if err == nil {
			return tkt, nil

		} else if e, ok := err.(RemoteError); r.proto == "udp" && ok && e.ErrorCode() == KRB_ERR_RESPONSE_TOO_BIG {
			r.nonce = 0
			r.proto = "tcp"
			r.sock.Close()
			r.sock = nil
			continue

		} else if e, ok := err.(timeoutError); r.proto == "udp" && ok && e.Timeout() {
			// Try again for UDP timeouts.  Reuse nonce, time, and
			// seqnum values so if the multiple requests end up at
			// the server, the server will ignore the retries as
			// replays.
			continue

		} else {
			break
		}
	}

	// Reset the socket if we got some error (even if we could reuse the
	// socket in some cases) so that next time we start with a clean
	// slate.
	r.proto = ""

	if r.sock != nil {
		r.sock.Close()
		r.sock = nil
	}

	return nil, err
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
	key       cipher
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
	key, err := loadKey(rc4HmacAlgorithm, rc4HmacKey(password), 0)
	if err != nil {
		panic(err)
	}

	return &Credential{
		key:       key,
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
		ckey:    c.key,
		flags:   defaultLoginFlags,
		till:    time.Now().Add(defaultLoginDuration),
		crealm:  c.realm,
		srealm:  c.realm,
		client:  c.principal,
		service: principalName{serviceNameType, []string{"krbtgt", c.realm}},
	}

	tgt, err := r.do()
	if err != nil {
		return nil, "", err
	}

	// Save the socket for reuse with TGS requests
	tgt.sock = r.sock
	tgt.proto = r.proto
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
			proto:   tgt.proto,
			sock:    tgt.sock,
		}

		tkt, err := r.do()
		if err != nil {
			return nil, err
		}

		// r.do() may have closed and opened a new socket
		tgt.proto = r.proto
		tgt.sock = r.sock

		tktserv := composePrincipal(tkt.service)
		c.cache[tktserv] = tkt

		// Did we get the service we wanted
		if service == tktserv {
			return tkt, nil
		}

		// If we got a different service, then we may have a ticket to
		// a next hop ticket granting service.
		if s := tkt.service; s.Type == serviceNameType && len(s.Parts) == 2 && s.Parts[0] == "krbtgt" {
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

		keydata := make([]byte, keysize)
		size -= int32(keysize)
		if _, err = io.ReadFull(file, keydata); err != nil {
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

		var key cipher
		if key, err = loadKey(int(keytype), keydata, keyversion); err != nil {
			return
		}

		cred := &Credential{
			key:       key,
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
