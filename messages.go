package kerb

import (
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"time"
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
	serviceInstanceType
	serviceHostType
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
	gssFakeChecksum  = 0x8003
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
	privKey
	credKey
	safeChecksumKey
	_
	_
	_
	_
	_
	_
	_
	gssWrapSeal
	gssWrapSign

	gssSequenceNumber = -1
)

const (
	kerberosVersion      = 5
	applicationClass     = 0x40
	udpReadTimeout       = 3e9
	defaultLoginDuration = time.Hour * 24
	maxUDPWrite          = 1400 // TODO: figure out better way of doing this
	maxGSSWrapRead       = 64 * 1024 // TODO: remove this as a limitation
	maxPDUSize           = 4 * 1024
)

var (
	ErrParse               = errors.New("kerb: parse error")
	ErrProtocol            = errors.New("kerb: protocol error")
	ErrAuthLoop            = errors.New("kerb: auth loop")
	ErrPassword            = errors.New("kerb: can't renew the main krbtgt ticket as the password is unknown")
	ErrNoAvailableSecurity = errors.New("kerb: no available SASL security mode")

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

	negTokenInitParam  = "explicit,tag:0"
	negTokenReplyParam = "explicit,tag:1"

	gssKrb5Oid    = asn1.ObjectIdentifier([]int{1, 2, 840, 113554, 1, 2, 2})
	gssOldKrb5Oid = asn1.ObjectIdentifier([]int{1, 3, 5, 1, 5, 2})
	gssMsKrb5Oid  = asn1.ObjectIdentifier([]int{1, 2, 840, 48018, 1, 2, 2})
	gssSpnegoOid  = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 5, 5, 2})
)

type ErrInvalidProto string

func (s ErrInvalidProto) Error() string {
	return "kerb: invalid protocol - " + string(s)
}

type ErrTicket struct {
	reason string
}

func (s ErrTicket) Error() string {
	return "kerb: invalid ticket - " + s.reason
}

// Flags for tkt.Connect and tkt.Accept
const (
	MutualAuth = 1 << iota
	SASLAuth
	NoConfidentiality
	NoSecurity
	RequireConfidentiality
	RequireIntegrity
)

const (
	// default of negTokenReply.State so it appears when State is not set
	// in the asn1 marshalled stream
	spnegoUseContext = iota - 1
	spnegoAccepted
	spnegoIncomplete
	spnegoReject
	spnegoRequestMIC
)

// gss token types
const (
	// From RFC1964
	gssAppRequest    = 0x0100
	gssGetMIC        = 0x0101
	gssDeleteContext = 0x0102
	gssAppReply      = 0x0200
	gssWrap          = 0x0201
	gssAppError      = 0x0300
)

// App request flags
const (
	useSessionKey = 1 << 30
	mutualAuth    = 1 << 29
)

// gss app request flags - found in the gss fake checksum in the AP-REQ
// authenticator
const (
	gssDelegation = 1 << iota
	gssMutual
	gssReplay
	gssSequence
	gssConfidential
	gssIntegrity
	gssAnonymous
	gssProtectionReady
	gssTransferable
)

// gss sasl flags - first byte of the 4 bytes gss wrap exchange after the AP-REQ
const (
	saslNoSecurity = 1 << iota
	saslIntegrity
	saslConfidential
)

// gss wrap encryption and checksum types
const (
	gssSealDES  = 0x0000
	gssSealRC4  = 0x1000
	gssSealNone = 0xFFFF

	gssSignDES_MAC_MD5 = 0x0000
	gssSignMD2_5       = 0x0100
	gssSignDES_MAC     = 0x0200
	gssSignHMAC_MD5    = 0x1100
)

type principalName struct {
	Type  int      `asn1:"explicit,tag:0"`
	Parts []string `asn1:"general,explicit,tag:1"`
}

type encryptedData struct {
	Algo       int    `asn1:"explicit,tag:0"`
	KeyVersion int    `asn1:"optional,explicit,tag:1"`
	Data       []byte `asn1:"explicit,tag:2"`
}

type encryptionKey struct {
	Algo int    `asn1:"explicit,tag:0"`
	Key  []byte `asn1:"explicit,tag:1"`
}

type ticket struct {
	ProtoVersion int           `asn1:"explicit,tag:0"`
	Realm        string        `asn1:"general,explicit,tag:1"`
	Service      principalName `asn1:"explicit,tag:2"`
	Encrypted    encryptedData `asn1:"explicit,tag:3"`
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
	Algo int    `asn1:"explicit,tag:0"`
	Data []byte `asn1:"explicit,tag:1"`
}

type encryptedTimestamp struct {
	Time         time.Time `asn1:"generalized,explicit,tag:0"`
	Microseconds int       `asn1:"optional,explicit,tag:1"`
}

type encryptedTicket struct {
	Flags        asn1.BitString    `asn1:"explicit,tag:0"`
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
	ClientTime         time.Time     `asn1:"generalized,explicit,tag:0"`
	ClientMicroseconds int           `asn1:"explicit,tag:1"`
	SubKey             encryptionKey `asn1:"optional,explicit,tag:2"`
	SequenceNumber     uint32        `asn1:"optional,explicit,tag:3"`
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

type negTokenInit struct {
	Mechanisms []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	Token      []byte                  `asn1:"explicit,tag:1"`
}

type negTokenReply struct {
	State     int                   `asn1:"optional,explicit,tag:0,default:-1"`
	Mechanism asn1.ObjectIdentifier `asn1:"optional,explicit,tag:1"`
	Response  []byte                `asn1:"optional,explicit,tag:2"`
}

func nameEquals(a, b principalName) bool {
	// Note two principals with different types but the same components
	// are considered equivalent
	if len(a.Parts) != len(b.Parts) {
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
	// Per the RFC: When a name implies no information other than its
	// uniqueness at a particular time, the name type PRINCIPAL SHOULD be
	// used.
	r.Type = principalNameType
	r.Parts = strings.Split(p, "/")
	return
}

// composePrincipal converts the on wire principal format to a composed
// string.
func composePrincipal(n principalName) string {
	return strings.Join(n.Parts, "/")
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

func must(cond bool) {
	if !cond {
		errpanic(ErrProtocol)
	}
}

func mustMarshal(val interface{}, params string) []byte {
	data, err := asn1.MarshalWithParams(val, params)
	if err != nil {
		errpanic(err)
	}
	return data
}

func mustUnmarshal(data []byte, val interface{}, params string) {
	left, err := asn1.UnmarshalWithParams(data, val, params)
	if err != nil {
		errpanic(err)
	}
	if len(left) > 0 {
		errpanic(ErrProtocol)
	}
}

func mustRead(r io.Reader, buf []byte) []byte {
	n, err := r.Read(buf)
	if err != nil {
		errpanic(err)
	}
	return buf[:n]
}

func mustReadFull(r io.Reader, buf []byte) {
	if _, err := io.ReadFull(r, buf); err != nil {
		errpanic(err)
	}
}

func mustWrite(w io.Writer, buf []byte) {
	if _, err := w.Write(buf); err != nil {
		errpanic(err)
	}
}

func errpanic(err error) {
	panic(err)
}

func recoverMust(perr *error) {
	v := recover()
	if v == nil {
		return
	}

	err, ok := v.(error)
	if !ok {
		panic(v)
	}

	*perr = err
}

