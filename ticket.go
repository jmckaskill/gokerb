package kerb

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

func initSequenceNumber() (ret uint32) {
	buf := mustRead(rand.Reader, make([]byte, 4))
	return binary.BigEndian.Uint32(buf)
}

var usSequenceNumber uint32 = initSequenceNumber()

func nextSequenceNumber() uint32 {
	return atomic.AddUint32(&usSequenceNumber, 1)
}

type request struct {
	dial    func(proto, realm string) (net.Conn, error)
	client  principalName
	crealm  string
	ckey    key // only needed for AS requests when tgt == nil
	ckvno   int
	service principalName
	srealm  string
	till    time.Time
	flags   int
	tgt     *Ticket
	salt    []byte

	// Setup by request.do()
	nonce  uint32
	time   time.Time
	seqnum uint32
	sock   net.Conn
	proto  string
	subkey key
}

var notill = asn1.RawValue{
	Bytes: []byte("19700101000000Z"),
	Class: 0,
	Tag:   24,
}

// sendRequest sends a single ticket request down the sock writer. If r.tgt is
// set this is a ticket granting service request, otherwise its an
// authentication service request. Note this does not use any random data, so
// resending will generate the exact same byte stream. This is needed with UDP
// connections such that if the remote receives multiple retries it discards
// the latters as replays.
func (r *request) sendRequest() (err error) {
	defer recoverMust(&err)

	body := kdcRequestBody{
		Client:       r.client,
		ServiceRealm: r.srealm,
		Service:      r.service,
		Flags:        flagsToBitString(r.flags),
		Till:         notill,
		Nonce:        r.nonce,
		Algorithms:   supportedAlgorithms,
	}

	if (r.till != time.Time{}) {
		body.Till.FullBytes = mustMarshal(r.till, "generalized")
	}

	bodydata := mustMarshal(body, "")

	reqparam := ""
	req := kdcRequest{
		ProtoVersion: kerberosVersion,
		Body:         asn1.RawValue{FullBytes: bodydata},
		// MsgType and Preauth filled out below
	}

	if r.tgt != nil {
		// For TGS requests we stash an AP_REQ for the ticket granting
		// service (using the krbtgt) as a preauth.
		reqparam = tgsRequestParam
		req.MsgType = tgsRequestType

		calgo := r.tgt.key.SignAlgo(paTgsRequestChecksumKey)
		chk := mustSign(r.tgt.key, calgo, paTgsRequestChecksumKey, bodydata)

		auth := authenticator{
			ProtoVersion:   kerberosVersion,
			ClientRealm:    r.crealm,
			Client:         r.client,
			Microseconds:   r.time.Nanosecond() / 1000,
			SequenceNumber: r.seqnum,
			Time:           time.Unix(r.time.Unix(), 0).UTC(), // round to the nearest second
			Checksum:       checksumData{calgo, chk},
			SubKey: encryptionKey{
				Algo: r.subkey.EncryptAlgo(tgsReplySubKey),
				Key:  r.subkey.Key(),
			},
		}

		authdata := mustMarshal(auth, authenticatorParam)
		app := appRequest{
			ProtoVersion: kerberosVersion,
			MsgType:      appRequestType,
			Flags:        flagsToBitString(0),
			Ticket:       asn1.RawValue{FullBytes: r.tgt.ticket},
			Authenticator: encryptedData{
				Algo: r.tgt.key.EncryptAlgo(paTgsRequestKey),
				Data: r.tgt.key.Encrypt(nil, paTgsRequestKey, authdata),
			},
		}

		appdata := mustMarshal(app, appRequestParam)
		req.Preauth = []preauth{{paTgsRequest, appdata}}

	} else {
		reqparam = asRequestParam
		req.MsgType = asRequestType

		// For AS requests we add a PA-ENC-TIMESTAMP preauth if we
		// have a key spefied. We won't on the first request so that
		// we can get a preauth error with the salt to use.
		if r.ckey != nil {
			// Use the sequence number as the microseconds in the
			// timestamp so that each one is guarenteed to be unique
			tsdata := mustMarshal(encryptedTimestamp{r.time, int(r.seqnum % 1000000)}, "")

			algo := r.ckey.EncryptAlgo(paEncryptedTimestampKey)
			edata := r.ckey.Encrypt(r.salt, paEncryptedTimestampKey, tsdata)
			enc := mustMarshal(encryptedData{algo, r.ckvno, edata}, "")

			req.Preauth = []preauth{{paEncryptedTimestamp, enc}}
		}
	}

	data := mustMarshal(req, reqparam)

	if r.proto == "tcp" {
		var bsz [4]byte
		binary.BigEndian.PutUint32(bsz[:], uint32(len(data)))
		mustWrite(r.sock, bsz[:])
	}

	if r.proto == "udp" && len(data) > maxUDPWrite {
		panic(io.ErrShortWrite)
	}

	mustWrite(r.sock, data)
	return nil
}

func (r *request) recvReply() (tkt *Ticket, err error) {
	defer recoverMust(&err)

	var data []byte

	switch r.proto {
	case "tcp":
		// TCP streams prepend a 32bit big endian size before each PDU
		bsz := [4]byte{}
		mustReadFull(r.sock, bsz[:])

		size := int(binary.BigEndian.Uint32(bsz[:]))
		must(0 <= size && size <= maxPDUSize)

		data = make([]byte, size)
		mustReadFull(r.sock, data)

	case "udp":
		// UDP PDUs are packed in individual frames
		data = make([]byte, maxPDUSize)
		data = mustRead(r.sock, data)

	default:
		panic(ErrInvalidProto(r.proto))
	}

	must(len(data) > 0)

	if (data[0] & 0x1F) == errorType {
		errmsg := errorMessage{}
		mustUnmarshal(data, &errmsg, errorParam)
		return nil, ErrRemote{&errmsg}
	}

	var msgtype, usage int
	var repparam, encparam string
	var key key

	if r.tgt != nil {
		repparam = tgsReplyParam
		msgtype = tgsReplyType
		key = r.subkey
		usage = tgsReplySubKey
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
	mustUnmarshal(data, &rep, repparam)
	must(rep.ProtoVersion == kerberosVersion && rep.MsgType == msgtype)
	must(rep.ClientRealm == r.crealm && nameEquals(rep.Client, r.client))

	// TGS doesn't use key versions as its using session keys
	if r.tgt == nil {
		// If we created the key from a keytab then we know the
		// version number, if we created it from plaintext then we use
		// the reply to find the key version

		if r.ckvno == 0 {
			r.ckvno = rep.Encrypted.KeyVersion
		} else {
			must(r.ckvno == rep.Encrypted.KeyVersion)
		}
	}

	// Decode encrypted part
	enc := encryptedKdcReply{}
	edata := rep.Encrypted.Data
	if key != nil {
		edata = mustDecrypt(key, nil, rep.Encrypted.Algo, usage, rep.Encrypted.Data)
	}
	mustUnmarshal(edata, &enc, encparam)

	// The returned service may be different from the request. This
	// happens when we get a tgt of the next server to try.
	must(enc.Nonce == r.nonce && enc.ServiceRealm == r.srealm)
	key = mustLoadKey(enc.Key.Algo, enc.Key.Key)

	return &Ticket{
		client:    r.client,
		crealm:    r.crealm,
		service:   enc.Service,
		srealm:    enc.ServiceRealm,
		ticket:    rep.Ticket.FullBytes,
		till:      enc.Till,
		renewTill: enc.RenewTill,
		authTime:  enc.AuthTime,
		startTime: enc.From,
		flags:     bitStringToFlags(enc.Flags),
		key:       key,
	}, nil
}

type Ticket struct {
	client    principalName
	crealm    string
	service   principalName
	srealm    string
	ticket    []byte
	till      time.Time
	renewTill time.Time
	authTime  time.Time
	startTime time.Time
	flags     int
	key       key
}

func DefaultDial(proto, realm string) (net.Conn, error) {
	if proto != "tcp" && proto != "udp" {
		return nil, ErrInvalidProto(proto)
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

// do performs an AS_REQ (r.ckey != nil) or TGS_REQ (r.tgt != nil) returning a
// new ticket
func (r *request) do() (tkt *Ticket, err error) {
	r.proto = "udp"
	r.sock = nil
	r.nonce = 0

	if r.dial == nil {
		r.dial = DefaultDial
	}

	// Limit the number of retries before we give up and error out with
	// the last error
	for i := 0; i < 3; i++ {
		if r.sock == nil {
			if r.sock, err = r.dial(r.proto, r.srealm); err != nil {
				break
			}
		}

		if r.nonce == 0 {
			// Reduce the entropy of the nonce to 31 bits to ensure it fits in a 4
			// byte asn.1 value. Active directory seems to need this.
			if err = binary.Read(rand.Reader, binary.BigEndian, &r.nonce); err != nil {
				break
			}
			r.nonce >>= 1
			r.time = time.Now().UTC()
			r.seqnum = nextSequenceNumber()
			if r.tgt != nil {
				r.subkey = mustGenerateKey(r.tgt.key.EncryptAlgo(tgsReplySubKey), rand.Reader)
			}
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
			break

		} else if e, ok := err.(ErrRemote); r.proto == "udp" && ok && e.ErrorCode() == KRB_ERR_RESPONSE_TOO_BIG {
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

	if r.sock != nil {
		r.sock.Close()
		r.sock = nil
	}

	return tkt, err
}

// Principal returns the principal of the service the ticket is for
func (t *Ticket) Principal() string {
	return composePrincipal(t.service)
}

// Realm returns the realm of the service the ticket is for
func (t *Ticket) Realm() string {
	return t.srealm
}

// ExpiryTime returns the time at which the ticket expires
func (t *Ticket) ExpiryTime() time.Time {
	return t.till
}
