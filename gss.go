package kerb

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"time"
)

// GSS requests are a bit screwy in that they are partially asn1 The format
// is:
//
// [APPLICATION 0] IMPLICIT SEQUENCE {
//	mech OBJECT IDENTIFIER
//	data of unknown type and may not be asn1
// }
//
// To decode this we manually unpack the outer header, run the mech through
// the asn1 unmarshaller and then return the rest of the data.

type gssRequest struct {
	Mechanism asn1.ObjectIdentifier
	Data      asn1.RawValue
}

var gssRequestParam = "application,tag:0"

func encodeGSSWrapper(oid asn1.ObjectIdentifier, data []byte) ([]byte, error) {
	req := gssRequest{
		Mechanism: oid,
		Data:      asn1.RawValue{FullBytes: data},
	}

	return asn1.MarshalWithParams(req, gssRequestParam)
}

func decodeGSSWrapper(data []byte) (oid asn1.ObjectIdentifier, idata []byte, err error) {
	if len(data) < 2 {
		err = ErrParse
		return
	}

	// GSS wrappers are optional, if they are not supplied we assume the data is KRB5
	if data[0] != 0x60 {
		return gssKrb5Oid, data, nil
	}

	isz := int(data[1])
	data = data[2:]

	// Note for the long forms, the data len must be >= 0x80 anyways
	if isz > len(data) {
		err = ErrParse
		return
	}

	switch {
	case isz == 0x84:
		isz = int(data[0])<<24 + int(data[1])<<16 + int(data[2])<<8 + int(data[3])
		data = data[4:]

	case isz == 0x83:
		isz = int(data[0])<<16 + int(data[1])<<8 + int(data[2])
		data = data[3:]

	case isz == 0x82:
		isz = int(data[0])<<8 + int(data[1])
		data = data[2:]

	case isz == 0x81:
		isz = int(data[0])
		data = data[1:]

	case isz <= 0x7F:
		// short length form

	default:
		err = ErrParse
		return
	}

	if isz < 0 || isz > len(data) {
		err = ErrParse
		return
	}

	data = data[:isz]
	oid = asn1.ObjectIdentifier{}
	idata, err = asn1.Unmarshal(data, &oid)
	return
}

type replayKey struct {
	keyType        int
	key            string
	time           time.Time
	microseconds   int
	sequenceNumber uint32
}

func (t *Ticket) Connect(rw io.ReadWriter, flags int) (io.ReadWriter, error) {
	appflags := 0
	gssflags := 0

	if (flags & MutualAuth) != 0 {
		appflags |= mutualAuth
		gssflags |= gssMutual
	}

	if (flags & SASLAuth) != 0 {
		// SASL auth requires the AP_REP always
		appflags |= mutualAuth
		gssflags |= gssMutual
		// gssWrapper handles out of order messages but does not keep
		// a replay list
		gssflags |= gssSequence
	}

	if (flags & NoConfidentiality) == 0 {
		gssflags |= gssConfidential
	}

	if (flags & NoIntegrity) == 0 {
		gssflags |= gssIntegrity
	}

	// See RFC4121 4.1.1 for the GSS fake auth checksum
	gsschk := [24]byte{}

	// 0..3 Lgth: Number of bytes in Bnd field; Currently contains hex 10
	// 00 00 00 (16, represented in little-endian form)
	binary.LittleEndian.PutUint32(gsschk[0:4], 16)

	// 4..19 Bnd: MD5 hash of channel bindings, taken over all non-null
	// components of bindings, in order of declaration. Integer fields
	// within channel bindings are represented in little-endian order for
	// the purposes of the MD5 calculation; Currently left as 0.

	// 20..23 Flags: Bit vector of context-establishment flags, with
	// values consistent with RFC-1509, p. 41. The resulting bit vector is
	// encoded into bytes 20..23 in little-endian form.
	binary.LittleEndian.PutUint32(gsschk[20:24], uint32(gssflags))

	// 24..25 DlgOpt The Delegation Option identifier (=1) [optional]
	// 26..27 Dlgth: The length of the Deleg field. [optional]
	// 28..(n-1) Deleg: A KRB_CRED message (n = Dlgth + 28) [optional]
	// n..last Exts: Extensions [optional].

	subkey, err := generateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	auth := authenticator{
		ProtoVersion:   kerberosVersion,
		ClientRealm:    t.crealm,
		Client:         t.client,
		SequenceNumber: nextSequenceNumber(),
		Time:           time.Unix(now.Unix(), 0), // round to the nearest second
		Microseconds:   now.Nanosecond() / 1000,
		Checksum:       checksumData{gssFakeChecksum, gsschk[:]},
		SubKey: encryptionKey{
			Algo: subkey.EncryptAlgo(appRequestAuthKey),
			Key:  subkey.Key(),
		},
	}

	fmt.Printf("APP_REQUEST auth %+v\n\n", auth)

	authdata, err := asn1.MarshalWithParams(auth, authenticatorParam)
	if err != nil {
		return nil, err
	}

	req := appRequest{
		ProtoVersion: kerberosVersion,
		MsgType:      appRequestType,
		Flags:        flagsToBitString(appflags),
		Ticket:       asn1.RawValue{FullBytes: t.ticket},
		Authenticator: encryptedData{
			Algo: t.key.EncryptAlgo(appRequestAuthKey),
			Data: t.key.Encrypt(authdata, nil, appRequestAuthKey),
		},
	}

	reqdata, err := asn1.MarshalWithParams(req, appRequestParam)
	if err != nil {
		return nil, err
	}

	reqdata = append([]byte{(gssAppRequest >> 8) & 0xFF, gssAppRequest & 0xFF}, reqdata...)
	gssdata, err := encodeGSSWrapper(gssKrb5Oid, reqdata)
	if err != nil {
		return nil, err
	}

	if _, err := rw.Write(gssdata); err != nil {
		return nil, err
	}

	// Now get the reply

	if (appflags & mutualAuth) == 0 {
		return nil, nil
	}

	brep := [4096]byte{}
	n, err := rw.Read(brep[:])
	if err != nil {
		return nil, err
	}

	oid, repdata, err := decodeGSSWrapper(brep[:n])
	if err != nil {
		return nil, err
	}

	if !oid.Equal(gssKrb5Oid) || len(repdata) < 2 {
		return nil, ErrProtocol
	}

	gsstype := binary.BigEndian.Uint16(repdata[:2])

	switch gsstype {
	case gssAppError:
		errmsg := errorMessage{}
		if _, err := asn1.UnmarshalWithParams(repdata[2:], &errmsg, errorParam); err != nil {
			return nil, err
		}
		return nil, RemoteError{&errmsg}

	case gssAppReply:
		// continue below
	default:
		return nil, ErrProtocol
	}

	rep := appReply{}
	if _, err := asn1.UnmarshalWithParams(repdata[2:], &rep, appReplyParam); err != nil {
		return nil, err
	}

	fmt.Printf("APP_REPLY %+v\n\n", rep)
	if rep.ProtoVersion != kerberosVersion || rep.MsgType != appReplyType {
		return nil, ErrProtocol
	}

	edata, err := t.key.Decrypt(rep.Encrypted.Data, nil, rep.Encrypted.Algo, appReplyEncryptedKey)
	if err != nil {
		return nil, err
	}

	erep := encryptedAppReply{}
	if _, err := asn1.UnmarshalWithParams(edata, &erep, encAppReplyParam); err != nil {
		return nil, err
	}

	fmt.Printf("APP_REPLY enc %+v\n\n", erep)
	if !erep.ClientTime.Equal(auth.Time) || erep.ClientMicroseconds != auth.Microseconds {
		return nil, ErrProtocol
	}

	// Now non-SASL requests eg HTTP negotiate are finished.
	if (flags & SASLAuth) == 0 {
		return nil, nil
	}

	key := t.key
	if erep.SubKey.Algo != 0 {
		fmt.Printf("prevkey %d %x\n", key.EncryptAlgo(appReplyEncryptedKey), key.Key())
		fmt.Printf("subkey %d %x\n", erep.SubKey.Algo, erep.SubKey.Key)
		key, err = loadKey(erep.SubKey.Algo, erep.SubKey.Key)
		if err != nil {
			panic(err)
			return nil, err
		}
	}

	// SASL requests on the otherhand GSS_wrap all messages from now on.
	// We return a read writer for the user to be able to do this. However
	// we first exchange an intial gss_wrap exchange where we each
	// specific the sasl flags as well as the max wrap size. The server
	// starts this exchange. Both of these intial messages are not encrypted.

	g := gssWrapper{
		// add some extra room for GSS_wrap header and GSS fake ASN1 wrapper
		rxbuf:    make([]byte, maxGSSWrapRead+64),
		rxseqnum: erep.SequenceNumber,
		txseqnum: auth.SequenceNumber,
		checkseq: (gssflags & gssSequence) != 0,
		key:      key,
		client:   true,
		conf:     false,
		rw:       rw,
	}

	if n, err := g.Read(brep[:]); err != nil {
		panic(err)
		return nil, err
	} else if n != 4 {
		panic(ErrProtocol)
		return nil, ErrProtocol
	}

	availsec := int(brep[0])
	g.maxtxsize = int(binary.BigEndian.Uint32(brep[:4]) & 0xFFFFFF)

	sec := chooseGSSSecurity(availsec, flags)
	if sec == 0 {
		panic(ErrProtocol)
		return nil, ErrProtocol
	}

	grep := [4]byte{}
	binary.BigEndian.PutUint32(grep[:], maxGSSWrapRead)
	grep[0] = byte(sec)

	if _, err := g.Write(grep[:]); err != nil {
		panic(err)
		return nil, err
	}

	if sec == saslNoSecurity {
		return nil, nil
	}

	g.conf = (sec == saslConfidential)
	return &g, nil
}

type gssWrapper struct {
	rxbuf              []byte
	rxseqnum, txseqnum uint32
	checkseq           bool
	maxtxsize          int
	key                cipher
	client, conf       bool
	rw                 io.ReadWriter
}

func (s *gssWrapper) Read(b []byte) (int, error) {
	n, err := s.rw.Read(s.rxbuf)
	if err != nil {
		panic(err)
		return 0, err
	}

	seqnum, gdata, err := gss_unwrap(s.rxbuf[:n], s.key, s.client, s.conf)
	if err != nil {
		panic(err)
		return 0, err
	}

	if s.checkseq && seqnum != s.rxseqnum {
		return 0, ErrProtocol
	}

	s.rxseqnum++

	return copy(b, gdata), nil
}

func (s *gssWrapper) Write(b []byte) (int, error) {
	for n := 0; n < len(b); n += s.maxtxsize {
		d := b[n:]
		if len(d) > s.maxtxsize {
			d = d[:s.maxtxsize]
		}

		gdata, err := gss_wrap(s.txseqnum, d, s.key, s.client, s.conf)
		s.txseqnum++
		if err != nil {
			return n, err
		}

		_, err = s.rw.Write(gdata)
		if err != nil {
			return n, err
		}
	}

	return len(b), nil
}

func chooseGSSSecurity(avail, flags int) int {
	rconf := (flags & RequireConfidentiality) != 0
	rint := (flags & RequireIntegrity) != 0
	tconf := (flags & NoConfidentiality) == 0
	tint := (flags & NoIntegrity) == 0

	aconf := (avail & saslConfidential) != 0
	aint := (avail & saslIntegrity) != 0
	anone := (avail & saslNoSecurity) != 0

	if (rconf || tconf) && aconf {
		return saslConfidential
	} else if rconf {
		return 0
	}

	if (rint || tint) && aint {
		return saslIntegrity
	} else if rint {
		return 0
	}

	if anone {
		return saslNoSecurity
	}

	return 0
}

// See RFC1964 1.2.2
func gss_unwrap(gdata []byte, key cipher, client, conf bool) (seqnum uint32, data []byte, err error) {
	if len(gdata) < 2 {
		panic(ErrProtocol)
		return 0, nil, ErrProtocol
	}

	oid, idata, err := decodeGSSWrapper(gdata)
	if err != nil {
		panic(err)
		return 0, nil, err
	}

	if !oid.Equal(gssKrb5Oid) || len(idata) < 32 {
		panic(ErrProtocol)
		return 0, nil, ErrProtocol
	}

	tok := int(binary.BigEndian.Uint16(idata[0:2]))
	signalg := int(binary.BigEndian.Uint16(idata[2:4]))
	sealalg := int(binary.BigEndian.Uint16(idata[4:6]))
	// filler for 6:8
	seqdata := idata[8:16]
	chk := idata[16:24]
	data = idata[24:]

	if tok != gssWrap {
		panic(ErrProtocol)
		return 0, nil, ErrProtocol
	}

	if (sealalg != gssSealNone) != conf {
		panic(ErrProtocol)
		return 0, nil, ErrProtocol
	}

	// checksum salt
	seqdata, err = key.Decrypt(seqdata, chk, sealalg, gssSequenceNumber)
	if err != nil {
		panic(err)
		return 0, nil, err
	}
	fmt.Printf("gss_unwrap %x\n", idata)

	if conf {
		// sequence number salt
		if client {
			data, err = key.Decrypt(data, seqdata[:4], sealalg, gssAcceptorSeal)
		} else {
			data, err = key.Decrypt(data, seqdata[:4], sealalg, gssInitiatorSeal)
		}

		if err != nil {
			panic(err)
			return 0, nil, err
		}
	}

	var chk2 []byte
	if client {
		chk2, err = key.Sign([][]byte{idata[:8], data}, signalg, gssAcceptorSign)
	} else {
		chk2, err = key.Sign([][]byte{idata[:8], data}, signalg, gssInitiatorSign)
	}

	if err != nil {
		panic(err)
		return 0, nil, err
	}

	fmt.Printf("gss_unwrap checksum %x %x\n", chk2, chk)
	if subtle.ConstantTimeCompare(chk, chk2[:8]) != 1 {
		panic(ErrProtocol)
		return 0, nil, ErrProtocol
	}

	dir := binary.BigEndian.Uint32(seqdata[4:8])
	fmt.Printf("gss_unwrap dir %v %x\n", client, dir)
	if (client && dir != 0xFFFFFFFF) || (!client && dir != 0) {
		panic(ErrProtocol)
		return 0, nil, ErrProtocol
	}

	// The first 8 bytes of the data is the confounder.
	// The trailing [1:8] pad bytes all have the padding size as the value
	padsz := int(data[len(data)-1])
	if 8+padsz > len(data) {
		panic(ErrProtocol)
		return 0, nil, ErrProtocol
	}

	return binary.BigEndian.Uint32(seqdata), data[8 : len(data)-padsz], nil
}

// See RFC1964 1.2.2
func gss_wrap(seqnum uint32, data []byte, key cipher, client, conf bool) ([]byte, error) {
	signalgo := key.SignAlgo(gssAcceptorSign)
	sealalgo := key.EncryptAlgo(gssAcceptorSeal)

	if !conf {
		sealalgo = gssSealNone
	}

	d := make([]byte, 32)
	binary.BigEndian.PutUint16(d[0:2], gssWrap)
	binary.BigEndian.PutUint16(d[2:4], uint16(signalgo))
	binary.BigEndian.PutUint16(d[4:6], uint16(sealalgo))
	binary.BigEndian.PutUint16(d[6:8], 0xFFFF) // filler
	// 8:16 is encrypted sequence number
	// 16:24 is checksum below
	binary.BigEndian.PutUint32(d[8:12], seqnum)
	if client {
		binary.BigEndian.PutUint32(d[12:16], 0)
	} else {
		binary.BigEndian.PutUint32(d[12:16], 0xFFFFFFFF)
	}

	// 24:32 is the confounder
	if _, err := io.ReadFull(rand.Reader, d[24:32]); err != nil {
		return nil, err
	}

	d = append(d, data...)

	// 8 byte round padding must be at least one byte
	//padsz := ((len(d) + 8) &^ 7) - len(d)
	padsz := 1
	for i := 0; i < padsz; i++ {
		d = append(d, byte(padsz))
	}

	var chk []byte
	var err error

	if client {
		chk, err = key.Sign([][]byte{d[0:8], d[24:]}, signalgo, gssInitiatorSign)
	} else {
		chk, err = key.Sign([][]byte{d[0:8], d[24:]}, signalgo, gssAcceptorSign)
	}

	if err != nil {
		return nil, err
	}

	fmt.Printf("gss_wrap chksum %x\n", chk)

	copy(d[16:24], chk)

	fmt.Printf("gss_wrap data %x\n", d)

	if conf {
		// encrypt data using sequence number salt
		if client {
			copy(d[24:], key.Encrypt(d[24:], d[8:12], gssInitiatorSeal))
		} else {
			copy(d[24:], key.Encrypt(d[24:], d[8:12], gssAcceptorSeal))
		}
	}

	// encrypt seqnum using checksum salt
	copy(d[8:16], key.Encrypt(d[8:16], d[16:24], gssSequenceNumber))

	return encodeGSSWrapper(gssKrb5Oid, d)
}

func (c *Credential) isReplay(auth *authenticator, etkt *encryptedTicket) bool {
	now := time.Now()

	c.lk.Lock()
	defer c.lk.Unlock()

	rkey := replayKey{
		keyType:        etkt.Key.Algo,
		key:            string(etkt.Key.Key),
		time:           auth.Time,
		microseconds:   auth.Microseconds,
		sequenceNumber: auth.SequenceNumber,
	}

	if c.replay == nil {
		c.replay = make(map[replayKey]bool)
		c.lastReplayPurge = now
	}

	if _, ok := c.replay[rkey]; ok {
		return true
	}

	if now.Sub(c.lastReplayPurge) > time.Minute*10 {
		for rkey := range c.replay {
			if now.Sub(rkey.time) > time.Minute*10 {
				delete(c.replay, rkey)
			}
		}

		c.lastReplayPurge = now
	}

	c.replay[rkey] = true
	return false
}

func (c *Credential) Accept(rw io.ReadWriter, flags int) (gssrw io.ReadWriter, user, realm string, rerr error) {
	// TODO send error replies
	breq := [4096]byte{}
	n, err := rw.Read(breq[:])
	if err != nil {
		rerr = err
		return
	}

	oid, reqdata, err := decodeGSSWrapper(breq[:n])
	if err != nil {
		rerr = err
		return
	}

	spnego := oid.Equal(gssSpnegoOid)
	if spnego {
		neg := negTokenInit{}
		if _, err := asn1.UnmarshalWithParams(reqdata, &neg, negTokenInitParam); err != nil {
			rerr = err
			return
		}

		oid, reqdata, err = decodeGSSWrapper(neg.Token)
		if err != nil {
			rerr = err
			return
		}
	}

	if !oid.Equal(gssKrb5Oid) && !oid.Equal(gssMsKrb5Oid) {
		rerr = ErrProtocol
		return
	}

	if len(reqdata) < 2 || binary.BigEndian.Uint16(reqdata[:2]) != gssAppRequest {
		rerr = ErrProtocol
		return
	}

	req := appRequest{}
	if _, err := asn1.UnmarshalWithParams(reqdata[2:], &req, appRequestParam); err != nil {
		rerr = err
		return
	}

	if req.ProtoVersion != kerberosVersion || req.MsgType != appRequestType {
		rerr = ErrProtocol
		return
	}

	// Check the ticket

	tkt := ticket{}
	if _, err := asn1.UnmarshalWithParams(req.Ticket.FullBytes, &tkt, ticketParam); err != nil {
		rerr = err
		return
	}

	if tkt.ProtoVersion != kerberosVersion || tkt.Realm != c.realm || !nameEquals(tkt.Service, c.principal) {
		rerr = ErrInvalidTicket
		return
	}

	etktdata, err := c.key.Decrypt(tkt.Encrypted.Data, nil, tkt.Encrypted.Algo, ticketKey)
	if err != nil {
		rerr = err
		return
	}

	etkt := encryptedTicket{}
	if _, err := asn1.UnmarshalWithParams(etktdata, &etkt, encTicketParam); err != nil {
		rerr = err
		return
	}

	now := time.Now()
	if (etkt.From != time.Time{} && now.Before(etkt.From)) || now.After(etkt.Till) {
		rerr = ErrInvalidTicket
		return
	}

	tkey, err := loadKey(etkt.Key.Algo, etkt.Key.Key)
	if err != nil {
		rerr = err
		return
	}

	// Check the authenticator

	authdata, err := tkey.Decrypt(req.Authenticator.Data, nil, req.Authenticator.Algo, appRequestAuthKey)
	if err != nil {
		rerr = err
		return
	}

	auth := authenticator{}
	if _, err := asn1.UnmarshalWithParams(authdata, &auth, authenticatorParam); err != nil {
		rerr = err
		return
	}

	if auth.ProtoVersion != kerberosVersion || auth.ClientRealm != etkt.ClientRealm || !nameEquals(auth.Client, etkt.Client) {
		rerr = ErrProtocol
		return
	}

	if math.Abs(float64(now.Sub(auth.Time))) > float64(time.Minute*5) {
		rerr = ErrProtocol
		return
	}

	if auth.Checksum.Algo != gssFakeChecksum || len(auth.Checksum.Data) < 4 {
		rerr = ErrProtocol
		return
	}

	bndlen := int(binary.LittleEndian.Uint32(auth.Checksum.Data))
	if bndlen < 0 || bndlen + 8 > len(auth.Checksum.Data) {
		rerr = ErrProtocol
		return
	}
	gssflags := binary.LittleEndian.Uint32(auth.Checksum.Data[bndlen+4:])
	// TODO: handle forwarded credentials

	appflags := bitStringToFlags(req.Flags)
	if ((gssflags & gssMutual) != 0) != ((appflags & mutualAuth) != 0) {
		rerr = ErrProtocol
		return
	}

	// Now check for replays
	if c.isReplay(&auth, &etkt) {
		rerr = ErrProtocol
		return
	}

	user = composePrincipal(etkt.Client)
	realm = etkt.ClientRealm

	if (appflags & mutualAuth) == 0 {
		return
	}

	// Now send the reply

	erep := encryptedAppReply{
		ClientTime:         auth.Time,
		ClientMicroseconds: auth.Microseconds,
		SequenceNumber:     nextSequenceNumber(),
	}

	edata, err := asn1.MarshalWithParams(erep, encAppReplyParam)
	if err != nil {
		rerr = err
		return
	}

	rep := appReply{
		ProtoVersion: kerberosVersion,
		MsgType:      appReplyType,
		Encrypted: encryptedData{
			Algo: tkey.EncryptAlgo(appReplyEncryptedKey),
			Data: tkey.Encrypt(edata, nil, appReplyEncryptedKey),
		},
	}

	repdata, err := asn1.MarshalWithParams(rep, appReplyParam)
	if err != nil {
		rerr = err
		return
	}

	repdata = append([]byte{(gssAppReply >> 8) & 0xFF, gssAppReply & 0xFF}, repdata...)
	gssrep, err := encodeGSSWrapper(oid, repdata)
	if err != nil {
		rerr = err
		return
	}

	if spnego {
		srep := negTokenReply{
			State:     spnegoAccepted,
			Mechanism: oid,
			Response:  gssrep,
		}

		repdata, err := asn1.MarshalWithParams(srep, negTokenReplyParam)
		if err != nil {
			rerr = err
			return
		}

		gssrep, err = encodeGSSWrapper(gssSpnegoOid, repdata)
		if err != nil {
			rerr = err
			return
		}
	}

	if _, err := rw.Write(gssrep); err != nil {
		rerr = err
		return
	}

	// Non-SASL accepts eg HTTP negotiate are now finished
	if (flags & SASLAuth) == 0 {
		return
	}

	// We need to be able to do further handshakes
	if (gssflags & gssProtectionReady) == 0 {
		rerr = ErrProtocol
		return
	}

	// SASL accept continues on with sending a GSS_wrapped request from
	// the server to the client to negotiate the wrapping security mode.

	availsec := saslNoSecurity | saslIntegrity | saslConfidential

	// Remove modes we don't support
	if (flags & NoConfidentiality) != 0 {
		availsec &^= saslConfidential
	}
	if (flags & NoIntegrity) != 0 {
		availsec &^= saslIntegrity
	}

	// Remove modes where we require a higher level
	if (flags & RequireConfidentiality) != 0 {
		availsec &^= saslNoSecurity | saslIntegrity
	} else if (flags & RequireIntegrity) != 0 {
		availsec &^= saslNoSecurity
	}

	// Remove modes the client doesn't support
	if (gssflags & gssIntegrity) == 0 {
		availsec &^= saslIntegrity
	}
	if (gssflags & gssConfidential) == 0 {
		availsec &^= saslConfidential
	}

	if availsec == 0 {
		rerr = ErrNoAvailableSecurity
		return
	}

	g := gssWrapper{
		// add some extra room for GSS_wrap header and GSS fake ASN1 wrapper
		rxbuf:     make([]byte, maxGSSWrapRead+64),
		rxseqnum:  auth.SequenceNumber,
		txseqnum:  erep.SequenceNumber,
		checkseq:  (gssflags & gssSequence) != 0,
		maxtxsize: maxGSSWrapRead, // fill in properly later
		key:       tkey,
		client:    false,
		conf:      false,
		rw:        rw,
	}

	gd := [4]byte{}
	binary.BigEndian.PutUint32(gd[:], maxGSSWrapRead)
	gd[0] = byte(availsec)

	if _, err := g.Write(gd[:]); err != nil {
		rerr = err
		return
	}

	if n, err := g.Read(gd[:]); err != nil {
		rerr = err
		return
	} else if n != 4 {
		rerr = ErrProtocol
		return
	}

	g.maxtxsize = int(binary.BigEndian.Uint32(gd[:]) & 0xFFFFFF)

	switch gd[0] {
	case saslNoSecurity:
		return

	case saslIntegrity:
		gssrw = &g
		return

	case saslConfidential:
		g.conf = true
		gssrw = &g
		return
	}

	rerr = ErrProtocol
	return
}
