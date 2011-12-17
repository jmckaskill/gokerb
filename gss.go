package kerb

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
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

func encodeGssWrapper(oid asn1.ObjectIdentifier, data []byte) ([]byte, error) {
	req := gssRequest{
		Mechanism: oid,
		Data:      asn1.RawValue{FullBytes: data},
	}

	return asn1.MarshalWithParams(req, gssRequestParam)
}

func decodeGssWrapper(data []byte) (oid asn1.ObjectIdentifier, idata []byte, err error) {
	if len(data) < 2 || data[0] != 0x60 {
		err = ErrParse
		return
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
		isz = int(data[0]<<24) + int(data[1]<<16) + int(data[2]<<8) + int(data[3])
		data = data[4:]

	case isz == 0x83:
		isz = int(data[0]<<16) + int(data[1]<<8) + int(data[2])
		data = data[3:]

	case isz == 0x82:
		isz = int(data[0]<<8) + int(data[1])
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

func (t *Ticket) Connect(sock io.ReadWriter, flags int) error {
	gssflags := byte(0)
	if (flags & mutualRequired) != 0 {
		gssflags |= gssMutual
	}

	// See RFC4121 4.1.1
	gsschk := []byte{
		// 0..3 Lgth: Number of bytes in Bnd field; Currently contains
		// hex 10 00 00 00 (16, represented in little-endian form)
		0x10, 0, 0, 0,
		// 4..19 Bnd: MD5 hash of channel bindings, taken over all
		// non-null components of bindings, in order of declaration.
		// Integer fields within channel bindings are represented in
		// little-endian order for the purposes of the MD5
		// calculation.
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		// 20..23 Flags: Bit vector of context-establishment flags, with
		// values consistent with RFC-1509, p. 41. The resulting bit
		// vector is encoded into bytes 20..23 in little-endian form.
		gssflags, 0, 0, 0,
		// 24..25 DlgOpt The Delegation Option identifier (=1) [optional]
		// 26..27 Dlgth: The length of the Deleg field. [optional]
		// 28..(n-1) Deleg: A KRB_CRED message (n = Dlgth + 28) [optional]
		// n..last Exts: Extensions [optional].
	}

	auth := authenticator{
		ProtoVersion: kerberosVersion,
		ClientRealm:  t.crealm,
		Client:       t.client,
		Microseconds: nextSequenceNumber() % 1000000,
		Time:         time.Now(),
		Checksum:     checksumData{gssFakeChecksum, gsschk},
	}

	authdata, err := asn1.MarshalWithParams(auth, authenticatorParam)
	if err != nil {
		return err
	}

	req := appRequest{
		ProtoVersion:  kerberosVersion,
		MsgType:       appRequestType,
		Flags:         flagsToBitString(flags),
		Ticket:        asn1.RawValue{FullBytes: t.ticket},
		Authenticator: t.key.encrypt(authdata, appRequestAuthKey),
	}

	reqdata, err := asn1.MarshalWithParams(req, appRequestParam)
	if err != nil {
		return err
	}

	reqdata = append([]byte{byte(appRequestType >> 8), byte(appRequestType)}, reqdata...)
	gssdata, err := encodeGssWrapper(gssKrb5Oid, reqdata)
	if err != nil {
		return err
	}

	if _, err := sock.Write(gssdata); err != nil {
		return err
	}

	if (flags & mutualRequired) == 0 {
		return nil
	}

	// Now get the reply

	repbuf := bytes.NewBuffer(nil)
	if _, err := io.Copy(repbuf, sock); err != nil {
		return err
	}

	oid, repdata, err := decodeGssWrapper(repbuf.Bytes())
	if err != nil {
		return err
	}

	if !oid.Equal(gssKrb5Oid) || len(repdata) < 2 || binary.BigEndian.Uint16(repdata[:2]) != appReplyType {
		return ErrProtocol
	}

	rep := appReply{}
	if _, err := asn1.UnmarshalWithParams(repdata[2:], &rep, appReplyParam); err != nil {
		return err
	}

	if rep.ProtoVersion != kerberosVersion || rep.MsgType != appReplyType {
		return ErrProtocol
	}

	edata, err := t.key.decrypt(rep.Encrypted, appReplyEncryptedKey)
	if err != nil {
		return err
	}

	erep := encryptedAppReply{}
	if _, err := asn1.UnmarshalWithParams(edata, &erep, encAppReplyParam); err != nil {
		return err
	}

	if !erep.ClientTime.Equal(auth.Time) || erep.ClientMicroseconds != auth.Microseconds || erep.SequenceNumber != auth.SequenceNumber {
		return ErrProtocol
	}

	return nil
}

func (c *Credential) Accept(rw io.ReadWriter) error {
	// TODO send error replies
	reqbuf := bytes.NewBuffer(nil)
	if _, err := io.Copy(reqbuf, rw); err != nil {
		return err
	}

	oid, reqdata, err := decodeGssWrapper(reqbuf.Bytes())
	if err != nil {
		return err
	}

	spnego := oid.Equal(gssSpnegoOid)
	if spnego {
		neg := negTokenInit{}
		if _, err := asn1.UnmarshalWithParams(reqdata, &neg, negTokenInitParam); err != nil {
			return err
		}

		oid, reqdata, err = decodeGssWrapper(neg.Token)
		if err != nil {
			return err
		}
	}

	if !oid.Equal(gssKrb5Oid) && !oid.Equal(gssMsKrb5Oid) {
		return ErrProtocol
	}

	req := appRequest{}
	if _, err := asn1.UnmarshalWithParams(reqdata, &req, appRequestParam); err != nil {
		return err
	}

	if req.ProtoVersion != kerberosVersion || req.MsgType != appRequestType {
		return ErrProtocol
	}

	// Check the ticket

	tkt := ticket{}
	if _, err := asn1.UnmarshalWithParams(req.Ticket.FullBytes, &tkt, ticketParam); err != nil {
		return err
	}

	if tkt.Realm != c.realm || !nameEquals(tkt.Service, c.principal) {
		return ErrInvalidTicket
	}

	etktdata, err := c.key.decrypt(tkt.Encrypted, ticketKey)
	if err != nil {
		return err
	}

	etkt := encryptedTicket{}
	if _, err := asn1.UnmarshalWithParams(etktdata, &etkt, encTicketParam); err != nil {
		return err
	}

	now := time.Now()
	if (etkt.From != time.Time{} && now.Before(etkt.From)) || now.After(etkt.Till) {
		return ErrInvalidTicket
	}

	tkey, err := loadKey(etkt.Key.Algorithm, etkt.Key.Key, tkt.KeyVersion)
	if err != nil {
		return err
	}

	// Check the authenticator

	authdata, err := tkey.decrypt(req.Authenticator, appRequestAuthKey)
	if err != nil {
		return err
	}

	auth := authenticator{}
	if _, err := asn1.UnmarshalWithParams(authdata, &auth, authenticatorParam); err != nil {
		return err
	}

	if auth.ProtoVersion != kerberosVersion || auth.ClientRealm != etkt.ClientRealm || !nameEquals(auth.Client, etkt.Client) {
		return ErrProtocol
	}

	if math.Abs(float64(now.Sub(auth.Time))) > float64(time.Minute*5) {
		return ErrProtocol
	}

	// Now check for replays

	rkey := replayKey{
		keyType:        etkt.Key.Algorithm,
		key:            string(etkt.Key.Key),
		time:           auth.Time,
		microseconds:   auth.Microseconds,
		sequenceNumber: auth.SequenceNumber,
	}

	if _, ok := c.replay[rkey]; ok {
		return ErrProtocol
	}

	// Check for an empty replay cache so that we can initialise c.lastReplayPurge
	if len(c.replay) == 0 || now.Sub(c.lastReplayPurge) > time.Minute*10 {
		for rkey := range c.replay {
			if now.Sub(rkey.time) > time.Minute*10 {
				delete(c.replay, rkey)
			}
		}

		c.lastReplayPurge = now
	}

	c.replay[rkey] = true

	if (bitStringToFlags(req.Flags) & mutualRequired) == 0 {
		return nil
	}

	// Now send the reply

	enc := encryptedAppReply{
		ClientTime:         auth.Time,
		ClientMicroseconds: auth.Microseconds,
		SequenceNumber:     auth.SequenceNumber,
	}

	edata, err := asn1.MarshalWithParams(enc, encAppReplyParam)
	if err != nil {
		return err
	}

	rep := appReply{
		ProtoVersion: kerberosVersion,
		MsgType:      appReplyType,
		Encrypted:    tkey.encrypt(edata, appReplyEncryptedKey),
	}

	repdata, err := asn1.MarshalWithParams(rep, appReplyParam)
	if err != nil {
		return err
	}

	repdata = append([]byte{byte(appReplyType >> 8), byte(appReplyType)}, repdata...)
	gssrep, err := encodeGssWrapper(oid, repdata)
	if err != nil {
		return err
	}

	if spnego {
		srep := negTokenReply{
			State:     spnegoAccepted,
			Mechanism: oid,
			Response:  gssrep,
		}

		repdata, err := asn1.MarshalWithParams(srep, negTokenReplyParam)
		if err != nil {
			return err
		}

		gssrep, err = encodeGssWrapper(gssSpnegoOid, repdata)
		if err != nil {
			return err
		}
	}

	if _, err := rw.Write(gssrep); err != nil {
		return err
	}

	return nil
}
