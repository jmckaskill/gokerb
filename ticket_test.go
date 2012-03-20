package kerb

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/jmckaskill/asn1"
	"io"
	"reflect"
	"testing"
	"time"
)

var _ = fmt.Println

type req struct {
	realm string
	key   key
	req   *kdcRequest
	app   *appRequest
	auth  *authenticator
	time  time.Time
	out   []byte
	udp   []byte
}

type conn struct {
	req   *req
	proto string
	buf   *bytes.Buffer
}

func domd5(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}

func (c *conn) Write(d []byte) (n int, err error) {
	//defer recoverMust(&err)

	if c.proto == "tcp" {
		must(len(d) >= 4)
		sz := int(binary.BigEndian.Uint32(d))
		must(sz == len(d)+4)
		d = d[4:]
	}

	r := c.req
	c.req = nil
	req := kdcRequest{}

	if r.app != nil {
		// TGS request
		mustUnmarshal(d, &req, tgsRequestParam)

		app := appRequest{}
		must(len(req.Preauth) == 1 && req.Preauth[0].Type == paTgsRequest)
		mustUnmarshal(req.Preauth[0].Data, &app, appRequestParam)
		req.Preauth = nil

		auth := authenticator{}
		adata := mustDecrypt(r.key, nil, app.Auth.Algo, paTgsRequestKey, app.Auth.Data)
		mustUnmarshal(adata, &auth, authenticatorParam)
		must(auth.Checksum.Algo == signMd5)
		must(bytes.Equal(auth.Checksum.Data, domd5(req.Body.FullBytes)))
		app.Auth = encryptedData{}
		auth.Checksum = checksumData{}

		//fmt.Printf("%#v\n\n%#v\n\n", app, *r.app)
		must(reflect.DeepEqual(app, *r.app))

		//fmt.Printf("%#v\n\n%#v\n\n", auth, *r.auth)
		must(reflect.DeepEqual(auth, *r.auth))

	} else if !r.time.IsZero() {
		// AS request
		mustUnmarshal(d, &req, asRequestParam)

		ets := encryptedData{}
		ts := encryptedTimestamp{}
		must(len(req.Preauth) == 1 && req.Preauth[0].Type == paEncryptedTimestamp)
		mustUnmarshal(req.Preauth[0].Data, &ets, "")
		tsdata := mustDecrypt(r.key, nil, ets.Algo, paEncryptedTimestampKey, ets.Data)
		mustUnmarshal(tsdata, &ts, "")
		req.Preauth = nil

		must(time.Unix(ts.Time.Unix(), int64(ts.Microseconds)*1000).Equal(r.time))

	} else {
		// AS preauth request
		mustUnmarshal(d, &req, asRequestParam)
		must(len(req.Preauth) == 0)
	}

	var b1, b2 kdcRequestBody
	mustUnmarshal(req.Body.FullBytes, &b1, "")
	mustUnmarshal(r.req.Body.FullBytes, &b2, "")
	//fmt.Printf("%#v\n\n%#v\n\n", req, *r.req)
	//fmt.Printf("%#v\n\n%#v\n\n", b1, b2)
	must(reflect.DeepEqual(req, *r.req))

	if c.proto == "udp" && r.udp != nil {
		c.buf = bytes.NewBuffer(r.udp)
	} else {
		c.buf = bytes.NewBuffer(r.out)
	}

	return len(d), nil
}

func (c *conn) Read(d []byte) (int, error) {
	return c.buf.Read(d)
}

func (c *conn) Close() error {
	return nil
}

var reqs []*req
var now = time.Now()
var randsrc io.Reader

type randreader struct{}

func (randreader) Read(b []byte) (int, error) {
	return randsrc.Read(b)
}

var kcfg = &CredConfig{
	Now: func() time.Time {
		return now
	},
	Dial: func(proto, realm string) (io.ReadWriteCloser, error) {
		if len(reqs) == 0 {
			return nil, errors.New("unexpected request")
		}
		if reqs[0].realm != realm {
			return nil, errors.New("wrong realm")
		}
		req := reqs[0]
		reqs = reqs[1:]
		return &conn{req, proto, nil}, nil
	},
	Rand: randreader{},
}

func addrand(u uint32) {
	binary.Write(randsrc.(io.Writer), binary.BigEndian, u)
}

func mkerror(code int, service, realm string, edata []byte) []byte {
	now := time.Now()
	msg := errorMessage{
		ProtoVersion:       kerberosVersion,
		MsgType:            errorType,
		ServerTime:         now,
		ServerMicroseconds: int(now.Nanosecond() / 1000),
		Service:            splitPrincipal(service),
		ServiceRealm:       realm,
		ErrorCode:          code,
		ErrorData:          edata,
	}
	return mustMarshal(msg, errorParam)
}

func mkasreq(client, realm string, nonce uint32) *kdcRequest {
	return mkreq(client, "krbtgt/"+realm, realm, nonce, defaultLoginFlags, asRequestParam, asRequestType)
}

func mktgsreq(client, service, srealm string, nonce uint32) *kdcRequest {
	return mkreq(client, service, srealm, nonce, DefaultTicketConfig.Flags, tgsRequestParam, tgsRequestType)
}

func mkreq(client, service, realm string, nonce uint32, flags int, param string, typ int) *kdcRequest {
	body := kdcRequestBody{
		Flags:        flagsToBitString(flags),
		Client:       splitPrincipal(client),
		ServiceRealm: realm,
		Service:      splitPrincipal(service),
		Till:         notill,
		Nonce:        nonce >> 1,
		Algorithms:   supportedAlgorithms,
	}

	braw := asn1.RawValue{}
	mustUnmarshal(mustMarshal(body, param), &braw, param)

	return &kdcRequest{
		ProtoVersion: kerberosVersion,
		MsgType:      typ,
		Body:         braw,
	}
}

func mktgsapp(tgs *Ticket) *appRequest {
	rtkt := asn1.RawValue{}
	mustUnmarshal(tgs.ticket, &rtkt, "")

	return &appRequest{
		ProtoVersion: kerberosVersion,
		MsgType:      appRequestType,
		Flags:        flagsToBitString(0),
		Ticket:       rtkt,
	}
}

func mkauth(client, crealm string, seqnum uint32) *authenticator {
	return &authenticator{
		ProtoVersion:   kerberosVersion,
		Client:         splitPrincipal(client),
		ClientRealm:    crealm,
		Microseconds:   int(now.Nanosecond() / 1000),
		Time:           time.Unix(now.Unix(), 0).UTC(),
		SequenceNumber: seqnum,
	}
}

func mkasrep(tkt *Ticket, nonce uint32, ckey key) []byte {
	rep, erep := mkrep(tkt, nonce)

	erepdata := mustMarshal(*erep, encAsReplyParam)
	rep.MsgType = asReplyType
	rep.Encrypted = encryptedData{
		Algo: ckey.EncryptAlgo(asReplyClientKey),
		Data: ckey.Encrypt(nil, asReplyClientKey, erepdata),
	}

	return mustMarshal(*rep, asReplyParam)
}

func mktgsrep(tkt *Ticket, nonce uint32, ckey key) []byte {
	rep, erep := mkrep(tkt, nonce)

	erepdata := mustMarshal(*erep, encTgsReplyParam)
	rep.MsgType = tgsReplyType
	rep.Encrypted = encryptedData{
		Algo: ckey.EncryptAlgo(tgsReplySessionKey),
		Data: ckey.Encrypt(nil, tgsReplySessionKey, erepdata),
	}

	return mustMarshal(*rep, tgsReplyParam)
}

func mkrep(tkt *Ticket, nonce uint32) (*kdcReply, *encryptedKdcReply) {
	erep := encryptedKdcReply{
		Key: encryptionKey{
			Algo: tkt.key.EncryptAlgo(ticketKey),
			Key:  tkt.key.Key(),
		},
		Nonce:        nonce >> 1,
		Flags:        flagsToBitString(tkt.flags),
		AuthTime:     tkt.authTime,
		From:         tkt.startTime,
		Till:         tkt.till,
		RenewTill:    tkt.renewTill,
		Service:      tkt.service,
		ServiceRealm: tkt.srealm,
	}

	rep := kdcReply{
		ProtoVersion: kerberosVersion,
		Client:       tkt.client,
		ClientRealm:  tkt.crealm,
		Ticket:       asn1.RawValue{FullBytes: tkt.ticket},
	}

	return &rep, &erep
}

// mkcred creates a credential in the given realm.
//
// krbtgt/realm@realm is a login tgs, krbtgt/realm1@realm2 is a cross TGS for
// granting tickets for services in realm1 to clients in realm2.
func mkcred(serv, realm string) *Credential {
	key := mustGenerateKey(cryptRc4Hmac, rand.Reader)
	return newCredential(splitPrincipal(serv), realm, key, 0, kcfg)
}

var saltTests = []struct {
	algo   int
	salt   string
	et2    []eTypeInfo2
	et     []eTypeInfo
	pasalt []byte
}{
	{cryptRc4Hmac, "", []eTypeInfo2{{cryptRc4Hmac, ""}}, nil, nil},
	{cryptDesCbcMd5, "", []eTypeInfo2{{cryptDesCbcMd5, ""}}, nil, nil},
	{cryptDesCbcMd5, "salt", []eTypeInfo2{{cryptDesCbcMd5, "salt"}}, nil, nil},
	{cryptDesCbcMd5, "salt", nil, []eTypeInfo{{cryptDesCbcMd5, []byte("salt")}}, nil},
	{cryptRc4Hmac, "", []eTypeInfo2{{cryptRc4Hmac, ""}}, nil, []byte("salt")},
	{cryptDesCbcMd5, "salt", nil, nil, []byte("salt")},
}

func TestPreauth(t *testing.T) {
	for i, d := range saltTests {
		ckey := mustLoadStringKey(d.algo, "password", d.salt)

		var pa []preauth
		if d.et2 != nil {
			d := mustMarshal(d.et2, "")
			pa = append(pa, preauth{paETypeInfo2, d})
		}
		if d.et != nil {
			d := mustMarshal(d.et, "")
			pa = append(pa, preauth{paETypeInfo, d})
		}
		if d.pasalt != nil {
			pa = append(pa, preauth{paPasswordSalt, d.pasalt})
		}
		edata := mustMarshal(pa, "")

		randsrc = new(bytes.Buffer)
		addrand(0x12345678) // nonce
		addrand(123456)     // microseconds

		reqs = []*req{
			{
				realm: "EXAMPLE.COM",
				req:   mkasreq("foo", "EXAMPLE.COM", 0x12345678),
				out:   mkerror(KDC_ERR_PREAUTH_REQUIRED, "krbtgt/EXAMPLE.COM", "EXAMPLE.COM", edata),
			},
		}

		c, err := NewCredential("foo", "EXAMPLE.COM", "password", kcfg)

		if err != nil {
			t.Errorf("Test %d failed with %v\n", i, err)

		} else if !reflect.DeepEqual(ckey, c.key) {
			t.Errorf("Test %d failed - key mismatch\n", i)

		} else if len(reqs) > 0 {
			t.Errorf("Test %d failed - requests left\n", i)
		}
	}
}

func TestGetTicket(t *testing.T) {
	randsrc = rand.Reader

	tgs := mkcred("krbtgt/EXAMPLE.COM", "EXAMPLE.COM")
	serv := mkcred("http/www.example.com", "EXAMPLE.COM")
	cred := mkcred("foo", "EXAMPLE.COM")

	tgt := tgs.mustGenerateTicket("foo", "EXAMPLE.COM", nil)
	tkt := serv.mustGenerateTicket("foo", "EXAMPLE.COM", nil)

	randsrc = new(bytes.Buffer)
	addrand(0x12345678) // AS_REQ nonce
	addrand(123456)     // AS_REQ microseconds
	addrand(0x23456789) // TGS_REQ nonce
	addrand(0x34567890) // TGS_REQ seqnum

	reqs = []*req{
		{
			realm: "EXAMPLE.COM",
			key:   cred.key,
			req:   mkasreq("foo", "EXAMPLE.COM", 0x12345678),
			time:  time.Unix(now.Unix(), 123456000),
			out:   mkasrep(tgt, 0x12345678, cred.key),
		},
		{
			realm: "EXAMPLE.COM",
			key:   tgt.key,
			req:   mktgsreq("foo", "http/www.example.com", "EXAMPLE.COM", 0x23456789),
			app:   mktgsapp(tgt),
			auth:  mkauth("foo", "EXAMPLE.COM", 0x34567890),
			out:   mktgsrep(tkt, 0x23456789, tgt.key),
		},
	}

	tkt2, err := cred.GetTicket("http/www.example.com", nil)
	if err != nil {
		t.Fatal(err)
	} else if len(reqs) > 0 {
		t.Fatal("requests left")
	} else if !reflect.DeepEqual(tkt, tkt2) {
		t.Fatalf("ticket mismatch\ngot: %+v\nexp: %+v\n", tkt2, tkt)
	}
}

func TestGetTicket2(t *testing.T) {
	randsrc = rand.Reader
	serv := mkcred("http/www.example.com", "E.EXAMPLE.COM")
	cred := mkcred("foo", "A.EXAMPLE.COM")

	tgsa := mkcred("krbtgt/A.EXAMPLE.COM", "A.EXAMPLE.COM")
	tgsb := mkcred("krbtgt/B.EXAMPLE.COM", "A.EXAMPLE.COM")
	tgsc := mkcred("krbtgt/C.EXAMPLE.COM", "B.EXAMPLE.COM")
	tgsd := mkcred("krbtgt/D.EXAMPLE.COM", "C.EXAMPLE.COM")
	tgse := mkcred("krbtgt/E.EXAMPLE.COM", "D.EXAMPLE.COM")

	tgta := tgsa.mustGenerateTicket("foo", "A.EXAMPLE.COM", nil)
	tgtb := tgsb.mustGenerateTicket("foo", "A.EXAMPLE.COM", nil)
	tgtc := tgsc.mustGenerateTicket("foo", "A.EXAMPLE.COM", nil)
	tgtd := tgsd.mustGenerateTicket("foo", "A.EXAMPLE.COM", nil)
	tgte := tgse.mustGenerateTicket("foo", "A.EXAMPLE.COM", nil)

	tkt := serv.mustGenerateTicket("foo", "A.EXAMPLE.COM", nil)

	randsrc = new(bytes.Buffer)
	addrand(0x12345678) // AS_REQ nonce
	addrand(123456)     // AS_REQ microseconds
	addrand(0x23456789) // A nonce
	addrand(0x3456789A) // A seqnum
	addrand(0x456789AB) // B nonce
	addrand(0x56789ABC) // B seqnum
	addrand(0x6789ABCD) // C nonce
	addrand(0x789ABCDE) // C seqnum
	addrand(0x89ABCDEF) // D nonce
	addrand(0x9ABCDEF0) // D seqnum
	addrand(0xABCDEF01) // E nonce
	addrand(0xBCDEF012) // E seqnum

	reqs = []*req{
		{
			realm: "A.EXAMPLE.COM",
			key:   cred.key,
			req:   mkasreq("foo", "A.EXAMPLE.COM", 0x12345678),
			time:  time.Unix(now.Unix(), 123456000),
			out:   mkasrep(tgta, 0x12345678, cred.key),
		},
		{
			realm: "A.EXAMPLE.COM",
			key:   tgta.key,
			req:   mktgsreq("foo", "http/www.example.com", "A.EXAMPLE.COM", 0x23456789),
			app:   mktgsapp(tgta),
			auth:  mkauth("foo", "A.EXAMPLE.COM", 0x3456789A),
			out:   mktgsrep(tgtb, 0x23456789, tgta.key),
		},
		{
			realm: "B.EXAMPLE.COM",
			key:   tgtb.key,
			req:   mktgsreq("foo", "http/www.example.com", "B.EXAMPLE.COM", 0x456789AB),
			app:   mktgsapp(tgtb),
			auth:  mkauth("foo", "A.EXAMPLE.COM", 0x56789ABC),
			out:   mktgsrep(tgtc, 0x456789AB, tgtb.key),
		},
		{
			realm: "C.EXAMPLE.COM",
			key:   tgtc.key,
			req:   mktgsreq("foo", "http/www.example.com", "C.EXAMPLE.COM", 0x6789ABCD),
			app:   mktgsapp(tgtc),
			auth:  mkauth("foo", "A.EXAMPLE.COM", 0x789ABCDE),
			out:   mktgsrep(tgtd, 0x6789ABCD, tgtc.key),
		},
		{
			realm: "D.EXAMPLE.COM",
			key:   tgtd.key,
			req:   mktgsreq("foo", "http/www.example.com", "D.EXAMPLE.COM", 0x89ABCDEF),
			app:   mktgsapp(tgtd),
			auth:  mkauth("foo", "A.EXAMPLE.COM", 0x9ABCDEF0),
			out:   mktgsrep(tgte, 0x89ABCDEF, tgtd.key),
		},
		{
			realm: "E.EXAMPLE.COM",
			key:   tgte.key,
			req:   mktgsreq("foo", "http/www.example.com", "E.EXAMPLE.COM", 0xABCDEF01),
			app:   mktgsapp(tgte),
			auth:  mkauth("foo", "A.EXAMPLE.COM", 0xBCDEF012),
			out:   mktgsrep(tkt, 0xABCDEF01, tgte.key),
		},
	}

	tkt2, err := cred.GetTicket("http/www.example.com", nil)
	if err != nil {
		t.Fatal(err)
	} else if len(reqs) > 0 {
		t.Fatal("requests left")
	} else if !reflect.DeepEqual(tkt, tkt2) {
		t.Fatalf("ticket mismatch\ngot: %+v\nexp: %+v\n", tkt2, tkt)
	}
}
