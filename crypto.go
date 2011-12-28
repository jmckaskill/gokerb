package kerb

import (
	"crypto/hmac"
	"crypto/md4"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"unicode/utf16"

	"encoding/hex"
	"encoding/asn1"
	"fmt"
)

type cipher interface {
	// If algo is -1 then use the default
	Sign(data [][]byte, algo, usage int) ([]byte, error)
	SignAlgo(usage int) int

	Encrypt(data, salt []byte, usage int) []byte
	Decrypt(data, salt []byte, algo, usage int) ([]byte, error)
	EncryptAlgo(usage int) int

	Key() []byte
}

type rc4HmacCipher struct {
	key  []byte
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
	case gssInitiatorSign, gssAcceptorSign:
		return 13
	}

	return uint32(usage)
}

func (c *rc4HmacCipher) EncryptAlgo(usage int) int {
	switch usage {
	case gssAcceptorSeal, gssInitiatorSeal, gssSequenceNumber:
		return gssSealRC4
	}

	return rc4HmacAlgorithm
}

func (c *rc4HmacCipher) Key() []byte {
	return c.key
}

func (c *rc4HmacCipher) SignAlgo(usage int) int {
	switch usage {
	case gssAcceptorSign, gssInitiatorSign:
		return gssSignHMAC_MD5
	}

	// TODO: replace with RC4-HMAC checksum algorithm. For now we are
	// using the unkeyed RSA-MD5 checksum algorithm
	return md5Checksum
}

var signaturekey = []byte("signaturekey\x00")

func (c *rc4HmacCipher) Sign(data [][]byte, algo, usage int) ([]byte, error) {
	switch algo {
	case md5Checksum:
		h := md5.New()
		for _, d := range data {
			h.Write(d)
		}
		return h.Sum(nil), nil

	case gssSignHMAC_MD5, rc4HmacChecksum:
		h := hmac.NewMD5(c.key)
		h.Write(signaturekey)
		ksign := h.Sum(nil)

		chk := md5.New()
		binary.Write(chk, binary.LittleEndian, rc4HmacUsage(usage))
		for _, d := range data {
			chk.Write(d)
		}

		h = hmac.NewMD5(ksign)
		h.Write(chk.Sum(nil))
		return h.Sum(nil), nil
	}

	return nil, ErrProtocol
}

func (c *rc4HmacCipher) Encrypt(data, salt []byte, usage int) []byte {
	switch usage {
	case gssSequenceNumber:
		// salt is the checksum
		h := hmac.NewMD5(c.key)
		binary.Write(h, binary.LittleEndian, uint32(0))
		h = hmac.NewMD5(h.Sum(nil))
		h.Write(salt)
		r, _ := rc4.NewCipher(h.Sum(nil))
		r.XORKeyStream(data, data)
		return data

	case gssAcceptorSeal, gssInitiatorSeal:
		// salt is the sequence number in big endian
		seqnum := binary.BigEndian.Uint32(salt)
		kcrypt := make([]byte, len(c.key))
		for i, b := range c.key {
			kcrypt[i] = b ^ 0xF0
		}
		h := hmac.NewMD5(kcrypt)
		binary.Write(h, binary.LittleEndian, seqnum)
		r, _ := rc4.NewCipher(h.Sum(nil))
		r.XORKeyStream(data, data)
		return data

	default:
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

		return out
	}

	panic("")
}

func (c *rc4HmacCipher) Decrypt(data, salt []byte, algo, usage int) ([]byte, error) {
	switch usage {
	case gssSequenceNumber:
		if algo != gssSealRC4 && algo != gssSealNone {
			return nil, ErrProtocol
		}

		return c.Encrypt(data, salt, usage), nil

	case gssAcceptorSeal, gssInitiatorSeal:
		// GSS sealing uses an external checksum for integrity and
		// since RC4 is symettric we can just reencrypt the data
		if algo != gssSealRC4 {
			return nil, ErrProtocol
		}

		return c.Encrypt(data, salt, usage), nil

	default:
		if algo != rc4HmacAlgorithm || len(data) < 24 {
			return nil, ErrProtocol
		}

		// Hash the key and usage together to get the HMAC-MD5 key
		h1 := hmac.NewMD5(c.key)
		binary.Write(h1, binary.LittleEndian, rc4HmacUsage(usage))
		K1 := h1.Sum(nil)

		// Calculate the RC4 key using the checksum
		h3 := hmac.NewMD5(K1)
		h3.Write(data[:16])
		K3 := h3.Sum(nil)

		// Decrypt d.Data[16:] in place with 16:24 being random data and 24:
		// being the encrypted data
		r, _ := rc4.NewCipher(K3)
		r.XORKeyStream(data[16:], data[16:])

		// Recalculate the checksum using the decrypted data
		ch := hmac.NewMD5(K1)
		ch.Write(data[16:])
		chk := ch.Sum(nil)

		// Check the input checksum
		if subtle.ConstantTimeCompare(chk, data[:16]) != 1 {
			return nil, ErrProtocol
		}

		return data[24:], nil
	}

	panic("")
}

func generateKey(rand io.Reader) (cipher, error) {
	data := [16]byte{}
	if _, err := io.ReadFull(rand, data[:]); err != nil {
		return nil, err
	}

	return loadKey(rc4HmacAlgorithm, data[:])
}

func loadKey(algorithm int, key []byte) (cipher, error) {
	switch algorithm {
	case rc4HmacAlgorithm:
		return &rc4HmacCipher{key}, nil
	}
	return nil, ErrProtocol
}
