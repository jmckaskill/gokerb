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
)

type cipher interface {
	Encrypt(d []byte, usage int) encryptedData
	Decrypt(d encryptedData, usage int) ([]byte, error)
	Checksum(d []byte, usage int) checksumData
	SetKeyVersion(kvno int)
	Key() (kvno int, key encryptionKey)
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

func (c *rc4HmacCipher) SetKeyVersion(kvno int) {
	c.kvno = kvno
}

func (c *rc4HmacCipher) Key() (int, encryptionKey) {
	return c.kvno, encryptionKey{
		Algorithm: rc4HmacAlgorithm,
		Key:       c.key,
	}
}

func (c *rc4HmacCipher) Checksum(data []byte, usage int) checksumData {
	// TODO: replace with RC4-HMAC checksum algorithm. For now we are
	// using the unkeyed RSA-MD5 checksum algorithm
	h := md5.New()
	h.Write(data)
	return checksumData{
		Type: md5Checksum,
		Data: h.Sum(nil),
	}
}

func (c *rc4HmacCipher) Encrypt(data []byte, usage int) encryptedData {
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

func (c *rc4HmacCipher) Decrypt(d encryptedData, usage int) ([]byte, error) {
	if d.Algorithm != rc4HmacAlgorithm || (c.kvno != 0 && d.KeyVersion != c.kvno) || len(d.Data) < 24 {
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
