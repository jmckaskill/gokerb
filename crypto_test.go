package kerb

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHexDecode(str string) []byte {
	d, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return d
}

var desStringTests = []struct {
	salt, pass, key string
}{
	{"ATHENA.MIT.EDUraeburn", "password", "cbc22fae235298e3"},
	{"WHITEHOUSE.GOVdanny", "potatoe", "df3d32a74fd92a01"},
	{"EXAMPLE.COMpianist", "\U0001D11E", "4ffb26bab0cd9413"},
	{"ATHENA.MIT.EDUJuri\u0161i\u0107", "\u00df", "62c81a5232b5e69d"},
	{"AAAAAAAA", "11119999", "984054d0f1a73e31"},
	{"FFFFAAAA", "NNNN6666", "c4bf6b25adf7a4f8"},
}

func TestDesStringKey(t *testing.T) {
	for i, d := range desStringTests {
		key := desStringKey(d.pass, d.salt)
		if !bytes.Equal(key, mustHexDecode(d.key)) {
			t.Errorf("Test %d failed, got %x expected %s\n", i, key, d.key)
		}
	}
}

var gssDesTests = []struct {
	data, key, out string
}{
	{"7654321 Now is the time for ", "0123456789abcdef", "f1d30f6849312ca4"},
}

func TestGssDes(t *testing.T) {
	for i, d := range gssDesTests {
		k := mustLoadKey(cryptDesCbcMd5, mustHexDecode(d.key))
		chk, err := k.Sign(signGssDes, 0, []byte(d.data))
		if err != nil {
			t.Errorf("Test %d failed %v\n", i, err)
		}
		if !bytes.Equal(chk, mustHexDecode(d.out)) {
			t.Errorf("Test %d failed got %x expected %s\n", i, chk, d.out)
		}
	}
}

var cryptTests = []struct {
	algo int
	key  string
	data string
}{
	{cryptDesCbcMd5, "cbc22fae235298e3", "0123456789abcdef"},
	{cryptDesCbcMd5, "cbc22fae235298e3", "0123456789"},
	{cryptDesCbcMd5, "cbc22fae235298e3", "0123456789abcdef0123"},
	{cryptDesCbcMd4, "cbc22fae235298e3", "0123456789abcdef"},
	{cryptDesCbcMd4, "cbc22fae235298e3", "0123456789"},
	{cryptDesCbcMd4, "cbc22fae235298e3", "0123456789abcdef0123"},
}

func TestCrypt(t *testing.T) {
	for i, d := range cryptTests {
		key := mustLoadKey(d.algo, mustHexDecode(d.key))
		enc := key.Encrypt(nil, paEncryptedTimestampKey, mustHexDecode(d.data))
		dec, err := key.Decrypt(nil, d.algo, paEncryptedTimestampKey, enc)
		if err != nil {
			t.Errorf("Test %d failed %v\n", i, err)
			continue
		}
		if !bytes.HasPrefix(dec, mustHexDecode(d.data)) {
			t.Errorf("Test %d failed got %x expected %s\n", i, dec, d.data)
		}
	}
}
