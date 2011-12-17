package kerb

import (
	"encoding/binary"
	"io"
)

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
