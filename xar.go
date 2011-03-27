// Copyright (c) 2011 Mikkel Krautz <mikkel@krautz.dk>
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

// The xar package provides for reading and writing XAR archives.
package xar

import (
	"bytes"
	"compress/zlib"
	"crypto"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
	"xml"
)

const xarVersion = 1
const xarHeaderMagic = 0x78617221 // 'xar!'
const xarHeaderSize = 28

type xarHeader struct {
	magic         uint32
	size          uint16
	version       uint16
	toc_len_zlib  uint64
	toc_len_plain uint64
	checksum_kind uint32
}

const (
	xarChecksumKindNone = iota
	xarChecksumKindSHA1
	xarChecksumKindMD5
)

type File struct {
}

type Reader struct {
	File []*File
	xar        *os.File
	heapOffset int64
}

// Create a new XAR reader
func NewReader(name string) (r *Reader, err os.Error) {
	r = &Reader{}

	r.xar, err = os.Open(name, os.O_RDONLY, 0400)
	if err != nil {
		return nil, err
	}

	hdr := make([]byte, xarHeaderSize)
	_, err = r.xar.Read(hdr)
	if err != nil {
		return nil, err
	}

	xh := &xarHeader{}
	xh.magic = binary.BigEndian.Uint32(hdr[0:4])
	xh.size = binary.BigEndian.Uint16(hdr[4:6])
	xh.version = binary.BigEndian.Uint16(hdr[6:8])
	xh.toc_len_zlib = binary.BigEndian.Uint64(hdr[8:16])
	xh.toc_len_plain = binary.BigEndian.Uint64(hdr[16:24])
	xh.checksum_kind = binary.BigEndian.Uint32(hdr[24:28])

	if xh.magic != xarHeaderMagic {
		err = os.NewError("Bad magic")
		return nil, err
	}

	if xh.version != xarVersion {
		err = os.NewError("Bad version")
		return nil, err
	}

	if xh.size != xarHeaderSize {
		err = os.NewError("Bad header size")
	}

	ztoc := make([]byte, xh.toc_len_zlib)
	ztocr := io.LimitReader(r.xar, int64(len(ztoc)))
	_, err = io.ReadFull(ztocr, ztoc)
	if err != nil {
		return nil, err
	}

	br := bytes.NewBuffer(ztoc)
	zr, err := zlib.NewReader(br)
	if err != nil {
		return nil, err
	}

	root := &xmlXar{}
	err = xml.Unmarshal(zr, &root)
	if err != nil {
		return nil, err
	}

	r.heapOffset = xarHeaderSize + int64(xh.toc_len_zlib)

	if root.Toc.Checksum == nil {
		return nil, os.NewError("No TOC checksum info in TOC")
	}

	// Check whether the XAR checksum matches
	storedsum := make([]byte, root.Toc.Checksum.Size)
	_, err = io.ReadFull(io.NewSectionReader(r.xar, r.heapOffset + root.Toc.Checksum.Offset, root.Toc.Checksum.Size), storedsum)
	if err != nil {
		return nil, err
	}

	var hasher hash.Hash
	switch xh.checksum_kind {
	case xarChecksumKindNone:
		return nil, os.NewError("Encountered xarChecksumKindNone. Don't know how to handle.")
	case xarChecksumKindSHA1:
		if root.Toc.Checksum.Style != "sha1" {
			return nil, os.NewError("Mismatch between TOC checksum kind and header checksum kind")
		}
		hasher = sha1.New()
	case xarChecksumKindMD5:
		if root.Toc.Checksum.Style != "md5" {
			return nil, os.NewError("Mismatch between TOC checksum kind and header checksum kind")
		}
		hasher = md5.New()
	default:
		return nil, os.NewError("Unknown checksum kind in header")
	}

	hasher.Write(ztoc)
	calcedsum := hasher.Sum()

	if !bytes.Equal(calcedsum, storedsum) {
		return nil, os.NewError("TOC checksum mismatch")
	}

	// Check if there's a signature ...
	if root.Toc.Signature != nil {
		if len(root.Toc.Signature.Certificates) == 0 {
			return nil, os.NewError("No certificates in XAR")
		}

		signature := make([]byte, root.Toc.Signature.Size)
		_, err = io.ReadFull(io.NewSectionReader(r.xar, r.heapOffset + root.Toc.Signature.Offset, root.Toc.Signature.Size), signature)
		if err != nil {
			return nil, err
		}

		// Get the public key from the leaf certificate
		leafb64 := []byte(strings.Replace(root.Toc.Signature.Certificates[0], "\n", "", -1))
		leafder := make([]byte, base64.StdEncoding.DecodedLen(len(leafb64)))
		ndec, err := base64.StdEncoding.Decode(leafder, leafb64)
		if err != nil {
			return nil, err
		}

		cert, err := x509.ParseCertificate(leafder[0:ndec])
		if err != nil {
			return nil, err
		}

		var sighash crypto.Hash
		if xh.checksum_kind == xarChecksumKindNone {
			return nil, os.NewError("Cannot use xarChecksumKindNone with signature")
		} else if xh.checksum_kind == xarChecksumKindSHA1 {
			sighash = crypto.SHA1
		} else if xh.checksum_kind == xarChecksumKindMD5 {
			sighash = crypto.MD5
		}

		if root.Toc.Signature.Style == "RSA" {
			pubkey := cert.PublicKey.(*rsa.PublicKey)
			if pubkey == nil {
				return nil, os.NewError("Signature style is RSA but certificate's public key is not.")
			}
			err = rsa.VerifyPKCS1v15(pubkey, sighash, storedsum, signature)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, os.NewError(fmt.Sprint("Unknown signature style %s", root.Toc.Signature.Style))
		}

	}

	return r, nil
}
