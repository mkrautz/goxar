// Copyright (c) 2011 Mikkel Krautz <mikkel@krautz.dk>
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

// The xar package provides for reading and writing XAR archives.
package xar

import (
	"bytes"
	"compress/zlib"
	"crypto"
	"crypto/tls"
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

type Config struct {
	// The set of CA certificates that are considered trusted.
	RootCAs *tls.CASet

	// For xar.Readers, setting this to true will make the reader
	// validate the signature (if any) and verify that the certificate
	// chain found in the archive is trusted by the system.
	//
	// If set to true, the package will ignore invalid signatures and/or
	// untrusted certificates in the certificate chain.
	//
	// Note: Since there is no way in Go to easily get a list of system
	// CAs in a cross-platform way, the certificates in RootCAs are considered
	// the 'trusted root certificates' of the system.
	VerifySignature bool
}

type File struct {
}

type Reader struct {
	File []*File

	HasSignature    bool
	Certificates    []*x509.Certificate
	ValidSignature  bool

	xar        *os.File
	heapOffset int64
}

// Default configuration for Readers
func defaultReaderConfig() *Config {
	return &Config{
		RootCAs: nil,
		VerifySignature: true,
	}
}

// Create a new XAR reader
func NewReader(name string, config *Config) (r *Reader, err os.Error) {
	r = &Reader{}

	if config == nil {
		config = defaultReaderConfig()
	}

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
	r.HasSignature = root.Toc.Signature != nil
	if config.VerifySignature == true && root.Toc.Signature != nil {
		if len(root.Toc.Signature.Certificates) == 0 {
			return nil, os.NewError("No certificates in XAR")
		}

		signature := make([]byte, root.Toc.Signature.Size)
		_, err = io.ReadFull(io.NewSectionReader(r.xar, r.heapOffset + root.Toc.Signature.Offset, root.Toc.Signature.Size), signature)
		if err != nil {
			return nil, err
		}

		// Read certificates
		for i := 0; i < len(root.Toc.Signature.Certificates); i++ {
			cb64 := []byte(strings.Replace(root.Toc.Signature.Certificates[i], "\n", "", -1))
			cder := make([]byte, base64.StdEncoding.DecodedLen(len(cb64)))
			ndec, err := base64.StdEncoding.Decode(cder, cb64)
			if err != nil {
				return nil, err
			}

			cert, err := x509.ParseCertificate(cder[0:ndec])
			if err != nil {
				return nil, err
			}

			r.Certificates = append(r.Certificates, cert)
		}

		// Verify validity of chain
		// fixme(mkrautz): Check CA certs against config.RootCAs
		for i := 1; i < len(r.Certificates); i++ {
			if err := r.Certificates[i-1].CheckSignatureFrom(r.Certificates[i]); err != nil {
				return nil, err
			}
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
			pubkey := r.Certificates[0].PublicKey.(*rsa.PublicKey)
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

		r.ValidSignature = true
	}

	return r, nil
}
