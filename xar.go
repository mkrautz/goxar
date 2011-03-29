// Copyright (c) 2011 Mikkel Krautz <mikkel@krautz.dk>
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

// The xar package provides for reading and writing XAR archives.
package xar

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto"
	"crypto/tls"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
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


type FileType int

const (
	FileTypeFile FileType = iota
	FileTypeDirectory
	FileTypeSymlink
	FileTypeFifo
	FileTypeCharDevice
	FileTypeBlockDevice
	FileTypeSocket
)

type FileChecksumKind int

const (
	FileChecksumKindSHA1 FileChecksumKind = iota
	FileChecksumKindMD5
)

type FileInfo struct {
	DeviceNo uint64
	Mode     uint32
	Inode    uint64
	Uid      int
	User     string
	Gid      int
	Group    string
	Atime    int64
	Mtime    int64
	Ctime    int64
}

type FileChecksum struct {
	Kind FileChecksumKind
	Sum  []byte
}

type File struct {
	Type FileType
	Info FileInfo
	Id   uint64
	Name string

	EncodingMimetype   string
	CompressedChecksum FileChecksum
	ExtractedChecksum  FileChecksum
	// The size of the archived file (the size of the file after decompressing)
	Size int64

	offset int64
	length int64
	heap   io.ReaderAt
}

type Reader struct {
	File map[uint64]*File

	HasSignature   bool
	Certificates   []*x509.Certificate
	ValidSignature bool

	xar        io.ReaderAt
	info       *os.FileInfo
	heapOffset int64
}

// Default configuration for Readers
func defaultReaderConfig() *Config {
	return &Config{
		RootCAs:         nil,
		VerifySignature: true,
	}
}

// Create a new XAR reader
func NewReader(name string, config *Config) (r *Reader, err os.Error) {
	r = &Reader{}
	r.File = make(map[uint64]*File)

	if config == nil {
		config = defaultReaderConfig()
	}

	f, err := os.Open(name, os.O_RDONLY, 0400)
	if err != nil {
		return nil, err
	}
	r.info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	r.xar = f

	hdr := make([]byte, xarHeaderSize)
	_, err = r.xar.ReadAt(hdr, 0)
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
	_, err = r.xar.ReadAt(ztoc, xarHeaderSize)
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
	_, err = io.ReadFull(io.NewSectionReader(r.xar, r.heapOffset+root.Toc.Checksum.Offset, root.Toc.Checksum.Size), storedsum)
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
		_, err = io.ReadFull(io.NewSectionReader(r.xar, r.heapOffset+root.Toc.Signature.Offset, root.Toc.Signature.Size), signature)
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

	// Add files to Reader
	for _, xmlFile := range root.Toc.File {
		err := r.readXmlFileTree(xmlFile, "")
		if err != nil {
			return nil, err
		}
	}

	return r, nil
}

func xmlFileToFileInfo(xmlFile *xmlFile) (fi FileInfo, err os.Error) {
	t, err := time.Parse(time.RFC3339, xmlFile.Ctime)
	if err != nil {
		return
	}
	fi.Ctime = t.Seconds()

	t, err = time.Parse(time.RFC3339, xmlFile.Mtime)
	if err != nil {
		return
	}
	fi.Mtime = t.Seconds()

	t, err = time.Parse(time.RFC3339, xmlFile.Atime)
	if err != nil {
		return
	}
	fi.Atime = t.Seconds()

	fi.Group = xmlFile.Group
	fi.Gid = xmlFile.Gid

	fi.User = xmlFile.User
	fi.Uid = xmlFile.Uid

	fi.Mode = xmlFile.Mode

	fi.Inode = xmlFile.Inode
	fi.DeviceNo = xmlFile.DeviceNo

	return
}

// Convert a xmlFileChecksum to a FileChecksum.
func fileChecksumFromXml(f *FileChecksum, x *xmlFileChecksum) (err os.Error) {
	f.Sum, err = hex.DecodeString(x.Digest)
	if err != nil {
		return
	}

	switch x.Style {
	case "MD5":
		f.Kind = FileChecksumKindMD5
	case "SHA1":
		f.Kind = FileChecksumKindSHA1
	default:
		return os.NewError("Unknown file checksum kind")
	}

	return nil
}

// Create a new SectionReader that is limited to reading from the file's heap
func (r *Reader) newHeapReader() *io.SectionReader {
	return io.NewSectionReader(r.xar, r.heapOffset, r.info.Size-r.heapOffset)
}

// Reads the file tree from a parse XAR TOC into the Reader.
func (r *Reader) readXmlFileTree(xmlFile *xmlFile, dir string) (err os.Error) {
	xf := &File{}
	xf.heap = r.newHeapReader()

	if xmlFile.Type == "file" {
		xf.Type = FileTypeFile
	} else if xmlFile.Type == "directory" {
		xf.Type = FileTypeDirectory
	} else {
		return
	}

	xf.Id, err = strconv.Atoui64(xmlFile.Id)
	if err != nil {
		return
	}

	xf.Name = path.Join(dir, xmlFile.Name)

	xf.Info, err = xmlFileToFileInfo(xmlFile)
	if err != nil {
		return
	}

	if xf.Type == FileTypeFile && xmlFile.Data == nil {
		err = os.NewError("Encountered file with no data")
		return
	}
	if xf.Type == FileTypeFile {
		xf.EncodingMimetype = xmlFile.Data.Encoding.Style
		xf.Size = xmlFile.Data.Size
		xf.length = xmlFile.Data.Length
		xf.offset = xmlFile.Data.Offset

		err = fileChecksumFromXml(&xf.CompressedChecksum, &xmlFile.Data.ArchivedChecksum)
		if err != nil {
			return
		}

		err = fileChecksumFromXml(&xf.ExtractedChecksum, &xmlFile.Data.ExtractedChecksum)
		if err != nil {
			return
		}
	}

	r.File[xf.Id] = xf

	if xf.Type == FileTypeDirectory {
		for _, subXmlFile := range xmlFile.File {
			err = r.readXmlFileTree(subXmlFile, xf.Name)
			if err != nil {
				return
			}
		}
	}

	return
}

// Open returns a ReadCloser that provides access to the file's
// uncompressed content.
func (f *File) Open() (rc io.ReadCloser, err os.Error) {
	r := io.NewSectionReader(f.heap, f.offset, f.length)
	switch f.EncodingMimetype {
	case "application/octet-stream":
		rc = ioutil.NopCloser(r)
	case "application/x-gzip":
		rc, err = gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
	}

	return rc, nil
}

// Verify that the compressed content of the File in the
// archive matches the stored checksum.
func (f *File) VerifyChecksum() bool {
	// Non-files are implicitly OK, since all metadata
	// is stored in the TOC.
	if f.Type != FileTypeFile {
		return true
	}

	var hasher hash.Hash
	switch f.CompressedChecksum.Kind {
	case FileChecksumKindSHA1:
		hasher = sha1.New()
	case FileChecksumKindMD5:
		hasher = md5.New()
	default:
		return false
	}

	io.Copy(hasher, io.NewSectionReader(f.heap, f.offset, f.length))
	sum := hasher.Sum()
	return bytes.Equal(sum, f.CompressedChecksum.Sum)
}
