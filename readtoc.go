// Copyright (c) 2011 Mikkel Krautz <mikkel@krautz.dk>
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package xar

// This file implements the logic that translates a XAR TOC
// to the internal format of this library.

import (
	"xml"
)

type xmlXar struct {
	XMLName xml.Name "xar"
	Toc     xmlToc
}

type xmlChecksum struct {
	XMLName xml.Name "checksum"
	Style   string   "attr"
	Offset  int64
	Size    int64
}

type xmlSignature struct {
	XMLName      xml.Name "signature"
	Style        string   "attr"
	Offset       int64
	Size         int64
	Certificates []string "KeyInfo>X509Data>X509Certificate"
}

type xmlToc struct {
	XMLName               xml.Name "toc"
	CreationTime          string
	Checksum              *xmlChecksum
	SignatureCreationTime uint64
	Signature             *xmlSignature
	File                  []*xmlFile
}

type xmlFileChecksum struct {
	XMLName xml.Name
	Style   string "attr"
	Digest  string "chardata"
}

type xmlFinderCreateTime struct {
	XMLName     xml.Name "FinderCreateTime"
	Nanoseconds uint64
	Time        string
}

type xmlFileEncoding struct {
	XMLName xml.Name "encoding"
	Style   string   "attr"
}

type xmlFileData struct {
	XMLName           xml.Name "data"
	Length            int64
	Offset            int64
	Size              int64
	Encoding          xmlFileEncoding
	ArchivedChecksum  xmlFileChecksum
	ExtractedChecksum xmlFileChecksum
}

type xmlFile struct {
	XMLName          xml.Name "file"
	Id               string   "attr"
	Ctime            string
	Mtime            string
	Atime            string
	Group            string
	Gid              int
	User             string
	Uid              int
	Mode             uint32
	DeviceNo         uint64
	Inode            uint64
	Type             string
	Name             string
	FinderCreateTime *xmlFinderCreateTime
	Data             *xmlFileData
	File             []*xmlFile
}
