// Copyright (c) 2011 Mikkel Krautz <mikkel@krautz.dk>
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package xar

import (
	"testing"
)

func TestOpenFile(t *testing.T) {
	r, err := NewReader("payload.xar", nil)
	if err != nil {
		t.Errorf(err.String())
	}

	_ = r
}
