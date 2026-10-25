// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux && !darwin

package store

// volumeSpace is unknown here; a percentage size limit then does not apply.
func volumeSpace(string) (total, free int64, ok bool) { return 0, 0, false }
