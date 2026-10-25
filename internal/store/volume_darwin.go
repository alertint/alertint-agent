// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import "syscall"

// volumeSpace reports the size and the space available to unprivileged
// writers of the filesystem holding dir.
func volumeSpace(dir string) (total, free int64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, false
	}
	bsize := uint64(st.Bsize)
	return clampInt64(st.Blocks * bsize), clampInt64(st.Bavail * bsize), true
}
