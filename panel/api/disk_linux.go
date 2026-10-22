//go:build linux

package api

import "syscall"

// diskUsage returns total and used bytes of the filesystem holding path.
func diskUsage(path string) (total, used uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	bs := uint64(st.Bsize)
	total = st.Blocks * bs
	used = (st.Blocks - st.Bfree) * bs
	return total, used
}
