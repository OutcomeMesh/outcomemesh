//go:build linux

package pruneservice

import "golang.org/x/sys/unix"

// Bind mounts share st_dev with their source but have a distinct mount ID.
func transferMountID(path string) (uint64, error) {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &st); err != nil {
		return 0, err
	}
	if st.Mask&unix.STATX_MNT_ID == 0 {
		return 0, unix.EOPNOTSUPP
	}
	return st.Mnt_id, nil
}
