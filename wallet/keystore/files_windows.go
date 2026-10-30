package keystore

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errPrivateFile = errors.New("private file must be a local regular file owned by the current user, accessible only to that user and SYSTEM, and within the size limit")

// Only local drive paths are accepted. Device namespaces, alternate streams,
// reserved DOS names and ambiguous trailing dots/spaces are not key paths.
func privatePath(path string) (*uint16, error) {
	if path == "" {
		return nil, errPrivateFile
	}
	// GetFullPathName (used by filepath.Abs) strips trailing dots/spaces.
	// Reject ambiguous input before that normalization can erase evidence.
	for _, part := range strings.Split(strings.ReplaceAll(path, "/", `\`), `\`) {
		if part != "." && part != ".." && strings.TrimRight(part, ". ") != part {
			return nil, errPrivateFile
		}
	}
	p, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	volume := filepath.VolumeName(p)
	if len(volume) != 2 || volume[1] != ':' {
		return nil, errPrivateFile
	}
	for _, part := range strings.Split(p[2:], `\`) {
		if part == "" {
			continue
		}
		if !filepath.IsLocal(part) || strings.ContainsAny(part, `:<>"|?*`) || strings.TrimRight(part, ". ") != part {
			return nil, errPrivateFile
		}
		name := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" || name == "CONIN$" || name == "CONOUT$" || (len(name) == 4 && (strings.HasPrefix(name, "COM") || strings.HasPrefix(name, "LPT")) && name[3] >= '1' && name[3] <= '9') {
			return nil, errPrivateFile
		}
	}
	return windows.UTF16PtrFromString(p)
}

func currentOwner() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid.Copy()
}

// ReadPrivate validates the opened handle, without following leaf reparse points.
// Denying write/delete sharing keeps the checked object fixed during the read.
// As on Unix, securing the parent directory remains the operator's duty.
func ReadPrivate(path string, maximum int) ([]byte, error) {
	if maximum < 0 {
		return nil, errPrivateFile
	}
	p, err := privatePath(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	if err = verifyPrivateHandle(h, maximum); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(maximum)+1))
	if err != nil || len(b) > maximum {
		clear(b)
		return nil, ErrKey
	}
	return b, nil
}

// Both reads and newly created files must have enforceable private permissions.
// Validate an empty new file before placing secret bytes on the volume.
func verifyPrivateHandle(h windows.Handle, maximum int) error {
	kind, err := windows.GetFileType(h)
	if err != nil || kind != windows.FILE_TYPE_DISK {
		return errPrivateFile
	}
	var filesystemFlags uint32
	if err = windows.GetVolumeInformationByHandle(h, nil, 0, nil, nil, &filesystemFlags, nil, 0); err != nil {
		return err
	}
	if filesystemFlags&windows.FILE_PERSISTENT_ACLS == 0 {
		return errPrivateFile
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 || uint64(info.FileSizeHigh)<<32|uint64(info.FileSizeLow) > uint64(maximum) {
		return errPrivateFile
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errPrivateFile
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errPrivateFile
	}
	user, err := currentOwner()
	if err != nil {
		return err
	}
	if !windows.EqualSid(owner, user) {
		return errPrivateFile
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errPrivateFile
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		// Accept only simple allow entries. Reject unknown/object/callback entries,
		// including deny entries, instead of attempting to emulate Windows AccessCheck.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Header.AceSize < 16 {
			return errPrivateFile
		}
		sidHeader := unsafe.Slice((*byte)(unsafe.Pointer(&ace.SidStart)), 8)
		if sidHeader[1] > 15 || 16+uint32(sidHeader[1])*4 > uint32(ace.Header.AceSize) {
			return errPrivateFile
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || uint32(sid.Len())+8 > uint32(ace.Header.AceSize) || (!windows.EqualSid(sid, user) && !sid.IsWellKnown(windows.WinLocalSystemSid)) {
			return errPrivateFile
		}
	}
	return nil
}

// WriteNew installs a protected owner/SYSTEM DACL atomically with creation.
// File data is flushed before success. An error preserves the partial file for
// inspection; no existing file is replaced and no directory durability is implied.
func WriteNew(path string, b []byte) error {
	p, err := privatePath(path)
	if err != nil {
		return err
	}
	user, err := currentOwner()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + user.String() + "D:P(A;;FA;;;" + user.String() + ")(A;;FA;;;SY)")
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), path)
	if err = verifyPrivateHandle(h, 0); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
