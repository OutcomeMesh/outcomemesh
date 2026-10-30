package keystore

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateFileBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := WriteNew(path, []byte("private")); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(path, []byte("replacement")); err == nil {
		t.Fatal("overwrote key")
	}
	if b, err := ReadPrivate(path, 7); err != nil || string(b) != "private" {
		t.Fatalf("read: %q %v", b, err)
	}
	if _, err := ReadPrivate(path, 6); err == nil {
		t.Fatal("accepted oversized key")
	}
	if _, err := ReadPrivate(path, -1); err == nil {
		t.Fatal("accepted negative limit")
	}
	alias := path + "-alias"
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivate(path, 7); err == nil {
		t.Fatal("accepted hard-linked key")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivate(filepath.Dir(path), 7); err == nil {
		t.Fatal("accepted directory")
	}
}

func TestWindowsPrivateFileRejectsBroadAndNullDACL(t *testing.T) {
	for _, null := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "key")
		if err := WriteNew(path, []byte("private")); err != nil {
			t.Fatal(err)
		}
		var acl *windows.ACL
		if !null {
			sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
			if err != nil {
				t.Fatal(err)
			}
			acl, _, err = sd.DACL()
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadPrivate(path, 7); err == nil {
			t.Fatalf("accepted public ACL (null=%v)", null)
		}
	}
}

func TestWindowsPrivateFileRejectsReparsePoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := WriteNew(path, []byte("private")); err != nil {
		t.Fatal(err)
	}
	link := path + "-link"
	// The native CI runner has symlink privilege; a missing privilege is a failure.
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivate(link, 7); err == nil {
		t.Fatal("followed symlink")
	}
	if err := WriteNew(link, []byte("replacement")); err == nil {
		t.Fatal("replaced symlink")
	}
	if b, err := ReadPrivate(path, 7); err != nil || string(b) != "private" {
		t.Fatal("changed target", err)
	}
}

func TestWindowsPrivatePathsRejectDevicesAndStreams(t *testing.T) {
	for _, path := range []string{`\\server\share\key`, `\\?\C:\key`, `\\.\pipe\key`, `C:\key:secret`, `C:\NUL`, `C:\CON.txt`, `C:\COM1`, `C:\LPT9.txt`, `C:\key.`, `C:\key `, `C:\key.\child`, `C:\key \child`, `relative.`, `relative `, ""} {
		if _, err := privatePath(path); err == nil {
			t.Fatalf("accepted %q", path)
		}
	}
}
