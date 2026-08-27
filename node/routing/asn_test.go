package routing

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestASNTableUsesLongestPrefixAndSeparatesAddressFamilies(t *testing.T) {
	t.Parallel()

	table, err := ParseASNTable(strings.NewReader(`
# local deterministic fixture
10.0.0.0/8,64500
10.1.0.0/16,64501
2001:db8::/32,64502
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		address string
		asn     uint32
		found   bool
	}{
		{address: "10.1.2.3", asn: 64501, found: true},
		{address: "10.2.2.3", asn: 64500, found: true},
		{address: "2001:db8::1", asn: 64502, found: true},
		{address: "192.0.2.1", found: false},
	} {
		asn, found := table.Lookup(netip.MustParseAddr(test.address))
		if asn != test.asn || found != test.found {
			t.Fatalf("lookup %s = (%d,%v), want (%d,%v)", test.address, asn, found, test.asn, test.found)
		}
	}
}

func TestManagedASNTableReloadsAtomicallyAndRejectsStaleData(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), "asn.csv")
	write := func(contents string, modified time.Time) {
		t.Helper()
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, modified, modified); err != nil {
			t.Fatal(err)
		}
	}
	write("10.0.0.0/8,64500\n", now.Add(-time.Hour))
	managed, err := NewManagedASNTable(path, 24*time.Hour, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr("10.1.2.3")
	if asn, found := managed.Lookup(address); !found || asn != 64500 {
		t.Fatalf("initial managed lookup = (%d,%v)", asn, found)
	}
	write("malformed\n", now.Add(-30*time.Minute))
	if err := managed.Refresh(); !errors.Is(err, ErrASNTable) {
		t.Fatalf("malformed refresh error = %v", err)
	}
	if asn, found := managed.Lookup(address); !found || asn != 64500 {
		t.Fatalf("failed refresh replaced valid table = (%d,%v)", asn, found)
	}
	write("10.0.0.0/8,64501\n", now.Add(-time.Minute))
	if err := managed.Refresh(); err != nil {
		t.Fatal(err)
	}
	if asn, found := managed.Lookup(address); !found || asn != 64501 {
		t.Fatalf("reloaded managed lookup = (%d,%v)", asn, found)
	}
	write("10.0.0.0/8,64502\n", now.Add(-25*time.Hour))
	if err := managed.Refresh(); !errors.Is(err, ErrASNTableStale) {
		t.Fatalf("stale refresh error = %v", err)
	}
	if asn, _ := managed.Lookup(address); asn != 64501 {
		t.Fatalf("stale refresh replaced valid table with ASN %d", asn)
	}
}

func TestASNTableRejectsMalformedDuplicateAndEmptyInput(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		"",
		"not-a-prefix,64500",
		"10.0.0.0/8,0",
		"10.0.0.1/8,64500\n10.0.0.0/8,64501\n",
		"10.0.0.0/8,64500,extra",
	} {
		if _, err := ParseASNTable(strings.NewReader(input)); !errors.Is(err, ErrASNTable) {
			t.Fatalf("input %q error = %v", input, err)
		}
	}
}
