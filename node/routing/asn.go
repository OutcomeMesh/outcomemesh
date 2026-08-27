package routing

import (
	"bufio"
	"errors"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MaxASNPrefixes   = 65_536
	MaxASNTableBytes = 16 << 20
	MaxASNTableAge   = 30 * 24 * time.Hour
	maxASNFutureSkew = 5 * time.Minute
)

var (
	ErrASNTable      = errors.New("invalid ASN prefix table")
	ErrASNTableStale = errors.New("ASN prefix table is stale")
)

// ASNResolver maps a literal peer IP to an autonomous-system number. Discovery
// remains DNS-free; implementations are local policy inputs, never consensus
// or signed-record fields.
type ASNResolver interface {
	Lookup(netip.Addr) (uint32, bool)
}

type asnPrefix struct {
	prefix netip.Prefix
	asn    uint32
}

// ASNTable is an immutable, longest-prefix-match table loaded from local
// operator data. Each non-comment line is "CIDR,ASN".
type ASNTable struct {
	entries []asnPrefix
}

// ManagedASNTable atomically reloads an operator-owned local table. A failed
// parse never replaces the last valid table, but Refresh still returns the
// failure so a scheduler can stop before dialing with stale policy.
type ManagedASNTable struct {
	mu       sync.RWMutex
	path     string
	maxAge   time.Duration
	now      func() time.Time
	table    *ASNTable
	modTime  time.Time
	fileSize int64
}

func NewManagedASNTable(path string, maxAge time.Duration, now func() time.Time) (*ManagedASNTable, error) {
	if path == "" || maxAge <= 0 || maxAge > MaxASNTableAge {
		return nil, ErrASNTable
	}
	if now == nil {
		now = time.Now
	}
	managed := &ManagedASNTable{path: path, maxAge: maxAge, now: now}
	if err := managed.Refresh(); err != nil {
		return nil, err
	}
	return managed, nil
}

func (managed *ManagedASNTable) Refresh() error {
	if managed == nil {
		return ErrASNTable
	}
	file, err := os.Open(managed.path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxASNTableBytes {
		return ErrASNTable
	}
	now := managed.now()
	if info.ModTime().After(now.Add(maxASNFutureSkew)) {
		return ErrASNTable
	}
	if now.After(info.ModTime().Add(managed.maxAge)) {
		return ErrASNTableStale
	}
	managed.mu.RLock()
	unchanged := managed.table != nil && managed.fileSize == info.Size() && managed.modTime.Equal(info.ModTime())
	managed.mu.RUnlock()
	if unchanged {
		return nil
	}
	table, err := ParseASNTable(file)
	if err != nil {
		return err
	}
	managed.mu.Lock()
	managed.table = table
	managed.modTime = info.ModTime()
	managed.fileSize = info.Size()
	managed.mu.Unlock()
	return nil
}

func (managed *ManagedASNTable) Lookup(address netip.Addr) (uint32, bool) {
	if managed == nil {
		return 0, false
	}
	managed.mu.RLock()
	table := managed.table
	managed.mu.RUnlock()
	return table.Lookup(address)
}

func ParseASNTable(reader io.Reader) (*ASNTable, error) {
	if reader == nil {
		return nil, ErrASNTable
	}
	limited := &io.LimitedReader{R: reader, N: MaxASNTableBytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	entries := make([]asnPrefix, 0)
	seen := make(map[netip.Prefix]struct{})
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) != 2 {
			return nil, ErrASNTable
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, ErrASNTable
		}
		prefix = prefix.Masked()
		parsedASN, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
		if err != nil || parsedASN == 0 {
			return nil, ErrASNTable
		}
		if _, exists := seen[prefix]; exists || len(entries) >= MaxASNPrefixes {
			return nil, ErrASNTable
		}
		seen[prefix] = struct{}{}
		entries = append(entries, asnPrefix{prefix: prefix, asn: uint32(parsedASN)})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if limited.N == 0 {
		return nil, ErrASNTable
	}
	if len(entries) == 0 {
		return nil, ErrASNTable
	}
	sort.Slice(entries, func(left, right int) bool {
		if entries[left].prefix.Bits() != entries[right].prefix.Bits() {
			return entries[left].prefix.Bits() > entries[right].prefix.Bits()
		}
		return entries[left].prefix.String() < entries[right].prefix.String()
	})
	return &ASNTable{entries: entries}, nil
}

func (table *ASNTable) Lookup(address netip.Addr) (uint32, bool) {
	if table == nil || !address.IsValid() {
		return 0, false
	}
	address = address.Unmap()
	for _, entry := range table.entries {
		if entry.prefix.Addr().Is4() != address.Is4() {
			continue
		}
		if entry.prefix.Contains(address) {
			return entry.asn, true
		}
	}
	return 0, false
}
