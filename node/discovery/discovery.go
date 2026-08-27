package discovery

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"

	libpeer "github.com/libp2p/go-libp2p/core/peer"
	multiaddr "github.com/multiformats/go-multiaddr"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	Version0        uint16 = 0
	MaxAddresses           = 8
	MaxAddressBytes        = 128
	MaxRecordBytes         = 2_048
	MaxBookRecords         = 4_096
	MaxLifetime     uint64 = 24 * 60 * 60
)

var (
	ErrVersion      = errors.New("unsupported peer advertisement version")
	ErrNetwork      = errors.New("peer advertisement belongs to another network")
	ErrSequence     = errors.New("peer advertisement sequence is zero")
	ErrExpired      = errors.New("peer advertisement is expired")
	ErrLifetime     = errors.New("peer advertisement lifetime exceeds limit")
	ErrPublicKey    = errors.New("invalid peer advertisement public key")
	ErrSignature    = errors.New("invalid peer advertisement signature")
	ErrAddress      = errors.New("invalid peer advertisement address")
	ErrAddressOrder = errors.New("peer advertisement addresses are not canonical")
	ErrStale        = errors.New("stale peer advertisement sequence")
	ErrCapacity     = errors.New("peer address book capacity reached")
	ErrDiversity    = errors.New("peer address diversity bucket is full")
	ErrPolicy       = errors.New("invalid peer address book policy")
)

type Record struct {
	Version   uint16
	NetworkID uint32
	Sequence  uint64
	ExpiresAt uint64
	PublicKey [ed25519.PublicKeySize]byte
	Addresses []string
	Signature [ed25519.SignatureSize]byte
}

func Sign(privateKey ed25519.PrivateKey, networkID uint32, sequence, expiresAt uint64, addresses []string) (Record, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Record{}, ErrPublicKey
	}
	if networkID == 0 {
		return Record{}, ErrNetwork
	}
	if sequence == 0 {
		return Record{}, ErrSequence
	}
	if expiresAt == 0 {
		return Record{}, ErrExpired
	}
	result := Record{
		Version:   Version0,
		NetworkID: networkID,
		Sequence:  sequence,
		ExpiresAt: expiresAt,
	}
	copy(result.PublicKey[:], privateKey.Public().(ed25519.PublicKey))
	canonical, err := canonicalAddresses(addresses)
	if err != nil {
		return Record{}, err
	}
	result.Addresses = canonical
	if err := result.validateAddressIdentities(); err != nil {
		return Record{}, err
	}
	signature := ed25519.Sign(privateKey, result.signatureMessage())
	copy(result.Signature[:], signature)
	return result, nil
}

func (record Record) PeerID() (types.Hash, error) {
	publicKey := ed25519.PublicKey(record.PublicKey[:])
	if len(publicKey) != ed25519.PublicKeySize {
		return types.Hash{}, ErrPublicKey
	}
	return types.DomainHash("OMESH/p2p/ed25519/v0", publicKey), nil
}

func (record Record) Validate(now uint64) error {
	if record.Version != Version0 {
		return ErrVersion
	}
	if record.NetworkID == 0 {
		return ErrNetwork
	}
	if record.Sequence == 0 {
		return ErrSequence
	}
	if record.ExpiresAt <= now {
		return ErrExpired
	}
	if record.ExpiresAt-now > MaxLifetime {
		return ErrLifetime
	}
	canonical, err := canonicalAddresses(record.Addresses)
	if err != nil {
		return err
	}
	if len(canonical) != len(record.Addresses) {
		return ErrAddressOrder
	}
	for index := range canonical {
		if canonical[index] != record.Addresses[index] {
			return ErrAddressOrder
		}
	}
	if err := record.validateAddressIdentities(); err != nil {
		return err
	}
	publicKey := ed25519.PublicKey(record.PublicKey[:])
	if !ed25519.Verify(publicKey, record.signatureMessage(), record.Signature[:]) {
		return ErrSignature
	}
	return nil
}

func (record Record) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(256)
	record.encodeUnsigned(encoder)
	encoder.Fixed(record.Signature[:])
	return encoder.Bytes()
}

func Decode(input []byte) (Record, error) {
	if len(input) > MaxRecordBytes {
		return Record{}, ErrAddress
	}
	decoder := codec.NewDecoder(input)
	var result Record
	var err error
	result.Version, err = decoder.U16()
	if err != nil {
		return Record{}, err
	}
	result.NetworkID, err = decoder.U32()
	if err != nil {
		return Record{}, err
	}
	result.Sequence, err = decoder.U64()
	if err != nil {
		return Record{}, err
	}
	result.ExpiresAt, err = decoder.U64()
	if err != nil {
		return Record{}, err
	}
	publicKey, err := decoder.Fixed(ed25519.PublicKeySize)
	if err != nil {
		return Record{}, err
	}
	copy(result.PublicKey[:], publicKey)
	count, err := decoder.ListLength(MaxAddresses)
	if err != nil {
		return Record{}, err
	}
	result.Addresses = make([]string, count)
	for index := range result.Addresses {
		encoded, err := decoder.BytesField(MaxAddressBytes)
		if err != nil {
			return Record{}, err
		}
		result.Addresses[index] = string(encoded)
	}
	signature, err := decoder.Fixed(ed25519.SignatureSize)
	if err != nil {
		return Record{}, err
	}
	copy(result.Signature[:], signature)
	if err := decoder.Finish(); err != nil {
		return Record{}, err
	}
	return result, nil
}

func (record Record) signatureMessage() []byte {
	encoder := codec.NewEncoder(256)
	record.encodeUnsigned(encoder)
	hash := types.DomainHash("OMESH/p2p/advertisement/v0", encoder.Bytes())
	return hash[:]
}

func (record Record) encodeUnsigned(encoder *codec.Encoder) {
	encoder.U16(record.Version)
	encoder.U32(record.NetworkID)
	encoder.U64(record.Sequence)
	encoder.U64(record.ExpiresAt)
	encoder.Fixed(record.PublicKey[:])
	encoder.Uvarint(uint64(len(record.Addresses)))
	for _, address := range record.Addresses {
		encoder.BytesField([]byte(address))
	}
}

type Book struct {
	mu            sync.Mutex
	networkID     uint32
	maxRecords    int
	maxPerNetwork int
	records       map[types.Hash]Record
}

type Policy struct {
	MaxRecords    int
	MaxPerNetwork int
}

func DefaultPolicy() Policy {
	return Policy{MaxRecords: 4_096, MaxPerNetwork: 64}
}

func NewBook(networkID uint32, maxRecords int) (*Book, error) {
	return NewBookWithPolicy(networkID, Policy{MaxRecords: maxRecords, MaxPerNetwork: maxRecords})
}

func NewBookWithPolicy(networkID uint32, policy Policy) (*Book, error) {
	if networkID == 0 || policy.MaxRecords <= 0 || policy.MaxRecords > MaxBookRecords ||
		policy.MaxPerNetwork <= 0 || policy.MaxPerNetwork > policy.MaxRecords {
		return nil, ErrPolicy
	}
	return &Book{
		networkID: networkID, maxRecords: policy.MaxRecords, maxPerNetwork: policy.MaxPerNetwork,
		records: make(map[types.Hash]Record),
	}, nil
}

func (book *Book) Add(record Record, now uint64) error {
	return book.AddBatch([]Record{record}, now)
}

// AddBatch validates and applies an entire response atomically. A malformed,
// stale, foreign-network, or over-capacity batch cannot leave a partial update.
func (book *Book) AddBatch(records []Record, now uint64) error {
	return book.addBatch(records, now, false)
}

// MergeBatch is the network-gossip variant of AddBatch: an exact byte-for-byte
// replay is an idempotent no-op, while an equal-sequence mutation or any older
// sequence remains stale. The whole batch is still admitted atomically.
func (book *Book) MergeBatch(records []Record, now uint64) error {
	return book.addBatch(records, now, true)
}

func (book *Book) addBatch(records []Record, now uint64, allowExactReplay bool) error {
	type identified struct {
		id     types.Hash
		record Record
	}
	identifiedRecords := make([]identified, len(records))
	for index, record := range records {
		if err := record.Validate(now); err != nil {
			return err
		}
		if record.NetworkID != book.networkID {
			return ErrNetwork
		}
		id, err := record.PeerID()
		if err != nil {
			return err
		}
		identifiedRecords[index] = identified{id: id, record: cloneRecord(record)}
	}
	book.mu.Lock()
	defer book.mu.Unlock()
	book.prune(now)
	staged := make(map[types.Hash]Record, len(book.records)+len(records))
	for id, record := range book.records {
		staged[id] = record
	}
	for _, candidate := range identifiedRecords {
		if existing, exists := staged[candidate.id]; exists {
			if candidate.record.Sequence == existing.Sequence && allowExactReplay &&
				bytes.Equal(candidate.record.CanonicalBytes(), existing.CanonicalBytes()) {
				continue
			}
			if candidate.record.Sequence <= existing.Sequence {
				return ErrStale
			}
		} else if len(staged) >= book.maxRecords {
			return ErrCapacity
		}
		staged[candidate.id] = candidate.record
	}
	if err := book.validateDiversity(staged); err != nil {
		return err
	}
	book.records = staged
	return nil
}

func (book *Book) validateDiversity(records map[types.Hash]Record) error {
	counts := make(map[string]int)
	for _, record := range records {
		buckets, err := diversityBuckets(record)
		if err != nil {
			return err
		}
		for bucket := range buckets {
			counts[bucket]++
			if counts[bucket] > book.maxPerNetwork {
				return ErrDiversity
			}
		}
	}
	return nil
}

func diversityBuckets(record Record) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(record.Addresses))
	for _, address := range record.Addresses {
		var ip net.IP
		if len(address) > 0 && address[0] == '/' {
			parsed, err := multiaddr.NewMultiaddr(address)
			if err != nil {
				return nil, ErrAddress
			}
			ipText, err := parsed.ValueForProtocol(multiaddr.P_IP4)
			if err != nil {
				ipText, err = parsed.ValueForProtocol(multiaddr.P_IP6)
			}
			if err != nil {
				return nil, ErrAddress
			}
			ip = net.ParseIP(ipText)
		} else {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, ErrAddress
			}
			ip = net.ParseIP(host)
		}
		if ip == nil {
			return nil, ErrAddress
		}
		if ipv4 := ip.To4(); ipv4 != nil {
			result[fmt.Sprintf("4:%02x%02x", ipv4[0], ipv4[1])] = struct{}{}
			continue
		}
		ipv6 := ip.To16()
		if ipv6 == nil {
			return nil, ErrAddress
		}
		result[fmt.Sprintf("6:%02x%02x%02x%02x", ipv6[0], ipv6[1], ipv6[2], ipv6[3])] = struct{}{}
	}
	return result, nil
}

func (book *Book) List(now uint64, limit int) []Record {
	if limit <= 0 {
		return nil
	}
	book.mu.Lock()
	defer book.mu.Unlock()
	book.prune(now)
	ids := make([]types.Hash, 0, len(book.records))
	for id := range book.records {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return types.CompareHash(ids[left], ids[right]) < 0 })
	if len(ids) > limit {
		ids = ids[:limit]
	}
	result := make([]Record, len(ids))
	for index, id := range ids {
		result[index] = cloneRecord(book.records[id])
	}
	return result
}

func (book *Book) Len(now uint64) int {
	book.mu.Lock()
	defer book.mu.Unlock()
	book.prune(now)
	return len(book.records)
}

// NextSequence makes restart publication monotonic even if the wall clock
// moves backwards relative to the last persisted self-advertisement.
func (book *Book) NextSequence(id types.Hash, suggested uint64) (uint64, error) {
	if book == nil || id.IsZero() || suggested == 0 {
		return 0, ErrSequence
	}
	book.mu.Lock()
	defer book.mu.Unlock()
	existing, exists := book.records[id]
	if !exists || suggested > existing.Sequence {
		return suggested, nil
	}
	if existing.Sequence == ^uint64(0) {
		return 0, ErrSequence
	}
	return existing.Sequence + 1, nil
}

func (book *Book) prune(now uint64) {
	for id, record := range book.records {
		if record.ExpiresAt <= now {
			delete(book.records, id)
		}
	}
}

func canonicalAddresses(addresses []string) ([]string, error) {
	if len(addresses) == 0 || len(addresses) > MaxAddresses {
		return nil, ErrAddress
	}
	result := make([]string, len(addresses))
	for index, address := range addresses {
		if len(address) == 0 || len(address) > MaxAddressBytes {
			return nil, ErrAddress
		}
		if address[0] == '/' {
			canonical, err := canonicalQUICAddress(address)
			if err != nil {
				return nil, err
			}
			result[index] = canonical
			continue
		}
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrAddress, err)
		}
		ip := net.ParseIP(host)
		port, err := strconv.ParseUint(portText, 10, 16)
		if ip == nil || err != nil || port == 0 {
			return nil, ErrAddress
		}
		result[index] = net.JoinHostPort(ip.String(), strconv.FormatUint(port, 10))
	}
	sort.Strings(result)
	for index := 1; index < len(result); index++ {
		if result[index] == result[index-1] {
			return nil, ErrAddress
		}
	}
	return result, nil
}

func canonicalQUICAddress(address string) (string, error) {
	parsed, err := multiaddr.NewMultiaddr(address)
	if err != nil {
		return "", ErrAddress
	}
	protocols := parsed.Protocols()
	if len(protocols) != 4 ||
		(protocols[0].Code != multiaddr.P_IP4 && protocols[0].Code != multiaddr.P_IP6) ||
		protocols[1].Code != multiaddr.P_UDP || protocols[2].Code != multiaddr.P_QUIC_V1 || protocols[3].Code != multiaddr.P_P2P {
		return "", ErrAddress
	}
	ipText, err := parsed.ValueForProtocol(protocols[0].Code)
	if err != nil || net.ParseIP(ipText) == nil {
		return "", ErrAddress
	}
	portText, err := parsed.ValueForProtocol(multiaddr.P_UDP)
	if err != nil {
		return "", ErrAddress
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", ErrAddress
	}
	return parsed.String(), nil
}

func (record Record) validateAddressIdentities() error {
	for _, address := range record.Addresses {
		if len(address) == 0 || address[0] != '/' {
			continue
		}
		info, err := libpeer.AddrInfoFromString(address)
		if err != nil {
			return ErrAddress
		}
		publicKey, err := info.ID.ExtractPublicKey()
		if err != nil {
			return ErrAddress
		}
		raw, err := publicKey.Raw()
		if err != nil || !bytes.Equal(raw, record.PublicKey[:]) {
			return ErrAddress
		}
	}
	return nil
}

func cloneRecord(record Record) Record {
	record.Addresses = append([]string(nil), record.Addresses...)
	return record
}
