package calibration

import (
	"crypto/ed25519"
	"errors"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	Version0               uint16 = 0
	MaximumClusters               = 4_096
	MaximumRecordBytes            = 192 * 1024
	MaximumIntervalSeconds uint64 = 60 * 60
	MaximumManifestRecords        = 10_000
)

const (
	recordSignatureDomain = "OMESH/testnet/calibration/record/signature/v0"
	recordIDDomain        = "OMESH/testnet/calibration/record/id/v0"
)

var (
	ErrVersion       = errors.New("unsupported calibration record version")
	ErrNetwork       = errors.New("invalid calibration network")
	ErrBinding       = errors.New("calibration binding mismatch")
	ErrSequence      = errors.New("invalid calibration sequence")
	ErrInterval      = errors.New("invalid calibration interval")
	ErrPrevious      = errors.New("invalid previous calibration record")
	ErrCounters      = errors.New("invalid calibration counters")
	ErrClusters      = errors.New("invalid calibration clusters")
	ErrPublicKey     = errors.New("invalid calibration public key")
	ErrSignature     = errors.New("invalid calibration signature")
	ErrRecordLimit   = errors.New("calibration record exceeds limit")
	ErrManifest      = errors.New("invalid calibration manifest")
	ErrManifestLimit = errors.New("calibration manifest exceeds limit")
)

type ClusterWork struct {
	ID   types.Hash
	Work uint64
}

// Record covers one contiguous telemetry interval. Counts are interval deltas,
// not cumulative counters. ClusterWork must account for ObservedWork exactly.
type Record struct {
	Version                 uint16
	NetworkID               uint32
	GenesisID               types.Hash
	ActivationHeight        uint64
	ClusterPolicyID         types.Hash
	ClusterComparisonBudget uint32
	Sequence                uint64
	StartedAt               uint64
	EndedAt                 uint64
	PreviousID              types.Hash
	ControlledTieAdoptions  uint64
	ControlledTieTrials     uint64
	ObservedWork            uint64
	Clusters                []ClusterWork
	ObserverPublicKey       [ed25519.PublicKeySize]byte
	Signature               [ed25519.SignatureSize]byte
}

// Binding is the independently trusted identity of one telemetry chain.
// ClusterPolicyID commits to the external classification rules and the budget
// caps the family of clusters compared when the largest is selected.
type Binding struct {
	NetworkID               uint32
	GenesisID               types.Hash
	ActivationHeight        uint64
	ClusterPolicyID         types.Hash
	ClusterComparisonBudget uint32
	ObserverPublicKey       [ed25519.PublicKeySize]byte
}

type Aggregate struct {
	Binding                Binding
	FirstRecordID          types.Hash
	LastRecordID           types.Hash
	RecordCount            uint64
	StartedAt              uint64
	EndedAt                uint64
	ControlledTieAdoptions uint64
	ControlledTieTrials    uint64
	ObservedWork           uint64
	LargestCoordinatedWork uint64
	Clusters               []ClusterWork
}

func Sign(privateKey ed25519.PrivateKey, record Record) (Record, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Record{}, ErrPublicKey
	}
	record.Clusters = append([]ClusterWork(nil), record.Clusters...)
	copy(record.ObserverPublicKey[:], privateKey.Public().(ed25519.PublicKey))
	record.Signature = [ed25519.SignatureSize]byte{}
	if err := record.validateShape(); err != nil {
		return Record{}, err
	}
	signature := ed25519.Sign(privateKey, record.signatureMessage())
	copy(record.Signature[:], signature)
	return record, nil
}

func (record Record) Validate() error {
	if err := record.validateShape(); err != nil {
		return err
	}
	if !ed25519.Verify(
		ed25519.PublicKey(record.ObserverPublicKey[:]),
		record.signatureMessage(),
		record.Signature[:],
	) {
		return ErrSignature
	}
	return nil
}

func (record Record) ID() (types.Hash, error) {
	if err := record.Validate(); err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(recordIDDomain, record.CanonicalBytes()), nil
}

func (record Record) Binding() Binding {
	return Binding{
		NetworkID: record.NetworkID, GenesisID: record.GenesisID,
		ActivationHeight: record.ActivationHeight, ClusterPolicyID: record.ClusterPolicyID,
		ClusterComparisonBudget: record.ClusterComparisonBudget,
		ObserverPublicKey:       record.ObserverPublicKey,
	}
}

func (record Record) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(320 + len(record.Clusters)*40)
	record.encodeUnsigned(encoder)
	encoder.Fixed(record.Signature[:])
	return encoder.Bytes()
}

func DecodeRecord(input []byte) (Record, error) {
	if len(input) == 0 || len(input) > MaximumRecordBytes {
		return Record{}, ErrRecordLimit
	}
	decoder := codec.NewDecoder(input)
	var result Record
	var err error
	if result.Version, err = decoder.U16(); err != nil {
		return Record{}, err
	}
	if result.Version != Version0 {
		return Record{}, ErrVersion
	}
	if result.NetworkID, err = decoder.U32(); err != nil {
		return Record{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return Record{}, decodeErr
	} else {
		copy(result.GenesisID[:], value)
	}
	if result.ActivationHeight, err = decoder.U64(); err != nil {
		return Record{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return Record{}, decodeErr
	} else {
		copy(result.ClusterPolicyID[:], value)
	}
	if result.ClusterComparisonBudget, err = decoder.U32(); err != nil {
		return Record{}, err
	}
	if result.Sequence, err = decoder.U64(); err != nil {
		return Record{}, err
	}
	if result.StartedAt, err = decoder.U64(); err != nil {
		return Record{}, err
	}
	if result.EndedAt, err = decoder.U64(); err != nil {
		return Record{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return Record{}, decodeErr
	} else {
		copy(result.PreviousID[:], value)
	}
	if result.ControlledTieAdoptions, err = decoder.U64(); err != nil {
		return Record{}, err
	}
	if result.ControlledTieTrials, err = decoder.U64(); err != nil {
		return Record{}, err
	}
	if result.ObservedWork, err = decoder.U64(); err != nil {
		return Record{}, err
	}
	count, err := decoder.ListLength(MaximumClusters)
	if err != nil {
		return Record{}, err
	}
	result.Clusters = make([]ClusterWork, count)
	for index := range result.Clusters {
		value, err := decoder.Fixed(types.HashSize)
		if err != nil {
			return Record{}, err
		}
		copy(result.Clusters[index].ID[:], value)
		if result.Clusters[index].Work, err = decoder.U64(); err != nil {
			return Record{}, err
		}
	}
	publicKey, err := decoder.Fixed(ed25519.PublicKeySize)
	if err != nil {
		return Record{}, err
	}
	copy(result.ObserverPublicKey[:], publicKey)
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

func ValidateManifest(records []Record, expected Binding) (Aggregate, error) {
	if len(records) == 0 {
		return Aggregate{}, ErrManifest
	}
	if len(records) > MaximumManifestRecords {
		return Aggregate{}, ErrManifestLimit
	}
	if !validBinding(expected) {
		return Aggregate{}, ErrBinding
	}
	clusterTotals := make(map[types.Hash]uint64)
	result := Aggregate{Binding: expected, RecordCount: uint64(len(records))}
	var previousID types.Hash
	for index, record := range records {
		if err := record.Validate(); err != nil {
			return Aggregate{}, err
		}
		if record.Binding() != expected {
			return Aggregate{}, ErrBinding
		}
		if record.Sequence != uint64(index)+1 {
			return Aggregate{}, ErrSequence
		}
		if index == 0 {
			if !record.PreviousID.IsZero() {
				return Aggregate{}, ErrPrevious
			}
			result.StartedAt = record.StartedAt
		} else if record.PreviousID != previousID {
			return Aggregate{}, ErrPrevious
		} else if record.StartedAt != records[index-1].EndedAt {
			return Aggregate{}, ErrInterval
		}
		identifier, err := record.ID()
		if err != nil {
			return Aggregate{}, err
		}
		if index == 0 {
			result.FirstRecordID = identifier
		}
		previousID = identifier
		result.LastRecordID = identifier
		result.EndedAt = record.EndedAt
		if result.ControlledTieAdoptions, err = checkedAdd(result.ControlledTieAdoptions, record.ControlledTieAdoptions); err != nil {
			return Aggregate{}, err
		}
		if result.ControlledTieTrials, err = checkedAdd(result.ControlledTieTrials, record.ControlledTieTrials); err != nil {
			return Aggregate{}, err
		}
		if result.ObservedWork, err = checkedAdd(result.ObservedWork, record.ObservedWork); err != nil {
			return Aggregate{}, err
		}
		for _, cluster := range record.Clusters {
			if _, known := clusterTotals[cluster.ID]; !known &&
				len(clusterTotals) >= int(expected.ClusterComparisonBudget) {
				return Aggregate{}, ErrClusters
			}
			total, err := checkedAdd(clusterTotals[cluster.ID], cluster.Work)
			if err != nil {
				return Aggregate{}, err
			}
			clusterTotals[cluster.ID] = total
		}
	}
	result.Clusters = make([]ClusterWork, 0, len(clusterTotals))
	for identifier, work := range clusterTotals {
		result.Clusters = append(result.Clusters, ClusterWork{ID: identifier, Work: work})
		if work > result.LargestCoordinatedWork {
			result.LargestCoordinatedWork = work
		}
	}
	sort.Slice(result.Clusters, func(left, right int) bool {
		return types.CompareHash(result.Clusters[left].ID, result.Clusters[right].ID) < 0
	})
	return result, nil
}

func (record Record) signatureMessage() []byte {
	encoder := codec.NewEncoder(256 + len(record.Clusters)*40)
	record.encodeUnsigned(encoder)
	hash := types.DomainHash(recordSignatureDomain, encoder.Bytes())
	return hash[:]
}

func (record Record) encodeUnsigned(encoder *codec.Encoder) {
	encoder.U16(record.Version)
	encoder.U32(record.NetworkID)
	encoder.Fixed(record.GenesisID[:])
	encoder.U64(record.ActivationHeight)
	encoder.Fixed(record.ClusterPolicyID[:])
	encoder.U32(record.ClusterComparisonBudget)
	encoder.U64(record.Sequence)
	encoder.U64(record.StartedAt)
	encoder.U64(record.EndedAt)
	encoder.Fixed(record.PreviousID[:])
	encoder.U64(record.ControlledTieAdoptions)
	encoder.U64(record.ControlledTieTrials)
	encoder.U64(record.ObservedWork)
	encoder.Uvarint(uint64(len(record.Clusters)))
	for _, cluster := range record.Clusters {
		encoder.Fixed(cluster.ID[:])
		encoder.U64(cluster.Work)
	}
	encoder.Fixed(record.ObserverPublicKey[:])
}

func (record Record) validateShape() error {
	if record.Version != Version0 {
		return ErrVersion
	}
	if record.NetworkID == 0 || record.GenesisID.IsZero() || record.ActivationHeight == 0 {
		return ErrNetwork
	}
	if record.ClusterPolicyID.IsZero() || record.ClusterComparisonBudget == 0 ||
		record.ClusterComparisonBudget > MaximumClusters {
		return ErrBinding
	}
	if record.Sequence == 0 || (record.Sequence == 1) != record.PreviousID.IsZero() {
		return ErrSequence
	}
	if record.StartedAt == 0 || record.EndedAt <= record.StartedAt ||
		record.EndedAt-record.StartedAt > MaximumIntervalSeconds {
		return ErrInterval
	}
	if record.ControlledTieAdoptions > record.ControlledTieTrials {
		return ErrCounters
	}
	if len(record.Clusters) > int(record.ClusterComparisonBudget) {
		return ErrClusters
	}
	var accounted uint64
	for index, cluster := range record.Clusters {
		if cluster.ID.IsZero() || cluster.Work == 0 ||
			(index > 0 && types.CompareHash(record.Clusters[index-1].ID, cluster.ID) >= 0) {
			return ErrClusters
		}
		var err error
		accounted, err = checkedAdd(accounted, cluster.Work)
		if err != nil {
			return err
		}
	}
	if accounted != record.ObservedWork {
		return ErrCounters
	}
	return nil
}

func validBinding(binding Binding) bool {
	return binding.NetworkID != 0 && !binding.GenesisID.IsZero() && binding.ActivationHeight != 0 &&
		!binding.ClusterPolicyID.IsZero() && binding.ClusterComparisonBudget != 0 &&
		binding.ClusterComparisonBudget <= MaximumClusters && binding.ObserverPublicKey != [ed25519.PublicKeySize]byte{}
}

func checkedAdd(left, right uint64) (uint64, error) {
	result := left + right
	if result < left {
		return 0, ErrCounters
	}
	return result, nil
}
