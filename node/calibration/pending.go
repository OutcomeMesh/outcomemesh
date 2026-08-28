package calibration

import (
	"crypto/ed25519"
	"io"
	"os"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	pendingVersion               uint16 = 0
	MaximumWorkEventsPerInterval        = 100_000
	MaximumTieEventsPerInterval         = 100_000
	MaximumPendingBytes                 = 16 * 1024 * 1024
)

var pendingMagic = [8]byte{'O', 'M', 'T', 'E', 'L', 'P', 'N', '0'}

type WorkObservation struct {
	ID        types.Hash
	ClusterID types.Hash
}

type TieObservation struct {
	ID      types.Hash
	Adopted bool
}

type pendingState struct {
	Binding    Binding
	Sequence   uint64
	StartedAt  uint64
	EndedAt    uint64
	PreviousID types.Hash
	Work       []WorkObservation
	Ties       []TieObservation
}

func (pending pendingState) canonicalBytes() ([]byte, error) {
	if err := pending.validate(pending.Binding); err != nil {
		return nil, err
	}
	encoder := codec.NewEncoder(192 + len(pending.Work)*64 + len(pending.Ties)*33)
	encoder.Fixed(pendingMagic[:])
	encoder.U16(pendingVersion)
	encodeBinding(encoder, pending.Binding)
	encoder.U64(pending.Sequence)
	encoder.U64(pending.StartedAt)
	encoder.U64(pending.EndedAt)
	encoder.Fixed(pending.PreviousID[:])
	encoder.Uvarint(uint64(len(pending.Work)))
	for _, observation := range pending.Work {
		encoder.Fixed(observation.ID[:])
		encoder.Fixed(observation.ClusterID[:])
	}
	encoder.Uvarint(uint64(len(pending.Ties)))
	for _, observation := range pending.Ties {
		encoder.Fixed(observation.ID[:])
		if observation.Adopted {
			encoder.U8(1)
		} else {
			encoder.U8(0)
		}
	}
	encoded := encoder.Bytes()
	if len(encoded) > MaximumPendingBytes {
		return nil, ErrPending
	}
	return encoded, nil
}

func decodePending(input []byte, expected Binding) (pendingState, error) {
	if len(input) == 0 || len(input) > MaximumPendingBytes {
		return pendingState{}, ErrPending
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(pendingMagic))
	if err != nil || string(magic) != string(pendingMagic[:]) {
		return pendingState{}, ErrPending
	}
	version, err := decoder.U16()
	if err != nil || version != pendingVersion {
		return pendingState{}, ErrPending
	}
	binding, err := decodeBinding(decoder)
	if err != nil {
		return pendingState{}, err
	}
	result := pendingState{Binding: binding}
	if result.Sequence, err = decoder.U64(); err != nil {
		return pendingState{}, err
	}
	if result.StartedAt, err = decoder.U64(); err != nil {
		return pendingState{}, err
	}
	if result.EndedAt, err = decoder.U64(); err != nil {
		return pendingState{}, err
	}
	previous, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return pendingState{}, err
	}
	copy(result.PreviousID[:], previous)
	workCount, err := decoder.ListLength(MaximumWorkEventsPerInterval)
	if err != nil {
		return pendingState{}, err
	}
	result.Work = make([]WorkObservation, workCount)
	for index := range result.Work {
		identifier, err := decoder.Fixed(types.HashSize)
		if err != nil {
			return pendingState{}, err
		}
		copy(result.Work[index].ID[:], identifier)
		cluster, err := decoder.Fixed(types.HashSize)
		if err != nil {
			return pendingState{}, err
		}
		copy(result.Work[index].ClusterID[:], cluster)
	}
	tieCount, err := decoder.ListLength(MaximumTieEventsPerInterval)
	if err != nil {
		return pendingState{}, err
	}
	result.Ties = make([]TieObservation, tieCount)
	for index := range result.Ties {
		identifier, err := decoder.Fixed(types.HashSize)
		if err != nil {
			return pendingState{}, err
		}
		copy(result.Ties[index].ID[:], identifier)
		adopted, err := decoder.U8()
		if err != nil || adopted > 1 {
			return pendingState{}, ErrPending
		}
		result.Ties[index].Adopted = adopted == 1
	}
	if err := decoder.Finish(); err != nil {
		return pendingState{}, err
	}
	if err := result.validate(expected); err != nil {
		return pendingState{}, err
	}
	return result, nil
}

func (pending pendingState) validate(expected Binding) error {
	if !validBinding(expected) || pending.Binding != expected {
		return ErrBinding
	}
	if pending.Sequence == 0 || (pending.Sequence == 1) != pending.PreviousID.IsZero() {
		return ErrSequence
	}
	if pending.StartedAt == 0 || pending.EndedAt <= pending.StartedAt ||
		pending.EndedAt-pending.StartedAt != MaximumIntervalSeconds {
		return ErrInterval
	}
	if len(pending.Work) > MaximumWorkEventsPerInterval || len(pending.Ties) > MaximumTieEventsPerInterval {
		return ErrPending
	}
	clusters := make(map[types.Hash]struct{})
	for index, observation := range pending.Work {
		if observation.ID.IsZero() || observation.ClusterID.IsZero() ||
			(index > 0 && types.CompareHash(pending.Work[index-1].ID, observation.ID) >= 0) {
			return ErrObservation
		}
		clusters[observation.ClusterID] = struct{}{}
	}
	if len(clusters) > int(expected.ClusterComparisonBudget) {
		return ErrClusters
	}
	for index, observation := range pending.Ties {
		if observation.ID.IsZero() ||
			(index > 0 && types.CompareHash(pending.Ties[index-1].ID, observation.ID) >= 0) {
			return ErrObservation
		}
	}
	return nil
}

func (pending pendingState) record() (Record, error) {
	clusters := make(map[types.Hash]uint64)
	for _, observation := range pending.Work {
		value, err := checkedAdd(clusters[observation.ClusterID], 1)
		if err != nil {
			return Record{}, err
		}
		clusters[observation.ClusterID] = value
	}
	clusterWork := make([]ClusterWork, 0, len(clusters))
	for identifier, work := range clusters {
		clusterWork = append(clusterWork, ClusterWork{ID: identifier, Work: work})
	}
	sortClusterWork(clusterWork)
	var adoptions uint64
	for _, observation := range pending.Ties {
		if observation.Adopted {
			adoptions++
		}
	}
	return Record{
		Version: Version0, NetworkID: pending.Binding.NetworkID, GenesisID: pending.Binding.GenesisID,
		ActivationHeight: pending.Binding.ActivationHeight, ClusterPolicyID: pending.Binding.ClusterPolicyID,
		ClusterComparisonBudget: pending.Binding.ClusterComparisonBudget,
		Sequence:                pending.Sequence, StartedAt: pending.StartedAt, EndedAt: pending.EndedAt,
		PreviousID: pending.PreviousID, ControlledTieAdoptions: adoptions,
		ControlledTieTrials: uint64(len(pending.Ties)), ObservedWork: uint64(len(pending.Work)),
		Clusters: clusterWork,
	}, nil
}

func savePending(path string, pending pendingState) error {
	if path == "" {
		return ErrPending
	}
	encoded, err := pending.canonicalBytes()
	if err != nil {
		return err
	}
	return savePrivateFile(path, ".outcomemesh-telemetry-pending-*", encoded)
}

func loadPending(path string, expected Binding) (pendingState, error) {
	file, err := os.Open(path)
	if err != nil {
		return pendingState{}, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, MaximumPendingBytes+1))
	if err != nil {
		return pendingState{}, err
	}
	if len(encoded) > MaximumPendingBytes {
		return pendingState{}, ErrPending
	}
	return decodePending(encoded, expected)
}

func encodeBinding(encoder *codec.Encoder, binding Binding) {
	encoder.U32(binding.NetworkID)
	encoder.Fixed(binding.GenesisID[:])
	encoder.U64(binding.ActivationHeight)
	encoder.Fixed(binding.ClusterPolicyID[:])
	encoder.U32(binding.ClusterComparisonBudget)
	encoder.Fixed(binding.ObserverPublicKey[:])
}

func decodeBinding(decoder *codec.Decoder) (Binding, error) {
	var result Binding
	var err error
	if result.NetworkID, err = decoder.U32(); err != nil {
		return Binding{}, err
	}
	genesis, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Binding{}, err
	}
	copy(result.GenesisID[:], genesis)
	if result.ActivationHeight, err = decoder.U64(); err != nil {
		return Binding{}, err
	}
	policy, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Binding{}, err
	}
	copy(result.ClusterPolicyID[:], policy)
	if result.ClusterComparisonBudget, err = decoder.U32(); err != nil {
		return Binding{}, err
	}
	publicKey, err := decoder.Fixed(ed25519.PublicKeySize)
	if err != nil {
		return Binding{}, err
	}
	copy(result.ObserverPublicKey[:], publicKey)
	return result, nil
}
