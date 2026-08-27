package peers

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	reputationVersionV0   uint16 = 0
	reputationVersion     uint16 = 1
	MaxReputationBytes           = 2 << 20
	maxStoredDialFailures uint64 = 64
)

var (
	reputationMagic    = [8]byte{'O', 'M', 'R', 'E', 'P', 'U', 'T', '0'}
	ErrReputationStore = errors.New("invalid persisted peer reputation")
)

// CanonicalBytes returns local-policy state only. Active sessions, dial
// reservations, and byte windows are deliberately not persisted.
func (manager *Manager) CanonicalBytes() ([]byte, error) {
	if manager == nil {
		return nil, ErrReputationStore
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	now := manager.currentTime()
	manager.prune(now)
	ids := make([]types.Hash, 0, len(manager.records))
	for id, entry := range manager.records {
		manager.decayScore(entry, now)
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return types.CompareHash(ids[left], ids[right]) < 0 })
	encoder := codec.NewEncoder(16 + len(ids)*160)
	encoder.Fixed(reputationMagic[:])
	encoder.U16(reputationVersion)
	encoder.Uvarint(uint64(len(ids)))
	for _, id := range ids {
		entry := manager.records[id]
		lastSeen, err := persistedUnix(entry.LastSeen)
		if err != nil {
			return nil, err
		}
		bannedUntil, err := persistedUnix(entry.BannedUntil)
		if err != nil {
			return nil, err
		}
		nextDial, err := persistedUnix(entry.NextDial)
		if err != nil {
			return nil, err
		}
		lastScoreUpdate, err := persistedUnix(entry.lastScoreUpdate)
		if err != nil {
			return nil, err
		}
		failures := uint64(entry.DialFailures)
		if failures > maxStoredDialFailures {
			failures = maxStoredDialFailures
		}
		encoder.Fixed(id[:])
		encoder.U64(encodeScore(entry.Score))
		encoder.U64(lastSeen)
		encoder.U64(bannedUntil)
		encoder.U64(failures)
		encoder.U64(nextDial)
		encoder.U64(lastScoreUpdate)
		encoder.U64(entry.ValidEvents)
		encoder.U64(entry.UsefulSyncs)
		encoder.U64(entry.StaleEvents)
		encoder.U64(entry.InvalidEvents)
		encoder.U64(entry.Timeouts)
		encoder.U64(entry.LatencyMillis)
		encoder.U64(entry.LatencySamples)
	}
	result := encoder.Bytes()
	if len(result) > MaxReputationBytes {
		return nil, ErrReputationStore
	}
	return result, nil
}

func DecodeManager(input []byte, policy Policy, now func() time.Time) (*Manager, error) {
	if len(input) == 0 || len(input) > MaxReputationBytes {
		return nil, ErrReputationStore
	}
	manager, err := New(policy, now)
	if err != nil {
		return nil, err
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(reputationMagic))
	if err != nil || string(magic) != string(reputationMagic[:]) {
		return nil, ErrReputationStore
	}
	version, err := decoder.U16()
	if err != nil || (version != reputationVersionV0 && version != reputationVersion) {
		return nil, ErrReputationStore
	}
	count, err := decoder.ListLength(uint64(manager.policy.MaxTrackedPeers))
	if err != nil {
		return nil, err
	}
	current := manager.currentTime()
	var previousID types.Hash
	hasPrevious := false
	for range count {
		encodedID, err := decoder.Fixed(types.HashSize)
		if err != nil {
			return nil, err
		}
		var id types.Hash
		copy(id[:], encodedID)
		if id.IsZero() || manager.records[id] != nil ||
			(hasPrevious && types.CompareHash(previousID, id) >= 0) {
			return nil, ErrReputationStore
		}
		previousID = id
		hasPrevious = true
		encodedScore, err := decoder.U64()
		if err != nil {
			return nil, err
		}
		score, ok := decodeScore(encodedScore)
		if !ok || score < manager.policy.BanThreshold || score > manager.policy.MaxScore {
			return nil, ErrReputationStore
		}
		lastSeenUnix, err := decoder.U64()
		if err != nil {
			return nil, err
		}
		bannedUnix, err := decoder.U64()
		if err != nil {
			return nil, err
		}
		failures, err := decoder.U64()
		if err != nil || failures > maxStoredDialFailures {
			return nil, ErrReputationStore
		}
		nextDialUnix, err := decoder.U64()
		if err != nil {
			return nil, err
		}
		lastScoreUnix, err := decoder.U64()
		if err != nil {
			return nil, err
		}
		lastSeen, ok := decodedUnix(lastSeenUnix, false)
		if !ok {
			return nil, ErrReputationStore
		}
		bannedUntil, ok := decodedUnix(bannedUnix, true)
		if !ok {
			return nil, ErrReputationStore
		}
		nextDial, ok := decodedUnix(nextDialUnix, true)
		if !ok {
			return nil, ErrReputationStore
		}
		lastScoreUpdate, ok := decodedUnix(lastScoreUnix, false)
		if !ok {
			return nil, ErrReputationStore
		}
		if lastSeen.After(current) {
			lastSeen = current
		}
		if lastScoreUpdate.After(current) {
			lastScoreUpdate = current
		}
		if bannedUntil.After(current.Add(manager.policy.BanDuration)) {
			bannedUntil = current.Add(manager.policy.BanDuration)
		}
		if nextDial.After(current.Add(manager.policy.DialMaxBackoff)) {
			nextDial = current.Add(manager.policy.DialMaxBackoff)
		}
		entry := &record{
			Snapshot: Snapshot{
				Score: score, LastSeen: lastSeen, BannedUntil: bannedUntil,
				DialFailures: int(failures), NextDial: nextDial,
			},
			inboundWindowStart: current, outboundWindowStart: current, lastScoreUpdate: lastScoreUpdate,
		}
		entry.ValidEvents, err = decoder.U64()
		if err != nil {
			return nil, err
		}
		entry.UsefulSyncs, err = decoder.U64()
		if err != nil {
			return nil, err
		}
		entry.StaleEvents, err = decoder.U64()
		if err != nil {
			return nil, err
		}
		entry.InvalidEvents, err = decoder.U64()
		if err != nil {
			return nil, err
		}
		entry.Timeouts, err = decoder.U64()
		if err != nil {
			return nil, err
		}
		if version >= reputationVersion {
			entry.LatencyMillis, err = decoder.U64()
			if err != nil {
				return nil, err
			}
			entry.LatencySamples, err = decoder.U64()
			if err != nil {
				return nil, err
			}
			maxMilliseconds := uint64(MaxObservedLatency / time.Millisecond)
			if entry.LatencyMillis > maxMilliseconds ||
				(entry.LatencySamples == 0) != (entry.LatencyMillis == 0) {
				return nil, ErrReputationStore
			}
		}
		if !current.Before(lastSeen.Add(manager.policy.Retention)) &&
			!current.Before(bannedUntil) && !current.Before(nextDial) {
			continue
		}
		manager.decayScore(entry, current)
		manager.records[id] = entry
	}
	if err := decoder.Finish(); err != nil {
		return nil, err
	}
	return manager, nil
}

func SaveFile(path string, manager *Manager) error {
	if path == "" {
		return ErrReputationStore
	}
	encoded, err := manager.CanonicalBytes()
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".outcomemesh-reputation-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}

func LoadFile(path string, policy Policy, now func() time.Time) (*Manager, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, MaxReputationBytes+1))
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxReputationBytes {
		return nil, ErrReputationStore
	}
	return DecodeManager(encoded, policy, now)
}

func persistedUnix(value time.Time) (uint64, error) {
	if value.IsZero() {
		return 0, nil
	}
	unix := value.Unix()
	if unix <= 0 {
		return 0, ErrReputationStore
	}
	return uint64(unix), nil
}

func decodedUnix(value uint64, allowZero bool) (time.Time, bool) {
	if value == 0 {
		return time.Time{}, allowZero
	}
	if value > uint64(^uint64(0)>>1) {
		return time.Time{}, false
	}
	return time.Unix(int64(value), 0), true
}

func encodeScore(value int) uint64 {
	if value >= 0 {
		return uint64(value) << 1
	}
	return uint64(-(value+1))<<1 | 1
}

func decodeScore(value uint64) (int, bool) {
	magnitude := value >> 1
	if magnitude > ScoreMagnitudeLimit {
		return 0, false
	}
	if value&1 == 0 {
		return int(magnitude), true
	}
	return -int(magnitude) - 1, true
}
