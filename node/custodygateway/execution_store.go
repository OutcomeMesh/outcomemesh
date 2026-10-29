//go:build linux || darwin

package custodygateway

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/outcomemesh/outcomemesh/core/types"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func (o *Owner) executionPath(names ...string) string {
	return filepath.Join(append([]string{o.root, "execution"}, names...)...)
}
func (o *Owner) checkExecution() error {
	if o.execution == nil {
		return nil
	}
	r := o.execution
	for _, path := range []string{o.executionPath(), o.executionPath("jobs"), o.executionPath("calls")} {
		if _, e := PlacementID(path, true); e != nil {
			return e
		}
	}
	raw, e := privateRead(o.executionPath("config"), wire.MaximumDeploymentBytes*4)
	if e != nil || types.DomainHash(wire.Domain+"execution-config/id", raw) != r.configHash {
		return ErrExecution
	}
	b, e := privateRead(o.executionPath("ready"), 32)
	if e != nil || !bytes.Equal(b, r.configHash[:]) {
		return ErrExecution
	}
	did, _ := r.deployment.ID()
	b, e = privateRead(filepath.Join(o.root, "deployment-choice"), 32)
	if e != nil || !bytes.Equal(b, did[:]) {
		return ErrExecution
	}
	for name, key := range map[string][]byte{"replica.key": r.keys.Replica, "control.key": r.keys.Control, "authority.key": r.keys.Authority} {
		if len(key) == 0 {
			continue
		}
		b, e := privateRead(o.executionPath(name), 64)
		same := e == nil && bytes.Equal(b, key)
		clear(b)
		if !same {
			return ErrExecution
		}
	}
	_, e = o.executionUsage()
	return e
}
func (o *Owner) executionUsage() (int, error) {
	total := 0
	for _, root := range []string{o.executionPath(), filepath.Join(o.root, "runtime-calls")} {
		if _, e := os.Lstat(root); errors.Is(e, os.ErrNotExist) {
			continue
		} else if e != nil {
			return 0, e
		}
		count := 0
		e := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			count++
			if count > 16*wire.MaximumEvents+16 {
				return ErrExecution
			}
			if _, err = PlacementID(path, entry.IsDir()); err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil || info.Size() > wire.MaximumRuntimePayloadBytes+wire.MaximumDataBytes {
				return ErrExecution
			}
			total += int(info.Size())
			if total > MaximumExecutionStoreBytes {
				return ErrExecution
			}
			return nil
		})
		if e != nil {
			return 0, e
		}
	}
	return total, nil
}
func (o *Owner) checkRuntimeCalls(recover *wire.Request) error {
	path := filepath.Join(o.root, "runtime-calls")
	entries, e := os.ReadDir(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil || len(entries) > int(o.descriptor.EventLimit) {
		return ErrExecution
	}
	if _, e = PlacementID(path, true); e != nil {
		return e
	}
	pending := false
	for _, entry := range entries {
		n, e := strconv.ParseUint(strings.TrimSuffix(entry.Name(), ".intent"), 10, 64)
		if e != nil || entry.Name() != fmt.Sprintf("%08d.intent", n) || n == 0 || n > o.position.Sequence+1 {
			return ErrExecution
		}
		raw, e := privateRead(filepath.Join(path, entry.Name()), wire.MaximumServiceRequestBytes)
		if e != nil {
			return e
		}
		q, _, e := wire.DecodeRuntimeRequest(raw)
		if e != nil || q.Authorize(o.descriptor) != nil || q.Before.Sequence+1 != n {
			return ErrExecution
		}
		if n <= o.position.Sequence {
			ev, e := privateRead(filepath.Join(o.root, "events", eventName(n)), wire.MaximumResponseBytes)
			if e != nil {
				return e
			}
			reply, e := wire.DecodeResponse(ev)
			a, _ := q.CanonicalBytes()
			b, _ := reply.Request.CanonicalBytes()
			if e != nil || (!bytes.Equal(a, b) && !(reply.Request.Kind == wire.Revoke && reply.Request.Before == q.Before)) {
				return ErrExecution
			}
			continue
		}
		if pending || recover == nil || *recover != q || q.Before != o.position {
			return ErrExecution
		}
		pending = true
	}
	return nil
}
func (o *Owner) pendingRequest(q wire.Request) error {
	raw, e := privateRead(filepath.Join(o.root, "runtime-calls", fmt.Sprintf("%08d.intent", o.position.Sequence+1)), wire.MaximumServiceRequestBytes)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	prior, _, e := wire.DecodeRuntimeRequest(raw)
	if e != nil {
		return e
	}
	if q.Kind != wire.Revoke && prior != q {
		return ErrExecution
	}
	return nil
}
func (o *Owner) retainRuntimeIntent(q wire.Request, payload []byte) error {
	raw, e := wire.EncodeRuntimeRequest(q, payload)
	if e != nil {
		return e
	}
	dir := filepath.Join(o.root, "runtime-calls")
	if _, e = os.Lstat(dir); errors.Is(e, os.ErrNotExist) {
		if e = os.Mkdir(dir, 0700); e != nil {
			return e
		}
		if e = syncDir(o.root); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	if _, e = PlacementID(dir, true); e != nil {
		return e
	}
	path := filepath.Join(dir, fmt.Sprintf("%08d.intent", q.Before.Sequence+1))
	old, e := privateRead(path, wire.MaximumServiceRequestBytes)
	if e == nil {
		if !bytes.Equal(old, raw) {
			return ErrExecution
		}
		return nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = publish(path, raw); e != nil {
		o.poisoned = true
	}
	return e
}
func (o *Owner) jobPath(sid types.Hash, name string) string {
	return o.executionPath("jobs", sid.String(), name)
}
func (o *Owner) jobRead(sid types.Hash, name string, limit int) ([]byte, error) {
	return privateRead(o.jobPath(sid, name), limit)
}
func (o *Owner) jobWrite(sid types.Hash, name string, raw []byte) error {
	path := o.jobPath(sid, name)
	if _, e := PlacementID(filepath.Dir(path), true); e != nil {
		return e
	}
	if old, e := privateRead(path, len(raw)); e == nil {
		if bytes.Equal(old, raw) {
			return nil
		}
		return ErrExecution
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e := publish(path, raw); e != nil {
		o.poisoned = true
		return e
	}
	return nil
}
func (o *Owner) retainJob(sid types.Hash, b v2.AdmissionBinding) error {
	raw, e := b.CanonicalBytes()
	if e != nil {
		return e
	}
	dir := o.jobPath(sid, "")
	if _, e = os.Lstat(dir); errors.Is(e, os.ErrNotExist) {
		if e = os.Mkdir(dir, 0700); e != nil {
			return e
		}
		if e = syncDir(filepath.Dir(dir)); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	return o.jobWrite(sid, "admission", raw)
}

type executionSource struct {
	Sequence uint64
	Head     types.Hash
	Receipt  workarchive.ReplicaReceipt
	Retain   uint64
}

// Replay only protected continuation records, with the original sealed prefix as
// predecessor. Never initialize a second ordinary journal or copy old entries.
func (o *Owner) currentExecutionSource() (executionSource, error) {
	receipt := o.g.Initial
	if cycles := o.g.Import.Evidence.Cycles; len(cycles) > 0 {
		receipt = cycles[len(cycles)-1].Terminal.Entry.Record.RenewedReceipt
	}
	current := executionSource{o.handoff.SourceSequence, o.handoff.SourceHeadID, receipt, o.handoff.RetainUntil}
	rid, e := receipt.ID()
	if e != nil || rid != o.handoff.ReceiptID {
		return current, ErrExecution
	}
	dirs, e := os.ReadDir(o.executionPath("jobs"))
	if e != nil || len(dirs) > wire.MaximumEvents {
		return current, ErrExecution
	}
	type item struct {
		entry   workarchive.CustodyJournalEntry
		context v2.Context
		path    string
	}
	var all []item
	for _, d := range dirs {
		sid, e := parseExecutionHash(d.Name())
		if e != nil || !d.IsDir() {
			return current, ErrExecution
		}
		path := o.jobPath(sid, "")
		if _, e = PlacementID(path, true); e != nil {
			return current, e
		}
		raw, e := o.jobRead(sid, "admission", wire.MaximumRuntimePayloadBytes)
		if e != nil {
			return current, e
		}
		fingerprint := types.DomainHash(wire.Domain+"retained-job/admission", raw)
		cached, known := o.execution.jobs[sid]
		if known && cached.hash != fingerprint {
			return current, ErrExecution
		}
		var c v2.Context
		if known {
			c = cached.context
		} else {
			binding, e := v2.DecodeAdmissionBinding(raw)
			if e != nil || v2.VerifyProtectedBinding(binding, o.b, o.execution.deployment) != nil {
				return current, ErrExecution
			}
			c, e = v2.ProtectedContextOf(binding)
			scope, _ := c.Scope()
			actual, _ := scope.ID()
			if e != nil || actual != sid {
				return current, ErrExecution
			}
			o.execution.jobs[sid] = validatedExecutionJob{fingerprint, c}
		}
		entries, e := os.ReadDir(path)
		if e != nil || len(entries) > 12 {
			return current, ErrExecution
		}
		allowed := map[string]bool{"admission": true, "candidate": true, "consumed": true, "entry": true, "core-result": true, "result": true, "pending": true, "accepted": true, "serve.pending": true, "serve.settled": true}
		for _, f := range entries {
			if !allowed[f.Name()] || f.IsDir() {
				return current, ErrExecution
			}
		}
		raw, e = o.jobRead(sid, "entry", workarchive.MaximumCustodyJournalEntryBytes)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return current, e
		}
		entry, e := workarchive.DecodeCustodyJournalEntry(raw)
		if e != nil {
			return current, e
		}
		all = append(all, item{entry, c, path})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].entry.Sequence < all[j].entry.Sequence })
	for _, v := range all {
		if v.context.Plan.Intent.PriorSequence != current.Sequence || v.context.Plan.Intent.PriorHeadID != current.Head || v.context.Previous != current.Receipt || v.entry.Verify(o.g.Manifest, o.g.CustodyPolicy, current.Sequence+1, current.Head, current.Receipt) != nil {
			return current, ErrExecution
		}
		current.Sequence = v.entry.Sequence
		current.Head, _ = v.entry.ID()
		current.Receipt = v.entry.Record.RenewedReceipt
		if current.Retain < current.Receipt.RetainUntil {
			current.Retain = current.Receipt.RetainUntil
		}
	}
	return current, nil
}
func (o *Owner) requireExecutionSource(c v2.Context, allowApplied bool) error {
	s, e := o.currentExecutionSource()
	if e != nil {
		return e
	}
	if s.Sequence == c.Plan.Intent.PriorSequence && s.Head == c.Plan.Intent.PriorHeadID && s.Receipt == c.Previous {
		return nil
	}
	if allowApplied && s.Sequence == c.Plan.Intent.PriorSequence+1 {
		scope, _ := c.Scope()
		sid, _ := scope.ID()
		raw, e := o.jobRead(sid, "entry", workarchive.MaximumCustodyJournalEntryBytes)
		if e == nil {
			entry, e := workarchive.DecodeCustodyJournalEntry(raw)
			id, _ := entry.ID()
			if e == nil && id == s.Head {
				return nil
			}
		}
	}
	return ErrExecution
}

func parseExecutionHash(s string) (types.Hash, error) {
	var h types.Hash
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 32 {
		return h, ErrExecution
	}
	copy(h[:], b)
	if h.String() != s {
		return types.Hash{}, ErrExecution
	}
	return h, nil
}

type validatedExecutionJob struct {
	hash    types.Hash
	context v2.Context
}
