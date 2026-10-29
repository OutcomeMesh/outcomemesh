package custodyv2

import (
	"bytes"
	"errors"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const MaximumAdmissionBindingBytes = MaximumAdmissionWitnessBytes

var ErrAdmissionRequired = errors.New("signed custody profile requires the exact retained admission binding")

// AdmissionBinding is a bounded complete accounting prefix ending in this
// exact job's Admit, not a live query of the global ledger. Later closure cannot
// authorize another effect: fulfilled jobs already consumed the winning live
// session; unclaimed closure excludes an execution Claim quorum. Mandatory
// original-source/session/consumed gates remain necessary in the runtime.
type AdmissionBinding struct {
	Version uint16
	Genesis AdmissionGenesis
	Chain   []AdmissionCertificate
}

func (b AdmissionBinding) CanonicalBytes() ([]byte, error) {
	if b.Version != Version2 || !requiresAdmission(b.Genesis.Assignment.Policy.Version) || len(b.Chain) == 0 || uint64(len(b.Chain)) > MaxAdmissionEntries(b.Genesis) {
		return nil, ErrAdmissionRequired
	}
	g, e := b.Genesis.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	out := codec.NewEncoder(len(g) + 1024)
	out.Fixed([]byte("OMCVBND2"))
	out.U16(b.Version)
	out.BytesField(g)
	out.U32(uint32(len(b.Chain)))
	total := len(g) + 32
	for _, q := range b.Chain {
		raw, e := q.CanonicalBytes()
		if e != nil {
			return nil, e
		}
		total += len(raw) + 10
		if total > MaximumAdmissionBindingBytes {
			return nil, ErrAdmissionRequired
		}
		out.BytesField(raw)
	}
	raw := out.Bytes()
	if len(raw) > MaximumAdmissionBindingBytes {
		return nil, ErrAdmissionRequired
	}
	return raw, nil
}
func DecodeAdmissionBinding(raw []byte) (AdmissionBinding, error) {
	var b AdmissionBinding
	if len(raw) > MaximumAdmissionBindingBytes {
		return b, ErrAdmissionRequired
	}
	d := codec.NewDecoder(raw)
	if !magic(d, "OMCVBND2") {
		return b, ErrAdmissionRequired
	}
	b.Version, _ = d.U16()
	g, e := d.BytesField(MaximumAdmissionGenesisBytes)
	if e != nil {
		return b, e
	}
	b.Genesis, e = DecodeAdmissionGenesis(g)
	if e != nil {
		return b, e
	}
	n, e := d.U32()
	if e != nil || n == 0 || uint64(n) > MaxAdmissionEntries(b.Genesis) || uint64(n) > uint64(d.Remaining()) {
		return b, ErrAdmissionRequired
	}
	// A declared count is not evidence that complete certificates are present.
	// Context is a large value: eagerly allocating the maximum 65,538 slots
	// allowed a small malformed binding to reserve over 160 MiB before the
	// first certificate was decoded. Grow only from fully decoded evidence.
	for i := uint32(0); i < n; i++ {
		q, e := d.BytesField(MaximumAdmissionCertificateBytes)
		if e != nil {
			return AdmissionBinding{}, e
		}
		certificate, e := DecodeAdmissionCertificate(q)
		if e != nil {
			return AdmissionBinding{}, e
		}
		b.Chain = append(b.Chain, certificate)
	}
	if d.Finish() != nil {
		return AdmissionBinding{}, ErrAdmissionRequired
	}
	again, e := b.CanonicalBytes()
	if e != nil || !bytes.Equal(again, raw) {
		return AdmissionBinding{}, ErrAdmissionRequired
	}
	return b, nil
}
func (b AdmissionBinding) ID() (types.Hash, error) {
	raw, e := b.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody/v2/required/admission-binding/id", raw), nil
}
func (b AdmissionBinding) Verify(c Context) error {
	if !requiresAdmission(c.Assignment.Policy.Version) {
		return ErrAdmissionRequired
	}
	if e := c.Validate(); e != nil {
		return e
	}
	raw, e := b.CanonicalBytes()
	if e != nil {
		return e
	}
	b, e = DecodeAdmissionBinding(raw)
	if e != nil {
		return e
	}
	gid, e := b.Genesis.ID()
	if e != nil {
		return e
	}
	state, e := NewAdmissionState(b.Genesis, gid)
	if e != nil {
		return e
	}
	for _, q := range b.Chain {
		if c.Plan.Deployment != nil && c.Plan.Deployment.Guard != ([32]byte{}) {
			if q.Entry.Context.Plan.Deployment == nil {
				return ErrAdmissionRequired
			}
			want, _ := c.Plan.Deployment.ID()
			got, e := q.Entry.Context.Plan.Deployment.ID()
			if e != nil || got != want {
				return ErrAdmissionRequired
			}
		}
		if e := state.Apply(q); e != nil {
			return e
		}
	}
	last := b.Chain[len(b.Chain)-1].Entry
	cid, _ := c.ID()
	actual, _ := last.Context.ID()
	pid, _ := c.Plan.ID()
	x := state.Snapshot()
	aid, _ := c.Assignment.ID()
	gaid, _ := b.Genesis.Assignment.ID()
	if aid != gaid || last.Kind != AdmissionAdmit || actual != cid || x.ActiveContextID != cid || x.ActivePlanID != pid || x.PendingOperations != 2 || x.SourceSequence != c.Plan.Intent.PriorSequence || x.SourceHeadID != c.Plan.Intent.PriorHeadID || x.SourceReceiptID != c.Plan.Intent.PriorReceiptID || x.CurrentReceipt != c.Previous {
		return ErrAdmissionRequired
	}
	return nil
}
func (b AdmissionBinding) admissionID() (types.Hash, error) {
	if len(b.Chain) == 0 {
		return types.Hash{}, ErrAdmissionRequired
	}
	return b.Chain[len(b.Chain)-1].Entry.ID()
}
func freezeRequiredBinding(c Context, b *AdmissionBinding) (frozen *AdmissionBinding, raw []byte, id types.Hash, err error) {
	if c.Assignment.Policy.Version == PolicyVersionImported {
		return nil, nil, id, ErrImportInactive
	}
	if !requiresAdmission(c.Assignment.Policy.Version) {
		if b != nil {
			return nil, nil, id, ErrAdmissionRequired
		}
		return nil, nil, id, nil
	}
	if b == nil {
		return nil, nil, id, ErrAdmissionRequired
	}
	raw, err = b.CanonicalBytes()
	if err != nil {
		return nil, nil, id, err
	}
	value, e := DecodeAdmissionBinding(raw)
	if e != nil {
		return nil, nil, id, e
	}
	if e := value.Verify(c); e != nil {
		return nil, nil, id, e
	}
	id, e = value.ID()
	return &value, raw, id, e
}
func (r *root) checkAdmission() error {
	if !requiresAdmission(r.ctx.Assignment.Policy.Version) {
		if r.binding != nil || len(r.bindingBytes) != 0 || !r.bindingID.IsZero() {
			return ErrAdmissionRequired
		}
		return nil
	}
	if r.binding == nil || len(r.bindingBytes) == 0 || r.bindingID.IsZero() {
		return ErrAdmissionRequired
	}
	raw, e := readFile(filepath.Join(r.path, "admission"), len(r.bindingBytes))
	if e != nil || !bytes.Equal(raw, r.bindingBytes) {
		return errors.Join(ErrAdmissionRequired, e)
	}
	return nil
}

// A single binding-aware record preserves the existing durable boundary. There
// is no separate pre-consumption marker whose recovery could restart execution.
func (r *root) wrapAdmissionRecord(kind string, raw []byte) ([]byte, error) {
	if e := r.checkAdmission(); e != nil {
		return nil, e
	}
	if r.binding == nil {
		return raw, nil
	}
	aid, e := r.binding.admissionID()
	if e != nil {
		return nil, e
	}
	magic := "OMCVUSE3"
	if kind == "pending" {
		magic = "OMCVPEN3"
	} else if kind != "consumed" {
		return nil, ErrAdmissionRequired
	}
	version := PolicyVersionAdmission
	if r.ctx.Assignment.Policy.Version == PolicyVersionEnrolled {
		if e := r.checkEnrollment(); e != nil {
			return nil, e
		}
		version = PolicyVersionEnrolled
		if kind == "pending" {
			magic = "OMCVPEN4"
		} else {
			magic = "OMCVUSE4"
		}
	}
	out := codec.NewEncoder(len(raw) + 128)
	out.Fixed([]byte(magic))
	out.U16(version)
	out.Fixed(r.bindingID[:])
	out.Fixed(aid[:])
	if version == PolicyVersionEnrolled {
		out.Fixed(r.enrollmentID[:])
	}
	out.BytesField(raw)
	return out.Bytes(), nil
}
func (r *root) unwrapAdmissionRecord(kind string, raw []byte) ([]byte, error) {
	if r.binding == nil {
		return raw, nil
	}
	d := codec.NewDecoder(raw)
	m := "OMCVUSE3"
	if kind == "pending" {
		m = "OMCVPEN3"
	} else if kind != "consumed" {
		return nil, ErrAdmissionRequired
	}
	wantedVersion := PolicyVersionAdmission
	if r.ctx.Assignment.Policy.Version == PolicyVersionEnrolled {
		wantedVersion = PolicyVersionEnrolled
		if kind == "pending" {
			m = "OMCVPEN4"
		} else {
			m = "OMCVUSE4"
		}
	}
	if !magic(d, m) {
		return nil, ErrAdmissionRequired
	}
	version, _ := d.U16()
	var bid, aid types.Hash
	fixed(d, bid[:])
	fixed(d, aid[:])
	expected, e := r.binding.admissionID()
	if e != nil || version != wantedVersion || bid != r.bindingID || aid != expected {
		return nil, ErrAdmissionRequired
	}
	if wantedVersion == PolicyVersionEnrolled {
		var enrollment types.Hash
		fixed(d, enrollment[:])
		if enrollment != r.enrollmentID || enrollment.IsZero() {
			return nil, ErrEnrollmentRequired
		}
	}
	body, e := d.BytesField(MaximumBundleBytes + 32)
	if e != nil || d.Finish() != nil {
		return nil, ErrAdmissionRequired
	}
	return body, nil
}
