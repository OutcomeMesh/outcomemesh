package custodyv2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/transport"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// AdmissionInbox retains public proof only. Its acknowledgement never creates
// an owner, prepares an execution session, appends a source or clears a hold.
// The original source decision is retained until Close; stop this intake before
// explicitly creating/opening the corresponding required owner.
type AdmissionInbox struct {
	mu         sync.Mutex
	s          *admissionDeliveryStore
	c          Context
	sources    Sources
	enrollment AdmissionDeliveryEnrollment
	key        ed25519.PrivateKey
	decision   *workarchive.CustodyJournalDecision
}

// AdmissionOutbox fixes one complete delivery and route before any network
// dispatch. Missing receipt means unresolved, including when a send timed out.
type AdmissionOutbox struct {
	mu       sync.Mutex
	s        *admissionDeliveryStore
	delivery AdmissionDelivery
	route    string
}

// hook is private fault injection, deliberately shared with the existing
// immutable publish boundary: <filename>-before-sync and <filename>-durable.
type admissionDeliveryStore struct {
	path      string
	lock      *os.File
	identity  map[string]os.FileInfo
	placement []byte
	static    map[string][]byte
	retained  map[string][]byte
	limits    map[string]int
	failed    bool
	hook      func(string) error
}

func admissionDeliveryRoleName(role AdmissionDeliveryRole) (string, error) {
	switch role {
	case AdmissionDeliveryAuthority:
		return "acceptor", nil
	case AdmissionDeliveryTarget:
		return "target", nil
	default:
		return "", ErrAdmissionDelivery
	}
}

func admissionDeliveryFreeze(d AdmissionDelivery) (AdmissionDelivery, []byte, error) {
	raw, e := d.CanonicalBytes()
	if e != nil {
		return AdmissionDelivery{}, nil, e
	}
	frozen, e := DecodeAdmissionDelivery(raw)
	if e != nil {
		return AdmissionDelivery{}, nil, e
	}
	if e := frozen.Validate(); e != nil {
		return AdmissionDelivery{}, nil, e
	}
	return frozen, raw, nil
}

func admissionDeliveryContext(c Context, scopeID types.Hash, version uint16) (Context, error) {
	c, e := c.freeze()
	if e != nil {
		return Context{}, e
	}
	scope, e := c.Scope()
	if e != nil {
		return Context{}, e
	}
	id, e := scope.ID()
	if e != nil || scopeID.IsZero() || id != scopeID || c.Assignment.Policy.Version != deliveryProfile(version) {
		return Context{}, errors.Join(ErrAdmissionDelivery, e)
	}
	return c, nil
}

func admissionDeliverySource(c Context, sources Sources) (*workarchive.CustodyJournalDecision, error) {
	j, _, e := workarchive.OpenExistingCustodyJournalWithLimits(nilContext(), sources.Journal, c.Manifest, c.Initial, c.CustodyPolicy, workarchive.DefaultCustodyJournalLimits())
	if e != nil {
		return nil, e
	}
	return j.AcquireDecision()
}

func admissionDeliverySources(sources Sources, role string) (Sources, error) {
	sources, e := canonicalSources(sources, role)
	if e != nil {
		return Sources{}, e
	}
	for _, path := range []string{sources.Journal, sources.Objects} {
		if path == "" {
			continue
		}
		info, e := os.Lstat(path)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return Sources{}, errors.Join(ErrAdmissionDelivery, e)
		}
	}
	return sources, nil
}

// CreateAdmissionInbox is explicit enrollment against an independently selected
// binding ID. The opaque public placement commitment salts private source paths
// and inode stamps; canonical proof has not been delivered yet.
func CreateAdmissionInbox(path string, c Context, scopeID, bindingID types.Hash, role AdmissionDeliveryRole, sources Sources, recipientPeerID types.Hash) (AdmissionDeliveryEnrollment, error) {
	return createAdmissionInbox(path, c, scopeID, bindingID, types.Hash{}, role, sources, recipientPeerID, Version2)
}

// CreateEnrolledAdmissionInbox pins both exact proof IDs before any network receive.
func CreateEnrolledAdmissionInbox(path string, c Context, scopeID, bindingID, registryEnrollmentID types.Hash, role AdmissionDeliveryRole, sources Sources, recipientPeerID types.Hash) (AdmissionDeliveryEnrollment, error) {
	return createAdmissionInbox(path, c, scopeID, bindingID, registryEnrollmentID, role, sources, recipientPeerID, PolicyVersionEnrolled)
}
func createAdmissionInbox(path string, c Context, scopeID, bindingID, registryEnrollmentID types.Hash, role AdmissionDeliveryRole, sources Sources, recipientPeerID types.Hash, version uint16) (enrollment AdmissionDeliveryEnrollment, returnErr error) {
	c, e := admissionDeliveryContext(c, scopeID, version)
	if e != nil {
		return enrollment, e
	}
	roleName, e := admissionDeliveryRoleName(role)
	if e != nil {
		return enrollment, e
	}
	path, e = canonical(path)
	if e != nil {
		return enrollment, e
	}
	sources, e = admissionDeliverySources(sources, roleName)
	if e != nil {
		return enrollment, e
	}
	if e := disjoint(path, sources); e != nil {
		return enrollment, e
	}
	cid, _ := c.ID()
	sender, e := transport.PeerIDFromPublicKey(c.Plan.ClientTransportPublicKey[:])
	if e != nil {
		return enrollment, e
	}
	enrollment = AdmissionDeliveryEnrollment{Version: version, RegistryEnrollmentID: registryEnrollmentID, ContextID: cid, ScopeID: scopeID, BindingID: bindingID, SenderPeerID: sender, RecipientPeerID: recipientPeerID, Role: role}
	if role == AdmissionDeliveryAuthority {
		enrollment.ReceiptPublicKey = c.Assignment.Base.AuthorityPublicKey
	} else {
		enrollment.ReceiptPublicKey = c.Assignment.Base.RemoteControlPublicKey
	}
	if _, e := rand.Read(enrollment.Nonce[:]); e != nil {
		return AdmissionDeliveryEnrollment{}, e
	}
	// Validate all public selectors before creating a directory. The real
	// placement commitment is calculated only after its lock inode exists.
	enrollment.PlacementID = types.DomainHash(deliveryPlacementDomain(enrollment.Version), enrollment.Nonce[:])
	if e := enrollment.Verify(c); e != nil {
		return AdmissionDeliveryEnrollment{}, e
	}
	decision, e := admissionDeliverySource(c, sources)
	if e != nil {
		return AdmissionDeliveryEnrollment{}, e
	}
	defer func() { returnErr = errors.Join(returnErr, decision.Close()) }()
	state, e := decision.State()
	if e != nil || !atPredecessor(c, state) {
		return AdmissionDeliveryEnrollment{}, errors.Join(ErrAdmissionDelivery, e)
	}
	lock, e := admissionDeliveryCreateDirectory(path)
	if e != nil {
		return AdmissionDeliveryEnrollment{}, e
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	placed, e := sourcePlacement(roleName, sources, path)
	if e != nil {
		return AdmissionDeliveryEnrollment{}, e
	}
	enrollment.PlacementID = types.DomainHash(deliveryPlacementDomain(enrollment.Version), enrollment.Nonce[:], placed)
	raw, e := enrollment.CanonicalBytes()
	if e != nil {
		return AdmissionDeliveryEnrollment{}, e
	}
	contextRaw, _ := c.CanonicalBytes()
	for _, value := range []struct {
		name string
		raw  []byte
	}{{"context", contextRaw}, {"placement", placed}, {"enrollment", raw}} {
		if e := publish(path, value.name, value.raw, nil); e != nil {
			return AdmissionDeliveryEnrollment{}, e
		}
	}
	id, _ := enrollment.ID()
	if e := publish(path, "ready", append([]byte(deliveryMagic("OMCVIDY", enrollment.Version)), id[:]...), nil); e != nil {
		return AdmissionDeliveryEnrollment{}, e
	}
	return enrollment, nil
}

func OpenAdmissionInbox(path string, c Context, scopeID types.Hash, sources Sources, enrollment AdmissionDeliveryEnrollment, key ed25519.PrivateKey) (*AdmissionInbox, error) {
	return openAdmissionInbox(path, c, scopeID, sources, enrollment, key, Version2)
}
func OpenEnrolledAdmissionInbox(path string, c Context, scopeID types.Hash, sources Sources, enrollment AdmissionDeliveryEnrollment, key ed25519.PrivateKey) (*AdmissionInbox, error) {
	return openAdmissionInbox(path, c, scopeID, sources, enrollment, key, PolicyVersionEnrolled)
}
func openAdmissionInbox(path string, c Context, scopeID types.Hash, sources Sources, enrollment AdmissionDeliveryEnrollment, key ed25519.PrivateKey, version uint16) (inbox *AdmissionInbox, returnErr error) {
	if enrollment.Version != version {
		return nil, ErrAdmissionDelivery
	}
	c, e := admissionDeliveryContext(c, scopeID, version)
	if e != nil {
		return nil, e
	}
	if e := enrollment.Verify(c); e != nil {
		return nil, e
	}
	if !matches(key, enrollment.ReceiptPublicKey) {
		return nil, ErrAdmissionDelivery
	}
	roleName, e := admissionDeliveryRoleName(enrollment.Role)
	if e != nil {
		return nil, e
	}
	path, e = canonical(path)
	if e != nil {
		return nil, e
	}
	sources, e = admissionDeliverySources(sources, roleName)
	if e != nil {
		return nil, e
	}
	if e := disjoint(path, sources); e != nil {
		return nil, e
	}
	placed, e := sourcePlacement(roleName, sources, path)
	if e != nil {
		return nil, e
	}
	if types.DomainHash(deliveryPlacementDomain(enrollment.Version), enrollment.Nonce[:], placed) != enrollment.PlacementID {
		return nil, ErrAdmissionDelivery
	}
	raw, _ := enrollment.CanonicalBytes()
	contextRaw, _ := c.CanonicalBytes()
	id, _ := enrollment.ID()
	s, e := admissionDeliveryOpenDirectory(path, placed, map[string][]byte{"context": contextRaw, "placement": placed, "enrollment": raw, "ready": append([]byte(deliveryMagic("OMCVIDY", enrollment.Version)), id[:]...)}, map[string]int{"delivery": MaximumAdmissionDeliveryBytes, "receipt": deliveryReceiptLimit(enrollment.Version)}, placementFiles(sources))
	if e != nil {
		return nil, e
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, s.close())
		}
	}()
	decision, e := admissionDeliverySource(c, sources)
	if e != nil {
		return nil, e
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, decision.Close())
		}
	}()
	inbox = &AdmissionInbox{s: s, c: c, sources: sources, enrollment: enrollment, decision: decision, key: append(ed25519.PrivateKey(nil), key...)}
	if e := inbox.validateRetained(); e != nil {
		clear(inbox.key)
		return nil, e
	}
	if e := s.stabilize(); e != nil {
		clear(inbox.key)
		return nil, e
	}
	return inbox, nil
}

// ReadAdmissionInboxEnrollment recovers a public descriptor after enrollment
// output was lost. It does not adopt that descriptor as an independent pin,
// sign, flush, send, recreate or resume anything. The caller must independently
// review and retain its ID before opening an inbox or constructing a delivery.
func ReadAdmissionInboxEnrollment(path string, c Context, scopeID, bindingID types.Hash, role AdmissionDeliveryRole, sources Sources, recipientPeerID types.Hash) (AdmissionDeliveryEnrollment, error) {
	return readAdmissionInboxEnrollment(path, c, scopeID, bindingID, types.Hash{}, role, sources, recipientPeerID, Version2)
}
func ReadEnrolledAdmissionInboxEnrollment(path string, c Context, scopeID, bindingID, registryEnrollmentID types.Hash, role AdmissionDeliveryRole, sources Sources, recipientPeerID types.Hash) (AdmissionDeliveryEnrollment, error) {
	return readAdmissionInboxEnrollment(path, c, scopeID, bindingID, registryEnrollmentID, role, sources, recipientPeerID, PolicyVersionEnrolled)
}
func readAdmissionInboxEnrollment(path string, c Context, scopeID, bindingID, registryEnrollmentID types.Hash, role AdmissionDeliveryRole, sources Sources, recipientPeerID types.Hash, version uint16) (enrollment AdmissionDeliveryEnrollment, returnErr error) {
	c, e := admissionDeliveryContext(c, scopeID, version)
	if e != nil {
		return enrollment, e
	}
	roleName, e := admissionDeliveryRoleName(role)
	if e != nil {
		return enrollment, e
	}
	path, e = canonical(path)
	if e != nil {
		return enrollment, e
	}
	sources, e = admissionDeliverySources(sources, roleName)
	if e != nil {
		return enrollment, e
	}
	if e := disjoint(path, sources); e != nil {
		return enrollment, e
	}
	raw, e := readFile(filepath.Join(path, "enrollment"), MaximumEnrolledDeliveryEnrollmentBytes)
	if e != nil {
		return enrollment, e
	}
	enrollment, e = DecodeAdmissionDeliveryEnrollment(raw)
	if e != nil {
		return AdmissionDeliveryEnrollment{}, e
	}
	if e := enrollment.Verify(c); e != nil {
		return AdmissionDeliveryEnrollment{}, e
	}
	if enrollment.Version != version || enrollment.RegistryEnrollmentID != registryEnrollmentID || enrollment.ScopeID != scopeID || enrollment.BindingID != bindingID || enrollment.Role != role || enrollment.RecipientPeerID != recipientPeerID {
		return AdmissionDeliveryEnrollment{}, ErrAdmissionDelivery
	}
	placed, e := sourcePlacement(roleName, sources, path)
	if e != nil {
		return AdmissionDeliveryEnrollment{}, e
	}
	if types.DomainHash(deliveryPlacementDomain(enrollment.Version), enrollment.Nonce[:], placed) != enrollment.PlacementID {
		return AdmissionDeliveryEnrollment{}, ErrAdmissionDelivery
	}
	contextRaw, _ := c.CanonicalBytes()
	id, _ := enrollment.ID()
	s, e := admissionDeliveryOpenDirectory(path, placed, map[string][]byte{"context": contextRaw, "placement": placed, "enrollment": raw, "ready": append([]byte(deliveryMagic("OMCVIDY", enrollment.Version)), id[:]...)}, map[string]int{"delivery": MaximumAdmissionDeliveryBytes, "receipt": deliveryReceiptLimit(enrollment.Version)}, placementFiles(sources))
	if e != nil {
		return AdmissionDeliveryEnrollment{}, e
	}
	defer func() { returnErr = errors.Join(returnErr, s.close()) }()
	decision, e := admissionDeliverySource(c, sources)
	if e != nil {
		return AdmissionDeliveryEnrollment{}, e
	}
	defer func() { returnErr = errors.Join(returnErr, decision.Close()) }()
	probe := AdmissionInbox{s: s, c: c, sources: sources, enrollment: enrollment, decision: decision}
	if e := probe.validateRetained(); e != nil {
		return AdmissionDeliveryEnrollment{}, e
	}
	return enrollment, nil
}

func (i *AdmissionInbox) Enrollment() AdmissionDeliveryEnrollment { return i.enrollment }

func (i *AdmissionInbox) Check() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.checkSource()
}

func (i *AdmissionInbox) validateDelivery(d AdmissionDelivery) error {
	if e := d.Validate(); e != nil {
		return e
	}
	if d.Enrollment != i.enrollment {
		return ErrAdmissionDelivery
	}
	want, _ := i.c.CanonicalBytes()
	got, _ := d.Context.CanonicalBytes()
	if !bytes.Equal(want, got) {
		return ErrAdmissionDelivery
	}
	return nil
}

func (i *AdmissionInbox) validateRetained() error {
	raw, e := readFile(filepath.Join(i.s.path, "delivery"), MaximumAdmissionDeliveryBytes)
	if errors.Is(e, os.ErrNotExist) {
		if _, err := os.Lstat(filepath.Join(i.s.path, "receipt")); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(ErrAdmissionDelivery, err)
		}
		return i.checkSource()
	}
	if e != nil {
		return e
	}
	d, e := DecodeAdmissionDelivery(raw)
	if e != nil {
		return e
	}
	if e := i.validateDelivery(d); e != nil {
		return e
	}
	i.s.retained["delivery"] = append([]byte(nil), raw...)
	raw, e = readFile(filepath.Join(i.s.path, "receipt"), deliveryReceiptLimit(i.enrollment.Version))
	if errors.Is(e, os.ErrNotExist) {
		return i.checkSource()
	}
	if e != nil {
		return e
	}
	r, e := DecodeAdmissionDeliveryReceipt(raw)
	if e != nil {
		return e
	}
	if e := r.Verify(d); e != nil {
		return e
	}
	i.s.retained["receipt"] = append([]byte(nil), raw...)
	return i.checkSource()
}

func (i *AdmissionInbox) Delivery() (AdmissionDelivery, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if e := i.checkSource(); e != nil {
		return AdmissionDelivery{}, e
	}
	raw, ok := i.s.retained["delivery"]
	if !ok {
		return AdmissionDelivery{}, os.ErrNotExist
	}
	return DecodeAdmissionDelivery(raw)
}

func (i *AdmissionInbox) ReadReceipt() (AdmissionDeliveryReceipt, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if e := i.checkSource(); e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	raw, ok := i.s.retained["receipt"]
	if !ok {
		return AdmissionDeliveryReceipt{}, os.ErrNotExist
	}
	return DecodeAdmissionDeliveryReceipt(raw)
}

// Receive explicitly resumes the same immutable delivery after uncertain output.
// Only an already retained receipt can be read after the source has advanced;
// a retained proof without a receipt never relaxes the predecessor check.
func (i *AdmissionInbox) Receive(ctx context.Context, delivery AdmissionDelivery) (AdmissionDeliveryReceipt, error) {
	if ctx == nil {
		return AdmissionDeliveryReceipt{}, ErrAdmissionDelivery
	}
	delivery, raw, e := admissionDeliveryFreeze(delivery)
	if e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if e := i.checkSource(); e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	if e := ctx.Err(); e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	if e := i.validateDelivery(delivery); e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	if old, exists := i.s.retained["delivery"]; exists && !bytes.Equal(old, raw) {
		return AdmissionDeliveryReceipt{}, ErrAdmissionDelivery
	}
	if receipt, exists := i.s.retained["receipt"]; exists {
		return DecodeAdmissionDeliveryReceipt(receipt)
	}
	state, e := i.decision.State()
	if e != nil || !atPredecessor(i.c, state) {
		return AdmissionDeliveryReceipt{}, errors.Join(ErrAdmissionDelivery, e)
	}
	if e := ctx.Err(); e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	if e := i.s.write("delivery", raw); e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	if e := ctx.Err(); e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	if e := i.checkSource(); e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	receipt, e := (AdmissionDeliveryReceipt{}).Sign(delivery, i.key)
	if e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	receiptRaw, e := receipt.CanonicalBytes()
	if e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	if e := ctx.Err(); e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	if e := i.s.write("receipt", receiptRaw); e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	if e := ctx.Err(); e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	return receipt, nil
}

func (i *AdmissionInbox) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	clear(i.key)
	if i.s.lock == nil {
		return nil
	}
	return errors.Join(i.decision.Close(), i.s.close())
}

// ValidateAdmissionDeliveryRoute rejects a foreign or unusable explicit route
// before outbox creation. It requires the same direct QUIC-v1 /p2p endpoint and
// Ed25519-derived identity that the authenticated transport will later verify.
func ValidateAdmissionDeliveryRoute(address string, expected types.Hash) error {
	if address == "" || expected.IsZero() {
		return ErrAdmissionDelivery
	}
	// The transport parser enforces its hard address-length bound before any
	// multiaddress allocation; retain that ordering for this exported helper.
	peer, e := libp2ptransport.PeerIDFromAddress(address)
	if e != nil || peer != expected {
		return errors.Join(ErrAdmissionDelivery, e)
	}
	a, e := ma.NewMultiaddr(address)
	if e != nil || a.String() != address {
		return errors.Join(ErrAdmissionDelivery, e)
	}
	return nil
}

func CreateAdmissionOutbox(path string, d AdmissionDelivery, address string) error {
	return createAdmissionOutbox(path, d, address, Version2)
}
func CreateEnrolledAdmissionOutbox(path string, d AdmissionDelivery, address string) error {
	return createAdmissionOutbox(path, d, address, PolicyVersionEnrolled)
}
func createAdmissionOutbox(path string, d AdmissionDelivery, address string, version uint16) (returnErr error) {
	if d.Version != version {
		return ErrAdmissionDelivery
	}
	d, raw, e := admissionDeliveryFreeze(d)
	if e != nil {
		return e
	}
	if e := ValidateAdmissionDeliveryRoute(address, d.Enrollment.RecipientPeerID); e != nil {
		return e
	}
	path, e = canonical(path)
	if e != nil {
		return e
	}
	lock, e := admissionDeliveryCreateDirectory(path)
	if e != nil {
		return e
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	placed, e := admissionDeliveryOutboxPlacement(path)
	if e != nil {
		return e
	}
	for _, value := range []struct {
		name string
		raw  []byte
	}{{"delivery", raw}, {"route", []byte(address)}, {"placement", placed}} {
		if e := publish(path, value.name, value.raw, nil); e != nil {
			return e
		}
	}
	id, _ := d.ID()
	return publish(path, "ready", append([]byte(deliveryMagic("OMCVODY", d.Version)), id[:]...), nil)
}

func OpenAdmissionOutbox(path string, d AdmissionDelivery, address string) (*AdmissionOutbox, error) {
	return openAdmissionOutbox(path, d, address, Version2)
}
func OpenEnrolledAdmissionOutbox(path string, d AdmissionDelivery, address string) (*AdmissionOutbox, error) {
	return openAdmissionOutbox(path, d, address, PolicyVersionEnrolled)
}
func openAdmissionOutbox(path string, d AdmissionDelivery, address string, version uint16) (outbox *AdmissionOutbox, returnErr error) {
	if d.Version != version {
		return nil, ErrAdmissionDelivery
	}
	d, raw, e := admissionDeliveryFreeze(d)
	if e != nil {
		return nil, e
	}
	if e := ValidateAdmissionDeliveryRoute(address, d.Enrollment.RecipientPeerID); e != nil {
		return nil, e
	}
	path, e = canonical(path)
	if e != nil {
		return nil, e
	}
	placed, e := admissionDeliveryOutboxPlacement(path)
	if e != nil {
		return nil, e
	}
	id, _ := d.ID()
	s, e := admissionDeliveryOpenDirectory(path, placed, map[string][]byte{"delivery": raw, "route": []byte(address), "placement": placed, "ready": append([]byte(deliveryMagic("OMCVODY", d.Version)), id[:]...)}, map[string]int{"receipt": deliveryReceiptLimit(d.Version)}, nil)
	if e != nil {
		return nil, e
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, s.close())
		}
	}()
	outbox = &AdmissionOutbox{s: s, delivery: d, route: address}
	receiptRaw, e := readFile(filepath.Join(path, "receipt"), deliveryReceiptLimit(d.Version))
	if e == nil {
		r, e := DecodeAdmissionDeliveryReceipt(receiptRaw)
		if e != nil {
			return nil, e
		}
		if e := r.Verify(d); e != nil {
			return nil, e
		}
		s.retained["receipt"] = receiptRaw
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if e := s.stabilize(); e != nil {
		return nil, e
	}
	return outbox, nil
}

// Delivery returns a detached immutable value. Check must succeed immediately
// before dispatch; this accessor by itself does not certify live store health.
func (o *AdmissionOutbox) Delivery() AdmissionDelivery {
	o.mu.Lock()
	defer o.mu.Unlock()
	raw, _ := o.delivery.CanonicalBytes()
	d, _ := DecodeAdmissionDelivery(raw)
	return d
}
func (o *AdmissionOutbox) Route() string { return o.route }
func (o *AdmissionOutbox) Check() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.s.check()
}
func (o *AdmissionOutbox) ReadReceipt() (AdmissionDeliveryReceipt, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if e := o.s.check(); e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	raw, ok := o.s.retained["receipt"]
	if !ok {
		return AdmissionDeliveryReceipt{}, os.ErrNotExist
	}
	return DecodeAdmissionDeliveryReceipt(raw)
}
func (o *AdmissionOutbox) Confirm(ctx context.Context, receipt AdmissionDeliveryReceipt) error {
	if ctx == nil {
		return ErrAdmissionDelivery
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if e := o.s.check(); e != nil {
		return e
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := receipt.Verify(o.delivery); e != nil {
		return e
	}
	raw, e := receipt.CanonicalBytes()
	if e != nil {
		return e
	}
	if old, ok := o.s.retained["receipt"]; ok {
		if !bytes.Equal(old, raw) {
			return ErrAdmissionDelivery
		}
		return nil
	}
	return o.s.write("receipt", raw)
}
func (o *AdmissionOutbox) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.s.close()
}

func admissionDeliveryCreateDirectory(path string) (lock *os.File, returnErr error) {
	if e := os.Mkdir(path, 0o700); e != nil {
		return nil, e
	}
	if e := syncDir(filepath.Dir(path)); e != nil {
		return nil, e
	}
	lock, e := os.OpenFile(filepath.Join(path, "owner.lock"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if e != nil {
		return nil, e
	}
	created := lock
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, created.Close())
		}
	}()
	if e := lockRoot(lock); e != nil {
		return nil, e
	}
	if e := errors.Join(lock.Sync(), syncDir(path)); e != nil {
		return nil, e
	}
	return lock, nil
}

func admissionDeliveryOutboxPlacement(path string) ([]byte, error) {
	p := placement{Role: "admission-outbox", Files: map[string]fileStamp{}}
	for _, name := range []string{path, filepath.Join(path, "owner.lock")} {
		info, e := os.Lstat(name)
		if e != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.Join(ErrAdmissionDelivery, e)
		}
		stamp, e := stampFile(info)
		if e != nil {
			return nil, e
		}
		p.Files[name] = stamp
	}
	return json.Marshal(p)
}

func admissionDeliveryOpenDirectory(path string, placed []byte, static map[string][]byte, optional map[string]int, sources map[string]bool) (s *admissionDeliveryStore, returnErr error) {
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.Join(ErrAdmissionDelivery, e)
	}
	li, e := os.Lstat(filepath.Join(path, "owner.lock"))
	if e != nil || !privateFile(li) || li.Size() != 0 {
		return nil, errors.Join(ErrAdmissionDelivery, e)
	}
	lock, e := os.OpenFile(filepath.Join(path, "owner.lock"), os.O_RDWR, 0)
	if e != nil {
		return nil, e
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, lock.Close())
		}
	}()
	held, e := lock.Stat()
	if e != nil || !os.SameFile(li, held) {
		return nil, errors.Join(ErrAdmissionDelivery, e)
	}
	if e := lockRoot(lock); e != nil {
		return nil, e
	}
	s = &admissionDeliveryStore{path: path, lock: lock, identity: map[string]os.FileInfo{path: info, filepath.Join(path, "owner.lock"): held}, placement: append([]byte(nil), placed...), static: static, retained: map[string][]byte{}, limits: optional}
	for name := range sources {
		info, e := os.Lstat(name)
		if e != nil {
			return nil, e
		}
		s.identity[name] = info
	}
	if e := s.checkPhysical(); e != nil {
		return nil, e
	}
	return s, nil
}

func (s *admissionDeliveryStore) checkPhysical() error {
	if s.lock == nil || s.failed {
		return ErrUncertain
	}
	for path, previous := range s.identity {
		info, e := os.Lstat(path)
		if e != nil || !os.SameFile(previous, info) || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(ErrAdmissionDelivery, e)
		}
		before, e := stampFile(previous)
		if e != nil {
			return e
		}
		after, e := stampFile(info)
		if e != nil || before != after {
			return errors.Join(ErrAdmissionDelivery, e)
		}
	}
	for name, expected := range s.static {
		raw, e := readFile(filepath.Join(s.path, name), len(expected))
		if e != nil || !bytes.Equal(expected, raw) {
			return errors.Join(ErrAdmissionDelivery, e)
		}
	}
	f, e := os.Open(s.path)
	if e != nil {
		return e
	}
	maximum := len(s.static) + len(s.limits) + 1
	entries, scanErr := f.ReadDir(maximum + 1)
	closeErr := f.Close()
	if scanErr != nil && !errors.Is(scanErr, io.EOF) || closeErr != nil {
		return errors.Join(scanErr, closeErr)
	}
	if len(entries) > maximum {
		return ErrAdmissionDelivery
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "owner.lock" {
			continue
		}
		if _, exists := s.static[name]; exists {
			continue
		}
		limit, exists := s.limits[name]
		if !exists {
			return ErrAdmissionDelivery
		}
		if _, e := readFile(filepath.Join(s.path, name), limit); e != nil {
			return e
		}
	}
	return nil
}

func (s *admissionDeliveryStore) check() error {
	if e := s.checkPhysical(); e != nil {
		return e
	}
	for name, limit := range s.limits {
		raw, e := readFile(filepath.Join(s.path, name), limit)
		expected, retained := s.retained[name]
		if !retained && errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil || !retained || !bytes.Equal(expected, raw) {
			return errors.Join(ErrAdmissionDelivery, e)
		}
	}
	return nil
}

func (s *admissionDeliveryStore) write(name string, raw []byte) error {
	if e := s.check(); e != nil {
		return e
	}
	limit, allowed := s.limits[name]
	if !allowed || len(raw) > limit {
		return ErrAdmissionDelivery
	}
	if old, exists := s.retained[name]; exists && !bytes.Equal(old, raw) {
		return ErrAdmissionDelivery
	}
	if e := publish(s.path, name, raw, s.hook); e != nil {
		s.failed = true
		return errors.Join(ErrUncertain, e)
	}
	s.retained[name] = append([]byte(nil), raw...)
	if e := s.check(); e != nil {
		s.failed = true
		return errors.Join(ErrUncertain, e)
	}
	return nil
}

// Cold open flushes only fully validated existing files. It never constructs an
// absent receipt, sends a packet, creates an owner or resumes an archive effect.
func (s *admissionDeliveryStore) stabilize() (returnErr error) {
	defer func() {
		if returnErr != nil {
			s.failed = true
			returnErr = errors.Join(ErrUncertain, returnErr)
		}
	}()
	if e := s.check(); e != nil {
		return e
	}
	names := []string{"owner.lock"}
	for name := range s.static {
		names = append(names, name)
	}
	for name := range s.retained {
		names = append(names, name)
	}
	for _, name := range names {
		path := filepath.Join(s.path, name)
		before, e := os.Lstat(path)
		if e != nil || !privateFile(before) {
			return errors.Join(ErrAdmissionDelivery, e)
		}
		f, e := os.OpenFile(path, os.O_RDWR, 0)
		if e != nil {
			return e
		}
		after, e := f.Stat()
		if e != nil || !os.SameFile(before, after) {
			_ = f.Close()
			return errors.Join(ErrAdmissionDelivery, e)
		}
		if e := errors.Join(f.Sync(), f.Close()); e != nil {
			return e
		}
	}
	if e := syncDir(s.path); e != nil {
		return e
	}
	return s.check()
}

func (s *admissionDeliveryStore) close() error {
	if s.lock == nil {
		return nil
	}
	e := s.lock.Close()
	s.lock = nil
	return e
}

func (i *AdmissionInbox) checkSource() error {
	if i.decision == nil {
		return ErrAdmissionDelivery
	}
	if e := i.decision.CheckAccess(); e != nil {
		return e
	}
	return i.s.check()
}
