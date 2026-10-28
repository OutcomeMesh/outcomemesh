package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	cut "github.com/outcomemesh/outcomemesh/node/custodycutover"
	gateway "github.com/outcomemesh/outcomemesh/node/custodygateway"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

func gatewayCLIInProcess(t testing.TB, args []string) string {
	t.Helper()
	var out bytes.Buffer
	if e := runCustodyGateway(t.Context(), args, &out); e != nil {
		t.Fatal(args, e)
	}
	return out.String()
}
func gatewayReviewed(t testing.TB, driver v2CLIDriver, args []string) []string {
	t.Helper()
	fields := pruneCLIFields(strings.SplitN(driver(t, args), "\n", 2)[0])
	if fields["review_id"] == "" || fields["owners_opened"] != "false" || fields["keys_loaded"] != "false" {
		t.Fatal(fields)
	}
	return append(append([]string{}, args...), "--mode", "run", "--expected-review-id", fields["review_id"])
}

type gatewayFixture struct {
	root, dir  string
	config     gateway.Config
	descriptor wire.Descriptor
	id         types.Hash
	g          v2.AdmissionGenesis
	b          v2.EnrollmentBinding
}

func gatewayPrepare(t testing.TB, driver v2CLIDriver, g v2.AdmissionGenesis, b v2.EnrollmentBinding, l cut.SourceLocation, placement types.Hash, objects string) gatewayFixture {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(dir, "owner")
	identityPath := filepath.Join(dir, "identity.json")
	args := []string{custodyGatewayCommand, "--action", "identity-create", "--root", root, "--out", identityPath}
	review := gatewayReviewed(t, driver, args)
	if _, e = os.Stat(root); !os.IsNotExist(e) {
		t.Fatal("review created root", e)
	}
	if e = runCustodyGateway(t.Context(), replaceRemoteCLIFlag(review, "--root", filepath.Join(dir, "wrong")), &bytes.Buffer{}); e == nil {
		t.Fatal("changed review")
	}
	driver(t, review)
	var identity gateway.Identity
	raw, e := os.ReadFile(identityPath)
	if e != nil || json.Unmarshal(raw, &identity) != nil {
		t.Fatal(e)
	}
	gid, _ := g.ID()
	gdid, _ := g.DescriptorID()
	bid, _ := b.ID()
	pins := cut.SourceHandoffPins{GenesisID: gid, GenesisDescriptorID: gdid, EnrollmentID: bid, PlacementID: placement}
	h, e := cut.ReviewSourceHandoff(g, b, pins, l.Role)
	if e != nil {
		t.Fatal(e)
	}
	hid, _ := h.ID()
	var oid types.Hash
	if objects != "" {
		objects, e = filepath.EvalSymlinks(objects)
		if e != nil {
			t.Fatal(e)
		}
	}
	if l.Role == cut.Target {
		oid, e = gateway.PlacementID(objects, true)
		if e != nil {
			t.Fatal(e)
		}
	} else {
		objects = ""
	}
	d := wire.Descriptor{RootID: identity.RootID, SourceID: hid, GenesisID: gid, GenesisDescriptorID: gdid, EnrollmentID: bid, ObjectsID: oid, Gateway: identity.PublicKey, Issuer: b.Registry.Issuer, Clients: [][32]byte{f.Public(14)}, OwnerUID: uint32(os.Geteuid()), ParticipantUID: 65534, EventLimit: 8}
	if os.Geteuid() == 65534 {
		d.ParticipantUID = 65533
	}
	template := filepath.Join(dir, "descriptor.json")
	gbDraft, _ := g.CanonicalBytes()
	bbDraft, _ := b.CanonicalBytes()
	draftConfig := gateway.Config{Genesis: gbDraft, Enrollment: bbDraft, Pins: pins, Source: l, Objects: objects}
	draftPath := filepath.Join(dir, "draft-config.json")
	cutoverWrite(t, draftPath, draftConfig)
	prepare := []string{custodyGatewayCommand, "--action", "descriptor-prepare", "--root", root, "--input", draftPath, "--participant-uid", fmt.Sprint(d.ParticipantUID), "--event-limit", "8", "--clients", hex.EncodeToString(d.Clients[0][:]), "--out", template}
	driver(t, gatewayReviewed(t, driver, prepare))
	draftRaw, e := os.ReadFile(template)
	var derived wire.Descriptor
	if e != nil || json.Unmarshal(draftRaw, &derived) != nil {
		t.Fatal(e)
	}
	expectedJSON, _ := json.Marshal(d)
	actualJSON, _ := json.Marshal(derived)
	if !bytes.Equal(expectedJSON, actualJSON) {
		t.Fatal("descriptor derivation changed public pins")
	}

	issuer := filepath.Join(dir, "issuer.seed")
	writePruneCLIFile(t, issuer, []byte(hex.EncodeToString(f.Key(110).Seed())))
	descPath := filepath.Join(dir, "descriptor")
	args = []string{custodyGatewayCommand, "--action", "descriptor-sign", "--input", template, "--key", issuer, "--out", descPath}
	driver(t, gatewayReviewed(t, driver, args))
	raw, e = os.ReadFile(descPath)
	if e != nil {
		t.Fatal(e)
	}
	d, e = wire.DecodeDescriptor(raw)
	if e != nil {
		t.Fatal(e)
	}
	did, _ := d.ID()
	gb, _ := g.CanonicalBytes()
	bb, _ := b.CanonicalBytes()
	config := gateway.Config{Descriptor: raw, Genesis: gb, Enrollment: bb, Pins: pins, Source: l, Objects: objects}
	configPath := filepath.Join(dir, "config.json")
	cutoverWrite(t, configPath, config)
	args = []string{custodyGatewayCommand, "--action", "configure", "--root", root, "--input", configPath, "--out", filepath.Join(dir, "configured.json")}
	driver(t, gatewayReviewed(t, driver, args))
	return gatewayFixture{root, dir, config, d, did, g, b}
}
func gatewayRequest(t testing.TB, d wire.Descriptor, p wire.Position, kind uint8, chunk types.Hash, nonce string, seed byte) wire.Request {
	t.Helper()
	id, _ := d.ID()
	q, e := (wire.Request{DescriptorID: id, Before: p, Nonce: f.Hash(nonce), Kind: kind, ChunkID: chunk}).Sign(f.Key(seed))
	if e != nil {
		t.Fatal(e)
	}
	return q
}
func gatewayExecute(t testing.TB, o *gateway.Owner, d wire.Descriptor, q wire.Request) wire.Response {
	t.Helper()
	raw, e := o.Execute(t.Context(), q)
	if e != nil {
		t.Fatal(e)
	}
	r, e := wire.DecodeResponse(raw)
	if e != nil || r.Verify(d, q) != nil {
		t.Fatal(e)
	}
	return r
}
func runGatewayOwnerAcceptance(t *testing.T, driver v2CLIDriver, g v2.AdmissionGenesis, b v2.EnrollmentBinding, locations []cut.SourceLocation, placements []types.Hash, objects string) {
	t.Helper()
	fixture := gatewayPrepare(t, driver, g, b, locations[1], placements[1], objects)
	o, e := gateway.Open(fixture.root, fixture.id, wire.Position{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = gateway.Open(fixture.root, fixture.id, wire.Position{}, nil); e == nil {
		t.Fatal("second owner")
	}
	q := gatewayRequest(t, fixture.descriptor, wire.Position{}, wire.Inspect, types.Hash{}, "inspect", 14)
	r := gatewayExecute(t, o, fixture.descriptor, q)
	p, _ := r.Position()
	responsePath := filepath.Join(fixture.dir, "first.response")
	writePruneCLIFile(t, responsePath, wantResponse(t, r))
	inspectArgs := []string{custodyGatewayCommand, "--action", "response-inspect", "--descriptor", filepath.Join(fixture.dir, "descriptor"), "--descriptor-id", fixture.id.String(), "--response", responsePath, "--out", filepath.Join(fixture.dir, "public-position.json")}
	driver(t, gatewayReviewed(t, driver, inspectArgs))
	var report struct {
		Position         wire.Position
		Revoked          bool
		ExecutionGranted bool
	}
	reportRaw, e := os.ReadFile(filepath.Join(fixture.dir, "public-position.json"))
	if e != nil || json.Unmarshal(reportRaw, &report) != nil || report.Position != p || report.Revoked || report.ExecutionGranted {
		t.Fatal("public reply inspection", e)
	}

	retry, e := o.Execute(t.Context(), q)
	want, _ := r.CanonicalBytes()
	if e != nil || !bytes.Equal(retry, want) {
		t.Fatal("retry changed", e)
	}
	stale := gatewayRequest(t, fixture.descriptor, wire.Position{}, wire.Inspect, types.Hash{}, "other attempt", 14)
	if _, e = o.Execute(t.Context(), stale); e == nil {
		t.Fatal("stale request")
	}
	outsider := gatewayRequest(t, fixture.descriptor, p, wire.Inspect, types.Hash{}, "outsider", 101)
	if _, e = o.Execute(t.Context(), outsider); e == nil {
		t.Fatal("unlisted old/new key")
	}
	badChunk := gatewayRequest(t, fixture.descriptor, p, wire.ReadChunk, f.Hash("absent"), "bad chunk", 14)
	if _, e = o.Execute(t.Context(), badChunk); e == nil {
		t.Fatal("arbitrary chunk")
	}
	if pos, _ := o.Position(); pos != p {
		t.Fatal("refusal advanced")
	}
	q = gatewayRequest(t, fixture.descriptor, p, wire.ReadChunk, g.Manifest.Chunks[0].ID, "read original", 14)
	r = gatewayExecute(t, o, fixture.descriptor, q)
	p, _ = r.Position()
	if len(r.Data) != int(g.Manifest.Chunks[0].EncodedBytes) {
		t.Fatal("missing original object")
	}
	// Lost response recovery cannot adopt the live tip or another attempt.
	if e = o.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = gateway.Open(fixture.root, fixture.id, q.Before, nil); e == nil {
		t.Fatal("adopted tip")
	}
	other := q
	other.Nonce = f.Hash("wrong recovery")
	other, _ = other.Sign(f.Key(14))
	if _, e = gateway.Open(fixture.root, fixture.id, q.Before, &other); e == nil {
		t.Fatal("other recovery")
	}
	o, e = gateway.Open(fixture.root, fixture.id, q.Before, &q)
	if e != nil {
		t.Fatal(e)
	}
	retry, e = o.Execute(t.Context(), q)
	want, _ = r.CanonicalBytes()
	if e != nil || !bytes.Equal(want, retry) {
		t.Fatal("cold exact retry", e)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	next := gatewayRequest(t, fixture.descriptor, p, wire.Inspect, types.Hash{}, "cancel", 14)
	if _, e = o.Execute(canceled, next); e == nil {
		t.Fatal("canceled operation")
	}
	revoke := gatewayRequest(t, fixture.descriptor, p, wire.Revoke, types.Hash{}, "revoke", 110)
	rr := gatewayExecute(t, o, fixture.descriptor, revoke)
	end, _ := rr.Position()
	if _, e = o.Execute(t.Context(), q); e == nil {
		t.Fatal("old read replayed after revoke")
	}
	if _, e = o.Execute(t.Context(), gatewayRequest(t, fixture.descriptor, end, wire.Inspect, types.Hash{}, "after revoke", 14)); e == nil {
		t.Fatal("read after revoke")
	}
	o.Close()
	o, e = gateway.Open(fixture.root, fixture.id, end, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, revoked := o.Position(); !revoked {
		t.Fatal("revocation lost")
	}
	o.Close()
	copyRoot := filepath.Join(fixture.dir, "copy")
	if e = os.CopyFS(copyRoot, os.DirFS(fixture.root)); e != nil {
		t.Fatal(e)
	}
	os.Chmod(copyRoot, 0700)
	if _, e = gateway.Open(copyRoot, fixture.id, end, nil); e == nil {
		t.Fatal("copied owner")
	}
	// A source proof failure does not make revocation unavailable.
	proof := filepath.Join(locations[1].Journal, "source-handoff-proof.omcsh")
	proofRaw, e := os.ReadFile(proof)
	if e != nil {
		t.Fatal(e)
	}
	second := gatewayPrepare(t, driver, g, b, locations[1], placements[1], objects)
	o, e = gateway.Open(second.root, second.id, wire.Position{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(proof, []byte("corrupt"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = o.Execute(t.Context(), gatewayRequest(t, second.descriptor, wire.Position{}, wire.ReadChunk, g.Manifest.Chunks[0].ID, "corrupt source", 14)); e == nil {
		t.Fatal("corrupt source read")
	}
	gatewayExecute(t, o, second.descriptor, gatewayRequest(t, second.descriptor, wire.Position{}, wire.Revoke, types.Hash{}, "revoke corrupt", 110))
	o.Close()
	if e = os.WriteFile(proof, proofRaw, 0600); e != nil {
		t.Fatal(e)
	}
	// No participant seed was reused as the service identity.
	for _, seed := range []byte{1, 14, 101, 102, 103, 110, 111, 112, 113} {
		if bytes.Equal(f.Key(seed).Public().(ed25519.PublicKey), fixture.descriptor.Gateway[:]) {
			t.Fatal("reused participant key")
		}
	}
}
func TestRequiredGatewayCLIAndOriginalStorage(t *testing.T) {
	runSourceHandoffFixture(t, sourceHandoffCLIInProcess, func(g v2.AdmissionGenesis, b v2.EnrollmentBinding, l []cut.SourceLocation, p []types.Hash, objects string) {
		runGatewayOwnerAcceptance(t, gatewayCLIInProcess, g, b, l, p, objects)
	})
}

func wantResponse(t testing.TB, r wire.Response) []byte {
	t.Helper()
	raw, e := r.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
