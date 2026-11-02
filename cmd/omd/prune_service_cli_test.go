package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	fencefixture "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

func pruneServiceCLIReview(t testing.TB, args []string) string {
	t.Helper()
	var out bytes.Buffer
	if err := runPruneServiceCLIContext(t.Context(), args, &out); err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	for _, field := range strings.Fields(strings.SplitN(out.String(), "\n", 2)[0]) {
		if strings.HasPrefix(field, "review_id=") {
			return strings.TrimPrefix(field, "review_id=")
		}
	}
	t.Fatal("service action omitted review ID")
	return ""
}
func pruneServiceCLIRun(t testing.TB, args []string) string {
	t.Helper()
	review := pruneServiceCLIReview(t, args)
	var out bytes.Buffer
	if err := runPruneServiceCLIContext(t.Context(), append(append([]string(nil), args...), "--mode", "run", "--expected-review-id", review), &out); err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	for _, field := range strings.Fields(out.String()) {
		if strings.HasPrefix(field, "artifact_id=") {
			return strings.TrimPrefix(field, "artifact_id=")
		}
	}
	t.Fatal("service action omitted artifact ID")
	return ""
}
func pruneServiceCLIJSON(t testing.TB, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writePruneCLIFile(t, path, raw)
}
func pruneServiceCLIRead(t testing.TB, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPruneServiceCLIPublicArtifactsStrictReviewAndSeedlessRetry(t *testing.T) {
	root := t.TempDir()
	input, output, seed := filepath.Join(root, "enrollment.json"), filepath.Join(root, "enrollment"), filepath.Join(root, "issuer.seed")
	e := prunefence.ServiceEnrollment{AssignmentID: fencefixture.Hash("assignment"), ScheduleID: fencefixture.Hash("schedule"), StorageID: fencefixture.Hash("storage"), StoragePairID: fencefixture.Hash("pair"), Service: fencefixture.Public(108), Issuer: fencefixture.Public(109), Guard: fencefixture.Public(110)}
	pruneServiceCLIJSON(t, input, e)
	args := []string{pruneServiceCommand, "--action", "enrollment-sign", "--input", input, "--key", seed, "--out", output}
	review := pruneServiceCLIReview(t, args)
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("review wrote output", err)
	}
	for _, extra := range [][]string{{"--mode", "run"}, {"--mode", "run", "--expected-review-id", fencefixture.Hash("other").String()}, {"--root", root}, {"--input", input}} {
		if err := runPruneServiceCLIContext(t.Context(), append(append([]string(nil), args...), extra...), io.Discard); err == nil {
			t.Fatal("invalid review accepted", extra)
		}
	}
	writePruneCLIFile(t, seed, fencefixture.Key(109).Seed())
	lost := pruneEffectTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
	if err := runPruneServiceCLIContext(t.Context(), append(append([]string(nil), args...), "--mode", "run", "--expected-review-id", review), lost); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("lost output", err)
	}
	signed, err := prunefence.DecodeServiceEnrollment(pruneServiceCLIRead(t, output))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := signed.ID()
	if err = os.Remove(seed); err != nil {
		t.Fatal(err)
	}
	if got := pruneServiceCLIRun(t, args); got != id.String() {
		t.Fatal("reported enrollment identity differs", got, id)
	}
	before := pruneServiceCLIRead(t, output)
	for _, bad := range [][]byte{[]byte(`null`), []byte(`{}`), append(pruneServiceCLIRead(t, input), []byte(` {}`)...), bytes.Replace(pruneServiceCLIRead(t, input), []byte(`"Service":`), []byte(`"unknown":`), 1), bytes.Replace(pruneServiceCLIRead(t, input), []byte(`"Issuer":`), []byte(`"Issuer":[],"Issuer":`), 1)} {
		original := pruneServiceCLIRead(t, input)
		writePruneCLIFile(t, input, bad)
		if err := runPruneServiceCLIContext(t.Context(), args, io.Discard); err == nil {
			t.Fatal("malformed unsigned enrollment accepted")
		}
		writePruneCLIFile(t, input, original)
	}
	if !bytes.Equal(before, pruneServiceCLIRead(t, output)) {
		t.Fatal("invalid input changed signed artifact")
	}

	policy := prunefence.Policy{Owner: pruneCLIPublic(4), Controller: pruneCLIPublic(1), Threshold: 3, Witnesses: fencefixture.Scope().Witnesses, Service: &signed}
	draft := wire.Descriptor{RootID: fencefixture.Hash("root"), ScopeID: fencefixture.Hash("scope"), ReviewID: fencefixture.Hash("review"), ConfigID: fencefixture.Hash("config"), Policy: policy, Binding: prunefence.Binding{RequestID: fencefixture.Hash("request"), AssignmentID: e.AssignmentID, OperationID: fencefixture.Hash("operation"), InventoryID: fencefixture.Hash("inventory"), ExecutorBindingID: fencefixture.Hash("executor"), StoragePairID: e.StoragePairID}, Transport: fencefixture.Public(111), OwnerUID: 0, ParticipantUID: 65534}
	draftPath, descriptorPath := filepath.Join(root, "descriptor.json"), filepath.Join(root, "descriptor")
	pruneServiceCLIJSON(t, draftPath, draft)
	writePruneCLIFile(t, seed, fencefixture.Key(109).Seed())
	descriptorArgs := []string{pruneServiceCommand, "--action", "descriptor-sign", "--input", draftPath, "--key", seed, "--out", descriptorPath}
	did := pruneServiceCLIRun(t, descriptorArgs)
	if err = os.Remove(seed); err != nil {
		t.Fatal(err)
	}
	if got := pruneServiceCLIRun(t, descriptorArgs); got != did {
		t.Fatal("descriptor retry changed ID")
	}
	d, err := wire.DecodeDescriptor(pruneServiceCLIRead(t, descriptorPath))
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := d.ID()
	if did != expected.String() {
		t.Fatal("wrong descriptor pin")
	}
	requestDraft, requestPath, consumer := filepath.Join(root, "request.json"), filepath.Join(root, "request"), filepath.Join(root, "consumer.seed")
	prepare := []string{pruneServiceCommand, "--action", "request-prepare", "--descriptor", descriptorPath, "--descriptor-id", did, "--nonce", fencefixture.Hash("nonce").String(), "--out", requestDraft}
	initialCursor := filepath.Join(root, "initial-position.json")
	prepare = append(prepare, "--position-out", initialCursor)
	pruneServiceCLIRun(t, prepare)
	var initial wire.Position
	if err = json.Unmarshal(pruneServiceCLIRead(t, initialCursor), &initial); err != nil || initial != (wire.Position{}) {
		t.Fatal("initial cursor export", err)
	}
	writePruneCLIFile(t, consumer, pruneCLIKey(4).Seed())
	sign := []string{pruneServiceCommand, "--action", "request-sign", "--input", requestDraft, "--descriptor", descriptorPath, "--descriptor-id", did, "--key", consumer, "--out", requestPath}
	qid := pruneServiceCLIRun(t, sign)
	if err = os.Remove(consumer); err != nil {
		t.Fatal(err)
	}
	if got := pruneServiceCLIRun(t, sign); got != qid {
		t.Fatal("request retry changed ID")
	}
	q, err := wire.DecodeRequest(pruneServiceCLIRead(t, requestPath))
	if err != nil || q.Authorize(d) != nil {
		t.Fatal("invalid signed request", err)
	}
	if got, _ := q.ID(); got.String() != qid {
		t.Fatal("wrong request pin")
	}
	bad := append([]string(nil), prepare...)
	for i := range bad {
		if bad[i] == did {
			bad[i] = types.Hash{7}.String()
		}
	}
	if err := runPruneServiceCLIContext(t.Context(), bad, io.Discard); err == nil {
		t.Fatal("substituted descriptor accepted")
	}
}

func TestPruneServiceCLIRejectsUnsupportedTransportBeforePlacement(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux supports peer credentials")
	}
	for _, action := range []string{"serve", "call", "cleanup-socket"} {
		err := runPruneServiceCLIContext(t.Context(), []string{pruneServiceCommand, "--action", action}, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "Linux peer credentials") {
			t.Fatal("unsupported transport inspected placement", action, err)
		}
	}
}

func TestPruneServiceCLIReviewRejectsUnrepresentableOwnerPaths(t *testing.T) {
	for _, path := range []string{"/owner/\xff", "/owner/\x00"} {
		args := []string{pruneServiceCommand, "--action", "identity-create", "--root", path, "--out", filepath.Join(t.TempDir(), "identity")}
		if err := runPruneServiceCLIContext(t.Context(), args, io.Discard); err == nil {
			t.Fatal("invalid path was lossy in the reviewed JSON")
		}
	}
}
