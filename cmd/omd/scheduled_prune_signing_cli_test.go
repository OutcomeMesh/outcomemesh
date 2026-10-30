package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

func scheduledSigningCLIFixture(t testing.TB) ([]string, store.ScheduledPrunePlan) {
	t.Helper()
	raw, err := os.ReadFile("../../node/custodyauthority/store/testdata/scheduled_prune_plan_v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Plan   []byte
		PlanID types.Hash
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "plan")
	writePruneCLIFile(t, path, v.Plan)
	p, err := store.LoadScheduledPrunePlan(path, v.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile("../../node/custodyauthority/store/testdata/scheduled_prune_v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var old struct{ Inventory []byte }
	if err := json.Unmarshal(original, &old); err != nil {
		t.Fatal(err)
	}
	inv, err := store.DecodeScheduledPruneInventory(old.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	s := inv.Replicas[0]
	aid, _ := s.Assignment.ID()
	c := s.Admission.Command
	return []string{scheduledSignCommand, "--plan", path, "--plan-id", v.PlanID.String(), "--assignment-id", aid.String(), "--kind", "admit", "--expected-sequence", strconv.FormatUint(c.ExpectedSequence, 10), "--expected-head", c.ExpectedHead.String()}, p
}
func TestScheduledPruneSigningCLIRejectsBeforeReadingKeys(t *testing.T) {
	base, _ := scheduledSigningCLIFixture(t)
	var review struct{ ReviewID types.Hash }
	scheduledCLIRun(t, base, &review)
	key := filepath.Join(t.TempDir(), "missing-key")
	out := filepath.Join(t.TempDir(), "command")
	wrong := append(append([]string(nil), base...), "--mode", "sign", "--expected-review-id", types.DomainHash("cli-test", []byte{231}).String(), "--consumer-key", key, "--out", out)
	if err := runScheduledPruneOperator(t.Context(), wrong, io.Discard); !errors.Is(err, custodyauthority.ErrPruneReview) || errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrong review reached key", err)
	}
	for _, extra := range [][]string{{"--consumer-key", ""}, {"--out", ""}, {"--expected-review-id", ""}, {"--inventory", ""}, {"--effect", ""}, {"--kind", "admit"}, {"--mode", "execute"}, {"--expected-sequence", "02"}, {"unexpected"}} {
		args := append(append([]string(nil), base...), extra...)
		if err := runScheduledPruneOperator(t.Context(), args, io.Discard); err == nil {
			t.Fatal("ambiguous review accepted", extra)
		}
	}
	writePruneCLIFile(t, key, pruneCLIKey(4).Seed())
	sign := append(append([]string(nil), base...), "--mode", "sign", "--expected-review-id", review.ReviewID.String(), "--consumer-key", key)
	if err := runScheduledPruneOperator(t.Context(), append(append([]string(nil), sign...), "--out", key), io.Discard); err == nil {
		t.Fatal("output replaced key")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runScheduledPruneOperator(ctx, append(append([]string(nil), sign...), "--out", out), io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled signing published")
	}
	lost := errors.New("output disconnected")
	args := append(append([]string(nil), sign...), "--out", out)
	if err := runScheduledPruneOperator(t.Context(), args, pruneEffectTestWriter(func([]byte) (int, error) { return 0, lost })); !errors.Is(err, lost) {
		t.Fatal(err)
	}
	retained, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	scheduledCLIRun(t, args, nil)
	again, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(retained, again) {
		t.Fatal("lost signing output changed artifact", err)
	}
	signed, err := custodyauthority.DecodeCommand(retained)
	if err != nil {
		t.Fatal(err)
	}
	signed.OperationID = types.DomainHash("cli-test", []byte{232})
	signed, err = signed.Sign(pruneCLIKey(4))
	if err != nil {
		t.Fatal(err)
	}
	changed, _ := signed.CanonicalBytes()
	foreign := filepath.Join(t.TempDir(), "foreign-command")
	writePruneCLIFile(t, foreign, changed)
	cosign := append([]string(nil), base...)
	cosign[0] = scheduledCosignCommand
	cosign = append(cosign, "--command", foreign)
	if err := runScheduledPruneOperator(t.Context(), cosign, io.Discard); err == nil {
		t.Fatal("cosigned another request")
	}
	for _, flag := range []string{"entry", "entry-id", "journal"} {
		if err := runScheduledPruneOperator(t.Context(), []string{scheduledEffectCommand, "--" + flag, ""}, io.Discard); err == nil {
			t.Fatal("effect accepted ignored flag", flag)
		}
	}
}
func TestScheduledPruneInventorySourcesRejectAmbiguousJSON(t *testing.T) {
	base, _ := scheduledSigningCLIFixture(t)
	planPath, planID := base[2], base[4]
	for _, raw := range []string{`[{"assignment_id":"x","assignment_id":"y"}]`, `[{"Assignment_id":"x"}]`, `[{"assignment_id":"x","unknown":"x"}]`, `[] {}`, `null`, `[]`} {
		path := filepath.Join(t.TempDir(), "sources")
		writePruneCLIFile(t, path, []byte(raw))
		if err := runScheduledPruneOperator(t.Context(), []string{scheduledInventoryCommand, "--plan", planPath, "--plan-id", planID, "--sources", path}, io.Discard); err == nil {
			t.Fatal("ambiguous package sources accepted", raw)
		}
	}
}
