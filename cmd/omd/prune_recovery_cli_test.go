package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

func pruneCLIRecoveryFixture(t testing.TB, cancelled bool) *pruneCLIFixture {
	t.Helper()
	f := newPruneCLIFixture(t)
	admitPruneMaintenanceFixture(t, f)
	name := "01.omcpp"
	if cancelled {
		review := runPruneMaintenanceFields(t, f.maintenanceArgs())
		runPruneMaintenanceFields(t, append(f.maintenanceArgs(), "--mode", "cancel", "--expected-review-id", review["review_id"]))
		name = "02.omcpp"
	}
	// Keep the disposable fixture's original confirmation; simulate the exact
	// already-published record with an independently retained pending intent.
	if err := os.Rename(filepath.Join(f.config.ExecutorPinsPath, "confirmed", name), filepath.Join(f.root, "saved-confirmation")); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestPruneRecoveryCLIReviewAndExactAction(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		action := "executor-admission"
		if cancelled {
			action = "executor-cancellation"
		}
		t.Run(action, func(t *testing.T) {
			f := pruneCLIRecoveryFixture(t, cancelled)
			before := prunePrepareTree(t, f.root)
			reviewArgs := append(f.maintenanceArgs(), "--mode", "recovery-review")
			review := runPruneMaintenanceFields(t, reviewArgs)
			if review["recovery_action"] != action || review["recovery_performed"] != "false" || review["effect_execution"] != "false" || review["automatic_resume"] != "false" {
				t.Fatal("wrong recovery review", review)
			}
			if again := runPruneMaintenanceFields(t, reviewArgs); !reflect.DeepEqual(review, again) {
				t.Fatal("review was not repeatable")
			}
			args := append(f.maintenanceArgs(), "--mode", "recover", "--expected-review-id", review["review_id"], "--recovery-action", action)
			for _, wrong := range [][]string{pruneCLISet(args, "expected-review-id", pruneCLIHash(99).String()), pruneCLISet(args, "recovery-action", "executor-start")} {
				var output bytes.Buffer
				if err := runPruneOffline(t.Context(), wrong, &output); !errors.Is(err, authoritystore.ErrPruneRecoveryReview) || output.Len() != 0 {
					t.Fatal("unreviewed recovery accepted", err)
				}
			}
			if !reflect.DeepEqual(before, prunePrepareTree(t, f.root)) {
				t.Fatal("review/rejection changed retained files")
			}
			result := runPruneMaintenanceFields(t, args)
			if result["expected_review_id"] != review["review_id"] || result["recovered_action"] != action || result["recovery_action"] != "none" ||
				result["recovery_performed"] != "true" || result["single_transition"] != "true" || result["effect_execution"] != "false" || result["automatic_retry"] != "false" {
				t.Fatal("invalid recovery result", result)
			}
			after := runPruneMaintenanceFields(t, reviewArgs)
			if after["review_id"] == review["review_id"] || after["review_id"] != result["after_review_id"] || after["recovery_action"] != "none" {
				t.Fatal("recovery did not replace the reviewed prefix")
			}
			for _, stale := range [][]string{args, pruneCLISet(args, "expected-review-id", after["review_id"])} {
				if err := runPruneOffline(t.Context(), stale, io.Discard); !errors.Is(err, authoritystore.ErrPruneRecoveryReview) {
					t.Fatal("recovery automatically retried", err)
				}
			}
			state, authority := f.snapshot(t)
			if state.Protection.Pending != nil || authority.Authority.Sequence != 1 || authority.Authority.Pending != 1 {
				t.Fatal("recovery submitted Complete or did not confirm")
			}
		})
	}
}

func TestPruneRecoveryCLIRejectsFlags(t *testing.T) {
	f := newPruneCLIFixture(t)
	before := prunePrepareTree(t, f.root)
	for _, extra := range [][]string{
		{"--recovery-action", ""}, {"--mode", "cancel", "--recovery-action", "executor-cancellation"},
		{"--mode", "recovery-review", "--expected-review-id", ""}, {"--mode", "recovery-review", "--recovery-action", ""},
		{"--mode", "recover"}, {"--mode", "recover", "--expected-review-id", pruneCLIHash(99).String()},
		{"--mode", "recover", "--recovery-action", "executor-start"},
	} {
		if err := runPruneOffline(t.Context(), append(f.maintenanceArgs(), extra...), io.Discard); err == nil {
			t.Fatal("missing/forbidden flag accepted", extra)
		}
	}
	for _, action := range []string{"", "none", "blocked", "execute", "Executor-Start", "executor-start ", "retire", "complete"} {
		if _, err := parsePruneRecoveryAction(action); err == nil {
			t.Fatal("invalid action accepted", action)
		}
	}
	for action := authoritystore.PruneRecoveryAuthorityAdmission; action <= authoritystore.PruneRecoveryExecutorCancellation; action++ {
		if got, err := parsePruneRecoveryAction(action.String()); err != nil || got != action {
			t.Fatal("valid action rejected", action, err)
		}
	}
	if !reflect.DeepEqual(before, prunePrepareTree(t, f.root)) {
		t.Fatal("invalid flag changed roots")
	}
}

func TestPruneRecoveryCLIOutputFailureKeepsConfirmation(t *testing.T) {
	for _, short := range []bool{false, true} {
		f := pruneCLIRecoveryFixture(t, true)
		reviewArgs := append(f.maintenanceArgs(), "--mode", "recovery-review")
		review := runPruneMaintenanceFields(t, reviewArgs)
		fault := errors.New("unavailable recovery output")
		var output io.Writer = pruneFailWriter{fault}
		if short {
			output, fault = pruneShortWriter{}, io.ErrShortWrite
		}
		before := prunePrepareTree(t, f.root)
		if err := runPruneOffline(t.Context(), reviewArgs, output); !errors.Is(err, fault) {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, prunePrepareTree(t, f.root)) {
			t.Fatal("lost review changed files")
		}
		args := append(f.maintenanceArgs(), "--mode", "recover", "--recovery-action", "executor-cancellation", "--expected-review-id", review["review_id"])
		if err := runPruneOffline(t.Context(), args, output); !errors.Is(err, fault) || !errors.Is(err, errPruneMaintenanceUnobserved) {
			t.Fatal("lost confirmation output reported success", err)
		}
		if err := runPruneOffline(t.Context(), args, io.Discard); !errors.Is(err, authoritystore.ErrPruneRecoveryReview) {
			t.Fatal("old review remained usable", err)
		}
		after := runPruneMaintenanceFields(t, reviewArgs)
		if after["review_id"] == review["review_id"] || after["recovery_action"] != "none" || after["executor_confirmed_stage"] != "5" {
			t.Fatal("lost stdout erased confirmation")
		}
	}
}
