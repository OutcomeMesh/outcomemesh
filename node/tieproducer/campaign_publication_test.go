package tieproducer

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/calibration"
)

type fileCampaignPublicationFixture struct {
	directory  string
	plan       calibration.TiePlan
	binding    calibration.TiePlanBinding
	planID     types.Hash
	checkpoint calibration.TiePairCheckpoint
	id         types.Hash
	reader     *FileObserverCampaign
}

func newCampaignPublicationFixture(t *testing.T) fileCampaignPublicationFixture {
	t.Helper()
	plan, binding, keys := campaignPlan(t)
	planID, _ := plan.ID()
	_, checkpoint := campaignPair(t, plan, binding, keys.coordinator, 1)
	id, err := checkpoint.ID(plan, binding, planID)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	reader, err := NewFileObserverCampaign(directory, t.TempDir(), plan, binding, planID)
	if err != nil {
		t.Fatal(err)
	}
	return fileCampaignPublicationFixture{directory, plan, binding, planID, checkpoint, id, reader}
}

func (f fileCampaignPublicationFixture) publish() error {
	return PublishCampaignCheckpoint(f.directory, f.plan, f.binding, f.planID, f.checkpoint, f.id)
}

func (f fileCampaignPublicationFixture) assertVisible(t *testing.T, visible bool) {
	t.Helper()
	checkpoint, id, err := f.reader.LoadPublishedCheckpoint(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	gate := FileCampaignPublicationGate{Directory: f.directory, PollInterval: time.Millisecond}
	gateErr := gate.WaitPublished(ctx, 1, f.id)
	if visible {
		if err != nil || checkpoint != f.checkpoint || id != f.id || gateErr != nil {
			t.Fatalf("published checkpoint=%+v id=%s err=%v gate=%v", checkpoint, id, err, gateErr)
		}
	} else if !IsMissingObserverCampaignFile(err) || !errors.Is(gateErr, context.Canceled) {
		t.Fatalf("staging exposed a final publication: observer=%v gate=%v", err, gateErr)
	}
}

func TestCampaignCheckpointPublicationReaderVisibility(t *testing.T) {
	f := newCampaignPublicationFixture(t)
	var visits []string
	writer := func(path string, encoded []byte, maximum int) error {
		return writeImmutableCampaignFileWithCheckpoint(path, encoded, maximum, func(stage string) error {
			extension := filepath.Ext(path)
			visits = append(visits, extension+":"+stage)
			visible := extension == ".published" && (stage == "linked" || stage == "directory-synced")
			f.assertVisible(t, visible)
			if extension == ".published" {
				// The checkpoint has completed both syncs before marker staging.
				got, err := os.ReadFile(filepath.Join(f.directory, "0000000001.omtcp"))
				if err != nil || !bytes.Equal(got, f.checkpoint.CanonicalBytes()) {
					t.Fatalf("marker preceded complete checkpoint: %x %v", got, err)
				}
			}
			return nil
		})
	}
	if err := publishCampaignCheckpoint(f.directory, f.plan, f.binding, f.planID, f.checkpoint, f.id, writer); err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, extension := range []string{".omtcp", ".published"} {
		for _, stage := range []string{"created", "written", "synced", "linked", "directory-synced"} {
			want = append(want, extension+":"+stage)
		}
	}
	if !slices.Equal(visits, want) {
		t.Fatalf("publication boundaries=%v want=%v", visits, want)
	}
	if err := f.publish(); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	f.assertVisible(t, true)
	entries, err := os.ReadDir(f.directory)
	if err != nil || len(entries) != 2 {
		t.Fatalf("publication left staging files: %v %v", entries, err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("publication permissions: %v %v", info, err)
		}
	}
}

// Split the former os.WriteFile publisher at its create/write boundary. This
// deterministically reproduces the process failure without relying on timing:
// both strict readers see an invalid marker, not an absent publication.
func TestDirectCampaignMarkerWriteExposesIncompletePublication(t *testing.T) {
	f := newCampaignPublicationFixture(t)
	if err := writeImmutableCampaignFile(filepath.Join(f.directory, "0000000001.omtcp"),
		f.checkpoint.CanonicalBytes(), calibration.TiePairCheckpointBytes); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(f.directory, "0000000001.published"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	_, _, observerErr := f.reader.LoadPublishedCheckpoint(1)
	gate := FileCampaignPublicationGate{Directory: f.directory, PollInterval: time.Millisecond}
	if err := gate.WaitPublished(context.Background(), 1, f.id); !errors.Is(err, ErrCampaignState) ||
		!errors.Is(observerErr, ErrCampaignState) {
		t.Fatalf("incomplete final file: observer=%v gate=%v", observerErr, err)
	}
	if _, err := file.WriteString(f.id.String() + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	f.assertVisible(t, true)
}

func TestCampaignCheckpointPublicationInterruptedAtEachBoundary(t *testing.T) {
	for _, extension := range []string{".omtcp", ".published"} {
		for _, stage := range []string{"created", "written", "synced", "linked", "directory-synced"} {
			t.Run(extension+"/"+stage, func(t *testing.T) {
				f := newCampaignPublicationFixture(t)
				injected := errors.New("interrupted publication")
				writer := func(path string, encoded []byte, maximum int) error {
					return writeImmutableCampaignFileWithCheckpoint(path, encoded, maximum, func(current string) error {
						if filepath.Ext(path) == extension && current == stage {
							return injected
						}
						return nil
					})
				}
				if err := publishCampaignCheckpoint(f.directory, f.plan, f.binding, f.planID, f.checkpoint, f.id, writer); !errors.Is(err, injected) {
					t.Fatalf("interruption error=%v", err)
				}
				f.assertVisible(t, extension == ".published" && (stage == "linked" || stage == "directory-synced"))
				if err := f.publish(); err != nil {
					t.Fatalf("exact retry: %v", err)
				}
				f.assertVisible(t, true)
			})
		}
	}
}

func TestCampaignCheckpointPublicationValidatesBeforeWriting(t *testing.T) {
	for _, name := range []string{"empty-directory", "missing-directory", "zero-plan-pin", "wrong-plan-pin", "zero-checkpoint-pin", "wrong-checkpoint-pin", "binding", "signature", "sequence", "plan-signature"} {
		t.Run(name, func(t *testing.T) {
			f := newCampaignPublicationFixture(t)
			directory := f.directory
			switch name {
			case "empty-directory":
				f.directory = ""
			case "missing-directory":
				f.directory = filepath.Join(directory, "missing")
			case "zero-plan-pin":
				f.planID = types.Hash{}
			case "wrong-plan-pin":
				f.planID[0] ^= 1
			case "zero-checkpoint-pin":
				f.id = types.Hash{}
			case "wrong-checkpoint-pin":
				f.id[0] ^= 1
			case "binding":
				f.binding.NetworkID++
			case "signature":
				f.checkpoint.Signature[0] ^= 1
			case "sequence":
				f.checkpoint.Sequence = 0
			case "plan-signature":
				f.plan.Signature[0] ^= 1
			}
			if err := f.publish(); err == nil {
				t.Fatal("invalid publication succeeded")
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 0 {
				t.Fatalf("invalid input wrote files: %v %v", entries, err)
			}
		})
	}
}

func TestCampaignCheckpointPublicationNeverReplacesExistingFiles(t *testing.T) {
	for _, extension := range []string{".omtcp", ".published"} {
		for _, contents := range []string{"", "conflicting-content"} {
			t.Run(extension+"/"+contents, func(t *testing.T) {
				f := newCampaignPublicationFixture(t)
				path := filepath.Join(f.directory, "0000000001"+extension)
				if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := f.publish(); !errors.Is(err, ErrCampaignState) {
					t.Fatalf("existing file error=%v", err)
				}
				got, err := os.ReadFile(path)
				if err != nil || string(got) != contents {
					t.Fatalf("existing file changed: %q %v", got, err)
				}
			})
		}
	}
}

func TestCampaignCheckpointPublicationConcurrentExactRetries(t *testing.T) {
	f := newCampaignPublicationFixture(t)
	var wg sync.WaitGroup
	start := make(chan struct{})
	errorsByWriter := make([]error, 16)
	for index := range errorsByWriter {
		wg.Go(func() {
			<-start
			errorsByWriter[index] = f.publish()
		})
	}
	close(start)
	wg.Wait()
	for _, err := range errorsByWriter {
		if err != nil {
			t.Fatalf("concurrent exact publication: %v", err)
		}
	}
	f.assertVisible(t, true)
}

func TestImmutableCampaignFileRejectsConflictingLinkWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "publication")
	winner := []byte("independently published value")
	err := writeImmutableCampaignFileWithCheckpoint(path, []byte("losing value"), 100, func(stage string) error {
		if stage == "synced" {
			return writeImmutableCampaignFile(path, winner, 100)
		}
		return nil
	})
	if !errors.Is(err, ErrCampaignState) {
		t.Fatalf("link conflict=%v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, winner) {
		t.Fatalf("conflicting publisher replaced winner: %q %v", got, err)
	}
}
