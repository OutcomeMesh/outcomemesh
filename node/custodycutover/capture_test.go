package custodycutover

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	a "github.com/outcomemesh/outcomemesh/node/custodyauthority"
	s "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func originalSources(t testing.TB) (Evidence, SourceLocation, SourceLocation) {
	t.Helper()
	e := evidenceFixture(t, false)
	root := originalTemp(t)
	aid, _ := e.Assignment.ID()
	authority, pins := filepath.Join(root, "authority"), filepath.Join(root, "pins")
	owner, err := s.CreateCoordinatedAuthority(authority, pins, e.Assignment, aid)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range e.History {
		if _, err = owner.Append(t.Context(), entry); err != nil {
			t.Fatal(err)
		}
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	aa := SourceLocation{Role: Authority, Journal: filepath.Join(root, "source-a"), Authority: authority, AuthorityPins: pins}
	bb := SourceLocation{Role: Target, Journal: filepath.Join(root, "source-b")}
	for _, p := range []string{aa.Journal, bb.Journal} {
		if _, _, err = workarchive.OpenOrCreateCustodyJournal(p, e.Manifest, e.Initial, e.Policy); err != nil {
			t.Fatal(err)
		}
	}
	return e, aa, bb
}
func TestRemoteCutoverOriginalHistoryExportAndSourceGuards(t *testing.T) {
	e, aa, bb := originalSources(t)
	lid, _ := e.Assignment.ID()
	anchor := f.Hash("pinned-stable-anchor")
	owner, err := s.OpenCoordinator(aa.Authority, aa.AuthorityPins, e.Assignment, lid)
	if err != nil {
		t.Fatal(err)
	}
	template := cloneEvidence(t, e)
	template.History = nil
	template.End = a.Position{}
	var exported Evidence
	called := false
	if err = ExportEvidence(t.Context(), owner, template, lid, e.End, func(v Evidence) error {
		exported = v
		called = true
		if other, err := s.OpenCoordinator(aa.Authority, aa.AuthorityPins, e.Assignment, lid); err == nil {
			other.Close()
			t.Fatal("export released original owner")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("missing full original history")
	}
	want, _ := e.CanonicalBytes()
	got, _ := exported.CanonicalBytes()
	if !bytes.Equal(want, got) {
		t.Fatal("history changed")
	}
	if err = ExportEvidence(t.Context(), owner, e, lid, e.End, func(Evidence) error { return nil }); err == nil {
		t.Fatal("accepted supplied history in template")
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	for _, location := range []SourceLocation{aa, bb} {
		placement, err := location.LocationID()
		if err != nil {
			t.Fatal(err)
		}
		seed := byte(1)
		if location.Role == Target {
			seed = 14
		}
		count := 0
		observe := func(o Observation) error {
			count++
			if err := o.Verify(e, anchor); err != nil {
				t.Fatal(err)
			}
			lock, err := os.OpenFile(filepath.Join(location.Journal, "journal.lock"), os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			if err := lockPreparation(lock); err == nil {
				t.Fatal("observation released source lock before publication")
			}
			return nil
		}
		o, err := CaptureSource(t.Context(), e, lid, anchor, e.End, location, placement, f.Hash("capture-nonce"), f.Key(seed), observe)
		if err != nil {
			t.Fatal("capture", err)
		}
		retry, err := CaptureSource(t.Context(), e, lid, anchor, e.End, location, placement, f.Hash("capture-nonce"), f.Key(seed), func(Observation) error { return nil })
		if err != nil || retry != o || count != 1 {
			t.Fatal("exact historical recapture changed", err)
		}
		never := func(Observation) error { t.Fatal("invalid source published"); return nil }
		if _, err = CaptureSource(t.Context(), e, lid, anchor, e.End, location, f.Hash("other location"), f.Hash("nonce"), f.Key(seed), never); err == nil {
			t.Fatal("wrong original placement accepted")
		}
		if _, err = CaptureSource(t.Context(), e, lid, anchor, e.End, location, placement, types.Hash{}, f.Key(seed), never); err == nil {
			t.Fatal("implicit nonce")
		}
		if _, err = CaptureSource(t.Context(), e, lid, anchor, e.End, location, placement, f.Hash("nonce"), f.Key(120), never); err == nil {
			t.Fatal("wrong source signer")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err = CaptureSource(ctx, e, lid, anchor, e.End, location, placement, f.Hash("nonce"), f.Key(seed), never); !errors.Is(err, context.Canceled) {
			t.Fatal("cancel ignored", err)
		}
		callbackErr := errors.New("publication failed")
		if _, err = CaptureSource(t.Context(), e, lid, anchor, e.End, location, placement, f.Hash("nonce"), f.Key(seed), func(Observation) error { return callbackErr }); !errors.Is(err, callbackErr) {
			t.Fatal("lost failed publication", err)
		}
	}
}
func TestRemoteCutoverChangedSourcePlacementAndUnretiredHistoryRefused(t *testing.T) {
	e, aa, bb := originalSources(t)
	lid, _ := e.Assignment.ID()
	placement, err := bb.LocationID()
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(originalTemp(t), "copied-source")
	if err = os.CopyFS(destination, os.DirFS(bb.Journal)); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(destination, 0700); err != nil {
		t.Fatal(err)
	}
	bb.Journal = destination
	if _, err = CaptureSource(t.Context(), e, lid, f.Hash("anchor"), e.End, bb, placement, f.Hash("nonce"), f.Key(14), func(Observation) error { t.Fatal("copied source published"); return nil }); err == nil {
		t.Fatal("copy used original placement pin")
	}
	owner, err := s.OpenCoordinator(aa.Authority, aa.AuthorityPins, e.Assignment, lid)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err = owner.WithConfirmedRetirement(t.Context(), a.Position{Sequence: e.End.Sequence - 1, HeadID: e.End.HeadID}, MaximumHistoryEntries, func(a.Assignment, []a.Entry) error { t.Fatal("wrong position exported"); return nil }); err == nil {
		t.Fatal("wrong retirement pin")
	}
	c := publicContext(t)
	path := originalTemp(t)
	fresh, err := s.CreateCoordinatedAuthority(filepath.Join(path, "a"), filepath.Join(path, "p"), c.Assignment.Base, lid)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err = fresh.WithConfirmedRetirement(t.Context(), a.Position{HeadID: lid}, MaximumHistoryEntries, func(a.Assignment, []a.Entry) error { t.Fatal("live authority exported"); return nil }); err == nil {
		t.Fatal("unretired original exported")
	}
}
