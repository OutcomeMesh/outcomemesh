//go:build integration

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/transport"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const remoteCustodyFixtureOutputEnvironment = "OUTCOMEMESH_REMOTE_FIXTURE_OUT"

// This exporter is intentionally absent from omd. It provisions two fresh test
// roles, not copies of a live coordinator. Only immutable archive data comes
// from the existing archive generator; none of its owners or keys is exported.
// Run it last, after builds/deployment preparation: the fixed intent has the
// core's maximum 600-second lifetime and is never refreshed by this exporter.
func TestExportRemoteCustodyFixture(t *testing.T) {
	parent := os.Getenv(remoteCustodyFixtureOutputEnvironment)
	if parent == "" {
		t.Skip("set OUTCOMEMESH_REMOTE_FIXTURE_OUT to an existing private parent for an explicit test fixture export")
	}
	if !filepath.IsAbs(parent) || !utf8.ValidString(parent) || strings.ContainsRune(parent, 0) {
		t.Fatal("fixture export parent must be an absolute UTF-8 path")
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		t.Fatal("fixture export parent must be an existing nonsymlink private directory with mode 0700", err)
	}
	parent, err = filepath.EvalSymlinks(parent)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(parent, "fixture-")
	if err != nil {
		t.Fatal(err)
	}
	// The exported child is deliberately retained on success or failure. Test
	// cleanup removes only the unrelated archive-generator temporary fixtures.
	archive := newPruneEffectCLIFixture(t, false)
	manifest, err := loadArchiveManifest(archive.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	used := make(map[[ed25519.PublicKeySize]byte]bool)
	key := func() ed25519.PrivateKey {
		for {
			seed := make([]byte, ed25519.SeedSize)
			if _, err := rand.Read(seed); err != nil {
				t.Fatal(err)
			}
			private := ed25519.NewKeyFromSeed(seed)
			public := [ed25519.PublicKeySize]byte(private.Public().(ed25519.PublicKey))
			if !used[public] {
				used[public] = true
				return private
			}
		}
	}
	authorityA, consumerA, auditor, client := key(), key(), key(), key()
	authorityB, consumerB, replica, server := key(), key(), key(), key()
	auditorPublic := [32]byte(auditor.Public().(ed25519.PublicKey))
	clientID, err := transport.PeerIDFromPublicKey(client.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := transport.PeerIDFromPublicKey(server.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	policy := workarchive.CustodyPolicy{TrustedAuditors: [][32]byte{auditorPublic},
		MaximumChallengeLifetime: workarchive.MaximumCustodyChallengeLifetime,
		MaximumProofAge:          120, MaximumRenewalTerm: 24 * 60 * 60}
	now := uint64(time.Now().Unix())
	receipt, err := workarchive.CreateReplicaReceipt(archive.config.Replicas[0].Directory,
		archive.inventory.Policy.Checkpoint, archive.inventory.Policy.CheckpointPolicy,
		archive.config.Base, archive.config.Parameters, workarchive.DefaultLimits(), replica,
		remoteCustodyRandomHash(t), now-30, now+8*60*60)
	if err != nil {
		t.Fatal(err)
	}
	receiptID, err := receipt.ID()
	if err != nil {
		t.Fatal(err)
	}
	roles := make([]remoteCustodyFixtureScope, 0, 2)
	var intentA workarchive.CustodyAuditIntent
	for _, role := range []struct {
		name                                     string
		authority, consumer, evidence, transport ed25519.PrivateKey
		purpose                                  custodyauthority.Purpose
	}{
		{"role-a", authorityA, consumerA, auditor, client, custodyauthority.Audit},
		{"role-b", authorityB, consumerB, replica, server, custodyauthority.Serve},
	} {
		roleRoot := filepath.Join(root, role.name)
		if err := os.Mkdir(roleRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"metadata", "intent", "keys", "operations", "incoming"} {
			if err := os.Mkdir(filepath.Join(roleRoot, name), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		// The reference assignment requires declared coverage of every purpose.
		// This fresh test actor declares that coverage, but this run admits only
		// its selected Audit or Serve operation. No Prune ticket is created.
		purposes := custodyauthority.AllPurposes
		assignment, err := workarchive.CreateCustodyAuthorityAssignment(manifest, receipt, policy,
			remoteCustodyRandomHash(t), [32]byte(role.authority.Public().(ed25519.PublicKey)),
			[]custodyauthority.Consumer{{PublicKey: [32]byte(role.consumer.Public().(ed25519.PublicKey)), Purposes: purposes}}, 16, 4)
		if err != nil {
			t.Fatal(err)
		}
		assignmentID, err := assignment.ID()
		if err != nil {
			t.Fatal(err)
		}
		intent := workarchive.CustodyAuditIntent{AssignmentID: assignmentID,
			ConsumerPublicKey: [32]byte(role.consumer.Public().(ed25519.PublicKey)), AuditorPublicKey: auditorPublic,
			ReplicaPeerID: serverID, PriorReceiptID: receiptID, IssuedAt: now,
			ExpiresAt: now + policy.MaximumChallengeLifetime, RenewUntil: now + 16*60*60,
			RequestedSamples: 1}
		if role.purpose == custodyauthority.Audit {
			intent.Nonce = remoteCustodyRandomHash(t)
			intentA = intent
		} else {
			intent.Nonce = intentA.Nonce
		}
		intentID, err := intent.ID()
		if err != nil {
			t.Fatal(err)
		}
		paths := remoteCustodyFixturePaths{Assignment: "metadata/assignment.omcaa", Manifest: "metadata/manifest.omwm",
			InitialReceipt: "metadata/initial.omrr", Intent: "intent/intent.omcai", Journal: "journal",
			Authority: "authority", AuthorityPins: "authority-pins", AuthoritySeed: "keys/authority.seed",
			ConsumerSeed: "keys/consumer.seed", AdmissionCommand: "operations/admit.omcac", AdmissionEntry: "operations/admit.omcae",
			Terminal: "operations/terminal.omct", CompleteCommand: "operations/complete.omcac", CompleteEntry: "operations/complete.omcae"}
		if role.purpose == custodyauthority.Audit {
			paths.EvidenceSeed, paths.TransportSeed = "keys/auditor-evidence.seed", "keys/auditor-transport.seed"
			paths.Artifacts, paths.Challenge = "artifacts", "artifacts/cycle-00000000000000000001/challenge.omcc"
		} else {
			paths.EvidenceSeed, paths.TransportSeed = "keys/replica-evidence.seed", "keys/replica-transport.seed"
			paths.Objects, paths.Challenge = "objects", "incoming/challenge.omcc"
		}
		for _, artifact := range []struct {
			path  string
			value interface{ CanonicalBytes() ([]byte, error) }
		}{
			{paths.Assignment, assignment}, {paths.Manifest, manifest}, {paths.InitialReceipt, receipt},
		} {
			b, err := artifact.value.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			writeRemoteCustodyFixtureFile(t, filepath.Join(roleRoot, artifact.path), b)
		}
		if err := workarchive.PublishCustodyAuditIntent(t.Context(), filepath.Join(roleRoot, paths.Intent), intent); err != nil {
			t.Fatal(err)
		}
		for _, seed := range []struct {
			path string
			key  ed25519.PrivateKey
		}{
			{paths.AuthoritySeed, role.authority}, {paths.ConsumerSeed, role.consumer},
			{paths.EvidenceSeed, role.evidence}, {paths.TransportSeed, role.transport},
		} {
			writeRemoteCustodyFixtureFile(t, filepath.Join(roleRoot, seed.path), seed.key.Seed())
		}
		_, state, err := workarchive.OpenOrCreateCustodyJournal(filepath.Join(roleRoot, paths.Journal), manifest, receipt, policy)
		if err != nil || state.Sequence != 0 || !state.HeadEntryID.IsZero() || state.CurrentReceipt != receipt {
			t.Fatal("export did not initialize an empty local custody journal", err)
		}
		if role.purpose == custodyauthority.Audit {
			lock, err := workarchive.AcquireCustodyArtifacts(filepath.Join(roleRoot, paths.Artifacts))
			if err != nil {
				t.Fatal(err)
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
		} else {
			objects, err := workarchive.OpenObjectStore(filepath.Join(roleRoot, paths.Objects), workarchive.DefaultObjectStorePolicy())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := objects.ImportArchiveDirectory(archive.config.Replicas[0].Directory, archive.inventory.Policy.Checkpoint,
				archive.inventory.Policy.CheckpointPolicy, archive.config.Base, archive.config.Parameters, workarchive.DefaultLimits()); err != nil {
				t.Fatal(err)
			}
		}
		manifestID, _ := manifest.ID()
		scope := remoteCustodyFixtureScope{Version: 1, Role: role.name, Purpose: "audit", AssignmentID: assignmentID.String(), IntentID: intentID.String(),
			ManifestID: manifestID.String(), InitialReceiptID: receiptID.String(), AuthorityPublicKey: fmt.Sprintf("%x", assignment.AuthorityPublicKey),
			ConsumerPublicKey: fmt.Sprintf("%x", intent.ConsumerPublicKey), AuditorPublicKey: fmt.Sprintf("%x", auditorPublic),
			ReplicaPublicKey: fmt.Sprintf("%x", receipt.ReplicaPublicKey), AuditorPeerID: clientID.String(), ReplicaPeerID: serverID.String(),
			IssuedAt: now, ExpiresAt: intent.ExpiresAt, RenewUntil: intent.RenewUntil, MaximumChallengeLifetime: policy.MaximumChallengeLifetime,
			MaximumProofAge: policy.MaximumProofAge, MaximumRenewalTerm: policy.MaximumRenewalTerm, Paths: paths}
		if role.purpose == custodyauthority.Serve {
			scope.Purpose = "serve"
		}
		writeRemoteCustodyFixtureJSON(t, filepath.Join(roleRoot, "scope.json"), scope)
		writeRemoteCustodyFixtureJSON(t, filepath.Join(roleRoot, "commands.json"), remoteCustodyFixtureCommands(scope))
		// Bootstrapping must happen once at the installed role's destination,
		// rather than copying any already initialized authority or pin root.
		for _, path := range []string{paths.Authority, paths.AuthorityPins, paths.Challenge} {
			if _, err := os.Lstat(filepath.Join(roleRoot, path)); !os.IsNotExist(err) {
				t.Fatal("export contains an owner or prematurely signed challenge", path, err)
			}
		}
		roles = append(roles, scope)
	}
	if roles[0].AssignmentID == roles[1].AssignmentID || roles[0].IntentID == roles[1].IntentID || roles[0].AuthorityPublicKey == roles[1].AuthorityPublicKey || roles[0].ConsumerPublicKey == roles[1].ConsumerPublicKey {
		t.Fatal("remote roles did not retain independent local authority domains")
	}
	writeRemoteCustodyFixtureJSON(t, filepath.Join(root, "summary.json"), struct {
		Version int                         `json:"version"`
		Scope   string                      `json:"scope"`
		Roles   []remoteCustodyFixtureScope `json:"roles"`
	}{1, "test-only independent local Audit(A) and Serve(B) guards; no distributed freshness or copied-owner fencing claim", roles})
	fmt.Printf("remote_custody_fixture root=%s role_a_assignment=%s role_b_assignment=%s intent_expires_at=%d authority_roots_created=false challenge_signed=false\n", root, roles[0].AssignmentID, roles[1].AssignmentID, roles[0].ExpiresAt)
}

type remoteCustodyFixtureScope struct {
	Version                  int                       `json:"version"`
	Role                     string                    `json:"role"`
	Purpose                  string                    `json:"purpose"`
	AssignmentID             string                    `json:"assignment_id"`
	IntentID                 string                    `json:"intent_id"`
	ManifestID               string                    `json:"manifest_id"`
	InitialReceiptID         string                    `json:"initial_receipt_id"`
	AuthorityPublicKey       string                    `json:"authority_public_key"`
	ConsumerPublicKey        string                    `json:"consumer_public_key"`
	AuditorPublicKey         string                    `json:"auditor_public_key"`
	ReplicaPublicKey         string                    `json:"replica_public_key"`
	AuditorPeerID            string                    `json:"auditor_peer_id"`
	ReplicaPeerID            string                    `json:"replica_peer_id"`
	IssuedAt                 uint64                    `json:"issued_at"`
	ExpiresAt                uint64                    `json:"expires_at"`
	RenewUntil               uint64                    `json:"renew_until"`
	MaximumChallengeLifetime uint64                    `json:"maximum_challenge_lifetime_seconds"`
	MaximumProofAge          uint64                    `json:"maximum_proof_age_seconds"`
	MaximumRenewalTerm       uint64                    `json:"maximum_renewal_term_seconds"`
	Paths                    remoteCustodyFixturePaths `json:"paths"`
}

type remoteCustodyFixturePaths struct {
	Assignment       string `json:"assignment"`
	Manifest         string `json:"manifest"`
	InitialReceipt   string `json:"initial_receipt"`
	Intent           string `json:"intent"`
	Authority        string `json:"authority"`
	AuthorityPins    string `json:"authority_pins"`
	Journal          string `json:"journal"`
	Artifacts        string `json:"artifacts,omitempty"`
	Objects          string `json:"objects,omitempty"`
	Challenge        string `json:"challenge"`
	AuthoritySeed    string `json:"authority_seed"`
	ConsumerSeed     string `json:"consumer_seed"`
	EvidenceSeed     string `json:"evidence_seed"`
	TransportSeed    string `json:"transport_seed"`
	AdmissionCommand string `json:"admission_command"`
	AdmissionEntry   string `json:"admission_entry"`
	Terminal         string `json:"terminal"`
	CompleteCommand  string `json:"complete_command"`
	CompleteEntry    string `json:"complete_entry"`
}

func remoteCustodyFixtureCommands(s remoteCustodyFixtureScope) map[string][]string {
	p := s.Paths
	path := func(relative string) string { return "{ROOT}/" + filepath.ToSlash(relative) }
	common := []string{"--assignment", path(p.Assignment), "--assignment-id", s.AssignmentID, "--manifest", path(p.Manifest),
		"--receipt", path(p.InitialReceipt), "--intent", path(p.Intent), "--intent-id", s.IntentID, "--previous-receipt", path(p.InitialReceipt),
		"--max-challenge-lifetime-seconds", strconv.FormatUint(s.MaximumChallengeLifetime, 10),
		"--max-proof-age-seconds", strconv.FormatUint(s.MaximumProofAge, 10), "--max-renewal-term-seconds", strconv.FormatUint(s.MaximumRenewalTerm, 10)}
	policy := []string{"--max-challenge-lifetime-seconds", strconv.FormatUint(s.MaximumChallengeLifetime, 10),
		"--max-proof-age-seconds", strconv.FormatUint(s.MaximumProofAge, 10), "--max-renewal-term-seconds", strconv.FormatUint(s.MaximumRenewalTerm, 10)}
	owner := []string{"--authority", path(p.Authority), "--authority-pins", path(p.AuthorityPins), "--journal", path(p.Journal)}
	appendArgs := func(parts ...[]string) []string {
		var args []string
		for _, part := range parts {
			args = append(args, part...)
		}
		return args
	}
	commands := make(map[string][]string)
	bootstrap := []string{pruneAuthorityBootstrapCommand, "--assignment", path(p.Assignment), "--assignment-id", s.AssignmentID,
		"--authority", path(p.Authority), "--authority-pins", path(p.AuthorityPins)}
	for _, mode := range []string{"review", "create", "verify"} {
		commands["authority-"+mode] = appendArgs(bootstrap, []string{"--mode", mode})
	}
	admit := appendArgs(common, []string{"--purpose", s.Purpose, "--kind", "admit", "--consumer-public-key", s.ConsumerPublicKey,
		"--expected-sequence", "0", "--expected-head", s.AssignmentID})
	if s.Purpose == "serve" {
		admit = appendArgs(admit, []string{"--challenge", path(p.Challenge), "--challenge-id", "{CHALLENGE_ID}"})
	}
	complete := appendArgs(common, []string{"--purpose", s.Purpose, "--kind", "complete", "--expected-sequence", "1", "--expected-head", "{ADMISSION_ID}",
		"--admission", path(p.AdmissionEntry), "--admission-id", "{ADMISSION_ID}", "--terminal", path(p.Terminal), "--terminal-id", "{TERMINAL_ID}"})
	for _, phase := range []struct {
		name           string
		scope          []string
		command, entry string
	}{
		{"admit", admit, p.AdmissionCommand, p.AdmissionEntry}, {"complete", complete, p.CompleteCommand, p.CompleteEntry},
	} {
		commands[phase.name+"-consumer-review"] = appendArgs([]string{custodyCommandSignCommand}, phase.scope)
		commands[phase.name+"-consumer-sign"] = appendArgs([]string{custodyCommandSignCommand}, phase.scope, []string{"--mode", "sign", "--consumer-key", path(p.ConsumerSeed), "--expected-review-id", "{CONSUMER_REVIEW_ID}", "--out", path(phase.command)})
		commands[phase.name+"-authority-review"] = appendArgs([]string{custodyCommandCosignCommand}, phase.scope, []string{"--command", path(phase.command)})
		commands[phase.name+"-authority-sign"] = appendArgs([]string{custodyCommandCosignCommand}, phase.scope, []string{"--command", path(phase.command), "--mode", "sign", "--authority-key", path(p.AuthoritySeed), "--expected-review-id", "{AUTHORITY_REVIEW_ID}", "--out", path(phase.entry)})
		entryID := "{ADMISSION_ID}"
		if phase.name == "complete" {
			entryID = "{COMPLETION_ID}"
		}
		apply := appendArgs([]string{custodyCommandApplyCommand}, common, owner, []string{"--purpose", s.Purpose, "--entry", path(phase.entry), "--entry-id", entryID})
		if phase.name == "complete" {
			apply = appendArgs(apply, []string{"--admission", path(p.AdmissionEntry), "--admission-id", "{ADMISSION_ID}", "--terminal", path(p.Terminal), "--terminal-id", "{TERMINAL_ID}"})
		} else if s.Purpose == "serve" {
			apply = appendArgs(apply, []string{"--challenge", path(p.Challenge), "--challenge-id", "{CHALLENGE_ID}"})
		}
		commands[phase.name+"-apply-review"] = apply
		commands[phase.name+"-apply-control"] = appendArgs(apply, []string{"--mode", "control"})
	}
	terminal := appendArgs([]string{custodyTerminalCommand}, common, owner, []string{"--purpose", s.Purpose, "--admission", path(p.AdmissionEntry), "--admission-id", "{ADMISSION_ID}"})
	commands["terminal-review"] = terminal
	commands["terminal-control"] = appendArgs(terminal, []string{"--mode", "control", "--out", path(p.Terminal)})
	runtime := appendArgs([]string{"--assignment", path(p.Assignment), "--assignment-id", s.AssignmentID, "--admission", path(p.AdmissionEntry),
		"--ticket-id", "{ADMISSION_ID}", "--manifest", path(p.Manifest), "--receipt", path(p.InitialReceipt)}, owner, policy, []string{"--timeout", "10s"})
	if s.Purpose == "audit" {
		runtime = appendArgs(runtime, []string{"--intent", path(p.Intent), "--intent-id", s.IntentID, "--artifacts", path(p.Artifacts),
			"--auditor-key", path(p.EvidenceSeed), "--auditor-peer-id", s.AuditorPeerID, "--listen", "{AUDIT_LISTEN}"})
		commands["prepare-review"] = appendArgs([]string{managedCustodyAuditCommand}, runtime)
		commands["prepare-control"] = appendArgs([]string{managedCustodyAuditCommand}, runtime, []string{"--mode", "control"})
		runtime = appendArgs(runtime, []string{"--transport-key", path(p.TransportSeed), "--peer", "{PEER}"})
		commands["audit-review"] = appendArgs([]string{managedCustodyAuditCommand}, runtime)
		commands["audit-control"] = appendArgs([]string{managedCustodyAuditCommand}, runtime, []string{"--mode", "control"})
	} else {
		runtime = appendArgs(runtime, []string{"--challenge-id", "{CHALLENGE_ID}", "--objects", path(p.Objects), "--key", path(p.TransportSeed),
			"--replica-key", path(p.EvidenceSeed), "--server-peer-id", s.ReplicaPeerID, "--auditor-peer-id", s.AuditorPeerID, "--listen", "{LISTEN}"})
		commands["serve-review"] = appendArgs([]string{managedCustodyServeCommand}, runtime)
		commands["serve"] = appendArgs([]string{managedCustodyServeCommand}, runtime, []string{"--mode", "serve"})
	}
	return commands
}

func remoteCustodyRandomHash(t testing.TB) types.Hash {
	t.Helper()
	var id types.Hash
	for id.IsZero() {
		if _, err := rand.Read(id[:]); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func writeRemoteCustodyFixtureJSON(t testing.TB, path string, value any) {
	t.Helper()
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeRemoteCustodyFixtureFile(t, path, append(b, '\n'))
}

func writeRemoteCustodyFixtureFile(t testing.TB, path string, b []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := file.Write(b); err != nil || n != len(b) {
		_ = file.Close()
		t.Fatal("fixture file write failed", path, err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := syncCustodyArtifactDirectory(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
}

// TestInspectRemoteCustodyFixture is an opt-in diagnostic helper for the
// installed role. It opens only retained public metadata and existing original
// roots, never seeds. Both owners close before the observation reaches stdout.
func TestInspectRemoteCustodyFixture(t *testing.T) {
	root := os.Getenv("OUTCOMEMESH_REMOTE_ROLE_ROOT")
	if root == "" {
		t.Skip("set OUTCOMEMESH_REMOTE_ROLE_ROOT to inspect an installed test role")
	}
	observation, err := inspectRemoteCustodyFixture(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("remote_custody_inspect %s\n", b)
}

type remoteCustodyInspection struct {
	AssignmentID      string                            `json:"assignment_id"`
	AuthoritySequence uint64                            `json:"authority_sequence"`
	AuthorityHeadID   string                            `json:"authority_head_id"`
	AuthorityPending  uint16                            `json:"authority_pending"`
	ConfirmedSequence uint64                            `json:"confirmed_sequence"`
	ConfirmedHeadID   string                            `json:"confirmed_head_id"`
	PendingAttempt    bool                              `json:"pending_attempt"`
	PendingEntryID    string                            `json:"pending_entry_id"`
	Phase             string                            `json:"phase"`
	Operations        []remoteCustodyInspectedOperation `json:"operations"`
	JournalSequence   uint64                            `json:"journal_sequence"`
	JournalHeadID     string                            `json:"journal_head_id"`
	CurrentReceiptID  string                            `json:"current_receipt_id"`
	HeadProofID       string                            `json:"head_proof_id"`
	RespondedAt       uint64                            `json:"responded_at"`
	ChallengeID       string                            `json:"challenge_id"`
}

type remoteCustodyInspectedOperation struct {
	TicketID     string `json:"ticket_id"`
	Purpose      string `json:"purpose"`
	OperationID  string `json:"operation_id"`
	CompletionID string `json:"completion_id"`
	EvidenceID   string `json:"evidence_id"`
}

func inspectRemoteCustodyFixture(ctx context.Context, root string) (observation remoteCustodyInspection, returnErr error) {
	root, err := managedCustodyCanonicalDirectory(root)
	if err != nil {
		return observation, err
	}
	b, err := readRegularArtifact(filepath.Join(root, "scope.json"), 256<<10)
	if err != nil {
		return observation, err
	}
	var s remoteCustodyFixtureScope
	if err := json.Unmarshal(b, &s); err != nil {
		return observation, err
	}
	if s.Version != 1 || (s.Role != "role-a" && s.Role != "role-b") || (s.Purpose != "audit" && s.Purpose != "serve") {
		return observation, errors.New("invalid remote test fixture scope")
	}
	resolve := func(relative string) (string, error) {
		clean := filepath.Clean(relative)
		if relative == "" || filepath.IsAbs(relative) || clean != relative || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || !utf8.ValidString(relative) || strings.ContainsRune(relative, 0) {
			return "", errors.New("remote test metadata must use bounded role-relative placement")
		}
		return filepath.Join(root, relative), nil
	}
	var assignmentPath, manifestPath, receiptPath, intentPath, authorityPath, pinsPath, journalPath string
	for _, p := range []struct {
		relative string
		target   *string
	}{
		{s.Paths.Assignment, &assignmentPath}, {s.Paths.Manifest, &manifestPath}, {s.Paths.InitialReceipt, &receiptPath},
		{s.Paths.Intent, &intentPath}, {s.Paths.Authority, &authorityPath}, {s.Paths.AuthorityPins, &pinsPath}, {s.Paths.Journal, &journalPath},
	} {
		*p.target, err = resolve(p.relative)
		if err != nil {
			return observation, err
		}
	}
	assignmentID, err := managedCustodyExternalID("assignment-id", s.AssignmentID)
	if err != nil {
		return observation, err
	}
	a, err := loadPruneOfflineAssignment(assignmentPath, assignmentID)
	if err != nil {
		return observation, err
	}
	manifest, err := loadArchiveManifest(manifestPath)
	if err != nil {
		return observation, err
	}
	receipt, err := loadArchiveReplicaReceipt(receiptPath)
	if err != nil {
		return observation, err
	}
	intentID, err := managedCustodyExternalID("intent-id", s.IntentID)
	if err != nil {
		return observation, err
	}
	intent, err := workarchive.LoadCustodyAuditIntent(intentPath, intentID)
	if err != nil {
		return observation, err
	}
	policy := workarchive.CustodyPolicy{TrustedAuditors: append([][32]byte(nil), a.Auditors...), MaximumChallengeLifetime: s.MaximumChallengeLifetime,
		MaximumProofAge: s.MaximumProofAge, MaximumRenewalTerm: s.MaximumRenewalTerm}
	if err := authoritystore.ValidateCustodyCommandScope(authoritystore.CustodyCommandScope{Assignment: a, AssignmentID: assignmentID, Manifest: manifest,
		InitialReceipt: receipt, CustodyPolicy: policy, Intent: intent, PreviousReceipt: receipt}); err != nil {
		return observation, err
	}
	owner, err := authoritystore.OpenCoordinator(authorityPath, pinsPath, a, assignmentID)
	if err != nil {
		return observation, err
	}
	defer func() { returnErr = errors.Join(returnErr, owner.Close()) }()
	// OpenExisting and AcquireDecision reject missing, retired or historical
	// roots. No fallback constructor, append, confirmation or resume is used.
	journal, _, err := workarchive.OpenExistingCustodyJournalWithLimits(ctx, journalPath, manifest, receipt, policy, workarchive.DefaultCustodyJournalLimits())
	if err != nil {
		return observation, err
	}
	decision, err := journal.AcquireDecision()
	if err != nil {
		return observation, err
	}
	defer func() { returnErr = errors.Join(returnErr, decision.Close()) }()
	coordination, err := owner.Snapshot()
	if err != nil {
		return observation, err
	}
	state, err := decision.State()
	if err != nil {
		return observation, err
	}
	head, hasHead, err := decision.Head()
	if err != nil {
		return observation, err
	}
	currentReceiptID, err := state.CurrentReceipt.ID()
	if err != nil {
		return observation, err
	}
	current := coordination.Authority
	observation = remoteCustodyInspection{AssignmentID: assignmentID.String(), AuthoritySequence: current.Sequence, AuthorityHeadID: current.HeadID.String(),
		AuthorityPending: current.Pending, ConfirmedSequence: coordination.Confirmed.Sequence, ConfirmedHeadID: coordination.Confirmed.HeadID.String(),
		PendingAttempt: coordination.Pending != nil, Operations: make([]remoteCustodyInspectedOperation, 0, len(current.Operations)),
		JournalSequence: state.Sequence, JournalHeadID: state.HeadEntryID.String(), CurrentReceiptID: currentReceiptID.String()}
	switch current.Phase {
	case custodyauthority.Accepting:
		observation.Phase = "accepting"
	case custodyauthority.Stopping:
		observation.Phase = "stopping"
	case custodyauthority.Retired:
		observation.Phase = "retired"
	default:
		return observation, errors.New("invalid retained authority phase")
	}
	if coordination.Pending != nil {
		id, err := coordination.Pending.ID()
		if err != nil {
			return observation, err
		}
		observation.PendingEntryID = id.String()
	}
	for _, operation := range current.Operations {
		purpose := "audit"
		if operation.Purpose == custodyauthority.Serve {
			purpose = "serve"
		} else if operation.Purpose != custodyauthority.Audit {
			return observation, errors.New("unexpected remote test operation purpose")
		}
		observation.Operations = append(observation.Operations, remoteCustodyInspectedOperation{operation.TicketID.String(), purpose, operation.OperationID.String(), operation.CompletionID.String(), operation.EvidenceID.String()})
	}
	if hasHead {
		id, err := head.Record.Proof.ID()
		if err != nil {
			return observation, err
		}
		observation.HeadProofID = id.String()
		id, err = head.Record.Challenge.ID()
		if err != nil {
			return observation, err
		}
		observation.ChallengeID = id.String()
		observation.RespondedAt = head.Record.Proof.RespondedAt
	}
	return observation, nil
}
