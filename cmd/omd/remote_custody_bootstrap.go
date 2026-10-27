package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func runRemoteCustodyAssignment(ctx context.Context, args []string, output io.Writer) error {
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "review", "review (default), or publish immutable public assignment")
	manifestPath := f.String("manifest", "", "existing canonical manifest")
	receiptPath := f.String("receipt", "", "existing initial receipt")
	incarnation := f.String("incarnation-id", "", "explicit fresh independently selected incarnation")
	authority := f.String("authority-public-key", "", "authority public key")
	auditors := f.String("auditor-public-keys", "", "comma-separated sorted auditor evidence public keys")
	consumers := f.String("consumers", "", "sorted comma-separated PUBLIC_KEY:audit+serve+prune members; specify each member's actual purposes")
	control := f.String("remote-control-public-key", "", "B's separate command signing public key")
	transport := f.String("remote-transport-public-key", "", "B's separate transport public key")
	maxOps := f.Uint64("max-operations", 0, "explicit bounded lifetime admissions budget")
	maxPending := f.Uint64("max-pending", 0, "explicit bounded simultaneous pending budget")
	policyFlags := addArchiveCustodyPolicyFlags(f)
	out := f.String("out", "", "publish only: immutable output in an existing parent")
	pin := f.String("assignment-id", "", "publish only: independently reviewed new assignment ID")
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return err
	}
	if *mode != "review" && *mode != "publish" {
		return errors.New("assignment mode must be review or publish")
	}
	if *mode == "review" {
		if err := custodyCommandForbid(custodyCommandPresence(f), "out", "assignment-id"); err != nil {
			return err
		}
	}
	manifestFile, err := custodyCommandFile(*manifestPath)
	if err != nil {
		return err
	}
	receiptFile, err := custodyCommandFile(*receiptPath)
	if err != nil {
		return err
	}
	manifest, err := loadArchiveManifest(manifestFile)
	if err != nil {
		return err
	}
	receipt, err := loadArchiveReplicaReceipt(receiptFile)
	if err != nil {
		return err
	}
	keys := make([]types.Hash, 4)
	for i, v := range []struct{ name, text string }{{"incarnation-id", *incarnation}, {"authority-public-key", *authority}, {"remote-control-public-key", *control}, {"remote-transport-public-key", *transport}} {
		keys[i], err = managedCustodyExternalID(v.name, v.text)
		if err != nil {
			return err
		}
	}
	policy := workarchive.CustodyPolicy{MaximumChallengeLifetime: *policyFlags.challengeLifetime, MaximumProofAge: *policyFlags.proofAge, MaximumRenewalTerm: *policyFlags.renewalTerm}
	for _, text := range strings.Split(*auditors, ",") {
		key, err := managedCustodyExternalID("auditor-public-keys member", text)
		if err != nil {
			return err
		}
		policy.TrustedAuditors = append(policy.TrustedAuditors, [32]byte(key))
	}
	var members []custodyauthority.Consumer
	for _, text := range strings.Split(*consumers, ",") {
		pair := strings.Split(text, ":")
		if len(pair) != 2 {
			return errors.New("consumer must be PUBLIC_KEY:audit+serve+prune with its selected purposes")
		}
		key, err := managedCustodyExternalID("consumer public key", pair[0])
		if err != nil {
			return err
		}
		var purposes custodyauthority.Purpose
		for _, name := range strings.Split(pair[1], "+") {
			var p custodyauthority.Purpose
			switch name {
			case "audit":
				p = custodyauthority.Audit
			case "serve":
				p = custodyauthority.Serve
			case "prune":
				p = custodyauthority.Prune
			default:
				return errors.New("consumer purpose must be audit, serve or prune")
			}
			if purposes&p != 0 {
				return errors.New("duplicate consumer purpose")
			}
			purposes |= p
		}
		members = append(members, custodyauthority.Consumer{PublicKey: [32]byte(key), Purposes: purposes})
	}
	if *maxOps == 0 || *maxOps > uint64(custodyauthority.MaximumOperations) || *maxPending == 0 || *maxPending > uint64(custodyauthority.MaximumPending) {
		return errors.New("explicit admission and pending budgets exceed assignment bounds")
	}
	a, err := workarchive.CreateRemoteCustodyAuthorityAssignment(manifest, receipt, policy, keys[0], [32]byte(keys[1]), members, uint32(*maxOps), uint16(*maxPending), [32]byte(keys[2]), [32]byte(keys[3]))
	if err != nil {
		return err
	}
	id, _ := a.ID()
	if *mode == "publish" {
		b, _ := a.CanonicalBytes()
		if err := publishRemotePreparation(ctx, *out, *pin, id, b, []string{manifestFile, receiptFile}); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return writePruneOutputLine(output, fmt.Sprintf("remote_custody_assignment mode=%s assignment_id=%s artifact_published=%t owners_opened=false execution_authorized=false\nassignment:\n%s\nremote_custody_assignment_scope_end\n", *mode, id, *mode == "publish", b))
}

func publishRemotePreparation(ctx context.Context, path, pin string, id types.Hash, b []byte, inputs []string) error {
	expected, err := managedCustodyExternalID("reviewed artifact ID", pin)
	if err != nil || expected != id {
		return errors.Join(errors.New("publication requires the exact reviewed artifact ID"), err)
	}
	out, err := custodyCommandOutput(path)
	if err != nil {
		return err
	}
	if err := rejectPruneLineageOutputAlias(out, inputs); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return publishCustodyCommandArtifact(out, b)
}

func runRemoteCustodyPreparation(ctx context.Context, args []string, output io.Writer) error {
	worker := args[0] == remoteCustodyWorkerPrepareCommand
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	common := addCustodyCommandScopeFlags(f)
	mode := f.String("mode", "review", "review (default); plan: publish; worker: create or verify")
	challengePath := f.String("challenge", "", "exact signed challenge")
	challengePin := f.String("challenge-id", "", "independent challenge ID")
	var planPath, planPin, beginPath, beginPin, workerPath, expectedReview string
	var admissionPath, admissionPin, authorityTransport, auditTransport, noncePath, out, artifactPin string
	if worker {
		f.StringVar(&planPath, "plan", "", "existing canonical plan")
		f.StringVar(&planPin, "plan-id", "", "independent plan ID")
		f.StringVar(&beginPath, "begin", "", "existing co-signed Begin proposal")
		f.StringVar(&beginPin, "begin-id", "", "independent Begin ID")
		f.StringVar(&workerPath, "worker", "", "dedicated B-local worker root with existing parent")
		f.StringVar(&expectedReview, "expected-review-id", "", "create only: reviewed placement and session ID")
	} else {
		f.StringVar(&admissionPath, "admission", "", "exact co-signed Serve admission")
		f.StringVar(&admissionPin, "admission-id", "", "independent Serve ticket ID")
		f.StringVar(&authorityTransport, "authority-transport-public-key", "", "A's separate control transport public key")
		f.StringVar(&auditTransport, "audit-transport-public-key", "", "A's separate Audit transport public key")
		f.StringVar(&noncePath, "nonce-file", "", "existing separate 32-byte nonzero plan nonce file")
		f.StringVar(&out, "out", "", "publish only: immutable plan output")
		f.StringVar(&artifactPin, "plan-id", "", "publish only: reviewed plan ID")
	}
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return err
	}
	if (!worker && *mode != "review" && *mode != "publish") || (worker && *mode != "review" && *mode != "create" && *mode != "verify") {
		return errors.New("mode must be review/publish for a plan or review/create/verify for a worker")
	}
	if *mode == "review" || *mode == "verify" {
		forbidden := []string{"out", "plan-id"}
		if worker {
			forbidden = []string{"expected-review-id"}
		}
		if err := custodyCommandForbid(custodyCommandPresence(f), forbidden...); err != nil {
			return err
		}
	}
	scope, sources, err := common.loadVersion(custodyauthority.Version1)
	if err != nil {
		return err
	}
	challenge, challengeFile, err := custodyCommandChallenge(*challengePath, *challengePin)
	if err != nil {
		return err
	}
	inputs := []string{sources.Assignment, sources.Manifest, sources.InitialReceipt, sources.PreviousReceipt, sources.Intent, challengeFile}
	var plan remoteworker.Plan
	if worker {
		var file string
		plan, file, err = remoteOfflinePlan(planPath, planPin)
		inputs = append(inputs, file)
	} else {
		var admission custodyauthority.Entry
		var file string
		admission, file, err = custodyCommandEntry(admissionPath, admissionPin)
		if err != nil {
			return err
		}
		inputs = append(inputs, file)
		ctrl, err := managedCustodyExternalID("authority-transport-public-key", authorityTransport)
		if err != nil {
			return err
		}
		audit, err := managedCustodyExternalID("audit-transport-public-key", auditTransport)
		if err != nil {
			return err
		}
		nonceFile, err := custodyCommandFile(noncePath)
		if err != nil {
			return err
		}
		if err := rejectPruneLineageOutputAlias(nonceFile, inputs); err != nil {
			return err
		}
		nonce, err := readRegularArtifact(nonceFile, types.HashSize)
		if err != nil || len(nonce) != types.HashSize {
			return errors.Join(errors.New("plan nonce must contain exactly 32 nonzero bytes"), err)
		}
		var hash types.Hash
		copy(hash[:], nonce)
		i := scope.Intent
		plan = remoteworker.Plan{AssignmentID: scope.AssignmentID, Admission: admission, AuthorityTransportPublicKey: [32]byte(ctrl), AuditorTransportPublicKey: [32]byte(audit), PriorSequence: i.PriorSequence, PriorHeadID: i.PriorHeadID, PriorReceiptID: i.PriorReceiptID, Nonce: hash}
		inputs = append(inputs, nonceFile)
	}
	if err != nil {
		return err
	}
	if err := store.ValidateRemoteCustodyPlan(scope, plan, challenge); err != nil {
		return err
	}
	pid, _ := plan.ID()
	if !worker {
		if *mode == "publish" {
			b, _ := plan.CanonicalBytes()
			if err := publishRemotePreparation(ctx, out, artifactPin, pid, b, inputs); err != nil {
				return err
			}
		}
		b, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			return err
		}
		return writePruneOutputLine(output, fmt.Sprintf("remote_custody_plan mode=%s assignment_id=%s plan_id=%s artifact_published=%t owners_opened=false execution_authorized=false\nplan:\n%s\nremote_custody_plan_scope_end\n", *mode, scope.AssignmentID, pid, *mode == "publish", b))
	}
	begin, beginFile, err := custodyCommandEntry(beginPath, beginPin)
	if err != nil {
		return err
	}
	remote, err := remoteOfflineScope(scope, plan, begin, challenge)
	if err != nil {
		return err
	}
	inputs = append(inputs, beginFile)
	root, err := remoteBootstrapRoot(workerPath)
	if err != nil {
		return err
	}
	for _, input := range inputs {
		if err := store.ValidateBootstrapPaths(root, filepath.Dir(input)); err != nil {
			return err
		}
	}
	review, err := remoteBootstrapReviewID("worker", scope.AssignmentID, pid, remote.Worker.BeginID, []string{root})
	if err != nil {
		return err
	}
	var snapshot remoteworker.Snapshot
	if *mode != "review" {
		if err := ctx.Err(); err != nil {
			return err
		}
		var owner *remoteworker.Journal
		if *mode == "create" {
			if err := remoteBootstrapExpected(expectedReview, review); err != nil {
				return err
			}
			owner, err = remoteworker.Create(ctx, root, remote.Worker)
		} else {
			owner, err = remoteworker.Open(ctx, root, remote.Worker)
		}
		if err != nil {
			return err
		}
		snapshot, err = owner.Snapshot(ctx)
		if err := errors.Join(err, owner.Close()); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return writePruneOutputLine(output, fmt.Sprintf("remote_custody_worker_prepare mode=%s assignment_id=%s plan_id=%s begin_id=%s review_id=%s worker=%q stage=%d pending=%d roots_inspected=%t owners_closed=true execution_authorized=false automatic_resume=false\n", *mode, scope.AssignmentID, pid, remote.Worker.BeginID, review, root, snapshot.Stage, snapshot.Pending, *mode != "review"))
}

func remoteBootstrapReviewID(kind string, assignment, plan, begin types.Hash, paths []string) (types.Hash, error) {
	b, err := json.Marshal(struct {
		Kind                    string
		Assignment, Plan, Begin types.Hash
		Paths                   []string
	}{kind, assignment, plan, begin, paths})
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/local/remote-custody-bootstrap-review/v0", b), nil
}

func remoteBootstrapExpected(text string, review types.Hash) error {
	expected, err := managedCustodyExternalID("expected-review-id", text)
	if err != nil || expected != review {
		return errors.Join(errors.New("creation requires the exact reviewed session and placement"), err)
	}
	return nil
}

func runRemoteCustodyAuthorityBootstrap(ctx context.Context, args []string, output io.Writer) error {
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "review", "review placement (default), create fresh roots, or verify existing roots")
	assignmentPath := f.String("assignment", "", "existing canonical V1 assignment")
	assignmentPin := f.String("assignment-id", "", "independently pinned assignment ID")
	authority := f.String("authority", "", "original A authority root with existing parent")
	pins := f.String("authority-pins", "", "disjoint original A pin root with existing parent")
	expected := f.String("expected-review-id", "", "create only: exact reviewed placement ID")
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return err
	}
	if *mode != "review" && *mode != "create" && *mode != "verify" {
		return errors.New("authority bootstrap mode must be review, create or verify")
	}
	if *mode != "create" {
		if err := custodyCommandForbid(custodyCommandPresence(f), "expected-review-id"); err != nil {
			return err
		}
	}
	id, err := managedCustodyExternalID("assignment-id", *assignmentPin)
	if err != nil {
		return err
	}
	file, err := custodyCommandFile(*assignmentPath)
	if err != nil {
		return err
	}
	a, err := loadPruneOfflineAssignment(file, id)
	if err != nil || a.Version != custodyauthority.Version1 {
		return errors.Join(errors.New("remote bootstrap requires a separately pinned fresh V1 assignment"), err)
	}
	roots := make([]string, 2)
	for i, text := range []string{*authority, *pins} {
		roots[i], err = remoteBootstrapRoot(text)
		if err != nil {
			return err
		}
		if err := store.ValidateBootstrapPaths(roots[i], filepath.Dir(file)); err != nil {
			return err
		}
	}
	if err := store.ValidateBootstrapPaths(roots[0], roots[1]); err != nil {
		return err
	}
	review, err := remoteBootstrapReviewID("authority", id, types.Hash{}, types.Hash{}, roots)
	if err != nil {
		return err
	}
	var position custodyauthority.Position
	var pending bool
	if *mode != "review" {
		if err := ctx.Err(); err != nil {
			return err
		}
		var owner *store.Coordinator
		if *mode == "create" {
			if err := remoteBootstrapExpected(*expected, review); err != nil {
				return err
			}
			owner, err = store.CreateCoordinatedAuthority(roots[0], roots[1], a, id)
		} else {
			owner, err = store.OpenCoordinator(roots[0], roots[1], a, id)
		}
		if err != nil {
			return err
		}
		s, err := owner.Snapshot()
		if err := errors.Join(err, owner.Close()); err != nil {
			return err
		}
		position, pending = s.Confirmed, s.Pending != nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return writePruneOutputLine(output, fmt.Sprintf("remote_custody_authority_bootstrap mode=%s assignment_id=%s review_id=%s authority=%q authority_pins=%q confirmed_sequence=%d confirmed_head=%s retained_attempt=%t roots_inspected=%t owners_closed=true execution_authorized=false automatic_resume=false\n", *mode, id, review, roots[0], roots[1], position.Sequence, position.HeadID, pending, *mode != "review"))
}

func remoteBootstrapRoot(path string) (string, error) {
	if path == "" || !utf8.ValidString(path) || strings.ContainsRune(path, 0) {
		return "", errors.New("root must be an explicit UTF-8 path without NUL")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent, err := canonicalPruneLineageDirectory(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	root := filepath.Join(parent, filepath.Base(abs))
	if !utf8.ValidString(root) {
		return "", errors.New("canonical root must be valid UTF-8")
	}
	if info, err := os.Lstat(root); err == nil {
		if !info.IsDir() {
			return "", errors.New("existing root must be a real directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return root, nil
}
