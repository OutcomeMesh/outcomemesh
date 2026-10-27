package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	multiaddr "github.com/multiformats/go-multiaddr"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/transport"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const (
	remoteCustodyAuditCommand = "work-archive-custody-remote-audit"
	remoteCustodyServeCommand = "work-archive-custody-remote-serve"
)

var errRemoteCustodyUnobserved = errors.New("remote custody action or publication was not observed; inspect retained owners and artifacts before explicit recovery")

type remoteCustodyPath struct{ Name, Path string }
type remoteCustodyOptions struct {
	role, mode, address, listen        string
	scope                              store.RemoteCustodyScope
	audit                              store.RemoteCustodyAuditRuntimeConfig
	serve                              store.RemoteCustodyServeServiceConfig
	controlKey, transportKey           ed25519.PrivateKey
	paths                              []remoteCustodyPath
	drainPath, terminalPath, entryPath string
	drainID, terminalID, entryID       types.Hash
}

func runRemoteCustodyCLI(args []string) error {
	broken := make(chan os.Signal, 1)
	signal.Notify(broken, syscall.SIGPIPE)
	defer signal.Stop(broken)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runRemoteCustody(ctx, args, os.Stdin, os.Stdout)
}

func remoteCustodyPathFile(path string) (string, error) {
	if path == "" || !utf8.ValidString(path) || strings.ContainsRune(path, 0) {
		return "", errors.New("an exact nonempty UTF-8 artifact path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		return "", errors.Join(errors.New("artifact parent must already exist"), err)
	}
	path = filepath.Join(parent, filepath.Base(abs))
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return "", errors.New("artifact must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return path, nil
}

func loadRemoteCustodyOptions(ctx context.Context, args []string) (o remoteCustodyOptions, returnErr error) {
	if ctx == nil || len(args) == 0 || (args[0] != remoteCustodyAuditCommand && args[0] != remoteCustodyServeCommand) {
		return o, errors.New("explicit remote custody command is required")
	}
	if err := ctx.Err(); err != nil {
		return o, err
	}
	o.role = "audit"
	if args[0] == remoteCustodyServeCommand {
		o.role = "serve"
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "review", "review (default) or supervised control")
	assignmentPath := f.String("assignment", "", "existing canonical V1 assignment")
	assignmentPin := f.String("assignment-id", "", "independently retained assignment ID")
	planPath := f.String("plan", "", "existing canonical remote worker plan")
	planPin := f.String("plan-id", "", "independently retained plan ID")
	beginPath := f.String("begin", "", "existing co-signed Begin proposal")
	beginPin := f.String("begin-id", "", "independently retained Begin entry ID")
	manifestPath := f.String("manifest", "", "existing canonical manifest")
	receiptPath := f.String("receipt", "", "existing initial replica receipt")
	previousPath := f.String("previous-receipt", "", "existing exact predecessor receipt")
	challengePath := f.String("challenge", "", "existing pinned signed challenge")
	journalPath := f.String("journal", "", "existing original local custody journal")
	listen := f.String("listen", "/ip4/127.0.0.1/udp/0/quic-v1", "dedicated direct QUIC-v1 listen address")
	address := f.String("peer", "", "independently selected B route (audit only)")
	timeout := f.Duration("timeout", 10*time.Second, "exchange timeout, 100ms..2m")
	policyFlags := addArchiveCustodyPolicyFlags(f)
	journalFlags := addArchiveCustodyJournalLimitFlags(f)
	workerPath := f.String("worker", "", "existing B worker journal (serve only)")
	objectPath := f.String("objects", "", "existing B archive object store")
	objectPolicy := workarchive.DefaultObjectStorePolicy()
	f.Uint64Var(&objectPolicy.MaximumObjects, "max-objects", objectPolicy.MaximumObjects, "existing object count budget")
	f.Uint64Var(&objectPolicy.MaximumBytes, "max-object-bytes", objectPolicy.MaximumBytes, "existing object byte budget")
	authorityPath := f.String("authority", "", "existing original A authority")
	pinsPath := f.String("authority-pins", "", "existing original A authority pin journal")
	intentPath := f.String("intent", "", "existing unsigned A audit intent")
	intentPin := f.String("intent-id", "", "independently retained intent ID")
	auditAdmission := f.String("audit-admission", "", "existing co-signed V1 Audit admission")
	auditPin := f.String("audit-ticket-id", "", "independently retained Audit ticket ID")
	artifactsPath := f.String("artifacts", "", "existing original A artifact root")
	controlKey := f.String("control-key", "", "existing local control transport seed on A; B command-signing seed on B")
	transportKey := f.String("key", "", "existing B transport seed (serve) or A auditor transport seed (audit)")
	replicaKey := f.String("replica-key", "", "existing B proof seed")
	authorityKey := f.String("authority-key", "", "existing A authority seed")
	auditorKey := f.String("auditor-key", "", "existing A auditor evidence seed")
	drainPath := f.String("drain", "", "dedicated immutable sealed-metadata artifact path")
	drainPin := f.String("drain-id", "", "pin required when an existing drain artifact is selected")
	terminalPath := f.String("terminal", "", "dedicated immutable accepted-terminal artifact path")
	terminalPin := f.String("terminal-id", "", "pin required when an existing terminal is selected")
	entryPath := f.String("complete-entry", "", "optional externally co-signed V1 Complete entry")
	entryPin := f.String("complete-entry-id", "", "independent Complete entry pin")
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return o, err
	}
	if *mode != "review" && *mode != "control" {
		return o, errors.New("mode must be review or control")
	}
	if o.role == "serve" && (*authorityPath != "" || *pinsPath != "" || *intentPath != "" || *intentPin != "" || *auditAdmission != "" || *auditPin != "" || *artifactsPath != "" || *authorityKey != "" || *auditorKey != "" || *address != "" || *drainPath != "" || *terminalPath != "" || *entryPath != "" || *drainPin != "" || *terminalPin != "" || *entryPin != "") {
		return o, errors.New("B cannot select A owners, audit keys or result artifacts")
	}
	if o.role == "audit" && (*workerPath != "" || *objectPath != "" || *replicaKey != "") {
		return o, errors.New("A cannot select B worker, object store or proof key")
	}
	o.mode = *mode
	o.listen = *listen
	o.address = *address
	ma, err := multiaddr.NewMultiaddr(*listen)
	if err != nil {
		return o, err
	}
	protocols := ma.Protocols()
	if ma.String() != *listen || len(protocols) != 3 || (protocols[0].Code != multiaddr.P_IP4 && protocols[0].Code != multiaddr.P_IP6) || protocols[1].Code != multiaddr.P_UDP || protocols[2].Code != multiaddr.P_QUIC_V1 {
		return o, errors.New("listen must be a canonical direct IP/UDP/QUIC-v1 address")
	}
	if *timeout < remotewire.MinimumTimeout || *timeout > remotewire.MaximumTimeout {
		return o, errors.New("remote exchange timeout must be 100ms..2m")
	}
	if err := errors.Join(policyFlags.validate(), journalFlags.limits().Validate(), objectPolicy.Validate()); err != nil {
		return o, err
	}
	var assignmentID, planID, beginID types.Hash
	for _, v := range []struct {
		name, text string
		dst        *types.Hash
	}{{"assignment-id", *assignmentPin, &assignmentID}, {"plan-id", *planPin, &planID}, {"begin-id", *beginPin, &beginID}} {
		id, err := pruneExternalID(v.name, v.text)
		if err != nil {
			return o, err
		}
		*v.dst = id
	}
	files := []struct {
		name string
		path *string
	}{{"assignment", assignmentPath}, {"plan", planPath}, {"begin", beginPath}, {"manifest", manifestPath}, {"receipt", receiptPath}, {"previous-receipt", previousPath}, {"challenge", challengePath}, {"control-key", controlKey}, {"key", transportKey}}
	if o.role == "audit" {
		files = append(files, struct {
			name string
			path *string
		}{"intent", intentPath}, struct {
			name string
			path *string
		}{"audit-admission", auditAdmission}, struct {
			name string
			path *string
		}{"authority-key", authorityKey}, struct {
			name string
			path *string
		}{"auditor-key", auditorKey})
	} else {
		files = append(files, struct {
			name string
			path *string
		}{"replica-key", replicaKey})
	}
	for _, v := range files {
		*v.path, err = remoteCustodyPathFile(*v.path)
		if err != nil {
			return o, err
		}
		o.paths = append(o.paths, remoteCustodyPath{v.name, *v.path})
	}
	a, err := loadPruneOfflineAssignment(*assignmentPath, assignmentID)
	if err != nil {
		return o, err
	}
	b, err := readRegularArtifact(*planPath, remoteworker.MaximumPlanBytes)
	if err != nil {
		return o, err
	}
	plan, err := remoteworker.DecodePlan(b)
	if err != nil {
		return o, err
	}
	b, err = readRegularArtifact(*beginPath, custodyauthority.MaximumEntryBytes)
	if err != nil {
		return o, err
	}
	begin, err := custodyauthority.DecodeEntry(b)
	if err != nil {
		return o, err
	}
	manifest, err := loadArchiveManifest(*manifestPath)
	if err != nil {
		return o, err
	}
	receipt, err := loadArchiveReplicaReceipt(*receiptPath)
	if err != nil {
		return o, err
	}
	previous, err := loadArchiveReplicaReceipt(*previousPath)
	if err != nil {
		return o, err
	}
	b, err = readRegularArtifact(*challengePath, workarchive.MaximumCustodyChallengeBytes)
	if err != nil {
		return o, err
	}
	challenge, err := workarchive.DecodeCustodyChallenge(b)
	if err != nil {
		return o, err
	}
	o.scope = store.RemoteCustodyScope{Worker: remoteworker.Config{Assignment: a, Plan: plan, PlanID: planID, Begin: begin, BeginID: beginID}, Manifest: manifest, InitialReceipt: receipt, PreviousReceipt: previous,
		CustodyPolicy: workarchive.CustodyPolicy{TrustedAuditors: append([][32]byte(nil), a.Auditors...), MaximumChallengeLifetime: *policyFlags.challengeLifetime, MaximumProofAge: *policyFlags.proofAge, MaximumRenewalTerm: *policyFlags.renewalTerm}, Challenge: challenge}
	if err := store.ValidateRemoteCustodyScope(o.scope); err != nil {
		return o, err
	}
	roots := []struct {
		name string
		path *string
	}{{"journal", journalPath}}
	if o.role == "audit" {
		roots = append(roots, struct {
			name string
			path *string
		}{"authority", authorityPath}, struct {
			name string
			path *string
		}{"authority-pins", pinsPath}, struct {
			name string
			path *string
		}{"artifacts", artifactsPath})
	} else {
		roots = append(roots, struct {
			name string
			path *string
		}{"worker", workerPath}, struct {
			name string
			path *string
		}{"objects", objectPath})
	}
	for _, v := range roots {
		*v.path, err = managedCustodyCanonicalDirectory(*v.path)
		if err != nil {
			return o, err
		}
		o.paths = append(o.paths, remoteCustodyPath{v.name, *v.path})
	}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if err := store.ValidateBootstrapPaths(*roots[i].path, *roots[j].path); err != nil {
				return o, err
			}
		}
	}
	session := workarchive.DefaultCustodySessionConfig()
	session.RequestTimeout = *timeout
	if o.role == "audit" {
		intentID, err := pruneExternalID("intent-id", *intentPin)
		if err != nil {
			return o, err
		}
		intent, err := workarchive.LoadCustodyAuditIntent(*intentPath, intentID)
		if err != nil {
			return o, err
		}
		ticket, err := pruneExternalID("audit-ticket-id", *auditPin)
		if err != nil {
			return o, err
		}
		b, err := readRegularArtifact(*auditAdmission, custodyauthority.MaximumEntryBytes)
		if err != nil {
			return o, err
		}
		admission, err := custodyauthority.DecodeEntry(b)
		if err != nil {
			return o, err
		}
		actual, _ := admission.ID()
		if actual != ticket {
			return o, errors.New("Audit admission differs from selected ticket")
		}
		if err := store.ValidateRemoteCustodyAuditScope(o.scope, intent, admission); err != nil {
			return o, err
		}
		if *address != "" {
			peer, err := libp2ptransport.PeerIDFromAddress(*address)
			expected, pe := transportPeer(a.RemoteTransportPublicKey)
			if err != nil || pe != nil || peer != expected {
				return o, errors.New("peer route differs from pinned B transport")
			}
		}
		o.audit = store.RemoteCustodyAuditRuntimeConfig{AuthorityPath: *authorityPath, AuthorityPinsPath: *pinsPath, Scope: o.scope, Audit: store.ManagedCustodyAuditConfig{AssignmentID: assignmentID, Admission: admission, IntentID: intentID, IntentPath: *intentPath, JournalPath: *journalPath, ArtifactsPath: *artifactsPath, Manifest: manifest, InitialReceipt: receipt, CustodyPolicy: o.scope.CustodyPolicy, JournalLimits: journalFlags.limits(), SessionConfig: session}}
		for _, v := range []struct {
			name string
			path *string
			pin  string
			dst  *types.Hash
		}{{"drain", drainPath, *drainPin, &o.drainID}, {"terminal", terminalPath, *terminalPin, &o.terminalID}, {"complete-entry", entryPath, *entryPin, &o.entryID}} {
			if *v.path == "" {
				if v.pin != "" {
					return o, errors.New("artifact pin requires its path")
				}
				continue
			}
			*v.path, err = remoteCustodyPathFile(*v.path)
			if err != nil {
				return o, err
			}
			o.paths = append(o.paths, remoteCustodyPath{v.name, *v.path})
			if v.pin != "" {
				*v.dst, err = pruneExternalID(v.name+"-id", v.pin)
				if err != nil {
					return o, err
				}
			} else if _, err := os.Lstat(*v.path); err == nil {
				return o, errors.New("existing artifact requires an independent ID")
			}
			for _, root := range roots {
				if err := store.ValidateBootstrapPaths(filepath.Dir(*v.path), *root.path); err != nil {
					return o, err
				}
			}
			if err := store.ValidateBootstrapPaths(filepath.Dir(*v.path), filepath.Dir(*intentPath)); err != nil {
				return o, err
			}
			for _, input := range files {
				if *v.path == *input.path {
					return o, errors.New("output cannot replace a scope or key file")
				}
			}
		}
		o.drainPath, o.terminalPath, o.entryPath = *drainPath, *terminalPath, *entryPath
		if o.drainPath != "" && o.drainPath == o.terminalPath {
			return o, errors.New("drain and terminal must be distinct files")
		}
		if !o.drainID.IsZero() {
			if _, err := store.LoadRemoteCustodyDrain(o.drainPath, o.drainID, o.scope); err != nil {
				return o, err
			}
		}
		if !o.terminalID.IsZero() {
			term, err := store.LoadRemoteCustodyTerminal(o.terminalPath, o.terminalID)
			if err != nil {
				return o, err
			}
			if err := term.Validate(o.scope); err != nil {
				return o, err
			}
		}
		if o.entryPath != "" {
			if o.entryID.IsZero() || o.terminalID.IsZero() {
				return o, errors.New("Complete input requires entry and terminal pins")
			}
			b, err := readRegularArtifact(o.entryPath, custodyauthority.MaximumEntryBytes)
			if err != nil {
				return o, err
			}
			entry, err := custodyauthority.DecodeEntry(b)
			if err != nil {
				return o, err
			}
			id, _ := entry.ID()
			c := entry.Command
			if id != o.entryID || entry.Version != custodyauthority.Version1 || entry.AuthorityPublicKey != a.AuthorityPublicKey || c.AssignmentID != assignmentID || c.Kind != custodyauthority.Complete || c.EvidenceID != o.terminalID {
				return o, errors.New("Complete input differs from scope or retained terminal")
			}
		}
	}
	// All public scope and placement checks precede reading private seeds.
	ctrl, err := loadPruneOfflineKey(*controlKey)
	if err != nil {
		return o, err
	}
	key, err := loadPruneOfflineKey(*transportKey)
	if err != nil {
		return o, err
	}
	o.controlKey, o.transportKey = ctrl, key
	if o.role == "serve" {
		replica, err := loadPruneOfflineKey(*replicaKey)
		if err != nil {
			return o, err
		}
		if !remoteKeyMatches(ctrl, a.RemoteControlPublicKey) || !remoteKeyMatches(key, a.RemoteTransportPublicKey) || !remoteKeyMatches(replica, a.ReplicaPublicKey) {
			return o, errors.New("B seeds differ from independently pinned roles")
		}
		o.serve = store.RemoteCustodyServeServiceConfig{Scope: o.scope, WorkerPath: *workerPath, JournalPath: *journalPath, ObjectPath: *objectPath, ObjectPolicy: objectPolicy, JournalLimits: journalFlags.limits(), ReplicaPrivateKey: replica, ControlPrivateKey: ctrl, SessionConfig: session}
	} else {
		authority, err := loadPruneOfflineKey(*authorityKey)
		if err != nil {
			return o, err
		}
		auditor, err := loadPruneOfflineKey(*auditorKey)
		if err != nil {
			return o, err
		}
		intent, err := workarchive.LoadCustodyAuditIntent(*intentPath, o.audit.Audit.IntentID)
		if err != nil {
			return o, err
		}
		if !remoteKeyMatches(ctrl, plan.AuthorityTransportPublicKey) || !remoteKeyMatches(key, plan.AuditorTransportPublicKey) || !remoteKeyMatches(authority, a.AuthorityPublicKey) || !remoteKeyMatches(auditor, intent.AuditorPublicKey) {
			return o, errors.New("A seeds differ from independently pinned roles")
		}
		o.audit.AuthorityPrivateKey = authority
		o.audit.Audit.AuditorPrivateKey = auditor
	}
	return o, nil
}

func transportPeer(key [32]byte) (types.Hash, error) { return transport.PeerIDFromPublicKey(key[:]) }
func remoteKeyMatches(key ed25519.PrivateKey, expected [32]byte) bool {
	return len(key) == ed25519.PrivateKeySize && [32]byte(key.Public().(ed25519.PublicKey)) == expected
}

type remoteCustodyDisplay struct {
	Role, AssignmentID, PlanID, BeginID, AuditTicketID, ServeTicketID                      string
	ConfirmedSequence, ObservedSequence, JournalSequence                                   uint64
	ConfirmedHead, ObservedHead, PendingEntry, ActiveBegin, JournalHead, ReceiptID, SealID string
	Phase                                                                                  custodyauthority.Phase
	Pending                                                                                uint16
	WorkerStage, WorkerPending                                                             remoteworker.Stage
	Paths                                                                                  []remoteCustodyPath
	OwnerPaths                                                                             []string
	Peer, Listen, Timeout, DrainID, TerminalID, CompleteEntryID                            string
	JournalLimits                                                                          workarchive.CustodyJournalLimits
	ObjectPolicy                                                                           workarchive.ObjectStorePolicy
}

func remoteCustodyDisplayFor(o remoteCustodyOptions, r store.RemoteCustodyReview) remoteCustodyDisplay {
	return remoteCustodyDisplay{Role: r.Role, AssignmentID: r.AssignmentID.String(), PlanID: r.PlanID.String(), BeginID: r.BeginID.String(), AuditTicketID: r.AuditTicketID.String(), ServeTicketID: r.ServeTicketID.String(),
		ConfirmedSequence: r.Confirmed.Sequence, ObservedSequence: r.Observed.Sequence, JournalSequence: r.JournalSequence, ConfirmedHead: r.Confirmed.HeadID.String(), ObservedHead: r.Observed.HeadID.String(),
		PendingEntry: r.PendingEntryID.String(), ActiveBegin: r.ActiveBeginID.String(), JournalHead: r.JournalHeadID.String(), ReceiptID: r.CurrentReceiptID.String(), SealID: r.SealID.String(), Phase: r.Phase, Pending: r.Pending,
		WorkerStage: r.WorkerStage, WorkerPending: r.WorkerPending, Paths: o.paths, OwnerPaths: r.Paths, Peer: o.address, Listen: o.listen, Timeout: r.Timeout.String(), DrainID: o.drainID.String(), TerminalID: o.terminalID.String(), CompleteEntryID: o.entryID.String(), JournalLimits: r.JournalLimits, ObjectPolicy: r.ObjectPolicy}
}

func writeRemoteCustodyReview(out io.Writer, o remoteCustodyOptions, r store.RemoteCustodyReview, retained bool, nonce types.Hash) (types.Hash, error) {
	base, err := r.ID()
	if err != nil {
		return types.Hash{}, err
	}
	body, err := json.MarshalIndent(remoteCustodyDisplayFor(o, r), "", "  ")
	if err != nil {
		return types.Hash{}, err
	}
	token := types.DomainHash("OMESH/local/remote-custody-cli-review/v0", base[:], body, nonce[:])
	err = writePruneOutputLine(out, fmt.Sprintf("remote_custody_review role=%s review_id=%s base_id=%s owners_retained=%t listener_started=false\nscope:\n%s\nremote_custody_scope_end\n", o.role, token, base, retained, body))
	if err != nil {
		return types.Hash{}, err
	}
	return token, nil
}

func runRemoteCustody(ctx context.Context, args []string, input io.ReadCloser, output io.Writer) (returnErr error) {
	if ctx == nil || output == nil {
		return errors.New("remote custody needs context and output")
	}
	o, err := loadRemoteCustodyOptions(ctx, args)
	if err != nil {
		return err
	}
	if o.mode == "review" {
		var review store.RemoteCustodyReview
		if o.role == "serve" {
			review, err = store.InspectRemoteCustodyServe(ctx, o.serve)
		} else {
			runtime, e := store.OpenRemoteCustodyAuditRuntime(ctx, o.audit)
			if e != nil {
				return e
			}
			review, err = runtime.Review(ctx)
			err = errors.Join(err, runtime.Close())
		}
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return remoteCustodyOneShotOutput(ctx, output, o, review)
	}
	control, err := ownPruneControlInput(input)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, control.Close()) }()
	writer, err := ownPruneEffectOutput(output)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, writer.Close()) }()
	return runRemoteCustodyControl(ctx, o, control, writer)
}

func remoteCustodyOneShotOutput(ctx context.Context, output io.Writer, o remoteCustodyOptions, r store.RemoteCustodyReview) (returnErr error) {
	if file, ok := output.(*os.File); ok {
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeNamedPipe != 0 && (runtime.GOOS == "darwin" || runtime.GOOS == "linux") {
			owned, err := ownPruneEffectOutput(output)
			if err != nil {
				return err
			}
			defer func() { returnErr = errors.Join(returnErr, owned.Close()) }()
			done := make(chan struct{})
			stop := context.AfterFunc(ctx, func() { defer close(done); _ = owned.Close() })
			defer func() {
				if !stop() {
					<-done
				}
			}()
			output = owned
		}
	}
	_, err := writeRemoteCustodyReview(output, o, r, false, types.Hash{})
	return err
}

func runRemoteCustodyControl(parent context.Context, o remoteCustodyOptions, input *pruneControlInput, output *pruneEffectOutput) (returnErr error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	lines := make(chan string, 1)
	terminal := make(chan error, 1)
	readerDone := make(chan struct{})
	go func() { defer close(readerDone); readPruneEffectControl(ctx, input, lines, terminal, cancel) }()
	ioDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(ioDone); _ = input.Close(); _ = output.Close() })
	defer func() {
		cancel()
		if !stop() {
			<-ioDone
		}
		_ = input.Close()
		_ = output.Close()
		<-readerDone
	}()
	var a *store.RemoteCustodyAuditRuntime
	var b *store.RemoteCustodyServeService
	var err error
	if o.role == "audit" {
		a, err = store.OpenRemoteCustodyAuditRuntime(ctx, o.audit)
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, a.Close()) }()
	} else {
		b, err = store.OpenRemoteCustodyServeService(ctx, o.serve)
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, b.Close()) }()
	}
	if err := writePruneOutputLine(output, fmt.Sprintf("remote_custody_ready role=%s assignment_id=%s plan_id=%s begin_id=%s owners_retained=true listener_started=false\n", o.role, o.scope.Worker.Plan.AssignmentID, o.scope.Worker.PlanID, o.scope.Worker.BeginID)); err != nil {
		return err
	}
	var nonce types.Hash
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	var reported, base types.Hash
	for {
		select {
		case <-ctx.Done():
			select {
			case e := <-terminal:
				if errors.Is(e, io.EOF) {
					return nil
				}
				return e
			default:
				return ctx.Err()
			}
		case e := <-terminal:
			if errors.Is(e, io.EOF) {
				return nil
			}
			return e
		case line := <-lines:
			if err := ctx.Err(); err != nil {
				return err
			}
			if line == "close" {
				return nil
			}
			if line == "review" {
				var r store.RemoteCustodyReview
				if a != nil {
					r, err = a.Review(ctx)
				} else {
					r, err = b.Review(ctx)
				}
				if err != nil {
					return err
				}
				base, err = r.ID()
				if err != nil {
					return err
				}
				reported, err = writeRemoteCustodyReview(output, o, r, true, nonce)
				if err != nil {
					return err
				}
				continue
			}
			action, text, ok := strings.Cut(line, " ")
			if !ok {
				return errors.New("expected review, <action> <review-id>, or close")
			}
			id, err := pruneExternalID("review-id", text)
			if err != nil || reported.IsZero() || id != reported {
				return errors.New("action needs the exact fully reported same-session review ID")
			}
			reported = types.Hash{}
			tcg := libp2ptransport.DefaultConfig()
			tcg.Listen = []string{o.listen}
			if b != nil {
				if action != "serve" {
					return errors.New("B control accepts review, serve <review-id>, or close")
				}
				if err := b.StartReviewed(ctx, o.transportKey, tcg, base); err != nil {
					return err
				}
				if err := writePruneOutputLine(output, fmt.Sprintf("remote_custody_serving expected_review_id=%s listen=%s owners_retained=true\n", id, strings.Join(b.Addresses(), ","))); err != nil {
					return errors.Join(errRemoteCustodyUnobserved, err)
				}
				continue
			}
			run, err := store.WithRemoteCustodyReview(ctx, base)
			if err != nil {
				return err
			}
			switch action {
			case "prepare":
				c, err := a.PrepareChallenge(run)
				if err != nil {
					return err
				}
				cid, _ := c.ID()
				err = writePruneOutputLine(output, fmt.Sprintf("remote_custody_prepared expected_review_id=%s challenge_id=%s\n", id, cid))
			case "begin", "resume-begin":
				var commit store.Commit
				if action == "begin" {
					commit, err = a.Begin(run)
				} else {
					commit, err = a.ResumeBegin(run)
				}
				if err != nil {
					return err
				}
				err = writePruneOutputLine(output, fmt.Sprintf("remote_custody_begun expected_review_id=%s entry_id=%s sequence=%d appended=%t\n", id, commit.EntryID, commit.Snapshot.Sequence, commit.Appended))
			case "execute":
				if o.address == "" {
					return errors.New("execute needs --peer")
				}
				result, e := a.ExecuteQUIC(run, o.controlKey, o.transportKey, tcg, o.address)
				if e != nil {
					return e
				}
				proof, _ := result.Record.Proof.ID()
				err = writePruneOutputLine(output, fmt.Sprintf("remote_custody_executed expected_review_id=%s journal_sequence=%d proof_id=%s responded_at=%d recovered=%t completion_submitted=false\n", id, result.JournalSequence, proof, result.Record.Proof.RespondedAt, result.Recovered))
			case "seal", "resume-drain", "reconcile":
				if o.address == "" || o.drainPath == "" {
					return errors.New("metadata action needs --peer and --drain")
				}
				var response remotewire.Response
				if action == "seal" {
					response, err = a.SealQUIC(run, o.controlKey, tcg, o.address)
				} else if action == "resume-drain" {
					response, err = a.ResumeDrainQUIC(run, o.controlKey, tcg, o.address)
				} else {
					response, err = a.ReconcileQUIC(run, o.controlKey, tcg, o.address)
				}
				if err != nil {
					return err
				}
				if response.Status == remotewire.StatusDrained {
					o.drainID, err = store.PublishRemoteCustodyDrain(ctx, o.drainPath, o.scope, response)
					if err != nil {
						return errors.Join(errRemoteCustodyUnobserved, err)
					}
				}
				err = writePruneOutputLine(output, fmt.Sprintf("remote_custody_metadata expected_review_id=%s status=%d drain_id=%s disposition=%d completion_submitted=false\n", id, response.Status, o.drainID, response.Seal.Disposition))
			case "capture":
				if o.drainPath == "" || o.drainID.IsZero() || o.terminalPath == "" {
					return errors.New("capture needs retained pinned --drain and --terminal output")
				}
				response, e := store.LoadRemoteCustodyDrain(o.drainPath, o.drainID, o.scope)
				if e != nil {
					return e
				}
				term, e := a.CaptureTerminalToFile(run, response, o.terminalPath)
				if e != nil {
					return errors.Join(errRemoteCustodyUnobserved, e)
				}
				o.terminalID, _ = term.ID()
				err = writePruneOutputLine(output, fmt.Sprintf("remote_custody_captured expected_review_id=%s terminal_id=%s completion_submitted=false\n", id, o.terminalID))
			case "apply-complete", "resume-complete":
				if o.entryPath == "" || o.entryID.IsZero() || o.terminalID.IsZero() {
					return errors.New("completion needs a pinned external --complete-entry and retained --terminal")
				}
				term, e := store.LoadRemoteCustodyTerminal(o.terminalPath, o.terminalID)
				if e != nil {
					return e
				}
				bytes, e := readRegularArtifact(o.entryPath, custodyauthority.MaximumEntryBytes)
				if e != nil {
					return e
				}
				entry, e := custodyauthority.DecodeEntry(bytes)
				if e != nil {
					return e
				}
				eid, _ := entry.ID()
				if eid != o.entryID {
					return errors.New("Complete entry differs from selected ID")
				}
				var commit store.Commit
				if action == "apply-complete" {
					commit, err = a.ApplyComplete(run, term, entry)
				} else {
					commit, err = a.ResumeComplete(run, term, entry)
				}
				if err != nil {
					return err
				}
				err = writePruneOutputLine(output, fmt.Sprintf("remote_custody_completed expected_review_id=%s entry_id=%s sequence=%d appended=%t pending=%d\n", id, commit.EntryID, commit.Snapshot.Sequence, commit.Appended, commit.Snapshot.Pending))
			default:
				return errors.New("unknown remote custody operator action")
			}
			if err != nil {
				return errors.Join(errRemoteCustodyUnobserved, err)
			}
		}
	}
}
