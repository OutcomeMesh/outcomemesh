package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/storage"
)

type archiveVerificationFlags struct {
	data                 *string
	manifest             *string
	checkpoint           *string
	trustedAttestors     repeatedStringFlag
	requiredAttestations *uint
	maximumBlocks        *uint64
	maximumChunks        *uint
	maximumBytes         *uint64
}

func addArchiveVerificationFlags(flags *flag.FlagSet) *archiveVerificationFlags {
	values := archiveVerificationFlags{
		data: flags.String(
			"data", defaultDataDirectory,
			"WorkGraph-enabled node containing the independently verified activation base",
		),
		manifest:   flags.String("manifest", "", "canonical target archive manifest"),
		checkpoint: flags.String("checkpoint", "", "canonical multi-attestor archive checkpoint"),
		requiredAttestations: flags.Uint(
			"required-attestations", workarchive.MinimumAttestors,
			"required trusted checkpoint signatures",
		),
		maximumBlocks: flags.Uint64(
			"max-archive-blocks", workarchive.MaximumArchiveBlocks,
			"local replay limit for archive blocks",
		),
		maximumChunks: flags.Uint(
			"max-archive-chunks", workarchive.MaximumArchiveChunks,
			"local replay limit for archive chunks",
		),
		maximumBytes: flags.Uint64(
			"max-archive-bytes", workarchive.MaximumArchiveBytes,
			"local replay limit for canonical chunk bytes",
		),
	}
	flags.Var(
		&values.trustedAttestors, "attestor-public-key",
		"trusted Ed25519 checkpoint public key; repeat for every trusted attestor",
	)
	return &values
}

type archiveVerificationContext struct {
	manifest   workarchive.Manifest
	checkpoint workarchive.Checkpoint
	policy     workarchive.Policy
	base       workchain.Base
	parameters workblock.Parameters
	limits     workarchive.Limits
}

func (values *archiveVerificationFlags) load() (archiveVerificationContext, error) {
	if values == nil {
		return archiveVerificationContext{}, errors.New("archive verification flags are missing")
	}
	if *values.data == "" || *values.manifest == "" || *values.checkpoint == "" ||
		len(values.trustedAttestors) < workarchive.MinimumAttestors ||
		len(values.trustedAttestors) > workarchive.MaximumAttestors ||
		*values.requiredAttestations < workarchive.MinimumAttestors ||
		*values.requiredAttestations > uint(len(values.trustedAttestors)) ||
		*values.requiredAttestations > uint(^uint16(0)) ||
		*values.maximumChunks > uint(^uint32(0)) {
		return archiveVerificationContext{}, errors.New(
			"data, manifest, checkpoint, 2..64 trusted attestors, and a bounded quorum are required",
		)
	}
	limits := workarchive.Limits{
		MaximumBlocks: *values.maximumBlocks,
		MaximumChunks: uint32(*values.maximumChunks),
		MaximumBytes:  *values.maximumBytes,
	}
	if err := limits.Validate(); err != nil {
		return archiveVerificationContext{}, err
	}
	manifest, err := loadArchiveManifest(*values.manifest)
	if err != nil {
		return archiveVerificationContext{}, err
	}
	if manifest.BlockCount > limits.MaximumBlocks ||
		uint32(len(manifest.Chunks)) > limits.MaximumChunks ||
		manifest.TotalChunkBytes > limits.MaximumBytes {
		return archiveVerificationContext{}, workarchive.ErrArchiveLimit
	}
	checkpoint, err := loadArchiveCheckpoint(*values.checkpoint)
	if err != nil {
		return archiveVerificationContext{}, err
	}
	trusted := make([][ed25519.PublicKeySize]byte, len(values.trustedAttestors))
	for index, encoded := range values.trustedAttestors {
		trusted[index], err = parseArchivePublicKey(encoded)
		if err != nil {
			return archiveVerificationContext{}, fmt.Errorf("attestor-public-key %d: %w", index+1, err)
		}
	}
	sort.Slice(trusted, func(left, right int) bool {
		return types.CompareHash(types.Hash(trusted[left]), types.Hash(trusted[right])) < 0
	})
	for index := 1; index < len(trusted); index++ {
		if trusted[index-1] == trusted[index] {
			return archiveVerificationContext{}, errors.New("trusted archive attestor keys must be unique")
		}
	}
	policy := workarchive.Policy{
		Binding: manifest.Binding, TrustedAttestors: trusted,
		RequiredAttestations: uint16(*values.requiredAttestations),
	}
	if err := checkpoint.Verify(policy); err != nil {
		return archiveVerificationContext{}, err
	}
	if err := manifest.VerifyStatement(checkpoint.Statement); err != nil {
		return archiveVerificationContext{}, err
	}

	document, err := loadGenesis(*values.data)
	if err != nil {
		return archiveVerificationContext{}, err
	}
	profile, err := loadWorkActivation(*values.data, document)
	if err != nil {
		return archiveVerificationContext{}, err
	}
	genesisID, err := document.ID()
	if err != nil {
		return archiveVerificationContext{}, err
	}
	if manifest.Binding.NetworkID != document.NetworkID ||
		manifest.Binding.GenesisID != genesisID ||
		manifest.Binding.ActivationHeight != profile.ActivationHeight {
		return archiveVerificationContext{}, errors.New("archive binding does not match node activation")
	}
	ledger, err := openStore(*values.data, document)
	if err != nil {
		return archiveVerificationContext{}, err
	}
	base, baseErr := archiveBaseFromLedger(
		ledger, manifest.Binding.BaseID, profile.ActivationHeight,
	)
	closeErr := ledger.Close()
	if baseErr != nil || closeErr != nil {
		return archiveVerificationContext{}, errors.Join(baseErr, closeErr)
	}
	legacy := legacyblock.ParametersFromGenesis(document)
	parameters := workblock.Parameters{
		NetworkID: document.NetworkID, BlockSubsidy: document.BlockSubsidy,
		RewardMaturity: legacy.RewardMaturity, ActivationHeight: profile.ActivationHeight,
		DifficultyAnchorTimestamp: document.Timestamp,
		DifficultyAnchorTarget:    document.Target,
		TargetSpacing:             legacy.TargetSpacing, ASERTHalfLife: legacy.ASERTHalfLife,
		FeeDelay: profile.FeeDelay,
	}
	validationChain, err := workchain.New(base, parameters)
	if err != nil {
		return archiveVerificationContext{}, err
	}
	if err := validationChain.Close(); err != nil {
		return archiveVerificationContext{}, err
	}
	return archiveVerificationContext{
		manifest: manifest, checkpoint: checkpoint, policy: policy,
		base: base, parameters: parameters, limits: limits,
	}, nil
}

func archiveBaseFromLedger(
	ledger storage.Ledger,
	baseID types.Hash,
	activationHeight uint64,
) (workchain.Base, error) {
	if ledger == nil || baseID.IsZero() || activationHeight == 0 {
		return workchain.Base{}, errors.New("invalid archive activation base request")
	}
	tip, err := ledger.TipByID(baseID)
	if err != nil || tip.Height == ^uint64(0) || tip.Height+1 != activationHeight {
		return workchain.Base{}, errors.Join(errors.New("archive base is not the activation parent"), err)
	}
	snapshot, err := ledger.SnapshotAt(baseID)
	if err != nil {
		return workchain.Base{}, err
	}
	history := []uint64{tip.Timestamp}
	if tip.Height > 0 {
		history = history[:0]
		cursor := tip.ID
		for height := tip.Height; height > 0 && len(history) < 11; height-- {
			candidate, loadErr := ledger.BlockByID(cursor)
			if loadErr != nil {
				return workchain.Base{}, loadErr
			}
			id, idErr := candidate.Header.ID()
			if idErr != nil || id != cursor || candidate.Header.Height != height {
				return workchain.Base{}, errors.Join(storage.ErrCorrupt, idErr)
			}
			history = append(history, candidate.Header.Timestamp)
			cursor = candidate.Header.Parent
		}
		for left, right := 0, len(history)-1; left < right; left, right = left+1, right-1 {
			history[left], history[right] = history[right], history[left]
		}
	}
	return workchain.Base{Tip: tip, State: snapshot, RecentTimestamps: history}, nil
}

func loadArchiveCheckpoint(path string) (workarchive.Checkpoint, error) {
	encoded, err := readRegularArtifact(path, workarchive.MaximumCheckpointBytes)
	if err != nil {
		return workarchive.Checkpoint{}, err
	}
	checkpoint, err := workarchive.DecodeCheckpoint(encoded)
	if err != nil {
		return workarchive.Checkpoint{}, err
	}
	return checkpoint, nil
}

func runWorkArchiveObjectServeQUIC(arguments []string) error {
	flags := flag.NewFlagSet("work-archive-object-serve-quic", flag.ContinueOnError)
	transportKeyPath := flags.String("key", "", "archive server QUIC transport Ed25519 seed file")
	listenAddress := flags.String("listen", "/ip4/127.0.0.1/udp/0/quic-v1", "direct QUIC-v1 listen multiaddress")
	archivePath := flags.String("archive", "", "complete source archive directory to replay and import")
	objectStorePath := flags.String("object-store", "", "persistent verified content-addressed archive object store")
	var clientPeerIDs repeatedStringFlag
	flags.Var(&clientPeerIDs, "client-peer-id", "allowed client OutcomeMesh transport peer ID; repeat for each client")
	verificationFlags := addArchiveVerificationFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *transportKeyPath == "" || *archivePath == "" || *objectStorePath == "" {
		return errors.New("transport key, source archive, and object store are required")
	}
	allowedClients, err := parseArchivePeerIDs(clientPeerIDs)
	if err != nil {
		return err
	}
	verification, err := verificationFlags.load()
	if err != nil {
		return err
	}
	sourceManifest, err := workarchive.VerifyArchiveDirectory(
		*archivePath, verification.checkpoint, verification.policy,
		verification.base, verification.parameters, verification.limits,
	)
	if err != nil {
		return err
	}
	manifestID, err := verification.manifest.ID()
	if err != nil {
		return err
	}
	sourceManifestID, err := sourceManifest.ID()
	if err != nil || sourceManifestID != manifestID {
		return errors.Join(errors.New("source archive differs from configured manifest"), err)
	}
	store, err := workarchive.OpenObjectStore(
		*objectStorePath, workarchive.DefaultObjectStorePolicy(),
	)
	if err != nil {
		return err
	}
	imported, err := store.ImportArchiveDirectory(
		*archivePath, verification.checkpoint, verification.policy,
		verification.base, verification.parameters, verification.limits,
	)
	if err != nil {
		return err
	}
	if imported.ManifestID != manifestID {
		return errors.New("source archive differs from configured manifest")
	}
	session, err := workarchive.NewObjectSession(
		verification.manifest, store, workarchive.DefaultObjectSessionConfig(),
	)
	if err != nil {
		return err
	}
	transportKey, err := loadPrivateKey(*transportKeyPath)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.Listen = []string{*listenAddress}
	host, err := libp2ptransport.New(ctx, transportKey, config, nil)
	if err != nil {
		return err
	}
	defer host.Close()
	for _, allowed := range allowedClients {
		if allowed == host.ID() {
			return errors.New("archive server and client transport identities must be distinct")
		}
	}
	type serveResult struct {
		peer   types.Hash
		report workarchive.ObjectServeReport
		err    error
	}
	completed := make(chan serveResult, 1)
	if err := host.SetArchiveObjectHandler(
		allowedClients,
		func(handlerContext context.Context, remoteID types.Hash, stream libp2pnetwork.Stream) {
			report, serveErr := session.Serve(handlerContext, stream)
			select {
			case completed <- serveResult{peer: remoteID, report: report, err: serveErr}:
			default:
			}
		},
	); err != nil {
		return err
	}
	addresses := host.Addresses()
	if len(addresses) == 0 {
		return errors.New("archive object server has no direct QUIC address")
	}
	fmt.Printf(
		"work_archive_objects_receiving transport_peer_id=%s manifest=%s clients=%d objects_added=%d objects_reused=%d listen=%s\n",
		host.ID(), manifestID, len(allowedClients), imported.AddedObjects,
		imported.ReusedObjects, strings.Join(addresses, ","),
	)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case outcome := <-completed:
		if outcome.err != nil {
			return outcome.err
		}
		fmt.Printf(
			"work_archive_objects_served peer_id=%s manifest=%s requests=%d objects=%d bytes=%d\n",
			outcome.peer, outcome.report.ManifestID, outcome.report.Requests,
			outcome.report.Objects, outcome.report.SentBytes,
		)
		return nil
	}
}

func runWorkArchiveObjectFetchQUIC(arguments []string) error {
	flags := flag.NewFlagSet("work-archive-object-fetch-quic", flag.ContinueOnError)
	transportKeyPath := flags.String("key", "", "archive client QUIC transport Ed25519 seed file")
	peerAddress := flags.String("peer", "", "source direct QUIC-v1 multiaddress including /p2p/<id>")
	serverPeerIDText := flags.String("peer-id", "", "expected source OutcomeMesh transport peer ID")
	objectStorePath := flags.String("object-store", "", "persistent append-only destination object store")
	destinationPath := flags.String("out", "", "complete replay-verified archive output directory")
	verificationFlags := addArchiveVerificationFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *transportKeyPath == "" || *peerAddress == "" || *serverPeerIDText == "" ||
		*objectStorePath == "" || *destinationPath == "" {
		return errors.New("transport key, pinned source, object store, and output directory are required")
	}
	serverPeerID, err := parseHash(*serverPeerIDText)
	if err != nil {
		return fmt.Errorf("peer-id: %w", err)
	}
	verification, err := verificationFlags.load()
	if err != nil {
		return err
	}
	store, err := workarchive.OpenObjectStore(
		*objectStorePath, workarchive.DefaultObjectStorePolicy(),
	)
	if err != nil {
		return err
	}
	session, err := workarchive.NewObjectSession(
		verification.manifest, store, workarchive.DefaultObjectSessionConfig(),
	)
	if err != nil {
		return err
	}
	_, complete, err := workarchive.BuildChunkRequest(
		verification.manifest, store, workarchive.MaximumObjectRequestIDs,
	)
	if err != nil {
		return err
	}
	report := workarchive.ObjectFetchReport{}
	remoteID := serverPeerID
	networkUsed := false
	if !complete {
		transportKey, loadErr := loadPrivateKey(*transportKeyPath)
		if loadErr != nil {
			return loadErr
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		host, hostErr := libp2ptransport.New(
			ctx, transportKey, libp2ptransport.DefaultConfig(), nil,
		)
		if hostErr != nil {
			return hostErr
		}
		defer host.Close()
		if host.ID() == serverPeerID {
			return errors.New("archive client and server transport identities must be distinct")
		}
		stream, authenticated, openErr := host.OpenArchiveObjectStream(
			ctx, *peerAddress, serverPeerID,
		)
		if openErr != nil {
			return openErr
		}
		remoteID = authenticated
		networkUsed = true
		report, err = session.Fetch(ctx, stream)
		if err != nil {
			return err
		}
		complete = report.Complete
	} else {
		report.ManifestID, err = verification.manifest.ID()
		if err != nil {
			return err
		}
		report.Complete = true
	}
	if !complete {
		fmt.Printf(
			"work_archive_objects_fetched peer_id=%s manifest=%s requests=%d objects=%d added=%d reused=%d bytes=%d complete=false network=%t store=%s\n",
			remoteID, report.ManifestID, report.Requests, report.Objects,
			report.AddedObjects, report.ReusedObjects, report.ReceivedBytes,
			networkUsed, *objectStorePath,
		)
		return nil
	}
	recovered, materialized, err := materializeOrVerifyArchive(
		*destinationPath, store, verification,
	)
	if err != nil {
		return err
	}
	fmt.Printf(
		"work_archive_objects_fetched peer_id=%s manifest=%s requests=%d objects=%d added=%d reused=%d bytes=%d complete=true network=%t materialized_objects=%d materialized_bytes=%d recovered=%t store=%s out=%s\n",
		remoteID, report.ManifestID, report.Requests, report.Objects,
		report.AddedObjects, report.ReusedObjects, report.ReceivedBytes,
		networkUsed, materialized.Objects, materialized.Bytes, recovered,
		*objectStorePath, *destinationPath,
	)
	return nil
}

func materializeOrVerifyArchive(
	path string,
	store *workarchive.ObjectStore,
	verification archiveVerificationContext,
) (bool, workarchive.ObjectMaterializeReport, error) {
	manifestID, err := verification.manifest.ID()
	if err != nil {
		return false, workarchive.ObjectMaterializeReport{}, err
	}
	if _, err := os.Lstat(path); err == nil {
		verified, verifyErr := workarchive.VerifyArchiveDirectory(
			path, verification.checkpoint, verification.policy,
			verification.base, verification.parameters, verification.limits,
		)
		if verifyErr != nil {
			return false, workarchive.ObjectMaterializeReport{}, verifyErr
		}
		verifiedID, idErr := verified.ID()
		if idErr != nil || verifiedID != manifestID {
			return false, workarchive.ObjectMaterializeReport{}, errors.Join(
				errors.New("existing archive output differs from target"), idErr,
			)
		}
		return true, workarchive.ObjectMaterializeReport{
			ManifestID: manifestID, Objects: uint64(len(verified.Chunks)),
			Bytes: verified.TotalChunkBytes,
		}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, workarchive.ObjectMaterializeReport{}, err
	}
	report, err := store.MaterializeDirectory(
		path, verification.manifest, verification.checkpoint, verification.policy,
		verification.base, verification.parameters, verification.limits,
	)
	return false, report, err
}

func parseArchivePeerIDs(encoded []string) ([]types.Hash, error) {
	if len(encoded) == 0 || len(encoded) > libp2ptransport.MaximumArchiveObjectPeers {
		return nil, fmt.Errorf(
			"client-peer-id must be repeated 1..%d times",
			libp2ptransport.MaximumArchiveObjectPeers,
		)
	}
	result := make([]types.Hash, len(encoded))
	for index, value := range encoded {
		parsed, err := parseHash(value)
		if err != nil {
			return nil, fmt.Errorf("client-peer-id %d: %w", index+1, err)
		}
		result[index] = parsed
	}
	sort.Slice(result, func(left, right int) bool {
		return types.CompareHash(result[left], result[right]) < 0
	})
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, errors.New("client peer IDs must be unique")
		}
	}
	return result, nil
}
