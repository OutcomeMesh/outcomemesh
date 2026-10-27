GO ?= go
FUZZTIME ?= 3s
WORKROLLOVERCYCLES ?= 256

.PHONY: build fmt vet test test-race test-fuzz-smoke test-process test-remote-support test-work-rollover-soak test-economic-review economic-review test-calibration test-all

build:
	$(GO) build -trimpath -o bin/omd ./cmd/omd

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

test-race:
	# Three disjoint groups cover all tests without extending timeouts.
	$(GO) test -race ./... -run '^TestArchive'
	$(GO) test -race ./... -skip '^(TestArchive|TestManagedCustody)'
	$(GO) test -race ./... -run '^TestManagedCustody'

test-fuzz-smoke:
	$(GO) test ./cmd/omd -run '^$$' -fuzz '^FuzzDecodePruneEffectRootsNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./core/codec -run '^$$' -fuzz '^FuzzDecoderNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./core/outcome -run '^$$' -fuzz '^FuzzDecodeTransactionNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./core/resource -run '^$$' -fuzz '^FuzzDecodeNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./core/difficulty -run '^$$' -fuzz '^FuzzASERTNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./core/guardvm -run '^$$' -fuzz '^FuzzExecuteDecodedProgramNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./core/execution -run '^$$' -fuzz '^FuzzApplyNeverMutatesPreState$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./core/genesis -run '^$$' -fuzz '^FuzzDecodeNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./core/block -run '^$$' -fuzz '^FuzzDecodeNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./core/chainblock -run '^$$' -fuzz '^FuzzDecodeAnyNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./core/workgraph -run '^$$' -fuzz '^FuzzDecodeNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./core/workgraph -run '^$$' -fuzz '^FuzzDecodeSharesNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./core/workgraph -run '^$$' -fuzz '^FuzzDecodeFeeQueueNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./core/workblock -run '^$$' -fuzz '^FuzzDecodeNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./storage -run '^$$' -fuzz '^FuzzDecodeTipNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/wire -run '^$$' -fuzz '^FuzzDecodeFrameBodyNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/discovery -run '^$$' -fuzz '^FuzzDecodeNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/discovery -run '^$$' -fuzz '^FuzzDecodeBookNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/peers -run '^$$' -fuzz '^FuzzManagerStateMachine$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/peers -run '^$$' -fuzz '^FuzzDecodeManagerNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/snapshot -run '^$$' -fuzz '^FuzzDecodeManifestNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/snapshot -run '^$$' -fuzz '^FuzzDecodeChunkNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/activation -run '^$$' -fuzz '^FuzzDecodeRoutedBlockNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/activation -run '^$$' -fuzz '^FuzzDecodeWorkForestSelectionNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/calibration -run '^$$' -fuzz '^FuzzDecodeRecordNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/calibration -run '^$$' -fuzz '^FuzzDecodeManifestNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/calibration -run '^$$' -fuzz '^FuzzDecodePendingNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/calibration -run '^$$' -fuzz '^FuzzDecodeTiePlanNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/calibration -run '^$$' -fuzz '^FuzzDecodeTiePairCheckpointNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/calibration -run '^$$' -fuzz '^FuzzDecodeTieTrialReceiptNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/calibration -run '^$$' -fuzz '^FuzzDecodeTieReceiptManifestNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/calibration -run '^$$' -fuzz '^FuzzDecodeTiePendingNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/tieexchange -run '^$$' -fuzz '^FuzzReadRequestNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/tieproducer -run '^$$' -fuzz '^FuzzDecodePairNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/tieproducer -run '^$$' -fuzz '^FuzzDecodeCampaignStateNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workchain -run '^$$' -fuzz '^FuzzDecodeNodeMetadataNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workchain -run '^$$' -fuzz '^FuzzDecodePersistedStateNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workchain -run '^$$' -fuzz '^FuzzDecodeStateDeltaNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workchain -run '^$$' -fuzz '^FuzzCanonicalPruneEffect$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workchain -run '^$$' -fuzz '^FuzzDecodeStoragePositionRecord$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeStatementNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeCheckpointNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeArchiveManifestNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeArchiveChunkNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeReplicaReceiptNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeAvailabilityBundleNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeChunkRequestNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeChunkBatchNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzReadObjectSessionFrameNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeCustodyChallengeNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeCustodyProofNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeCustodyRecordNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeCustodyJournalHeaderNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeCustodyJournalEntryNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeCustodyAuditIntent$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeCustodyJournalSlotNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeCustodyCheckpointNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeCustodyBackupPinNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzCustodyReconciliationPendingNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeCustodyHistoricalTransferNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeCustodyHistoricalApplicationNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeCustodyRebaselineProposal$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzDecodeCustodyParticipantRetirement$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/custodyauthority -run '^$$' -fuzz '^FuzzDecodeAuthorityAssignment$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/custodyauthority -run '^$$' -fuzz '^FuzzDecodeAuthorityCommand$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/custodyauthority -run '^$$' -fuzz '^FuzzDecodeAuthorityEntry$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/custodyauthority -run '^$$' -fuzz '^FuzzAuthorityDrainStateMachine$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/custodyauthority -run '^$$' -fuzz '^FuzzRemoteAuthorityCanonical$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/custodyauthority/remoteworker -run '^$$' -fuzz '^FuzzDecodeRemoteWorkerArtifacts$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/custodyauthority/store -run '^$$' -fuzz '^FuzzDecodePruneRequest$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/custodyauthority/store -run '^$$' -fuzz '^FuzzDecodeArchivePruneInventory$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/custodyauthority/store -run '^$$' -fuzz '^FuzzDecodePruneLineageEvidence$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/custodyauthority/store -run '^$$' -fuzz '^FuzzPrunePinTransitions$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/custodyauthority/store -run '^$$' -fuzz '^FuzzDecodePruneCancellation$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/custodyauthority/store -run '^$$' -fuzz '^FuzzDecodeCustodyTerminal$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/custodyauthority/completionwire -run '^$$' -fuzz '^FuzzCompletionFrames$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/custodyauthority/store -run '^$$' -fuzz '^FuzzCompletionOutboxRecords$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/custodyauthority/admissionwire -run '^$$' -fuzz '^FuzzAdmissionFrames$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/custodyauthority/store -run '^$$' -fuzz '^FuzzAdmissionOutboxRecords$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzReadCustodySessionFrameNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./sim/workgraphmodel -run '^$$' -fuzz '^FuzzRunSelfishStrategiesNeverBreakAccounting$$' -fuzztime=$(FUZZTIME)

test-process:
	$(GO) test -tags=integration ./node/custodyauthority/store -run '^TestRemoteCoordinatorProcessCrashBarriers$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./node/custodyauthority/remoteworker -run '^TestWorkerSealingSurvivesKilledOriginalProcess$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./cmd/omd -run '^TestRemoteCustodyGatedServe(Loopback|Control)$$' -count=1 -timeout=90s
	$(GO) test -tags=integration ./cmd/omd -run '^TestProcessCustodyCommand' -count=1 -timeout=2m
	$(GO) test -tags=integration ./node/custodyauthority/store -run '^TestManagedCustodyCommandProcessRecovery$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./cmd/omd -run '^TestProcessManagedCustody(AuditOperator|PairOperator|PairLostResult|Operator)' -count=1 -timeout=2m
	$(GO) test -tags=integration ./cmd/omd -run '^TestProcessManagedCustodyServe' -count=1 -timeout=2m
	$(GO) test -tags=integration ./cmd/omd -run '^(TestProcessPruneArchiveEffect|TestPruneEffectNativeOutput)' -count=1 -timeout=2m
	$(GO) test -tags=integration ./cmd/omd -run '^TestProcessPrunePreparation(RoundTrip|BrokenPipe)$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./cmd/omd -run '^TestProcessPruneSecondarySigning(RoundTrip|BrokenPipe)$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./cmd/omd -run '^TestProcessPruneLineageExtraction(RoundTrip|BrokenPipe)$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./cmd/omd -run '^TestProcessPruneSecondaryCLI(Recovery|BrokenOutput)$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./cmd/omd -run '^TestProcessPrune(CommandCLI(Recovery|BrokenPipe)|MaintenanceCLI(Lifetime|BrokenPipe|Recovery))$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./cmd/omd -run '^TestProcess(QUICRestartSoak|WorkGraphActivationQUICRestart|Archive(ObjectQUICMaterializesAndRecoversAcrossRestart|Custody(QUICSurvivesReplicaRestart|JournalRunsTwoRestartedCycles|(Checkpoint|Backup)RestoresPendingCycle|PinsTrackLatestBackup|ReconciliationKeepsStaleEvidenceReadOnly|RebaselineProposesWithoutCutover))|ControlledTieProducerRecoversWaitingState|TiePair(QUICReachesIndependentV2ObserversAndRecoversAck|CompletionWaitsForCoordinatorEOF)|TieCampaign.*)$$' -count=1 -timeout=10m
	$(GO) test -tags=integration ./node/workchain -run '^Test(Pebble|BoundStorage|PositionStorage)ProcessCrashAtomicity$$' -count=1 -timeout=3m
	$(GO) test -tags=integration ./node/workarchive -run '^Test(ArchiveRestoreProcessCrashAtomicity|AvailabilityPruneProcessCrashAtomicity|Custody(Record|Journal|Backup|Pin|Transfer|Application|Retirement)ProcessCrashAtomicity)$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./node/custodyauthority/store -run '^Test(Authority(Store|Coordinator)|PruneExecutor|PinnedPrune|StorageBoundPrune|PruneCancellation|PruneCompletion(QUIC)?)ProcessCrashAtomicity$$' -count=1 -timeout=5m
	$(GO) test -tags=integration ./node/custodyauthority/store -run '^TestCompletionOutboxProcessCrashAtomicity$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./node/custodyauthority/store -run '^TestPruneAdmissionQUICProcessCrashAtomicity$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./node/custodyauthority/store -run '^TestAdmissionOutboxProcessCrashAtomicity$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./node/custodyauthority/store -run '^TestPrune((CommandRuntime|Maintenance|Recovery|Archive(Lineage)?)ProcessRecovery|InventoryProcessCrashAtomicity)$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./node/custodyauthority/store -run '^TestPrune(PreparedArchiveProcessRecovery|LineageEvidenceProcessCrashAtomicity)$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./node/custodyauthority/store -run '^TestPruneArchiveEffectServiceProcessRecovery$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./node/custodyauthority/store -run '^TestManagedCustodyServeProcessRecovery$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./node/custodyauthority/store -run '^TestManagedCustodyAuditProcessRecovery$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./node/custodyauthority/store -run '^TestArchiveSecondaryAdmissionProcessRecovery$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./node/custodyauthority/store -run '^TestArchiveSecondaryCompletionProcessRecovery$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./node/custodyauthority/store -run '^TestArchiveSecondaryQUICProcessRecovery$$' -count=1 -timeout=2m

test-remote-support:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/remote_acceptance -p 'test_*.py'

test-work-rollover-soak:
	OUTCOMEMESH_WORK_ROLLOVER_SOAK_CYCLES=$(WORKROLLOVERCYCLES) $(GO) test ./cmd/omd -run '^TestMultiNodeWorkRolloverConvergesAcrossClockSkewChurnAndRelayLoss$$' -count=1 -timeout=5m

test-economic-review:
	$(GO) test ./sim/powmodel -count=1
	$(GO) test ./sim/workgraphmodel -run '^TestActivationReviewCorpus$$' -count=1 -v

economic-review:
	@$(GO) run ./cmd/omreview

test-calibration:
	$(GO) test ./cmd/omcalibrate -count=1 -v
	$(GO) test ./node/calibration -count=1 -v
	$(GO) test ./sim/workgraphmodel -run '^(TestHoeffding.*Upper99PPM|TestPublicTestnetCalibration)' -count=1 -v

test-all: fmt vet test-race
