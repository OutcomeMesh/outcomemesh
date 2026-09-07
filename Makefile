GO ?= go
FUZZTIME ?= 3s
WORKROLLOVERCYCLES ?= 256

.PHONY: build fmt vet test test-race test-fuzz-smoke test-process test-work-rollover-soak test-economic-review economic-review test-calibration test-all

build:
	$(GO) build -trimpath -o bin/omd ./cmd/omd

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

test-fuzz-smoke:
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
	$(GO) test ./node/custodyauthority/store -run '^$$' -fuzz '^FuzzDecodePruneRequest$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workarchive -run '^$$' -fuzz '^FuzzReadCustodySessionFrameNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./sim/workgraphmodel -run '^$$' -fuzz '^FuzzRunSelfishStrategiesNeverBreakAccounting$$' -fuzztime=$(FUZZTIME)

test-process:
	$(GO) test -tags=integration ./cmd/omd -run '^TestProcess(QUICRestartSoak|WorkGraphActivationQUICRestart|Archive(ObjectQUICMaterializesAndRecoversAcrossRestart|Custody(QUICSurvivesReplicaRestart|JournalRunsTwoRestartedCycles|(Checkpoint|Backup)RestoresPendingCycle|PinsTrackLatestBackup|ReconciliationKeepsStaleEvidenceReadOnly|RebaselineProposesWithoutCutover))|ControlledTieProducerRecoversWaitingState|TiePair(QUICReachesIndependentV2ObserversAndRecoversAck|CompletionWaitsForCoordinatorEOF)|TieCampaign.*)$$' -count=1 -timeout=10m
	$(GO) test -tags=integration ./node/workchain -run '^TestPebbleProcessCrashAtomicity$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./node/workarchive -run '^Test(ArchiveRestoreProcessCrashAtomicity|AvailabilityPruneProcessCrashAtomicity|Custody(Record|Journal|Backup|Pin|Transfer|Application|Retirement)ProcessCrashAtomicity)$$' -count=1 -timeout=2m
	$(GO) test -tags=integration ./node/custodyauthority/store -run '^Test(Authority(Store|Coordinator)|PruneExecutor)ProcessCrashAtomicity$$' -count=1 -timeout=3m

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
