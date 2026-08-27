GO ?= go
FUZZTIME ?= 3s

.PHONY: build fmt vet test test-race test-fuzz-smoke test-process test-all

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
	$(GO) test ./node/workchain -run '^$$' -fuzz '^FuzzDecodeNodeMetadataNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workchain -run '^$$' -fuzz '^FuzzDecodePersistedStateNeverPanics$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./node/workchain -run '^$$' -fuzz '^FuzzDecodeStateDeltaNeverPanics$$' -fuzztime=$(FUZZTIME)

test-process:
	$(GO) test -tags=integration ./cmd/omd -run '^TestProcessQUICRestartSoak$$' -count=1 -timeout=10m
	$(GO) test -tags=integration ./node/workchain -run '^TestPebbleProcessCrashAtomicity$$' -count=1 -timeout=2m

test-all: fmt vet test-race
