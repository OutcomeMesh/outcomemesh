//go:build !linux && !darwin

package main

import "errors"

const (
	custodyGuardCommand          = "work-archive-custody-guard"
	custodyGuardRevokeCommand    = "work-archive-custody-guard-revoke"
	custodyGuardReplaceCommand   = "work-archive-custody-guard-replace"
	custodyGatewayCommand        = "work-archive-custody-gateway"
	custodyGatewayReplaceCommand = "work-archive-custody-gateway-replace"
	custodyProfile5Command       = "work-archive-custody-profile5"
)

var errCustodyServerPlatform = errors.New("this custody server command requires the Unix storage and process-isolation backend; use a supported Linux server")

// Refuse before parsing paths, loading secrets or creating any owner state.
func runCustodyGuardCLI([]string) error          { return errCustodyServerPlatform }
func runCustodyGuardRevokeCLI([]string) error    { return errCustodyServerPlatform }
func runCustodyGuardReplaceCLI([]string) error   { return errCustodyServerPlatform }
func runCustodyGatewayCLI([]string) error        { return errCustodyServerPlatform }
func runCustodyGatewayReplaceCLI([]string) error { return errCustodyServerPlatform }
func runCustodyProfile5CLI([]string) error       { return errCustodyServerPlatform }
