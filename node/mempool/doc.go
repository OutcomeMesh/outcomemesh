// Package mempool implements bounded, deterministic local transaction policy.
// Mempool decisions are not consensus rules; every selected transaction is
// replayed by the consensus execution engine before block construction.
package mempool
