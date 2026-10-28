//go:build !linux

package gatewayclient

import (
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	"net"
)

func Supported() bool                       { return false }
func PeerUID(*net.UnixConn) (uint32, error) { return 0, wire.ErrAccess }
