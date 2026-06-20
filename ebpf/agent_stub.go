//go:build !linux
// +build !linux

package ebpf

import (
	"errors"
)

type Callbacks struct {
	OnHTTP500 func(pid uint32, snippet string)
	OnTCPConn func(pid uint32, destIP string, destPort uint16)
}

func StartAgent(cb Callbacks) error {
	return errors.New("eBPF agent is only supported on Linux")
}
