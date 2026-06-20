//go:build linux
// +build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type EventType uint32

const (
	EventHTTP500 EventType = 1
	EventTCPConn EventType = 2
)

type EventHeader struct {
	Type EventType
}

type HTTPEvent struct {
	Header  EventHeader
	PID     uint32
	TGID    uint32
	Snippet [32]byte
}

type ConnEvent struct {
	Header EventHeader
	PID    uint32
	TGID   uint32
	DAddr  uint32
	DPort  uint16
	Pad    uint16
}

type Callbacks struct {
	OnHTTP500 func(pid uint32, snippet string)
	OnTCPConn func(pid uint32, destIP string, destPort uint16)
}

func StartAgent(cb Callbacks) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return err
	}

	lWrite, err := link.Tracepoint("syscalls", "sys_enter_write", objs.HandleSysWrite, nil)
	if err != nil {
		objs.Close()
		return fmt.Errorf("trace sys_enter_write: %v", err)
	}

	lConn, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.HandleSysConnect, nil)
	if err != nil {
		lWrite.Close()
		objs.Close()
		return fmt.Errorf("trace sys_enter_connect: %v", err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		lConn.Close()
		lWrite.Close()
		objs.Close()
		return err
	}

	log.Println("[ebpf] Agent started, capturing HTTP 500s and Network Connections...")

	go func() {
		defer lWrite.Close()
		defer lConn.Close()
		defer objs.Close()
		defer rd.Close()

		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}

			var hdr EventHeader
			buf := bytes.NewBuffer(record.RawSample)
			if err := binary.Read(buf, binary.LittleEndian, &hdr); err != nil {
				continue
			}

			// Rewind buffer
			buf = bytes.NewBuffer(record.RawSample)

			if hdr.Type == EventHTTP500 {
				var ev HTTPEvent
				if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
					continue
				}
				idx := bytes.IndexByte(ev.Snippet[:], 0)
				var snippetStr string
				if idx == -1 {
					snippetStr = string(ev.Snippet[:])
				} else {
					snippetStr = string(ev.Snippet[:idx])
				}
				if cb.OnHTTP500 != nil {
					cb.OnHTTP500(ev.PID, snippetStr)
				}
			} else if hdr.Type == EventTCPConn {
				var ev ConnEvent
				if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
					continue
				}
				
				// Decode IP
				ipBytes := make([]byte, 4)
				binary.LittleEndian.PutUint32(ipBytes, ev.DAddr)
				destIP := net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]).String()
				
				// Decode Port (it's in network byte order big endian)
				portBytes := make([]byte, 2)
				binary.LittleEndian.PutUint16(portBytes, ev.DPort)
				destPort := binary.BigEndian.Uint16(portBytes)
				
				if cb.OnTCPConn != nil {
					cb.OnTCPConn(ev.PID, destIP, destPort)
				}
			}
		}
	}()

	return nil
}
