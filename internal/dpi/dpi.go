// Package dpi implements first-packet protocol blocking for NFQUEUE.
package dpi

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/mdlayher/netlink"

	"github.com/mora1n/nwall/internal/conf"
)

// QueueNum is the nft queue number used by nwall.
const QueueNum = 100

const (
	// PendingConnMark marks flows that must keep visiting NFQUEUE until DPI
	// sees enough payload to allow or drop them.
	PendingConnMark uint32 = 0x6e776470
	// AcceptConnMark marks flows that DPI has inspected and allowed.
	AcceptConnMark uint32 = 0x6e77616c
)

// Decision 是 DPI 对单包的判定。
type Decision struct {
	Drop   bool
	Reason string
	Final  bool
}

// InspectPacket 检查完整 IP packet，并返回是否应 drop。
func InspectPacket(packet []byte, cfg conf.Protect) Decision {
	payload, ok := tcpPayload(packet)
	if !ok {
		return Decision{Final: true}
	}
	if len(payload) == 0 {
		return Decision{}
	}
	switch {
	case cfg.BlockHTTP && isHTTP(payload):
		return Decision{Drop: true, Reason: "http", Final: true}
	case cfg.BlockTLS && isTLSClientHello(payload):
		return Decision{Drop: true, Reason: "tls", Final: true}
	case cfg.BlockSOCKS && isSOCKS(payload):
		return Decision{Drop: true, Reason: "socks", Final: true}
	default:
		return Decision{Final: true}
	}
}

// Run attaches to NFQUEUE and applies verdicts until ctx is cancelled.
func Run(ctx context.Context, cfg conf.Protect) error {
	nfq, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      QueueNum,
		MaxPacketLen: 0xffff,
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		return fmt.Errorf("打开 NFQUEUE 失败: %w", err)
	}
	defer nfq.Close()
	if err := nfq.SetOption(netlink.NoENOBUFS, true); err != nil {
		return fmt.Errorf("设置 NFQUEUE socket option 失败: %w", err)
	}
	fn := func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		verdict := nfqueue.NfAccept
		decision := Decision{Final: true}
		if a.Payload != nil {
			decision = InspectPacket(*a.Payload, cfg)
			if decision.Drop {
				verdict = nfqueue.NfDrop
				log.Printf("dpi drop reason=%s", decision.Reason)
			}
		}
		var err error
		if verdict == nfqueue.NfAccept && decision.Final {
			err = nfq.SetVerdictWithOption(*a.PacketID, verdict, nfqueue.WithConnMark(AcceptConnMark))
		} else {
			err = nfq.SetVerdict(*a.PacketID, verdict)
		}
		if err != nil {
			log.Printf("dpi verdict failed: %v", err)
			return 1
		}
		return 0
	}
	errfn := func(err error) int {
		log.Printf("dpi receive error: %v", err)
		return 1
	}
	if err := nfq.RegisterWithErrorFunc(ctx, fn, errfn); err != nil {
		return fmt.Errorf("注册 NFQUEUE 回调失败: %w", err)
	}
	<-ctx.Done()
	return nil
}

func tcpPayload(packet []byte) ([]byte, bool) {
	if len(packet) < 1 {
		return nil, false
	}
	version := packet[0] >> 4
	switch version {
	case 4:
		return tcpPayloadIPv4(packet)
	case 6:
		return tcpPayloadIPv6(packet)
	default:
		return nil, false
	}
}

func tcpPayloadIPv4(packet []byte) ([]byte, bool) {
	if len(packet) < 20 {
		return nil, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+20 || packet[9] != 6 {
		return nil, false
	}
	return tcpPayloadFromSegment(packet[ihl:])
}

func tcpPayloadIPv6(packet []byte) ([]byte, bool) {
	if len(packet) < 60 || packet[6] != 6 {
		return nil, false
	}
	return tcpPayloadFromSegment(packet[40:])
}

func tcpPayloadFromSegment(segment []byte) ([]byte, bool) {
	if len(segment) < 20 {
		return nil, false
	}
	offset := int(segment[12]>>4) * 4
	if offset < 20 || len(segment) < offset {
		return nil, false
	}
	return segment[offset:], true
}

func isHTTP(payload []byte) bool {
	text := strings.ToUpper(string(payload[:min(len(payload), 8)]))
	methods := []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}
	for _, method := range methods {
		if strings.HasPrefix(text, method) {
			return true
		}
	}
	return strings.HasPrefix(text, "HTTP/")
}

func isTLSClientHello(payload []byte) bool {
	if len(payload) < 6 {
		return false
	}
	if payload[0] != 0x16 || payload[1] != 0x03 {
		return false
	}
	return payload[5] == 0x01
}

func isSOCKS(payload []byte) bool {
	if len(payload) < 2 {
		return false
	}
	if payload[0] == 0x05 && payload[1] > 0 && len(payload) >= int(2+payload[1]) {
		return true
	}
	return payload[0] == 0x04 && len(payload) >= 9
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
