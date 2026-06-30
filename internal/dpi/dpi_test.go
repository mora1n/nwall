package dpi

import (
	"testing"

	"github.com/mora1n/nwall/internal/conf"
)

func TestInspectPacketProtocols(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		cfg     conf.Protect
		reason  string
	}{
		{name: "http", payload: []byte("GET / HTTP/1.1\r\n"), cfg: conf.Protect{BlockHTTP: true}, reason: "http"},
		{name: "tls", payload: []byte{0x16, 0x03, 0x03, 0x00, 0x2a, 0x01}, cfg: conf.Protect{BlockTLS: true}, reason: "tls"},
		{name: "socks5", payload: []byte{0x05, 0x01, 0x00}, cfg: conf.Protect{BlockSOCKS: true}, reason: "socks"},
		{name: "unknown_accept", payload: []byte("SSH-2.0"), cfg: conf.Protect{BlockHTTP: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision := InspectPacket(ipv4TCPPacket(tc.payload), tc.cfg)
			if tc.reason == "" {
				if decision.Drop {
					t.Fatalf("unexpected drop: %+v", decision)
				}
				return
			}
			if !decision.Drop || decision.Reason != tc.reason {
				t.Fatalf("decision=%+v want drop reason=%s", decision, tc.reason)
			}
		})
	}
}

func TestInspectPacketWaitsForPayload(t *testing.T) {
	decision := InspectPacket(ipv4TCPPacket(nil), conf.Protect{BlockHTTP: true})
	if decision.Drop || decision.Final {
		t.Fatalf("无 payload 的 TCP 包不应终结 DPI 判定: %+v", decision)
	}
}

func ipv4TCPPacket(payload []byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 6
	tcp := make([]byte, 20)
	tcp[12] = 0x50
	return append(append(ip, tcp...), payload...)
}
