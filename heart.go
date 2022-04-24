package main

import (
	"bytes"
	"io"
	"net"
	"time"
)

var (
	HEART_BEAT_1 = []byte{0x03, 0x0d, 0x77, 0x77, 0x77, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x50, 0x80}
	HEART_BEAT_2 = []byte{0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x77, 0x77, 0x77, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x63, 0x75, 0x72, 0x6c, 0x2f, 0x37, 0x2e, 0x34, 0x33, 0x2e, 0x30, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 0x0d, 0x0a}
)

func HeartBeat(server, token string, done chan<- bool) {
	buf := make([]byte, 0, 192)
	b := bytes.NewBuffer(buf)
	b.Write(HEART_BEAT_1)
	b.WriteByte(byte(len(token)))
	b.Write([]byte(token))
	b.Write(HEART_BEAT_2)

	recvbuf := make([]byte, 64)
	tick := time.Tick(10 * time.Second)
	dialer := net.Dialer{
		Timeout: 4 * time.Second,
	}
	for {
		func() {
			rc, err := dialer.Dial("tcp", server)
			if err != nil {
				logf("heartbeat failed to connect to server %v: %v", server, err)
				if done != nil {
					done <- false
				}
				return
			}
			defer rc.Close()
			if _, err = rc.Write(b.Bytes()); err != nil {
				logf("failed to send heartbeat: %v", err)
				if done != nil {
					done <- false
				}
				return
			}
			rc.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err = io.ReadAtLeast(rc, recvbuf, 64); err != nil {
				logf("failed to get heartbeat echoback: %v", err)
				if done != nil {
					done <- false
					done = nil
				}
			} else {
				logf("heartbeat succeed")
				if done != nil {
					done <- true
					done = nil
				}
			}
		}()
		<-tick
	}
}
