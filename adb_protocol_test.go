package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAdbExecOutPreservesBinary(t *testing.T) {
	payload := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x00, 0xff}
	withFakeADB(t, func(serial, service string, conn net.Conn) {
		if serial != "dev-1" || service != "exec:screencap -p" {
			writeADBFail(conn, "unexpected "+serial+" "+service)
			return
		}
		conn.Write([]byte("OKAY"))
		conn.Write(payload)
	})

	got, err := adbExecOut("dev-1", "screencap -p")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload changed: got %x", got)
	}
}

func TestAdbExecOutErrorsWhenBodyTimesOut(t *testing.T) {
	previous := adbScreenshotDeadline
	adbScreenshotDeadline = 80 * time.Millisecond
	t.Cleanup(func() { adbScreenshotDeadline = previous })

	withFakeADB(t, func(serial, service string, conn net.Conn) {
		conn.Write([]byte("OKAY"))
		conn.Write([]byte{0x89, 'P'})
		time.Sleep(2 * time.Second)
	})

	if _, err := adbExecOut("dev-1", "screencap -p"); err == nil {
		t.Fatal("expected a read error when the PNG stream stalls")
	}
}

func TestAdbHostCommandFailStatus(t *testing.T) {
	withFakeADB(t, func(serial, service string, conn net.Conn) {
		writeADBFail(conn, "device offline")
	})

	_, err := adbHostCommand("missing", "root:")
	if err == nil || !strings.Contains(err.Error(), "device offline") {
		t.Fatalf("got %v", err)
	}
}

func TestAdbHostCommandBestEffortWhenConnectionStaysOpen(t *testing.T) {
	previous := adbCommandDeadline
	adbCommandDeadline = 80 * time.Millisecond
	t.Cleanup(func() { adbCommandDeadline = previous })

	withFakeADB(t, func(serial, service string, conn net.Conn) {
		if service != "root:" {
			writeADBFail(conn, "unexpected "+service)
			return
		}
		conn.Write([]byte("OKAY"))
		conn.Write([]byte("restarting adbd as root\n"))
		time.Sleep(2 * time.Second)
	})

	start := time.Now()
	text, err := adbHostCommand("dev-1", "root:")
	if err != nil {
		t.Fatal(err)
	}
	if text != "restarting adbd as root" {
		t.Fatalf("text %q", text)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("blocked until peer close: %s", time.Since(start))
	}
}

func TestRootResult(t *testing.T) {
	previous := adbRootRestartWait
	t.Cleanup(func() { adbRootRestartWait = previous })

	_, err := rootResult(context.Background(), "adbd cannot run as root in production builds\n")
	if err == nil || !strings.Contains(err.Error(), "cannot run as root") {
		t.Fatalf("got %v", err)
	}

	adbRootRestartWait = 2 * time.Second
	start := time.Now()
	text, err := rootResult(context.Background(), "adbd is already running as root\n")
	if err != nil {
		t.Fatal(err)
	}
	if text != "adbd is already running as root" {
		t.Fatalf("text %q", text)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatalf("already-root waited %s", time.Since(start))
	}

	adbRootRestartWait = 80 * time.Millisecond
	start = time.Now()
	text, err = rootResult(context.Background(), "restarting adbd as root\n")
	if err != nil {
		t.Fatal(err)
	}
	if text != "restarting adbd as root" {
		t.Fatalf("text %q", text)
	}
	if time.Since(start) < 50*time.Millisecond {
		t.Fatalf("restart returned too soon: %s", time.Since(start))
	}
}

func withFakeADB(t *testing.T, onService func(serial, service string, conn net.Conn)) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	previous := adbServerAddr
	adbServerAddr = ln.Addr().String()
	t.Cleanup(func() { adbServerAddr = previous })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				cmd, err := readADBPacket(conn)
				if err != nil || !strings.HasPrefix(cmd, "host:transport:") {
					writeADBFail(conn, "bad transport")
					return
				}
				if _, err := conn.Write([]byte("OKAY")); err != nil {
					return
				}
				service, err := readADBPacket(conn)
				if err != nil {
					return
				}
				onService(strings.TrimPrefix(cmd, "host:transport:"), service, conn)
			}(conn)
		}
	}()
}

func readADBPacket(conn net.Conn) (string, error) {
	head, err := readExact(conn, 4)
	if err != nil {
		return "", err
	}
	n, err := strconv.ParseUint(string(head), 16, 16)
	if err != nil {
		return "", err
	}
	body, err := readExact(conn, int(n))
	return string(body), err
}

func writeADBFail(conn net.Conn, message string) {
	fmt.Fprintf(conn, "FAIL%04x%s", len(message), message)
}
