package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	testKey = key
	os.Exit(m.Run())
}

func TestAndroidPublicKey(t *testing.T) {
	raw, err := encodeAndroidPublicKey(&testKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 524 {
		t.Fatalf("encoded key length %d", len(raw))
	}
	if binary.LittleEndian.Uint32(raw[0:]) != 64 {
		t.Fatalf("modulus words %d", binary.LittleEndian.Uint32(raw[0:]))
	}
	n0 := testKey.N.Uint64() & 0xffffffff
	inv := uint64(binary.LittleEndian.Uint32(raw[4:]))
	if n0*inv&0xffffffff != 0xffffffff {
		t.Fatalf("n0inv mismatch n0=%x inv=%x", n0, inv)
	}
	if binary.LittleEndian.Uint32(raw[520:]) != uint32(testKey.E) {
		t.Fatalf("exponent %d", binary.LittleEndian.Uint32(raw[520:]))
	}
	pub, err := androidPublicKey(&testKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(pub, []byte(" debug-mcp@")) || pub[len(pub)-1] != 0 {
		t.Fatalf("public key text %q", pub)
	}
}

func TestSignTokenIsNotHashedAgain(t *testing.T) {
	token := bytes.Repeat([]byte{0x5a}, 20)
	sig, err := signToken(testKey, token)
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA1, token, sig); err != nil {
		t.Fatal(err)
	}
	sum := sha1.Sum(token)
	if rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA1, sum[:], sig) == nil {
		t.Fatal("token was hashed before signing")
	}
}

func TestPacketRoundTrip(t *testing.T) {
	payload := []byte{0x00, 0xff, '\r', '\n'}
	var buf bytes.Buffer
	if err := writeUSBPacket(&buf, cmdWRTE, 1, 2, payload); err != nil {
		t.Fatal(err)
	}
	cmd, a0, a1, data, err := readUSBPacket(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if cmd != cmdWRTE || a0 != 1 || a1 != 2 || !bytes.Equal(data, payload) {
		t.Fatalf("got cmd=%08x %d %d %x", cmd, a0, a1, data)
	}
}

func TestHandshakeAndShellPreservesBytes(t *testing.T) {
	link, device := connectedPair(t, false)
	payload := []byte("hi\r\n\x00\xff")
	errCh := make(chan error, 1)
	go func() {
		errCh <- serveBytes(device, "shell:echo", payload)
	}()
	out, err := link.readService("shell:echo")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("payload changed: %x", out)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeSendsPublicKeyWhenSignatureIsRejected(t *testing.T) {
	client, device := net.Pipe()
	defer client.Close()
	defer device.Close()
	deadline := time.Now().Add(5 * time.Second)
	client.SetDeadline(deadline)
	device.SetDeadline(deadline)
	errCh := make(chan error, 1)
	go func() {
		errCh <- finishHandshake(device, true)
	}()
	if _, err := handshake(client, "pixel"); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestSyncPushPull(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "note.txt")
	body := []byte("abc\r\n\x00")
	if err := os.WriteFile(local, body, 0o644); err != nil {
		t.Fatal(err)
	}

	link, device := connectedPair(t, false)
	got := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		data, err := servePush(device)
		got <- data
		errCh <- err
	}()
	if err := link.push(local, "/sdcard/"); err != nil {
		t.Fatal(err)
	}
	pushed := <-got
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pushed, body) {
		t.Fatalf("pushed %x", pushed)
	}

	link, device = connectedPair(t, false)
	errCh = make(chan error, 1)
	go func() {
		errCh <- servePull(device, "/sdcard/note.txt", body)
	}()
	dest := filepath.Join(dir, "out.txt")
	if err := link.pull("/sdcard/note.txt", dest); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	read, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read, body) {
		t.Fatalf("pulled %x", read)
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

func TestSourcesDoNotUseHostADB(t *testing.T) {
	for _, name := range []string{"debug-mcp.go", "adb_proto.go", "usb_linux.go", "usb_windows.go", "usb_other.go", "usb_errno.go"} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, bad := range []string{"5037", "gadb", "exec.Command", "start-server", "NewClient"} {
			if strings.Contains(s, bad) {
				t.Fatalf("%s contains %s", name, bad)
			}
		}
	}
}

func connectedPair(t *testing.T, rejectSig bool) (*usbLink, net.Conn) {
	t.Helper()
	client, device := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		device.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	client.SetDeadline(deadline)
	device.SetDeadline(deadline)
	errCh := make(chan error, 1)
	go func() {
		errCh <- finishHandshake(device, rejectSig)
	}()
	link, err := handshake(client, "39251FDJG004W4")
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	return link, device
}

func finishHandshake(conn net.Conn, rejectSig bool) error {
	cmd, _, _, _, err := readUSBPacket(conn)
	if err != nil {
		return err
	}
	if cmd != cmdCNXN {
		return errCmd(cmd)
	}
	token := bytes.Repeat([]byte{0x5a}, 20)
	if err := writeUSBPacket(conn, cmdAUTH, authToken, 0, token); err != nil {
		return err
	}
	cmd, arg0, _, data, err := readUSBPacket(conn)
	if err != nil {
		return err
	}
	if cmd != cmdAUTH || arg0 != authSignature {
		return errCmd(cmd)
	}
	if err := rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA1, token, data); err != nil {
		return err
	}
	if rejectSig {
		if err := writeUSBPacket(conn, cmdAUTH, authToken, 0, token); err != nil {
			return err
		}
		cmd, arg0, _, data, err = readUSBPacket(conn)
		if err != nil {
			return err
		}
		if cmd != cmdAUTH || arg0 != authRSAPUBKEY {
			return errCmd(cmd)
		}
		if !bytes.Contains(data, []byte(" debug-mcp@")) || data[len(data)-1] != 0 {
			return errCmd(cmd)
		}
	}
	return writeUSBPacket(conn, cmdCNXN, adbVersion, 64*1024, []byte("device::\x00"))
}

func serveBytes(conn net.Conn, service string, payload []byte) error {
	d := &devSide{conn: conn}
	got, err := d.accept()
	if err != nil {
		return err
	}
	if got != service {
		return errCmd(0)
	}
	if err := d.write(payload); err != nil {
		return err
	}
	if err := writeUSBPacket(conn, cmdCLSE, d.local, d.remote, nil); err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, d)
	return err
}

func servePush(conn net.Conn) ([]byte, error) {
	d := &devSide{conn: conn}
	got, err := d.accept()
	if err != nil {
		return nil, err
	}
	if got != "sync:" {
		return nil, errCmd(0)
	}
	var file bytes.Buffer
	for {
		id, data, err := readSync(d)
		if err != nil {
			return nil, err
		}
		switch id {
		case "SEND":
			if !bytes.Contains(data, []byte("/sdcard/note.txt,")) {
				return nil, errCmd(0)
			}
		case "DATA":
			file.Write(data)
		case "DONE":
			if err := writeSync(d, "OKAY", nil); err != nil {
				return nil, err
			}
			_, err := io.Copy(io.Discard, d)
			return file.Bytes(), err
		default:
			return nil, errCmd(0)
		}
	}
}

func servePull(conn net.Conn, remote string, body []byte) error {
	d := &devSide{conn: conn}
	got, err := d.accept()
	if err != nil {
		return err
	}
	if got != "sync:" {
		return errCmd(0)
	}
	id, data, err := readSync(d)
	if err != nil {
		return err
	}
	if id != "RECV" || string(data) != remote {
		return errCmd(0)
	}
	if err := writeSync(d, "DATA", body); err != nil {
		return err
	}
	var done [4]byte
	if err := writeSync(d, "DONE", done[:]); err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, d)
	return err
}

func readSync(r io.Reader) (string, []byte, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[4:])
	data := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, data); err != nil {
			return "", nil, err
		}
	}
	return string(hdr[:4]), data, nil
}

type devSide struct {
	conn          net.Conn
	buf           []byte
	local, remote uint32
}

func (d *devSide) accept() (string, error) {
	cmd, arg0, _, data, err := readUSBPacket(d.conn)
	if err != nil {
		return "", err
	}
	if cmd != cmdOPEN {
		return "", errCmd(cmd)
	}
	d.remote = arg0
	d.local = 1
	if err := writeUSBPacket(d.conn, cmdOKAY, d.local, d.remote, nil); err != nil {
		return "", err
	}
	return strings.TrimRight(string(data), "\x00"), nil
}

func (d *devSide) Read(p []byte) (int, error) {
	for len(d.buf) == 0 {
		cmd, arg0, _, data, err := readUSBPacket(d.conn)
		if err != nil {
			return 0, err
		}
		switch cmd {
		case cmdWRTE:
			if err := writeUSBPacket(d.conn, cmdOKAY, d.local, arg0, nil); err != nil {
				return 0, err
			}
			d.buf = append(d.buf, data...)
		case cmdCLSE:
			return 0, io.EOF
		default:
			return 0, errCmd(cmd)
		}
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}

func (d *devSide) Write(p []byte) (int, error) {
	return len(p), d.write(p)
}

func (d *devSide) write(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	if err := writeUSBPacket(d.conn, cmdWRTE, d.local, d.remote, p); err != nil {
		return err
	}
	cmd, _, _, _, err := readUSBPacket(d.conn)
	if err != nil {
		return err
	}
	if cmd != cmdOKAY {
		return errCmd(cmd)
	}
	return nil
}

type cmdErr uint32

func errCmd(cmd uint32) error { return cmdErr(cmd) }

func (e cmdErr) Error() string { return "unexpected packet" }
