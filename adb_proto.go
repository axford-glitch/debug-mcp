package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Device-side USB debugging protocol. Packets go straight to the phone.
// The host adb program and its TCP service are not used.

const (
	cmdCNXN = 0x4e584e43
	cmdOPEN = 0x4e45504f
	cmdOKAY = 0x59414b4f
	cmdCLSE = 0x45534c43
	cmdWRTE = 0x45545257
	cmdAUTH = 0x48545541

	authToken     = 1
	authSignature = 2
	authRSAPUBKEY = 3

	adbVersion = 0x01000001
	maxPayload = 256 * 1024

	usbAuthWait = 60 * time.Second
)

type adbTransport interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}

type usbCandidate struct {
	serial string
	open   func() (adbTransport, string, error)
}

type usbLink struct {
	t         adbTransport
	serial    string
	peerMax   uint32
	nextLocal uint32
}

type usbStream struct {
	l      *usbLink
	local  uint32
	remote uint32
	buf    []byte
	eof    bool
	closed bool
}

var (
	phoneMu sync.Mutex
	phone   *usbLink

	keyOnce   sync.Once
	adbKey    *rsa.PrivateKey
	adbKeyErr error

	// testKey, when set, skips reading or creating a key file.
	testKey *rsa.PrivateKey
)

func deviceKey() (*rsa.PrivateKey, error) {
	if testKey != nil {
		return testKey, nil
	}
	keyOnce.Do(func() {
		adbKey, adbKeyErr = loadOrCreateADBKey()
	})
	return adbKey, adbKeyErr
}

func adbKeyPaths() []string {
	var paths []string
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".android", "adbkey"))
	}
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(exe), "adbkey"))
	}
	paths = append(paths, "adbkey")
	return paths
}

func loadOrCreateADBKey() (*rsa.PrivateKey, error) {
	for _, path := range adbKeyPaths() {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		key, err := parseADBKey(b)
		if err != nil {
			continue
		}
		if _, err := encodeAndroidPublicKey(&key.PublicKey); err != nil {
			continue
		}
		return key, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("生成 USB 调试密钥失败: %w", err)
	}
	if err := saveADBKey(key); err != nil {
		debugLogf("save usb debug key: %v\n", err)
	}
	return key, nil
}

func parseADBKey(b []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("密钥不是 PEM")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("密钥不是 RSA")
		}
		return rk, nil
	default:
		return nil, fmt.Errorf("不支持的密钥类型 %s", block.Type)
	}
}

func saveADBKey(key *rsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	var paths []string
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(exe), "adbkey"))
	}
	paths = append(paths, "adbkey")
	var last error
	for _, path := range paths {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			last = err
			continue
		}
		pub, err := androidPublicKey(&key.PublicKey)
		if err == nil {
			_ = os.WriteFile(path+".pub", bytes.TrimRight(pub, "\x00"), 0o644)
		}
		return nil
	}
	return last
}

// encodeAndroidPublicKey builds the 524-byte mincrypt RSAPublicKey that
// adbd shows on the USB debugging authorization dialog.
func encodeAndroidPublicKey(key *rsa.PublicKey) ([]byte, error) {
	if key.N.BitLen() > 2048 || key.E <= 0 {
		return nil, fmt.Errorf("USB 调试密钥必须是 2048 位 RSA")
	}
	buf := make([]byte, 4+4+256+256+4)
	binary.LittleEndian.PutUint32(buf[0:], 64) // modulus words
	binary.LittleEndian.PutUint32(buf[4:], n0inv(key.N))
	putLE(buf[8:8+256], key.N)
	putLE(buf[8+256:8+512], rr(key.N))
	binary.LittleEndian.PutUint32(buf[8+512:], uint32(key.E))
	return buf, nil
}

func n0inv(n *big.Int) uint32 {
	mod := new(big.Int).Lsh(big.NewInt(1), 32)
	n0 := new(big.Int).Mod(new(big.Int).Set(n), mod)
	inv := new(big.Int).ModInverse(n0, mod)
	if inv == nil {
		return 0
	}
	return uint32(new(big.Int).Sub(mod, inv).Uint64())
}

func rr(n *big.Int) *big.Int {
	r := new(big.Int).Lsh(big.NewInt(1), 2048)
	r2 := new(big.Int).Mul(r, r)
	return r2.Mod(r2, n)
}

func putLE(dst []byte, x *big.Int) {
	b := x.Bytes()
	for i := 0; i < len(b) && i < len(dst); i++ {
		dst[i] = b[len(b)-1-i]
	}
}

func androidPublicKey(key *rsa.PublicKey) ([]byte, error) {
	raw, err := encodeAndroidPublicKey(key)
	if err != nil {
		return nil, err
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localhost"
	}
	body := base64.StdEncoding.EncodeToString(raw) + " debug-mcp@" + host
	return append([]byte(body), 0), nil
}

// signToken matches adbd: the 20-byte token is itself the SHA-1 digest
// that RSA_sign wraps. Hashing it again makes the phone reject the key.
func signToken(key *rsa.PrivateKey, token []byte) ([]byte, error) {
	if len(token) != sha1.Size {
		return nil, fmt.Errorf("USB 调试令牌长度异常: %d", len(token))
	}
	return rsa.SignPKCS1v15(nil, key, crypto.SHA1, token)
}

func checksum(data []byte) uint32 {
	var sum uint32
	for _, b := range data {
		sum += uint32(b)
	}
	return sum
}

func writeUSBPacket(w io.Writer, cmd, arg0, arg1 uint32, data []byte) error {
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:], cmd)
	binary.LittleEndian.PutUint32(hdr[4:], arg0)
	binary.LittleEndian.PutUint32(hdr[8:], arg1)
	binary.LittleEndian.PutUint32(hdr[12:], uint32(len(data)))
	binary.LittleEndian.PutUint32(hdr[16:], checksum(data))
	binary.LittleEndian.PutUint32(hdr[20:], cmd^0xffffffff)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	_, err := w.Write(data)
	return err
}

func readUSBPacket(r io.Reader) (cmd, arg0, arg1 uint32, data []byte, err error) {
	var hdr [24]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	cmd = binary.LittleEndian.Uint32(hdr[0:])
	arg0 = binary.LittleEndian.Uint32(hdr[4:])
	arg1 = binary.LittleEndian.Uint32(hdr[8:])
	n := binary.LittleEndian.Uint32(hdr[12:])
	sum := binary.LittleEndian.Uint32(hdr[16:])
	magic := binary.LittleEndian.Uint32(hdr[20:])
	if magic != cmd^0xffffffff {
		err = fmt.Errorf("USB 调试数据包头无效")
		return
	}
	if n > 1024*1024 {
		err = fmt.Errorf("USB 调试数据包过大")
		return
	}
	if n == 0 {
		if sum != 0 {
			err = fmt.Errorf("USB 调试数据校验失败")
		}
		return
	}
	data = make([]byte, n)
	if _, err = io.ReadFull(r, data); err != nil {
		return
	}
	if checksum(data) != sum {
		err = fmt.Errorf("USB 调试数据校验失败")
	}
	return
}

func (l *usbLink) writePacket(cmd, arg0, arg1 uint32, data []byte) error {
	if err := writeUSBPacket(l.t, cmd, arg0, arg1, data); err != nil {
		return fmt.Errorf("写入 USB 失败: %w", err)
	}
	return nil
}

func (l *usbLink) readPacket() (cmd, arg0, arg1 uint32, data []byte, err error) {
	cmd, arg0, arg1, data, err = readUSBPacket(l.t)
	if err != nil {
		err = fmt.Errorf("读取 USB 失败: %w", err)
	}
	return
}

func (l *usbLink) Close() error {
	if l == nil || l.t == nil {
		return nil
	}
	err := l.t.Close()
	l.t = nil
	return err
}

func handshake(t adbTransport, serial string) (*usbLink, error) {
	key, err := deviceKey()
	if err != nil {
		return nil, err
	}
	l := &usbLink{t: t, serial: serial, peerMax: 4096}
	if err := l.writePacket(cmdCNXN, adbVersion, maxPayload, []byte("host::\x00")); err != nil {
		return nil, err
	}
	signed := false
	sentKey := false
	for {
		cmd, arg0, arg1, data, err := l.readPacket()
		if err != nil {
			if sentKey {
				return nil, fmt.Errorf("设备要求确认 USB 调试授权，请在手机上点允许后重试: %w", err)
			}
			return nil, fmt.Errorf("设备没有完成 USB 调试握手: %w", err)
		}
		switch cmd {
		case cmdCNXN:
			if arg1 > 0 {
				l.peerMax = arg1
			}
			if l.peerMax > maxPayload {
				l.peerMax = maxPayload
			}
			return l, nil
		case cmdAUTH:
			if arg0 != authToken {
				return nil, fmt.Errorf("不支持的 USB 调试认证类型 %d", arg0)
			}
			if !signed {
				sig, err := signToken(key, data)
				if err != nil {
					return nil, err
				}
				if err := l.writePacket(cmdAUTH, authSignature, 0, sig); err != nil {
					return nil, err
				}
				signed = true
				continue
			}
			if !sentKey {
				pub, err := androidPublicKey(&key.PublicKey)
				if err != nil {
					return nil, err
				}
				if err := l.writePacket(cmdAUTH, authRSAPUBKEY, 0, pub); err != nil {
					return nil, err
				}
				sentKey = true
				continue
			}
			return nil, fmt.Errorf("设备拒绝了 USB 调试密钥")
		default:
			return nil, fmt.Errorf("握手时收到意外消息 %08x", cmd)
		}
	}
}

func connectUSB(want string) (*usbLink, error) {
	cands, err := listUSBDevices()
	if err != nil {
		return nil, err
	}
	debugLogf("usb candidates=%d\n", len(cands))
	want = strings.TrimSpace(want)
	if len(cands) == 0 {
		return nil, fmt.Errorf("没有找到 USB 上的 Android 设备。请确认手机已连接并打开了 USB 调试")
	}
	var firstErr error
	for _, cand := range cands {
		if want != "" && cand.serial != "" && cand.serial != want {
			continue
		}
		t, serial, err := cand.open()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if serial == "" {
			serial = cand.serial
		}
		if want != "" && serial != "" && serial != want {
			t.Close()
			continue
		}
		if err := t.SetDeadline(time.Now().Add(usbAuthWait)); err != nil {
			t.Close()
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		link, err := handshake(t, serial)
		if err != nil {
			t.Close()
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		debugLogf("usb connected serial=%s\n", link.serial)
		return link, nil
	}
	if want != "" && firstErr == nil {
		return nil, fmt.Errorf("未找到序列号为 %s 的 USB 设备", want)
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, fmt.Errorf("没有找到 USB 上的 Android 设备。请确认手机已连接并打开了 USB 调试")
}

func closePhone() {
	phoneMu.Lock()
	defer phoneMu.Unlock()
	if phone != nil {
		phone.Close()
		phone = nil
	}
}

func withPhone(serial string, deadline time.Duration, fn func(*usbLink) ([]byte, error)) ([]byte, error) {
	phoneMu.Lock()
	defer phoneMu.Unlock()
	serial = strings.TrimSpace(serial)
	if phone != nil && serial != "" && phone.serial != "" && phone.serial != serial {
		phone.Close()
		phone = nil
	}
	if phone == nil {
		link, err := connectUSB(serial)
		if err != nil {
			return nil, err
		}
		phone = link
	}
	if deadline <= 0 {
		deadline = 2 * time.Minute
	}
	if err := phone.t.SetDeadline(time.Now().Add(deadline)); err != nil {
		phone.Close()
		phone = nil
		return nil, err
	}
	out, err := fn(phone)
	if err != nil {
		phone.Close()
		phone = nil
	}
	return out, err
}

func (l *usbLink) open(service string) (*usbStream, error) {
	l.nextLocal++
	if l.nextLocal == 0 {
		l.nextLocal = 1
	}
	id := l.nextLocal
	if err := l.writePacket(cmdOPEN, id, 0, append([]byte(service), 0)); err != nil {
		return nil, err
	}
	cmd, arg0, _, _, err := l.readPacket()
	if err != nil {
		return nil, fmt.Errorf("打开 %s 失败: %w", service, err)
	}
	switch cmd {
	case cmdOKAY:
		return &usbStream{l: l, local: id, remote: arg0}, nil
	case cmdCLSE:
		return nil, fmt.Errorf("设备拒绝 %s", service)
	default:
		return nil, fmt.Errorf("打开 %s 时收到意外消息 %08x", service, cmd)
	}
}

func (st *usbStream) Read(p []byte) (int, error) {
	for len(st.buf) == 0 {
		if st.eof {
			return 0, io.EOF
		}
		cmd, arg0, _, data, err := st.l.readPacket()
		if err != nil {
			return 0, err
		}
		switch cmd {
		case cmdWRTE:
			if err := st.l.writePacket(cmdOKAY, st.local, arg0, nil); err != nil {
				return 0, err
			}
			st.buf = append(st.buf, data...)
		case cmdCLSE:
			st.eof = true
			return 0, io.EOF
		case cmdOKAY:
		default:
			return 0, fmt.Errorf("收到意外消息 %08x", cmd)
		}
	}
	n := copy(p, st.buf)
	st.buf = st.buf[n:]
	return n, nil
}

func (st *usbStream) Write(p []byte) (int, error) {
	if st.closed {
		return 0, io.ErrClosedPipe
	}
	sent := 0
	max := int(st.l.peerMax)
	if max <= 0 {
		max = 4096
	}
	for len(p) > 0 {
		n := len(p)
		if n > max {
			n = max
		}
		if err := st.l.writePacket(cmdWRTE, st.local, st.remote, p[:n]); err != nil {
			return sent, err
		}
		if err := st.waitOKAY(); err != nil {
			return sent, err
		}
		p = p[n:]
		sent += n
	}
	return sent, nil
}

func (st *usbStream) waitOKAY() error {
	for {
		cmd, arg0, _, data, err := st.l.readPacket()
		if err != nil {
			return err
		}
		switch cmd {
		case cmdOKAY:
			return nil
		case cmdWRTE:
			if err := st.l.writePacket(cmdOKAY, st.local, arg0, nil); err != nil {
				return err
			}
			st.buf = append(st.buf, data...)
		case cmdCLSE:
			st.eof = true
			return io.EOF
		default:
			return fmt.Errorf("收到意外消息 %08x", cmd)
		}
	}
}

func (st *usbStream) Close() error {
	if st.closed {
		return nil
	}
	st.closed = true
	return st.l.writePacket(cmdCLSE, st.local, st.remote, nil)
}

func (l *usbLink) readService(service string) ([]byte, error) {
	st, err := l.open(service)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	var buf bytes.Buffer
	_, err = io.Copy(&buf, st)
	if err == nil || err == io.EOF {
		return buf.Bytes(), nil
	}
	if service == "reboot:" || (service == "root:" && buf.Len() > 0) {
		return buf.Bytes(), nil
	}
	return buf.Bytes(), err
}

func writeSync(w io.Writer, id string, data []byte) error {
	if len(id) != 4 {
		return fmt.Errorf("同步头无效")
	}
	buf := make([]byte, 8+len(data))
	copy(buf[:4], id)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(len(data)))
	copy(buf[8:], data)
	_, err := w.Write(buf)
	return err
}

func (l *usbLink) push(local, remote string) error {
	f, err := os.Open(local)
	if err != nil {
		return fmt.Errorf("无法打开本地文件: %w", err)
	}
	defer f.Close()
	st, err := l.open("sync:")
	if err != nil {
		return err
	}
	defer st.Close()
	if strings.HasSuffix(remote, "/") || strings.HasSuffix(remote, `\`) {
		remote = strings.TrimRight(remote, `/\`) + "/" + filepath.Base(local)
	}
	// 0100644 is the mode adbd expects, printed as a decimal integer.
	if err := writeSync(st, "SEND", []byte(fmt.Sprintf("%s,%d", remote, 0o100644))); err != nil {
		return err
	}
	buf := make([]byte, 64*1024)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if err := writeSync(st, "DATA", buf[:n]); err != nil {
				return err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	var mtime [4]byte
	binary.LittleEndian.PutUint32(mtime[:], uint32(time.Now().Unix()))
	if err := writeSync(st, "DONE", mtime[:]); err != nil {
		return err
	}
	return readSyncStatus(st)
}

func (l *usbLink) pull(remote, local string) error {
	st, err := l.open("sync:")
	if err != nil {
		return err
	}
	defer st.Close()
	if err := writeSync(st, "RECV", []byte(remote)); err != nil {
		return err
	}
	out, err := os.Create(local)
	if err != nil {
		return fmt.Errorf("无法创建本地文件: %w", err)
	}
	defer out.Close()
	for {
		var hdr [8]byte
		if _, err := io.ReadFull(st, hdr[:]); err != nil {
			return fmt.Errorf("读取同步数据失败: %w", err)
		}
		id := string(hdr[:4])
		n := binary.LittleEndian.Uint32(hdr[4:])
		switch id {
		case "DATA":
			if n > 64*1024 {
				return fmt.Errorf("同步数据块过大")
			}
			if _, err := io.CopyN(out, st, int64(n)); err != nil {
				return err
			}
		case "DONE":
			_ = writeSync(st, "QUIT", nil)
			return nil
		case "FAIL":
			msg := make([]byte, n)
			if n > 0 {
				if _, err := io.ReadFull(st, msg); err != nil {
					return fmt.Errorf("下载失败")
				}
			}
			return fmt.Errorf("下载失败: %s", strings.TrimSpace(string(msg)))
		default:
			return fmt.Errorf("同步响应异常: %s", id)
		}
	}
}

func readSyncStatus(st *usbStream) error {
	var hdr [8]byte
	if _, err := io.ReadFull(st, hdr[:]); err != nil {
		return fmt.Errorf("读取同步结果失败: %w", err)
	}
	id := string(hdr[:4])
	n := binary.LittleEndian.Uint32(hdr[4:])
	if id == "OKAY" {
		_ = writeSync(st, "QUIT", nil)
		return nil
	}
	if id == "FAIL" {
		msg := make([]byte, n)
		if n > 0 {
			if _, err := io.ReadFull(st, msg); err != nil {
				return fmt.Errorf("上传失败")
			}
		}
		return fmt.Errorf("上传失败: %s", strings.TrimSpace(string(msg)))
	}
	return fmt.Errorf("同步响应异常: %s", id)
}

func commandDeadline(sleepSeconds int) time.Duration {
	d := 2 * time.Minute
	if sleepSeconds > 0 {
		need := time.Duration(sleepSeconds)*time.Second + 15*time.Second
		if need > d {
			return need
		}
	}
	return d
}

func usbShell(serial, command string, deadline time.Duration) (string, error) {
	out, err := withPhone(serial, deadline, func(l *usbLink) ([]byte, error) {
		return l.readService("shell:" + command)
	})
	return string(out), err
}

func usbService(serial, service string, deadline time.Duration) ([]byte, error) {
	out, err := withPhone(serial, deadline, func(l *usbLink) ([]byte, error) {
		return l.readService(service)
	})
	if service == "root:" || service == "reboot:" {
		closePhone()
	}
	return out, err
}

func usbPush(localPath, remotePath string) error {
	_, err := withPhone("", 2*time.Minute, func(l *usbLink) ([]byte, error) {
		return nil, l.push(localPath, remotePath)
	})
	return err
}

func usbPull(remotePath, localPath string) error {
	_, err := withPhone("", 2*time.Minute, func(l *usbLink) ([]byte, error) {
		return nil, l.pull(remotePath, localPath)
	})
	return err
}
