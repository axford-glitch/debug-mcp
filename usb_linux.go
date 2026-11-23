//go:build linux && (amd64 || arm64)

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	usbdevfsBulk    = 0xc0185502
	usbdevfsClaim   = 0x8004550f
	usbdevfsRelease = 0x80045510
	usbdevfsDisconn = 0x5516
)

// linuxBulk matches struct usbdevfs_bulktransfer on 64-bit Linux.
type linuxBulk struct {
	ep      uint32
	length  uint32
	timeout uint32
	data    uintptr
}

func init() {
	var b linuxBulk
	if unsafe.Sizeof(b) != 24 || unsafe.Offsetof(b.data) != 16 {
		panic("usbdevfs_bulktransfer layout mismatch")
	}
}

type linuxUSB struct {
	fd       int
	iface    uint32
	epIn     uint8
	epOut    uint8
	deadline time.Time
}

func listUSBDevices() ([]usbCandidate, error) {
	entries, err := os.ReadDir("/sys/bus/usb/devices")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("无法枚举 USB 设备: %w", err)
	}
	var out []usbCandidate
	for _, e := range entries {
		name := e.Name()
		if !strings.Contains(name, ":") {
			continue
		}
		base := filepath.Join("/sys/bus/usb/devices", name)
		class, err := readHex(filepath.Join(base, "bInterfaceClass"))
		if err != nil || class != 0xff {
			continue
		}
		sub, err := readHex(filepath.Join(base, "bInterfaceSubClass"))
		if err != nil || sub != 0x42 {
			continue
		}
		proto, err := readHex(filepath.Join(base, "bInterfaceProtocol"))
		if err != nil || proto != 0x01 {
			continue
		}
		ifNum, err := readHex(filepath.Join(base, "bInterfaceNumber"))
		if err != nil {
			continue
		}
		epIn, epOut := findBulkEndpoints(base)
		if epIn == 0 || epOut == 0 {
			continue
		}
		devName := strings.SplitN(name, ":", 2)[0]
		devBase := filepath.Join("/sys/bus/usb/devices", devName)
		bus, err := readDec(filepath.Join(devBase, "busnum"))
		if err != nil {
			continue
		}
		devnum, err := readDec(filepath.Join(devBase, "devnum"))
		if err != nil {
			continue
		}
		serialBytes, _ := os.ReadFile(filepath.Join(devBase, "serial"))
		serial := strings.TrimSpace(string(serialBytes))
		path := fmt.Sprintf("/dev/bus/usb/%03d/%03d", bus, devnum)
		iface := uint32(ifNum)
		in, outEp := epIn, epOut
		out = append(out, usbCandidate{
			serial: serial,
			open: func() (adbTransport, string, error) {
				return openLinuxUSB(path, iface, in, outEp, serial)
			},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].serial < out[j].serial })
	return out, nil
}

func findBulkEndpoints(ifacePath string) (epIn, epOut uint8) {
	eps, err := os.ReadDir(ifacePath)
	if err != nil {
		return 0, 0
	}
	for _, ep := range eps {
		if !strings.HasPrefix(ep.Name(), "ep_") {
			continue
		}
		dir := filepath.Join(ifacePath, ep.Name())
		addr, err := readHex(filepath.Join(dir, "bEndpointAddress"))
		if err != nil {
			continue
		}
		attr, err := readHex(filepath.Join(dir, "bmAttributes"))
		if err != nil || attr&0x3 != 2 {
			continue
		}
		if addr&0x80 != 0 {
			epIn = uint8(addr)
		} else {
			epOut = uint8(addr)
		}
	}
	return epIn, epOut
}

func readHex(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 16, 32)
	return int(n), err
}

func readDec(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

func openLinuxUSB(path string, iface uint32, epIn, epOut uint8, serial string) (adbTransport, string, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR, 0)
	if err != nil {
		return nil, "", fmt.Errorf("无法打开 %s: %w", path, err)
	}
	if errno := ioctlPtr(fd, usbdevfsClaim, unsafe.Pointer(&iface)); errno != 0 {
		_ = ioctlPtr(fd, usbdevfsDisconn, unsafe.Pointer(&iface))
		if errno = ioctlPtr(fd, usbdevfsClaim, unsafe.Pointer(&iface)); errno != 0 {
			syscall.Close(fd)
			if errno == syscall.EBUSY || errno == syscall.EACCES || errno == syscall.EPERM {
				return nil, "", fmt.Errorf("USB 调试接口被占用或没有权限 (%s)。请先关闭正在占用手机的程序", path)
			}
			return nil, "", fmt.Errorf("无法占用 USB 接口 %s: %w", path, errno)
		}
	}
	return &linuxUSB{fd: fd, iface: iface, epIn: epIn, epOut: epOut}, serial, nil
}

func ioctlPtr(fd int, req uintptr, p unsafe.Pointer) syscall.Errno {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(p))
	return errno
}

func (c *linuxUSB) timeoutMS() uint32 {
	if c.deadline.IsZero() {
		return 30000
	}
	d := time.Until(c.deadline)
	if d <= 0 {
		return 1
	}
	ms := d / time.Millisecond
	if ms < 1 {
		return 1
	}
	if ms > 600000 {
		return 600000
	}
	return uint32(ms)
}

func (c *linuxUSB) SetDeadline(t time.Time) error {
	c.deadline = t
	return nil
}

func (c *linuxUSB) xfer(ep uint8, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	bulk := linuxBulk{
		ep:      uint32(ep),
		length:  uint32(len(p)),
		timeout: c.timeoutMS(),
		data:    uintptr(unsafe.Pointer(&p[0])),
	}
	var errno syscall.Errno
	for attempt := 0; attempt < 3; attempt++ {
		bulk.length = uint32(len(p))
		errno = ioctlPtr(c.fd, usbdevfsBulk, unsafe.Pointer(&bulk))
		if errno != syscall.EINTR {
			break
		}
	}
	if errno != 0 {
		if errno == syscall.ETIMEDOUT || errno == syscall.EAGAIN {
			return 0, fmt.Errorf("USB 传输超时")
		}
		return 0, fmt.Errorf("USB 传输失败: %w", errno)
	}
	return int(bulk.length), nil
}

func (c *linuxUSB) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > usbChunk {
		p = p[:usbChunk]
	}
	for i := 0; i < 8; i++ {
		n, err := c.xfer(c.epIn, p)
		if err != nil {
			return 0, err
		}
		if n > 0 {
			return n, nil
		}
	}
	return 0, ioErrUnexpected
}

func (c *linuxUSB) Write(p []byte) (int, error) {
	off := 0
	for off < len(p) {
		end := off + usbChunk
		if end > len(p) {
			end = len(p)
		}
		n, err := c.xfer(c.epOut, p[off:end])
		if err != nil {
			return off, err
		}
		if n <= 0 {
			return off, ioErrUnexpected
		}
		if n > end-off {
			n = end - off
		}
		off += n
	}
	return off, nil
}

func (c *linuxUSB) Close() error {
	if c.fd < 0 {
		return nil
	}
	iface := c.iface
	_ = ioctlPtr(c.fd, usbdevfsRelease, unsafe.Pointer(&iface))
	err := syscall.Close(c.fd)
	c.fd = -1
	if err != nil {
		return err
	}
	return nil
}
