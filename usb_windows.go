//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"sort"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Android WinUSB interface published by the Google USB driver.
var adbInterfaceGUID = windows.GUID{
	Data1: 0xF72FE0D4,
	Data2: 0xCBCB,
	Data3: 0x407D,
	Data4: [8]byte{0x88, 0x14, 0x9E, 0xD6, 0x73, 0xD0, 0xDD, 0x6B},
}

const (
	winPipeTimeout   = 3
	winErrorTimeout  = syscall.Errno(121)
	winErrorSharing  = syscall.Errno(32)
	winErrorAccess   = syscall.Errno(5)
	winErrorNoMore   = syscall.Errno(259)
	winErrorTooSmall = syscall.Errno(122)
)

var (
	setupapi = windows.NewLazySystemDLL("setupapi.dll")
	winusb   = windows.NewLazySystemDLL("winusb.dll")

	procEnumInterfaces  = setupapi.NewProc("SetupDiEnumDeviceInterfaces")
	procInterfaceDetail = setupapi.NewProc("SetupDiGetDeviceInterfaceDetailW")

	procUsbInit       = winusb.NewProc("WinUsb_Initialize")
	procUsbFree       = winusb.NewProc("WinUsb_Free")
	procUsbIface      = winusb.NewProc("WinUsb_QueryInterfaceSettings")
	procUsbPipe       = winusb.NewProc("WinUsb_QueryPipe")
	procUsbRead       = winusb.NewProc("WinUsb_ReadPipe")
	procUsbWrite      = winusb.NewProc("WinUsb_WritePipe")
	procUsbPolicy     = winusb.NewProc("WinUsb_SetPipePolicy")
	procUsbDescriptor = winusb.NewProc("WinUsb_GetDescriptor")
	procUsbAbort      = winusb.NewProc("WinUsb_AbortPipe")
	procUsbOverlapped = winusb.NewProc("WinUsb_GetOverlappedResult")
)

const winWaitTimeout = 258

type spDeviceInterfaceData struct {
	cbSize   uint32
	guid     windows.GUID
	flags    uint32
	reserved uintptr
}

type winUSB struct {
	file       windows.Handle
	iface      uintptr
	epIn       uint8
	epOut      uint8
	readEvent  windows.Handle
	writeEvent windows.Handle
	deadline   time.Time
}

func listUSBDevices() ([]usbCandidate, error) {
	handle, err := windows.SetupDiGetClassDevsEx(&adbInterfaceGUID, "", 0, windows.DIGCF_PRESENT|windows.DIGCF_DEVICEINTERFACE, 0, "")
	if err != nil {
		return nil, fmt.Errorf("无法枚举 USB 调试接口: %w", err)
	}
	defer windows.SetupDiDestroyDeviceInfoList(handle)

	var out []usbCandidate
	for i := uint32(0); ; i++ {
		data := spDeviceInterfaceData{cbSize: uint32(unsafe.Sizeof(spDeviceInterfaceData{}))}
		r, _, e := procEnumInterfaces.Call(
			uintptr(handle),
			0,
			uintptr(unsafe.Pointer(&adbInterfaceGUID)),
			uintptr(i),
			uintptr(unsafe.Pointer(&data)),
		)
		if r == 0 {
			if e == winErrorNoMore {
				break
			}
			if i == 0 && (e == nil || e == syscall.Errno(0)) {
				break
			}
			if i == 0 {
				return nil, fmt.Errorf("无法枚举 USB 调试接口: %w", e)
			}
			break
		}
		path, err := interfacePath(handle, &data)
		if err != nil {
			continue
		}
		devPath := path
		out = append(out, usbCandidate{
			open: func() (adbTransport, string, error) {
				return openWinUSB(devPath)
			},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].serial < out[j].serial })
	return out, nil
}

func interfacePath(list windows.DevInfo, data *spDeviceInterfaceData) (string, error) {
	var required uint32
	r, _, e := procInterfaceDetail.Call(
		uintptr(list),
		uintptr(unsafe.Pointer(data)),
		0,
		0,
		uintptr(unsafe.Pointer(&required)),
		0,
	)
	if r == 0 && e != winErrorTooSmall && e != syscall.Errno(0) && required == 0 {
		return "", e
	}
	if required < 8 {
		return "", fmt.Errorf("USB 设备路径长度为 0")
	}
	buf := make([]byte, required)
	cbSize := uint32(8)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		cbSize = 6
	}
	binary.LittleEndian.PutUint32(buf[:4], cbSize)
	r, _, e = procInterfaceDetail.Call(
		uintptr(list),
		uintptr(unsafe.Pointer(data)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&required)),
		0,
	)
	if r == 0 {
		return "", fmt.Errorf("读取 USB 设备路径失败: %w", e)
	}
	n := (len(buf) - 4) / 2
	chars := make([]uint16, n)
	for i := range chars {
		chars[i] = binary.LittleEndian.Uint16(buf[4+i*2:])
	}
	return windows.UTF16ToString(chars), nil
}

func openWinUSB(path string) (adbTransport, string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, "", err
	}
	// WinUSB requires an overlapped file handle. Transfers wait on their own events.
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		if err == winErrorSharing || err == winErrorAccess {
			return nil, "", fmt.Errorf("USB 调试接口被占用。请先关闭正在占用手机的程序")
		}
		return nil, "", fmt.Errorf("打开 USB 设备失败: %w", err)
	}
	var iface uintptr
	r, _, e := procUsbInit.Call(uintptr(h), uintptr(unsafe.Pointer(&iface)))
	if r == 0 {
		windows.CloseHandle(h)
		return nil, "", fmt.Errorf("初始化 USB 接口失败: %w", e)
	}
	readEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		procUsbFree.Call(iface)
		windows.CloseHandle(h)
		return nil, "", err
	}
	writeEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(readEvent)
		procUsbFree.Call(iface)
		windows.CloseHandle(h)
		return nil, "", err
	}
	conn := &winUSB{file: h, iface: iface, readEvent: readEvent, writeEvent: writeEvent}
	if err := conn.prepare(); err != nil {
		conn.Close()
		return nil, "", err
	}
	serial := conn.serialString()
	return conn, serial, nil
}

func (c *winUSB) prepare() error {
	var desc [16]byte
	r, _, e := procUsbIface.Call(c.iface, 0, uintptr(unsafe.Pointer(&desc[0])))
	if r == 0 {
		return fmt.Errorf("读取 USB 接口描述符失败: %w", e)
	}
	if desc[5] != 0xff || desc[6] != 0x42 || desc[7] != 0x01 {
		return fmt.Errorf("该 USB 接口不是 Android 调试接口")
	}
	n := desc[4]
	for i := byte(0); i < n; i++ {
		var info [16]byte
		r, _, e := procUsbPipe.Call(c.iface, 0, uintptr(i), uintptr(unsafe.Pointer(&info[0])))
		if r == 0 {
			return fmt.Errorf("读取 USB 管道失败: %w", e)
		}
		pipeType := binary.LittleEndian.Uint32(info[0:4])
		pipeID := info[4]
		if pipeType != 2 {
			continue
		}
		if pipeID&0x80 != 0 {
			c.epIn = pipeID
		} else {
			c.epOut = pipeID
		}
	}
	if c.epIn == 0 || c.epOut == 0 {
		return fmt.Errorf("Android 调试接口缺少批量传输管道")
	}
	c.setMaxTransfer(1024 * 1024)
	return c.setTimeout(30000)
}

func (c *winUSB) setMaxTransfer(n uint32) {
	for _, ep := range []uint8{c.epIn, c.epOut} {
		val := n
		procUsbPolicy.Call(c.iface, uintptr(ep), 0x08, 4, uintptr(unsafe.Pointer(&val)))
	}
}

func (c *winUSB) serialString() string {
	var desc [32]byte
	var n uint32
	r, _, _ := procUsbDescriptor.Call(c.iface, 1, 0, 0, uintptr(unsafe.Pointer(&desc[0])), uintptr(len(desc)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || n < 18 || desc[16] == 0 {
		return ""
	}
	if s := c.stringDescriptor(desc[16], 0x0409); s != "" {
		return s
	}
	lang := c.stringDescriptorWord(0, 0)
	if lang == 0 {
		return ""
	}
	return c.stringDescriptor(desc[16], lang)
}

func (c *winUSB) stringDescriptorWord(index byte, lang uint16) uint16 {
	var raw [255]byte
	var n uint32
	r, _, _ := procUsbDescriptor.Call(c.iface, 3, uintptr(index), uintptr(lang), uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || n < 4 || raw[1] != 3 {
		return 0
	}
	return binary.LittleEndian.Uint16(raw[2:4])
}

func (c *winUSB) stringDescriptor(index byte, lang uint16) string {
	var raw [255]byte
	var n uint32
	r, _, _ := procUsbDescriptor.Call(
		c.iface,
		3,
		uintptr(index),
		uintptr(lang),
		uintptr(unsafe.Pointer(&raw[0])),
		uintptr(len(raw)),
		uintptr(unsafe.Pointer(&n)),
	)
	if r == 0 || n < 4 || raw[1] != 3 {
		return ""
	}
	if int(n) > len(raw) {
		n = uint32(len(raw))
	}
	chars := make([]uint16, 0, (n-2)/2)
	for i := uint32(2); i+1 < n; i += 2 {
		chars = append(chars, binary.LittleEndian.Uint16(raw[i:i+2]))
	}
	return windows.UTF16ToString(chars)
}

func (c *winUSB) setTimeout(ms uint32) error {
	for _, ep := range []uint8{c.epIn, c.epOut} {
		if ep == 0 {
			continue
		}
		val := ms
		r, _, e := procUsbPolicy.Call(c.iface, uintptr(ep), winPipeTimeout, 4, uintptr(unsafe.Pointer(&val)))
		if r == 0 {
			return fmt.Errorf("设置 USB 超时失败: %w", e)
		}
	}
	return nil
}

func (c *winUSB) SetDeadline(t time.Time) error {
	c.deadline = t
	ms := uint32(30000)
	if !t.IsZero() {
		d := time.Until(t)
		if d <= 0 {
			ms = 1
		} else {
			ms = uint32(d / time.Millisecond)
			if ms < 1 {
				ms = 1
			}
		}
	}
	return c.setTimeout(ms)
}

func (c *winUSB) waitMS() uint32 {
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

func (c *winUSB) transfer(write bool, p []byte) (int, error) {
	ep := c.epIn
	event := c.readEvent
	proc := procUsbRead
	if write {
		ep = c.epOut
		event = c.writeEvent
		proc = procUsbWrite
	}
	if err := windows.ResetEvent(event); err != nil {
		return 0, err
	}
	var ov windows.Overlapped
	ov.HEvent = event
	var n uint32
	r, _, e := proc.Call(c.iface, uintptr(ep), uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&ov)))
	if r == 0 && e != windows.ERROR_IO_PENDING {
		if e == winErrorTimeout {
			return 0, fmt.Errorf("USB 传输超时")
		}
		return 0, fmt.Errorf("USB 传输失败: %w", e)
	}
	if r == 0 {
		status, _ := windows.WaitForSingleObject(event, c.waitMS())
		if status != windows.WAIT_OBJECT_0 {
			procUsbAbort.Call(c.iface, uintptr(ep))
			windows.WaitForSingleObject(event, 2000)
			return 0, fmt.Errorf("USB 传输超时")
		}
		var got uint32
		rr, _, ge := procUsbOverlapped.Call(c.iface, uintptr(unsafe.Pointer(&ov)), uintptr(unsafe.Pointer(&got)), 0)
		if rr == 0 {
			if ge == winErrorTimeout {
				return 0, fmt.Errorf("USB 传输超时")
			}
			return 0, fmt.Errorf("USB 传输失败: %w", ge)
		}
		n = got
	}
	return int(n), nil
}

func (c *winUSB) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > usbChunk {
		p = p[:usbChunk]
	}
	for i := 0; i < 8; i++ {
		n, err := c.transfer(false, p)
		if err != nil {
			return 0, err
		}
		if n > 0 {
			return n, nil
		}
	}
	return 0, ioErrUnexpected
}

func (c *winUSB) Write(p []byte) (int, error) {
	off := 0
	for off < len(p) {
		end := off + usbChunk
		if end > len(p) {
			end = len(p)
		}
		n, err := c.transfer(true, p[off:end])
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

func (c *winUSB) Close() error {
	if c.iface != 0 {
		procUsbFree.Call(c.iface)
		c.iface = 0
	}
	if c.readEvent != 0 {
		windows.CloseHandle(c.readEvent)
		c.readEvent = 0
	}
	if c.writeEvent != 0 {
		windows.CloseHandle(c.writeEvent)
		c.writeEvent = 0
	}
	if c.file != 0 {
		windows.CloseHandle(c.file)
		c.file = 0
	}
	return nil
}
