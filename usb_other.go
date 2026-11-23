//go:build !windows && !(linux && (amd64 || arm64))

package main

import "fmt"

func listUSBDevices() ([]usbCandidate, error) {
	return nil, fmt.Errorf("当前系统没有直接 USB 调试实现")
}
