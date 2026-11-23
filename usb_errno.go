package main

import "io"

// ioErrUnexpected is the short read/write failure shared by the USB backends.
var ioErrUnexpected = io.ErrUnexpectedEOF

// usbChunk is the largest bulk transfer requested at once. Smaller reads
// are reassembled by the caller. 4 KiB stays inside WinUSB's default limit.
const usbChunk = 4 * 1024
