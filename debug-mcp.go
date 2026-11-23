package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image/png"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/electricbubble/gadb"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.bug.st/serial"
)

// serialPortName serial port device name, configurable via SERIAL_PORT env var, default "COM3"
var serialPortName string

// serialMutex ensures only one caller uses the serial port at a time
var serialMutex sync.Mutex

const debugEnabled = true

var logFile *os.File

// commands in /mnt/usr/bin/ (not /ifs/bin/)
var mntUsrBinCommands = map[string]bool{
	"ads_update_test": true, "awk": true, "basename": true, "ccitool": true,
	"cksum": true, "coreinfo": true, "cpudbgr": true, "curl": true,
	"cut": true, "devmem": true, "dvtm": true, "eolcfg": true,
	"events": true, "expr": true, "file": true, "ftp": true,
	"fuse_launcher": true, "fuse_manager": true, "getconf": true, "gles2-gears": true,
	"gzip": true, "hogs": true, "i2ctool": true, "iperf2": true,
	"iperf2_d": true, "iperf3": true, "ipctool": true, "ldd": true,
	"log_dump": true, "lsof": true, "memtester": true, "mkfifo": true,
	"mt_audio": true, "mt_bootctrl": true, "mt_display": true, "mt_guest": true,
	"mt_sysinfo": true, "mtouch.startup.sh": true, "netstat": true, "nspStlTest": true,
	"openssl": true, "passthrough": true, "passthrough_svs": true, "passwd": true,
	"pdebug": true, "printf": true, "ps": true, "qtdctl": true,
	"scp": true, "screenshot": true, "setconf": true, "sleep": true,
	"ssh": true, "ssh-keygen": true, "svs_dmesg": true, "svs_pm": true,
	"svs_pm_ctl": true, "svs_pm_pluse": true, "svs_rdmem": true, "svs_spi": true,
	"svs_top": true, "tail": true, "telnet": true, "textto": true,
	"tiobench": true, "top": true, "touch_test": true, "touch_tool": true,
	"unzip": true, "uppertester": true, "vidc_enc": true, "vmwindow": true,
	"wc": true, "which": true, "xargs": true, "zip": true,
}

// qnxBinDir returns the bin directory for a QNX command.
// Commands in mntUsrBinCommands use /mnt/usr/bin, others use /ifs/bin.
func qnxBinDir(command string) string {
	// extract first word (the command name, ignoring args)
	first := strings.Fields(command)
	if len(first) > 0 && mntUsrBinCommands[first[0]] {
		return "/mnt/usr/bin"
	}
	return "/ifs/bin"
}

func checkErr(err error, msg ...string) {
	if err == nil {
		return
	}

	var output string
	if len(msg) != 0 {
		output = msg[0] + " "
	}
	output += err.Error()
	debugLog("ERROR: " + output)
}

// autoDetectSerialPort discovers available serial ports, excludes ports listed
// in SERIAL_EXCLUDE env var (comma-separated), and returns the one with the
// smallest numeric suffix. Falls back to "COM3" if detection fails.
func autoDetectSerialPort() string {
	ports, err := serial.GetPortsList()
	if err != nil || len(ports) == 0 {
		debugLogf("autoDetectSerialPort: GetPortsList failed or empty\n")
		return ""
	}
	debugLogf("autoDetectSerialPort: found ports: %v\n", ports)

	// build exclude set
	exclude := make(map[string]bool)
	if ex := os.Getenv("SERIAL_EXCLUDE"); ex != "" {
		for _, p := range strings.Split(ex, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				exclude[p] = true
			}
		}
		debugLogf("autoDetectSerialPort: exclude set: %v\n", exclude)
	}

	// extract numeric suffix for sorting (e.g. COM3 -> 3, /dev/ttyUSB0 -> 0)
	re := regexp.MustCompile(`(\d+)$`)
	type portEntry struct {
		name string
		num  int
	}
	var candidates []portEntry
	for _, p := range ports {
		if exclude[p] {
			debugLogf("autoDetectSerialPort: excluding %s\n", p)
			continue
		}
		m := re.FindStringSubmatch(p)
		num := -1
		if m != nil {
			num, _ = strconv.Atoi(m[1])
		}
		candidates = append(candidates, portEntry{p, num})
	}

	if len(candidates) == 0 {
		debugLogf("autoDetectSerialPort: no candidates after filtering\n")
		return ""
	}

	// sort by numeric suffix, smallest first
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].num < candidates[j].num
	})

	debugLogf("autoDetectSerialPort: selected %s\n", candidates[0].name)
	return candidates[0].name
}

func main() {
	// 0. init log file
	var err error
	logFile, err = os.OpenFile("debug-mcp.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("can't create log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	debugLog("log system initialized")

	// 1b. get serial port: explicit > auto-detect > default
	if port := os.Getenv("SERIAL_PORT"); port != "" {
		serialPortName = port
		debugLogf("serial port from env: %s\n", serialPortName)
	} else {
		serialPortName = autoDetectSerialPort()
		debugLogf("serial port auto-detected: %s\n", serialPortName)
	}

	// 2. init MCP Server
	s := server.NewMCPServer("debug-mcp-server", "1.0.0")

	// 3. execute_android_commands tool
	executeAndroidCommandsTool := mcp.NewTool("execute_android_commands",
		mcp.WithDescription("在 Android 系统上执行指定的命令"),
	)
	executeAndroidCommandsTool.InputSchema.Properties = map[string]interface{}{
		"command": map[string]interface{}{
			"type":        "string",
			"description": "要执行的命令",
		},
		"sleep_seconds": map[string]interface{}{
			"type":        "number",
			"description": "等待输出时间（秒），默认2",
		},
	}
	executeAndroidCommandsTool.InputSchema.Required = []string{"command"}

	s.AddTool(executeAndroidCommandsTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]interface{})
		if !ok {
			return mcp.NewToolResultError("无效的参数格式"), nil
		}

		command, ok := args["command"].(string)
		if !ok {
			return mcp.NewToolResultError("缺少 command 参数"), nil
		}

		sleepSeconds := 2
		if sleep, ok := args["sleep_seconds"]; ok {
			switch v := sleep.(type) {
			case float64:
				sleepSeconds = int(v)
			case string:
				if n, err := strconv.Atoi(v); err == nil {
					sleepSeconds = n
				}
			}
		}

		result, err := executeAndroidCommands(command, sleepSeconds)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Android 命令执行失败: %v", err)), nil
		}
		return mcp.NewToolResultText(result), nil
	})

	// 3b. execute_android_commands_fallback (backup: SSH only, skip ADB)
	executeAndroidFallbackTool := mcp.NewTool("execute_android_commands_fallback",
		mcp.WithDescription(
			"【备选接口】当 execute_android_commands 执行失败时使用此接口。"+
				"通过串口直连方式在 Android 系统上执行命令（不经过 ADB/SSH）。"+
				"参数和返回值与 execute_android_commands 相同。",
		),
	)
	executeAndroidFallbackTool.InputSchema.Properties = map[string]interface{}{
		"command": map[string]interface{}{
			"type":        "string",
			"description": "要执行的命令",
		},
		"sleep_seconds": map[string]interface{}{
			"type":        "number",
			"description": "等待输出时间（秒），默认2",
		},
	}
	executeAndroidFallbackTool.InputSchema.Required = []string{"command"}

	s.AddTool(executeAndroidFallbackTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]interface{})
		if !ok {
			return mcp.NewToolResultError("无效的参数格式"), nil
		}

		command, ok := args["command"].(string)
		if !ok {
			return mcp.NewToolResultError("缺少 command 参数"), nil
		}

		sleepSeconds := 2
		if sleep, ok := args["sleep_seconds"]; ok {
			switch v := sleep.(type) {
			case float64:
				sleepSeconds = int(v)
			case string:
				if n, err := strconv.Atoi(v); err == nil {
					sleepSeconds = n
				}
			}
		}

		result, err := executeAndroidCommandsFallback(command, sleepSeconds)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Android 备选命令执行失败: %v", err)), nil
		}
		return mcp.NewToolResultText(result), nil
	})

	// 4. execute_qnx_commands tool
	executeQNXCommandsTool := mcp.NewTool("execute_qnx_commands",
		mcp.WithDescription("在 QNX 系统上执行指定的命令"),
	)
	executeQNXCommandsTool.InputSchema.Properties = map[string]interface{}{
		"command": map[string]interface{}{
			"type":        "string",
			"description": "要执行的命令",
		},
		"sleep_seconds": map[string]interface{}{
			"type":        "number",
			"description": "等待输出时间（秒），默认2",
		},
	}
	executeQNXCommandsTool.InputSchema.Required = []string{"command"}

	s.AddTool(executeQNXCommandsTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]interface{})
		if !ok {
			return mcp.NewToolResultError("无效的参数格式"), nil
		}

		command, ok := args["command"].(string)
		if !ok {
			return mcp.NewToolResultError("缺少 command 参数"), nil
		}

		sleepSeconds := 2
		if sleep, ok := args["sleep_seconds"]; ok {
			switch v := sleep.(type) {
			case float64:
				sleepSeconds = int(v)
			case string:
				if n, err := strconv.Atoi(v); err == nil {
					sleepSeconds = n
				}
			}
		}

		result, err := executeQNXCommands(command, sleepSeconds)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("QNX 命令执行失败: %v", err)), nil
		}
		return mcp.NewToolResultText(result), nil
	})

	// 4b. execute_qnx_commands_fallback (backup: SSH only, skip ADB)
	executeQNXFallbackTool := mcp.NewTool("execute_qnx_commands_fallback",
		mcp.WithDescription(
			"【备选接口】当 execute_qnx_commands 执行失败时使用此接口。"+
				"通过串口直连方式在 QNX 系统上执行命令（不经过 ADB/SSH）。"+
				"参数和返回值与 execute_qnx_commands 相同。",
		),
	)
	executeQNXFallbackTool.InputSchema.Properties = map[string]interface{}{
		"command": map[string]interface{}{
			"type":        "string",
			"description": "要执行的命令",
		},
		"sleep_seconds": map[string]interface{}{
			"type":        "number",
			"description": "等待输出时间（秒），默认2",
		},
	}
	executeQNXFallbackTool.InputSchema.Required = []string{"command"}

	s.AddTool(executeQNXFallbackTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]interface{})
		if !ok {
			return mcp.NewToolResultError("无效的参数格式"), nil
		}

		command, ok := args["command"].(string)
		if !ok {
			return mcp.NewToolResultError("缺少 command 参数"), nil
		}

		sleepSeconds := 2
		if sleep, ok := args["sleep_seconds"]; ok {
			switch v := sleep.(type) {
			case float64:
				sleepSeconds = int(v)
			case string:
				if n, err := strconv.Atoi(v); err == nil {
					sleepSeconds = n
				}
			}
		}

		result, err := executeQNXCommandsFallback(command, sleepSeconds)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("QNX 备选命令执行失败: %v", err)), nil
		}
		return mcp.NewToolResultText(result), nil
	})

	// 5. android_push_file tool
	androidPushFileTool := mcp.NewTool("android_push_file",
		mcp.WithDescription("将本地文件上传到 Android 设备"),
	)
	androidPushFileTool.InputSchema.Properties = map[string]interface{}{
		"local_path": map[string]interface{}{
			"type":        "string",
			"description": "本地文件路径",
		},
		"remote_path": map[string]interface{}{
			"type":        "string",
			"description": "Android 设备上的目标路径",
		},
	}
	androidPushFileTool.InputSchema.Required = []string{"local_path", "remote_path"}

	s.AddTool(androidPushFileTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]interface{})
		if !ok {
			return mcp.NewToolResultError("无效的参数格式"), nil
		}

		localPath, ok := args["local_path"].(string)
		if !ok || localPath == "" {
			return mcp.NewToolResultError("缺少 local_path 参数"), nil
		}

		remotePath, ok := args["remote_path"].(string)
		if !ok || remotePath == "" {
			return mcp.NewToolResultError("缺少 remote_path 参数"), nil
		}

		result, err := androidPushFile(localPath, remotePath)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Android 文件上传失败: %v", err)), nil
		}
		return mcp.NewToolResultText(result), nil
	})

	// 6. android_pull_file tool
	androidPullFileTool := mcp.NewTool("android_pull_file",
		mcp.WithDescription("从 Android 设备下载文件到本地"),
	)
	androidPullFileTool.InputSchema.Properties = map[string]interface{}{
		"remote_path": map[string]interface{}{
			"type":        "string",
			"description": "Android 设备上的文件路径",
		},
		"local_path": map[string]interface{}{
			"type":        "string",
			"description": "本地保存路径",
		},
	}
	androidPullFileTool.InputSchema.Required = []string{"remote_path", "local_path"}

	s.AddTool(androidPullFileTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]interface{})
		if !ok {
			return mcp.NewToolResultError("无效的参数格式"), nil
		}

		remotePath, ok := args["remote_path"].(string)
		if !ok || remotePath == "" {
			return mcp.NewToolResultError("缺少 remote_path 参数"), nil
		}

		localPath, ok := args["local_path"].(string)
		if !ok || localPath == "" {
			return mcp.NewToolResultError("缺少 local_path 参数"), nil
		}

		result, err := androidPullFile(remotePath, localPath)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Android 文件下载失败: %v", err)), nil
		}
		return mcp.NewToolResultText(result), nil
	})

	for _, tool := range []struct {
		name, description, service string
		image                      bool
	}{
		{"adb_root", "重启设备上的 adbd 并请求 root 权限", "root:", false},
		{"adb_reboot", "重启 Android 设备", "reboot:", false},
		{"adb_screenshot", "获取 Android 设备屏幕截图", "exec:screencap -p", true},
	} {
		tool := tool
		s.AddTool(mcp.NewTool(tool.name, mcp.WithDescription(tool.description),
			mcp.WithString("serial", mcp.Description("ADB 设备序列号；单设备时可省略"))),
			func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				args, _ := request.Params.Arguments.(map[string]interface{})
				serial, ok := args["serial"].(string)
				if args["serial"] != nil && !ok {
					return mcp.NewToolResultError("serial 必须是字符串"), nil
				}
				dev, err := selectDevice(serial)
				if err != nil {
					return mcp.NewToolResultError(err.Error()), nil
				}
				if tool.image {
					// exec: is adb exec-out. shell: would translate newlines and corrupt the PNG.
					output, err := adbExecOut(dev.Serial(), "screencap -p")
					if err != nil {
						return mcp.NewToolResultError(err.Error()), nil
					}
					if _, err := png.DecodeConfig(bytes.NewReader(output)); err != nil {
						return mcp.NewToolResultError("截图不是有效的 PNG: " + err.Error()), nil
					}
					return mcp.NewToolResultImage("截图成功", base64.StdEncoding.EncodeToString(output), "image/png"), nil
				}
				text, err := adbHostCommand(dev.Serial(), tool.service)
				if err != nil {
					return mcp.NewToolResultError(err.Error()), nil
				}
				if tool.name == "adb_root" {
					text, err = rootResult(ctx, text)
					if err != nil {
						return mcp.NewToolResultError(err.Error()), nil
					}
				}
				if text == "" && tool.name == "adb_reboot" {
					text = "rebooting"
				}
				return mcp.NewToolResultText(text), nil
			})
	}

	// 7. start MCP service
	if err := server.ServeStdio(s); err != nil {
		return
	}
}

// adbServerAddr is the IPv4 socket the adb server listens on. "localhost"
// can resolve to ::1, which Windows rejects when adb is bound to 127.0.0.1.
var adbServerAddr = fmt.Sprintf("127.0.0.1:%d", gadb.AdbServerPort)

// adbCommandDeadline bounds root/reboot. Those services usually close
// right after OKAY; the deadline stops a stuck socket from hanging.
var adbCommandDeadline = 10 * time.Second

// adbScreenshotDeadline bounds exec-out screencap, which streams a PNG.
var adbScreenshotDeadline = 30 * time.Second

// adbRootRestartWait matches the adb client: after adbd says it is
// restarting, wait for it to come back before the tool returns.
var adbRootRestartWait = 3 * time.Second

// listADBDevices dials 127.0.0.1:5037. A failed startup used to keep a
// zero client and later dial ":0". If nothing is listening, start the
// adb server and try again.
func listADBDevices() ([]gadb.Device, error) {
	stdout, stderr := os.Stdout, os.Stderr
	if logFile != nil {
		os.Stdout = logFile
		os.Stderr = logFile
	}
	defer func() {
		os.Stdout = stdout
		os.Stderr = stderr
	}()

	client, err := connectADB()
	if err != nil {
		return nil, err
	}
	return client.DeviceList()
}

func connectADB() (gadb.Client, error) {
	client, err := dialADB()
	if err == nil {
		return client, nil
	}
	dialErr := err
	debugLogf("adb dial failed: %v\n", dialErr)
	if startErr := startADBServer(); startErr != nil {
		return gadb.Client{}, fmt.Errorf("连接 ADB 服务 %s 失败: %v; %w", adbServerAddr, startErr, dialErr)
	}
	var last error
	for i := 0; i < 10; i++ {
		client, err = dialADB()
		if err == nil {
			return client, nil
		}
		last = err
		time.Sleep(200 * time.Millisecond)
	}
	return gadb.Client{}, fmt.Errorf("连接 ADB 服务 %s 失败: %w", adbServerAddr, last)
}

func dialADB() (gadb.Client, error) {
	return gadb.NewClientWith("127.0.0.1", gadb.AdbServerPort)
}

func startADBServer() error {
	exe := findADB()
	if exe == "" {
		return fmt.Errorf("找不到 adb，无法启动本机 ADB 服务")
	}
	debugLogf("starting adb server with %s\n", exe)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "start-server")
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("adb start-server 失败: %w", err)
	}
	return nil
}

func findADB() string {
	name := "adb"
	if runtime.GOOS == "windows" {
		name = "adb.exe"
	}
	var candidates []string
	if p, err := exec.LookPath(name); err == nil {
		candidates = append(candidates, p)
	}
	for _, env := range []string{"ANDROID_HOME", "ANDROID_SDK_ROOT"} {
		if v := os.Getenv(env); v != "" {
			candidates = append(candidates, filepath.Join(v, "platform-tools", name))
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		local := os.Getenv("LOCALAPPDATA")
		if local == "" {
			local = filepath.Join(home, "AppData", "Local")
		}
		candidates = append(candidates,
			filepath.Join(local, "Android", "Sdk", "platform-tools", name),
			filepath.Join(home, "AppData", "Local", "Android", "Sdk", "platform-tools", name),
			filepath.Join(home, "Android", "Sdk", "platform-tools", name),
			filepath.Join(home, "Library", "Android", "sdk", "platform-tools", name),
		)
	}
	return firstExistingFile(candidates...)
}

func firstExistingFile(paths ...string) string {
	seen := make(map[string]bool, len(paths))
	for _, path := range paths {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

// selectDevice picks a device from the ADB server. An empty serial is
// accepted only when exactly one device is connected.
func selectDevice(serial string) (gadb.Device, error) {
	devices, err := listADBDevices()
	if err != nil {
		return gadb.Device{}, err
	}

	serial = strings.TrimSpace(serial)
	if serial != "" {
		for _, dev := range devices {
			if dev.Serial() == serial {
				return dev, nil
			}
		}
		return gadb.Device{}, fmt.Errorf("未找到序列号为 %s 的 ADB 设备", serial)
	}
	switch len(devices) {
	case 0:
		return gadb.Device{}, fmt.Errorf("没有已连接的 ADB 设备")
	case 1:
		return devices[0], nil
	default:
		return gadb.Device{}, fmt.Errorf("连接了多台设备，请传入 serial")
	}
}

// adbHostCommand sends a device-scoped ADB host command ("root:",
// "reboot:", ...) over the ADB server protocol. root: and reboot: are
// fire-and-forget: adbd often closes right after OKAY, so bytes read
// after that are best-effort status text.
func adbHostCommand(serial, service string) (string, error) {
	rest, err := adbExchange(serial, service, adbCommandDeadline, false)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(rest)), nil
}

// adbExecOut runs a device command the way `adb exec-out` does, returning
// the raw stdout. Screenshot uses this so PNG bytes are not CRLF-translated.
func adbExecOut(serial, command string) ([]byte, error) {
	return adbExchange(serial, "exec:"+command, adbScreenshotDeadline, true)
}

func adbExchange(serial, service string, deadline time.Duration, strictBody bool) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", adbServerAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("连接 ADB 服务 %s 失败: %w", adbServerAddr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(deadline))

	if err := adbSend(conn, fmt.Sprintf("host:transport:%s", serial)); err != nil {
		return nil, err
	}
	if err := adbCheckOKAY(conn); err != nil {
		return nil, fmt.Errorf("选择设备 %s 失败: %w", serial, err)
	}

	if err := adbSend(conn, service); err != nil {
		return nil, err
	}
	if err := adbCheckOKAY(conn); err != nil {
		return nil, err
	}

	rest, err := io.ReadAll(conn)
	if strictBody && err != nil {
		return nil, fmt.Errorf("读取 ADB 响应失败: %w", err)
	}
	return rest, nil
}

func adbSend(conn net.Conn, command string) error {
	msg := fmt.Sprintf("%04x%s", len(command), command)
	_, err := conn.Write([]byte(msg))
	if err != nil {
		return fmt.Errorf("发送 ADB 命令失败: %w", err)
	}
	return nil
}

func adbCheckOKAY(conn net.Conn) error {
	status, err := readExact(conn, 4)
	if err != nil {
		return err
	}
	if string(status) == "OKAY" {
		return nil
	}
	lenBuf, err := readExact(conn, 4)
	if err != nil {
		return fmt.Errorf("adb %s (no error detail: %v)", status, err)
	}
	size, err := strconv.ParseInt(string(lenBuf), 16, 64)
	if err != nil {
		return fmt.Errorf("adb %s", status)
	}
	msg, err := readExact(conn, int(size))
	if err != nil {
		return fmt.Errorf("adb %s: %s", status, msg)
	}
	return fmt.Errorf("adb %s: %s", status, strings.TrimSpace(string(msg)))
}

func readExact(conn net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

// rootResult interprets the payload of the root: service. "cannot run as
// root" is a failure even though the socket status is OKAY. A restarting
// adbd needs the same pause the adb client waits before returning.
func rootResult(ctx context.Context, message string) (string, error) {
	message = strings.TrimSpace(message)
	if strings.Contains(strings.ToLower(message), "cannot run as root") {
		return "", fmt.Errorf("adb root 失败: %s", message)
	}
	if message == "" || strings.Contains(message, "restarting") {
		timer := time.NewTimer(adbRootRestartWait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
	return message, nil
}

// androidPushFile uploads a local file to the Android device via ADB.
func androidPushFile(localPath, remotePath string) (string, error) {
	debugLogf("androidPushFile: local=%s, remote=%s\n", localPath, remotePath)

	devices, err := listADBDevices()
	if err != nil || len(devices) == 0 {
		return "", fmt.Errorf("file transfer requires an ADB-connected device (no device found)")
	}

	f, err := os.Open(localPath)
	if err != nil {
		return "", fmt.Errorf("cannot open local file: %w", err)
	}
	defer f.Close()

	dev := devices[0]
	if err := dev.PushFile(f, remotePath); err != nil {
		return "", fmt.Errorf("push failed: %w", err)
	}
	return fmt.Sprintf("pushed %s -> %s", localPath, remotePath), nil
}

// androidPullFile downloads a file from the Android device to local via ADB.
func androidPullFile(remotePath, localPath string) (string, error) {
	debugLogf("androidPullFile: remote=%s, local=%s\n", remotePath, localPath)

	devices, err := listADBDevices()
	if err != nil || len(devices) == 0 {
		return "", fmt.Errorf("file transfer requires an ADB-connected device (no device found)")
	}

	f, err := os.Create(localPath)
	if err != nil {
		return "", fmt.Errorf("cannot create local file: %w", err)
	}
	defer f.Close()

	dev := devices[0]
	if err := dev.Pull(remotePath, f); err != nil {
		return "", fmt.Errorf("pull failed: %w", err)
	}
	return fmt.Sprintf("pulled %s -> %s", remotePath, localPath), nil
}

// wrapBackgroundCommand detects commands intended to run in the background
// (trailing &) and wraps them so the process survives the ADB shell PTY
// closing.  ADB shell runs via a PTY: when it closes, the kernel sends
// SIGHUP to the session, killing background children.  Plain nohup is not
// sufficient on Android because the PTY file-descriptor stays open, keeping
// the ADB connection alive and causing timeouts.  setsid creates a new
// session, fully detaching from the controlling PTY.  sh -c + sleep 1 is
// required to avoid a race: without the sleep, the ADB shell exits
// immediately after the background fork, closing the PTY before setsid has
// finished its setsid(2) call to join a new session.
func wrapBackgroundCommand(command string) string {
	trimmed := strings.TrimSpace(command)
	if !strings.HasSuffix(trimmed, "&") {
		return command
	}
	// Strip trailing "&"; extract the inner command, removing any existing
	// wrapper we may have added on a previous pass (idempotent).
	inner := strings.TrimSpace(strings.TrimSuffix(trimmed, "&"))
	// If already wrapped, don't double-wrap.
	if strings.HasPrefix(inner, "setsid ") || strings.HasPrefix(inner, "nohup ") ||
		strings.HasPrefix(inner, "sh -c 'setsid ") {
		return command
	}
	return "sh -c 'setsid " + inner + " </dev/null >/dev/null 2>&1 & sleep 1'"
}

func executeAndroidCommands(command string, sleepSeconds int) (string, error) {
	debugLogf("executeAndroidCommands: command=%s, sleepSeconds=%d\n", command, sleepSeconds)

	devices, err := listADBDevices()
	if err != nil {
		return "", fmt.Errorf("failed to list ADB devices: %w; use the serial fallback if needed", err)
	}
	if len(devices) == 0 {
		return "", fmt.Errorf("no ADB device connected; use the serial fallback if needed")
	}
	dev := devices[0]

	// Wrap background commands with nohup and output redirection.
	// ADB shell uses a PTY: when the shell exits, SIGHUP kills background
	// processes.  nohup prevents that, and redirecting stdout/stderr avoids
	// the PTY file-descriptor keeping the ADB connection open indefinitely.
	adbCommand := wrapBackgroundCommand(command)
	debugLogf("executeAndroidCommands: adbCommand=%s\n", adbCommand)

	shellOutput, err := dev.RunShellCommand(adbCommand, "")
	shellOutput = truncateString(shellOutput, 20000)
	checkErr(err, "RunShellCommand")
	return shellOutput, err
}

// executeAndroidCommandsFallback uses serial port instead of SSH
func executeAndroidCommandsFallback(command string, sleepSeconds int) (string, error) {
	debugLogf("executeAndroidCommandsFallback: command=%s, sleepSeconds=%d\n", command, sleepSeconds)
	serialPortName = autoDetectSerialPort()
	result, err := executeSerialCommands(serialPortName,
		[]string{"dtach -a /tmp/android", "su", command},
		true, sleepSeconds)
	if err != nil {
		return "", fmt.Errorf("execution failed: %w", err)
	}
	return result, nil
}

func executeQNXCommands(command string, sleepSeconds int) (string, error) {
	debugLogf("executeQNXCommands: command=%s, sleepSeconds=%d\n", command, sleepSeconds)
	devices, err := listADBDevices()
	if err != nil {
		return "", fmt.Errorf("failed to list ADB devices: %w; use the serial fallback if needed", err)
	}
	if len(devices) == 0 {
		return "", fmt.Errorf("no ADB device connected; use the serial fallback if needed")
	}
	dev := devices[0]
	binDir := qnxBinDir(command)
	commandString := "dbclient -o StrictHostKeyChecking=no root@192.168.1.1 \"" + binDir + "/" + command + "\""
	shellOutput, err := dev.RunShellCommand(commandString, "")
	shellOutput = truncateString(shellOutput, 20000)
	checkErr(err, "RunShellCommand")
	return shellOutput, err
}

// executeQNXCommandsFallback uses serial port instead of SSH
func executeQNXCommandsFallback(command string, sleepSeconds int) (string, error) {
	debugLogf("executeQNXCommandsFallback: command=%s, sleepSeconds=%d\n", command, sleepSeconds)
	serialPortName = autoDetectSerialPort()
	result, err := executeSerialCommands(serialPortName,
		[]string{command},
		false, sleepSeconds)
	if err != nil {
		return "", fmt.Errorf("execution failed: %w", err)
	}
	return result, nil
}

// executeSerialCommands opens a serial port and executes commands
func executeSerialCommands(portName string, commands []string, ctrl_z bool, sleepSeconds int) (string, error) {
	debugLogf("executeSerialCommands: port=%s, ctrl_z=%v, sleepSeconds=%d\n", portName, ctrl_z, sleepSeconds)
	debugLogf("command count: %d, list: %v\n", len(commands), commands)

	if portName == "" {
		return "", fmt.Errorf("系统当前没有连接串口！！")
	}

	serialMutex.Lock()
	defer serialMutex.Unlock()
	debugLog("serial mutex acquired")

	// 1. open serial port
	debugLogf("opening serial port: %s\n", portName)
	mode := &serial.Mode{
		BaudRate: 921600,
		DataBits: 8,
		StopBits: serial.OneStopBit,
		Parity:   serial.NoParity,
	}
	port, err := serial.Open(portName, mode)
	if err != nil {
		return "", fmt.Errorf("can't open serial port: %w", err)
	}
	debugLog("serial port opened")
	defer func() {
		port.Close()
		debugLog("serial port closed")
	}()

	// 2. set short read timeout for prompt detection
	port.SetReadTimeout(500 * time.Millisecond)

	_, err = port.Write([]byte{'\x03'})
	// 3. execute commands
	debugLog("executing commands via serial")
	var outputBuf bytes.Buffer
	for i, cmd := range commands {
		debugLogf("executing %d/%d: %s\n", i+1, len(commands), cmd)
		_, err := port.Write([]byte(cmd + "\n"))
		if err != nil {
			return "", fmt.Errorf("write command failed: %w", err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	if ctrl_z {
		debugLog("sending Ctrl+Z")
		_, err := port.Write([]byte{'\x1a'})
		if err != nil {
			// silently handle Ctrl+Z error
		}
	}

	// 4. read output: read until no more data or deadline reached
	debugLogf("reading output (deadline: %d seconds)\n", sleepSeconds)
	deadline := time.Now().Add(time.Duration(sleepSeconds) * time.Second)
	buf := make([]byte, 4096)
	noDataCount := 0
	for time.Now().Before(deadline) {
		n, err := port.Read(buf)
		if err != nil {
			noDataCount++
			if noDataCount >= 3 {
				break // 3 consecutive timeouts, assume output is done
			}
			continue
		}
		if n > 0 {
			noDataCount = 0
			outputBuf.Write(buf[:n])
		}
	}

	currentOutput := outputBuf.String()
	debugLogf("current output length: %d bytes\n", len(currentOutput))
	if len(currentOutput) > 0 {
		debugLogf("output preview (first 500 chars):\n%s\n", truncateString(currentOutput, 500))
	} else {
		debugLog("warning: no output captured!")
	}

	// 5. return result
	finalOutput := truncateString(currentOutput, 20000)
	debugLogf("final output length: %d bytes\n", len(finalOutput))
	return finalOutput, nil
}

// saveResultToFile saves result to file
func saveResultToFile(result, file string) error {
	localFilePath := file
	debugLogf("saving result to file: %s\n", localFilePath)

	f, err := os.Create(localFilePath)
	if err != nil {
		return fmt.Errorf("create local file failed: %w", err)
	}
	defer f.Close()

	bytesWritten, err := f.WriteString(result)
	if err != nil {
		return fmt.Errorf("write file failed: %w", err)
	}
	debugLogf("bytes written: %d\n", bytesWritten)

	debugLog("file saved")
	return nil
}

// debugLog prints debug log only when debugEnabled is true
func debugLog(msg string) {
	if debugEnabled {
		log.Println("[DEBUG] " + msg)
	}
}

// debugLogf prints formatted debug log only when debugEnabled is true
func debugLogf(format string, args ...interface{}) {
	if debugEnabled {
		log.Printf("[DEBUG] "+format, args...)
	}
}

// truncateString truncates string to maxLen
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...(truncated)"
}
