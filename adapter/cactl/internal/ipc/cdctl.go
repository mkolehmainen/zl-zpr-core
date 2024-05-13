package ipc

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

type CDCtl struct {
	socketPath string
}

type CDResponse struct {
	IsError bool
	lines   []string
}

func NewCDCtl(socketPath string) (*CDCtl, error) {
	cdc := &CDCtl{
		socketPath: socketPath,
	}
	if _, err := os.Stat(cdc.socketPath); errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("cd socket not found")
	}
	return cdc, nil
}

func NewCDResponse(isError bool, lines []string) *CDResponse {
	return &CDResponse{
		IsError: isError,
		lines:   lines,
	}
}

func (cdr *CDResponse) Message() string {
	return strings.Join(cdr.lines, "\n")
}

func (cdc *CDCtl) Status() (*CDResponse, error) {
	return cdc.cactlToResp("status\n")
}

func (cdc *CDCtl) Connect(configPath string) (*CDResponse, error) {
	return cdc.cactlToResp(fmt.Sprintf("connect %s\n", configPath))
}

func (cdc *CDCtl) Disconnect(configName string) (*CDResponse, error) {
	if configName == "" {
		return cdc.cactlToResp("disconnect\n")
	} else {
		return cdc.cactlToResp(fmt.Sprintf("disconnect %s\n", configName))
	}
}

func (cdc *CDCtl) dial() (net.Conn, error) {
	return net.Dial("unix", cdc.socketPath)
}

// Send command message to the control socket, parse response.
func (cdc *CDCtl) cactlToResp(cmd string) (*CDResponse, error) {
	var buf bytes.Buffer
	if err := cdc.cactlToBuffer(cmd, &buf); err != nil {
		return nil, err
	}
	var results []string
	scanner := bufio.NewScanner(strings.NewReader(buf.String()))
	lineno := 0
	expect := 1
	isError := false
	for scanner.Scan() {
		line := scanner.Text()
		lineno++
		// fmt.Printf("%d ) >> '%s'\n", lineno, line)
		switch lineno {
		case 1:
			if n, err := strconv.Atoi(line); err == nil {
				expect = n
			} else {
				// A badly formatted response or some other bug
				return nil, fmt.Errorf("failed to parse header from CD response, expected interger got '%v'", line)
			}
		case 2:
			isError = strings.HasPrefix(line, "ERR")
		default:
			results = append(results, strings.TrimSpace(line))
		}
		if lineno > (expect + 1) {
			break
		}
	}
	return NewCDResponse(isError, results), nil
}

// cactlToBuffer open connection to control socket, run the command, copy all result
// data into the supplied buffer.
func (cdc *CDCtl) cactlToBuffer(cmd string, bufp *bytes.Buffer) error {
	con, err := cdc.dial()
	if err != nil {
		return err
	}
	defer con.Close()
	if err := writeAll(con, cmd); err != nil {
		return err
	}
	_, err = io.Copy(bufp, con)
	if err != nil {
		return err
	}
	return nil
}

func writeAll(conn net.Conn, msg string) error {
	bw := bufio.NewWriter(conn)
	bw.WriteString(msg)
	bw.WriteString("\n")
	return bw.Flush()
}
