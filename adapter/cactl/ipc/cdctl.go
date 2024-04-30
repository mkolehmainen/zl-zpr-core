package ipc

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"strings"
)

type CDCtl struct {
	socketPath string
}

type CDResponse struct {
	IsError bool
	Message string
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

func CDResponseFromLines(lines []string) (*CDResponse, error) {
	if len(lines) == 0 {
		return nil, errors.New("empt response from CD")
	}
	cdr := new(CDResponse)
	cdr.IsError = strings.HasPrefix(lines[0], "ERR")

	// Obviously the response contents will get more complicated.
	cdr.Message = strings.Join(lines, "\n")
	return cdr, nil
}

func (cdc *CDCtl) Status() (*CDResponse, error) {
	lines, err := cdc.cactlToStrs("status\n")
	if err != nil {
		return nil, err
	}
	return CDResponseFromLines(lines)
}

func (cdc *CDCtl) dial() (net.Conn, error) {
	return net.Dial("unix", cdc.socketPath)
}

// cactlToStrs runs a command that is expected to run, spit out some text and then close the
// connection.  The text returned from the adapter is returned in the string array (minus the OK n)
// line for some reason.
func (cdc *CDCtl) cactlToStrs(cmd string) ([]string, error) {
	var buf bytes.Buffer
	if err := cdc.cactlToBuffer(cmd, &buf); err != nil {
		return nil, err
	}
	var results []string
	scanner := bufio.NewScanner(strings.NewReader(buf.String()))
	for scanner.Scan() {
		line := scanner.Text()
		results = append(results, strings.TrimSpace(line))
	}
	return results, nil
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
