package libcontainer

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// Console represents a pseudo TTY.
type Console interface {
	io.ReadWriter
	io.Closer

	// Path returns the filesystem path to the slave side of the pty.
	Path() string

	// Fd returns the fd for the master of the pty.
	File() *os.File
}

const (
	TerminalInfoVersion = 1
	TerminalInfoType    = "terminal"
)

// TerminalInfo is the structure which is passed as the nonancilliary data
// in the sendmsg(2) call when runc is run with --console-socket. It
// contains some information about the container which the console master fd
// relates to (to allow for consumers to use a single unix socket to handle
// multiple containers). This structure will probably move to runtime-spec
// at some point. But for now it lies in libcontainer.
type TerminalInfo struct {
	// Version of the API.
	Version int `json:"version"`

	// Type of message (future proofing).
	Type string `json:"type"`

	// Container contains the ID of the container.
	Container string `json:"container"`
}

func (ti *TerminalInfo) String() string {
	encoded, err := json.Marshal(*ti)
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(encoded))
}

func NewTerminalInfo(container string) *TerminalInfo {
	return &TerminalInfo{
		Version:   TerminalInfoVersion,
		Type:      TerminalInfoType,
		Container: container,
	}
}

func GetTerminalInfo(encoded string) (*TerminalInfo, error) {
	ti := new(TerminalInfo)
	if err := json.Unmarshal([]byte(encoded), ti); err != nil {
		return nil, err
	}

	if ti.Type != TerminalInfoType {
		return nil, fmt.Errorf("terminal info: incorrect type in payload (%s): %s", TerminalInfoType, ti.Type)
	}
	if ti.Version != TerminalInfoVersion {
		return nil, fmt.Errorf("terminal info: incorrect version in payload (%d): %d", TerminalInfoVersion, ti.Version)
	}

	return ti, nil
}
