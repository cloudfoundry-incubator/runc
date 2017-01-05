// +build linux

package libcontainer

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/opencontainers/runc/libcontainer/apparmor"
	"github.com/opencontainers/runc/libcontainer/keys"
	"github.com/opencontainers/runc/libcontainer/label"
	"github.com/opencontainers/runc/libcontainer/seccomp"
	"github.com/opencontainers/runc/libcontainer/system"
)

// linuxSetnsInit performs the container's initialization for running a new process
// inside an existing container.
type linuxSetnsInit struct {
	pipe   *os.File
	config *initConfig
}

func (l *linuxSetnsInit) getSessionRingName() string {
	return fmt.Sprintf("_ses.%s", l.config.ContainerId)
}

func (l *linuxSetnsInit) Init() error {
	if !l.config.Config.NoNewKeyring {
		// do not inherit the parent's session keyring
		if _, err := keys.JoinSessionKeyring(l.getSessionRingName()); err != nil {
			return err
		}
	}
	if l.config.CreateConsole {
		if err := setupConsole(l.pipe, l.config, false); err != nil {
			return err
		}
		if err := system.Setctty(); err != nil {
			return err
		}
	}
	if l.config.NoNewPrivileges {
		if err := system.Prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return err
		}
	}
	if l.config.Config.Seccomp != nil {
		if err := seccomp.InitSeccomp(l.config.Config.Seccomp); err != nil {
			return err
		}
	}
	if err := finalizeNamespace(l.config); err != nil {
		return err
	}
	if err := apparmor.ApplyProfile(l.config.AppArmorProfile); err != nil {
		return err
	}
	if err := label.SetProcessLabel(l.config.ProcessLabel); err != nil {
		return err
	}

	stdoutFd := os.Getenv("STDOUT_FD")
	if len(stdoutFd) > 0 {
		outFd, _ := strconv.Atoi(stdoutFd)
		syscall.Dup2(1, outFd)
	}

	stderrFd := os.Getenv("STDERR_FD")
	if len(stderrFd) > 0 {
		println("errorFD: ", stderrFd)
		errFd, err := strconv.Atoi(stderrFd)
		if err != nil {
			println("ERRRRRRRRRRRRR1", err.Error())
		}
		err = syscall.Dup2(errFd, 2)
		if err != nil {
			println("ERRRRRRRRRRRRR2", err.Error())
		}
	}

	return system.Execv(l.config.Args[0], l.config.Args[0:], os.Environ())
}
