package scanner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// procSpec describes one subprocess (no shell, argv as an array).
type procSpec struct {
	bin    string
	args   []string
	env    []string
	dir    string
	grace  time.Duration
	maxOut int
}

type procResult struct {
	exitCode int // -1 when killed by a signal or not started
	stdout   string
	stderr   string
	notFound bool
}

// runProc runs a subprocess in its own process group. Cancelling ctx sends
// SIGTERM to the whole group and SIGKILL after the grace period.
func runProc(ctx context.Context, sp procSpec) procResult {
	cmd := exec.CommandContext(ctx, sp.bin, sp.args...)
	cmd.Env = sp.env
	cmd.Dir = sp.dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, errb := &limitedBuffer{max: sp.maxOut}, &limitedBuffer{max: sp.maxOut}
	cmd.Stdout, cmd.Stderr = out, errb
	var killTimer *time.Timer
	cmd.Cancel = func() error {
		pid := cmd.Process.Pid
		err := syscall.Kill(-pid, syscall.SIGTERM)
		killTimer = time.AfterFunc(sp.grace, func() { _ = syscall.Kill(-pid, syscall.SIGKILL) })
		return err
	}
	cmd.WaitDelay = sp.grace + time.Second
	err := cmd.Run()
	if killTimer != nil {
		killTimer.Stop()
	}
	// Make sure no stray children of the group survive.
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	res := procResult{stdout: out.String(), stderr: errb.String()}
	if err == nil {
		return res
	}
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		res.exitCode = ee.ExitCode() // -1 for signals
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, os.ErrNotExist), errors.Is(err, syscall.ENOENT), errors.Is(err, syscall.EACCES):
		res.exitCode, res.notFound = -1, true
	default:
		res.exitCode = -1
		if strings.Contains(err.Error(), "no such file") {
			res.notFound = true
		}
	}
	return res
}
