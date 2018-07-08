package policy

import (
	"os"
	"os/exec"
	"strings"

	"github.com/rancher/log"
)

func execCmdNoStdoutNoStderr(cmd *exec.Cmd) error {
	log.Debugf("cmd: %+v", cmd)
	cmd.Stdout = nil
	cmd.Stderr = nil
	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func execCmdNoStderr(cmd *exec.Cmd) error {
	log.Debugf("cmd: %+v", cmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = nil
	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func execCmd(cmd *exec.Cmd) error {
	log.Debugf("cmd: %+v", cmd)
	cmdOutput, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorf("err: %v, cmdOut=%v", err, string(cmdOutput))
		return err
	}

	return nil
}

func buildCommand(cmdStr string) *exec.Cmd {
	cmd := strings.Split(strings.TrimSpace(cmdStr), " ")
	return exec.Command(cmd[0], cmd[1:]...)
}

func executeCommandNoStderr(cmdStr string) error {
	cmd := buildCommand(cmdStr)
	return execCmdNoStderr(cmd)
}

func executeCommandNoStdoutNoStderr(cmdStr string) error {
	cmd := buildCommand(cmdStr)
	return execCmdNoStdoutNoStderr(cmd)
}

func executeCommand(cmdStr string) error {
	cmd := buildCommand(cmdStr)
	return execCmd(cmd)
}
