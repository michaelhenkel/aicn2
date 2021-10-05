package container

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os/exec"
	"strings"

	"github.com/docker/docker/client"
	"k8s.io/klog"
)

type ErrorLine struct {
	Error       string      `json:"error"`
	ErrorDetail ErrorDetail `json:"errorDetail"`
}

type ErrorDetail struct {
	Message string `json:"message"`
}

type containerImage struct {
	Name     string
	Registry string
	Path     string
	client   *client.Client
}

func NewContainerImage(name, registry, path string) (*containerImage, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		klog.Error(err)
		return nil, err
	}
	ci := &containerImage{
		Name:     name,
		Registry: registry,
		Path:     path,
		client:   cli,
	}
	return ci, nil
}

func (c *containerImage) BuildBaseImage() error {
	dockerfileContent := `FROM scratch
ADD --chown=107:107 disk.img /disk/`
	dockerfileLocation := fmt.Sprintf("%s/Dockerfile", c.Path)
	if err := ioutil.WriteFile(dockerfileLocation, []byte(dockerfileContent), 0660); err != nil {
		return err
	}

	buildCmd := fmt.Sprintf("docker build -t %s/%s -f %s %s", c.Registry, c.Name, dockerfileLocation, c.Path)
	stderr, err := runCmd(buildCmd)
	if err != nil {
		klog.Error(stderr.String(), buildCmd, err)
		return err
	}
	pushCmd := fmt.Sprintf("docker push %s/%s", c.Registry, c.Name)
	stderr, err = runCmd(pushCmd)
	if err != nil {
		klog.Error(stderr.String(), pushCmd, err)
		return err
	}
	return nil
}

func runCmd(command string) (bytes.Buffer, error) {
	var outb, errb bytes.Buffer
	commandList := strings.Split(command, " ")
	commandArgs := commandList[1:]
	cmd := exec.Command(commandList[0], commandArgs...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return errb, err
	}
	defer stdin.Close()

	cmd.Stdout = &outb
	cmd.Stderr = &errb

	if err := cmd.Start(); err != nil {
		return errb, err
	}
	if err := cmd.Wait(); err != nil {
		return errb, err
	}
	return outb, nil
}
