package cn2

import (
	"context"
	"fmt"

	"github.com/containers/buildah/imagebuildah"
	"github.com/containers/podman/v2/pkg/bindings"
	"github.com/containers/podman/v2/pkg/bindings/images"
	"github.com/containers/podman/v2/pkg/domain/entities"
)

type CN2 struct {
}

func (c *CN2) UploadISO(path string) error {
	return nil
}

func buildContainerImage(path string) error {
	socket := "ssh://10.87.64.31/run/user/1000/podman/podman.socket"
	ctx, err := bindings.NewConnection(context.Background(), socket)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer ctx.Done()
	buildOptions := imagebuildah.BuildOptions{
		ContextDirectory: path,
	}
	images.Build(ctx, []string{path}, entities.BuildOptions{
		BuildOptions: imagebuildah.BuildOptions{
			ContextDirectory: path,
		},
	})
	return nil
}
