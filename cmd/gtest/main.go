package main

import "github.com/gluster/gogfapi/gfapi"

func main() {
	vol := &gfapi.Volume{}
	if err := vol.Init("testvol", "localhost"); err != nil {
		// handle error
	}

	if err := vol.Mount(); err != nil {
		// handle error
	}
	defer vol.Unmount()

	f, err := vol.Create("testfile")
	if err != nil {
		// handle error
	}
	defer f.Close()

	if _, err := f.Write([]byte("hello")); err != nil {
		// handle error
	}

	return
}
