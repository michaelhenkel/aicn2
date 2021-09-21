package cn2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/michaelhenkel/aicn2/pkg/infrastructure"
	"github.com/michaelhenkel/aicn2/pkg/k8s"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
)

type CN2 struct {
}

func (c *CN2) PrepareStorage(image infrastructure.Image) error {
	if err := createGlusterFSVolumes(image.Name); err != nil {
		return err
	}
	if _, err := fileCopy(image.Path, fmt.Sprintf("/tmp/%s-iso/disk.img", image.Name)); err != nil {
		return err
	}

	if err := createPVandPVC(image.Name); err != nil {
		return err
	}
	return nil
}

func (c *CN2) DeleteISO(image infrastructure.Image) error {
	if err := deleteGlusterFSVolumes(image.Name); err != nil {
		return err
	}
	return nil
}

func createPVandPVC(name string) error {
	client, err := k8s.NewClient()
	if err != nil {
		return err
	}

	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	if _, err := client.K8S.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}

	isoPV := &v1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-iso", name),
			Namespace: name,
		},
		Spec: v1.PersistentVolumeSpec{
			Capacity: v1.ResourceList{
				"storage": *resource.NewQuantity(2, resource.Format("Gi")),
			},
			AccessModes: []v1.PersistentVolumeAccessMode{"ReadWriteMany"},
			PersistentVolumeSource: v1.PersistentVolumeSource{
				Glusterfs: &v1.GlusterfsPersistentVolumeSource{
					ReadOnly:      false,
					EndpointsName: "glusterfs-cluster",
					Path:          fmt.Sprintf("%s-iso", name),
				},
			},
		},
	}
	if _, err := client.K8S.CoreV1().PersistentVolumes().Create(context.Background(), isoPV, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}

	isoPVC := &v1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-iso", name),
			Namespace: name,
		},
		Spec: v1.PersistentVolumeClaimSpec{
			AccessModes: []v1.PersistentVolumeAccessMode{"ReadWriteMany"},
			Resources: v1.ResourceRequirements{
				Requests: v1.ResourceList{
					"storage": *resource.NewQuantity(2, resource.Format("Gi")),
				},
			},
		},
	}
	if _, err := client.K8S.CoreV1().PersistentVolumeClaims(name).Create(context.Background(), isoPVC, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}

	diskPV := &v1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-disk", name),
			Namespace: name,
		},
		Spec: v1.PersistentVolumeSpec{
			Capacity: v1.ResourceList{
				"storage": *resource.NewQuantity(120, resource.Format("Gi")),
			},
			AccessModes: []v1.PersistentVolumeAccessMode{"ReadWriteMany"},
			PersistentVolumeSource: v1.PersistentVolumeSource{
				Glusterfs: &v1.GlusterfsPersistentVolumeSource{
					ReadOnly:      false,
					EndpointsName: "glusterfs-cluster",
					Path:          fmt.Sprintf("%s-disk", name),
				},
			},
		},
	}
	if _, err := client.K8S.CoreV1().PersistentVolumes().Create(context.Background(), diskPV, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}

	diskPVC := &v1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-disk", name),
			Namespace: name,
		},
		Spec: v1.PersistentVolumeClaimSpec{
			AccessModes: []v1.PersistentVolumeAccessMode{"ReadWriteMany"},
			Resources: v1.ResourceRequirements{
				Requests: v1.ResourceList{
					"storage": *resource.NewQuantity(120, resource.Format("Gi")),
				},
			},
		},
	}
	if _, err := client.K8S.CoreV1().PersistentVolumeClaims(name).Create(context.Background(), diskPVC, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}
	return nil
}

func createGlusterFSVolumes(name string) error {
	isoVolumeCreateCommandString := fmt.Sprintf("gluster volume create %s-iso 5b3s30.cluster1.local:/glusterfs/%s-iso", name, name)
	stderr, err := runSudo(isoVolumeCreateCommandString, "")
	if err != nil {
		klog.Error(stderr.String(), isoVolumeCreateCommandString)
		return err
	}

	isoVolumeStartCommandString := fmt.Sprintf("gluster volume start %s-iso", name)
	stderr, err = runSudo(isoVolumeStartCommandString, "")
	if err != nil {
		klog.Error(stderr.String())
		return err
	}

	isoVolumeMountCommandString := fmt.Sprintf("mount -t glusterfs 5b3s30:/%s-iso /tmp/%s-iso", name, name)
	stderr, err = runSudo(isoVolumeMountCommandString, "")
	if err != nil {
		klog.Error(stderr.String())
		return err
	}

	stderr, err = runSudo(fmt.Sprintf("chmod 777 /tmp/%s-iso", name), "")
	if err != nil {
		klog.Error(stderr.String())
		return err
	}

	diskVolumeCreateCommandString := fmt.Sprintf("gluster volume create %s-disk 5b3s30.cluster1.local:/glusterfs/%s-disk", name, name)
	stderr, err = runSudo(diskVolumeCreateCommandString, "")
	if err != nil {
		klog.Error(stderr.String(), diskVolumeCreateCommandString)
		return err
	}

	diskVolumeStartCommandString := fmt.Sprintf("gluster volume start %s-disk", name)
	stderr, err = runSudo(diskVolumeStartCommandString, "")
	if err != nil {
		klog.Error(stderr.String())
		return err
	}

	return nil
}

func fileCopy(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

func deleteGlusterFSVolumes(name string) error {
	stderr, err := runSudo(fmt.Sprintf("umount /tmp/%s-iso", name), "")
	if err != nil {
		klog.Error(stderr.String())
		return err
	}

	stderr, err = runSudo(fmt.Sprintf("gluster volume stop %s-iso", name), "y")
	if err != nil {
		klog.Error(stderr.String())
		return err
	}

	stderr, err = runSudo(fmt.Sprintf("gluster volume delete %s-iso", name), "y")
	if err != nil {
		klog.Error(stderr.String())
		return err
	}

	stderr, err = runSudo(fmt.Sprintf("rm -rf /glusterfs/%s-iso", name), "")
	if err != nil {
		klog.Error(stderr.String())
		return err
	}

	stderr, err = runSudo(fmt.Sprintf("gluster volume stop %s-disk", name), "y")
	if err != nil {
		klog.Error(stderr.String())
		return err
	}

	stderr, err = runSudo(fmt.Sprintf("gluster volume delete %s-disk", name), "y")
	if err != nil {
		klog.Error(stderr.String())
		return err
	}

	stderr, err = runSudo(fmt.Sprintf("rm -rf /glusterfs/%s-disk", name), "")
	if err != nil {
		klog.Error(stderr.String())
		return err
	}

	return nil
}

func runSudo(command, input string) (bytes.Buffer, error) {
	var outb, errb bytes.Buffer
	commandList := strings.Split(command, " ")
	cmd := exec.Command("sudo", commandList...)
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
	if input != "" {
		_, err := io.WriteString(stdin, fmt.Sprintf("%s\n", input))
		if err != nil {
			return errb, err
		}
	}
	if err := cmd.Wait(); err != nil {
		return errb, err
	}
	return outb, nil
}
