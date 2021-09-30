package cn2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/michaelhenkel/aicn2/pkg/infrastructure"
	"github.com/michaelhenkel/aicn2/pkg/k8s"
	"github.com/txn2/txeh"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"

	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
	kubevirtV1 "kubevirt.io/client-go/api/v1"
)

type CN2 struct {
	Client *k8s.Client
}

func New() (*CN2, error) {
	client, err := k8s.NewClient()
	if err != nil {
		return nil, err
	}
	return &CN2{
		Client: client,
	}, nil
}

func (c *CN2) GetClusterDomain(name string) (string, error) {
	cm, err := c.Client.K8S.CoreV1().ConfigMaps("kube-system").Get(context.Background(), "kubeadm-config", metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	clusterConfig, ok := cm.Data["ClusterConfiguration"]
	if !ok {
		return "", fmt.Errorf("cluster config not found")
	}

	var cc struct {
		ClusterName string `yaml:"clusterName"`
	}
	if err := yaml.Unmarshal([]byte(clusterConfig), &cc); err != nil {
		return "", err
	}
	if cc.ClusterName == "" {
		return "", fmt.Errorf("cluster name empty")
	}
	return fmt.Sprintf("svc.%s", cc.ClusterName), nil
}

func (c *CN2) CreateVN(name, subnet string) error {
	if _, err := c.Client.Nad.K8sCniCncfIoV1().NetworkAttachmentDefinitions(name).Get(context.Background(), name, metav1.GetOptions{}); err != nil {
		if errors.IsNotFound(err) {
			nad := &nadv1.NetworkAttachmentDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: name,
					Annotations: map[string]string{
						"juniper.net/networks": fmt.Sprintf(`{"ipamV4Subnet": "%s","fabricSNAT": true}`, subnet),
					},
				},
				Spec: nadv1.NetworkAttachmentDefinitionSpec{
					Config: `{"cniVersion": "0.3.1","name": "contrail-k8s-cni",	"type": "contrail-k8s-cni"}`,
				},
			}
			_, err = c.Client.Nad.K8sCniCncfIoV1().NetworkAttachmentDefinitions(name).Create(context.Background(), nad, metav1.CreateOptions{})
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}

	return nil
}

func (c *CN2) DeleteVN(name string) error {
	return nil
}

func (c *CN2) CreateDNSLB(name, domain string) error {
	apiSvc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api",
			Namespace: name,
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{{
				Name:     "api",
				Port:     6443,
				Protocol: "TCP",
				TargetPort: intstr.IntOrString{
					IntVal: 6443,
				},
			}, {
				Name:     "machine",
				Port:     22623,
				Protocol: "TCP",
				TargetPort: intstr.IntOrString{
					IntVal: 22623,
				},
			}},
			Selector: map[string]string{"occluster": name, "role": "controller"},
		},
	}
	if _, err := c.Client.K8S.CoreV1().Services(name).Create(context.Background(), apiSvc, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}
	for {
		apiSvc, err := c.Client.K8S.CoreV1().Services(name).Get(context.Background(), "api", metav1.GetOptions{})
		if err != nil {
			return err
		}
		if apiSvc.Spec.ClusterIP != "" {
			hosts, err := txeh.NewHostsDefault()
			if err != nil {
				return err
			}
			hosts.AddHost(apiSvc.Spec.ClusterIP, fmt.Sprintf("api.%s.%s", name, domain))
			hosts.AddHost(apiSvc.Spec.ClusterIP, fmt.Sprintf("api-int.%s.%s", name, domain))
			hosts.RenderHostsFile()
			f, err := os.CreateTemp("", "")
			if err != nil {
				return err
			}
			defer f.Close()
			if err := hosts.SaveAs(f.Name()); err != nil {
				return err
			}
			stderr, err := RunSudo(fmt.Sprintf("cp %s /etc/hosts", f.Name()), "")
			if err != nil {
				return fmt.Errorf(stderr.String())
			}
			break
		}
		time.Sleep(time.Second * 2)
	}

	intApiSvc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api-int",
			Namespace: name,
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{{
				Name:     "api",
				Port:     6443,
				Protocol: "TCP",
				TargetPort: intstr.IntOrString{
					IntVal: 6443,
				},
			}, {
				Name:     "machine",
				Port:     22623,
				Protocol: "TCP",
				TargetPort: intstr.IntOrString{
					IntVal: 22623,
				},
			}},
			Selector: map[string]string{"occluster": name, "role": "controller"},
		},
	}
	if _, err := c.Client.K8S.CoreV1().Services(name).Create(context.Background(), intApiSvc, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}

	appSvc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress",
			Namespace: name,
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{{
				Name:     "ingress-433",
				Port:     443,
				Protocol: "TCP",
				TargetPort: intstr.IntOrString{
					IntVal: 443,
				},
			}, {
				Name:     "ingress-80",
				Port:     80,
				Protocol: "TCP",
				TargetPort: intstr.IntOrString{
					IntVal: 80,
				},
			}},
			Selector: map[string]string{"occluster": name, "role": "worker"},
		},
	}
	if _, err := c.Client.K8S.CoreV1().Services(name).Create(context.Background(), appSvc, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}

	return nil
}

func (c *CN2) DeleteDNSLB(name string) error {
	if err := c.Client.K8S.CoreV1().Services(name).Delete(context.Background(), "api", metav1.DeleteOptions{}); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
	}
	if err := c.Client.K8S.CoreV1().Services(name).Delete(context.Background(), "api-int", metav1.DeleteOptions{}); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
	}
	if err := c.Client.K8S.CoreV1().Services(name).Delete(context.Background(), "ingress", metav1.DeleteOptions{}); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func defineVMI(name, clustername, role, nameserver, domainName string) *kubevirtV1.VirtualMachineInstance {
	var firstBootOrder uint = 1
	var secondBootOrder uint = 2

	vmi := &kubevirtV1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: clustername,
			Labels:    map[string]string{"occluster": clustername, "role": role},
		},
		Spec: kubevirtV1.VirtualMachineInstanceSpec{
			DNSPolicy: v1.DNSNone,
			DNSConfig: &v1.PodDNSConfig{
				Nameservers: []string{nameserver},
				Searches:    []string{fmt.Sprintf("%s.%s", clustername, domainName)},
			},
			Networks: []kubevirtV1.Network{{
				Name: "default",
				NetworkSource: kubevirtV1.NetworkSource{
					Pod: &kubevirtV1.PodNetwork{},
				},
				/*
					}, {
						Name: name,
						NetworkSource: kubevirtV1.NetworkSource{
							Multus: &kubevirtV1.MultusNetwork{
								NetworkName: fmt.Sprintf("%s/%s", name, name),
							},
						},
				*/
			}},
			Domain: kubevirtV1.DomainSpec{
				CPU: &kubevirtV1.CPU{
					Sockets:               12,
					Threads:               1,
					Cores:                 1,
					DedicatedCPUPlacement: true,
				},
				Resources: kubevirtV1.ResourceRequirements{
					Requests: v1.ResourceList{
						"memory": resource.MustParse("32Gi"),
						//"cpu":    resource.MustParse("8"),
					},
				},
				Devices: kubevirtV1.Devices{
					Interfaces: []kubevirtV1.Interface{{
						Name: "default",
						InterfaceBindingMethod: kubevirtV1.InterfaceBindingMethod{
							Bridge: &kubevirtV1.InterfaceBridge{},
						},
						/*
							}, {
								Name: name,
								InterfaceBindingMethod: kubevirtV1.InterfaceBindingMethod{
									Bridge: &kubevirtV1.InterfaceBridge{},
								},
						*/
					}},
					Disks: []kubevirtV1.Disk{{
						Name: fmt.Sprintf("%s-iso", name),
						DiskDevice: kubevirtV1.DiskDevice{
							CDRom: &kubevirtV1.CDRomTarget{
								Bus: "sata",
							},
						},
						BootOrder: &secondBootOrder,
					}, {
						Name: fmt.Sprintf("%s-disk", name),
						DiskDevice: kubevirtV1.DiskDevice{
							Disk: &kubevirtV1.DiskTarget{
								Bus: "virtio",
							},
						},
						BootOrder: &firstBootOrder,
					}},
				},
			},
			Volumes: []kubevirtV1.Volume{{
				Name: fmt.Sprintf("%s-disk", name),
				VolumeSource: kubevirtV1.VolumeSource{
					HostDisk: &kubevirtV1.HostDisk{
						Capacity: resource.MustParse("120Gi"),
						Path:     fmt.Sprintf("/glusterfs/images/%s.img", name),
						Type:     kubevirtV1.HostDiskExistsOrCreate,
					},
				},
				/*
					VolumeSource: kubevirtV1.VolumeSource{
						PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{
							ClaimName: fmt.Sprintf("%s-disk", name),
							ReadOnly:  false,
						},
					},
				*/
			}, {
				Name: fmt.Sprintf("%s-iso", name),
				VolumeSource: kubevirtV1.VolumeSource{
					PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{
						ClaimName: fmt.Sprintf("%s-iso", name),
						ReadOnly:  false,
					},
				},
			}},
		},
	}
	if role == "controller" {
		vmi.Spec.ReadinessProbe = &kubevirtV1.Probe{
			Handler: kubevirtV1.Handler{
				TCPSocket: &v1.TCPSocketAction{
					Port: intstr.FromInt(6443),
				},
			},
		}
	}
	if role == "worker" {
		vmi.Spec.ReadinessProbe = &kubevirtV1.Probe{
			Handler: kubevirtV1.Handler{
				HTTPGet: &v1.HTTPGetAction{
					Path: "/healthz/ready",
					Port: intstr.IntOrString{
						IntVal: 1936,
					},
					Scheme: v1.URISchemeHTTP,
				},
			},
		}
	}
	return vmi
}

func (c *CN2) CreateVMS(name, domainName string, controller int, worker int) error {
	dnsSvc, err := c.Client.K8S.CoreV1().Services("kube-system").Get(context.Background(), "coredns", metav1.GetOptions{})
	if err != nil {
		return err
	}
	for i := 0; i < controller; i++ {
		nodename := fmt.Sprintf("%s-controller-%d", name, i)
		vmi := defineVMI(nodename, name, "controller", dnsSvc.Spec.ClusterIP, domainName)
		if _, err := c.Client.Kubevirt.VirtualMachineInstance(name).Create(vmi); err != nil {
			if !errors.IsAlreadyExists(err) {
				return err
			}
		}
	}
	for i := 0; i < worker; i++ {
		nodename := fmt.Sprintf("%s-worker-%d", name, i)
		vmi := defineVMI(nodename, name, "worker", dnsSvc.Spec.ClusterIP, domainName)
		if _, err := c.Client.Kubevirt.VirtualMachineInstance(name).Create(vmi); err != nil {
			if !errors.IsAlreadyExists(err) {
				return err
			}
		}
	}
	return nil
}

func (c *CN2) DeleteVMS(name string, controller, worker int) error {
	for i := 0; i < controller; i++ {
		nodename := fmt.Sprintf("%s-controller-%d", name, i)
		if err := c.Client.Kubevirt.VirtualMachineInstance(name).Delete(nodename, &metav1.DeleteOptions{}); err != nil {
			if !errors.IsNotFound(err) {
				return err
			}
		}
	}
	for i := 0; i < worker; i++ {
		nodename := fmt.Sprintf("%s-worker-%d", name, i)
		if err := c.Client.Kubevirt.VirtualMachineInstance(name).Delete(nodename, &metav1.DeleteOptions{}); err != nil {
			if !errors.IsNotFound(err) {
				return err
			}
		}
	}
	return nil
}

func (c *CN2) CreateStorage(image infrastructure.Image, controller int, worker int) error {

	for i := 0; i < controller; i++ {
		nodename := fmt.Sprintf("%s-controller-%d", image.Name, i)
		if err := createGlusterFSVolumes(nodename); err != nil {
			return err
		}
		if _, err := os.Stat(fmt.Sprintf("/var/glusterfsmnt/%s-iso/disk.img", nodename)); os.IsNotExist(err) {
			if err := CopyFile(image.Path, fmt.Sprintf("/var/glusterfsmnt/%s-iso/disk.img", nodename)); err != nil {
				return err
			}
		}

		if err := c.createPVandPVC(nodename, image.Name); err != nil {
			return err
		}
	}
	for i := 0; i < worker; i++ {
		nodename := fmt.Sprintf("%s-worker-%d", image.Name, i)
		if err := createGlusterFSVolumes(nodename); err != nil {
			return err
		}
		if _, err := os.Stat(fmt.Sprintf("/var/glusterfsmnt/%s-iso/disk.img", nodename)); os.IsNotExist(err) {
			if err := CopyFile(image.Path, fmt.Sprintf("/var/glusterfsmnt/%s-iso/disk.img", nodename)); err != nil {
				return err
			}
		}

		if err := c.createPVandPVC(nodename, image.Name); err != nil {
			return err
		}
	}
	return nil
}

func (c *CN2) DeleteStorage(image infrastructure.Image, controller int, worker int) error {
	for i := 0; i < controller; i++ {
		nodename := fmt.Sprintf("%s-controller-%d", image.Name, i)
		if err := c.deletePVandPVC(nodename, image.Name); err != nil {
			return err
		}

		if err := deleteGlusterFSVolumes(nodename, image.Path); err != nil {
			return err
		}
	}
	for i := 0; i < worker; i++ {
		nodename := fmt.Sprintf("%s-worker-%d", image.Name, i)
		if err := c.deletePVandPVC(nodename, image.Name); err != nil {
			return err
		}

		if err := deleteGlusterFSVolumes(nodename, image.Path); err != nil {
			return err
		}
	}

	return nil
}

func (c *CN2) deletePVandPVC(name, namespace string) error {
	if err := c.Client.K8S.CoreV1().PersistentVolumeClaims(namespace).Delete(context.Background(), fmt.Sprintf("%s-iso", name), metav1.DeleteOptions{}); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
	}

	if err := c.Client.K8S.CoreV1().PersistentVolumes().Delete(context.Background(), fmt.Sprintf("%s-iso", name), metav1.DeleteOptions{}); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
	}

	if err := c.Client.K8S.CoreV1().PersistentVolumeClaims(namespace).Delete(context.Background(), fmt.Sprintf("%s-disk", name), metav1.DeleteOptions{}); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
	}

	if err := c.Client.K8S.CoreV1().PersistentVolumes().Delete(context.Background(), fmt.Sprintf("%s-disk", name), metav1.DeleteOptions{}); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
	}

	if err := c.Client.K8S.CoreV1().Endpoints(name).Delete(context.Background(), "glusterfs-cluster", metav1.DeleteOptions{}); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
	}

	return nil
}

func (c *CN2) createPVandPVC(name, namespace string) error {
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	if _, err := c.Client.K8S.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}
	epNamespace := "default"
	isoPV := &v1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-iso", name),
			Namespace: namespace,
		},
		Spec: v1.PersistentVolumeSpec{
			Capacity: v1.ResourceList{
				"storage": resource.MustParse("2Gi"),
			},
			AccessModes: []v1.PersistentVolumeAccessMode{"ReadWriteMany"},
			PersistentVolumeSource: v1.PersistentVolumeSource{
				Glusterfs: &v1.GlusterfsPersistentVolumeSource{
					ReadOnly:           false,
					EndpointsNamespace: &epNamespace,
					EndpointsName:      "glusterfs-cluster",
					Path:               fmt.Sprintf("%s-iso", name),
				},
			},
		},
	}
	if _, err := c.Client.K8S.CoreV1().PersistentVolumes().Create(context.Background(), isoPV, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}

	isoPVC := &v1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-iso", name),
			Namespace: namespace,
		},
		Spec: v1.PersistentVolumeClaimSpec{
			AccessModes: []v1.PersistentVolumeAccessMode{"ReadWriteMany"},
			Resources: v1.ResourceRequirements{
				Requests: v1.ResourceList{
					"storage": resource.MustParse("2Gi"),
				},
			},
		},
	}

	if _, err := c.Client.K8S.CoreV1().PersistentVolumeClaims(namespace).Create(context.Background(), isoPVC, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}

	diskPV := &v1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-disk", name),
			Namespace: namespace,
		},
		Spec: v1.PersistentVolumeSpec{
			Capacity: v1.ResourceList{
				"storage": resource.MustParse("120Gi"),
			},
			AccessModes: []v1.PersistentVolumeAccessMode{"ReadWriteMany"},
			PersistentVolumeSource: v1.PersistentVolumeSource{
				Glusterfs: &v1.GlusterfsPersistentVolumeSource{
					ReadOnly:           false,
					EndpointsNamespace: &epNamespace,
					EndpointsName:      "glusterfs-cluster",
					Path:               fmt.Sprintf("%s-disk", name),
				},
			},
		},
	}
	if _, err := c.Client.K8S.CoreV1().PersistentVolumes().Create(context.Background(), diskPV, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}

	diskPVC := &v1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-disk", name),
			Namespace: namespace,
		},
		Spec: v1.PersistentVolumeClaimSpec{
			AccessModes: []v1.PersistentVolumeAccessMode{"ReadWriteMany"},
			Resources: v1.ResourceRequirements{
				Requests: v1.ResourceList{
					"storage": resource.MustParse("120Gi"),
				},
			},
		},
	}
	if _, err := c.Client.K8S.CoreV1().PersistentVolumeClaims(namespace).Create(context.Background(), diskPVC, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}

	return nil
}

func createGlusterFSVolumes(name string) error {

	isoVolumeExists := true
	isoVolumeInfoCommandString := fmt.Sprintf("gluster volume info %s-iso", name)
	stderr, err := RunSudo(isoVolumeInfoCommandString, "")
	if err != nil {
		if strings.Trim(stderr.String(), "\n") == fmt.Sprintf("Volume %s-iso does not exist", name) {
			isoVolumeExists = false
		} else {
			klog.Error(stderr.String(), isoVolumeInfoCommandString)
			return err
		}
	}

	if !isoVolumeExists {
		isoVolumeCreateCommandString := fmt.Sprintf("gluster volume create %s-iso 5b3s30.cluster1.local:/glusterfs/%s-iso", name, name)
		stderr, err := RunSudo(isoVolumeCreateCommandString, "")
		if err != nil {
			klog.Error(stderr.String(), isoVolumeCreateCommandString)
			return err
		}

		isoVolumeStartCommandString := fmt.Sprintf("gluster volume start %s-iso", name)
		stderr, err = RunSudo(isoVolumeStartCommandString, "")
		if err != nil {
			klog.Error(stderr.String())
			return err
		}
	}
	if _, err := os.Stat(fmt.Sprintf("/var/glusterfsmnt/%s-iso", name)); os.IsNotExist(err) {
		if err := os.Mkdir(fmt.Sprintf("/var/glusterfsmnt/%s-iso", name), 0777); err != nil {
			return err
		}
		isoVolumeMountCommandString := fmt.Sprintf("mount -t glusterfs 5b3s30.cluster1.local:/%s-iso /var/glusterfsmnt/%s-iso", name, name)
		stderr, err = RunSudo(isoVolumeMountCommandString, "")
		if err != nil {
			klog.Error(stderr.String())
			return err
		}
		isoVolumeChmodCommandString := fmt.Sprintf("chmod 777 /var/glusterfsmnt/%s-iso", name)
		stderr, err = RunSudo(isoVolumeChmodCommandString, "")
		if err != nil {
			klog.Error(stderr.String())
			return err
		}
	}

	diskVolumeExists := true
	diskVolumeInfoCommandString := fmt.Sprintf("gluster volume info %s-disk", name)
	stderr, err = RunSudo(diskVolumeInfoCommandString, "")
	if err != nil {
		if strings.Trim(stderr.String(), "\n") == fmt.Sprintf("Volume %s-disk does not exist", name) {
			diskVolumeExists = false
		} else {
			klog.Error(stderr.String(), diskVolumeInfoCommandString)
			return err
		}
	}

	if !diskVolumeExists {
		diskVolumeCreateCommandString := fmt.Sprintf("gluster volume create %s-disk 5b3s30.cluster1.local:/glusterfs/%s-disk", name, name)
		stderr, err := RunSudo(diskVolumeCreateCommandString, "")
		if err != nil {
			klog.Error(stderr.String(), diskVolumeCreateCommandString)
			return err
		}

		diskVolumeStartCommandString := fmt.Sprintf("gluster volume start %s-disk", name)
		stderr, err = RunSudo(diskVolumeStartCommandString, "")
		if err != nil {
			klog.Error(stderr.String())
			return err
		}
	}
	return nil
}

func deleteGlusterFSVolumes(name, path string) error {
	if _, err := os.Stat(fmt.Sprintf("/var/glusterfsmnt/%s-iso", name)); err == nil {
		stderr, err := RunSudo(fmt.Sprintf("umount /var/glusterfsmnt/%s-iso", name), "")
		if err != nil {
			if strings.Trim(stderr.String(), "\n") != fmt.Sprintf("umount: /var/glusterfsmnt/%s-iso: not mounted.", name) {
				klog.Error(stderr.String())
				return err
			}
		}

		stderr, err = RunSudo(fmt.Sprintf("rm -rf /var/glusterfsmnt/%s-iso", name), "")
		if err != nil {
			klog.Error(stderr.String())
			return err
		}

		stderr, err = RunSudo(fmt.Sprintf("gluster volume stop %s-iso", name), "y")
		if err != nil {
			klog.Error(stderr.String())
			return err
		}

		stderr, err = RunSudo(fmt.Sprintf("gluster volume delete %s-iso", name), "y")
		if err != nil {
			klog.Error(stderr.String())
			return err
		}

		stderr, err = RunSudo(fmt.Sprintf("rm -rf /glusterfs/%s-iso", name), "")
		if err != nil {
			klog.Error(stderr.String())
			return err
		}

		stderr, err = RunSudo(fmt.Sprintf("gluster volume stop %s-disk", name), "y")
		if err != nil {
			klog.Error(stderr.String())
			return err
		}

		stderr, err = RunSudo(fmt.Sprintf("gluster volume delete %s-disk", name), "y")
		if err != nil {
			klog.Error(stderr.String())
			return err
		}

		stderr, err = RunSudo(fmt.Sprintf("rm -rf /glusterfs/%s-disk", name), "")
		if err != nil {
			klog.Error(stderr.String())
			return err
		}
	}

	/*
		stderr, err = runSudo(fmt.Sprintf("rm -rf %s", path), "")
		if err != nil {
			klog.Error(stderr.String())
			return err
		}
	*/

	return nil
}

func RunSudo(command, input string) (bytes.Buffer, error) {
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

// CopyFile copies a file from src to dst. If src and dst files exist, and are
// the same, then return success. Otherise, attempt to create a hard link
// between the two files. If that fail, copy the file contents from src to dst.
func CopyFile(src, dst string) error {
	sfi, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !sfi.Mode().IsRegular() {
		// cannot copy non-regular files (e.g., directories,
		// symlinks, devices, etc.)
		return fmt.Errorf("CopyFile: non-regular source file %s (%q)", sfi.Name(), sfi.Mode().String())
	}
	dfi, err := os.Stat(dst)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else {
		if !(dfi.Mode().IsRegular()) {
			return fmt.Errorf("CopyFile: non-regular destination file %s (%q)", dfi.Name(), dfi.Mode().String())
		}
		if os.SameFile(sfi, dfi) {
			return nil
		}
	}
	if err := copyFileContents(src, dst); err != nil {
		return err
	}
	return nil
}

// copyFileContents copies the contents of the file named src to the file named
// by dst. The file will be created if it does not already exist. If the
// destination file exists, all it's contents will be replaced by the contents
// of the source file.
func copyFileContents(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	return err
}
