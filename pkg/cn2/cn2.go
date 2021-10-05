package cn2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	containerImage "github.com/michaelhenkel/aicn2/pkg/container"
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

const (
	REGISTRY = "registry.default.svc.cluster1.local:5000"
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
	/*
		sn := &corev1alpha1.Subnet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-v4", name),
				Namespace: name,
			},
			Spec: corev1alpha1.SubnetSpec{
				CIDR:           corev1alpha1.CIDR(subnet),
				DefaultGateway: corev1alpha1.IPAddress("10.87.73.14"),
				Ranges: []corev1alpha1.Range{{
					Key: "contrail-k8s-kubemanager-cluster1-local-5b3s31",
					IPRanges: []corev1alpha1.IPRange{{
						From: corev1alpha1.IPAddress("10.87.73.5"),
						To:   corev1alpha1.IPAddress("10.87.73.6"),
					}},
				}, {
					Key: "contrail-k8s-kubemanager-cluster1-local-5b3s32",
					IPRanges: []corev1alpha1.IPRange{{
						From: corev1alpha1.IPAddress("10.87.73.7"),
						To:   corev1alpha1.IPAddress("10.87.73.8"),
					}},
				}, {
					Key: "contrail-k8s-kubemanager-cluster1-local-5b3s33",
					IPRanges: []corev1alpha1.IPRange{{
						From: corev1alpha1.IPAddress("10.87.73.9"),
						To:   corev1alpha1.IPAddress("10.87.73.10"),
					}},
				}},
			},
		}
		if _, err := c.Client.Contrail.CoreV1alpha1().Subnets(name).Create(context.Background(), sn, metav1.CreateOptions{}); err != nil {
			if !errors.IsAlreadyExists(err) {
				return err
			}
		}
		vn := &corev1alpha1.VirtualNetwork{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: name,
			},
			Spec: corev1alpha1.VirtualNetworkSpec{
				V4SubnetReference: &corev1alpha1.ResourceReference{
					ObjectReference: v1.ObjectReference{
						Name:       sn.Name,
						Namespace:  sn.Namespace,
						Kind:       "Subnet",
						APIVersion: "core.contrail.juniper.net/v1alpha1",
					},
				},
				ProviderNetworkReference: &corev1alpha1.ResourceReference{
					ObjectReference: v1.ObjectReference{
						Name:       "ip-fabric",
						Namespace:  "contrail",
						Kind:       "VirtualNetwork",
						APIVersion: "core.contrail.juniper.net/v1alpha1",
					},
				},
			},
		}
		if _, err := c.Client.Contrail.CoreV1alpha1().VirtualNetworks(name).Create(context.Background(), vn, metav1.CreateOptions{}); err != nil {
			if !errors.IsAlreadyExists(err) {
				return err
			}
		}
	*/
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

func defineVM(name, clustername, role, nameserver, domainName string) *kubevirtV1.VirtualMachine {
	var firstBootOrder uint = 1
	var secondBootOrder uint = 2
	running := true
	vm := &kubevirtV1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: clustername,
			Labels:    map[string]string{"occluster": clustername, "role": role},
		},
		Spec: kubevirtV1.VirtualMachineSpec{
			Running: &running,
			Template: &kubevirtV1.VirtualMachineInstanceTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: clustername,
					Labels:    map[string]string{"occluster": clustername, "role": role},
				},
				Spec: kubevirtV1.VirtualMachineInstanceSpec{
					Hostname:  name,
					DNSPolicy: v1.DNSNone,
					DNSConfig: &v1.PodDNSConfig{
						Nameservers: []string{nameserver},
						Searches:    []string{fmt.Sprintf("%s.%s", clustername, domainName)},
					},
					Networks: []kubevirtV1.Network{{
						/*
								Name: clustername,
								NetworkSource: kubevirtV1.NetworkSource{
									Multus: &kubevirtV1.MultusNetwork{
										NetworkName: fmt.Sprintf("%s/%s", clustername, clustername),
									},
								},
							}, {
						*/
						Name: "default",
						NetworkSource: kubevirtV1.NetworkSource{
							Pod: &kubevirtV1.PodNetwork{},
						},
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
										Name: clustername,
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
							EmptyDisk: &kubevirtV1.EmptyDiskSource{
								Capacity: resource.MustParse("120Gi"),
							},
						},
					}, {
						Name: fmt.Sprintf("%s-iso", name),
						VolumeSource: kubevirtV1.VolumeSource{
							ContainerDisk: &kubevirtV1.ContainerDiskSource{
								Image:           fmt.Sprintf("%s/%s", REGISTRY, name),
								ImagePullPolicy: v1.PullAlways,
							},
						},
					}},
				},
			},
		},
	}

	if role == "controller" {
		vm.Spec.Template.Spec.ReadinessProbe = &kubevirtV1.Probe{
			Handler: kubevirtV1.Handler{
				TCPSocket: &v1.TCPSocketAction{
					Port: intstr.FromInt(6443),
				},
			},
		}
	}
	if role == "worker" {
		vm.Spec.Template.Spec.ReadinessProbe = &kubevirtV1.Probe{
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
	return vm
}

func (c *CN2) CreateVMS(name, domainName string, controller int, worker int) error {
	dnsSvc, err := c.Client.K8S.CoreV1().Services("kube-system").Get(context.Background(), "coredns", metav1.GetOptions{})
	if err != nil {
		return err
	}
	for i := 0; i < controller; i++ {
		nodename := fmt.Sprintf("%s-controller-%d", name, i)
		vm := defineVM(nodename, name, "controller", dnsSvc.Spec.ClusterIP, domainName)
		if _, err := c.Client.Kubevirt.VirtualMachine(name).Create(vm); err != nil {
			if !errors.IsAlreadyExists(err) {
				return err
			}
		}
	}
	for i := 0; i < worker; i++ {
		nodename := fmt.Sprintf("%s-worker-%d", name, i)
		vm := defineVM(nodename, name, "worker", dnsSvc.Spec.ClusterIP, domainName)
		if _, err := c.Client.Kubevirt.VirtualMachine(name).Create(vm); err != nil {
			if !errors.IsAlreadyExists(err) {
				return err
			}
		}
	}
	return nil
}

func (c *CN2) DeleteVMS(name string) error {
	vmList, err := c.Client.Kubevirt.VirtualMachine(name).List(&metav1.ListOptions{
		LabelSelector: fmt.Sprintf("occluster=%s", name),
	})
	if err != nil {
		return err
	}
	for _, vm := range vmList.Items {
		if err := c.Client.Kubevirt.VirtualMachine(name).Delete(vm.Name, &metav1.DeleteOptions{}); err != nil {
			return err
		}
	}
	return nil
}

func (c *CN2) CreateStorage(image infrastructure.Image, controller int, worker int) error {

	for i := 0; i < controller; i++ {
		nodename := fmt.Sprintf("%s-controller-%d", image.Name, i)
		ci, err := containerImage.NewContainerImage(nodename, REGISTRY, filepath.Dir(image.Path))
		if err != nil {
			return err
		}
		klog.Infof("CN2: Building and Pushing ISO Image Container for %s", nodename)
		if err := ci.BuildBaseImage(); err != nil {
			return err
		}
		/*
			klog.Infof("CN2: Tagging and Uploading ISO Container for node %s", nodename)
			if err := ci.TagAndPush(nodename); err != nil {
				return err
			}
		*/
	}
	for i := 0; i < worker; i++ {
		nodename := fmt.Sprintf("%s-worker-%d", image.Name, i)
		ci, err := containerImage.NewContainerImage(nodename, REGISTRY, filepath.Dir(image.Path))
		if err != nil {
			return err
		}
		klog.Infof("CN2: Building and Pushing ISO Image Container for %s", nodename)
		if err := ci.BuildBaseImage(); err != nil {
			return err
		}
		/*
			klog.Infof("CN2: Tagging and Uploading ISO Container for node %s", nodename)
			if err := ci.TagAndPush(nodename); err != nil {
				return err
			}
		*/
	}
	return nil
}

func (c *CN2) DeleteStorage(image infrastructure.Image, controller int, worker int, hostMap map[string]string) error {
	for i := 0; i < controller; i++ {
		nodename := fmt.Sprintf("%s-controller-%d", image.Name, i)
		node := hostMap[nodename]
		rmCommand := fmt.Sprintf("rm -f /var/glusterfsmnt/%s-images/%s.img", node, nodename)
		stderr, err := RunSudo(rmCommand, "")
		if err != nil {
			klog.Error(stderr.String(), err)
			return err
		}
	}
	for i := 0; i < worker; i++ {
		nodename := fmt.Sprintf("%s-worker-%d", image.Name, i)
		node := hostMap[nodename]
		rmCommand := fmt.Sprintf("rm -f /var/glusterfsmnt/%s-images/%s.img", node, nodename)
		stderr, err := RunSudo(rmCommand, "")
		if err != nil {
			klog.Error(stderr.String(), err)
			return err
		}
	}

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
