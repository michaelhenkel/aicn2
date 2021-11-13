package cn2

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	corev1alpha1 "ssd-git.juniper.net/contrail/cn2/contrail/pkg/apis/core/v1alpha1"
)

type CN2 struct {
	Client   *k8s.Client
	registry string
}

func New(registry, kubeconfig string) (*CN2, error) {
	client, err := k8s.NewClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	return &CN2{
		Client:   client,
		registry: registry,
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

func (c *CN2) checkCreateNamespace(name string) error {
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	if _, err := c.Client.K8S.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
	}
	return nil
}

func (c *CN2) CreateVN(name, subnet string) error {
	if err := c.checkCreateNamespace(name); err != nil {
		return err
	}
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

func (c *CN2) AssociateVip(name, ip, role string) error {
	// Labels:    map[string]string{"occluster": clustername, "role": role},
	podList, err := c.Client.K8S.CoreV1().Pods(name).List(context.Background(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("occluster=%s,role=%s", name, role),
	})
	if err != nil {
		return err
	}
	vmiList, err := c.Client.Contrail.CoreV1alpha1().VirtualMachineInterfaces(name).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, pod := range podList.Items {
		for _, vmi := range vmiList.Items {
			if vmi.Annotations["kube-manager.juniper.net/pod-name"] == pod.Name && vmi.Annotations["kube-manager.juniper.net/pod-namespace"] == pod.Namespace {
				vmi.Spec.AllowedAddressPairs = corev1alpha1.AllowedAddressPairs{
					AllowedAddressPair: []corev1alpha1.AllowedAddressPair{{
						IPAddress: corev1alpha1.AllowedAddressPairSubnet{
							IPPrefix:       corev1alpha1.IPAddress(ip),
							IPPrefixLength: intstr.FromInt(32),
						},
						AddressMode: corev1alpha1.ActiveStandby,
					}},
				}
				if _, err := c.Client.Contrail.CoreV1alpha1().VirtualMachineInterfaces(name).Update(context.Background(), &vmi, metav1.UpdateOptions{}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (c *CN2) AllocateAPIVip(name, role string) (string, error) {
	iip := &corev1alpha1.InstanceIP{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-%s-vip", name, role),
			Labels: map[string]string{
				"occluster": name,
			},
		},
		Spec: corev1alpha1.InstanceIPSpec{
			IPFamily: corev1alpha1.IPFamilyV4,
			VirtualNetworkReference: &corev1alpha1.ResourceReference{
				ObjectReference: v1.ObjectReference{
					Name:       "default-podnetwork",
					Namespace:  "contrail-k8s-kubemanager-cluster1-local-contrail",
					Kind:       "VirtualNetwork",
					APIVersion: "core.contrail.juniper.net/v1alpha1",
				},
			},
		},
	}
	_, err := c.Client.Contrail.CoreV1alpha1().InstanceIPs().Create(context.Background(), iip, metav1.CreateOptions{})
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return "", err
		}
	}

	for i := 0; i < 5; i++ {
		iip, err = c.Client.Contrail.CoreV1alpha1().InstanceIPs().Get(context.Background(), fmt.Sprintf("%s-%s-vip", name, role), metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		ip := iip.Spec.IPAddress.IP().String()
		if _, _, err := net.ParseCIDR(ip + "/32"); err != nil {
			time.Sleep(time.Second * 2)
		} else {
			return iip.Spec.IPAddress.IP().String(), nil
		}
	}

	return "", fmt.Errorf("no valid IP")
}

func (c *CN2) DeleteAPIVip(name, role string) error {
	if err := c.Client.Contrail.CoreV1alpha1().InstanceIPs().Delete(context.Background(), fmt.Sprintf("%s-%s-vip", name, role), metav1.DeleteOptions{}); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (c *CN2) CreateDNSLB(name, domain string, modifyHosts bool) error {
	if err := c.checkCreateNamespace(name); err != nil {
		return err
	}
	coreDNSCM, err := c.Client.K8S.CoreV1().ConfigMaps("kube-system").Get(context.Background(), "coredns", metav1.GetOptions{})
	if err != nil {
		return err
	}
	coreDNSConfig, ok := coreDNSCM.Data["Corefile"]
	if !ok {
		return fmt.Errorf("core dns config not found")
	}
	var lines []string
	r := strings.NewReader(coreDNSConfig)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	var lineIdx *int
	for idx, line := range lines {
		r, _ := regexp.Compile(`kubernetes (.*) in-addr.arpa ip6.arpa`)
		found := r.FindStringSubmatch(line)
		if len(found) > 0 {
			lineIdx = &idx
			break
		}
	}
	rewriteLine := fmt.Sprintf(`    rewrite name regex (.*)\.apps.%s.%s ingress.%s.%s`, name, domain, name, domain)

	alreadyExists := false
	for _, line := range lines {
		r, _ := regexp.Compile(rewriteLine)
		found := r.FindString(line)
		if found != "" {
			alreadyExists = true
			break
		}
	}
	var newConfig string
	if !alreadyExists {
		for idx, line := range lines {
			if idx == *lineIdx {
				newConfig = fmt.Sprintf("%s\n%s", newConfig, rewriteLine)
			}
			if idx == 0 {
				newConfig = line
			} else {
				newConfig = fmt.Sprintf("%s\n%s", newConfig, line)
			}
		}
		coreDNSCM.Data["Corefile"] = newConfig
		if _, err := c.Client.K8S.CoreV1().ConfigMaps("kube-system").Update(context.Background(), coreDNSCM, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}

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
			if modifyHosts {
				stderr, err := RunSudo(fmt.Sprintf("cp %s /etc/hosts", f.Name()), "")
				if err != nil {
					return fmt.Errorf(stderr.String())
				}
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
	domain, err := c.GetClusterDomain(name)
	if err != nil {
		return err
	}
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

	coreDNSCM, err := c.Client.K8S.CoreV1().ConfigMaps("kube-system").Get(context.Background(), "coredns", metav1.GetOptions{})
	if err != nil {
		return err
	}
	coreDNSConfig, ok := coreDNSCM.Data["Corefile"]
	if !ok {
		return fmt.Errorf("core dns config not found")
	}
	var lines []string
	r := strings.NewReader(coreDNSConfig)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	rewriteLine := fmt.Sprintf(`    rewrite name regex (.*)\.apps.%s.%s ingress.%s.%s`, name, domain, name, domain)

	var lineIdx *int
	for idx, line := range lines {
		r, _ := regexp.Compile(rewriteLine)
		found := r.FindString(line)
		if found != "" {
			lineIdx = &idx
			break
		}
	}
	var newConfig string
	if lineIdx != nil {
		for idx, line := range lines {
			if idx == *lineIdx {
				continue
			}
			if idx == 0 {
				newConfig = line
			} else {
				newConfig = fmt.Sprintf("%s\n%s", newConfig, line)
			}
		}
		coreDNSCM.Data["Corefile"] = newConfig
		if _, err := c.Client.K8S.CoreV1().ConfigMaps("kube-system").Update(context.Background(), coreDNSCM, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}

	return nil
}

func defineVM(name, clustername, role, nameserver, domainName, registry, memory string, vcpu uint32, dedicatedCPUPlacement bool) *kubevirtV1.VirtualMachine {
	var firstBootOrder uint = 1
	var secondBootOrder uint = 2
	//etcResolvEntry := fmt.Sprintf(`"nameserver %s"`, nameserver)
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
					/*
						LivenessProbe: &kubevirtV1.Probe{
							Handler: kubevirtV1.Handler{
								Exec: &v1.ExecAction{
									Command: []string{"grep", nameserver, "/etc/resolv.conf"},
								},
							},
							InitialDelaySeconds: 100,
							FailureThreshold:    10,
						},
					*/
					Networks: []kubevirtV1.Network{{
						Name: "default",
						NetworkSource: kubevirtV1.NetworkSource{
							Pod: &kubevirtV1.PodNetwork{},
						},
					}, {
						Name: clustername,
						NetworkSource: kubevirtV1.NetworkSource{
							Multus: &kubevirtV1.MultusNetwork{
								NetworkName: fmt.Sprintf("%s/%s", clustername, clustername),
							},
						},
					}},
					Domain: kubevirtV1.DomainSpec{
						CPU: &kubevirtV1.CPU{
							Sockets:               vcpu,
							Threads:               1,
							Cores:                 1,
							DedicatedCPUPlacement: dedicatedCPUPlacement,
						},
						Resources: kubevirtV1.ResourceRequirements{
							Requests: v1.ResourceList{
								"memory": resource.MustParse(memory),
							},
						},
						Devices: kubevirtV1.Devices{
							Interfaces: []kubevirtV1.Interface{{
								Name: "default",
								InterfaceBindingMethod: kubevirtV1.InterfaceBindingMethod{
									Bridge: &kubevirtV1.InterfaceBridge{},
								},
							}, {
								Name: clustername,
								InterfaceBindingMethod: kubevirtV1.InterfaceBindingMethod{
									Bridge: &kubevirtV1.InterfaceBridge{},
								},
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
								Image:           fmt.Sprintf("%s/%s", registry, name),
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
			InitialDelaySeconds: 10,
			PeriodSeconds:       10,
			SuccessThreshold:    1,
			TimeoutSeconds:      10,
			FailureThreshold:    3,
			Handler: kubevirtV1.Handler{
				/*
					TCPSocket: &v1.TCPSocketAction{
						Port: intstr.FromInt(6443),
					},
				*/
				HTTPGet: &v1.HTTPGetAction{
					Path: "readyz",
					Port: intstr.IntOrString{
						IntVal: 6443,
					},
					Scheme: v1.URISchemeHTTPS,
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

func (c *CN2) CreateVMS(name, domainName string, controller int, worker int, memory string, vcpu uint32, dedicatedCPUPlacement bool) error {
	if err := c.checkCreateNamespace(name); err != nil {
		return err
	}
	dnsSvc, err := c.Client.K8S.CoreV1().Services("kube-system").Get(context.Background(), "coredns", metav1.GetOptions{})
	if err != nil {
		return err
	}
	for i := 0; i < controller; i++ {
		nodename := fmt.Sprintf("%s-controller-%d", name, i)
		vm := defineVM(nodename, name, "controller", dnsSvc.Spec.ClusterIP, domainName, c.registry, memory, vcpu, dedicatedCPUPlacement)
		if _, err := c.Client.Kubevirt.VirtualMachine(name).Create(vm); err != nil {
			if !errors.IsAlreadyExists(err) {
				return err
			}
		}
	}
	for i := 0; i < worker; i++ {
		nodename := fmt.Sprintf("%s-worker-%d", name, i)
		vm := defineVM(nodename, name, "worker", dnsSvc.Spec.ClusterIP, domainName, c.registry, memory, vcpu, dedicatedCPUPlacement)
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
		ci, err := containerImage.NewContainerImage(nodename, c.registry, filepath.Dir(image.Path))
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
		ci, err := containerImage.NewContainerImage(nodename, c.registry, filepath.Dir(image.Path))
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
