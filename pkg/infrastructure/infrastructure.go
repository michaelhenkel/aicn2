package infrastructure

type InfrastructureInterface interface {
	CreateStorage(image Image, controller int, worker int) error
	GetClusterDomain(name string) (string, error)
	AllocateAPIVip(name, role string) (string, error)
	AssociateVip(name, ip, role string) error
	DeleteAPIVip(name, role string) error
	CreateVN(name string, subnet string) error
	CreateVMS(name string, domainName string, controller int, worker int, memory string, vcpu uint32, dedicatedCPUPlacement bool) error
	CreateDNSLB(name string, domain string, modifyHosts bool) error
	DeleteStorage(image Image, controller int, worker int, hostMap map[string]string) error
	DeleteVMS(name string) error
	DeleteDNSLB(name string) error
	DeleteVN(name string) error
}

type Image struct {
	Path string
	Name string
}
