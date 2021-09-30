package infrastructure

type InfrastructureInterface interface {
	CreateStorage(image Image, controller int, worker int) error
	GetClusterDomain(name string) (string, error)
	CreateVN(name string, subnet string) error
	CreateVMS(name string, domainName string, controller int, worker int) error
	CreateDNSLB(name string, domain string) error
	DeleteStorage(image Image, controller int, worker int, hostMap map[string]string) error
	DeleteVMS(name string, controller int, worker int) (map[string]string, error)
	DeleteDNSLB(name string) error
	DeleteVN(name string) error
}

type Image struct {
	Path string
	Name string
}
