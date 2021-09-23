package infrastructure

type InfrastructureInterface interface {
	CreateStorage(image Image) error
	CreateVN(name string, subnet string) error
	CreateVMS(name string) error
	CreateDNSLB(name string) error
	DeleteStorage(image Image) error
	DeleteVMS(name string) error
	DeleteDNSLB(name string) error
	DeleteVN(name string) error
}

type Image struct {
	Path string
	Name string
}
