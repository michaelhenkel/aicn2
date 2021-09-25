package infrastructure

type InfrastructureInterface interface {
	CreateStorage(image Image, controller int, worker int) error
	CreateVN(name string, subnet string) error
	CreateVMS(name string, controller int, worker int) error
	CreateDNSLB(name string) error
	DeleteStorage(image Image, controller int, worker int) error
	DeleteVMS(name string, controller int, worker int) error
	DeleteDNSLB(name string) error
	DeleteVN(name string) error
}

type Image struct {
	Path string
	Name string
}
