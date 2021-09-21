package infrastructure

type InfrastructureInterface interface {
	CreateStorage(image Image) error
	CreateVMS(name string) error
	CreateDNSLB(name string) error
	DeleteStorage(image Image) error
	DeleteVMS(name string) error
	DeleteDNSLB(name string) error
}

type Image struct {
	Path string
	Name string
}
