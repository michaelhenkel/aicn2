package infrastructure

type InfrastructureInterface interface {
	PrepareStorage(image Image) error
	DeleteISO(image Image) error
}

type Image struct {
	Path string
	Name string
}
