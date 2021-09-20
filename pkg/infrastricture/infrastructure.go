package infrastructure

type InfrastructureInterface interface {
	UploadISO(path string) error
}
