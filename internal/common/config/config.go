package config

type Config struct {
	Port            uint32
	IsDevelopment   bool
	ShutdownTimeout int64
	Oidc            Oidc
}

type Oidc struct {
	Issuer   string
	ClientId string
}
