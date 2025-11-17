package config

type Config struct {
	Port            uint32
	IsDevelopment   bool
	ShutdownTimeout int64
	Oidc            Oidc
	S3              S3
	Vault           Vault
}

type Oidc struct {
	Issuer,
	ClientId string
}

type S3 struct {
	AccessKeyId,
	SecretAccessKey,
	DefaultRegion,
	DefaultBucket,
	URL string
}

type Vault struct {
	URL             string
	Token           string
	TransitBasePath string
	TransitKey      string
}
