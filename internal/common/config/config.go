package config

type Config struct {
	Port            uint32
	IsDevelopment   bool
	ShutdownTimeout int64
	SecretKey       string
	Oidc            Oidc
	S3              S3
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
