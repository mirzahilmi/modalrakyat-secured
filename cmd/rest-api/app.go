package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/barasher/go-exiftool"
	vaultApi "github.com/hashicorp/vault/api"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/middleware"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/knowyourcustomer"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/utility"
	"github.com/rs/zerolog/log"
)

func setup(ctx context.Context) (func() error, error) {
	// deprecated, but whatever. thanks to https://github.com/minio/docs/issues/406#issuecomment-1246316964
	resolver := aws.EndpointResolverFunc(func(service, region string) (aws.Endpoint, error) {
		return aws.Endpoint{
			PartitionID:       "aws",
			URL:               cfg.S3.URL,
			SigningRegion:     cfg.S3.DefaultRegion,
			HostnameImmutable: true,
		}, nil
	})
	s3client := s3.NewFromConfig(aws.Config{
		Region: cfg.S3.DefaultRegion,
		Credentials: credentials.NewStaticCredentialsProvider(
			cfg.S3.AccessKeyId,
			cfg.S3.SecretAccessKey,
			"",
		),
		EndpointResolver: resolver,
	}, func(o *s3.Options) {
		o.UsePathStyle = true
	})
	s3presignedClient := s3.NewPresignClient(s3client)

	exif, err := exiftool.NewExiftool()
	if err != nil {
		return nil, err
	}

	vaultConfig := vaultApi.DefaultConfig()
	vaultConfig.Address = cfg.Vault.URL
	vault, err := vaultApi.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}
	vault.SetToken(cfg.Vault.Token)

	pgxConfig, err := pgxpool.ParseConfig(cfg.PostgreSQL.ConnectionURL)
	if err != nil {
		log.Fatal().Err(err).Msg(fmt.Sprintf("timescaledb: failed to parse dsn uri %s", cfg.PostgreSQL.ConnectionURL))
	}
	// pgxConfig.ConnConfig.Tracer = pgxlogger.NewTraceLogger()
	pool, err := pgxpool.NewWithConfig(ctx, pgxConfig)
	if err != nil {
		log.Fatal().Err(err).Msg(fmt.Sprintf("timescaledb: cannot start connection with %s", cfg.PostgreSQL.ConnectionURL))
	}

	middleware := middleware.NewMiddleware(api, cfg)

	utility.RegisterHandler(ctx, api, middleware)
	knowyourcustomer.RegisterHandler(
		ctx,
		api,
		middleware,
		cfg,
		s3client,
		s3presignedClient,
		exif,
		vault,
		pool,
	)

	return func() error {
		if err := exif.Close(); err != nil {
			return err
		}
		return nil
	}, nil
}
