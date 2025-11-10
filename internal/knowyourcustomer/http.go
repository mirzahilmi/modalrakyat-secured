package knowyourcustomer

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"mime/multipart"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/danielgtaylor/huma/v2"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/config"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/constant"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/middleware"
	"github.com/rs/zerolog/log"
)

type handler struct {
	config            config.Config
	s3client          *s3.Client
	s3presignedClient *s3.PresignClient
}

func RegisterHandler(
	ctx context.Context,
	router huma.API,
	middleware middleware.Middleware,
	config config.Config,
	s3client *s3.Client,
	s3presignedClient *s3.PresignClient,
) {
	h := handler{config, s3client, s3presignedClient}

	huma.Register(router, huma.Operation{
		OperationID: "upload-document",
		Method:      http.MethodPost,
		Path:        "/assets",
		Summary:     "Upload KTP & Slip Gaji",
		Tags:        []string{constant.OAPI_TAG_KYC},
		Security:    []map[string][]string{{constant.OAPI_SECURITY_SCHEME: {}}},
		Middlewares: huma.Middlewares{middleware.NewOidcAuthorization(ctx)},
	}, h.PostAsset)

	huma.Register(router, huma.Operation{
		OperationID: "upload-document",
		Method:      http.MethodGet,
		Path:        "/assets/{filename}",
		Summary:     "Download KTP & Slip gaji",
		Tags:        []string{constant.OAPI_TAG_KYC},
		Security:    []map[string][]string{{constant.OAPI_SECURITY_SCHEME: {}}},
		Middlewares: huma.Middlewares{middleware.NewOidcAuthorization(ctx)},
	}, h.DownloadAsset)

}

type file struct {
	URL     string      `json:"url"`
	Headers http.Header `json:"headers"`
}

func (h handler) PostAsset(ctx context.Context, req *struct {
	RawBody multipart.Form
}) (*struct {
	Body []file
}, error) {
	attachments, ok := req.RawBody.File[constant.MULTIPART_KEY_ATTACHMENTS]
	if !ok {
		return nil, errors.New("missing attachments in multipart")
	}

	keyRaw, err := base64.StdEncoding.DecodeString(h.config.SecretKey)
	if err != nil {
		return nil, err
	}
	sum := md5.Sum(keyRaw)
	digest := base64.StdEncoding.EncodeToString(sum[:])

	urls := []file{}
	for _, header := range attachments {
		_file, err := header.Open()
		if err != nil {
			return nil, err
		}
		defer _file.Close()

		_, err = h.s3client.PutObject(ctx, &s3.PutObjectInput{
			Key:  aws.String(header.Filename),
			Body: _file,

			Bucket:               aws.String(h.config.S3.DefaultBucket),
			SSECustomerAlgorithm: aws.String("AES256"),
			SSECustomerKey:       aws.String(h.config.SecretKey),
			SSECustomerKeyMD5:    aws.String(digest),
		})
		if err != nil {
			return nil, err
		}
		if err := _file.Close(); err != nil {
			log.Error().Err(err).Msg("failed to close file")
		}

		obj, err := h.s3presignedClient.PresignGetObject(ctx, &s3.GetObjectInput{
			Bucket:               aws.String(h.config.S3.DefaultBucket),
			Key:                  aws.String(header.Filename),
			SSECustomerAlgorithm: aws.String("AES256"),
			SSECustomerKey:       aws.String(h.config.SecretKey),
			SSECustomerKeyMD5:    aws.String(digest),
		}, s3.WithPresignExpires(10*time.Minute))

		urls = append(urls, file{
			URL:     obj.URL,
			Headers: obj.SignedHeader,
		})
	}

	return &struct{ Body []file }{Body: urls}, nil
}

func (h handler) DownloadAsset(ctx context.Context, request *struct {
	Filename             string `path:"filename"`
	SSECustomerAlgorithm string `header:"X-Amz-Server-Side-Encryption-Customer-Algorithm" required:"true"`
	SSECustomerKey       string `header:"X-Amz-Server-Side-Encryption-Customer-Key" required:"true"`
	SSECustomerKeyMD5    string `header:"X-Amz-Server-Side-Encryption-Customer-Key-Md5" required:"true"`
}) (*struct {
	Body []byte
}, error) {
	obj, err := h.s3client.GetObject(ctx, &s3.GetObjectInput{
		Bucket:               aws.String(h.config.S3.DefaultBucket),
		Key:                  aws.String(request.Filename),
		SSECustomerAlgorithm: aws.String(request.SSECustomerAlgorithm),
		SSECustomerKey:       aws.String(request.SSECustomerKey),
		SSECustomerKeyMD5:    aws.String(request.SSECustomerKeyMD5),
	})
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(obj.Body)

	return &struct{ Body []byte }{Body: buf.Bytes()}, nil
}
