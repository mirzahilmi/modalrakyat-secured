package knowyourcustomer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/barasher/go-exiftool"
	"github.com/danielgtaylor/huma/v2"
	vaultApi "github.com/hashicorp/vault/api"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/config"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/constant"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/cryptography"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/middleware"
	"github.com/rs/zerolog/log"
)

type handler struct {
	config            config.Config
	s3client          *s3.Client
	s3presignedClient *s3.PresignClient
	exif              *exiftool.Exiftool
	vault             *vaultApi.Client
}

func RegisterHandler(
	ctx context.Context,
	router huma.API,
	middleware middleware.Middleware,
	config config.Config,
	s3client *s3.Client,
	s3presignedClient *s3.PresignClient,
	exif *exiftool.Exiftool,
	vault *vaultApi.Client,
) {
	h := handler{config, s3client, s3presignedClient, exif, vault}

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
		OperationID: "download-document",
		Method:      http.MethodGet,
		Path:        "/assets/{filename}",
		Summary:     "Download KTP & Slip gaji",
		Tags:        []string{constant.OAPI_TAG_KYC},
		Security:    []map[string][]string{{constant.OAPI_SECURITY_SCHEME: {}}},
		Middlewares: huma.Middlewares{middleware.NewOidcAuthorization(ctx)},
	}, h.DownloadAsset)

}

func (h handler) PostAsset(ctx context.Context, req *struct {
	RawBody multipart.Form
}) (*struct {
	Body []File
}, error) {
	attachments, ok := req.RawBody.File[constant.MULTIPART_KEY_ATTACHMENTS]
	if !ok {
		return nil, errors.New("missing attachments in multipart")
	}

	path := fmt.Sprintf(
		"%s/encrypt/%s",
		h.config.Vault.TransitBasePath,
		h.config.Vault.TransitKey,
	)

	keys := make([]SecretKey, len(attachments))
	inputs := make([]TransitEncryptRequest, len(keys))
	for i := range keys {
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}
		keyEncoded := base64.StdEncoding.EncodeToString(key)

		hf := sha256.New()
		if _, err := hf.Write(key); err != nil {
			return nil, err
		}
		digest := hf.Sum(nil)
		digestEncoded := base64.StdEncoding.EncodeToString(digest)

		keys[i] = SecretKey{
			Data:          key,
			Encoded:       keyEncoded,
			DigestEncoded: digestEncoded,
		}
		inputs[i] = TransitEncryptRequest{Plaintext: keyEncoded}
	}

	secret, err := h.vault.Logical().WriteWithRequest(ctx,
		vaultApi.NewLogicalWriteRequest(
			path,
			map[string]interface{}{"batch_input": inputs},
			make(http.Header),
		),
	)
	if err != nil {
		return nil, err
	}
	resultsUntyped, ok := secret.Data["batch_results"]
	if !ok {
		return nil, errors.New("vault transit secrets engine missing batch_results response field")
	}
	results, ok := resultsUntyped.([]interface{})
	if !ok {
		return nil, errors.New("body.batch_results is not the correct type")
	}
	for i := range results {
		resultUntyped, ok := results[i].(map[string]interface{})
		if !ok {
			continue
		}
		untyped, ok := resultUntyped["ciphertext"]
		if !ok {
			continue
		}
		ciphertext, ok := untyped.(string)
		if !ok {
			continue
		}
		keys[i].CiphertextEncoded = ciphertext
	}

	urls := []File{}
	filenames := []string{}
	for i, header := range attachments {
		_file, err := header.Open()
		if err != nil {
			return nil, err
		}
		defer _file.Close()

		body := new(bytes.Buffer)
		if _, err := io.Copy(body, _file); err != nil {
			return nil, err
		}
		if err := _file.Close(); err != nil {
			log.Error().Err(err).Msg("failed to close file")
		}

		ciphertext, err := cryptography.EncryptAesGcm(keys[i].Data, body.Bytes())
		if err != nil {
			return nil, err
		}

		f := bytes.NewReader(ciphertext)

		_, err = h.s3client.PutObject(ctx, &s3.PutObjectInput{
			Key:    aws.String(header.Filename),
			Body:   f,
			Bucket: aws.String(h.config.S3.DefaultBucket),
			Metadata: map[string]string{
				constant.EDEK_HEADER: keys[i].CiphertextEncoded,
				constant.DEK_DIGEST:  keys[i].DigestEncoded,
			},
		})
		if err != nil {
			return nil, err
		}
		if err := _file.Close(); err != nil {
			log.Error().Err(err).Msg("failed to close file")
		}

		obj, err := h.s3presignedClient.PresignHeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(h.config.S3.DefaultBucket),
			Key:    aws.String(header.Filename),
		}, s3.WithPresignExpires(10*time.Minute))

		urls = append(urls, File{
			URL:     obj.URL,
			Headers: obj.SignedHeader,
		})
		filenames = append(filenames, fmt.Sprintf("%s/%s", os.TempDir(), header.Filename))
	}

	return &struct{ Body []File }{Body: urls}, nil
}

func (h handler) DownloadAsset(ctx context.Context, request *struct {
	Filename string `path:"filename"`
}) (*struct {
	Body []byte
}, error) {
	obj, err := h.s3client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(h.config.S3.DefaultBucket),
		Key:    aws.String(request.Filename),
	})
	if err != nil {
		return nil, err
	}
	edek, ok := obj.Metadata[constant.EDEK_HEADER]
	if !ok {
		return nil, errors.New("missing stored edek in object metadata")
	}

	path := fmt.Sprintf(
		"%s/decrypt/%s",
		h.config.Vault.TransitBasePath,
		h.config.Vault.TransitKey,
	)
	secret, err := h.vault.Logical().WriteWithRequest(ctx,
		vaultApi.NewLogicalWriteRequest(
			path,
			map[string]interface{}{"ciphertext": edek},
			make(http.Header),
		))
	if err != nil {
		return nil, err
	}
	untyped, ok := secret.Data["plaintext"]
	if !ok {
		return nil, errors.New("missing plaintext response from vault")
	}
	dekEncoded, ok := untyped.(string)
	if !ok {
		return nil, errors.New("stored dek is not a valid string type")
	}
	dek, err := base64.StdEncoding.DecodeString(dekEncoded)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, obj.Body); err != nil {
		return nil, err
	}
	defer obj.Body.Close()

	plaintext, err := cryptography.DecryptAesGcm(dek, buf.Bytes())
	if err != nil {
		return nil, err
	}

	return &struct{ Body []byte }{Body: plaintext}, nil

}
