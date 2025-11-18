package knowyourcustomer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/barasher/go-exiftool"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/danielgtaylor/huma/v2"
	vaultApi "github.com/hashicorp/vault/api"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/config"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/constant"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/cryptography"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/middleware"
	"github.com/oklog/ulid/v2"
	"github.com/rs/zerolog/log"
)

type handler struct {
	config            config.Config
	s3client          *s3.Client
	s3presignedClient *s3.PresignClient
	exif              *exiftool.Exiftool
	vault             *vaultApi.Client
	pool              *pgxpool.Pool
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
	pool *pgxpool.Pool,
) {
	h := handler{config, s3client, s3presignedClient, exif, vault, pool}

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
	Body []string
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

	filenames := make([]string, len(attachments))
	files := make([]File, len(attachments))
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
			log.Warn().Err(err).Msg("failed to close file")
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
				constant.DEK_DIGEST:  keys[i].DigestEncoded},
		})
		if err != nil {
			return nil, err
		}

		filenames[i] = header.Filename

		tmpFilename := fmt.Sprintf("modalrakyat-%s", header.Filename)
		tmpFilepath := filepath.Join(os.TempDir(), tmpFilename)
		if err := os.WriteFile(tmpFilepath, body.Bytes(), 0644); err != nil {
			return nil, err
		}
		defer os.Remove(tmpFilepath)

		exif := h.exif.ExtractMetadata(tmpFilepath)
		os.Remove(tmpFilepath)

		if len(exif) < 1 {
			return nil, errors.New("empty exif metadata")
		}
		jsonMetas, err := json.Marshal(exif[0].Fields)
		if err != nil {
			return nil, err
		}

		files[i] = File{
			Filename: header.Filename,
			Metadata: jsonMetas,
		}
	}

	principalToken, ok := ctx.Value(constant.CONTEXT_KEY_PRINCIPAL).(*oidc.IDToken)
	if !ok {
		log.Warn().Msg("missing principal token in context, skipping db insertion")
		return &struct{ Body []string }{Body: filenames}, nil
	}

	rows := make([][]interface{}, len(files))
	for i, file := range files {
		row := rows[i]
		row = append(row, ulid.Make().String())
		row = append(row, file.Filename)
		row = append(row, file.Metadata)
		row = append(row, principalToken.Subject)
		row = append(row, time.Now())
		rows[i] = row
	}

	if _, err := h.pool.CopyFrom(
		ctx,
		pgx.Identifier{constant.TABLE_DOCUMENTS},
		[]string{"id", "filename", "metadata", "created_by", "created_at"},
		pgx.CopyFromRows(rows),
	); err != nil {
		return nil, err
	}

	return &struct{ Body []string }{Body: filenames}, nil
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
