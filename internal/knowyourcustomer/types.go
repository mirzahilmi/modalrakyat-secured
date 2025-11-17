package knowyourcustomer

import "net/http"

type File struct {
	URL     string      `json:"url"`
	Headers http.Header `json:"headers"`
}

type TransitEncryptRequest struct {
	Plaintext string `json:"plaintext"`
}

type TransitEncryptResponse struct {
	Ciphertext string `json:"ciphertext"`
	KeyVersion string `json:"key_version"`
	Reference  string `json:"reference"`
}

type SecretKey struct {
	Data []byte
	Encoded,
	DigestEncoded,
	CiphertextEncoded string
}
