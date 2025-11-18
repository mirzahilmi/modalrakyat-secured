package knowyourcustomer

import "encoding/json"

type File struct {
	Filename string
	Metadata json.RawMessage
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
