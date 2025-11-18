package constant

const (
	// MUST BE lower-case, bcs somehow aws-sdk-go-v2 always returns lower-cased header :/
	EDEK_HEADER = "x-edek"
	DEK_DIGEST  = "x-dek-digest"
)
