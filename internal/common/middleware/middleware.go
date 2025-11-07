package middleware

import (
	"github.com/danielgtaylor/huma/v2"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/config"
)

type Middleware struct {
	api    huma.API
	config config.Config
}

func NewMiddleware(api huma.API, config config.Config) Middleware {
	return Middleware{api, config}
}
