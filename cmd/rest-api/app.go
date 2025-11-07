package main

import (
	"context"

	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/middleware"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/utility"
)

func setup(ctx context.Context) error {
	middleware := middleware.NewMiddleware(api, cfg)

	utility.RegisterHandler(ctx, api, middleware)

	return nil
}
