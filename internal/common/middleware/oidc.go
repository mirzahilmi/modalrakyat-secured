package middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/danielgtaylor/huma/v2"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/constant"
	"github.com/rs/zerolog/log"
)

func (m Middleware) NewOidcAuthorization(ctx context.Context) func(huma.Context, func(huma.Context)) {
	oidcProvider, err := oidc.NewProvider(ctx, m.config.Oidc.Issuer)
	if err != nil {
		log.Fatal().Err(err).Msg("oidc: failed create oidc provider instance")
	}
	verifier := oidcProvider.VerifierContext(ctx, &oidc.Config{ClientID: m.config.Oidc.ClientId})

	return func(ctx huma.Context, next func(huma.Context)) {
		header := ctx.Header("Authorization")
		if header == "" || len(header) < 7 {
			if err := huma.WriteErr(m.api, ctx, http.StatusForbidden, "missing/malformed authorization header"); err != nil {
				log.Warn().Err(err).Msg("oidc: failed write http error")
			}
			return
		}
		bearerToken := header[7:]

		token, err := verifier.Verify(ctx.Context(), bearerToken)
		if err != nil {
			log.Debug().Err(err).Msg(fmt.Sprintf("oidc: failed to verify id token: %s", bearerToken))
			if err := huma.WriteErr(m.api, ctx, http.StatusForbidden, "unauthorized access"); err != nil {
				log.Warn().Err(err).Msg("oidc: failed write http error")
			}
			return
		}

		ctx = huma.WithValue(ctx, constant.CONTEXT_KEY_PRINCIPAL, token)
		next(ctx)
	}
}
