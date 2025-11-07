package utility

import (
	"context"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/danielgtaylor/huma/v2"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/constant"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/errors"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/httperr"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/middleware"
)

type handler struct {
}

func RegisterHandler(ctx context.Context, router huma.API, middleware middleware.Middleware) {
	h := handler{}

	huma.Register(router, huma.Operation{
		OperationID: "check-health",
		Method:      http.MethodGet,
		Path:        "/healthz",
		Summary:     "Check health",
		Tags:        []string{constant.OAPI_TAG_MISC},
		Security:    []map[string][]string{},
	}, h.GetHealthz)

	huma.Register(router, huma.Operation{
		OperationID: "userinfo",
		Method:      http.MethodGet,
		Path:        "/userinfo",
		Summary:     "Whoami?",
		Tags:        []string{constant.OAPI_TAG_MISC},
		Security:    []map[string][]string{{constant.OAPI_SECURITY_SCHEME: {}}},
		Middlewares: huma.Middlewares{middleware.NewOidcAuthorization(ctx)},
	}, h.GetUserInfo)
}

func (h handler) GetHealthz(ctx context.Context, _ *struct{}) (*struct{}, error) {
	return nil, nil
}

func (h handler) GetUserInfo(ctx context.Context, _ *struct{}) (*struct{ Body UserInfo }, error) {
	principal, ok := ctx.Value(constant.CONTEXT_KEY_PRINCIPAL).(*oidc.IDToken)
	if !ok {
		return httperr.Handle[struct{ Body UserInfo }](ctx,
			errors.NewInternalError("utility: failed to assert principal struct"),
		)
	}
	return &struct{ Body UserInfo }{Body: UserInfo{Id: principal.Subject}}, nil
}
