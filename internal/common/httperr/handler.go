package httperr

import (
	"context"
	"errors"

	"github.com/danielgtaylor/huma/v2"
	_errors "github.com/mirzahilmi/modalrakyat-hardened/internal/common/errors"
	"github.com/rs/zerolog/log"
)

func Handle[T any](ctx context.Context, err error) (*T, error) {
	errValidation := new(_errors.ValidationError)
	if errors.As(err, &errValidation) {
		return nil, huma.Error400BadRequest(errValidation.Error(), errValidation.ProblemDetails())
	}

	log.Error().Err(err).Msg("")
	return nil, huma.Error500InternalServerError("something went wrong")
}
