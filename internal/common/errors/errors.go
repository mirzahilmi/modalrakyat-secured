package errors

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

type ValidationError struct {
	fields map[string]string
}

func (e *ValidationError) Error() string {
	return "validation errors"
}

func NewValidationError(fields map[string]string) *ValidationError {
	return &ValidationError{fields}
}

func (e ValidationError) ProblemDetails() *huma.ErrorModel {
	errors := make([]*huma.ErrorDetail, len(e.fields))
	i := 0
	for field, message := range e.fields {
		errors[i] = &huma.ErrorDetail{
			Message:  message,
			Location: field,
		}
	}
	return &huma.ErrorModel{
		Title:  http.StatusText(http.StatusBadRequest),
		Status: http.StatusBadRequest,
		Detail: "Validation failed",
		Errors: errors,
	}
}

type InternalError struct {
	message string
	values  []any
}

func (e *InternalError) Error() string {
	return e.message
}

func NewInternalError(message string, values ...any) *InternalError {
	return &InternalError{message, values}
}
