// Package apierr defines the typed API error shared by the HTTP layer, the
// ingest pipeline and the store.
package apierr

import (
	"errors"
	"fmt"
	"net/http"
)

// Error is an error that maps to a fixed HTTP status and a stable code.
type Error struct {
	Status  int
	Code    string
	Message string
	Details any
	// Headers are extra response headers (e.g. Retry-After).
	Headers map[string]string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

// New builds an Error.
func New(status int, code, message string) *Error {
	return &Error{Status: status, Code: code, Message: message}
}

// WithDetails returns a copy of e carrying details.
func (e *Error) WithDetails(d any) *Error {
	c := *e
	c.Details = d
	return &c
}

// Newf builds an Error with a formatted message.
func Newf(status int, code, format string, args ...any) *Error {
	return New(status, code, fmt.Sprintf(format, args...))
}

// As extracts an *Error from err.
func As(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// Common constructors.
func BadRequest(msg string) *Error { return New(http.StatusBadRequest, "bad_request", msg) }
func Validation(msg string, details any) *Error {
	return &Error{Status: http.StatusUnprocessableEntity, Code: "validation_failed", Message: msg, Details: details}
}

// ValidationField is a 422 validation_failed error about one input field. field is the JSON name of
// the field; objects use a dotted path ("login.password", "headers.Authorization") and list
// elements an index ("dast_crawl_exclude[2]"). The response carries details.field = field.
func ValidationField(field, msg string) *Error {
	return Validation(msg, map[string]any{"field": field})
}

// BadRequestField is a 400 bad_request error about one query or body field.
func BadRequestField(field, msg string) *Error {
	return New(http.StatusBadRequest, "bad_request", msg).WithDetails(map[string]any{"field": field})
}

// WithField returns a copy of e whose details carry field (existing detail keys are kept).
func (e *Error) WithField(field string) *Error {
	d := map[string]any{}
	switch m := e.Details.(type) {
	case map[string]any:
		for k, v := range m {
			d[k] = v
		}
	case map[string]string:
		for k, v := range m {
			d[k] = v
		}
	}
	d["field"] = field
	return e.WithDetails(d)
}

// FieldOf returns details.field of e ("" when there is none).
func FieldOf(e *Error) string {
	switch m := e.Details.(type) {
	case map[string]any:
		s, _ := m["field"].(string)
		return s
	case map[string]string:
		return m["field"]
	}
	return ""
}

// FieldError is one failed input field.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	// Code is the specific error code (e.g. "address_not_allowed"); empty means validation_failed.
	Code string `json:"code,omitempty"`
}

// FieldErrors collects the failed fields of one request, so that the client learns about all of
// them at once. The zero value is ready to use.
type FieldErrors struct {
	items []FieldError
	first *Error // the typed error behind items[0] when it was added with AddError
}

// Add records a validation failure of field.
func (f *FieldErrors) Add(field, msg string) {
	f.items = append(f.items, FieldError{Field: field, Message: msg})
}

// AddError records err. A typed error that carries details.field keeps its field and (when it is
// not validation_failed) its code; any other error is returned unchanged with false so that the
// caller can abort with it.
func (f *FieldErrors) AddError(err error) bool {
	e, ok := As(err)
	if !ok || e.Status != http.StatusUnprocessableEntity {
		return false
	}
	fe := FieldError{Field: FieldOf(e), Message: e.Message}
	if e.Code != "validation_failed" {
		fe.Code = e.Code
	}
	if len(f.items) == 0 {
		f.first = e
	}
	f.items = append(f.items, fe)
	return true
}

// Merge records every field error of err (single or multi); false when err is not a 422.
func (f *FieldErrors) Merge(err error) bool {
	e, ok := As(err)
	if !ok || e.Status != http.StatusUnprocessableEntity {
		return false
	}
	if list := FieldsOf(e); len(list) > 1 {
		f.items = append(f.items, list...)
		return true
	}
	return f.AddError(err)
}

// FieldsOf lists the field errors carried by e: details.fields, else the single details.field.
func FieldsOf(e *Error) []FieldError {
	if m, ok := e.Details.(map[string]any); ok {
		if l, ok := m["fields"].([]FieldError); ok {
			return l
		}
	}
	if fld := FieldOf(e); fld != "" {
		return []FieldError{{Field: fld, Message: e.Message}}
	}
	return nil
}

// Len is the number of recorded failures.
func (f *FieldErrors) Len() int { return len(f.items) }

// Err returns nil when nothing was recorded. One failure yields the plain single-field error;
// several yield a 422 validation_failed whose message and details.field are those of the first
// failure and whose details.fields lists all of them.
func (f *FieldErrors) Err() error {
	switch len(f.items) {
	case 0:
		return nil
	case 1:
		if f.first != nil {
			return f.first
		}
		return ValidationField(f.items[0].Field, f.items[0].Message)
	}
	list := append([]FieldError(nil), f.items...)
	return Validation(list[0].Message, map[string]any{"field": list[0].Field, "fields": list})
}
func NotFound(what string) *Error {
	return New(http.StatusNotFound, "not_found", what+" not found.")
}
func Forbidden(code, msg string) *Error { return New(http.StatusForbidden, code, msg) }
func Conflict(code, msg string) *Error  { return New(http.StatusConflict, code, msg) }
func Internal() *Error {
	return New(http.StatusInternalServerError, "internal", "Internal server error.")
}
