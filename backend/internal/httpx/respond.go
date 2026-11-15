package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// JSON writes payload as a JSON response with the given status.
func JSON(w http.ResponseWriter, code int, payload any) {
	response, _ := json.Marshal(payload)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// Error writes the API's error body, {"error": "<code>", "message": "<text>"}, with a code derived from
// the status (see StatusCode). The message is for people; clients branch on the code.
func Error(w http.ResponseWriter, status int, message string) {
	ErrorCode(w, status, StatusCode(status), message)
}

// ErrorCode is Error with an explicit code, for errors a client must be able to tell apart.
func ErrorCode(w http.ResponseWriter, status int, code, message string) {
	JSON(w, status, map[string]string{"error": code, "message": message})
}

// StatusCode is the error code for an HTTP status.
func StatusCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusMethodNotAllowed:
		return "method_not_allowed"
	case http.StatusConflict:
		return "conflict"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusServiceUnavailable:
		return "unavailable"
	}
	if status >= 500 {
		return "server_error"
	}
	return "error"
}

// NoContent answers 204.
func NoContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

// Success writes {"result": "success"} with status 200.
func Success(w http.ResponseWriter) {
	JSON(w, http.StatusOK, map[string]string{"result": "success"})
}

// DecodeJSON reads a size-limited JSON object into v. Unknown fields and trailing data are refused, so a
// misspelt field is an error instead of being silently ignored. On failure it writes the error response
// and returns false.
func DecodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil && dec.More() {
		err = errors.New("unexpected data after the JSON object")
	}
	if err != nil {
		msg := "Invalid request body"
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			msg = "The request body is larger than 1 MiB"
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			msg = "Unknown field " + strings.TrimPrefix(err.Error(), "json: unknown field ")
		case errors.Is(err, io.EOF):
			msg = "A JSON body is required"
		}
		Error(w, http.StatusBadRequest, msg)
		return false
	}
	return true
}
