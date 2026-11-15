package httpx

import (
	"encoding/json"
	"net/http"
)

// JSON writes payload as a JSON response with the given status.
func JSON(w http.ResponseWriter, code int, payload any) {
	response, _ := json.Marshal(payload)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// Error writes {"error": message} with the given status.
func Error(w http.ResponseWriter, code int, message string) {
	JSON(w, code, map[string]string{"error": message})
}

// Success writes {"result": "success"} with status 200.
func Success(w http.ResponseWriter) {
	JSON(w, http.StatusOK, map[string]string{"result": "success"})
}

// DecodeJSON reads a size-limited JSON body; on failure it writes the error response and returns false.
func DecodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		Error(w, http.StatusBadRequest, "Invalid request payload")
		return false
	}
	return true
}
