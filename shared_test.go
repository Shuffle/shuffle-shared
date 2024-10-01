package shuffle

import (
    "testing"
    "net/http"
)

func TestIsLoop(t *testing.T) {
    handlers := []struct {
        arg         string
        expected    bool
    }{
        {"$exec.#1-2", true},
        {"$exec.#.value.#1", true},
        {"$exec.#1", false},
        {"$exec", false},
        {"$exec.#1.value.#2", false},
        {"$start_node.#", true},
        {"\n$Change_Me\n.#3.value\n", false},
        {"\n\n\n\n$Change_Me\n\n.\n#\n.\n\nvalue\n\n\n", true},
    }

    for _, tt := range handlers {
        result := isLoop(tt.arg)
        if result != tt.expected {
            t.Errorf("isLoop(%s) = %v; expected %v", tt.arg, result, tt.expected)
        }
    }
}

// Simple Test for HandleInternalProxy(client)
// set env SHUFFLE_INTERNAL_HTTP_PROXY to test the function.
func TestHandleInternalProxy(t *testing.T) {
	client := &http.Client{}
	result := HandleInternalProxy(client)

	if result.Transport.(*http.Transport).Proxy != nil {
		proxyURL, _ := result.Transport.(*http.Transport).Proxy(nil)
		t.Logf("Proxy URL set: %v", proxyURL)
	} else {
		t.Log("No proxy set")
	}
}
