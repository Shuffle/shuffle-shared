package shuffle

import (
    "testing"
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
    }

    for _, tt := range handlers {
        result := isLoop(tt.arg)
        if result != tt.expected {
            t.Errorf("isLoop(%s) = %v; expected %v", tt.arg, result, tt.expected)
        }
    }
}
