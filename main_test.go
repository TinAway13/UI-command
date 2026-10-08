package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCommandHandler(t *testing.T) {
	privateKey, publicKey, err := generateKeyPairPEM(2048)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	const secret = "test-secret"
	server := &Server{
		privateKey: privateKey,
		publicKey:  publicKey,
		jwtSecret:  secret,
		rootDir:    t.TempDir(),
	}
	token, err := generateJWT(secret, time.Minute)
	if err != nil {
		t.Fatalf("generate JWT: %v", err)
	}

	t.Run("authenticated command", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/api/command", strings.NewReader(`{"action":"list","path":"."}`))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		responseRecorder := httptest.NewRecorder()

		server.commandHandler(responseRecorder, request)

		if responseRecorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", responseRecorder.Code, http.StatusOK, responseRecorder.Body.String())
		}
		var response ServerResponse
		if err := json.NewDecoder(responseRecorder.Body).Decode(&response); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if !response.Success {
			t.Fatalf("response = %#v, want success", response)
		}
	})

	t.Run("authentication required", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/api/command", strings.NewReader(`{"action":"list","path":"."}`))
		responseRecorder := httptest.NewRecorder()

		server.commandHandler(responseRecorder, request)

		if responseRecorder.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", responseRecorder.Code, http.StatusUnauthorized)
		}
	})
}
