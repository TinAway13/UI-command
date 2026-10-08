package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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

func TestUploadAndDownloadFile(t *testing.T) {
	privateKey, publicKey, err := generateKeyPairPEM(2048)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	const secret = "test-secret"
	rootDir := t.TempDir()
	server := &Server{
		privateKey: privateKey,
		publicKey:  publicKey,
		jwtSecret:  secret,
		rootDir:    rootDir,
	}
	token, err := generateJWT(secret, time.Minute)
	if err != nil {
		t.Fatalf("generate JWT: %v", err)
	}

	content := []byte("uploaded content")
	targetPath := filepath.Join(rootDir, "uploaded.txt")
	uploadRequest := httptest.NewRequest(http.MethodPost, "/api/upload?path="+url.QueryEscape(targetPath), bytes.NewReader(content))
	uploadRequest.Header.Set("Authorization", "Bearer "+token)
	uploadResponse := httptest.NewRecorder()
	server.uploadHandler(uploadResponse, uploadRequest)
	if uploadResponse.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want %d; body: %s", uploadResponse.Code, http.StatusOK, uploadResponse.Body.String())
	}

	stored, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("read uploaded file: %v", err)
	}
	if !bytes.Equal(stored, content) {
		t.Fatalf("uploaded content = %q, want %q", stored, content)
	}

	downloadRequest := httptest.NewRequest(http.MethodGet, "/api/download?path="+url.QueryEscape(targetPath), nil)
	downloadRequest.Header.Set("Authorization", "Bearer "+token)
	downloadResponse := httptest.NewRecorder()
	server.downloadHandler(downloadResponse, downloadRequest)
	if downloadResponse.Code != http.StatusOK {
		t.Fatalf("download status = %d, want %d; body: %s", downloadResponse.Code, http.StatusOK, downloadResponse.Body.String())
	}
	if !bytes.Equal(downloadResponse.Body.Bytes(), content) {
		t.Fatalf("downloaded content = %q, want %q", downloadResponse.Body.Bytes(), content)
	}
	if disposition := downloadResponse.Header().Get("Content-Disposition"); !strings.Contains(disposition, "uploaded.txt") {
		t.Fatalf("Content-Disposition = %q, want uploaded filename", disposition)
	}
}
