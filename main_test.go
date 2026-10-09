package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPageAccessAndPasswordLogin(t *testing.T) {
	passwordHash := sha256.Sum256([]byte("correct-password"))
	server := &Server{
		jwtSecret: "test-jwt-secret",
		users: []UserCredential{
			{Username: "tinaway13", PasswordHash: passwordHash},
		},
		accessKeys: []string{"key_test-access", "key_second-access"},
	}

	t.Run("page requires access key", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		response := httptest.NewRecorder()
		server.indexHandler(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
		}
	})

	pageRequest := httptest.NewRequest(http.MethodGet, "/?key=key_test-access", nil)
	pageResponse := httptest.NewRecorder()
	server.indexHandler(pageResponse, pageRequest)
	if pageResponse.Code != http.StatusOK {
		t.Fatalf("keyed page status = %d, want %d", pageResponse.Code, http.StatusOK)
	}
	cookies := pageResponse.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != accessCookieName {
		t.Fatalf("access cookie = %#v, want %s", cookies, accessCookieName)
	}

	t.Run("second configured key is accepted", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/?key=key_second-access", nil)
		response := httptest.NewRecorder()
		server.indexHandler(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
		}
	})

	t.Run("correct credentials return JWT", func(t *testing.T) {
		body := strings.NewReader(`{"username":"tinaway13","password":"correct-password"}`)
		request := httptest.NewRequest(http.MethodPost, "/api/login", body)
		request.AddCookie(cookies[0])
		response := httptest.NewRecorder()
		server.loginHandler(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", response.Code, http.StatusOK, response.Body.String())
		}
		var login LoginResponse
		if err := json.NewDecoder(response.Body).Decode(&login); err != nil {
			t.Fatalf("decode login response: %v", err)
		}
		if !login.Success || login.Token == "" {
			t.Fatalf("login response = %#v, want token", login)
		}
		if err := server.validateToken(login.Token); err != nil {
			t.Fatalf("returned token is invalid: %v", err)
		}
	})

	t.Run("incorrect password is rejected", func(t *testing.T) {
		body := strings.NewReader(`{"username":"tinaway13","password":"wrong"}`)
		request := httptest.NewRequest(http.MethodPost, "/api/login", body)
		request.AddCookie(cookies[0])
		response := httptest.NewRecorder()
		server.loginHandler(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
		}
	})
}

func TestLoadConfigArrays(t *testing.T) {
	passwordHash := sha256.Sum256([]byte("password"))
	configPath := filepath.Join(t.TempDir(), "config.json")
	configJSON := fmt.Sprintf(`{
  "jwt_secret": "jwt-secret",
  "users": [
    {"username": "first", "password_sha256": %q},
    {"username": "second", "password_sha256": %q}
  ],
  "access_keys": ["key_one", "key_two"]
}`, fmt.Sprintf("%x", passwordHash), fmt.Sprintf("%x", passwordHash))
	if err := os.WriteFile(configPath, []byte(configJSON), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(config.Users) != 2 || config.Users[1].Username != "second" {
		t.Fatalf("users = %#v, want two configured users", config.Users)
	}
	if len(config.AccessKeys) != 2 || config.AccessKeys[1] != "key_two" {
		t.Fatalf("access keys = %#v, want two configured keys", config.AccessKeys)
	}
	if config.BrowserBaseHref != "/" {
		t.Fatalf("browser base href = %q, want /", config.BrowserBaseHref)
	}
	if config.ProxyPath != "" {
		t.Fatalf("proxy path = %q, want empty", config.ProxyPath)
	}
}

func TestProxyBaseHref(t *testing.T) {
	tests := []struct {
		name    string
		config  ProxyServerConfig
		want    string
		wantErr bool
	}{
		{name: "disabled", config: ProxyServerConfig{}, want: "/"},
		{name: "enabled", config: ProxyServerConfig{Enabled: true, Path: "/portal/"}, want: "/portal/"},
		{name: "nested", config: ProxyServerConfig{Enabled: true, Path: "/tools/command"}, want: "/tools/command/"},
		{name: "missing path", config: ProxyServerConfig{Enabled: true}, wantErr: true},
		{name: "relative path", config: ProxyServerConfig{Enabled: true, Path: "portal"}, wantErr: true},
		{name: "parent segment", config: ProxyServerConfig{Enabled: true, Path: "/tools/../portal"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := proxyBaseHref(test.config)
			if test.wantErr {
				if err == nil {
					t.Fatalf("proxyBaseHref() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("proxyBaseHref() error: %v", err)
			}
			if got != test.want {
				t.Fatalf("proxyBaseHref() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestProxyRoutes(t *testing.T) {
	server := &Server{
		accessKeys:      []string{"key_proxy-test"},
		browserBaseHref: "/portal/",
		proxyPath:       "/portal",
	}
	mux := http.NewServeMux()
	server.registerRoutes(mux, "")
	server.registerRoutes(mux, server.proxyPath)

	pageRequest := httptest.NewRequest(http.MethodGet, "/portal/?key=key_proxy-test", nil)
	pageResponse := httptest.NewRecorder()
	mux.ServeHTTP(pageResponse, pageRequest)
	if pageResponse.Code != http.StatusOK {
		t.Fatalf("page status = %d, want %d", pageResponse.Code, http.StatusOK)
	}
	if !strings.Contains(pageResponse.Body.String(), `<base href="/portal/"`) {
		t.Fatalf("page does not contain configured proxy base href")
	}
	cookies := pageResponse.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("proxy page did not set access cookie")
	}

	staticRequest := httptest.NewRequest(http.MethodGet, "/portal/static/styles.css", nil)
	staticRequest.AddCookie(cookies[0])
	staticResponse := httptest.NewRecorder()
	mux.ServeHTTP(staticResponse, staticRequest)
	if staticResponse.Code != http.StatusOK {
		t.Fatalf("static status = %d, want %d", staticResponse.Code, http.StatusOK)
	}
}

func TestLoadCommandRuntime(t *testing.T) {
	if _, err := loadCommandRuntime(defaultCommandRuntimeConfigPath); err != nil {
		t.Fatalf("load default command config: %v", err)
	}

	configuredPath := "/configured-tools"
	if runtime.GOOS == "windows" {
		configuredPath = `C:\configured-tools`
	}
	fileConfig := CommandRuntimeFile{
		Paths: map[string][]string{runtime.GOOS: {configuredPath}},
		Environment: map[string]map[string]string{
			runtime.GOOS: {"UI_COMMAND_TEST_VALUE": "loaded"},
		},
		TimeoutSeconds: 45,
	}
	content, err := json.Marshal(fileConfig)
	if err != nil {
		t.Fatalf("encode command config: %v", err)
	}
	configPath := filepath.Join(t.TempDir(), "command-config.json")
	if err := os.WriteFile(configPath, content, 0600); err != nil {
		t.Fatalf("write command config: %v", err)
	}

	config, err := loadCommandRuntime(configPath)
	if err != nil {
		t.Fatalf("load command config: %v", err)
	}
	if config.Timeout != 45*time.Second {
		t.Fatalf("timeout = %s, want 45s", config.Timeout)
	}
	pathValue := environmentValue(config.Environment, "PATH")
	if !strings.HasPrefix(strings.ToLower(pathValue), strings.ToLower(configuredPath)) {
		t.Fatalf("PATH = %q, want prefix %q", pathValue, configuredPath)
	}
	if value := environmentValue(config.Environment, "UI_COMMAND_TEST_VALUE"); value != "loaded" {
		t.Fatalf("UI_COMMAND_TEST_VALUE = %q, want loaded", value)
	}
}

func environmentValue(environment []string, name string) string {
	for _, entry := range environment {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], name) {
			return parts[1]
		}
	}
	return ""
}

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
