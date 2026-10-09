package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

const defaultRootDir = "."
const defaultConfigPath = "ui-command-config.json"
const defaultCommandRuntimeConfigPath = "command-runtime-config.json"
const accessCookieName = "ui_command_access"
const accessCookieTTL = 8 * time.Hour
const maxReadFileBytes = 2 * 1024 * 1024
const maxWebSocketMessageBytes = 4 * 1024 * 1024
const maxUploadBytes = 1024 * 1024 * 1024
const webSocketPingInterval = 20 * time.Second
const webSocketWriteTimeout = 10 * time.Second
const jwtTokenTTL = time.Hour

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type Server struct {
	privateKey      *rsa.PrivateKey
	publicKey       []byte
	jwtSecret       string
	rootDir         string
	users           []UserCredential
	accessKeys      []string
	commandRuntime  CommandRuntime
	browserBaseHref string
	proxyPath       string
}

type ConfigFile struct {
	JWTSecret   string            `json:"jwt_secret"`
	Users       []ConfigUser      `json:"users"`
	AccessKeys  []string          `json:"access_keys"`
	ProxyServer ProxyServerConfig `json:"proxy_server"`
}

type ProxyServerConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

type ConfigUser struct {
	Username       string `json:"username"`
	PasswordSHA256 string `json:"password_sha256"`
}

type UserCredential struct {
	Username     string
	PasswordHash [sha256.Size]byte
}

type RuntimeConfig struct {
	JWTSecret       string
	Users           []UserCredential
	AccessKeys      []string
	BrowserBaseHref string
	ProxyPath       string
}

type CommandRuntimeFile struct {
	Paths          map[string][]string          `json:"paths"`
	Environment    map[string]map[string]string `json:"environment"`
	TimeoutSeconds int                          `json:"timeout_seconds"`
}

type CommandRuntime struct {
	Environment []string
	Timeout     time.Duration
}

type EncryptedMessage struct {
	Ciphertext string `json:"ciphertext"`
	Key        string `json:"key,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
}

type ClientRequest struct {
	Action  string `json:"action"`
	Path    string `json:"path,omitempty"`
	Target  string `json:"target,omitempty"`
	Content string `json:"content,omitempty"`
	Session string `json:"session,omitempty"`
	Command string `json:"command,omitempty"`
}

type FileEntry struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"isDir"`
	Size    int64  `json:"size"`
	ModTime string `json:"modTime"`
}

type ServerResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Entries []FileEntry `json:"entries,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type PublicKeyResponse struct {
	PublicKey string `json:"publicKey"`
}

type SystemInfoResponse struct {
	RootDir   string `json:"rootDir"`
	Separator string `json:"separator"`
}

type FileContentResponse struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
}

func main() {
	configPath := os.Getenv("UI_COMMAND_CONFIG")
	if configPath == "" {
		configPath = defaultConfigPath
	}
	config, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("unable to load config %q: %v; run go run script_create_password.go", configPath, err)
	}
	commandConfigPath := os.Getenv("COMMAND_RUNTIME_CONFIG")
	if commandConfigPath == "" {
		commandConfigPath = defaultCommandRuntimeConfigPath
	}
	commandRuntime, err := loadCommandRuntime(commandConfigPath)
	if err != nil {
		log.Fatalf("unable to load command config %q: %v", commandConfigPath, err)
	}

	rootDir := os.Getenv("APP_ROOT")
	if rootDir == "" {
		rootDir = defaultRootDir
	}

	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		log.Fatalf("unable to resolve root directory: %v", err)
	}

	privateKey, publicKeyPEM, err := generateKeyPairPEM(2048)
	if err != nil {
		log.Fatalf("unable to generate server RSA key pair: %v", err)
	}

	s := &Server{
		privateKey:      privateKey,
		publicKey:       publicKeyPEM,
		jwtSecret:       config.JWTSecret,
		rootDir:         absRoot,
		users:           config.Users,
		accessKeys:      config.AccessKeys,
		commandRuntime:  commandRuntime,
		browserBaseHref: config.BrowserBaseHref,
		proxyPath:       config.ProxyPath,
	}

	mux := http.NewServeMux()
	s.registerRoutes(mux, "")
	if s.proxyPath != "" {
		s.registerRoutes(mux, s.proxyPath)
		mux.HandleFunc(s.proxyPath, func(w http.ResponseWriter, r *http.Request) {
			target := s.proxyPath + "/"
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusPermanentRedirect)
		})
	}

	log.Printf("starting server on http://localhost:8082")
	log.Printf("start path: %s", absRoot)
	log.Fatal(http.ListenAndServe(":8082", mux))
}

func (s *Server) registerRoutes(mux *http.ServeMux, prefix string) {
	mux.HandleFunc(prefix+"/", s.indexHandler)
	mux.HandleFunc(prefix+"/api/login", s.loginHandler)
	mux.HandleFunc(prefix+"/publicKey", s.publicKeyHandler)
	mux.HandleFunc(prefix+"/systemInfo", s.systemInfoHandler)
	mux.HandleFunc(prefix+"/api/command", s.commandHandler)
	mux.HandleFunc(prefix+"/api/download", s.downloadHandler)
	mux.HandleFunc(prefix+"/api/upload", s.uploadHandler)
	mux.HandleFunc(prefix+"/ws", s.websocketHandler)
	staticPrefix := prefix + "/static/"
	staticFiles := http.StripPrefix(staticPrefix, http.FileServer(http.Dir("static")))
	mux.Handle(staticPrefix, noCache(s.requirePageAccess(staticFiles)))
}

func (s *Server) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != s.proxyPath+"/" {
		http.NotFound(w, r)
		return
	}
	if !s.hasPageAccess(w, r) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	content, err := os.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "unable to load application page", http.StatusInternalServerError)
		return
	}
	baseHref := s.browserBaseHref
	if baseHref == "" {
		baseHref = "/"
	}
	content = []byte(strings.Replace(string(content), "{{APP_BASE_HREF}}", baseHref, 1))
	w.Write(content)
}

func (s *Server) requirePageAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hasPageAccess(w, r) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hasPageAccess(w http.ResponseWriter, r *http.Request) bool {
	providedKey := r.URL.Query().Get("key")
	if providedKey != "" && s.isValidAccessKey(providedKey) {
		http.SetCookie(w, &http.Cookie{
			Name: accessCookieName, Value: providedKey, Path: "/",
			MaxAge: int(accessCookieTTL.Seconds()), HttpOnly: true,
			Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
		})
		return true
	}
	cookie, err := r.Cookie(accessCookieName)
	return err == nil && s.isValidAccessKey(cookie.Value)
}

func (s *Server) isValidAccessKey(provided string) bool {
	valid := false
	for _, accessKey := range s.accessKeys {
		valid = secureStringEqual(provided, accessKey) || valid
	}
	return valid
}

func secureStringEqual(left, right string) bool {
	leftHash := sha256.Sum256([]byte(left))
	rightHash := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftHash[:], rightHash[:]) == 1
}

func parsePasswordHash(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if value == "" {
		return result, errors.New("value is required")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return result, errors.New("must be a 64-character SHA-256 hex value")
	}
	copy(result[:], decoded)
	return result, nil
}

func loadConfig(path string) (RuntimeConfig, error) {
	var runtimeConfig RuntimeConfig
	content, err := os.ReadFile(path)
	if err != nil {
		return runtimeConfig, err
	}
	var fileConfig ConfigFile
	if err := json.Unmarshal(content, &fileConfig); err != nil {
		return runtimeConfig, fmt.Errorf("invalid JSON: %w", err)
	}
	fileConfig.JWTSecret = strings.TrimSpace(fileConfig.JWTSecret)
	if fileConfig.JWTSecret == "" {
		return runtimeConfig, errors.New("jwt_secret is required")
	}
	if len(fileConfig.Users) == 0 {
		return runtimeConfig, errors.New("at least one user is required")
	}
	if len(fileConfig.AccessKeys) == 0 {
		return runtimeConfig, errors.New("at least one access key is required")
	}

	runtimeConfig.JWTSecret = fileConfig.JWTSecret
	for index, user := range fileConfig.Users {
		user.Username = strings.TrimSpace(user.Username)
		if user.Username == "" {
			return RuntimeConfig{}, fmt.Errorf("users[%d].username is required", index)
		}
		passwordHash, err := parsePasswordHash(user.PasswordSHA256)
		if err != nil {
			return RuntimeConfig{}, fmt.Errorf("users[%d].password_sha256: %w", index, err)
		}
		runtimeConfig.Users = append(runtimeConfig.Users, UserCredential{
			Username: user.Username, PasswordHash: passwordHash,
		})
	}
	for index, accessKey := range fileConfig.AccessKeys {
		accessKey = strings.TrimSpace(accessKey)
		if accessKey == "" {
			return RuntimeConfig{}, fmt.Errorf("access_keys[%d] cannot be empty", index)
		}
		runtimeConfig.AccessKeys = append(runtimeConfig.AccessKeys, accessKey)
	}
	baseHref, proxyPath, err := proxyBaseSettings(fileConfig.ProxyServer)
	if err != nil {
		return RuntimeConfig{}, err
	}
	runtimeConfig.BrowserBaseHref = baseHref
	runtimeConfig.ProxyPath = proxyPath
	return runtimeConfig, nil
}

func proxyBaseHref(config ProxyServerConfig) (string, error) {
	baseHref, _, err := proxyBaseSettings(config)
	return baseHref, err
}

func proxyBaseSettings(config ProxyServerConfig) (string, string, error) {
	if !config.Enabled {
		return "/", "", nil
	}
	proxyPath := strings.TrimSpace(config.Path)
	if proxyPath == "" {
		return "", "", errors.New("proxy_server.path is required when proxy_server.enabled is true")
	}
	if !strings.HasPrefix(proxyPath, "/") {
		return "", "", errors.New("proxy_server.path must start with /")
	}
	if strings.ContainsAny(proxyPath, `?#\`) {
		return "", "", errors.New("proxy_server.path cannot contain ?, #, or \\")
	}
	segments := strings.Split(strings.Trim(proxyPath, "/"), "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return "", "", errors.New("proxy_server.path contains an invalid segment")
		}
	}
	cleanPath := "/" + strings.Join(segments, "/")
	return cleanPath + "/", cleanPath, nil
}

func loadCommandRuntime(path string) (CommandRuntime, error) {
	var runtimeConfig CommandRuntime
	content, err := os.ReadFile(path)
	if err != nil {
		return runtimeConfig, err
	}
	var fileConfig CommandRuntimeFile
	if err := json.Unmarshal(content, &fileConfig); err != nil {
		return runtimeConfig, fmt.Errorf("invalid JSON: %w", err)
	}
	if fileConfig.TimeoutSeconds < 1 || fileConfig.TimeoutSeconds > 3600 {
		return runtimeConfig, errors.New("timeout_seconds must be between 1 and 3600")
	}

	runtimeConfig.Timeout = time.Duration(fileConfig.TimeoutSeconds) * time.Second
	runtimeConfig.Environment = append([]string(nil), os.Environ()...)
	configuredPaths := make([]string, 0, len(fileConfig.Paths[runtime.GOOS]))
	for _, pathEntry := range fileConfig.Paths[runtime.GOOS] {
		pathEntry = strings.TrimSpace(pathEntry)
		if pathEntry != "" {
			configuredPaths = append(configuredPaths, pathEntry)
		}
	}
	if len(configuredPaths) > 0 {
		pathValue := strings.Join(configuredPaths, string(os.PathListSeparator))
		if inheritedPath := os.Getenv("PATH"); inheritedPath != "" {
			pathValue += string(os.PathListSeparator) + inheritedPath
		}
		runtimeConfig.Environment = setEnvironmentValue(runtimeConfig.Environment, "PATH", pathValue)
	}
	for name, value := range fileConfig.Environment[runtime.GOOS] {
		name = strings.TrimSpace(name)
		if name == "" || strings.Contains(name, "=") {
			return CommandRuntime{}, fmt.Errorf("invalid environment variable name %q", name)
		}
		runtimeConfig.Environment = setEnvironmentValue(runtimeConfig.Environment, name, value)
	}
	return runtimeConfig, nil
}

func setEnvironmentValue(environment []string, name, value string) []string {
	prefix := name + "="
	for index, entry := range environment {
		matches := strings.HasPrefix(entry, prefix)
		if runtime.GOOS == "windows" {
			matches = strings.EqualFold(strings.SplitN(entry, "=", 2)[0], name)
		}
		if matches {
			environment[index] = prefix + value
			return environment
		}
	}
	return append(environment, prefix+value)
}

func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "POST required"})
		return
	}
	if !s.hasPageAccess(w, r) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "not found"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	var request LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "invalid login request"})
		return
	}
	providedHash := sha256.Sum256([]byte(request.Password))
	validCredentials := false
	for _, user := range s.users {
		usernameMatches := secureStringEqual(request.Username, user.Username)
		passwordMatches := subtle.ConstantTimeCompare(providedHash[:], user.PasswordHash[:]) == 1
		validCredentials = (usernameMatches && passwordMatches) || validCredentials
	}
	if !validCredentials {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "invalid username or password"})
		return
	}

	token, err := generateJWT(s.jwtSecret, jwtTokenTTL)
	if err != nil {
		log.Printf("JWT generation failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "login failed"})
		return
	}
	json.NewEncoder(w).Encode(LoginResponse{Success: true, Token: token})
}

func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) publicKeyHandler(w http.ResponseWriter, r *http.Request) {
	if !s.hasPageAccess(w, r) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(PublicKeyResponse{PublicKey: string(s.publicKey)}); err != nil {
		log.Printf("public key response failed: %v", err)
	}
}

func (s *Server) systemInfoHandler(w http.ResponseWriter, r *http.Request) {
	if !s.hasPageAccess(w, r) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(SystemInfoResponse{
		RootDir:   s.rootDir,
		Separator: string(os.PathSeparator),
	}); err != nil {
		log.Printf("system info response failed: %v", err)
	}
}

func (s *Server) commandHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ServerResponse{Success: false, Message: "POST required"})
		return
	}

	token := parseBearerToken(r.Header.Get("Authorization"))
	if err := s.validateToken(token); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ServerResponse{Success: false, Message: "unauthorized"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxWebSocketMessageBytes)
	message, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ServerResponse{Success: false, Message: fmt.Sprintf("request read failed: %v", err)})
		return
	}

	request, err := s.decodeClientRequest(message)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ServerResponse{Success: false, Message: err.Error()})
		return
	}

	if err := json.NewEncoder(w).Encode(s.executeRequest(request)); err != nil {
		log.Printf("HTTP command response failed for %s: %v", r.RemoteAddr, err)
	}
}

func (s *Server) downloadHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if err := s.validateToken(parseBearerToken(r.Header.Get("Authorization"))); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	path, err := sanitizePath(s.rootDir, r.URL.Query().Get("path"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		http.Error(w, fmt.Sprintf("download failed: %v", err), http.StatusNotFound)
		return
	}

	if info.IsDir() {
		s.serveFolderArchive(w, r, path, info)
		return
	}
	s.serveDownloadFile(w, r, path, info.Name(), info.ModTime())
}

func (s *Server) serveFolderArchive(w http.ResponseWriter, r *http.Request, path string, info os.FileInfo) {
	archive, err := os.CreateTemp("", "ui-command-download-*.zip")
	if err != nil {
		http.Error(w, fmt.Sprintf("create archive failed: %v", err), http.StatusInternalServerError)
		return
	}
	archivePath := archive.Name()
	if err := archive.Close(); err != nil {
		os.Remove(archivePath)
		http.Error(w, fmt.Sprintf("create archive failed: %v", err), http.StatusInternalServerError)
		return
	}
	if err := os.Remove(archivePath); err != nil {
		http.Error(w, fmt.Sprintf("prepare archive failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer os.Remove(archivePath)

	sevenZipCommand := os.Getenv("SEVEN_ZIP_COMMAND")
	if sevenZipCommand == "" {
		sevenZipCommand = "7z"
	}
	sevenZipPath, err := exec.LookPath(sevenZipCommand)
	if err != nil {
		http.Error(w, fmt.Sprintf("folder download failed: %s command was not found", sevenZipCommand), http.StatusInternalServerError)
		return
	}
	command := exec.Command(sevenZipPath, "a", "-tzip", "-mx=5", archivePath, "--", filepath.Base(path))
	command.Dir = filepath.Dir(path)
	if output, err := command.CombinedOutput(); err != nil {
		log.Printf("7z archive failed for %s: %v: %s", path, err, strings.TrimSpace(string(output)))
		http.Error(w, "folder download failed: 7z could not create the ZIP archive", http.StatusInternalServerError)
		return
	}

	s.serveDownloadFile(w, r, archivePath, info.Name()+".zip", info.ModTime())
}

func (s *Server) serveDownloadFile(w http.ResponseWriter, r *http.Request, path, downloadName string, modTime time.Time) {
	file, err := os.Open(path)
	if err != nil {
		http.Error(w, fmt.Sprintf("download failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	disposition := mime.FormatMediaType("attachment", map[string]string{"filename": downloadName})
	w.Header().Set("Content-Disposition", disposition)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, downloadName, modTime, file)
}

func (s *Server) uploadHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ServerResponse{Success: false, Message: "POST required"})
		return
	}
	if err := s.validateToken(parseBearerToken(r.Header.Get("Authorization"))); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ServerResponse{Success: false, Message: "unauthorized"})
		return
	}
	if r.ContentLength > maxUploadBytes {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		json.NewEncoder(w).Encode(ServerResponse{Success: false, Message: "upload exceeds the 1 GiB limit"})
		return
	}

	targetPath, err := sanitizePath(s.rootDir, r.URL.Query().Get("path"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ServerResponse{Success: false, Message: err.Error()})
		return
	}
	if info, err := os.Stat(targetPath); err == nil && info.IsDir() {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ServerResponse{Success: false, Message: "cannot upload over a folder"})
		return
	}

	tempFile, err := os.CreateTemp(filepath.Dir(targetPath), "."+filepath.Base(targetPath)+".upload-*")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ServerResponse{Success: false, Message: fmt.Sprintf("upload failed: %v", err)})
		return
	}
	tempPath := tempFile.Name()
	completed := false
	defer func() {
		tempFile.Close()
		if !completed {
			os.Remove(tempPath)
		}
	}()

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	written, copyErr := io.Copy(tempFile, r.Body)
	if copyErr != nil {
		status := http.StatusBadRequest
		var maxBytesError *http.MaxBytesError
		if errors.As(copyErr, &maxBytesError) {
			status = http.StatusRequestEntityTooLarge
		}
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(ServerResponse{Success: false, Message: fmt.Sprintf("upload failed: %v", copyErr)})
		return
	}
	if err := tempFile.Sync(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ServerResponse{Success: false, Message: fmt.Sprintf("upload failed: %v", err)})
		return
	}
	if err := tempFile.Close(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ServerResponse{Success: false, Message: fmt.Sprintf("upload failed: %v", err)})
		return
	}
	if err := os.Rename(tempPath, targetPath); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ServerResponse{Success: false, Message: fmt.Sprintf("upload failed: %v", err)})
		return
	}
	completed = true
	json.NewEncoder(w).Encode(ServerResponse{
		Success: true,
		Message: fmt.Sprintf("uploaded %s (%d bytes)", filepath.Base(targetPath), written),
	})
}

func (s *Server) websocketHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		token = parseBearerToken(r.Header.Get("Authorization"))
	}
	if err := s.validateToken(token); err != nil {
		log.Printf("unauthorized websocket request: %v", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(maxWebSocketMessageBytes)
	remoteAddr := r.RemoteAddr

	done := make(chan struct{})
	defer close(done)
	go s.keepWebSocketAlive(conn, remoteAddr, done)

	writeResponse := func(response ServerResponse) bool {
		if err := conn.SetWriteDeadline(time.Now().Add(webSocketWriteTimeout)); err != nil {
			log.Printf("websocket write deadline failed for %s: %v", remoteAddr, err)
			return false
		}
		if err := conn.WriteJSON(response); err != nil {
			log.Printf("websocket write failed for %s: %v", remoteAddr, err)
			return false
		}
		return true
	}

	resp := ServerResponse{Success: true, Message: "authenticated, socket ready"}
	if !writeResponse(resp) {
		return
	}
	log.Printf("websocket client connected: %s", remoteAddr)

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("websocket client disconnected: %s", remoteAddr)
				return
			}
			log.Printf("websocket read error for %s: %v", remoteAddr, err)
			return
		}

		request, err := s.decodeClientRequest(msg)
		if err != nil {
			if !writeResponse(ServerResponse{Success: false, Message: err.Error()}) {
				return
			}
			continue
		}

		response := s.executeRequest(request)
		if !writeResponse(response) {
			return
		}
	}
}

func (s *Server) decodeClientRequest(message []byte) (ClientRequest, error) {
	var request ClientRequest
	if err := json.Unmarshal(message, &request); err == nil && request.Action != "" {
		return request, nil
	}

	var encrypted EncryptedMessage
	if err := json.Unmarshal(message, &encrypted); err != nil || encrypted.Ciphertext == "" {
		return ClientRequest{}, errors.New("invalid message format")
	}

	plaintext, err := s.decryptEnvelope(encrypted)
	if err != nil {
		return ClientRequest{}, fmt.Errorf("decryption failed: %w", err)
	}
	if err := json.Unmarshal(plaintext, &request); err != nil || request.Action == "" {
		return ClientRequest{}, errors.New("request JSON invalid")
	}
	return request, nil
}

func (s *Server) keepWebSocketAlive(conn *websocket.Conn, remoteAddr string, done <-chan struct{}) {
	ticker := time.NewTicker(webSocketPingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			deadline := time.Now().Add(webSocketWriteTimeout)
			if err := conn.WriteControl(websocket.PingMessage, nil, deadline); err != nil {
				log.Printf("websocket ping failed for %s: %v", remoteAddr, err)
				conn.Close()
				return
			}
		case <-done:
			return
		}
	}
}

func (s *Server) decryptMessage(encoded string) ([]byte, error) {
	return s.decryptRSA(encoded)
}

func (s *Server) decryptEnvelope(message EncryptedMessage) ([]byte, error) {
	if message.Key == "" || message.Nonce == "" {
		return s.decryptRSA(message.Ciphertext)
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(message.Key)
	if err != nil {
		return nil, err
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.privateKey, encryptedKey, nil)
	if err != nil {
		return nil, err
	}

	nonce, err := base64.StdEncoding.DecodeString(message.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(message.Ciphertext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (s *Server) decryptRSA(encoded string) ([]byte, error) {
	cipher, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, s.privateKey, cipher, nil)
}

func (s *Server) executeRequest(req ClientRequest) ServerResponse {
	if req.Action == "" {
		return ServerResponse{Success: false, Message: "action required"}
	}

	switch req.Action {
	case "list":
		path, err := sanitizePath(s.rootDir, req.Path)
		if err != nil {
			return ServerResponse{Success: false, Message: err.Error()}
		}
		entries, err := listDirectory(path)
		if err != nil {
			return ServerResponse{Success: false, Message: fmt.Sprintf("list failed: %v", err)}
		}
		return ServerResponse{Success: true, Entries: entries, Message: "directory listed"}

	case "mkdir":
		path, err := sanitizePath(s.rootDir, req.Path)
		if err != nil {
			return ServerResponse{Success: false, Message: err.Error()}
		}
		if err := os.MkdirAll(path, 0755); err != nil {
			return ServerResponse{Success: false, Message: fmt.Sprintf("create folder failed: %v", err)}
		}
		return ServerResponse{Success: true, Message: "folder created"}

	case "rename":
		from, err := sanitizePath(s.rootDir, req.Path)
		if err != nil {
			return ServerResponse{Success: false, Message: err.Error()}
		}

		target, err := sanitizePath(s.rootDir, req.Target)
		if err != nil {
			return ServerResponse{Success: false, Message: err.Error()}
		}
		if err := os.Rename(from, target); err != nil {
			return ServerResponse{Success: false, Message: fmt.Sprintf("rename failed: %v", err)}
		}
		return ServerResponse{Success: true, Message: "entry renamed"}

	case "remove":
		path, err := sanitizePath(s.rootDir, req.Path)
		if err != nil {
			return ServerResponse{Success: false, Message: err.Error()}
		}
		if err := os.RemoveAll(path); err != nil {
			return ServerResponse{Success: false, Message: fmt.Sprintf("remove failed: %v", err)}
		}
		return ServerResponse{Success: true, Message: "entry removed"}

	case "readFile":
		path, err := sanitizePath(s.rootDir, req.Path)
		if err != nil {
			return ServerResponse{Success: false, Message: err.Error()}
		}
		content, err := readTextFile(path)
		if err != nil {
			return ServerResponse{Success: false, Message: fmt.Sprintf("read file failed: %v", err)}
		}
		return ServerResponse{
			Success: true,
			Message: "file read",
			Data: FileContentResponse{
				Path:    path,
				Content: content,
			},
		}

	case "writeFileStart":
		path, err := sanitizePath(s.rootDir, req.Path)
		if err != nil {
			return ServerResponse{Success: false, Message: err.Error()}
		}
		tmpPath, err := tempWritePath(path, req.Session)
		if err != nil {
			return ServerResponse{Success: false, Message: err.Error()}
		}
		if err := os.WriteFile(tmpPath, []byte(req.Content), 0644); err != nil {
			return ServerResponse{Success: false, Message: fmt.Sprintf("start write failed: %v", err)}
		}
		return ServerResponse{Success: true, Message: "write started"}

	case "writeFileAppend":
		path, err := sanitizePath(s.rootDir, req.Path)
		if err != nil {
			return ServerResponse{Success: false, Message: err.Error()}
		}
		tmpPath, err := tempWritePath(path, req.Session)
		if err != nil {
			return ServerResponse{Success: false, Message: err.Error()}
		}
		f, err := os.OpenFile(tmpPath, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return ServerResponse{Success: false, Message: fmt.Sprintf("append write failed: %v", err)}
		}
		defer f.Close()
		if _, err := f.WriteString(req.Content); err != nil {
			return ServerResponse{Success: false, Message: fmt.Sprintf("append write failed: %v", err)}
		}
		return ServerResponse{Success: true, Message: "write appended"}

	case "writeFileFinish":
		path, err := sanitizePath(s.rootDir, req.Path)
		if err != nil {
			return ServerResponse{Success: false, Message: err.Error()}
		}
		tmpPath, err := tempWritePath(path, req.Session)
		if err != nil {
			return ServerResponse{Success: false, Message: err.Error()}
		}
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return ServerResponse{Success: false, Message: "cannot save over a folder"}
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return ServerResponse{Success: false, Message: fmt.Sprintf("finish write failed: %v", err)}
		}
		if err := os.Rename(tmpPath, path); err != nil {
			return ServerResponse{Success: false, Message: fmt.Sprintf("finish write failed: %v", err)}
		}
		return ServerResponse{Success: true, Message: "file saved"}

	case "execute":
		path, err := sanitizePath(s.rootDir, req.Path)
		if err != nil {
			return ServerResponse{Success: false, Message: err.Error()}
		}
		if strings.TrimSpace(req.Command) == "" {
			return ServerResponse{Success: false, Message: "command required"}
		}

		var shell string
		var args []string
		if runtime.GOOS == "windows" {
			shell = os.Getenv("COMSPEC")
			if shell == "" {
				shell = "C:\\Windows\\System32\\cmd.exe"
			}
			args = []string{"/C", req.Command}
		} else {
			shell = "/bin/sh"
			args = []string{"-c", req.Command}
		}
		output, err := runCommand(shell, args, path, s.commandRuntime)
		message := strings.TrimRight(string(output), "\r\n")
		if err != nil {
			if message == "" {
				message = err.Error()
			}
			return ServerResponse{Success: false, Message: message}
		}
		return ServerResponse{Success: true, Message: message}

	default:
		return ServerResponse{Success: false, Message: "unsupported action"}
	}
}

func runCommand(program string, args []string, dir string, commandRuntime CommandRuntime) ([]byte, error) {
	if commandRuntime.Timeout <= 0 {
		commandRuntime.Timeout = 120 * time.Second
	}
	if len(commandRuntime.Environment) == 0 {
		commandRuntime.Environment = os.Environ()
	}
	outputFile, err := os.CreateTemp("", "ui-command-output-*")
	if err != nil {
		return nil, err
	}
	outputPath := outputFile.Name()
	defer os.Remove(outputPath)

	ctx, cancel := context.WithTimeout(context.Background(), commandRuntime.Timeout)
	defer cancel()
	command := exec.CommandContext(ctx, program, args...)
	command.Dir = dir
	command.Env = commandRuntime.Environment
	command.Stdin = os.Stdin
	command.Stdout = outputFile
	command.Stderr = outputFile
	waitErr := command.Run()
	if _, err := outputFile.Seek(0, 0); err != nil {
		outputFile.Close()
		return nil, err
	}
	output, readErr := io.ReadAll(outputFile)
	outputFile.Close()
	if readErr != nil {
		return output, readErr
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return output, fmt.Errorf("command exceeded the %s timeout", commandRuntime.Timeout)
	}
	if waitErr != nil {
		return output, waitErr
	}
	return output, nil
}

func parseBearerToken(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func (s *Server) validateToken(tokenString string) error {
	if tokenString == "" {
		return errors.New("token missing")
	}
	_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected JWT signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})
	if err != nil {
		return fmt.Errorf("token validation failed: %w", err)
	}
	return nil
}

func generateJWT(secret string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func sanitizePath(root, rel string) (string, error) {
	if rel == "" {
		rel = "."
	}

	osPath := filepath.FromSlash(strings.ReplaceAll(rel, "\\", "/"))
	if filepath.IsAbs(osPath) || filepath.VolumeName(osPath) != "" {
		return filepath.Abs(filepath.Clean(osPath))
	}

	absPath, err := filepath.Abs(filepath.Join(root, osPath))
	if err != nil {
		return "", err
	}

	return filepath.Clean(absPath), nil
}

func listDirectory(path string) ([]FileEntry, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	result := make([]FileEntry, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		result = append(result, FileEntry{
			Name:    entry.Name(),
			IsDir:   entry.IsDir(),
			Size:    info.Size(),
			ModTime: info.ModTime().Format(time.RFC3339),
		})
	}
	return result, nil
}

func readTextFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", errors.New("cannot read a folder")
	}
	if info.Size() > maxReadFileBytes {
		return "", fmt.Errorf("file is too large to read in the browser (%d bytes max)", maxReadFileBytes)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func tempWritePath(path, session string) (string, error) {
	if session == "" {
		return "", errors.New("write session required")
	}
	if strings.ContainsAny(session, `/\:.`) {
		return "", errors.New("invalid write session")
	}
	return filepath.Join(filepath.Dir(path), fmt.Sprintf(".%s.tmp-%s", filepath.Base(path), session)), nil
}

func generateKeyPairPEM(bits int) (*rsa.PrivateKey, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return privateKey, publicKeyPEM, nil
}
