package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

const defaultJWTSecret = "change_this_secret_to_a_strong_value"
const defaultRootDir = "."
const maxReadFileBytes = 2 * 1024 * 1024

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type Server struct {
	privateKey *rsa.PrivateKey
	publicKey  []byte
	jwtSecret  string
	rootDir    string
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

func main() {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = defaultJWTSecret
		log.Println("WARNING: using default JWT secret. Set JWT_SECRET to a strong value in production.")
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

	startupToken, err := generateJWT(jwtSecret, time.Hour)
	if err != nil {
		log.Fatalf("unable to generate startup JWT token: %v", err)
	}

	s := &Server{
		privateKey: privateKey,
		publicKey:  publicKeyPEM,
		jwtSecret:  jwtSecret,
		rootDir:    absRoot,
	}

	http.HandleFunc("/", s.indexHandler)
	http.HandleFunc("/publicKey", s.publicKeyHandler)
	http.HandleFunc("/systemInfo", s.systemInfoHandler)
	http.HandleFunc("/ws", s.websocketHandler)
	staticFiles := http.StripPrefix("/static/", http.FileServer(http.Dir("static")))
	http.Handle("/static/", noCache(staticFiles))

	log.Printf("starting server on http://localhost:8080")
	log.Printf("start path: %s", absRoot)
	log.Printf("JWT token valid for 60 minutes: %s", startupToken)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func (s *Server) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFile(w, r, "static/index.html")
}

func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) publicKeyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(PublicKeyResponse{PublicKey: string(s.publicKey)})
}

func (s *Server) systemInfoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SystemInfoResponse{
		RootDir:   s.rootDir,
		Separator: string(os.PathSeparator),
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

	resp := ServerResponse{Success: true, Message: "authenticated, socket ready"}
	conn.WriteJSON(resp)

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("websocket client disconnected")
				return
			}
			log.Printf("read error: %v", err)
			return
		}

		var request ClientRequest
		if err := json.Unmarshal(msg, &request); err != nil || request.Action == "" {
			var encrypted EncryptedMessage
			if err := json.Unmarshal(msg, &encrypted); err != nil {
				conn.WriteJSON(ServerResponse{Success: false, Message: "invalid message format"})
				continue
			}

			plaintext, err := s.decryptEnvelope(encrypted)
			if err != nil {
				conn.WriteJSON(ServerResponse{Success: false, Message: fmt.Sprintf("decryption failed: %v", err)})
				continue
			}
			if err := json.Unmarshal(plaintext, &request); err != nil {
				conn.WriteJSON(ServerResponse{Success: false, Message: "request JSON invalid"})
				continue
			}
		}

		response := s.executeRequest(request)
		conn.WriteJSON(response)
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
			args = []string{shell, "/C", req.Command}
		} else {
			shell = "/bin/sh"
			args = []string{shell, "-c", req.Command}
		}
		output, err := runCommand(shell, args, path)
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

func runCommand(program string, args []string, dir string) ([]byte, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	process, err := os.StartProcess(program, args, &os.ProcAttr{
		Dir:   dir,
		Files: []*os.File{os.Stdin, writer, writer},
	})
	writer.Close()
	if err != nil {
		return nil, err
	}

	output, readErr := io.ReadAll(reader)
	state, waitErr := process.Wait()
	if readErr != nil {
		return output, readErr
	}
	if waitErr != nil {
		return output, waitErr
	}
	if !state.Success() {
		return output, fmt.Errorf("command exited with %s", state.String())
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
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
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
