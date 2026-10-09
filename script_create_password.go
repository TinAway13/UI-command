//go:build ignore

// Run with: go run script_create_password.go
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

type generatedConfig struct {
	JWTSecret   string               `json:"jwt_secret"`
	Users       []generatedUser      `json:"users"`
	AccessKeys  []string             `json:"access_keys"`
	ProxyServer generatedProxyServer `json:"proxy_server"`
}

type generatedProxyServer struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

type generatedUser struct {
	Username       string `json:"username"`
	PasswordSHA256 string `json:"password_sha256"`
}

type displayedPassword struct {
	Username string
	Password string
}

func main() {
	outputPath := flag.String("output", "ui-command-config.json", "configuration file to create")
	userList := flag.String("users", "TinAway13", "comma-separated usernames")
	keyCount := flag.Int("keys", 1, "number of access keys to generate")
	proxyPath := flag.String("proxy-path", "", "public reverse-proxy path, for example /portal")
	flag.Parse()

	if *keyCount < 1 {
		log.Fatal("keys must be at least 1")
	}
	usernames := parseUsernames(*userList)
	if len(usernames) == 0 {
		log.Fatal("at least one username is required")
	}

	normalizedProxyPath := strings.TrimRight(strings.TrimSpace(*proxyPath), "/")
	if normalizedProxyPath != "" && !strings.HasPrefix(normalizedProxyPath, "/") {
		log.Fatal("proxy-path must start with /")
	}
	config := generatedConfig{
		JWTSecret: randomSecret(48),
		ProxyServer: generatedProxyServer{
			Enabled: normalizedProxyPath != "",
			Path:    normalizedProxyPath,
		},
	}
	passwords := make([]displayedPassword, 0, len(usernames))
	for _, username := range usernames {
		password := randomSecret(24)
		passwordDigest := sha256.Sum256([]byte(password))
		config.Users = append(config.Users, generatedUser{
			Username:       username,
			PasswordSHA256: hex.EncodeToString(passwordDigest[:]),
		})
		passwords = append(passwords, displayedPassword{Username: username, Password: password})
	}
	for index := 0; index < *keyCount; index++ {
		config.AccessKeys = append(config.AccessKeys, "key_"+randomSecret(32))
	}

	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		log.Fatalf("encode config: %v", err)
	}
	file, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		log.Fatalf("create config %q: %v", *outputPath, err)
	}
	if _, err := file.Write(append(content, '\n')); err != nil {
		file.Close()
		log.Fatalf("write config %q: %v", *outputPath, err)
	}
	if err := file.Close(); err != nil {
		log.Fatalf("close config %q: %v", *outputPath, err)
	}

	fmt.Printf("Created %s\n", *outputPath)
	fmt.Println("Save these passwords now; the config contains only their hashes:")
	for _, account := range passwords {
		fmt.Printf("  %s: %s\n", account.Username, account.Password)
	}
	fmt.Println("Access URLs:")
	browserPath := normalizedProxyPath
	for _, accessKey := range config.AccessKeys {
		fmt.Printf("  http://localhost:8082%s/?key=%s\n", browserPath, accessKey)
	}
}

func parseUsernames(value string) []string {
	seen := make(map[string]bool)
	var usernames []string
	for _, username := range strings.Split(value, ",") {
		username = strings.TrimSpace(username)
		if username != "" && !seen[username] {
			seen[username] = true
			usernames = append(usernames, username)
		}
	}
	return usernames
}

func randomSecret(byteCount int) string {
	value := make([]byte, byteCount)
	if _, err := rand.Read(value); err != nil {
		log.Fatalf("generate secure random value: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
