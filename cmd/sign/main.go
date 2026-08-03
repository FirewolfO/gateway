package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"gateway/internal/security"
)

func main() {
	accessKey := flag.String("access-key", os.Getenv("GATEWAY_ACCESS_KEY"), "caller service access key")
	method := flag.String("method", "GET", "HTTP method")
	target := flag.String("url", "", "full request URL or path")
	body := flag.String("body", "", "raw request body")
	secretKey := flag.String("secret-key", os.Getenv("GATEWAY_SECRET_KEY"), "caller service secret key")
	flag.Parse()

	if *accessKey == "" || *target == "" || len(*secretKey) < 32 {
		log.Fatal("access-key, url and a secret-key of at least 32 characters are required")
	}
	parsed, err := url.Parse(*target)
	if err != nil {
		log.Fatalf("invalid URL: %v", err)
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce := randomNonce()
	payloadHash := security.PayloadHash([]byte(*body))
	canonical, err := security.CanonicalRequest(strings.ToUpper(*method), path, parsed.RawQuery, timestamp, nonce, payloadHash)
	if err != nil {
		log.Fatalf("build canonical request: %v", err)
	}
	signature := security.Sign(*secretKey, canonical)

	fmt.Printf("%s: %s\n", security.CredentialHeader, *accessKey)
	fmt.Printf("%s: %s\n", security.SignatureHeader, signature)
	fmt.Printf("%s: %s\n", security.TimestampHeader, timestamp)
	fmt.Printf("%s: %s\n", security.NonceHeader, nonce)
	fmt.Printf("%s: %s\n", security.PayloadHeader, payloadHash)
}

func randomNonce() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		log.Fatalf("generate nonce: %v", err)
	}
	return hex.EncodeToString(value)
}
