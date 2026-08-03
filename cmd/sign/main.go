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
	service := flag.String("service", "", "service code used in /api/{service}/{path}")
	method := flag.String("method", "GET", "HTTP method")
	target := flag.String("url", "", "full request URL or path")
	body := flag.String("body", "", "raw request body")
	secret := flag.String("secret", os.Getenv("GATEWAY_SIGNING_SECRET"), "shared signing secret")
	flag.Parse()

	if *service == "" || *target == "" || len(*secret) < 32 {
		log.Fatal("service, url and a signing secret of at least 32 characters are required")
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
	signature := security.Sign(*secret, canonical)

	fmt.Printf("%s: %s\n", security.CredentialHeader, *service)
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
