package security

import (
	"errors"
	"testing"
	"time"
)

func TestVerifier(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	now := time.Unix(1_700_000_000, 0).UTC()
	verifier, err := NewVerifier(secret, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now }
	body := []byte(`{"id":1}`)
	timestamp := "1700000000"
	nonce := "0123456789abcdef"
	payloadHash := PayloadHash(body)
	canonical, err := CanonicalRequest("POST", "/api/orders/orders/1", "z=last&a=hello+world", timestamp, nonce, payloadHash)
	if err != nil {
		t.Fatal(err)
	}
	signature := Sign(secret, canonical)
	if err := verifier.Verify("orders", "POST", "/api/orders/orders/1", "z=last&a=hello+world", body, timestamp, nonce, payloadHash, signature); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if err := verifier.Verify("orders", "POST", "/api/orders/orders/1", "z=last&a=hello+world", body, timestamp, nonce, payloadHash, signature); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed Verify() error = %v, want replay", err)
	}
}

func TestVerifierRejectsTamperingAndExpiredRequests(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	now := time.Unix(1_700_000_000, 0).UTC()
	verifier, _ := NewVerifier(secret, 5*time.Minute)
	verifier.now = func() time.Time { return now }
	body := []byte("original")
	payloadHash := PayloadHash(body)
	canonical, _ := CanonicalRequest("POST", "/api/orders/create", "", "1700000000", "0123456789abcdef", payloadHash)
	signature := Sign(secret, canonical)

	if err := verifier.Verify("orders", "POST", "/api/orders/create", "", []byte("changed"), "1700000000", "0123456789abcdef", payloadHash, signature); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered request error = %v", err)
	}
	if err := verifier.Verify("orders", "POST", "/api/orders/create", "", body, "1699999000", "fedcba9876543210", payloadHash, signature); !errors.Is(err, ErrExpiredSignature) {
		t.Fatalf("expired request error = %v", err)
	}
}
