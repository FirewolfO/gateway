package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	Algorithm        = "Gateway-HMAC-SHA256"
	CredentialHeader = "X-Gateway-Credential"
	SignatureHeader  = "X-Gateway-Signature"
	TimestampHeader  = "X-Gateway-Timestamp"
	NonceHeader      = "X-Gateway-Nonce"
	PayloadHeader    = "X-Gateway-Content-SHA256"
)

var (
	ErrInvalidSignature = errors.New("请求签名无效")
	ErrExpiredSignature = errors.New("请求签名已过期")
	ErrReplay           = errors.New("请求 nonce 已使用")
)

type Verifier struct {
	skew   time.Duration
	mu     sync.Mutex
	nonces map[string]time.Time
	now    func() time.Time
}

func NewVerifier(skew time.Duration) (*Verifier, error) {
	if skew <= 0 {
		return nil, errors.New("签名有效时间必须大于 0")
	}
	return &Verifier{skew: skew, nonces: make(map[string]time.Time), now: time.Now}, nil
}

func (v *Verifier) Verify(secret, credential, method, path, rawQuery string, body []byte, timestamp, nonce, payloadHash, signature string) error {
	if len(secret) < 32 || credential == "" || len(credential) > 64 || len(nonce) < 16 || len(nonce) > 128 {
		return ErrInvalidSignature
	}
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return ErrInvalidSignature
	}
	now := v.now().UTC()
	requestTime := time.Unix(seconds, 0).UTC()
	if requestTime.Before(now.Add(-v.skew)) || requestTime.After(now.Add(v.skew)) {
		return ErrExpiredSignature
	}
	actualPayloadHash := PayloadHash(body)
	if len(payloadHash) != sha256.Size*2 || subtle.ConstantTimeCompare([]byte(strings.ToLower(payloadHash)), []byte(actualPayloadHash)) != 1 {
		return ErrInvalidSignature
	}
	canonical, err := CanonicalRequest(method, path, rawQuery, timestamp, nonce, actualPayloadHash)
	if err != nil {
		return ErrInvalidSignature
	}
	expected := Sign(secret, canonical)
	if len(signature) != len(expected) || subtle.ConstantTimeCompare([]byte(strings.ToLower(signature)), []byte(expected)) != 1 {
		return ErrInvalidSignature
	}
	if !v.acceptNonce(credential+":"+nonce, requestTime.Add(v.skew), now) {
		return ErrReplay
	}
	return nil
}

func (v *Verifier) acceptNonce(key string, expiresAt, now time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	for nonce, expiresAt := range v.nonces {
		if !expiresAt.After(now) {
			delete(v.nonces, nonce)
		}
	}
	if _, exists := v.nonces[key]; exists {
		return false
	}
	v.nonces[key] = expiresAt
	return true
}

func PayloadHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func CanonicalRequest(method, path, rawQuery, timestamp, nonce, payloadHash string) (string, error) {
	query, err := CanonicalQuery(rawQuery)
	if err != nil {
		return "", err
	}
	if path == "" {
		path = "/"
	}
	return strings.Join([]string{strings.ToUpper(method), path, query, timestamp, nonce, strings.ToLower(payloadHash)}, "\n"), nil
}

func CanonicalQuery(rawQuery string) (string, error) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", err
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0)
	for _, key := range keys {
		items := append([]string(nil), values[key]...)
		sort.Strings(items)
		if len(items) == 0 {
			items = []string{""}
		}
		for _, value := range items {
			parts = append(parts, rfc3986Encode(key)+"="+rfc3986Encode(value))
		}
	}
	return strings.Join(parts, "&"), nil
}

func Sign(secret, canonicalRequest string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(canonicalRequest))
	return hex.EncodeToString(mac.Sum(nil))
}

func rfc3986Encode(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}
