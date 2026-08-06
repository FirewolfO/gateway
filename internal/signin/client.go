package signin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gateway/internal/model"
	"gateway/internal/security"
)

var (
	ErrUnauthorized = errors.New("signin session or credential is invalid")
)

type Client struct {
	baseURL   string
	accessKey string
	secretKey string
	client    *http.Client
	now       func() time.Time
}

type envelope struct {
	Code    string               `json:"code"`
	Message string               `json:"message"`
	Data    model.OpenCredential `json:"data"`
}

func NewClient(baseURL, accessKey, secretKey string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"), accessKey: accessKey, secretKey: secretKey,
		client: &http.Client{Timeout: 5 * time.Second}, now: time.Now,
	}
}

func (c *Client) Resolve(ctx context.Context, accessKey string) (model.OpenCredential, error) {
	body, err := json.Marshal(map[string]string{"accessKey": accessKey})
	if err != nil {
		return model.OpenCredential{}, err
	}
	return c.request(ctx, "/api/inner/signin/credentials/resolve", body, "")
}

func (c *Client) Exchange(ctx context.Context, cookie string) (model.OpenCredential, error) {
	return c.request(ctx, "/api/inner/signin/credentials/exchange", []byte(`{}`), cookie)
}

func (c *Client) request(ctx context.Context, path string, body []byte, cookie string) (model.OpenCredential, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return model.OpenCredential{}, err
	}
	timestamp := fmt.Sprintf("%d", c.now().UTC().Unix())
	nonce, err := randomNonce()
	if err != nil {
		return model.OpenCredential{}, err
	}
	payloadHash := security.PayloadHash(body)
	canonical, err := security.CanonicalRequest(http.MethodPost, path, "", timestamp, nonce, payloadHash)
	if err != nil {
		return model.OpenCredential{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(security.CredentialHeader, c.accessKey)
	request.Header.Set(security.TimestampHeader, timestamp)
	request.Header.Set(security.NonceHeader, nonce)
	request.Header.Set(security.PayloadHeader, payloadHash)
	request.Header.Set(security.SignatureHeader, security.Sign(c.secretKey, canonical))
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	response, err := c.client.Do(request)
	if err != nil {
		return model.OpenCredential{}, err
	}
	defer response.Body.Close()
	var result envelope
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return model.OpenCredential{}, err
	}
	switch response.StatusCode {
	case http.StatusOK:
		if result.Code != "OK" || result.Data.AccountID == "" || result.Data.AccessKey == "" || len(result.Data.SecretKey) < 32 {
			return model.OpenCredential{}, errors.New("signin returned an invalid credential")
		}
		return result.Data, nil
	case http.StatusForbidden, http.StatusUnauthorized, http.StatusNotFound:
		return model.OpenCredential{}, ErrUnauthorized
	default:
		return model.OpenCredential{}, fmt.Errorf("signin returned status %d", response.StatusCode)
	}
}

func randomNonce() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
