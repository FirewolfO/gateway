package signin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gateway/internal/security"
)

func TestClientSignsResolveAndExchangeRequests(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	verifier, err := security.NewVerifier(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if verifyErr := verifier.Verify(secret, request.Header.Get(security.CredentialHeader), request.Method,
			request.URL.EscapedPath(), request.URL.RawQuery, body, request.Header.Get(security.TimestampHeader),
			request.Header.Get(security.NonceHeader), request.Header.Get(security.PayloadHeader),
			request.Header.Get(security.SignatureHeader)); verifyErr != nil {
			t.Fatalf("signed request verification failed: %v", verifyErr)
		}
		if request.URL.Path == "/api/inner/signin/credentials/exchange" && request.Header.Get("Cookie") != "CLOUD_SESSION=session" {
			t.Fatalf("session cookie = %q", request.Header.Get("Cookie"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":"OK","message":"操作成功","data":{"accountId":"account-1","accessKey":"uak_example","secretKey":"0123456789abcdef0123456789abcdef","expiresAt":null}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "gwak_gateway", secret)
	resolved, err := client.Resolve(context.Background(), "uak_example")
	if err != nil || resolved.AccountID != "account-1" {
		t.Fatalf("Resolve() = %#v, %v", resolved, err)
	}
	exchanged, err := client.Exchange(context.Background(), "CLOUD_SESSION=session")
	if err != nil || exchanged.AccessKey != "uak_example" {
		t.Fatalf("Exchange() = %#v, %v", exchanged, err)
	}
}

func TestClientTreatsRejectedCredentialAsUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"FORBIDDEN","message":"凭据不可用"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "gwak_gateway", "0123456789abcdef0123456789abcdef")
	if _, err := client.Resolve(context.Background(), "uak_example"); err != ErrUnauthorized {
		t.Fatalf("Resolve() error = %v", err)
	}
}
