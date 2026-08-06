package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProviderRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/config" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer runtime-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":"OK","message":"操作成功","data":{"generatedAt":"2026-08-03T00:00:00Z","services":[{"id":1,"code":"orders","name":"订单","baseUrl":"http://orders.internal","timeoutMs":5000,"routes":[{"id":3,"name":"内部查询","path":"/orders/:id","upstreamPath":"/orders/:id","methods":["GET"],"audience":"inner","allowedCallerServiceCodes":["orders"],"priority":100,"timeoutMs":5000}]}],"credentials":[{"id":2,"callerServiceCode":"orders","accessKey":"gwak_example","secretKey":"0123456789abcdef0123456789abcdef"}]}}`))
	}))
	defer server.Close()

	provider := NewProvider(server.URL, "runtime-token", time.Second)
	if err := provider.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	config, ok := provider.Snapshot()
	if !ok || len(config.Services) != 1 || config.Services[0].Code != "orders" || len(config.Credentials) != 1 {
		t.Fatalf("Snapshot() = %#v, %v", config, ok)
	}
}
