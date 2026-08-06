package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gateway/internal/model"
	"gateway/internal/runtime"
	"gateway/internal/security"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/route/param"
)

func TestMatchRouteByServiceMethodPathAndPriority(t *testing.T) {
	config := &model.RuntimeConfig{Services: []model.RuntimeService{{
		Code: "orders", Audience: "inner", BaseURL: "http://orders.internal", TimeoutMS: 5000,
		Routes: []model.RuntimeRoute{
			{ID: 1, Path: "/orders/:id", UpstreamPath: "/internal/orders/:id", Methods: []string{"GET"}, Audience: "inner", AllowedCallerServiceCodes: []string{"billing"}, Priority: 100},
			{ID: 2, Path: "/orders/special", UpstreamPath: "/internal/special", Methods: []string{"GET"}, Audience: "inner", AllowedCallerServiceCodes: []string{"billing"}, Priority: 200},
		},
	}, {
		Code: "orders", Audience: "open", BaseURL: "http://orders-open.internal", TimeoutMS: 5000,
		Routes: []model.RuntimeRoute{
			{ID: 3, Path: "/orders/:id", UpstreamPath: "/public/orders/:id", Methods: []string{"GET"}, Audience: "open", ProgrammingAccessEnabled: true, Priority: 100},
		},
	}}, Credentials: []model.RuntimeCredential{{
		ID: 9, CallerServiceCode: "billing", AccessKey: "gwak_billing", SecretKey: "0123456789abcdef0123456789abcdef",
	}}}

	credential, ok := findCredential(config, "gwak_billing")
	if !ok || credential.CallerServiceCode != "billing" {
		t.Fatalf("findCredential() = %#v, %v", credential, ok)
	}
	if _, ok := findCredential(config, "orders"); ok {
		t.Fatal("target service code unexpectedly matched an access key")
	}

	matched, ok := matchRoute(config, "inner", "orders", "GET", "/orders/special")
	if !ok || matched.route.ID != 2 {
		t.Fatalf("matchRoute() = %#v, %v", matched, ok)
	}
	matched, ok = matchRoute(config, "inner", "orders", "GET", "/orders/42")
	if !ok || matched.params["id"] != "42" {
		t.Fatalf("parameter match = %#v, %v", matched, ok)
	}
	if !routeAllowsService(matched.route, "billing") || routeAllowsService(matched.route, "catalog") {
		t.Fatal("inner route service authorization was not enforced")
	}
	openMatched, ok := matchRoute(config, "open", "orders", "GET", "/orders/42")
	if !ok || openMatched.route.ID != 3 || !openMatched.route.ProgrammingAccessEnabled {
		t.Fatalf("open route isolation = %#v, %v", openMatched, ok)
	}
	if _, ok := matchRoute(config, "inner", "orders", "POST", "/orders/42"); ok {
		t.Fatal("POST unexpectedly matched GET route")
	}
	if _, ok := matchRoute(config, "inner", "unknown", "GET", "/orders/42"); ok {
		t.Fatal("unknown service unexpectedly matched")
	}
}

func TestWildcardAndTargetURL(t *testing.T) {
	params, ok := matchPath("/assets/*path", "/assets/css/app.css")
	if !ok || params["path"] != "css/app.css" {
		t.Fatalf("matchPath() = %#v, %v", params, ok)
	}
	target, err := buildTargetURL("http://assets.internal/base", "/static/*path", params, "v=1")
	if err != nil {
		t.Fatal(err)
	}
	if target != "http://assets.internal/base/static/css/app.css?v=1" {
		t.Fatalf("target = %q", target)
	}
}

func TestForwardedHeadersAndTraversalProtection(t *testing.T) {
	if !shouldForwardRequestHeader("Authorization") {
		t.Fatal("business Authorization header should be forwarded")
	}
	if shouldForwardRequestHeader("X-Gateway-Signature") {
		t.Fatal("gateway signature header should not be forwarded")
	}
	if !containsTraversal("/files/../secret") || !containsTraversal("/files/./current") {
		t.Fatal("path traversal segments were not detected")
	}
	if cloudSessionCookie("theme=dark; CLOUD_SESSION=session-value; other=value") != "CLOUD_SESSION=session-value" {
		t.Fatal("cloud session cookie was not isolated")
	}
	if cloudSessionCookie("theme=dark") != "" {
		t.Fatal("unrelated cookies were accepted as a cloud session")
	}
	if !isBrowserCredentialHeader("Cookie") || !isBrowserCredentialHeader("X-XSRF-TOKEN") {
		t.Fatal("browser credentials were not marked for removal")
	}
}

func TestSignUpstreamRequestSignsActualTarget(t *testing.T) {
	body := []byte(`{"displayName":"Gateway User"}`)
	request, err := http.NewRequest(http.MethodPut,
		"http://signin.internal/api/v1/account/profile?z=1&a=x+y&a=0", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	credential := model.OpenCredential{
		AccessKey: "utak_gateway_test",
		SecretKey: "0123456789abcdef0123456789abcdef",
	}
	if err := signUpstreamRequest(request, credential, body); err != nil {
		t.Fatalf("signUpstreamRequest() error = %v", err)
	}
	verifier, err := security.NewVerifier(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(credential.SecretKey, credential.AccessKey, request.Method,
		request.URL.EscapedPath(), request.URL.RawQuery, body,
		request.Header.Get(security.TimestampHeader), request.Header.Get(security.NonceHeader),
		request.Header.Get(security.PayloadHeader), request.Header.Get(security.SignatureHeader)); err != nil {
		t.Fatalf("upstream signature verification error = %v", err)
	}
}

func TestAnonymousOpenRouteUsesGatewayCredentialAndForwardsPeopleSession(t *testing.T) {
	const (
		accessKey = "gwak_gateway_test"
		secretKey = "0123456789abcdef0123456789abcdef"
	)
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamCalled = true
		if request.URL.Path != "/api/v1/auth/me" || request.Header.Get("X-Gateway-Auth-Type") != "gateway" ||
			request.Header.Get("X-Gateway-Caller-Service") != "gateway-runtime" || request.Header.Get(security.CredentialHeader) != accessKey {
			t.Errorf("unexpected upstream request: path=%s headers=%v", request.URL.Path, request.Header)
		}
		if request.Header.Get("Cookie") != "PEOPLE_SESSION=session-value" || request.Header.Get("X-XSRF-TOKEN") != "csrf-value" {
			t.Errorf("browser credentials were not forwarded: %v", request.Header)
		}
		verifier, err := security.NewVerifier(5 * time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifier.Verify(secretKey, accessKey, request.Method, request.URL.EscapedPath(), request.URL.RawQuery, nil,
			request.Header.Get(security.TimestampHeader), request.Header.Get(security.NonceHeader),
			request.Header.Get(security.PayloadHeader), request.Header.Get(security.SignatureHeader)); err != nil {
			t.Errorf("upstream signature error = %v", err)
		}
		writer.Header().Add("Set-Cookie", "PEOPLE_SESSION=refreshed; Path=/; HttpOnly")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	config := model.RuntimeConfig{
		Services: []model.RuntimeService{
			{Code: "gateway-runtime", Audience: "inner", BaseURL: "http://gateway.invalid", TimeoutMS: 1000},
			{Code: "people", Audience: "open", BaseURL: upstream.URL, TimeoutMS: 1000, Routes: []model.RuntimeRoute{{
				ID: 1, Path: "/auth/me", UpstreamPath: "/api/v1/auth/me", Methods: []string{"GET"}, Audience: "open",
				AnonymousAccessEnabled: true, ForwardBrowserCredentials: true, TimeoutMS: 1000,
			}}},
		},
		Credentials: []model.RuntimeCredential{{ID: 1, CallerServiceCode: "gateway-runtime", AccessKey: accessKey, SecretKey: secretKey}},
	}
	admin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(map[string]any{"code": "OK", "data": config})
	}))
	defer admin.Close()
	provider := runtime.NewProvider(admin.URL, "runtime-token", time.Minute)
	if err := provider.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	requestVerifier, err := security.NewVerifier(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	handler := New(provider, requestVerifier, nil)
	c := app.NewContext(3)
	c.Params = append(c.Params, param.Param{Key: "audience", Value: "open"}, param.Param{Key: "service", Value: "people"}, param.Param{Key: "path", Value: "auth/me"})
	c.Request.SetRequestURI("/api/open/people/auth/me")
	c.Request.Header.SetMethod(http.MethodGet)
	c.Request.Header.Set("Cookie", "PEOPLE_SESSION=session-value")
	c.Request.Header.Set("X-XSRF-TOKEN", "csrf-value")
	handler.Serve(context.Background(), c)
	if !upstreamCalled || c.Response.StatusCode() != http.StatusOK || string(c.Response.Body()) != `{"ok":true}` {
		t.Fatalf("response status=%d body=%s upstreamCalled=%v", c.Response.StatusCode(), c.Response.Body(), upstreamCalled)
	}
	if !bytes.Contains(c.Response.Header.Peek("Set-Cookie"), []byte("PEOPLE_SESSION=refreshed")) {
		t.Fatalf("Set-Cookie not returned: %s", c.Response.Header.Peek("Set-Cookie"))
	}
}
