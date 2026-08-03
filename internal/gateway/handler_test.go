package gateway

import (
	"testing"

	"gateway/internal/model"
)

func TestMatchRouteByServiceMethodPathAndPriority(t *testing.T) {
	config := &model.RuntimeConfig{Services: []model.RuntimeService{{
		Code: "orders", BaseURL: "http://orders.internal", TimeoutMS: 5000,
		Routes: []model.RuntimeRoute{
			{ID: 1, Path: "/orders/:id", UpstreamPath: "/internal/orders/:id", Methods: []string{"GET"}, Priority: 100},
			{ID: 2, Path: "/orders/special", UpstreamPath: "/internal/special", Methods: []string{"GET"}, Priority: 200},
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

	matched, ok := matchRoute(config, "orders", "GET", "/orders/special")
	if !ok || matched.route.ID != 2 {
		t.Fatalf("matchRoute() = %#v, %v", matched, ok)
	}
	matched, ok = matchRoute(config, "orders", "GET", "/orders/42")
	if !ok || matched.params["id"] != "42" {
		t.Fatalf("parameter match = %#v, %v", matched, ok)
	}
	if _, ok := matchRoute(config, "orders", "POST", "/orders/42"); ok {
		t.Fatal("POST unexpectedly matched GET route")
	}
	if _, ok := matchRoute(config, "unknown", "GET", "/orders/42"); ok {
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
}
