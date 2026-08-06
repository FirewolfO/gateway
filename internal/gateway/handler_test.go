package gateway

import (
	"testing"

	"gateway/internal/model"
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
