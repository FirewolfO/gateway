package gateway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gateway/internal/model"
	"gateway/internal/runtime"
	"gateway/internal/security"

	"github.com/cloudwego/hertz/pkg/app"
)

const (
	maxRequestBody  = 10 << 20
	maxResponseBody = 32 << 20
)

type Handler struct {
	provider *runtime.Provider
	verifier *security.Verifier
	client   *http.Client
}

type routeMatch struct {
	service model.RuntimeService
	route   model.RuntimeRoute
	params  map[string]string
}

type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func New(provider *runtime.Provider, verifier *security.Verifier) *Handler {
	return &Handler{
		provider: provider,
		verifier: verifier,
		client: &http.Client{
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   20,
				IdleConnTimeout:       90 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
			},
		},
	}
}

func (h *Handler) Serve(ctx context.Context, c *app.RequestContext) {
	serviceCode := c.Param("service")
	requestPath := string(c.Request.URI().PathOriginal())
	rawQuery := string(c.Request.URI().QueryString())
	body := c.Request.Body()
	if len(body) > maxRequestBody {
		writeError(c, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "请求体不能超过 10 MiB")
		return
	}
	credential := string(c.Request.Header.Peek(security.CredentialHeader))
	signature := string(c.Request.Header.Peek(security.SignatureHeader))
	if credential != serviceCode {
		writeError(c, http.StatusUnauthorized, "INVALID_SIGNATURE", "请求签名无效")
		return
	}
	err := h.verifier.Verify(
		credential,
		string(c.Method()),
		requestPath,
		rawQuery,
		body,
		string(c.Request.Header.Peek(security.TimestampHeader)),
		string(c.Request.Header.Peek(security.NonceHeader)),
		string(c.Request.Header.Peek(security.PayloadHeader)),
		signature,
	)
	if err != nil {
		writeError(c, http.StatusUnauthorized, "INVALID_SIGNATURE", err.Error())
		return
	}

	config, available := h.provider.Snapshot()
	if !available {
		writeError(c, http.StatusServiceUnavailable, "CONFIG_UNAVAILABLE", "路由配置暂不可用")
		return
	}
	routePath := strings.TrimPrefix(requestPath, "/api/"+serviceCode)
	if routePath == "" {
		routePath = "/"
	}
	decodedRoutePath, err := url.PathUnescape(routePath)
	if err != nil || containsTraversal(decodedRoutePath) {
		writeError(c, http.StatusBadRequest, "INVALID_PATH", "请求路径无效")
		return
	}
	matched, found := matchRoute(config, serviceCode, string(c.Method()), decodedRoutePath)
	if !found {
		writeError(c, http.StatusNotFound, "ROUTE_NOT_FOUND", "路由不存在")
		return
	}
	if err := h.forward(ctx, c, matched, body, rawQuery); err != nil {
		writeError(c, http.StatusBadGateway, "UPSTREAM_ERROR", "上游服务请求失败")
	}
}

func (h *Handler) forward(ctx context.Context, c *app.RequestContext, matched routeMatch, body []byte, rawQuery string) error {
	target, err := buildTargetURL(matched.service.BaseURL, matched.route.UpstreamPath, matched.params, rawQuery)
	if err != nil {
		return err
	}
	timeout := matched.route.TimeoutMS
	if timeout <= 0 {
		timeout = matched.service.TimeoutMS
	}
	requestCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, string(c.Method()), target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.Request.Header.VisitAll(func(key, value []byte) {
		if shouldForwardRequestHeader(string(key)) {
			request.Header.Add(string(key), string(value))
		}
	})
	request.Header.Set("X-Forwarded-Host", string(c.Host()))
	request.Header.Set("X-Forwarded-For", c.ClientIP())
	request.Header.Set("X-Gateway-Service", matched.service.Code)
	request.Header.Set("X-Gateway-Route", fmt.Sprintf("%d", matched.route.ID))

	response, err := h.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if err != nil {
		return err
	}
	if len(responseBody) > maxResponseBody {
		return fmt.Errorf("upstream response exceeds 32 MiB")
	}
	for key, values := range response.Header {
		if !isHopByHopHeader(key) {
			for _, value := range values {
				c.Response.Header.Add(key, value)
			}
		}
	}
	c.Response.SetStatusCode(response.StatusCode)
	c.Response.SetBody(responseBody)
	return nil
}

func matchRoute(config *model.RuntimeConfig, serviceCode, method, requestPath string) (routeMatch, bool) {
	method = strings.ToUpper(method)
	for _, service := range config.Services {
		if service.Code != serviceCode {
			continue
		}
		var best routeMatch
		found := false
		for _, route := range service.Routes {
			if !containsMethod(route.Methods, method) {
				continue
			}
			params, matches := matchPath(route.Path, requestPath)
			if matches && (!found || route.Priority > best.route.Priority) {
				best = routeMatch{service: service, route: route, params: params}
				found = true
			}
		}
		return best, found
	}
	return routeMatch{}, false
}

func matchPath(pattern, actual string) (map[string]string, bool) {
	patternParts := splitPath(pattern)
	actualParts := splitPath(actual)
	params := make(map[string]string)
	for index, patternPart := range patternParts {
		if strings.HasPrefix(patternPart, "*") {
			if index != len(patternParts)-1 {
				return nil, false
			}
			params[strings.TrimPrefix(patternPart, "*")] = strings.Join(actualParts[index:], "/")
			return params, true
		}
		if index >= len(actualParts) {
			return nil, false
		}
		if strings.HasPrefix(patternPart, ":") {
			params[strings.TrimPrefix(patternPart, ":")] = actualParts[index]
		} else if patternPart != actualParts[index] {
			return nil, false
		}
	}
	return params, len(patternParts) == len(actualParts)
}

func buildTargetURL(baseURL, upstreamPattern string, params map[string]string, rawQuery string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	parts := splitPath(upstreamPattern)
	for index, part := range parts {
		if strings.HasPrefix(part, ":") {
			value, ok := params[strings.TrimPrefix(part, ":")]
			if !ok {
				return "", fmt.Errorf("missing route parameter %s", part)
			}
			parts[index] = value
		} else if strings.HasPrefix(part, "*") {
			value, ok := params[strings.TrimPrefix(part, "*")]
			if !ok {
				return "", fmt.Errorf("missing route wildcard %s", part)
			}
			parts[index] = value
		}
	}
	upstreamPath := "/" + strings.Join(parts, "/")
	parsed.Path = strings.TrimRight(parsed.Path, "/") + upstreamPath
	parsed.RawQuery = rawQuery
	return parsed.String(), nil
}

func splitPath(value string) []string {
	trimmed := strings.Trim(value, "/")
	if trimmed == "" {
		return []string{}
	}
	return strings.Split(trimmed, "/")
}

func containsMethod(methods []string, target string) bool {
	for _, method := range methods {
		if strings.EqualFold(method, target) {
			return true
		}
	}
	return false
}

func shouldForwardRequestHeader(header string) bool {
	if isHopByHopHeader(header) {
		return false
	}
	switch strings.ToLower(header) {
	case "host", strings.ToLower(security.CredentialHeader), strings.ToLower(security.SignatureHeader), strings.ToLower(security.TimestampHeader), strings.ToLower(security.NonceHeader), strings.ToLower(security.PayloadHeader):
		return false
	default:
		return true
	}
}

func isHopByHopHeader(header string) bool {
	switch strings.ToLower(header) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func writeError(c *app.RequestContext, status int, code, message string) {
	c.JSON(status, errorResponse{Code: code, Message: message})
}

func containsTraversal(value string) bool {
	for _, part := range splitPath(value) {
		if part == "." || part == ".." {
			return true
		}
	}
	return false
}
