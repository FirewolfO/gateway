package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"gateway/internal/model"
)

type Provider struct {
	adminURL        string
	runtimeToken    string
	refreshInterval time.Duration
	client          *http.Client
	snapshot        atomic.Pointer[model.RuntimeConfig]
}

type envelope struct {
	Code    string              `json:"code"`
	Message string              `json:"message"`
	Data    model.RuntimeConfig `json:"data"`
}

func NewProvider(adminURL, runtimeToken string, refreshInterval time.Duration) *Provider {
	return &Provider{
		adminURL:        strings.TrimRight(adminURL, "/"),
		runtimeToken:    runtimeToken,
		refreshInterval: refreshInterval,
		client:          &http.Client{Timeout: 5 * time.Second},
	}
}

func (p *Provider) Refresh(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.adminURL+"/api/v1/runtime/config", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+p.runtimeToken)
	response, err := p.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway admin returned status %d", response.StatusCode)
	}
	var result envelope
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return err
	}
	if result.Code != "OK" {
		return fmt.Errorf("gateway admin rejected config request: %s", result.Message)
	}
	if err := validateConfig(&result.Data); err != nil {
		return err
	}
	p.snapshot.Store(&result.Data)
	return nil
}

func (p *Provider) Start(ctx context.Context) {
	ticker := time.NewTicker(p.refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = p.Refresh(refreshCtx)
			cancel()
		}
	}
}

func (p *Provider) Snapshot() (*model.RuntimeConfig, bool) {
	current := p.snapshot.Load()
	return current, current != nil
}

func validateConfig(config *model.RuntimeConfig) error {
	seenServices := make(map[string]struct{}, len(config.Services))
	for _, service := range config.Services {
		if strings.TrimSpace(service.Code) == "" {
			return errors.New("runtime config contains an empty service code")
		}
		if _, exists := seenServices[service.Code]; exists {
			return fmt.Errorf("runtime config contains duplicate service %q", service.Code)
		}
		seenServices[service.Code] = struct{}{}
		parsed, err := url.ParseRequestURI(service.BaseURL)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return fmt.Errorf("runtime config contains invalid upstream URL for %q", service.Code)
		}
		for _, route := range service.Routes {
			if !strings.HasPrefix(route.Path, "/") || !strings.HasPrefix(route.UpstreamPath, "/") || len(route.Methods) == 0 {
				return fmt.Errorf("runtime config contains invalid route %d", route.ID)
			}
		}
	}
	seenCredentials := make(map[string]struct{}, len(config.Credentials))
	for _, credential := range config.Credentials {
		if strings.TrimSpace(credential.AccessKey) == "" || len(credential.AccessKey) > 64 || len(credential.SecretKey) < 32 {
			return fmt.Errorf("runtime config contains invalid credential %d", credential.ID)
		}
		if _, exists := seenCredentials[credential.AccessKey]; exists {
			return fmt.Errorf("runtime config contains duplicate access key %q", credential.AccessKey)
		}
		seenCredentials[credential.AccessKey] = struct{}{}
		if _, exists := seenServices[credential.CallerServiceCode]; !exists {
			return fmt.Errorf("runtime credential %d references unknown caller service %q", credential.ID, credential.CallerServiceCode)
		}
	}
	return nil
}
