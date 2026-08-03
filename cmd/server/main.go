package main

import (
	"context"
	"log"
	"time"

	"gateway/internal/config"
	gatewayhandler "gateway/internal/gateway"
	"gateway/internal/runtime"
	"gateway/internal/security"

	"github.com/cloudwego/hertz/pkg/app/server"
)

func main() {
	cfg := config.Load()
	provider := runtime.NewProvider(cfg.AdminURL, cfg.ConfigRefreshInterval)
	if err := refreshWithRetry(provider); err != nil {
		log.Printf("首次加载路由配置失败，将在后台继续重试: %v", err)
	}
	go provider.Start(context.Background())

	verifier, err := security.NewVerifier(cfg.SigningSecret, cfg.SignatureSkew)
	if err != nil {
		log.Fatalf("初始化验签器失败: %v", err)
	}
	handler := gatewayhandler.New(provider, verifier)
	h := server.Default(server.WithHostPorts(cfg.Address))
	h.Any("/api/:service/*path", handler.Serve)
	log.Printf("Gateway 运行时监听于 %s", cfg.Address)
	h.Spin()
}

func refreshWithRetry(provider *runtime.Provider) error {
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		lastErr = provider.Refresh(ctx)
		cancel()
		if lastErr == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return lastErr
}
