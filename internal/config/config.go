package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Address               string
	AdminURL              string
	RuntimeToken          string
	ConfigRefreshInterval time.Duration
	SignatureSkew         time.Duration
	SigninInnerURL        string
	SigninAccessKey       string
	SigninSecretKey       string
}

func Load() Config {
	return Config{
		Address:               env("GATEWAY_ADDR", ":8082"),
		AdminURL:              strings.TrimRight(env("GATEWAY_ADMIN_URL", "http://127.0.0.1:8083"), "/"),
		RuntimeToken:          env("GATEWAY_RUNTIME_TOKEN", "local-development-runtime-token-change-me"),
		ConfigRefreshInterval: time.Duration(envInt("GATEWAY_CONFIG_REFRESH_SECONDS", 5)) * time.Second,
		SignatureSkew:         time.Duration(envInt("GATEWAY_SIGNATURE_SKEW_SECONDS", 300)) * time.Second,
		SigninInnerURL:        strings.TrimRight(env("SIGNIN_INNER_URL", "http://127.0.0.1:8084"), "/"),
		SigninAccessKey:       env("GATEWAY_SIGNIN_ACCESS_KEY", ""),
		SigninSecretKey:       env("GATEWAY_SIGNIN_SECRET_KEY", ""),
	}
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
