package model

import "time"

type RuntimeConfig struct {
	GeneratedAt time.Time           `json:"generatedAt"`
	Services    []RuntimeService    `json:"services"`
	Credentials []RuntimeCredential `json:"credentials"`
}

type RuntimeCredential struct {
	ID                uint   `json:"id"`
	CallerServiceCode string `json:"callerServiceCode"`
	AccessKey         string `json:"accessKey"`
	SecretKey         string `json:"secretKey"`
}

type RuntimeService struct {
	ID        uint           `json:"id"`
	Code      string         `json:"code"`
	Name      string         `json:"name"`
	BaseURL   string         `json:"baseUrl"`
	TimeoutMS int            `json:"timeoutMs"`
	Routes    []RuntimeRoute `json:"routes"`
}

type RuntimeRoute struct {
	ID           uint     `json:"id"`
	Name         string   `json:"name"`
	Path         string   `json:"path"`
	UpstreamPath string   `json:"upstreamPath"`
	Methods      []string `json:"methods"`
	Priority     int      `json:"priority"`
	TimeoutMS    int      `json:"timeoutMs"`
}
