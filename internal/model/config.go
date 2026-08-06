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
	Audience  string         `json:"audience"`
	Name      string         `json:"name"`
	BaseURL   string         `json:"baseUrl"`
	TimeoutMS int            `json:"timeoutMs"`
	Routes    []RuntimeRoute `json:"routes"`
}

type RuntimeRoute struct {
	ID                        uint     `json:"id"`
	Name                      string   `json:"name"`
	Path                      string   `json:"path"`
	UpstreamPath              string   `json:"upstreamPath"`
	Methods                   []string `json:"methods"`
	Audience                  string   `json:"audience"`
	ProgrammingAccessEnabled  bool     `json:"programmingAccessEnabled"`
	AllowedCallerServiceCodes []string `json:"allowedCallerServiceCodes"`
	Priority                  int      `json:"priority"`
	TimeoutMS                 int      `json:"timeoutMs"`
}

type OpenCredential struct {
	AccountID string     `json:"accountId"`
	AccessKey string     `json:"accessKey"`
	SecretKey string     `json:"secretKey"`
	ExpiresAt *time.Time `json:"expiresAt"`
}
