package mail

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OAuthConfig — параметры Google OAuth2 для xoauth2 (порт google_oauth_* из config.py).
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	RefreshToken string
	TokenURI     string
	Timeout      time.Duration
}

// oauthTokenSource кеширует access-токен и обновляет его по refresh-токену.
type oauthTokenSource struct {
	cfg OAuthConfig
	mu  sync.Mutex
	tok string
	exp time.Time
}

func newOAuthTokenSource(cfg OAuthConfig) *oauthTokenSource {
	if cfg.TokenURI == "" {
		cfg.TokenURI = "https://oauth2.googleapis.com/token"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}
	return &oauthTokenSource{cfg: cfg}
}

// token возвращает валидный access-токен, обновляя его при необходимости.
func (s *oauthTokenSource) token() (string, error) {
	if s.cfg.ClientID == "" || s.cfg.ClientSecret == "" || s.cfg.RefreshToken == "" {
		return "", errors.New("xoauth2: не заданы google_oauth_client_id/secret/refresh_token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tok != "" && time.Now().Before(s.exp) {
		return s.tok, nil
	}
	form := url.Values{
		"client_id":     {s.cfg.ClientID},
		"client_secret": {s.cfg.ClientSecret},
		"refresh_token": {s.cfg.RefreshToken},
		"grant_type":    {"refresh_token"},
	}
	client := &http.Client{Timeout: s.cfg.Timeout}
	resp, err := client.PostForm(s.cfg.TokenURI, form)
	if err != nil {
		return "", fmt.Errorf("xoauth2 token: %w", err)
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusOK || body.AccessToken == "" {
		return "", fmt.Errorf("xoauth2 token: %s %s %s", resp.Status, body.Error, strings.TrimSpace(body.ErrorDesc))
	}
	expiresIn := body.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	s.tok = body.AccessToken
	s.exp = time.Now().Add(time.Duration(max(0, expiresIn-60)) * time.Second)
	return s.tok, nil
}
