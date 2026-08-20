package mail

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// SMTPConfig — параметры отправки (порт smtp_* из app/config.py).
type SMTPConfig struct {
	Host       string
	Port       int
	Username   string
	Password   string
	UseTLS     bool // STARTTLS (587)
	UseSSL     bool // implicit TLS (465)
	Timeout    time.Duration
	FromEmail  string
	FromName   string
	AuthMethod string // "password" | "xoauth2"
	OAuth      OAuthConfig
}

// Sender отправляет письма по SMTP.
type Sender struct {
	cfg   SMTPConfig
	oauth *oauthTokenSource
}

// NewSender собирает отправитель.
func NewSender(cfg SMTPConfig) *Sender {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}
	return &Sender{cfg: cfg, oauth: newOAuthTokenSource(cfg.OAuth)}
}

// Send отправляет письмо (text + опционально html как multipart/alternative).
func (s *Sender) Send(to, subject, text, htmlBody string) error {
	msg := s.buildMessage(to, subject, text, htmlBody)
	addr := net.JoinHostPort(s.cfg.Host, fmt.Sprint(s.cfg.Port))

	client, err := s.dial(addr)
	if err != nil {
		return err
	}
	defer client.Close()

	if s.cfg.UseTLS && !s.cfg.UseSSL {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: s.cfg.Host}); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
		}
	}

	if err := s.authenticate(client); err != nil {
		return err
	}
	if err := client.Mail(s.cfg.FromEmail); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := wc.Write([]byte(msg)); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func (s *Sender) dial(addr string) (*smtp.Client, error) {
	if s.cfg.UseSSL {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: s.cfg.Timeout}, "tcp", addr, &tls.Config{ServerName: s.cfg.Host})
		if err != nil {
			return nil, fmt.Errorf("tls dial: %w", err)
		}
		return smtp.NewClient(conn, s.cfg.Host)
	}
	conn, err := net.DialTimeout("tcp", addr, s.cfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	return smtp.NewClient(conn, s.cfg.Host)
}

func (s *Sender) authenticate(client *smtp.Client) error {
	if s.cfg.AuthMethod == "xoauth2" {
		token, err := s.oauth.token()
		if err != nil {
			return err
		}
		user := s.cfg.Username
		if user == "" {
			user = s.cfg.FromEmail
		}
		return client.Auth(&xoauth2Auth{user: user, token: token})
	}
	if s.cfg.Username == "" {
		return nil // dev/mailpit: без auth
	}
	if ok, _ := client.Extension("AUTH"); !ok {
		return nil
	}
	return client.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host))
}

func (s *Sender) buildMessage(to, subject, text, htmlBody string) string {
	from := (&mail.Address{Name: s.cfg.FromName, Address: s.cfg.FromEmail}).String()
	encSubject := mime.QEncoding.Encode("utf-8", subject)
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + encSubject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	if htmlBody == "" {
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		b.WriteString(text)
		return b.String()
	}
	// multipart/related объединяет письмо (text+html как alternative) и
	// inline-логотип, на который html ссылается по cid:. Клиент показывает html
	// с картинкой; при блокировке картинок остаётся текстовый бренд в шапке.
	nano := fmt.Sprint(time.Now().UnixNano())
	rel := "frost-rel-" + nano
	alt := "frost-alt-" + nano
	b.WriteString("Content-Type: multipart/related; boundary=\"" + rel + "\"\r\n\r\n")
	b.WriteString("--" + rel + "\r\n")
	b.WriteString("Content-Type: multipart/alternative; boundary=\"" + alt + "\"\r\n\r\n")
	b.WriteString("--" + alt + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(text + "\r\n")
	b.WriteString("--" + alt + "\r\n")
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
	b.WriteString(htmlBody + "\r\n")
	b.WriteString("--" + alt + "--\r\n")
	if len(logoPNG) > 0 {
		b.WriteString("--" + rel + "\r\n")
		b.WriteString("Content-Type: image/png\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n")
		b.WriteString("Content-ID: <" + logoCID + ">\r\n")
		b.WriteString("Content-Disposition: inline; filename=\"frost.png\"\r\n\r\n")
		b.WriteString(base64Wrap(logoPNG) + "\r\n")
	}
	b.WriteString("--" + rel + "--\r\n")
	return b.String()
}

// base64Wrap кодирует данные в base64 и переносит строки по 76 символов (RFC 2045).
func base64Wrap(data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteString("\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc)
	return b.String()
}

// xoauth2Auth реализует smtp.Auth для механизма XOAUTH2 (Gmail).
type xoauth2Auth struct {
	user  string
	token string
}

func (a *xoauth2Auth) Start(_ *smtp.ServerInfo) (string, []byte, error) {
	resp := fmt.Sprintf("user=%s\x01auth=Bearer %s\x01\x01", a.user, a.token)
	return "XOAUTH2", []byte(resp), nil
}

func (a *xoauth2Auth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		// Сервер вернул challenge (обычно base64-JSON с ошибкой) — отвечаем пусто,
		// чтобы получить финальный код и корректно провалить аутентификацию.
		return []byte{}, errors.New("xoauth2: " + string(fromServer))
	}
	return nil, nil
}
