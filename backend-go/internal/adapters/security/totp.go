package security

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

// totpIssuer — эмитент в otpauth-URI (в приложении-аутентификаторе). Порт TOTP_ISSUER.
const totpIssuer = "FROST"

// timeNow вынесен в переменную для подмены в тестах.
var timeNow = time.Now

// GenerateTOTPSecret возвращает случайный base32-секрет (как pyotp.random_base32).
func GenerateTOTPSecret() (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: totpIssuer, AccountName: "seed"})
	if err != nil {
		return "", err
	}
	return key.Secret(), nil
}

// VerifyTOTP проверяет 6-значный код с допуском ±30с (valid_window=1 у pyotp).
func VerifyTOTP(secret, code string) bool {
	cleaned := strings.TrimSpace(strings.ReplaceAll(code, " ", ""))
	if cleaned == "" {
		return false
	}
	ok, _ := totp.ValidateCustom(cleaned, secret, timeNow(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return ok
}

// TOTPProvisioningURI строит otpauth://-URI для добавления в аутентификатор.
func TOTPProvisioningURI(secret, accountName string) string {
	label := url.PathEscape(totpIssuer + ":" + accountName)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", totpIssuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return fmt.Sprintf("otpauth://totp/%s?%s", label, q.Encode())
}

// TOTPQRPNGDataURL рендерит otpauth-URI в QR и возвращает data:image/png;base64.
func TOTPQRPNGDataURL(otpauthURI string) (string, error) {
	png, err := qrcode.Encode(otpauthURI, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	b.WriteString("data:image/png;base64,")
	b.WriteString(base64.StdEncoding.EncodeToString(png))
	return b.String(), nil
}
