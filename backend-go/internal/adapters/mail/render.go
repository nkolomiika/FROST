// Package mail — рендер писем (порт app/mail.py: build_*_email + _html_shell/_button)
// и SMTP-отправка. Subject берётся из колонки mail_jobs.subject; воркер рендерит
// только text/html по template+payload.
package mail

import (
	"fmt"
	"html"
)

// Бренд и палитра (порт констант mail.py).
const (
	brand  = "FROST"
	accent = "#2E5FBF"
	ink    = "#0F1B2D"
	muted  = "#5A6B84"
	faint  = "#8A97AB"
	footer = "Copyright © 2026. All rights reserved."
)

// Rendered — результат рендера письма (subject хранится в строке mail_jobs).
type Rendered struct {
	Text string
	HTML string
}

// Render строит text+html письма по имени шаблона и payload'у из mail_jobs.
func Render(template string, payload map[string]any) (Rendered, error) {
	switch template {
	case "temporary_password":
		return buildTemporaryPassword(str(payload, "username"), str(payload, "temporary_password")), nil
	case "invitation":
		return buildInvitation(str(payload, "username"), str(payload, "activation_url")), nil
	case "password_reset":
		return buildPasswordReset(str(payload, "username"), str(payload, "reset_url"), intp(payload, "expire_hours")), nil
	case "reactivation":
		return buildReactivation(str(payload, "username"), str(payload, "reactivate_url"), intp(payload, "expire_hours")), nil
	default:
		return Rendered{}, fmt.Errorf("неизвестный шаблон письма %q", template)
	}
}

func str(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprint(v)
	}
	return ""
}

func intp(m map[string]any, k string) int {
	if v, ok := m[k]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return 0
}

func htmlShell(heading, intro, inner, outro string) string {
	return `<!doctype html><html lang="ru"><body style="margin:0;background:#eef1f6;">` +
		`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef1f6;">` +
		`<tr><td align="center" style="padding:32px 12px;">` +
		`<table role="presentation" width="520" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%;">` +
		// header — кристалл-логотип над словесным знаком (картинка inline по cid:,
		// при блокировке картинок остаётся текстовый бейдж).
		`<tr><td align="center" style="padding-bottom:18px;">` +
		`<img src="cid:` + logoCID + `" width="54" height="54" alt="" ` +
		`style="display:block;margin:0 auto 10px;border-radius:13px;">` +
		`<span style="display:inline-block;background:` + ink + `;border-radius:14px;padding:12px 22px;` +
		`color:#fff;font:700 18px/1 Arial,Helvetica,sans-serif;letter-spacing:3px;">` + brand + `</span></td></tr>` +
		// card
		`<tr><td style="background:#fff;border:1px solid #e9edf4;border-radius:16px;padding:32px 34px;">` +
		`<h1 style="margin:0 0 14px;font:700 22px/1.3 Arial,Helvetica,sans-serif;color:` + ink + `;">` + html.EscapeString(heading) + `</h1>` +
		`<p style="margin:0 0 18px;font:400 15px/1.6 Arial,Helvetica,sans-serif;color:` + muted + `;">` + html.EscapeString(intro) + `</p>` +
		inner +
		`<p style="margin:22px 0 0;font:400 13px/1.6 Arial,Helvetica,sans-serif;color:` + faint + `;">` + html.EscapeString(outro) + `</p>` +
		`</td></tr>` +
		// footer
		`<tr><td align="center" style="padding-top:18px;font:400 12px/1.6 Arial,Helvetica,sans-serif;color:` + faint + `;">` +
		brand + ` · ` + footer + `<br>Это письмо отправлено автоматически, отвечать на него не нужно.</td></tr>` +
		`</table></td></tr></table></body></html>`
}

func button(url, label string) string {
	esc := html.EscapeString(url)
	return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:6px 0 4px;">` +
		`<table role="presentation" cellpadding="0" cellspacing="0"><tr><td style="background:` + accent + `;border-radius:12px;">` +
		`<a href="` + esc + `" style="display:inline-block;padding:14px 30px;color:#fff;font:700 15px/1 Arial,Helvetica,sans-serif;text-decoration:none;">` +
		html.EscapeString(label) + `</a></td></tr></table></td></tr></table>` +
		`<p style="margin:22px 0 0;font:400 13px/1.6 Arial,Helvetica,sans-serif;color:` + faint + `;">` +
		`Если кнопка не открывается, скопируйте ссылку в браузер:<br>` +
		`<a href="` + esc + `" style="color:` + accent + `;word-break:break-all;">` + esc + `</a></p>`
}

func buildTemporaryPassword(username, temp string) Rendered {
	text := fmt.Sprintf("Здравствуйте, %s!\n\nДля вашей учётной записи в %s создан или сброшен пароль.\n"+
		"Временный пароль: %s\n\nПри первом входе система попросит задать новый пароль.\n"+
		"Если вы не ожидали это письмо, свяжитесь с администратором.", username, brand, temp)
	inner := `<div style="background:#f6f8fc;border-radius:12px;padding:18px 20px;margin:4px 0;">` +
		`<div style="font:700 11px/1 Arial,Helvetica,sans-serif;color:` + faint + `;letter-spacing:1px;">ВРЕМЕННЫЙ ПАРОЛЬ</div>` +
		`<div style="margin-top:8px;font:700 20px/1.2 'Courier New',monospace;color:` + ink + `;">` + html.EscapeString(temp) + `</div></div>`
	h := htmlShell("Временный пароль",
		fmt.Sprintf("Здравствуйте, %s! Для вашей учётной записи в %s создан или сброшен пароль.", username, brand),
		inner,
		"При первом входе система попросит задать новый пароль. Если вы не ожидали это письмо, свяжитесь с администратором.")
	return Rendered{Text: text, HTML: h}
}

func buildInvitation(username, activationURL string) Rendered {
	greeting := "Здравствуйте!"
	if username != "" {
		greeting = fmt.Sprintf("Здравствуйте, %s!", username)
	}
	text := fmt.Sprintf("%s\n\nВас пригласили в %s. Чтобы завершить регистрацию, перейдите по ссылке:\n\n%s\n\n"+
		"Ссылка одноразовая и действует ограниченное время. Если вы не ожидали приглашение, просто проигнорируйте письмо.",
		greeting, brand, activationURL)
	h := htmlShell("Добро пожаловать в "+brand+"!",
		fmt.Sprintf("%s Вас пригласили в %s. Осталось задать имя пользователя и пароль.", greeting, brand),
		button(activationURL, "Активировать аккаунт"),
		"Ссылка одноразовая и действует ограниченное время. Если вы не ожидали приглашение, просто проигнорируйте письмо.")
	return Rendered{Text: text, HTML: h}
}

func buildPasswordReset(username, resetURL string, expireHours int) Rendered {
	text := fmt.Sprintf("Здравствуйте, %s!\n\nМы получили запрос на восстановление пароля в %s. Чтобы задать новый "+
		"пароль, перейдите по ссылке:\n\n%s\n\nСсылка одноразовая и действует %d ч.\n"+
		"Если вы не запрашивали восстановление, просто проигнорируйте письмо — пароль останется прежним.",
		username, brand, resetURL, expireHours)
	h := htmlShell("Восстановление пароля",
		fmt.Sprintf("Здравствуйте, %s! Мы получили запрос на восстановление пароля в %s. Нажмите кнопку ниже, чтобы задать новый.", username, brand),
		button(resetURL, "Задать новый пароль"),
		fmt.Sprintf("Ссылка одноразовая и действует %d ч. Если вы не запрашивали восстановление, просто проигнорируйте письмо — пароль останется прежним.", expireHours))
	return Rendered{Text: text, HTML: h}
}

func buildReactivation(username, reactivateURL string, expireHours int) Rendered {
	text := fmt.Sprintf("С возвращением, %s!\n\nВаш доступ в %s восстановлен. Чтобы войти, перейдите по ссылке:\n\n%s\n\n"+
		"Ссылка одноразовая и действует %d ч.", username, brand, reactivateURL, expireHours)
	h := htmlShell("С возвращением",
		fmt.Sprintf("С возвращением, %s! Ваш доступ в %s восстановлен — нажмите кнопку ниже, чтобы войти.", username, brand),
		button(reactivateURL, "Вернуться в аккаунт"),
		fmt.Sprintf("Ссылка одноразовая и действует %d ч.", expireHours))
	return Rendered{Text: text, HTML: h}
}
