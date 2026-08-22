package recon

import "context"

// staticKeyResolver — резолвер ключей источников из статической карты (значения из
// окружения/конфига). Пришёл на смену БД-резолверу интеграций: ключи теперь задаются
// только через .env.prod, а не редактируются через вебку (раздел Integrations удалён).
type staticKeyResolver struct{ keys map[string]string }

// NewStaticKeyResolver собирает резолвер из карты name→ключ. Пустое значение = ключ
// не задан (источник самопропустится).
func NewStaticKeyResolver(keys map[string]string) IntegrationResolver {
	return staticKeyResolver{keys: keys}
}

func (r staticKeyResolver) GetIntegrationKey(_ context.Context, name string) (string, bool, error) {
	v, ok := r.keys[name]
	if !ok || v == "" {
		return "", false, nil
	}
	return v, true, nil
}
