package mail

import _ "embed"

// Встроенный логотип FROST для писем: почтовые клиенты не рендерят SVG, поэтому
// шлём PNG (тёмная плитка-кристалл B6, переживает тёмную тему клиента) как
// inline-вложение multipart/related и ссылаемся на него из HTML по cid:.
//
//go:embed assets/frost-logo.png
var logoPNG []byte

// logoCID — Content-ID встроенного логотипа (без угловых скобок).
const logoCID = "frostlogo@frost"
