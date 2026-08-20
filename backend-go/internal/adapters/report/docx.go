// Package report — генерация Word-отчётов (.docx) на Go, порт app/reports/word_builder.py.
// OOXML-механика: .docx распаковывается как zip, части word/*.xml правятся через
// beevik/etree (сохраняет структуру дерева, как lxml в Python), затем перепаковываются.
package report

import (
	"archive/zip"
	"bytes"
	"embed"
	"fmt"
	"io"
	"sort"

	"github.com/beevik/etree"
)

//go:embed templates/szi_template.docx templates/pp_template.docx
var templates embed.FS

// Kind — тип отчёта (порт ReportKind).
type Kind string

const (
	KindSZI Kind = "szi"
	KindPP  Kind = "pp"
)

// Docx — распакованный .docx: сырые части + распарсенные XML-документы word/*.
type Docx struct {
	parts map[string][]byte          // имя части → содержимое (для нетронутых)
	xml   map[string]*etree.Document // имя части → etree (для правимых word/*.xml)
	order []string                   // исходный порядок частей в zip
}

// LoadTemplate открывает встроенный шаблон отчёта нужного типа.
func LoadTemplate(kind Kind) (*Docx, error) {
	name := "templates/" + string(kind) + "_template.docx"
	raw, err := templates.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("template %s: %w", kind, err)
	}
	return Open(raw)
}

// Open распаковывает .docx из байтов.
func Open(raw []byte) (*Docx, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("zip: %w", err)
	}
	d := &Docx{parts: map[string][]byte{}, xml: map[string]*etree.Document{}}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		d.parts[f.Name] = content
		d.order = append(d.order, f.Name)
	}
	return d, nil
}

// Part возвращает распарсенный XML-документ части (word/document.xml и т.п.),
// кешируя его; изменения через etree попадут в Save.
func (d *Docx) Part(name string) (*etree.Document, error) {
	if doc, ok := d.xml[name]; ok {
		return doc, nil
	}
	raw, ok := d.parts[name]
	if !ok {
		return nil, fmt.Errorf("часть %s отсутствует", name)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	d.xml[name] = doc
	return doc, nil
}

// Document — сокращение для word/document.xml.
func (d *Docx) Document() (*etree.Document, error) { return d.Part("word/document.xml") }

// HasPart сообщает, есть ли такая часть в архиве.
func (d *Docx) HasPart(name string) bool { _, ok := d.parts[name]; return ok }

// SetPartRaw заменяет/добавляет сырую часть (например, вставленное изображение media/*).
func (d *Docx) SetPartRaw(name string, content []byte) {
	if _, ok := d.parts[name]; !ok {
		d.order = append(d.order, name)
	}
	d.parts[name] = content
	delete(d.xml, name)
}

// PartNames возвращает имена частей с заданным префиксом (например, "word/header").
func (d *Docx) PartNames(prefix string) []string {
	var out []string
	for _, n := range d.order {
		if len(n) >= len(prefix) && n[:len(prefix)] == prefix {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// Save перепаковывает .docx в байты, сериализуя изменённые XML-части.
func (d *Docx) Save() ([]byte, error) {
	// Сериализуем изменённые etree-части обратно в parts.
	for name, doc := range d.xml {
		doc.WriteSettings = etree.WriteSettings{CanonicalEndTags: false, CanonicalText: false, CanonicalAttrVal: false}
		buf, err := doc.WriteToBytes()
		if err != nil {
			return nil, fmt.Errorf("serialize %s: %w", name, err)
		}
		d.parts[name] = buf
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, name := range d.order {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(d.parts[name]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
