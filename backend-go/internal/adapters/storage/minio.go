// Package storage — адаптер объектного хранилища (MinIO/S3) для файлов и аватаров.
// Реализует порт хранилища доменных контекстов (vulns.Storage, users avatar storage):
// Put/Get/Delete по ключу.
package storage

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Minio — клиент объектного хранилища с фиксированным бакетом.
type Minio struct {
	client *minio.Client
	bucket string
}

// NewMinio создаёт клиент и (best-effort) создаёт бакет, если его нет.
// Недоступность MinIO на старте не считается фатальной — ошибка бакета логируется вызывающим.
func NewMinio(endpoint, accessKey, secretKey, bucket string, useSSL bool) (*Minio, error) {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, err
	}
	m := &Minio{client: client, bucket: bucket}
	return m, nil
}

// EnsureBucket создаёт бакет, если он отсутствует (best-effort, зовётся на старте).
func (m *Minio) EnsureBucket(ctx context.Context) error {
	exists, err := m.client.BucketExists(ctx, m.bucket)
	if err != nil {
		return err
	}
	if !exists {
		return m.client.MakeBucket(ctx, m.bucket, minio.MakeBucketOptions{})
	}
	return nil
}

// Put загружает объект по ключу.
func (m *Minio) Put(ctx context.Context, key string, data []byte, contentType string) error {
	_, err := m.client.PutObject(ctx, m.bucket, key, bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: contentType})
	return err
}

// Get скачивает объект по ключу и возвращает содержимое и content-type.
func (m *Minio) Get(ctx context.Context, key string) ([]byte, string, error) {
	obj, err := m.client.GetObject(ctx, m.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, "", err
	}
	defer obj.Close()
	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, "", err
	}
	stat, err := obj.Stat()
	ct := ""
	if err == nil {
		ct = stat.ContentType
	}
	return data, ct, nil
}

// Delete удаляет объект по ключу.
func (m *Minio) Delete(ctx context.Context, key string) error {
	return m.client.RemoveObject(ctx, m.bucket, key, minio.RemoveObjectOptions{})
}

// ─────────────────────────── stub ───────────────────────────

// ErrStorageUnavailable — операция с хранилищем при неотконфигурированном MinIO.
var ErrStorageUnavailable = errors.New("object storage не сконфигурирован (MINIO_ENDPOINT пуст)")

// Stub — заглушка Storage, когда MinIO не сконфигурирован (все операции — ошибка).
type Stub struct{}

func (Stub) Put(context.Context, string, []byte, string) error { return ErrStorageUnavailable }
func (Stub) Get(context.Context, string) ([]byte, string, error) {
	return nil, "", ErrStorageUnavailable
}
func (Stub) Delete(context.Context, string) error { return ErrStorageUnavailable }
