package sql

import (
	"context"
	"testing"

	"github.com/glebarez/sqlite"
	jose "github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"github.com/ory/hydra/v2/aead"
	"github.com/ory/hydra/v2/jwk"
	"gorm.io/gorm"

	csql "github.com/pydio/cells/v5/common/storage/sql"
	json "github.com/pydio/cells/v5/common/utils/jsonx"
)

type keyTestRegistry struct {
	jwk.Registry
	cipher *aead.AESGCM
}

func (r keyTestRegistry) KeyCipher() *aead.AESGCM { return r.cipher }

func TestJWKAddsKeySetsAlongsideLegacyKey(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	cipher := aead.NewAESGCM(&fosite.Config{GlobalSecret: []byte("0123456789abcdef0123456789abcdef")})
	driver := &jwkDriver{Abstract: csql.NewAbstract(db), r: keyTestRegistry{cipher: cipher}}
	if err := driver.AutoMigrate(); err != nil {
		t.Fatal(err)
	}
	legacy := jose.JSONWebKey{Key: []byte("legacy-test-key"), KeyID: "legacy-kid", Algorithm: "HS256", Use: "sig"}
	plain, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt(ctx, plain, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Existing Cells installations may already have a valid key under the zero UUID.
	if err := db.Model(SqlJWK{}).Create(&jwk.SQLData{Set: "legacy", KID: legacy.KeyID, Key: encrypted}).Error; err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"id-token", "access-token"} {
		key := jose.JSONWebKey{Key: []byte("new-test-key-" + name), KeyID: name + "-kid", Algorithm: "HS256", Use: "sig"}
		if err := driver.AddKeySet(ctx, name, &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}); err != nil {
			t.Fatalf("add %s alongside legacy key: %v", name, err)
		}
	}
	for _, name := range []string{"legacy", "id-token", "access-token"} {
		keys, err := driver.GetKeySet(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		if len(keys.Keys) != 1 || keys.Keys[0].KeyID != name+"-kid" {
			t.Fatalf("unexpected key set %s: %#v", name, keys)
		}
	}
}
