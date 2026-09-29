package modifiers

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pydio/cells/v5/common/auth/claim"
	pauth "github.com/pydio/cells/v5/common/proto/auth"
	"github.com/pydio/cells/v5/common/proto/rest"
	"google.golang.org/grpc"
)

type deviceClient struct {
	pauth.PersonalAccessTokenServiceClient
	rows      []*pauth.PersonalAccessToken
	generated *pauth.PatGenerateRequest
	revoked   string
}

func (c *deviceClient) Generate(_ context.Context, r *pauth.PatGenerateRequest, _ ...grpc.CallOption) (*pauth.PatGenerateResponse, error) {
	c.generated = r
	return &pauth.PatGenerateResponse{AccessToken: "synthetic-secret", TokenUuid: "new-device"}, nil
}
func (c *deviceClient) List(_ context.Context, r *pauth.PatListRequest, _ ...grpc.CallOption) (*pauth.PatListResponse, error) {
	if r.ByUserLogin != "alice" || r.Type != pauth.PatType_PERSONAL {
		panic("unscoped list")
	}
	return &pauth.PatListResponse{Tokens: c.rows}, nil
}
func (c *deviceClient) Revoke(_ context.Context, r *pauth.PatRevokeRequest, _ ...grpc.CallOption) (*pauth.PatRevokeResponse, error) {
	c.revoked = r.Uuid
	return &pauth.PatRevokeResponse{Success: true}, nil
}

func TestDevicePasswordOwnershipAndOneTimeSecret(t *testing.T) {
	owner := &claim.Claims{Subject: "alice-uuid", Name: "alice"}
	client := &deviceClient{rows: []*pauth.PersonalAccessToken{
		{Uuid: "mine", Type: pauth.PatType_PERSONAL, UserUuid: "alice-uuid", UserLogin: "alice", Label: devicePasswordPrefix + "My Mac", SecretPair: "never-return", CacheKey: "never-return", RevocationKey: "never-return"},
		{Uuid: "other", Type: pauth.PatType_PERSONAL, UserUuid: "bob-uuid", UserLogin: "bob", Label: devicePasswordPrefix + "Other"},
		{Uuid: "regular", Type: pauth.PatType_PERSONAL, UserUuid: "alice-uuid", UserLogin: "alice", Label: "CLI token"},
	}}
	out := &rest.FrontSessionResponse{}
	if err := manageDevicePassword(context.Background(), owner, map[string]string{"type": "device_password_list"}, out, client); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(out)
	if out.Token != nil || strings.Contains(string(encoded), "never-return") || strings.Contains(string(encoded), "other") {
		t.Fatal("list leaked secret or another device")
	}
	var list []devicePasswordInfo
	if err := json.Unmarshal([]byte(out.TriggerInfo["devices"]), &list); err != nil || len(list) != 1 || list[0].ID != "mine" {
		t.Fatal("incorrect device list")
	}
	for _, id := range []string{"other", "regular", "unknown", ""} {
		if manageDevicePassword(context.Background(), owner, map[string]string{"type": "device_password_revoke", "id": id}, &rest.FrontSessionResponse{}, client) == nil || client.revoked != "" {
			t.Fatalf("revoked unauthorized device %q", id)
		}
	}
	if err := manageDevicePassword(context.Background(), owner, map[string]string{"type": "device_password_revoke", "id": "mine"}, &rest.FrontSessionResponse{}, client); err != nil || client.revoked != "mine" {
		t.Fatal("own revoke failed")
	}
	out = &rest.FrontSessionResponse{}
	if err := manageDevicePassword(context.Background(), owner, map[string]string{"type": "device_password_create", "label": " My Mac ", "UserUuid": "bob"}, out, client); err != nil {
		t.Fatal(err)
	}
	if client.generated.UserUuid != "alice-uuid" || client.generated.UserLogin != "alice" || len(client.generated.Scopes) != 0 || client.generated.AutoRefreshWindow != 15552000 || client.generated.Label != devicePasswordPrefix+"My Mac" || out.Token.AccessToken != "synthetic-secret" {
		t.Fatal("create identity/lifetime contract failed")
	}
}

func TestDevicePasswordRejectsLimitedIdentitiesAndInvalidNames(t *testing.T) {
	for _, identity := range []*claim.Claims{nil, {}, {Subject: "a", Name: "alice", Public: true}, {Subject: "a", Name: "alice", ProvidesScopes: true}, {Subject: "a", Name: "alice", Scopes: []string{"node:x:r"}}} {
		if manageDevicePassword(context.Background(), identity, map[string]string{"type": "device_password_create", "label": "Mac"}, &rest.FrontSessionResponse{}, &deviceClient{}) == nil {
			t.Fatal("restricted identity minted full-ACL credential")
		}
	}
	for _, label := range []string{"", "  ", "Mac\nLaptop", strings.Repeat("a", 81)} {
		if manageDevicePassword(context.Background(), &claim.Claims{Subject: "a", Name: "alice"}, map[string]string{"type": "device_password_create", "label": label}, &rest.FrontSessionResponse{}, &deviceClient{}) == nil {
			t.Fatal("invalid label accepted")
		}
	}
}
