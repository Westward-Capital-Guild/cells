// SPDX-License-Identifier: AGPL-3.0-or-later

package service

import (
	"context"
	"testing"

	"github.com/pydio/cells/v5/common/config"
	configmock "github.com/pydio/cells/v5/common/config/mock"
	"github.com/pydio/cells/v5/common/service/frontend"
)

func TestValidateNavigationURL(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "root relative", value: "/auth/oidc/login"},
		{name: "https", value: "https://passport.example.com/auth/signed-out?application_id=files"},
		{name: "loopback http", value: "http://127.0.0.1:8080/signed-out"},
		{name: "empty", value: "", wantErr: true},
		{name: "scheme relative", value: "//evil.example.com/logout", wantErr: true},
		{name: "relative without root", value: "logout", wantErr: true},
		{name: "insecure remote", value: "http://passport.example.com/logout", wantErr: true},
		{name: "javascript", value: "javascript:alert(1)", wantErr: true},
		{name: "credentials", value: "https://user:pass@passport.example.com/logout", wantErr: true},
		{name: "fragment", value: "https://passport.example.com/logout#next", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNavigationURL("test", tt.value)
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestApplyBootConfExposesExternalIdentitySettings(t *testing.T) {
	ctx, err := configmock.RegisterMockConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	settings := map[string]interface{}{
		"enabled":              true,
		"passwordLoginEnabled": false,
		"loginURL":             "/auth/oidc/login",
		"loginButtonLabel":     "Use Passport",
		"logoutURL":            "https://passport.example.com/auth/edge/signed-out?application_id=files",
	}
	if err := config.Set(ctx, settings, "services", Name); err != nil {
		t.Fatal(err)
	}

	bootConf := &frontend.BootConf{}
	if err := applyBootConf(ctx, bootConf); err != nil {
		t.Fatal(err)
	}
	if bootConf.ExternalIdentity == nil {
		t.Fatal("external identity configuration was not exposed")
	}
	if bootConf.ExternalIdentity.PasswordLoginEnabled {
		t.Fatal("password login should be disabled")
	}
	if bootConf.ExternalIdentity.LoginURL != "/auth/oidc/login" {
		t.Fatalf("unexpected login URL: %s", bootConf.ExternalIdentity.LoginURL)
	}
	if bootConf.ExternalIdentity.LoginButtonLabel != "Use Passport" {
		t.Fatalf("unexpected login button label: %s", bootConf.ExternalIdentity.LoginButtonLabel)
	}
	if bootConf.ExternalIdentity.LogoutURL != settings["logoutURL"] {
		t.Fatalf("unexpected logout URL: %s", bootConf.ExternalIdentity.LogoutURL)
	}
}
