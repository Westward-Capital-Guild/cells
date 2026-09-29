package modifiers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/pydio/cells/v5/common/auth/claim"
	"github.com/pydio/cells/v5/common/errors"
	pauth "github.com/pydio/cells/v5/common/proto/auth"
	"github.com/pydio/cells/v5/common/proto/rest"
)

const devicePasswordWindow = 180 * 24 * 60 * 60
const devicePasswordPrefix = "WebDAV device: "

// Only metadata is returned when listing: no token, cache key, secret pair or
// revocation key can be recovered by reopening the panel.
type devicePasswordInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt"`
}

func manageDevicePassword(ctx context.Context, claims *claim.Claims, input map[string]string, out *rest.FrontSessionResponse, client pauth.PersonalAccessTokenServiceClient) error {
	if claims == nil || claims.Subject == "" || claims.Name == "" {
		return errors.WithStack(errors.StatusForbidden)
	}
	ctx = claim.ToContext(ctx, *claims)
	out.TriggerInfo = map[string]string{"username": claims.Name, "refreshDays": "180"}
	switch input["type"] {
	case "device_password_create":
		name := strings.TrimSpace(input["label"])
		if name == "" || utf8.RuneCountInString(name) > 80 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
			return errors.WithMessage(errors.InvalidParameters, "Device name must contain 1 to 80 printable characters")
		}
		result, err := client.Generate(ctx, &pauth.PatGenerateRequest{
			Type: pauth.PatType_PERSONAL, UserUuid: claims.Subject, UserLogin: claims.Name,
			Label: devicePasswordPrefix + name, AutoRefreshWindow: devicePasswordWindow,
		})
		if err != nil {
			return err
		}
		out.Token = &pauth.Token{AccessToken: result.AccessToken, ExpiresAt: fmt.Sprint(time.Now().Add(devicePasswordWindow * time.Second).Unix())}
		out.TriggerInfo["id"] = result.TokenUuid
		return nil
	case "device_password_list", "device_password_revoke":
		result, err := client.List(ctx, &pauth.PatListRequest{Type: pauth.PatType_PERSONAL, ByUserLogin: claims.Name})
		if err != nil {
			return err
		}
		devices := make([]devicePasswordInfo, 0)
		for _, token := range result.Tokens {
			// Check immutable identity as well as login, including for administrators.
			if token.UserUuid != claims.Subject || token.UserLogin != claims.Name || token.Type != pauth.PatType_PERSONAL || !strings.HasPrefix(token.Label, devicePasswordPrefix) {
				continue
			}
			if input["type"] == "device_password_revoke" && token.Uuid == input["id"] {
				_, err = client.Revoke(ctx, &pauth.PatRevokeRequest{Uuid: token.Uuid})
				return err
			}
			devices = append(devices, devicePasswordInfo{token.Uuid, strings.TrimPrefix(token.Label, devicePasswordPrefix), token.CreatedAt, token.ExpiresAt})
		}
		if input["type"] == "device_password_revoke" {
			return errors.WithStack(errors.StatusNotFound)
		}
		encoded, err := json.Marshal(devices)
		if err != nil {
			return err
		}
		out.TriggerInfo["devices"] = string(encoded)
		return nil
	default:
		return errors.WithStack(errors.InvalidParameters)
	}
}
