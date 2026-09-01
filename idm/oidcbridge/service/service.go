// SPDX-License-Identifier: AGPL-3.0-or-later
// Added by Westward Capital Guild on 2026-09-01.

// Package service registers the customer OIDC adapter with the Cells runtime.
package service

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/pydio/cells/v5/common/config"
	"github.com/pydio/cells/v5/common/config/routing"
	"github.com/pydio/cells/v5/common/middleware"
	"github.com/pydio/cells/v5/common/runtime"
	service2 "github.com/pydio/cells/v5/common/service"
	"github.com/pydio/cells/v5/idm/oidcbridge"
)

const (
	Name         = "pydio.web.customer-oidc"
	RouteID      = "customer-oidc"
	DefaultRoute = "/auth/oidc"
)

func init() {
	config.RegisterVaultKey("services", Name, "clientSecret")
	routing.RegisterRoute(RouteID, "Customer OpenID Connect login", DefaultRoute)

	runtime.Register("main", func(ctx context.Context) {
		if !config.Get(ctx, "services", Name, "enabled").Bool() {
			return
		}
		service2.NewService(
			service2.Name(Name),
			service2.Context(ctx),
			service2.Description("Customer OpenID Connect login adapter"),
			service2.WithHTTPOptions(func(ctx context.Context, mux routing.RouteRegistrar, options *service2.ServiceOptions) error {
				cfg, err := loadConfig(ctx)
				if err != nil {
					return err
				}
				discoveryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()
				client, err := oidcbridge.NewProviderClient(discoveryCtx, cfg)
				if err != nil {
					return err
				}
				users := oidcbridge.NewUserSynchronizer(oidcbridge.CellsDirectory{})
				completer := oidcbridge.NewCellsCompleter(users, nil, cfg.Source)
				handler := oidcbridge.NewHandler(client, completer, oidcbridge.NewFlowStore(cfg.FlowTTL, time.Now))
				wrapped := middleware.WebIncomingContextMiddleware(ctx, DefaultRoute, service2.ContextKey, options.Server, handler)
				mux.Route(RouteID).Handle("/", wrapped, routing.WithStripPrefix())
				return nil
			}),
			service2.WithHTTPStop(func(_ context.Context, mux routing.RouteRegistrar) error {
				mux.DeregisterRoute(RouteID)
				return nil
			}),
		)
	})
}

func loadConfig(ctx context.Context) (oidcbridge.Config, error) {
	values := config.Get(ctx, "services", Name)
	secret := os.Getenv("CELLS_CUSTOMER_OIDC_CLIENT_SECRET")
	if secret == "" {
		secret = config.GetSecret(ctx, values.Val("clientSecret").String()).String()
	}
	flowTTL, err := time.ParseDuration(values.Val("flowTTL").Default(oidcbridge.DefaultFlowTTL.String()).String())
	if err != nil {
		return oidcbridge.Config{}, fmt.Errorf("parse customer OIDC flow TTL: %w", err)
	}
	redirectURL := values.Val("redirectURL").String()
	if redirectURL == "" {
		redirectURL = routing.GetDefaultSiteURL(ctx) + DefaultRoute + "/callback"
	}
	return oidcbridge.Config{
		IssuerURL:        values.Val("issuerURL").String(),
		ClientID:         values.Val("clientID").String(),
		ClientSecret:     secret,
		RedirectURL:      redirectURL,
		Scopes:           values.Val("scopes").Default([]string{"openid", "profile", "email"}).StringArray(),
		UsernameClaim:    values.Val("usernameClaim").Default("preferred_username").String(),
		EmailClaim:       values.Val("emailClaim").Default("email").String(),
		DisplayNameClaim: values.Val("displayNameClaim").Default("name").String(),
		GroupsClaim:      values.Val("groupsClaim").Default("groups").String(),
		Source:           values.Val("source").Default("customer-oidc").String(),
		FlowTTL:          flowTTL,
	}, nil
}
