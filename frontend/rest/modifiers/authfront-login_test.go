package modifiers

import (
	"context"
	"net/http/httptest"
	"testing"

	restful "github.com/emicklei/go-restful/v3"
	"github.com/gorilla/sessions"

	"github.com/pydio/cells/v5/common/config"
	configmock "github.com/pydio/cells/v5/common/config/mock"
	"github.com/pydio/cells/v5/common/proto/rest"
	"github.com/pydio/cells/v5/common/service/frontend"
)

func TestLoginPasswordAuthRejectsDisabledCredentialsBeforeNextMiddleware(t *testing.T) {
	ctx, err := configmock.RegisterMockConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Set(ctx, false, "services", "pydio.web.customer-oidc", "passwordLoginEnabled"); err != nil {
		t.Fatal(err)
	}
	if err := config.Set(ctx, true, "services", "pydio.web.customer-oidc", "enabled"); err != nil {
		t.Fatal(err)
	}

	called := false
	next := func(_ *restful.Request, _ *restful.Response, _ *frontend.FrontSessionWithRuntimeCtx, _ *rest.FrontSessionResponse, _ *sessions.Session) error {
		called = true
		return nil
	}
	handler := LoginPasswordAuth(next)
	httpRequest := httptest.NewRequest("POST", "https://files.example.com/a/frontend/session", nil).WithContext(ctx)
	request := restful.NewRequest(httpRequest)
	response := restful.NewResponse(httptest.NewRecorder())
	input := &frontend.FrontSessionWithRuntimeCtx{
		RuntimeCtx: ctx,
		FrontSessionRequest: &rest.FrontSessionRequest{AuthInfo: map[string]string{
			"type":     "credentials",
			"login":    "admin",
			"password": "not-checked",
		}},
	}
	session := sessions.NewSession(sessions.NewCookieStore([]byte("test-secret")), "test")

	err = handler(request, response, input, &rest.FrontSessionResponse{}, session)
	if err == nil {
		t.Fatal("expected disabled password login to be rejected")
	}
	if called {
		t.Fatal("next middleware was called for disabled password credentials")
	}
}

func TestLoginPasswordAuthDoesNotBlockAuthorizationCode(t *testing.T) {
	ctx, err := configmock.RegisterMockConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Set(ctx, false, "services", "pydio.web.customer-oidc", "passwordLoginEnabled"); err != nil {
		t.Fatal(err)
	}
	if err := config.Set(ctx, true, "services", "pydio.web.customer-oidc", "enabled"); err != nil {
		t.Fatal(err)
	}

	called := false
	next := func(_ *restful.Request, _ *restful.Response, _ *frontend.FrontSessionWithRuntimeCtx, _ *rest.FrontSessionResponse, _ *sessions.Session) error {
		called = true
		return nil
	}
	handler := LoginPasswordAuth(next)
	httpRequest := httptest.NewRequest("POST", "https://files.example.com/a/frontend/session", nil).WithContext(ctx)
	input := &frontend.FrontSessionWithRuntimeCtx{
		RuntimeCtx:          ctx,
		FrontSessionRequest: &rest.FrontSessionRequest{AuthInfo: map[string]string{"type": "authorization_code"}},
	}

	err = handler(
		restful.NewRequest(httpRequest),
		restful.NewResponse(httptest.NewRecorder()),
		input,
		&rest.FrontSessionResponse{},
		sessions.NewSession(sessions.NewCookieStore([]byte("test-secret")), "test"),
	)
	if err != nil {
		t.Fatalf("authorization code was rejected: %v", err)
	}
	if !called {
		t.Fatal("authorization code did not continue to the next middleware")
	}
}
