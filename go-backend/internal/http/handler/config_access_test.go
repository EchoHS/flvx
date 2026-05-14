package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-backend/internal/auth"
	"go-backend/internal/http/middleware"
	"go-backend/internal/http/response"
	"go-backend/internal/store/repo"
)

func TestPublicConfigGetAllowsBrandKeys(t *testing.T) {
	router, r := setupConfigAccessTestRouter(t)
	seedConfigValue(t, r, "app_name", "FLVX Brand")
	seedConfigValue(t, r, "app_logo", "logo-data")
	seedConfigValue(t, r, "app_favicon", "favicon-data")
	seedConfigValue(t, r, "app_bg_image", "bg-data")
	seedConfigValue(t, r, "cloudflare_site_key", "site-key")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/config/get", bytes.NewBufferString(`{"name":"app_name"}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	router.ServeHTTP(resp, req)

	assertHandlerCode(t, resp, 0)
}

func TestPublicConfigGetRejectsSensitiveKeys(t *testing.T) {
	router, _ := setupConfigAccessTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/config/get", bytes.NewBufferString(`{"name":"jwt_secret"}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	router.ServeHTTP(resp, req)

	assertHandlerCodeMsg(t, resp, 403, "禁止访问敏感配置")
}

func TestConfigGetNowRequiresAuth(t *testing.T) {
	router, _ := setupConfigAccessTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/get", bytes.NewBufferString(`{"name":"app_name"}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	router.ServeHTTP(resp, req)

	assertHandlerCodeMsg(t, resp, 401, "未登录或token已过期")
}

func TestConfigUpdateRejectsSensitiveKeys(t *testing.T) {
	router, _ := setupConfigAccessTestRouter(t)
	adminToken := mustGenerateConfigAccessToken(t, 1, "admin_user", 0)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/update", bytes.NewBufferString(`{"jwt_secret":"rotated-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", adminToken)
	resp := httptest.NewRecorder()

	router.ServeHTTP(resp, req)

	assertHandlerCodeMsg(t, resp, 403, "禁止访问敏感配置")
}

func TestConfigUpdateSingleRejectsSensitiveKeys(t *testing.T) {
	router, _ := setupConfigAccessTestRouter(t)
	adminToken := mustGenerateConfigAccessToken(t, 1, "admin_user", 0)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/update-single", bytes.NewBufferString(`{"name":"jwt_secret","value":"rotated-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", adminToken)
	resp := httptest.NewRecorder()

	router.ServeHTTP(resp, req)

	assertHandlerCodeMsg(t, resp, 403, "禁止访问敏感配置")
}

func setupConfigAccessTestRouter(t *testing.T) (http.Handler, *repo.Repository) {
	t.Helper()
	r, err := repo.Open(t.TempDir() + "/config-access.db")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() {
		_ = r.Close()
	})

	h := New(r, "unit-test-secret")
	mux := http.NewServeMux()
	h.Register(mux)
	wrapped := middleware.Recover(mux)
	wrapped = middleware.JWT(middleware.AuthOptions{JWTSecret: "unit-test-secret", GetUserAuthState: h.GetUserAuthState})(wrapped)
	wrapped = middleware.RequestLog(wrapped)
	wrapped = middleware.CORS(wrapped)
	return wrapped, r
}

func seedConfigValue(t *testing.T, r *repo.Repository, name, value string) {
	t.Helper()
	if err := r.DB().Exec(`INSERT INTO vite_config(name, value, time) VALUES(?, ?, 0) ON CONFLICT(name) DO UPDATE SET value = excluded.value, time = excluded.time`, name, value).Error; err != nil {
		t.Fatalf("seed config %s: %v", name, err)
	}
}

func mustGenerateConfigAccessToken(t *testing.T, userID int64, username string, roleID int) string {
	t.Helper()
	token, err := auth.GenerateToken(userID, username, roleID, "unit-test-secret")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	return token
}

func assertHandlerCode(t *testing.T, rec *httptest.ResponseRecorder, expected int) {
	t.Helper()
	var out response.R
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Code != expected {
		t.Fatalf("expected code %d, got %d", expected, out.Code)
	}
}

func assertHandlerCodeMsg(t *testing.T, rec *httptest.ResponseRecorder, expectedCode int, expectedMsg string) {
	t.Helper()
	var out response.R
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Code != expectedCode || out.Msg != expectedMsg {
		t.Fatalf("expected (%d,%q), got (%d,%q)", expectedCode, expectedMsg, out.Code, out.Msg)
	}
}
