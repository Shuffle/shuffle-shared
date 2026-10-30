package shuffle

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
)

func TestVerifyPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.New()
	h.Write([]byte(verifier))
	challenge := base64URLEncode(h.Sum(nil))

	// 1. Valid S256
	if !verifyPKCE(verifier, challenge, "S256") {
		t.Errorf("Expected PKCE S256 verification to pass")
	}

	// 2. Default method (empty string defaults to S256)
	if !verifyPKCE(verifier, challenge, "") {
		t.Errorf("Expected PKCE default method to pass S256")
	}

	// 3. Invalid verifier with S256
	if verifyPKCE("wrong_verifier", challenge, "S256") {
		t.Errorf("Expected wrong verifier to fail")
	}

	// 4. Valid plain
	if !verifyPKCE("plain_secret_123", "plain_secret_123", "plain") {
		t.Errorf("Expected PKCE plain verification to pass")
	}

	// 5. Invalid plain
	if verifyPKCE("plain_secret_123", "plain_secret_456", "plain") {
		t.Errorf("Expected mismatched plain verifier to fail")
	}

	// 6. Empty values
	if verifyPKCE("", challenge, "S256") {
		t.Errorf("Expected empty verifier to fail")
	}
	if verifyPKCE(verifier, "", "S256") {
		t.Errorf("Expected empty challenge to fail")
	}
}

func TestParseAllowedAppsFromScope(t *testing.T) {
	// 1. App prefix format
	apps := parseAllowedAppsFromScope("app:jira app:slack")
	if len(apps) != 2 || apps[0] != "jira" || apps[1] != "slack" {
		t.Errorf("Unexpected apps for app: prefix: %#v", apps)
	}

	// 2. Apps comma-separated format
	apps = parseAllowedAppsFromScope("apps:jira,slack,outlook")
	if len(apps) != 3 || apps[0] != "jira" || apps[1] != "slack" || apps[2] != "outlook" {
		t.Errorf("Unexpected apps for apps: prefix: %#v", apps)
	}

	// 3. Mixed with standard scopes
	apps = parseAllowedAppsFromScope("workflow:edit app:virustotal workflow:run")
	if len(apps) != 1 || apps[0] != "virustotal" {
		t.Errorf("Unexpected apps for mixed scope: %#v", apps)
	}

	// 4. Empty scope
	apps = parseAllowedAppsFromScope("")
	if len(apps) != 0 {
		t.Errorf("Expected empty apps for empty scope, got: %#v", apps)
	}
}

func TestIsAppAllowedForOAuth(t *testing.T) {
	jiraApp := WorkflowApp{
		ID:   "app_12345",
		Name: "Jira Service Management",
	}
	vtApp := WorkflowApp{
		ID:   "app_67890",
		Name: "VirusTotal",
	}

	// 1. Empty allowedApps -> allows all
	if !IsAppAllowedForOAuth([]string{}, jiraApp) {
		t.Errorf("Expected empty allowedApps to allow Jira")
	}

	// 2. Wildcard -> allows all
	if !IsAppAllowedForOAuth([]string{"*"}, vtApp) {
		t.Errorf("Expected wildcard to allow VirusTotal")
	}
	if !IsAppAllowedForOAuth([]string{"mcp"}, vtApp) {
		t.Errorf("Expected 'mcp' wildcard to allow VirusTotal")
	}

	// 3. Specific app name / slug matching
	allowed := []string{"jira_service_management", "slack"}
	if !IsAppAllowedForOAuth(allowed, jiraApp) {
		t.Errorf("Expected Jira to be allowed by slug")
	}
	if IsAppAllowedForOAuth(allowed, vtApp) {
		t.Errorf("Expected VirusTotal to be blocked")
	}

	// 4. App ID matching with app: prefix
	allowedWithPrefix := []string{"app:app_67890"}
	if !IsAppAllowedForOAuth(allowedWithPrefix, vtApp) {
		t.Errorf("Expected VirusTotal to be allowed by ID prefix")
	}
	if IsAppAllowedForOAuth(allowedWithPrefix, jiraApp) {
		t.Errorf("Expected Jira to be blocked when only VirusTotal is allowed")
	}
}

func TestHandleOAuthTokenValidation(t *testing.T) {
	// 1. Method Not Allowed (GET)
	req := httptest.NewRequest("GET", "/oauth2/token", nil)
	rec := httptest.NewRecorder()
	HandleOAuthToken(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 for GET /oauth2/token, got %d", rec.Code)
	}

	// 2. Unsupported Grant Type
	req = httptest.NewRequest("POST", "/oauth2/token", strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	HandleOAuthToken(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for unsupported grant_type, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "unsupported_grant_type") {
		t.Errorf("Unexpected body for unsupported grant_type: %s", rec.Body.String())
	}

	// 3. authorization_code missing code
	req = httptest.NewRequest("POST", "/oauth2/token", strings.NewReader("grant_type=authorization_code&redirect_uri=https://chatgpt.com/callback"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	HandleOAuthToken(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing code, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "code parameter is required") {
		t.Errorf("Unexpected body for missing code: %s", rec.Body.String())
	}

	// 4. authorization_code missing redirect_uri
	req = httptest.NewRequest("POST", "/oauth2/token", strings.NewReader("grant_type=authorization_code&code=test_code"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	HandleOAuthToken(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing redirect_uri, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "redirect_uri parameter is required") {
		t.Errorf("Unexpected body for missing redirect_uri: %s", rec.Body.String())
	}

	// 5. refresh_token missing refresh_token
	req = httptest.NewRequest("POST", "/oauth2/token", strings.NewReader("grant_type=refresh_token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	HandleOAuthToken(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing refresh_token, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "refresh_token parameter is required") {
		t.Errorf("Unexpected body for missing refresh_token: %s", rec.Body.String())
	}
}

func TestHandleOAuthTokenFullCodeExchangeAndRefresh(t *testing.T) {
	ctx := context.Background()
	project.CacheDb = true

	// 1. Setup client
	clientID := "test_mcp_client_e2e"
	redirectURI := "https://chatgpt.com/aip/oauth/callback"
	client := OAuthClient{
		ClientID:     clientID,
		RedirectUris: []string{redirectURI},
		ClientName:   "ChatGPT MCP Test Client",
	}
	_ = SetOAuthClient(ctx, client)

	// 2. Setup PKCE & Authorization Code
	codeVerifier := "test_pkce_verifier_very_long_secret_string_12345"
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	codeChallenge := base64URLEncode(h.Sum(nil))

	authCode := "test_auth_code_e2e_123"
	authCodeObj := OAuthAuthCode{
		Code:                authCode,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		Scope:               "app:jira app:slack",
		AllowedApps:         []string{"jira", "slack"},
		OrgId:               "org_test_mcp_123",
		UserId:              "usr_test_mcp_456",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	_ = SetOAuthAuthCode(ctx, authCodeObj)

	// 3. Exchange code for token with PKCE
	bodyStr := fmt.Sprintf("grant_type=authorization_code&code=%s&client_id=%s&redirect_uri=%s&code_verifier=%s",
		authCode, clientID, redirectURI, codeVerifier)
	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(bodyStr))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	HandleOAuthToken(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on token exchange, got %d: %s", rec.Code, rec.Body.String())
	}

	var tokenResp OAuthTokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("Failed to parse token response JSON: %s", err)
	}

	if !strings.HasPrefix(tokenResp.AccessToken, "shfl_mcp_") {
		t.Errorf("Expected access token prefix 'shfl_mcp_', got %s", tokenResp.AccessToken)
	}
	if !strings.HasPrefix(tokenResp.RefreshToken, "shfl_mcp_refresh_") {
		t.Errorf("Expected refresh token prefix 'shfl_mcp_refresh_', got %s", tokenResp.RefreshToken)
	}
	if tokenResp.TokenType != "Bearer" {
		t.Errorf("Expected token_type 'Bearer', got %s", tokenResp.TokenType)
	}
	if tokenResp.ExpiresIn != 2592000 {
		t.Errorf("Expected expires_in 2592000 (30 days), got %d", tokenResp.ExpiresIn)
	}

	// 4. Verify single-use of auth code: reusing same code should fail
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(bodyStr))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	HandleOAuthToken(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for reused auth code, got %d", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), "invalid_grant") {
		t.Errorf("Expected invalid_grant for reused auth code: %s", rec2.Body.String())
	}

	// 5. Test refresh token rotation
	refreshBody := fmt.Sprintf("grant_type=refresh_token&refresh_token=%s&client_id=%s",
		tokenResp.RefreshToken, clientID)
	reqRefresh := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(refreshBody))
	reqRefresh.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recRefresh := httptest.NewRecorder()

	HandleOAuthToken(recRefresh, reqRefresh)

	if recRefresh.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on refresh token exchange, got %d: %s", recRefresh.Code, recRefresh.Body.String())
	}

	var refreshedResp OAuthTokenResponse
	if err := json.Unmarshal(recRefresh.Body.Bytes(), &refreshedResp); err != nil {
		t.Fatalf("Failed to parse refreshed token response JSON: %s", err)
	}

	if !strings.HasPrefix(refreshedResp.AccessToken, "shfl_mcp_") {
		t.Errorf("Expected refreshed access token prefix 'shfl_mcp_', got %s", refreshedResp.AccessToken)
	}
	if refreshedResp.AccessToken == tokenResp.AccessToken {
		t.Errorf("Expected rotated access token, got identical token")
	}
	if refreshedResp.RefreshToken == tokenResp.RefreshToken {
		t.Errorf("Expected rotated refresh token, got identical refresh token")
	}

	// Verify old access token is revoked
	_, err := GetOAuthToken(ctx, tokenResp.AccessToken)
	if err == nil {
		t.Errorf("Expected old access token to be deleted after refresh rotation")
	}

	// Verify new access token exists with correct permissions
	newTok, err := GetOAuthToken(ctx, refreshedResp.AccessToken)
	if err != nil {
		t.Fatalf("Failed to get new OAuth token: %s", err)
	}
	if newTok.OrgId != "org_test_mcp_123" {
		t.Errorf("Expected OrgId 'org_test_mcp_123', got %s", newTok.OrgId)
	}
	if len(newTok.AllowedApps) != 2 || newTok.AllowedApps[0] != "jira" || newTok.AllowedApps[1] != "slack" {
		t.Errorf("Expected AllowedApps ['jira', 'slack'], got %#v", newTok.AllowedApps)
	}
}

func TestHandleApiAuthenticationWithOAuthToken(t *testing.T) {
	ctx := context.Background()
	project.CacheDb = true

	// 1. Create a user in cache
	user := User{
		Id:       "usr_mcp_auth_test",
		Username: "mcp_user@example.com",
		ActiveOrg: OrgMini{
			Id:   "org_primary_123",
			Name: "Primary Org",
		},
		Orgs: []string{"org_primary_123", "org_target_mcp_456"},
	}
	// Cache user by username and ID
	userData, _ := json.Marshal(user)
	_ = SetCache(ctx, fmt.Sprintf("user_%s", strings.ToLower(user.Username)), userData, 300)
	_ = SetCache(ctx, fmt.Sprintf("user_%s", strings.ToLower(user.Id)), userData, 300)
	_ = SetCache(ctx, fmt.Sprintf("Users_%s", user.Username), userData, 300)
	_ = SetCache(ctx, fmt.Sprintf("Users_%s", user.Id), userData, 300)

	// Cache target Org
	targetOrg := Org{
		Id:   "org_target_mcp_456",
		Name: "Target MCP Org",
	}
	orgData, _ := json.Marshal(targetOrg)
	_ = SetCache(ctx, "Organizations_org_target_mcp_456", orgData, 300)

	// 2. Create OAuthToken scoped to a specific org and apps
	accessToken := "shfl_mcp_test_api_auth_token_xyz"
	tok := OAuthToken{
		AccessToken: accessToken,
		UserId:      user.Username,
		OrgId:       "org_target_mcp_456",
		Scope:       "app:jira app:slack",
		AllowedApps: []string{"jira", "slack"},
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}
	_ = SetOAuthToken(ctx, tok)

	// 3. Request API with Bearer token
	req := httptest.NewRequest("GET", "/api/v1/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rec := httptest.NewRecorder()

	authResult, err := HandleApiAuthentication(rec, req)
	if err != nil {
		t.Fatalf("HandleApiAuthentication failed: %s", err)
	}

	if authResult.ActiveOrg.Id != "org_target_mcp_456" {
		t.Errorf("Expected ActiveOrg.Id 'org_target_mcp_456', got %s", authResult.ActiveOrg.Id)
	}
	if len(authResult.AllowedApps) != 2 || authResult.AllowedApps[0] != "jira" || authResult.AllowedApps[1] != "slack" {
		t.Errorf("Expected AllowedApps ['jira', 'slack'], got %#v", authResult.AllowedApps)
	}
	if authResult.OAuthScope != "app:jira app:slack" {
		t.Errorf("Expected OAuthScope 'app:jira app:slack', got %s", authResult.OAuthScope)
	}
}

func TestHandleOAuthTokenClientIDEnforcement(t *testing.T) {
	ctx := context.Background()
	project.CacheDb = true

	code := "shuffle_code_enforcement_test"
	authCodeObj := OAuthAuthCode{
		ID:                  code,
		Code:                code,
		ClientID:            "client_expected_123",
		RedirectURI:         "https://chatgpt.com/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		OrgId:               "org_1",
		UserId:              "user_1",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	_ = SetOAuthAuthCode(ctx, authCodeObj)

	// 1. Missing client_id
	body := fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=https://chatgpt.com/callback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", code)
	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	HandleOAuthToken(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_client") {
		t.Errorf("Expected 400 invalid_client for missing client_id, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Mismatched client_id
	body = fmt.Sprintf("grant_type=authorization_code&code=%s&client_id=wrong_client&redirect_uri=https://chatgpt.com/callback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", code)
	req = httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	HandleOAuthToken(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_client") {
		t.Errorf("Expected 400 invalid_client for mismatched client_id, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleOAuthTokenScopeDownscoping(t *testing.T) {
	ctx := context.Background()
	project.CacheDb = true

	refreshToken := "shfl_mcp_refresh_scope_test"
	tok := OAuthToken{
		ID:           "shfl_mcp_old_token",
		AccessToken:  "shfl_mcp_old_token",
		RefreshToken: refreshToken,
		ClientID:     "client_mcp_scope",
		OrgId:        "org_scope_1",
		UserId:       "user_scope_1",
		Scope:        "app:jira app:slack",
		AllowedApps:  []string{"jira", "slack"},
		ExpiresIn:    3600,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	_ = SetOAuthToken(ctx, tok)

	// 1. Requesting unauthorized escalated scope (e.g. app:github)
	body := fmt.Sprintf("grant_type=refresh_token&refresh_token=%s&client_id=client_mcp_scope&scope=app:github", refreshToken)
	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	HandleOAuthToken(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_scope") {
		t.Errorf("Expected 400 invalid_scope for privilege escalation, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Requesting valid downscoped scope (e.g. only app:jira)
	body = fmt.Sprintf("grant_type=refresh_token&refresh_token=%s&client_id=client_mcp_scope&scope=app:jira", refreshToken)
	req = httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	HandleOAuthToken(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for valid downscoping, got %d: %s", rec.Code, rec.Body.String())
	}

	var respObj OAuthTokenResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &respObj)
	if respObj.Scope != "app:jira" {
		t.Errorf("Expected refreshed token scope 'app:jira', got %s", respObj.Scope)
	}

	newTok, _ := GetOAuthToken(ctx, respObj.AccessToken)
	if newTok == nil || len(newTok.AllowedApps) != 1 || newTok.AllowedApps[0] != "jira" {
		t.Errorf("Expected AllowedApps ['jira'], got %#v", newTok)
	}
}

func TestHandleOAuthRevoke(t *testing.T) {
	ctx := context.Background()
	project.CacheDb = true

	accessToken := "shfl_mcp_to_revoke"
	refreshToken := "shfl_mcp_refresh_to_revoke"
	tok := OAuthToken{
		ID:           accessToken,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ClientID:     "client_revoke_test",
		OrgId:        "org_revoke_1",
		UserId:       "user_revoke_1",
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	_ = SetOAuthToken(ctx, tok)

	// Verify token exists before revocation
	savedTok, err := GetOAuthToken(ctx, accessToken)
	if err != nil || savedTok == nil {
		t.Fatalf("Token should exist prior to revocation")
	}

	// 1. Revoke by access token
	body := fmt.Sprintf("token=%s&client_id=client_revoke_test", accessToken)
	req := httptest.NewRequest("POST", "/oauth2/revoke", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	HandleOAuthRevoke(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from /oauth2/revoke, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify token was deleted
	revokedTok, err := GetOAuthToken(ctx, accessToken)
	if err == nil && revokedTok != nil {
		t.Errorf("Expected token to be deleted, but still found: %#v", revokedTok)
	}

	// 2. RFC 7009 Section 2.2: Revoking an already deleted/invalid token must return 200 OK
	req = httptest.NewRequest("POST", "/oauth2/revoke", strings.NewReader("token=non_existent_token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	HandleOAuthRevoke(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for already revoked token per RFC 7009, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestValidateOAuthTokenAccess_BasicAndExpiry(t *testing.T) {
	ctx := context.Background()

	// 1. Nil token
	req := httptest.NewRequest("GET", "/api/v1/info", nil)
	if err := ValidateOAuthTokenAccess(ctx, nil, req); err == nil {
		t.Errorf("Expected error for nil token, got nil")
	}

	// 2. Expired token
	expiredTok := &OAuthToken{
		AccessToken: "shfl_mcp_expired_tok",
		ExpiresAt:   time.Now().Add(-1 * time.Hour),
		Scope:       "workflow:read",
	}
	if err := ValidateOAuthTokenAccess(ctx, expiredTok, req); err == nil || !strings.Contains(err.Error(), "token_expired") {
		t.Errorf("Expected token_expired error, got: %v", err)
	}

	// 3. Valid active token
	validTok := &OAuthToken{
		AccessToken: "shfl_mcp_valid_tok",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Scope:       "workflow:read",
	}
	if err := ValidateOAuthTokenAccess(ctx, validTok, req); err != nil {
		t.Errorf("Expected valid token on safe /api/v1/info to pass, got: %v", err)
	}
}

func TestValidateOAuthTokenAccess_OrgBoundaries(t *testing.T) {
	ctx := context.Background()

	tok := &OAuthToken{
		AccessToken: "shfl_mcp_org_bound_tok",
		OrgId:       "org_acme_corp",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Scope:       "workflow:read",
	}

	// 1. Same org in header -> OK
	req1 := httptest.NewRequest("GET", "/api/v1/workflows", nil)
	req1.Header.Set("Org-Id", "org_acme_corp")
	if err := ValidateOAuthTokenAccess(ctx, tok, req1); err != nil {
		t.Errorf("Expected same org header to pass, got: %v", err)
	}

	// 2. Mismatched org in header -> Error
	req2 := httptest.NewRequest("GET", "/api/v1/workflows", nil)
	req2.Header.Set("Org-Id", "org_other_corp")
	if err := ValidateOAuthTokenAccess(ctx, tok, req2); err == nil || !strings.Contains(err.Error(), "org_mismatch") {
		t.Errorf("Expected org_mismatch error for header, got: %v", err)
	}

	// 3. Mismatched org in query parameter -> Error
	req3 := httptest.NewRequest("GET", "/api/v1/workflows?org_id=org_other_corp", nil)
	if err := ValidateOAuthTokenAccess(ctx, tok, req3); err == nil || !strings.Contains(err.Error(), "org_mismatch") {
		t.Errorf("Expected org_mismatch error for query param, got: %v", err)
	}

	// 4. Mismatched org in REST path (/api/v1/orgs/{id}/...) -> Error
	req4 := httptest.NewRequest("GET", "/api/v1/orgs/org_other_corp/workflows", nil)
	if err := ValidateOAuthTokenAccess(ctx, tok, req4); err == nil || !strings.Contains(err.Error(), "org_mismatch") {
		t.Errorf("Expected org_mismatch error for path, got: %v", err)
	}
}

func TestValidateOAuthTokenAccess_ScopesAndWorkflows(t *testing.T) {
	ctx := context.Background()

	readTok := &OAuthToken{
		AccessToken: "shfl_mcp_read_tok",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Scope:       "workflow:read",
	}

	runTok := &OAuthToken{
		AccessToken: "shfl_mcp_run_tok",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Scope:       "workflow:run",
	}

	editTok := &OAuthToken{
		AccessToken: "shfl_mcp_edit_tok",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Scope:       "workflow:edit",
	}

	// Read scope: Can GET workflows, cannot RUN or MODIFY
	reqGet := httptest.NewRequest("GET", "/api/v1/workflows", nil)
	if err := ValidateOAuthTokenAccess(ctx, readTok, reqGet); err != nil {
		t.Errorf("readTok should be allowed to GET workflows: %v", err)
	}

	reqRun := httptest.NewRequest("POST", "/api/v1/workflows/wf_123/run", nil)
	if err := ValidateOAuthTokenAccess(ctx, readTok, reqRun); err == nil || !strings.Contains(err.Error(), "insufficient_scope") {
		t.Errorf("readTok should NOT be allowed to run workflow, got: %v", err)
	}

	reqDel := httptest.NewRequest("DELETE", "/api/v1/workflows/wf_123", nil)
	if err := ValidateOAuthTokenAccess(ctx, readTok, reqDel); err == nil || !strings.Contains(err.Error(), "insufficient_scope") {
		t.Errorf("readTok should NOT be allowed to delete workflow, got: %v", err)
	}

	// Run scope: Can GET and RUN workflows, cannot MODIFY
	if err := ValidateOAuthTokenAccess(ctx, runTok, reqRun); err != nil {
		t.Errorf("runTok should be allowed to run workflow: %v", err)
	}
	if err := ValidateOAuthTokenAccess(ctx, runTok, reqDel); err == nil || !strings.Contains(err.Error(), "insufficient_scope") {
		t.Errorf("runTok should NOT be allowed to delete workflow, got: %v", err)
	}

	// Edit scope: Can GET, RUN, and MODIFY workflows
	if err := ValidateOAuthTokenAccess(ctx, editTok, reqGet); err != nil {
		t.Errorf("editTok should be allowed to GET workflows: %v", err)
	}
	if err := ValidateOAuthTokenAccess(ctx, editTok, reqRun); err != nil {
		t.Errorf("editTok should be allowed to run workflow: %v", err)
	}
	if err := ValidateOAuthTokenAccess(ctx, editTok, reqDel); err != nil {
		t.Errorf("editTok should be allowed to delete workflow: %v", err)
	}
}

func TestValidateOAuthTokenAccess_AppAccessControl(t *testing.T) {
	ctx := context.Background()

	tok := &OAuthToken{
		AccessToken: "shfl_mcp_app_tok",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Scope:       "apps:run",
		AllowedApps: []string{"jira", "slack"},
	}

	// 1. Allowed app via path: /api/v1/apps/jira/run -> OK
	reqJira := httptest.NewRequest("POST", "/api/v1/apps/jira/run", nil)
	if err := ValidateOAuthTokenAccess(ctx, tok, reqJira); err != nil {
		t.Errorf("Expected jira run to be allowed, got: %v", err)
	}

	// 2. Disallowed app via path: /api/v1/apps/salesforce/run -> Error
	reqSalesforce := httptest.NewRequest("POST", "/api/v1/apps/salesforce/run", nil)
	if err := ValidateOAuthTokenAccess(ctx, tok, reqSalesforce); err == nil || !strings.Contains(err.Error(), "unauthorized_app") {
		t.Errorf("Expected unauthorized_app for salesforce, got: %v", err)
	}

	// 3. Allowed app via categories query param: /api/v1/apps/categories/run?app_name=slack -> OK
	reqCatSlack := httptest.NewRequest("POST", "/api/v1/apps/categories/run?app_name=slack", nil)
	if err := ValidateOAuthTokenAccess(ctx, tok, reqCatSlack); err != nil {
		t.Errorf("Expected categories run with slack to be allowed, got: %v", err)
	}

	// 4. Disallowed app via categories query param: /api/v1/apps/categories/run?app_name=github -> Error
	reqCatGithub := httptest.NewRequest("POST", "/api/v1/apps/categories/run?app_name=github", nil)
	if err := ValidateOAuthTokenAccess(ctx, tok, reqCatGithub); err == nil || !strings.Contains(err.Error(), "unauthorized_app") {
		t.Errorf("Expected unauthorized_app for github via query param, got: %v", err)
	}
}

func TestValidateOAuthTokenAccess_BlockedEndpoints(t *testing.T) {
	ctx := context.Background()

	standardTok := &OAuthToken{
		AccessToken: "shfl_mcp_standard_tok",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Scope:       "workflow:edit apps:run",
	}

	adminTok := &OAuthToken{
		AccessToken: "shfl_mcp_admin_tok",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Scope:       "admin",
	}

	blockedPaths := []string{
		"/api/v1/admin/users",
		"/api/v1/billing/invoices",
		"/api/v1/cloud_sync/config",
		"/api/v1/orgs/org_123/users",
		"/api/v1/orgs/org_123/delete",
	}

	for _, p := range blockedPaths {
		req := httptest.NewRequest("POST", p, nil)

		// Standard token MUST be rejected
		if err := ValidateOAuthTokenAccess(ctx, standardTok, req); err == nil || !strings.Contains(err.Error(), "forbidden_endpoint") {
			t.Errorf("Expected forbidden_endpoint for %s with standard token, got: %v", p, err)
		}

		// Superuser / Admin token is allowed
		if err := ValidateOAuthTokenAccess(ctx, adminTok, req); err != nil {
			t.Errorf("Admin token should be permitted on %s, got: %v", p, err)
		}
	}
}

func TestValidateOAuthTokenAccess_CustomRuleExtensibility(t *testing.T) {
	ctx := context.Background()

	// Register a plugin rule
	RegisterOAuthEndpointRule(OAuthEndpointRule{
		Name:           "Custom Security Scan",
		PathPrefix:     "/api/v1/security/scan",
		Methods:        []string{"POST"},
		RequiredScopes: []string{"security:scan"},
		Description:    "Execute custom security audit scan",
	})

	noScopeTok := &OAuthToken{
		AccessToken: "shfl_mcp_custom_tok1",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Scope:       "workflow:run",
	}

	hasScopeTok := &OAuthToken{
		AccessToken: "shfl_mcp_custom_tok2",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Scope:       "security:scan",
	}

	req := httptest.NewRequest("POST", "/api/v1/security/scan", nil)

	if err := ValidateOAuthTokenAccess(ctx, noScopeTok, req); err == nil || !strings.Contains(err.Error(), "insufficient_scope") {
		t.Errorf("Expected insufficient_scope for custom rule without security:scan, got: %v", err)
	}

	if err := ValidateOAuthTokenAccess(ctx, hasScopeTok, req); err != nil {
		t.Errorf("Expected custom rule to pass with security:scan scope, got: %v", err)
	}
}

func TestHandleOAuthAuthorize_OrgAdminEnforcement(t *testing.T) {
	ctx := context.Background()
	project.CacheDb = true

	// 1. Create client
	client := OAuthClient{
		ClientID:     "client_admin_test",
		ClientSecret: "secret_admin_test",
		ClientName:   "Admin Enforcer App",
		RedirectUris: []string{"https://app.example.com/oauth/callback"},
	}
	_ = SetOAuthClient(ctx, client)

	// 2. Setup organization with 1 Admin and 1 Member
	testOrg := Org{
		Id:   "org_with_roles_123",
		Name: "Role Testing Org",
		Users: []User{
			{
				Id:       "usr_admin_1",
				Username: "admin@corp.internal",
				Role:     "admin",
			},
			{
				Id:       "usr_member_1",
				Username: "member@corp.internal",
				Role:     "member",
			},
		},
	}
	orgBytes, _ := json.Marshal(testOrg)
	_ = SetCache(ctx, "Organizations_org_with_roles_123", orgBytes, 300)

	// User objects in cache
	adminUser := User{
		Id:        "usr_admin_1",
		Username:  "admin@corp.internal",
		Role:      "org_user", // Global role is non-admin, but org role is admin
		ActiveOrg: OrgMini{Id: "org_with_roles_123"},
		Orgs:      []string{"org_with_roles_123"},
	}
	adminBytes, _ := json.Marshal(adminUser)
	_ = SetCache(ctx, "Users_usr_admin_1", adminBytes, 300)
	_ = SetCache(ctx, "user_usr_admin_1", adminBytes, 300)

	memberUser := User{
		Id:        "usr_member_1",
		Username:  "member@corp.internal",
		Role:      "org_user", // Neither global admin nor org admin
		ActiveOrg: OrgMini{Id: "org_with_roles_123"},
		Orgs:      []string{"org_with_roles_123"},
	}
	memberBytes, _ := json.Marshal(memberUser)
	_ = SetCache(ctx, "Users_usr_member_1", memberBytes, 300)
	_ = SetCache(ctx, "user_usr_member_1", memberBytes, 300)

	// 3. Member user tries to approve consent -> MUST be 403 Forbidden
	memberAuthReq := OAuthAuthorizeRequest{
		ClientID:            client.ClientID,
		RedirectURI:         client.RedirectUris[0],
		ResponseType:        "code",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Scope:               "workflow:edit",
		Approved:            true,
		OrgId:               testOrg.Id,
	}
	memberPayload, _ := json.Marshal(memberAuthReq)
	reqMember := httptest.NewRequest("POST", "/oauth2/authorize", strings.NewReader(string(memberPayload)))
	reqMember.Header.Set("Content-Type", "application/json")
	// Set session auth as member
	reqMember.AddCookie(&http.Cookie{Name: "session_token", Value: "session_member_token_123"})
	_ = SetCache(ctx, "session_session_member_token_123", memberBytes, 300)

	recMember := httptest.NewRecorder()
	HandleOAuthAuthorize(recMember, reqMember)

	if recMember.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for non-admin member consent approval, got %d: %s", recMember.Code, recMember.Body.String())
	}
	if !strings.Contains(recMember.Body.String(), "administrators") {
		t.Errorf("Expected error to mention administrators, got: %s", recMember.Body.String())
	}

	// 4. Admin user approves consent -> MUST succeed with 302 redirect
	adminAuthReq := memberAuthReq
	adminPayload, _ := json.Marshal(adminAuthReq)
	reqAdmin := httptest.NewRequest("POST", "/oauth2/authorize", strings.NewReader(string(adminPayload)))
	reqAdmin.Header.Set("Content-Type", "application/json")
	reqAdmin.AddCookie(&http.Cookie{Name: "session_token", Value: "session_admin_token_123"})
	_ = SetCache(ctx, "session_session_admin_token_123", adminBytes, 300)

	recAdmin := httptest.NewRecorder()
	HandleOAuthAuthorize(recAdmin, reqAdmin)

	if recAdmin.Code != http.StatusFound && recAdmin.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK or 302 Found for org admin consent approval, got %d: %s", recAdmin.Code, recAdmin.Body.String())
	}
	targetURL := recAdmin.Header().Get("Location")
	if targetURL == "" {
		var respMap map[string]string
		_ = json.Unmarshal(recAdmin.Body.Bytes(), &respMap)
		targetURL = respMap["redirect_url"]
	}
	if !strings.Contains(targetURL, "code=") {
		t.Errorf("Expected redirect URL to contain code=, got: %s", targetURL)
	}
}

func TestHandleOAuthAuthorize_ConsentDefaultAndExplicitDenial(t *testing.T) {
	ctx := context.Background()
	project.CacheDb = true

	// 1. Setup client
	client := OAuthClient{
		ClientID:     "client_consent_test",
		ClientSecret: "secret_consent_test",
		RedirectUris: []string{"https://chatgpt.com/connector_platform_oauth_redirect"},
		Scope:        "workflow:edit",
	}
	_ = SetOAuthClient(ctx, client)

	// 2. Setup admin user
	adminUser := User{
		Id:        "usr_consent_admin",
		Username:  "frikky@shuffler.io",
		Role:      "admin",
		ActiveOrg: OrgMini{Id: "org_consent_123"},
		Orgs:      []string{"org_consent_123"},
	}
	adminBytes, _ := json.Marshal(adminUser)
	_ = SetCache(ctx, "Users_usr_consent_admin", adminBytes, 300)
	_ = SetCache(ctx, "user_usr_consent_admin", adminBytes, 300)
	_ = SetCache(ctx, "session_session_consent_admin", adminBytes, 300)

	// Case 1: JSON payload with NO "approved" field (OpenAI dynamic setup) -> defaults to APPROVED
	jsonOmittedApproved := `{
		"client_id": "client_consent_test",
		"redirect_uri": "https://chatgpt.com/connector_platform_oauth_redirect",
		"org_id": "org_consent_123",
		"scope": "workflow:edit",
		"state": "oauth_s_test_123",
		"code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		"code_challenge_method": "S256"
	}`
	req1 := httptest.NewRequest("POST", "/api/v1/oauth2/authorize", strings.NewReader(jsonOmittedApproved))
	req1.Header.Set("Content-Type", "application/json")
	req1.AddCookie(&http.Cookie{Name: "session_token", Value: "session_consent_admin"})
	rec1 := httptest.NewRecorder()
	HandleOAuthAuthorize(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("Case 1 (omitted approved): Expected 200 OK, got %d: %s", rec1.Code, rec1.Body.String())
	}
	var resp1 OAuthAuthorizeResponse
	if err := json.Unmarshal(rec1.Body.Bytes(), &resp1); err != nil {
		t.Fatalf("Case 1: Failed to parse response: %v", err)
	}
	if !strings.Contains(resp1.RedirectURL, "code=shuffle_code_") {
		t.Errorf("Case 1: Expected redirect_url to have code=shuffle_code_, got: %s", resp1.RedirectURL)
	}
	if !strings.Contains(resp1.RedirectURL, "state=oauth_s_test_123") {
		t.Errorf("Case 1: Expected redirect_url to preserve state, got: %s", resp1.RedirectURL)
	}
	if !strings.Contains(resp1.RedirectURL, "iss=") {
		t.Errorf("Case 1: Expected redirect_url to have RFC 9207 iss, got: %s", resp1.RedirectURL)
	}

	// Case 2: JSON payload with explicit "approved": false -> DENIED
	jsonExplicitFalse := `{
		"client_id": "client_consent_test",
		"redirect_uri": "https://chatgpt.com/connector_platform_oauth_redirect",
		"org_id": "org_consent_123",
		"scope": "workflow:edit",
		"state": "oauth_s_test_123",
		"code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		"code_challenge_method": "S256",
		"approved": false
	}`
	req2 := httptest.NewRequest("POST", "/api/v1/oauth2/authorize", strings.NewReader(jsonExplicitFalse))
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(&http.Cookie{Name: "session_token", Value: "session_consent_admin"})
	rec2 := httptest.NewRecorder()
	HandleOAuthAuthorize(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("Case 2 (approved=false): Expected 200 OK, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var resp2 OAuthAuthorizeResponse
	_ = json.Unmarshal(rec2.Body.Bytes(), &resp2)
	if !strings.Contains(resp2.RedirectURL, "error=access_denied") {
		t.Errorf("Case 2: Expected redirect_url to have error=access_denied, got: %s", resp2.RedirectURL)
	}

	// Case 3: JSON payload with explicit "action": "deny" -> DENIED
	jsonActionDeny := `{
		"client_id": "client_consent_test",
		"redirect_uri": "https://chatgpt.com/connector_platform_oauth_redirect",
		"org_id": "org_consent_123",
		"code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		"code_challenge_method": "S256",
		"action": "deny",
		"state": "oauth_s_test_123"
	}`
	req3 := httptest.NewRequest("POST", "/api/v1/oauth2/authorize", strings.NewReader(jsonActionDeny))
	req3.Header.Set("Content-Type", "application/json")
	req3.AddCookie(&http.Cookie{Name: "session_token", Value: "session_consent_admin"})
	rec3 := httptest.NewRecorder()
	HandleOAuthAuthorize(rec3, req3)

	var resp3 OAuthAuthorizeResponse
	_ = json.Unmarshal(rec3.Body.Bytes(), &resp3)
	if !strings.Contains(resp3.RedirectURL, "error=access_denied") {
		t.Errorf("Case 3: Expected redirect_url to have error=access_denied, got: %s", resp3.RedirectURL)
	}

	// Case 4: Form-encoded with no approved field -> defaults to APPROVED
	formBody := url.Values{}
	formBody.Set("client_id", "client_consent_test")
	formBody.Set("redirect_uri", "https://chatgpt.com/connector_platform_oauth_redirect")
	formBody.Set("org_id", "org_consent_123")
	formBody.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	formBody.Set("code_challenge_method", "S256")
	formBody.Set("state", "oauth_s_test_form")

	req4 := httptest.NewRequest("POST", "/oauth2/authorize", strings.NewReader(formBody.Encode()))
	req4.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req4.AddCookie(&http.Cookie{Name: "session_token", Value: "session_consent_admin"})
	rec4 := httptest.NewRecorder()
	HandleOAuthAuthorize(rec4, req4)

	if rec4.Code != http.StatusFound {
		t.Fatalf("Case 4 (form omitted approved): Expected 302 Found, got %d: %s", rec4.Code, rec4.Body.String())
	}
	loc4 := rec4.Header().Get("Location")
	if !strings.Contains(loc4, "code=shuffle_code_") {
		t.Errorf("Case 4: Expected Location header to contain code=shuffle_code_, got: %s", loc4)
	}

	// Case 5: Form-encoded with action=deny -> DENIED
	formBodyDeny := url.Values{}
	formBodyDeny.Set("client_id", "client_consent_test")
	formBodyDeny.Set("redirect_uri", "https://chatgpt.com/connector_platform_oauth_redirect")
	formBodyDeny.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	formBodyDeny.Set("action", "deny")
	formBodyDeny.Set("state", "oauth_s_test_form_deny")

	req5 := httptest.NewRequest("POST", "/oauth2/authorize", strings.NewReader(formBodyDeny.Encode()))
	req5.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req5.AddCookie(&http.Cookie{Name: "session_token", Value: "session_consent_admin"})
	rec5 := httptest.NewRecorder()
	HandleOAuthAuthorize(rec5, req5)

	if rec5.Code != http.StatusFound {
		t.Fatalf("Case 5 (form action=deny): Expected 302 Found, got %d: %s", rec5.Code, rec5.Body.String())
	}
	loc5 := rec5.Header().Get("Location")
	if !strings.Contains(loc5, "error=access_denied") {
		t.Errorf("Case 5: Expected Location header to have error=access_denied, got: %s", loc5)
	}
}

func TestHandleApiAuthentication_WithEndpointValidation(t *testing.T) {
	ctx := context.Background()
	project.CacheDb = true

	user := User{
		Id:        "usr_api_val_test",
		Username:  "val_test@shuffler.io",
		ActiveOrg: OrgMini{Id: "org_val_101"},
		Orgs:      []string{"org_val_101"},
	}
	userData, _ := json.Marshal(user)
	_ = SetCache(ctx, "user_usr_api_val_test", userData, 300)
	_ = SetCache(ctx, "Users_usr_api_val_test", userData, 300)
	_ = SetCache(ctx, "Organizations_org_val_101", []byte(`{"id":"org_val_101","name":"Val Org"}`), 300)

	tok := OAuthToken{
		AccessToken: "shfl_mcp_val_token_999",
		UserId:      user.Id,
		OrgId:       "org_val_101",
		Scope:       "workflow:read",
		ExpiresAt:   time.Now().Add(2 * time.Hour),
	}
	_ = SetOAuthToken(ctx, tok)

	// 1. Authorized GET /api/v1/workflows -> Succeeds
	req1 := httptest.NewRequest("GET", "/api/v1/workflows", nil)
	req1.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rec1 := httptest.NewRecorder()

	u1, err1 := HandleApiAuthentication(rec1, req1)
	if err1 != nil {
		t.Fatalf("Expected successful authentication for GET /api/v1/workflows, got error: %v", err1)
	}
	if u1.Id != user.Id {
		t.Errorf("Expected user ID %s, got %s", user.Id, u1.Id)
	}

	// 2. Unauthorized POST /api/v1/admin/users -> Rejected by endpoint validation
	req2 := httptest.NewRequest("POST", "/api/v1/admin/users", nil)
	req2.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rec2 := httptest.NewRecorder()

	_, err2 := HandleApiAuthentication(rec2, req2)
	if err2 == nil || !strings.Contains(err2.Error(), "forbidden_endpoint") {
		t.Errorf("Expected forbidden_endpoint error for admin path, got: %v", err2)
	}

	// 3. Unauthorized DELETE /api/v1/workflows/123 -> Rejected due to insufficient scope
	req3 := httptest.NewRequest("DELETE", "/api/v1/workflows/123", nil)
	req3.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rec3 := httptest.NewRecorder()

	_, err3 := HandleApiAuthentication(rec3, req3)
	if err3 == nil || !strings.Contains(err3.Error(), "insufficient_scope") {
		t.Errorf("Expected insufficient_scope error for DELETE workflow, got: %v", err3)
	}
}

func TestHandleOAuthAuthorizationServer_EndpointsAndAuthMethods(t *testing.T) {
	origPrefix := os.Getenv("SHUFFLE_OAUTH_API_PREFIX")
	defer os.Setenv("SHUFFLE_OAUTH_API_PREFIX", origPrefix)

	// 1. Default prefix should be /api/v1
	os.Unsetenv("SHUFFLE_OAUTH_API_PREFIX")
	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	req.Host = "tunnel.schemaless.org"
	rec := httptest.NewRecorder()

	HandleOAuthAuthorizationServer(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rec.Code)
	}

	var meta map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	expectedToken := "https://tunnel.schemaless.org/api/v1/oauth2/token"
	if meta["token_endpoint"] != expectedToken {
		t.Errorf("Expected token_endpoint '%s', got '%s'", expectedToken, meta["token_endpoint"])
	}

	expectedRegister := "https://tunnel.schemaless.org/api/v1/oauth2/register"
	if meta["registration_endpoint"] != expectedRegister {
		t.Errorf("Expected registration_endpoint '%s', got '%s'", expectedRegister, meta["registration_endpoint"])
	}

	expectedRevoke := "https://tunnel.schemaless.org/api/v1/oauth2/revoke"
	if meta["revocation_endpoint"] != expectedRevoke {
		t.Errorf("Expected revocation_endpoint '%s', got '%s'", expectedRevoke, meta["revocation_endpoint"])
	}

	authMethods, ok := meta["token_endpoint_auth_methods_supported"].([]interface{})
	if !ok {
		t.Fatalf("Expected token_endpoint_auth_methods_supported to be []interface{}, got %T", meta["token_endpoint_auth_methods_supported"])
	}
	var methods []string
	for _, m := range authMethods {
		methods = append(methods, fmt.Sprintf("%v", m))
	}
	if !ArrayContains(methods, "client_secret_basic") {
		t.Errorf("Expected token_endpoint_auth_methods_supported to include 'client_secret_basic', got %v", methods)
	}

	// 2. Override prefix to "" (none)
	os.Setenv("SHUFFLE_OAUTH_API_PREFIX", "none")
	rec2 := httptest.NewRecorder()
	HandleOAuthAuthorizationServer(rec2, req)
	var meta2 map[string]interface{}
	json.Unmarshal(rec2.Body.Bytes(), &meta2)
	if meta2["token_endpoint"] != "https://tunnel.schemaless.org/oauth2/token" {
		t.Errorf("Expected token_endpoint 'https://tunnel.schemaless.org/oauth2/token' with prefix 'none', got '%s'", meta2["token_endpoint"])
	}
}

func TestOAuthAuthCodeDatastoreSerialization(t *testing.T) {
	code := OAuthAuthCode{
		ID:                  "shuffle_code_test123",
		Code:                "shuffle_code_test123",
		ClientID:            "client_123",
		RedirectURI:         "https://chatgpt.com/redirect",
		CodeChallenge:       "challenge123",
		CodeChallengeMethod: "S256",
		Scope:               "workflow:edit",
		AllowedApps:         []string{"app1", "app2"},
		OrgId:               "org_123",
		UserId:              "usr_123",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		Used:                false,
		CreatedAt:           time.Now().Unix(),
	}

	props, err := datastore.SaveStruct(&code)
	if err != nil {
		t.Fatalf("datastore.SaveStruct failed for OAuthAuthCode: %v", err)
	}

	var loaded OAuthAuthCode
	if err := datastore.LoadStruct(&loaded, props); err != nil {
		t.Fatalf("datastore.LoadStruct failed for OAuthAuthCode: %v", err)
	}

	if loaded.Code != code.Code {
		t.Errorf("Expected code '%s', got '%s'", code.Code, loaded.Code)
	}
}

func TestGetSupportedOAuthScopes(t *testing.T) {
	scopes := GetSupportedOAuthScopes()
	if _, ok := scopes["workflow:edit"]; !ok {
		t.Fatalf("Expected workflow:edit in supported scopes")
	}
	if _, ok := scopes["workflow:read"]; !ok {
		t.Fatalf("Expected workflow:read in supported scopes")
	}
	if _, ok := scopes["workflow:run"]; !ok {
		t.Fatalf("Expected workflow:run in supported scopes")
	}
}

func TestParseOAuthScopes(t *testing.T) {
	// 1. Default fallback
	scopes := ParseOAuthScopes("")
	if len(scopes) != 1 || scopes[0].Scope != "workflow:edit" {
		t.Errorf("Expected default to workflow:edit, got: %#v", scopes)
	}

	// 2. Multiple scopes with custom scope fallback
	scopes = ParseOAuthScopes("workflow:edit workflow:run custom:action")
	if len(scopes) != 3 {
		t.Fatalf("Expected 3 scopes, got %d", len(scopes))
	}
	if scopes[0].Scope != "workflow:edit" || scopes[0].Category != "Workflows" {
		t.Errorf("Unexpected scope[0]: %#v", scopes[0])
	}
	if scopes[1].Scope != "workflow:run" || scopes[1].Category != "Workflows" {
		t.Errorf("Unexpected scope[1]: %#v", scopes[1])
	}
	if scopes[2].Scope != "custom:action" || scopes[2].Category != "Custom" {
		t.Errorf("Unexpected scope[2]: %#v", scopes[2])
	}
}

func TestHandleOAuthAuthorizeValidationEdgecases(t *testing.T) {
	// Edgecase: Missing client_id
	req := httptest.NewRequest("GET", "/oauth2/authorize", nil)
	rec := httptest.NewRecorder()
	HandleOAuthAuthorize(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing client_id, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "client_id query parameter is required") {
		t.Errorf("Unexpected body for missing client_id: %s", rec.Body.String())
	}

	// Edgecase: Unknown client_id
	req = httptest.NewRequest("GET", "/oauth2/authorize?client_id=nonexistent_client_123", nil)
	rec = httptest.NewRecorder()
	HandleOAuthAuthorize(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for nonexistent client, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "invalid_client") {
		t.Errorf("Unexpected body for nonexistent client: %s", rec.Body.String())
	}

	// Edgecase: Unsupported HTTP method
	req = httptest.NewRequest("DELETE", "/oauth2/authorize", nil)
	rec = httptest.NewRecorder()
	HandleOAuthAuthorize(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 for DELETE, got %d", rec.Code)
	}

	// Edgecase: Unauthenticated POST
	req = httptest.NewRequest("POST", "/oauth2/authorize", strings.NewReader(`{"client_id": "test"}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	HandleOAuthAuthorize(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for unauthenticated POST, got %d", rec.Code)
	}
}

func TestDynamicShuffleClientLoopback(t *testing.T) {
	if !isLoopbackURI("http://127.0.0.1:56780/callback") {
		t.Errorf("Expected http://127.0.0.1:56780/callback to be loopback")
	}
	if !isLoopbackURI("http://localhost:8080/callback") {
		t.Errorf("Expected http://localhost:8080/callback to be loopback")
	}
	if isLoopbackURI("https://evil.com/callback") {
		t.Errorf("Expected https://evil.com/callback to not be loopback")
	}

	if !isMatchingLoopbackURI("http://127.0.0.1:5000/callback", "http://127.0.0.1:6000/callback") {
		t.Errorf("Expected matching loopback URIs across ports")
	}

	if isMatchingLoopbackURI("http://127.0.0.1:5000/callback", "http://evil.com:5000/callback") {
		t.Errorf("Expected false for non-loopback matching")
	}

	if !isDynamicShuffleClient("shuffle_client_1234567890abcdef", "http://127.0.0.1:5000/callback") {
		t.Errorf("Expected shuffle_client_ to be recognized as dynamic shuffle client")
	}

	if !isDynamicShuffleClient("shuffle-agent", "http://127.0.0.1:5000/callback") {
		t.Errorf("Expected shuffle-agent to be recognized as dynamic shuffle client")
	}

	// Verify standard third-party clients are NOT treated as dynamic
	if isDynamicShuffleClient("chatgpt", "https://chatgpt.com/connector_platform_oauth_redirect") {
		t.Errorf("Standard client chatgpt should not be dynamic")
	}

	if isDynamicShuffleClient("thirdparty_corp_app", "https://example.com/oauth/callback") {
		t.Errorf("Standard thirdparty app should not be dynamic")
	}

	if isDynamicShuffleClient("", "http://127.0.0.1:5000/callback") {
		t.Errorf("Empty client_id should not be dynamic")
	}

	if isDynamicShuffleClient("random_desktop_app", "http://127.0.0.1:5000/callback") {
		t.Errorf("Unregistered non-shuffle desktop app should not be auto-treated as dynamic shuffle client")
	}
}
