package shuffle

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"testing"
)

func TestHandleDeviceRemove(t *testing.T) {
	origEnv := project.Environment
	project.Environment = "cloud"
	defer func() { project.Environment = origEnv }()

	ctx := context.Background()
	user := User{
		Id: "user-1",
		Devices: []Device{
			{ID: "dev-1", Token: "tok-1", Platform: "ios"},
			{ID: "dev-2", Token: "tok-2", Platform: "web"},
		},
	}

	updated, err := handleDeviceRemove(ctx, user, "dev-1")
	if err != nil {
		t.Fatalf("expected no error removing dev-1, got: %v", err)
	}
	if len(updated.Devices) != 1 || updated.Devices[0].ID != "dev-2" {
		t.Fatalf("expected only dev-2 to remain, got: %+v", updated.Devices)
	}

	if _, err := handleDeviceRemove(ctx, updated, "dev-missing"); !errors.Is(err, errDeviceNotFound) {
		t.Fatalf("expected errDeviceNotFound, got: %v", err)
	}

	if _, err := handleDeviceRemove(ctx, updated, "   "); err == nil {
		t.Fatalf("expected error for empty device ID")
	}

	project.Environment = "onprem"
	if _, err := handleDeviceRemove(ctx, user, "dev-2"); !errors.Is(err, errCloudSyncRequired) {
		t.Fatalf("expected errCloudSyncRequired in non-cloud environment without Cloud Sync, got: %v", err)
	}

	if _, err := handleDeviceUpsert(ctx, user, Device{ID: "dev-3", Token: "tok-3"}); !errors.Is(err, errCloudSyncRequired) {
		t.Fatalf("expected errCloudSyncRequired on upsert in non-cloud environment without Cloud Sync, got: %v", err)
	}
}

func TestHandleDeviceUpsertDisconnectPreservesMetadata(t *testing.T) {
	origEnv := project.Environment
	project.Environment = "cloud"
	defer func() { project.Environment = origEnv }()

	user := User{
		Id: "user-1",
		Devices: []Device{
			{
				ID:         "dev-1",
				Token:      "tok-1",
				Platform:   "ios",
				DeviceName: "iPhone 16",
				AppVersion: "1.2.3",
				CreatedAt:  1000,
				LastSeenAt: 2000,
			},
		},
	}

	updated, err := handleDeviceUpsert(context.Background(), user, Device{
		ID:    "dev-1",
		Token: "",
	})
	if err != nil {
		t.Fatalf("expected no error disconnecting device, got: %v", err)
	}
	if len(updated.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(updated.Devices))
	}
	dev := updated.Devices[0]
	if dev.Token != "" {
		t.Fatalf("expected empty token, got %q", dev.Token)
	}
	if dev.Platform != "ios" || dev.DeviceName != "iPhone 16" || dev.AppVersion != "1.2.3" || dev.CreatedAt != 1000 || dev.LastSeenAt != 2000 {
		t.Fatalf("expected metadata to be preserved, got %+v", dev)
	}
}

func TestHandleHybridDeviceRemoveIdempotent(t *testing.T) {
	user := User{
		Id: "onprem-user-1",
		Devices: []Device{
			{ID: "dev-1", Token: "tok-1"},
		},
	}

	updated, err := HandleHybridDeviceRemove(user, "dev-1")
	if err != nil || len(updated.Devices) != 0 {
		t.Fatalf("expected dev-1 to be removed, got devices=%+v err=%v", updated.Devices, err)
	}

	// Idempotent when already absent
	if _, err := HandleHybridDeviceRemove(updated, "dev-1"); err != nil {
		t.Fatalf("expected idempotent removal, got: %v", err)
	}
}

func TestIsDeviceUnregisterAction(t *testing.T) {
	for _, action := range []string{"unregister", "UNREGISTER", " remove ", "delete"} {
		if !isDeviceUnregisterAction(action) {
			t.Fatalf("expected %q to be treated as unregister action", action)
		}
	}
	for _, action := range []string{"", "upsert", "register"} {
		if isDeviceUnregisterAction(action) {
			t.Fatalf("expected %q not to be treated as unregister action", action)
		}
	}
}

func TestDeviceWebhookHelpers(t *testing.T) {
	for _, p := range []string{"ios", "iOS", "android", " Android "} {
		if !isMobileDevicePlatform(p) {
			t.Fatalf("expected %q to be a mobile platform", p)
		}
	}
	for _, p := range []string{"web", "desktop", ""} {
		if isMobileDevicePlatform(p) {
			t.Fatalf("expected %q not to be a mobile platform", p)
		}
	}

	tok1, err := generateDeviceWebhookToken()
	if err != nil {
		t.Fatalf("failed generating token: %v", err)
	}
	tok2, err := generateDeviceWebhookToken()
	if err != nil {
		t.Fatalf("failed generating second token: %v", err)
	}
	if tok1 == tok2 || len(tok1) < 50 {
		t.Fatalf("expected unique high-entropy tokens, got %q and %q", tok1, tok2)
	}
	if len(hashDeviceWebhookToken(tok1)) != 64 {
		t.Fatalf("expected 64-char sha256 hex hash")
	}
}

func TestOAuthTokenMultiTenancy(t *testing.T) {
	orgA := "11111111-1111-1111-1111-111111111111"
	orgB := "22222222-2222-2222-2222-222222222222"
	orgField := " " + orgA + " , " + orgB + ", " + orgA + " "

	parsed := parseOAuthTokenOrgs(orgField)
	if len(parsed) != 2 || parsed[0] != orgA || parsed[1] != orgB {
		t.Fatalf("unexpected parsed orgs: %+v", parsed)
	}

	if !oauthTokenAllowsOrg(orgField, orgA) || !oauthTokenAllowsOrg(orgField, orgB) {
		t.Fatalf("expected both exact org UUIDs to be allowed")
	}
	if oauthTokenAllowsOrg(orgField, "11111111") || oauthTokenAllowsOrg(orgField, "33333333-3333-3333-3333-333333333333") || oauthTokenAllowsOrg(orgField, "") {
		t.Fatalf("expected partial or unlisted orgs to be rejected")
	}

	req := httptest.NewRequest("GET", "/api/v1/workflows", nil)
	req.Header.Set("Org-Id", orgB)
	user := User{ActiveOrg: OrgMini{Id: orgA}}
	if eff := resolveOAuthEffectiveOrg(orgField, user, req); eff != orgB {
		t.Fatalf("expected requested allowed org %s, got %s", orgB, eff)
	}

	reqNoHeader := httptest.NewRequest("GET", "/api/v1/workflows", nil)
	if eff := resolveOAuthEffectiveOrg(orgField, user, reqNoHeader); eff != orgA {
		t.Fatalf("expected user active org %s, got %s", orgA, eff)
	}
}

func TestDevicePlusRegionUniqueConnection(t *testing.T) {
	origEnv := project.Environment
	origProj := os.Getenv("SHUFFLE_GCEPROJECT")
	project.Environment = "cloud"
	os.Setenv("SHUFFLE_GCEPROJECT", "uk")
	defer func() {
		project.Environment = origEnv
		os.Setenv("SHUFFLE_GCEPROJECT", origProj)
	}()

	ctx := context.Background()
	user := User{Id: "user-1"}

	// Register same device ID in US ("shuffler") and UK ("uk")
	var err error
	user, err = upsertDeviceIntoUser(ctx, user, Device{
		ID:       "iphone-1",
		Token:    "tok-us",
		Platform: "ios",
		Region:   "shuffler",
		Preferences: DeviceNotificationPreferences{
			GeneralAlerts: true,
		},
	}, false)
	if err != nil {
		t.Fatalf("failed adding US device: %v", err)
	}

	user, err = upsertDeviceIntoUser(ctx, user, Device{
		ID:       "iphone-1",
		Token:    "tok-uk",
		Platform: "ios",
		Region:   "uk",
		Preferences: DeviceNotificationPreferences{
			GeneralAlerts: true,
		},
	}, false)
	if err != nil {
		t.Fatalf("failed adding UK device: %v", err)
	}

	if len(user.Devices) != 2 {
		t.Fatalf("expected 2 distinct Device+Region connections, got %d", len(user.Devices))
	}
	if user.Devices[0].ID != "shuffler_iphone-1" || user.Devices[1].ID != "uk_iphone-1" {
		t.Fatalf("expected namespaced IDs shuffler_iphone-1 and uk_iphone-1, got %q and %q", user.Devices[0].ID, user.Devices[1].ID)
	}

	// In UK region, only the UK token should be selected
	tokens := GetUserDeviceTokensForTypeAndOrg(user, NotificationTypeGeneral, "org-1")
	if len(tokens) != 1 || tokens[0] != "tok-uk" {
		t.Fatalf("expected only UK token [tok-uk], got %v", tokens)
	}

	// Removing by unique device ID alone (no region param needed) leaves US connection intact
	user, err = handleDeviceRemove(ctx, user, "uk_iphone-1")
	if err != nil {
		t.Fatalf("failed removing UK device: %v", err)
	}
	if len(user.Devices) != 1 || user.Devices[0].ID != "shuffler_iphone-1" {
		t.Fatalf("expected shuffler_iphone-1 to remain, got %+v", user.Devices)
	}
}
