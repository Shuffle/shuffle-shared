package shuffle

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"strings"
	"testing"

	"cloud.google.com/go/datastore"
	uuid "github.com/satori/go.uuid"
)

func setupOrgTestEnv(t *testing.T) context.Context {
	t.Helper()
	fixture := newDatastoreAPIFixture(t)
	fixture.entities = nil
	project.Environment = "cloud"
	project.GceProject = "release-tests"
	project.DbType = ""
	project.CacheDb = true
	resetOrgRecoveryLogLimiter()
	return context.Background()
}

func sampleEnterpriseOrg(orgId string) Org {
	return Org{
		Id:          orgId,
		Name:        "Acme Security",
		Org:         "Acme Security",
		Description: "Enterprise SOC Tenant",
		CompanyType: "Enterprise",
		Image:       "https://shuffler.io/logo.png",
		Users: []User{
			{
				Id:       uuid.NewV4().String(),
				Username: "alice@acme.io",
				Role:     "admin",
				Roles:    []string{"admin", "user"},
				Active:   true,
			},
			{
				Id:       uuid.NewV4().String(),
				Username: "bob@acme.io",
				Role:     "user",
				Roles:    []string{"user"},
				Active:   true,
			},
		},
		Roles:           []string{"admin", "user"},
		ActiveApps:      []string{"app-1", "app-2", "app-3"},
		CloudSync:       true,
		CloudSyncActive: true,
		Licensed:        true,
		EulaSigned:      true,
		EulaSignedBy:    "alice@acme.io",
		Region:          "europe-west2",
		RegionUrl:       "https://shuffler.io",
		CreatorId:       "creator-123",
		SyncFeatures: SyncFeatures{
			AppExecutions:         SyncData{Active: true, Limit: 300000, Usage: 12000},
			OnpremAppExecutions:   SyncData{Active: true, Limit: 150000, Usage: 5000},
			AnnualAppRunsGrouping: SyncData{Active: true},
			MultiEnv:              SyncData{Active: true, Limit: 25},
			MultiTenant:           SyncData{Active: true, Limit: 100},
			Webhook:               SyncData{Active: true, Limit: 500},
			Schedules:             SyncData{Active: true, Limit: 200},
			UserInput:             SyncData{Active: true, Limit: 100},
			SendMail:              SyncData{Active: true, Limit: 5000},
			SendSms:               SyncData{Active: true, Limit: 500},
			AgentTokens:           SyncData{Active: true, Limit: 50000000},
			LLMTokens:             SyncData{Active: true, Limit: 25000000},
			Branding:              SyncData{Active: true},
		},
		Subscriptions: []PaymentSubscription{
			{
				Id:         uuid.NewV4().String(),
				Name:       "Enterprise License (Cloud)",
				Active:     true,
				Startdate:  1700000000,
				Enddate:    1731536000,
				Recurrence: "annual",
				Amount:     "1200",
				Currency:   "USD",
				Limit:      300000,
				EulaSigned: true,
			},
		},
		Billing: Billing{
			Email:                    "billing@acme.io",
			AppRunsHardLimit:         3600000,
			InternalAppRunsHardLimit: 500000,
			DefaultAlertsApplied:     true,
			AlertThreshold: []AlertThreshold{
				{Percentage: 50, Count: 150000, Email_send: false},
				{Percentage: 90, Count: 270000, Email_send: false},
			},
		},
		SSOConfig: SSOConfig{
			SSOEntrypoint:      "https://idp.acme.io/sso",
			SSOCertificate:     "MIICERTDATA",
			OpenIdClientId:     "oidc-client-id-real",
			OpenIdClientSecret: "oidc-client-secret-real",
			SSORequired:        true,
		},
		SyncConfig: SyncConfig{
			URL:                   "https://shuffler.io",
			Interval:              60,
			Apikey:                "secret-sync-api-key",
			Source:                "cloud",
			WorkflowBackup:        true,
			WorkflowBackupUpdated: 1700000100,
			AppBackup:             true,
			AppBackupUpdated:      1700000100,
		},
		Defaults: Defaults{
			AppDownloadRepo:        "https://github.com/Shuffle/python-apps",
			AppDownloadBranch:      "master",
			WorkflowDownloadRepo:   "https://github.com/Shuffle/workflows",
			WorkflowDownloadBranch: "main",
			NotificationWorkflow:   uuid.NewV4().String(),
			KmsId:                  "projects/acme/locations/global/keyRings/kr/cryptoKeys/k",
			TokensEncrypted:        true,
		},
		Branding: OrgBranding{
			BrandName:    "Acme SOAR",
			BrandColor:   "#FF5500",
			Theme:        "dark",
			SupportEmail: "soc@acme.io",
		},
		ChildOrgs: []OrgMini{
			{Id: uuid.NewV4().String(), Name: "Child 1"},
			{Id: uuid.NewV4().String(), Name: "Child 2"},
		},
	}
}

func TestSetOrg_NewOrgCreationAndValidation(t *testing.T) {
	ctx := setupOrgTestEnv(t)

	// 1. Valid first-time org creation with uninitialized limits gets baseline defaults
	validId := uuid.NewV4().String()
	newOrg := Org{
		Id:   validId,
		Name: "Fresh Startup Org",
		Users: []User{
			{
				Id:       uuid.NewV4().String(),
				Username: "founder@startup.io",
				Role:     "admin",
			},
		},
	}

	if err := SetOrg(ctx, newOrg, validId); err != nil {
		t.Fatalf("expected valid new org creation to succeed, got error: %v", err)
	}

	got, err := GetOrg(ctx, validId, true)
	if err != nil {
		t.Fatalf("GetOrg from DB failed: %v", err)
	}
	if got.Id != validId || got.Name != "Fresh Startup Org" {
		t.Fatalf("unexpected org identity: id=%q name=%q", got.Id, got.Name)
	}
	if got.SyncFeatures.AppExecutions.Limit != 2000 {
		t.Fatalf("expected baseline AppExecutions.Limit=2000 on new org, got %d", got.SyncFeatures.AppExecutions.Limit)
	}
	if got.SyncFeatures.MultiEnv.Limit != 1 || got.SyncFeatures.MultiTenant.Limit != 3 {
		t.Fatalf("expected baseline MultiEnv=1, MultiTenant=3, got %d and %d",
			got.SyncFeatures.MultiEnv.Limit, got.SyncFeatures.MultiTenant.Limit)
	}

	// 2. Reject invalid IDs (not 36-char UUID, or padded with whitespace/quotes since no stripping is allowed)
	badIDs := []string{
		"",
		"short-id",
		"12345678-1234-1234-1234-123456789ab",   // 35 chars
		"12345678-1234-1234-1234-123456789abcd", // 37 chars
		" " + validId,                           // leading space (37 chars)
		"\"" + validId[:34] + "\"",              // 36 chars with quotes, invalid UUID
		"zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz",  // 36 chars, invalid hex UUID
	}
	for _, badID := range badIDs {
		candidate := newOrg
		candidate.Id = badID
		if err := SetOrg(ctx, candidate, badID); err == nil {
			t.Errorf("expected SetOrg to reject invalid ID %q, but it succeeded", badID)
		}
	}

	// 3. Reject ID mismatch between payload data.Id and target id parameter
	otherId := uuid.NewV4().String()
	mismatchOrg := newOrg
	mismatchOrg.Id = validId
	if err := SetOrg(ctx, mismatchOrg, otherId); err == nil {
		t.Fatalf("expected SetOrg to hard-fail when data.Id (%s) != target id (%s)", validId, otherId)
	}

	// 4. Reject new org with empty or "tmp" name
	for _, badName := range []string{"", "   ", "tmp"} {
		badNameId := uuid.NewV4().String()
		badNameOrg := newOrg
		badNameOrg.Id = badNameId
		badNameOrg.Name = badNameName(badName)
		badNameOrg.Org = ""
		if err := SetOrg(ctx, badNameOrg, badNameId); err == nil {
			t.Errorf("expected SetOrg to reject new org with invalid name %q", badName)
		}
	}

	// 5. Reject new org with 0 valid users
	noUserId := uuid.NewV4().String()
	noUserOrg := Org{
		Id:    noUserId,
		Name:  "No User Org",
		Users: []User{{Id: "", Username: ""}},
	}
	if err := SetOrg(ctx, noUserOrg, noUserId); err == nil {
		t.Fatalf("expected SetOrg to reject new org with 0 valid users")
	}
}

func badNameName(s string) string { return s }

func TestSetOrg_EditMultipleLimitsAtOnce(t *testing.T) {
	ctx := setupOrgTestEnv(t)
	orgId := uuid.NewV4().String()
	org := sampleEnterpriseOrg(orgId)

	if err := SetOrg(ctx, org, orgId); err != nil {
		t.Fatalf("initial SetOrg failed: %v", err)
	}

	// Edit 7 limits at once (increasing some, decreasing others) just like HandleEditOrg
	loaded, err := GetOrg(ctx, orgId)
	if err != nil {
		t.Fatalf("GetOrg failed: %v", err)
	}

	loaded.SyncFeatures.Editing = true
	loaded.SyncFeatures.AppExecutions.Limit = 750000       // 1. changed 300k -> 750k
	loaded.SyncFeatures.OnpremAppExecutions.Limit = 500000 // 2. changed 150k -> 500k
	loaded.SyncFeatures.MultiEnv.Limit = 10                // 3. lowered 25 -> 10
	loaded.SyncFeatures.MultiTenant.Limit = 250            // 4. changed 100 -> 250
	loaded.SyncFeatures.Webhook.Limit = 1200               // 5. changed 500 -> 1200
	loaded.SyncFeatures.Schedules.Limit = 800              // 6. changed 200 -> 800
	loaded.SyncFeatures.AgentTokens.Limit = 100000000      // 7. changed 50M -> 100M
	loaded.Name = "Acme Security Global"

	if err := SetOrg(ctx, *loaded, orgId); err != nil {
		t.Fatalf("SetOrg with 7 limit changes failed: %v", err)
	}

	// Verify both from cache and bypassing cache (direct from DB)
	for _, bypass := range []bool{false, true} {
		updated, err := GetOrg(ctx, orgId, bypass)
		if err != nil {
			t.Fatalf("GetOrg(bypass=%v) failed: %v", bypass, err)
		}
		if updated.Name != "Acme Security Global" {
			t.Errorf("bypass=%v: expected Name='Acme Security Global', got %q", bypass, updated.Name)
		}
		if updated.SyncFeatures.Editing {
			t.Errorf("bypass=%v: expected SyncFeatures.Editing to be reset to false", bypass)
		}
		if updated.SyncFeatures.AppExecutions.Limit != 750000 {
			t.Errorf("bypass=%v: expected AppExecutions.Limit=750000, got %d", bypass, updated.SyncFeatures.AppExecutions.Limit)
		}
		if updated.SyncFeatures.OnpremAppExecutions.Limit != 500000 {
			t.Errorf("bypass=%v: expected OnpremAppExecutions.Limit=500000, got %d", bypass, updated.SyncFeatures.OnpremAppExecutions.Limit)
		}
		if updated.SyncFeatures.MultiEnv.Limit != 10 {
			t.Errorf("bypass=%v: expected MultiEnv.Limit=10, got %d", bypass, updated.SyncFeatures.MultiEnv.Limit)
		}
		if updated.SyncFeatures.MultiTenant.Limit != 250 {
			t.Errorf("bypass=%v: expected MultiTenant.Limit=250, got %d", bypass, updated.SyncFeatures.MultiTenant.Limit)
		}
		if updated.SyncFeatures.Webhook.Limit != 1200 {
			t.Errorf("bypass=%v: expected Webhook.Limit=1200, got %d", bypass, updated.SyncFeatures.Webhook.Limit)
		}
		if updated.SyncFeatures.Schedules.Limit != 800 {
			t.Errorf("bypass=%v: expected Schedules.Limit=800, got %d", bypass, updated.SyncFeatures.Schedules.Limit)
		}
		if updated.SyncFeatures.AgentTokens.Limit != 100000000 {
			t.Errorf("bypass=%v: expected AgentTokens.Limit=100000000, got %d", bypass, updated.SyncFeatures.AgentTokens.Limit)
		}
	}
}

func TestSetOrg_RecoversOmittedFieldsAndSubStructs(t *testing.T) {
	ctx := setupOrgTestEnv(t)
	orgId := uuid.NewV4().String()
	org := sampleEnterpriseOrg(orgId)

	if err := SetOrg(ctx, org, orgId); err != nil {
		t.Fatalf("initial SetOrg failed: %v", err)
	}

	// Case 1: Accidental wipe of SyncFeatures limits (e.g. caller passed empty SyncFeatures{})
	partial := org
	partial.Description = "Updated Description"
	partial.SyncFeatures = SyncFeatures{} // Wiped limits (1 section lost -> auto-recovers)
	if err := SetOrg(ctx, partial, orgId); err != nil {
		t.Fatalf("expected single-section loss to auto-recover, got error: %v", err)
	}

	got, err := GetOrg(ctx, orgId, true)
	if err != nil {
		t.Fatalf("GetOrg failed: %v", err)
	}
	if got.Description != "Updated Description" {
		t.Errorf("expected Description update to persist, got %q", got.Description)
	}
	if got.SyncFeatures.AppExecutions.Limit != 300000 || got.SyncFeatures.OnpremAppExecutions.Limit != 150000 {
		t.Errorf("expected SyncFeatures limits (300000 / 150000) to be recovered, got %d / %d",
			got.SyncFeatures.AppExecutions.Limit, got.SyncFeatures.OnpremAppExecutions.Limit)
	}
	if got.SyncFeatures.MultiEnv.Limit != 25 || got.SyncFeatures.MultiTenant.Limit != 100 {
		t.Errorf("expected MultiEnv/MultiTenant limits (25/100) to be recovered, got %d/%d",
			got.SyncFeatures.MultiEnv.Limit, got.SyncFeatures.MultiTenant.Limit)
	}
	if !got.SyncFeatures.AnnualAppRunsGrouping.Active || !got.SyncFeatures.Branding.Active {
		t.Errorf("expected AnnualAppRunsGrouping and Branding active flags to be recovered")
	}

	// Case 2: Sanitized "CLEANED" SSO secrets & partial Defaults update
	partial2 := *got
	partial2.SSOConfig.OpenIdClientId = "CLEANED"
	partial2.SSOConfig.OpenIdClientSecret = "CLEANED"
	partial2.Defaults = Defaults{
		NotificationWorkflow: "11111111-2222-3333-4444-555555555555", // Only 1 field set in Defaults
	}
	partial2.SyncConfig.Apikey = "" // Stripped by HandleGetOrg
	partial2.SyncConfig.Source = ""

	if err := SetOrg(ctx, partial2, orgId); err != nil {
		t.Fatalf("SetOrg with sanitized SSO and partial Defaults failed: %v", err)
	}

	got2, err := GetOrg(ctx, orgId, true)
	if err != nil {
		t.Fatalf("GetOrg failed: %v", err)
	}
	if got2.SSOConfig.OpenIdClientId != "oidc-client-id-real" || got2.SSOConfig.OpenIdClientSecret != "oidc-client-secret-real" {
		t.Errorf("expected CLEANED SSO credentials to be recovered, got id=%q secret=%q",
			got2.SSOConfig.OpenIdClientId, got2.SSOConfig.OpenIdClientSecret)
	}
	if got2.Defaults.NotificationWorkflow != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("expected updated NotificationWorkflow to persist, got %q", got2.Defaults.NotificationWorkflow)
	}
	if got2.Defaults.AppDownloadRepo != org.Defaults.AppDownloadRepo || got2.Defaults.KmsId != org.Defaults.KmsId {
		t.Errorf("expected sibling Defaults fields (AppDownloadRepo, KmsId) to be recovered, got repo=%q kms=%q",
			got2.Defaults.AppDownloadRepo, got2.Defaults.KmsId)
	}
	if got2.SyncConfig.Apikey != "secret-sync-api-key" || got2.SyncConfig.Source != "cloud" {
		t.Errorf("expected stripped SyncConfig.Apikey and Source to be recovered, got apikey=%q source=%q",
			got2.SyncConfig.Apikey, got2.SyncConfig.Source)
	}
}

func TestSetOrg_HardFailsOnSevereDataLoss(t *testing.T) {
	ctx := setupOrgTestEnv(t)
	orgId := uuid.NewV4().String()
	org := sampleEnterpriseOrg(orgId)

	if err := SetOrg(ctx, org, orgId); err != nil {
		t.Fatalf("initial SetOrg failed: %v", err)
	}

	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOut)

	// 1. Hollowed-out struct losing 3+ sections simultaneously -> MUST HARD FAIL
	hollow := Org{
		Id:   orgId,
		Name: "tmp", // Lost Name, Users, SyncFeatures, Subscriptions, Billing, SSOConfig, Defaults...
	}
	if err := SetOrg(ctx, hollow, orgId); err == nil {
		t.Fatalf("expected SetOrg to HARD FAIL on hollowed-out org, but it succeeded")
	}
	if count := strings.Count(logBuf.String(), "[ORG_CORRUPTION_BLOCKED]"); count != 1 {
		t.Errorf("expected exactly 1 [ORG_CORRUPTION_BLOCKED] monitor log, got %d:\n%s", count, logBuf.String())
	}

	// 2. Dropping Users + SyncFeatures/Limits simultaneously -> MUST HARD FAIL
	logBuf.Reset()
	dropUsersAndLimits := org
	dropUsersAndLimits.Users = nil
	dropUsersAndLimits.SyncFeatures = SyncFeatures{}
	if err := SetOrg(ctx, dropUsersAndLimits, orgId); err == nil {
		t.Fatalf("expected SetOrg to HARD FAIL when both Users and Limits are dropped")
	}
	if !strings.Contains(logBuf.String(), "[ORG_CORRUPTION_BLOCKED]") {
		t.Errorf("expected [ORG_CORRUPTION_BLOCKED] log when Users + Limits dropped")
	}

	// 3. Dropping Limits + Subscriptions/License simultaneously -> MUST HARD FAIL
	logBuf.Reset()
	dropLimitsAndSubs := org
	dropLimitsAndSubs.SyncFeatures = SyncFeatures{}
	dropLimitsAndSubs.Subscriptions = nil
	dropLimitsAndSubs.Licensed = false
	if err := SetOrg(ctx, dropLimitsAndSubs, orgId); err == nil {
		t.Fatalf("expected SetOrg to HARD FAIL when both Limits and Subscriptions are dropped")
	}

	// 4. Verify the database still holds the untouched, uncorrupted enterprise org!
	intact, err := GetOrg(ctx, orgId, true)
	if err != nil {
		t.Fatalf("GetOrg from DB failed: %v", err)
	}
	if intact.Name != "Acme Security" || len(intact.Users) != 2 || intact.SyncFeatures.AppExecutions.Limit != 300000 || len(intact.Subscriptions) != 1 {
		t.Fatalf("database was mutated despite hard-fail! got name=%q users=%d limit=%d subs=%d",
			intact.Name, len(intact.Users), intact.SyncFeatures.AppExecutions.Limit, len(intact.Subscriptions))
	}
}

func TestGetOrg_RecoversFromCorruptedCacheAndValidatesDedicatedCache(t *testing.T) {
	ctx := setupOrgTestEnv(t)
	orgId := uuid.NewV4().String()
	org := sampleEnterpriseOrg(orgId)

	if err := SetOrg(ctx, org, orgId); err != nil {
		t.Fatalf("initial SetOrg failed: %v", err)
	}

	// 1. Validate that setDedicatedOrgSyncFeatures refuses empty SyncFeatures
	if err := setDedicatedOrgSyncFeatures(ctx, orgId, SyncFeatures{}); err == nil {
		t.Fatalf("expected setDedicatedOrgSyncFeatures to reject empty SyncFeatures{}")
	}

	// 2. Poison org_sync_features_<id> directly in cache with empty JSON "{}" and verify getDedicatedOrgSyncFeatures rejects it
	_ = SetCache(ctx, "org_sync_features_"+orgId, []byte(`{}`), 60)
	if _, err := getDedicatedOrgSyncFeatures(ctx, orgId); err == nil {
		t.Fatalf("expected getDedicatedOrgSyncFeatures to reject empty '{}' SyncFeatures from cache")
	}

	// Restore valid dedicated cache
	if err := setDedicatedOrgSyncFeatures(ctx, orgId, org.SyncFeatures); err != nil {
		t.Fatalf("setDedicatedOrgSyncFeatures failed: %v", err)
	}

	// 3. Poison general Organizations_<id> cache with wiped limits (Limit = 0)
	corruptedCacheOrg := org
	corruptedCacheOrg.SyncFeatures = SyncFeatures{}
	corruptedBytes, _ := json.Marshal(corruptedCacheOrg)
	_ = SetCache(ctx, "Organizations_"+orgId, corruptedBytes, 60)

	// GetOrg (with cache enabled) must restore the 300,000 limit from dedicated cache via FixOrg
	// AND re-save the healed org to Organizations_<id> cache so subsequent GetOrg calls do not re-trigger recovery logs
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOut)

	recovered, err := GetOrg(ctx, orgId)
	if err != nil {
		t.Fatalf("GetOrg failed: %v", err)
	}
	if recovered.SyncFeatures.AppExecutions.Limit != 300000 || recovered.SyncFeatures.OnpremAppExecutions.Limit != 150000 {
		t.Fatalf("expected GetOrg to restore limits (300000/150000) from dedicated cache, got %d/%d",
			recovered.SyncFeatures.AppExecutions.Limit, recovered.SyncFeatures.OnpremAppExecutions.Limit)
	}
	if count := strings.Count(logBuf.String(), "[ORG_CORRUPTION_RECOVERED]"); count != 1 {
		t.Errorf("expected 1 [ORG_CORRUPTION_RECOVERED] log on first healing read, got %d", count)
	}
	if !strings.Contains(logBuf.String(), `why="dedicated_cache_had_higher_limits"`) || !strings.Contains(logBuf.String(), "restored_fields=") {
		t.Errorf("expected log to specify explicit why and restored_fields, got:\n%s", logBuf.String())
	}

	// Second GetOrg read must hit the now-healed Organizations_<id> cache with 0 recovery logs!
	logBuf.Reset()
	recoveredSecond, err := GetOrg(ctx, orgId)
	if err != nil {
		t.Fatalf("second GetOrg failed: %v", err)
	}
	if recoveredSecond.SyncFeatures.AppExecutions.Limit != 300000 {
		t.Fatalf("expected second GetOrg to have 300000 limit, got %d", recoveredSecond.SyncFeatures.AppExecutions.Limit)
	}
	if count := strings.Count(logBuf.String(), "[ORG_CORRUPTION_RECOVERED]"); count != 0 {
		t.Errorf("expected 0 [ORG_CORRUPTION_RECOVERED] logs after cache was healed, got %d:\n%s", count, logBuf.String())
	}

	// 4. Verify per-org rate limiting: even if cache were poisoned again within the 15-min cooldown, it won't spam logs
	_ = SetCache(ctx, "Organizations_"+orgId, corruptedBytes, 60)
	logBuf.Reset()
	recoveredThird, err := GetOrg(ctx, orgId)
	if err != nil {
		t.Fatalf("third GetOrg failed: %v", err)
	}
	if recoveredThird.SyncFeatures.AppExecutions.Limit != 300000 {
		t.Fatalf("expected third GetOrg to still heal limit to 300000, got %d", recoveredThird.SyncFeatures.AppExecutions.Limit)
	}
	if count := strings.Count(logBuf.String(), "[ORG_CORRUPTION_RECOVERED]"); count != 0 {
		t.Errorf("expected per-org cooldown to suppress duplicate [ORG_CORRUPTION_RECOVERED] log within cooldown window, got %d", count)
	}

	// 5. Verify legacy sub-orgs cached with 0 limits (and no dedicated cache) silently heal to default 2000 limit without log spam
	subOrgId := uuid.NewV4().String()
	subOrg := Org{
		Id:   subOrgId,
		Name: "hello-soar",
		Users: []User{
			{Id: uuid.NewV4().String(), Username: "sub@acme.io", Role: "admin"},
		},
	}
	subOrgBytes, _ := json.Marshal(subOrg)
	_ = SetCache(ctx, "Organizations_"+subOrgId, subOrgBytes, 60)
	logBuf.Reset()
	healedSubOrg, err := GetOrg(ctx, subOrgId)
	if err != nil {
		t.Fatalf("GetOrg for cached sub-org failed: %v", err)
	}
	if healedSubOrg.SyncFeatures.AppExecutions.Limit != 2000 {
		t.Fatalf("expected cached sub-org with 0 limits to silently heal to 2000, got %d", healedSubOrg.SyncFeatures.AppExecutions.Limit)
	}
	if count := strings.Count(logBuf.String(), "[ORG_CORRUPTION_RECOVERED]"); count != 0 {
		t.Errorf("expected 0 warning logs when healing uninitialized sub-org default limits, got %d:\n%s", count, logBuf.String())
	}

	// 6. Explicit cache bypass (GetOrg(ctx, orgId, true)) loads directly from DB even if cache has corrupted data
	_ = DeleteCache(ctx, "org_sync_features_"+orgId)
	corruptedNoUsers := org
	corruptedNoUsers.Users = nil
	corruptedNoUsers.SyncFeatures = SyncFeatures{}
	noUsersBytes, _ := json.Marshal(corruptedNoUsers)
	_ = SetCache(ctx, "Organizations_"+orgId, noUsersBytes, 60)

	// Make sure DB entity itself is in Datastore
	if _, err := project.Dbclient.Put(ctx, datastore.NameKey("Organizations", orgId, nil), &org); err != nil {
		t.Fatalf("Datastore put failed: %v", err)
	}

	fromDB, err := GetOrg(ctx, orgId, true)
	if err != nil {
		t.Fatalf("GetOrg explicit bypass failed: %v", err)
	}
	if len(fromDB.Users) != 2 || fromDB.SyncFeatures.AppExecutions.Limit != 300000 {
		t.Fatalf("expected GetOrg(bypassCache=true) to load 2 users & 300000 limit from DB, got users=%d limit=%d",
			len(fromDB.Users), fromDB.SyncFeatures.AppExecutions.Limit)
	}
}
