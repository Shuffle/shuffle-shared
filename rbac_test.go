package shuffle

import (
	"context"
	"testing"
)

func TestNormalizeRole(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"reader", "org-reader"},
		{"shuffle-org-reader", "org-reader"},
		{"org_reader", "org-reader"},
		{"shuffle-user", "user"},
		{"user", "user"},
		{"shuffle-admin", "admin"},
		{"admin", "admin"},
		{"custom-role", "custom-role"},
	}

	for _, tt := range tests {
		result := NormalizeRole(tt.input)
		if result != tt.expected {
			t.Errorf("NormalizeRole(%q) = %q; want %q", tt.input, result, tt.expected)
		}
	}
}

func TestHasActiveRBAC(t *testing.T) {
	if HasActiveRBAC(nil) {
		t.Errorf("HasActiveRBAC(nil) should be false")
	}

	emptyRBAC := &RBAC{}
	if HasActiveRBAC(emptyRBAC) {
		t.Errorf("HasActiveRBAC(&RBAC{}) should be false")
	}

	activeWithRole := &RBAC{
		Read: PermissionRule{Roles: []string{"org-reader"}},
	}
	if !HasActiveRBAC(activeWithRole) {
		t.Errorf("HasActiveRBAC with Read.Roles should be true")
	}

	activeWithUser := &RBAC{
		Write: PermissionRule{Users: []string{"usr_123"}},
	}
	if !HasActiveRBAC(activeWithUser) {
		t.Errorf("HasActiveRBAC with Write.Users should be true")
	}

	activePublic := &RBAC{
		Public: true,
	}
	if !HasActiveRBAC(activePublic) {
		t.Errorf("HasActiveRBAC with Public=true should be true")
	}
}

func TestEnsureOwnerRBAC(t *testing.T) {
	u := User{
		Id:       "usr_frikky",
		Username: "frikky",
	}

	// 1. Inactive RBAC should remain unchanged
	emptyRBAC := &RBAC{}
	res := EnsureOwnerRBAC(emptyRBAC, u)
	if HasActiveRBAC(res) {
		t.Errorf("EnsureOwnerRBAC should not activate an inactive RBAC")
	}

	// 2. Active RBAC should ensure user is in Admin, Write, Read
	rbac := &RBAC{
		Read: PermissionRule{Roles: []string{"soc_team"}},
	}
	res = EnsureOwnerRBAC(rbac, u)
	if !ArrayContains(res.Admin.Users, "usr_frikky") {
		t.Errorf("User must be in Admin.Users")
	}
	if !ArrayContains(res.Write.Users, "usr_frikky") {
		t.Errorf("User must be in Write.Users")
	}
	if !ArrayContains(res.Read.Users, "usr_frikky") {
		t.Errorf("User must be in Read.Users")
	}
}

func TestCheckUserAccess(t *testing.T) {
	orgId := "org_tenant_1"
	otherOrgId := "org_tenant_2"

	adminUser := User{
		Id:        "usr_admin",
		Role:      "admin",
		ActiveOrg: OrgMini{Id: orgId, Role: "admin"},
	}

	stdUser := User{
		Id:        "usr_regular",
		Role:      "user",
		ActiveOrg: OrgMini{Id: orgId, Role: "user"},
	}

	readerUser := User{
		Id:        "usr_reader",
		Role:      "org-reader",
		ActiveOrg: OrgMini{Id: orgId, Role: "org-reader"},
	}

	// 1. DO NOTHING: Inactive RBAC allows regular flow
	allowed, _ := CheckUserAccess(stdUser, nil, "read", orgId, nil)
	if !allowed {
		t.Errorf("Expected allow when RBAC is inactive (do nothing)")
	}
	allowed, _ = CheckUserAccess(stdUser, nil, "write", orgId, nil)
	if !allowed {
		t.Errorf("Expected allow when RBAC is inactive (do nothing)")
	}

	// 2. Tenant Mismatch
	allowed, _ = CheckUserAccess(adminUser, &RBAC{Public: true}, "read", otherOrgId, nil)
	if allowed {
		t.Errorf("Expected deny on org mismatch")
	}

	// 3. Admin Override
	restrictedRBAC := &RBAC{
		Read:  PermissionRule{Users: []string{"some_other_user"}},
		Write: PermissionRule{Users: []string{"some_other_user"}},
	}
	allowed, _ = CheckUserAccess(adminUser, restrictedRBAC, "read", orgId, nil)
	if !allowed {
		t.Errorf("Admin must bypass restrictions within tenant")
	}
	allowed, _ = CheckUserAccess(adminUser, restrictedRBAC, "write", orgId, nil)
	if !allowed {
		t.Errorf("Admin must bypass restrictions within tenant on write")
	}

	// 4. org-reader can NEVER write
	openWriteRBAC := &RBAC{
		Write: PermissionRule{Roles: []string{"org-reader", "user"}},
	}
	allowed, _ = CheckUserAccess(readerUser, openWriteRBAC, "write", orgId, nil)
	if allowed {
		t.Errorf("org-reader must never be permitted to write")
	}

	// 5. Explicit user access
	allowed, _ = CheckUserAccess(stdUser, restrictedRBAC, "read", orgId, nil)
	if allowed {
		t.Errorf("stdUser should be denied when not listed in restrictedRBAC")
	}

	userSpecificRBAC := &RBAC{
		Read: PermissionRule{Users: []string{"usr_regular"}},
	}
	allowed, _ = CheckUserAccess(stdUser, userSpecificRBAC, "read", orgId, nil)
	if !allowed {
		t.Errorf("stdUser should be allowed when explicitly in Read.Users")
	}

	// 6. Category Inheritance
	categoryRBAC := &RBAC{
		Read:  PermissionRule{Roles: []string{"org-reader", "user"}},
		Write: PermissionRule{Roles: []string{"user"}},
	}
	keyWithoutRBAC := &RBAC{
		Inherit: true,
	}

	// Reader should read inherited from category
	allowed, _ = CheckUserAccess(readerUser, keyWithoutRBAC, "read", orgId, categoryRBAC)
	if !allowed {
		t.Errorf("Reader should inherit read permission from category")
	}

	// Reader cannot write inherited from category
	allowed, _ = CheckUserAccess(readerUser, keyWithoutRBAC, "write", orgId, categoryRBAC)
	if allowed {
		t.Errorf("Reader should not inherit write permission")
	}

	// stdUser can write inherited from category
	allowed, _ = CheckUserAccess(stdUser, keyWithoutRBAC, "write", orgId, categoryRBAC)
	if !allowed {
		t.Errorf("stdUser should inherit write permission from category")
	}

	// 7. Key override takes precedence
	keyOverrideRBAC := &RBAC{
		Inherit: false,
		Read:    PermissionRule{Users: []string{"usr_special"}},
	}
	allowed, _ = CheckUserAccess(stdUser, keyOverrideRBAC, "read", orgId, categoryRBAC)
	if allowed {
		t.Errorf("Key override without stdUser should deny access despite category allowing it")
	}
}

func TestCheckOAuthTokenAccess(t *testing.T) {
	orgId := "org_tenant_1"
	token := &OAuthToken{
		AccessToken: "shfl_test_token",
		OrgId:       orgId,
		UserId:      "usr_api_service",
		Scope:       "read write",
	}

	// 1. Inactive RBAC -> Allow
	allowed, _ := CheckOAuthTokenAccess(token, nil, "read", orgId, nil)
	if !allowed {
		t.Errorf("Expected allow when RBAC is inactive")
	}

	// 2. Matching Scope
	scopedRBAC := &RBAC{
		Read: PermissionRule{Scopes: []string{"read"}},
	}
	allowed, _ = CheckOAuthTokenAccess(token, scopedRBAC, "read", orgId, nil)
	if !allowed {
		t.Errorf("Expected allow when token has matching read scope")
	}

	// 3. Missing Scope
	adminScopedRBAC := &RBAC{
		Admin: PermissionRule{Scopes: []string{"admin:keys"}},
	}
	allowed, _ = CheckOAuthTokenAccess(token, adminScopedRBAC, "admin", orgId, nil)
	if allowed {
		t.Errorf("Expected deny when token lacks admin:keys scope")
	}
}

func TestValidateAndResolveUser(t *testing.T) {
	ctx := context.Background()
	org := &Org{
		Id:   "org_test_123",
		Name: "Test Org",
		Users: []User{
			{Id: "uid-alice-1234", Username: "alice@example.com"},
			{Id: "uid-bob-5678", Username: "bob"},
		},
	}

	// 1. Resolve by exact UID
	u, err := ValidateAndResolveUser(ctx, "uid-alice-1234", org)
	if err != nil || u == nil || u.Id != "uid-alice-1234" {
		t.Errorf("Failed to resolve user by UID: %v", err)
	}

	// 2. Resolve by email / username (case-insensitive)
	u, err = ValidateAndResolveUser(ctx, "ALICE@example.com", org)
	if err != nil || u == nil || u.Id != "uid-alice-1234" {
		t.Errorf("Failed to resolve user by email: %v", err)
	}

	u, err = ValidateAndResolveUser(ctx, "BoB", org)
	if err != nil || u == nil || u.Id != "uid-bob-5678" {
		t.Errorf("Failed to resolve user by username: %v", err)
	}

	// 3. Unknown user returns error
	_, err = ValidateAndResolveUser(ctx, "eve@unknown.com", org)
	if err == nil {
		t.Errorf("Expected error resolving unknown user, got nil")
	}
}

func TestValidateAndNormalizeRBACOrg(t *testing.T) {
	ctx := context.Background()
	org := &Org{
		Id:   "org_test_123",
		Name: "Test Org",
		Users: []User{
			{Id: "uid-alice-1234", Username: "alice@example.com"},
			{Id: "uid-bob-5678", Username: "bob"},
		},
		Roles: []string{"custom-analyst"},
	}
	inviter := User{Id: "uid-owner-000", Username: "owner@example.com"}

	// 1. Inactive RBAC -> returns unmodified, nil error
	res, err := ValidateAndNormalizeRBACOrg(ctx, nil, org, inviter, "key", "test")
	if err != nil || res != nil {
		t.Errorf("Expected nil, nil for nil RBAC")
	}

	// 2. Valid RBAC with mixed username and UUID, plus custom role
	inputRBAC := &RBAC{
		Read: PermissionRule{
			Users: []string{"alice@example.com", "uid-bob-5678", "BoB"},
			Roles: []string{"org-reader", "custom-analyst"},
		},
		Write: PermissionRule{
			Users: []string{"uid-alice-1234"},
			Roles: []string{"user"},
		},
	}

	norm, err := ValidateAndNormalizeRBACOrg(ctx, inputRBAC, org, inviter, "key", "test")
	if err != nil {
		t.Fatalf("Expected valid normalization, got error: %v", err)
	}

	// Read.Users should be normalized to [uid-alice-1234, uid-bob-5678] (deduplicated)
	if len(norm.Read.Users) != 2 || norm.Read.Users[0] != "uid-alice-1234" || norm.Read.Users[1] != "uid-bob-5678" {
		t.Errorf("Read.Users normalization failed: got %v", norm.Read.Users)
	}

	// 3. Bad user data -> must fail
	badRBAC := &RBAC{
		Read: PermissionRule{
			Users: []string{"malicious_or_unknown@corp.com"},
		},
	}
	_, err = ValidateAndNormalizeRBACOrg(ctx, badRBAC, org, inviter, "key", "test")
	if err == nil {
		t.Errorf("Expected error for non-existent user in RBAC, got nil")
	}

	// 4. Bad role -> must fail
	badRoleRBAC := &RBAC{
		Read: PermissionRule{
			Roles: []string{"super-hacker-role"},
		},
	}
	_, err = ValidateAndNormalizeRBACOrg(ctx, badRoleRBAC, org, inviter, "key", "test")
	if err == nil {
		t.Errorf("Expected error for non-existent role in RBAC, got nil")
	}
}

