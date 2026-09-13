package shuffle

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// NormalizeRole standardizes role variants across Shuffle and SSO providers.
func NormalizeRole(role string) string {
	r := strings.ToLower(strings.TrimSpace(role))
	switch r {
	case "reader", "shuffle-org-reader", "org_reader":
		return "org-reader"
	case "shuffle-user":
		return "user"
	case "shuffle-admin":
		return "admin"
	default:
		return r
	}
}

// HasActiveRBAC returns true only if at least one rule (roles, users, groups, scopes, or public flag) is active.
// If this returns false, the RBAC system does NOTHING and defers completely to legacy behavior.
func HasActiveRBAC(rbac *RBAC) bool {
	if rbac == nil {
		return false
	}

	return len(rbac.Read.Roles) > 0 || len(rbac.Read.Users) > 0 || len(rbac.Read.Groups) > 0 || len(rbac.Read.Scopes) > 0 ||
		len(rbac.Write.Roles) > 0 || len(rbac.Write.Users) > 0 || len(rbac.Write.Groups) > 0 || len(rbac.Write.Scopes) > 0 ||
		len(rbac.Execute.Roles) > 0 || len(rbac.Execute.Users) > 0 || len(rbac.Execute.Groups) > 0 || len(rbac.Execute.Scopes) > 0 ||
		len(rbac.Admin.Roles) > 0 || len(rbac.Admin.Users) > 0 || len(rbac.Admin.Groups) > 0 || len(rbac.Admin.Scopes) > 0 ||
		rbac.Public
}

// GetRuleForAction extracts the specific PermissionRule for a given action string.
func GetRuleForAction(rbac *RBAC, action string) PermissionRule {
	if rbac == nil {
		return PermissionRule{}
	}
	switch strings.ToLower(action) {
	case "read":
		return rbac.Read
	case "write":
		return rbac.Write
	case "execute":
		return rbac.Execute
	case "admin":
		return rbac.Admin
	default:
		return PermissionRule{}
	}
}

// IsRuleEmpty checks if a PermissionRule has any assigned principals.
func IsRuleEmpty(rule PermissionRule) bool {
	return len(rule.Roles) == 0 && len(rule.Users) == 0 && len(rule.Groups) == 0 && len(rule.Scopes) == 0
}

// CheckUserAccess verifies if a standard User satisfies RBAC rules.
// If NO active RBAC rules are assigned to either the object or its parent, this returns (true, "")
// so existing system behavior remains completely untouched.
func CheckUserAccess(user User, rbac *RBAC, action string, targetOrgId string, parent *RBAC) (bool, string) {
	// 1. If NO RBAC rules are configured on this object or its parent, DO NOTHING.
	if !HasActiveRBAC(rbac) && !HasActiveRBAC(parent) {
		return true, ""
	}

	// 2. Organization Boundary Check
	if len(user.ActiveOrg.Id) > 0 && len(targetOrgId) > 0 && user.ActiveOrg.Id != targetOrgId {
		return false, "Organization mismatch"
	}

	userRole := NormalizeRole(user.Role)
	if len(userRole) == 0 && len(user.ActiveOrg.Role) > 0 {
		userRole = NormalizeRole(user.ActiveOrg.Role)
	}

	// 3. Admin Override: Org admins / support access always have access across tenant resources
	if userRole == "admin" || user.SupportAccess {
		return true, ""
	}

	// 4. Hard safety check for org-reader: readers can NEVER write, execute, or administrate
	actionLower := strings.ToLower(action)
	if userRole == "org-reader" && (actionLower == "write" || actionLower == "execute" || actionLower == "admin") {
		return false, "Users with org-reader role cannot perform write, execute, or admin actions"
	}

	// 5. Public read check
	if actionLower == "read" && rbac != nil && rbac.Public {
		return true, ""
	}

	// 6. Inheritance: Fallback to parent if object has no specific rules for this action
	rule := GetRuleForAction(rbac, actionLower)
	if (rbac == nil || rbac.Inherit || IsRuleEmpty(rule)) && parent != nil && HasActiveRBAC(parent) {
		return CheckUserAccess(user, parent, action, targetOrgId, nil)
	}

	// 7. If this specific action has no explicit rules on an active RBAC object:
	// Default allow read for org members, allow write/execute for non-readers, and require admin for admin.
	if IsRuleEmpty(rule) {
		switch actionLower {
		case "read":
			return true, ""
		case "write", "execute":
			if userRole == "org-reader" {
				return false, "Users with org-reader role cannot perform write or execute actions"
			}
			return true, ""
		case "admin":
			return false, "Admin permissions required"
		default:
			return false, fmt.Sprintf("Unknown action: %s", action)
		}
	}

	// 8. Direct User match (ID or Username)
	if len(rule.Users) > 0 {
		if (len(user.Id) > 0 && ArrayContains(rule.Users, user.Id)) ||
			(len(user.Username) > 0 && ArrayContains(rule.Users, user.Username)) {
			return true, ""
		}
	}

	// 9. Role match with default role understanding
	var checkRoles []string
	if len(userRole) > 0 {
		checkRoles = append(checkRoles, userRole)
	}
	for _, r := range user.Roles {
		checkRoles = append(checkRoles, NormalizeRole(r))
	}

	for _, assignedRole := range rule.Roles {
		normalizedAssigned := NormalizeRole(assignedRole)

		// Exact role match
		if ArrayContains(checkRoles, normalizedAssigned) {
			return true, ""
		}

		// Role hierarchy: a "user" satisfies "org-reader" for read operations
		if actionLower == "read" && normalizedAssigned == "org-reader" && ArrayContains(checkRoles, "user") {
			return true, ""
		}
	}

	return false, fmt.Sprintf("User lacks required role or user permissions for action '%s'", action)
}

// CheckOAuthTokenAccess verifies an OAuth 2.0 Bearer token (shfl_...) against resource RBAC.
func CheckOAuthTokenAccess(token *OAuthToken, rbac *RBAC, action string, targetOrgId string, parent *RBAC) (bool, string) {
	if token == nil || len(token.AccessToken) == 0 {
		return false, "Missing or invalid OAuth token"
	}

	// If neither this object nor parent has RBAC active, DO NOTHING
	if !HasActiveRBAC(rbac) && !HasActiveRBAC(parent) {
		return true, ""
	}

	// 1. Organization boundary check
	if len(token.OrgId) > 0 && len(targetOrgId) > 0 && token.OrgId != targetOrgId {
		return false, "OAuth token organization mismatch"
	}

	// 2. Token-level admin scope override
	if HasOAuthScope(token.Scope, "admin", "*") {
		return true, ""
	}

	// 3. Public access (read only)
	actionLower := strings.ToLower(action)
	if actionLower == "read" && rbac != nil && rbac.Public {
		return true, ""
	}

	// 4. Inheritance fallback
	rule := GetRuleForAction(rbac, actionLower)
	if (rbac == nil || rbac.Inherit || IsRuleEmpty(rule)) && parent != nil && HasActiveRBAC(parent) {
		return CheckOAuthTokenAccess(token, parent, action, targetOrgId, nil)
	}

	// 5. Default scope evaluation if rule is empty
	if IsRuleEmpty(rule) {
		switch actionLower {
		case "read":
			if HasOAuthScope(token.Scope, "read", "write", "edit", "*") {
				return true, ""
			}
			return false, "OAuth token missing read scope"
		case "write", "execute":
			if HasOAuthScope(token.Scope, "write", "edit", "run", "*") {
				return true, ""
			}
			return false, "OAuth token missing write/execute scope"
		case "admin":
			return false, "OAuth token missing admin scope"
		}
	}

	// 6. Direct User match (token creator/bound user)
	if len(rule.Users) > 0 && len(token.UserId) > 0 {
		if ArrayContains(rule.Users, token.UserId) {
			return true, ""
		}
	}

	// 7. Explicit Scope match
	if len(rule.Scopes) > 0 {
		for _, requiredScope := range rule.Scopes {
			if HasOAuthScope(token.Scope, requiredScope, "*") {
				return true, ""
			}
		}
	}

	return false, fmt.Sprintf("OAuth token lacks required scopes for action '%s'", action)
}

// EnsureOwnerRBAC guarantees that the modifying user is ALWAYS added to Admin, Write, and Read
// so they can never accidentally remove themselves and lose access to the object.
func EnsureOwnerRBAC(rbac *RBAC, user User) *RBAC {
	if rbac == nil {
		return nil
	}
	if !HasActiveRBAC(rbac) {
		return rbac
	}

	userId := user.Id
	if len(userId) == 0 {
		userId = user.Username
	}
	if len(userId) == 0 {
		return rbac
	}

	// Ensure user is in Admin
	if !ArrayContains(rbac.Admin.Users, userId) {
		rbac.Admin.Users = append(rbac.Admin.Users, userId)
	}

	// Ensure user is in Write
	if !ArrayContains(rbac.Write.Users, userId) {
		rbac.Write.Users = append(rbac.Write.Users, userId)
	}

	// Ensure user is in Read
	if !ArrayContains(rbac.Read.Users, userId) {
		rbac.Read.Users = append(rbac.Read.Users, userId)
	}

	return rbac
}

// ValidateAndResolveUser verifies that a user identifier (UUID, username, or email)
// corresponds to a valid user in the given organization.
// If found, it returns the matched User struct with their canonical Id.
func ValidateAndResolveUser(ctx context.Context, identifier string, org *Org) (*User, error) {
	if org == nil {
		return nil, errors.New("organization cannot be nil")
	}

	trimmed := strings.TrimSpace(identifier)
	if len(trimmed) == 0 {
		return nil, errors.New("user identifier cannot be empty")
	}

	for _, u := range org.Users {
		// 1. Direct UUID match
		if u.Id == trimmed {
			return &u, nil
		}

		// 2. Username or Email match (case-insensitive)
		if strings.EqualFold(u.Username, trimmed) {
			return &u, nil
		}
	}

	return nil, fmt.Errorf("user '%s' not found in organization '%s'", trimmed, org.Name)
}

// InviteOrShareUser is the standard entrypoint used when sharing an object with or inviting a user.
// Currently, it validates and resolves the user against the organization.
// In the future, this function will also trigger notification emails, in-app alerts, or pending invites.
func InviteOrShareUser(ctx context.Context, identifier string, org *Org, resourceType string, resourceName string, inviter User) (*User, error) {
	user, err := ValidateAndResolveUser(ctx, identifier, org)
	if err != nil {
		return nil, err
	}

	// NOTE: Future invitation extensions (e.g. email notifications, audit logs, or platform invites)
	// should be dispatched here.

	return user, nil
}

// ValidateAndNormalizeRBACOrg validates all user identifiers and roles within an RBAC configuration against an Org,
// resolving usernames/emails to canonical UUIDs, deduplicating entries, and ensuring invalid users
// cause the validation to fail immediately.
func ValidateAndNormalizeRBACOrg(ctx context.Context, rbac *RBAC, org *Org, inviter User, resourceType string, resourceName string) (*RBAC, error) {
	if rbac == nil || !HasActiveRBAC(rbac) {
		return rbac, nil
	}

	if org == nil {
		return nil, errors.New("organization cannot be nil for access validation")
	}

	normalizeRule := func(rule PermissionRule) (PermissionRule, error) {
		newRule := PermissionRule{
			Groups: rule.Groups,
			Scopes: rule.Scopes,
		}

		// Normalize and resolve users to canonical UIDs
		resolvedUserIds := []string{}
		for _, u := range rule.Users {
			trimmed := strings.TrimSpace(u)
			if len(trimmed) == 0 {
				continue
			}

			resolvedUser, err := InviteOrShareUser(ctx, trimmed, org, resourceType, resourceName, inviter)
			if err != nil {
				return PermissionRule{}, err
			}

			if !ArrayContains(resolvedUserIds, resolvedUser.Id) {
				resolvedUserIds = append(resolvedUserIds, resolvedUser.Id)
			}
		}
		newRule.Users = resolvedUserIds

		// Validate roles
		normalizedRoles := []string{}
		for _, r := range rule.Roles {
			trimmed := strings.TrimSpace(r)
			if len(trimmed) == 0 {
				continue
			}

			normRole := NormalizeRole(trimmed)
			// Standard Shuffle roles
			isStandard := normRole == "admin" || normRole == "user" || normRole == "org-reader"
			isOrgRole := ArrayContains(org.Roles, trimmed) || ArrayContains(org.Roles, normRole)

			if !isStandard && !isOrgRole {
				return PermissionRule{}, fmt.Errorf("role '%s' is not valid in organization '%s'", trimmed, org.Name)
			}

			if !ArrayContains(normalizedRoles, normRole) {
				normalizedRoles = append(normalizedRoles, normRole)
			}
		}
		newRule.Roles = normalizedRoles

		return newRule, nil
	}

	normRead, err := normalizeRule(rbac.Read)
	if err != nil {
		return nil, err
	}

	normWrite, err := normalizeRule(rbac.Write)
	if err != nil {
		return nil, err
	}

	normExecute, err := normalizeRule(rbac.Execute)
	if err != nil {
		return nil, err
	}

	normAdmin, err := normalizeRule(rbac.Admin)
	if err != nil {
		return nil, err
	}

	normalizedRBAC := &RBAC{
		Inherit: rbac.Inherit,
		Public:  rbac.Public,
		Read:    normRead,
		Write:   normWrite,
		Execute: normExecute,
		Admin:   normAdmin,
	}

	return normalizedRBAC, nil
}

// ValidateAndNormalizeRBAC loads the organization and delegates to ValidateAndNormalizeRBACOrg.
func ValidateAndNormalizeRBAC(ctx context.Context, rbac *RBAC, orgId string, inviter User, resourceType string, resourceName string) (*RBAC, error) {
	if rbac == nil || !HasActiveRBAC(rbac) {
		return rbac, nil
	}

	org, err := GetOrg(ctx, orgId)
	if err != nil || org == nil {
		return nil, fmt.Errorf("failed to retrieve organization '%s' for access validation: %v", orgId, err)
	}

	return ValidateAndNormalizeRBACOrg(ctx, rbac, org, inviter, resourceType, resourceName)
}
