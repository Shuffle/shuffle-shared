package shuffle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const MaxDepth = 10

func EvalPolicyJSON(policy, oldJSON, newJSON string) (string, bool, string) {
	var oldDoc, newDoc map[string]any

	if err := json.Unmarshal([]byte(oldJSON), &oldDoc); err != nil {
		return oldJSON, false, "invalid old JSON"
	}
	if err := json.Unmarshal([]byte(newJSON), &newDoc); err != nil {
		return oldJSON, false, "invalid new JSON"
	}

	rules := parsePolicy(policy)
	merged, ok, reason := evalPolicyRules(rules, oldDoc, newDoc)

	if !ok {
		oldBytes, _ := marshalOrdered(oldDoc)
		return string(oldBytes), false, reason
	}

	resultBytes, _ := marshalOrdered(merged)
	return string(resultBytes), true, ""
}

// findDeletedField returns the path of the first missing field found, or "" if none.
func findDeletedField(oldVal, newVal any, currentPath string) string {
	switch o := oldVal.(type) {

	case map[string]any:
		// Expect new value to also be a map
		n, ok := newVal.(map[string]any)
		if !ok {
			// Type mismatch implies the whole object at 'currentPath' was replaced/deleted
			return currentPath
		}

		for k, vOld := range o {
			vNew, exists := n[k]

			// Format the next path segment
			nextPath := k
			if currentPath != "" {
				nextPath = currentPath + "." + k
			}

			if !exists {
				return nextPath // Found it!
			}

			// Recurse
			if path := findDeletedField(vOld, vNew, nextPath); path != "" {
				return path
			}
		}

	case []any:
		n, ok := newVal.([]any)
		if !ok {
			return currentPath
		}

		// If the new array is shorter, we lost items
		if len(n) < len(o) {
			if currentPath == "" {
				return "[]" // Root array truncated
			}
			return fmt.Sprintf("%s[%d]", currentPath, len(n)) // Point to the first missing index
		}

		// Check matching items recursively
		for i := range o {
			nextPath := fmt.Sprintf("[%d]", i)
			if currentPath != "" {
				nextPath = fmt.Sprintf("%s[%d]", currentPath, i)
			}

			if path := findDeletedField(o[i], n[i], nextPath); path != "" {
				return path
			}
		}
	}

	return ""
}

// ----------------------
// Core Logic
// ----------------------
func evalPolicyRules(rules []Rule, oldDoc, newDoc map[string]any) (map[string]any, bool, string) {
	// ... (Phase 1: Determine Candidate logic remains the same) ...
	
	// [COPY_PASTE_YOUR_PHASE_1_CODE_HERE_OR_LEAVE_IT_AS_IS]
	// Recapping Phase 1 briefly for context:
	candidate := deepCopyMap(newDoc)
	ruleMatched := false

	for _, r := range rules {
		if r.Action == ActionOverwrite {
			if r.Condition == "same_shape" && compareShape(oldDoc, newDoc) {
				candidate = deepCopyMap(newDoc)
				ruleMatched = true
				break
			}
		} else if r.Action == ActionMerge {
			if r.Condition == "true" || r.Condition == "always" {
				candidate = mergeJSON(oldDoc, newDoc)
				ruleMatched = true
				break
			}
			if strings.HasPrefix(r.Condition, "allowed_fields[") {
				fields := parseAllowedFields(r.Condition)
				candidate = mergeAllowedFields(oldDoc, newDoc, fields)
				ruleMatched = true
				break
			}
		}
	}

	hasPositiveRules := false
	for _, r := range rules {
		if r.Action == ActionMerge || r.Action == ActionOverwrite {
			hasPositiveRules = true
			break
		}
	}
	
	if hasPositiveRules && !ruleMatched {
		return deepCopyMap(oldDoc), false, "no matching allow rule"
	}

	// Phase 2: Apply Deny Rules (Guardrails)
	for _, r := range rules {
		if r.Action == ActionDeny {
			if r.Condition == "has_deleted_field" {
				// NEW: Get the specific path of the deleted field
				if deletedPath := findDeletedField(oldDoc, candidate, ""); deletedPath != "" {
					return deepCopyMap(oldDoc), false, fmt.Sprintf("deny: field deletion detected at '%s'", deletedPath)
				}
			}
		}
	}

	return candidate, true, ""
}

// ----------------------
// Merge & Check Logic
// ----------------------

// mergeAllowedFields creates a new doc based on OldDoc, merging ONLY the keys in `allowed` from newDoc.
func mergeAllowedFields(oldDoc, newDoc map[string]any, allowed []string) map[string]any {
	// Start with a full copy of OldDoc (preserve everything by default)
	result := deepCopyMap(oldDoc)

	for _, k := range allowed {
		newVal, existsInNew := newDoc[k]
		if !existsInNew {
			continue // No update for this allowed field
		}

		oldVal, existsInOld := result[k]

		// Smart Merge:
		// If both are maps, we merge recursively (to preserve siblings like "a" when updating "b").
		// If not, we overwrite.
		if existsInOld {
			oldMap, oldIsMap := oldVal.(map[string]any)
			newMap, newIsMap := newVal.(map[string]any)
			
			if oldIsMap && newIsMap {
				// Recursive merge inside the allowed field
				result[k] = mergeJSON(oldMap, newMap)
			} else {
				// Direct replacement (Primitive or Type Change)
				result[k] = deepCopy(newVal)
			}
		} else {
			// Injection (Field didn't exist in Old)
			result[k] = deepCopy(newVal)
		}
	}
	return result
}

// mergeJSON recursively merges source into target.
// CHANGE: Arrays are now appended, not replaced.
func mergeJSON(target, source map[string]any) map[string]any {
	result := deepCopyMap(target)

	for k, vNew := range source {
		vOld, exists := result[k]

		if !exists {
			// New key? Just add it.
			result[k] = deepCopy(vNew)
			continue
		}

		// Check types for recursion
		oldMap, oldIsMap := vOld.(map[string]any)
		newMap, newIsMap := vNew.(map[string]any)

		oldSlice, oldIsSlice := vOld.([]any)
		newSlice, newIsSlice := vNew.([]any)

		if oldIsMap && newIsMap {
			// both are maps -> recurse
			result[k] = mergeJSON(oldMap, newMap)
		} else if oldIsSlice && newIsSlice {
			// NEW LOGIC: both are arrays -> APPEND
			// We create a new slice containing Old + New elements
			combined := make([]any, 0, len(oldSlice)+len(newSlice))

			// Copy old items
			for _, item := range oldSlice {
				combined = append(combined, deepCopy(item))
			}
			// Append new items
			for _, item := range newSlice {
				combined = append(combined, deepCopy(item))
			}
			result[k] = combined
		} else {
			// Type mismatch or primitives -> Overwrite
			result[k] = deepCopy(vNew)
		}
	}
	return result
}

// hasDeletedField checks if any key present in `original` is missing in `candidate`.
// It recurses into Maps AND Arrays.
func hasDeletedField(original, candidate map[string]any) bool {
	for k, vOld := range original {
		vNew, exists := candidate[k]
		if !exists {
			return true // Key completely missing in the new object
		}

		// Check if the value itself has internal deletions (nested maps or arrays)
		if hasDeletedValue(vOld, vNew) {
			return true
		}
	}
	return false
}

// hasDeletedValue inspects the values to see if they contain deletions.
func hasDeletedValue(oldVal, newVal any) bool {
	switch o := oldVal.(type) {

	// Case 1: The old value is a Map
	case map[string]any:
		n, ok := newVal.(map[string]any)
		if !ok {
			// Old was a Map, New is NOT a Map (e.g., replaced by string/null).
			// This implies all fields inside the old map are deleted.
			// (Unless the old map was empty, technically no fields lost).
			return len(o) > 0
		}
		// Recurse: Check the keys of this nested map
		return hasDeletedField(o, n)

	// Case 2: The old value is an Array/Slice
	case []any:
		n, ok := newVal.([]any)
		if !ok {
			// Old was Array, New is Not. Data loss.
			return len(o) > 0
		}

		// logic: If the new array is shorter, items (and their fields) were deleted.
		if len(n) < len(o) {
			return true
		}

		// Recurse: Check items pairwise.
		// We assume standard JSON semantics where indices align.
		// If you swap items, this might flag false positives/negatives depending on structure,
		// but for RLS "Anti-Deletion", strict index checking is the safest default.
		for i := range o {
			if hasDeletedValue(o[i], n[i]) {
				return true
			}
		}
	}

	// Primitives (strings, numbers) do not have "fields", so they can't have deleted fields.
	return false
}

func compareShape(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, vA := range a {
		vB, ok := b[k]
		if !ok {
			return false
		}
		mapA, aIsMap := vA.(map[string]any)
		mapB, bIsMap := vB.(map[string]any)
		if aIsMap && bIsMap {
			if !compareShape(mapA, mapB) {
				return false
			}
		} else if aIsMap != bIsMap {
			return false
		}
	}
	return true
}

// ----------------------
// Policy Parser
// ----------------------

type NewAction string
const (
	ActionMerge     NewAction = "merge"
	ActionOverwrite NewAction = "overwrite"
	ActionDeny      NewAction = "deny"
)

type Rule struct {
	Action    NewAction
	Condition string
}

func parsePolicy(policy string) []Rule {
	var rules []Rule
	parts := strings.Split(policy, ";")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		fields := strings.Fields(p)
		if len(fields) < 3 || fields[1] != "if" {
			continue
		}
		rules = append(rules, Rule{
			Action:    NewAction(strings.ToLower(fields[0])),
			Condition: strings.Join(fields[2:], " "),
		})
	}
	return rules
}

func parseAllowedFields(cond string) []string {
	start := strings.Index(cond, "[")
	end := strings.LastIndex(cond, "]")
	if start == -1 || end == -1 {
		return nil
	}
	inner := cond[start+1 : end]
	if strings.TrimSpace(inner) == "" {
		return nil
	}
	raw := strings.Split(inner, ",")
	clean := make([]string, 0, len(raw))
	for _, s := range raw {
		s = strings.TrimSpace(s)
		s = strings.Trim(s, "\"")
		s = strings.Trim(s, "'")
		clean = append(clean, s)
	}
	return clean
}

// ----------------------
// Deep Copy / Utils
// ----------------------

func deepCopy(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return deepCopyMap(val)
	case []any:
		newSlice := make([]any, len(val))
		for i, item := range val {
			newSlice[i] = deepCopy(item)
		}
		return newSlice
	default:
		return val
	}
}

func deepCopyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = deepCopy(v)
	}
	return out
}

func marshalOrdered(v any) ([]byte, error) {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var buf bytes.Buffer
		buf.WriteString("{")
		for i, k := range keys {
			if i > 0 {
				buf.WriteString(",")
			}
			b, _ := json.Marshal(k)
			buf.Write(b)
			buf.WriteString(":")
			valBytes, _ := marshalOrdered(val[k])
			buf.Write(valBytes)
		}
		buf.WriteString("}")
		return buf.Bytes(), nil
	case []any:
		var buf bytes.Buffer
		buf.WriteString("[")
		for i, item := range val {
			if i > 0 {
				buf.WriteString(",")
			}
			valBytes, _ := marshalOrdered(item)
			buf.Write(valBytes)
		}
		buf.WriteString("]")
		return buf.Bytes(), nil
	default:
		return json.Marshal(v)
	}
}
