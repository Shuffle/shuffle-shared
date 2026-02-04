package shuffle

import (
	"bytes"
	"encoding/json"
	//"fmt"
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

// ----------------------
// Core Logic
// ----------------------

func evalPolicyRules(rules []Rule, oldDoc, newDoc map[string]any) (map[string]any, bool, string) {
	// Start with oldDoc as the base, but we need to determine the 'Candidate' (Proposed State).
	
	// Default Strategy: Overwrite (Full Replacement)
	// If no positive rule matches, we assume the user intends to replace the document with newDoc.
	// This allows "deny" rules to correctly catch missing fields.
	candidate := deepCopyMap(newDoc)
	
	ruleMatched := false

	// Phase 1: Determine Candidate via Positive Rules (Merge/Overwrite)
	for _, r := range rules {
		if r.Action == ActionOverwrite {
			if r.Condition == "same_shape" {
				if compareShape(oldDoc, newDoc) {
					candidate = deepCopyMap(newDoc)
					ruleMatched = true
					break 
				}
			}
		} else if r.Action == ActionMerge {
            // NEW: Generic merge support (Patch Mode)
            if r.Condition == "always" {
                candidate = mergeJSON(oldDoc, newDoc)
                ruleMatched = true
                break
            }
            // EXISTING: Specific field merging
            if strings.HasPrefix(r.Condition, "allowed_fields[") {
                fields := parseAllowedFields(r.Condition)
                candidate = mergeAllowedFields(oldDoc, newDoc, fields)
                ruleMatched = true
                break
            }
        }
	}

	// If positive rules existed but none matched (e.g., shape mismatch), we fail fast.
	// But if ONLY "deny" rules exist (no Merge/Overwrite rules), we use the Default Strategy (Overwrite).
	hasPositiveRules := false
	for _, r := range rules {
		if r.Action == ActionMerge || r.Action == ActionOverwrite {
			hasPositiveRules = true
			break
		}
	}
	
	if hasPositiveRules && !ruleMatched {
		// Specific allow rules exist but weren't met (e.g. wrong shape)
		// We return oldDoc to signify "No Change Allowed"
		return deepCopyMap(oldDoc), false, "no matching allow rule"
	}

	// Phase 2: Apply Deny Rules (Guardrails)
	// These run against the Candidate vs OldDoc
	for _, r := range rules {
		if r.Action == ActionDeny {
			if r.Condition == "has_deleted_field" {
				if hasDeletedField(oldDoc, candidate) {
					return deepCopyMap(oldDoc), false, "deny: field deletion detected"
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

// mergeJSON recursively merges `source` into `target` (standard merge patch logic).
func mergeJSON(target, source map[string]any) map[string]any {
	result := deepCopyMap(target)
	for k, vNew := range source {
		vOld, exists := result[k]
		
		oldMap, oldIsMap := vOld.(map[string]any)
		newMap, newIsMap := vNew.(map[string]any)

		if exists && oldIsMap && newIsMap {
			result[k] = mergeJSON(oldMap, newMap)
		} else {
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
