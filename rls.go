package shuffle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"math"
)

const MaxDepth = 10

// ----------------------
// Public API
// ----------------------

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
	// Default: Overwrite candidate
	candidate := deepCopyMap(newDoc)
	ruleMatched := false

	// Phase 1: Determine Candidate
	for _, r := range rules {
		if r.Action == ActionOverwrite {
			if r.Condition == "same_shape" && compareShape(oldDoc, newDoc) {
				candidate = deepCopyMap(newDoc)
				ruleMatched = true
				break 
			}
		} else if r.Action == ActionMerge {
			// Handle "merge" (implicit true) OR "merge if always"
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

	// If explicit rules existed but didn't match, fail.
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

	// Phase 2: Deny Guardrails
	for _, r := range rules {
		if r.Action == ActionDeny {
			if r.Condition == "has_deleted_field" {
				if path := findDeletedField(oldDoc, candidate, ""); path != "" {
					return deepCopyMap(oldDoc), false, fmt.Sprintf("deny: field deletion detected at '%s'", path)
				}
			}
		}
	}

	return candidate, true, ""
}

// ----------------------
// Smart Merge Logic
// ----------------------

func mergeAllowedFields(oldDoc, newDoc map[string]any, allowed []string) map[string]any {
	result := deepCopyMap(oldDoc)
	for _, k := range allowed {
		if newVal, ok := newDoc[k]; ok {
			if oldVal, exists := result[k]; exists {
				if oldMap, ok1 := oldVal.(map[string]any); ok1 {
					if newMap, ok2 := newVal.(map[string]any); ok2 {
						result[k] = mergeJSON(oldMap, newMap)
						continue
					}
				}
			}
			result[k] = deepCopy(newVal)
		}
	}
	return result
}

func mergeJSON(target, source map[string]any) map[string]any {
	result := deepCopyMap(target)

	for k, vNew := range source {
		vOld, exists := result[k]
		if !exists {
			result[k] = deepCopy(vNew)
			continue
		}

		oldMap, oldIsMap := vOld.(map[string]any)
		newMap, newIsMap := vNew.(map[string]any)
		oldSlice, oldIsSlice := vOld.([]any)
		newSlice, newIsSlice := vNew.([]any)

		if oldIsMap && newIsMap {
			result[k] = mergeJSON(oldMap, newMap)
		} else if oldIsSlice && newIsSlice {
			// KEYED LIST LOGIC
			if isKeyedList(oldSlice) || isKeyedList(newSlice) {
				result[k] = mergeKeyedList(oldSlice, newSlice)
			} else {
				// Primitive List -> Overwrite
				result[k] = deepCopy(vNew)
			}
		} else {
			result[k] = deepCopy(vNew)
		}
	}
	return result
}

func isKeyedList(s []any) bool {
	if len(s) == 0 { return false }
	_, ok := getID(s[0])
	return ok
}

// getID robustly handles float/int/string IDs
func getID(v any) (any, bool) {
	if m, ok := v.(map[string]any); ok {
		// Priority 1: "id"
		if val, found := m["id"]; found {
			return normalizeID(val), true
		}
		// Priority 2: "uid"
		if val, found := m["uid"]; found {
			return normalizeID(val), true
		}
	}
	return nil, false
}

// normalizeID ensures that 1.0 (float) and 1 (int) are treated as the same key
func normalizeID(v any) any {
	switch n := v.(type) {
	case float64:
		// If it's a whole number, return it as int to ensure map matching works
		if n == math.Trunc(n) {
			return int(n)
		}
		return n
	case int:
		return int(n)
	default:
		return v // strings, etc.
	}
}

func mergeKeyedList(oldList, newList []any) []any {
	// 1. Start with a COPY of the Old List (Preserve History)
	result := make([]any, len(oldList))
	
	// Lookup Map: ID -> Index in Result
	lookup := make(map[any]int)

	for i, item := range oldList {
		result[i] = deepCopy(item)
		if id, ok := getID(item); ok {
			lookup[id] = i
		}
	}

	// 2. Merge in the New Items
	for _, newItem := range newList {
		newID, ok := getID(newItem)
		
		if ok {
			if idx, found := lookup[newID]; found {
				// UPDATE: Merge newItem into the existing result item
				oldItemMap, _ := result[idx].(map[string]any)
				newItemMap, _ := newItem.(map[string]any)
				result[idx] = mergeJSON(oldItemMap, newItemMap)
				continue
			}
		}
		
		// APPEND: It's new (or has no ID), so add it
		result = append(result, deepCopy(newItem))
		
		// If it has an ID, add to lookup (handles duplicates in new list)
		if ok {
			lookup[newID] = len(result) - 1
		}
	}
	return result
}

// ----------------------
// Check Logic (Deletion)
// ----------------------

func findDeletedField(oldVal, newVal any, currentPath string) string {
	switch o := oldVal.(type) {
	case map[string]any:
		n, ok := newVal.(map[string]any)
		if !ok { return currentPath }
		for k, vOld := range o {
			vNew, exists := n[k]
			nextPath := k
			if currentPath != "" { nextPath = currentPath + "." + k }
			if !exists { return nextPath }
			if path := findDeletedField(vOld, vNew, nextPath); path != "" { return path }
		}

	case []any:
		n, ok := newVal.([]any)
		if !ok { return currentPath }

		// KEYED MATCHING
		if len(o) > 0 {
			if _, hasID := getID(o[0]); hasID {
				newItemsByID := make(map[any]any)
				for _, item := range n {
					if id, ok := getID(item); ok {
						newItemsByID[id] = item
					}
				}
				for _, oldItem := range o {
					id, _ := getID(oldItem)
					newItem, found := newItemsByID[id]
					nextPath := fmt.Sprintf("%s[id=%v]", currentPath, id)
					
					if !found { return nextPath } // ID missing
					if path := findDeletedField(oldItem, newItem, nextPath); path != "" {
						return path
					}
				}
				return ""
			}
		}

		// POSITIONAL MATCHING
		if len(n) < len(o) {
			if currentPath == "" { return "[]" }
			return fmt.Sprintf("%s[%d]", currentPath, len(n))
		}
		for i, vOld := range o {
			if i >= len(n) { return fmt.Sprintf("%s[%d]", currentPath, i) }
			vNew := n[i]
			nextPath := fmt.Sprintf("[%d]", i)
			if currentPath != "" { nextPath = fmt.Sprintf("%s[%d]", currentPath, i) }
			if path := findDeletedField(vOld, vNew, nextPath); path != "" { return path }
		}
	}
	return ""
}

func compareShape(a, b map[string]any) bool {
	if len(a) != len(b) { return false }
	for k, vA := range a {
		vB, ok := b[k]
		if !ok { return false }
		mapA, aIsMap := vA.(map[string]any)
		mapB, bIsMap := vB.(map[string]any)
		if aIsMap && bIsMap {
			if !compareShape(mapA, mapB) { return false }
		} else if aIsMap != bIsMap {
			return false
		}
	}
	return true
}

// ----------------------
// Parser / Utils
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
		if p == "" { continue }
		fields := strings.Fields(p)
		if len(fields) == 1 {
			rules = append(rules, Rule{Action: NewAction(strings.ToLower(fields[0])), Condition: "true"})
			continue
		}
		if len(fields) < 3 || fields[1] != "if" { continue }
		rules = append(rules, Rule{Action: NewAction(strings.ToLower(fields[0])), Condition: strings.Join(fields[2:], " ")})
	}
	return rules
}

func parseAllowedFields(cond string) []string {
	start := strings.Index(cond, "[")
	end := strings.LastIndex(cond, "]")
	if start == -1 || end == -1 { return nil }
	inner := cond[start+1 : end]
	if strings.TrimSpace(inner) == "" { return nil }
	raw := strings.Split(inner, ",")
	clean := make([]string, 0, len(raw))
	for _, s := range raw {
		clean = append(clean, strings.Trim(strings.TrimSpace(s), "\"'"))
	}
	return clean
}

func deepCopy(v any) any {
	switch val := v.(type) {
	case map[string]any: return deepCopyMap(val)
	case []any:
		out := make([]any, len(val))
		for i, item := range val { out[i] = deepCopy(item) }
		return out
	default: return val
	}
}

func deepCopyMap(m map[string]any) map[string]any {
	if m == nil { return nil }
	out := make(map[string]any, len(m))
	for k, v := range m { out[k] = deepCopy(v) }
	return out
}

func marshalOrdered(v any) ([]byte, error) {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val { keys = append(keys, k) }
		sort.Strings(keys)
		var buf bytes.Buffer
		buf.WriteString("{")
		for i, k := range keys {
			if i > 0 { buf.WriteString(",") }
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
			if i > 0 { buf.WriteString(",") }
			valBytes, _ := marshalOrdered(item)
			buf.Write(valBytes)
		}
		buf.WriteString("]")
		return buf.Bytes(), nil
	default: return json.Marshal(v)
	}
}
