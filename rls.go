package shuffle

import (
	"strings"
	//"reflect"
	"encoding/json"

	"sort"
	"bytes"
	"fmt"
)

const MaxDepth = 10
// --------------------
// Deep copy
// --------------------
func deepCopy(v any) any {
	switch val := v.(type) {
	case map[string]any:
		copyMap := make(map[string]any, len(val))
		for k, v := range val {
			copyMap[k] = deepCopy(v)
		}
		return copyMap
	case []any:
		copySlice := make([]any, len(val))
		for i, item := range val {
			copySlice[i] = deepCopy(item)
		}
		return copySlice
	default:
		return val
	}
}

func deepCopyMapSafe(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return deepCopy(m).(map[string]any)
}

// --------------------
// Field-level merge
// --------------------
func evalAllowedFields(mergedDoc, newDoc any, paths []string, maxDepth int) (any, bool) {
	merged := deepCopy(mergedDoc)
	for _, p := range paths {
		pathParts := strings.Split(p, ".")
		vNew, ok := getLeaf(newDoc, pathParts, maxDepth)
		if !ok {
			continue
		}
		merged = setLeafByPath(merged, pathParts, vNew)
	}
	return merged, true
}

func getLeaf(doc any, path []string, maxDepth int) (any, bool) {
	if maxDepth < 0 {
		return nil, false
	}
	if len(path) == 0 {
		return doc, true
	}
	key := path[0]
	switch d := doc.(type) {
	case map[string]any:
		v, exists := d[key]
		if !exists {
			return nil, false
		}
		return getLeaf(v, path[1:], maxDepth-1)
	case []any:
		if key != "[]" {
			return nil, false
		}
		return doc, true
	default:
		if len(path) == 1 {
			return d, true
		}
		return nil, false
	}
}

func setLeafByPath(merged any, path []string, newVal any) any {
	if len(path) == 0 {
		return newVal
	}
	key := path[0]

	switch m := merged.(type) {
	case map[string]any:
		copyMap := deepCopyMapSafe(m)
		if len(path) == 1 {
			copyMap[key] = newVal
		} else {
			next, ok := copyMap[key].(map[string]any)
			if !ok {
				next = map[string]any{}
			}
			copyMap[key] = setLeafByPath(next, path[1:], newVal)
		}
		return copyMap
	default:
		if len(path) == 1 {
			return newVal
		}
		newMap := map[string]any{}
		return setLeafByPath(newMap, path, newVal)
	}
}

// EvalPolicyJSON applies RLS rules to oldJSON and newJSON.
// Returns:
//   merged JSON (updated if allowed, otherwise oldJSON),
//   ok (true if allowed, false if denied),
//   reason string (why denied, empty if ok)
func EvalPolicyJSON(policy, oldJSON, newJSON string) (string, bool, string) {
	var oldDoc, newDoc map[string]any
	if err := json.Unmarshal([]byte(oldJSON), &oldDoc); err != nil {
		return oldJSON, false, "invalid old JSON"
	}
	if err := json.Unmarshal([]byte(newJSON), &newDoc); err != nil {
		return oldJSON, false, "invalid new JSON"
	}

	merged, ok, reason := evalPolicyRules(parsePolicy(policy), oldDoc, newDoc, 0)
	if !ok {
		// Denied: return old JSON
		resultBytes, _ := marshalOrdered(oldDoc)
		return string(resultBytes), false, reason
	}

	resultBytes, _ := marshalOrdered(merged)
	return string(resultBytes), true, ""
}

// ---------------------- Policy Parsing ----------------------

type NewAction string
const (
	ActionMerge     NewAction = "merge"
	ActionOverwrite NewAction = "overwrite"
	ActionDeny      NewAction = "deny"
)

type ConditionFunc func(oldDoc, newDoc map[string]any) bool

type Rule struct {
	Action    NewAction
	Condition string
}

func parsePolicy(policy string) []Rule {
	rules := []Rule{}
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
			Action:    NewAction(fields[0]),
			Condition: strings.Join(fields[2:], " "),
		})
	}
	return rules
}

// ---------------------- Core Rule Evaluation ----------------------

func evalPolicyRules(rules []Rule, oldDoc, newDoc map[string]any, depth int) (map[string]any, bool, string) {
	if depth > MaxDepth {
		return oldDoc, false, "max depth exceeded"
	}

	for _, r := range rules {
		if evalCondition(r.Condition, oldDoc, newDoc) {
			switch r.Action {
			case ActionMerge:
				fields := parseAllowedFields(r.Condition)
				merged := mergeAllowedFieldsRecursive(oldDoc, newDoc, fields)
				return merged, true, ""

			case ActionOverwrite:
				return newDoc, true, ""
			case ActionDeny:
				return oldDoc, false, r.Condition
			}
		}
	}
	// No rule matched: deny by default
	return oldDoc, false, "no rule matched"
}

func mergeAllowedFieldsRecursive(oldDoc, newDoc map[string]any, allowed []string) map[string]any {
	result := deepCopyMap(oldDoc)
	for _, key := range allowed {
		newVal, ok := newDoc[key]
		if !ok {
			continue // skip missing keys
		}

		// Check for nested map
		if oldMap, ok1 := oldDoc[key].(map[string]any); ok1 {
			if newMap, ok2 := newVal.(map[string]any); ok2 {
				// recursive merge for nested map
				result[key] = mergeAllowedFieldsRecursive(oldMap, newMap, allowedFieldsForMap(newMap))
				continue
			}
		}

		// Otherwise just overwrite
		result[key] = newVal
	}
	return result
}

// optional helper: allow all keys in nested map
func allowedFieldsForMap(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}


func mergeAllowedFields(oldDoc, newDoc map[string]any, allowed []string) map[string]any {
	result := deepCopyMap(oldDoc)
	for _, f := range allowed {
		if val, ok := newDoc[f]; ok {
			result[f] = val
		}
	}
	return result
}

func evalCondition(cond string, oldDoc, newDoc map[string]any) bool {
	cond = strings.TrimSpace(cond)
	switch {
	case cond == "same_shape":
		return compareShape(oldDoc, newDoc)
	case strings.HasPrefix(cond, "allowed_fields["):
		fields := parseAllowedFields(cond)
		// return true if at least one field exists in newDoc
		for _, f := range fields {
			if _, ok := newDoc[f]; ok {
				return true
			}
		}
		return false
	case cond == "has_deleted_field":
		for k := range oldDoc {
			if _, ok := newDoc[k]; !ok {
				return true
			}
		}
		return false
	}
	return false
}


func parseAllowedFields(cond string) []string {
	start := strings.Index(cond, "[")
	end := strings.Index(cond, "]")
	if start < 0 || end < 0 || end <= start {
		return nil
	}
	inner := cond[start+1 : end]
	parts := strings.Split(inner, ",")
	for i := range parts {
		parts[i] = strings.Trim(strings.Trim(parts[i], `"`), " ")
	}
	return parts
}

func mergeJSON(oldDoc, newDoc map[string]any) map[string]any {
    result := deepCopyMap(oldDoc)
    for k, v := range newDoc {
        if oldMap, ok1 := result[k].(map[string]any); ok1 {
            if newMap, ok2 := v.(map[string]any); ok2 {
                result[k] = mergeJSON(oldMap, newMap)
                continue
            }
        }
        result[k] = v
    }
    return result
}

func compareShape(oldDoc, newDoc map[string]any) bool {
	if len(oldDoc) != len(newDoc) {
		return false
	}
	for k, oldVal := range oldDoc {
		newVal, ok := newDoc[k]
		if !ok {
			return false
		}
		oldMap, oldIsMap := oldVal.(map[string]any)
		newMap, newIsMap := newVal.(map[string]any)
		if oldIsMap && newIsMap {
			if !compareShape(oldMap, newMap) {
				return false
			}
		} else if oldIsMap != newIsMap {
			return false
		}
	}
	return true
}

// ---------------------- Utilities ----------------------

func deepCopyMap(orig map[string]any) map[string]any {
	copy := make(map[string]any, len(orig))
	for k, v := range orig {
		if m, ok := v.(map[string]any); ok {
			copy[k] = deepCopyMap(m)
		} else {
			copy[k] = v
		}
	}
	return copy
}

// Recursively marshal maps with sorted keys
func marshalOrdered(v any) ([]byte, error) {
	switch vv := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(vv))
		for k := range vv {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf := bytes.NewBufferString("{")
		for i, k := range keys {
			if i > 0 {
				buf.WriteString(",")
			}
			buf.WriteString(fmt.Sprintf("%q:", k))
			valBytes, _ := marshalOrdered(vv[k])
			buf.Write(valBytes)
		}
		buf.WriteString("}")
		return buf.Bytes(), nil
	case []any:
		buf := bytes.NewBufferString("[")
		for i, elem := range vv {
			if i > 0 {
				buf.WriteString(",")
			}
			elemBytes, _ := marshalOrdered(elem)
			buf.Write(elemBytes)
		}
		buf.WriteString("]")
		return buf.Bytes(), nil
	default:
		return json.Marshal(v)
	}
}
