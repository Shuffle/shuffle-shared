package shuffle

import (
	"strings"
	"reflect"
	"encoding/json"
)

// This file is for handling RLS-like security rules for datastore
// It is an attempt to prevent overwrites of fields that should not be 
// changed based on shape comparisons and allowed fields lists

const MaxDepth = 10
func EvalPolicyJSON(policy string, oldJSON, newJSON string) (string, bool) {
	var oldDoc, newDoc map[string]any
	if err := json.Unmarshal([]byte(oldJSON), &oldDoc); err != nil {
		return "", false
	}
	if err := json.Unmarshal([]byte(newJSON), &newDoc); err != nil {
		return "", false
	}

	var merged any = deepCopy(oldDoc)
	clauses := strings.Split(policy, ";")
	for _, c := range clauses {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		parts := strings.SplitN(c, "if", 2)
		if len(parts) != 2 {
			continue
		}
		action := strings.TrimSpace(parts[0])
		condition := strings.TrimSpace(parts[1])

		var mergedResult any
		var ok bool

		// allowed_fields
		if strings.HasPrefix(condition, "allowed_fields") {
			start := strings.Index(condition, "[")
			end := strings.Index(condition, "]")
			if start < 0 || end < 0 || start >= end {
				continue
			}
			listStr := condition[start+1 : end]
			paths := []string{}
			for _, s := range strings.Split(listStr, ",") {
				paths = append(paths, strings.Trim(strings.TrimSpace(s), `"`))
			}
			mergedResult, ok = evalAllowedFields(merged, newDoc, paths, MaxDepth)
		} else {
			mergedResult, ok = evalConditionMerge(condition, merged, newDoc, MaxDepth)
		}

		if !ok {
			continue
		}

		// apply action
		switch action {
		case "merge":
			merged = mergedResult
		case "overwrite":
			merged = deepCopy(newDoc)
		case "deny":
			return "", false
		default:
			return "", false
		}
	}

	resultJSON, err := json.Marshal(merged)
	if err != nil {
		return "", false
	}
	return string(resultJSON), true
}

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

// --------------------
// Merge engine for merge/overwrite logic
// --------------------
func mergeJSON(oldDoc, newDoc any, maxDepth int) any {
	if maxDepth < 0 || newDoc == nil {
		return newDoc
	}
	if oldDoc == nil {
		return deepCopy(newDoc)
	}

	switch oldVal := oldDoc.(type) {
	case map[string]any:
		newVal, ok := newDoc.(map[string]any)
		if !ok {
			return deepCopy(newDoc) // type mismatch → replace
		}
		result := deepCopy(oldVal).(map[string]any)
		for k, vNew := range newVal {
			if vOld, exists := result[k]; exists {
				result[k] = mergeJSON(vOld, vNew, maxDepth-1)
			} else {
				result[k] = deepCopy(vNew)
			}
		}
		return result
	case []any:
		newVal, ok := newDoc.([]any)
		if !ok {
			return deepCopy(newDoc)
		}
		result := deepCopy(oldVal).([]any)
		for _, item := range newVal {
			found := false
			for _, oldItem := range oldVal {
				if reflect.DeepEqual(oldItem, item) {
					found = true
					break
				}
			}
			if !found {
				result = append(result, item)
			}
		}
		return result
	default:
		return deepCopy(newDoc) // primitive → always replace
	}
}

// --------------------
// Condition evaluation
// --------------------
func evalConditionMerge(condition string, oldDoc, newDoc any, maxDepth int) (any, bool) {
	switch condition {
	case "same_shape":
		if compareShape(oldDoc, newDoc, false, maxDepth) {
			return mergeJSON(oldDoc, newDoc, maxDepth), true
		}
		return nil, false
	case "is_superset":
		if compareShape(oldDoc, newDoc, true, maxDepth) {
			return mergeJSON(oldDoc, newDoc, maxDepth), true
		}
		return nil, false
	case "has_deleted_field":
		if !compareShape(oldDoc, newDoc, true, maxDepth) {
			return nil, false
		}
		return oldDoc, true
	default:
		return nil, false
	}
}

// --------------------
// Shape comparison
// --------------------
func compareShape(a, b any, allowSubset bool, maxDepth int) bool {
	if maxDepth < 0 {
		return true
	}
	if a == nil || b == nil {
		return a == b
	}

	typeA := reflect.TypeOf(a)
	typeB := reflect.TypeOf(b)
	if typeA != typeB {
		return false
	}

	switch va := a.(type) {
	case map[string]any:
		vb := b.(map[string]any)
		if !allowSubset && len(va) != len(vb) {
			return false
		}
		for k, vA := range va {
			vB, exists := vb[k]
			if !exists {
				if !allowSubset {
					return false
				}
				continue
			}
			if !compareShape(vA, vB, allowSubset, maxDepth-1) {
				return false
			}
		}
		return true
	case []any:
		vb := b.([]any)
		if !allowSubset && len(va) != len(vb) {
			return false
		}
		minLen := len(va)
		if len(vb) < minLen {
			minLen = len(vb)
		}
		for i := 0; i < minLen; i++ {
			if !compareShape(va[i], vb[i], allowSubset, maxDepth-1) {
				return false
			}
		}
		return true
	default:
		return true
	}
}

