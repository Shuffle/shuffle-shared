package shuffle

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// seedUsecaseTestCache configures in-memory caching so GetDefaultWorkflowByType
// can resolve GetEnvironments and GetAllWorkflowAppAuth locally without any external DB.
func seedUsecaseTestCache(t *testing.T, orgId string) {
	t.Helper()
	project.CacheDb = true
	ctx := context.Background()

	envs := []Environment{
		{
			Name:    "Shuffle",
			Type:    "cloud",
			OrgId:   orgId,
			Default: true,
			Id:      "env-local-test",
		},
	}
	envBytes, err := json.Marshal(envs)
	if err != nil {
		t.Fatalf("failed to marshal test environments: %v", err)
	}
	_ = SetCache(ctx, "Environments_"+orgId, envBytes, 60)

	auths := []AppAuthenticationStorage{
		{
			Label:   "Shuffle OpenAPI Auth",
			Id:      "auth-openapi-local-123",
			OrgId:   orgId,
			Defined: true,
			Active:  true,
			Type:    "bearer",
			App: WorkflowApp{
				ID:   "fc92c1d806df0c96f0c152a7b43b2878",
				Name: "shuffle_openapi",
			},
		},
	}
	authBytes, err := json.Marshal(auths)
	if err != nil {
		t.Fatalf("failed to marshal test app auth: %v", err)
	}
	_ = SetCache(ctx, "workflowappauth_"+orgId, authBytes, 60)
}

func generateTestWorkflow(t *testing.T, orgId, actionType, appNames string, extra CategoryAction) Workflow {
	t.Helper()
	seedUsecaseTestCache(t, orgId)
	extra.Label = actionType
	extra.AppName = appNames

	wf, err := GetDefaultWorkflowByType(Workflow{ID: "wf-" + actionType, OrgId: orgId}, orgId, extra)
	if err != nil {
		t.Fatalf("GetDefaultWorkflowByType(%q) failed: %v", actionType, err)
	}
	return wf
}

// localUsecaseMockServer simulates Shuffle backend APIs (Datastore, Pager, Comments, Vulnerabilities, Threat Feeds)
// so every usecase workflow and embedded Python script can execute end-to-end locally with sample data.
type localUsecaseMockServer struct {
	mu            sync.Mutex
	server        *httptest.Server
	datastore     map[string]map[string]interface{}             // category -> key -> value
	orgDatastore  map[string]map[string]map[string]interface{}  // orgId -> category -> key -> value
	statsCalls    []map[string]interface{}
	bulkPostCalls [][]map[string]interface{}
	setKeyCalls   []map[string]interface{}
	pagerCalls    []map[string]interface{}
	commentCalls  []map[string]interface{}
	vulnQueries   []map[string]interface{}
}

func newLocalUsecaseMockServer(t *testing.T) *localUsecaseMockServer {
	t.Helper()
	m := &localUsecaseMockServer{
		datastore:    make(map[string]map[string]interface{}),
		orgDatastore: make(map[string]map[string]map[string]interface{}),
	}

	mux := http.NewServeMux()

	// Threat feed CSV endpoint used by threatlist_monitor (getIocIngestionScript)
	// Timestamp is unquoted at start of line so the ingestion script's date filter matches cleanly.
	mux.HandleFunc("/threat-feed.csv", func(w http.ResponseWriter, r *http.Request) {
		nowStr := time.Now().UTC().Format("2006-01-02 15:04:05")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "# Sample Threat Feed\n%s,198.51.100.77,evil-c2.example.org,https://evil-c2.example.org/payload.exe\n", nowStr)
	})

	// Vulnerability API endpoint used by vulnerability_correlation (getVulnerabilityCorrelationScript)
	mux.HandleFunc("/api/v1/vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		_ = json.Unmarshal(body, &payload)
		m.mu.Lock()
		m.vulnQueries = append(m.vulnQueries, payload)
		m.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"vulns": []map[string]interface{}{
				{
					"id":        "CVE-2024-99999",
					"summary":   "Critical remote code execution in sample package",
					"details":   "Detailed description for CVE-2024-99999",
					"published": "2025-01-10T00:00:00Z",
					"modified":  "2025-01-15T00:00:00Z",
					"aliases":   []string{"GHSA-xxxx-yyyy-zzzz"},
					"severity": []map[string]interface{}{
						{"type": "CVSS_V3", "score": "9.8"},
					},
					"database_specific": map[string]interface{}{
						"severity": "CRITICAL",
					},
					"references": []map[string]interface{}{
						{"type": "ADVISORY", "url": "https://osv.dev/vulnerability/CVE-2024-99999"},
					},
					"affected": []map[string]interface{}{
						{
							"ranges": []map[string]interface{}{
								{
									"type": "ECOSYSTEM",
									"events": []map[string]interface{}{
										{"introduced": "0"},
										{"fixed": "2.17.1"},
									},
								},
							},
						},
					},
				},
			},
		})
	})

	// Shuffle Datastore category listing endpoint (/api/v2/datastore/category/<category>)
	// used by Tools.list_datastore_category in app.py (e.g. Step 1: Get_all_rules_from_the_system).
	mux.HandleFunc("/api/v2/datastore/category/", func(w http.ResponseWriter, r *http.Request) {
		category := strings.TrimPrefix(r.URL.Path, "/api/v2/datastore/category/")
		if category == "" {
			category = "default"
		}
		outputType := r.URL.Query().Get("type")
		if outputType == "" {
			outputType = "values"
		}

		m.mu.Lock()
		catMap := m.datastore[category]
		var values []interface{}
		var keys []string
		for k, v := range catMap {
			keys = append(keys, k)
			values = append(values, v)
		}
		m.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if outputType == "values" {
			if values == nil {
				values = []interface{}{}
			}
			_ = json.NewEncoder(w).Encode(values)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"category": category,
			"keys":     keys,
			"values":   values,
		})
	})

	// Shuffle Datastore bulk & single-key endpoint (/api/v2/datastore)
	mux.HandleFunc("/api/v2/datastore", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			orgHeader := strings.TrimSpace(r.Header.Get("Org-Id"))
			var items []map[string]interface{}
			if err := json.Unmarshal(body, &items); err != nil {
				var single map[string]interface{}
				if err2 := json.Unmarshal(body, &single); err2 == nil {
					items = []map[string]interface{}{single}
				}
			}

			m.mu.Lock()
			m.bulkPostCalls = append(m.bulkPostCalls, items)
			for _, item := range items {
				if orgHeader != "" {
					item["_org_id_header"] = orgHeader
				}
				cat, _ := item["category"].(string)
				if cat == "" {
					cat = "default"
				}
				key, _ := item["key"].(string)
				if key != "" {
					if m.datastore[cat] == nil {
						m.datastore[cat] = make(map[string]interface{})
					}
					var parsedVal interface{}
					if val, hasVal := item["value"]; hasVal {
						if strVal, ok := val.(string); ok {
							var parsed interface{}
							if err := json.Unmarshal([]byte(strVal), &parsed); err == nil {
								parsedVal = parsed
							} else {
								parsedVal = strVal
							}
						} else {
							parsedVal = val
						}
					} else {
						parsedVal = item
					}
					m.datastore[cat][key] = parsedVal

					targetOrg := orgHeader
					if targetOrg == "" {
						targetOrg, _ = item["org_id"].(string)
					}
					if targetOrg != "" {
						if m.orgDatastore[targetOrg] == nil {
							m.orgDatastore[targetOrg] = make(map[string]map[string]interface{})
						}
						if m.orgDatastore[targetOrg][cat] == nil {
							m.orgDatastore[targetOrg][cat] = make(map[string]interface{})
						}
						m.orgDatastore[targetOrg][cat][key] = parsedVal
					}
				}
			}
			m.mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	// Shuffle Custom Stats endpoint (/api/v1/stats) used by shuffle_openapi post_count_custom_stats
	// (Step 4: Update_rule_statistics).
	mux.HandleFunc("/api/v1/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		_ = json.Unmarshal(body, &payload)
		if auth := r.Header.Get("Authorization"); auth != "" {
			payload["_authorization_header"] = auth
		}
		m.mu.Lock()
		m.statsCalls = append(m.statsCalls, payload)
		m.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"key":     payload["key"],
			"value":   payload["value"],
		})
	})

	// Shuffle Datastore key/category endpoint (/api/v1/datastore/...)
	mux.HandleFunc("/api/v1/datastore/", func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/api/v1/datastore/")
		category := r.URL.Query().Get("category")
		if category == "" {
			category = "default"
		}

		if r.Method == http.MethodGet {
			m.mu.Lock()
			catMap := m.datastore[category]
			val, exists := catMap[key]
			m.mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			if !exists {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "value": nil})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success":  true,
				"key":      key,
				"category": category,
				"value":    val,
			})
			return
		}

		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			body, _ := io.ReadAll(r.Body)
			var payload map[string]interface{}
			_ = json.Unmarshal(body, &payload)

			m.mu.Lock()
			m.setKeyCalls = append(m.setKeyCalls, payload)
			if m.datastore[category] == nil {
				m.datastore[category] = make(map[string]interface{})
			}
			rawVal := payload["value"]
			if strVal, ok := rawVal.(string); ok {
				var parsed interface{}
				if err := json.Unmarshal([]byte(strVal), &parsed); err == nil {
					m.datastore[category][key] = parsed
				} else {
					m.datastore[category][key] = strVal
				}
			} else {
				m.datastore[category][key] = rawVal
			}
			m.mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
			return
		}
	})

	// Shuffle App SDK cache/datastore endpoints (/api/v1/orgs/<org_id>/get_cache and /api/v1/orgs/<org_id>/set_cache)
	// used by AppBase.get_key / AppBase.set_key in shuffle_sdk.py when running app.py --standalone.
	mux.HandleFunc("/api/v1/orgs/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		_ = json.Unmarshal(body, &payload)

		key, _ := payload["key"].(string)
		category, _ := payload["category"].(string)
		if category == "" {
			category = "default"
		}

		if strings.HasSuffix(r.URL.Path, "/get_cache") {
			m.mu.Lock()
			catMap := m.datastore[category]
			val, exists := catMap[key]
			m.mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			if !exists {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"key":     key,
					"value":   nil,
				})
				return
			}
			var valStr string
			if s, ok := val.(string); ok {
				valStr = s
			} else {
				b, _ := json.Marshal(val)
				valStr = string(b)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success":  true,
				"key":      key,
				"category": category,
				"value":    valStr,
			})
			return
		}

		if strings.HasSuffix(r.URL.Path, "/set_cache") {
			m.mu.Lock()
			m.setKeyCalls = append(m.setKeyCalls, payload)
			if m.datastore[category] == nil {
				m.datastore[category] = make(map[string]interface{})
			}
			rawVal := payload["value"]
			if strVal, ok := rawVal.(string); ok {
				var parsed interface{}
				if err := json.Unmarshal([]byte(strVal), &parsed); err == nil {
					m.datastore[category][key] = parsed
				} else {
					m.datastore[category][key] = strVal
				}
			} else {
				m.datastore[category][key] = rawVal
			}
			m.mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"key":     key,
			})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	})

	// Shuffle Mobile Pager endpoints (/api/v1/functions/pager and /api/v1/pager/alert)
	pagerHandler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		_ = json.Unmarshal(body, &payload)
		m.mu.Lock()
		m.pagerCalls = append(m.pagerCalls, payload)
		m.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "status": "paged"})
	}
	mux.HandleFunc("/api/v1/functions/pager", pagerHandler)
	mux.HandleFunc("/api/v1/pager/alert", pagerHandler)

	m.server = httptest.NewServer(mux)
	t.Cleanup(func() {
		m.server.Close()
	})
	return m
}

func (m *localUsecaseMockServer) seedDatastore(category, key string, val interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.datastore[category] == nil {
		m.datastore[category] = make(map[string]interface{})
	}
	m.datastore[category][key] = val
}

func (m *localUsecaseMockServer) getDatastoreValue(category, key string) (interface{}, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.datastore[category] == nil {
		return nil, false
	}
	v, ok := m.datastore[category][key]
	return v, ok
}

// findActionByLabel finds an action in a workflow by its label or name.
func findActionByLabel(wf Workflow, label string) *Action {
	for i := range wf.Actions {
		if wf.Actions[i].Label == label || wf.Actions[i].Name == label {
			return &wf.Actions[i]
		}
	}
	return nil
}

// findConditionalBranches returns all branches in a workflow that have at least one condition.
func findConditionalBranches(wf Workflow) []Branch {
	var out []Branch
	for _, b := range wf.Branches {
		if len(b.Conditions) > 0 {
			out = append(out, b)
		}
	}
	return out
}

// getActionParam retrieves a parameter value by name from an Action.
func getActionParam(action *Action, paramName string) (string, bool) {
	if action == nil {
		return "", false
	}
	for _, p := range action.Parameters {
		if p.Name == paramName {
			return p.Value, true
		}
	}
	return "", false
}

// evaluateUsecaseCondition evaluates a Shuffle Branch Condition against step results.
func evaluateUsecaseCondition(t *testing.T, cond Condition, stepOutputs map[string]interface{}) bool {
	t.Helper()
	src := resolveConditionExpression(cond.Source.Value, stepOutputs)
	dst := resolveConditionExpression(cond.Destination.Value, stepOutputs)
	op := strings.ToLower(strings.TrimSpace(cond.Condition.Value))

	switch op {
	case "equals", "equal", "==":
		return fmt.Sprintf("%v", src) == fmt.Sprintf("%v", dst)
	case "does not equal", "!=":
		return fmt.Sprintf("%v", src) != fmt.Sprintf("%v", dst)
	case "larger than", ">":
		sNum, err1 := strconv.ParseFloat(fmt.Sprintf("%v", src), 64)
		dNum, err2 := strconv.ParseFloat(fmt.Sprintf("%v", dst), 64)
		if err1 == nil && err2 == nil {
			return sNum > dNum
		}
		if sStr, ok := src.(string); ok {
			if dNum, err := strconv.Atoi(fmt.Sprintf("%v", dst)); err == nil {
				return len(sStr) > dNum
			}
		}
		return false
	default:
		t.Fatalf("unsupported condition operator in test evaluator: %q", cond.Condition.Value)
		return false
	}
}

func resolveConditionExpression(expr string, stepOutputs map[string]interface{}) interface{} {
	trimmed := strings.TrimSpace(expr)

	// Liquid size filter: {{ $path | size }} or {{ $$path | size }}
	if strings.HasPrefix(trimmed, "{{") && strings.HasSuffix(trimmed, "}}") {
		inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "{{"), "}}"))
		parts := strings.Split(inner, "|")
		varExpr := strings.TrimSpace(parts[0])
		val := lookupVariablePath(varExpr, stepOutputs)
		if len(parts) > 1 && strings.TrimSpace(parts[1]) == "size" {
			switch v := val.(type) {
			case []interface{}:
				return len(v)
			case []map[string]interface{}:
				return len(v)
			case map[string]interface{}:
				return len(v)
			case string:
				var arr []interface{}
				if err := json.Unmarshal([]byte(v), &arr); err == nil {
					return len(arr)
				}
				return len(v)
			default:
				return 0
			}
		}
		return val
	}

	if strings.HasPrefix(trimmed, "$") {
		return lookupVariablePath(trimmed, stepOutputs)
	}

	return trimmed
}

func lookupVariablePath(varExpr string, stepOutputs map[string]interface{}) interface{} {
	clean := strings.TrimLeft(strings.TrimSpace(varExpr), "$")
	segments := strings.Split(clean, ".")
	if len(segments) == 0 {
		return nil
	}

	rootKey := strings.ToLower(segments[0])
	var current interface{}
	for k, v := range stepOutputs {
		if strings.ToLower(k) == rootKey {
			current = v
			break
		}
	}
	if current == nil {
		return nil
	}

	for _, seg := range segments[1:] {
		if strVal, ok := current.(string); ok {
			var parsed interface{}
			if err := json.Unmarshal([]byte(strVal), &parsed); err == nil {
				current = parsed
			}
		}
		switch typed := current.(type) {
		case map[string]interface{}:
			current = typed[seg]
		default:
			return nil
		}
	}
	return current
}

var (
	shuffleToolsSetupOnce sync.Once
	shuffleToolsAppDir    string
	shuffleToolsSetupErr  error
)

// ensureLocalShuffleToolsApp sets up the local Shuffle Tools 1.2.0 directory
// (app_upload/generated_apps/shuffle-tools_1.2.0) with shuffle_sdk.py and app.py
// extracted from main.py so `python3 app.py --standalone --action=execute_python --code=<code>`
// executes the real Shuffle Tools app locally.
func ensureLocalShuffleToolsApp(t *testing.T) string {
	t.Helper()
	shuffleToolsSetupOnce.Do(func() {
		appDir, err := filepath.Abs(filepath.Join("app_upload", "generated_apps", "shuffle-tools_1.2.0"))
		if err != nil {
			shuffleToolsSetupErr = fmt.Errorf("failed resolving shuffle-tools_1.2.0 path: %w", err)
			return
		}
		mainPyPath := filepath.Join(appDir, "main.py")
		mainBytes, err := os.ReadFile(mainPyPath)
		if err != nil {
			shuffleToolsSetupErr = fmt.Errorf("failed reading %s: %w", mainPyPath, err)
			return
		}

		sdkSplitMarker := "if __name__ == \"__main__\":\n    AppBase.run()\n"
		parts := strings.SplitN(string(mainBytes), sdkSplitMarker, 2)
		if len(parts) != 2 {
			shuffleToolsSetupErr = fmt.Errorf("could not locate AppBase.run() split marker in %s", mainPyPath)
			return
		}
		sdkContent := parts[0] + sdkSplitMarker

		cloudFuncMarker := "# Run the actual thing after we've checked params\ndef run(request):"
		appParts := strings.SplitN(parts[1], cloudFuncMarker, 2)
		appBody := appParts[0]
		appContent := appBody + "\nif __name__ == \"__main__\":\n    Tools.run()\n"

		sdkPath := filepath.Join(appDir, "shuffle_sdk.py")
		if err := os.WriteFile(sdkPath, []byte(sdkContent), 0644); err != nil {
			shuffleToolsSetupErr = fmt.Errorf("failed writing %s: %w", sdkPath, err)
			return
		}

		appPyPath := filepath.Join(appDir, "app.py")
		if err := os.WriteFile(appPyPath, []byte(appContent), 0644); err != nil {
			shuffleToolsSetupErr = fmt.Errorf("failed writing %s: %w", appPyPath, err)
			return
		}

		shuffleToolsAppDir = appDir
	})
	if shuffleToolsSetupErr != nil {
		t.Fatalf("Shuffle Tools local app setup failed: %v", shuffleToolsSetupErr)
	}
	return shuffleToolsAppDir
}

// executeUsecasePython runs a Shuffle execute_python script locally by invoking the actual
// Shuffle Tools app (`python3 app.py --standalone --action=execute_python --code=<code>`),
// substituting workflow variables ($exec, $exec.shuffle_datastore.key, $ioc_listing, etc.)
// and routing Shuffle SDK/API calls to our localUsecaseMockServer.
func executeUsecasePython(
	t *testing.T,
	code string,
	mockSrv *localUsecaseMockServer,
	vars map[string]interface{},
	envVars map[string]string,
) (string, map[string]interface{}) {
	t.Helper()

	appDir := ensureLocalShuffleToolsApp(t)

	// Replace raw/quoted Shuffle variable tokens (e.g. r"""$exec""", r'''$threat_feed_listing''', r"""$exec.shuffle_datastore.key""")
	// with safe base64-decoded UTF-8 strings so Python scripts receive exact JSON or scalar strings without quote-escaping issues.
	reQuotedVar := regexp.MustCompile(`(?:r?"""|r?''')\$\$?([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*)(?:"""|''')`)
	processed := reQuotedVar.ReplaceAllStringFunc(code, func(m string) string {
		sub := reQuotedVar.FindStringSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		varPath := sub[1]
		resolved := lookupVariablePath("$"+varPath, vars)
		if resolved == nil {
			return `""`
		}
		var strBytes []byte
		if s, ok := resolved.(string); ok {
			strBytes = []byte(s)
		} else {
			b, err := json.Marshal(resolved)
			if err != nil {
				return m
			}
			strBytes = b
		}
		b64 := base64.StdEncoding.EncodeToString(strBytes)
		return fmt.Sprintf(`__import__("base64").b64decode(%q).decode("utf-8")`, b64)
	})

	// Route hardcoded vulnerability API calls to our local test server.
	processed = strings.ReplaceAll(processed, "https://shuffler.io/api/v1/vulnerabilities", mockSrv.server.URL+"/api/v1/vulnerabilities")
	processed = strings.ReplaceAll(processed, "https://api.osv.dev/v1/query", mockSrv.server.URL+"/api/v1/vulnerabilities")

	// Escape any remaining literal '$' in Python source code (such as startswith("$") or regex anchors)
	// so AppBase.parse_params restores them cleanly to '$' without treating them as workflow variables.
	processed = strings.ReplaceAll(processed, "$", `\$`)

	// Prepend proxy-bypass opener and liquid/wrapper skip markers so AppBase.parse_params and
	// AppBase.parse_wrapper_start pass the multi-line Python source straight to Tools.execute_python(code).
	preamble := fmt.Sprintf(
		"[1] # \\${skip_liquid}\\$\nimport os, urllib.request\nurllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))\nos.environ.setdefault(\"BASE_URL\", %q)\nos.environ.setdefault(\"SHUFFLE_BACKEND_URL\", %q)\nos.environ.setdefault(\"AUTHORIZATION\", \"standalone\")\nos.environ.setdefault(\"ORG_ID\", \"STANDALONE\")\n",
		mockSrv.server.URL,
		mockSrv.server.URL,
	)
	fullCode := preamble + processed + "\n{1}"

	cmd := exec.Command(
		"python3",
		"app.py",
		"--standalone",
		"--action=execute_python",
		"--code="+fullCode,
	)
	cmd.Dir = appDir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	cmd.Env = cmd.Environ()
	cmd.Env = append(cmd.Env,
		"CALLBACK_URL="+mockSrv.server.URL,
		"BASE_URL="+mockSrv.server.URL,
		"SHUFFLE_BACKEND_URL="+mockSrv.server.URL,
		"SHUFFLE_LOGS_DISABLED=true",
		"SHUFFLE_INTERNAL_HTTP_PROXY=",
		"SHUFFLE_INTERNAL_HTTPS_PROXY=",
		"HTTP_PROXY=",
		"HTTPS_PROXY=",
		"http_proxy=",
		"https_proxy=",
		"NO_PROXY=127.0.0.1,localhost",
		"no_proxy=127.0.0.1,localhost",
	)
	for k, v := range envVars {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	if err := cmd.Run(); err != nil {
		t.Fatalf("Shuffle Tools app.py execute_python failed: %v\nSTDERR:\n%s\nSTDOUT:\n%s", err, stderr.String(), stdout.String())
	}

	fullStdout := stdout.String()
	const resultMarker = "===== Successful result From the Function"
	idx := strings.LastIndex(fullStdout, resultMarker)
	if idx == -1 {
		t.Fatalf("did not find standalone result marker in app.py output.\nSTDERR:\n%s\nSTDOUT:\n%s", stderr.String(), fullStdout)
	}
	afterMarker := fullStdout[idx:]
	if nl := strings.IndexByte(afterMarker, '\n'); nl != -1 {
		afterMarker = strings.TrimSpace(afterMarker[nl+1:])
	}

	var outer map[string]interface{}
	if err := json.Unmarshal([]byte(afterMarker), &outer); err != nil {
		t.Fatalf("failed to unmarshal Tools.execute_python JSON result: %v\nRAW:\n%s", err, afterMarker)
	}
	if succ, ok := outer["success"].(bool); !ok || !succ {
		t.Fatalf("Tools.execute_python returned success=false: %v\nSTDERR:\n%s", outer, stderr.String())
	}

	var rawOut string
	var parsed map[string]interface{}
	switch msg := outer["message"].(type) {
	case map[string]interface{}:
		parsed = msg
		b, _ := json.Marshal(msg)
		rawOut = string(b)
	case string:
		rawOut = strings.TrimSpace(msg)
		if err := json.Unmarshal([]byte(rawOut), &parsed); err != nil {
			lines := strings.Split(rawOut, "\n")
			for i := len(lines) - 1; i >= 0; i-- {
				line := strings.TrimSpace(lines[i])
				if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
					if err2 := json.Unmarshal([]byte(line), &parsed); err2 == nil {
						break
					}
				}
			}
		}
	default:
		b, _ := json.Marshal(msg)
		rawOut = string(b)
	}

	return rawOut, parsed
}

// executeShuffleToolsAction executes a non-Python Shuffle Tools action (such as list_datastore_category)
// by running `python3 app.py --standalone --action=<name> --<param>=<val>...` in the local Shuffle Tools directory.
func executeShuffleToolsAction(
	t *testing.T,
	act *Action,
	mockSrv *localUsecaseMockServer,
	orgId string,
) (string, interface{}) {
	t.Helper()

	appDir := ensureLocalShuffleToolsApp(t)
	args := []string{
		"app.py",
		"--standalone",
		"--action=" + act.Name,
		"--shuffle_url=" + mockSrv.server.URL,
	}
	for _, p := range act.Parameters {
		args = append(args, fmt.Sprintf("--%s=%s", p.Name, p.Value))
	}

	fullExecJSON, _ := json.Marshal(map[string]interface{}{
		"workflow": map[string]interface{}{
			"id":       "wf-routing-local",
			"branches": []interface{}{},
			"execution_org": map[string]interface{}{
				"id": orgId,
			},
		},
		"results": []interface{}{},
	})

	cmd := exec.Command("python3", args...)
	cmd.Dir = appDir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	cmd.Env = append(cmd.Environ(),
		"CALLBACK_URL="+mockSrv.server.URL,
		"BASE_URL="+mockSrv.server.URL,
		"SHUFFLE_BACKEND_URL="+mockSrv.server.URL,
		"FULL_EXECUTION="+string(fullExecJSON),
		"SHUFFLE_LOGS_DISABLED=true",
		"SHUFFLE_INTERNAL_HTTP_PROXY=",
		"SHUFFLE_INTERNAL_HTTPS_PROXY=",
		"HTTP_PROXY=",
		"HTTPS_PROXY=",
		"http_proxy=",
		"https_proxy=",
		"NO_PROXY=127.0.0.1,localhost",
		"no_proxy=127.0.0.1,localhost",
	)

	if err := cmd.Run(); err != nil {
		t.Fatalf("Shuffle Tools app.py --action=%s failed: %v\nSTDERR:\n%s\nSTDOUT:\n%s", act.Name, err, stderr.String(), stdout.String())
	}

	fullStdout := stdout.String()
	const resultMarker = "===== Successful result From the Function"
	idx := strings.LastIndex(fullStdout, resultMarker)
	if idx == -1 {
		t.Fatalf("did not find standalone result marker in app.py --action=%s output.\nSTDERR:\n%s\nSTDOUT:\n%s", act.Name, stderr.String(), fullStdout)
	}
	afterMarker := fullStdout[idx:]
	if nl := strings.IndexByte(afterMarker, '\n'); nl != -1 {
		afterMarker = strings.TrimSpace(afterMarker[nl+1:])
	}

	var parsed interface{}
	if err := json.Unmarshal([]byte(afterMarker), &parsed); err != nil {
		t.Fatalf("failed to unmarshal Tools.%s JSON result: %v\nRAW:\n%s", act.Name, err, afterMarker)
	}
	return afterMarker, parsed
}

// resolveActionTemplateString interpolates Shuffle `$step.field` references inside an action parameter string
// (such as OpenAPI `url`, `headers`, and `body`).
func resolveActionTemplateString(raw string, vars map[string]interface{}) string {
	reVar := regexp.MustCompile(`\$([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*)`)
	return reVar.ReplaceAllStringFunc(raw, func(m string) string {
		val := lookupVariablePath(m, vars)
		if val == nil {
			return m
		}
		switch v := val.(type) {
		case string:
			return v
		default:
			b, err := json.Marshal(v)
			if err != nil {
				return fmt.Sprintf("%v", v)
			}
			return string(b)
		}
	})
}

// executeOpenApiAction executes a generated `shuffle_openapi` action (such as `post_count_custom_stats`
// or `post_add_a_key`) by resolving its parameters (`url`, `headers`, `body`, `queries`, `org_id`, `ssl_verify`, `to_file`)
// from `stepOutputs` and sending the real HTTP request to `localUsecaseMockServer`.
func executeOpenApiAction(
	t *testing.T,
	act *Action,
	mockSrv *localUsecaseMockServer,
	vars map[string]interface{},
) (string, map[string]interface{}) {
	t.Helper()

	var endpointPath string
	switch act.Name {
	case "post_count_custom_stats":
		endpointPath = "/api/v1/stats"
	case "post_add_a_key":
		endpointPath = "/api/v2/datastore"
	default:
		t.Fatalf("unsupported shuffle_openapi action %q in test executor", act.Name)
	}

	rawUrl, _ := getActionParam(act, "url")
	resolvedBaseUrl := strings.TrimSpace(resolveActionTemplateString(rawUrl, vars))
	targetUrl := mockSrv.server.URL + endpointPath

	rawHeaders, _ := getActionParam(act, "headers")
	resolvedHeaders := resolveActionTemplateString(rawHeaders, vars)

	rawBody, _ := getActionParam(act, "body")
	resolvedBody := resolveActionTemplateString(rawBody, vars)

	req, err := http.NewRequest(http.MethodPost, targetUrl, strings.NewReader(resolvedBody))
	if err != nil {
		t.Fatalf("failed creating HTTP request for %s (%s): %v", act.Label, act.Name, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if act.AuthenticationId != "" {
		req.Header.Set("Authorization", "Bearer "+act.AuthenticationId)
	}
	if resolvedBaseUrl != "" {
		req.Header.Set("X-Resolved-Regional-Url", resolvedBaseUrl)
	}
	for _, line := range strings.Split(resolvedHeaders, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP request for %s (%s) failed: %v", act.Label, act.Name, err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("HTTP request for %s (%s) returned status %d: %s", act.Label, act.Name, resp.StatusCode, string(respBytes))
	}

	var parsed map[string]interface{}
	_ = json.Unmarshal(respBytes, &parsed)
	return resolvedBaseUrl, parsed
}

// TestUsecaseCatalogAndTargetCategories verifies that GetUsecaseData returns valid JSON
// with all categories and subitems, and that resolveRoutingDatastoreCategory maps each
// routing category to its expected Shuffle Datastore category.
func TestUsecaseCatalogAndTargetCategories(t *testing.T) {
	rawCatalog := GetUsecaseData()
	if strings.TrimSpace(rawCatalog) == "" {
		t.Fatal("expected GetUsecaseData() to return non-empty JSON")
	}

	var categories []map[string]interface{}
	if err := json.Unmarshal([]byte(rawCatalog), &categories); err != nil {
		t.Fatalf("expected GetUsecaseData() to return valid JSON array, got error: %v", err)
	}
	if len(categories) == 0 {
		t.Fatal("expected at least one usecase category in GetUsecaseData()")
	}

	totalSubitems := 0
	for _, cat := range categories {
		list, _ := cat["list"].([]interface{})
		totalSubitems += len(list)
	}
	if totalSubitems == 0 {
		t.Fatal("expected usecase categories to contain subitems in 'list'")
	}

	cases := []struct {
		actionType string
		catAction  CategoryAction
		expected   string
	}{
		{"incident_routing_rules", CategoryAction{}, "shuffle-security_incidents"},
		{"automated_routing", CategoryAction{}, "shuffle-security_incidents"},
		{"vulnerability_routing_rules", CategoryAction{}, "shuffle-security_vulns"},
		{"asset_routing_rules", CategoryAction{}, "shuffle-security_assets"},
		{"infrastructure_routing_rules", CategoryAction{}, "shuffle-security_infrastructure"},
		{"package_routing_rules", CategoryAction{}, "shuffle-security_packages"},
		{"software_routing_rules", CategoryAction{}, "shuffle-security_software"},
		{"user_routing_rules", CategoryAction{}, "shuffle-security_users"},
		{"automated_routing_rules", CategoryAction{Category: "Vulnerabilities"}, "shuffle-security_vulns"},
		{"automated_routing_rules", CategoryAction{Label: "asset_routing"}, "shuffle-security_assets"},
	}

	for _, tc := range cases {
		got := resolveRoutingDatastoreCategory(tc.actionType, tc.catAction)
		if got != tc.expected {
			t.Errorf("resolveRoutingDatastoreCategory(%q, %+v) = %q, want %q", tc.actionType, tc.catAction, got, tc.expected)
		}
	}
}

// TestAllUsecasesEndToEnd tests each individual usecase workflow from start to finish locally,
// feeding realistic sample data through triggers, actions, branch conditions, and Python scripts.
func TestAllUsecasesEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available in PATH")
	}

	const orgId = "org-local-test-001"

	t.Run("1_CorrelateCategories", func(t *testing.T) {
		wf := generateTestWorkflow(t, orgId, "correlate_categories", "", CategoryAction{})
		if len(wf.Actions) != 1 {
			t.Fatalf("expected 1 action in correlate_categories workflow, got %d", len(wf.Actions))
		}
		startAction := findActionByLabel(wf, "Start")
		if startAction == nil {
			t.Fatal("expected 'Start' action in correlate_categories workflow")
		}
		if startAction.AppName != "Shuffle Tools" || startAction.Name != "repeat_back_to_me" {
			t.Fatalf("unexpected Start action: %s / %s", startAction.AppName, startAction.Name)
		}
		if wf.Start != startAction.ID {
			t.Fatalf("expected workflow Start ID %q to match Start action ID %q", wf.Start, startAction.ID)
		}
	})

	t.Run("2_ForwardTickets_And_ForwardIncidents", func(t *testing.T) {
		for _, usecaseType := range []string{"forward_tickets", "forward_incidents"} {
			wf := generateTestWorkflow(t, orgId, usecaseType, "jira,servicenow", CategoryAction{})
			startAction := findActionByLabel(wf, "Start")
			if startAction == nil {
				t.Fatalf("[%s] missing Start action", usecaseType)
			}

			jiraAction := findActionByLabel(wf, "jira")
			snowAction := findActionByLabel(wf, "servicenow")
			if jiraAction == nil || snowAction == nil {
				t.Fatalf("[%s] expected Singul replicated actions for 'jira' and 'servicenow', got %d actions", usecaseType, len(wf.Actions))
			}

			for _, act := range []*Action{jiraAction, snowAction} {
				if act.AppName != "Singul" || act.Name != "Cases" {
					t.Errorf("[%s] expected Singul Cases action, got %s/%s", usecaseType, act.AppName, act.Name)
				}
				actionParam, _ := getActionParam(act, "action")
				fieldsParam, _ := getActionParam(act, "fields")
				if actionParam != "Create ticket" || fieldsParam != "data=$exec" {
					t.Errorf("[%s] unexpected Singul params: action=%q fields=%q", usecaseType, actionParam, fieldsParam)
				}
			}

			if len(wf.Branches) < 2 {
				t.Fatalf("[%s] expected at least 2 branches from Start to replicated apps, got %d", usecaseType, len(wf.Branches))
			}
		}
	})

	t.Run("3_IngestScheduled_Tickets_Assets_Users_Vulnerabilities", func(t *testing.T) {
		cases := []struct {
			usecaseType    string
			apps           string
			expectedName   string
			expectedAction string
		}{
			{"ingest_tickets", "jira,thehive", "Cases", "List tickets"},
			{"ingest_assets", "crowdstrike", "Assets", "List assets"},
			{"ingest_users", "okta", "IAM", "List users"},
			{"ingest_vulnerabilities", "tenable", "Assets", "List vulnerabilities"},
		}

		for _, tc := range cases {
			wf := generateTestWorkflow(t, orgId, tc.usecaseType, tc.apps, CategoryAction{})
			if len(wf.Triggers) == 0 || wf.Triggers[0].TriggerType != "SCHEDULE" {
				t.Fatalf("[%s] expected SCHEDULE trigger", tc.usecaseType)
			}

			firstApp := strings.Split(tc.apps, ",")[0]
			replicated := findActionByLabel(wf, firstApp)
			if replicated == nil {
				t.Fatalf("[%s] expected replicated action with label %q", tc.usecaseType, firstApp)
			}
			if replicated.AppName != "Singul" || replicated.Name != tc.expectedName {
				t.Errorf("[%s] expected Singul/%s, got %s/%s", tc.usecaseType, tc.expectedName, replicated.AppName, replicated.Name)
			}
			actVal, _ := getActionParam(replicated, "action")
			fieldsVal, _ := getActionParam(replicated, "fields")
			if actVal != tc.expectedAction || fieldsVal != "amount=10" {
				t.Errorf("[%s] unexpected params: action=%q fields=%q", tc.usecaseType, actVal, fieldsVal)
			}
		}
	})

	t.Run("4_IngestTicketsWebhook_And_VulnerabilitiesWebhook", func(t *testing.T) {
		cases := []struct {
			usecaseType      string
			expectedStandard string
		}{
			{"ingest_tickets_webhook", "OCSF"},
			{"vulnerabilities_webhook", "vulnerability"},
		}

		for _, tc := range cases {
			wf := generateTestWorkflow(t, orgId, tc.usecaseType, "", CategoryAction{})
			if len(wf.Triggers) == 0 || wf.Triggers[0].TriggerType != "WEBHOOK" {
				t.Fatalf("[%s] expected WEBHOOK trigger", tc.usecaseType)
			}
			act := findActionByLabel(wf, "Ingest Ticket from Webhook")
			if act == nil {
				t.Fatalf("[%s] expected 'Ingest Ticket from Webhook' action", tc.usecaseType)
			}
			if act.AppName != "Singul" || act.Name != "Translate standard" {
				t.Errorf("[%s] expected Singul/Translate standard, got %s/%s", tc.usecaseType, act.AppName, act.Name)
			}
			srcData, _ := getActionParam(act, "source_data")
			stdVal, _ := getActionParam(act, "standard")
			if srcData != "$exec" || stdVal != tc.expectedStandard {
				t.Errorf("[%s] unexpected params: source_data=%q standard=%q", tc.usecaseType, srcData, stdVal)
			}
		}
	})

	t.Run("5_Notifications_And_ForwardNotifications", func(t *testing.T) {
		for _, usecaseType := range []string{"notification", "notifications", "forward_notification", "forward_notifications"} {
			wf := generateTestWorkflow(t, orgId, usecaseType, "slack,teams", CategoryAction{})
			slackAct := findActionByLabel(wf, "slack")
			teamsAct := findActionByLabel(wf, "teams")
			if slackAct == nil || teamsAct == nil {
				t.Fatalf("[%s] expected Singul replicated actions for slack and teams", usecaseType)
			}
			for _, act := range []*Action{slackAct, teamsAct} {
				if act.AppName != "Singul" || act.Name != "communication" {
					t.Errorf("[%s] expected Singul/communication, got %s/%s", usecaseType, act.AppName, act.Name)
				}
				actParam, _ := getActionParam(act, "action")
				fieldsParam, _ := getActionParam(act, "fields")
				if actParam != "Send message" || fieldsParam != "$exec" {
					t.Errorf("[%s] unexpected params: action=%q fields=%q", usecaseType, actParam, fieldsParam)
				}
			}
		}
	})

	t.Run("6_ThreatlistMonitorWebhook_EndToEnd", func(t *testing.T) {
		mockSrv := newLocalUsecaseMockServer(t)
		wf := generateTestWorkflow(t, orgId, "threatlist_monitor_webhook", "", CategoryAction{})

		iocListingAct := findActionByLabel(wf, "IOC listing")
		enrichAct := findActionByLabel(wf, "Add enrichments to entry")
		if iocListingAct == nil || enrichAct == nil {
			t.Fatalf("expected 'IOC listing' and 'Add enrichments to entry' actions in threatlist_monitor_webhook")
		}

		catParam, _ := getActionParam(iocListingAct, "category")
		if catParam != "shuffle-security_ioc-config" {
			t.Fatalf("expected IOC listing category 'shuffle-security_ioc-config', got %q", catParam)
		}

		// Step 1 output: IOC regex configurations from datastore
		sampleIocConfig := []map[string]interface{}{
			{
				"name":    "ipv4",
				"enabled": true,
				"regex":   `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
			},
			{
				"name":    "domain",
				"enabled": true,
				"regex":   `\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|io)\b`,
			},
		}

		// Sample webhook execution input ($exec) containing IOCs and shuffle_datastore pointer
		sampleExec := map[string]interface{}{
			"title":       "Outbound beacon to 198.51.100.77 and c2.badactor.org",
			"description": "Suspicious traffic detected from workstation to 198.51.100.77",
			"shuffle_datastore": map[string]interface{}{
				"key":      "inc-webhook-001",
				"category": "shuffle-security_incidents",
				"org_id":   orgId,
			},
		}

		code, _ := getActionParam(enrichAct, "code")
		_, out := executeUsecasePython(t, code, mockSrv, map[string]interface{}{
			"exec":        sampleExec,
			"ioc_listing": sampleIocConfig,
		}, nil)

		if out == nil || out["success"] != true {
			t.Fatalf("expected threatlist_monitor_webhook python script to succeed, got: %+v", out)
		}

		if len(mockSrv.bulkPostCalls) == 0 {
			t.Fatal("expected threatlist_monitor_webhook script to POST enrichments to /api/v2/datastore?bulk=true")
		}
		postedItem := mockSrv.bulkPostCalls[0][0]
		if postedItem["key"] != "inc-webhook-001" || postedItem["category"] != "shuffle-security_incidents" {
			t.Errorf("unexpected datastore bulk target: %+v", postedItem)
		}
		enrichments, _ := postedItem["enrichments"].([]interface{})
		if len(enrichments) == 0 {
			t.Errorf("expected extracted IOC enrichments to be non-empty, got: %+v", postedItem["enrichments"])
		}
	})

	t.Run("7_ThreatlistMonitor_ScheduledIngestion_EndToEnd", func(t *testing.T) {
		mockSrv := newLocalUsecaseMockServer(t)
		wf := generateTestWorkflow(t, orgId, "threatlist_monitor", "", CategoryAction{})

		feedListAct := findActionByLabel(wf, "Threat feed listing")
		iocListAct := findActionByLabel(wf, "IOC listing")
		ingestAct := findActionByLabel(wf, "Ingest IOCs")
		if feedListAct == nil || iocListAct == nil || ingestAct == nil {
			t.Fatalf("missing actions in threatlist_monitor workflow")
		}

		// Step 1 output: Threat feed list (enabled=true)
		sampleFeeds := []map[string]interface{}{
			{
				"url":         mockSrv.server.URL + "/threat-feed.csv",
				"name":        "Local Abuse.ch Mock Feed",
				"description": "Test CSV threat feed",
				"enabled":     true,
			},
		}

		// Step 2 output: IOC regex list
		sampleIocConfig := []map[string]interface{}{
			{
				"name":    "ipv4",
				"enabled": true,
				"regex":   `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
			},
		}

		stepOutputs := map[string]interface{}{
			"threat_feed_listing": sampleFeeds,
			"ioc_listing":         sampleIocConfig,
		}

		// Verify conditional branch between Threat feed listing and IOC listing
		condBranches := findConditionalBranches(wf)
		if len(condBranches) == 0 {
			t.Fatal("expected conditional branch in threatlist_monitor workflow")
		}
		if !evaluateUsecaseCondition(t, condBranches[0].Conditions[0], stepOutputs) {
			t.Fatal("expected branch condition {{ $$threat_feed_listing | size }} > 0 to evaluate to true")
		}

		// Step 3: Run Ingest IOCs Python script against local threat feed CSV
		code, _ := getActionParam(ingestAct, "code")
		_, out := executeUsecasePython(t, code, mockSrv, stepOutputs, nil)

		if out == nil {
			t.Fatal("expected JSON output from Ingest IOCs script")
		}
		uploadedIPs, _ := out["uploaded_ipv4"].(float64)
		if uploadedIPs < 1 {
			t.Fatalf("expected uploaded_ipv4 >= 1 from threat feed CSV, got: %+v", out)
		}
		if _, ok := mockSrv.getDatastoreValue("ioc_ipv4", "198.51.100.77"); !ok {
			t.Fatal("expected 198.51.100.77 to be stored in datastore category 'ioc_ipv4'")
		}
	})

	t.Run("8_VulnerabilityCorrelation_PackageAndIncidentModes_EndToEnd", func(t *testing.T) {
		mockSrv := newLocalUsecaseMockServer(t)
		wf := generateTestWorkflow(t, orgId, "vulnerability_correlation", "", CategoryAction{})

		verifyAct := findActionByLabel(wf, "verify_package_vulnerability")
		uploadAct := findActionByLabel(wf, "Create ticket")
		if verifyAct == nil || uploadAct == nil {
			t.Fatal("expected verify_package_vulnerability and Create ticket actions in vulnerability_correlation")
		}

		code, _ := getActionParam(verifyAct, "code")

		// Seed package in datastore so package correlation mode can update it with correlated CVEs
		packageKey := "pkg-log4j-2.14.1"
		packageExec := map[string]interface{}{
			"name":      "log4j-core",
			"version":   "2.14.1",
			"os":        "Maven",
			"ecosystem": "Maven",
			"purl":      "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			"type":      "maven",
			"hostnames": []map[string]interface{}{
				{"hostname": "prod-web-01", "version": "2.14.1", "user": "root"},
			},
			"shuffle_datastore": map[string]interface{}{
				"key":      packageKey,
				"category": "shuffle-security_packages",
				"org_id":   orgId,
			},
		}
		mockSrv.seedDatastore("shuffle-security_packages", packageKey, packageExec)

		// Subtest A: Package / Software mode
		_, pkgOut := executeUsecasePython(t, code, mockSrv, map[string]interface{}{
			"exec": packageExec,
		}, nil)

		if pkgOut == nil || pkgOut["success"] != true || pkgOut["mode"] != "package" {
			t.Fatalf("expected package mode correlation to succeed, got: %+v", pkgOut)
		}
		vulnCount, _ := pkgOut["vuln_count"].(float64)
		if vulnCount < 1 {
			t.Fatalf("expected vuln_count >= 1 in package mode, got: %+v", pkgOut)
		}

		// Verify conditional branch ({{ $$verify_package_vulnerability.vuln_count }} > 0)
		stepOutputs := map[string]interface{}{
			"verify_package_vulnerability": pkgOut,
		}
		condBranches := findConditionalBranches(wf)
		if len(condBranches) == 0 || !evaluateUsecaseCondition(t, condBranches[0].Conditions[0], stepOutputs) {
			t.Fatal("expected branch condition verify_package_vulnerability.vuln_count > 0 to pass")
		}

		// Verify CVE was stored in shuffle-security_vulns datastore
		if _, ok := mockSrv.getDatastoreValue("shuffle-security_vulns", "CVE-2024-99999"); !ok {
			t.Fatal("expected CVE-2024-99999 to be saved in shuffle-security_vulns datastore")
		}

		// Subtest B: Incident correlation mode (correlates stored package + CVE onto an incident)
		incidentExec := map[string]interface{}{
			"finding_uid": "inc-vuln-001",
			"title":       "Exploit attempt on prod-web-01",
			"observables": []map[string]interface{}{
				{"name": "hostname", "type": "hostname", "value": "prod-web-01"},
				{"name": "package", "type": "package", "value": packageKey},
				{"name": "cve", "type": "cve", "value": "CVE-2024-99999"},
			},
			"shuffle_datastore": map[string]interface{}{
				"key":      "inc-vuln-001",
				"category": "shuffle-security_incidents",
				"org_id":   orgId,
			},
		}

		_, incOut := executeUsecasePython(t, code, mockSrv, map[string]interface{}{
			"exec": incidentExec,
		}, nil)

		if incOut == nil || incOut["success"] != true || incOut["mode"] != "incident" {
			t.Fatalf("expected incident mode correlation to succeed, got: %+v", incOut)
		}
		corrCount, _ := incOut["correlated_count"].(float64)
		if corrCount < 1 {
			t.Fatalf("expected correlated_count >= 1 in incident mode, got: %+v", incOut)
		}
	})

	t.Run("9_AssignAndEscalate_EndToEnd", func(t *testing.T) {
		mockSrv := newLocalUsecaseMockServer(t)
		wf := generateTestWorkflow(t, orgId, "assign_&_escalate", "", CategoryAction{})

		getSchedAct := findActionByLabel(wf, "Get_assignment_schedules")
		findPeopleAct := findActionByLabel(wf, "Find_relevant_people")
		connectAct := findActionByLabel(wf, "Connect_to_responder")
		aiPrepAct := findActionByLabel(wf, "Handle_AI_Agent_run")
		runQuestionsAct := findActionByLabel(wf, "Run_questions")
		aiRespAct := findActionByLabel(wf, "Add_AI_response")

		if getSchedAct == nil || findPeopleAct == nil || connectAct == nil || aiPrepAct == nil || runQuestionsAct == nil || aiRespAct == nil {
			t.Fatal("missing expected actions in assign_&_escalate workflow")
		}

		// Seed incident in datastore with an unhandled @AIAgent activity request
		incidentKey := "inc-assign-001"
		sampleIncident := map[string]interface{}{
			"id":          incidentKey,
			"key":         incidentKey,
			"finding_uid": incidentKey,
			"title":       "Critical Ransomware Alert on Finance Host",
			"severity":    "Critical",
			"severity_id": 5,
			"status":      "New",
			"activity": []map[string]interface{}{
				{
					"id":         "act-ai-req-1",
					"type":       "comment",
					"user":       "analyst@example.com",
					"content":    "@AIAgent Summarize root cause and affected hostnames.",
					"ai_handled": false,
				},
			},
			"shuffle_datastore": map[string]interface{}{
				"key":      incidentKey,
				"category": "shuffle-security_incidents",
				"org_id":   orgId,
			},
		}
		mockSrv.seedDatastore("shuffle-security_incidents", incidentKey, sampleIncident)

		// Step 1 output: Get_assignment_schedules matching getRelevantPeopleCode schema
		scheduleOutput := map[string]interface{}{
			"success": true,
			"value": map[string]interface{}{
				"userSchedules": []map[string]interface{}{
					{
						"enabled":         true,
						"userName":        "alice@example.com",
						"userEmail":       "alice@example.com",
						"email":           "alice@example.com",
						"escalationLevel": "tier1",
						"schedules": []map[string]interface{}{
							{
								"timezone":  "UTC",
								"startDate": "2020-01-01",
								"endDate":   "2035-12-31",
								"startTime": "00:00:00",
								"endTime":   "23:59:59",
							},
						},
					},
				},
			},
		}

		stepOutputs := map[string]interface{}{
			"exec":                     sampleIncident,
			"get_assignment_schedules": scheduleOutput,
			"get_assigned_apps": map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"agent": "default",
						"tools": []map[string]interface{}{
							{"name": "shuffle_incidents"},
						},
					},
				},
			},
		}

		// Verify conditional branch: {{ $get_assignment_schedules.value.userSchedules | size }} > 0
		condBranches := findConditionalBranches(wf)
		if len(condBranches) == 0 || !evaluateUsecaseCondition(t, condBranches[0].Conditions[0], stepOutputs) {
			t.Fatal("expected userSchedules size > 0 branch condition to pass")
		}

		// Step 2: Execute Find_relevant_people
		findCode, _ := getActionParam(findPeopleAct, "code")
		_, findOut := executeUsecasePython(t, findCode, mockSrv, stepOutputs, nil)
		if findOut == nil || findOut["assign"] != "alice@example.com" {
			t.Fatalf("expected Find_relevant_people to assign alice@example.com, got: %+v", findOut)
		}
		stepOutputs["find_relevant_people"] = findOut

		// Step 3: Execute Connect_to_responder (pages assigned responder via /api/v1/functions/pager)
		connectCode, _ := getActionParam(connectAct, "code")
		_, connectOut := executeUsecasePython(t, connectCode, mockSrv, stepOutputs, nil)
		if connectOut == nil || connectOut["success"] != true || connectOut["pager_dispatched"] != true {
			t.Fatalf("expected Connect_to_responder to dispatch pager alert, got: %+v", connectOut)
		}
		if len(mockSrv.pagerCalls) == 0 {
			t.Fatal("expected Connect_to_responder to send alert to /api/v1/functions/pager")
		}

		// Step 4: Execute Handle_AI_Agent_run (marks @AIAgent activity handled and assigns responder)
		aiPrepCode, _ := getActionParam(aiPrepAct, "code")
		_, aiPrepOut := executeUsecasePython(t, aiPrepCode, mockSrv, stepOutputs, nil)
		if aiPrepOut == nil || aiPrepOut["updated"] != true {
			t.Fatalf("expected Handle_AI_Agent_run to update incident in datastore, got: %+v", aiPrepOut)
		}
		stepOutputs["handle_ai_agent_run"] = map[string]interface{}{
			"message": aiPrepOut,
		}

		// Simulate Step 5 (Run_questions AI Agent LLM output) and run Step 6 (Add_AI_response)
		stepOutputs["run_questions"] = map[string]interface{}{
			"status": "FINISHED",
			"output": "AI Summary: Ransomware detected on Finance Host. Isolate host immediately.",
		}
		aiRespCode, _ := getActionParam(aiRespAct, "code")
		_, aiRespOut := executeUsecasePython(t, aiRespCode, mockSrv, stepOutputs, nil)
		if aiRespOut == nil || aiRespOut["success"] != true || aiRespOut["updated"] != true {
			t.Fatalf("expected Add_AI_response to succeed and persist AI reply comment, got: %+v", aiRespOut)
		}
	})

	t.Run("10_RoutingRules_AllCategories_NestedLogic_Encodings_Stats_And_CloudMoveToTenant", func(t *testing.T) {
		mockSrv := newLocalUsecaseMockServer(t)

		// Enable cloud environment so Set_key_in_target_tenant includes dynamic regional URL
		prevEnv := project.Environment
		project.Environment = "cloud"
		t.Cleanup(func() {
			project.Environment = prevEnv
		})

		wf := generateTestWorkflow(t, orgId, "incident_routing_rules", "", CategoryAction{})

		listRulesAct := findActionByLabel(wf, "Get_all_rules_from_the_system")
		validateAct := findActionByLabel(wf, "Find_relevant_rules_for_category")
		executeAct := findActionByLabel(wf, "Execute_rule_automation_for_found_rules")
		statsAct := findActionByLabel(wf, "Update_rule_statistics")
		moveTenantAct := findActionByLabel(wf, "Set_key_in_target_tenant")

		if listRulesAct == nil || validateAct == nil || executeAct == nil || statsAct == nil || moveTenantAct == nil {
			t.Fatal("missing expected actions in incident_routing_rules workflow")
		}

		// Verify Shuffle OpenAPI actions have optional parameters (queries, org_id, ssl_verify, to_file),
		// authentication_id populated from cached shuffle_openapi app auth,
		// and cloud dynamic regional url on Set_key_in_target_tenant
		for _, openApiAct := range []*Action{statsAct, moveTenantAct} {
			if openApiAct.AuthenticationId != "auth-openapi-local-123" {
				t.Errorf("expected action %q to have AuthenticationId 'auth-openapi-local-123', got %q", openApiAct.Label, openApiAct.AuthenticationId)
			}
			for _, optionalParam := range []string{"queries", "org_id", "ssl_verify", "to_file"} {
				if _, ok := getActionParam(openApiAct, optionalParam); !ok {
					t.Errorf("expected Shuffle OpenAPI action %q to include optional parameter %q", openApiAct.Label, optionalParam)
				}
			}
		}
		if moveTenantAct.Name != "post_add_a_key" {
			t.Errorf("expected Set_key_in_target_tenant action name 'post_add_a_key', got %q", moveTenantAct.Name)
		}
		moveUrlParam, hasUrl := getActionParam(moveTenantAct, "url")
		if !hasUrl || !strings.Contains(moveUrlParam, "target_region_url") {
			t.Errorf("expected cloud Set_key_in_target_tenant action to have dynamic regional url param, got %q", moveUrlParam)
		}

		// Create a base64-encoded command payload to verify automatic encoded + decoded validation
		encodedCmd := base64.StdEncoding.EncodeToString([]byte("powershell.exe -nop -w hidden -c Invoke-Mimikatz"))

		incidentKey := "inc-routing-001"
		sampleIncident := map[string]interface{}{
			"key":         incidentKey,
			"finding_uid": incidentKey,
			"title":       "Suspicious Encoded PowerShell Execution",
			"severity":    "Medium",
			"severity_id": 3,
			"status":      "New",
			"encoded_cmd": encodedCmd,
			"device": map[string]interface{}{
				"hostname": "fin-wks-42",
				"network": map[string]interface{}{
					"interfaces": []map[string]interface{}{
						{"ip": "10.20.30.40", "mac": "00:11:22:33:44:55"},
					},
				},
			},
			"shuffle_datastore": map[string]interface{}{
				"key":      incidentKey,
				"category": "shuffle-security_incidents",
				"org_id":   orgId,
			},
		}
		mockSrv.seedDatastore("shuffle-security_incidents", incidentKey, sampleIncident)

		// Define routing rules testing:
		// 1. Deeply nested fields (device.network.interfaces.0.ip)
		// 2. Base64 decoded content matching (encoded_cmd contains "Invoke-Mimikatz")
		// 3. Nested conditionTree (AND + OR boolean tree)
		// 4. Multiple actions: set_severity, set_status, add_label, add_comment, assign_to, suggest_move (with targetRegion)
		sampleRules := []map[string]interface{}{
			{
				"id":       "rule-nested-b64-001",
				"name":     "Escalate & Route Mimikatz on Finance Subnet",
				"category": "incidents",
				"enabled":  true,
				"priority": 10,
				"conditionTree": map[string]interface{}{
					"kind": "group",
					"op":   "and",
					"children": []map[string]interface{}{
						{
							"kind":  "condition",
							"field": "device.network.interfaces.0.ip",
							"op":    "starts_with",
							"value": "10.20.30.",
						},
						{
							"kind": "group",
							"op":   "or",
							"children": []map[string]interface{}{
								{
									"kind":  "condition",
									"field": "encoded_cmd",
									"op":    "contains",
									"value": "Invoke-Mimikatz",
								},
								{
									"kind":  "condition",
									"field": "title",
									"op":    "contains",
									"value": "UnrelatedAlertTitle",
								},
							},
						},
					},
				},
				"actions": []map[string]interface{}{
					{"type": "set_severity", "value": "Critical"},
					{"type": "set_status", "value": "In Progress"},
					{"type": "add_label", "value": "mimikatz-detected"},
					{"type": "add_comment", "value": "Auto-escalated by Routing Editor rule"},
					{"type": "assign_to", "value": "soc-tier2@example.com"},
					{
						"type":            "suggest_move",
						"targetOrgId":     "org-child-eu-999",
						"targetOrgName":   "EU Child Org",
						"targetRegion":    "frankfurt",
						"targetRegionUrl": "https://frankfurt.shuffler.io",
					},
				},
			},
		}

		// Seed the routing rule into the local datastore category "shuffle-security_routing"
		// and execute Step 1 (Get_all_rules_from_the_system) via `python3 app.py --standalone --action=list_datastore_category`
		mockSrv.seedDatastore("shuffle-security_routing", "rule-nested-b64-001", sampleRules[0])
		_, listedRulesOut := executeShuffleToolsAction(t, listRulesAct, mockSrv, orgId)
		listedRulesSlice, ok := listedRulesOut.([]interface{})
		if !ok || len(listedRulesSlice) != 1 {
			t.Fatalf("expected Step 1 (Get_all_rules_from_the_system via Tools.list_datastore_category) to return 1 rule from shuffle-security_routing, got: %+v", listedRulesOut)
		}

		stepOutputs := map[string]interface{}{
			"exec":                          sampleIncident,
			"get_all_rules_from_the_system": listedRulesOut,
		}

		condBranches := findConditionalBranches(wf)
		if len(condBranches) < 4 {
			t.Fatalf("expected 4 conditional branches in incident_routing_rules workflow, got %d", len(condBranches))
		}

		// Verify Branch 1: {{ $$get_all_rules_from_the_system | size }} > 0
		if !evaluateUsecaseCondition(t, condBranches[0].Conditions[0], stepOutputs) {
			t.Fatal("expected get_all_rules_from_the_system size > 0 branch condition to pass")
		}

		// Step 2: Execute Find_relevant_rules_for_category
		valCode, _ := getActionParam(validateAct, "code")
		_, valOut := executeUsecasePython(t, valCode, mockSrv, stepOutputs, nil)
		if valOut == nil || valOut["matched"] != true {
			t.Fatalf("expected rule-nested-b64-001 to match nested field + base64 decoded payload, got: %+v", valOut)
		}
		stepOutputs["find_relevant_rules_for_category"] = map[string]interface{}{
			"message": valOut,
		}

		// Verify Branch 2: $find_relevant_rules_for_category.message.matched == true
		if !evaluateUsecaseCondition(t, condBranches[1].Conditions[0], stepOutputs) {
			t.Fatal("expected find_relevant_rules_for_category.message.matched == true branch condition to pass")
		}

		// Step 3: Execute Execute_rule_automation_for_found_rules
		execCode, _ := getActionParam(executeAct, "code")
		_, execOut := executeUsecasePython(t, execCode, mockSrv, stepOutputs, nil)
		if execOut == nil || execOut["matched"] != true {
			t.Fatalf("expected Execute_rule_automation_for_found_rules matched=true, got: %+v", execOut)
		}
		stepOutputs["execute_rule_automation_for_found_rules"] = map[string]interface{}{
			"message": execOut,
		}

		// Verify stats counter fields and move_to_org regional URL
		if execOut["stats_key"] != "routing_rule_rule-nested-b64-001" {
			t.Errorf("expected stats_key 'routing_rule_rule-nested-b64-001', got %v", execOut["stats_key"])
		}
		if execOut["move_to_org"] != true {
			t.Errorf("expected move_to_org=true, got %v", execOut["move_to_org"])
		}
		if execOut["target_org_id"] != "org-child-eu-999" {
			t.Errorf("expected target_org_id 'org-child-eu-999', got %v", execOut["target_org_id"])
		}
		if execOut["target_region_url"] != "https://frankfurt.shuffler.io" {
			t.Errorf("expected target_region_url 'https://frankfurt.shuffler.io', got %v", execOut["target_region_url"])
		}

		// Verify domain-aware resolution: when running on shuffle.security, target_region_url resolves to *.shuffle.security
		_, secDomainOut := executeUsecasePython(t, execCode, mockSrv, stepOutputs, map[string]string{
			"SHUFFLE_CLOUD_DOMAIN": "https://shuffle.security",
		})
		if secDomainOut == nil || secDomainOut["target_region_url"] != "https://frankfurt.shuffle.security" {
			t.Errorf("expected target_region_url 'https://frankfurt.shuffle.security' when on shuffle.security domain, got %v", secDomainOut["target_region_url"])
		}

		// Verify Branch 3 (to Update_rule_statistics) and Branch 4 (to Set_key_in_target_tenant)
		if !evaluateUsecaseCondition(t, condBranches[2].Conditions[0], stepOutputs) {
			t.Fatal("expected branch condition to Update_rule_statistics to evaluate to true")
		}
		if !evaluateUsecaseCondition(t, condBranches[3].Conditions[0], stepOutputs) {
			t.Fatal("expected branch condition to Set_key_in_target_tenant to evaluate to true")
		}

		// Step 4: Execute Update_rule_statistics (shuffle_openapi post_count_custom_stats -> POST /api/v1/stats)
		_, statsResp := executeOpenApiAction(t, statsAct, mockSrv, stepOutputs)
		if statsResp["success"] != true || statsResp["key"] != "routing_rule_rule-nested-b64-001" {
			t.Fatalf("expected Step 4 (Update_rule_statistics) to increment routing_rule_rule-nested-b64-001, got: %+v", statsResp)
		}
		if len(mockSrv.statsCalls) != 1 || fmt.Sprintf("%v", mockSrv.statsCalls[0]["value"]) != "1" {
			t.Fatalf("expected 1 stats call with value=1, got: %+v", mockSrv.statsCalls)
		}

		// Step 5: Execute Set_key_in_target_tenant (shuffle_openapi post_add_a_key -> POST /api/v2/datastore with Org-Id header)
		resolvedMoveUrl, moveResp := executeOpenApiAction(t, moveTenantAct, mockSrv, stepOutputs)
		if resolvedMoveUrl != "https://frankfurt.shuffler.io" {
			t.Errorf("expected Step 5 (Set_key_in_target_tenant) resolved regional URL 'https://frankfurt.shuffler.io', got %q", resolvedMoveUrl)
		}
		if moveResp["success"] != true {
			t.Fatalf("expected Step 5 (Set_key_in_target_tenant) to succeed, got: %+v", moveResp)
		}

		// Verify the incident in the source org datastore AND the target child tenant ("org-child-eu-999") datastore
		updatedRaw, ok := mockSrv.getDatastoreValue("shuffle-security_incidents", incidentKey)
		if !ok {
			t.Fatal("expected updated incident to exist in local datastore")
		}
		updatedInc, _ := updatedRaw.(map[string]interface{})
		if updatedInc["severity"] != "Critical" || updatedInc["status"] != "In Progress" {
			t.Errorf("expected incident severity=Critical and status=In Progress, got severity=%v status=%v", updatedInc["severity"], updatedInc["status"])
		}
		if updatedInc["assignee"] != "soc-tier2@example.com" {
			t.Errorf("expected incident assignee='soc-tier2@example.com', got %v", updatedInc["assignee"])
		}

		mockSrv.mu.Lock()
		childTenantInc, childHasInc := mockSrv.orgDatastore["org-child-eu-999"]["shuffle-security_incidents"][incidentKey]
		mockSrv.mu.Unlock()
		if !childHasInc {
			t.Fatal("expected Step 5 (Set_key_in_target_tenant) to replicate incident into target tenant 'org-child-eu-999'")
		}
		childIncMap, _ := childTenantInc.(map[string]interface{})
		if childIncMap["severity"] != "Critical" || childIncMap["assignee"] != "soc-tier2@example.com" {
			t.Errorf("expected target tenant 'org-child-eu-999' incident to have updated fields, got: %+v", childIncMap)
		}
	})
}
