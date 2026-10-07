package shuffle

// TestEsIdIntegration runs against a live OpenSearch and is skipped unless ESID_INTEGRATION=true.
// It uses a throwaway org and cleans up after itself.
//   ESID_INTEGRATION=true SHUFFLE_OPENSEARCH_URL=https://localhost:9200 SHUFFLE_OPENSEARCH_USERNAME=admin \
//   SHUFFLE_OPENSEARCH_PASSWORD=... SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY=true \
//   go test -vet=off -run TestEsIdIntegration -count=1 -timeout 30m -v .
// ESID_SEED=<n> replays a run's random categories, ESID_CACHE=true enables the in-memory cache.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The ID OpenSearch sees after decoding the request path must be exactly the
// ID we built, same as a bulk write (ID in the body) or Datastore.
func TestEsDocumentIdSurvivesPathDecoding(t *testing.T) {
	ids := []string{
		"7447fe35-2ca1-4e72-9d67-8aa2dd2df902",
		"org_" + url.QueryEscape("水"),
		"org_" + url.QueryEscape("a b/c?d#e&f"),
		"org_%E6%B0", // cut mid-escape by the 127 char limit
		"org_a+b",
	}

	for _, id := range ids {
		req, err := http.NewRequest("GET", "/org_cache/_doc/"+esDocumentId(id), nil)
		if err != nil {
			t.Fatalf("%q: %s", id, err)
		}

		decoded, err := url.PathUnescape(req.URL.EscapedPath())
		if err != nil {
			t.Fatalf("%q: %s", id, err)
		}

		if decoded != "/org_cache/_doc/"+id {
			t.Errorf("%q: OpenSearch would see %q", id, decoded)
		}
	}
}

func TestLegacyEsDocumentId(t *testing.T) {
	cases := map[string]string{
		"org_%E6%B0%B4": "org_水",
		"7447fe35-2ca1": "",
		"org_a+b":       "",
		"org_%E6%B0":    "org_\xe6\xb0", // valid escapes, still decodes
		"org_%E":        "",             // invalid escape, could never be written by path
	}

	for id, want := range cases {
		if got := legacyEsDocumentId(id); got != want {
			t.Errorf("legacyEsDocumentId(%q) = %q, want %q", id, got, want)
		}
	}
}

var esHttp = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

func esRaw(t *testing.T, method, path string, body interface{}) (int, map[string]interface{}) {
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}

	// Builds the URL the same way the opensearch client did before the fix
	req, err := http.NewRequest(method, os.Getenv("SHUFFLE_OPENSEARCH_URL")+path, reader)
	if err != nil {
		return 0, nil
	}
	req.SetBasicAuth(os.Getenv("SHUFFLE_OPENSEARCH_USERNAME"), os.Getenv("SHUFFLE_OPENSEARCH_PASSWORD"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := esHttp.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()

	out := map[string]interface{}{}
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// How the datastore stores a category ("default" and "" are the same thing)
func storedCategory(category string) string {
	category = strings.ReplaceAll(strings.ToLower(category), " ", "_")
	if category == "default" {
		return ""
	}
	return category
}

// Every stored org_cache doc for this org+key+category, whatever its _id
func storedIds(t *testing.T, index, orgId, key, category string) []string {
	esRaw(t, "POST", "/"+index+"/_refresh", nil)
	_, res := esRaw(t, "POST", "/"+index+"/_search?size=100", map[string]interface{}{
		"query": map[string]interface{}{"bool": map[string]interface{}{"filter": []interface{}{
			map[string]interface{}{"term": map[string]interface{}{"org_id": orgId}},
			map[string]interface{}{"term": map[string]interface{}{"key": key}},
		}}},
	})

	ids := []string{}
	hits, _ := res["hits"].(map[string]interface{})
	list, _ := hits["hits"].([]interface{})
	for _, h := range list {
		hit := h.(map[string]interface{})
		src, _ := hit["_source"].(map[string]interface{})
		cat, _ := src["category"].(string)
		if storedCategory(cat) == storedCategory(category) {
			ids = append(ids, hit["_id"].(string))
		}
	}
	return ids
}

// Same ID building as the delete handlers, with the category the UI sends (the stored one)
func handlerDocId(orgId, key, category string) string {
	id := fmt.Sprintf("%s_%s", orgId, strings.Trim(key, " "))
	if len(category) > 0 {
		id = fmt.Sprintf("%s_%s", id, category)
	}
	id = url.QueryEscape(id)
	if len(id) > 127 {
		id = id[:127]
	}
	return id
}

func randomCategory(r *rand.Rand, pool []string, length int) string {
	out := ""
	for i := 0; i < length; i++ {
		out += pool[r.Intn(len(pool))]
	}
	return strings.Trim(out, " ")
}

type esIdResult struct {
	scenario, key, step string
	ok                  bool
	detail              string
}

func TestEsIdIntegration(t *testing.T) {
	if os.Getenv("ESID_INTEGRATION") != "true" {
		t.Skip("set ESID_INTEGRATION=true to run against a live OpenSearch")
	}

	ctx := context.Background()
	project = ShuffleStorage{DbType: "opensearch", Environment: "onprem", CacheDb: os.Getenv("ESID_CACHE") == "true"}
	project.Es = *GetEsConfig(false)

	seed := time.Now().UnixNano()
	if s, err := strconv.ParseInt(os.Getenv("ESID_SEED"), 10, 64); err == nil {
		seed = s
	}
	r := rand.New(rand.NewSource(seed))
	fmt.Printf("SEED|%d\n", seed)

	orgId := fmt.Sprintf("esidtest-%d", time.Now().UnixNano())
	defer func() {
		time.Sleep(2 * time.Second) // revisions are written in goroutines
		for _, index := range []string{"org_cache", "org_cache_revisions"} {
			esRaw(t, "POST", "/"+index+"/_delete_by_query?refresh=true", map[string]interface{}{
				"query": map[string]interface{}{"prefix": map[string]interface{}{"org_id": "esidtest-"}},
			})
		}
	}()

	results := []esIdResult{}
	check := func(scenario, key, step string, ok bool, detail string, args ...interface{}) {
		results = append(results, esIdResult{scenario, key, step, ok, fmt.Sprintf(detail, args...)})
		if !ok {
			t.Errorf("%s | %q | %s | %s", scenario, key, step, fmt.Sprintf(detail, args...))
		}
	}

	ascii := strings.Split("abcdefghijklmnopqrstuvwxyz0123456789", "")
	mixed := append(append([]string{}, ascii...), strings.Split("ABCXYZ_-. ", "")...)
	wild := append(append([]string{}, mixed...), "%", "+", "/", "&", "?", "#", "=", "火", "类", "é", "ß", "🔥", "ü")
	categories := []string{
		"",
		"default",
		"test_cat",
		"webhook_test",
		"shuffle_health_check",
		"类别",
		"My Category",
		"UPPER",
		"c@t%1+x/y",
		randomCategory(r, ascii, 8),
		randomCategory(r, mixed, 10),
		randomCategory(r, wild, 6),
		randomCategory(r, wild, 12),
	}

	type keyCase struct{ key, category string }
	cases := []keyCase{}
	for _, category := range categories {
		stored := storedCategory(category)
		keys := []string{"plainkey", "with space", "plus+sign", "水", "key/with?url#chars&x=1", "100% done", "emoji🔥key"}
		if len(stored) > 0 {
			// The webhook_test pattern: key ends with "_<category>", and friends
			keys = append(keys,
				"x_"+stored,
				"uuid-1234__"+stored,
				stored,
				strings.ToUpper(stored),
				stored+"_x",
				"a_"+stored+"_b",
			)
		}
		for _, key := range keys {
			cases = append(cases, keyCase{key, category})
		}
	}
	cases = append(cases, keyCase{strings.Repeat("长", 40), ""}) // escaped ID > 127 chars, cut mid-escape

	label := func(k keyCase) string { return k.key + "|" + k.category }

	readBack := func(scenario string, k keyCase, want string) {
		// Raw category, as a workflow/API caller may pass it, and the stored one, as the UI does
		for _, category := range []string{k.category, storedCategory(k.category)} {
			got, err := GetDatastoreKey(ctx, fmt.Sprintf("%s_%s", orgId, k.key), category)
			ok := err == nil && got != nil && got.Value == want
			gotVal := ""
			if got != nil {
				gotVal = got.Value
			}
			check(scenario, label(k), "get (category "+strconv.Quote(category)+")", ok, "want %q got %q err=%v", want, gotVal, err)
			if category == storedCategory(k.category) {
				break
			}
		}
	}

	deleteAndVerify := func(scenario string, k keyCase) {
		err := DeleteKey(ctx, "org_cache", handlerDocId(orgId, k.key, storedCategory(k.category)), orgId)
		check(scenario, label(k), "delete", err == nil, "err=%v", err)

		left := storedIds(t, "org_cache", orgId, k.key, k.category)
		check(scenario, label(k), "gone from DB after delete", len(left) == 0, "docs left=%v", left)

		_, getErr := GetDatastoreKey(ctx, fmt.Sprintf("%s_%s", orgId, k.key), k.category)
		check(scenario, label(k), "get fails after delete", getErr != nil, "get err=%v", getErr)

		// Leftovers would pollute later cases
		for _, id := range left {
			esRaw(t, "DELETE", "/org_cache/_doc/"+url.PathEscape(id)+"?refresh=true", nil)
		}
	}

	for _, k := range cases {
		// 1. Bulk write (UI uploads, workflow set_cache, pipelines)
		scenario := "bulk"
		mini, err := SetDatastoreKeyBulk(ctx, []CacheKeyData{{OrgId: orgId, Key: k.key, Value: "v1", Category: k.category}})
		check(scenario, label(k), "create", err == nil && len(mini) == 1 && !mini[0].Existed, "err=%v mini=%+v", err, mini)
		readBack(scenario, k, "v1")

		mini, err = SetDatastoreKeyBulk(ctx, []CacheKeyData{{OrgId: orgId, Key: k.key, Value: "v2", Category: k.category}})
		check(scenario, label(k), "update detected as existing", err == nil && len(mini) == 1 && mini[0].Existed, "err=%v mini=%+v", err, mini)
		readBack(scenario, k, "v2")

		listed, _, err := GetAllCacheKeys(ctx, orgId, k.category, 1000, "")
		count := 0
		for _, l := range listed {
			if l.Key == k.key {
				count++
			}
		}
		check(scenario, label(k), "listed exactly once", err == nil && count == 1, "count=%d err=%v", count, err)
		ids := storedIds(t, "org_cache", orgId, k.key, k.category)
		check(scenario, label(k), "one stored doc", len(ids) == 1, "ids=%v", ids)
		deleteAndVerify(scenario, k)

		// 2. Single write (key config save, AI agent requests)
		scenario = "single"
		err = SetDatastoreKey(ctx, CacheKeyData{OrgId: orgId, Key: k.key, Value: "s1", Category: k.category})
		check(scenario, label(k), "create", err == nil, "err=%v", err)
		readBack(scenario, k, "s1")
		err = SetDatastoreKey(ctx, CacheKeyData{OrgId: orgId, Key: k.key, Value: "s2", Category: k.category})
		check(scenario, label(k), "update", err == nil, "err=%v", err)
		readBack(scenario, k, "s2")
		ids = storedIds(t, "org_cache", orgId, k.key, k.category)
		check(scenario, label(k), "one stored doc", len(ids) == 1, "ids=%v", ids)
		deleteAndVerify(scenario, k)

		// 3. Mixed paths on the same key
		scenario = "bulk->single"
		SetDatastoreKeyBulk(ctx, []CacheKeyData{{OrgId: orgId, Key: k.key, Value: "m1", Category: k.category}})
		SetDatastoreKey(ctx, CacheKeyData{OrgId: orgId, Key: k.key, Value: "m2", Category: k.category})
		readBack(scenario, k, "m2")
		ids = storedIds(t, "org_cache", orgId, k.key, k.category)
		check(scenario, label(k), "one stored doc", len(ids) == 1, "ids=%v", ids)
		deleteAndVerify(scenario, k)

		scenario = "single->bulk"
		SetDatastoreKey(ctx, CacheKeyData{OrgId: orgId, Key: k.key, Value: "n1", Category: k.category})
		mini, _ = SetDatastoreKeyBulk(ctx, []CacheKeyData{{OrgId: orgId, Key: k.key, Value: "n2", Category: k.category}})
		check(scenario, label(k), "update detected as existing", len(mini) == 1 && mini[0].Existed, "mini=%+v", mini)
		readBack(scenario, k, "n2")
		ids = storedIds(t, "org_cache", orgId, k.key, k.category)
		check(scenario, label(k), "one stored doc", len(ids) == 1, "ids=%v", ids)
		deleteAndVerify(scenario, k)

		// 4. Legacy: stored by the old single path, i.e. under the URL-decoded _id
		scenario = "legacy-decoded"
		status, _ := esRaw(t, "PUT", "/org_cache/_doc/"+handlerDocId(orgId, k.key, storedCategory(k.category))+"?refresh=true",
			CacheKeyData{OrgId: orgId, Key: k.key, Value: "old", Category: storedCategory(k.category)})
		if status == 0 || status >= 300 {
			check(scenario, label(k), "seed", true, "old client couldn't store this ID at all (status %d), nothing to migrate", status)
		} else {
			readBack(scenario, k, "old")
			deleteAndVerify(scenario, k)
		}
	}

	// 5. Real local datastore keys, read-only
	{
		_, res := esRaw(t, "POST", "/org_cache/_search?size=500", map[string]interface{}{
			"query": map[string]interface{}{"bool": map[string]interface{}{"must_not": map[string]interface{}{"prefix": map[string]interface{}{"org_id": "esidtest-"}}}},
		})
		hits, _ := res["hits"].(map[string]interface{})
		list, _ := hits["hits"].([]interface{})
		for _, h := range list {
			src := h.(map[string]interface{})["_source"].(map[string]interface{})
			docId := h.(map[string]interface{})["_id"].(string)
			org, _ := src["org_id"].(string)
			key, _ := src["key"].(string)
			category, _ := src["category"].(string)
			value, _ := src["value"].(string)
			got, err := GetDatastoreKey(ctx, fmt.Sprintf("%s_%s", org, key), category)
			check("real-keys", key+"|"+category, "get", err == nil && got != nil && got.Value == value, "_id=%s err=%v", docId, err)
		}
	}

	// 6. Revisions are recorded per write and listed by search
	{
		k := keyCase{"水", "webhook_test"}
		SetDatastoreKeyBulk(ctx, []CacheKeyData{{OrgId: orgId, Key: k.key, Value: "r1", Category: k.category}})
		SetDatastoreKeyBulk(ctx, []CacheKeyData{{OrgId: orgId, Key: k.key, Value: "r2", Category: k.category}})
		time.Sleep(1500 * time.Millisecond)
		revs := storedIds(t, "org_cache_revisions", orgId, k.key, k.category)
		check("revisions", label(k), "recorded", len(revs) >= 2, "revision docs=%d", len(revs))
		_, err := GetDatastoreRevisions(ctx, k.key, k.category, orgId)
		check("revisions", label(k), "list", err == nil, "err=%v", err)
		deleteAndVerify("revisions", k)
	}

	// 7. Other entities, read-only, using real local IDs
	for _, entity := range []struct {
		index string
		get   func(id string) error
	}{
		{"users", func(id string) error { _, err := GetUser(ctx, id); return err }},
		{"organizations", func(id string) error { _, err := GetOrg(ctx, id); return err }},
		{"workflow", func(id string) error { _, err := GetWorkflow(ctx, id); return err }},
		{"workflowexecution", func(id string) error { _, err := GetWorkflowExecution(ctx, id); return err }},
	} {
		_, res := esRaw(t, "POST", "/"+entity.index+"/_search?size=3", map[string]interface{}{"_source": false})
		hits, _ := res["hits"].(map[string]interface{})
		list, _ := hits["hits"].([]interface{})
		for _, h := range list {
			id := h.(map[string]interface{})["_id"].(string)
			err := entity.get(id)
			check("other-entities", entity.index, "get "+id, err == nil, "err=%v", err)
		}
	}

	passed, failed := 0, 0
	for _, res := range results {
		mark := "PASS"
		if !res.ok {
			mark = "FAIL"
			failed++
		} else {
			passed++
		}
		fmt.Printf("RESULT|%s|%s|%s|%s|%s\n", mark, res.scenario, res.key, res.step, res.detail)
	}
	fmt.Printf("CATEGORIES|%q\n", categories)
	fmt.Printf("SUMMARY|cases=%d|passed=%d|failed=%d\n", len(cases), passed, failed)
}
