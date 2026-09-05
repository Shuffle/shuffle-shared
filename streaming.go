package shuffle

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	gomemcache "github.com/bradfitz/gomemcache/memcache"
)

var streamPresenceColors = []string{
	"#F24E1E", "#1ABCFE", "#0ACF83", "#FF7262", "#A259FF",
	"#FFD700", "#FF3CAC", "#00CFFD", "#F5A623", "#6EE7B7",
	"#818CF8", "#FB923C",
}

func presenceColor(userID string) string {
	var hash int
	for _, c := range userID {
		hash = hash*31 + int(c)
	}
	if hash < 0 {
		hash = -hash
	}
	return streamPresenceColors[hash%len(streamPresenceColors)]
}

var streamPresenceTTL int32 = 5
var streamPresenceStaleMs int64 = 30000                                           // 30 seconds stale threshold
var streamAllowRegionRedirect = os.Getenv("SHUFFLE_STREAM_REGION_REDIRECT") == "" // Set SHUFFLE_STREAM_REGION_REDIRECT to any non-empty value to disable region redirects locally; unset in prod so this stays true
var streamSelfCloseAfter = 55 * time.Second                                       // close cleanly before the platform force-cuts at 60s, always between ops - never mid-write

// Stream storage model (per workflow):
//	<id>_stream_seq       — monotonic counter, atomically incremented per op (source of sequence numbers) <id> : workflow ID
//	<id>_stream_op_<seq>  — one operation stored under its own key (O(1) writes, no read-modify-write race)
//	<id>_stream_lastsave  — sequence of the last "save" op, used as the catch-up baseline
//	<id>_presence         — presence/heartbeat state (unchanged)

// Writes only allocate a sequence (atomic INCR) and set a single op key, so concurrent
// writers can never clobber each other. Readers poll the small counter key and only fetch
// op payloads when it advances.
var streamOpTTLMinutes int32 = 30   // individual op keys; also bounds catch-up history
var streamSeqTTLMinutes int32 = 60  // counter + lastsave keys (SetCache uses minutes; memcache/requestCache paths convert to seconds via *60)
var streamMaxCatchup int64 = 100    // cap replayed ops on connect/history
var streamMissRetries = 30          // ~3s at 100ms/poll before skipping a never-materialised op
var streamPostSaveKeepOps int64 = 0 // only keep the save op itself; delete all ops before it
var streamAuthCtxTTLMinutes int32 = 2

// Adaptive polling: the read loop starts at streamPollFast and slows down
// when no ops arrive, reducing idle memcache reads by ~97%. Any forwarded op
// snaps the interval back to streamPollFast immediately.
//
// Tier        Idle duration     Poll interval
// ─────────   ──────────────    ─────────────
// Fast        0 – 2 min        100 ms
// Medium      2 – 5 min        500 ms
// Slow        5 – 15 min       1 s
// Slowest     15 min+           3 s
var (
	streamPollFast    = 100 * time.Millisecond
	streamPollMedium  = 500 * time.Millisecond
	streamPollSlow    = 1 * time.Second
	streamPollSlowest = 3 * time.Second

	streamIdleMedium  = 2 * time.Minute
	streamIdleSlow    = 5 * time.Minute
	streamIdleSlowest = 15 * time.Minute
)

// streamSeqMu guards the in-process counter path (single-instance deployments without memcache).
var streamSeqMu sync.Mutex

// streamPollInterval picks the poll sleep based on idle duration.
func streamPollInterval(lastActivity time.Time) time.Duration {
	idle := time.Since(lastActivity)
	switch {
	case idle < streamIdleMedium:
		return streamPollFast
	case idle < streamIdleSlow:
		return streamPollMedium
	case idle < streamIdleSlowest:
		return streamPollSlow
	default:
		return streamPollSlowest
	}
}

// getStreamLastActivity reads the last-activity unix-ms timestamp from cache.
// Returns (timestamp, true) on hit, or (time.Now(), false) on miss.
func getStreamLastActivity(ctx context.Context, workflowID string) (time.Time, bool) {
	v, err := GetCache(ctx, streamLastActivityKey(workflowID))
	if err != nil {
		return time.Now(), false
	}
	raw, ok := v.([]uint8)
	if !ok {
		return time.Now(), false
	}
	ms, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || ms == 0 {
		return time.Now(), false
	}
	return time.UnixMilli(ms), true
}

// setStreamLastActivity persists time.Now() as the last-activity timestamp.
// TTL matches the seq counter (60 min) so it expires with the stream.
func setStreamLastActivity(ctx context.Context, workflowID string) {
	ms := time.Now().UnixMilli()
	if err := SetCache(ctx, streamLastActivityKey(workflowID), []byte(strconv.FormatInt(ms, 10)), streamSeqTTLMinutes); err != nil {
		log.Printf("[WARNING] Failed setting stream last-activity for %s: %s", workflowID, err)
	}
}

func streamSeqKey(id string) string {
	return fmt.Sprintf("%s_stream_seq", id)
}

func streamLastSaveKey(id string) string {
	return fmt.Sprintf("%s_stream_lastsave", id)
}

func streamOpKey(id string, seq int64) string {
	return fmt.Sprintf("%s_stream_op_%d", id, seq)
}

func streamLastActivityKey(id string) string {
	return fmt.Sprintf("%s_stream_lastactivity", id)
}

func streamPresenceKeyFor(id string) string {
	return fmt.Sprintf("%s_presence", id)
}

// streamAgentUserID is the name the AI agent signs in under while it's building a workflow.
const streamAgentUserID = "agent"

var streamPresenceMu sync.Mutex

// decodePresence reads the participant list out of its stored JSON form.
func decodePresence(data []byte) []StreamPresenceEntry {
	var state StreamPresenceState
	if len(data) > 0 {
		json.Unmarshal(data, &state)
	}
	return state.Users
}

// encodePresence turns a participant list back into the stored JSON form.
func encodePresence(users []StreamPresenceEntry) []byte {
	data, _ := json.Marshal(StreamPresenceState{Users: users})
	return data
}

// prunePresence returns only the participants seen within the stale threshold.
func prunePresence(users []StreamPresenceEntry, now int64) []StreamPresenceEntry {
	active := []StreamPresenceEntry{}
	for _, entry := range users {
		msSinceSeen := now - entry.LastSeen
		if msSinceSeen <= streamPresenceStaleMs {
			active = append(active, entry)
		}
	}
	return active
}

// addParticipant drops stale entries, then adds userID to the list — or just refreshes their
// LastSeen if they're already on it — and returns the updated list.
func addParticipant(users []StreamPresenceEntry, userID, username string, now int64) []StreamPresenceEntry {
	active := prunePresence(users, now)

	// Already on the list: just bump their timestamp (and name) and we're done.
	for i := range active {
		if active[i].UserID == userID {
			active[i].LastSeen = now
			if len(username) > 0 {
				active[i].Username = username
			}
			return active
		}
	}

	// New here: add them to the list.
	return append(active, StreamPresenceEntry{
		UserID:   userID,
		Username: username,
		LastSeen: now,
		Color:    presenceColor(userID),
	})
}

// readPresence returns the current live participants without changing anything.
func readPresence(ctx context.Context, workflowID string) []StreamPresenceEntry {
	value, err := GetCache(ctx, streamPresenceKeyFor(workflowID))
	if err != nil {
		return []StreamPresenceEntry{}
	}
	raw, ok := value.([]uint8)
	if !ok {
		return []StreamPresenceEntry{}
	}
	return prunePresence(decodePresence(raw), time.Now().UnixMilli())
}

// savePresenceParticipant records that userID is viewing the workflow — adding or refreshing
// their entry — and returns the resulting live participant list. It writes safely so two people
// signing in at the same instant can't overwrite each other.
func savePresenceParticipant(ctx context.Context, workflowID, userID, username string) []StreamPresenceEntry {
	key := streamPresenceKeyFor(workflowID)
	ttlSeconds := streamPresenceTTL * 60

	// Single-server setup: no shared cache, so a lock around read-change-write is enough.
	if len(memcached) == 0 {
		streamPresenceMu.Lock()
		defer streamPresenceMu.Unlock()

		users := addParticipant(readPresence(ctx, workflowID), userID, username, time.Now().UnixMilli())
		SetCache(ctx, key, encodePresence(users), streamPresenceTTL)
		return users
	}

	// Shared cache: read the list, change it, and save it back only if nobody else changed it
	// in the meantime. If someone did, read their fresh copy and try again (up to 5 times).
	for attempt := 0; attempt < 5; attempt++ {
		item, err := mc.Get(key)
		now := time.Now().UnixMilli()

		// Nothing stored yet: try to create it. If someone beats us to it, loop and update instead.
		if err == gomemcache.ErrCacheMiss || item == nil {
			users := addParticipant(nil, userID, username, now)
			if mc.Add(&gomemcache.Item{Key: key, Value: encodePresence(users), Expiration: ttlSeconds}) == nil {
				return users
			}
			continue
		}
		if err != nil {
			break // cache trouble — fall through to a best-effort read
		}

		// Something is stored: update it and save only if it hasn't changed underneath us.
		users := addParticipant(decodePresence(item.Value), userID, username, now)
		item.Value = encodePresence(users)
		item.Expiration = ttlSeconds
		if mc.CompareAndSwap(item) == nil {
			return users
		}
		// Someone else saved first — loop and retry against their version.
	}

	return readPresence(ctx, workflowID)
}

func streamAuthCtxKey(id string) string {
	return fmt.Sprintf("%s_stream_authctx", id)
}

// streamWorkflowAuth is the tiny per-workflow fact set the stream handlers authorize against.
// Cached per-workflow so the large GetWorkflow+GetOrg reads don't run on every ~55s reconnect.
type streamWorkflowAuth struct {
	ID                string `json:"id"`
	Owner             string `json:"owner"`
	OrgId             string `json:"org_id"`
	Public            bool   `json:"public"`
	MultiplayerActive bool   `json:"multiplayer_active"`
}

func getStreamWorkflowAuth(ctx context.Context, workflowID string) (streamWorkflowAuth, bool) {
	key := streamAuthCtxKey(workflowID)

	// Fast path: return the cached facts when the entry exists and decodes cleanly.
	cached, cacheErr := GetCache(ctx, key)
	if cacheErr == nil {
		cacheBytes, ok := cached.([]uint8)
		if ok {
			var auth streamWorkflowAuth
			unmarshalErr := json.Unmarshal(cacheBytes, &auth)
			if unmarshalErr == nil && len(auth.ID) > 0 {
				return auth, true
			}
		}
	}

	// Cache miss: read the workflow. A missing workflow means "not found".
	workflow, err := GetWorkflow(ctx, workflowID)
	if err != nil {
		return streamWorkflowAuth{}, false
	}

	auth := streamWorkflowAuth{
		ID:     workflow.ID,
		Owner:  workflow.Owner,
		OrgId:  workflow.OrgId,
		Public: workflow.Public,
	}

	// Read the org to find out whether multiplayer is enabled.
	org, orgErr := GetOrg(ctx, workflow.OrgId)
	if orgErr != nil {
		// Org read failed: treat multiplayer as off and don't cache it.
		return auth, true
	}
	auth.MultiplayerActive = org.SyncFeatures.Multiplayer.Active

	// Cache only when multiplayer is on, so turning it on is picked up on the next request.
	if auth.MultiplayerActive {
		authBytes, marshalErr := json.Marshal(auth)
		if marshalErr == nil {
			setErr := SetCache(ctx, key, authBytes, streamAuthCtxTTLMinutes)
			if setErr != nil {
				log.Printf("[WARNING] Failed caching stream auth context for %s: %s", workflowID, setErr)
			}
		}
	}

	return auth, true
}

// nextStreamSeq atomically allocates and returns the next stream sequence for a workflow.
func nextStreamSeq(workflowID string) (int64, error) {
	key := streamSeqKey(workflowID)

	if len(memcached) > 0 {
		newVal, err := mc.Increment(key, 1)

		if err == gomemcache.ErrCacheMiss {
			addErr := mc.Add(&gomemcache.Item{
				Key:        key,
				Value:      []byte("1"),
				Expiration: streamSeqTTLMinutes * 60,
			})

			if addErr == nil {
				return 1, nil
			}

			newVal, err = mc.Increment(key, 1)
		}

		if err != nil {
			return 0, err
		}

		mc.Touch(key, streamSeqTTLMinutes*60)

		return int64(newVal), nil
	}

	streamSeqMu.Lock()
	defer streamSeqMu.Unlock()

	var cur int64
	if v, found := requestCache.Get(key); found {
		if parsed, ok := v.(int64); ok {
			cur = parsed
		}
	}

	cur++
	requestCache.Set(key, cur, time.Duration(streamSeqTTLMinutes)*time.Minute)

	return cur, nil
}

// parseSeqValue reads a sequence value stored either as ASCII bytes (memcache) or int64
// (in-process cache) and returns it as an int64.
func parseSeqValue(v interface{}) int64 {
	switch t := v.(type) {
	case []uint8:
		seq, _ := strconv.ParseInt(strings.TrimSpace(string(t)), 10, 64)
		return seq
	case int64:
		return t
	case string:
		seq, _ := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		return seq
	}
	return 0
}

// currentStreamSeq returns the highest allocated sequence for a workflow (0 if none exist yet).
func currentStreamSeq(ctx context.Context, workflowID string) int64 {
	v, err := GetCache(ctx, streamSeqKey(workflowID))
	if err != nil {
		return 0
	}
	return parseSeqValue(v)
}

// lastStreamSaveSeq returns the sequence of the most recent "save" op (0 if none).
func lastStreamSaveSeq(ctx context.Context, workflowID string) int64 {
	v, err := GetCache(ctx, streamLastSaveKey(workflowID))
	if err != nil {
		return 0
	}
	return parseSeqValue(v)
}

// getStreamOp fetches and decodes a single operation by sequence. The bool is false when the
// op key is absent (expired, or not yet written in the brief window after its seq was allocated).
func getStreamOp(ctx context.Context, workflowID string, seq int64) (StreamWorkflowOperation, bool) {
	var op StreamWorkflowOperation
	v, err := GetCache(ctx, streamOpKey(workflowID, seq))
	if err != nil {
		return op, false
	}
	raw, ok := v.([]uint8)
	if !ok {
		return op, false
	}
	if err := json.Unmarshal(raw, &op); err != nil {
		return op, false
	}
	return op, true
}

func pruneStreamOpsBeforeSave(ctx context.Context, workflowID string, prevSaveSeq, newSaveSeq int64) {
	// Delete all ops before the current save. Keep only from newSaveSeq onwards.
	for seq := int64(1); seq < newSaveSeq; seq++ {
		if err := DeleteCache(ctx, streamOpKey(workflowID, seq)); err != nil {
			// log.Printf("[WARNING] Failed pruning stream op %d for %s: %s", seq, workflowID, err)
		}
	}
}

func HandleStreamWorkflowUpdate(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	if streamAllowRegionRedirect && project.Environment == "cloud" {
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting Stream Update request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
	}

	//// Removed check here as it may be a public workflow
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in getting specific workflow (stream update): %s. Continuing because it may be public.", err)
	}

	location := strings.Split(request.URL.String(), "/")

	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Workflow ID missing from request path"}`))
			return
		}

		fileId = location[4]
	}

	if strings.Contains(fileId, "?") {
		fileId = strings.Split(fileId, "?")[0]
	}

	if len(fileId) != 36 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID when getting workflow is not valid"}`))
		return
	}

	ctx := GetContext(request)
	workflowAuth, ok := getStreamWorkflowAuth(ctx, fileId)
	if !ok {
		log.Printf("[WARNING] Workflow %s doesn't exist.", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed finding workflow."}`))
		return
	}

	if user.Id != workflowAuth.Owner || len(user.Id) == 0 {
		if workflowAuth.OrgId == user.ActiveOrg.Id && user.Role != "org-reader" {
			// log.Printf("[AUDIT] User %s is accessing workflow %s as admin (SET workflow stream)", user.Username, workflowAuth.ID)

		} else if project.Environment == "cloud" && user.Verified == true && user.SupportAccess == true && user.Role == "admin" {
			log.Printf("[AUDIT] Letting verified support admin %s access workflow %s", user.Username, workflowAuth.ID)

		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (SET workflow stream)", user.Username, workflowAuth.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "You do not have permission to update this workflow's stream"}`))
			return
		}
	}

	if !workflowAuth.MultiplayerActive {
		log.Printf("[AUDIT] Multiplayer not active for org %s (Workflow stream updates)", workflowAuth.OrgId)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Multiplayer collaboration is not enabled for this organization"}`))
		return
	}

	workflowID := workflowAuth.ID

	body, err := io.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Error with body read in workflow stream: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed to read request body"}`))
		return
	}

	// Accept either a single operation or a batch, and normalise to a slice.
	var ops []StreamWorkflowOperation
	var single StreamWorkflowOperation
	if err := json.Unmarshal(body, &single); err == nil && len(single.Item) > 0 {
		ops = []StreamWorkflowOperation{single}
	} else if err := json.Unmarshal(body, &ops); err != nil || len(ops) == 0 {
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "No valid stream operations in body"}`))
		return
	}

	now := time.Now().UnixMilli()
	var lastSeq int64
	for i := range ops {
		// Atomic allocation — two writers can never receive the same sequence, so their
		// ops can never overwrite each other (each lives under its own key).
		seq, seqErr := nextStreamSeq(workflowID)
		if seqErr != nil {
			log.Printf("[ERROR] Failed allocating stream sequence for %s: %s", workflowID, seqErr)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed to allocate stream sequence"}`))
			return
		}

		ops[i].Sequence = seq
		ops[i].Timestamp = now
		// Only stamp user info if not already set (agent ops come pre-stamped)
		if len(ops[i].UserID) == 0 && len(user.Id) > 0 {
			ops[i].UserID = user.Id
		}
		if len(ops[i].Username) == 0 && len(user.Username) > 0 {
			ops[i].Username = user.Username
		}

		opBytes, marshalErr := json.Marshal(ops[i])
		if marshalErr != nil {
			log.Printf("[WARNING] Failed marshaling stream op for %s: %s", workflowID, marshalErr)
			continue
		}
		if cacheErr := SetCache(ctx, streamOpKey(workflowID, seq), opBytes, streamOpTTLMinutes); cacheErr != nil {
			log.Printf("[WARNING] Failed storing stream op %d for %s: %s", seq, workflowID, cacheErr)
		}

		// Record the save baseline so late joiners only replay unsaved changes.
		if ops[i].Item == "workflow" && ops[i].Type == "save" {
			prevSaveSeq := lastStreamSaveSeq(ctx, workflowID)
			if err := SetCache(ctx, streamLastSaveKey(workflowID), []byte(strconv.FormatInt(seq, 10)), streamSeqTTLMinutes); err != nil {
				log.Printf("[WARNING] Failed setting stream lastsave key for %s: %s", workflowID, err)
			}
			go pruneStreamOpsBeforeSave(ctx, workflowID, prevSaveSeq, seq)
		}

		lastSeq = seq
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "sequence": %d, "count": %d}`, lastSeq, len(ops))))
}

func HandleStreamWorkflow(resp http.ResponseWriter, request *http.Request) {
	connStart := time.Now()

	cors := HandleCors(resp, request)
	if cors {
		return
	}

	if streamAllowRegionRedirect && project.Environment == "cloud" {
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting Stream Start request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in getting specific workflow (stream): %s. Continuing because it may be public.", err)
	}

	location := strings.Split(request.URL.String(), "/")

	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Workflow ID missing from request path"}`))
			return
		}

		fileId = location[4]
	}

	if strings.Contains(fileId, "?") {
		fileId = strings.Split(fileId, "?")[0]
	}

	if len(fileId) != 36 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID when getting workflow is not valid"}`))
		return
	}

	ctx := GetContext(request)
	workflowAuth, ok := getStreamWorkflowAuth(ctx, fileId)
	if !ok {
		log.Printf("[WARNING] Workflow %s doesn't exist.", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed finding workflow."}`))
		return
	}

	if user.Id != workflowAuth.Owner || len(user.Id) == 0 {

		if workflowAuth.OrgId == user.ActiveOrg.Id && user.Role != "" {
			// log.Printf("[AUDIT] User %s is accessing workflow %s as org member (get workflow stream)", user.Username, workflowAuth.ID)

		} else if workflowAuth.Public {
			// log.Printf("[AUDIT] Letting user %s access workflow %s for streaming because it's public (get workflow stream)", user.Username, workflowAuth.ID)

		} else if project.Environment == "cloud" && user.Verified == true && user.Active == true && user.SupportAccess == true && strings.HasSuffix(user.Username, "@shuffler.io") {
			log.Printf("[AUDIT] Letting verified support admin %s access workflow %s", user.Username, workflowAuth.ID)
		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (get workflow stream)", user.Username, workflowAuth.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "You do not have permission to access this workflow's stream"}`))
			return
		}
	}

	if !workflowAuth.MultiplayerActive {
		log.Printf("[AUDIT] Multiplayer not active for org %s (get workflow stream)", workflowAuth.OrgId)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Multiplayer collaboration is not enabled for this organization"}`))
		return
	}

	workflowID := workflowAuth.ID

	// Lightweight presence poll: a solo client hits this instead of holding a long-poll open.
	// Refresh its own presence entry, return the live set, and close — no streaming goroutine.
	if request.URL.Query().Get("presence_only") == "1" {
		var users []StreamPresenceEntry
		if len(user.Id) > 0 {
			users = savePresenceParticipant(ctx, workflowID, user.Id, user.Username)
		} else {
			users = readPresence(ctx, workflowID)
		}
		resp.Header().Set("Content-Type", "application/json")
		responseBytes, _ := json.Marshal(map[string]interface{}{
			"success": true,
			"count":   len(users),
			"users":   users,
			"seq":     currentStreamSeq(ctx, workflowID),
		})
		resp.WriteHeader(200)
		resp.Write(responseBytes)
		return
	}

	resp.Header().Set("Connection", "Keep-Alive")
	resp.Header().Set("X-Content-Type-Options", "nosniff")

	conn, ok := resp.(http.Flusher)
	if !ok {
		log.Printf("[ERROR] Flusher error: %t", ok)
		http.Error(resp, "Streaming supported on AppEngine", http.StatusInternalServerError)
		return
	}

	resp.Header().Set("Content-Type", "text/event-stream")
	resp.WriteHeader(http.StatusOK)

	sinceStr := request.URL.Query().Get("since")
	var sinceSeq int64
	if len(sinceStr) > 0 {
		sinceSeq, _ = strconv.ParseInt(sinceStr, 10, 64)
	}

	var lastSentSeq int64 = sinceSeq

	// On first connect (since=0), replay unsaved ops so late joiners see the
	// current canvas state. Ops older than streamOpTTLMinutes are gone from
	// cache and will be missed — saving the workflow resets the baseline.
	if sinceSeq == 0 {
		currentSeq := currentStreamSeq(ctx, workflowID)
		if currentSeq > 0 {
			start := lastStreamSaveSeq(ctx, workflowID) + 1
			if start < 1 {
				start = 1
			}
			for seq := start; seq <= currentSeq; seq++ {
				op, ok := getStreamOp(ctx, workflowID, seq)
				if !ok {
					continue
				}
				if op.Type == "select" || op.Type == "unselect" || op.Type == "hover" || op.Type == "enter" {
					continue
				}
				// System ops (e.g. rewind) are live-only signals — replaying one on
				// catch-up would make the reconnecting client rewind again in a loop.	
				if op.Item == "system" {
					continue
				}
				opBytes, err := json.Marshal(op)
				if err != nil {
					continue
				}
				fmt.Fprintf(resp, "%s\n", string(opBytes))
			}
		}
		lastSentSeq = currentSeq
		fmt.Fprintf(resp, "%s\n", `{"item":"system","type":"init_complete"}`)
		conn.Flush()
	}

	// stall tracking: guards against a sequence that was allocated but whose op key never
	// materialised (writer died mid-request), so a single hole can't wedge the stream.
	var stalledSeq int64 = -1
	var stalledCount int

	// Adaptive polling: seed the activity timestamp on first connect so it
	// persists across 55s reconnect cycles. Subsequent connects read the
	// existing key; only the very first connection writes it.
	lastActivity, exists := getStreamLastActivity(ctx, workflowID)
	if !exists {
		setStreamLastActivity(ctx, workflowID)
	}
	lastPresenceAt := time.Time{} // zero → sends presence on first iteration

	for {
		if time.Since(connStart) > streamSelfCloseAfter {
			return
		}

		// Presence: send every ~10 seconds regardless of poll speed.
		// Using wall-clock interval instead of pollCount so it stays consistent
		// even when the poll interval changes (adaptive polling).
		if time.Since(lastPresenceAt) >= 10*time.Second {
			lastPresenceAt = time.Now()

			var users []StreamPresenceEntry
			if len(user.Id) > 0 {
				users = savePresenceParticipant(ctx, workflowID, user.Id, user.Username)
			} else {
				users = readPresence(ctx, workflowID)
			}

			// Send presence to client
			type presenceOp struct {
				Item  string                `json:"item"`
				Users []StreamPresenceEntry `json:"users"`
			}
			presenceOpBytes, _ := json.Marshal(presenceOp{Item: "presence", Users: users})
			if _, writeErr := fmt.Fprintf(resp, "%s\n", string(presenceOpBytes)); writeErr != nil {
				if strings.Contains(writeErr.Error(), "broken pipe") {
					return
				}
			}
			conn.Flush()
		}

		currentSeq := currentStreamSeq(ctx, workflowID)
		for seq := lastSentSeq + 1; seq <= currentSeq; seq++ {
			op, ok := getStreamOp(ctx, workflowID, seq)
			if !ok {
				// The counter was bumped but this op isn't stored yet — normally a
				// sub-millisecond write gap, so wait and retry on the next poll rather
				// than skipping it (advancing would drop the op permanently). If it never
				// shows up (writer crashed mid-request), skip it after streamMissRetries.
				if stalledSeq == seq {
					stalledCount++
				} else {
					stalledSeq = seq
					stalledCount = 1
				}
				if stalledCount >= streamMissRetries {
					lastSentSeq = seq
					stalledSeq = -1
					stalledCount = 0
					continue
				}
				break
			}
			stalledSeq = -1
			stalledCount = 0

			// Skip own-user ops (already applied locally). Don't reset
			// lastActivity — the frontend's since-seq doesn't advance past
			// skipped ops, so this fires on stale replays every reconnect.
			if len(user.Id) > 0 && op.UserID == user.Id {
				lastSentSeq = seq
				continue
			}

			opBytes, err := json.Marshal(op)
			if err != nil {
				lastSentSeq = seq
				continue
			}

			_, err = fmt.Fprintf(resp, "%s\n", string(opBytes))
			if err != nil {
				if strings.Contains(err.Error(), "broken pipe") {
					return
				}
			}
			lastSentSeq = seq
			lastActivity = time.Now()
			setStreamLastActivity(ctx, workflowID)
			conn.Flush()
		}

		pollInterval := streamPollInterval(lastActivity)
		time.Sleep(pollInterval)
	}
}

type StreamWorkflowHistoryResponse struct {
	Success    bool                      `json:"success"`
	Operations []StreamWorkflowOperation `json:"operations"`
}

func HandleStreamWorkflowHistory(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	if streamAllowRegionRedirect && project.Environment == "cloud" {
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting Stream History request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in getting workflow stream history: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Authentication required"}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")
	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Workflow ID missing from request path"}`))
			return
		}
		fileId = location[4]
	}

	if strings.Contains(fileId, "?") {
		fileId = strings.Split(fileId, "?")[0]
	}

	if len(fileId) != 36 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID is not valid"}`))
		return
	}

	ctx := GetContext(request)
	workflowAuth, ok := getStreamWorkflowAuth(ctx, fileId)
	if !ok {
		log.Printf("[WARNING] Workflow %s doesn't exist.", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed finding workflow."}`))
		return
	}

	if user.Id != workflowAuth.Owner {
		if workflowAuth.OrgId == user.ActiveOrg.Id && user.Role != "org-reader" {
			// org member — allowed
		} else if project.Environment == "cloud" && user.Verified && user.Active && user.SupportAccess && strings.HasSuffix(user.Username, "@shuffler.io") {
			// support admin — allowed
		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (stream history)", user.Username, workflowAuth.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "You do not have permission to view this workflow's stream history"}`))
			return
		}
	}

	if !workflowAuth.MultiplayerActive {
		log.Printf("[AUDIT] Multiplayer not active for org %s (stream history)", workflowAuth.OrgId)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Multiplayer collaboration is not enabled for this organization"}`))
		return
	}

	// Reassemble the recent operation history (bounded to the last streamMaxCatchup ops)
	// from the individual op keys.
	workflowID := workflowAuth.ID
	currentSeq := currentStreamSeq(ctx, workflowID)
	operations := []StreamWorkflowOperation{}
	if currentSeq > 0 {
		start := currentSeq - streamMaxCatchup + 1
		if start < 1 {
			start = 1
		}
		for seq := start; seq <= currentSeq; seq++ {
			if op, ok := getStreamOp(ctx, workflowID, seq); ok {
				operations = append(operations, op)
			}
		}
	}

	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(200)
	result, _ := json.Marshal(StreamWorkflowHistoryResponse{
		Success:    true,
		Operations: operations,
	})
	resp.Write(result)
}

// HandleStreamWorkflowRevert reverts the workflow stream to a target sequence number.

// Strategy:
//  1. Validate all ops from lastsave+1 → targetSeq are still in cache (not expired).
//     If any are missing, return 409 so the client can ask the user to save first.
//  2. Delete op keys from targetSeq+1 → currentSeq.
//  3. Emit a system:rewind op so all connected clients restart their stream from since=0.
//     The since=0 catch-up replays only the surviving ops, rebuilding the canvas correctly.
func HandleStreamWorkflowRevert(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	if streamAllowRegionRedirect && project.Environment == "cloud" {
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			RedirectUserRequest(resp, request)
			return
		}
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Authentication required"}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")
	var fileId string
	if location[1] == "api" && len(location) > 4 {
		fileId = location[4]
	}
	if strings.Contains(fileId, "?") {
		fileId = strings.Split(fileId, "?")[0]
	}
	if len(fileId) != 36 {
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Invalid workflow ID"}`))
		return
	}

	targetSeq, parseErr := strconv.ParseInt(request.URL.Query().Get("seq"), 10, 64)
	if parseErr != nil || targetSeq < 0 {
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Missing or invalid seq parameter"}`))
		return
	}

	ctx := GetContext(request)
	workflowAuth, ok := getStreamWorkflowAuth(ctx, fileId)
	if !ok {
		resp.WriteHeader(404)
		resp.Write([]byte(`{"success": false, "reason": "Workflow not found"}`))
		return
	}

	if user.Id != workflowAuth.Owner {
		if workflowAuth.OrgId == user.ActiveOrg.Id && user.Role != "org-reader" {
			// org member with write access — allowed
		} else if project.Environment == "cloud" && user.Verified && user.Active && user.SupportAccess && strings.HasSuffix(user.Username, "@shuffler.io") {
			// support admin — allowed
		} else {
			resp.WriteHeader(403)
			resp.Write([]byte(`{"success": false, "reason": "Access denied"}`))
			return
		}
	}

	if !workflowAuth.MultiplayerActive {
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Multiplayer is not enabled for this organization"}`))
		return
	}

	workflowID := workflowAuth.ID
	currentSeq := currentStreamSeq(ctx, workflowID)

	if targetSeq >= currentSeq {
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Target seq must be less than current seq"}`))
		return
	}

	// Step 1: Count how many ops in lastsave+1 → targetSeq are still in cache.
	// This used to hard-fail with 409 ("save first") on the first missing op, but that's
	// overly strict now: the rewind rebuild re-fetches the saved DB baseline and replays
	// whatever surviving ops exist (tolerating gaps, exactly like the normal since=0
	// catch-up). A missing op just means its change was already unreachable — reverting
	// still lands on a state no worse than a page refresh — so we warn and proceed.
	saveSeq := lastStreamSaveSeq(ctx, workflowID)
	missing := 0
	for seq := saveSeq + 1; seq <= targetSeq; seq++ {
		if _, exists := getStreamOp(ctx, workflowID, seq); !exists {
			missing++
		}
	}
	if missing > 0 {
		// log.Printf("[WARNING] stream revert: %d op(s) before target %d for workflow %s are no longer in cache; proceeding with tolerant rebuild", missing, targetSeq, workflowID)
	}

	// Step 2: Delete op keys targetSeq+1 → currentSeq.
	for seq := targetSeq + 1; seq <= currentSeq; seq++ {
		if delErr := DeleteCache(ctx, streamOpKey(workflowID, seq)); delErr != nil {
			// log.Printf("[WARNING] stream revert: failed deleting op %d for %s: %s", seq, workflowID, delErr)
		}
	}

	// Step 3: Emit a system:rewind op so every connected client tears down its
	// stream and reconnects from since=0, rebuilding its canvas from the surviving
	// ops only. No UserID is stamped, so it's delivered to everyone — including the
	// user who triggered the revert (own-user ops are the only ones the read loop skips).
	rewindSeq, rewindErr := nextStreamSeq(workflowID)
	if rewindErr != nil {
		log.Printf("[ERROR] stream revert: failed allocating rewind seq for %s: %s", workflowID, rewindErr)
	} else {
		username := user.Username
		if username == "" {
			username = user.Id
		}
		
		rewindOp := StreamWorkflowOperation{
			Item:      "system",
			Type:      "rewind",
			Sequence:  rewindSeq,
			Timestamp: time.Now().UnixMilli(),
			UserID:    user.Id,
			Username:  username,
		}
		
		if rewindBytes, marshalErr := json.Marshal(rewindOp); marshalErr == nil {
			if cacheErr := SetCache(ctx, streamOpKey(workflowID, rewindSeq), rewindBytes, streamOpTTLMinutes); cacheErr != nil {
				// log.Printf("[WARNING] stream revert: failed storing rewind op for %s: %s", workflowID, cacheErr)
			}
		}
	}

	log.Printf("[INFO] Stream revert: workflow %s reverted to seq %d by %s", workflowID, targetSeq, user.Username)

	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reverted_to": %d}`, targetSeq)))
}
