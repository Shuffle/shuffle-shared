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

// streamPresenceInterval: presence update every 100 poll iterations (~10s at 100ms/poll)
var streamPresenceInterval = 100
var streamPresenceTTL int32 = 5
var streamPresenceStaleMs int64 = 30000 // 30 seconds stale threshold
var streamAllowRegionRedirect = os.Getenv("SHUFFLE_STREAM_REGION_REDIRECT") == "" // set SHUFFLE_STREAM_DISABLE_REGION_REDIRECT locally to always handle stream requests locally instead of redirecting by region; unset in prod so this stays true
var streamSelfCloseAfter = 55 * time.Second // close cleanly before the platform force-cuts at 60s, always between ops - never mid-write

// Stream storage model (per workflow):
//
//	<id>_stream_seq       — monotonic counter, atomically incremented per op (source of sequence numbers)
//	<id>_stream_op_<seq>  — one operation stored under its own key (O(1) writes, no read-modify-write race)
//	<id>_stream_lastsave  — sequence of the last "save" op, used as the catch-up baseline
//	<id>_presence         — presence/heartbeat state (unchanged)
//
// Writes only allocate a sequence (atomic INCR) and set a single op key, so concurrent
// writers can never clobber each other. Readers poll the small counter key and only fetch
// op payloads when it advances.
var streamOpTTLMinutes int32 = 5     // individual op keys; also bounds catch-up history
var streamSeqTTLMinutes int32 = 60   // counter + lastsave keys (SetCache uses minutes)
var streamSeqTTLSeconds int32 = 3600 // counter key for direct memcache Add/Touch (seconds)
var streamMaxCatchup int64 = 100     // cap replayed ops on connect/history
var streamMissRetries = 30           // ~3s at 100ms/poll before skipping a never-materialised op
var streamPostSaveKeepOps int64 = 4  // ops just before a save are kept as a small safety buffer; older ones are pruned

// streamSeqMu guards the in-process counter path (single-instance deployments without memcache).
var streamSeqMu sync.Mutex

func streamSeqKey(id string) string           { return fmt.Sprintf("%s_stream_seq", id) }
func streamLastSaveKey(id string) string      { return fmt.Sprintf("%s_stream_lastsave", id) }
func streamOpKey(id string, seq int64) string { return fmt.Sprintf("%s_stream_op_%d", id, seq) }
func streamPresenceKeyFor(id string) string   { return fmt.Sprintf("%s_presence", id) }

// nextStreamSeq atomically allocates and returns the next stream sequence for a workflow.
// It is race-free across instances via memcache atomic INCR (when SHUFFLE_MEMCACHED is set),
// and falls back to a mutex-guarded in-process counter otherwise.
func nextStreamSeq(workflowID string) (int64, error) {
	key := streamSeqKey(workflowID)

	if len(memcached) > 0 {
		newVal, err := mc.Increment(key, 1)
		if err == gomemcache.ErrCacheMiss {
			// First op for this workflow: initialise the counter at 1. Add fails with
			// ErrNotStored if another writer created it first, so fall through to INCR.
			if addErr := mc.Add(&gomemcache.Item{Key: key, Value: []byte("1"), Expiration: streamSeqTTLSeconds}); addErr == nil {
				return 1, nil
			}
			newVal, err = mc.Increment(key, 1)
		}
		if err != nil {
			return 0, err
		}
		// Keep the counter alive across write-idle gaps so sequences never reset mid-session.
		mc.Touch(key, streamSeqTTLSeconds)
		return int64(newVal), nil
	}

	// In-process fallback — single instance, so a plain mutex is sufficient and race-free.
	streamSeqMu.Lock()
	defer streamSeqMu.Unlock()
	var cur int64
	if v, found := requestCache.Get(key); found {
		if parsed, ok := v.(int64); ok {
			cur = parsed
		}
	}
	cur++
	requestCache.Set(key, cur, time.Duration(streamSeqTTLSeconds)*time.Second)
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
	start := prevSaveSeq - streamPostSaveKeepOps + 1
	if start < 1 {
		start = 1
	}
	for seq := start; seq <= newSaveSeq-streamPostSaveKeepOps; seq++ {
		DeleteCache(ctx, streamOpKey(workflowID, seq))
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
	workflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Workflow %s doesn't exist.", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed finding workflow."}`))
		return
	}

	if user.Id != workflow.Owner || len(user.Id) == 0 {
		if workflow.OrgId == user.ActiveOrg.Id && user.Role != "org-reader" {
			// log.Printf("[AUDIT] User %s is accessing workflow %s as admin (SET workflow stream)", user.Username, workflow.ID)

		} else if project.Environment == "cloud" && user.Verified == true && user.SupportAccess == true && user.Role == "admin" {
			log.Printf("[AUDIT] Letting verified support admin %s access workflow %s", user.Username, workflow.ID)

		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (SET workflow stream)", user.Username, workflow.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "You do not have permission to update this workflow's stream"}`))
			return
		}
	}

	org, err := GetOrg(ctx, workflow.OrgId)
	if err != nil || !org.SyncFeatures.Multiplayer.Active {
		log.Printf("[AUDIT] Multiplayer not active for org %s (Workflow stream updates)", workflow.OrgId)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Multiplayer collaboration is not enabled for this organization"}`))
		return
	}

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
		seq, seqErr := nextStreamSeq(workflow.ID)
		if seqErr != nil {
			log.Printf("[ERROR] Failed allocating stream sequence for %s: %s", workflow.ID, seqErr)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed to allocate stream sequence"}`))
			return
		}

		ops[i].Sequence = seq
		ops[i].Timestamp = now
		if len(ops[i].UserID) == 0 && len(user.Id) > 0 {
			ops[i].UserID = user.Id
		}
		if len(user.Username) > 0 {
			ops[i].Username = user.Username
		}

		opBytes, marshalErr := json.Marshal(ops[i])
		if marshalErr != nil {
			log.Printf("[WARNING] Failed marshaling stream op for %s: %s", workflow.ID, marshalErr)
			continue
		}
		if cacheErr := SetCache(ctx, streamOpKey(workflow.ID, seq), opBytes, streamOpTTLMinutes); cacheErr != nil {
			log.Printf("[WARNING] Failed storing stream op %d for %s: %s", seq, workflow.ID, cacheErr)
		}

		// Record the save baseline so late joiners only replay unsaved changes.
		if ops[i].Item == "workflow" && ops[i].Type == "save" {
			prevSaveSeq := lastStreamSaveSeq(ctx, workflow.ID)
			SetCache(ctx, streamLastSaveKey(workflow.ID), []byte(strconv.FormatInt(seq, 10)), streamSeqTTLMinutes)
			go pruneStreamOpsBeforeSave(ctx, workflow.ID, prevSaveSeq, seq)
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
	workflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Workflow %s doesn't exist.", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed finding workflow."}`))
		return
	}

	if user.Id != workflow.Owner || len(user.Id) == 0 {

		if workflow.OrgId == user.ActiveOrg.Id && user.Role != "" {
			// log.Printf("[AUDIT] User %s is accessing workflow %s as org member (get workflow stream)", user.Username, workflow.ID)

		} else if workflow.Public {
			// log.Printf("[AUDIT] Letting user %s access workflow %s for streaming because it's public (get workflow stream)", user.Username, workflow.ID)

		} else if project.Environment == "cloud" && user.Verified == true && user.Active == true && user.SupportAccess == true && strings.HasSuffix(user.Username, "@shuffler.io") {
			log.Printf("[AUDIT] Letting verified support admin %s access workflow %s", user.Username, workflow.ID)
		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (get workflow stream)", user.Username, workflow.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "You do not have permission to access this workflow's stream"}`))
			return
		}
	}

	org, err := GetOrg(ctx, workflow.OrgId)
	if err != nil || !org.SyncFeatures.Multiplayer.Active {
		log.Printf("[AUDIT] Multiplayer not active for org %s (get workflow stream)", workflow.OrgId)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Multiplayer collaboration is not enabled for this organization"}`))
		return
	}
	
	workflowID := workflow.ID

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

	presenceKey := streamPresenceKeyFor(workflowID)
	var lastSentSeq int64 = sinceSeq
	var pollCount int

	// On initial connect (since=0), replay every op since the last save so late joiners see
	// the full unsaved backlog - it only exists in the stream, a reload wouldn't recover it.
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
				opBytes, err := json.Marshal(op)
				if err != nil {
					continue
				}
				fmt.Fprintf(resp, "%s\n", string(opBytes))
			}
		}

		// Everything up to currentSeq has been handled by catch-up; the live loop only
		// forwards ops that arrive after this point.
		lastSentSeq = currentSeq
		fmt.Fprintf(resp, "%s\n", `{"item":"system","type":"init_complete"}`)
		conn.Flush()
	}

	// stall tracking: guards against a sequence that was allocated but whose op key never
	// materialised (writer died mid-request), so a single hole can't wedge the stream.
	var stalledSeq int64 = -1
	var stalledCount int

	for {
		if time.Since(connStart) > streamSelfCloseAfter {
			return
		}

		pollCount++
		if pollCount%streamPresenceInterval == 1 {
			var presence StreamPresenceState
			presenceCache, err := GetCache(ctx, presenceKey)
			if err == nil {
				presenceData, ok := presenceCache.([]uint8)
				if !ok {
					log.Printf("[WARNING] Unexpected cache type for presence %s", presenceKey)
				} else if err := json.Unmarshal(presenceData, &presence); err != nil {
					log.Printf("[WARNING] Failed to unmarshal presence for %s: %s", workflowID, err)
				}
			}

			now := time.Now().UnixMilli()
			updated := false
			activeUsers := []StreamPresenceEntry{}
			for _, entry := range presence.Users {
				if now-entry.LastSeen > streamPresenceStaleMs {
					continue
				}
				if entry.UserID == user.Id {
					entry.LastSeen = now
					if len(user.Username) > 0 {
						entry.Username = user.Username
					}
					updated = true
				}
				activeUsers = append(activeUsers, entry)
			}
			if !updated && len(user.Id) > 0 {
				activeUsers = append(activeUsers, StreamPresenceEntry{
					UserID:   user.Id,
					Username: user.Username,
					LastSeen: now,
					Color:    presenceColor(user.Id),
				})
			}
			presence.Users = activeUsers

			presenceBytes, _ := json.Marshal(presence)
			if err := SetCache(ctx, presenceKey, presenceBytes, streamPresenceTTL); err != nil {
				log.Printf("[WARNING] Failed setting presence cache for %s: %s", workflowID, err)
			}

			// Send presence to client
			type presenceOp struct {
				Item  string                `json:"item"`
				Users []StreamPresenceEntry `json:"users"`
			}
			presenceOpBytes, _ := json.Marshal(presenceOp{Item: "presence", Users: presence.Users})
			_, err = fmt.Fprintf(resp, "%s\n", string(presenceOpBytes))
			if err != nil {
				if strings.Contains(err.Error(), "broken pipe") {
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
					log.Printf("[WARNING] Stream v2: op %d for %s never materialised after %d retries, skipping", seq, workflowID, streamMissRetries)
					lastSentSeq = seq
					stalledSeq = -1
					stalledCount = 0
					continue
				}
				break
			}
			stalledSeq = -1
			stalledCount = 0

			// Skip ops from this user — they already applied them locally.
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
			conn.Flush()
		}

		time.Sleep(100 * time.Millisecond)
	}
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
	workflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Workflow %s doesn't exist.", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed finding workflow."}`))
		return
	}

	if user.Id != workflow.Owner {
		if workflow.OrgId == user.ActiveOrg.Id && user.Role != "org-reader" {
			// org member — allowed
		} else if project.Environment == "cloud" && user.Verified && user.Active && user.SupportAccess && strings.HasSuffix(user.Username, "@shuffler.io") {
			// support admin — allowed
		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (stream history)", user.Username, workflow.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "You do not have permission to view this workflow's stream history"}`))
			return
		}
	}

	org, err := GetOrg(ctx, workflow.OrgId)
	if err != nil || !org.SyncFeatures.Multiplayer.Active {
		log.Printf("[AUDIT] Multiplayer not active for org %s (stream history)", workflow.OrgId)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Multiplayer collaboration is not enabled for this organization"}`))
		return
	}

	// Reassemble the recent operation history (bounded to the last streamMaxCatchup ops)
	// from the individual op keys.
	currentSeq := currentStreamSeq(ctx, workflow.ID)
	operations := []StreamWorkflowOperation{}
	if currentSeq > 0 {
		start := currentSeq - streamMaxCatchup + 1
		if start < 1 {
			start = 1
		}
		for seq := start; seq <= currentSeq; seq++ {
			if op, ok := getStreamOp(ctx, workflow.ID, seq); ok {
				operations = append(operations, op)
			}
		}
	}

	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(200)
	result, _ := json.Marshal(map[string]interface{}{
		"success":    true,
		"operations": operations,
	})
	resp.Write(result)
}
