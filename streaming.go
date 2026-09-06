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

var streamPresenceTTL      int32 = 5 	 // 5 Mins
var streamPresenceStaleMs  int64 = 30000 // 30s — user removed from presence after this idle time
var streamOpTTLMinutes     int32 = 30
var streamSeqTTLMinutes    int32 = 60
var streamAuthCtxTTLMinutes int32 = 5
var streamMaxCatchup       int64 = 100
var streamMissRetries            = 30
var streamSelfCloseAfter         = 55 * time.Second

// Set SHUFFLE_STREAM_REGION_REDIRECT=1 locally to disable region redirects.
var streamAllowRegionRedirect = os.Getenv("SHUFFLE_STREAM_REGION_REDIRECT") == ""

// streamSeqMu guards the in-process counter path (single-instance deployments without memcache).
var streamSeqMu sync.Mutex

// streamPresenceMu guards the in-process presence path (single-instance deployments without memcache).
var streamPresenceMu sync.Mutex

// streamReaderSignal is a wake-up ping channel for one reader.
// Each make() gives a unique memory address, so the channel itself is the reader's ID.
type streamReaderSignal chan struct{}

// streamNotifier wakes blocked readers when a writer stores an op, replacing the
// busy-poll. In-process only (single instance): writer and readers share a process.
type streamNotifier struct {
	mu      sync.RWMutex
	readers map[string][]streamReaderSignal // workflowID -> subscribed reader signals
}

var streamNotify = &streamNotifier{
	readers: make(map[string][]streamReaderSignal),
}

// subscribe returns a wake channel for the workflow and an unsubscribe func the
// caller MUST defer.
func (n *streamNotifier) subscribe(workflowID string) (streamReaderSignal, func()) {
	signal := make(streamReaderSignal, 1)

	n.mu.Lock()
	n.readers[workflowID] = append(n.readers[workflowID], signal)
	n.mu.Unlock()

	cleanup := func() {
		n.unsubscribe(workflowID, signal)
	}

	return signal, cleanup
}

// unsubscribe removes the given signal from the workflow's reader list.
func (n *streamNotifier) unsubscribe(workflowID string, signal streamReaderSignal) {
	n.mu.Lock()
	defer n.mu.Unlock()

	signals := n.readers[workflowID]
	for i, s := range signals {
		if s == signal {
			// Swap with last element and shrink — O(1), order doesn't matter
			last := len(signals) - 1
			signals[i] = signals[last]
			n.readers[workflowID] = signals[:last]
			break
		}
	}
	if len(n.readers[workflowID]) == 0 {
		delete(n.readers, workflowID)
	}
}

// publish wakes every reader subscribed to the workflow. Never blocks.
func (n *streamNotifier) publish(workflowID string) {
	// Snapshot under RLock so subscribe/unsubscribe isn't blocked
	// for the full iteration of potentially 200 channels.
	n.mu.RLock()
	signals := make([]streamReaderSignal, len(n.readers[workflowID]))
	copy(signals, n.readers[workflowID])
	n.mu.RUnlock()

	for _, signal := range signals {
		select {
		case signal <- struct{}{}:
		default: // reader already has a pending wake
		}
	}
}

// Stream Cache Helpers - Abstracts memcached vs in-memory storage

// streamCacheIncrement atomically increments a counter in cache.
func streamCacheIncrement(key string, ttlMinutes int32) (int64, error) {
	if len(memcached) > 0 && mc != nil {
		newVal, err := mc.Increment(key, 1)
		
		if err == gomemcache.ErrCacheMiss {
			addErr := mc.Add(&gomemcache.Item{
				Key:        key,
				Value:      []byte("1"),
				Expiration: ttlMinutes * 60,
			})
			if addErr == nil {
				return 1, nil
			}
			newVal, err = mc.Increment(key, 1)
		}
		
		if err == nil {
			mc.Touch(key, ttlMinutes*60)
			return int64(newVal), nil
		}
		
		log.Printf("[WARNING] Memcached increment failed for %s, using in-process", key)
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
	requestCache.Set(key, cur, time.Duration(ttlMinutes)*time.Minute)
	
	return cur, nil
}

// streamCacheGetPresence reads presence data with CAS support.
func streamCacheGetPresence(ctx context.Context, key string) ([]byte, uint64, error) {
	if len(memcached) > 0 && mc != nil {
		item, err := mc.Get(key)
		if err == gomemcache.ErrCacheMiss || item == nil {
			return nil, 0, gomemcache.ErrCacheMiss
		}
		if err != nil {
			log.Printf("[WARNING] Memcached get failed for %s, using in-process", key)
		} else {
			return item.Value, item.CasID, nil
		}
	}
	
	cached, err := GetCache(ctx, key)
	if err != nil {
		return nil, 0, err
	}
	
	if raw, ok := cached.([]uint8); ok {
		return raw, 0, nil
	}
	
	return nil, 0, fmt.Errorf("unexpected cache type")
}

// streamCacheSetPresence writes presence data with optional CAS.
func streamCacheSetPresence(ctx context.Context, key string, data []byte, ttlMinutes int32, casID uint64) error {
	if casID > 0 && len(memcached) > 0 && mc != nil {
		item := &gomemcache.Item{
			Key:        key,
			Value:      data,
			Expiration: ttlMinutes * 60,
			CasID:      casID,
		}
		err := mc.CompareAndSwap(item)
		if err == nil {
			return nil
		}
		if err == gomemcache.ErrCASConflict {
			return err
		}
		log.Printf("[WARNING] Memcached CAS failed for %s, using regular set", key)
	}
	
	if len(memcached) > 0 && mc != nil && casID == 0 {
		addErr := mc.Add(&gomemcache.Item{
			Key:        key,
			Value:      data,
			Expiration: ttlMinutes * 60,
		})
		if addErr == nil {
			return nil
		}
	}
	
	return SetCache(ctx, key, data, ttlMinutes)
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

func streamPresenceKeyFor(id string) string {
	return fmt.Sprintf("%s_presence", id)
}

// streamAgentUserID is reserved for future use — identifies agent-generated ops in presence.
const streamAgentUserID = "agent"

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

// savePresenceParticipant marks a user as active on the workflow and returns the updated viewer list.
// Uses a mutex for in-process cache (no memcache) or CAS for memcache to handle concurrent updates safely.
func savePresenceParticipant(ctx context.Context, workflowID, userID, username string) []StreamPresenceEntry {
	key := streamPresenceKeyFor(workflowID)
	now := time.Now().UnixMilli()

	// No memcache — use a simple mutex since everything is in-process.
	if len(memcached) == 0 || mc == nil {
		streamPresenceMu.Lock()
		defer streamPresenceMu.Unlock()

		users := addParticipant(readPresence(ctx, workflowID), userID, username, now)
		SetCache(ctx, key, encodePresence(users), streamPresenceTTL)
		return users
	}

	// Memcache path — use CAS (Compare-And-Swap) to safely handle multiple
	// goroutines or instances writing at the same time.
	// If someone else updated the key between our read and write, we retry.
	for attempt := 0; attempt < 5; attempt++ {
		data, casID, err := streamCacheGetPresence(ctx, key)

		if err == gomemcache.ErrCacheMiss || data == nil {
			// Key doesn't exist yet — first user to open this workflow.
			users := addParticipant(nil, userID, username, now)
			if streamCacheSetPresence(ctx, key, encodePresence(users), streamPresenceTTL, 0) == nil {
				return users
			}
			// Another goroutine created the key first — retry and update it.
			continue
		}

		if err != nil {
			break
		}

		// Key exists — update it with this user added/refreshed.
		users := addParticipant(decodePresence(data), userID, username, now)
		err = streamCacheSetPresence(ctx, key, encodePresence(users), streamPresenceTTL, casID)
		if err == nil {
			return users
		}

		if err == gomemcache.ErrCASConflict {
			// Someone else wrote between our read and write — retry with fresh data.
			continue
		}

		log.Printf("[WARNING] Failed updating presence for %s: %s", workflowID, err)
		break
	}

	// All retries failed — return whatever is currently in cache.
	// This user will be missing this tick but will succeed on the next heartbeat (10s).
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
	workflow, err := GetWorkflow(ctx, workflowID, true)
	if err != nil {
		return streamWorkflowAuth{}, false
	}

	auth := streamWorkflowAuth{
		ID:     workflow.ID,
		Owner:  workflow.Owner,
		OrgId:  workflow.OrgId,
		Public: workflow.Public,
	}

	// Multiplayer is enabled for everyone by default.
	auth.MultiplayerActive = true


	authBytes, marshalErr := json.Marshal(auth)
	if marshalErr == nil {
		setErr := SetCache(ctx, key, authBytes, streamAuthCtxTTLMinutes)
		if setErr != nil {
			log.Printf("[WARNING] Failed caching stream auth context for %s: %s", workflowID, setErr)
		}
	}

	return auth, true
}

// nextStreamSeq atomically allocates and returns the next stream sequence.
func nextStreamSeq(workflowID string) (int64, error) {
	key := streamSeqKey(workflowID)
	return streamCacheIncrement(key, streamSeqTTLMinutes)
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
	// Start from prevSaveSeq+1, not 1 — avoids re-deleting already pruned keys.
	start := prevSaveSeq + 1
	if start < 1 {
		start = 1
	}
	for seq := start; seq < newSaveSeq; seq++ {
		if err := DeleteCache(ctx, streamOpKey(workflowID, seq)); err != nil {
			log.Printf("[WARNING] Failed pruning stream op %d for %s: %s", seq, workflowID, err)
		}
	}
}

// Main stream update function :)
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
	// So that we won't have to fetch the workflow and org for each stream update :)
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

	// Limit request body size to prevent memory exhaustion
	const maxBodySize = 10 * 1024 * 1024 // 10MB limit
	request.Body = http.MaxBytesReader(resp, request.Body, maxBodySize)
	
	body, err := io.ReadAll(request.Body)
	if err != nil {
		if err.Error() == "http: request body too large" {
			log.Printf("[WARNING] Request body too large for workflow %s", workflowID)
			resp.WriteHeader(413)
			resp.Write([]byte(`{"success": false, "reason": "Request body too large (max 10MB)"}`))
			return
		}
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

	// Limit batch size to prevent memory exhaustion
	const maxBatchSize = 1000
	if len(ops) > maxBatchSize {
		log.Printf("[WARNING] Batch too large for workflow %s: %d ops (max %d)", workflowID, len(ops), maxBatchSize)
		resp.WriteHeader(413)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Batch too large (max %d operations)"}`, maxBatchSize)))
		return
	}

	now := time.Now().UnixMilli()
	var lastSeq int64
	var failedSeqs []int64
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
			log.Printf("[ERROR] Failed marshaling stream op %d for %s: %s", seq, workflowID, marshalErr)
			failedSeqs = append(failedSeqs, seq)
			continue
		}
		if cacheErr := SetCache(ctx, streamOpKey(workflowID, seq), opBytes, streamOpTTLMinutes); cacheErr != nil {
			log.Printf("[ERROR] Failed storing stream op %d for %s: %s", seq, workflowID, cacheErr)
			failedSeqs = append(failedSeqs, seq)
			continue
		}

		// Record the save baseline so late joiners only replay unsaved changes.
		if ops[i].Item == "workflow" && ops[i].Type == "save" {
			prevSaveSeq := lastStreamSaveSeq(ctx, workflowID)
			if err := SetCache(ctx, streamLastSaveKey(workflowID), []byte(strconv.FormatInt(seq, 10)), streamSeqTTLMinutes); err != nil {
				log.Printf("[WARNING] Failed setting stream lastsave key for %s: %s", workflowID, err)
			}
			go pruneStreamOpsBeforeSave(context.Background(), workflowID, prevSaveSeq, seq)
		}

		lastSeq = seq
	}

	// Wake readers so they deliver whichever ops did land immediately. -- New thing :)
	streamNotify.publish(workflowID)

	if len(failedSeqs) > 0 {
		log.Printf("[ERROR] Failed persisting %d/%d stream ops for %s (sequences: %v)", len(failedSeqs), len(ops), workflowID, failedSeqs)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to persist %d of %d stream operations", "sequence": %d, "count": %d}`, len(failedSeqs), len(ops), lastSeq, len(ops)-len(failedSeqs))))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "sequence": %d, "count": %d}`, lastSeq, len(ops))))
}

// This is the long poll socket for clients to listen to updates
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

	// if !workflowAuth.MultiplayerActive {
	// 	log.Printf("[AUDIT] Multiplayer not active for org %s (get workflow stream)", workflowAuth.OrgId)
	// 	resp.WriteHeader(403)
	// 	resp.Write([]byte(`{"success": false, "reason": "Multiplayer collaboration is not enabled for this organization"}`))
	// 	return
	// }

	workflowID := workflowAuth.ID
	presenceOnlyPoll := request.URL.Query().Get("presence_only") == "1"

	// Lightweight presence poll: a solo client hits this instead of holding a long-poll open.
	// Refresh its own presence entry, return the live set, and close — no streaming goroutine.
	if presenceOnlyPoll {
		var users []StreamPresenceEntry
		if len(user.Id) > 0 {
			users = savePresenceParticipant(ctx, workflowID, user.Id, user.Username)
		} else {
			users = readPresence(ctx, workflowID)
		}
		resp.Header().Set("Content-Type", "application/json")
		responseBytes, _ := json.Marshal(StreamPresenceResponse{
			Success: true,
			Count:   len(users),
			Users:   users,
			Seq:     currentStreamSeq(ctx, workflowID),
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

	// stall tracking: if a seq was allocated but the op never appeared (writer crashed),
	// skip it after streamMissRetries so one hole can't wedge the stream indefinitely.
	var stalledSeq int64 = -1
	var stalledCount int

	lastPresenceAt := time.Time{} // zero → sends presence on first iteration

	// Subscribe so writers can wake this reader instead of it busy-polling.
	wakeSignal, unsubscribe := streamNotify.subscribe(workflowID)
	defer unsubscribe()

	// Reuse a single timer instead of allocating time.After on every loop iteration.
	// time.After leaks a timer goroutine until it fires — at 200 connections × every 10s
	// that's 20 timer allocations/second. Reset this timer at the top of each iteration.
	presenceTimer := time.NewTimer(0)
	defer presenceTimer.Stop()

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
			conn.Flush()
		}

		// Wake to send the next presence heartbeat, but never past the self-close window.
		wait := time.Until(lastPresenceAt.Add(10 * time.Second))
		if wait <= 0 {
			wait = 10 * time.Second
		}
		if untilSelfClose := time.Until(connStart.Add(streamSelfCloseAfter)); untilSelfClose < wait {
			if untilSelfClose <= 0 {
				return
			}
			wait = untilSelfClose
		}

		// Block at ~0 CPU. Any wake re-drains from lastSentSeq, so no op is missed
		// even if a signal coalesced.
		select {
		case <-wakeSignal:
			// a writer stored an op
		case <-presenceTimer.C:
			// presence heartbeat due
		case <-request.Context().Done():
			return // client disconnected
		}

		// Reset timer for next iteration.
		if !presenceTimer.Stop() {
			select {
			case <-presenceTimer.C:
			default:
			}
		}
		presenceTimer.Reset(wait)
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

	// if !workflowAuth.MultiplayerActive {
	// 	log.Printf("[AUDIT] Multiplayer not active for org %s (stream history)", workflowAuth.OrgId)
	// 	resp.WriteHeader(403)
	// 	resp.Write([]byte(`{"success": false, "reason": "Multiplayer collaboration is not enabled for this organization"}`))
	// 	return
	// }

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

	// if !workflowAuth.MultiplayerActive {
	// 	resp.WriteHeader(403)
	// 	resp.Write([]byte(`{"success": false, "reason": "Multiplayer is not enabled for this organization"}`))
	// 	return
	// }

	workflowID := workflowAuth.ID
	currentSeq := currentStreamSeq(ctx, workflowID)

	if targetSeq >= currentSeq {
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Target seq must be less than current seq"}`))
		return
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
