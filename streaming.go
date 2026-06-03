package shuffle

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var streamPresenceColors = []string{
	"#F24E1E", "#1ABCFE", "#0ACF83", "#FF7262", "#A259FF",
	"#FFD700", "#FF3CAC", "#00CFFD", "#F5A623", "#6EE7B7",
	"#818CF8", "#FB923C",
}

func presenceColor(userID string, slotIndex int) string {
	return streamPresenceColors[slotIndex%len(streamPresenceColors)]
}

// streamPresenceInterval: presence update every 100 poll iterations (~10s at 100ms/poll)
var streamPresenceInterval = 100
var streamPresenceTTL int32 = 5
var streamPresenceStaleMs int64 = 30000 // 30 seconds stale threshold

func HandleStreamWorkflowUpdate(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
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
			resp.Write([]byte(`{"success": false}`))
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
			log.Printf("[AUDIT] User %s is accessing workflow %s as admin (SET workflow stream)", user.Username, workflow.ID)

		} else if project.Environment == "cloud" && user.Verified == true && user.SupportAccess == true && user.Role == "admin" {
			log.Printf("[AUDIT] Letting verified support admin %s access workflow %s", user.Username, workflow.ID)

		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (SET workflow stream)", user.Username, workflow.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	org, err := GetOrg(ctx, workflow.OrgId)
	if err != nil || !org.SyncFeatures.Multiplayer.Active {
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	body, err := io.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Error with body read in workflow stream: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Try to parse as a single operation and assign sequence + timestamp
	var op StreamWorkflowOperation
	if err := json.Unmarshal(body, &op); err == nil && len(op.Item) > 0 {
		op.Timestamp = time.Now().UnixMilli()

		if len(op.UserID) == 0 && len(user.Id) > 0 {
			op.UserID = user.Id
		}
		if len(user.Username) > 0 {
			op.Username = user.Username
		}

		sessionKey := fmt.Sprintf("%s_stream", workflow.ID)
		var state StreamWorkflowState

		cache, err := GetCache(ctx, sessionKey)
		if err == nil {
			cacheData, ok := cache.([]uint8)
			if !ok {
				log.Printf("[WARNING] Unexpected cache type for stream state %s", sessionKey)
			} else if err := json.Unmarshal(cacheData, &state); err != nil {
				log.Printf("[WARNING] Failed to unmarshal stream state for %s: %s", workflow.ID, err)
			}
		}

		op.Sequence = state.LastSeq + 1
		state.Operations = append(state.Operations, op)
		state.LastSeq = op.Sequence

		if len(state.Operations) > 100 {
			state.Operations = state.Operations[len(state.Operations)-100:]
		}

		stateBytes, err := json.Marshal(state)
		if err != nil {
			log.Printf("[WARNING] Failed to marshal stream state: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		err = SetCache(ctx, sessionKey, stateBytes, 120)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for stream: %s", err)
		}

		resp.WriteHeader(200)
		resp.Write([]byte(fmt.Sprintf(`{"success": true, "sequence": %d}`, op.Sequence)))
		return
	}

	// Fallback: batch of operations
	var ops []StreamWorkflowOperation
	if err := json.Unmarshal(body, &ops); err == nil && len(ops) > 0 {
		sessionKey := fmt.Sprintf("%s_stream", workflow.ID)
		var state StreamWorkflowState

		cache, err := GetCache(ctx, sessionKey)
		if err == nil {
			cacheData, ok := cache.([]uint8)
			if !ok {
				log.Printf("[WARNING] Unexpected cache type for stream state %s", sessionKey)
			} else if err := json.Unmarshal(cacheData, &state); err != nil {
				log.Printf("[WARNING] Failed to unmarshal stream state for %s: %s", workflow.ID, err)
			}
		}

		for i := range ops {
			ops[i].Sequence = state.LastSeq + 1
			state.LastSeq = ops[i].Sequence
			ops[i].Timestamp = time.Now().UnixMilli()
			if len(ops[i].UserID) == 0 && len(user.Id) > 0 {
				ops[i].UserID = user.Id
			}
			state.Operations = append(state.Operations, ops[i])
		}

		if len(state.Operations) > 100 {
			state.Operations = state.Operations[len(state.Operations)-100:]
		}

		stateBytes, err := json.Marshal(state)
		if err != nil {
			log.Printf("[WARNING] Failed to marshal stream state: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		err = SetCache(ctx, sessionKey, stateBytes, 120)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for stream: %s", err)
		}

		resp.WriteHeader(200)
		resp.Write([]byte(fmt.Sprintf(`{"success": true, "sequence": %d, "count": %d}`, state.LastSeq, len(ops))))
		return
	}

	// Legacy fallback: raw body overwrite (backwards compat for old clients)
	sessionKey := fmt.Sprintf("%s_stream", workflow.ID)
	err = SetCache(ctx, sessionKey, body, 30)
	if err != nil {
		log.Printf("[WARNING] Failed setting cache for apikey: %s", err)
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleStreamWorkflow(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
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
			resp.Write([]byte(`{"success": false}`))
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
			log.Printf("[AUDIT] User %s is accessing workflow %s as org member (get workflow stream)", user.Username, workflow.ID)

		} else if workflow.Public {
			log.Printf("[AUDIT] Letting user %s access workflow %s for streaming because it's public (get workflow stream)", user.Username, workflow.ID)

		} else if project.Environment == "cloud" && user.Verified == true && user.Active == true && user.SupportAccess == true && strings.HasSuffix(user.Username, "@shuffler.io") {
			log.Printf("[AUDIT] Letting verified support admin %s access workflow %s", user.Username, workflow.ID)
		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (get workflow stream)", user.Username, workflow.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	org, err := GetOrg(ctx, workflow.OrgId)
	if err != nil || !org.SyncFeatures.Multiplayer.Active {
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false}`))
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

	sessionKey := fmt.Sprintf("%s_stream", workflow.ID)
	presenceKey := fmt.Sprintf("%s_presence", workflow.ID)
	var lastSentSeq int64 = sinceSeq
	var pollCount int

	// On initial connect (since=0), flush the delta ops since the last save so late joiners
	// catch up to unsaved changes made by other users before they arrived.
	if sinceSeq == 0 {
		cache, err := GetCache(ctx, sessionKey)
		if err == nil {
			cacheData, ok := cache.([]uint8)
			if ok {
				var state StreamWorkflowState
				if err := json.Unmarshal(cacheData, &state); err == nil && len(state.Operations) > 0 {
					// Find the sequence of the last save op — that's the catch-up baseline
					var lastSaveSeq int64
					for _, op := range state.Operations {
						if op.Item == "workflow" && op.Type == "save" {
							lastSaveSeq = op.Sequence
						}
					}

					for _, op := range state.Operations {
						if op.Sequence <= lastSaveSeq {
							continue
						}
						// Skip ephemeral ops — they reflect transient UI state, not structural changes
						if op.Type == "select" || op.Type == "unselect" || op.Type == "hover" || op.Type == "enter" {
							continue
						}
						opBytes, err := json.Marshal(op)
						if err != nil {
							continue
						}
						fmt.Fprintf(resp, "%s\n", string(opBytes))
						lastSentSeq = op.Sequence
					}
				}
			}
		}

		// Signal to the client that catch-up is done — it can now arm its time filter
		fmt.Fprintf(resp, "%s\n", `{"item":"system","type":"init_complete"}`)
		conn.Flush()
	}

	for {
		pollCount++
		if pollCount%streamPresenceInterval == 1 {
			var presence StreamPresenceState
			presenceCache, err := GetCache(ctx, presenceKey)
			if err == nil {
				presenceData, ok := presenceCache.([]uint8)
				if !ok {
					log.Printf("[WARNING] Unexpected cache type for presence %s", presenceKey)
				} else if err := json.Unmarshal(presenceData, &presence); err != nil {
					log.Printf("[WARNING] Failed to unmarshal presence for %s: %s", workflow.ID, err)
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
					Color:    presenceColor(user.Id, len(activeUsers)),
				})
			}
			presence.Users = activeUsers

			presenceBytes, _ := json.Marshal(presence)
			if err := SetCache(ctx, presenceKey, presenceBytes, streamPresenceTTL); err != nil {
				log.Printf("[WARNING] Failed setting presence cache for %s: %s", workflow.ID, err)
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

		cache, err := GetCache(ctx, sessionKey)
		if err == nil {
			cacheData, ok := cache.([]uint8)
			if !ok {
				log.Printf("[WARNING] Unexpected cache type for stream state %s", sessionKey)
			} else {
				var state StreamWorkflowState
				if err := json.Unmarshal(cacheData, &state); err == nil {
					for _, op := range state.Operations {
						if op.Sequence <= lastSentSeq {
							continue
						}

						// Skip ops from this user (they already applied them locally)
						if len(user.Id) > 0 && op.UserID == user.Id {
							lastSentSeq = op.Sequence
							continue
						}

						opBytes, err := json.Marshal(op)
						if err != nil {
							continue
						}

						_, err = fmt.Fprintf(resp, "%s\n", string(opBytes))
						if err != nil {
							if strings.Contains(err.Error(), "broken pipe") {
								return
							}
						}
						lastSentSeq = op.Sequence
						conn.Flush()
					}
				} else {
					// Legacy format: raw body (backwards compat)
					if lastSentSeq == 0 {
						if (len(user.Id) > 0 && !strings.Contains(string(cacheData), user.Id)) || len(user.Id) == 0 {
							_, err := fmt.Fprintf(resp, "%s", string(cacheData))
							if err != nil {
								if strings.Contains(err.Error(), "broken pipe") {
									return
								}
							} else {
								conn.Flush()
							}
						}
						lastSentSeq = 1
					}
				}
			}
		}

		time.Sleep(100 * time.Millisecond)
	}
}

func HandleStreamWorkflowHistory(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in getting workflow stream history: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")
	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
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
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	org, err := GetOrg(ctx, workflow.OrgId)
	if err != nil || !org.SyncFeatures.Multiplayer.Active {
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	sessionKey := fmt.Sprintf("%s_stream", workflow.ID)
	var state StreamWorkflowState
	cache, err := GetCache(ctx, sessionKey)
	if err == nil {
		cacheData, ok := cache.([]uint8)
		if ok {
			json.Unmarshal(cacheData, &state)
		}
	}

	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(200)
	result, _ := json.Marshal(map[string]interface{}{
		"success":    true,
		"operations": state.Operations,
	})
	resp.Write(result)
}
