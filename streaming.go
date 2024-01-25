package shuffle

import (
	"log"
	"strings"
	"net/http"
	"io/ioutil"
	"fmt"
	"time"
)

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

			//} else if workflow.Public {
			//log.Printf("[AUDIT] Letting user %s access workflow %s for streaming because it's public (SET workflow stream)", user.Username, workflow.ID)

		} else if project.Environment == "cloud" && user.Verified == true && user.SupportAccess == true && user.Role == "admin" {
			log.Printf("[AUDIT] Letting verified support admin %s access workflow %s", user.Username, workflow.ID)

		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (SET workflow stream)", user.Username, workflow.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Error with body read in workflow stream: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	/*
	streamKey := fmt.Sprintf("%s_stream_users", workflow.ID)
	cache, err = GetCache(ctx, streamKey, user.Id, 30)
	if err != nil {
		log.Printf("[WARNING] Failed setting cache for apikey: %s", err)
	} else {
		// We are here to get the users in the stream
		cacheData := []byte(cache.([]uint8))
	}
	*/

	// FIXME: Should append to the stream and keep some items in memory
	// Not just purely overwrite it
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

	//// Removed check here as it may be a public workflow
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

	//ctx := GetContext(request)
	ctx := GetContext(request)
	workflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Workflow %s doesn't exist.", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed finding workflow."}`))
		return
	}

	if user.Id != workflow.Owner || len(user.Id) == 0 {

		if workflow.OrgId == user.ActiveOrg.Id && (user.Role == "admin" || user.Role == "org-reader") {
			log.Printf("[AUDIT] User %s is accessing workflow %s as admin (stream edit workflow)", user.Username, workflow.ID)

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

	// FIXME: If public, it should ONLY allow you to set certain actions

	resp.Header().Set("Connection", "Keep-Alive")
	resp.Header().Set("X-Content-Type-Options", "nosniff")

	conn, ok := resp.(http.Flusher)
	if !ok {
		log.Printf("[ERROR] Flusher error: %s", ok)
		http.Error(resp, "Streaming supported on AppEngine", http.StatusInternalServerError)
		return
	}

	resp.Header().Set("Content-Type", "text/event-stream")
	resp.WriteHeader(http.StatusOK)


	sessionKey := fmt.Sprintf("%s_stream", workflow.ID)
	previousCache := []byte{}
	for {
		cache, err := GetCache(ctx, sessionKey)
		if err == nil {

			cacheData := []byte(cache.([]uint8))
			if string(previousCache) == string(cacheData) {
				//log.Printf("[DEBUG] Still same cache for %s", user.Id)
			} else {

				// A way to only check for data from other people
				if (len(user.Id) > 0 && !strings.Contains(string(cacheData), user.Id)) || len(user.Id) == 0 {
					//log.Printf("[DEBUG] NEW cache for %s (1) - sending: %s.", user.Id, cacheData)

					//fw.Write(cacheData)
					//w.Write(cacheData)

					_, err := fmt.Fprintf(resp, string(cacheData))
					if err != nil {
						log.Printf("[ERROR] Failed in writing stream to user '%s' (%s): %s", user.Username, user.Id, err)

						if strings.Contains(err.Error(), "broken pipe") { 
							break
						}
					} else {
						previousCache = cacheData
						conn.Flush()
					}

				} else {
					//log.Printf("[ERROR] NEW cache for %s (2) - NOT sending: %s.", user.Id, cacheData)

					previousCache = cacheData
				}

			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for %s: %s", user.Id, err)
		}

		// FIXME: This is a hack to make sure we don't fully utilize the thread 
		time.Sleep(100 * time.Millisecond)
	}
}
