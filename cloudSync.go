package shuffle

import (
	"bytes"
	"net/url"
	"context"
	"io"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"path/filepath"

	//"github.com/algolia/algoliasearch-client-go/v3/algolia/opt"
	"github.com/algolia/algoliasearch-client-go/v3/algolia/search"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	//"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"

)

func executeCloudAction(action CloudSyncJob, apikey string) error {
	data, err := json.Marshal(action)
	if err != nil {
		log.Printf("Failed cloud webhook action marshalling: %s", err)
		return err
	}

	client := &http.Client{}
	syncUrl := fmt.Sprintf("https://shuffler.io/api/v1/cloud/sync/handle_action")
	req, err := http.NewRequest(
		"POST",
		syncUrl,
		bytes.NewBuffer(data),
	)

	req.Header.Add("Authorization", fmt.Sprintf(`Bearer %s`, apikey))
	newresp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer newresp.Body.Close()
	respBody, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		return err
	}

	type Result struct {
		Success bool   `json:"success"`
		Reason  string `json:"reason"`
	}

	//log.Printf("Data: %s", string(respBody))
	responseData := Result{}
	err = json.Unmarshal(respBody, &responseData)
	if err != nil {
		return err
	}

	if !responseData.Success {
		return errors.New(fmt.Sprintf("Cloud error from Shuffler: %s", responseData.Reason))
	}

	return nil
}

func HandleAlgoliaAppSearch(ctx context.Context, appname string) (AlgoliaSearchApp, error) {
	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return AlgoliaSearchApp{}, errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("appsearch")
	appname = strings.TrimSpace(strings.ToLower(strings.Replace(appname, "_", " ", -1)))
	res, err := algoliaIndex.Search(appname)
	if err != nil {
		log.Printf("[WARNING] Failed searching Algolia: %s", err)
		return AlgoliaSearchApp{}, err
	}

	var newRecords []AlgoliaSearchApp
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia: %s", err)
		return AlgoliaSearchApp{}, err
	}

	//log.Printf("[INFO] Algolia hits for '%s': %d", appname, len(newRecords))
	for _, newRecord := range newRecords {
		newApp := strings.TrimSpace(strings.ToLower(strings.Replace(newRecord.Name, "_", " ", -1)))
		if newApp == appname || newRecord.ObjectID == appname {
			//return newRecord.ObjectID, nil
			return newRecord, nil
		}
	}

	// Second try with contains
	for _, newRecord := range newRecords {
		newApp := strings.TrimSpace(strings.ToLower(strings.Replace(newRecord.Name, "_", " ", -1)))
		if strings.Contains(newApp, appname) {
			return newRecord, nil
		}
	}

	return AlgoliaSearchApp{}, nil
}

func HandleAlgoliaWorkflowSearchByApp(ctx context.Context, appname string) ([]AlgoliaSearchWorkflow, error) {
	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return []AlgoliaSearchWorkflow{}, errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("workflows")

	appSearch := fmt.Sprintf("%s", appname)
	res, err := algoliaIndex.Search(appSearch)
	if err != nil {
		log.Printf("[WARNING] Failed app searching Algolia for creators: %s", err)
		return []AlgoliaSearchWorkflow{}, err
	}

	var newRecords []AlgoliaSearchWorkflow
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia with app creators: %s", err)
		return []AlgoliaSearchWorkflow{}, err
	}
	//log.Printf("[INFO] Algolia hits for %s: %d", appSearch, len(newRecords))

	allRecords := []AlgoliaSearchWorkflow{}
	for _, newRecord := range newRecords {
		allRecords = append(allRecords, newRecord)

	}

	return allRecords, nil
}

func HandleAlgoliaWorkflowSearchByUser(ctx context.Context, userId string) ([]AlgoliaSearchWorkflow, error) {
	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return []AlgoliaSearchWorkflow{}, errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("workflows")

	appSearch := fmt.Sprintf("%s", userId)
	res, err := algoliaIndex.Search(appSearch)
	if err != nil {
		log.Printf("[WARNING] Failed app searching Algolia for creators: %s", err)
		return []AlgoliaSearchWorkflow{}, err
	}

	var newRecords []AlgoliaSearchWorkflow
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia with app creators: %s", err)
		return []AlgoliaSearchWorkflow{}, err
	}
	//log.Printf("[INFO] Algolia hits for %s: %d", appSearch, len(newRecords))

	allRecords := []AlgoliaSearchWorkflow{}
	for _, newRecord := range newRecords {
		allRecords = append(allRecords, newRecord)

	}

	return allRecords, nil
}

func HandleAlgoliaAppSearchByUser(ctx context.Context, userId string) ([]AlgoliaSearchApp, error) {
	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return []AlgoliaSearchApp{}, errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("appsearch")

	appSearch := fmt.Sprintf("%s", userId)
	res, err := algoliaIndex.Search(appSearch)
	if err != nil {
		log.Printf("[WARNING] Failed app searching Algolia for creators: %s", err)
		return []AlgoliaSearchApp{}, err
	}

	var newRecords []AlgoliaSearchApp
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia with app creators: %s", err)
		return []AlgoliaSearchApp{}, err
	}
	//log.Printf("[INFO] Algolia hits for %s: %d", appSearch, len(newRecords))

	allRecords := []AlgoliaSearchApp{}
	for _, newRecord := range newRecords {
		newAppName := strings.TrimSpace(strings.Replace(newRecord.Name, "_", " ", -1))
		newRecord.Name = newAppName
		allRecords = append(allRecords, newRecord)

	}

	return allRecords, nil
}

func HandleAlgoliaCreatorSearch(ctx context.Context, username string) (AlgoliaSearchCreator, error) {
	tmpUsername, err := url.QueryUnescape(username)
	if err == nil {
		username = tmpUsername
	}

	if strings.HasPrefix(username, "@") {
		username = strings.Replace(username, "@", "", 1)
	}

	username = strings.ToLower(strings.TrimSpace(username))

	cacheKey := fmt.Sprintf("algolia_creator_%s", username)
	searchCreator := AlgoliaSearchCreator{}
	cache, err := GetCache(ctx, cacheKey)
	if err == nil {
		cacheData := []byte(cache.([]uint8))
		//log.Printf("CACHE: %d", len(cacheData))
		//log.Printf("CACHEDATA: %#v", cacheData)
		err = json.Unmarshal(cacheData, &searchCreator)
		if err == nil {
			return searchCreator, nil
		}
	}

	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return searchCreator, errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("creators")
	res, err := algoliaIndex.Search(username)
	if err != nil {
		log.Printf("[WARNING] Failed searching Algolia creators: %s", err)
		return searchCreator, err
	}

	var newRecords []AlgoliaSearchCreator
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia creators: %s", err)
		return searchCreator, err
	}

	//log.Printf("RECORDS: %d", len(newRecords))
	foundUser := AlgoliaSearchCreator{}
	for _, newRecord := range newRecords {
		if strings.ToLower(newRecord.Username) == strings.ToLower(username) || newRecord.ObjectID == username || ArrayContainsLower(newRecord.Synonyms, username) {
			foundUser = newRecord
			break
		}
	}

	// Handling search within a workflow, and in the future, within apps
	if len(foundUser.ObjectID) == 0 {
		if len(username) == 36 {
			// Check workflows
			algoliaIndex := algClient.InitIndex("workflows")
			res, err := algoliaIndex.Search(username)
			if err != nil {
				log.Printf("[WARNING] Failed searching Algolia creator workflow: %s", err)
				return searchCreator, err
			}

			var newRecords []AlgoliaSearchWorkflow
			err = res.UnmarshalHits(&newRecords)
			if err != nil {
				log.Printf("[WARNING] Failed unmarshaling from Algolia creator workflow: %s", err)

				if len(newRecords) > 0 && len(newRecords[0].ObjectID) > 0 {
					log.Printf("[INFO] Workflow search ID: %#v", newRecords[0].ObjectID)
				} else {
					return searchCreator, err
				}
			}

			//log.Printf("[DEBUG] Got %d records for workflow sub", len(newRecords))
			if len(newRecords) == 1 {
				if len(newRecords[0].Creator) > 0 && username != newRecords[0].Creator {
					foundCreator, err := HandleAlgoliaCreatorSearch(ctx, newRecords[0].Creator)
					if err != nil {
						return searchCreator, err
					}

					foundUser = foundCreator
				} else {
					return searchCreator, errors.New("User not found")
				}
			} else {
				return searchCreator, errors.New("User not found")
			}
		} else {
			return searchCreator, errors.New("User not found")
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(foundUser)
		if err != nil {
			return foundUser, nil
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed updating algolia username cache: %s", err)
		}
	}

	return foundUser, nil
}

func HandleAlgoliaCreatorUpload(ctx context.Context, user User, overwrite bool, isOrg bool) (string, error) {
	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return "", errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("creators")
	res, err := algoliaIndex.Search(user.Id)
	if err != nil {
		log.Printf("[WARNING] Failed searching Algolia creators: %s", err)
		return "", err
	}

	var newRecords []AlgoliaSearchCreator
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia creators: %s", err)
		return "", err
	}

	//log.Printf("RECORDS: %d", len(newRecords))
	for _, newRecord := range newRecords {
		if newRecord.ObjectID == user.Id {
			log.Printf("[INFO] Object %s already exists in Algolia", user.Id)

			if overwrite {
				break
			} else {
				return user.Id, errors.New("User ID already exists!")
			}
		}
	}

	timeNow := int64(time.Now().Unix())
	records := []AlgoliaSearchCreator{
		AlgoliaSearchCreator{
			ObjectID:   user.Id,
			TimeEdited: timeNow,
			Image:      user.PublicProfile.GithubAvatar,
			Username:   user.PublicProfile.GithubUsername,
			IsOrg:      isOrg,
		},
	}

	_, err = algoliaIndex.SaveObjects(records)
	if err != nil {
		log.Printf("[WARNING] Algolia Object put err: %s", err)
		return "", err
	}

	log.Printf("[INFO] SUCCESSFULLY UPLOADED creator %s with ID %s TO ALGOLIA!", user.Username, user.Id)
	return user.Id, nil
}

func HandleAlgoliaCreatorDeletion(ctx context.Context, userId string) (error) {
	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("creators")
	res, err := algoliaIndex.Search(userId)
	if err != nil {
		log.Printf("[WARNING] Failed searching Algolia creators: %s", err)
		return err
	}

	var newRecords []AlgoliaSearchCreator
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia creators: %s", err)
		return err
	}

	//log.Printf("RECORDS: %d", len(newRecords))
	foundItem := AlgoliaSearchCreator{}
	for _, newRecord := range newRecords {
		if newRecord.ObjectID == userId {
			foundItem = newRecord
			break
		}
	}

	// Should delete it? 
	if len(foundItem.ObjectID) > 0 {
		_, err = algoliaIndex.DeleteObject(foundItem.ObjectID)
		if err != nil {
			log.Printf("[WARNING] Algolia Creator delete problem: %s", err)
			return err
		} 

		log.Printf("[INFO] Successfully removed creator %s with ID %s FROM ALGOLIA!", foundItem.Username, userId)
	}

	return nil
}

// Shitty temorary system
// Adding schedule to run over with another algorithm
// as well as this one, as to increase priority based on popularity:
// searches, clicks & conversions (CTR)
func GetWorkflowPriority(workflow Workflow) int {
	prio := 0
	if len(workflow.Tags) > 2 {
		prio += 1
	}

	if len(workflow.Name) > 5 {
		prio += 1
	}

	if len(workflow.Description) > 100 {
		prio += 1
	}

	if len(workflow.WorkflowType) > 0 {
		prio += 1
	}

	if len(workflow.UsecaseIds) > 0 {
		prio += 3
	}

	if len(workflow.Comments) >= 2 {
		prio += 2
	}

	return prio
}

func handleAlgoliaWorkflowUpdate(ctx context.Context, workflow Workflow) (string, error) {
	log.Printf("[INFO] Should try to UPLOAD the Workflow to Algolia")

	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return "", errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("workflows")

	//res, err := algoliaIndex.Search("%s", api.ID)
	res, err := algoliaIndex.Search(workflow.ID)
	if err != nil {
		log.Printf("[WARNING] Failed searching Algolia: %s", err)
		return "", err
	}

	var newRecords []AlgoliaSearchWorkflow
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia workflow upload: %s", err)
		return "", err
	}

	found := false
	record := AlgoliaSearchWorkflow{}
	for _, newRecord := range newRecords {
		if newRecord.ObjectID == workflow.ID {
			log.Printf("[INFO] Workflow Object %s already exists in Algolia", workflow.ID)
			record = newRecord
			found = true
			break
		}
	}

	if !found {
		return "", errors.New(fmt.Sprintf("Couldn't find public workflow for ID %s", workflow.ID))
	}

	record.TimeEdited = int64(time.Now().Unix())
	categories := []string{}
	actions := []string{}
	triggers := []string{}
	actionRefs := []ActionReference{}
	for _, action := range workflow.Actions {
		if !ArrayContains(actions, action.AppName) {
			// Using this API as the original is kinda stupid
			foundApps, err := HandleAlgoliaAppSearchByUser(ctx, action.AppName)
			if err == nil && len(foundApps) > 0 {
				actionRefs = append(actionRefs, ActionReference{
					Name:       foundApps[0].Name,
					Id:         foundApps[0].ObjectID,
					ImageUrl:   foundApps[0].ImageUrl,
					ActionName: []string{action.Name},
				})
			}

			actions = append(actions, action.AppName)
		} else {
			for refIndex, ref := range actionRefs {
				if ref.Name == action.AppName {
					if !ArrayContains(ref.ActionName, action.Name) {
						actionRefs[refIndex].ActionName = append(actionRefs[refIndex].ActionName, action.Name)
					}
				}
			}
		}
	}

	for _, trigger := range workflow.Triggers {
		if !ArrayContains(triggers, trigger.TriggerType) {
			triggers = append(triggers, trigger.TriggerType)
		}
	}

	if workflow.WorkflowType != "" {
		record.Type = workflow.WorkflowType
	}

	record.Name = workflow.Name
	record.Description = workflow.Description
	record.UsecaseIds = workflow.UsecaseIds
	record.Triggers = triggers
	record.Actions = actions
	record.TriggerAmount = len(triggers)
	record.ActionAmount = len(actions)
	record.Tags = workflow.Tags
	record.Categories = categories
	record.ActionReferences = actionRefs

	record.Priority = GetWorkflowPriority(workflow)
	record.Validated = workflow.Validated

	records := []AlgoliaSearchWorkflow{
		record,
	}

	//log.Printf("[WARNING] Returning before upload with data %#v", records)
	//return records[0].ObjectID, nil
	//return "", errors.New("Not prepared yet!")

	_, err = algoliaIndex.SaveObjects(records)
	if err != nil {
		log.Printf("[WARNING] Algolia Object update err: %s", err)
		return "", err
	}

	return workflow.ID, nil
}

// Returns an error if the users' org is over quota
func ValidateExecutionUsage(ctx context.Context, orgId string) (*Org, error) {
	if len(orgId) == 0 {
		return nil, errors.New("Org ID is empty")
	}

	org, err := GetOrg(ctx, orgId)
	if err != nil {
		return org, errors.New(fmt.Sprintf("Failed getting the organization %s: %s", orgId, err))
	}

	// Allows parent & childorgs to run as much as they want. No limitations
	if len(org.ChildOrgs) > 0 || len(org.ManagerOrgs) > 0 {
		//log.Printf("[DEBUG] Execution for org '%s' (%s) is allowed due to being a child-or parent org. This is only accessible to customers. We're not force-stopping them.", org.Name, org.Id)
		return org, nil
	}

	info, err := GetOrgStatistics(ctx, orgId)
	if err == nil {
		//log.Printf("[DEBUG] Found executions for org %s (%s): %d", org.Name, org.Id, info.MonthlyAppExecutions)
		org.SyncFeatures.AppExecutions.Usage = info.MonthlyAppExecutions
		if org.SyncFeatures.AppExecutions.Limit <= 10000 {
			org.SyncFeatures.AppExecutions.Limit = 10000
		} else {
			// FIXME: Not strictly enforcing other limits yet
			// Should just warn our team about them going over
			org.SyncFeatures.AppExecutions.Limit = 15000000000
		}

		//log.Printf("[DEBUG] Org %s (%s) has values: org.LeadInfo.POV: %v, org.LeadInfo.Internal: %v", org.Name, org.Id, org.LeadInfo.POV, org.LeadInfo.Internal) 

		// FIXME: When inside this, check if usage should be sent to the user
		if (org.SyncFeatures.AppExecutions.Usage > org.SyncFeatures.AppExecutions.Limit) && !(org.LeadInfo.POV || org.LeadInfo.Internal) {
			return org, errors.New(fmt.Sprintf("You are above your limited usage of app executions this month (%d / %d) when running with triggers. Contact support@shuffler.io or the live chat to extend this for org %s (%s)", org.SyncFeatures.AppExecutions.Usage, org.SyncFeatures.AppExecutions.Limit, org.Name, org.Id))
		}

		return org, nil
	} else {
		//log.Printf("[WARNING] Failed finding executions for org %s (%s)", org.Name, org.Id)
	}

	return org, nil
}

func RunActionAI(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in get action AI: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := GetContext(request)
	org, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed getting the organization`)))
		return
	}

	log.Printf("[DEBUG] Running action AI for org %s (%s). Cloud sync: %#v and %#v", org.Name, org.Id, org.CloudSyncActive, org.CloudSync)
	if !org.CloudSync {
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Cloud sync is not active for this organization"}`)))
		return
	}

	// For now, just redirecting
	log.Printf("[DEBUG] Redirecting Action AI request to main site handler (shuffler.io)")

	// Add api-key from the org sync
	if org.SyncConfig.Apikey != "" {
		request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", org.SyncConfig.Apikey))

		// Remove cookie header after checking if it exists
		if request.Header.Get("Cookie") != "" {
			request.Header.Del("Cookie")
		}
	}

	RedirectUserRequest(resp, request)
	return
}

func RedirectUserRequest(w http.ResponseWriter, req *http.Request) {
	proxyScheme := "https"
	proxyHost := fmt.Sprintf("shuffler.io")

	httpClient := &http.Client{
		Timeout: 120 * time.Second,
	}

	//fmt.Fprint(resp, "OK")
	//http.Redirect(resp, request, "https://europe-west2-shuffler.cloudfunctions.net/ShuffleSSR", 303)
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Printf("[ERROR] Issue in SSR body proxy: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//req.Body = ioutil.NopCloser(bytes.NewReader(body))
	url := fmt.Sprintf("%s://%s%s", proxyScheme, proxyHost, req.RequestURI)
	log.Printf("[DEBUG] Request (%s) request URL: %s. More: %s", req.Method, url, req.URL.String())

	proxyReq, err := http.NewRequest(req.Method, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[ERROR] Failed handling proxy request: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// We may want to filter some headers, otherwise we could just use a shallow copy
	proxyReq.Header = make(http.Header)
	for h, val := range req.Header {
		proxyReq.Header[h] = val
	}

	newresp, err := httpClient.Do(proxyReq)
	if err != nil {
		log.Printf("[ERROR] Issue in SSR newresp for %s - should retry: %s", url, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	defer newresp.Body.Close()
	urlbody, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	//log.Printf("RESP: %s", urlbody)
	for key, value := range newresp.Header {
		//log.Printf("%s %s", key, value)
		for _, item := range value {
			w.Header().Set(key, item)
		}
	}

	w.WriteHeader(newresp.StatusCode)
	w.Write(urlbody)

	// Need to clear cache in case user gets updated in db
	// with a new session and such. This only forces a new search,
	// and shouldn't get them logged out
	ctx := GetContext(req)
	c, err := req.Cookie("session_token")
	if err != nil {
		c, err = req.Cookie("__session")
	}

	if err == nil {
		DeleteCache(ctx, fmt.Sprintf("session_%s", c.Value))
	}
}

// Checks if a specific user should have "self" access to a creator user
// A creator user can be both a user and an org, so this got a bit tricky
func CheckCreatorSelfPermission(ctx context.Context, requestUser, creatorUser User, algoliaUser *AlgoliaSearchCreator) bool {
	if project.Environment != "cloud" {
		return false
	}

	if creatorUser.Id == requestUser.Id {
		return true
	} else {
		for _, user := range algoliaUser.Synonyms {
			if user == requestUser.Id {
				return true
			}
		}

		if algoliaUser.IsOrg {
			log.Printf("[AUDIT] User %s (%s) is an org. Checking if the current user should have access.", algoliaUser.Username, algoliaUser.ObjectID)
			// Get the org and check
			org, err := GetOrgByCreatorId(ctx, algoliaUser.ObjectID)
			if err != nil {
				log.Printf("[WARNING] Couldn't find org for creator %s (%s): %s", algoliaUser.Username, algoliaUser.ObjectID, err)
				return false
			}

			log.Printf("[AUDIT] Found org %s (%s) for creator %s (%s)", org.Name, org.Id, algoliaUser.Username, algoliaUser.ObjectID)
			for _, user := range org.Users {
				if user.Id == requestUser.Id {
					if user.Role == "admin" {
						return true
					}

					break
				}
			}

		}
	}

	return false 
}

// Uploads updates for a workflow to a specific file on git
func SetGitWorkflow(ctx context.Context, workflow Workflow, org *Org) error {
	if workflow.BackupConfig.UploadRepo != "" && workflow.BackupConfig.UploadBranch != "" && workflow.BackupConfig.UploadUsername != "" && workflow.BackupConfig.UploadToken != "" {
		//log.Printf("\n\n\n[DEBUG] Using workflow backup config for org %s (%s)\n\n\n", org.Name, org.Id)

		org.Defaults.WorkflowUploadRepo = workflow.BackupConfig.UploadRepo
		org.Defaults.WorkflowUploadBranch = workflow.BackupConfig.UploadBranch
		org.Defaults.WorkflowUploadUsername = workflow.BackupConfig.UploadUsername
		org.Defaults.WorkflowUploadToken = workflow.BackupConfig.UploadToken
	}


	if org.Defaults.WorkflowUploadRepo == "" || org.Defaults.WorkflowUploadBranch == "" || org.Defaults.WorkflowUploadUsername == "" || org.Defaults.WorkflowUploadToken == "" {
		//log.Printf("[DEBUG] No workflow upload repo for org %s (%s)", org.Name, org.Id)
		return nil
	}

	org.Defaults.WorkflowUploadRepo = strings.TrimSpace(org.Defaults.WorkflowUploadRepo)
	if strings.HasPrefix(org.Defaults.WorkflowUploadRepo, "https://") {
		org.Defaults.WorkflowUploadRepo = strings.Replace(org.Defaults.WorkflowUploadRepo, "https://", "", 1)
		org.Defaults.WorkflowUploadRepo = strings.Replace(org.Defaults.WorkflowUploadRepo, "http://", "", 1)
	}

	if strings.HasSuffix(org.Defaults.WorkflowUploadRepo, ".git") {
		org.Defaults.WorkflowUploadRepo = strings.TrimSuffix(org.Defaults.WorkflowUploadRepo, ".git")
	}

	//log.Printf("[DEBUG] Uploading workflow %s to repo %s for org %s (%s)", workflow.ID, org.Defaults.WorkflowUploadRepo, org.Name, org.Id)

	// Remove images
	workflow.Image = ""
	for actionIndex, _ := range workflow.Actions {
		workflow.Actions[actionIndex].LargeImage = ""
		workflow.Actions[actionIndex].SmallImage = ""
	}

	for triggerIndex, _ := range workflow.Triggers {
		workflow.Triggers[triggerIndex].LargeImage = ""
		workflow.Triggers[triggerIndex].SmallImage = ""
	}

	// Use git to upload the workflow. 
	workflowData, err := json.MarshalIndent(workflow, "", "  ")
	if err != nil {
		log.Printf("[ERROR] Failed marshalling workflow %s (%s) for git upload: %s", workflow.Name, workflow.ID, err)
		return err
	}

	commitMessage := fmt.Sprintf("User '%s' updated workflow '%s' with status '%s'", workflow.UpdatedBy, workflow.Name, workflow.Status)
	location := fmt.Sprintf("https://%s:%s@%s.git", org.Defaults.WorkflowUploadUsername, org.Defaults.WorkflowUploadToken, org.Defaults.WorkflowUploadRepo)

	log.Printf("[DEBUG] Uploading workflow %s to repo: %s", workflow.ID, strings.Replace(location, org.Defaults.WorkflowUploadToken, "SCRAMBLED", -1))

	fs := memfs.New()
	if len(workflow.Status) == 0 {
		workflow.Status = "test"
	}
	//filePath := fmt.Sprintf("/%s/%s.json", workflow.Status, workflow.ID)
	filePath := fmt.Sprintf("%s/%s/%s_%s.json", workflow.ExecutingOrg.Id, workflow.Status, strings.ReplaceAll(workflow.Name, " ", "-"), workflow.ID)

	// Specify the file path within the repository
	repo, err := git.Clone(memory.NewStorage(), fs, &git.CloneOptions{
    	URL: location,
	})

	// Initialize a new Git repository in memory
	w := &git.Worktree{}
	if err != nil {
		log.Printf("[ERROR] Error cloning repo: %s", err)
		return err
	} 

	// Create a new commit with the in-memory file
	w, err = repo.Worktree()
	if err != nil {
		log.Printf("[ERROR] Error getting worktree (2): %s", err)
		return err
	}

	// Write the byte blob to the in-memory file system
	file, err := fs.Create(filePath)
	if err != nil {
		log.Printf("[ERROR] Creating file: %v", err)
		return err
	}

	defer file.Close()
	//_, err = io.Copy(file, bytes.NewReader(workflowData))
	_, err = io.Copy(file, bytes.NewReader(workflowData))
	if err != nil {
		log.Printf("[ERROR] Writing data to file: %v", err)
		return err
	}

	// Add the file to the staging area
	_, err = w.Add(filePath)
	if err != nil {
		log.Printf("[ERROR] Error adding file to staging area (2): %s", err)
		return err
	}

	// Commit the changes
	commit, err := w.Commit(commitMessage, &git.CommitOptions{
		Author: &object.Signature{
			Name:  org.Defaults.WorkflowUploadUsername,
			Email: "",
			When:  time.Now(),
		},
	})
	if err != nil {
		log.Printf("[ERROR] Committing changes: %v (2)", err)
		return err
	}

		// Print the commit hash
	log.Printf("[DEBUG] Commit Hash: %s", commit)

	// Push the changes to a remote repository (replace URL with your repository URL)
	// fmt.Sprintf("refs/heads/%s:refs/heads/%s", org.Defaults.WorkflowUploadBranch, org.Defaults.WorkflowUploadBranch)},
	ref := fmt.Sprintf("refs/heads/%s:refs/heads/%s", org.Defaults.WorkflowUploadBranch, org.Defaults.WorkflowUploadBranch)
	err = repo.Push(&git.PushOptions{
		RemoteName: "origin",
		RefSpecs:   []config.RefSpec{config.RefSpec(ref)},
		RemoteURL:  location,
	})
	if err != nil {
		log.Printf("[ERROR] Pushing changes: %v (2)", err)
		return err
	}

	log.Println("[DEBUG] File uploaded successfully!")



	return nil
}

// Creates osfs from folderpath with a basepath as directory base
func CreateFs(basepath, pathname string) (billy.Filesystem, error) {
	log.Printf("[INFO] MemFS base: %s, pathname: %s", basepath, pathname)

	fs := memfs.New()
	err := filepath.Walk(pathname,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if strings.Contains(path, ".git") {
				return nil
			}

			// Fix the inner path here
			newpath := strings.ReplaceAll(path, pathname, "")
			fullpath := fmt.Sprintf("%s%s", basepath, newpath)
			switch mode := info.Mode(); {
			case mode.IsDir():
				err = fs.MkdirAll(fullpath, 0644)
				if err != nil {
					log.Printf("Failed making folder: %s", err)
				}
			case mode.IsRegular():
				srcData, err := ioutil.ReadFile(path)
				if err != nil {
					log.Printf("Src error: %s", err)
					return err
				}

				dst, err := fs.Create(fullpath)
				if err != nil {
					log.Printf("Dst error: %s", err)
					return err
				}

				_, err = dst.Write(srcData)
				if err != nil {
					log.Printf("Dst write error: %s", err)
					return err
				}
			}

			return nil
		})

	return fs, err
}
