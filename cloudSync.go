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

	uuid "github.com/satori/go.uuid"
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
		// if (org.SyncFeatures.AppExecutions.Usage > org.SyncFeatures.AppExecutions.Limit) && !(org.LeadInfo.POV || org.LeadInfo.Internal) {
		if (org.SyncFeatures.AppExecutions.Usage > org.SyncFeatures.AppExecutions.Limit) && !(org.LeadInfo.POV) {
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
	//log.Printf("[DEBUG] Request (%s) request URL: %s. More: %s", req.Method, url, req.URL.String())

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
	if workflow.BackupConfig.UploadRepo != "" || workflow.BackupConfig.UploadBranch != "" || workflow.BackupConfig.UploadUsername != "" || workflow.BackupConfig.UploadToken != "" {
		//log.Printf("\n\n\n[DEBUG] Using workflow backup config for org %s (%s)\n\n\n", org.Name, org.Id)

		org.Defaults.WorkflowUploadRepo = workflow.BackupConfig.UploadRepo
		org.Defaults.WorkflowUploadBranch = workflow.BackupConfig.UploadBranch
		org.Defaults.WorkflowUploadUsername = workflow.BackupConfig.UploadUsername
		org.Defaults.WorkflowUploadToken = workflow.BackupConfig.UploadToken

		// FIXME: Decrypt here 
		if workflow.BackupConfig.TokensEncrypted {
			log.Printf("[DEBUG] Should realtime decrypt token for org %s (%s)", org.Name, org.Id) 
			org.Defaults.TokensEncrypted = true
		} else {
			org.Defaults.TokensEncrypted = false 
		}
	}

	if org.Defaults.TokensEncrypted == true {
		log.Printf("[DEBUG] Decrypting token for org %s (%s)", org.Name, org.Id)

		parsedKey := fmt.Sprintf("%s_upload_token", org.Id)
		newValue, err := HandleKeyDecryption([]byte(org.Defaults.WorkflowUploadToken), parsedKey)
		if err != nil {
			log.Printf("[ERROR] Failed decrypting token for org %s (%s): %s", org.Name, org.Id, err)
		} else {
			org.Defaults.WorkflowUploadToken = string(newValue)
		}

		parsedKey = fmt.Sprintf("%s_upload_username", org.Id)
		newValue, err = HandleKeyDecryption([]byte(org.Defaults.WorkflowUploadUsername), parsedKey)
		if err != nil {
			log.Printf("[ERROR] Failed decrypting username for org %s (%s): %s", org.Name, org.Id, err)
		} else {
			org.Defaults.WorkflowUploadUsername = string(newValue)
		}

		parsedKey = fmt.Sprintf("%s_upload_repo", org.Id)
		newValue, err = HandleKeyDecryption([]byte(org.Defaults.WorkflowUploadRepo), parsedKey)
		if err != nil {
			log.Printf("[ERROR] Failed decrypting repo for org %s (%s): %s", org.Name, org.Id, err)
		} else {
			org.Defaults.WorkflowUploadRepo = string(newValue)
		}

		parsedKey = fmt.Sprintf("%s_upload_branch", org.Id)
		newValue, err = HandleKeyDecryption([]byte(org.Defaults.WorkflowUploadBranch), parsedKey)
		if err != nil {
			log.Printf("[ERROR] Failed decrypting branch for org %s (%s): %s", org.Name, org.Id, err)
		} else {
			org.Defaults.WorkflowUploadBranch = string(newValue)
		}

		log.Printf("[DEBUG] Decrypted token for org %s (%s): %s", org.Name, org.Id, newValue)
	}

	if len(org.Defaults.WorkflowUploadBranch) == 0 {
		org.Defaults.WorkflowUploadBranch = "master"
	}


	if org.Defaults.WorkflowUploadRepo == "" || org.Defaults.WorkflowUploadToken == "" {
		//log.Printf("[DEBUG] Missing Repo/Token during Workflow backup upload for org %s (%s)", org.Name, org.Id)
		//return errors.New("Missing repo or token")
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

	// remove github backup info
	workflow.BackupConfig = BackupConfig{}

	// Use git to upload the workflow. 
	workflowData, err := json.MarshalIndent(workflow, "", "  ")
	if err != nil {
		log.Printf("[ERROR] Failed marshalling workflow %s (%s) for git upload: %s", workflow.Name, workflow.ID, err)
		return err
	}

	commitMessage := fmt.Sprintf("User '%s' updated workflow '%s' with status '%s'", workflow.UpdatedBy, workflow.Name, workflow.Status)
	urlEncodedPassword := url.QueryEscape(org.Defaults.WorkflowUploadToken)
	location := fmt.Sprintf("https://%s:%s@%s.git", org.Defaults.WorkflowUploadUsername, urlEncodedPassword, org.Defaults.WorkflowUploadRepo)

	newRepoName := strings.Replace(strings.Replace(location, org.Defaults.WorkflowUploadToken, "****", -1), urlEncodedPassword, "****", -1)
	log.Printf("[DEBUG] Uploading workflow %s to repo: %s", workflow.ID, newRepoName)

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
	if err != nil {
		newErr := strings.ReplaceAll(err.Error(), org.Defaults.WorkflowUploadToken, "****")
		newErr = strings.ReplaceAll(newErr, urlEncodedPassword, "****")

		log.Printf("[ERROR] Error cloning repo '%s' (workflow backup): %s", newRepoName, newErr)
		return err
	} 

	// Initialize a new Git repository in memory
	w := &git.Worktree{}

	// Create a new commit with the in-memory file
	w, err = repo.Worktree()
	if err != nil {
		newErr := strings.ReplaceAll(err.Error(), org.Defaults.WorkflowUploadToken, "****")
		newErr = strings.ReplaceAll(newErr, urlEncodedPassword, "****")

		log.Printf("[ERROR] Error getting worktree for repo '%s' (2): %s", newRepoName, newErr)
		return err
	}

	// Write the byte blob to the in-memory file system
	file, err := fs.Create(filePath)
	if err != nil {
		newErr := strings.ReplaceAll(err.Error(), org.Defaults.WorkflowUploadToken, "****")

		log.Printf("[ERROR] Creating git file: %v", newErr)
		return err
	}

	defer file.Close()
	//_, err = io.Copy(file, bytes.NewReader(workflowData))
	_, err = io.Copy(file, bytes.NewReader(workflowData))
	if err != nil {
		log.Printf("[ERROR] Writing data to git file: %v", err)
		return err
	}

	// Add the file to the staging area
	_, err = w.Add(filePath)
	if err != nil {
		log.Printf("[ERROR] Error adding file to git staging area (2): %s", err)
		return err
	}

	// Commit the changes
	_, err = w.Commit(commitMessage, &git.CommitOptions{
		Author: &object.Signature{
			Name:  org.Defaults.WorkflowUploadUsername,
			Email: "",
			When:  time.Now(),
		},
	})
	if err != nil {
		log.Printf("[ERROR] Committing git changes: %v (2)", err)
		return err
	}

	//log.Printf("[DEBUG] Commit Hash: %s", commit)

	// Push the changes to a remote repository (replace URL with your repository URL)
	// fmt.Sprintf("refs/heads/%s:refs/heads/%s", org.Defaults.WorkflowUploadBranch, org.Defaults.WorkflowUploadBranch)},
	ref := fmt.Sprintf("refs/heads/%s:refs/heads/%s", org.Defaults.WorkflowUploadBranch, org.Defaults.WorkflowUploadBranch)
	err = repo.Push(&git.PushOptions{
		RemoteName: "origin",
		RefSpecs:   []config.RefSpec{config.RefSpec(ref)},
		RemoteURL:  location,
	})
	if err != nil {
		log.Printf("[ERROR] Change git Push issue: %v (2)", err)
		return err
	}

	log.Printf("[DEBUG] File uploaded successfully to '%s'!", newRepoName)



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


func loadAppConfigFromMain(fileId string) {
	// Send request to /api/v1/apps/{fileId}/config
	// Parse out the config and add it to the database
	ctx := context.Background()

	app, err := GetApp(ctx, fileId, User{}, false)
	if err == nil && len(app.Name) > 0 && len(app.ID) > 0 {
		log.Printf("[INFO] Found app %s (%s) for config loading. Running cross-region DOWNLOAD shuffler.io->local", app.Name, app.ID)
	}

	app.ID = fileId

	backendHost := fmt.Sprintf("https://shuffler.io")
	appApi := fmt.Sprintf("%s/api/v1/apps/%s/config", backendHost, fileId)
	client := &http.Client{}
	req, err := http.NewRequest(
		"GET", 
		appApi, 
		nil,
	)

	if err != nil {
		log.Printf("[ERROR] Failed creating request for app config: %s", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed getting app config: %s", err)
		return
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Printf("[ERROR] Failed getting app config for ID %s: %d", fileId, resp.StatusCode)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading app config: %s", err)
		return
	}

	newApp := AppParser{}
	err = json.Unmarshal(body, &newApp)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshaling app config: %s", err)
		return
	}

	//log.Printf("[INFO] Got app config: %s", string(body))
	if !newApp.Success {
		log.Printf("[ERROR] No success in app config for id %s", fileId)
		return
	}

	if len(newApp.App) == 0 {
		log.Printf("[ERROR] No app found for id %s", app.ID)
	} else {

		err = json.Unmarshal(newApp.App, &app)
		if err != nil {
			log.Printf("[ERROR] Failed unmarshaling app for id %s: %s", app.ID, err)
			return
		}

		err = SetWorkflowAppDatastore(ctx, *app, app.ID)
		if err != nil {
			log.Printf("[ERROR] Failed saving app for id %s: %s", app.ID, err)
		}
	}

	if len(newApp.OpenAPI) == 0 {
		log.Printf("[ERROR] No openapi found for id %s", app.ID)
	} else {
		// Save the data to the database with the ParsedOpenApi struct
		parsedOpenApi := ParsedOpenApi{}
		err = json.Unmarshal(newApp.OpenAPI, &parsedOpenApi)
		if err != nil {
			log.Printf("[ERROR] Failed unmarshaling openapi for id %s: %s", app.ID, err)
			return
		}

		err = SetOpenApiDatastore(ctx, parsedOpenApi.ID, parsedOpenApi)
		if err != nil {
			log.Printf("[ERROR] Failed saving openapi for id %s: %s", app.ID, err)
		}

		// FIXME: Send it to get built as well as cloud function
		// What is the function for this? Maybe just send localhost/api/ request?
		// Run verify openapi here (?)

		baseurl := "http://localhost:5002"
		if os.Getenv("BASE_URL") != "" {
			baseurl = os.Getenv("BASE_URL")
		}

		if os.Getenv("SHUFFLE_CLOUDRUN_URL") != "" {
			baseurl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
		}

		fullUrl := fmt.Sprintf("%s/api/v1/verify_swagger", baseurl)
		req, err := http.NewRequest(
			"POST",
			fullUrl,
			bytes.NewBuffer(newApp.OpenAPI),
		)

		if err != nil {
			log.Printf("[ERROR] Failed creating request for openapi verification: %s", err)
			return
		}

		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[ERROR] Failed verifying openapi: %s", err)
			return
		}

		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			log.Printf("[ERROR] Failed building openapi for ID %s: %d", fileId, resp.StatusCode)
			return
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed reading openapi verification: %s", err)
			return
		}

		log.Printf("[INFO] OpenAPI build: %s", string(body))
	}
}

// Also deactivates. It's a toggle for off and on.
func ActivateWorkflowApp(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get active apps: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to activate workflow app (shared): %s (%s)", user.Username, user.Id)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	ctx := GetContext(request)
	location := strings.Split(request.URL.String(), "/")
	var fileId string
	activate := true
	shouldDistributeToLocation := false 
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
		if strings.ToLower(location[5]) == "deactivate" {
			activate = false
		}

		if strings.ToLower(location[5]) == "distribute" {
			shouldDistributeToLocation = true
		}
	}

	app, err := GetApp(ctx, fileId, user, false)
	if err != nil {
		appName := request.URL.Query().Get("app_name")
		appVersion := request.URL.Query().Get("app_version")

		if len(appName) > 0 && len(appVersion) > 0 {
			apps, err := FindWorkflowAppByName(ctx, appName)
			//log.Printf("[INFO] Found %d apps for %s", len(apps), appName)
			if err != nil || len(apps) == 0 {
				log.Printf("[WARNING] Error getting app from name '%s' (app config): %s", appName, err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "App doesn't exist"}`))
				return
			}

			selectedApp := WorkflowApp{}
			for _, app := range apps {
				if !app.Sharing && !app.Public {
					continue
				}

				if app.Name == appName {
					selectedApp = app
				}

				if app.Name == appName && app.AppVersion == appVersion {
					selectedApp = app
				}
			}

			app = &selectedApp
		} else {
			log.Printf("[WARNING] Error getting app with ID %s (app config): %s", fileId, err)


			// Automatic propagation to cloud regions
			if project.Environment == "cloud" && gceProject != "shuffler" {
				app, err := HandleAlgoliaAppSearch(ctx, fileId)
				if err == nil {
					// this means that the app exists. so, let's
					// ask our propagator to proagate it further.
					log.Printf("[INFO] Found apps %s - %s in algolia", app.Name, app.ObjectID)

					if app.ObjectID != fileId {
						log.Printf("[WARNING] App %s doesn't exist in algolia", fileId)
						resp.WriteHeader(401)
						resp.Write([]byte(`{"success": false, "reason": "App doesn't exist"}`))
						return
					}
					// i can in theory, run this without using goroutines
					// and then recursively call the same function. but that
					// would make this request way too long.
					go func() {
						err = propagateApp(fileId, false)
						if err != nil {
							log.Printf("[WARNING] Error propagating app %s - %s: %s", app.Name, app.ObjectID, err)
						} else {
							log.Printf("[INFO] Propagated app %s - %s. Sending request again!", app.Name, app.ObjectID)
						}
					}()

					resp.WriteHeader(202)
					resp.Write([]byte(`{"success": false, "reason": "Taking care of some magic. Please try activation again in a few seconds!"}`))
					return
				} else {
					log.Printf("[WARNING] Error getting app %s (algolia): %s", appName, err)
				}
			} else if project.Environment == "cloud" && gceProject == "shuffler" {
				// Automatic deletion in the main region if the app doesn't exist
				if len(app.ID) == 0 {
					log.Printf("[INFO] Auto-Removing app %s from Algolia as it doesn't exist with the same ID anymore. Request source: %s (%s) in org %s (%s)", fileId, user.Username, user.Id, user.ActiveOrg.Name, user.ActiveOrg.Id)

					algoliaClient := os.Getenv("ALGOLIA_CLIENT")
					algoliaSecret := os.Getenv("ALGOLIA_SECRET")
					if len(algoliaClient) > 0 && len(algoliaSecret) > 0 {

						algClient := search.NewClient(algoliaClient, algoliaSecret)
						algoliaIndex := algClient.InitIndex("appsearch")
						_, err = algoliaIndex.DeleteObject(fileId)
						if err != nil {
							resp.WriteHeader(500)
							resp.Write([]byte(`{"success": false, "reason": "Failed removing the app from Algolia"}`))
							return
						}
					}
				}
			}

			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "App doesn't exist"}`))
			return
		}
	}

	if activate == false && app.ReferenceOrg == user.ActiveOrg.Id {
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Can't remove app from current org as it is the owner org."}`))
		return
	}

	org := &Org{}
	added := false
	if app.Sharing || app.Public || !activate {
		org, err = GetOrg(ctx, user.ActiveOrg.Id)
		if err == nil {
			if len(org.ActiveApps) > 150 {
				// No reason for it to be this big. Arbitrarily reducing.
				same := []string{}
				samecnt := 0
				for _, activeApp := range org.ActiveApps {
					if ArrayContains(same, activeApp) {
						samecnt += 1
						continue
					}

					same = append(same, activeApp)
				}

				added = true
				//log.Printf("Same: %d, total uniq: %d", samecnt, len(same))
				org.ActiveApps = org.ActiveApps[len(org.ActiveApps)-100 : len(org.ActiveApps)-1]
			}

			if activate {
				if !ArrayContains(org.ActiveApps, app.ID) {
					org.ActiveApps = append(org.ActiveApps, app.ID)
					added = true
				}
			} else {
				// Remove from the array
				newActiveApps := []string{}
				for _, activeApp := range org.ActiveApps {
					if activeApp == app.ID {
						continue
					}

					newActiveApps = append(newActiveApps, activeApp)
				}

				org.ActiveApps = newActiveApps
				added = true
			}

			if added {
				err = SetOrg(ctx, *org, org.Id)
				if err != nil {
					log.Printf("[WARNING] Failed setting org when autoadding apps on save: %s", err)
				} else {
					addRemove := "Added"
					if !activate {
						addRemove = "Removed"
					}

					log.Printf("[INFO] %s public app %s (%s) to/from org %s (%s). Activated apps: %d", addRemove, app.Name, app.ID, user.ActiveOrg.Name, user.ActiveOrg.Id, len(org.ActiveApps))
					DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
					DeleteCache(ctx, fmt.Sprintf("apps_%s", user.ActiveOrg.Id))

					if project.Environment == "cloud" && gceProject != "shuffler" {
						// propagate org.ActiveApps to the main region
						go func() {
							// wait for a second before propagating again
							log.Printf("[INFO] Propagating org %s after sleeping for a second!", user.ActiveOrg.Id)
							time.Sleep(1 * time.Second)
							err = propagateOrg(*org, true)
							if err != nil {
								log.Printf("[WARNING] Error propagating org %s: %s", user.ActiveOrg.Id, err)
							}
						}()
					}

				}
			}
		}
	} else {
		log.Printf("[WARNING] User is trying to activate %s which is NOT a public app", app.Name)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if shouldDistributeToLocation {
		// Distribute to runtime Locations
		allEnvironments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("[ERROR] Failed getting environments for org %s: %s", user.ActiveOrg.Id, err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed getting environments"}`))
			return
		}

		relevantEnvironments := []Environment{}
		for _, env := range allEnvironments {
			if strings.ToLower(env.Type) == "cloud" {
				continue
			}

			if env.Archived {
				continue
			}

			relevantEnvironments = append(relevantEnvironments, env)
		}

		if len(relevantEnvironments) == 0 {
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "No relevant environments"}`))
			return
		}


		appName := fmt.Sprintf("%s_%s", strings.ToLower(strings.ReplaceAll(app.Name, " ", "-")), app.AppVersion)
		if project.Environment == "cloud" {
			if app.Public == true { 
			} else {
				appName = fmt.Sprintf("%s_%s", strings.ToLower(strings.ReplaceAll(app.Name, " ", "-")), app.ID)
			}
		}

		for _, env := range relevantEnvironments {
			//log.Printf("[INFO] Distributing app %s to environment %s", app.Name, env.Name)
			request := ExecutionRequest{
				Type:              "DOCKER_IMAGE_DOWNLOAD",
				ExecutionId:       uuid.NewV4().String(),
				ExecutionArgument: fmt.Sprintf("frikky/shuffle:%s", appName),
				Priority:          11,
			}

			parsedId := fmt.Sprintf("%s_%s", strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(env.Name, " ", "-"), "_", "-")), env.OrgId)
			err = SetWorkflowQueue(ctx, request, parsedId)
			if err != nil {
				log.Printf("[ERROR] Failed setting workflow queue for env: %s", err)
				continue
			}
		}


		resp.WriteHeader(200)
		resp.Write([]byte(`{"success": true, "reason": "Re-download request sent to all relevant environments"}`))
		return
	}

	if activate {
		log.Printf("[DEBUG] App %s (%s) activated for org %s by user %s (%s). Active apps: %d. Already existed: %t", app.Name, app.ID, user.ActiveOrg.Id, user.Username, user.Id, len(org.ActiveApps), !added)
	} else {
		log.Printf("[DEBUG] App %s (%s) deactivated for org %s by user %s (%s). Active apps: %d. Already existed: %t", app.Name, app.ID, user.ActiveOrg.Id, user.Username, user.Id, len(org.ActiveApps), !added)
	}

	DeleteCache(ctx, fmt.Sprintf("apps_%s", user.ActiveOrg.Id))
	DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
	DeleteCache(ctx, "all_apps")
	DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-100"))
	DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-500"))
	DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-1000"))

	// If onprem, it should autobuild the container(s) from here
	if project.Environment == "cloud" && gceProject != "shuffler" {
		go loadAppConfigFromMain(fileId)

		RedirectUserRequest(resp, request)
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

// For replicating HTTP request from schedule user
func HandleSuborgScheduleRun(request *http.Request, workflow *Workflow) {
	ctx := context.Background()
	if len(workflow.SuborgDistribution) == 0 {
		log.Printf("[WARNING] No suborgs to run for workflow %s", workflow.ID)
		return
	}

	// Finding first one.
	originalTriggerId := ""
	for _, trigger := range workflow.Triggers {
		if trigger.TriggerType == "SCHEDULE" {
			originalTriggerId = trigger.ID
			break
		}
	}

	if len(originalTriggerId) == 0 {
		return
	}

	// 1. Get child workflows of workflow
	// 2. Map to the right ones
	childWorkflows, err := ListChildWorkflows(ctx, workflow.ID) 
	if err != nil {
		log.Printf("[ERROR] Failed getting child workflows for parent workflow %s: %s", workflow.ID, err)
		return
	}

	client := http.Client{}
	for _, childWorkflow := range childWorkflows {
		if childWorkflow.ID == workflow.ID {
			continue
		}

		if childWorkflow.OrgId == workflow.OrgId {
			continue
		}

		// Check if the OrgId is still in the workflow.Sub
		found := false 
		for _, suborg := range workflow.SuborgDistribution {
			if childWorkflow.OrgId == suborg {
				found = true
				break
			}
		}

		if !found {
			continue
		}

		// Ensuring the trigger still exists in the child
		found = false
		for _, trigger := range childWorkflow.Triggers {
			if trigger.ReplacementForTrigger == originalTriggerId {
				found = true
				break
			}
		}

		if !found {
			continue
		}

		log.Printf("[DEBUG] Should be running %s schedule suborg workflows", childWorkflow.ID)
		go func(client http.Client, request *http.Request, childWorkflow Workflow) {
			baseurl := "https://shuffler.io"
			if os.Getenv("BASE_URL") != "" {
				baseurl = os.Getenv("BASE_URL")
			}

			if os.Getenv("SHUFFLE_CLOUDRUN_URL") != "" {
				baseurl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
			}

			body, err := ioutil.ReadAll(request.Body)
			if err != nil {
				log.Printf("[ERROR] Failed reading body from schedule request: %s", err)
				return
			}

			request.Body = io.NopCloser(bytes.NewBuffer(body))
			formattedUrl := fmt.Sprintf("%s/api/v1/workflows/%s/run", baseurl, childWorkflow.ID)
			req, err := http.NewRequest(
				"POST",
				formattedUrl,
				bytes.NewBuffer(body),
			)

			if err != nil {
				log.Printf("[WARNING] Failed mapping child workflow schedule: %s", err)
				return
			}

			for key, value := range request.Header {
				req.Header.Set(key, value[0])
			}

			newresp, err := client.Do(req)
			if err != nil {
				log.Printf("[ERROR] Failed running child workflow schedule: %s", err)
				return 
			}

			defer newresp.Body.Close()
			if newresp.StatusCode == 200 {
				log.Printf("[DEBUG] Started suborg workflow from schedule. Parent: %s. Child: %s", childWorkflow.ParentWorkflowId, childWorkflow.ID)
			} else {
				respBody, err := ioutil.ReadAll(newresp.Body)
				if err != nil {
					log.Printf("[ERROR] Failed to read body from failed newresp")
					return
				}

				log.Printf("[ERROR] Failed to start suborg workflow from schedule with status %d. Parent: %s. Child: %s. Raw Body: %s", newresp.StatusCode, childWorkflow.ParentWorkflowId, childWorkflow.ID, string(respBody))
			}

		}(client, request, childWorkflow)
	}
}
