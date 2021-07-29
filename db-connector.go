package shuffle

import (
	"bytes"
	"cloud.google.com/go/datastore"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bradfitz/slice"
	"io/ioutil"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"github.com/frikky/go-elasticsearch/v8/esapi"
	"github.com/patrickmn/go-cache"
	"github.com/satori/go.uuid"
	"google.golang.org/api/iterator"

	"cloud.google.com/go/storage"
	"google.golang.org/appengine/memcache"
)

var err error
var requestCache *cache.Cache

var maxCacheSize = 1020000

//var maxCacheSize = 2000000

// Cache handlers
func DeleteCache(ctx context.Context, name string) error {
	if project.Environment == "cloud" {
		return memcache.Delete(ctx, name)
	} else if project.Environment == "onprem" {
		requestCache.Delete(name)
		return nil
	} else {
		return errors.New(fmt.Sprintf("No cache handler for environment %s yet WHILE DELETING", project.Environment))
	}

	return errors.New(fmt.Sprintf("No cache found for %s when DELETING cache", name))
}

// Cache handlers
func GetCache(ctx context.Context, name string) (interface{}, error) {
	if project.Environment == "cloud" {
		if item, err := memcache.Get(ctx, name); err == memcache.ErrCacheMiss {
		} else if err != nil {
			return "", errors.New(fmt.Sprintf("Failed getting CLOUD cache for %s: %s", name, err))
		} else {
			// Loops if cachesize is more than max allowed in memcache (multikey)
			if len(item.Value) == maxCacheSize {
				totalData := item.Value
				keyCount := 1
				keyname := fmt.Sprintf("%s_%d", name, keyCount)
				for {
					if item, err := memcache.Get(ctx, keyname); err == memcache.ErrCacheMiss {
						break
					} else {
						totalData = append(totalData, item.Value...)

						//log.Printf("%d - %d = ", len(item.Value), maxCacheSize)
						if len(item.Value) != maxCacheSize {
							break
						}
					}

					keyCount += 1
					keyname = fmt.Sprintf("%s_%d", name, keyCount)
				}

				// Random~ high number
				if len(totalData) > 10062147 {
					log.Printf("[WARNING] CACHE: TOTAL SIZE FOR %s: %d", name, len(totalData))
				}
				return totalData, nil
			} else {
				return item.Value, nil
			}
		}
	} else if project.Environment == "onprem" {
		//log.Printf("[INFO] GETTING CACHE FOR %s ONPREM", name)
		if value, found := requestCache.Get(name); found {
			return value, nil
		} else {
			return "", errors.New(fmt.Sprintf("Failed getting ONPREM cache for %s", name))
		}
	} else {
		return "", errors.New(fmt.Sprintf("No cache handler for environment %s yet", project.Environment))
	}

	return "", errors.New(fmt.Sprintf("No cache found for %s", name))
}

func SetCache(ctx context.Context, name string, data []byte) error {
	//log.Printf("DATA SIZE: %d", len(data))
	// Maxsize ish~

	if project.Environment == "cloud" {
		if len(data) > maxCacheSize*10 {
			return errors.New(fmt.Sprintf("Couldn't set cache for %s - too large: %d > %d", name, len(data), maxCacheSize*10))
		}
		loop := false
		if len(data) > maxCacheSize {
			loop = true
			//log.Printf("Should make multiple cache items for %s", name)
		}

		// Custom for larger sizes. Max is maxSize*10 when being set
		if loop {
			currentChunk := 0
			keyAmount := 0
			totalAdded := 0
			chunkSize := maxCacheSize
			nextStep := chunkSize
			keyname := name

			for {
				if len(data) < nextStep {
					nextStep = len(data)
				}

				//log.Printf("%d - %d = ", currentChunk, nextStep)
				parsedData := data[currentChunk:nextStep]
				item := &memcache.Item{
					Key:        keyname,
					Value:      parsedData,
					Expiration: time.Minute * 30,
				}

				if err := memcache.Set(ctx, item); err != nil {
					log.Printf("[WARNING] Failed setting cache for %s: %s", keyname, err)
					break
				} else {
					totalAdded += chunkSize
					currentChunk = nextStep
					nextStep += chunkSize

					keyAmount += 1
					//log.Printf("%s: %d: %d", keyname, totalAdded, len(data))

					keyname = fmt.Sprintf("%s_%d", name, keyAmount)
					if totalAdded > len(data) {
						break
					}
				}
			}

			log.Printf("[INFO] Set app cache with length %d and %d keys", len(data), keyAmount)
		} else {
			item := &memcache.Item{
				Key:        name,
				Value:      data,
				Expiration: time.Minute * 30,
			}

			if err := memcache.Set(ctx, item); err != nil {
				log.Printf("[WARNING] Failed setting cache for %s: %s", name, err)
			}
		}

		return nil
	} else if project.Environment == "onprem" {
		//log.Printf("SETTING CACHE FOR %s ONPREM", name)
		requestCache.Set(name, data, cache.DefaultExpiration)
	} else {
		return errors.New(fmt.Sprintf("No cache handler for environment %s yet", project.Environment))
	}

	return nil
}

func GetDatastoreClient(ctx context.Context, projectID string) (datastore.Client, error) {
	//client, err := datastore.NewClient(ctx, projectID, option.WithCredentialsFile(test"))
	client, err := datastore.NewClient(ctx, projectID)
	//client, err := datastore.NewClient(ctx, projectID, option.WithCredentialsFile("test"))
	if err != nil {
		return datastore.Client{}, err
	}

	return *client, nil
}

func SetWorkflowAppDatastore(ctx context.Context, workflowapp WorkflowApp, id string) error {
	nameKey := "workflowapp"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	key := datastore.NameKey(nameKey, id, nil)

	// New struct, to not add body, author etc
	data, err := json.Marshal(workflowapp)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in setapp: %s", err)
		return nil
	}
	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, workflowapp.ID, data)
		if err != nil {
			return err
		}
	} else {
		if _, err := project.Dbclient.Put(ctx, key, &workflowapp); err != nil {
			log.Printf("[WARNING] Error adding workflow app: %s", err)
			return err
		}
	}

	if project.CacheDb {

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for setapp: %s", err)
		}
	}

	return nil
}

func SetWorkflowExecution(ctx context.Context, workflowExecution WorkflowExecution, dbSave bool) error {
	//log.Printf("\n\n\nRESULT: %s\n\n\n", workflowExecution.Status)
	if len(workflowExecution.ExecutionId) == 0 {
		log.Printf("[WARNING] Workflowexeciton executionId can't be empty.")
		return errors.New("ExecutionId can't be empty.")
	}

	nameKey := "workflowexecution"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, workflowExecution.ExecutionId)
	executionData, err := json.Marshal(workflowExecution)
	if err == nil {

		err = SetCache(ctx, cacheKey, executionData)
		if err != nil {
			log.Printf("[WARNING] Failed updating execution cache. Setting DB! %s", err)
			dbSave = true
		} else {
			//log.Printf("\n\n\n[INFO] Set cache for %s with length %d", cacheKey, len(executionData))

		}
	} else {
		log.Printf("[WARNING] Failed marshalling execution for cache: %s", err)
		//log.Printf("[INFO] Set execution cache for workflowexecution %s", cacheKey)
	}

	//requestCache.Set(cacheKey, &workflowExecution, cache.DefaultExpiration)
	if !dbSave && workflowExecution.Status == "EXECUTING" && len(workflowExecution.Results) > 1 {
		log.Printf("[WARNING] SHOULD skip DB saving for execution")
		return nil
	}

	// New struct, to not add body, author etc
	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, workflowExecution.ExecutionId, executionData)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, workflowExecution.ExecutionId, nil)
		if _, err := project.Dbclient.Put(ctx, key, &workflowExecution); err != nil {
			log.Printf("Error adding workflow_execution: %s", err)
			return err
		}
	}

	return nil
}

// Initializes an execution's extra variables
func SetInitExecutionVariables(ctx context.Context, workflowExecution WorkflowExecution) {
	environments := []string{}
	nextActions := []string{}
	startAction := ""
	extra := 0
	parents := map[string][]string{}
	children := map[string][]string{}

	// Hmm
	triggersHandled := []string{}

	for _, action := range workflowExecution.Workflow.Actions {
		if !ArrayContains(environments, action.Environment) {
			environments = append(environments, action.Environment)
		}

		if action.ID == workflowExecution.Start {
			/*
				functionName = fmt.Sprintf("%s-%s", action.AppName, action.AppVersion)

				if !action.Sharing {
					functionName = fmt.Sprintf("%s-%s", action.AppName, action.PrivateID)
				}
			*/

			startAction = action.ID
		}
	}

	nextActions = append(nextActions, startAction)
	for _, branch := range workflowExecution.Workflow.Branches {
		// Check what the parent is first. If it's trigger - skip
		sourceFound := false
		destinationFound := false
		for _, action := range workflowExecution.Workflow.Actions {
			if action.ID == branch.SourceID {
				sourceFound = true
			}

			if action.ID == branch.DestinationID {
				destinationFound = true
			}
		}

		for _, trigger := range workflowExecution.Workflow.Triggers {
			//log.Printf("Appname trigger (0): %s", trigger.AppName)
			if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
				//log.Printf("%s is a special trigger. Checking where.", trigger.AppName)

				found := false
				for _, check := range triggersHandled {
					if check == trigger.ID {
						found = true
						break
					}
				}

				if !found {
					extra += 1
				} else {
					triggersHandled = append(triggersHandled, trigger.ID)
				}

				if trigger.ID == branch.SourceID {
					log.Printf("Trigger %s is the source!", trigger.AppName)
					sourceFound = true
				} else if trigger.ID == branch.DestinationID {
					log.Printf("Trigger %s is the destination!", trigger.AppName)
					destinationFound = true
				}
			}
		}

		if sourceFound {
			parents[branch.DestinationID] = append(parents[branch.DestinationID], branch.SourceID)
		} else {
			//log.Printf("[WARNING] Action ID %s was not found in actions! Skipping parent. (TRIGGER?)", branch.SourceID)
		}

		if destinationFound {
			children[branch.SourceID] = append(children[branch.SourceID], branch.DestinationID)
		} else {
			//log.Printf("[WARNING] Action ID %s was not found in actions! Skipping child. (TRIGGER?)", branch.SourceID)
		}
	}

	/*
		log.Printf("\n\nEnvironments: %#v", environments)
		log.Printf("Startnode: %s", startAction)
		log.Printf("Parents: %#v", parents)
		log.Printf("NextActions: %#v", nextActions)
		log.Printf("Extra: %d", extra)
		log.Printf("Children: %s", children)
	*/

	UpdateExecutionVariables(ctx, workflowExecution.ExecutionId, startAction, children, parents, []string{startAction}, []string{startAction}, nextActions, environments, extra)

}

func UpdateExecutionVariables(ctx context.Context, executionId, startnode string, children, parents map[string][]string, visited, executed, nextActions, environments []string, extra int) {
	cacheKey := fmt.Sprintf("%s-actions", executionId)
	//log.Printf("\n\nSHOULD UPDATE VARIABLES FOR %s\n\n", executionId)
	_ = cacheKey

	newVariableWrapper := ExecutionVariableWrapper{
		StartNode:    startnode,
		Children:     children,
		Parents:      parents,
		NextActions:  nextActions,
		Environments: environments,
		Extra:        extra,
		Visited:      visited,
		Executed:     visited,
	}

	variableWrapperData, err := json.Marshal(newVariableWrapper)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling execution: %s", err)
		return
	}

	err = SetCache(ctx, cacheKey, variableWrapperData)
	if err != nil {
		log.Printf("[WARNING] Failed updating execution: %s", err)
	}

	log.Printf("[INFO] Successfully set cache for execution variables %s\n\n", cacheKey)
}

func GetExecutionVariables(ctx context.Context, executionId string) (string, int, map[string][]string, map[string][]string, []string, []string, []string, []string) {

	cacheKey := fmt.Sprintf("%s-actions", executionId)
	wrapper := &ExecutionVariableWrapper{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %#v", cacheData)
			err = json.Unmarshal(cacheData, &wrapper)
			if err == nil {
				return wrapper.StartNode, wrapper.Extra, wrapper.Children, wrapper.Parents, wrapper.Visited, wrapper.Executed, wrapper.NextActions, wrapper.Environments
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for execution variables data %s: %s", executionId, err)
		}
	}

	return "", 0, map[string][]string{}, map[string][]string{}, []string{}, []string{}, []string{}, []string{}
}

func GetWorkflowExecution(ctx context.Context, id string) (*WorkflowExecution, error) {
	nameKey := "workflowexecution"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	workflowExecution := &WorkflowExecution{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %#v", cacheData)
			err = json.Unmarshal(cacheData, &workflowExecution)
			if err == nil {
				return workflowExecution, nil
			} else {
				log.Printf("[WARNING] Failed getting workflowexecution: %s", err)
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for workflow execution: %s", err)
		}
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(nameKey), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return workflowExecution, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return workflowExecution, errors.New("User doesn't exist")
		}

		defer res.Body.Close()
		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return workflowExecution, err
		}

		wrapped := ExecWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return workflowExecution, err
		}

		workflowExecution = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		if err := project.Dbclient.Get(ctx, key, workflowExecution); err != nil {
			return &WorkflowExecution{}, err
		}
	}

	if project.CacheDb {
		newexecution, err := json.Marshal(workflowExecution)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling execution: %s", err)
			return workflowExecution, nil
		}

		err = SetCache(ctx, id, newexecution)
		if err != nil {
			log.Printf("[WARNING] Failed updating execution: %s", err)
		}
	}

	return workflowExecution, nil
}

func GetApp(ctx context.Context, id string, user User) (*WorkflowApp, error) {
	nameKey := "workflowapp"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)

	workflowApp := &WorkflowApp{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %#v", cacheData)
			err = json.Unmarshal(cacheData, &workflowApp)
			if err == nil {
				return workflowApp, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for org: %s", err)
		}
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(nameKey), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return workflowApp, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return workflowApp, errors.New("App doesn't exist")
		}

		defer res.Body.Close()
		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return workflowApp, err
		}

		wrapped := AppWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return workflowApp, err
		}

		workflowApp = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		if err := project.Dbclient.Get(ctx, key, workflowApp); err != nil {
			log.Printf("[WARNING] Failed getting app in GetApp: %s", err)
			for _, app := range user.PrivateApps {
				if app.ID == id {
					workflowApp = &app
					break
				}
			}
		}
	}

	if workflowApp.ID == "" {
		return &WorkflowApp{}, errors.New(fmt.Sprintf("Couldn't find app %s", id))
	}

	if project.CacheDb {
		data, err := json.Marshal(workflowApp)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getapp: %s", err)
			return workflowApp, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getapp: %s", err)
		}
	}

	return workflowApp, nil
}

func GetWorkflow(ctx context.Context, id string) (*Workflow, error) {
	workflow := &Workflow{}
	nameKey := "workflow"

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %#v", cacheData)
			err = json.Unmarshal(cacheData, &workflow)
			if err == nil {
				return workflow, nil
			}
		} else {
			log.Printf("[DEBUG] Failed getting cache for workflow: %s", err)
		}
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(nameKey), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return workflow, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return workflow, errors.New("Workflow doesn't exist")
		}

		defer res.Body.Close()
		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return workflow, err
		}

		wrapped := WorkflowWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return workflow, err
		}

		workflow = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		if err := project.Dbclient.Get(ctx, key, workflow); err != nil {
			if strings.Contains(err.Error(), `cannot load field`) {
				log.Printf("[INFO] Error in workflow loading. Migrating workflow to new workflow handler.")
				err = nil
			} else {
				return &Workflow{}, err
			}
		}
	}

	if project.CacheDb {
		log.Printf("[DEBUG] Setting cache for workflow %s", cacheKey)
		data, err := json.Marshal(workflow)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getworkflow: %s", err)
			return workflow, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getworkflow: %s", err)
		}
	}

	return workflow, nil
}

func GetAllWorkflowsByQuery(ctx context.Context, user User) ([]Workflow, error) {
	var workflows []Workflow
	limit := 30

	// Appending the users' workflows
	nameKey := "workflow"
	log.Printf("[INFO] Getting workflows for user %s (%s - %s)", user.Username, user.Role, user.Id)
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"owner": user.Id,
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return workflows, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(nameKey)),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[WARNING] Error getting response: %s", err)
			return workflows, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return workflows, nil
		}

		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return workflows, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return workflows, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return workflows, err
		}

		wrapped := WorkflowSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return workflows, err
		}

		for _, hit := range wrapped.Hits.Hits {
			if hit.Source.Owner == user.Id {
				workflows = append(workflows, hit.Source)
			}
		}

		if user.Role == "admin" {
			var buf bytes.Buffer
			query := map[string]interface{}{
				"size": 1000,
				"query": map[string]interface{}{
					"match": map[string]interface{}{
						"org_id": user.ActiveOrg.Id,
					},
				},
			}
			if err := json.NewEncoder(&buf).Encode(query); err != nil {
				log.Printf("[WARNING] Error encoding find user query: %s", err)
				return workflows, err
			}

			res, err := project.Es.Search(
				project.Es.Search.WithContext(context.Background()),
				project.Es.Search.WithIndex(strings.ToLower(nameKey)),
				project.Es.Search.WithBody(&buf),
				project.Es.Search.WithTrackTotalHits(true),
			)
			if err != nil {
				log.Printf("[WARNING] Error getting response: %s", err)
				return workflows, err
			}

			defer res.Body.Close()
			if res.StatusCode == 404 {
				return workflows, nil
			}

			defer res.Body.Close()
			if res.IsError() {
				var e map[string]interface{}
				if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
					log.Printf("[WARNING] Error parsing the response body: %s", err)
					return workflows, err
				} else {
					// Print the response status and error information.
					log.Printf("[%s] %s: %s",
						res.Status(),
						e["error"].(map[string]interface{})["type"],
						e["error"].(map[string]interface{})["reason"],
					)
				}
			}

			if res.StatusCode != 200 && res.StatusCode != 201 {
				return workflows, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
			}

			respBody, err := ioutil.ReadAll(res.Body)
			if err != nil {
				return workflows, err
			}

			wrapped := WorkflowSearchWrapper{}
			err = json.Unmarshal(respBody, &wrapped)
			if err != nil {
				return workflows, err
			}

			log.Printf("[INFO] Appending workflows (ADMIN) for organization %s. Already have %d workflows for the user. Found %d for org", user.ActiveOrg.Id, len(workflows), len(wrapped.Hits.Hits))
			for _, hit := range wrapped.Hits.Hits {
				found := false
				for _, workflow := range workflows {
					if workflow.ID == hit.ID {
						found = true
						break
					}
				}

				if !found {
					workflows = append(workflows, hit.Source)
				}
			}
		}

	} else {
		query := datastore.NewQuery(nameKey).Filter("owner =", user.Id).Limit(limit)
		cursorStr := ""
		for {
			it := project.Dbclient.Run(ctx, query)

			for {
				innerWorkflow := Workflow{}
				_, err := it.Next(&innerWorkflow)
				if err != nil {
					if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
						log.Printf("[INFO] Fixing workflow %s to have proper org (0.8.74)", innerWorkflow.ID)
						innerWorkflow.Org = []OrgMini{user.ActiveOrg}
						err = SetWorkflow(ctx, innerWorkflow, innerWorkflow.ID)
						if err != nil {
							log.Printf("[WARNING] Failed automatic update of workflow %s", innerWorkflow.ID)
						}
					} else {
						//log.Printf("[WARNING] Workflow iterator issue: %s", err)
						break
					}
				}

				workflows = append(workflows, innerWorkflow)
			}

			if err != iterator.Done {
				//log.Printf("[INFO] Failed fetching results: %v", err)
				//break
			}

			// Get the cursor for the next page of results.
			nextCursor, err := it.Cursor()
			if err != nil {
				log.Printf("Cursorerror: %s", err)
				break
			} else {
				//log.Printf("NEXTCURSOR: %s", nextCursor)
				nextStr := fmt.Sprintf("%s", nextCursor)
				if cursorStr == nextStr {
					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)
				//cursorStr = nextCursor
				//break
			}
		}

		// q *datastore.Query

		if user.Role == "admin" {
			log.Printf("[INFO] Appending workflows (ADMIN) for organization %s", user.ActiveOrg.Id)
			query = datastore.NewQuery(nameKey).Filter("org_id =", user.ActiveOrg.Id).Limit(limit)
			//if project.Environment != "cloud" {
			//	query = query.Order("-edited")
			//}

			cursorStr := ""
			for {
				it := project.Dbclient.Run(ctx, query)

				for {
					innerWorkflow := Workflow{}
					_, err := it.Next(&innerWorkflow)
					if err != nil {
						if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
							log.Printf("[INFO] Fixing workflow %s to have proper org (0.8.74)", innerWorkflow.ID)
							innerWorkflow.Org = []OrgMini{user.ActiveOrg}
							err = SetWorkflow(ctx, innerWorkflow, innerWorkflow.ID)
							if err != nil {
								log.Printf("[WARNING] Failed automatic update of workflow %s", innerWorkflow.ID)
							}
						} else {
							//log.Printf("[WARNING] Workflow iterator issue: %s", err)
							break
						}
					}

					found := false
					for _, loopedWorkflow := range workflows {
						if loopedWorkflow.ID == innerWorkflow.ID {
							found = true
							break
						}
					}

					if !found {
						workflows = append(workflows, innerWorkflow)
					}
				}

				if err != iterator.Done {
					//log.Printf("[INFO] Failed fetching results: %v", err)
					//break
				}

				// Get the cursor for the next page of results.
				nextCursor, err := it.Cursor()
				if err != nil {
					log.Printf("Cursorerror: %s", err)
					break
				} else {
					//log.Printf("NEXTCURSOR: %s", nextCursor)
					nextStr := fmt.Sprintf("%s", nextCursor)
					if cursorStr == nextStr {
						break
					}

					cursorStr = nextStr
					query = query.Start(nextCursor)
					//cursorStr = nextCursor
					//break
				}
			}
		}
	}

	fixedWorkflows := []Workflow{}
	for _, workflow := range workflows {
		if len(workflow.Name) == 0 && len(workflow.Actions) <= 1 {
			continue
		}

		fixedWorkflows = append(fixedWorkflows, workflow)
	}

	slice.Sort(fixedWorkflows[:], func(i, j int) bool {
		return fixedWorkflows[i].Edited > fixedWorkflows[j].Edited
	})

	return fixedWorkflows, nil
}

func GetAllHooks(ctx context.Context) ([]Hook, error) {
	var apis []Hook
	q := datastore.NewQuery("hooks")

	_, err := project.Dbclient.GetAll(ctx, q, &apis)
	if err != nil && len(apis) == 0 {
		return []Hook{}, err
	}

	return apis, nil
}

func GetAllOpenApi(ctx context.Context) ([]ParsedOpenApi, error) {
	var apis []ParsedOpenApi
	q := datastore.NewQuery("openapi3")

	_, err := project.Dbclient.GetAll(ctx, q, &apis)
	if err != nil && len(apis) == 0 {
		return []ParsedOpenApi{}, err
	}

	return apis, nil
}

func GetAllWorkflows(ctx context.Context, orgId string) ([]Workflow, error) {
	var allworkflows []Workflow
	q := datastore.NewQuery("workflow").Filter("org_id = ", orgId)
	if orgId == "ALL" {
		q = datastore.NewQuery("workflow")
	}

	_, err := project.Dbclient.GetAll(ctx, q, &allworkflows)
	if err != nil && len(allworkflows) == 0 {
		return []Workflow{}, err
	}

	return allworkflows, nil
}

// ListBooks returns a list of books, ordered by title.
// Handles org grabbing and user / org migrations
func GetOrg(ctx context.Context, id string) (*Org, error) {
	nameKey := "Organizations"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)

	curOrg := &Org{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %#v", cacheData)
			err = json.Unmarshal(cacheData, &curOrg)
			if err == nil {
				return curOrg, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for org: %s", err)
		}
	}

	setOrg := false
	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(nameKey), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return &Org{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return &Org{}, errors.New("Org doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return &Org{}, err
		}

		wrapped := OrgWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return &Org{}, err
		}

		curOrg = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if err := project.Dbclient.Get(ctx, key, curOrg); err != nil {
			if strings.Contains(err.Error(), `cannot load field`) && strings.Contains(err.Error(), `users`) {
				//Self correcting Org handler for user migration. This may come in handy if we change the structure of private apps later too.
				log.Printf("[INFO] Error in org loading. Migrating org to new org and user handler: %s", err)
				err = nil

				users := []User{}
				q := datastore.NewQuery("Users").Filter("orgs =", id)
				_, usererr := project.Dbclient.GetAll(ctx, q, &users)

				if usererr != nil {
					log.Printf("[WARNING] Failed handling users in org fixer: %s", usererr)
					for index, user := range users {
						users[index].ActiveOrg = OrgMini{
							Name: curOrg.Name,
							Id:   curOrg.Id,
							Role: user.Role,
						}

						//log.Printf("Should update user %s because there's an error with it", users[index].Id)
						SetUser(ctx, &users[index], false)
					}
				}

				if len(users) > 0 {
					curOrg.Users = users
					setOrg = true
				}
			} else {
				return &Org{}, err
			}
		}
	}

	newUsers := []User{}
	for _, user := range curOrg.Users {
		user.Password = ""
		user.Session = ""
		user.ResetReference = ""
		user.PrivateApps = []WorkflowApp{}
		user.VerificationToken = ""
		//user.ApiKey = ""
		user.Executions = ExecutionInfo{}
		newUsers = append(newUsers, user)
	}

	curOrg.Users = newUsers
	if project.CacheDb {
		neworg, err := json.Marshal(curOrg)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling org for cache: %s", err)
			return curOrg, nil
		}

		err = SetCache(ctx, cacheKey, neworg)
		if err != nil {
			log.Printf("[WARNING] Failed updating org cache: %s", err)
		}

		if setOrg {
			log.Printf("[INFO] UPDATING ORG %s!!", curOrg.Id)
			SetOrg(ctx, *curOrg, curOrg.Id)
		}
	}

	return curOrg, nil
}

func indexEs(ctx context.Context, nameKey, id string, bytes []byte) error {
	req := esapi.IndexRequest{
		Index:      strings.ToLower(nameKey),
		DocumentID: id,
		Body:       strings.NewReader(string(bytes)),
		Refresh:    "true",
		Pretty:     true,
	}

	res, err := req.Do(ctx, &project.Es)
	if err != nil {
		log.Printf("[WARNING] Error getting response: %s", err)
		return err
	}

	defer res.Body.Close()

	if res.StatusCode != 200 && res.StatusCode != 201 {
		return errors.New(fmt.Sprintf("Bad statuscode from database: %d", res.StatusCode))
	}

	var r map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		log.Printf("[WARNING] Error parsing the response body: %s", err)
		return err
	}
	return nil
}

func SetOrg(ctx context.Context, data Org, id string) error {
	nameKey := "Organizations"
	timeNow := int64(time.Now().Unix())
	if data.Created == 0 {
		data.Created = timeNow
	}

	data.Edited = timeNow

	// clear session_token and API_token for user
	if project.DbType == "elasticsearch" {
		b, err := json.Marshal(data)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling %s - %s: %s", id, nameKey, err)
			return err
		}

		err = indexEs(ctx, nameKey, id, b)
		if err != nil {
			return err
		}
	} else {
		k := datastore.NameKey(nameKey, id, nil)
		if _, err := project.Dbclient.Put(ctx, k, &data); err != nil {
			log.Println(err)
			return err
		}
	}

	if project.CacheDb {
		newUsers := []User{}
		for _, user := range data.Users {
			user.Password = ""
			user.Session = ""
			user.ResetReference = ""
			user.PrivateApps = []WorkflowApp{}
			user.VerificationToken = ""
			user.Executions = ExecutionInfo{}
			newUsers = append(newUsers, user)
		}

		data.Users = newUsers

		neworg, err := json.Marshal(data)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in setorg: %s", err)
			return nil
		}

		cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
		err = SetCache(ctx, cacheKey, neworg)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for org: %s", err)
		}
	}

	return nil
}

func GetSession(ctx context.Context, thissession string) (*Session, error) {
	session := &Session{}
	cache, err := GetCache(ctx, thissession)
	if err == nil {
		cacheData := []byte(cache.([]uint8))
		//log.Printf("CACHEDATA: %#v", cacheData)
		err = json.Unmarshal(cacheData, &session)
		if err == nil {
			return session, nil
		}
	} else {
		//log.Printf("[WARNING] Error getting session cache for %s: %v", thissession, err)
	}

	nameKey := "sessions"
	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(nameKey), thissession)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return session, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return session, errors.New("Session doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return session, err
		}

		wrapped := SessionWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return session, err
		}

		session = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, thissession, nil)
		if err := project.Dbclient.Get(ctx, key, session); err != nil {
			return &Session{}, err
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(thissession)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling session: %s", err)
			return session, nil
		}

		err = SetCache(ctx, thissession, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating session cache: %s", err)
		}
	}

	return session, nil
}

// Index = Username
func DeleteKey(ctx context.Context, entity string, value string) error {
	// Non indexed User data
	DeleteCache(ctx, fmt.Sprintf("%s_%s", entity, value))

	if project.DbType == "elasticsearch" {
		res, err := project.Es.Delete(strings.ToLower(entity), value)

		if err != nil {
			log.Printf("[WARNING] Error in DELETE: %s", err)
			return err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			log.Printf("Couldn't delete %s:%s", entity, value)
			return nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body (DELETE): %s", err)
				return err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		log.Printf("[DEBUG] Deleted %s (%s)", strings.ToLower(entity), value)
	} else {
		key1 := datastore.NameKey(entity, value, nil)
		err = project.Dbclient.Delete(ctx, key1)
		if err != nil {
			log.Printf("[WARNING] Error deleting %s from %s: %s", value, entity, err)
			return err
		}
	}

	return nil
}

// Index = Username
func SetApikey(ctx context.Context, Userdata User) error {

	// Non indexed User data
	newapiUser := new(Userapi)
	newapiUser.ApiKey = Userdata.ApiKey
	newapiUser.Username = strings.ToLower(Userdata.Username)
	nameKey := "apikey"

	// New struct, to not add body, author etc
	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(Userdata)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling user in set apikey: %s", err)
			return err
		}

		err = indexEs(ctx, nameKey, newapiUser.ApiKey, data)
		if err != nil {
			return err
		}
	} else {
		key1 := datastore.NameKey(nameKey, newapiUser.ApiKey, nil)
		if _, err := project.Dbclient.Put(ctx, key1, newapiUser); err != nil {
			log.Printf("Error adding apikey: %s", err)
			return err
		}
	}

	return nil
}

func SetOpenApiDatastore(ctx context.Context, id string, openapi ParsedOpenApi) error {
	nameKey := "openapi3"
	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(openapi)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling user: %s", err)
			return err
		}
		err = indexEs(ctx, nameKey, id, data)
		if err != nil {
			return err
		}
	} else {
		k := datastore.NameKey(nameKey, id, nil)
		if _, err := project.Dbclient.Put(ctx, k, &openapi); err != nil {
			log.Println(err)
			return err
		}
	}

	return nil
}

func GetOpenApiDatastore(ctx context.Context, id string) (ParsedOpenApi, error) {
	nameKey := "openapi3"
	api := &ParsedOpenApi{}

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &api)
			if err == nil {
				return *api, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for user: %s", err)
		}
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(nameKey), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return *api, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return *api, errors.New("OpenAPI spec doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return *api, err
		}

		wrapped := ParsedApiWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return *api, err
		}

		api = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if err := project.Dbclient.Get(ctx, key, api); err != nil {
			internalBucket := "shuffler.appspot.com"
			fullParsedPath := fmt.Sprintf("extra_specs/%s/openapi.json", id)
			//gs://shuffler.appspot.com/extra_specs/0373ed696a3a2cba0a2b6838068f2b80
			log.Printf("[WARNING] Couldn't find openapi for %s. Should check filepath gs://%s/%s (size too big)", id, internalBucket, fullParsedPath)

			client, err := storage.NewClient(ctx)
			if err != nil {
				log.Printf("[WARNING] Failed to create client (storage - algolia img): %s", err)
				return *api, err
			}

			bucket := client.Bucket(internalBucket)
			obj := bucket.Object(fullParsedPath)
			fileReader, err := obj.NewReader(ctx)
			if err != nil {
				log.Printf("[WARNING] Failed making reader for %s: %s", fullParsedPath, err)
				return *api, err
			}

			data, err := ioutil.ReadAll(fileReader)
			if err != nil {
				log.Printf("[WARNING] Failed reading from filereader: %s", err)
				return *api, err
			}

			err = json.Unmarshal(data, &api)
			if err != nil {
				log.Printf("[WARNING] Failed unmarshaling from remote store: %s", err)
				return *api, err
			}

			defer fileReader.Close()
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(api)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling openapi: %s", err)
			return *api, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating openapi cache: %s", err)
		}
	}

	return *api, nil
}

// Index = Username
func SetSession(ctx context.Context, user User, value string) error {
	//parsedKey := strings.ToLower(user.Username)
	//if project.Environment != "cloud" {
	//}
	// Non indexed User data
	parsedKey := user.Id
	user.Session = value

	nameKey := "Users"
	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(user)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling user: %s", err)
			return err
		}

		//log.Printf("SESSION RES: %#v", res)
		err = indexEs(ctx, nameKey, parsedKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating user with session: %s", err)
			return err
		}
	} else {
		key1 := datastore.NameKey(nameKey, parsedKey, nil)
		if _, err := project.Dbclient.Put(ctx, key1, &user); err != nil {
			log.Printf("[WARNING] Error adding Usersession: %s", err)
			return err
		}
	}

	if len(user.Session) > 0 {
		// Indexed session data
		sessiondata := new(Session)
		sessiondata.UserId = strings.ToLower(user.Id)
		sessiondata.Username = strings.ToLower(user.Username)
		sessiondata.Session = user.Session
		sessiondata.Id = user.Id
		nameKey = "sessions"

		if project.DbType == "elasticsearch" {
			data, err := json.Marshal(sessiondata)
			if err != nil {
				log.Printf("[WARNING] Failed marshalling session %s", err)
				return err
			}

			err = indexEs(ctx, nameKey, sessiondata.Session, data)
			if err != nil {
				return err
			}
		} else {
			key2 := datastore.NameKey(nameKey, sessiondata.Session, nil)
			if _, err := project.Dbclient.Put(ctx, key2, sessiondata); err != nil {
				log.Printf("Error adding session: %s", err)
				return err
			}
		}
	}

	return nil
}

func FindUser(ctx context.Context, username string) ([]User, error) {
	var users []User

	nameKey := "Users"
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"username": username,
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return []User{}, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(nameKey)),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[WARNING] Error getting response: %s", err)
			return []User{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return []User{}, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return []User{}, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return []User{}, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return []User{}, err
		}

		wrapped := UserSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return []User{}, err
		}

		users = []User{}
		for _, hit := range wrapped.Hits.Hits {
			users = append(users, hit.Source)
		}
	} else {
		q := datastore.NewQuery(nameKey).Filter("Username =", username)
		_, err = project.Dbclient.GetAll(ctx, q, &users)
		if err != nil && len(users) == 0 {
			log.Printf("[WARNING] Failed getting users for username: %s", username)
			return users, err
		}
	}

	newUsers := []User{}
	parsedUsername := strings.ToLower(strings.TrimSpace(username))
	for _, user := range users {
		if strings.ToLower(strings.TrimSpace(user.Username)) != parsedUsername {
			continue
		}

		newUsers = append(newUsers, user)
	}

	log.Printf("[INFO] Found %d (%d) user(s) for username %s in db-connector", len(newUsers), len(users), username)
	return newUsers, nil
}

// ListBooks returns a list of books, ordered by title.
func GetUser(ctx context.Context, username string) (*User, error) {
	curUser := &User{}

	parsedKey := strings.ToLower(username)
	cacheKey := fmt.Sprintf("user_%s", parsedKey)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &curUser)
			if err == nil {
				return curUser, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for user: %s", err)
		}
	}

	nameKey := "Users"
	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(nameKey), parsedKey)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return curUser, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return curUser, errors.New("User doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return curUser, err
		}

		wrapped := UserWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return curUser, err
		}

		curUser = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, parsedKey, nil)
		if err := project.Dbclient.Get(ctx, key, curUser); err != nil {
			// Handles migration of the user
			if strings.Contains(err.Error(), `cannot load field`) {
				log.Printf("[INFO] Error in user. Migrating to new org and user handler.")
				curUser.ActiveOrg = OrgMini{
					Name: curUser.ActiveOrg.Name,
					Id:   curUser.ActiveOrg.Id,
					Role: "user",
				}

				// Updating the user and their org
				SetUser(ctx, curUser, false)
			} else {
				log.Printf("[WARNING] Error in Get User: %s", err)
				return &User{}, err
			}
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(curUser)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling user: %s", err)
			return curUser, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating cache: %s", err)
		}
	}

	return curUser, nil
}

func SetUser(ctx context.Context, user *User, updateOrg bool) error {
	log.Printf("[INFO] Updating a user (%s) that has the role %s with %d apps", user.Username, user.Role, len(user.PrivateApps))
	parsedKey := user.Id
	if updateOrg {
		user = fixUserOrg(ctx, user)
	}

	nameKey := "Users"
	data, err := json.Marshal(user)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling user: %s", err)
		return nil
	}
	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, parsedKey, data)
		if err != nil {
			return err
		}
	} else {
		k := datastore.NameKey(nameKey, parsedKey, nil)
		if _, err := project.Dbclient.Put(ctx, k, user); err != nil {
			log.Printf("[WARNING] Error updating user: %s", err)
			return err
		}
	}

	DeleteCache(ctx, user.ApiKey)
	DeleteCache(ctx, user.Session)

	if project.CacheDb {
		cacheKey := fmt.Sprintf("user_%s", parsedKey)

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating user cache: %s", err)
		}
	}

	return nil
}

func getDatastoreClient(ctx context.Context, projectID string) (datastore.Client, error) {
	// FIXME - this doesn't work
	//client, err := datastore.NewClient(ctx, projectID, option.WithCredentialsFile(test"))
	client, err := datastore.NewClient(ctx, projectID)
	//client, err := datastore.NewClient(ctx, projectID, option.WithCredentialsFile("test"))
	if err != nil {
		return datastore.Client{}, err
	}

	return *client, nil
}

func fixUserOrg(ctx context.Context, user *User) *User {
	found := false
	for _, id := range user.Orgs {
		if user.ActiveOrg.Id == id {
			found = true
			break
		}
	}

	if !found {
		user.Orgs = append(user.Orgs, user.ActiveOrg.Id)
	}

	innerUser := *user
	innerUser.PrivateApps = []WorkflowApp{}
	innerUser.Executions = ExecutionInfo{}
	innerUser.Limits = UserLimits{}
	innerUser.Authentication = []UserAuth{}
	innerUser.Password = ""
	innerUser.Session = ""

	// Might be vulnerable to timing attacks.
	for _, orgId := range user.Orgs {
		if len(orgId) == 0 {
			continue
		}

		org, err := GetOrg(ctx, orgId)
		if err != nil {
			log.Printf("[WARNING] Error getting org %s in fixUserOrg: %s", orgId, err)
			continue
		}

		orgIndex := 0
		userFound := false
		for index, orgUser := range org.Users {
			if orgUser.Id == user.Id {
				orgIndex = index
				userFound = true
				break
			}
		}

		if userFound {
			org.Users[orgIndex] = innerUser
		} else {
			org.Users = append(org.Users, innerUser)
		}

		err = SetOrg(ctx, *org, orgId)
		if err != nil {
			log.Printf("Failed setting org %s", orgId)
		}
	}

	return user
}

func GetAllWorkflowAppAuth(ctx context.Context, orgId string) ([]AppAuthenticationStorage, error) {
	var allworkflowappAuths []AppAuthenticationStorage
	nameKey := "workflowappauth"

	cacheKey := fmt.Sprintf("%s_%s", nameKey, orgId)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %#v", cacheData)
			err = json.Unmarshal(cacheData, &allworkflowappAuths)
			if err == nil {
				return allworkflowappAuths, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for app auth: %s", err)
		}
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"org_id": orgId,
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return allworkflowappAuths, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(nameKey)),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[WARNING] Error getting response: %s", err)
			return allworkflowappAuths, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return allworkflowappAuths, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return allworkflowappAuths, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return allworkflowappAuths, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return allworkflowappAuths, err
		}

		wrapped := AppAuthSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return allworkflowappAuths, err
		}

		allworkflowappAuths = []AppAuthenticationStorage{}
		for _, hit := range wrapped.Hits.Hits {
			allworkflowappAuths = append(allworkflowappAuths, hit.Source)
		}
	} else {
		q := datastore.NewQuery(nameKey).Filter("org_id = ", orgId)
		if orgId == "ALL" && project.Environment != "cloud" {
			q = datastore.NewQuery(nameKey)
		}

		_, err = project.Dbclient.GetAll(ctx, q, &allworkflowappAuths)
		if err != nil && len(allworkflowappAuths) == 0 {
			return allworkflowappAuths, err
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(allworkflowappAuths)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling get app auth: %s", err)
			return allworkflowappAuths, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating get app auth cache: %s", err)
		}

		log.Printf("[DEBUG] Set cache for app auth %s with length %d", cacheKey, len(allworkflowappAuths))
	}

	//for _, env := range allworkflowappAuths {
	//	for _, param := range env.Fields {
	//		log.Printf("ENV: %#v", param)
	//	}
	//}

	return allworkflowappAuths, nil
}

func GetEnvironments(ctx context.Context, orgId string) ([]Environment, error) {
	nameKey := "Environments"

	cacheKey := fmt.Sprintf("%s_%s", nameKey, orgId)
	environments := []Environment{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %#v", cacheData)
			err = json.Unmarshal(cacheData, &environments)
			if err == nil {
				return environments, nil
			}
		} else {
			log.Printf("[DEBUG] Failed getting cache in GET environments: %s", err)
		}
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"org_id": orgId,
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return environments, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(nameKey)),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[WARNING] Error getting response: %s", err)
			return environments, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			item := Environment{
				Name:    "Shuffle",
				Type:    "onprem",
				OrgId:   orgId,
				Default: true,
				Id:      uuid.NewV4().String(),
			}

			err = SetEnvironment(ctx, &item)
			if err != nil {
				log.Printf("[WARNING] Failed setting up new environment")
			} else {
				environments = append(environments, item)
			}

			return environments, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return environments, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return environments, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return environments, err
		}

		wrapped := EnvironmentSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return environments, err
		}

		environments = []Environment{}
		for _, hit := range wrapped.Hits.Hits {
			environments = append(environments, hit.Source)
		}
	} else {
		q := datastore.NewQuery(nameKey).Filter("org_id =", orgId)
		if orgId == "ALL" && project.Environment != "cloud" {
			q = datastore.NewQuery(nameKey)
		}

		_, err = project.Dbclient.GetAll(ctx, q, &environments)
		if err != nil && len(environments) == 0 {
			return []Environment{}, err
		}
	}

	if len(environments) == 0 {
		item := Environment{
			Name:    "Shuffle",
			Type:    "onprem",
			OrgId:   orgId,
			Default: true,
			Id:      uuid.NewV4().String(),
		}

		err = SetEnvironment(ctx, &item)
		if err != nil {
			log.Printf("[WARNING] Failed setting up new environment")
		} else {
			environments = append(environments, item)
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(environments)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling environment cache: %s", err)
			return environments, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating environment cache: %s", err)
		}

		log.Printf("[DEBUG] Set cache for environment %s", cacheKey)
	}

	return environments, nil
}

// Gets apps based on a new schema instead of looping everything
// Primarily made for cloud. Load in this order:
// 1. Get ORGs' private apps
// 2. Get USERs' private apps
// 3. Get PUBLIC apps
func GetPrioritizedApps(ctx context.Context, user User) ([]WorkflowApp, error) {
	if project.Environment != "cloud" {
		return GetAllWorkflowApps(ctx, 1000)
	}

	log.Printf("[INFO] Getting apps for user %s with active org %s", user.Username, user.ActiveOrg.Id)
	allApps := []WorkflowApp{}
	//log.Printf("[INFO] LOOPING REAL APPS: %d. Private: %d", len(user.PrivateApps))

	// 1. Caching apps locally
	cacheKey := fmt.Sprintf("apps_%s", user.Id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &allApps)
			if err == nil {
				return allApps, nil
			} else {
				log.Println(string(cacheData))
				log.Printf("Failed unmarshaling apps: %s", err)
				log.Printf("DATALEN: %d", len(cacheData))
			}
		} else {
			log.Printf("[DEBUG] Failed getting cache for apps with KEY %s: %s", cacheKey, err)
		}
	}

	maxLen := 100
	cursorStr := ""
	limit := 100
	allApps = user.PrivateApps
	org, orgErr := GetOrg(ctx, user.ActiveOrg.Id)
	if len(user.PrivateApps) > 0 {
		//log.Printf("[INFO] Migrating %d apps for user %s to org %s if they don't exist", len(user.PrivateApps), user.Username, user.ActiveOrg.Id)
		if orgErr == nil {
			orgChanged := false
			for _, app := range user.PrivateApps {
				if !ArrayContains(org.ActiveApps, app.ID) {
					orgChanged = true
					org.ActiveApps = append(org.ActiveApps, app.ID)
				}
			}

			if orgChanged {
				err = SetOrg(ctx, *org, org.Id)
				if err != nil {
					log.Printf("[WARNING] Failed setting org %s with %d apps: %s", org.Id, len(org.ActiveApps), err)
				}
			}
		}
	}

	nameKey := "workflowapp"

	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Printf("[WARNING] Failed to create client (storage - prioritizedapps): %s", err)
	}

	query := datastore.NewQuery(nameKey).Filter("reference_org =", user.ActiveOrg.Id).Limit(limit)
	for {
		it := project.Dbclient.Run(ctx, query)

		for {
			innerApp := WorkflowApp{}
			_, err := it.Next(&innerApp)
			if err != nil {
				if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
					log.Printf("[WARNING] Error in reference_org load: %s.", err)
					continue
				}

				//log.Printf("[WARNING] No more apps for %s in org app load? Breaking: %s.", user.Username, err)
				break
			}

			if len(innerApp.Actions) == 0 {
				log.Printf("App %s (%s) doesn't have actions - check filepath", innerApp.Name, innerApp.ID)

				internalBucket := "shuffler.appspot.com"
				fullParsedPath := fmt.Sprintf("extra_specs/%s/appspec.json", innerApp.ID)
				//gs://shuffler.appspot.com/extra_specs/0373ed696a3a2cba0a2b6838068f2b80
				//log.Printf("[WARNING] Couldn't find  for %s. Should check filepath gs://%s/%s (size too big)", innerApp.ID, internalBucket, fullParsedPath)

				bucket := client.Bucket(internalBucket)
				obj := bucket.Object(fullParsedPath)
				fileReader, err := obj.NewReader(ctx)
				if err == nil {

					data, err := ioutil.ReadAll(fileReader)
					if err == nil {
						err = json.Unmarshal(data, &innerApp)
						if err != nil {
							log.Printf("[WARNING] Failed unmarshaling from remote store: %s", err)
							continue
						}
					}
				}

				//log.Printf("%s\n%s - %s\n%d\n", string(data), innerApp.Name, innerApp.ID, len(innerApp.Actions))
			}

			found := false
			newIndex := -1
			newApp := WorkflowApp{}
			for appIndex, loopedApp := range allApps {
				if loopedApp.Name == innerApp.Name {
					if ArrayContains(loopedApp.LoopVersions, innerApp.AppVersion) || loopedApp.AppVersion == innerApp.AppVersion {
						found = true
					} else {
						//log.Printf("\n\nFound NEW version %s of app %s on index %d\n\n", innerApp.AppVersion, innerApp.Name, appIndex)

						v2, err := semver.NewVersion(innerApp.AppVersion)
						if err != nil {
							log.Printf("Failed parsing original app version %s: %s", innerApp.AppVersion, err)
						}

						appConstraint := fmt.Sprintf("> %s", loopedApp.AppVersion)
						c, err := semver.NewConstraint(appConstraint)
						if err != nil {
							log.Printf("Failed preparing constraint: %s", err)
						}

						if c.Check(v2) {
							//log.Printf("New IS larger - changing app on index %d from %s to %s", appIndex, loopedApp.AppVersion, innerApp.AppVersion)

							newApp = innerApp
							newApp.Versions = loopedApp.Versions
							newApp.LoopVersions = loopedApp.LoopVersions
						} else {
							//log.Printf("New is NOT larger - just appending")
							newApp = loopedApp
						}

						newApp.Versions = append(newApp.Versions, AppVersion{
							Version: innerApp.AppVersion,
							ID:      innerApp.ID,
						})

						newApp.LoopVersions = append(newApp.LoopVersions, innerApp.AppVersion)
						newIndex = appIndex
					}

					break
				}
			}

			if newIndex >= 0 && newApp.ID != "" {
				//log.Printf("Should update app on index %d", newIndex)
				allApps[newIndex] = newApp
			} else {
				if !found {
					allApps = append(allApps, innerApp)
				}
			}

		}

		if err != iterator.Done {
			//log.Printf("[INFO] Failed fetching results: %v", err)
			//break
		}

		// Get the cursor for the next page of results.
		nextCursor, err := it.Cursor()
		if err != nil {
			log.Printf("Cursorerror: %s", err)
			break
		} else {
			//log.Printf("NEXTCURSOR: %s", nextCursor)
			nextStr := fmt.Sprintf("%s", nextCursor)
			if cursorStr == nextStr {
				break
			}

			cursorStr = nextStr
			query = query.Start(nextCursor)
			//cursorStr = nextCursor
			//break
		}

		if len(allApps) > maxLen {
			break
		}
	}

	// Find public apps
	publicApps := []WorkflowApp{}
	publicAppsKey := fmt.Sprintf("public_apps")
	if project.CacheDb {
		cache, err := GetCache(ctx, publicAppsKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &publicApps)
			if err != nil {
				log.Printf("Failed unmarshaling PUBLIC apps: %s", err)
			}
		} else {
			log.Printf("[DEBUG] Failed getting cache for PUBLIC apps: %s", err)
		}
	}

	if len(publicApps) == 0 {
		query = datastore.NewQuery(nameKey).Filter("public =", true).Limit(limit)
		for {
			it := project.Dbclient.Run(ctx, query)

			for {
				innerApp := WorkflowApp{}
				_, err := it.Next(&innerApp)
				if err != nil {
					if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
						log.Printf("[WARNING] Error in public app load: %s.", err)
						continue
					}

					//log.Printf("[WARNING] No more apps (public) - Breaking: %s.", err)
					break
				}

				if len(innerApp.Actions) == 0 {
					log.Printf("App %s (%s) doesn't have actions - check filepath", innerApp.Name, innerApp.ID)

					internalBucket := "shuffler.appspot.com"
					fullParsedPath := fmt.Sprintf("extra_specs/%s/appspec.json", innerApp.ID)
					//gs://shuffler.appspot.com/extra_specs/0373ed696a3a2cba0a2b6838068f2b80
					//log.Printf("[WARNING] Couldn't find  for %s. Should check filepath gs://%s/%s (size too big)", innerApp.ID, internalBucket, fullParsedPath)

					bucket := client.Bucket(internalBucket)
					obj := bucket.Object(fullParsedPath)
					fileReader, err := obj.NewReader(ctx)
					if err == nil {

						data, err := ioutil.ReadAll(fileReader)
						if err == nil {
							err = json.Unmarshal(data, &innerApp)
							if err != nil {
								log.Printf("[WARNING] Failed unmarshaling from remote store: %s", err)
								continue
							}
						}
					}

					//log.Printf("%s\n%s - %s\n%d\n", string(data), innerApp.Name, innerApp.ID, len(innerApp.Actions))
				}

				found := false
				newIndex := -1
				newApp := WorkflowApp{}
				for appIndex, loopedApp := range publicApps {
					if loopedApp.Name == innerApp.Name {
						if ArrayContains(loopedApp.LoopVersions, innerApp.AppVersion) || loopedApp.AppVersion == innerApp.AppVersion {
							found = true
						} else {
							//log.Printf("\n\nFound NEW version %s of app %s on index %d\n\n", innerApp.AppVersion, innerApp.Name, appIndex)

							v2, err := semver.NewVersion(innerApp.AppVersion)
							if err != nil {
								log.Printf("Failed parsing original app version %s: %s", innerApp.AppVersion, err)
							}

							appConstraint := fmt.Sprintf("> %s", loopedApp.AppVersion)
							c, err := semver.NewConstraint(appConstraint)
							if err != nil {
								log.Printf("Failed preparing constraint: %s", err)
							}

							if c.Check(v2) {
								//log.Printf("New IS larger - changing app on index %d from %s to %s", appIndex, loopedApp.AppVersion, innerApp.AppVersion)

								newApp = innerApp
								newApp.Versions = loopedApp.Versions
								newApp.LoopVersions = loopedApp.LoopVersions
							} else {
								//log.Printf("New is NOT larger - just appending")
								newApp = loopedApp
							}

							newApp.Versions = append(newApp.Versions, AppVersion{
								Version: innerApp.AppVersion,
								ID:      innerApp.ID,
							})

							newApp.LoopVersions = append(newApp.LoopVersions, innerApp.AppVersion)
							newIndex = appIndex
						}

						break
					}
				}

				if newIndex >= 0 && newApp.ID != "" {
					//log.Printf("Should update app on index %d", newIndex)
					publicApps[newIndex] = newApp
				} else {
					if !found {
						publicApps = append(publicApps, innerApp)
					}
				}
			}

			if err != iterator.Done {
				//log.Printf("[INFO] Failed fetching results: %v", err)
				//break
			}

			// Get the cursor for the next page of results.
			nextCursor, err := it.Cursor()
			if err != nil {
				log.Printf("Cursorerror: %s", err)
				break
			} else {
				//log.Printf("NEXTCURSOR: %s", nextCursor)
				nextStr := fmt.Sprintf("%s", nextCursor)
				if cursorStr == nextStr {
					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)
				//cursorStr = nextCursor
				//break
			}

			if len(allApps) > maxLen {
				break
			}
		}

		newbody, err := json.Marshal(publicApps)
		if err != nil {
			return allApps, nil
		}

		err = SetCache(ctx, publicAppsKey, newbody)
		if err != nil {
			log.Printf("[INFO] Error setting app cache item for %s: %v", publicAppsKey, err)
		} else {
			log.Printf("[INFO] Set app cache for %s", publicAppsKey)
		}
	}

	allApps = append(allApps, publicApps...)

	if orgErr == nil && len(org.ActiveApps) > 0 {
		//log.Printf("[INFO] Should append ORG APPS: %#v", org.ActiveApps)

		allKeys := []*datastore.Key{}
		for _, appId := range org.ActiveApps {
			found := false
			for _, app := range allApps {
				if app.ID == appId {
					found = true
					break
				}
			}

			if !found && len(appId) > 0 {
				allKeys = append(allKeys, datastore.NameKey(nameKey, appId, nil))
			}
		}

		var newApps = make([]WorkflowApp, len(allKeys))
		err = project.Dbclient.GetMulti(ctx, allKeys, newApps)
		if err != nil {
			log.Printf("[WARNING] Failed getting org apps: %s", err)
		}

		allApps = append(allApps, newApps...)
	}

	if len(allApps) > 0 {
		newbody, err := json.Marshal(allApps)
		if err != nil {
			return allApps, nil
		}

		err = SetCache(ctx, cacheKey, newbody)
		if err != nil {
			log.Printf("[INFO] Error setting app cache item for %s: %v", cacheKey, err)
		} else {
			log.Printf("[INFO] Set app cache for %s", cacheKey)
		}
	}

	return allApps, nil
}

func GetAllWorkflowApps(ctx context.Context, maxLen int) ([]WorkflowApp, error) {
	var allApps []WorkflowApp

	wrapper := []WorkflowApp{}
	cacheKey := fmt.Sprintf("workflowapps-sorted-%d", maxLen)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &wrapper)
			if err == nil {
				return wrapper, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for apps with KEY %s: %s", cacheKey, err)
		}
	}

	nameKey := "workflowapp"
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer

		// FIXME: Overwrite necessary?
		query := map[string]interface{}{
			"size": 1000,
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find workflowapp query: %s", err)
			return []WorkflowApp{}, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(nameKey)),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[WARNING] Error getting response: %s", err)
			return []WorkflowApp{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return []WorkflowApp{}, err
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return []WorkflowApp{}, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return []WorkflowApp{}, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return []WorkflowApp{}, err
		}

		wrapped := AppSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return []WorkflowApp{}, err
		}

		allApps = []WorkflowApp{}
		//log.Printf("Hits: %d", len(wrapped.Hits.Hits))
		for _, hit := range wrapped.Hits.Hits {
			innerApp := hit.Source

			if innerApp.Name == "Shuffle Subflow" {
				continue
			}

			// This is used to validate with ALL apps
			if maxLen == 0 {
				allApps = append(allApps, innerApp)
				continue
			}

			if !innerApp.IsValid {
				continue
			}

			found := false
			newIndex := -1
			newApp := WorkflowApp{}
			for appIndex, loopedApp := range allApps {
				if loopedApp.Name == innerApp.Name {
					if ArrayContains(loopedApp.LoopVersions, innerApp.AppVersion) || loopedApp.AppVersion == innerApp.AppVersion {

						// If the new is active, and the old one is NOT - replace it.
						// FIXME: May be a problem here with semantic versioning
						// As of 0.8 this is not a concern, hence is ignored.
						if innerApp.Activated && !loopedApp.Activated {
							newIndex = appIndex
							newApp = innerApp

							//newApp.Versions = append(newApp.Versions, AppVersion{
							//	Version: innerApp.AppVersion,
							//	ID:      innerApp.ID,
							//})
							//newApp.LoopVersions = append(newApp.LoopVersions, innerApp.AppVersion)

							//newApp.Versions = loopedApp.Versions
							//newApp.LoopVersions = loopedApp.Versions
							found = false
						} else {
							found = true
						}
					} else {
						//log.Printf("\n\nFound NEW version %s of app %s on index %d\n\n", innerApp.AppVersion, innerApp.Name, appIndex)

						v2, err := semver.NewVersion(innerApp.AppVersion)
						if err != nil {
							log.Printf("[WARNING] Failed parsing original app version %s: %s", innerApp.AppVersion, err)
						}

						appConstraint := fmt.Sprintf("> %s", loopedApp.AppVersion)
						c, err := semver.NewConstraint(appConstraint)
						if err != nil {
							log.Printf("[WARNING] Failed preparing constraint: %s", err)
						}

						if c.Check(v2) {

							newApp = innerApp
							newApp.Versions = loopedApp.Versions
							newApp.LoopVersions = loopedApp.LoopVersions

							//log.Printf("[DEBUG] New IS larger - changing app on index %d from %s to %s. Versions: %#v", appIndex, loopedApp.AppVersion, innerApp.AppVersion, newApp.LoopVersions)
						} else {
							//log.Printf("[DEBUG] New is NOT larger: %s_%s (new) vs %s_%s - just appending", innerApp.Name, innerApp.AppVersion, loopedApp.Name, loopedApp.AppVersion)
							newApp = loopedApp
						}

						newApp.Versions = append(newApp.Versions, AppVersion{
							Version: innerApp.AppVersion,
							ID:      innerApp.ID,
						})
						newApp.LoopVersions = append(newApp.LoopVersions, innerApp.AppVersion)
						newIndex = appIndex
						//log.Printf("Versions for %s_%s: %#v", newApp.Name, newApp.AppVersion, newApp.LoopVersions)
					}

					break
				}
			}

			if newIndex >= 0 && newApp.ID != "" {
				//log.Printf("Should update app on index %d", newIndex)
				allApps[newIndex] = newApp
			} else {
				if !found {
					innerApp.Versions = append(innerApp.Versions, AppVersion{
						Version: innerApp.AppVersion,
						ID:      innerApp.ID,
					})
					innerApp.LoopVersions = append(innerApp.LoopVersions, innerApp.AppVersion)

					allApps = append(allApps, innerApp)
				}
			}

		}
	} else {
		cursorStr := ""
		query := datastore.NewQuery(nameKey).Order("-edited").Limit(10)
		for {
			it := project.Dbclient.Run(ctx, query)
			//innerApp := WorkflowApp{}
			//data, err := it.Next(&innerApp)
			//log.Printf("DATA: %#v, err: %s", data, err)

			for {
				innerApp := WorkflowApp{}
				_, err := it.Next(&innerApp)
				if err != nil {
					//log.Printf("No more apps? Breaking: %s.", err)
					break
				}

				if innerApp.Name == "Shuffle Subflow" {
					continue
				}

				if !innerApp.IsValid {
					continue
				}

				found := false
				newIndex := -1
				newApp := WorkflowApp{}
				for appIndex, loopedApp := range allApps {
					if loopedApp.Name == innerApp.Name {
						if ArrayContains(loopedApp.LoopVersions, innerApp.AppVersion) || loopedApp.AppVersion == innerApp.AppVersion {
							found = true
						} else {
							//log.Printf("\n\nFound NEW version %s of app %s on index %d\n\n", innerApp.AppVersion, innerApp.Name, appIndex)

							v2, err := semver.NewVersion(innerApp.AppVersion)
							if err != nil {
								log.Printf("Failed parsing original app version %s: %s", innerApp.AppVersion, err)
							}

							appConstraint := fmt.Sprintf("> %s", loopedApp.AppVersion)
							c, err := semver.NewConstraint(appConstraint)
							if err != nil {
								log.Printf("Failed preparing constraint: %s", err)
							}

							if c.Check(v2) {
								//log.Printf("New IS larger - changing app on index %d from %s to %s", appIndex, loopedApp.AppVersion, innerApp.AppVersion)

								newApp = innerApp
								newApp.Versions = loopedApp.Versions
								newApp.LoopVersions = loopedApp.LoopVersions
							} else {
								//log.Printf("New is NOT larger - just appending")
								newApp = loopedApp
							}

							newApp.Versions = append(newApp.Versions, AppVersion{
								Version: innerApp.AppVersion,
								ID:      innerApp.ID,
							})

							newApp.LoopVersions = append(newApp.LoopVersions, innerApp.AppVersion)
							newIndex = appIndex
						}

						break
					}
				}

				if newIndex >= 0 && newApp.ID != "" {
					//log.Printf("Should update app on index %d", newIndex)
					allApps[newIndex] = newApp
				} else {
					if !found {
						allApps = append(allApps, innerApp)
					}
				}
			}

			if err != iterator.Done {
				//log.Printf("[INFO] Failed fetching results: %v", err)
				//break
			}

			// Get the cursor for the next page of results.
			nextCursor, err := it.Cursor()
			if err != nil {
				log.Printf("Cursorerror: %s", err)
				break
			} else {
				//log.Printf("NEXTCURSOR: %s", nextCursor)
				nextStr := fmt.Sprintf("%s", nextCursor)
				if cursorStr == nextStr {
					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)
				//cursorStr = nextCursor
				//break
			}

			if len(allApps) > maxLen && maxLen != 0 {
				break
			}
		}
	}

	if project.CacheDb {
		log.Printf("[INFO] Setting %d apps in cache for 10 minutes for %s", len(allApps), cacheKey)

		//requestCache.Set(cacheKey, &apps, cache.DefaultExpiration)
		data, err := json.Marshal(allApps)
		if err == nil {
			err = SetCache(ctx, cacheKey, data)
			if err != nil {
				log.Printf("[WARNING] Failed updating cache for execution: %s", err)
			}
		} else {
			log.Printf("[WARNING] Failed marshalling execution: %s", err)
		}
	}

	return allApps, nil
}

func SetWorkflowQueue(ctx context.Context, executionRequest ExecutionRequest, env string) error {
	nameKey := fmt.Sprintf("workflowqueue-%s", env)

	// New struct, to not add body, author etc
	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(executionRequest)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getworkflow: %s", err)
			return nil
		}

		nameKey = strings.ToLower(nameKey)
		err = indexEs(ctx, nameKey, executionRequest.ExecutionId, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, executionRequest.ExecutionId, nil)
		if _, err := project.Dbclient.Put(ctx, key, &executionRequest); err != nil {
			log.Printf("Error adding workflow queue: %s", err)
			return err
		}
	}

	return nil
}

func GetWorkflowQueue(ctx context.Context, id string) (ExecutionRequestWrapper, error) {
	nameKey := fmt.Sprintf("workflowqueue-%s", id)
	q := datastore.NewQuery(nameKey).Limit(10)
	executions := []ExecutionRequest{}

	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"from": 0,
			"size": 10,
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return ExecutionRequestWrapper{}, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(nameKey)),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[WARNING] Error getting response: %s", err)
			return ExecutionRequestWrapper{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return ExecutionRequestWrapper{}, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return ExecutionRequestWrapper{}, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return ExecutionRequestWrapper{}, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))

		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return ExecutionRequestWrapper{}, err
		}

		wrapped := ExecRequestSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return ExecutionRequestWrapper{}, err
		}

		executions = []ExecutionRequest{}
		for _, hit := range wrapped.Hits.Hits {
			executions = append(executions, hit.Source)
		}
	} else {
		_, err := project.Dbclient.GetAll(ctx, q, &executions)
		if err != nil {
			return ExecutionRequestWrapper{}, err
		}
	}

	return ExecutionRequestWrapper{
		Data: executions,
	}, nil
}

func SetNewValue(ctx context.Context, newvalue NewValue) error {
	nameKey := fmt.Sprintf("app_execution_values")

	if newvalue.Created == 0 {
		newvalue.Created = int64(time.Now().Unix())
	}

	if newvalue.Id == "" {
		newvalue.Id = uuid.NewV4().String()
	}

	// New struct, to not add body, author etc
	data, err := json.Marshal(newvalue)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in newValue: %s", err)
		return nil
	}
	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, newvalue.Id, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, newvalue.Id, nil)
		if _, err := project.Dbclient.Put(ctx, key, &newvalue); err != nil {
			log.Printf("Error adding newvalue: %s", err)
			return err
		}

	}

	return nil
}

func SetWorkflow(ctx context.Context, workflow Workflow, id string, optionalEditedSecondsOffset ...int) error {
	nameKey := "workflow"
	timeNow := int64(time.Now().Unix())
	workflow.Edited = timeNow
	if workflow.Created == 0 {
		workflow.Created = timeNow
	}

	if len(optionalEditedSecondsOffset) > 0 {
		workflow.Edited += int64(optionalEditedSecondsOffset[0])
	}

	// New struct, to not add body, author etc
	data, err := json.Marshal(workflow)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in getworkflow: %s", err)
		return nil
	}
	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, id, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if _, err := project.Dbclient.Put(ctx, key, &workflow); err != nil {
			log.Printf("Error adding workflow: %s", err)
			return err
		}
	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getworkflow: %s", err)
		}
	}

	return nil
}

func SetWorkflowAppAuthDatastore(ctx context.Context, workflowappauth AppAuthenticationStorage, id string) error {
	nameKey := "workflowappauth"

	// New struct, to not add body, author etc
	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(workflowappauth)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in set app auth: %s", err)
			return err
		}

		indexEs(ctx, nameKey, id, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if _, err := project.Dbclient.Put(ctx, key, &workflowappauth); err != nil {
			log.Printf("[WARNING] Error adding workflow app AUTH: %s", err)
			return err
		}
	}

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	DeleteCache(ctx, cacheKey)
	cacheKey = fmt.Sprintf("%s_%s", nameKey, workflowappauth.OrgId)
	DeleteCache(ctx, cacheKey)

	return nil
}

func SetEnvironment(ctx context.Context, env *Environment) error {
	// clear session_token and API_token for user
	nameKey := "Environments"

	if env.Id == "" {
		env.Id = uuid.NewV4().String()
	}

	// New struct, to not add body, author etc
	//log.Printf("[INFO] SETTING ENVIRONMENT %s", env.Id)
	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(env)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in set env: %s", err)
			return err
		}

		err = indexEs(ctx, nameKey, env.Id, data)
		if err != nil {
			return err
		}
	} else {
		k := datastore.NameKey(nameKey, env.Id, nil)
		if _, err := project.Dbclient.Put(ctx, k, env); err != nil {
			log.Println(err)
			return err
		}
	}

	cacheKey := fmt.Sprintf("%s_%s", nameKey, env.OrgId)
	DeleteCache(ctx, cacheKey)

	return nil
}

func GetSchedule(ctx context.Context, schedulename string) (*ScheduleOld, error) {
	nameKey := "schedules"
	curUser := &ScheduleOld{}
	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(nameKey), strings.ToLower(schedulename))
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return &ScheduleOld{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return &ScheduleOld{}, errors.New("Schedule doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return &ScheduleOld{}, err
		}

		wrapped := ScheduleWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return &ScheduleOld{}, err
		}

		curUser = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(schedulename), nil)
		if err := project.Dbclient.Get(ctx, key, curUser); err != nil {
			return &ScheduleOld{}, err
		}

	}

	return curUser, nil
}

func GetApikey(ctx context.Context, apikey string) (User, error) {
	// Query for the specific API-key in users
	nameKey := "Users"
	var users []User
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"from": 0,
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"apikey": apikey,
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return User{}, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(nameKey)),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[WARNING] Error getting response: %s", err)
			return User{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return User{}, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return User{}, nil
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return User{}, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))

		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return User{}, err
		}

		wrapped := UserSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return User{}, err
		}

		users = []User{}
		for _, hit := range wrapped.Hits.Hits {
			users = append(users, hit.Source)
		}

	} else {
		q := datastore.NewQuery(nameKey).Filter("apikey =", apikey)
		_, err = project.Dbclient.GetAll(ctx, q, &users)
		if err != nil && len(users) == 0 {
			log.Printf("[WARNING] Error getting apikey: %s", err)
			return User{}, err
		}
	}

	if len(users) == 0 {
		log.Printf("[WARNING] No users found for apikey %s", apikey)
		return User{}, err
	}

	return users[0], nil
}

func GetHook(ctx context.Context, hookId string) (*Hook, error) {
	nameKey := "hooks"
	hookId = strings.ToLower(hookId)
	cacheKey := fmt.Sprintf("%s_%s", nameKey, hookId)

	hook := &Hook{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %#v", cacheData)
			err = json.Unmarshal(cacheData, &hook)
			if err == nil && len(hook.Id) > 0 {
				return hook, nil
			} else {
				return hook, errors.New(fmt.Sprintf("Bad cache for %s", hookId))
			}
		} else {
			log.Printf("[DEBUG] Failed getting cache for hook: %s", err)
		}
	}
	//log.Printf("DBTYPE: %#v", project.DbType)

	var err error
	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(nameKey), hookId)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return &Hook{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return &Hook{}, errors.New("Hook doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return &Hook{}, err
		}

		wrapped := HookWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return &Hook{}, err
		}

		hook = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, hookId, nil)
		err = project.Dbclient.Get(ctx, key, hook)
		if err != nil {
			return &Hook{}, err
		}
	}

	if project.CacheDb {
		hookData, err := json.Marshal(hook)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in gethook: %s", err)
			return hook, err
		}

		err = SetCache(ctx, cacheKey, hookData)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for gethook: %s", err)
		}
	}

	return hook, err
}

func SetHook(ctx context.Context, hook Hook) error {
	nameKey := "hooks"

	// New struct, to not add body, author etc
	hookData, err := json.Marshal(hook)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in setHook: %s", err)
		return nil
	}
	hookId := strings.ToLower(hook.Id)

	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, hookId, hookData)
		if err != nil {
			return err
		}
	} else {
		key1 := datastore.NameKey(nameKey, hookId, nil)
		if _, err := project.Dbclient.Put(ctx, key1, &hook); err != nil {
			log.Printf("Error adding hook: %s", err)
			return err
		}
	}

	if project.CacheDb {

		cacheKey := fmt.Sprintf("%s_%s", nameKey, hookId)
		err = SetCache(ctx, cacheKey, hookData)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for hook: %s", err)
		}
	}

	return nil
}

func GetFile(ctx context.Context, id string) (*File, error) {
	nameKey := "Files"
	curFile := &File{}
	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(nameKey), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return &File{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return &File{}, errors.New("File doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return &File{}, err
		}

		wrapped := FileWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return &File{}, err
		}

		curFile = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if err := project.Dbclient.Get(ctx, key, curFile); err != nil {
			return &File{}, err
		}

	}

	return curFile, nil
}

func SetFile(ctx context.Context, file File) error {
	// clear session_token and API_token for user
	timeNow := time.Now().Unix()
	file.UpdatedAt = timeNow
	nameKey := "Files"

	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(file)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling set file: %s", err)
			return err
		}

		err = indexEs(ctx, nameKey, file.Id, data)
		if err != nil {
			return err
		}
	} else {
		k := datastore.NameKey(nameKey, file.Id, nil)
		if _, err := project.Dbclient.Put(ctx, k, &file); err != nil {
			log.Println(err)
			return err
		}
	}

	return nil
}

func GetAllFiles(ctx context.Context, orgId string) ([]File, error) {
	var files []File

	nameKey := "Files"
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"from": 0,
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"org_id": orgId,
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return files, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(nameKey)),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[WARNING] Error getting response: %s", err)
			return files, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return files, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return files, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return files, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))

		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return files, err
		}

		wrapped := FileSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return files, err
		}

		files = []File{}
		for _, hit := range wrapped.Hits.Hits {
			files = append(files, hit.Source)
		}

	} else {
		q := datastore.NewQuery(nameKey).Filter("org_id =", orgId).Limit(100)

		_, err := project.Dbclient.GetAll(ctx, q, &files)
		if err != nil && len(files) == 0 {
			if strings.Contains(fmt.Sprintf("%s", err), "ResourceExhausted") {
				q = q.Limit(50)
				_, err := project.Dbclient.GetAll(ctx, q, &files)
				if err != nil && len(files) == 0 {
					return []File{}, err
				}
			} else if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
				log.Printf("[INFO] Failed loading SOME files - skipping: %s", err)
			} else {
				return []File{}, err
			}
		}
	}

	return files, nil
}

func GetWorkflowAppAuthDatastore(ctx context.Context, id string) (*AppAuthenticationStorage, error) {
	nameKey := "workflowappauth"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)

	appAuth := &AppAuthenticationStorage{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %#v", cacheData)
			err = json.Unmarshal(cacheData, &appAuth)
			if err == nil {
				return appAuth, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for org: %s", err)
		}
	}

	// New struct, to not add body, author etc
	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(nameKey), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return appAuth, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return appAuth, errors.New("App auth doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return appAuth, nil
		}

		wrapped := AppAuthWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return appAuth, nil
		}

		appAuth = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if err := project.Dbclient.Get(ctx, key, appAuth); err != nil {
			return &AppAuthenticationStorage{}, err
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(appAuth)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling app auth cache: %s", err)
			return appAuth, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating app auth cache: %s", err)
		}
	}

	return appAuth, nil
}

func GetAllSchedules(ctx context.Context, orgId string) ([]ScheduleOld, error) {
	var schedules []ScheduleOld

	nameKey := "schedules"
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"from": 0,
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"org": orgId,
				},
			},
		}

		if orgId == "ALL" && project.Environment != "cloud" {
			query = map[string]interface{}{}
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("Error encoding query: %s", err)
			return schedules, err
		}

		// Perform the search request.
		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(nameKey)),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[WARNING] Error getting response: %s", err)
			return schedules, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return schedules, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return schedules, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return schedules, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return schedules, err
		}

		wrapped := ScheduleSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return schedules, err
		}

		schedules = []ScheduleOld{}
		for _, hit := range wrapped.Hits.Hits {
			schedules = append(schedules, hit.Source)
		}

		return schedules, err
	} else {
		q := datastore.NewQuery(nameKey).Filter("org = ", orgId)
		if orgId == "ALL" && project.Environment != "cloud" {
			q = datastore.NewQuery(nameKey)
		}

		_, err := project.Dbclient.GetAll(ctx, q, &schedules)
		if err != nil && len(schedules) == 0 {
			return schedules, err
		}
	}

	return schedules, nil
}

func GetTriggerAuth(ctx context.Context, id string) (*TriggerAuth, error) {
	nameKey := "trigger_auth"
	triggerauth := &TriggerAuth{}
	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(nameKey), strings.ToLower(id))
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return &TriggerAuth{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return &TriggerAuth{}, errors.New("Trigger auth doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return &TriggerAuth{}, err
		}

		wrapped := TriggerAuthWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return &TriggerAuth{}, err
		}

		triggerauth = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		if err := project.Dbclient.Get(ctx, key, triggerauth); err != nil {
			return &TriggerAuth{}, err
		}
	}

	return triggerauth, nil
}

func SetTriggerAuth(ctx context.Context, trigger TriggerAuth) error {
	nameKey := "trigger_auth"

	// New struct, to not add body, author etc
	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(trigger)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in set trigger auth: %s", err)
			return err
		}

		err = indexEs(ctx, nameKey, strings.ToLower(trigger.Id), data)
		if err != nil {
			return err
		}
	} else {
		key1 := datastore.NameKey(nameKey, strings.ToLower(trigger.Id), nil)
		if _, err := project.Dbclient.Put(ctx, key1, &trigger); err != nil {
			log.Printf("Error adding trigger auth: %s", err)
			return err
		}
	}

	return nil
}

// Index = Username
func DeleteKeys(ctx context.Context, entity string, value []string) error {
	// Non indexed User data
	if project.DbType == "elasticsearch" {
		for _, item := range value {
			DeleteKey(ctx, entity, item)
		}
	} else {
		keys := []*datastore.Key{}
		for _, item := range value {
			keys = append(keys, datastore.NameKey(entity, item, nil))
		}

		err := project.Dbclient.DeleteMulti(ctx, keys)
		if err != nil {
			log.Printf("[WARNING] Error deleting %s from %s: %s", value, entity, err)
			return err
		}
	}

	return nil
}

func GetEnvironmentCount() (int, error) {
	ctx := context.Background()
	q := datastore.NewQuery("Environments").Limit(1)
	count, err := project.Dbclient.Count(ctx, q)
	if err != nil {
		return 0, err
	}

	return count, nil
}

func GetAllUsers(ctx context.Context) ([]User, error) {
	index := "Users"
	users := []User{}
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"from": 0,
			"size": 1000,
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find workflowapp query: %s", err)
			return []User{}, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(index)),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[WARNING] Error getting response: %s", err)
			return []User{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return []User{}, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return []User{}, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return []User{}, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return []User{}, err
		}

		wrapped := UserSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return []User{}, err
		}

		users = []User{}
		for _, hit := range wrapped.Hits.Hits {
			users = append(users, hit.Source)
		}

		return users, nil
	} else {
		q := datastore.NewQuery(index)
		_, err = project.Dbclient.GetAll(ctx, q, &users)
		if err != nil {
			return []User{}, err
		}
	}

	return users, nil
}

func GetAllWorkflowExecutions(ctx context.Context, workflowId string) ([]WorkflowExecution, error) {
	index := "workflowexecution"
	var executions []WorkflowExecution
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 100,
			"sort": map[string]interface{}{
				"started_at": map[string]interface{}{
					"order": "desc",
				},
			},
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"workflow_id": workflowId,
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("Error encoding query: %s", err)
			return executions, err
		}

		// Perform the search request.
		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(index)),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[WARNING] Error getting response: %s", err)
			return executions, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return executions, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return executions, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return executions, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return executions, err
		}

		wrapped := ExecutionSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return executions, err
		}

		executions = []WorkflowExecution{}
		for _, hit := range wrapped.Hits.Hits {
			executions = append(executions, hit.Source)
		}

		return executions, nil
	} else {
		q := datastore.NewQuery("workflowexecution").Filter("workflow_id =", workflowId).Limit(30)
		_, err = project.Dbclient.GetAll(ctx, q, &executions)
		if err != nil && len(executions) == 0 {
			log.Printf("Failed initial execution grabber: %s", err)
			if strings.Contains(fmt.Sprintf("%s", err), "ResourceExhausted") {
				q = datastore.NewQuery("workflowexecution").Filter("workflow_id =", workflowId).Limit(15)
				_, err = project.Dbclient.GetAll(ctx, q, &executions)
				if err != nil && len(executions) == 0 {
					log.Printf("[WARNING] Error getting workflowexec (2): %s", err)
					return executions, err
				}
			} else if strings.Contains(fmt.Sprintf("%s", err), "FailedPrecondition") {
				//log.Printf("[INFO] Failed precondition in workflowexecs: %s", err)

				q = datastore.NewQuery("workflowexecution").Filter("workflow_id =", workflowId).Limit(25)
				_, err = project.Dbclient.GetAll(ctx, q, &executions)
				if err != nil && len(executions) == 0 {
					log.Printf("[WARNING] Error getting workflowexec (3): %s", err)
					return executions, err
				}
			} else {
				log.Printf("[WARNING] Error getting workflowexec (4): %s", err)
				return executions, err
			}
		}
	}

	return executions, nil
}

func GetAllOrgs(ctx context.Context) ([]Org, error) {
	index := "Organizations"
	var orgs []Org
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find workflowapp query: %s", err)
			return []Org{}, err
		}

		// Perform the search request.
		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(index)),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[WARNING] Error getting response: %s", err)
			return []Org{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return []Org{}, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return []Org{}, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return []Org{}, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return []Org{}, err
		}

		wrapped := OrgSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return []Org{}, err
		}

		orgs = []Org{}
		for _, hit := range wrapped.Hits.Hits {
			orgs = append(orgs, hit.Source)
		}

		return orgs, nil
	} else {
		q := datastore.NewQuery(index)
		_, err = project.Dbclient.GetAll(ctx, q, &orgs)
		if err != nil {
			return []Org{}, err
		}
	}

	return orgs, nil
}

// Index = Username
func SetSchedule(ctx context.Context, schedule ScheduleOld) error {
	nameKey := "schedules"

	// New struct, to not add body, author etc
	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(schedule)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in setschedule: %s", err)
			return nil
		}
		err = indexEs(ctx, nameKey, strings.ToLower(schedule.Id), data)
		if err != nil {
			return err
		}
	} else {
		key1 := datastore.NameKey(nameKey, strings.ToLower(schedule.Id), nil)
		if _, err := project.Dbclient.Put(ctx, key1, &schedule); err != nil {
			log.Printf("Error adding schedule: %s", err)
			return err
		}
	}

	return nil
}

func GetAppExecutionValues(ctx context.Context, parameterNames, orgId, workflowId, value string) ([]NewValue, error) {
	nameKey := fmt.Sprintf("app_execution_values")
	var workflows []NewValue

	// Appending the users' workflows
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": []map[string]interface{}{
						{
							"match": map[string]interface{}{
								"org_id": orgId,
							},
						},
					},
				},
			},
		}

		//"workflow_id":    executionId,
		//"parameter_name": parameterNames,
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return workflows, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(nameKey)),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[WARNING] Error getting response: %s", err)
			return workflows, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return workflows, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return workflows, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return workflows, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return workflows, err
		}

		wrapped := NewValueSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return workflows, err
		}

		log.Printf("\n\nFOUND: %d", len(wrapped.Hits.Hits))
		workflows = []NewValue{}
		for _, hit := range wrapped.Hits.Hits {
			if hit.Source.Value == value && hit.Source.OrgId == orgId {
				workflows = append(workflows, hit.Source)
			}
		}
	} else {
		query := datastore.NewQuery(nameKey).Filter("org_id =", orgId).Filter("workflow_id =", workflowId).Filter("parameter_name =", parameterNames).Filter("value =", value)
		//foundCount, err := project.Dbclient.Count(ctx, q)
		cursorStr := ""
		for {
			it := project.Dbclient.Run(ctx, query)

			for {
				innerWorkflow := NewValue{}
				_, err := it.Next(&innerWorkflow)
				if err != nil {
					if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
					} else {
						log.Printf("[WARNING] CreateValue iterator issue: %s", err)
						break
					}
				}

				workflows = append(workflows, innerWorkflow)
			}

			if err != iterator.Done {
				//log.Printf("[INFO] Failed fetching results: %v", err)
				//break
			}

			// Get the cursor for the next page of results.
			nextCursor, err := it.Cursor()
			if err != nil {
				log.Printf("Cursorerror: %s", err)
				break
			} else {
				//log.Printf("NEXTCURSOR: %s", nextCursor)
				nextStr := fmt.Sprintf("%s", nextCursor)
				if cursorStr == nextStr {
					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)
				//cursorStr = nextCursor
				//break

			}
		}
	}

	return workflows, nil
}

// Used for cache for individual organizations
func SetCacheKey(ctx context.Context, cacheData CacheKeyData) error {
	nameKey := "org_cache"
	timeNow := int64(time.Now().Unix())
	cacheData.Edited = timeNow

	cacheId := fmt.Sprintf("%s_%s_%s", cacheData.OrgId, cacheData.WorkflowId, cacheData.Key)

	if len(cacheId) > 128 {
		cacheId = cacheId[0:127]
	}

	cacheId = url.QueryEscape(cacheId)
	cacheData.Authorization = ""

	// New struct, to not add body, author etc
	data, err := json.Marshal(cacheData)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in set cache key: %s", err)
		return nil
	}
	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, cacheId, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, cacheId, nil)
		if _, err := project.Dbclient.Put(ctx, key, &cacheData); err != nil {
			log.Printf("Error adding workflow: %s", err)
			return err
		}
	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, cacheId)
		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for set cache key: %s", err)
		}
	}

	return nil
}

// Used for cache for individual organizations
func GetCacheKey(ctx context.Context, id string) (*CacheKeyData, error) {
	cacheData := &CacheKeyData{}
	nameKey := "org_cache"

	if len(id) > 128 {
		id = id[0:127]
	}

	id = url.QueryEscape(id)
	//fmt.Println("http://example.com/say?message="+url.QueryEscape(s))

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			parsedCache := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %#v", cacheData)
			err = json.Unmarshal(parsedCache, &cacheData)
			if err == nil {
				return cacheData, nil
			}
		} else {
			log.Printf("[DEBUG] Failed getting cache for cache key %s: %s", id, err)
		}
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(nameKey), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return cacheData, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return cacheData, errors.New("Key doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return cacheData, err
		}

		wrapped := CacheKeyWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return cacheData, err
		}

		cacheData = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		if err := project.Dbclient.Get(ctx, key, cacheData); err != nil {
			if strings.Contains(err.Error(), `cannot load field`) {
				log.Printf("[INFO] Error in workflow loading. Migrating workflow to new workflow handler.")
				err = nil
			} else {
				return cacheData, err
			}
		}
	}

	if project.CacheDb {
		log.Printf("[DEBUG] Setting cache for workflow %s", cacheKey)
		data, err := json.Marshal(cacheData)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getcachekey: %s", err)
			return cacheData, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for get cache key: %s", err)
		}
	}

	return cacheData, nil
}
