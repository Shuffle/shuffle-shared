package shuffle

import (
	"cloud.google.com/go/datastore"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"github.com/patrickmn/go-cache"
	"github.com/satori/go.uuid"
	"google.golang.org/api/iterator"
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

				log.Printf("[INFO] CACHE: TOTAL SIZE FOR %s: %d", name, len(totalData))
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
	key := datastore.NameKey("workflowapp", id, nil)

	// New struct, to not add body, author etc
	if _, err := project.Dbclient.Put(ctx, key, &workflowapp); err != nil {
		log.Printf("[WARNING] Error adding workflow app: %s", err)
		return err
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
	key := datastore.NameKey(nameKey, workflowExecution.ExecutionId, nil)
	if _, err := project.Dbclient.Put(ctx, key, &workflowExecution); err != nil {
		log.Printf("Error adding workflow_execution: %s", err)
		return err
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
			log.Printf("[INFO] Action ID %s was not found in actions! Skipping parent. (TRIGGER?)", branch.SourceID)
		}

		if destinationFound {
			children[branch.SourceID] = append(children[branch.SourceID], branch.DestinationID)
		} else {
			log.Printf("[INFO] Action ID %s was not found in actions! Skipping child. (TRIGGER?)", branch.SourceID)
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
			//log.Printf("[INFO] Failed getting cache for execution variables data %s: %s", executionId, err)
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
			log.Printf("[INFO] Failed getting cache for workflow execution: %s", err)
		}
	}

	key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
	if err := project.Dbclient.Get(ctx, key, workflowExecution); err != nil {
		return &WorkflowExecution{}, err
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
			//log.Printf("[INFO] Failed getting cache for org: %s", err)
		}
	}

	key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
	if err := project.Dbclient.Get(ctx, key, workflowApp); err != nil {
		for _, app := range user.PrivateApps {
			if app.ID == id {
				workflowApp = &app
				break
			}
		}

	}

	if workflowApp.ID == "" {
		return &WorkflowApp{}, err
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
			log.Printf("[INFO] Failed getting cache for workflow: %s", err)
		}
	}

	key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
	if err := project.Dbclient.Get(ctx, key, workflow); err != nil {
		if strings.Contains(err.Error(), `cannot load field`) {
			log.Printf("[INFO] Error in workflow loading. Migrating workflow to new workflow handler.")
			err = nil
		} else {
			return &Workflow{}, err
		}
	}

	if project.CacheDb {
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

func GetAllWorkflows(ctx context.Context, orgId string) ([]Workflow, error) {
	var allworkflows []Workflow
	q := datastore.NewQuery("workflow").Filter("org_id = ", orgId)

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
			//log.Printf("[INFO] Failed getting cache for org: %s", err)
		}
	}

	setOrg := false
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

	newUsers := []User{}
	for _, user := range curOrg.Users {
		user.Password = ""
		user.Session = ""
		user.ResetReference = ""
		user.PrivateApps = []WorkflowApp{}
		user.VerificationToken = ""
		user.ApiKey = ""
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

func SetOrg(ctx context.Context, data Org, id string) error {
	nameKey := "Organizations"
	timeNow := int64(time.Now().Unix())
	if data.Created == 0 {
		data.Created = timeNow
	}

	data.Edited = timeNow

	// clear session_token and API_token for user
	k := datastore.NameKey(nameKey, id, nil)
	if _, err := project.Dbclient.Put(ctx, k, &data); err != nil {
		log.Println(err)
		return err
	}

	if project.CacheDb {

		newUsers := []User{}
		for _, user := range data.Users {
			user.Password = ""
			user.Session = ""
			user.ResetReference = ""
			user.PrivateApps = []WorkflowApp{}
			user.VerificationToken = ""
			user.ApiKey = ""
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

	key := datastore.NameKey("sessions", thissession, nil)
	if err := project.Dbclient.Get(ctx, key, session); err != nil {
		return &Session{}, err
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

	key1 := datastore.NameKey(entity, value, nil)

	err = project.Dbclient.Delete(ctx, key1)
	if err != nil {
		log.Printf("Error deleting %s from %s: %s", value, entity, err)
		return err
	}

	return nil
}

// Index = Username
func SetApikey(ctx context.Context, Userdata User) error {

	// Non indexed User data
	newapiUser := new(Userapi)
	newapiUser.ApiKey = Userdata.ApiKey
	newapiUser.Username = strings.ToLower(Userdata.Username)
	key1 := datastore.NameKey("apikey", newapiUser.ApiKey, nil)

	// New struct, to not add body, author etc
	if _, err := project.Dbclient.Put(ctx, key1, newapiUser); err != nil {
		log.Printf("Error adding apikey: %s", err)
		return err
	}

	return nil
}

func SetOpenApiDatastore(ctx context.Context, id string, data ParsedOpenApi) error {
	k := datastore.NameKey("openapi3", id, nil)
	if _, err := project.Dbclient.Put(ctx, k, &data); err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func GetOpenApiDatastore(ctx context.Context, id string) (ParsedOpenApi, error) {
	key := datastore.NameKey("openapi3", id, nil)
	api := &ParsedOpenApi{}
	if err := project.Dbclient.Get(ctx, key, api); err != nil {
		return ParsedOpenApi{}, err
	}

	return *api, nil
}

// Index = Username
func SetSession(ctx context.Context, user User, value string) error {
	//parsedKey := strings.ToLower(user.Username)
	//if project.Environment != "cloud" {
	//}
	parsedKey := user.Id

	// Non indexed User data
	user.Session = value
	key1 := datastore.NameKey("Users", parsedKey, nil)

	// New struct, to not add body, author etc
	if _, err := project.Dbclient.Put(ctx, key1, &user); err != nil {
		log.Printf("[WARNING] Error adding Usersession: %s", err)
		return err
	}

	if len(user.Session) > 0 {
		// Indexed session data
		sessiondata := new(Session)
		sessiondata.UserId = strings.ToLower(user.Id)
		sessiondata.Username = strings.ToLower(user.Username)
		sessiondata.Session = user.Session
		sessiondata.Id = user.Id
		key2 := datastore.NameKey("sessions", sessiondata.Session, nil)

		if _, err := project.Dbclient.Put(ctx, key2, sessiondata); err != nil {
			log.Printf("Error adding session: %s", err)
			return err
		}
	}

	return nil
}

func FindUser(ctx context.Context, username string) ([]User, error) {
	q := datastore.NewQuery("Users").Filter("Username =", username)
	var users []User
	_, err = project.Dbclient.GetAll(ctx, q, &users)
	if err != nil && len(users) == 0 {
		log.Printf("[WARNING] Failed getting users for username: %s", username)
		return users, err
	}

	log.Printf("[INFO] Found %d user(s) for email %s in db-connector", len(users), username)

	return users, nil
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
			//log.Printf("[INFO] Failed getting cache for user: %s", err)
		}
	}

	key := datastore.NameKey("Users", parsedKey, nil)
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

	k := datastore.NameKey("Users", parsedKey, nil)
	if _, err := project.Dbclient.Put(ctx, k, user); err != nil {
		log.Printf("[WARNING] Error updating user: %s", err)
		return err
	}

	DeleteCache(ctx, user.ApiKey)
	DeleteCache(ctx, user.Session)

	if project.CacheDb {
		cacheKey := fmt.Sprintf("user_%s", parsedKey)
		data, err := json.Marshal(user)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling user: %s", err)
			return nil
		}

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
			log.Printf("[INFO] Failed getting cache app auth: %s", err)
		}
	}

	q := datastore.NewQuery(nameKey).Filter("org_id = ", orgId)
	_, err = project.Dbclient.GetAll(ctx, q, &allworkflowappAuths)
	if err != nil && len(allworkflowappAuths) == 0 {
		return []AppAuthenticationStorage{}, err
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
	}

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
			log.Printf("[INFO] Failed getting cache in GET environments: %s", err)
		}
	}

	q := datastore.NewQuery(nameKey).Filter("org_id =", orgId)
	_, err = project.Dbclient.GetAll(ctx, q, &environments)
	if err != nil && len(environments) == 0 {
		return []Environment{}, err
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
		return GetAllWorkflowApps(ctx, 500)
	}

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
			log.Printf("[INFO] Failed getting cache for apps with KEY %s: %s", cacheKey, err)
		}
	}

	maxLen := 100
	cursorStr := ""
	limit := 100
	allApps = user.PrivateApps
	query := datastore.NewQuery("workflowapp").Filter("reference_org =", user.ActiveOrg.Id).Limit(limit)
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

				log.Printf("[WARNING] No more apps for %s in org app load? Breaking: %s.", user.Username, err)
				break
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
			if err == nil {
				return allApps, nil
			} else {
				log.Printf("Failed unmarshaling PUBLIC apps: %s", err)
				log.Printf("DATALEN: %d", len(cacheData))
			}
		} else {
			log.Printf("[INFO] Failed getting cache for PUBLIC apps: %s", err)
		}
	}

	if len(publicApps) == 0 {
		query = datastore.NewQuery("workflowapp").Filter("public =", true).Limit(limit)
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

					log.Printf("[WARNING] No more apps (public)? Breaking: %s.", err)
					break
				}

				//log.Printf("APP: %s", innerApp.Name)
				//found := false
				////log.Printf("ACTIONS: %d - %s", len(app.Actions), app.Name)
				//for _, loopedApp := range allApps {
				//	if loopedApp.Name == innerApp.Name || loopedApp.ID == innerApp.ID {
				//		found = true
				//		break
				//	}
				//}

				//if !found {
				//	publicApps = append(publicApps, innerApp)
				//}

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
			//log.Printf("[INFO] Failed getting cache for apps with KEY %s: %s", cacheKey, err)
		}
	}

	cursorStr := ""
	query := datastore.NewQuery("workflowapp").Order("-edited").Limit(10)
	//query := datastore.NewQuery("workflowapp").Order("-edited").Limit(40)

	// NOT BEING UPDATED
	// FIXME: Update the app with the correct actions. HOW DOES THIS WORK??
	// Seems like only actions are wrong. Could get the app individually.
	// Guessing it's a memory issue.
	//var err error
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

		if len(allApps) > maxLen {
			break
		}
	}

	//log.Printf("FOUND %d apps", len(allApps))
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

	//var allworkflowapps []WorkflowApp
	//_, err := dbclient.GetAll(ctx, query, &allworkflowapps)
	//if err != nil {
	//	if strings.Contains(fmt.Sprintf("%s", err), "ResourceExhausted") {
	//		//datastore.NewQuery("workflowapp").Limit(30).Order("-edited")
	//		query = datastore.NewQuery("workflowapp").Order("-edited").Limit(25)
	//		//q := q.Limit(25)
	//		_, err := dbclient.GetAll(ctx, query, &allworkflowapps)
	//		if err != nil {
	//			return []WorkflowApp{}, err
	//		}
	//	} else {
	//		return []WorkflowApp{}, err
	//	}
	//}

	return allApps, nil
}

func SetWorkflowQueue(ctx context.Context, executionRequests ExecutionRequestWrapper, id string) error {
	key := datastore.NameKey("workflowqueue", id, nil)

	// New struct, to not add body, author etc
	if _, err := project.Dbclient.Put(ctx, key, &executionRequests); err != nil {
		log.Printf("Error adding workflow queue: %s", err)
		return err
	}

	return nil
}

func GetWorkflowQueue(ctx context.Context, id string) (ExecutionRequestWrapper, error) {

	key := datastore.NameKey("workflowqueue", id, nil)
	workflows := ExecutionRequestWrapper{}
	if err := project.Dbclient.Get(ctx, key, &workflows); err != nil {
		return ExecutionRequestWrapper{}, err
	}

	return workflows, nil
}

func SetWorkflow(ctx context.Context, workflow Workflow, id string, optionalEditedSecondsOffset ...int) error {
	nameKey := "workflow"
	key := datastore.NameKey(nameKey, id, nil)
	workflow.Edited = int64(time.Now().Unix())
	if len(optionalEditedSecondsOffset) > 0 {
		workflow.Edited += int64(optionalEditedSecondsOffset[0])
	}

	// New struct, to not add body, author etc
	if _, err := project.Dbclient.Put(ctx, key, &workflow); err != nil {
		log.Printf("Error adding workflow: %s", err)
		return err
	}

	if project.CacheDb {
		data, err := json.Marshal(workflow)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getworkflow: %s", err)
			return nil
		}

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
	key := datastore.NameKey(nameKey, id, nil)

	// New struct, to not add body, author etc
	if _, err := project.Dbclient.Put(ctx, key, &workflowappauth); err != nil {
		log.Printf("[WARNING] Error adding workflow app AUTH: %s", err)
		return err
	}

	cacheKey := fmt.Sprintf("%s_%s", nameKey, workflowappauth.OrgId)
	DeleteCache(ctx, cacheKey)

	return nil
}

func SetEnvironment(ctx context.Context, data *Environment) error {
	// clear session_token and API_token for user
	nameKey := "Environments"

	if data.Id == "" {
		data.Id = uuid.NewV4().String()
	}

	// New struct, to not add body, author etc
	log.Printf("SETTING ENVIRONMENT %s", data.Id)
	k := datastore.NameKey(nameKey, data.Id, nil)
	if _, err := project.Dbclient.Put(ctx, k, data); err != nil {
		log.Println(err)
		return err
	}

	cacheKey := fmt.Sprintf("%s_%s", nameKey, data.OrgId)
	DeleteCache(ctx, cacheKey)

	return nil
}

func GetSchedule(ctx context.Context, schedulename string) (*ScheduleOld, error) {
	key := datastore.NameKey("schedules", strings.ToLower(schedulename), nil)
	curUser := &ScheduleOld{}
	if err := project.Dbclient.Get(ctx, key, curUser); err != nil {
		return &ScheduleOld{}, err
	}

	return curUser, nil
}

func GetApikey(ctx context.Context, apikey string) (User, error) {
	// Query for the specific API-key in users
	q := datastore.NewQuery("Users").Filter("apikey =", apikey)
	var users []User
	_, err = project.Dbclient.GetAll(ctx, q, &users)
	if err != nil && len(users) == 0 {
		log.Printf("[WARNING] Error getting apikey: %s", err)
		return User{}, err
	}

	if len(users) == 0 {
		log.Printf("[WARNING] No users found for apikey %s", apikey)
		return User{}, err
	}

	return users[0], nil
}

func GetHook(ctx context.Context, hookId string) (*Hook, error) {
	nameKey := "hooks"
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
			log.Printf("[INFO] Failed getting cache for hook: %s", err)
		}
	}

	key := datastore.NameKey(nameKey, hookId, nil)
	dbErr := project.Dbclient.Get(ctx, key, hook)
	if project.CacheDb {
		hookData, err := json.Marshal(hook)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in gethook: %s", err)
			return hook, dbErr
		}

		err = SetCache(ctx, cacheKey, hookData)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for gethook: %s", err)
		}
	}

	return hook, dbErr
}

func SetHook(ctx context.Context, hook Hook) error {
	nameKey := "hooks"
	key1 := datastore.NameKey(nameKey, strings.ToLower(hook.Id), nil)

	// New struct, to not add body, author etc
	if _, err := project.Dbclient.Put(ctx, key1, &hook); err != nil {
		log.Printf("Error adding hook: %s", err)
		return err
	}

	if project.CacheDb {
		hookData, err := json.Marshal(hook)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in setHook: %s", err)
			return nil
		}

		cacheKey := fmt.Sprintf("%s_%s", nameKey, hook.Id)
		err = SetCache(ctx, cacheKey, hookData)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for hook: %s", err)
		}
	}

	return nil
}

func GetFile(ctx context.Context, id string) (*File, error) {
	key := datastore.NameKey("Files", id, nil)
	curFile := &File{}
	if err := project.Dbclient.Get(ctx, key, curFile); err != nil {
		return &File{}, err
	}

	return curFile, nil
}

func SetFile(ctx context.Context, file File) error {
	// clear session_token and API_token for user
	timeNow := time.Now().Unix()
	file.UpdatedAt = timeNow

	k := datastore.NameKey("Files", file.Id, nil)
	if _, err := project.Dbclient.Put(ctx, k, &file); err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func GetAllFiles(ctx context.Context, orgId string) ([]File, error) {
	var files []File
	q := datastore.NewQuery("Files").Filter("org_id =", orgId).Limit(100)

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
			//log.Printf("[INFO] Failed getting cache for org: %s", err)
		}
	}

	// New struct, to not add body, author etc
	key := datastore.NameKey(nameKey, id, nil)
	if err := project.Dbclient.Get(ctx, key, appAuth); err != nil {
		return &AppAuthenticationStorage{}, err
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

	q := datastore.NewQuery("schedules").Filter("org = ", orgId)
	if orgId == "ALL" && project.Environment != "cloud" {
		q = datastore.NewQuery("schedules")
	}

	_, err := project.Dbclient.GetAll(ctx, q, &schedules)
	if err != nil && len(schedules) == 0 {
		return []ScheduleOld{}, err
	}

	return schedules, nil
}
