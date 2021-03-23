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

	"github.com/patrickmn/go-cache"
	"google.golang.org/api/iterator"
	"google.golang.org/appengine/memcache"
)

var err error
var requestCache *cache.Cache

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

	return errors.New(fmt.Sprintf("No cache found for %s", name))
}

// Cache handlers
func GetCache(ctx context.Context, name string) (interface{}, error) {
	if project.Environment == "cloud" {
		if item, err := memcache.Get(ctx, name); err == memcache.ErrCacheMiss {
		} else if err != nil {
			return "", errors.New(fmt.Sprintf("Failed getting CLOUD cache for %s: %s", name, err))
		} else {
			return item.Value, nil
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
		maxSize := 1020000
		loop := false
		if len(data) > maxSize {
			loop = true
			//log.Printf("Should make multiple cache items for %s", name)
			return errors.New(fmt.Sprintf("Couldn't set cache for %s - too large: %d > %d", name, len(data), maxSize))
		}
		_ = loop

		item := &memcache.Item{
			Key:        name,
			Value:      data,
			Expiration: time.Minute * 30,
		}

		if err := memcache.Set(ctx, item); err != nil {
			log.Printf("[WARNING] Failed setting cache for %s: %s", name, err)
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
	// FIXME - this doesn't work
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
		log.Printf("Error adding workflow app: %s", err)
		return err
	}

	return nil
}

func SetWorkflowExecution(ctx context.Context, workflowExecution WorkflowExecution, dbSave bool) error {
	//log.Printf("\n\n\nRESULT: %s\n\n\n", workflowExecution.Status)
	if len(workflowExecution.ExecutionId) == 0 {
		log.Printf("Workflowexeciton executionId can't be empty.")
		return errors.New("ExecutionId can't be empty.")
	}

	cacheKey := fmt.Sprintf("workflowexecution-%s", workflowExecution.ExecutionId)
	executionData, err := json.Marshal(workflowExecution)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling execution: %s", err)

		err = SetCache(ctx, cacheKey, executionData)
		if err != nil {
			log.Printf("[WARNING] Failed updating execution: %s", err)
		}
	} else {
		log.Printf("[WARNING] Failed to set execution cache for workflow.")
	}

	//requestCache.Set(cacheKey, &workflowExecution, cache.DefaultExpiration)
	if !dbSave && workflowExecution.Status == "EXECUTING" && len(workflowExecution.Results) > 1 {
		//log.Printf("[WARNING] SHOULD skip DB saving for execution")
		return nil
	}

	// New struct, to not add body, author etc
	key := datastore.NameKey("workflowexecution", workflowExecution.ExecutionId, nil)
	if _, err := project.Dbclient.Put(ctx, key, &workflowExecution); err != nil {
		log.Printf("Error adding workflow_execution: %s", err)
		return err
	}

	return nil
}

type ExecutionVariableWrapper struct {
	StartNode    string              `json:"startnode"`
	Children     map[string][]string `json:"children"`
	Parents      map[string][]string `json:"parents""`
	Visited      []string            `json:"visited"`
	Executed     []string            `json:"executed"`
	NextActions  []string            `json:"nextActions"`
	Environments []string            `json:"environments"`
	Extra        int                 `json:"extra"`
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
			log.Printf("ID %s was not found in actions! Skipping parent. (TRIGGER?)", branch.SourceID)
		}

		if destinationFound {
			children[branch.SourceID] = append(children[branch.SourceID], branch.DestinationID)
		} else {
			log.Printf("ID %s was not found in actions! Skipping child. (TRIGGER?)", branch.SourceID)
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
	cacheKey := fmt.Sprintf("workflowexecution-%s", id)
	workflowExecution := &WorkflowExecution{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %#v", cacheData)
			err = json.Unmarshal(cacheData, &workflowExecution)
			if err == nil {
				return workflowExecution, nil
			}
		} else {
			//log.Printf("[INFO] Failed getting cache for workflow execution: %s", err)
		}
	}

	key := datastore.NameKey("workflowexecution", strings.ToLower(id), nil)
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

func GetApp(ctx context.Context, id string) (*WorkflowApp, error) {

	key := datastore.NameKey("workflowapp", strings.ToLower(id), nil)
	workflowApp := &WorkflowApp{}
	if err := project.Dbclient.Get(ctx, key, workflowApp); err != nil {
		return &WorkflowApp{}, err
	}

	return workflowApp, nil
}

func GetWorkflow(ctx context.Context, id string) (*Workflow, error) {

	key := datastore.NameKey("workflow", strings.ToLower(id), nil)
	workflow := &Workflow{}
	if err := project.Dbclient.Get(ctx, key, workflow); err != nil {
		return &Workflow{}, err
	}

	return workflow, nil
}

func GetAllWorkflows(ctx context.Context, orgId string) ([]Workflow, error) {
	var allworkflows []Workflow
	q := datastore.NewQuery("workflow").Filter("org_id = ", orgId)

	_, err := project.Dbclient.GetAll(ctx, q, &allworkflows)
	if err != nil {
		return []Workflow{}, err
	}

	return allworkflows, nil
}

// ListBooks returns a list of books, ordered by title.
func GetOrg(ctx context.Context, id string) (*Org, error) {
	curOrg := &Org{}
	if project.CacheDb {
		cache, err := GetCache(ctx, id)
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

	key := datastore.NameKey("Organizations", id, nil)
	if err := project.Dbclient.Get(ctx, key, curOrg); err != nil {
		return &Org{}, err
	}

	if project.CacheDb {
		neworg, err := json.Marshal(curOrg)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling org: %s", err)
			return curOrg, nil
		}

		err = SetCache(ctx, id, neworg)
		if err != nil {
			log.Printf("[WARNING] Failed updating cache: %s", err)
		}
	}

	return curOrg, nil
}

func SetOrg(ctx context.Context, data Org, id string) error {
	timeNow := int64(time.Now().Unix())
	if data.Created == 0 {
		data.Created = timeNow
	}

	data.Edited = timeNow

	// clear session_token and API_token for user
	k := datastore.NameKey("Organizations", id, nil)
	if _, err := project.Dbclient.Put(ctx, k, &data); err != nil {
		log.Println(err)
		return err
	}

	if project.CacheDb {
		neworg, err := json.Marshal(data)
		if err != nil {
			return nil
		}

		err = SetCache(ctx, id, neworg)
		if err != nil {
			log.Printf("Failed setting cache: %s", err)
			//DeleteCache(neworg)
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
		log.Printf("[WARNING] Error getting session cache for %s: %v", thissession, err)
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
	newapiUser.Username = Userdata.Username
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
	parsedKey := strings.ToLower(user.Username)
	if project.Environment != "cloud" {
		parsedKey = user.Id
	}

	// Non indexed User data
	user.Session = value
	key1 := datastore.NameKey("Users", parsedKey, nil)

	// New struct, to not add body, author etc
	if _, err := project.Dbclient.Put(ctx, key1, &user); err != nil {
		log.Printf("rror adding Usersession: %s", err)
		return err
	}

	if len(user.Session) > 0 {
		// Indexed session data
		sessiondata := new(Session)
		sessiondata.Username = user.Username
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
		return &User{}, err
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

func SetUser(ctx context.Context, user *User) error {
	log.Printf("[INFO] Role: %s", user.Role)
	user = fixUserOrg(ctx, user)

	// clear session_token and API_token for user
	parsedKey := strings.ToLower(user.Username)
	if project.Environment != "cloud" {
		parsedKey = user.Id
	}

	k := datastore.NameKey("Users", parsedKey, nil)
	if _, err := project.Dbclient.Put(ctx, k, user); err != nil {
		log.Println(err)
		return err
	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("user_%s", strings.ToLower(user.Username))
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

	// Might be vulnerable to timing attacks.
	for _, orgId := range user.Orgs {
		if len(orgId) == 0 {
			continue
		}

		org, err := GetOrg(ctx, orgId)
		if err != nil {
			log.Printf("Error getting org %s", orgId)
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
			user.PrivateApps = []WorkflowApp{}
			user.Executions = ExecutionInfo{}
			user.Limits = UserLimits{}
			user.Authentication = []UserAuth{}

			org.Users[orgIndex] = *user
		} else {
			org.Users = append(org.Users, *user)
		}

		err = SetOrg(ctx, *org, orgId)
		if err != nil {
			log.Printf("Failed setting org %s", orgId)
		}
	}

	return user
}

func GetAllWorkflowAppAuth(ctx context.Context, OrgId string) ([]AppAuthenticationStorage, error) {
	var allworkflowapps []AppAuthenticationStorage
	q := datastore.NewQuery("workflowappauth").Filter("org_id = ", OrgId)

	_, err = project.Dbclient.GetAll(ctx, q, &allworkflowapps)
	if err != nil {
		return []AppAuthenticationStorage{}, err
	}

	return allworkflowapps, nil
}

func GetEnvironments(ctx context.Context, OrgId string) ([]Environment, error) {
	var environments []Environment
	q := datastore.NewQuery("Environments").Filter("org_id =", OrgId)

	_, err = project.Dbclient.GetAll(ctx, q, &environments)
	if err != nil {
		return []Environment{}, err
	}

	return environments, nil
}

//func GetAllWorkflowApps(ctx context.Context, maxLen int) ([]WorkflowApp, error) {
//	var apps []WorkflowApp
//	query := datastore.NewQuery("workflowapp").Order("-edited").Limit(20)
//	//query := datastore.NewQuery("workflowapp").Order("-edited").Limit(40)
//
//	cursorStr := ""
//
//	// NOT BEING UPDATED
//	// FIXME: Update the app with the correct actions. HOW DOES THIS WORK??
//	// Seems like only actions are wrong. Could get the app individually.
//	// Guessing it's a memory issue.
//	//Actions        []WorkflowAppAction `json:"actions" yaml:"actions" required:true datastore:"actions,noindex"`
//	//errors.New(nil)
//	for {
//		it := project.Dbclient.Run(ctx, query)
//		//_, err = it.Next(&app)
//		for {
//			var app WorkflowApp
//			_, err := it.Next(&app)
//			if err != nil {
//				break
//			}
//
//			found := false
//			//log.Printf("ACTIONS: %d - %s", len(app.Actions), app.Name)
//			for _, innerapp := range apps {
//				if innerapp.Name == app.Name {
//					found = true
//					break
//				}
//			}
//
//			if !found {
//				apps = append(apps, app)
//			}
//		}
//
//		// Get the cursor for the next page of results.
//		nextCursor, err := it.Cursor()
//		if err != nil {
//			log.Printf("Cursorerror: %s", err)
//			break
//		} else {
//			//log.Printf("NEXTCURSOR: %s", nextCursor)
//			nextStr := fmt.Sprintf("%s", nextCursor)
//			if cursorStr == nextStr {
//				break
//			}
//
//			cursorStr = nextStr
//			query = query.Start(nextCursor)
//			//cursorStr = nextCursor
//			//break
//		}
//
//		if len(apps) >= maxLen {
//			break
//		}
//	}
//
//	return apps, nil
//}
//
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
			//log.Printf("ACTIONS: %d - %s", len(app.Actions), app.Name)
			for _, loopedApp := range allApps {
				if loopedApp.Name == innerApp.Name {
					found = true
					break
				}
			}

			if !found {
				allApps = append(allApps, innerApp)
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

	log.Printf("FOUND %d apps", len(allApps))
	if project.CacheDb {
		log.Printf("[INFO] Setting %d apps in cache", len(allApps))

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
	workflow.Edited = int64(time.Now().Unix())
	if len(optionalEditedSecondsOffset) > 0 {
		workflow.Edited += int64(optionalEditedSecondsOffset[0])
	}

	key := datastore.NameKey("workflow", id, nil)

	// New struct, to not add body, author etc
	if _, err := project.Dbclient.Put(ctx, key, &workflow); err != nil {
		log.Printf("Error adding workflow: %s", err)
		return err
	}

	return nil
}

func SetWorkflowAppAuthDatastore(ctx context.Context, workflowappauth AppAuthenticationStorage, id string) error {
	key := datastore.NameKey("workflowappauth", id, nil)

	// New struct, to not add body, author etc
	if _, err := project.Dbclient.Put(ctx, key, &workflowappauth); err != nil {
		log.Printf("Error adding workflow app: %s", err)
		return err
	}

	return nil
}

func SetEnvironment(ctx context.Context, data *Environment) error {
	// clear session_token and API_token for user
	k := datastore.NameKey("Environments", strings.ToLower(data.Name), nil)

	// New struct, to not add body, author etc

	if _, err := project.Dbclient.Put(ctx, k, data); err != nil {
		log.Println(err)
		return err
	}

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
	// Query for the specifci workflowId
	//q := datastore.NewQuery("Users")
	q := datastore.NewQuery("Users").Filter("apikey =", apikey)
	var users []User
	_, err = project.Dbclient.GetAll(ctx, q, &users)
	if err != nil {
		log.Printf("Error getting apikeys: %s", err)
		return User{}, err
	}

	if len(users) == 0 {
		log.Printf("No users found for apikey %s", apikey)
		return User{}, err
	}

	return users[0], nil
}

func GetHook(ctx context.Context, hookId string) (*Hook, error) {
	key := datastore.NameKey("hooks", strings.ToLower(hookId), nil)
	hook := &Hook{}
	if err := project.Dbclient.Get(ctx, key, hook); err != nil {
		return &Hook{}, err
	}

	return hook, nil
}

func SetHook(ctx context.Context, hook Hook) error {
	key1 := datastore.NameKey("hooks", strings.ToLower(hook.Id), nil)

	// New struct, to not add body, author etc
	if _, err := project.Dbclient.Put(ctx, key1, &hook); err != nil {
		log.Printf("Error adding hook: %s", err)
		return err
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
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "ResourceExhausted") {
			q = q.Limit(50)
			_, err := project.Dbclient.GetAll(ctx, q, &files)
			if err != nil {
				return []File{}, err
			}
		} else {
			return []File{}, err
		}
	}

	return files, nil
}

func GetWorkflowAppAuthDatastore(ctx context.Context, id string) (*AppAuthenticationStorage, error) {

	key := datastore.NameKey("workflowappauth", id, nil)
	appAuth := &AppAuthenticationStorage{}
	// New struct, to not add body, author etc
	if err := project.Dbclient.Get(ctx, key, appAuth); err != nil {
		return &AppAuthenticationStorage{}, err
	}

	return appAuth, nil
}

func GetAllSchedules(ctx context.Context, orgId string) ([]ScheduleOld, error) {
	var schedules []ScheduleOld

	q := datastore.NewQuery("schedules").Filter("org = ", orgId)
	//CreatedAt    int64    `json:"created_at" datastore:"created_at"`
	if orgId == "ALL" {
		q = datastore.NewQuery("schedules")
	}

	_, err := project.Dbclient.GetAll(ctx, q, &schedules)
	if err != nil {
		return []ScheduleOld{}, err
	}

	return schedules, nil
}
