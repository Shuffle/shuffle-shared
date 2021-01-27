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

	"google.golang.org/appengine/memcache"
)

var err error

// Cache handlers
func DeleteCache(ctx context.Context, name string) error {
	if project.Environment == "cloud" {
		return memcache.Delete(ctx, name)
	} else {
		return errors.New(fmt.Sprintf("No cache handler for environment %s yet", project.Environment))
	}

	return errors.New(fmt.Sprintf("No cache found for %s", name))
}

// Cache handlers
func GetCache(ctx context.Context, name string) (interface{}, error) {
	if project.Environment == "cloud" {
		if item, err := memcache.Get(ctx, name); err == memcache.ErrCacheMiss {
		} else if err != nil {
			return "", errors.New(fmt.Sprintf("Failed getting cache: %s", err))
		} else {
			return item.Value, nil
		}
	} else {
		return "", errors.New(fmt.Sprintf("No cache handler for environment %s yet", project.Environment))
	}

	return "", errors.New(fmt.Sprintf("No cache found for %s", name))
}

func SetCache(ctx context.Context, name string, data []byte) error {
	log.Printf("DATA SIZE: %d", len(data))
	// Maxsize ish~

	if project.Environment == "cloud" {
		maxSize := 1020000
		loop := false
		if len(data) > maxSize {
			loop = true
			log.Printf("Should make multiple cache items for %s", name)
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

func SetWorkflowExecution(ctx context.Context, workflowExecution WorkflowExecution) error {
	if len(workflowExecution.ExecutionId) == 0 {
		log.Printf("Workflowexeciton executionId can't be empty.")
		return errors.New("ExecutionId can't be empty.")
	}

	key := datastore.NameKey("workflowexecution", workflowExecution.ExecutionId, nil)

	// New struct, to not add body, author etc
	if _, err := project.Dbclient.Put(ctx, key, &workflowExecution); err != nil {
		log.Printf("Error adding workflow_execution: %s", err)
		return err
	}

	return nil
}

func GetWorkflowExecution(ctx context.Context, id string) (*WorkflowExecution, error) {

	key := datastore.NameKey("workflowexecution", strings.ToLower(id), nil)
	workflowExecution := &WorkflowExecution{}
	if err := project.Dbclient.Get(ctx, key, workflowExecution); err != nil {
		return &WorkflowExecution{}, err
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

func GetAllWorkflows(ctx context.Context) ([]Workflow, error) {
	q := datastore.NewQuery("workflow")
	var allworkflows []Workflow

	_, err = project.Dbclient.GetAll(ctx, q, &allworkflows)
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
			log.Printf("Failed getting cache for org: %s", err)
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

func GetSession(ctx context.Context, thissession string) (*session, error) {
	key := datastore.NameKey("sessions", thissession, nil)
	curUser := &session{}
	if err := project.Dbclient.Get(ctx, key, curUser); err != nil {
		return &session{}, err
	}

	return curUser, nil
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
func SetSession(ctx context.Context, Userdata User, value string) error {

	// Non indexed User data
	Userdata.Session = value
	key1 := datastore.NameKey("Users", strings.ToLower(Userdata.Username), nil)

	// New struct, to not add body, author etc
	if _, err := project.Dbclient.Put(ctx, key1, &Userdata); err != nil {
		log.Printf("rror adding Usersession: %s", err)
		return err
	}

	if len(Userdata.Session) > 0 {
		// Indexed session data
		sessiondata := new(session)
		sessiondata.Username = Userdata.Username
		sessiondata.Session = Userdata.Session
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

	cacheKey := fmt.Sprintf("user_%s", strings.ToLower(username))
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &curUser)
			if err == nil {
				return curUser, nil
			}
		} else {
			log.Printf("Failed getting cache for user: %s", err)
		}
	}

	key := datastore.NameKey("Users", strings.ToLower(username), nil)
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
	k := datastore.NameKey("Users", strings.ToLower(user.Username), nil)
	if _, err := project.Dbclient.Put(ctx, k, user); err != nil {
		log.Println(err)
		return err
	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("user_%s", strings.ToLower(user.Username))
		data, err := json.Marshal(user)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling org: %s", err)
			return nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating cache: %s", err)
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

func GetAllWorkflowApps(ctx context.Context, maxLen int) ([]WorkflowApp, error) {
	var apps []WorkflowApp
	query := datastore.NewQuery("workflowapp").Order("-edited").Limit(20)
	//query := datastore.NewQuery("workflowapp").Order("-edited").Limit(40)

	cursorStr := ""

	// NOT BEING UPDATED
	// FIXME: Update the app with the correct actions. HOW DOES THIS WORK??
	// Seems like only actions are wrong. Could get the app individually.
	// Guessing it's a memory issue.
	//Actions        []WorkflowAppAction `json:"actions" yaml:"actions" required:true datastore:"actions,noindex"`
	//errors.New(nil)
	for {
		it := project.Dbclient.Run(ctx, query)
		//_, err = it.Next(&app)
		for {
			var app WorkflowApp
			_, err := it.Next(&app)
			if err != nil {
				break
			}

			found := false
			//log.Printf("ACTIONS: %d - %s", len(app.Actions), app.Name)
			for _, innerapp := range apps {
				if innerapp.Name == app.Name {
					found = true
					break
				}
			}

			if !found {
				apps = append(apps, app)
			}
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

		if len(apps) >= maxLen {
			break
		}
	}

	return apps, nil
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

func SetWorkflow(ctx context.Context, workflow Workflow, id string) error {
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

	//log.Printf("Users: %d", len(users))
	//for _, item := range users {
	//	if len(item.ApiKey) > 0 {
	//		log.Printf(item.ApiKey)
	//		break
	//	}
	//}

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
