package shuffle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/satori/go.uuid"
	"google.golang.org/appengine"
	"google.golang.org/appengine/memcache"
)

var project ShuffleStorage

func HandleCors(resp http.ResponseWriter, request *http.Request) bool {

	// FIXME - this is to handle multiple frontends in test rofl
	origin := request.Header["Origin"]
	resp.Header().Set("Vary", "Origin")
	if len(origin) > 0 {
		resp.Header().Set("Access-Control-Allow-Origin", origin[0])
	} else {
		resp.Header().Set("Access-Control-Allow-Origin", "http://localhost:4201")
	}
	//resp.Header().Set("Access-Control-Allow-Origin", "http://localhost:8000")
	resp.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, X-Requested-With, remember-me")
	resp.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, POST")
	resp.Header().Set("Access-Control-Allow-Credentials", "true")

	if request.Method == "OPTIONS" {
		resp.WriteHeader(200)
		resp.Write([]byte("OK"))
		return true
	}

	return false
}

func HandleGetOrgs(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("Api authentication failed in set new workflowhandler: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role != "global_admin" {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Not admin"}`))
		return
	}

	ctx := context.Background()
	dbclient, err := getDatastoreClient(ctx, project.GceProject)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed setting orgs"}`))
		return
	}

	var orgs []Org
	q := datastore.NewQuery("Organizations")
	_, err = dbclient.GetAll(ctx, q, &orgs)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't get orgs"}`))
		return
	}

	//newUsers := []User{}
	//for _, item := range users {
	//	if len(item.Username) == 0 {
	//		continue
	//	}

	//	item.Password = ""
	//	item.Session = ""
	//	item.VerificationToken = ""

	//	newUsers = append(newUsers, item)
	//}

	newjson, err := json.Marshal(orgs)
	if err != nil {
		log.Printf("Failed unmarshal: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func HandleGetOrg(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	var fileId string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("Path too short: %d", len(location))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("Api authentication failed in set new workflowhandler: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := context.Background()
	org, err := GetOrg(ctx, fileId)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting org users"}`))
		return
	}

	//FIXME : cleanup org before marshal
	userFound := false
	for _, foundUser := range org.Users {
		if foundUser.Id == user.Id {
			userFound = true
			break
		}
	}

	// FIXME
	if org.Users == nil || len(org.Users) == 0 {
		log.Printf("No users found in org. Checking if ok")
		if org.Name == user.Username {
			user.PrivateApps = []WorkflowApp{}
			user.Role = "admin"
			org.Users = append(org.Users, user)
			_ = SetOrg(ctx, *org, org.Id)
		} else {
			log.Printf("Couldn't find user in org")
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "User doesn't have access to org (1)"}`))
			return
		}
	} else if !userFound {
		log.Printf("Couldn't find user in org")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "User doesn't have access to org"}`))
		return
	}

	org.Users = []User{}
	org.SyncConfig.Apikey = ""
	newjson, err := json.Marshal(org)
	if err != nil {
		log.Printf("Failed unmarshal of org: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func HandleLogout(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	http.SetCookie(resp, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Path:    "/",
		Expires: time.Unix(0, 0),
	})

	userInfo, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("Api authentication failed in handleLogout: %s", err)
		resp.WriteHeader(200)
		resp.Write([]byte(`{"success": true, "reason": "Not logged in"}`))
		return
	}

	ctx := context.Background()
	session, err := GetSession(ctx, userInfo.Session)
	if err != nil {
		log.Printf("Session %#v doesn't exist: %s", session, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "No session"}`))
		return
	}

	err = SetSession(ctx, userInfo, "")
	if err != nil {
		log.Printf("Error removing session for: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Username and/or password is incorrect"}`))
		return
	}

	err = DeleteKey(ctx, "sessions", userInfo.Session)
	if err != nil {
		log.Printf("Error deleting key %s for %s: %s", userInfo.Session, userInfo.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Username and/or password is incorrect"}`))
		return
	}

	userInfo.Session = ""
	err = SetUser(ctx, &userInfo)
	if err != nil {
		log.Printf("Failed updating user: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed updating apikey"}`))
		return
	}

	//memcache.Delete(request.Context(), sessionToken)

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": false, "reason": "Successfully logged out"}`))
}

func SetNewWorkflow(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("Api authentication failed in set new workflowhandler: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Error with body read: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	var workflow Workflow
	err = json.Unmarshal(body, &workflow)
	if err != nil {
		log.Printf("Failed unmarshaling: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	workflow.ID = uuid.NewV4().String()
	workflow.Owner = user.Id
	workflow.Sharing = "private"
	workflow.ExecutingOrg = user.ActiveOrg
	workflow.OrgId = user.ActiveOrg.Id

	ctx := context.Background()
	log.Printf("Saved new workflow %s with name %s", workflow.ID, workflow.Name)

	if len(workflow.Actions) == 0 {
		workflow.Actions = []Action{}
	}
	if len(workflow.Branches) == 0 {
		workflow.Branches = []Branch{}
	}
	if len(workflow.Triggers) == 0 {
		workflow.Triggers = []Trigger{}
	}
	if len(workflow.Errors) == 0 {
		workflow.Errors = []string{}
	}

	newActions := []Action{}
	for _, action := range workflow.Actions {
		if action.Environment == "" {
			//action.Environment = baseEnvironment
			action.IsValid = true
		}

		newActions = append(newActions, action)
	}

	// Initialized without functions = adding a hello world node.
	if len(newActions) == 0 {
		log.Printf("APPENDING NEW APP FOR NEW WORKFLOW")

		// Adds the Testing app if it's a new workflow
		workflowapps, err := GetAllWorkflowApps(ctx, 100)
		if err == nil {
			// FIXME: Add real env
			envName := "Shuffle"
			environments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
			if err == nil {
				for _, env := range environments {
					if env.Default {
						envName = env.Name
						break
					}
				}
			}

			for _, item := range workflowapps {
				if item.Name == "Testing" && item.AppVersion == "1.0.0" {
					nodeId := "40447f30-fa44-4a4f-a133-4ee710368737"
					workflow.Start = nodeId
					newActions = append(newActions, Action{
						Label:       "Start node",
						Name:        "hello_world",
						Environment: envName,
						Parameters:  []WorkflowAppActionParameter{},
						Position: struct {
							X float64 "json:\"x\" datastore:\"x\""
							Y float64 "json:\"y\" datastore:\"y\""
						}{X: 449.5, Y: 446},
						Priority:    0,
						Errors:      []string{},
						ID:          nodeId,
						IsValid:     true,
						IsStartNode: true,
						Sharing:     true,
						PrivateID:   "",
						SmallImage:  "",
						AppName:     item.Name,
						AppVersion:  item.AppVersion,
						AppID:       item.ID,
						LargeImage:  item.LargeImage,
					})
					break
				}
			}
		}
	} else {
		log.Printf("Has %d actions already", len(newActions))
	}

	for _, item := range workflow.Actions {
		item.ID = uuid.NewV4().String()
		newActions = append(newActions, item)
	}

	newTriggers := []Trigger{}
	for _, item := range workflow.Triggers {
		item.Status = "uninitialized"
		item.ID = uuid.NewV4().String()
		newTriggers = append(newTriggers, item)
	}

	newSchedules := []Schedule{}
	for _, item := range workflow.Schedules {
		item.Id = uuid.NewV4().String()
		newSchedules = append(newSchedules, item)
	}

	workflow.Actions = newActions
	workflow.Triggers = newTriggers
	workflow.Schedules = newSchedules
	workflow.IsValid = true
	workflow.Configuration.ExitOnError = false

	workflowjson, err := json.Marshal(workflow)
	if err != nil {
		log.Printf("Failed workflow json setting marshalling: %s", err)
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	err = SetWorkflow(ctx, workflow, workflow.ID)
	if err != nil {
		log.Printf("Failed setting workflow: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	//memcacheName := fmt.Sprintf("%s_workflows", user.Username)
	//memcache.Delete(ctx, memcacheName)

	resp.WriteHeader(200)
	//log.Println(string(workflowjson))
	resp.Write(workflowjson)
}

// Basically a search for apps that aren't activated yet
func GetSpecificApps(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	//FIXME - shouldn't return everything :)
	returnData := fmt.Sprintf(`{"success": true, "reason": []}`)
	resp.WriteHeader(200)
	resp.Write([]byte(returnData))
	return

	// Just need to be logged in
	// FIXME - should have some permissions?
	_, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("Api authentication failed in set new app: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Error with body read: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	type tmpStruct struct {
		Search string `json:"search"`
	}

	var tmpBody tmpStruct
	err = json.Unmarshal(body, &tmpBody)
	if err != nil {
		log.Printf("Error with unmarshal tmpBody: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// FIXME - continue the search here with github repos etc.
	// Caching might be smart :D
	ctx := context.Background()
	workflowapps, err := GetAllWorkflowApps(ctx, 100)
	if err != nil {
		log.Printf("Error: Failed getting workflowapps: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	returnValues := []WorkflowApp{}
	search := strings.ToLower(tmpBody.Search)
	for _, app := range workflowapps {
		if !app.Activated && app.Generated {
			// This might be heavy with A LOT
			// Not too worried with todays tech tbh..
			appName := strings.ToLower(app.Name)
			appDesc := strings.ToLower(app.Description)
			if strings.Contains(appName, search) || strings.Contains(appDesc, search) {
				//log.Printf("Name: %s, Generated: %s, Activated: %s", app.Name, strconv.FormatBool(app.Generated), strconv.FormatBool(app.Activated))
				returnValues = append(returnValues, app)
			}
		}
	}

	newbody, err := json.Marshal(returnValues)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking workflow executions"}`)))
		return
	}

	returnData = fmt.Sprintf(`{"success": true, "reason": %s}`, string(newbody))
	resp.WriteHeader(200)
	resp.Write([]byte(returnData))
}

func GetAppAuthentication(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("Api authentication failed in get all apps: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// FIXME: Auth to get the right ones only
	//if user.Role != "admin" {
	//	log.Printf("User isn't admin")
	//	resp.WriteHeader(401)
	//	resp.Write([]byte(`{"success": false}`))
	//	return
	//}
	ctx := context.Background()
	allAuths, err := GetAllWorkflowAppAuth(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("Api authentication failed in get all app auth: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(allAuths) == 0 {
		resp.WriteHeader(200)
		resp.Write([]byte(`{"success": true, "data": []}`))
		return
	}

	// Cleanup for frontend
	newAuth := []AppAuthenticationStorage{}
	for _, auth := range allAuths {
		newAuthField := auth
		for index, _ := range auth.Fields {
			newAuthField.Fields[index].Value = "auth placeholder (replaced during execution)"
		}

		newAuth = append(newAuth, newAuthField)
	}

	newbody, err := json.Marshal(allAuths)
	if err != nil {
		log.Printf("Failed unmarshalling all app auths: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking workflow app auth"}`)))
		return
	}

	data := fmt.Sprintf(`{"success": true, "data": %s}`, string(newbody))

	resp.WriteHeader(200)
	resp.Write([]byte(data))

	/*
		data := `{
			"success": true,
			"data": [
				{
					"app": {
						"name": "thehive",
						"description": "what",
						"app_version": "1.0.0",
						"id": "4f97da9d-1caf-41cc-aa13-67104d8d825c",
						"large_image": "asd"
					},
					"fields": {
						"apikey": "hello",
						"url": "url"
					},
					"usage": [{
						"workflow_id": "asd",
						"nodes": [{
							"node_id": ""
						}]
					}],
					"label": "Original",
					"id": "4f97da9d-1caf-41cc-aa13-67104d8d825d",
					"active": true
				},
				{
					"app": {
						"name": "thehive",
						"description": "what",
						"app_version": "1.0.0",
						"id": "4f97da9d-1caf-41cc-aa13-67104d8d825c",
						"large_image": "asd"
					},
					"fields": {
						"apikey": "hello",
						"url": "url"
					},
					"usage": [{
						"workflow_id": "asd",
						"nodes": [{
							"node_id": ""
						}]
					}],
					"label": "Number 2",
					"id": "4f97da9d-1caf-41cc-aa13-67104d8d825d",
					"active": true
				}
			]
		}`
	*/
}

func AddAppAuthentication(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("Api authentication failed in get all apps: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Error with body read: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	var appAuth AppAuthenticationStorage
	err = json.Unmarshal(body, &appAuth)
	if err != nil {
		log.Printf("Failed unmarshaling (appauth): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(appAuth.Id) == 0 {
		appAuth.Id = uuid.NewV4().String()
	}

	ctx := context.Background()
	if len(appAuth.Label) == 0 {
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Label can't be empty"}`)))
		return
	}

	// Super basic check
	if len(appAuth.App.ID) != 36 && len(appAuth.App.ID) != 32 {
		log.Printf("Bad ID for app: %s", appAuth.App.ID)
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "App has to be defined"}`)))
		return
	}

	app, err := GetApp(ctx, appAuth.App.ID)
	if err != nil {
		log.Printf("Failed finding app %s while setting auth.", appAuth.App.ID)
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
		return
	}

	// Check if the items are correct
	for _, field := range appAuth.Fields {
		found := false
		for _, param := range app.Authentication.Parameters {
			if field.Key == param.Name {
				found = true
			}
		}

		if !found {
			log.Printf("Failed finding field %s in appauth fields", field.Key)
			resp.WriteHeader(409)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "All auth fields required"}`)))
			return
		}
	}

	appAuth.OrgId = user.ActiveOrg.Id
	err = SetWorkflowAppAuthDatastore(ctx, appAuth, appAuth.Id)
	if err != nil {
		log.Printf("Failed setting up app auth %s: %s", appAuth.Id, err)
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func DeleteAppAuthentication(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("Api authentication failed in edit workflow: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role != "admin" {
		log.Printf("Need to be admin to delete appauth")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")
	log.Printf("%#v", location)
	var fileId string
	if location[1] == "api" {
		if len(location) <= 5 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[5]
	}

	// FIXME: Set affected workflows to have errors
	// 1. Get the auth
	// 2. Loop the workflows (.Usage) and set them to have errors
	// 3. Loop the nodes in workflows and do the same

	log.Printf("ID: %s", fileId)
	ctx := context.Background()
	err := DeleteKey(ctx, "workflowappauth", fileId)
	if err != nil {
		log.Printf("Failed deleting workflowapp")
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed deleting workflow app"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleSetEnvironments(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// FIXME: Overhaul the top part.
	// Only admin can change environments, but if there are no users, anyone can make (first)
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't handle set env auth"}`))
		return
	}

	if user.Role != "admin" {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't set environment without being admin"}`))
		return
	}

	ctx := context.Background()
	var environments []Environment
	q := datastore.NewQuery("Environments").Filter("org_id =", user.ActiveOrg.Id)
	_, err = project.Dbclient.GetAll(ctx, q, &environments)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't get environments when setting"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Println("Failed reading body")
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to read data"}`)))
		return
	}

	var newEnvironments []Environment
	err = json.Unmarshal(body, &newEnvironments)
	if err != nil {
		log.Printf("Failed unmarshaling: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to unmarshal data"}`)))
		return
	}

	if len(newEnvironments) < 1 {
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "One environment is required"}`)))
		return
	}

	// Clear old data? Removed for archiving purpose. No straight deletion
	//for _, item := range environments {
	//	err = DeleteKey(ctx, "Environments", item.Name)
	//	if err != nil {
	//		resp.WriteHeader(401)
	//		resp.Write([]byte(`{"success": false, "reason": "Error cleaning up environment"}`))
	//		return
	//	}
	//}

	openEnvironments := 0
	for _, item := range newEnvironments {
		if !item.Archived {
			openEnvironments += 1
		}
	}

	if openEnvironments < 1 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't archived all environments"}`))
		return
	}

	for _, item := range newEnvironments {
		if item.OrgId != user.ActiveOrg.Id {
			item.OrgId = user.ActiveOrg.Id
		}

		err = SetEnvironment(ctx, &item)
		if err != nil {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed setting environment variable"}`))
			return
		}
	}

	//DeleteKey(ctx, entity string, value string) error {
	// FIXME - check which are in use
	//log.Printf("FIXME: Set new environments: %#v", newEnvironments)
	//log.Printf("DONT DELETE ONES THAT ARE IN USE")

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleGetEnvironments(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("Api authentication failed in set new workflowhandler: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := context.Background()
	var environments []Environment
	q := datastore.NewQuery("Environments").Filter("org_id =", user.ActiveOrg.Id)
	_, err = project.Dbclient.GetAll(ctx, q, &environments)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't get environments"}`))
		return
	}

	newjson, err := json.Marshal(environments)
	if err != nil {
		log.Printf("Failed unmarshal: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking environments"}`)))
		return
	}

	//log.Printf("Existing environments: %s", string(newjson))

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func HandleApiAuthentication(resp http.ResponseWriter, request *http.Request) (User, error) {
	apikey := request.Header.Get("Authorization")
	if len(apikey) > 0 {
		if !strings.HasPrefix(apikey, "Bearer ") {
			log.Printf("Apikey doesn't start with bearer")
			return User{}, errors.New("No bearer token for authorization header")
		}

		apikeyCheck := strings.Split(apikey, " ")
		if len(apikeyCheck) != 2 {
			log.Printf("Invalid format for apikey.")
			return User{}, errors.New("Invalid format for apikey")
		}

		// fml
		//log.Println(apikeyCheck)

		// This is annoying af
		newApikey := apikeyCheck[1]
		if len(newApikey) > 249 {
			newApikey = newApikey[0:248]
		}

		ctx := appengine.NewContext(request)
		if item, err := memcache.Get(ctx, newApikey); err == memcache.ErrCacheMiss {
			// Not in cache
		} else if err != nil {
			// Error with cache
			log.Printf("Error getting item: %v", err)
		} else {
			var Userdata User
			err = json.Unmarshal(item.Value, &Userdata)

			if err == nil {
				if len(Userdata.Username) > 0 {
					return Userdata, nil
				} else {
					return Userdata, errors.New("Error: User doesn't have a username")
				}
			}
		}

		// Make specific check for just service user?
		// Get the user based on APIkey here
		//log.Println(apikeyCheck[1])
		Userdata, err := GetApikey(ctx, apikeyCheck[1])
		if err != nil {
			log.Printf("Apikey %s doesn't exist: %s", apikey, err)
			return User{}, err
		}

		// Caching both bad and good apikeys :)
		b, err := json.Marshal(Userdata)
		if err != nil {
			log.Printf("Failed marshalling: %s", err)
			return User{}, err
		}

		// Add to cache if it doesn't exist
		item := &memcache.Item{
			Key:        newApikey,
			Value:      b,
			Expiration: time.Minute * 60,
		}

		if err := memcache.Add(ctx, item); err == memcache.ErrNotStored {
			if err := memcache.Set(ctx, item); err != nil {
				log.Printf("Error setting item: %v", err)
			}
		} else if err != nil {
			log.Printf("error adding item: %v", err)
		} else {
			log.Printf("Set cache for %s", item.Key)
		}

		if len(Userdata.Username) > 0 {
			return Userdata, nil
		} else {
			return Userdata, errors.New("Error: User is invalid - no username found")
		}
	}

	// One time API keys
	authorizationArr, ok := request.URL.Query()["authorization"]
	ctx := appengine.NewContext(request)
	if ok {
		authorization := ""
		if len(authorizationArr) > 0 {
			authorization = authorizationArr[0]
		}

		if item, err := memcache.Get(ctx, authorization); err == memcache.ErrCacheMiss {
			// Doesn't exist :(
			log.Printf("Couldn't find %s in cache!", authorization)
			return User{}, err
		} else if err != nil {
			log.Printf("Error getting item: %v", err)
			return User{}, err
		} else {
			log.Printf("%#v", item.Value)
			var Userdata User

			log.Printf("Deleting key %s", authorization)
			memcache.Delete(ctx, authorization)
			err = json.Unmarshal(item.Value, &Userdata)
			if err == nil {
				return Userdata, nil
			}

			return User{}, err
		}
	}

	c, err := request.Cookie("session_token")
	if err == nil {
		if item, err := memcache.Get(ctx, c.Value); err == memcache.ErrCacheMiss {
			// Not in cache
		} else if err != nil {
			log.Printf("Error getting item: %v", err)
		} else {
			var Userdata User
			err = json.Unmarshal(item.Value, &Userdata)
			if err == nil {
				return Userdata, nil
			}
		}

		sessionToken := c.Value
		session, err := GetSession(ctx, sessionToken)
		if err != nil {
			log.Printf("Session %s doesn't exist: %s", session.Session, err)
			return User{}, err
		}

		// Get session first
		// Should basically never happen
		Userdata, err := GetUser(ctx, session.Username)
		if err != nil {
			log.Printf("Username %s doesn't exist: %s", session.Username, err)
			return User{}, err
		}

		if Userdata.Session != sessionToken {
			return User{}, errors.New("Wrong session token")
		}

		// Means session exists, but
		return *Userdata, nil
	}

	// Key = apikey
	return User{}, errors.New("Missing authentication")
}

func RunInit(dbclient datastore.Client, gceProject, environment string) ShuffleStorage {
	project = ShuffleStorage{
		Dbclient:    dbclient,
		GceProject:  gceProject,
		Environment: environment,
	}

	return project
}

func UpdateWorkflowAppConfig(resp http.ResponseWriter, request *http.Request) {
	cors := handleCors(resp, request)
	if cors {
		return
	}

	user, userErr := handleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("Api authentication failed in get all apps: %s", userErr)
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

	ctx := context.Background()
	app, err := getApp(ctx, fileId)
	if err != nil {
		log.Printf("Error getting app (update app): %s", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Id != app.Owner && user.Role != "admin" {
		log.Printf("Wrong user (%s) for app %s in update app", user.Username, app.Name)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Error with body read in update app: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	type updatefields struct {
		Sharing       bool   `json:"sharing"`
		SharingConfig string `json:"sharing_config"`
	}

	var tmpfields updatefields
	err = json.Unmarshal(body, &tmpfields)
	if err != nil {
		log.Printf("Error with unmarshal body in update app: %s\n%s", err, string(body))
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if tmpfields.Sharing != app.Sharing {
		app.Sharing = tmpfields.Sharing
	}

	if tmpfields.SharingConfig != app.SharingConfig {
		app.SharingConfig = tmpfields.SharingConfig
	}

	err = setWorkflowAppDatastore(ctx, *app, app.ID)
	if err != nil {
		log.Printf("Failed patching workflowapp: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	cacheKey := fmt.Sprintf("workflowapps-sorted")
	requestCache.Delete(cacheKey)

	log.Printf("Changed workflow app %s", app.ID)
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true}`)))
}
