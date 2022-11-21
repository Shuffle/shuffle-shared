package shuffle

// This file contains all the function
// related to managing workflows

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	//"os/exec"
	"strings"
	"time"

	"encoding/json"
	"github.com/satori/go.uuid"
)

func GetWorkflows(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in getworkflows: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := GetContext(request)
	var workflows []Workflow

	cacheKey := fmt.Sprintf("%s_workflows", user.Id)
	cache, err := GetCache(ctx, cacheKey)
	if err == nil {
		cacheData := []byte(cache.([]uint8))
		err = json.Unmarshal(cacheData, &workflows)
		if err == nil {
			resp.WriteHeader(200)
			resp.Write(cacheData)
			return
		}
	} else {
		//log.Printf("[INFO] Failed getting cache for workflows for user %s", user.Id)
	}

	workflows, err = GetAllWorkflowsByQuery(ctx, user)
	if err != nil {
		log.Printf("[WARNING] Failed getting workflows for user %s (0): %s", user.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(workflows) == 0 {
		log.Printf("[INFO] No workflows found for user %s", user.Username)
		resp.WriteHeader(200)
		resp.Write([]byte("[]"))
		return
	}

	newWorkflows := []Workflow{}
	for _, workflow := range workflows {
		if workflow.OrgId != user.ActiveOrg.Id {
			//log.Printf("[DEBUG] Skipping workflow for org %s (user: %s)", workflow.OrgId, user.Username)
			continue
		}

		newActions := []Action{}
		for _, action := range workflow.Actions {
			//log.Printf("Image: %s", action.LargeImage)
			// Removed because of exports. These are needed there.
			//action.LargeImage = ""
			//action.SmallImage = ""
			action.ReferenceUrl = ""
			newActions = append(newActions, action)
		}

		workflow.Actions = newActions

		// Skipping these as they're related to onprem workflows in cloud
		//log.Printf("ENVIRONMENT: %s", workflow.ExecutionEnvironment)
		if project.Environment == "cloud" && workflow.ExecutionEnvironment == "onprem" {
			continue
		}

		newWorkflows = append(newWorkflows, workflow)
	}

	//log.Printf("[INFO] Returning %d workflows", len(newWorkflows))
	newjson, err := json.Marshal(newWorkflows)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking workflows"}`)))
		return
	}

	if project.CacheDb {
		err = SetCache(ctx, cacheKey, newjson)
		if err != nil {
			log.Printf("[WARNING] Failed updating workflow cache: %s", err)
		}
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

/*
func DeleteWorkflows(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("Api authentication failed in deleting workflow: %s", err)
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

	if len(fileId) != 36 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID to delete is not valid"}`))
		return
	}

	ctx := GetContext(request)
	workflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("Failed getting the workflow locally: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// FIXME - have a check for org etc too..
	if user.Id != workflow.Owner || len(user.Id) == 0 {
		if workflow.OrgId == user.ActiveOrg.Id && user.Role == "admin" {
			log.Printf("[INFO] User %s is accessing %s executions as admin", user.Username, workflow.ID)
		} else {
		log.Printf("Wrong user (%s) for workflow %s", user.Username, workflow.ID)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
		}
	}

	// Clean up triggers and executions
	for _, item := range workflow.Triggers {
		if item.TriggerType == "SCHEDULE" {
			err = deleteSchedule(ctx, item.ID)
			if err != nil {
				log.Printf("Failed to delete schedule: %s", err)
			}
		} else if item.TriggerType == "WEBHOOK" {
			err = removeWebhookFunction(ctx, item.ID)
			if err != nil {
				log.Printf("Failed to delete webhook: %s", err)
			}
		} else if item.TriggerType == "EMAIL" {
			err = handleOutlookSubRemoval(ctx, workflow.ID, item.ID)
			if err != nil {
				log.Printf("Failed to delete email sub: %s", err)
			}
		}
	}

	// FIXME - maybe delete workflow executions
	log.Printf("Should delete workflow %s", fileId)
	err = DeleteKey(ctx, "workflow", fileId)
	if err != nil {
		log.Printf("Failed deleting key %s", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed deleting key"}`))
		return
	}

	DeleteCache(ctx, fmt.Sprintf("%s_workflows", user.Id))
	DeleteCache(ctx, fmt.Sprintf("%s_%s", user.Username, fileId))

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}
*/

func SetNewWorkflow(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in set new workflow: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to set new workflow: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
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
	user.ActiveOrg.Users = []UserMini{}
	workflow.ExecutingOrg = user.ActiveOrg
	workflow.OrgId = user.ActiveOrg.Id
	//log.Printf("TRIGGERS: %d", len(workflow.Triggers))

	ctx := GetContext(request)
	//err = increaseStatisticsField(ctx, "total_workflows", workflow.ID, 1, workflow.OrgId)
	//if err != nil {
	//	log.Printf("Failed to increase total workflows stats: %s", err)
	//}

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

			// FIXME: Still necessary? This hinders hybrid mode cloud -> onprem
			//if project.Environment == "cloud" {
			//	action.Environment = "Cloud"
			//}

			action.IsValid = true
		}

		//action.LargeImage = ""
		newActions = append(newActions, action)
	}

	// Initialized without functions = adding a hello world node.
	if len(newActions) == 0 {
		//log.Printf("APPENDING NEW APP FOR NEW WORKFLOW")

		// Adds the Testing app if it's a new workflow
		workflowapps, err := GetPrioritizedApps(ctx, user)
		envName := "cloud"
		if project.Environment != "cloud" {
			workflowapps, err = GetAllWorkflowApps(ctx, 1000, 0)
			envName = "Shuffle"
		}

		//log.Printf("[DEBUG] Got %d apps. Err: %s", len(workflowapps), err)
		if err == nil {
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
				//log.Printf("NAME: %s", item.Name)
				if (item.Name == "Shuffle Tools" || item.Name == "Shuffle-Tools") && item.AppVersion == "1.2.0" {
					//nodeId := "40447f30-fa44-4a4f-a133-4ee710368737"
					nodeId := uuid.NewV4().String()
					workflow.Start = nodeId
					newActions = append(newActions, Action{
						Label:       "Change Me",
						Name:        "repeat_back_to_me",
						Environment: envName,
						Parameters: []WorkflowAppActionParameter{
							WorkflowAppActionParameter{
								Name:      "call",
								Value:     "Hello world",
								Example:   "Repeating: Hello World",
								Multiline: true,
							},
						},
						Position: struct {
							X float64 "json:\"x,omitempty\" datastore:\"x\""
							Y float64 "json:\"y,omitempty\" datastore:\"y\""
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
		log.Printf("[INFO] Has %d actions already", len(newActions))
		// FIXME: Check if they require authentication and if they exist locally
		//log.Printf("\n\nSHOULD VALIDATE AUTHENTICATION")
		//AuthenticationId string `json:"authentication_id,omitempty" datastore:"authentication_id"`
		//allAuths, err := GetAllWorkflowAppAuth(ctx, user.ActiveOrg.Id)
		//if err == nil {
		//	log.Printf("AUTH: %#v", allAuths)
		//	for _, action := range newActions {
		//		log.Printf("ACTION: %#v", action)
		//	}
		//}
	}

	workflow.Actions = []Action{}
	for _, item := range workflow.Actions {
		oldId := item.ID
		sourceIndexes := []int{}
		destinationIndexes := []int{}
		for branchIndex, branch := range workflow.Branches {
			if branch.SourceID == oldId {
				sourceIndexes = append(sourceIndexes, branchIndex)
			}

			if branch.DestinationID == oldId {
				destinationIndexes = append(destinationIndexes, branchIndex)
			}
		}

		item.ID = uuid.NewV4().String()
		for _, index := range sourceIndexes {
			workflow.Branches[index].SourceID = item.ID
		}

		for _, index := range destinationIndexes {
			workflow.Branches[index].DestinationID = item.ID
		}

		newActions = append(newActions, item)
	}

	newTriggers := []Trigger{}
	for _, item := range workflow.Triggers {
		oldId := item.ID
		sourceIndexes := []int{}
		destinationIndexes := []int{}
		for branchIndex, branch := range workflow.Branches {
			if branch.SourceID == oldId {
				sourceIndexes = append(sourceIndexes, branchIndex)
			}

			if branch.DestinationID == oldId {
				destinationIndexes = append(destinationIndexes, branchIndex)
			}
		}

		item.ID = uuid.NewV4().String()
		for _, index := range sourceIndexes {
			workflow.Branches[index].SourceID = item.ID
		}

		for _, index := range destinationIndexes {
			workflow.Branches[index].DestinationID = item.ID
		}

		item.Status = "uninitialized"
		newTriggers = append(newTriggers, item)
	}

	newSchedules := []Schedule{}
	for _, item := range workflow.Schedules {
		item.Id = uuid.NewV4().String()
		newSchedules = append(newSchedules, item)
	}

	timeNow := int64(time.Now().Unix())
	workflow.Actions = newActions
	workflow.Triggers = newTriggers
	workflow.Schedules = newSchedules
	workflow.IsValid = true
	workflow.Configuration.ExitOnError = false
	workflow.Created = timeNow

	workflowjson, err := json.Marshal(workflow)
	if err != nil {
		log.Printf("Failed workflow json setting marshalling: %s", err)
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	err = SetWorkflow(ctx, workflow, workflow.ID)
	if err != nil {
		log.Printf("[WARNING] Failed setting workflow: %s (Set workflow)", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Cleans up cache for the users
	org, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err == nil {
		for _, loopUser := range org.Users {
			cacheKey := fmt.Sprintf("%s_workflows", loopUser.Id)
			DeleteCache(ctx, cacheKey)
		}
	} else {
		cacheKey := fmt.Sprintf("%s_workflows", user.Id)
		DeleteCache(ctx, cacheKey)
	}

	log.Printf("[INFO] Saved new workflow %s with name %s", workflow.ID, workflow.Name)

	resp.WriteHeader(200)
	//log.Println(string(workflowjson))
	resp.Write(workflowjson)
}


// Saves a workflow to an ID
func SaveWorkflow(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	//log.Println("Start")
	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("[WARNING] Api authentication failed in save workflow: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to save workflow (2): %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	//log.Println("PostUser")
	location := strings.Split(request.URL.String(), "/")

	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
		if strings.Contains(fileId, "?") {
			fileId = strings.Split(fileId, "?")[0]
		}
	}

	if len(fileId) != 36 {
		log.Printf(`[WARNING] Workflow ID %s is not valid`, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID to save is not valid"}`))
		return
	}

	// Here to check access rights
	ctx := GetContext(request)
	tmpworkflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Failed getting the workflow locally (save workflow): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	workflow := Workflow{}
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Failed workflow body read: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	err = json.Unmarshal([]byte(body), &workflow)
	if err != nil {
		//log.Printf(string(body))
		log.Printf("[ERROR] Failed workflow unmarshaling (save): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
		return
	}

	type PublicCheck struct {
		UserEditing bool   `json:"user_editing"`
		Public      bool   `json:"public"`
		Owner       string `json:"owner"`
	}

	correctUser := false
	if user.Id != tmpworkflow.Owner || tmpworkflow.Public == true {
		if tmpworkflow.Public {
			// FIXME:
			// If the user Id is part of the creator: DONT update this way.
			// /users/creators/username
			// Just making sure
			if project.Environment == "cloud" {
				//algoliaUser, err := HandleAlgoliaCreatorSearch(ctx, username)
				algoliaUser, err := HandleAlgoliaCreatorSearch(ctx, tmpworkflow.ID)
				if err != nil {
					log.Printf("[WARNING] User with ID %s for Workflow %s could not be found (workflow update): %s", user.Id, tmpworkflow.ID, err)

					// Check if current user is one of the few allowed
					// This can only happen if the workflow doesn't already have an owner
					//log.Printf("CUR USER: %#v\n\n%s", user.PublicProfile, os.Getenv("GITHUB_USER_ALLOWLIST"))
					allowList := os.Getenv("GITHUB_USER_ALLOWLIST")
					found := false
					if user.PublicProfile.Public && len(allowList) > 0 {
						allowListSplit := strings.Split(allowList, ",")
						for _, username := range allowListSplit {
							if username == user.PublicProfile.GithubUsername {
								algoliaUser, err = HandleAlgoliaCreatorSearch(ctx, user.PublicProfile.GithubUsername)
								if err != nil {
									log.Printf("New error: %s", err)
								}

								found = true
								break
							}

						}

					}

					if !found {
						resp.WriteHeader(401)
						resp.Write([]byte(`{"success": false}`))
						return
					}
				}

				wf2 := PublicCheck{}
				err = json.Unmarshal([]byte(body), &wf2)
				if err != nil {
					log.Printf("[ERROR] Failed workflow unmarshaling (save - 2): %s", err)
				}

				if algoliaUser.ObjectID == user.Id || ArrayContains(algoliaUser.Synonyms, user.Id) {
					log.Printf("[WARNING] User %s (%s) has access to edit %s! Keep it public!!", user.Username, user.Id, workflow.ID)

					// Means the owner is using the workflow for their org
					if wf2.UserEditing == false {
						correctUser = false
					} else {
						correctUser = true
						tmpworkflow.Public = true
						workflow.Public = true
					}
				}
			}

			// FIX: Should check if this workflow has already been saved?
			if !correctUser {
				log.Printf("[INFO] User %s is saving the public workflow %s", user.Username, tmpworkflow.ID)
				workflow = *tmpworkflow
				workflow.PublishedId = workflow.ID
				workflow.ID = uuid.NewV4().String()
				workflow.Public = false
				workflow.Owner = user.Id
				workflow.Org = []OrgMini{
					user.ActiveOrg,
				}
				workflow.ExecutingOrg = user.ActiveOrg
				workflow.OrgId = user.ActiveOrg.Id
				workflow.PreviouslySaved = false

				newTriggers := []Trigger{}
				changedIds := map[string]string{}
				for _, trigger := range workflow.Triggers {
					log.Printf("TriggerID: %#v", trigger.ID)
					newId := uuid.NewV4().String()
					trigger.Environment = "cloud"

					hookAuth := ""
					customResponse := ""
					for paramIndex, param := range trigger.Parameters {
						if param.Name == "url" {
							trigger.Parameters[paramIndex].Value = fmt.Sprintf("https://shuffler.io/api/v1/hooks/webhook_%s", newId)
						}

						if param.Name == "auth_headers" {
							hookAuth = param.Value
						}

						if param.Name == "custom_response_body" {
							customResponse = param.Value
						}
					}

					if trigger.TriggerType != "SCHEDULE" {

						trigger.Status = "running"

						if trigger.TriggerType == "WEBHOOK" {
							hook := Hook{
								Id:        newId,
								Start:     workflow.Start,
								Workflows: []string{workflow.ID},
								Info: Info{
									Name:        trigger.Name,
									Description: trigger.Description,
									Url:         fmt.Sprintf("https://shuffler.io/api/v1/hooks/webhook_%s", newId),
								},
								Type:   "webhook",
								Owner:  user.Username,
								Status: "running",
								Actions: []HookAction{
									HookAction{
										Type:  "workflow",
										Name:  trigger.Name,
										Id:    workflow.ID,
										Field: "",
									},
								},
								Running:        true,
								OrgId:          user.ActiveOrg.Id,
								Environment:    "cloud",
								Auth:           hookAuth,
								CustomResponse: customResponse,
							}

							log.Printf("[DEBUG] Starting hook %s for user %s (%s) during Workflow Save for %s", hook.Id, user.Username, user.Id, workflow.ID)
							err = SetHook(ctx, hook)
							if err != nil {
								log.Printf("[WARNING] Failed setting hook during workflow copy of %s: %s", workflow.ID, err)
								resp.WriteHeader(401)
								resp.Write([]byte(`{"success": false}`))
								return
							}
						}
					}

					changedIds[trigger.ID] = newId

					trigger.ID = newId
					//log.Printf("New id for %s: %s", trigger.TriggerType, trigger.ID)
					newTriggers = append(newTriggers, trigger)
				}

				newBranches := []Branch{}
				for _, branch := range workflow.Branches {
					for key, value := range changedIds {
						if branch.SourceID == key {
							branch.SourceID = value
						}

						if branch.DestinationID == key {
							branch.DestinationID = value
						}
					}

					newBranches = append(newBranches, branch)
				}

				workflow.Branches = newBranches
				workflow.Triggers = newTriggers

				err = SetWorkflow(ctx, workflow, workflow.ID)
				if err != nil {
					log.Printf("[WARNING] Failed saving NEW version of public %s for user %s: %s", tmpworkflow.ID, user.Username, err)
					resp.WriteHeader(401)
					resp.Write([]byte(`{"success": false}`))
					return
				}
				org, err := GetOrg(ctx, user.ActiveOrg.Id)
				if err != nil {
					log.Printf("[WARNING] Failed getting org for cache release for public wf: %s", err)
				} else {
					for _, loopUser := range org.Users {
						DeleteCache(ctx, fmt.Sprintf("%s_workflows", loopUser.Id))
						DeleteCache(ctx, fmt.Sprintf("apps_%s", loopUser.Id))
						DeleteCache(ctx, fmt.Sprintf("user_%s", loopUser.Id))
					}

					// Activate all that aren't already there
					changed := false
					for _, action := range workflow.Actions {
						//log.Printf("App: %#v, Public: %#v", action.AppID, action.Public)
						if !ArrayContains(org.ActiveApps, action.AppID) {
							org.ActiveApps = append(org.ActiveApps, action.AppID)
							changed = true
						}
					}

					if changed {
						err = SetOrg(ctx, *org, org.Id)
						if err != nil {
							log.Printf("[ERROR] Failed updating active app list for org %s (%s): %s", org.Name, org.Id, err)
						} else {
							DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
							DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-100"))
							DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-500"))
							DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-1000"))
							DeleteCache(ctx, "all_apps")
							DeleteCache(ctx, fmt.Sprintf("user_%s", user.Username))
							DeleteCache(ctx, fmt.Sprintf("user_%s", user.Id))
						}
					}
				}

				resp.WriteHeader(200)
				resp.Write([]byte(fmt.Sprintf(`{"success": true, "new_id": "%s"}`, workflow.ID)))
				return
			}
		} else if tmpworkflow.OrgId == user.ActiveOrg.Id && user.Role == "admin" {
			log.Printf("[AUDIT] User %s is accessing workflow %s as admin (save workflow)", user.Username, tmpworkflow.ID)
			workflow.ID = tmpworkflow.ID
		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (save)", user.Username, tmpworkflow.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	} else {

		if workflow.Public {
			log.Printf("[WARNING] Rolling back public as the user set it to true themselves")
			workflow.Public = false
		}

		if len(workflow.PublishedId) > 0 {
			log.Printf("[INFO] Workflow %s has the published ID %s", workflow.ID, workflow.PublishedId)
		}
	}

	if fileId != workflow.ID {
		log.Printf("[WARNING] Path and request ID are not matching in workflow save: %s != %s.", fileId, workflow.ID)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(workflow.Name) == 0 {
		log.Printf("[WARNING] Can't save workflow without a name.")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow needs a name"}`))
		return
	}

	if len(workflow.Actions) == 0 {
		log.Printf("[WARNING] Can't save workflow without a single action.")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow needs at least one action"}`))
		return
	}

	// Resetting subflows as they shouldn't be entirely saved. Used just for imports/exports
	if len(workflow.Subflows) > 0 {
		log.Printf("[DEBUG] Got %d subflows saved in %s (to be saved and removed)", len(workflow.Subflows), workflow.ID)
	}

	if workflow.Status != "test" && workflow.Status != "production" {
		workflow.Status = "test"
		log.Printf("[DEBUG] Defaulted workflow status to %s. Alternative: prod", workflow.Status)
	}

	if strings.ToLower(workflow.Status) == "prod" {
		workflow.Status = "production"
	}

	workflow.Subflows = []Workflow{}
	if len(workflow.DefaultReturnValue) > 0 && len(workflow.DefaultReturnValue) < 200 {
		log.Printf("[INFO] Set default return value to on failure to (%s): %s", workflow.ID, workflow.DefaultReturnValue)
		//workflow.DefaultReturnValue
	}

	log.Printf("[INFO] Saving workflow %s with %d action(s) and %d trigger(s)", workflow.Name, len(workflow.Actions), len(workflow.Triggers))

	if len(user.ActiveOrg.Id) > 0 {
		if len(workflow.ExecutingOrg.Id) == 0 {
			log.Printf("[INFO] Setting executing org for workflow to %s", user.ActiveOrg.Id)
			user.ActiveOrg.Users = []UserMini{}
			workflow.ExecutingOrg = user.ActiveOrg
		}

		//if len(workflow.Org) == 0 {
		//	user.ActiveOrg.Users = []UserMini{}
		//	//workflow.Org = user.ActiveOrg
		//}

		if len(workflow.OrgId) == 0 {
			workflow.OrgId = user.ActiveOrg.Id
		}
	}

	newActions := []Action{}
	allNodes := []string{}
	workflow.Categories = Categories{}

	environments := []Environment{
		Environment{
			Name:       "Cloud",
			Type:       "cloud",
			Archived:   false,
			Registered: true,
			Default:    false,
			OrgId:      user.ActiveOrg.Id,
			Id:         uuid.NewV4().String(),
		},
	}

	//if project.Environment != "cloud" {
	environments, err = GetEnvironments(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Failed getting environments for org %s", user.ActiveOrg.Id)
		environments = []Environment{}
	}
	//}

	//log.Printf("ENVIRONMENTS: %#v", environments)
	defaultEnv := ""
	for _, env := range environments {
		if env.Default {
			defaultEnv = env.Name
			break
		}
	}

	if defaultEnv == "" {
		if project.Environment == "cloud" {
			defaultEnv = "Cloud"
		} else {
			defaultEnv = "Shuffle"
		}
	}

	orgUpdated := false
	startnodeFound := false
	workflowapps, apperr := GetPrioritizedApps(ctx, user)
	newOrgApps := []string{}
	org := &Org{}
	for _, action := range workflow.Actions {
		if action.SourceWorkflow != workflow.ID && len(action.SourceWorkflow) > 0 {
			continue
		}

		allNodes = append(allNodes, action.ID)
		if workflow.Start == action.ID {
			//log.Printf("[INFO] FOUND STARTNODE %d", workflow.Start)
			startnodeFound = true
			action.IsStartNode = true
		}

		if len(action.Errors) > 0 || !action.IsValid {
			action.IsValid = true
			action.Errors = []string{}
		}

		if action.ExecutionDelay > 86400 {
			parsedError := fmt.Sprintf("Max execution delay for an action is 86400 (1 day)")
			if !ArrayContains(workflow.Errors, parsedError) {
				workflow.Errors = append(workflow.Errors, parsedError)
			}

			action.ExecutionDelay = 86400
		}

		if action.Environment == "" {
			if project.Environment == "cloud" {
				action.Environment = defaultEnv
			} else {
				if len(environments) > 0 {
					for _, env := range environments {
						if !env.Archived && env.Default {
							//log.Printf("FOUND ENV %#v", env)
							action.Environment = env.Name
							break
						}
					}
				}

				if action.Environment == "" {
					action.Environment = defaultEnv
				}

				action.IsValid = true
			}
		} else {
			warned := []string{}
			found := false
			for _, env := range environments {
				if env.Name == action.Environment {
					found = true
					if env.Archived {
						log.Printf("[DEBUG] Environment %s is archived. Changing to default.")
						action.Environment = defaultEnv
					}

					break
				}
			}

			if !found {
				if ArrayContains(warned, action.Environment) {
					log.Printf("[DEBUG] Environment %s isn't available. Changing to default.", action.Environment)
					warned = append(warned, action.Environment)
				}

				action.Environment = defaultEnv
			}
		}

		// Fixing apps with bad IDs. This can happen a lot because of
		// autogeneration of app IDs, and export/imports of workflows
		idFound := false
		nameVersionFound := false
		nameFound := false
		discoveredApp := WorkflowApp{}
		for _, innerApp := range workflowapps {
			if innerApp.ID == action.AppID {
				discoveredApp = innerApp
				//log.Printf("[INFO] ID, Name AND version for %s:%s (%s) was FOUND", action.AppName, action.AppVersion, action.AppID)
				action.Sharing = innerApp.Sharing
				action.Public = innerApp.Public
				action.Generated = innerApp.Generated
				action.ReferenceUrl = innerApp.ReferenceUrl
				idFound = true
				break
			}
		}

		if !idFound {
			for _, innerApp := range workflowapps {
				if innerApp.Name == action.AppName && innerApp.AppVersion == action.AppVersion {
					discoveredApp = innerApp

					action.AppID = innerApp.ID
					action.Sharing = innerApp.Sharing
					action.Public = innerApp.Public
					action.Generated = innerApp.Generated
					action.ReferenceUrl = innerApp.ReferenceUrl
					nameVersionFound = true
					break
				}
			}
		}

		if !idFound {
			for _, innerApp := range workflowapps {
				if innerApp.Name == action.AppName {
					discoveredApp = innerApp

					action.AppID = innerApp.ID
					action.Sharing = innerApp.Sharing
					action.Public = innerApp.Public
					action.Generated = innerApp.Generated
					action.ReferenceUrl = innerApp.ReferenceUrl

					nameFound = true
					break
				}
			}
		}

		if !idFound {
			if nameVersionFound {
			} else if nameFound {
			} else {
				log.Printf("[WARNING] ID, Name AND version for %s:%s (%s) was NOT found", action.AppName, action.AppVersion, action.AppID)
				handled := false

				if project.Environment == "cloud" {
					appid, err := HandleAlgoliaAppSearch(ctx, action.AppName)
					if err == nil && len(appid.ObjectID) > 0 {
						//log.Printf("[INFO] Found NEW appid %s for app %s", appid, action.AppName)
						tmpApp, err := GetApp(ctx, appid.ObjectID, user, false)
						if err == nil {
							handled = true
							action.AppID = tmpApp.ID
							newOrgApps = append(newOrgApps, action.AppID)

							workflowapps = append(workflowapps, *tmpApp)
						}
					} else {
						log.Printf("[WARNING] Failed finding name %s in Algolia", action.AppName)
					}
				}

				if !handled {
					action.IsValid = false
					action.Errors = []string{fmt.Sprintf("Couldn't find app %s:%s", action.AppName, action.AppVersion)}
				}
			}
		}

		if !action.IsValid && len(action.Errors) > 0 {
			log.Printf("[INFO] Node %s is invalid and needs to be remade. Errors: %s", action.Label, strings.Join(action.Errors, "\n"))

			//if workflow.PreviouslySaved {
			//	resp.WriteHeader(401)
			//	resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Node %s is invalid and needs to be remade."}`, action.Label)))
			//	return
			//}
			//action.IsValid = true
			//action.Errors = []string{}
		}

		workflow.Categories = HandleCategoryIncrease(workflow.Categories, action, workflowapps)
		newActions = append(newActions, action)

		// FIXMe: Should be authenticated first?
		if len(discoveredApp.Categories) > 0 {
			category := discoveredApp.Categories[0]

			if org.Id == "" {
				org, err = GetOrg(ctx, user.ActiveOrg.Id)
				if err != nil {
					log.Printf("[WARNING] Failed getting org: %s", err)
					continue
				}
			}

			if strings.ToLower(category) == "siem" && org.SecurityFramework.SIEM.ID == "" {
				org.SecurityFramework.SIEM.Name = discoveredApp.Name
				org.SecurityFramework.SIEM.Description = discoveredApp.Description
				org.SecurityFramework.SIEM.ID = discoveredApp.ID
				org.SecurityFramework.SIEM.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "network" && org.SecurityFramework.Network.ID == "" {
				org.SecurityFramework.Network.Name = discoveredApp.Name
				org.SecurityFramework.Network.Description = discoveredApp.Description
				org.SecurityFramework.Network.ID = discoveredApp.ID
				org.SecurityFramework.Network.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "edr" || strings.ToLower(category) == "edr & av" && org.SecurityFramework.EDR.ID == "" {
				org.SecurityFramework.EDR.Name = discoveredApp.Name
				org.SecurityFramework.EDR.Description = discoveredApp.Description
				org.SecurityFramework.EDR.ID = discoveredApp.ID
				org.SecurityFramework.EDR.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "cases" && org.SecurityFramework.Cases.ID == "" {
				org.SecurityFramework.Cases.Name = discoveredApp.Name
				org.SecurityFramework.Cases.Description = discoveredApp.Description
				org.SecurityFramework.Cases.ID = discoveredApp.ID
				org.SecurityFramework.Cases.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "iam" && org.SecurityFramework.IAM.ID == "" {
				org.SecurityFramework.IAM.Name = discoveredApp.Name
				org.SecurityFramework.IAM.Description = discoveredApp.Description
				org.SecurityFramework.IAM.ID = discoveredApp.ID
				org.SecurityFramework.IAM.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "assets" && org.SecurityFramework.Assets.ID == "" {
				log.Printf("Setting assets?")
				org.SecurityFramework.Assets.Name = discoveredApp.Name
				org.SecurityFramework.Assets.Description = discoveredApp.Description
				org.SecurityFramework.Assets.ID = discoveredApp.ID
				org.SecurityFramework.Assets.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "intel" && org.SecurityFramework.Intel.ID == "" {
				org.SecurityFramework.Intel.Name = discoveredApp.Name
				org.SecurityFramework.Intel.Description = discoveredApp.Description
				org.SecurityFramework.Intel.ID = discoveredApp.ID
				org.SecurityFramework.Intel.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "comms" && org.SecurityFramework.Communication.ID == "" {
				org.SecurityFramework.Communication.Name = discoveredApp.Name
				org.SecurityFramework.Communication.Description = discoveredApp.Description
				org.SecurityFramework.Communication.ID = discoveredApp.ID
				org.SecurityFramework.Communication.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else {
				//log.Printf("[WARNING] No handler for type %s in app framework", category)
			}

		}
	}

	if !startnodeFound {
		log.Printf("[WARNING] No startnode found during save of %s!!", workflow.ID)
	}

	// Automatically adding new apps
	if len(newOrgApps) > 0 {
		log.Printf("[WARNING] Adding new apps to org: %#v", newOrgApps)

		if org.Id == "" {
			org, err = GetOrg(ctx, user.ActiveOrg.Id)
			if err != nil {
				log.Printf("[WARNING] Failed getting org during new app update for %s: %s", user.ActiveOrg.Id, err)
			}
		}

		if org.Id != "" {
			added := false
			for _, newApp := range newOrgApps {
				if !ArrayContains(org.ActiveApps, newApp) {
					org.ActiveApps = append(org.ActiveApps, newApp)
					added = true
				}
			}

			if added {
				orgUpdated = true
				//err = SetOrg(ctx, *org, org.Id)
				//if err != nil {
				//	log.Printf("[WARNING] Failed setting org when autoadding apps on save: %s", err)
				//} else {
				DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
				DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-100"))
				DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-500"))
				DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-1000"))
				DeleteCache(ctx, "all_apps")
				DeleteCache(ctx, fmt.Sprintf("user_%s", user.Username))
				DeleteCache(ctx, fmt.Sprintf("user_%s", user.Id))
			}
			//}
		}
	}

	workflow.Actions = newActions

	newTriggers := []Trigger{}
	for _, trigger := range workflow.Triggers {
		if trigger.SourceWorkflow != workflow.ID && len(trigger.SourceWorkflow) > 0 {
			continue
		}

		//log.Printf("[INFO] Workflow: %s, Trigger %s: %s", workflow.ID, trigger.TriggerType, trigger.Status)

		// Check if it's actually running
		// FIXME: Do this for other triggers too
		if trigger.TriggerType == "SCHEDULE" && trigger.Status != "uninitialized" {
			schedule, err := GetSchedule(ctx, trigger.ID)
			if err != nil {
				trigger.Status = "stopped"
			} else if schedule.Id == "" {
				trigger.Status = "stopped"
			}
		} else if trigger.TriggerType == "SUBFLOW" {
			for _, param := range trigger.Parameters {
				//log.Printf("PARAMS: %#v", param)
				if param.Name == "workflow" {
					// Validate workflow exists
					_, err := GetWorkflow(ctx, param.Value)
					if err != nil {
						parsedError := fmt.Sprintf("Workflow %s in Subflow %s (%s) doesn't exist", workflow.ID, trigger.Label, trigger.ID)
						if !ArrayContains(workflow.Errors, parsedError) {
							workflow.Errors = append(workflow.Errors, parsedError)
						}

						log.Printf("[WARNING] Couldn't find subflow %s for workflow %s (%s)", param.Value, workflow.Name, workflow.ID)
					}
				}

				//if len(param.Value) == 0 && param.Name != "argument" {
				// FIXME: No longer necessary to use the org's users' actual APIkey
				// Instead, this is replaced during runtime to use the executions' key
				/*
					if param.Name == "user_apikey" {
						apikey := ""
						if len(user.ApiKey) > 0 {
							apikey = user.ApiKey
						} else {
							user, err = GenerateApikey(ctx, user)
							if err != nil {
								workflow.IsValid = false
								workflow.Errors = []string{"Trigger is missing a parameter: %s", param.Name}

								log.Printf("[DEBUG] No type specified for subflow node")

								if workflow.PreviouslySaved {
									resp.WriteHeader(401)
									resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Trigger %s is missing the parameter %s"}`, trigger.Label, param.Name)))
									return
								}
							}

							apikey = user.ApiKey
						}

						log.Printf("[INFO] Set apikey in subflow trigger for user during save")
						if len(apikey) > 0 {
							trigger.Parameters[index].Value = apikey
						}
					}
				*/
				//} else {

				//	workflow.IsValid = false
				//	workflow.Errors = []string{"Trigger is missing a parameter: %s", param.Name}

				//	log.Printf("[WARNING] No type specified for user input node")
				//	if workflow.PreviouslySaved {
				//		resp.WriteHeader(401)
				//		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Trigger %s is missing the parameter %s"}`, trigger.Label, param.Name)))
				//		return
				//	}
				//}
				//}
			}
		} else if trigger.TriggerType == "WEBHOOK" {
			if trigger.Status != "uninitialized" && trigger.Status != "stopped" {
				hook, err := GetHook(ctx, trigger.ID)
				if err != nil {
					log.Printf("[WARNING] Failed getting webhook %s (%s)", trigger.ID, trigger.Status)
					trigger.Status = "stopped"
				} else if hook.Id == "" {
					trigger.Status = "stopped"
				}
			}

			//log.Printf("WEBHOOK: %d", len(trigger.Parameters))
			if len(trigger.Parameters) < 2 {
				log.Printf("[WARNING] Issue with parameters in webhook %s - missing params", trigger.ID)
			} else {
				if !strings.Contains(trigger.Parameters[0].Value, trigger.ID) {
					log.Printf("[INFO] Fixing webhook URL for %s", trigger.ID)
					baseUrl := "https://shuffler.io"
					if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
						baseUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
					}

					if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
						baseUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
					}

					if project.Environment != "cloud" {
						baseUrl = "http://localhost:3001"
					}

					newTriggerName := fmt.Sprintf("webhook_%s", trigger.ID)
					trigger.Parameters[0].Value = fmt.Sprintf("%s/api/v1/hooks/%s", baseUrl, newTriggerName)
					trigger.Parameters[1].Value = newTriggerName
				}
			}
		} else if trigger.TriggerType == "USERINPUT" {
			// E.g. check email
			sms := ""
			email := ""
			subflow := ""
			triggerType := ""
			triggerInformation := ""
			for _, item := range trigger.Parameters {
				if item.Name == "alertinfo" {
					triggerInformation = item.Value
				} else if item.Name == "type" {
					triggerType = item.Value
				} else if item.Name == "email" {
					email = item.Value
				} else if item.Name == "sms" {
					sms = item.Value
				} else if item.Name == "subflow" {
					subflow = item.Value
				}
			}

			if len(triggerType) == 0 {
				log.Printf("[DEBUG] No type specified for user input node")
				if workflow.PreviouslySaved {
					resp.WriteHeader(401)
					resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "No contact option specified in user input"}`)))
					return
				}
			}

			// FIXME: This is not the right time to send them, BUT it's well served for testing. Save -> send email / sms
			_ = triggerInformation
			if strings.Contains(triggerType, "email") {
				if email == "test@test.com" {
					log.Printf("Email isn't specified during save.")
					if workflow.PreviouslySaved {
						resp.WriteHeader(401)
						resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Email field in user input can't be empty"}`)))
						return
					}
				}

				log.Printf("[DEBUG] Should send email to %s during execution.", email)
			}
			if strings.Contains(triggerType, "sms") {
				if sms == "0000000" {
					log.Printf("Email isn't specified during save.")
					if workflow.PreviouslySaved {
						resp.WriteHeader(401)
						resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "SMS field in user input can't be empty"}`)))
						return
					}
				}

				log.Printf("[DEBUG] Should send SMS to %s during execution.", sms)
			}

			if strings.Contains(triggerType, "subflow") {
				if len(subflow) != 36 {
					log.Printf("[WARNING] Subflow isn't specified!")
					if workflow.PreviouslySaved {
						resp.WriteHeader(401)
						resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Subflow in User Input Trigger isn't specified"}`)))
						return
					}
				}

				log.Printf("[DEBUG] Should run subflow with workflow %s during execution.", subflow)
			}
		}

		//log.Println("TRIGGERS")
		allNodes = append(allNodes, trigger.ID)
		newTriggers = append(newTriggers, trigger)
	}

	newComments := []Comment{}
	for _, comment := range workflow.Comments {
		if comment.Height < 50 {
			comment.Height = 150
		}

		if comment.Width < 50 {
			comment.Height = 150
		}

		if len(comment.BackgroundColor) == 0 {
			comment.BackgroundColor = "#1f2023"
		}

		if len(comment.Color) == 0 {
			comment.Color = "#ffffff"
		}

		comment.Position.X = float64(comment.Position.X)
		comment.Position.Y = float64(comment.Position.Y)

		newComments = append(newComments, comment)
	}

	workflow.Comments = newComments
	workflow.Triggers = newTriggers

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
	if len(workflow.Comments) == 0 {
		workflow.Comments = []Comment{}
	}

	//log.Printf("PRE VARIABLES")
	for _, variable := range workflow.WorkflowVariables {
		if len(variable.Value) == 0 {
			log.Printf("[WARNING] Variable %s is empty!", variable.Name)
			workflow.Errors = append(workflow.Errors, fmt.Sprintf("Variable %s is empty!", variable.Name))
			//resp.WriteHeader(401)
			//resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Variable %s can't be empty"}`, variable.Name)))
			//return
			//} else {
			//	log.Printf("VALUE OF VAR IS %s", variable.Value)
		}
	}

	if len(workflow.ExecutionVariables) > 0 {
		log.Printf("[INFO] Found %d execution variable(s) for workflow %s", len(workflow.ExecutionVariables), workflow.ID)
	}

	if len(workflow.WorkflowVariables) > 0 {
		log.Printf("[INFO] Found %d workflow variable(s) for workflow %s", len(workflow.WorkflowVariables), workflow.ID)
	}

	// Nodechecks
	foundNodes := []string{}
	for _, node := range allNodes {
		for _, branch := range workflow.Branches {
			//log.Println("branch")
			//log.Println(node)
			//log.Println(branch.DestinationID)
			if node == branch.DestinationID || node == branch.SourceID {
				foundNodes = append(foundNodes, node)
				break
			}
		}
	}

	// FIXME - append all nodes (actions, triggers etc) to one single array here
	//log.Printf("PRE VARIABLES")
	if len(foundNodes) != len(allNodes) || len(workflow.Actions) <= 0 {
		// This shit takes a few seconds lol
		if !workflow.IsValid {
			oldworkflow, err := GetWorkflow(ctx, fileId)
			if err != nil {
				log.Printf("[WARNING] Workflow %s doesn't exist - oldworkflow.", fileId)
				if workflow.PreviouslySaved {
					resp.WriteHeader(401)
					resp.Write([]byte(`{"success": false, "reason": "Item already exists."}`))
					return
				}
			}

			oldworkflow.IsValid = false
			err = SetWorkflow(ctx, *oldworkflow, fileId)
			if err != nil {
				log.Printf("[WARNING] Failed saving workflow to database: %s", err)
				if workflow.PreviouslySaved {
					resp.WriteHeader(401)
					resp.Write([]byte(`{"success": false}`))
					return
				}
			}

			cacheKey := fmt.Sprintf("%s_workflows", user.Id)
			DeleteCache(ctx, cacheKey)
		}
	}

	// FIXME - might be a sploit to run someone elses app if getAllWorkflowApps
	// doesn't check sharing=true
	// Have to do it like this to add the user's apps
	//log.Println("Apps set starting")
	//log.Printf("EXIT ON ERROR: %#v", workflow.Configuration.ExitOnError)

	// Started getting the single apps, but if it's weird, this is faster
	// 1. Check workflow.Start
	// 2. Check if any node has "isStartnode"
	//if len(workflow.Actions) > 0 {
	//	index := -1
	//	for indexFound, action := range workflow.Actions {
	//		//log.Println("Apps set done")
	//		if workflow.Start == action.ID {
	//			index = indexFound
	//		}
	//	}

	//	if index >= 0 {
	//		workflow.Actions[0].IsStartNode = true
	//	} else {
	//		log.Printf("[WARNING] Couldn't find startnode %s!", workflow.Start)
	//		if workflow.PreviouslySaved {
	//			resp.WriteHeader(401)
	//			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "You need to set a startnode."}`)))
	//			return
	//		}
	//	}
	//}

	/*
		allAuths, err := GetAllWorkflowAppAuth(ctx, user.ActiveOrg.Id)
		if userErr != nil {
			log.Printf("Api authentication failed in get all apps: %s", userErr)
			if workflow.PreviouslySaved {
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false}`))
				return
			}
		}
	*/

	// Check every app action and param to see whether they exist
	//log.Printf("PRE ACTIONS 2")
	allAuths, autherr := GetAllWorkflowAppAuth(ctx, user.ActiveOrg.Id)
	newActions = []Action{}
	for _, action := range workflow.Actions {
		reservedApps := []string{
			"0ca8887e-b4af-4e3e-887c-87e9d3bc3d3e",
		}

		//log.Printf("%s Action execution var: %s", action.Label, action.ExecutionVariable.Name)

		builtin := false
		for _, id := range reservedApps {
			if id == action.AppID {
				builtin = true
				break
			}
		}

		// Check auth
		// 1. Find the auth in question
		// 2. Update the node and workflow info in the auth
		// 3. Get the values in the auth and add them to the action values
		handleOauth := false
		if len(action.AuthenticationId) > 0 {
			//log.Printf("\n\nLen: %d", len(allAuths))
			authFound := false
			for _, auth := range allAuths {
				if auth.Id == action.AuthenticationId {
					authFound = true

					if strings.ToLower(auth.Type) == "oauth2" {
						handleOauth = true
					}

					// Updates the auth item itself IF necessary
					go UpdateAppAuth(ctx, auth, workflow.ID, action.ID, true)
					break
				}
			}

			if !authFound {
				log.Printf("[WARNING] App auth %s doesn't exist. Setting error", action.AuthenticationId)

				errorMsg := fmt.Sprintf("App authentication %s for app %s doesn't exist!", action.AuthenticationId, action.AppName)
				if !ArrayContains(workflow.Errors, errorMsg) {
					workflow.Errors = append(workflow.Errors, errorMsg)
				}
				workflow.IsValid = false

				action.Errors = append(action.Errors, "App authentication doesn't exist")
				action.IsValid = false
				action.AuthenticationId = ""
				//resp.WriteHeader(401)
				//resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "App auth %s doesn't exist"}`, action.AuthenticationId)))
				//return
			}
		}

		if builtin {
			newActions = append(newActions, action)
		} else {
			curapp := WorkflowApp{}

			// ID first, then name + version
			// If it can't find param, it will swap it over farther down
			for _, app := range workflowapps {
				if app.ID == action.AppID {
					curapp = app
					break
				}
			}

			if curapp.ID == "" {
				//log.Printf("[WARNING] Didn't find the App ID for %s", action.AppID)
				for _, app := range workflowapps {
					if app.ID == action.AppID {
						curapp = app
						break
					}

					// Has to NOT be generated
					if app.Name == action.AppName {
						if app.AppVersion == action.AppVersion {
							curapp = app
							break
						} else if ArrayContains(app.LoopVersions, action.AppVersion) {
							// Get the real app
							for _, item := range app.Versions {
								if item.Version == action.AppVersion {
									//log.Printf("Should get app %s - %s", item.Version, item.ID)

									tmpApp, err := GetApp(ctx, item.ID, user, false)
									if err != nil && tmpApp.ID == "" {
										log.Printf("[WARNING] Failed getting app %s (%s): %s", app.Name, item.ID, err)
									}

									curapp = *tmpApp
									break
								}
							}

							//curapp = app
							break
						}
					}
				}
			} else {
				//log.Printf("[DEBUG] Found correct App ID for %s", action.AppID)
			}

			//log.Printf("CURAPP: %#v:%s", curapp.Name, curapp.AppVersion)

			if curapp.Name != action.AppName {
				errorMsg := fmt.Sprintf("App %s:%s doesn't exist", action.AppName, action.AppVersion)
				action.Errors = append(action.Errors, "This app doesn't exist.")

				if !ArrayContains(workflow.Errors, errorMsg) {
					workflow.Errors = append(workflow.Errors, errorMsg)
					log.Printf("[WARNING] App %s:%s doesn't exist. Adding as error.", action.AppName, action.AppVersion)
				}

				action.IsValid = false
				workflow.IsValid = false

				// Append with errors
				newActions = append(newActions, action)
				//resp.WriteHeader(401)
				//resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "App %s doesn't exist"}`, action.AppName)))
				//return
			} else {
				// Check to see if the appaction is valid
				curappaction := WorkflowAppAction{}
				for _, curAction := range curapp.Actions {
					if action.Name == curAction.Name {
						curappaction = curAction
						break
					}
				}

				if curappaction.Name != action.Name {
					// FIXME: Check if another app with the same name has the action here
					// Then update the ID? May be related to updated apps etc.
					//log.Printf("Couldn't find action - checking similar apps")
					for _, app := range workflowapps {
						if app.ID == curapp.ID {
							continue
						}

						// Has to NOT be generated
						if app.Name == action.AppName && app.AppVersion == action.AppVersion {
							for _, curAction := range app.Actions {
								if action.Name == curAction.Name {
									log.Printf("[DEBUG] Found app %s (NOT %s) with the param: %s", app.ID, curapp.ID, curAction.Name)
									curappaction = curAction
									action.AppID = app.ID
									curapp = app
									break
								}
							}
						}

						if curappaction.Name == action.Name {
							break
						}
					}
				}

				// Check to see if the action is valid
				if curappaction.Name != action.Name {
					// FIXME: Find the actual active app?

					log.Printf("[ERROR] Action %s in app %s doesn't exist.", action.Name, curapp.Name)
					thisError := fmt.Sprintf("%s: Action %s in app %s doesn't exist", action.Label, action.Name, action.AppName)
					workflow.Errors = append(workflow.Errors, thisError)
					workflow.IsValid = false

					if !ArrayContains(action.Errors, thisError) {
						action.Errors = append(action.Errors, thisError)
					}

					action.IsValid = false
					//if workflow.PreviouslySaved {
					//	resp.WriteHeader(401)
					//	resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Action %s in app %s doesn't exist"}`, action.Name, curapp.Name)))
					//	return
					//}
				}

				// FIXME - check all parameters to see if they're valid
				// Includes checking required fields

				selectedAuth := AppAuthenticationStorage{}
				if len(action.AuthenticationId) > 0 && autherr == nil {
					for _, auth := range allAuths {
						if auth.Id == action.AuthenticationId {
							selectedAuth = auth
							break
						}
					}
				}

				newParams := []WorkflowAppActionParameter{}
				for _, param := range curappaction.Parameters {
					paramFound := false

					// Handles check for parameter exists + value not empty in used fields
					for _, actionParam := range action.Parameters {
						if actionParam.Name == param.Name {
							paramFound = true

							if actionParam.Value == "" && actionParam.Variant == "STATIC_VALUE" && actionParam.Required == true {
								// Validating if the field is an authentication field
								if len(selectedAuth.Id) > 0 {
									authFound := false
									for _, field := range selectedAuth.Fields {
										if field.Key == actionParam.Name {
											authFound = true
											//log.Printf("FOUND REQUIRED KEY %s IN AUTH", field.Key)
											break
										}
									}

									if authFound {
										newParams = append(newParams, actionParam)
										continue
									}
								}

								//log.Printf("[WARNING] Appaction %s with required param '%s' is empty. Can't save.", action.Name, param.Name)
								thisError := fmt.Sprintf("%s is missing required parameter %s", action.Label, param.Name)
								if handleOauth {
									//log.Printf("[WARNING] Handling oauth2 app saving, hence not throwing warnings (1)")
									//workflow.Errors = append(workflow.Errors, fmt.Sprintf("Debug: Handling one Oauth2 app (%s). May cause issues during initial configuration (1)", action.Name))
								} else {
									action.Errors = append(action.Errors, thisError)
									workflow.Errors = append(workflow.Errors, thisError)
									action.IsValid = false
								}
							}

							if actionParam.Variant == "" {
								actionParam.Variant = "STATIC_VALUE"
							}

							newParams = append(newParams, actionParam)
							break
						}
					}

					// Handles check for required params
					if !paramFound && param.Required {
						if handleOauth {
							log.Printf("[WARNING] Handling oauth2 app saving, hence not throwing warnings (2)")
							//workflow.Errors = append(workflow.Errors, fmt.Sprintf("Debug: Handling one Oauth2 app (%s). May cause issues during initial configuration (2)", action.Name))
						} else {
							thisError := fmt.Sprintf("Parameter %s is required", param.Name)
							action.Errors = append(action.Errors, thisError)

							workflow.Errors = append(workflow.Errors, thisError)
							action.IsValid = false
						}

						//newActions = append(newActions, action)
						//resp.WriteHeader(401)
						//resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Appaction %s with required param '%s' is empty."}`, action.Name, param.Name)))
						//return
					}

				}

				action.Parameters = newParams
				newActions = append(newActions, action)
			}
		}
	}

	if !workflow.PreviouslySaved {
		log.Printf("[WORKFLOW INIT] NOT PREVIOUSLY SAVED - SET ACTION AUTH!")

		if autherr == nil && len(workflowapps) > 0 && apperr == nil {
			//log.Printf("Setting actions")
			actionFixing := []Action{}
			appsAdded := []string{}
			for _, action := range newActions {
				setAuthentication := false
				if len(action.AuthenticationId) > 0 {
					//found := false
					authenticationFound := false
					for _, auth := range allAuths {
						if auth.Id == action.AuthenticationId {
							authenticationFound = true
							break
						}
					}

					if !authenticationFound {
						setAuthentication = true
					}
				} else {
					// FIXME: 1. Validate if the app needs auth
					// 1. Validate if auth for the app exists
					// var appAuth AppAuthenticationStorage
					setAuthentication = true

					//App           WorkflowApp           `json:"app" datastore:"app,noindex"`
				}

				if setAuthentication {
					authSet := false
					for _, auth := range allAuths {
						if !auth.Active {
							continue
						}

						if !auth.Defined {
							continue
						}

						if auth.App.Name == action.AppName {
							//log.Printf("FOUND AUTH FOR APP %s: %s", auth.App.Name, auth.Id)
							action.AuthenticationId = auth.Id
							authSet = true
							break
						}
					}

					// FIXME: Only o this IF there isn't another one for the app already
					if !authSet {
						//log.Printf("Validate if the app NEEDS auth or not")
						outerapp := WorkflowApp{}
						for _, app := range workflowapps {
							if app.Name == action.AppName {
								outerapp = app
								break
							}
						}

						if len(outerapp.ID) > 0 && outerapp.Authentication.Required {
							found := false
							for _, auth := range allAuths {
								if auth.App.ID == outerapp.ID {
									found = true
									break
								}
							}

							for _, added := range appsAdded {
								if outerapp.ID == added {
									found = true
								}
							}

							// FIXME: Add app auth
							if !found {
								timeNow := int64(time.Now().Unix())
								authFields := []AuthenticationStore{}
								for _, param := range outerapp.Authentication.Parameters {
									authFields = append(authFields, AuthenticationStore{
										Key:   param.Name,
										Value: "",
									})
								}

								appAuth := AppAuthenticationStorage{
									Active:        true,
									Label:         fmt.Sprintf("default_%s", outerapp.Name),
									Id:            uuid.NewV4().String(),
									App:           outerapp,
									Fields:        authFields,
									Usage:         []AuthenticationUsage{},
									WorkflowCount: 0,
									NodeCount:     0,
									OrgId:         user.ActiveOrg.Id,
									Created:       timeNow,
									Edited:        timeNow,
								}

								err = SetWorkflowAppAuthDatastore(ctx, appAuth, appAuth.Id)
								if err != nil {
									log.Printf("Failed setting appauth for with name %s", appAuth.Label)
								} else {
									appsAdded = append(appsAdded, outerapp.ID)
								}
							}

							action.Errors = append(action.Errors, "Requires authentication")
							action.IsValid = false
							workflow.IsValid = false
						}
					}
				}

				actionFixing = append(actionFixing, action)
			}

			newActions = actionFixing
		} else {
			log.Printf("FirstSave error: %s - %s", err, apperr)
			//allAuths, err := GetAllWorkflowAppAuth(ctx, user.ActiveOrg.Id)
		}

		skipSave, skipSaveOk := request.URL.Query()["skip_save"]
		if skipSaveOk && len(skipSave) > 0 {
			//log.Printf("INSIDE SKIPSAVE: %s", skipSave[0])
			if strings.ToLower(skipSave[0]) != "true" {
				workflow.PreviouslySaved = true
			}
		} else {
			workflow.PreviouslySaved = true
		}
	}
	//log.Printf("SAVED: %#v", workflow.PreviouslySaved)

	workflow.Actions = newActions
	workflow.IsValid = true

	// TBD: Is this too drastic? May lead to issues in the future.
	if workflow.OrgId != user.ActiveOrg.Id {
		log.Printf("[WARNING] Editing workflow to be owned by org %s", user.ActiveOrg.Id)
		workflow.OrgId = user.ActiveOrg.Id
		workflow.ExecutingOrg = user.ActiveOrg
		workflow.Org = append(workflow.Org, user.ActiveOrg)
	}

	// Only happens if the workflow is public and being edited
	if correctUser {
		workflow.Public = true

		// Should save it in Algolia too?
		_, err = handleAlgoliaWorkflowUpdate(ctx, workflow)
		if err != nil {
			log.Printf("[ERROR] Failed finding publicly changed workflow %s for user %s (%s): %s", workflow.ID, user.Username, user.Id, err)
		} else {
			log.Printf("[DEBUG] User %s (%s) updated their public workflow %s (%s)", user.Username, user.Id, workflow.Name, workflow.ID)
		}
	}

	err = SetWorkflow(ctx, workflow, fileId)
	if err != nil {
		log.Printf("[WARNING] Failed saving workflow to database: %s", err)
		if workflow.PreviouslySaved {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	if org.Id == "" {
		org, err = GetOrg(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("[WARNING] Failed getting org during wf save of %s (org: %s): %s", workflow.ID, user.ActiveOrg.Id, err)
		}
	}

	// This may cause some issues with random slow loads with cross & suborgs, but that's fine (for now)
	// FIX: Should only happen for users with this org as the active one
	// Org-based workflows may also work
	if org.Id != "" {
		for _, loopUser := range org.Users {
			DeleteCache(ctx, fmt.Sprintf("%s_workflows", loopUser.Id))
		}
	}

	if orgUpdated {
		err = SetOrg(ctx, *org, org.Id)
		if err != nil {
			log.Printf("[WARNING] Failed setting org when autoadding apps and updating framework on save workflow save (%s): %s", workflow.ID, err)
		} else {
			log.Printf("[DEBUG] Successfully updated org %s during save of %s for user %s (%s", user.ActiveOrg.Id, workflow.ID, user.Username, user.Id)
		}
	}

	//totalOldActions := len(tmpworkflow.Actions)
	//totalNewActions := len(workflow.Actions)
	//err = increaseStatisticsField(ctx, "total_workflow_actions", workflow.ID, int64(totalNewActions-totalOldActions), workflow.OrgId)
	//if err != nil {
	//	log.Printf("Failed to change total actions data: %s", err)
	//}

	type returnData struct {
		Success bool     `json:"success"`
		Errors  []string `json:"errors"`
	}

	returndata := returnData{
		Success: true,
		Errors:  workflow.Errors,
	}

	// Really don't know why this was happening
	//cacheKey := fmt.Sprintf("workflowapps-sorted-100")
	//requestCache.Delete(cacheKey)
	//cacheKey = fmt.Sprintf("workflowapps-sorted-500")
	//requestCache.Delete(cacheKey)

	log.Printf("[INFO] Saved new version of workflow %s (%s) for org %s. Actions: %d, Triggers: %d", workflow.Name, fileId, workflow.OrgId, len(workflow.Actions), len(workflow.Triggers))
	resp.WriteHeader(200)
	newBody, err := json.Marshal(returndata)
	if err != nil {
		resp.Write([]byte(`{"success": true}`))
		return
	}

	resp.Write(newBody)
}


func GetSpecificWorkflow(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Removed check here as it may be a public workflow
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in getting specific workflow: %s. Continuing because it may be public.", err)
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
		resp.Write([]byte(`{"success": false, "reason": "Failed finding workflow"}`))
		return
	}

	//log.Printf("\n\nGetting workflow %s. Data: %#v\nPublic: %#v\n", fileId, workflow, workflow.Public)

	// CHECK orgs of user, or if user is owner
	// FIXME - add org check too, and not just owner
	// Check workflow.Sharing == private / public / org  too
	if user.Id != workflow.Owner || len(user.Id) == 0 {
		// Added org-reader as the user should be able to read everything in an org
		//if workflow.OrgId == user.ActiveOrg.Id && (user.Role == "admin" || user.Role == "org-reader") {
		if workflow.OrgId == user.ActiveOrg.Id {
			log.Printf("[AUDIT] User %s is accessing workflow %s as admin (get workflow)", user.Username, workflow.ID)
		} else if workflow.Public {
			log.Printf("[AUDIT] Letting user %s access workflow %s because it's public", user.Username, workflow.ID)

			// Only for Read-Only. No executions or impersonations.
		} else if project.Environment == "cloud" && user.Verified == true && user.Active == true && user.SupportAccess == true && strings.HasSuffix(user.Username, "@shuffler.io") {
			log.Printf("[AUDIT] Letting verified support admin %s access workflow %s", user.Username, workflow.ID)
		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (get workflow). Verified: %#v, Active: %#v, SupportAccess: %#v, Username: %#v", user.Username, workflow.ID, user.Verified, user.Active, user.SupportAccess, user.Username)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

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

	for key, _ := range workflow.Actions {
		workflow.Actions[key].ReferenceUrl = ""
	}

	body, err := json.Marshal(workflow)
	if err != nil {
		log.Printf("Failed workflow GET marshalling: %s", err)
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(body)
}


func SanitizeWorkflow(workflow Workflow) Workflow {
	log.Printf("[INFO] Sanitizing workflow %s", workflow.ID)

	for _, trigger := range workflow.Triggers {
		_ = trigger
	}

	for _, action := range workflow.Actions {
		_ = action
	}

	for _, variable := range workflow.WorkflowVariables {
		_ = variable
	}

	workflow.Owner = ""
	workflow.Org = []OrgMini{}
	workflow.OrgId = ""
	workflow.ExecutingOrg = OrgMini{}
	workflow.PreviouslySaved = false

	// Add Gitguardian or similar secrets discovery
	return workflow
}
