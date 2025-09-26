package shuffle

/*
This file is for blobs that we use throughout Shuffle in many locations. If we want to optimise Shuffle, we need to use structured data stored somewhere, but just creating blobs is a quick way to get a lot of things up and running until it needs proper fixing
*/

import (
	"os"
	"errors"
	"strings"
	"context"
	"fmt"
	"log"
	"encoding/json"

	uuid "github.com/satori/go.uuid"
)


// These are just specific examples for specific cases
// FIXME: Should these be loaded from public workflows?
// I kind of think so ~
// That means each algorithm needs to be written as if-statements to
// replace a specific part of a workflow :thinking:

// Should workflows be written as YAML and be text-editable? 
func GetDefaultWorkflowByType(workflow Workflow, orgId string, categoryAction CategoryAction) (Workflow, error) {
	actionType := categoryAction.Label  
	appNames := categoryAction.AppName

	if len(orgId) == 0 {
		return workflow, errors.New("Organization ID is empty. Can't generate workflow.")
	}

	parsedActiontype := strings.ReplaceAll(strings.ToLower(actionType), " ", "_")
	if strings.Contains(strings.ToLower(actionType), "threat feed") {
		parsedActiontype = "threatlist_monitor"
	}

	// If-else with specific rules per workflow
	// Make sure it uses workflow -> copies data, as 
	startActionId := uuid.NewV4().String()
	startTriggerId := workflow.ID
	if len(startTriggerId) == 0 {
		startTriggerId = uuid.NewV4().String()
	}

	actionEnv := "Cloud"
	triggerEnv := "Cloud"
	ctx := context.Background()
	if project.Environment != "cloud" {
		triggerEnv = "onprem"

		envs, err := GetEnvironments(ctx, orgId)
		if err == nil { 
			for _, env := range envs {
				if env.Default {
					actionEnv = env.Name
					break
				}
			}
		} else { 
			actionEnv = "Shuffle"
		}
	}

	if parsedActiontype == "correlate_categories" {
		defaultWorkflow := Workflow{
			Name: actionType,
			Description: "Correlates Datastore categories in Shuffle. The point is to graph data",
			OrgId: orgId,
			Start: startActionId,
			Actions: []Action{
				Action{
					ID: startActionId,
					Name: "repeat_back_to_me",
					AppName: "Shuffle Tools",
					AppVersion: "1.2.0",
					Environment: actionEnv,
					Label: "Start",
					IsStartNode: true, 
					Position: Position{
						X: 250,
						Y: 0,
					},
					Parameters: []WorkflowAppActionParameter{
						WorkflowAppActionParameter{
							Name:  "call",
							Value: "Some code here hello",
							Multiline: true,
						},
					},
				},
			},
		}

		workflow = defaultWorkflow
		workflow.OrgId = orgId

	} else if parsedActiontype == "ingest_tickets" || parsedActiontype == "ingest_assets" || parsedActiontype == "ingest_users" {
		actionName := "Cases"
		currentAction := WorkflowAppActionParameter{
			Name:  "action",
			Value: "List tickets",
			Options: []string{
				"List tickets",
				"Create ticket",
				"Close ticket",
				"Add comment",
			},
		}

		if parsedActiontype == "ingest_assets" {
			actionName = "Assets"
			currentAction.Value = "List assets"
			currentAction.Options = []string{
				"List assets",
				"Get asset",
				"Search assets",
				"Create asset",
			}
		} else if parsedActiontype == "ingest_users" {
			actionName = "IAM"
			currentAction.Value = "List users"
			currentAction.Options = []string{
				"List users",
				"Get users",
				"Search users",
				"Create user",
			}
		}

		defaultWorkflow := Workflow{
			Name: actionType,
			Description: "List tickets from different systems and ingest them",
			OrgId: orgId,
			Start: startActionId,
			Actions: []Action{
				Action{
					Name: actionName,
					AppID: "integration",
					AppName: "Singul",
					ID: startActionId,
					AppVersion: "1.0.0",
					Environment: actionEnv,
					Label: currentAction.Value,
					Parameters: []WorkflowAppActionParameter{
						WorkflowAppActionParameter{
							Name:  "app_name",
							Value: "",
						},
						currentAction,
						WorkflowAppActionParameter{
							Name:  "fields",
							Value: "",
							Multiline: true,
						},
					},
				},
			},
			Triggers: []Trigger{
				Trigger{
					ID: startTriggerId,
					Name: "Schedule",
					TriggerType: "SCHEDULE",
					Label: "Ingest tickets",
					Environment: triggerEnv,
					Parameters: []WorkflowAppActionParameter{
						WorkflowAppActionParameter{
							Name:  "cron",
							Value: "0 0 * * *", 
						},
						WorkflowAppActionParameter{
							Name:  "execution_argument",
							Value: "Automatically configured by Shuffle", 
						},
					},
				},
			},
		}

		workflow = defaultWorkflow
		workflow.OrgId = orgId
	} else if parsedActiontype == "ingest_tickets_webhook" {

		defaultWorkflow := Workflow{
			Name: actionType,
			Description: "Ingest tickets through a webhook",
			OrgId: orgId,
			Start: startActionId,
			Actions: []Action{
				Action{
					Name: "Translate standard",
					AppID: "integration",
					AppName: "Singul",
					ID: startActionId,
					AppVersion: "1.0.0",
					Environment: actionEnv,
					Label: "Ingest Ticket from Webhook",
					Parameters: []WorkflowAppActionParameter{
						WorkflowAppActionParameter{
							Name:  "source_data",
							Value: "$exec",
							Multiline: true,
						},
						WorkflowAppActionParameter{
							Name:  "standard",
							Description: "The standard to use from https://github.com/Shuffle/standards/tree/main",
							Value: "OCSF",
							Multiline: false,
						},
					},
				},
			},
			Triggers: []Trigger{
				Trigger{
					ID: startTriggerId,
					Name: "Webhook",
					TriggerType: "WEBHOOK",
					Label: "Ingest",
					Environment: triggerEnv,
					Parameters: []WorkflowAppActionParameter{
						WorkflowAppActionParameter{
							Name:  "url",
							Value: "",
						},
						WorkflowAppActionParameter{
							Name:  "tmp",
							Value: "", 
						},
						WorkflowAppActionParameter{
							Name:  "auth_header",
							Value: "", 
						},
						WorkflowAppActionParameter{
							Name:  "custom_response_body",
							Value: "", 
						},
						WorkflowAppActionParameter{
							Name:  "await_response",
							Value: "", 
						},
					},
				},
			},
		}

		workflow = defaultWorkflow
		workflow.OrgId = orgId
	} else if parsedActiontype == "threatlist_monitor" {
		secondActionId := uuid.NewV4().String()

		defaultWorkflow := Workflow{
			Name: actionType,
			Description: "Monitor threatlists and ingest regularly",
			OrgId: orgId,
			Start: startActionId,
			Actions: []Action{
				Action{
					Name: "GET",
					AppID: "HTTP",
					AppName: "HTTP",
					ID: startActionId,
					AppVersion: "1.4.0",
					Environment: actionEnv,
					Label: "Get threatlist URLs",
					Parameters: []WorkflowAppActionParameter{
						WorkflowAppActionParameter{
							Name:  "url",
							Value: "$shuffle_cache.threatlist_urls.value.#",
						},
						WorkflowAppActionParameter{
							Name:  "headers",
							Multiline: true,
							Value: "",
						},
					},
				},
				Action{
					Name: "execute_python",
					AppID: "Shuffle Tools",
					AppName: "Shuffle Tools",
					ID: secondActionId,
					AppVersion: "1.2.0",
					Environment: actionEnv,
					Label: "Ingest IOCs",
					Parameters: []WorkflowAppActionParameter{
						WorkflowAppActionParameter{
							Name:  "code",
							Multiline: true,
							Required: true,
							Value: getIocIngestionScript(),
						},
					},
				},
			},
			Triggers: []Trigger{
				Trigger{
					ID: startTriggerId,
					Name: "Schedule",
					TriggerType: "SCHEDULE",
					Label: "Pull threatlist URLs",
					Environment: triggerEnv,
					Parameters: []WorkflowAppActionParameter{
						WorkflowAppActionParameter{
							Name:  "cron",
							Value: "0 0 * * *", 
						},
						WorkflowAppActionParameter{
							Name:  "execution_argument",
							Value: "Automatically configured by Shuffle", 
						},
					},
				},
			},
			Branches: []Branch{
				Branch{
					SourceID: startTriggerId,
					DestinationID: startActionId,
					ID: uuid.NewV4().String(),
				},
				Branch{
					SourceID: startActionId,
					DestinationID: secondActionId,
					ID: uuid.NewV4().String(),
					Conditions: []Condition{
						Condition{
							Source: WorkflowAppActionParameter{
								Name: "source",
								Value: "{{ $get_threatlist_urls | size }}",
							},
							Condition: WorkflowAppActionParameter{
								Name: "condition",
								Value: "larger than",
							},
							Destination: WorkflowAppActionParameter{
								Name: "destination",
								Value: "0",
							},
						},
					},
				},
			},
		}

		// For now while testing
		workflow = defaultWorkflow
		workflow.OrgId = orgId

		/*
		if len(workflow.WorkflowVariables) == 0 {
			workflow.WorkflowVariables = defaultWorkflow.WorkflowVariables
		}

		if len(workflow.Actions) == 0 {
			workflow.Actions = defaultWorkflow.Actions
		}

		// Rules specific to this one
		if len(workflow.Triggers) == 0 {
			workflow.Triggers = defaultWorkflow.Triggers
		}
		*/

		// Get the item with key "threatlist_urls" from datastore
		ctx := GetContext(nil)
		_, err := GetDatastoreKey(ctx, "threatlist_urls", "")
		if err != nil {
			//log.Printf("[INFO] Failed to get threatlist URLs from datastore. Making it.: %s", err)
			urls := []string{
				"https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
			}

			jsonMarshalled, err := json.Marshal(urls)
			if err != nil {
				log.Printf("[ERROR] Failed to marshal threatlist URLs: %s", err)
			} else {
				key := CacheKeyData{
					Key: "threatlist_urls",
					Value: fmt.Sprintf(`%s`, string(jsonMarshalled)),
					OrgId: orgId,
				}

				err = SetDatastoreKey(ctx, key)
				if err != nil {
					log.Printf("[ERROR] Failed to set threatlist URLs in datastore: %s", err)
				} else {
					log.Printf("[INFO] Successfully set threatlist URLs in datastore")
				}
			}
		}
	}

	if len(workflow.Name) == 0 || len(workflow.Actions) == 0 {
		return workflow, errors.New("Workflow name or ID is empty")
	}

	// Appends actions in the workflow 
	positionAddition := float64(250)
	if len(workflow.Actions) == 1 && (workflow.Actions[0].AppName == "Singul" || workflow.Actions[0].AppID == "integration") && len(appNames) > 0 && len(workflow.Triggers) == 1 && workflow.Triggers[0].TriggerType == "SCHEDULE" {

		actionTemplate := workflow.Actions[0]

		// Pre-defining it with a startnode that does nothing
		workflow.Actions = []Action{
			Action{
				ID: startActionId,
				Name: "repeat_back_to_me",
				AppName: "Shuffle Tools",
				AppVersion: "1.2.0",
				Environment: actionEnv,
				Label: "Start",
				IsStartNode: true, 
				Position: Position{
					X: 250,
					Y: 0,
				},
				Parameters: []WorkflowAppActionParameter{
					WorkflowAppActionParameter{
						Name:  "call",
						Value: "",
						Multiline: true,
					},
				},
			},
		}

		// Point from trigger(s) to startnode (repeater)
		for _, trigger := range workflow.Triggers { 
			newBranch := Branch{
				SourceID: trigger.ID,
				DestinationID: workflow.Start,
				ID: uuid.NewV4().String(),
			}

			workflow.Branches = append(workflow.Branches, newBranch)
		}

		for appIndex, appName := range strings.Split(appNames, ",") {
			newAction := actionTemplate
			newAction.ID = uuid.NewV4().String()
			newAction.Parameters = append([]WorkflowAppActionParameter(nil), actionTemplate.Parameters...)

			// Positioning
			newAction.Position.X = positionAddition*float64(appIndex)
			newAction.Position.Y = positionAddition


			// Point from startnode to current one
			newBranch := Branch{
				SourceID: workflow.Start,
				DestinationID: newAction.ID,
				ID: uuid.NewV4().String(),
			}

			workflow.Branches = append(workflow.Branches, newBranch)

			appNameIndex := -1
			for paramIndex, param := range actionTemplate.Parameters {
				if param.Name == "app_name" || param.Name == "appName" {
					appNameIndex = paramIndex
					break
				}
			}

			newAction.Label += " " + appName
			if appNameIndex >= 0 {
				newAction.Parameters[appNameIndex].Value = appName
			} else {
				newAction.Parameters = append(newAction.Parameters, WorkflowAppActionParameter{
					Name:  "app_name",
					Value: appName,
				})

				appNameIndex = len(newAction.Parameters) - 1
			}

			workflow.Actions = append(workflow.Actions, newAction)
		}
	}

	if workflow.Actions[0].Position.X == 0 && workflow.Actions[0].Position.Y == 0 {
		startXPosition := float64(0)
		startYPosition := float64(0)
		for triggerIndex, _ := range workflow.Triggers {
			workflow.Triggers[triggerIndex].Position = Position{
				X: startXPosition,
				Y: startYPosition,
			}

			startXPosition += positionAddition 
		}

		for actionIndex, _ := range workflow.Actions {
			workflow.Actions[actionIndex].Position = Position{
				X: startXPosition,
				Y: startYPosition, 
			}

			startXPosition += positionAddition 
		}
	}

	if len(workflow.Actions) > 0 {
		for _, action := range workflow.Actions {
			if action.AppID == "integration" || action.AppName == "Singul" {

				for _, param := range action.Parameters {
					if (param.Name == "app_name" || param.Name == "appName") && len(param.Value) == 0 {
						log.Printf("[DEBUG] Should verify if an app of type '%s' exists", action.Name)
					}
				}
			}
		}
	}

	if len(workflow.Actions)+len(workflow.Triggers) > 1 {
		if len(workflow.Branches) == 0 {
			// Connect from trigger -> action

			sourceId := ""
			destId := ""
			if len(workflow.Triggers) == 1 {
				sourceId = workflow.Triggers[0].ID
				destId = workflow.Start
			}

			newBranch := Branch{
				SourceID: sourceId,
				DestinationID: destId,
				ID: uuid.NewV4().String(),
			}

			workflow.Branches = append(workflow.Branches, newBranch)
		}
	}

	// Check if the action has branches at all
	// This is not efficientm but ensures they all at least run
	for actionIndex, action := range workflow.Actions {
		if actionIndex == 0 {
			continue
		}

		found := false
		for _, branch := range workflow.Branches {
			if branch.SourceID == action.ID || branch.DestinationID == action.ID {
				found = true
				break
			}
		}

		if !found {
			log.Printf("Missing branch: %s", action.ID)
			// Create a branch from the previous action to this one
			workflow.Branches = append(workflow.Branches, Branch{
				SourceID: workflow.Actions[actionIndex-1].ID,
				DestinationID: action.ID,
				ID: uuid.NewV4().String(),
			})
		}
	}

	// API-available, but not UI visible by default
	//workflow.Hidden = true

	return workflow, nil
}

func GetPublicDetections() []DetectionResponse {
	return []DetectionResponse{
		DetectionResponse{
			Title:             "Sigma SIEM Detections",
			DetectionName:     "Sigma",
			Category:          "SIEM",
			DetectionInfo:     []DetectionFileInfo{},
			FolderDisabled:    false,
			IsConnectorActive: false,
			DownloadRepo:      "https://github.com/shuffle/security-rules",
		},
		DetectionResponse{
			Title:             "Sublime Email Detection",
			DetectionName:     "Sublime",
			Category:          "Email",
			DetectionInfo:     []DetectionFileInfo{},
			FolderDisabled:    false,
			IsConnectorActive: false,
			DownloadRepo:      "https://github.com/shuffle/security-rules",
		},
		DetectionResponse{
			Title:             "File Detection",
			DetectionName:     "Yara",
			Category:          "Files",
			DetectionInfo:     []DetectionFileInfo{},
			FolderDisabled:    false,
			IsConnectorActive: false,
			DownloadRepo:      "https://github.com/shuffle/security-rules",
		},
	}
}

func GetBaseDockerfile() []byte {
	return []byte(`FROM frikky/shuffle:app_sdk as base

# We're going to stage away all of the bloat from the build tools so lets create a builder stage
FROM base as builder

# Install all alpine build tools needed for our pip installs
RUN apk --no-cache add --update alpine-sdk libffi libffi-dev musl-dev openssl-dev git

# Install all of our pip packages in a single directory that we can copy to our base image later
RUN mkdir /install
WORKDIR /install
COPY requirements.txt /requirements.txt
RUN pip install --no-cache-dir --upgrade --prefix="/install" -r /requirements.txt

# Switch back to our base image and copy in all of our built packages and source code
FROM base
COPY --from=builder /install /usr/local
COPY src /app

# Install any binary dependencies needed in our final image
# RUN apk --no-cache add --update my_binary_dependency
RUN apk --no-cache add jq git curl

# Finally, lets run our app!
WORKDIR /app
CMD ["python", "app.py", "--log-level", "DEBUG"]`)
}

// For now, just keeping it as a blob.
func GetAppCategories() []AppCategory {
	return []AppCategory{
		AppCategory{
			Name:         "Communication",
			Color:        "#FFC107",
			Icon:         "communication",
			ActionLabels: []string{"List Messages", "Send Message", "Get Message", "Search messages", "List Attachments", "Get Attachment", "Get Contact"},
		},
		AppCategory{
			Name:         "SIEM",
			Color:        "#FFC107",
			Icon:         "siem",
			ActionLabels: []string{"Search", "List Alerts", "Close Alert", "Get Alert", "Create detection", "Add to lookup list", "Isolate endpoint"},
		},
		AppCategory{
			Name:         "Eradication",
			Color:        "#FFC107",
			Icon:         "eradication",
			ActionLabels: []string{"List Alerts", "Close Alert", "Get Alert", "Create detection", "Block hash", "Search Hosts", "Isolate host", "Unisolate host", "Trigger host scan"},
		},
		AppCategory{
			Name:         "Cases",
			Color:        "#FFC107",
			Icon:         "cases",
			ActionLabels: []string{"List tickets", "Get ticket", "Create ticket", "Close ticket", "Add comment", "Update ticket", "Search tickets"},
		},
		AppCategory{
			Name:         "Assets",
			Color:        "#FFC107",
			Icon:         "assets",
			ActionLabels: []string{"List Assets", "Get Asset", "Search Assets", "Search Users", "Search endpoints", "Search vulnerabilities"},
		},
		AppCategory{
			Name:         "Intel",
			Color:        "#FFC107",
			Icon:         "intel",
			ActionLabels: []string{"Get IOC", "Search IOC", "Create IOC", "Update IOC", "Delete IOC"},
		},
		AppCategory{
			Name:         "IAM",
			Color:        "#FFC107",
			Icon:         "iam",
			ActionLabels: []string{"Reset Password", "Enable user", "Disable user", "Get Identity", "Get Asset", "Search Identity", "Get KMS Key"},
		},
		AppCategory{
			Name:         "Network",
			Color:        "#FFC107",
			Icon:         "network",
			ActionLabels: []string{"Get Rules", "Allow IP", "Block IP"},
		},
		AppCategory{
			Name:         "AI",
			Color:        "#FFC107",
			Icon:         "AI",
			ActionLabels: []string{"Answer Question", "Run Action", "Run LLM"},
		},
		AppCategory{
			Name:         "Other",
			Color:        "#FFC107",
			Icon:         "other",
			ActionLabels: []string{"Update Info", "Get Info", "Get Status", "Get Version", "Get Health", "Get Config", "Get Configs", "Get Configs by type", "Get Configs by name", "Run script"},
		},
	}
}

// FIXME: why are there two?
func GetAllAppCategories() []AppCategory {
	if os.Getenv("STANDALONE") == "true" {
		standalone = true
	}

	categories := []AppCategory{
		AppCategory{
			Name:         "Cases",
			Color:        "",
			Icon:         "cases",
			ActionLabels: []string{"Create ticket", "List tickets", "Get ticket", "Create ticket", "Close ticket", "Add comment", "Update ticket"},
			RequiredFields: map[string][]string{
				"Create ticket": []string{"title"},
				"Add comment":   []string{"comment"},
				"Lis tickets":   []string{"time_range"},
			},
			OptionalFields: map[string][]string{
				"Create ticket": []string{"description"},
			},
		},
		AppCategory{
			Name:           "Communication",
			Color:          "",
			Icon:           "communication",
			ActionLabels:   []string{"List Messages", "Send Message", "Get Message", "Search messages"},
			RequiredFields: map[string][]string{},
			OptionalFields: map[string][]string{},
		},
		AppCategory{
			Name:           "SIEM",
			Color:          "",
			Icon:           "siem",
			ActionLabels:   []string{"Search", "List Alerts", "Close Alert", "Create detection", "Add to lookup list"},
			RequiredFields: map[string][]string{},
			OptionalFields: map[string][]string{},
		},
		AppCategory{
			Name:           "Eradication",
			Color:          "",
			Icon:           "eradication",
			ActionLabels:   []string{"List Alerts", "Close Alert", "Create detection", "Block hash", "Search Hosts", "Isolate host", "Unisolate host"},
			RequiredFields: map[string][]string{},
			OptionalFields: map[string][]string{},
		},
		AppCategory{
			Name:           "Assets",
			Color:          "",
			Icon:           "assets",
			ActionLabels:   []string{"List Assets", "Get Asset", "Search Assets", "Search Users", "Search endpoints", "Search vulnerabilities"},
			RequiredFields: map[string][]string{},
			OptionalFields: map[string][]string{},
		},
		AppCategory{
			Name:           "Intel",
			Color:          "",
			Icon:           "intel",
			ActionLabels:   []string{"Get IOC", "Search IOC", "Create IOC", "Update IOC", "Delete IOC"},
			RequiredFields: map[string][]string{},
			OptionalFields: map[string][]string{},
		},
		AppCategory{
			Name:           "IAM",
			Color:          "",
			Icon:           "iam",
			ActionLabels:   []string{"Reset Password", "Enable user", "Disable user", "Get Identity", "Get Asset", "Search Identity"},
			RequiredFields: map[string][]string{},
			OptionalFields: map[string][]string{},
		},
		AppCategory{
			Name:           "Network",
			Color:          "",
			Icon:           "network",
			ActionLabels:   []string{"Get Rules", "Allow IP", "Block IP"},
			RequiredFields: map[string][]string{},
			OptionalFields: map[string][]string{},
		},
		AppCategory{
			Name:           "Other",
			Color:          "",
			Icon:           "other",
			ActionLabels:   []string{"Update Info", "Get Info", "Get Status", "Get Version", "Get Health", "Get Config", "Get Configs", "Get Configs by type", "Get Configs by name", "Run script"},
			RequiredFields: map[string][]string{},
			OptionalFields: map[string][]string{},
		},
	}

	return categories
}

func GetWorkflowTest() []byte {
	return []byte(`{"workflow_as_code":false,"actions":[{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Repeats the call parameter","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"969da5d9-4f3c-4ae0-989d-810fbae8b329","is_valid":true,"isStartNode":true,"sharing":true,"label":"Repeat_back_to_me","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M19%208l-4%204h3c0%203.31-2.69%206-6%206-1.01%200-1.97-.25-2.8-.7l-1.46%201.46C8.97%2019.54%2010.43%2020%2012%2020c4.42%200%208-3.58%208-8h3l-4-4zM6%2012c0-3.31%202.69-6%206-6%201.01%200%201.97.25%202.8.7l1.46-1.46C15.03%204.46%2013.57%204%2012%204c-4.42%200-8%203.58-8%208H1l4%204%204-4H6z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"repeat_back_to_me","parameters":[{"description":"The message to repeat","id":"","name":"call","example":"REPEATING: Hello world","value":"[{\"hello\": \"what\"}]","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":194.776307170967,"y":360.99437618423},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Repeats the call parameter","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","is_valid":true,"sharing":true,"label":"Router","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M19%208l-4%204h3c0%203.31-2.69%206-6%206-1.01%200-1.97-.25-2.8-.7l-1.46%201.46C8.97%2019.54%2010.43%2020%2012%2020c4.42%200%208-3.58%208-8h3l-4-4zM6%2012c0-3.31%202.69-6%206-6%201.01%200%201.97.25%202.8.7l1.46-1.46C15.03%204.46%2013.57%204%2012%204c-4.42%200-8%203.58-8%208H1l4%204%204-4H6z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"repeat_back_to_me","parameters":[{"description":"The message to repeat","id":"","name":"call","example":"REPEATING: Hello world","value":"","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":1498.36437395801,"y":348.852912467049},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Checks Shuffle cache whether a user-provided key contains a value. Returns ALL the values previously appended.","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"3369c754-f535-4f49-93cf-dbe5af77bde4","is_valid":true,"sharing":true,"label":"Check_cache","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M15.5%2014h-.79l-.28-.27C15.41%2012.59%2016%2011.11%2016%209.5%2016%205.91%2013.09%203%209.5%203S3%205.91%203%209.5%205.91%2016%209.5%2016c1.61%200%203.09-.59%204.23-1.57l.27.28v.79l5%204.99L20.49%2019l-4.99-5zm-6%200C7.01%2014%205%2011.99%205%209.5S7.01%205%209.5%205%2014%207.01%2014%209.5%2011.99%2014%209.5%2014z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"check_cache_contains","parameters":[{"description":"The key to get","id":"","name":"key","example":"alert_ids","value":"cachekey","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The value to check for and append if applicable","id":"","name":"value","example":"1208301599081","value":"1234","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Whether to auto-append the value if it doesn't exist in the cache","id":"","name":"append","example":"timestamp","value":"true","multiline":false,"multiselect":false,"options":["true","false"],"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":473.731301690609,"y":493.192692855461},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Get a value saved to your organization in Shuffle","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"f63dd458-2ed4-49df-87b2-2c7b3ac99075","is_valid":true,"sharing":true,"label":"Get_cache","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M12%202C7.58%202%204%203.79%204%206C4%208.06%207.13%209.74%2011.15%209.96C12.45%208.7%2014.19%208%2016%208C16.8%208%2017.59%208.14%2018.34%208.41C19.37%207.74%2020%206.91%2020%206C20%203.79%2016.42%202%2012%202ZM4%208V11C4%2012.68%206.08%2014.11%209%2014.71C9.06%2013.7%209.32%2012.72%209.77%2011.82C6.44%2011.34%204%209.82%204%208ZM15.93%209.94C14.75%209.95%2013.53%2010.4%2012.46%2011.46C8.21%2015.71%2013.71%2022.5%2018.75%2019.17L23.29%2023.71L24.71%2022.29L20.17%2017.75C22.66%2013.97%2019.47%209.93%2015.93%209.94ZM15.9%2012C17.47%2011.95%2019%2013.16%2019%2015C19%2015.7956%2018.6839%2016.5587%2018.1213%2017.1213C17.5587%2017.6839%2016.7956%2018%2016%2018C13.33%2018%2012%2014.77%2013.88%2012.88C14.47%2012.29%2015.19%2012%2015.9%2012ZM4%2013V16C4%2018.05%207.09%2019.72%2011.06%2019.95C10.17%2019.07%209.54%2017.95%209.22%2016.74C6.18%2016.17%204%2014.72%204%2013Z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"get_cache_value","parameters":[{"description":"The key to get","id":"","name":"key","example":"timestamp","value":"cachekey","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":423.960345089251,"y":638.555806820559},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Set a value to be saved to your organization in Shuffle.","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"3d760e52-214b-4c6d-bfad-a043d11d700e","is_valid":true,"sharing":true,"label":"Set_cache","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M11%203C6.58%203%203%204.79%203%207C3%209.21%206.58%2011%2011%2011C15.42%2011%2019%209.21%2019%207C19%204.79%2015.42%203%2011%203ZM3%209V12C3%2014.21%206.58%2016%2011%2016C15.42%2016%2019%2014.21%2019%2012V9C19%2011.21%2015.42%2013%2011%2013C6.58%2013%203%2011.21%203%209ZM3%2014V17C3%2019.21%206.58%2021%2011%2021C12.41%2021%2013.79%2020.81%2015%2020.46V17.46C13.79%2017.81%2012.41%2018%2011%2018C6.58%2018%203%2016.21%203%2014ZM20%2014V17H17V19H20V22H22V19H25V17H22V14%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"set_cache_value","parameters":[{"description":"The key to set the value for","id":"","name":"key","example":"timestamp","value":"cachekey","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The value to set","id":"","name":"value","example":"1621959545","value":"what","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":353.068567601435,"y":742.248880347109},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Takes a list and filters based on your data","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"02f87429-a7d2-47ba-9fc4-08a7fce90662","is_valid":true,"sharing":true,"label":"Filter_list","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M4.25%205.61C6.27%208.2%2010%2013%2010%2013v6c0%20.55.45%201%201%201h2c.55%200%201-.45%201-1v-6s3.72-4.8%205.74-7.39c.51-.66.04-1.61-.79-1.61H5.04c-.83%200-1.3.95-.79%201.61z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"filter_list","parameters":[{"description":"The list to check","id":"","name":"input_list","example":"[{\"data\": \"1.2.3.4\"}, {\"data\": \"1.2.3.5\"}]","value":"[{\"test\": 1}, {\"test\": 2}]","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The field to check","id":"","name":"field","example":"data","value":"test","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Type of check","id":"","name":"check","example":"equals","value":"equals","multiline":false,"multiselect":false,"options":["equals","larger than","less than","is empty","contains","contains any of","starts with","ends with","field is unique","files by extension"],"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The value to check with","id":"","name":"value","example":"1.2.3.4","value":"1","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Whether to add or to NOT add","id":"","name":"opposite","example":"false","value":"false","multiline":false,"multiselect":false,"options":["false","true"],"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":1703.87481902106,"y":927.320007155152},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Parse IOC's based on https://github.com/fhightower/ioc-finder","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"a902d3ba-8732-4229-8c0d-fbe744a330a4","is_valid":true,"sharing":true,"label":"Parse_indicators","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M10%203H5c-1.1%200-2%20.9-2%202v14c0%201.1.9%202%202%202h5v2h2V1h-2v2zm0%2015H5l5-6v6zm9-15h-5v2h5v13l-5-6v9h5c1.1%200%202-.9%202-2V5c0-1.1-.9-2-2-2z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"parse_ioc","parameters":[{"description":"The string to check","id":"","name":"input_string","example":"123ijq192.168.3.6kljqwiejs8 https://shuffler.io","value":"$iocdata","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The string to check","id":"","name":"input_type","example":"md5s","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":781.138761913161,"y":-46.6098348080033},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Returns uploaded file data","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"6716f76f-c115-486f-9388-daecd7e66116","is_valid":true,"sharing":true,"label":"create_ioc_file","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M3%2017.25V21h3.75L17.81%209.94l-3.75-3.75L3%2017.25zM20.71%207.04c.39-.39.39-1.02%200-1.41l-2.34-2.34a.9959.9959%200%2000-1.41%200l-1.83%201.83%203.75%203.75%201.83-1.83z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"create_file","parameters":[{"description":"","id":"","name":"filename","example":"test.csv","value":"iocs.txt","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"","id":"","name":"data","example":"EventID,username\n4137,frikky","value":"$iocdata","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":858.038044443336,"y":245.133374745112},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Parse IOC's based on https://github.com/fhightower/ioc-finder","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"08276697-4048-4219-87ec-a7079b5cc782","is_valid":true,"sharing":true,"label":"Parse_indicators_file","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M10%203H5c-1.1%200-2%20.9-2%202v14c0%201.1.9%202%202%202h5v2h2V1h-2v2zm0%2015H5l5-6v6zm9-15h-5v2h5v13l-5-6v9h5c1.1%200%202-.9%202-2V5c0-1.1-.9-2-2-2z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"parse_file_ioc","parameters":[{"description":"The shuffle file to check","id":"","name":"file_ids","example":"","value":"$create_ioc_file.file_id","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The string to check","id":"","name":"input_type","example":"md5s","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":869.485371818295,"y":-154.531325136201},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Takes a mapping dictionary and translates the input data. This is a search and replace for multiple fields.","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"a26deed8-fc1a-42a0-aeaa-e11c09486238","is_valid":true,"sharing":true,"label":"Replace_value_in_string","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M3%2017.25V21h3.75L17.81%209.94l-3.75-3.75L3%2017.25zM20.71%207.04c.39-.39.39-1.02%200-1.41l-2.34-2.34a.9959.9959%200%2000-1.41%200l-1.83%201.83%203.75%203.75%201.83-1.83z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"replace_value_from_dictionary","parameters":[{"description":"The input data to use","id":"","name":"input_data","example":"$exec.field1","value":"This should turn the item Low into ","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The mapping dictionary","id":"","name":"mapping","example":"{\n  \"Low\": 1,\n  \"Medium\": 2,\n  \"High\": 3,\n}\n","value":"{\"Low\": 1, \"Medium\": 2, \"High\": 3}","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":-269.786601438428,"y":363.732912511964},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Takes a list of values and translates it in your input data","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"0d217720-71d3-49bf-905d-cee972a8c666","is_valid":true,"sharing":true,"label":"Map_string_value","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M3%2017.25V21h3.75L17.81%209.94l-3.75-3.75L3%2017.25zM20.71%207.04c.39-.39.39-1.02%200-1.41l-2.34-2.34a.9959.9959%200%2000-1.41%200l-1.83%201.83%203.75%203.75%201.83-1.83z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"replace_value","parameters":[{"description":"The input data to use","id":"","name":"input_data","example":"Hello this is an md5","value":"Hello this is an md5 and not a sha256. They should both become a hash","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The source items to look for","id":"","name":"translate_from","example":"sha256,md5,sha1","value":"sha256,md5,sha1","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The destination data to change to","id":"","name":"translate_to","example":"hash","value":"hash","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The value to set if it DOESNT match. Default to nothing.","id":"","name":"else_value","example":"","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":-237.714340225807,"y":228.367845228055},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Returns objects matching the capture group(s)","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"984d978c-f479-4807-8285-308e85285c54","is_valid":true,"sharing":true,"label":"Capture_regex","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M19%209h-4V3H9v6H5l7%207%207-7zM5%2018v2h14v-2H5z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"regex_capture_group","parameters":[{"description":"The input data to use","id":"","name":"input_data","example":"This is some text \u003Cwith.com\u003E a domain that is with.com","value":"This is some text to capture","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Your regular expression","id":"","name":"regex","example":"some text \u003C[a-zA-Z0-9.]+\u003E a domain","value":"This is some text (.*?) capture","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":-127.127697587993,"y":-44.8436042632348},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Replace all instances matching a regular expression","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"6a01def8-4ebb-4a1b-81a4-7e804d974d5b","is_valid":true,"sharing":true,"label":"Regex_replace","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M3%2017.25V21h3.75L17.81%209.94l-3.75-3.75L3%2017.25zM20.71%207.04c.39-.39.39-1.02%200-1.41l-2.34-2.34a.9959.9959%200%2000-1.41%200l-1.83%201.83%203.75%203.75%201.83-1.83z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"regex_replace","parameters":[{"description":"The input data to use","id":"","name":"input_data","example":"This is some text \u003Cwith.com\u003E a domain that is with.com","value":"This is some text to capture","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Your regular expression","id":"","name":"regex","example":"some text \u003C[a-zA-Z0-9.]+\u003E a domain","value":"This is some text (.*?) capture","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Replacement string (capture groups with \\1 \\2)","id":"","name":"replace_string","example":"some text \u003Cdomain was here\u003E a domain","value":"","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Make regex case insensitive (Default: False)","id":"","name":"ignore_case","example":"False","value":"true","multiline":false,"multiselect":false,"options":["false","true"],"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":8.69808888205262,"y":-82.0051867485513},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Parses a list and returns it as a json object","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"5fdcb4df-b8bf-4395-9c6e-3156db4aa083","is_valid":true,"sharing":true,"label":"Parse_list","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M3%209h14V7H3v2zm0%204h14v-2H3v2zm0%204h14v-2H3v2zm16%200h2v-2h-2v2zm0-10v2h2V7h-2zm0%206h2v-2h-2v2z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"parse_list","parameters":[{"description":"List of items","id":"","name":"items","example":"shuffler.io,test.com,test.no","value":"shuffler.io,test.com,test.no","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The splitter to use","id":"","name":"splitter","example":",","value":",","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":1815.28565529996,"y":863.014219471332},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Runs bash with the data input","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"366ea056-4c5c-4242-af9b-708190555684","is_valid":true,"sharing":true,"label":"Run_bash","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M9.4%2016.6%204.8%2012l4.6-4.6L8%206l-6%206%206%206zm5.2%200%204.6-4.6-4.6-4.6L16%206l6%206-6%206z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"execute_bash","parameters":[{"description":"The code to run","id":"","name":"code","example":"echo \"Hello\"","value":"echo \"Hello this is a test\"","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Alternative data to add","id":"","name":"shuffle_input","example":"{\"data\": \"Hello world\"}","value":"","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":244.124685685208,"y":-32.5533278561199},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Runs python with the data input. Any prints will be returned.","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"4e6bf5aa-85a0-4406-b327-97881fb4f789","is_valid":true,"sharing":true,"label":"Run_python","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M9.4%2016.6%204.8%2012l4.6-4.6L8%206l-6%206%206%206zm5.2%200%204.6-4.6-4.6-4.6L16%206l6%206-6%206z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"execute_python","parameters":[{"description":"The code to run. Can be a file ID from within Shuffle.","id":"","name":"code","example":"print(\"hello world\")","value":"print(\"Hello, this is a test\")","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":375.553257113779,"y":-41.1247564275485},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"This function is made for reading file(s), printing their data","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"bb1035a9-ff93-499e-aa54-726fbd63adae","is_valid":true,"sharing":true,"label":"Get_file_value","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M19%209h-4V3H9v6H5l7%207%207-7zM5%2018v2h14v-2H5z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"get_file_value","parameters":[{"description":"The files","id":"","name":"filedata","example":"a2f89576-a9ec-479e-8c83-da69f468c90a","value":"$create_ioc_file.file_id","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":1267.22276254998,"y":-176.850129200953},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Downloads a file from a URL","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"5e6911ff-a527-44a7-b0b7-87ba9f3953d4","is_valid":true,"sharing":true,"label":"Download_eicar_zip","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M19%209h-4V3H9v6H5l7%207%207-7zM5%2018v2h14v-2H5z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"download_remote_file","parameters":[{"description":"","id":"","name":"url","example":"https://secure.eicar.org/eicar.com.txt","value":"https://secure.eicar.org/eicar_com.zip","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"","id":"","name":"custom_filename","example":"newfile.txt","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":1528.80969190415,"y":-197.178380975223},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Gets the file meta","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"0de860a7-3f31-4956-bc2c-d77a77ad3fb4","is_valid":true,"sharing":true,"label":"Get_file_meta","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M19%209h-4V3H9v6H5l7%207%207-7zM5%2018v2h14v-2H5z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"get_file_meta","parameters":[{"description":"","id":"","name":"file_id","example":"","value":"$create_ioc_file.file_id","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":1395.590208479,"y":-206.129993478015},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Deletes a file based on ID","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"4a44956f-70e5-4cfa-8a36-31237f6affca","is_valid":true,"sharing":true,"label":"Delete_file","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M6%2019c0%201.1.9%202%202%202h8c1.1%200%202-.9%202-2V7H6v12zM19%204h-3.5l-1-1h-5l-1%201H5v2h14V4z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"delete_file","parameters":[{"description":"","id":"","name":"file_id","example":"Some data to put in the file","value":"$create_ioc_file.file_id","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":1239.66405043243,"y":-73.4135320926755},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Compress files in archive, return archive's file id","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"ff21084c-23ca-488d-826e-e46ba67383d5","is_valid":true,"sharing":true,"label":"Recreate_archive","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M3%2017.25V21h3.75L17.81%209.94l-3.75-3.75L3%2017.25zM20.71%207.04c.39-.39.39-1.02%200-1.41l-2.34-2.34a.9959.9959%200%2000-1.41%200l-1.83%201.83%203.75%203.75%201.83-1.83z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"create_archive","parameters":[{"description":"","id":"","name":"file_ids","example":"","value":"[\"$extract_archive.files.#0.file_id\"]","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"","id":"","name":"fileformat","example":"","value":"zip","multiline":false,"multiselect":false,"options":["zip","7zip"],"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"","id":"","name":"name","example":"","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"","id":"","name":"password","example":"","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":1546.38752398622,"y":-702.909963802793},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Extract compressed files, return file ids","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"e9bf1912-3351-481e-9656-28089a0436fa","is_valid":true,"sharing":true,"label":"Extract_archive","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M3%203h18v2H3z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"extract_archive","parameters":[{"description":"","id":"","name":"file_id","example":"","value":"$download_eicar_zip.file_id","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"","id":"","name":"fileformat","example":"","value":"zip","multiline":false,"multiselect":false,"options":["zip","rar","7zip","tar","tar.gz"],"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"","id":"","name":"password","example":"","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":1537.05673398774,"y":-443.708402571227},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Converts xml to json and vice versa","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"377f2050-25b8-42f5-bd77-5621734d5d1e","is_valid":true,"sharing":true,"label":"json_to_xml","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M3%2017.25V21h3.75L17.81%209.94l-3.75-3.75L3%2017.25zM20.71%207.04c.39-.39.39-1.02%200-1.41l-2.34-2.34a.9959.9959%200%2000-1.41%200l-1.83%201.83%203.75%203.75%201.83-1.83z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"xml_json_convertor","parameters":[{"description":"","id":"","name":"convertto","example":"","value":"xml","multiline":false,"multiselect":false,"options":["json","xml"],"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"","id":"","name":"data","example":"xml data / json data","value":"{\"this\":\"is\",\"a\":\"key\",\"which\":1,\"can\":false,\"become\":\"xml\"}","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":1957.88537287608,"y":-247.444022798138},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Converts xml to json and vice versa","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"3bfa97f0-fbcd-4c4f-b4cd-912c0ba8b079","is_valid":true,"sharing":true,"label":"xml_to_json","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M3%2017.25V21h3.75L17.81%209.94l-3.75-3.75L3%2017.25zM20.71%207.04c.39-.39.39-1.02%200-1.41l-2.34-2.34a.9959.9959%200%2000-1.41%200l-1.83%201.83%203.75%203.75%201.83-1.83z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"xml_json_convertor","parameters":[{"description":"","id":"","name":"convertto","example":"","value":"json","multiline":false,"multiselect":false,"options":["json","xml"],"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"","id":"","name":"data","example":"xml data / json data","value":"$json_to_xml","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":2296.48701677988,"y":-293.613113812886},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Converts a date field with a given format to an epoch time","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"5060fc6a-6469-4749-9b0e-ba13947aa9ee","is_valid":true,"sharing":true,"label":"Date_to_epoch","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M10%203H5c-1.1%200-2%20.9-2%202v14c0%201.1.9%202%202%202h5v2h2V1h-2v2zm0%2015H5l5-6v6zm9-15h-5v2h5v13l-5-6v9h5c1.1%200%202-.9%202-2V5c0-1.1-.9-2-2-2z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"date_to_epoch","parameters":[{"description":"The input data to use","id":"","name":"input_data","example":"2010-11-04T04:15:22.123Z","value":"{\"currentDateTime\": \"2010-11-04T04:15:22.123Z\"}","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"dict"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The field containing the date to parse","id":"","name":"date_field","example":"currentDateTime","value":"currentDateTime","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The datetime format of the field to parse (strftime format).","id":"","name":"date_format","example":"%Y-%m-%dT%H:%M:%s.%f%Z","value":"%Y-%m-%dT%H:%M:%S.%f%z","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":2049.50346028266,"y":258.022409888629},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Compares an input date to a relative date and returns a True/False result","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"ab444854-fa7e-48b3-ba72-e8c03ab833e6","is_valid":true,"sharing":true,"label":"Compare_timestamps","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M10%203H5c-1.1%200-2%20.9-2%202v14c0%201.1.9%202%202%202h5v2h2V1h-2v2zm0%2015H5l5-6v6zm9-15h-5v2h5v13l-5-6v9h5c1.1%200%202-.9%202-2V5c0-1.1-.9-2-2-2z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"compare_relative_date","parameters":[{"description":"The input data to use","id":"","name":"timestamp","example":"2010-11-04T04:15:22.123Z","value":"2010-11-04T04:15:22.123Z","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The format of the input date field  (strftime format)","id":"","name":"date_format","example":"%Y-%m-%dT%H:%M:%S.%f%Z","value":"%Y-%m-%dT%H:%M:%S.%f%z","multiline":false,"multiselect":false,"options":["%Y-%m-%dT%H:%M%z","%Y-%m-%dT%H:%M:%SZ","%Y-%m-%dT%H:%M:%S%Z","%Y-%m-%dT%H:%M:%S%z","%Y-%m-%dT%H:%M:%S.%f%z","%Y-%m-%d","%H:%M:%S","%s"],"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"How to compare the input date and offset date","id":"","name":"equality_test","example":"\u003E","value":"\u003E","multiline":false,"multiselect":false,"options":["\u003E","\u003C","=","!=","\u003E=","\u003C="],"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Numeric offset from current time","id":"","name":"offset","example":"60","value":"60","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The units of the provided value","id":"","name":"units","example":"seconds","value":"seconds","multiline":false,"multiselect":false,"options":["seconds","minutes","hours","days"],"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Whether the comparison should be in the past or future","id":"","name":"direction","example":"ago","value":"ago","multiline":false,"multiselect":false,"options":["ago","ahead"],"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":2073.10535495745,"y":364.921937542688},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Adds items of second list (list_two) to the first one (list_one). Can also append a single item (dict) to a list.","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"a48e4bab-009b-4aa0-9e5a-413333d1d261","is_valid":true,"sharing":true,"label":"Add_list_to_list","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M3%209h14V7H3v2zm0%204h14v-2H3v2zm0%204h14v-2H3v2zm16%200h2v-2h-2v2zm0-10v2h2V7h-2zm0%206h2v-2h-2v2z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"add_list_to_list","parameters":[{"description":"The first list","id":"","name":"list_one","example":"{'key': 'value'}","value":"[{\"list1\": \"item1\"}]","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The second list to use","id":"","name":"list_two","example":"{'key2': 'value2'}","value":"[{\"list2\": \"item2\"}]","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":1567.30488108249,"y":973.568815381571},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Merges two lists of same type AND length.","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"a3154c2c-8818-492d-897b-fdab09124055","is_valid":true,"sharing":true,"label":"Merge_lists","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M17%2020.41%2018.41%2019%2015%2015.59%2013.59%2017%2017%2020.41zM7.5%208H11v5.59L5.59%2019%207%2020.41l6-6V8h3.5L12%203.5%207.5%208z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"merge_lists","parameters":[{"description":"The first list","id":"","name":"list_one","example":"{'key': 'value'}","value":"[{\"list1\": \"item1\"}]","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The second list to use","id":"","name":"list_two","example":"{'key2': 'value2'}","value":"[{\"list2\": \"item2\"}]","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"If items in list 2 are strings, but first is JSON, sets the values to the specified key. Defaults to key \"new_shuffle_key\"","id":"","name":"set_field","example":"json_key","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Sort by this key before using list one for merging","id":"","name":"sort_key_list_one","example":"json_key","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Sort by this key before using list two for merging","id":"","name":"sort_key_list_two","example":"json_key","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":1886.16995822611,"y":758.006341015831},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Diffs two lists of strings or integers and finds what's missing","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"829bc77a-255c-4f52-a3d4-3c25991b15a2","is_valid":true,"sharing":true,"label":"Find_diff_in_lists","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M3%209h14V7H3v2zm0%204h14v-2H3v2zm0%204h14v-2H3v2zm16%200h2v-2h-2v2zm0-10v2h2V7h-2zm0%206h2v-2h-2v2z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"diff_lists","parameters":[{"description":"The first list","id":"","name":"list_one","example":"{'key': 'value'}","value":"[{\"list1\": \"item1\"}]","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The second list to use","id":"","name":"list_two","example":"{'key2': 'value2'}","value":"[{\"list2\": \"item2\"}]","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":2013.1438146784,"y":651.235295999877},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Adds a JSON key to an existing object","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"aff918a7-6b8a-4dd0-8a35-62e528c5a5ba","is_valid":true,"sharing":true,"label":"Add_JSON_key","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M2.01%2021L23%2012%202.01%203%202%2010l15%202-15%202z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"set_json_key","parameters":[{"description":"The object to edit","id":"","name":"json_object","example":"recipients","value":"{\"sender\": \"test@test.com\"}","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The object to add","id":"","name":"key","example":"recipients","value":"test","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The value to set it to in the JSON object","id":"","name":"value","example":"frikky@shuffler.io","value":"frikky@shuffler.io","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":1192.00463876683,"y":756.010841588042},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Deletes keys in a json object","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"e2c6bb39-7530-453d-8323-5e4dd7e455a8","is_valid":true,"sharing":true,"label":"Delete_JSON_key","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M6%2019c0%201.1.9%202%202%202h8c1.1%200%202-.9%202-2V7H6v12zM19%204h-3.5l-1-1h-5l-1%201H5v2h14V4z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"delete_json_keys","parameters":[{"description":"The object to edit","id":"","name":"json_object","example":"{'key': 'value', 'key2': 'value2', 'key3': 'value3'}","value":"$add_json_key","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The key(s) to remove","id":"","name":"keys","example":"key, key3","value":"test","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":1112.32110322415,"y":951.491460201029},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Creates key:value pairs and","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"1741d27e-cf0b-4603-b6e3-80d2c205f49c","is_valid":true,"sharing":true,"label":"JSON_keys_to_tags","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M3%2017.25V21h3.75L17.81%209.94l-3.75-3.75L3%2017.25zM20.71%207.04c.39-.39.39-1.02%200-1.41l-2.34-2.34a.9959.9959%200%2000-1.41%200l-1.83%201.83%203.75%203.75%201.83-1.83z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"convert_json_to_tags","parameters":[{"description":"The object to make into a key:value pair","id":"","name":"json_object","example":"{'key': 'value', 'key2': 'value2', 'key3': 'value3'}","value":"$add_json_key","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The way to split the values. Defaults to comma.","id":"","name":"split_value","example":",","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Whether it should include the key or not","id":"","name":"include_key","example":"","value":"true","multiline":false,"multiselect":false,"options":["true","false"],"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Whether it should be lowercase or not","id":"","name":"lowercase","example":"","value":"true","multiline":false,"multiselect":false,"options":["true","false"],"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":998.466920827055,"y":796.43955479876},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Takes a math input and gives you the result","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"a925e137-f07a-47e5-9262-eb1873a27257","is_valid":true,"sharing":true,"label":"Run_math_operation","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M8%205v14l11-7z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"run_math_operation","parameters":[{"description":"The operation to perform","id":"","name":"operation","example":"5+10","value":"5+10/2","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":425.481781272697,"y":73.8410909654048},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Encode or decode a Base64 string","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"676f4519-abe6-4325-a666-aeaebca72593","is_valid":true,"sharing":true,"label":"base64_encode","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M3%2017.25V21h3.75L17.81%209.94l-3.75-3.75L3%2017.25zM20.71%207.04c.39-.39.39-1.02%200-1.41l-2.34-2.34a.9959.9959%200%2000-1.41%200l-1.83%201.83%203.75%203.75%201.83-1.83z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"base64_conversion","parameters":[{"description":"string to process","id":"","name":"string","example":"This is a string to be encoded","value":"This is a complicated test no?","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Choose to encode or decode the string","id":"","name":"operation","example":"encode","value":"encode","multiline":false,"multiselect":false,"options":["encode","decode"],"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":1981.85195342792,"y":-166.42214654598},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Encode or decode a Base64 string","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"f2cb80aa-2e2d-42fd-af6e-b0232145a328","is_valid":true,"sharing":true,"label":"base64_decode","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M3%2017.25V21h3.75L17.81%209.94l-3.75-3.75L3%2017.25zM20.71%207.04c.39-.39.39-1.02%200-1.41l-2.34-2.34a.9959.9959%200%2000-1.41%200l-1.83%201.83%203.75%203.75%201.83-1.83z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"base64_conversion","parameters":[{"description":"string to process","id":"","name":"string","example":"This is a string to be encoded","value":"$base64_encode","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Choose to encode or decode the string","id":"","name":"operation","example":"encode","value":"decode","multiline":false,"multiselect":false,"options":["encode","decode"],"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":2295.1974379079,"y":-201.395820400663},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Gets a timestamp for right now. Default returns an epoch timestamp","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"156d47df-e9d4-4214-a7e5-13a479d4e3b1","is_valid":true,"sharing":true,"label":"Get_current_timestamp","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M19%209h-4V3H9v6H5l7%207%207-7zM5%2018v2h14v-2H5z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"get_timestamp","parameters":[{"description":"The format to use","id":"","name":"time_format","example":"","value":"epoch","multiline":false,"multiselect":false,"options":["epoch","unix"],"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":2064.31246420994,"y":440.279237682541},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Returns multiple formats of hashes based on the input value","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"f5f96293-8e61-45f8-87f3-8bfed99c0a69","is_valid":true,"sharing":true,"label":"Get_hashes_for_string","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M19%209h-4V3H9v6H5l7%207%207-7zM5%2018v2h14v-2H5z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"get_hash_sum","parameters":[{"description":"The value to hash","id":"","name":"value","example":"1.1.1.1","value":"1.2.3.4","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":2010.29464306382,"y":-63.9616357639554},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Check if an IP is contained in a CIDR defined network","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"e427b5d3-2199-429d-aa10-dd0f991a5bfb","is_valid":true,"sharing":true,"label":"Find_value_in_IP","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M15.5%2014h-.79l-.28-.27C15.41%2012.59%2016%2011.11%2016%209.5%2016%205.91%2013.09%203%209.5%203S3%205.91%203%209.5%205.91%2016%209.5%2016c1.61%200%203.09-.59%204.23-1.57l.27.28v.79l5%204.99L20.49%2019l-4.99-5zm-6%200C7.01%2014%205%2011.99%205%209.5S7.01%205%209.5%205%2014%207.01%2014%209.5%2011.99%2014%209.5%2014z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"cidr_ip_match","parameters":[{"description":"IP to check","id":"","name":"ip","example":"1.1.1.1","value":"1.2.3.4","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"List of network in CIDR format","id":"","name":"networks","example":"['10.0.0.0/8', '192.168.10.0/24']","value":"[\"1.0.0.0/24\"]","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":933.467344284921,"y":-4.36198823064659},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Adds items of second list (list_two) to the first one (list_one). Can also append a single item (dict) to a list.","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"93cb8cd9-60fb-4ac5-ad71-ec8b362321d3","is_valid":true,"sharing":true,"label":"Pure_ints","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M3%209h14V7H3v2zm0%204h14v-2H3v2zm0%204h14v-2H3v2zm16%200h2v-2h-2v2zm0-10v2h2V7h-2zm0%206h2v-2h-2v2z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"add_list_to_list","parameters":[{"description":"The first list","id":"","name":"list_one","example":"{'key': 'value'}","value":"[1,2,3]","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The second list to use","id":"","name":"list_two","example":"{'key2': 'value2'}","value":"[4,5,6]","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":2068.34463670886,"y":906.502872579423},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Merges two lists of same type AND length.","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"1c3b912b-4e8d-40f4-bfec-8e92b8379de9","is_valid":true,"sharing":true,"label":"Slightly_more_complex","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M17%2020.41%2018.41%2019%2015%2015.59%2013.59%2017%2017%2020.41zM7.5%208H11v5.59L5.59%2019%207%2020.41l6-6V8h3.5L12%203.5%207.5%208z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"merge_lists","parameters":[{"description":"The first list","id":"","name":"list_one","example":"{'key': 'value'}","value":"[ { \"thing\": \"object1\" }, { \"thing\": \"object2\" }, { \"thing\": \"object3\" } ]","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The second list to use","id":"","name":"list_two","example":"{'key2': 'value2'}","value":"[ { \"thing2\": \"true\" }, { \"thing2\": \"True\" }, { \"thing\": \"true\" } ]","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"If items in list 2 are strings, but first is JSON, sets the values to the specified key. Defaults to key \"new_shuffle_key\"","id":"","name":"set_field","example":"json_key","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Sort by this key before using list one for merging","id":"","name":"sort_key_list_one","example":"json_key","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"Sort by this key before using list two for merging","id":"","name":"sort_key_list_two","example":"json_key","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":false,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":2237.04805642395,"y":1036.13964186828},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Adds items of second list (list_two) to the first one (list_one). Can also append a single item (dict) to a list.","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"9ccd153e-a4ce-4e8d-9409-f4ff9101a8cc","is_valid":true,"sharing":true,"label":"Different_lengths","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M3%209h14V7H3v2zm0%204h14v-2H3v2zm0%204h14v-2H3v2zm16%200h2v-2h-2v2zm0-10v2h2V7h-2zm0%206h2v-2h-2v2z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"add_list_to_list","parameters":[{"description":"The first list","id":"","name":"list_one","example":"{'key': 'value'}","value":"[ { \"thing\": \"object1\" }, { \"thing\": \"object2\" }, { \"thing\": \"object3\" } ]","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The second list to use","id":"","name":"list_two","example":"{'key2': 'value2'}","value":"[ { \"thing2\": \"true\" }, { \"thing2\": \"True\" } ]","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":2416.52848315317,"y":1171.16491466421},"authentication_id":"","category":"Testing","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"email","app_version":"1.3.0","description":"Send an email from Shuffle","app_id":"f33aa6a9c04e64cbf5d89d927ff0cd38","errors":null,"id":"06523385-62e6-4d0a-a5cf-13766f045abf","is_valid":true,"sharing":true,"label":"email_1","public":true,"generated":false,"large_image":"data:image/png;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/4QAYRXhpZgAASUkqAAgAAAAAAAAAAAAAAP/hAytodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuMy1jMDExIDY2LjE0NTY2MSwgMjAxMi8wMi8wNi0xNDo1NjoyNyAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENTNiAoV2luZG93cykiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6Nzg4QTJBMjVEMDI1MTFFN0EwQUVDODc5QjYyQkFCMUQiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6Nzg4QTJBMjZEMDI1MTFFN0EwQUVDODc5QjYyQkFCMUQiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDo3ODhBMkEyM0QwMjUxMUU3QTBBRUM4NzlCNjJCQUIxRCIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDo3ODhBMkEyNEQwMjUxMUU3QTBBRUM4NzlCNjJCQUIxRCIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/Pv/bAEMAAwICAgICAwICAgMDAwMEBgQEBAQECAYGBQYJCAoKCQgJCQoM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","environment":"Cloud","name":"send_email_shuffle","parameters":[{"description":"Your https://shuffler.io apikey","id":"2c43e08a-a525-4c7f-82dd-2ac69c6f1e30","name":"apikey","example":"https://shuffler.io apikey","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The recipients of the email","id":"6639f6e5-81fc-4279-aa9c-5efdd84410f8","name":"recipients","example":"test@example.com,frikky@shuffler.io","value":"validemail@email.com","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The subject to use","id":"46787bde-6479-45b0-a0fa-9c2e581cc615","name":"subject","example":"SOS this is an alert :o","value":"some subject","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The body to add to the email","id":"78cac761-4522-4e4a-8f42-abc6f5b32a83","name":"body","example":"This is an email alert from Shuffler.io :)","value":"some subject","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":-105.375517386646,"y":620.145477515949},"authentication_id":"","category":"communication","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Repeats the call parameter","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"5e1b4107-3a80-4b84-8750-ddf967d661c7","is_valid":true,"sharing":true,"label":"call_subflow","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M19%208l-4%204h3c0%203.31-2.69%206-6%206-1.01%200-1.97-.25-2.8-.7l-1.46%201.46C8.97%2019.54%2010.43%2020%2012%2020c4.42%200%208-3.58%208-8h3l-4-4zM6%2012c0-3.31%202.69-6%206-6%201.01%200%201.97.25%202.8.7l1.46-1.46C15.03%204.46%2013.57%204%2012%204c-4.42%200-8%203.58-8%208H1l4%204%204-4H6z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"repeat_back_to_me","parameters":[{"description":"The message to repeat","id":"","name":"call","example":"REPEATING: Hello world","value":"","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":139.821479641082,"y":1233.9480114332},"authentication_id":"","category":"Other","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Send an SMS from Shuffle","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","errors":null,"id":"e77bb081-c28c-4b15-8593-86ff48f33ee3","is_valid":true,"sharing":true,"label":"Shuffle_Tools_1","public":true,"generated":false,"large_image":"data:image/svg+xml;utf-8,%3Csvg%20width=%2224%22%20height=%2224%22%20viewBox=%220%200%2024%2024%22%20version=%221.1%22%20xmlns=%22http://www.w3.org/2000/svg%22%3E%3Cpath%20d=%22M2.01%2021L23%2012%202.01%203%202%2010l15%202-15%202z%22%20fill=%22white%22%3E%3C/path%3E%3C/svg%3E","environment":"Cloud","name":"send_sms_shuffle","parameters":[{"description":"Your https://shuffler.io organization apikey","id":"","name":"apikey","example":"https://shuffler.io apikey","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The receivers of the SMS","id":"","name":"phone_numbers","example":"+4741323535,+8151023022","value":"+123456789","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"The SMS to add to the numbers","id":"","name":"body","example":"This is an alert from Shuffle :)","value":"This is an alert from Shuffle :)","multiline":true,"multiselect":false,"options":null,"action_field":"","variant":"","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":-6.52147270912914,"y":722.661880958063},"authentication_id":"","category":"Other","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false,"parent_controlled":false}],"branches":[{"destination_id":"f63dd458-2ed4-49df-87b2-2c7b3ac99075","id":"3eaf433d-d4fd-46f5-9a76-ccc86977b1f6","source_id":"3d760e52-214b-4c6d-bfad-a043d11d700e","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"f5f96293-8e61-45f8-87f3-8bfed99c0a69","id":"412d3973-2826-4e49-a268-5f8af090111f","source_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"93cb8cd9-60fb-4ac5-ad71-ec8b362321d3","id":"55d18636-290b-472a-9c05-16536256affc","source_id":"a3154c2c-8818-492d-897b-fdab09124055","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"e427b5d3-2199-429d-aa10-dd0f991a5bfb","id":"99a9fc1c-dffb-46c7-84e2-d3fbe5245401","source_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"ff21084c-23ca-488d-826e-e46ba67383d5","id":"67fabdcf-29d8-46be-9dff-8337598eca14","source_id":"e9bf1912-3351-481e-9656-28089a0436fa","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","id":"c7c3208a-d457-4127-a63e-dcad450a6f57","source_id":"969da5d9-4f3c-4ae0-989d-810fbae8b329","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"3369c754-f535-4f49-93cf-dbe5af77bde4","id":"2b0b7788-c9bb-4456-990a-fd695a5672a8","source_id":"f63dd458-2ed4-49df-87b2-2c7b3ac99075","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"06523385-62e6-4d0a-a5cf-13766f045abf","id":"1ebd119f-99a3-47a0-bd5a-74bcf1d175a0","source_id":"969da5d9-4f3c-4ae0-989d-810fbae8b329","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"3d760e52-214b-4c6d-bfad-a043d11d700e","id":"6469f4b3-bc05-41bc-b0f7-79b1f9cb78eb","source_id":"969da5d9-4f3c-4ae0-989d-810fbae8b329","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"2d88173c-f61c-56a0-84b0-1542a30153b2","id":"04ec6e54-5e23-455f-b3a5-8ffb2a42d504","source_id":"969da5d9-4f3c-4ae0-989d-810fbae8b329","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"1c3b912b-4e8d-40f4-bfec-8e92b8379de9","id":"a994bef6-7a67-4017-86d7-0ca7ad304ce8","source_id":"93cb8cd9-60fb-4ac5-ad71-ec8b362321d3","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"a902d3ba-8732-4229-8c0d-fbe744a330a4","id":"bba9737f-cc55-466d-86c0-d2c63d517299","source_id":"969da5d9-4f3c-4ae0-989d-810fbae8b329","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"6716f76f-c115-486f-9388-daecd7e66116","id":"1468ed78-f3e1-4c24-81de-737c3b9a7175","source_id":"969da5d9-4f3c-4ae0-989d-810fbae8b329","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"08276697-4048-4219-87ec-a7079b5cc782","id":"29c6e734-30ee-49f0-a3a3-7dda087295c4","source_id":"6716f76f-c115-486f-9388-daecd7e66116","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"a26deed8-fc1a-42a0-aeaa-e11c09486238","id":"bce031c7-c230-4256-8995-f33c2b87984e","source_id":"969da5d9-4f3c-4ae0-989d-810fbae8b329","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"0d217720-71d3-49bf-905d-cee972a8c666","id":"13d99859-4ff1-4f27-aa09-c385a6cf66f3","source_id":"969da5d9-4f3c-4ae0-989d-810fbae8b329","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"984d978c-f479-4807-8285-308e85285c54","id":"a5108283-8e52-4624-9594-49d996e06201","source_id":"969da5d9-4f3c-4ae0-989d-810fbae8b329","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"6a01def8-4ebb-4a1b-81a4-7e804d974d5b","id":"df6c8f29-51f1-401d-a18e-a904830d7d7e","source_id":"969da5d9-4f3c-4ae0-989d-810fbae8b329","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"366ea056-4c5c-4242-af9b-708190555684","id":"d8778f0c-b8fb-4078-b0a9-d80c79e1025f","source_id":"969da5d9-4f3c-4ae0-989d-810fbae8b329","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"4e6bf5aa-85a0-4406-b327-97881fb4f789","id":"4469fc16-e831-4b0a-8c2d-5802e7346b61","source_id":"969da5d9-4f3c-4ae0-989d-810fbae8b329","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"bb1035a9-ff93-499e-aa54-726fbd63adae","id":"47b820da-ad41-4d36-85ec-fe18f0e8801f","source_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"5e6911ff-a527-44a7-b0b7-87ba9f3953d4","id":"3730d421-6968-4fe3-aaba-fb83a4a34a8f","source_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","id":"682d6152-5f9b-42a2-8d4c-4240d8044a04","source_id":"6716f76f-c115-486f-9388-daecd7e66116","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"0de860a7-3f31-4956-bc2c-d77a77ad3fb4","id":"973bddcf-765e-4836-b3eb-9f34aa8087c7","source_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"4a44956f-70e5-4cfa-8a36-31237f6affca","id":"b8fc558d-bcc9-4e8d-bf4a-bddcbc78dcd3","source_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"4a44956f-70e5-4cfa-8a36-31237f6affca","id":"0d057d92-8a09-4ba5-95bb-6f58369d0b88","source_id":"08276697-4048-4219-87ec-a7079b5cc782","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"e9bf1912-3351-481e-9656-28089a0436fa","id":"7268530a-744f-495e-a290-cb96ebb0439d","source_id":"5e6911ff-a527-44a7-b0b7-87ba9f3953d4","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"377f2050-25b8-42f5-bd77-5621734d5d1e","id":"22761013-ade7-412a-8793-2c8d04cd4565","source_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"3bfa97f0-fbcd-4c4f-b4cd-912c0ba8b079","id":"054f9b4a-8509-49b1-995b-6bf7461bfe33","source_id":"377f2050-25b8-42f5-bd77-5621734d5d1e","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"5060fc6a-6469-4749-9b0e-ba13947aa9ee","id":"ed023416-f9f9-4c45-9235-bf1c7d0a3764","source_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"ab444854-fa7e-48b3-ba72-e8c03ab833e6","id":"906ce0ee-033a-4114-a2af-db6ad505e55b","source_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"a48e4bab-009b-4aa0-9e5a-413333d1d261","id":"a9cf0360-2e6c-41a0-bfa7-15f9626a93b3","source_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"a3154c2c-8818-492d-897b-fdab09124055","id":"ceb92305-cbe7-4ff5-b01b-be59fb3e5603","source_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"829bc77a-255c-4f52-a3d4-3c25991b15a2","id":"052ef258-589f-4da4-b23e-76f26b0e5d07","source_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"5fdcb4df-b8bf-4395-9c6e-3156db4aa083","id":"e3e039f3-5c09-4b75-97a1-c190af12517f","source_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"02f87429-a7d2-47ba-9fc4-08a7fce90662","id":"92f0d700-2bc4-4b36-85c0-166fc8cb6d14","source_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"aff918a7-6b8a-4dd0-8a35-62e528c5a5ba","id":"bbaefe76-4427-4f8d-af43-2ff32bbf6f09","source_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"1741d27e-cf0b-4603-b6e3-80d2c205f49c","id":"35b8bc62-f5ff-41f4-bbaa-ace151d16a96","source_id":"aff918a7-6b8a-4dd0-8a35-62e528c5a5ba","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"e2c6bb39-7530-453d-8323-5e4dd7e455a8","id":"b9f7fcd5-158e-4a66-aad7-11e591dcac4b","source_id":"aff918a7-6b8a-4dd0-8a35-62e528c5a5ba","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"156d47df-e9d4-4214-a7e5-13a479d4e3b1","id":"2f79874d-e943-474b-ae0c-8a925c47281d","source_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"a925e137-f07a-47e5-9262-eb1873a27257","id":"115c48e5-70cd-4103-b69c-d503b92de794","source_id":"969da5d9-4f3c-4ae0-989d-810fbae8b329","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"9ccd153e-a4ce-4e8d-9409-f4ff9101a8cc","id":"6e30c254-d5d6-4a3f-ba17-9e089088ef94","source_id":"1c3b912b-4e8d-40f4-bfec-8e92b8379de9","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"676f4519-abe6-4325-a666-aeaebca72593","id":"e4b19255-6af3-45a3-a80e-7d656fa7adfd","source_id":"5a06657d-cb9a-4d6f-bf77-74f00c0d3ac6","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"f2cb80aa-2e2d-42fd-af6e-b0232145a328","id":"3680e048-53b1-4ea3-abe4-ccda5538ffbe","source_id":"676f4519-abe6-4325-a666-aeaebca72593","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""},{"destination_id":"e77bb081-c28c-4b15-8593-86ff48f33ee3","id":"c5fd81d4-8fc9-4154-a1a4-2feef51e9725","source_id":"969da5d9-4f3c-4ae0-989d-810fbae8b329","label":"","has_errors":false,"conditions":null,"decorator":false,"parent_controlled":false,"source_parent":""}],"visual_branches":null,"triggers":[{"app_name":"Shuffle Workflow","description":"Run a Subflow trigger","long_description":"Execute another workflow from this workflow","status":"stopped","app_version":"1.0.0","errors":null,"id":"2d88173c-f61c-56a0-84b0-1542a30153b2","is_valid":true,"isStartNode":false,"label":"Shuffle_Workflow_1","small_image":"","large_image":"data:image/png;base64,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","environment":"cloud","trigger_type":"SUBFLOW","name":"Shuffle Workflow","tags":null,"parameters":[{"description":"","id":"","name":"workflow","example":"","value":"c570ae8a-8e2d-4e76-92ca-6f8cf33183a5","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"","required":false,"configuration":false,"tags":null,"schema":{"type":""},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"","id":"","name":"argument","example":"","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"","required":false,"configuration":false,"tags":null,"schema":{"type":""},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"","id":"","name":"user_apikey","example":"","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"","required":false,"configuration":false,"tags":null,"schema":{"type":""},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"","id":"","name":"startnode","example":"","value":"c4d8de6b-75f4-42c8-bca4-be47732818b0","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"","required":false,"configuration":false,"tags":null,"schema":{"type":""},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"","id":"","name":"check_result","example":"","value":"false","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"","required":false,"configuration":false,"tags":null,"schema":{"type":""},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false},{"description":"","id":"","name":"auth_override","example":"","value":"","multiline":false,"multiselect":false,"options":null,"action_field":"","variant":"","required":false,"configuration":false,"tags":null,"schema":{"type":""},"skip_multicheck":false,"value_replace":null,"unique_toggled":false,"error":"","hidden":false}],"position":{"x":182.285705850772,"y":1066.92205500842},"priority":0,"source_workflow":"","execution_delay":0,"app_association":{"name":"","app_version":"","id":"","link":"","is_valid":false,"generated":false,"downloaded":false,"sharing":false,"verified":false,"invalid":false,"activated":false,"tested":false,"hash":"","private_id":"","environment":"","small_image":"","large_image":"","contact_info":{"name":"","url":""},"folder_mount":{"folder_mount":false,"source_folder":"","destination_folder":""},"authentication":{"type":"","required":false,"parameters":null,"redirect_uri":"","token_uri":"","refresh_uri":"","scope":null,"client_id":"","client_secret":"","grant_type":""},"actions":null,"tags":null,"categories":null,"created":0,"edited":0,"last_runtime":0,"versions":null,"loop_versions":null,"owner":"","sharing_config":"","public":false,"published_id":"","child_ids":null,"reference_org":"","reference_url":"","action_file_path":"","template":false,"documentation":"","description":"","documentation_download_url":"","primary_usecases":null,"skipped_build":false,"reference_info":{"is_partner":false,"partner_contacts":"","documentation_url":"","github_url":"","triggers":null},"blogpost":"","video":"","company_url":"","contributors":null,"revision_id":"","collection":""},"parent_controlled":false,"replacement_for_trigger":""}],"comments":[{"id":"d71ffda1-71ab-47e9-bed3-b3341019d7c9","label":"String replacement","type":"COMMENT","is_valid":true,"decorator":true,"width":250,"height":150,"color":"#ffffff","backgroundcolor":"#1f2023","position":{"x":-454.285714285714,"y":225.714285714286}},{"id":"1b870588-8c9d-478f-8287-051944355798","label":"Execute commands","type":"COMMENT","is_valid":true,"decorator":true,"width":250,"height":150,"color":"#ffffff","backgroundcolor":"#1f2023","position":{"x":360.900132429672,"y":-197.190767925879}},{"id":"e65f31d5-ebcb-43cd-bd3f-b3955880f820","label":"Handle lists","type":"COMMENT","is_valid":true,"decorator":true,"width":250,"height":150,"color":"#ffffff","backgroundcolor":"#1f2023","position":{"x":1861.35073820887,"y":1070.67356100778}},{"id":"766a592a-134d-42f6-9690-acaf8dbc712f","label":"Regex","type":"COMMENT","is_valid":true,"decorator":true,"width":250,"height":150,"color":"#ffffff","backgroundcolor":"#1f2023","position":{"x":-74.2857142857143,"y":-197.142857142857}},{"id":"a39d5a87-e4ec-4733-af5b-5c3b34c3d756","label":"Key:value store (cache)","type":"COMMENT","is_valid":true,"decorator":true,"width":350,"height":150,"color":"#ffffff","backgroundcolor":"#1f2023","position":{"x":597.142857142857,"y":797.142857142857}},{"id":"a2bf1e27-6325-4bd7-8181-e6d526991483","label":"Parse indicators","type":"COMMENT","is_valid":true,"decorator":true,"width":250,"height":150,"color":"#ffffff","backgroundcolor":"#1f2023","position":{"x":720.001,"y":-171.428571428571}},{"id":"d1a512ed-1aeb-4f47-90ee-475b8a5d27fd","label":"SMS & Email","type":"COMMENT","is_valid":true,"decorator":true,"width":250,"height":150,"color":"#ffffff","backgroundcolor":"#1f2023","position":{"x":-185.714285714286,"y":808.571428571429}},{"id":"16294999-ce78-43ef-9d50-d2b5821d3e57","label":"Files & archives","type":"COMMENT","is_valid":true,"decorator":true,"width":250,"height":150,"color":"#ffffff","backgroundcolor":"#1f2023","position":{"x":1328.57142857143,"y":-345.714285714286}},{"id":"e766e207-5943-4d0e-9a26-40830180c88e","label":"Date parsing","type":"COMMENT","is_valid":true,"decorator":true,"width":250,"height":150,"color":"#ffffff","backgroundcolor":"#1f2023","position":{"x":2300.54359773061,"y":361.100214546921}},{"id":"0c098079-cd4f-41d1-8132-2cf8b6056871","label":"Data conversion (base64, xml..)","type":"COMMENT","is_valid":true,"decorator":true,"width":350,"height":150,"color":"#ffffff","backgroundcolor":"#1f2023","position":{"x":2159.28571428571,"y":-438.142857142857}},{"id":"9f0f8be6-6ce9-4f37-9d1e-a182dfbc5281","label":"Modify JSON","type":"COMMENT","is_valid":true,"decorator":true,"width":250,"height":150,"color":"#ffffff","backgroundcolor":"#1f2023","position":{"x":1025.001,"y":628.001}}],"configuration":{"exit_on_error":false,"start_from_top":false,"skip_notifications":false},"created":1648035878,"edited":1740481223,"last_runtime":0,"due_date":1737916200,"errors":["Variable shuffle_apikey is empty!","Variable cachekey is empty!"],"tags":["example","tools","testing"],"id":"ae89a788-a26b-4866-8a0b-ce0b31d354ea","is_valid":true,"name":"Shuffle Tools health API Subflow","description":"Sample workflow to show how to use different parts of the Shuffle Tools app. Built into sections, and used to make sure the app works at different stages.\n\nBased on Shuffle Tools version \u003E=1.2.0 ","start":"969da5d9-4f3c-4ae0-989d-810fbae8b329","owner":"","sharing":"public","image":"data:image/png;base64,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","execution_org":{"name":"","id":"","users":null,"role":"","creator_org":"","image":"","child_orgs":null,"region_url":""},"workflow_variables":[{"description":"","id":"eadfd5f2-e2b4-450b-a582-ce79f9e6aaea","name":"shuffle_apikey","value":""},{"description":"","id":"68098014-28e3-4ee0-a75a-0d31853f96df","name":"cachekey","value":""},{"description":"","id":"14376e70-7c66-4065-9aa5-61aef6a86efb","name":"iocdata","value":"1234,google.com,1.2.3.5"}],"execution_environment":"","previously_saved":true,"categories":{"siem":{"name":"","count":0,"id":"","description":"","large_image":""},"communication":{"name":"","count":3,"id":"","description":"","large_image":""},"assets":{"name":"","count":0,"id":"","description":"","large_image":""},"cases":{"name":"","count":0,"id":"","description":"","large_image":""},"network":{"name":"","count":0,"id":"","description":"","large_image":""},"intel":{"name":"","count":123,"id":"","description":"","large_image":""},"edr":{"name":"","count":0,"id":"","description":"","large_image":""},"iam":{"name":"","count":0,"id":"","description":"","large_image":""},"ai":{"name":"","count":0,"id":"","description":"","large_image":""},"email":{"name":"","count":0,"id":"","description":"","large_image":""},"other":{"name":"","count":6,"id":"","description":"","large_image":""}},"example_argument":"","public":true,"default_return_value":"","contact_info":{"name":"","url":""},"published_id":"2f95122d-cbdc-4f6f-907b-9cd196d1016c","revision_id":"","usecase_ids":null,"input_questions":null,"form_control":{"input_markdown":"","output_yields":null,"cleanup_actions":null,"form_width":500},"blogpost":"","video":"","status":"test","workflow_type":"","generated":false,"hidden":false,"updated_by":"yash@shuffler.io","validated":true,"validation":{"valid":false,"changed_at":1737991560000,"last_valid":0,"validation_ran":true,"notifications_created":0,"workflow_id":"","execution_id":"09f1da61-0cbf-4b79-bbb2-1bfade4a42c2","node_id":"","total_problems":3,"errors":[{"order":0,"action_id":"aa5d422f-1625-4bcf-b504-e27a2b32efb0","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","app_name":"Shuffle Tools","error":"Success is false: Check node for more failure details","type":"configuration","waiting":false},{"order":0,"action_id":"d7e461a8-3900-43be-9aa2-8feec3dc3f31","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","app_name":"Shuffle Tools","error":"Action 'Pure ints' failed: 'An error occurred while merging the lists. PS: List one can NOT be a list of integers. If this persists, contact us at support@shuffler.io'","type":"configuration","waiting":false},{"order":0,"action_id":"2534025d-37d0-4067-95a9-e6f1bef18ffa","app_id":"3e2bdf9d5069fe3f4746c29d68785a6a","app_name":"Shuffle Tools","error":"Success is false: Check node for more failure details","type":"configuration","waiting":false}],"subflow_apps":[]},"parentorg_workflow":"","childorg_workflow_ids":null,"suborg_distribution":null,"backup_config":{"upload_repo":"","upload_branch":"","upload_username":"","upload_token":"","tokens_encrypted":false},"auth_groups":null}`)
}

func GetOnpremPaidEula() string {
	return (`Shuffle AS - EULA
The Shuffle End User License Agreement is a legally binding contract between Shuffle and the user of Shuffle's services. By accepting this, you agree to the terms and conditions of this agreement. The Agreement is meant for those intending to buy Shuffle's services, and not when using the Free Open Source or Freemium versions of Shuffle. If you do not agree to these terms, please reach out to support@shuffler.io so we can discuss and create a custom contract.

Any quotation is monthly, and does not reflect any applicable sales tax unless otherwise specified. If you want this contract in PDF form, please contact support@shuffler.io

Shuffle Services
This section describes each part of the previously mentioned services in detail.
About the Shuffle Scale and Support plan
The Shuffle Scale and Support plan is made for anyone that wants to operate Shuffle within their own environment, with the option to scale out easily. It includes an upgraded license for the “Orborus” and “Worker” system, and includes regular, continuous support to help with uptime and maintenance of your Shuffle systems. The Shuffle team will spend time with you at the start of our contract to get your supported instance up and running, and provide a point of contact within Shuffle AS. Also included in the plan is assistance building your first workflows, as well as as many integrations as you want based on OpenAPI. This plan is aimed at growing together, and uses scalable pricing, starting at $75/core. As we grow together, this will be extended as seen below. 

Cost breakdown - Onprem:
- $75/core/month for the first 32 cores
- $60/core/month for the next 32 cores
- After $60/month, custom pricing is advised.		


If the customer has more throughput than what their paid infrastructure can handle, Shuffle can not and will not guarantee high availability of Shuffle and its services, unless more computational resources are made available. In the case Shuffle has helped scope and decide the amount of computational resources necessary to handle the amount of throughput, but these are underestimated or further scale is required because of the underestimation, this does not lead to further costs on the side of the customer until contract renegotiations.

About the Shuffle Cloud plan
The Shuffle Cloud plan is made for anyone that wants to use Shuffle as a Service (SaaS), without worrying about infrastructure or scalability. The Cloud plan includes, but is not limited to access to Multi-Tenancy, Multi-Region and an unlimited amount of Workflows, Users, Apps and Organizations, Workflows as Functions and more. Features such as Multi-Environments and running Workflows and their Actions on-premises are also available. Additional features added over time, will be made immediately available to the customer as it is released to their specific region. The pricing structure is based on the amount of App Runs completed per month. The Shuffle team will spend time with you at the start of the contract to make sure we can fully support your Apps and API’s, and will be available for followup sessions to help with your automation needs, and provide a point of contact within Shuffle AS. 

Cost possibilities - Cloud:	
- Pay As you Go - $0.0042/App Run
- Bulk Pricing  - $180/100k App Runs/month
- After 1m App Runs/month, custom pricing is advised

Support
Support will be provided by our experienced team of customer engineers. We will provide expert guidance and / or support with upgrades, solution configuration, deployment and bug fixes. Support further includes help with deployment, and additionally periodic health checks twice a year. This includes a maximum of 16 hours of support the first month, and 8 hours of support per month the following months. Hours above these times incurs hourly on the consultancy rate. Our initial response time for critical issues like service downtime is 2 hours, with normal inquiries having a response time of 24 hours. 

Hybrid Cloud Access
Shuffle Cloud access is a part of Shuffle Open Source, and gives the customer access to features which aren’t feasible without the cloud integrations. This includes such features as Cloud Triggers, Configuration backups, workflow recommendations, a search engine. It will further be extended by new features as they become available, such as notifications and platform recommendations, New Triggers, App, playbook downloads, a cloud search engine and more. Hybrid Cloud can be enabled by following the Organization management documentation found here: https://shuffler.io/docs/organizations. All future features that are made for our Software-As-A-Service offering will be made accessible from the day they are implemented. All limits are soft limits which can be seen for each individual Organization in their Admin dashboard. Default limits include 10.000 app executions, 1000 emails and 300 SMS for free each month, with the addition of multi-tenant cloud environments to enable hybrid for each on-premises organization. If the limits are exceeded over multiple periods (>=2 months), Shuffle may stop access to either of these features after notifying the customer. 

Training
Training is not included by default. Training for Shuffle happens at a time agreed upon by Shuffle and Customer, and is accessible for up to 5 people. It is a two-day online course with a trainer from Shuffle (2x4 hours), and includes but is not limited to: Workflow Development, App Development and Debugging, Organizational Control, Execution exploration and Information searching. 

The normal cost for this training is $4999.

Consultancy
Consultancy gives you access to Non-recurring engineering (NRE), advice and process improvement by the experienced Shuffle team. NRE is any special development required that is not Integration or Workflow development, but special development of the Shuffle platform itself. Advice and process improvements are part of our goal to help operations teams work more effectively, and in a more standardized manner. 

Custom Shuffle App Development
Custom App Development in Shuffle incurs when the customer requires an integration or extension which Shuffle doesn’t already have a developed version of. We will develop the necessary functions of the App, as well as any Action the Customer sees necessary for future use-cases. This process is typically started based on a use-case, where Shuffle will help identify the needs of the customer. If this is not proprietary software, Shuffle will share the use-cases with the community to further support the community, and if agreed upon, Shuffle will add information about the Customer as the sponsor and/or creator of the App. 

Custom Workflow Development
Custom Workflow Development in Shuffle incurs when the customer requires a process to be automated with the help of Shuffle automation experts. If the workflow requires custom App Creation to fulfill the request, this does not incur extra hours of app development. Workflow development will start with a conversation between Shuffle and Customer to define our goals, before Customer gives access to a demo environment of the required tools if applicable. If this is not proprietary software or processes, Shuffle will share the use-cases with the community to further support the community, and if agreed upon, Shuffle will add information about the Customer as the sponsor and/or creator of the Workflow.

The goals of the Proof of Value are as follows:

Support plan
Roles
The Account Executive (AE)
The Account Executive (AE) at Shuffle is the one who is responsible for prospecting customers and finding out whether or not the customer is a good fit for Shuffles’ services in the first place. Along with prospecting, The Account Executive works with the inside sales team to follow up with meetings for generated leads. The AE also works with the Pre-Sales Engineer to not only uncover pain points, but also strategize to translate current problems to solutions that the Shuffle Console solves.

The Account Executive is further tasked with telling the Shuffle story and explaining to the customer the vision that Shuffle has for our services. The big message that the Account Executive should get across is the economics behind Shuffle’s services. It is a lot cheaper for Shuffle to manage the customers’ Shuffle instance and provide the customer with additional add-ons, rather than trying to get internal staff fully up to speed on the product without training. Additionally, the account executive is the one who must submit the necessary documents such as the Deal Reg, NDA, MSA, SOW, RFP, and any other formal proposal documents to the customer for signature.

Automation Specialist (AS)
The Automation Specialist is the engineer assigned to ensure the customer’s automation needs are fulfilled as per the SLA. They will work with the TAM during the initialization and onboarding phase for default use-case implementations, and be the consultant for any extra service the customer may need. They may further work with the AE, TAM and developers to provide custom resources and training to the customer to ensure they understand the environment they are working with.

The Technical Account Manager (TAM)
The Technical Account Manager (TAM) is essentially the Tier III support engineer for a Shuffle customer. A TAM is assigned to a Shuffle customer as soon as the deal has been executed by the Account Executive, and becomes the primary point of contact for the customer. The Technical Account Manager oversees the initial Shuffle implementation and ongoing management phase after the initial deployment is complete. The Technical Account Manager is the one who will conduct the more difficult work of configuring SAML/OIDC, custom scaling configurations, Integration Management, Security Policy and Network Zone Setup and applicable Lifecycle Management configurations. Additionally, the Technical Account Manager may work with the Helpdesk support and Automation Specialists to not only get them up to speed on some more difficult tasks, but also assist them in some of the easier tasks during the initial Shuffle implementation.

After the implementation is complete, the TAM will be held accountable for the management of the customer. The TAM will oversee maintenance of the Shuffle customer, add/remove applications and other technologies to/from the Instance, work with the Shuffle development team for necessary features for the customer, and answer any highly technical questions the customer may have. For SLA purposes, the TAM will handle any major outages the Shuffle customer may experience or any support issue that the Helpdesk support or ATAM is unable to answer on their own. 
The Associate Technical Account Manager (ATAM)
Similarly, to the TAM, the Associate Technical Account Manager (ATAM) is best compared to the Tier II support engineer in any other scenario. During the implementation phase, the ATAM may take over the more remedial tasks such as Integrating customer applications and building out Shuffle workflows according to what the customer needs, together with our Automation specialists. The ATAM further observes the TAM during the more difficult tasks in hopes that one day the ATAM becomes a TAM. 

During the Management phase of the Shuffle implementation, the ATAM handles the day-to-day operations on behalf of the customer as per the defined SLA. These tasks include updating the instance, providing guidance for the customer, working with Helpdesk support etc. The ATAM also takes points on the Helpdesk during work hours. If any request comes through the helpdesk from the ATAM’s customer, then the ATAM is expected to handle and respond to the request as soon as possible. If a request comes through such as a major outage or another request that the ATAM is not capable of handling on his/her own, it is the ATAM’s responsibility to escalate the request to the TAM for remediation. Along with the helpdesk, it is the ATAM’s duty to work with the AE for any required reporting. The ATAM is responsible for pulling the necessary data from the customer’s systems, and preparing it for analysis in the case of custom updates.

The ATAM may be working as a partner of Shuffle to be able to cover business hours in certain geographical areas. Introduction and building will be discussed with the customer and partner, and be a part of the onboarding phase.
Tier I Helpdesk Support
The General Tier I Helpdesk Support role will serve as the helpdesk Point of Contact during the limited after-hours time window as spelled out in the Shuffle SLA. If any request comes up during this off-hours time, it is the Tier I Helpdesk support’s duty to respond to the customer to meet the SLA and then route the request to the TAM or ATAM support for a proper follow-up response to the customer. If the request is not urgent, the Tier I will pass along the ticket to the TAM or ATAM support so that they may begin work on the request the following morning. If the request is super urgent, it is the Tier I’s duty to get a hold of the TAM for immediate action and remediation.

The ATAM may be working as a partner of Shuffle to be able to cover business hours in certain geographical areas. Introduction and building will be discussed with the customer and partner, and be a part of the onboarding phase.
Support priorities

Shuffle’s support team will provide support via remote assistance. All requests will be performed via email or our support portal. Critical events can be performed by phone, and we will provide you with an alert email to reach us at any time after you have accepted this EULA and paid for Shuffle's services.

Priority
Business Impact


Critical
Trouble conditions where Shuffle is completely out of service, and is causing business impact to the customer.

High
Trouble conditions where Shuffle is not fully functional, and is causing business impact to the customer.

Medium
Trouble conditions where Shuffle is not fully functional, but is not causing business impact to the customer.

Low
Any condition or request that is not causing business impact to the customer. Further used for information exchange.

Standard maintenance and support
We provide technical support Monday through Friday, between 9:00AM - 3:00PM excluding holidays*.

Our team will make commercially reasonable efforts to respond within 8 business hours from the receipt of a trouble notification. Response times will vary depending on the severity of the notification.

Our team will make reasonable efforts to respond within 4 hours to emergency priority one (P1) and priority two (P2) issues.


Offboarding
If the customer stops using Shuffle’s services, all the information provided during onboarding and maintenance will still be available to the customer. The customer will lose access to the extra resources provided by the chosen subscription, but retain access to their organization, users, workflows, apps etc. Shuffle will further want to have a conversation with the customer to ensure Shuffle’s services will improve in all steps.

Disaster recovery & Business continuity
Shuffle’s cloud services run completely on GCP and use GCP serverless functionality all around the world as redundant systems to ensure that customers can reliably access their active utilities. 

In the case of problems with a self-hosted version of Shuffle, the TAM will work with the customer to provide the services necessary to get their instance up and running at full capacity.

In the case of complete failures with GCP, it is likely to be resolved in a number of hours, but the service failure also translates to a complete failure of GCP. This would mean that other services running on GCP have also failed too. If a customer strongly desires to get access to certain information during the outage, the TAM or ATAM will work with the customer’s IT team to access the required information. This may require extra verification of the person asking, as to verify whether they work with the customer or not.

Once GCP and Shuffle come back online, Shuffle will work with the customer to ensure any and all use-cases affected by the outage will be running again at full capacity.

If Shuffle on GCP is completely offline for an extended period of time (2+ days), Shuffle will work with the customer to figure out a contingency plan to ensure the environment works as expected.

In the case of circumstances outside of Shuffle’s control such as sickness or deaths, preventing the contract to be fulfilled by Shuffle directly, Shuffle’s partner Infopercept will take over all operations for the customer. Infopercept has certain access rights, allowing them to take over and host the Shuffle cloud platform by themselves under these circumstances, and have certain extra access due to support fulfillment.



Non-disclosure 
Shuffle will not disclose any information about the customer to any third party, unless the customer has given explicit permission to do so. This includes, but is not limited to, the customer’s name, address, contact information, and any other information that may be considered sensitive.

When information is shared between our entities, the receiving Party acknowledges that the disclosing Party retains proprietary rights and intellectual property rights in the Confidential Information disclosed to the receiving Party, and that the disclosure of such Confidential Information shall not be deemed to confer upon the receiving Party any rights or intellectual property rights whatsoever in respect of any part thereof.



Payment options
The default payment option is by paying through the Shuffle website https://shuffler.io/pricing. We further accept bank transfer if necessary.


Trial or Proof of Value (POV) 
If you have started a Proof-of-Value or Trial with Shuffle, and you want to end the trial, you can do so at any time. When the Trial or POV ends, the customer needs to decide whether to continue by paying Shuffle, or stop the Trial, losing access to any software and support, previously supplied by Shuffle. POV can be extended if needed, but will be discussed with the customer and Shuffle. The maximum length of a Trial or POV is 3 months.

Any payments made will not be refunded. If your license includes special software, the customer will lose access to this software, and has a maximum 30 day limit to remove the software from the time of contract end. The customer will still have access to their organization, users, workflows, apps etc. Shuffle will further want to have a conversation with the customer to ensure Shuffle’s services will improve in all steps.


End of Contract
If the customer wants to end the contract, the customer can do so at any time. The customer will still have access to their data, but will lose access to the extra resources provided by the chosen subscription. Any payments made will not be refunded. If your license includes special software, the customer will lose access to this software, and has a maximum 30 day limit to remove the software from the time of contract end. The customer will still have access to their organization, users, workflows, apps etc. Shuffle will further want to have a conversation with the customer to ensure Shuffle’s services will improve in all steps.


License Auditing
Shuffle may at any time, without warning, audit whether your are overutilizing your license in Shuffle. There are no hard limits when a license is bought, and any overutilization will be discussed with the customer. If the customer is overutilizing their license, the customer will be given a warning and a chance to fix the issue. If the issue is not fixed, Shuffle reserves the right to terminate the contract with the customer.


Misuse
Shuffle may temporarily suspend or limit access to the Platform if usage: (i) exceeds the scope of the license specified in this Agreement, (ii) unduly burdens the Platform, or, (iii) is otherwise inconsistent with normal usage. In any such event, Shuffle will get in contact to review and attempt to resolve the matter. Shuffle may charge, and the Customer will pay any costs associated with any such misuse if Customer fails to respond to and address the matter in a timely manner, not to exceed three (3) business day after Shuffle’s initial contact.

If you want this contract in PDF format to sign instead of as a digital End User License Agreement, please contact us at support@shuffler.io`)
}

// Should become a proper backend thing LOL
func GetUsecaseData() string {
	return (`[
    {
        "name": "1. Collect",
        "color": "#FB47A0",
        "list": [
            {
                "name": "Email management",
				"priority": 100,
				"type": "communication",
				"last": "cases", 
                "items": {
                    "name": "Release a quarantined message",
                    "items": {}
                }
            },
            {
                "name": "EDR to ticket",
				"priority": 100,
				"type": "edr",
				"last": "cases",
                "items": {
                    "name": "Get host information",
                    "items": {}
                }
            },
            {
                "name": "SIEM to ticket",
				"priority": 100,
				"type": "siem",
				"last": "cases",
				"description": "Ensure tickets are forwarded to the correct destination. Alternatively add enrichment on its way there.",
				"video": "https://www.youtube.com/watch?v=FBISHA7V15c&t=197s&ab_channel=OpenSecure",
				"blogpost": "https://medium.com/shuffle-automation/introducing-shuffle-an-open-source-soar-platform-part-1-58a529de7d12",
				"reference_image": "/images/detectionframework.png",
                "items": {}
            }        
		]
    },
    {
        "name": "2. Enrich",
        "color": "#f4c20d",
        "list": [
            {
                "name": "Internal Enrichment",
				"priority": 100,
				"type": "intel",
                "items": {
                    "name": "...",
                    "items": {}
                }
            },
            {
                "name": "External historical Enrichment",
				"priority": 90,
				"type": "intel",
                "items": {
                    "name": "...",
                    "items": {}
                }
            },
            {
                "name": "Sandbox",
				"priority": 60,
				"type": "intel",
                "items": {
                    "name": "Use a sandbox to analyze",
                    "items": {}
                }
            }
        ]
    },
    {
        "name": "3. Detect",
        "color": "#3cba54",
        "list": [
            {
                "name": "Search SIEM (Sigma)",
				"priority": 90,
				"type": "siem",
				"last": "cases",
                "items": {
                    "name": "Endpoint",
                    "items": {}
                }
            },
            {
                "name": "Search EDR (OSQuery)",
				"type": "edr",
				"priority": 90,
				"last": "cases",
                "items": {}
            },
            {
                "name": "Search emails (Sublime)",
				"priority": 90,
				"type": "communication",
				"last": "cases",
                "items": {
                    "name": "Check headers and IOCs",
                    "items": {}
                }
            },
            {
                "name": "Automate Threathunt (Kestrel)",
				"priority": 50,
				"type": "edr",
				"last": "cases",
                "items": {}
            },
            {
                "name": "Search IOCs (ioc-finder)",
				"priority": 50,
				"type": "intel",
				"last": "cases",
                "items": {}
            },
            {
                "name": "Search files (Yara)",
				"priority": 50,
				"type": "intel",
				"last": "cases",
                "items": {}
            },
            {
                "name": "Memory Analysis (Volatility)",
				"priority": 50,
				"type": "intel",
                "items": {}
            },
            {
                "name": "IDS & IPS (Snort/Surricata)",
				"priority": 50,
				"type": "network",
				"last": "cases",
                "items": {}
            },
            {
                "name": "Honeypot access",
				"priority": 50,
				"type": "network",
				"last": "cases",
                "items": {
                    "name": "...",
                    "items": {}
                }
            }
        ]
    },
    {
        "name": "4. Respond",
        "color": "#4885ed",
        "list": [
            {
                "name": "Isolate Host",
				"old_name": "Quarantine host(s)",
				"priority": 80,
				"type": "edr",
                "items": {}
            },
            {
                "name": "Block an IP",
				"old_name": "Block IPs, URLs, Domains and Hashes",
				"priority": 75,
				"type": "network",
                "items": {}
            },
            {
                "name": "Kill a process",
				"priority": 50,
				"type": "edr",
                "items": {}
            },
            {
                "name": "Lock account",
				"old_name": "Lock/Delete/Reset account",
				"priority": 70,
				"type": "iam",
                "items": {}
            }
        ]
    },
    {
        "name": "5. Verify",
        "color": "#7f00ff",
        "list": [
            {
                "name": "Discover vulnerabilities",
								"priority": 80,
								"type": "assets",
                "items": {}
            },
            {
                "name": "Discover assets",
				"priority": 80,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Ensure policies are followed",
				"priority": 80,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Find Inactive users",
				"priority": 50,
				"type": "iam",
                "items": {}
            },
            {
                "name": "Botnet tracker",
				"priority": 50,
				"type": "network",
                "items": {}
            },
            {
                "name": "Ensure access rights match HR systems",
				"priority": 50,
				"type": "iam",
                "items": {}
            },
            {
                "name": "Ensure onboarding is followed",
				"priority": 50,
				"type": "iam",
                "items": {}
            },
            {
                "name": "Track third party SaaS apps",
				"priority": 50,
				"type": "iam",
                "items": {}
            },
            {
                "name": "Devices used for your cloud account",
				"priority": 50,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Too much access in GCP/Azure/AWS other clouds",
				"priority": 50,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Certificate validation",
				"priority": 50,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Monitor domain creation and expiration",
				"priority": 50,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Monitor new DNS entries for domain with passive DNS",
				"priority": 50,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Monitor and track password dumps",
				"priority": 50,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Monitor for mentions of domain on darknet sites",
				"priority": 50,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Reporting",
				"priority": 50,
				"type": "assets",
				"keywords": ["report", "reporting", "sheets", "excel"],
				"keyword_matches": 1,
                "items": {
                    "name": "Monthly reports",
                    "items": {
                        "name": "...",
                        "items": {}
                    }
                }
            }
        ]
    }
]`)
}

func GetTriggerData(triggerType string) string {
	switch strings.ToLower(triggerType) {
	case "webhook":
		return "data:image/png;base64,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"
	case "schedule":
		return "data:image/png;base64,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"
	default:
		return ""
	}
}
							
func getIocIngestionScript() string {
	return `import os
import re
import json
import uuid
import time
import requests

input_data = json.loads(r'''$get_threatlist_urls''')
upload_url = f"{self.base_url}/api/v2/datastore?bulk=true"

parsed_headers = {}
if len(os.environ.get("SHUFFLE_AUTHORIZATION", "")) > 0:
  parsed_headers["Authorization"] = "Bearer %s" % os.environ.get("SHUFFLE_AUTHORIZATION", "")
else:
  upload_url += f"&authorization={self.authorization}&execution_id={self.current_execution_id}" 

# This is shitty, but is used for a basic test. 
regexsearch = {
  "md5": r"\b[a-fA-F0-9]{32}\b",
  "sha1": r'\b[a-fA-F0-9]{40}\b',
  "sha256": r"\b[a-fA-F0-9]{64}\b",
  "ip": r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.|$)){4}\b",
  "domain": r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b",
}

all_items = {
  "md5": {},
  "sha1": {},
  "sha256": {},
  "ip": {},
  "domain": {},
}

if not isinstance(input_data, list):
  input_data = [input_data]

## Assuming
max_items = 1000
threat_timeout = 90 # days
for content in input_data:
  iocs = content["body"]

  found_type = ""
  searchspace = iocs[0:1000]
  for key, value in regexsearch.items():
    match = re.search(value, searchspace)
    if match:
      found_type = key
      break

  if len(found_type) == 0:
    continue

  appended_items = []
  discovered_split_index = -1
  datestamp_index = -1

  cnt = 0
  for line in iocs.split("\n"):
    if len(line) < 3:
      continue

    if line.startswith("#"):
      continue

    if cnt > max_items:
      continue

    # Remove ANYTHING after # on the line
    line = line.split("#")[0].strip()

    linesplit = line.split(",")
    if discovered_split_index >= 0:
      if datestamp_index >= 0:
        # Check if the timestamp is more than 90 days ago (threat_timeout)
        try:
          timestamp = time.strptime(linesplit[datestamp_index], "%Y-%m-%d %H:%M:%S")
          current_time = time.time()
          if (current_time - time.mktime(timestamp)) / (24 * 3600) > threat_timeout:
            continue
        except ValueError:
          continue

      appended_items.append(linesplit[discovered_split_index])

    else:
      # Discovering pattern
      cnt += 1
      linesplit = line.split(",")
      if len(linesplit) == 1:
        discovered_split_index = 0
      else:
        itemcnt = 0

        for item in linesplit:
          # Check if item is a timestamp
          import time
          try:
            time.strptime(item, "%Y-%m-%d %H:%M:%S")
            datestamp_index = itemcnt

            # Check if the timestamp is more than 90 days ago. If so, break and continue
          except ValueError:
            pass

          match = re.search(regexsearch[found_type], item)
          if match:
            discovered_split_index = itemcnt
            break

          itemcnt += 1

        if discovered_split_index >= 0:
          appended_items.append(linesplit[discovered_split_index])

  # Parsing STIX
  for item in appended_items:
    key = item.strip()

    if key in all_items:
      if content["url"] not in all_items[found_type][key]["urls"]:
              all_items[found_type][key] = all_items[found_type][key]["urls"].append(content["url"])
    else:

      # Silly workaround to ensure we got a good UUID
      # But keeping it deterministic for now
      static_namespace = "c59d2471-df00-48ae-bc18-dd76e84a60df"
      stix_id = f"indicator--{uuid.uuid5(uuid.UUID(static_namespace), key)}"

      stix_pattern = ""
      if found_type == "md5":
        stix_pattern = "[file:hashes.MD5 = '%s']" % (key)
      elif found_type == "sha1":
        stix_pattern = "[file:hashes.SHA1 = '%s']" % (key)
      elif found_type == "sha256":
        stix_pattern = "[file:hashes.SHA256 = '%s']" % (key)
      elif found_type == "ip":
        stix_pattern = "[ipv4-addr:value = '%s']" % (key)
      elif found_type == "domain":
        stix_pattern = "[domain-name:value = '%s']" % (key)

      all_items[found_type][key] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id,
        "pattern": stix_pattern,
        "pattern_type": "stix",

        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),

		"x_raw_pattern": key,
        "urls": [content["url"]],
      }

for k, v in all_items.items():
    new_list = []

    cnt = 0
    for subkey, subval in v.items():
        subval["external_references"] = []
        for url in subval["urls"]:
            subval["external_references"].append({
                "source_name": "threatfeed",
                "url": url,
            })

        del subval["urls"]
        new_list.append({
            "key": subkey,
            "category": "%s_indicators" % k,
            "value": json.dumps(subval),
        })

        cnt += 1
        #if cnt == 100:
        #    break

    if len(new_list) > 0:
        print("Uploading %s items of type %s" % (len(new_list), k))
        ret = requests.post(upload_url, json=new_list, headers=parsed_headers)
        print(ret.text)
        print(ret.status_code)
	`
}
