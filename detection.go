package shuffle

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"errors"
	"sort"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
	"gopkg.in/yaml.v2"
)

func HandleGetDetectionRules(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get detection rules: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Extract detection_type
	location := strings.Split(request.URL.String(), "/")
	if len(location) < 5 {
		log.Printf("[WARNING] Path too short: %d", len(location))
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	detectionType := strings.ToLower(location[4])
	log.Printf("[AUDIT] User '%s' (%s) is trying to get detections from namespace %#v", user.Username, user.Id, detectionType)

	ctx := GetContext(request)
	files, err := GetAllFiles(ctx, user.ActiveOrg.Id, detectionType)
	if err != nil && len(files) == 0 {
		log.Printf("[ERROR] Failed to get files: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Error getting files."}`))
		return
	}

	log.Printf("[DEBUG] Loaded %d files for user %s from namespace %s", len(files), user.Username, detectionType)

	disabledRules, err := GetDisabledRules(ctx, user.ActiveOrg.Id)
	if err != nil && err.Error() != "rules doesn't exist" {
		log.Printf("[ERROR] Failed to get disabled rules: %s", err)
		//resp.WriteHeader(500)
		//resp.Write([]byte(`{"success": false, "reason": "Error getting disabled rules."}`))
		//return
	}

	sort.Slice(files[:], func(i, j int) bool {
		return files[i].UpdatedAt > files[j].UpdatedAt
	})

	var sigmaFileInfo []DetectionFileInfo

	for _, file := range files {
		if file.OrgId != user.ActiveOrg.Id {
			continue
		}

		var fileContent []byte

		if file.Encrypted {
			if project.Environment == "cloud" || file.StorageArea == "google_storage" {
				log.Printf("[ERROR] No namespace handler for cloud decryption (detection)!")
				//continue
			} else {
				Openfile, err := os.Open(file.DownloadPath)
				if err != nil {
					log.Printf("[ERROR] Failed to open file %s: %s", file.Filename, err)
					continue
				}
				defer Openfile.Close()

				allText := []byte{}
				buf := make([]byte, 1024)
				for {
					n, err := Openfile.Read(buf)
					if err == io.EOF {
						break
					}

					if err != nil {
						log.Printf("[ERROR] Failed to read file %s: %s", file.Filename, err)
						continue
					}

					if n > 0 {
						allText = append(allText, buf[:n]...)
					}
				}

				passphrase := fmt.Sprintf("%s_%s", user.ActiveOrg.Id, file.Id)
				if len(file.ReferenceFileId) > 0 {
					passphrase = fmt.Sprintf("%s_%s", user.ActiveOrg.Id, file.ReferenceFileId)
				}

				decryptedData, err := HandleKeyDecryption(allText, passphrase)
				if err != nil {
					log.Printf("[ERROR] Failed decrypting file %s: %s", file.Filename, err)
					continue
				}

				fileContent = []byte(decryptedData)
			}
		} else {
			fileContent, err = ioutil.ReadFile(file.DownloadPath)
			if err != nil {
				log.Printf("[ERROR] Failed to read file %s: %s", file.Filename, err)
				continue
			}
		}

		var rule DetectionFileInfo
		err = yaml.Unmarshal(fileContent, &rule)
		if err != nil {
			log.Printf("[ERROR] Failed to parse YAML file %s: %s", file.Filename, err)
			continue
		}

		isDisabled := disabledRules.DisabledFolder
		found := false
		if isDisabled {
			rule.IsEnabled = false
		} else {
			for _, disabledFile := range disabledRules.Files {
				if disabledFile.Id == file.Id {
					found = true
					break
				}
			}
			if found {
				rule.IsEnabled = false
			} else {
				rule.IsEnabled = true
			}
		}

		rule.FileId = file.Id
		rule.FileName = strings.Trim(file.Filename, ".yml")
		sigmaFileInfo = append(sigmaFileInfo, rule)
	}

	var isTenzirAlive bool
	if time.Now().Unix() > disabledRules.LastActive+10 {
		isTenzirAlive = false
	} else {
		isTenzirAlive = true
	}

	response := DetectionResponse{
		DetectionName: detectionType,
		Category:      "",
		OrgId:         user.ActiveOrg.Id,

		DetectionInfo:     sigmaFileInfo,
		FolderDisabled:    disabledRules.DisabledFolder,
		IsConnectorActive: isTenzirAlive,
	}

	detections := GetPublicDetections()
	for _, detection := range detections {
		if strings.ToLower(detection.DetectionName) != strings.ToLower(response.DetectionName) {
			continue
		}

		response.Title = detection.Title
		response.Category = detection.Category
		response.DownloadRepo = detection.DownloadRepo
		break
	}

	responseData, err := json.Marshal(response)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal response data: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Error processing rules."}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(responseData)
}

func HandleToggleRule(resp http.ResponseWriter, request *http.Request) {
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

		fileId = location[5]
	}
	ctx := GetContext(request)

	if len(fileId) != 36 && !strings.HasPrefix(fileId, "file_") {
		log.Printf("[WARNING] Bad format for fileId %s", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Badly formatted fileId"}`))
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in toggle rule: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	file, err := GetFile(ctx, fileId)
	if err != nil {
		log.Printf("[ERROR] File %s not found: %s", fileId, err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "File not found"}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to delete files: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	var action string
	switch location[6] {
	case "disable_rule":
		action = "disable"
	case "enable_rule":
		action = "enable"
	default:
		log.Printf("[WARNING] path not found: %s", location[6])
		resp.WriteHeader(404)
		resp.Write([]byte(`{"success": false, "message": "The URL doesn't exist or is not allowed."}`))
		return
	}

	if action == "disable" {
		err := disableRule(*file)
		if err != nil {
			log.Printf("[ERROR] Failed to %s file", action)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	} else if action == "enable" {
		err := enableRule(*file)
		if err != nil {
			if err.Error() != "rules doesn't exist" {
				log.Printf("[ERROR] Failed to %s file, reason: %s", action, err)
				resp.WriteHeader(404)
				resp.Write([]byte(`{"success": false}`))
				return
			} else {
				log.Printf("[ERROR] Failed to %s file, reason: %s", action, err)
				resp.WriteHeader(500)
				resp.Write([]byte(`{"success": false}`))
				return
			}
		}
	}

	var execType string

	if action == "disable" {
		execType = "DISABLE_SIGMA_FILE"
	} else if action == "enable" {
		execType = "ENABLE_SIGMA_FILE"
	}

	err = SetDetectionOrborusRequest(ctx, user.ActiveOrg.Id, execType, file.Filename, "SIGMA", "SHUFFLE_DISCOVER")
	if err != nil {
		log.Printf("[ERROR] Failed setting workflow queue for env: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte((`{"success": true}`)))
}

func HandleFolderToggle(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in toggle folder: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to toggle folder: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")
	if location[1] != "api" || len(location) < 6 {
		log.Printf("Path too short or incorrect: %s", request.URL.String())
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := GetContext(request)
	action := location[5]

	rules, err := GetDisabledRules(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Cannot get the rules, reason %s", err)
		resp.WriteHeader(404)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if action == "disable_folder" {
		rules.DisabledFolder = true
	} else if action == "enable_folder" {
		rules.DisabledFolder = false
	} else {
		log.Printf("[WARNING] path not found: %s", action)
		resp.WriteHeader(404)
		resp.Write([]byte(`{"success": false, "message": "The URL doesn't exist or is not allowed."}`))
		return
	}

	err = StoreDisabledRules(ctx, *rules)
	if err != nil {
		log.Printf("[ERROR] Failed to store disabled rules: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	var execType string
	if action == "disable_folder" {
		execType = "DISABLE_SIGMA_FOLDER"
	} else {
		execType = "CATEGORY_UPDATE"
	}

	err = SetDetectionOrborusRequest(ctx, user.ActiveOrg.Id, execType, "", "SIGMA", "SHUFFLE_DISCOVER")
	if err != nil {
		log.Printf("[ERROR] Failed setting workflow queue for env: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func disableRule(file File) error {
	ctx := context.Background()
	resp, err := GetDisabledRules(ctx, file.OrgId)
	if err != nil {
		if err.Error() == "rules doesn't exist" {
			// FIX ME :- code duplication : (
			disabRules := &DisabledRules{}
			disabRules.Files = append(disabRules.Files, file)
			err = StoreDisabledRules(ctx, *disabRules)
			if err != nil {
				return err
			}

			log.Printf("[INFO] file with ID %s is disabled successfully", file.Id)
			return nil
		} else {
			return err
		}
	}

	resp.Files = append(resp.Files, file)
	err = StoreDisabledRules(ctx, *resp)
	if err != nil {
		return err
	}

	log.Printf("[INFO] file with ID %s is disabled successfully", file.Id)
	return nil
}

func enableRule(file File) error {
	ctx := context.Background()
	resp, err := GetDisabledRules(ctx, file.OrgId)
	if err != nil {
		return err
	}

	// Check if resp.Files is empty
	if len(resp.Files) == 0 {
		log.Printf("[INFO] No disabled rules found.")
		return nil
	}

	found := false
	for i, innerFile := range resp.Files {
		if innerFile.Id == file.Id {
			resp.Files = append(resp.Files[:i], resp.Files[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		log.Printf("[INFO] File with ID %s not found in disabled rules", file.Id)
		return nil
	}

	err = StoreDisabledRules(ctx, *resp)
	if err != nil {
		return err
	}

	log.Printf("[INFO] File with ID %s is enabled successfully", file.Id)
	return nil
}

func HandleGetSelectedRules(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}
	_, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get env stats executions: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	var triggerId string
	location := strings.Split(request.URL.String(), "/")
	if len(location) < 5 || location[1] != "api" {
		log.Printf("[INFO] Path too short or incorrect: %d", len(location))
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	triggerId = location[4]

	selectedRules, err := GetSelectedRules(request.Context(), triggerId)
	if err != nil {
		if err.Error() != "rules doesnt exists" {
			log.Printf("[ERROR] Error getting selected rules for %s: %s", triggerId, err)
			resp.WriteHeader(http.StatusInternalServerError)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	responseData, err := json.Marshal(selectedRules)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal response data: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false"}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(responseData)
}

func HandleSaveSelectedRules(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in save selected rules: %s", err)
		resp.WriteHeader(http.StatusUnauthorized)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to save rules: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(http.StatusForbidden)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")
	if len(location) < 5 || location[1] != "api" {
		log.Printf("[INFO] Path too short or incorrect: %d", len(location))
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	triggerId := location[4]

	selectedRules := SelectedDetectionRules{}

	decoder := json.NewDecoder(request.Body)
	err = decoder.Decode(&selectedRules)
	if err != nil {
		log.Printf("[ERROR] Failed to decode request body: %s", err)
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte(`{"success": false, "reason": "Invalid request body"}`))
		return
	}

	err = StoreSelectedRules(request.Context(), triggerId, selectedRules)
	if err != nil {
		log.Printf("[ERROR] Error storing selected rules for %s: %s", triggerId, err)
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	responseData, err := json.Marshal(selectedRules)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal response data: %s", err)
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(http.StatusOK)
	resp.Write(responseData)
}

// FIXME: Should be generic - not just for SIEM/Sigma
// E.g. try for Email/Sublime
func HandleDetectionAutoConnect(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in conenct siem: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Org reader does not have permission to connect to SIEM"}`))
		return
	}

	// Check if url is /api/v1/detections/siem/
	location := strings.Split(request.URL.String(), "/")
	if len(location) < 5 {
		log.Printf("[WARNING] Path too short: %d", len(location))
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	detectionType := strings.ToLower(location[4])
	log.Printf("[DEBUG] Validating if the org %s (%s) has a %s sandbox handling workflow/system", user.ActiveOrg.Name, user.ActiveOrg.Id, detectionType)

	log.Printf("[AUDIT] User '%s' (%s) is trying to detection-connect to %s", user.Username, user.Id, strings.ToUpper(detectionType))

	workflow := Workflow{}
	if detectionType == "siem" {

		ctx := GetContext(request)
		workflow, err = ConfigureDetectionWorkflow(ctx, user.ActiveOrg.Id, "TENZIR-SIGMA")
		if err != nil {
			log.Printf("[ERROR] Failed to create Sigma handling workflow: %s", err)
		}

		log.Printf("[DEBUG] Sending orborus request to start Sigma handling workflow")

		execType := "START_TENZIR"
		err = SetDetectionOrborusRequest(ctx, user.ActiveOrg.Id, execType, "", "SIGMA", "SHUFFLE_DISCOVER")
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "must be started") {
				resp.WriteHeader(200)
				resp.Write([]byte(`{"success": true, "reason": "Please start the environment by running the relevant command.", "action": "environment_start"}`))
				return
			}

			log.Printf("[ERROR] Failed setting workflow queue for env: %s", err)
			if strings.Contains(strings.ToLower(err.Error()), "no valid environments") {
				resp.WriteHeader(400)
				resp.Write([]byte(`{"success": false, "reason": "No valid environments found. Go to /admin?tab=environments to create one.", "action": "environment_create"}`))
				return
			}

			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false}`))
			return
		}


	} else if detectionType == "email" {

		// FIXME:
		// 1. Can we track if it's active based on a workflow + validation?
		// 2. The workflow should get email
		// 3. It should track unread AND read emails separately
		// 4. When a new email is received, we should automatically track the statistics for it

		ctx := GetContext(request)
		workflow, err = ConfigureDetectionWorkflow(ctx, user.ActiveOrg.Id, "EMAIL-DETECTION")
		if err != nil {
			log.Printf("\n\n\n[ERROR] Failed to create email handling workflow: %s\n\n\n", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed to create email handling workflow. Please try again or contact support@shuffler.io"}`))
			return
		}

	} else {
		resp.WriteHeader(400)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Detection Type '%s' not implemented"}`, detectionType)))
		return
	}

	success := true
	if len(workflow.ID) == 0 {
		success = false
	} else {
		log.Printf("[INFO] '%s' detection workflow in org '%s' ID: %s", detectionType, workflow.OrgId, workflow.ID)
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": %v, "workflow_id": "%s", "workflow_valid": %v}`, success, workflow.ID, workflow.Validation.Valid)))
}

func SetDetectionOrborusRequest(ctx context.Context, orgId, execType, fileName, executionSource, environmentName string) error {
	if len(orgId) == 0 {
		log.Printf("[ERROR] No org ID provided for Orborus")
		return fmt.Errorf("No org ID provided")
	}

	environments, err := GetEnvironments(ctx, orgId)
	if err != nil {
		log.Printf("[ERROR] Failed to get environments: %s", err)
		return err
	}

	lakeNodes := 0
	selectedEnvironments := []Environment{}
	for _, env := range environments {
		if env.Archived {
			continue
		}

		if env.Type == "cloud" {
			continue
		}

		if env.Name != environmentName && environmentName != "SHUFFLE_DISCOVER" {
			continue
		}

		cacheKey := fmt.Sprintf("queueconfig-%s-%s", env.Name, env.OrgId)
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			newEnv := OrborusStats{}
			err = json.Unmarshal(cache.([]uint8), &newEnv)
			if err == nil {
				// No point in adding a job if the lake is already running 
				if env.DataLake.Enabled && execType == "START_TENZIR" {
					lakeNodes += 1
					continue
				}
			}
		}

		selectedEnvironments = append(selectedEnvironments, env)
	}

	if len(selectedEnvironments) == 0 {
		if lakeNodes > 0 {
			log.Printf("[ERROR] No environments needing a lake. Found lake nodes: %d", lakeNodes)
			return nil
		} else {
			return fmt.Errorf("No valid environments found")
		}
	}

	log.Printf("[DEBUG] Found %d potentially valid environment(s)", len(selectedEnvironments))

	deployedToActiveEnv := false
	for _, env := range selectedEnvironments {
		execRequest := ExecutionRequest{
			Type:              execType,
			ExecutionId:       uuid.NewV4().String(),
			ExecutionSource:   executionSource,
			ExecutionArgument: fileName,
			Priority:          11,
		}

		parsedEnv := fmt.Sprintf("%s_%s", strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(env.Name, " ", "-"), "_", "-")), orgId)
		if project.Environment != "cloud" {
			parsedEnv = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(env.Name, " ", "-"), "_", "-"))
		}

		err = SetWorkflowQueue(ctx, execRequest, parsedEnv)
		if err != nil {
			log.Printf("[ERROR] Failed to set workflow queue: %s", err)
			return err
		} else {
			if env.RunningIp != "" {
				deployedToActiveEnv = true
			}
		}
	}

	if !deployedToActiveEnv {
		return errors.New("This environment must be started first. Please start the environment by running it onprem")
	}

	go DeleteCache(ctx, fmt.Sprintf("environments_%s", orgId))

	return nil
}

func HandleListDetectionCategories(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	/*
		user, err := HandleApiAuthentication(resp, request)
		if err != nil {
			log.Printf("[WARNING] Api authentication failed in get detection rules: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	*/

	publicDetections := GetPublicDetections()
	data, err := json.Marshal(publicDetections)
	if err != nil {
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(data)
}

// FIXME: This is not ready - just a starting point
func ConfigureDetectionWorkflow(ctx context.Context, orgId, workflowType string) (Workflow, error) {
	log.Printf("[ERROR] Creating detection workflow for org %s (not implemented for all types). Type: %s", orgId, workflowType)
	/*
		// FIXME: Use Org to find the correct tools according to the Usecase
		// SHOULD map usecase from workflowType -> actual Usecase in blobs
		foundOrg, err := GetOrg(ctx, orgId)
		if err != nil {
			log.Printf("[ERROR] Failed to get org '%s' during detection workflow creation: %s", err)
			return err
		}
	*/

	user := User{
		Role: "admin",
		ActiveOrg: OrgMini{
			Id: orgId,
		},
	}

	workflows, err := GetAllWorkflowsByQuery(ctx, user, 250, "")
	if err != nil && len(workflows) == 0 {
		log.Printf("[ERROR] Failed to loading workflows to validate email: %s", err)
		return Workflow{}, err
	}

	workflow := Workflow{}
	workflowValid := false
	for _, foundworkflow := range workflows {
		if foundworkflow.WorkflowType != workflowType {
			continue
		}

		if foundworkflow.Validation.Valid {
			workflowValid = true
		}

		workflow = foundworkflow
		break
	}

	_ = workflowValid
	if len(workflow.ID) > 0 {
		return workflow, nil
	}

	workflow = Workflow{
		WorkflowType: workflowType,
		Actions:      []Action{},
		Triggers:     []Trigger{},
	}

	// Do this based on public workflows
	cloudWorkflowId := ""
	usecaseNames := []string{}
	if workflowType == "TENZIR-SIGMA" {
		log.Printf("[INFO] Creating SIEM handling workflow for org %s", orgId)

		// FIXME: Add a cloud workflow id here

	} else if workflowType == "EMAIL-DETECTION" {
		// How do we check what email tool they use?
		//log.Printf("[INFO] Creating email handling workflow for org %s", orgId)

		cloudWorkflowId = "31d1a492-9fe0-4c4a-807d-b44d9cb81fc0"
		usecaseNames = []string{"Search emails (Sublime)"}
	}

	if len(cloudWorkflowId) == 0 {
		return workflow, errors.New("No valid workflow found")
	}

	// Load it in from cloud with a normal GET request
	url := fmt.Sprintf("https://shuffler.io/api/v1/workflows/%s", cloudWorkflowId)
	client := GetExternalClient(url)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("[ERROR] Failed to create request for workflow: %s", err)
		return workflow, err
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed to get workflow from cloud: %s", err)
		return workflow, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Printf("[ERROR] Failed to get workflow from cloud: %s", resp.Status)
		return workflow, errors.New("Failed to get workflow from cloud")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read response body: %s", err)
		return workflow, err
	}

	err = json.Unmarshal(body, &workflow)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal response body: %s", err)
		return workflow, err
	}

	// Clear out and reset IDs
	workflow.Created = time.Now().Unix()
	workflow.ID = uuid.NewV4().String()
	workflow.OrgId = orgId
	workflow.Org = []OrgMini{
		OrgMini{
			Id: orgId,
		},
	}
	workflow.ExecutingOrg = OrgMini{
		Id: orgId,
	}
	workflow.Public = false
	workflow.WorkflowType = workflowType
	workflow.Validation = TypeValidation{}

	for _, usecaseName := range usecaseNames {
		workflow.UsecaseIds = append(workflow.UsecaseIds, usecaseName)
	}

	workflow.ParentWorkflowId = ""
	for actionIndex, _ := range workflow.Actions {
		newId := uuid.NewV4().String()

		if workflow.Start == workflow.Actions[actionIndex].ID {
			workflow.Start = newId
		}

		for branchIndex, _ := range workflow.Branches {
			if workflow.Actions[actionIndex].ID == workflow.Branches[branchIndex].SourceID {
				workflow.Branches[branchIndex].SourceID = newId
			}

			if workflow.Actions[actionIndex].ID == workflow.Branches[branchIndex].DestinationID {
				workflow.Branches[branchIndex].DestinationID = newId
			}
		}

		workflow.Actions[actionIndex].ID = newId
	}

	for triggerIndex, _ := range workflow.Triggers {
		newId := uuid.NewV4().String()

		for branchIndex, _ := range workflow.Branches {
			if workflow.Triggers[triggerIndex].ID == workflow.Branches[branchIndex].SourceID {
				workflow.Branches[branchIndex].SourceID = newId
			}

			if workflow.Triggers[triggerIndex].ID == workflow.Branches[branchIndex].DestinationID {
				workflow.Branches[branchIndex].DestinationID = newId
			}
		}

		workflow.Triggers[triggerIndex].ID = newId

		// FIXME: Check if it's a schedule, then set the interval + start it
		if workflow.Triggers[triggerIndex].TriggerType == "schedule" {
			//workflow.Triggers[triggerIndex].Interval = 60
			for paramIndex, param := range workflow.Triggers[triggerIndex].Parameters {
				if param.Name == "interval" {
					if project.Environment == "cloud" {
						param.Value = "*/5 * * * *"
					} else {
						param.Value = "300"
					}
				}

				workflow.Triggers[triggerIndex].Parameters[paramIndex] = param
			}

			// FIXME: Start the schedule automatically
		}
	}

	/*
		for branchIndex, _ := range workflow.Branches {
			workflow.Branches[branchIndex].ID = uuid.NewV4().String()
		}
	*/

	// FIXME: Add a changeout for ANY schemaless node to use the correct
	// action in it
	log.Printf("[DEBUG] Saving workflow for org %s", orgId)
	err = SetWorkflow(ctx, workflow, workflow.ID)
	if err != nil {
		log.Printf("[ERROR] Failed to set workflow during detection save: %s", err)
		return Workflow{}, err
	}

	return workflow, nil
}
