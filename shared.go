package shuffle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	//"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"

	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"

	"github.com/bradfitz/slice"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/frikky/kin-openapi/openapi2"
	"github.com/frikky/kin-openapi/openapi2conv"
	"github.com/frikky/kin-openapi/openapi3"

	"github.com/satori/go.uuid"
	"google.golang.org/appengine"
)

var project ShuffleStorage
var baseDockerName = "frikky/shuffle"
var SSOUrl = ""
var usecaseData = `[
    {
        "name": "1. Collect",
        "color": "#c51152",
        "list": [
            {
                "name": "Email management",
								"priority": 100,
								"type": "communication",
                "items": {
                    "name": "Release a quarantined message",
                    "items": {}
                }
            },
            {
                "name": "EDR to ticket",
								"priority": 100,
								"type": "edr",
                "items": {
                    "name": "Get host information",
                    "items": {}
                }
            },
            {
                "name": "SIEM to ticket",
								"priority": 100,
								"type": "siem",
								"description": "Ensure tickets are forwarded to the correct destination. Alternatively add enrichment on it's way there.",
								"video": "https://www.youtube.com/watch?v=FBISHA7V15c&t=197s&ab_channel=OpenSecure",
								"blogpost": "https://medium.com/shuffle-automation/introducing-shuffle-an-open-source-soar-platform-part-1-58a529de7d12",
								"reference_image": "/images/detectionframework.png",
                "items": {}
            },
            {
                "name": "2-way Ticket synchronization",
								"priority": 90,
                "items": {}
            },
            {
                "name": "ChatOps",
								"priority": 70,
                "items": {}
            },
            {
                "name": "Threat Intel received",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Assign tickets",
								"priority": 30,
                "items": {}
            },
            {
                "name": "Firewall alerts",
								"priority": 90,
                "items": {
                    "name": "URL filtering",
                    "items": {}
                }
            },
            {
                "name": "IDS/IPS alerts",
								"priority": 90,
                "items": {
                    "name": "Manage policies",
                    "items": {}
                }
            },
            {
                "name": "Deduplicate information",
								"priority": 70,
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
                "items": {
                    "name": "...",
                    "items": {}
                }
            },
            {
                "name": "External historical Enrichment",
								"priority": 90,
                "items": {
                    "name": "...",
                    "items": {}
                }
            },
            {
                "name": "Realtime",
								"priority": 50,
                "items": {
                    "name": "Analyze screenshots",
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
                "items": {
                    "name": "Endpoint",
                    "items": {}
                }
            },
            {
                "name": "Search EDR (OSQuery)",
								"priority": 90,
                "items": {}
            },
            {
                "name": "Search emails (Sublime)",
								"priority": 90,
                "items": {
                    "name": "Check headers and IOCs",
                    "items": {}
                }
            },
            {
                "name": "Search IOCs (ioc-finder)",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Search files (Yara)",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Memory Analysis (Volatility)",
								"priority": 50,
                "items": {}
            },
            {
                "name": "IDS & IPS (Snort/Surricata)",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Validate old tickets",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Honeypot access",
								"priority": 50,
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
                "name": "Eradicate malware",
								"priority": 90,
                "items": {}
            },
            {
                "name": "Quarantine host(s)",
								"priority": 90,
                "items": {}
            },
            {
                "name": "Block IPs, URLs, Domains and Hashes",
								"priority": 90,
                "items": {}
            },
            {
                "name": "Trigger scans",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Update indicators (FW, EDR, SIEM...)",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Autoblock activity when threat intel is received",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Lock/Delete/Reset account",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Lock vault",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Increase authentication",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Get policies from assets",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Run ansible scripts",
								"priority": 50,
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
                "items": {}
            },
            {
                "name": "Discover assets",
								"priority": 80,
                "items": {}
            },
            {
                "name": "Ensure policies are followed",
								"priority": 80,
                "items": {}
            },
            {
                "name": "Find Inactive users",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Botnet tracker",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Ensure access rights match HR systems",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Ensure onboarding is followed",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Third party apps in SaaS",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Devices used for your cloud account",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Too much access in GCP/Azure/AWS/ other clouds",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Certificate validation",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Domain investigation with LetsEncrypt",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Monitor new DNS entries for domain with passive DNS",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Monitor and track password dumps",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Monitor for mentions of domain on darknet sites",
								"priority": 50,
                "items": {}
            },
            {
                "name": "Reporting",
								"priority": 50,
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
]`

func GetContext(request *http.Request) context.Context {
	if project.Environment == "cloud" && len(memcached) == 0 {
		return appengine.NewContext(request)
	}

	return context.Background()
}

func HandleCors(resp http.ResponseWriter, request *http.Request) bool {

	// FIXME - this is to handle multiple frontends in test rofl
	origin := request.Header["Origin"]
	resp.Header().Set("Vary", "Origin")
	if len(origin) > 0 {
		resp.Header().Set("Access-Control-Allow-Origin", origin[0])
		//resp.Header().Set("Access-Control-Allow-Origin", "https://ca.shuffler.io")
		//resp.Header().Set("Access-Control-Allow-Origin", "http://localhost:3002")
	} else {
		resp.Header().Set("Access-Control-Allow-Origin", "http://localhost:4201")
	}
	//resp.Header().Set("Access-Control-Allow-Origin", "http://localhost:8000")
	resp.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, X-Requested-With, remember-me")
	resp.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, POST, PATCH")
	resp.Header().Set("Access-Control-Allow-Credentials", "true")

	if request.Method == "OPTIONS" {
		resp.WriteHeader(200)
		resp.Write([]byte("OK"))
		return true
	}

	return false
}

func Md5sum(data []byte) string {
	hasher := md5.New()
	hasher.Write(data)
	newmd5 := hex.EncodeToString(hasher.Sum(nil))

	return newmd5
}

func Md5sumfile(filepath string) string {
	dat, err := ioutil.ReadFile(filepath)
	if err != nil {
		log.Printf("Error in dat: %s", err)
	}

	hasher := md5.New()
	hasher.Write(dat)
	newmd5 := hex.EncodeToString(hasher.Sum(nil))

	log.Printf("%s: %s", filepath, newmd5)
	return newmd5
}

func randStr(strSize int, randType string) string {

	var dictionary string

	if randType == "alphanum" {
		dictionary = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	if randType == "alpha" {
		dictionary = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	if randType == "number" {
		dictionary = "0123456789"
	}

	var bytes = make([]byte, strSize)
	rand.Read(bytes)
	for k, v := range bytes {
		bytes[k] = dictionary[v%byte(len(dictionary))]
	}

	return string(bytes)
}

func getHOTPToken(secret string, interval int64) (string, error) {

	//Converts secret to base32 Encoding. Base32 encoding desires a 32-character
	//subset of the twenty-six letters A–Z and ten digits 0–9
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}

	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(interval))

	//Signing the value using HMAC-SHA1 Algorithm
	hash := hmac.New(sha1.New, key)
	hash.Write(bs)
	h := hash.Sum(nil)

	// We're going to use a subset of the generated hash.
	// Using the last nibble (half-byte) to choose the index to start from.
	// This number is always appropriate as it's maximum decimal 15, the hash will
	// have the maximum index 19 (20 bytes of SHA1) and we need 4 bytes.
	o := (h[19] & 15)

	var header uint32
	//Get 32 bit chunk from hash starting at the o
	r := bytes.NewReader(h[o : o+4])
	err = binary.Read(r, binary.BigEndian, &header)
	if err != nil {
		return "", err
	}

	//Ignore most significant bits as per RFC 4226.
	//Takes division from one million to generate a remainder less than < 7 digits
	h12 := (int(header) & 0x7fffffff) % 1000000

	//Converts number as a string
	otp := strconv.Itoa(int(h12))

	// Dumb solutions <3
	// This works well, as the numbers are small ^_^
	if len(otp) == 0 {
		otp = "000000"
	} else if len(otp) == 1 {
		otp = fmt.Sprintf("00000%s", otp)
	} else if len(otp) == 2 {
		otp = fmt.Sprintf("0000%s", otp)
	} else if len(otp) == 3 {
		otp = fmt.Sprintf("000%s", otp)
	} else if len(otp) == 4 {
		otp = fmt.Sprintf("00%s", otp)
	} else if len(otp) == 5 {
		otp = fmt.Sprintf("0%s", otp)
	}

	return otp, nil
}

func GetResult(ctx context.Context, workflowExecution WorkflowExecution, id string) (WorkflowExecution, ActionResult) {
	for _, actionResult := range workflowExecution.Results {
		if actionResult.Action.ID == id {
			return workflowExecution, actionResult
		}
	}

	//log.Printf("[WARNING] No result found for %s - add here too?", id)
	cacheId := fmt.Sprintf("%s_%s_result", workflowExecution.ExecutionId, id)
	cache, err := GetCache(ctx, cacheId)
	if err == nil {
		//log.Printf("[DEBUG] Already found %s executed, but not in list.. Adding!\n\n\n\n\n", id)

		actionResult := ActionResult{}
		cacheData := []byte(cache.([]uint8))
		// Just ensuring the data is good
		err = json.Unmarshal(cacheData, &actionResult)
		if err == nil {
			workflowExecution.Results = append(workflowExecution.Results, actionResult)
			SetWorkflowExecution(ctx, workflowExecution, false)
			return workflowExecution, actionResult
		}
	}

	return workflowExecution, ActionResult{}
}

func GetAction(workflowExecution WorkflowExecution, id, environment string) Action {
	for _, action := range workflowExecution.Workflow.Actions {
		if action.ID == id {
			return action
		}
	}

	for _, trigger := range workflowExecution.Workflow.Triggers {
		if trigger.ID == id {
			return Action{
				ID:          trigger.ID,
				AppName:     trigger.AppName,
				Name:        trigger.AppName,
				Environment: environment,
				Label:       trigger.Label,
			}
			log.Printf("FOUND TRIGGER: %#v!", trigger)
		}
	}

	return Action{}
}

func ArrayContainsLower(visited []string, id string) bool {
	found := false
	for _, item := range visited {
		if strings.ToLower(item) == strings.ToLower(id) {
			found = true
		}
	}

	return found
}

func ArrayContains(visited []string, id string) bool {
	found := false
	for _, item := range visited {
		if item == id {
			found = true
		}
	}

	return found
}

func SetAuthenticationConfig(resp http.ResponseWriter, request *http.Request) {
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

	if user.Role != "admin" {
		log.Printf("[AUDIT] User isn't admin during auth edit config")
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Must be admin to perform this action"}`)))
		return
	}

	var fileId string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 5 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[5]
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Error with body read: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	type configAuth struct {
		Id     string `json:"id"`
		Action string `json:"action"`
	}

	var config configAuth
	err = json.Unmarshal(body, &config)
	if err != nil {
		log.Printf("Failed unmarshaling (appauth): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if config.Id != fileId {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Bad ID match"}`))
		return
	}

	ctx := GetContext(request)
	auth, err := GetWorkflowAppAuthDatastore(ctx, fileId)
	if err != nil {
		log.Printf("Authget error: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": ":("}`))
		return
	}

	if auth.OrgId != user.ActiveOrg.Id {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "User can't edit this org"}`))
		return
	}

	if config.Action == "assign_everywhere" {
		log.Printf("[INFO] Should set authentication config")
		baseWorkflows, err := GetAllWorkflowsByQuery(ctx, user)
		if err != nil && len(baseWorkflows) == 0 {
			log.Printf("Getall error in auth update: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed getting workflows to update"}`))
			return
		}

		workflows := []Workflow{}
		for _, workflow := range baseWorkflows {
			if workflow.OrgId == user.ActiveOrg.Id {
				workflows = append(workflows, workflow)
			}
		}

		// FIXME: Add function to remove auth from other auth's
		actionCnt := 0
		workflowCnt := 0
		authenticationUsage := []AuthenticationUsage{}
		for _, workflow := range workflows {
			newActions := []Action{}
			edited := false
			usage := AuthenticationUsage{
				WorkflowId: workflow.ID,
				Nodes:      []string{},
			}

			for _, action := range workflow.Actions {
				if action.AppName == auth.App.Name {
					action.AuthenticationId = auth.Id

					edited = true
					actionCnt += 1
					usage.Nodes = append(usage.Nodes, action.ID)
				}

				newActions = append(newActions, action)
			}

			workflow.Actions = newActions
			if edited {
				//auth.Usage = usage
				authenticationUsage = append(authenticationUsage, usage)
				err = SetWorkflow(ctx, workflow, workflow.ID)
				if err != nil {
					log.Printf("Failed setting (authupdate) workflow: %s", err)
					continue
				}

				cacheKey := fmt.Sprintf("%s_workflows", user.Id)

				DeleteCache(ctx, cacheKey)

				workflowCnt += 1
			}
		}

		//Usage         []AuthenticationUsage `json:"usage" datastore:"usage"`
		log.Printf("[INFO] Found %d workflows, %d actions", workflowCnt, actionCnt)
		if actionCnt > 0 && workflowCnt > 0 {
			auth.WorkflowCount = int64(workflowCnt)
			auth.NodeCount = int64(actionCnt)
			auth.Usage = authenticationUsage
			auth.Defined = true

			err = SetWorkflowAppAuthDatastore(ctx, *auth, auth.Id)
			if err != nil {
				log.Printf("Failed setting appauth: %s", err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "Failed setting app auth for all workflows"}`))
				return
			} else {
				// FIXME: Remove ALL workflows from other auths using the same
			}
		}
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
	//var config configAuth

	//log.Printf("Should set %s
}

func HandleCategoryIncrease(categories Categories, action Action, workflowapps []WorkflowApp) Categories {
	if action.Category == "" {
		appName := action.AppName
		for _, app := range workflowapps {
			if appName != strings.ToLower(app.Name) {
				continue
			}

			if len(app.Categories) > 0 {
				log.Printf("[INFO] Setting category for %s: %s", app.Name, app.Categories)
				action.Category = app.Categories[0]
				break
			}
		}

		//log.Printf("Should find app's categories as it's empty during save")
		return categories
	}

	//log.Printf("Action: %s, category: %s", action.AppName, action.Category)
	// FIXME: Make this an "autodiscover" that's controlled by the category itself
	// Should just be a list that's looped against :)
	newCategory := strings.ToLower(action.Category)
	if strings.Contains(newCategory, "case") || strings.Contains(newCategory, "ticket") || strings.Contains(newCategory, "alert") || strings.Contains(newCategory, "mssp") {
		categories.Cases.Count += 1
	} else if strings.Contains(newCategory, "siem") || strings.Contains(newCategory, "event") || strings.Contains(newCategory, "log") || strings.Contains(newCategory, "search") {
		categories.SIEM.Count += 1
	} else if strings.Contains(newCategory, "sms") || strings.Contains(newCategory, "comm") || strings.Contains(newCategory, "phone") || strings.Contains(newCategory, "call") || strings.Contains(newCategory, "chat") || strings.Contains(newCategory, "mail") || strings.Contains(newCategory, "phish") {
		categories.Communication.Count += 1
	} else if strings.Contains(newCategory, "intel") || strings.Contains(newCategory, "crim") || strings.Contains(newCategory, "ti") {
		categories.Intel.Count += 1
	} else if strings.Contains(newCategory, "sand") || strings.Contains(newCategory, "virus") || strings.Contains(newCategory, "malware") || strings.Contains(newCategory, "scan") || strings.Contains(newCategory, "edr") || strings.Contains(newCategory, "endpoint detection") {
		// Sandbox lol
		categories.EDR.Count += 1
	} else if strings.Contains(newCategory, "vuln") || strings.Contains(newCategory, "fim") || strings.Contains(newCategory, "fim") || strings.Contains(newCategory, "integrity") {
		categories.Assets.Count += 1
	} else if strings.Contains(newCategory, "network") || strings.Contains(newCategory, "firewall") || strings.Contains(newCategory, "waf") || strings.Contains(newCategory, "switch") {
		categories.Network.Count += 1
	} else {
		categories.Other.Count += 1
	}

	return categories
}

func HandleKeyValueCheck(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	// Append: Checks if the value should be appended
	// WorkflowCheck: Checks if the value should only check for workflow in org, or entire org
	// Authorization: the Authorization to use
	// ExecutionRef: Ref for the execution
	// Values: The values to use
	type DataValues struct {
		App             string
		Actions         string
		ParameterNames  []string
		ParameterValues []string
	}

	type ReturnData struct {
		Append        bool         `json:"append"`
		WorkflowCheck bool         `json:"workflow_check"`
		Authorization string       `json:"authorization"`
		ExecutionRef  string       `json:"execution_ref"`
		OrgId         string       `json:"org_id"`
		Values        []DataValues `json:"values"`
	}

	//for key, value := range data.Apps {
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

	var tmpData ReturnData
	err = json.Unmarshal(body, &tmpData)
	if err != nil {
		log.Printf("Failed unmarshalling test: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if tmpData.OrgId != fileId {
		log.Printf("[INFO] OrgId %s and %s don't match", tmpData.OrgId, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "Organization ID's don't match"}`))
		return
	}

	ctx := GetContext(request)

	org, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("[INFO] Organization doesn't exist: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	workflowExecution, err := GetWorkflowExecution(ctx, tmpData.ExecutionRef)
	if err != nil {
		log.Printf("[INFO] Couldn't find workflow execution: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "No permission to get execution"}`))
		return
	}

	if workflowExecution.Authorization != tmpData.Authorization {
		// Get the user?

		log.Printf("[INFO] Execution auth %s and %s don't match", workflowExecution.Authorization, tmpData.Authorization)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "Auth doesn't match"}`))
		return
	}

	if workflowExecution.Status != "EXECUTING" {
		log.Printf("[INFO] Workflow isn't executing and shouldn't be searching", workflowExecution.ExecutionId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "Workflow isn't executing"}`))
		return
	}

	if workflowExecution.ExecutionOrg != org.Id {
		log.Printf("[INFO] Org %s wasn't used to execute %s", org.Id, workflowExecution.ExecutionId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "Bad organization specified"}`))
		return
	}

	// Prepared for the future~
	if len(tmpData.Values) != 1 {
		log.Printf("[INFO] Filter data can only hande 1 value right now, not %d", len(tmpData.Values))
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "Can't handle multiple apps yet, just one"}`))
		return
	}

	value := tmpData.Values[0]

	// FIXME: Alphabetically sort the parameternames
	// FIXME: Add organization wide search, not just workflow based

	found := []string{}
	notFound := []string{}

	dbKey := fmt.Sprintf("app_execution_values")
	parameterNames := fmt.Sprintf("%s_%s", value.App, strings.Join(value.ParameterNames, "_"))
	log.Printf("[INFO] PARAMNAME: %s", parameterNames)
	if tmpData.WorkflowCheck {
		// FIXME: Make this alphabetical
		for _, value := range value.ParameterValues {
			if len(value) == 0 {
				log.Printf("Shouldn't have value of length 0!")
				continue
			}

			log.Printf("[INFO] Looking for value %s in Workflow %s of ORG %s", value, workflowExecution.Workflow.ID, org.Id)

			executionValues, err := GetAppExecutionValues(ctx, parameterNames, org.Id, workflowExecution.Workflow.ID, value)
			if err != nil {
				log.Printf("[WARNING] Failed getting key %s: %s", dbKey, err)
				notFound = append(notFound, value)
				//found = append(found, value)
				continue
			}

			foundCount := len(executionValues)

			if foundCount > 0 {
				found = append(found, value)
			} else {
				log.Printf("[INFO] Found for %s: %d", dbKey, foundCount)
				notFound = append(notFound, value)
			}
		}
	} else {
		log.Printf("[INFO] Should validate if value %s is in workflow id %s", value, workflowExecution.Workflow.ID)
		for _, value := range value.ParameterValues {
			if len(value) == 0 {
				log.Printf("Shouldn't have value of length 0!")
				continue
			}

			log.Printf("[INFO] Looking for value %s in ORG %s", value, org.Id)

			executionValues, err := GetAppExecutionValues(ctx, parameterNames, org.Id, workflowExecution.Workflow.ID, value)
			if err != nil {
				log.Printf("[WARNING] Failed getting key %s: %s", dbKey, err)
				notFound = append(notFound, value)
				//found = append(found, value)
				continue
			}

			foundCount := len(executionValues)

			if foundCount > 0 {
				found = append(found, value)
			} else {
				log.Printf("[INFO] Found for %s: %d", dbKey, foundCount)
				notFound = append(notFound, value)
			}
		}
	}

	//App             string
	//Actions         string
	//ParameterNames  string
	//ParamererValues []string

	appended := 0
	if tmpData.Append {
		log.Printf("[INFO] Should append %d value(s) in K:V for %s_%s!", len(notFound), org.Id, workflowExecution.ExecutionId)

		//parameterNames := strings.Join(value.ParameterNames, "_")
		for _, notFoundValue := range notFound {
			newRequest := NewValue{
				OrgId:               org.Id,
				WorkflowExecutionId: workflowExecution.ExecutionId,
				ParameterName:       parameterNames,
				Value:               notFoundValue,
			}

			// WorkflowId:          workflowExecution.Workflow.Id,
			if tmpData.WorkflowCheck {
				newRequest.WorkflowId = workflowExecution.Workflow.ID
			}

			err = SetNewValue(ctx, newRequest)
			if err != nil {
				log.Printf("[ERROR] Error adding %s to appvalue: %s", notFoundValue, err)
				continue
			}

			appended += 1
			log.Printf("[INFO] Added %s as new appvalue to datastore", notFoundValue)
		}
	}

	type returnStruct struct {
		Success  bool     `json:"success"`
		Appended int      `json:"appended"`
		Found    []string `json:"found"`
	}

	returnData := returnStruct{
		Success:  true,
		Appended: appended,
		Found:    found,
	}

	b, _ := json.Marshal(returnData)
	resp.WriteHeader(200)
	resp.Write(b)
}

func ParseVersions(versions []string) []string {
	log.Printf("Versions: %#v", versions)

	//versions = sort.Sort(semver.Collection(versions))
	return versions
}

// Can't just regex out stuff due to unicode problems with other languages
func handleKeyRemoval(key string) string {
	abolish := []string{"!", "@", "#", "$", "%", "~", "|", "^", "&", "*", "(", ")", "[", "]", "{", "}", "<", ">", "+", "=", "?", ".", ",", "/", "\\", "'"}

	for _, remove := range abolish {
		key = strings.Replace(key, remove, "", -1)
	}

	return key
}

// https://www.codemio.com/2021/02/advanced-golang-tutorials-dynamic-json-parsing.html
func handleJSONObject(object interface{}, key, totalObject string) string {
	currentObject := ""
	key = handleKeyRemoval(key)

	switch t := object.(type) {
	case int:
		currentObject += fmt.Sprintf(`"%s": %d, `, key, t)
		if len(key) == 0 {
			currentObject += fmt.Sprintf(`%d, `, t)
		}
	case int64:
		currentObject += fmt.Sprintf(`"%s": %d, `, key, t)
		if len(key) == 0 {
			currentObject += fmt.Sprintf(`%d, `, t)
		}
	case float64:
		tmpObject := fmt.Sprintf(`"%s": %f, `, key, t)
		if len(key) == 0 {
			tmpObject = fmt.Sprintf(`%f, `, t)
		}

		if strings.HasSuffix(tmpObject, "000000, ") {
			tmpObject = tmpObject[0 : len(tmpObject)-9]
			tmpObject += ", "
		}

		currentObject += tmpObject
	case bool:
		if len(key) == 0 {
			currentObject += fmt.Sprintf(`%v, `, t)
		} else {
			currentObject += fmt.Sprintf(`"%s": %v, `, key, t)
		}
	case string:
		if len(key) == 0 {
			currentObject += fmt.Sprintf(`"%s", `, t)
		} else {
			currentObject += fmt.Sprintf(`"%s": "%s", `, key, t)
		}
	case map[string]interface{}:
		if len(key) == 0 {
			currentObject += fmt.Sprintf(`{`)
		} else {
			currentObject += fmt.Sprintf(`"%s": {`, key)
		}

		for k, v := range t {
			currentObject = handleJSONObject(v, k, currentObject)
		}

		if len(currentObject) > 3 {
			currentObject = currentObject[0 : len(currentObject)-2]
		}

		currentObject += "}, "
	case []interface{}:
		if len(key) == 0 {
			currentObject += fmt.Sprintf(`[`)
		} else {
			currentObject += fmt.Sprintf(`"%s": [`, key)
		}

		for _, v := range t {
			currentObject = handleJSONObject(v, "", currentObject)
		}

		if len(currentObject) > 3 {
			currentObject = currentObject[0 : len(currentObject)-2]
		}

		currentObject += "], "
	default:
		log.Printf("[ERROR] Missing handler for type %#v in app framework - key: %s", t, key)
	}

	totalObject += currentObject
	return totalObject
}

func FixBadJsonBody(parsedBody []byte) []byte {
	if os.Getenv("SHUFFLE_JSON_PARSER") != "parse" {
		return parsedBody
	}
	// NOT handling data that starts as a loop for now: [] instead of {} as outer wrapper.
	// Lists and all other types do work inside the JSON, and are rebuilt with a new key (if applicable).

	if !strings.HasPrefix(string(parsedBody), "{") {
		return parsedBody
	}

	var results map[string]interface{}
	err := json.Unmarshal([]byte(parsedBody), &results)
	if err != nil {
		log.Printf("[WARNING] Failed parsing data: %s", err)
		return parsedBody
	}

	totalObject := "{"
	for key, value := range results {
		_ = value
		totalObject = handleJSONObject(value, key, totalObject)
	}

	if len(totalObject) > 3 {
		totalObject = totalObject[0 : len(totalObject)-2]
	}

	totalObject += "}"

	//log.Printf("Auto sanitized keys.: %s", totalObject)
	//for _, result := range results {
	//	// But if you don't know the field types, you can use type switching to determine (safe):
	//	// Keep in mind that, since this is a map, the order is not guaranteed.
	//	fmt.Println("\nType Switching: ")
	//	for k := range result {
	//	}

	//	fmt.Println("------------------------------")
	//}

	return []byte(totalObject)
}

func ValidateSwagger(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just here to verify that the user is logged in
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in validate swagger: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to validate swagger (shared): %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	type versionCheck struct {
		Swagger        string `datastore:"swagger" json:"swagger" yaml:"swagger"`
		SwaggerVersion string `datastore:"swaggerVersion" json:"swaggerVersion" yaml:"swaggerVersion"`
		OpenAPI        string `datastore:"openapi" json:"openapi" yaml:"openapi"`
	}

	//body = []byte(`swagger: "2.0"`)
	//body = []byte(`swagger: '1.0'`)
	//newbody := string(body)
	//newbody = strings.TrimSpace(newbody)
	//body = []byte(newbody)
	//log.Println(string(body))
	//tmpbody, err := yaml.YAMLToJSON(body)
	//log.Println(err)
	//log.Println(string(tmpbody))

	// This has to be done in a weird way because Datastore doesn't
	// support map[string]interface and similar (openapi3.Swagger)
	var version versionCheck

	re := regexp.MustCompile("[[:^ascii:]]")
	//re := regexp.MustCompile("[[:^unicode:]]")
	t := re.ReplaceAllLiteralString(string(body), "")
	log.Printf("[DEBUG] App build API length: %d. Cleanup length: %d", len(string(body)), len(t))
	body = []byte(t)

	isJson := false
	err = json.Unmarshal(body, &version)
	if err != nil {
		log.Printf("[WARNING] Json upload err: %s", err)

		body = []byte(strings.Replace(string(body), "\\/", "/", -1))
		err = yaml.Unmarshal(body, &version)
		if err != nil {
			log.Printf("[WARNING] Yaml error (3): %s", err)
			//if len(string(body)) < 500 {
			//	log.Printf("%s",
			//}
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed reading openapi to json and yaml. Is version defined?: %s"}`, err)))
			return
		} else {
			log.Printf("[INFO] Successfully parsed YAML (3)!")
		}
	} else {
		isJson = true
		log.Printf("[INFO] Successfully parsed JSON!")
	}

	if len(version.SwaggerVersion) > 0 && len(version.Swagger) == 0 {
		version.Swagger = version.SwaggerVersion
	}
	log.Printf("[INFO] Version: %#v", version)
	log.Printf("[INFO] OpenAPI: %s", version.OpenAPI)

	if strings.HasPrefix(version.Swagger, "3.") || strings.HasPrefix(version.OpenAPI, "3.") {
		log.Println("[INFO] Handling v3 API")
		swaggerLoader := openapi3.NewSwaggerLoader()
		swaggerLoader.IsExternalRefsAllowed = true
		swagger, err := swaggerLoader.LoadSwaggerFromData(body)
		if err != nil {
			log.Printf("[WARNING] Failed to convert v3 API: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
			return
		}

		hasher := md5.New()
		hasher.Write(body)
		idstring := hex.EncodeToString(hasher.Sum(nil))

		log.Printf("[INFO] Swagger v3 validation success with ID %s and %d paths!", idstring, len(swagger.Paths))

		if !isJson {
			log.Printf("[INFO] NEED TO TRANSFORM FROM YAML TO JSON for %s", idstring)
		}

		swaggerdata, err := json.Marshal(swagger)
		if err != nil {
			log.Printf("[WARNING] Failed unmarshaling v3 data: %s", err)
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed marshalling swaggerv3 data: %s"}`, err)))
			return
		}
		parsed := ParsedOpenApi{
			ID:   idstring,
			Body: string(swaggerdata),
		}

		ctx := GetContext(request)
		err = SetOpenApiDatastore(ctx, idstring, parsed)
		if err != nil {
			log.Printf("[WARNING] Failed uploading openapi to datastore: %s", err)
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed reading openapi2: %s"}`, err)))
			return
		}

		log.Printf("[INFO] Successfully set OpenAPI with ID %s", idstring)
		resp.WriteHeader(200)
		resp.Write([]byte(fmt.Sprintf(`{"success": true, "id": "%s"}`, idstring)))
		return
	} else { //strings.HasPrefix(version.Swagger, "2.") || strings.HasPrefix(version.OpenAPI, "2.") {
		// Convert
		log.Println("[WARNING] Handling v2 API")
		swagger := openapi2.Swagger{}
		//log.Println(string(body))
		err = json.Unmarshal(body, &swagger)
		if err != nil {
			log.Printf("[WARNING] Json error for v2 - trying yaml next: %s", err)
			err = yaml.Unmarshal([]byte(body), &swagger)
			if err != nil {
				log.Printf("[WARNING] Yaml error (4): %s", err)

				resp.WriteHeader(422)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed reading openapi2: %s"}`, err)))
				return
			} else {
				log.Printf("Found valid yaml!")
			}

		}

		swaggerv3, err := openapi2conv.ToV3Swagger(&swagger)
		if err != nil {
			log.Printf("[WARNING] Failed converting from openapi2 to 3: %s", err)
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed converting from openapi2 to openapi3: %s"}`, err)))
			return
		}

		swaggerdata, err := json.Marshal(swaggerv3)
		if err != nil {
			log.Printf("[WARNING] Failed unmarshaling v3 from v2 data: %s", err)
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed marshalling swaggerv3 data: %s"}`, err)))
			return
		}

		hasher := md5.New()
		hasher.Write(swaggerdata)
		idstring := hex.EncodeToString(hasher.Sum(nil))
		if !isJson {
			log.Printf("[WARNING] FIXME: NEED TO TRANSFORM FROM YAML TO JSON for %s?", idstring)
		}
		log.Printf("[INFO] Swagger v2 -> v3 validation success with ID %s!", idstring)

		parsed := ParsedOpenApi{
			ID:   idstring,
			Body: string(swaggerdata),
		}

		ctx := context.Background()
		err = SetOpenApiDatastore(ctx, idstring, parsed)
		if err != nil {
			log.Printf("[WARNING] Failed uploading openapi2 to datastore: %s", err)
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed reading openapi2: %s"}`, err)))
			return
		}

		resp.WriteHeader(200)
		resp.Write([]byte(fmt.Sprintf(`{"success": true, "id": "%s"}`, idstring)))
		return
	}
	/*
		else {
			log.Printf("Swagger / OpenAPI version %s is not supported or there is an error.", version.Swagger)
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Swagger version %s is not currently supported"}`, version.Swagger)))
			return
		}
	*/

	// save the openapi ID
	resp.WriteHeader(422)
	resp.Write([]byte(`{"success": false}`))
}

/*
func HandleGetSpecificStats(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	_, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("Api authentication failed in getting specific workflow: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")

	var statsId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		statsId = location[4]
	}

	ctx := context.Background()
	statisticsId := "global_statistics"
	nameKey := statsId
	key := datastore.NameKey(statisticsId, nameKey, nil)
	statisticsItem := StatisticsItem{}
	if err := project.Dbclient.Get(ctx, key, &statisticsItem); err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	b, err := json.Marshal(statisticsItem)
	if err != nil {
		log.Printf("Failed to marshal data: %s", err)
		resp.WriteHeader(401)
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(b))
}
*/

// Uses a simple way to be able to modify the encryption key being used
// FIXME: Investigate better ways of handling EVERYTHING related to encryption
// E.g. rolling keys and such
func create32Hash(key string) ([]byte, error) {
	encryptionModifier := os.Getenv("SHUFFLE_ENCRYPTION_MODIFIER")
	if len(encryptionModifier) == 0 {
		return []byte{}, errors.New(fmt.Sprintf("No encryption modifier set. Define SHUFFLE_ENCRYPTION_MODIFIER and NEVER change it to start encrypting auth."))
	}

	key += encryptionModifier
	hasher := md5.New()
	hasher.Write([]byte(key))
	return []byte(hex.EncodeToString(hasher.Sum(nil))), nil
}

func handleKeyEncryption(data []byte, passphrase string) ([]byte, error) {
	key, err := create32Hash(passphrase)
	if err != nil {
		log.Printf("[WARNING] Failed hashing in encrypt: %s", err)
		return []byte{}, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("[WARNING] Error generating ciphertext: %s", err)
		return []byte{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("[WARNING] Error creating new GCM from block: %s", err)
		return []byte{}, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Printf("[WARNING] Error reading GCM nonce: %s", err)
		return []byte{}, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// base64 encoding to ensure we can store it as a string
	parsedValue := base64.StdEncoding.EncodeToString(ciphertext)
	return []byte(parsedValue), nil
}

func HandleKeyDecryption(data []byte, passphrase string) ([]byte, error) {
	key, err := create32Hash(passphrase)
	if err != nil {
		log.Printf("[WARNING] Failed hashing in decrypt: %s", err)
		return []byte{}, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("[WARNING] Error creating cipher from key in decryption: %s", err)
		return []byte{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("[WARNING] Error creating new GCM block in decryption: %s", err)
		return []byte{}, err
	}

	parsedData, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		log.Printf("[ERROR] Failed base64 decode for an auth key %s: %s. Data: %s", data, err, string(data))
		return []byte{}, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := parsedData[:nonceSize], parsedData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Printf("[WARNING] Error reading decryptionkey: %s", err)
		return []byte{}, err
	}

	return plaintext, nil
}

func HandleGetCacheKey(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	//for key, value := range data.Apps {
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

	var tmpData CacheKeyData
	err = json.Unmarshal(body, &tmpData)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshalling in GET value: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if tmpData.OrgId != fileId {
		log.Printf("[INFO] OrgId %s and %s don't match", tmpData.OrgId, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Organization ID's don't match"}`))
		return
	}

	ctx := GetContext(request)

	org, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("[INFO] Organization doesn't exist: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	workflowExecution, err := GetWorkflowExecution(ctx, tmpData.ExecutionId)
	if err != nil {
		log.Printf("[INFO] Failed getting the execution: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "No permission to get execution"}`))
		return
	}

	// Allows for execution auth AND user auth
	if workflowExecution.Authorization != tmpData.Authorization {
		// Get the user?
		user, err := HandleApiAuthentication(resp, request)
		if err != nil {
			log.Printf("[INFO] Execution auth %s and %s don't match", workflowExecution.Authorization, tmpData.Authorization)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
			return
		} else {
			if user.ActiveOrg.Id != org.Id {
				log.Printf("[INFO] Execution auth %s and %s don't match (2)", workflowExecution.Authorization, tmpData.Authorization)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
				return
			}
		}
	}

	if workflowExecution.Status != "EXECUTING" {
		log.Printf("[INFO] Workflow %s isn't executing and shouldn't be searching", workflowExecution.ExecutionId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow isn't executing"}`))
		return
	}

	if workflowExecution.ExecutionOrg != org.Id {
		log.Printf("[INFO] Org %s wasn't used to execute %s", org.Id, workflowExecution.ExecutionId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Bad organization specified"}`))
		return
	}

	tmpData.Key = strings.Trim(tmpData.Key, " ")
	cacheId := fmt.Sprintf("%s_%s", tmpData.OrgId, tmpData.Key)
	cacheData, err := GetCacheKey(ctx, cacheId)
	if err != nil {
		log.Printf("[WARNING] Failed to GET cache key %s for org %s", tmpData.Key, tmpData.OrgId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed to get key. Does it exist?"}`))
		return
	}

	cacheData.Success = true
	cacheData.ExecutionId = ""
	cacheData.Authorization = ""
	cacheData.OrgId = ""

	log.Printf("[INFO] Successfully GOT key %#v for org %s", tmpData.Key, tmpData.OrgId)
	b, err := json.Marshal(cacheData)
	if err != nil {
		log.Printf("[WARNING] Failed to GET cache key %s for org %s", tmpData.Key, tmpData.OrgId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed to get key. Does it exist?"}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(b)
}

func HandleSetCacheKey(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	//for key, value := range data.Apps {
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

	var tmpData CacheKeyData
	err = json.Unmarshal(body, &tmpData)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshalling in setvalue: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if tmpData.OrgId != fileId {
		log.Printf("[INFO] OrgId %s and %s don't match", tmpData.OrgId, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Organization ID's don't match"}`))
		return
	}

	ctx := GetContext(request)

	org, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("[WARNING] Organization doesn't exist: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	workflowExecution, err := GetWorkflowExecution(ctx, tmpData.ExecutionId)
	if err != nil {
		log.Printf("[WARNING] Failed getting exec: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "No permission to get execution"}`))
		return
	}

	// Allows for execution auth AND user auth
	if workflowExecution.Authorization != tmpData.Authorization {
		// Get the user?
		user, err := HandleApiAuthentication(resp, request)
		if err != nil {
			log.Printf("[INFO] Execution auth %s and %s don't match", workflowExecution.Authorization, tmpData.Authorization)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
			return
		} else {
			if user.ActiveOrg.Id != org.Id {
				log.Printf("[INFO] Execution auth %s and %s don't match (2)", workflowExecution.Authorization, tmpData.Authorization)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
				return
			}
		}

		_ = user
	}

	if workflowExecution.Status != "EXECUTING" {
		log.Printf("[INFO] Workflow %s isn't executing and shouldn't be searching", workflowExecution.ExecutionId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow isn't executing"}`))
		return
	}

	if workflowExecution.ExecutionOrg != org.Id {
		log.Printf("[INFO] Org %s wasn't used to execute %s", org.Id, workflowExecution.ExecutionId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Bad organization specified"}`))
		return
	}

	if len(tmpData.Value) == 0 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Value can't be empty"}`))
		return
	}

	tmpData.Key = strings.Trim(tmpData.Key, " ")
	err = SetCacheKey(ctx, tmpData)
	if err != nil {
		log.Printf("[WARNING] Failed to set cache key %s for org %s", tmpData.Key, tmpData.OrgId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "Failed to set data"}`))
		return
	}

	log.Printf("[INFO] Successfully set key %#v for org %s (%s)", tmpData.Key, org.Name, tmpData.OrgId)
	type returnStruct struct {
		Success bool `json:"success"`
	}

	returnData := returnStruct{
		Success: true,
	}

	b, err := json.Marshal(returnData)
	if err != nil {
		b = []byte(`{"success": true}`)
	}

	resp.WriteHeader(200)
	resp.Write(b)
}

func HandleRetValidation(ctx context.Context, workflowExecution WorkflowExecution) []byte {
	cnt := 0
	type retStruct struct {
		Success       bool   `json:"success"`
		Id            string `json:"id"`
		Authorization string `json:"authorization"`
		Result        string `json:"result"`
	}

	returnBody := retStruct{
		Success:       true,
		Id:            workflowExecution.ExecutionId,
		Authorization: workflowExecution.Authorization,
		Result:        "",
	}

	// VERY short sleeptime here on purpose
	maxSeconds := 10
	sleeptime := 25
	for {
		time.Sleep(25 * time.Millisecond)
		newExecution, err := GetWorkflowExecution(ctx, workflowExecution.ExecutionId)
		if err != nil {
			log.Printf("[WARNING] Failed getting single execution data: %s", err)
			break
		}

		if len(newExecution.Results) > 0 {
			if len(newExecution.Results[0].Result) > 0 {
				returnBody.Result = newExecution.Results[0].Result
				break
			}
		}

		cnt += 1
		//log.Println("Cnt: %d", cnt)
		if cnt == (maxSeconds * (maxSeconds * 100 / sleeptime)) {
			break
		}
	}

	if len(returnBody.Result) == 0 {
		returnBody.Success = false
	}

	returnBytes, err := json.Marshal(returnBody)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal retStruct in single execution: %s", err)
		return []byte{}
	}

	return returnBytes
}

func md5sum(data []byte) string {
	hasher := md5.New()
	hasher.Write(data)
	newmd5 := hex.EncodeToString(hasher.Sum(nil))
	return newmd5
}

func fixCertificate(parsedX509Key string) string {
	parsedX509Key = strings.Replace(parsedX509Key, "&#13;", "", -1)
	if strings.Contains(parsedX509Key, "BEGIN CERT") && strings.Contains(parsedX509Key, "END CERT") {
		parsedX509Key = strings.Replace(parsedX509Key, "-----BEGIN CERTIFICATE-----\n", "", -1)
		parsedX509Key = strings.Replace(parsedX509Key, "-----BEGIN CERTIFICATE-----", "", -1)
		parsedX509Key = strings.Replace(parsedX509Key, "-----END CERTIFICATE-----\n", "", -1)
		parsedX509Key = strings.Replace(parsedX509Key, "-----END CERTIFICATE-----", "", -1)
	}

	// PingOne issue
	parsedX509Key = strings.Replace(parsedX509Key, "\r\n", "", -1)
	parsedX509Key = strings.Replace(parsedX509Key, "\n", "", -1)
	parsedX509Key = strings.Replace(parsedX509Key, "\r", "", -1)
	parsedX509Key = strings.Replace(parsedX509Key, " ", "", -1)
	parsedX509Key = strings.TrimSpace(parsedX509Key)
	//log.Printf("Len: %d", len(parsedX509Key))
	//log.Printf("%#v", parsedX509Key)
	return parsedX509Key
}

func HealthCheckHandler(resp http.ResponseWriter, request *http.Request) {
	ret, err := project.Es.Info()
	if err != nil {
		log.Printf("[ERROR] Failed connecting to ES: %s", err)
		resp.WriteHeader(ret.StatusCode)
		resp.Write([]byte("Bad response from ES (1). Check logs for more details."))
		return
	}

	if ret.StatusCode >= 300 {
		resp.WriteHeader(ret.StatusCode)
		resp.Write([]byte(fmt.Sprintf("Bad response from ES - Status code %d", ret.StatusCode)))
		return
	}

	fmt.Fprint(resp, "OK")
}

func GetFrameworkConfiguration(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just here to verify that the user is logged in
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[DEBUG] Api authentication failed in get detection framework: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
		return
	}

	ctx := GetContext(request)
	org, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Error getting org: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	//log.Printf("Framework: %#v", org.SecurityFramework)
	newjson, err := json.Marshal(org.SecurityFramework)
	if err != nil {
		log.Printf("[ERROR] Failed marshal in get security framework: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking framework. Contact us to get it fixed."}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func SetFrameworkConfiguration(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just here to verify that the user is logged in
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[DEBUG] Api authentication failed in set detection framework: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Error with body read: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	type parsedValue struct {
		Type        string `json:"type"`
		Name        string `json:"name"`
		ID          string `json:"id"`
		LargeImage  string `json:"large_image"`
		Description string `json:"description"`
	}

	var value parsedValue
	err = json.Unmarshal(body, &value)
	if err != nil {
		log.Printf("[WARNING] Error with unmarshal tmpBody in frameworkconfig: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := GetContext(request)
	org, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Error getting org in set framework: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	app := &WorkflowApp{
		Name:        "",
		Description: "",
		ID:          "",
		LargeImage:  "",
	}

	// System for replacing an app if it's not defined
	if value.ID != "remove" {

		app, err = GetApp(ctx, value.ID, user, false)
		if err != nil {

			if project.Environment == "cloud" {
				log.Printf("[ERROR] Error getting app %s in set framework: %s", value.ID, err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false}`))
				return
			} else {
				// Forwarded from Algolia in the frontend
				app.Name = value.Name
				app.ID = value.Name
				app.Description = value.Description
				app.LargeImage = value.LargeImage
			}
		}

		if project.Environment == "cloud" && !app.Sharing && app.Public {
			log.Printf("[WARNING] Error setting app %s for org %s as it's not public.", value.ID, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	_ = org

	if value.Type == "email" {
		value.Type = "comms"
	}

	if value.Type == "eradication" {
		value.Type = "edr"
	}

	// 1. Check if the app exists and the user has access to it. If public/sharing ->
	if strings.ToLower(value.Type) == "siem" {
		org.SecurityFramework.SIEM.Name = app.Name
		org.SecurityFramework.SIEM.Description = app.Description
		org.SecurityFramework.SIEM.ID = app.ID
		org.SecurityFramework.SIEM.LargeImage = app.LargeImage
	} else if strings.ToLower(value.Type) == "network" {
		org.SecurityFramework.Network.Name = app.Name
		org.SecurityFramework.Network.Description = app.Description
		org.SecurityFramework.Network.ID = app.ID
		org.SecurityFramework.Network.LargeImage = app.LargeImage
	} else if strings.ToLower(value.Type) == "edr" || strings.ToLower(value.Type) == "edr & av" {
		org.SecurityFramework.EDR.Name = app.Name
		org.SecurityFramework.EDR.Description = app.Description
		org.SecurityFramework.EDR.ID = app.ID
		org.SecurityFramework.EDR.LargeImage = app.LargeImage
	} else if strings.ToLower(value.Type) == "cases" {
		org.SecurityFramework.Cases.Name = app.Name
		org.SecurityFramework.Cases.Description = app.Description
		org.SecurityFramework.Cases.ID = app.ID
		org.SecurityFramework.Cases.LargeImage = app.LargeImage
	} else if strings.ToLower(value.Type) == "iam" {
		org.SecurityFramework.IAM.Name = app.Name
		org.SecurityFramework.IAM.Description = app.Description
		org.SecurityFramework.IAM.ID = app.ID
		org.SecurityFramework.IAM.LargeImage = app.LargeImage
	} else if strings.ToLower(value.Type) == "assets" {
		org.SecurityFramework.Assets.Name = app.Name
		org.SecurityFramework.Assets.Description = app.Description
		org.SecurityFramework.Assets.ID = app.ID
		org.SecurityFramework.Assets.LargeImage = app.LargeImage
	} else if strings.ToLower(value.Type) == "intel" {
		org.SecurityFramework.Intel.Name = app.Name
		org.SecurityFramework.Intel.Description = app.Description
		org.SecurityFramework.Intel.ID = app.ID
		org.SecurityFramework.Intel.LargeImage = app.LargeImage
	} else if strings.ToLower(value.Type) == "comms" {
		org.SecurityFramework.Communication.Name = app.Name
		org.SecurityFramework.Communication.Description = app.Description
		org.SecurityFramework.Communication.ID = app.ID
		org.SecurityFramework.Communication.LargeImage = app.LargeImage
	} else {
		log.Printf("[WARNING] No handler for type %#v in app framework during update of app %#v", value.Type, app.Name)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Add app as active for org too
	if !ArrayContains(org.ActiveApps, app.ID) {
		org.ActiveApps = append(org.ActiveApps, app.ID)
	}

	err = SetOrg(ctx, *org, org.Id)
	if err != nil {
		log.Printf("[WARNING] Failed setting app framework for org %s: %s", org.Name, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed updating organization info. Please contact us if this persists."}`))
		return
	} else {
		DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
		DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-100"))
		DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-500"))
		DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-1000"))
		DeleteCache(ctx, "all_apps")
		DeleteCache(ctx, fmt.Sprintf("user_%s", user.Username))
		DeleteCache(ctx, fmt.Sprintf("user_%s", user.Id))
	}

	log.Printf("[DEBUG] Successfully updated app framework type %s to app %s (%s) for org %s (%s)!", value.Type, app.Name, app.ID, org.Name, org.Id)

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

type flushWriter struct {
	f http.Flusher
	w io.Writer
}

func (fw *flushWriter) Write(p []byte) (n int, err error) {
	n, err = fw.w.Write(p)
	if fw.f != nil {
		fw.f.Flush()
	}
	return
}

func LoadUsecases(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get usecases. Continuing anyway: %s", err)
		//resp.WriteHeader(401)
		//resp.Write([]byte(`{"success": false}`))
		//return
	}

	// FIXME: Load for the specific org and have structs for it all
	_ = user

	//ctx := GetContext(request)

	resp.WriteHeader(200)
	resp.Write([]byte(usecaseData))
}

func UpdateUsecases(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get usecases. Continuing anyway: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Needs to be a shuffler.io account to update
	if project.Environment == "cloud" && !strings.HasSuffix(user.Username, "@shuffler.io") {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't change framework info"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Error with body read for usecase update: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	var usecase Usecase
	err = json.Unmarshal(body, &usecase)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling usecase: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	usecase.Success = true
	usecase.Name = strings.Replace(usecase.Name, " ", "_", -1)
	usecase.Name = url.QueryEscape(usecase.Name)
	log.Printf("[DEBUG] Updated usecase %s as user %s (%s)", usecase.Name, user.Username, user.Id)
	usecase.EditedBy = user.Id
	ctx := GetContext(request)
	err = SetUsecase(ctx, usecase)
	if err != nil {
		log.Printf("[ERROR] Failed updating usecase: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleGetUsecase(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	_, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get usecase (1). Continuing anyway: %s", err)
		//resp.WriteHeader(401)
		//resp.Write([]byte(`{"success": false}`))
		//return
	}

	var name string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 5 {
			log.Printf("[ERROR] Path too short: %d", len(location))
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		name = location[5]
	}

	ctx := GetContext(request)
	usecase, err := GetUsecase(ctx, name)
	if err != nil {
		log.Printf("[ERROR] Failed getting usecase %s: %s", name, err)
		usecase.Success = true
		usecase.Name = name
		//resp.WriteHeader(400)
		//resp.Write([]byte(`{"success": false}`))
		//return
	} else {
		usecase.Success = true
	}

	// Hardcoding until we have something good for open source + cloud
	replacedName := strings.Replace(strings.ToLower(usecase.Name), " ", "_", -1)
	if replacedName == "email_management" {
		usecase.ExtraButtons = []ExtraButton{
			ExtraButton{
				Name:  "IMAP",
				App:   "Email",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/email_ec25da1fdbf18934ca468788b73bec32.png",
				Link:  "https://shuffler.io/workflows/b65d180c-4d27-4cb6-8128-3687a08aadb3",
				Type:  "communication",
			},
			ExtraButton{
				Name:  "Gmail",
				App:   "Gmail",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Gmail_794e51c3c1a8b24b89ccc573a3defc47.png",
				Link:  "https://shuffler.io/workflows/e506060f-0c58-4f95-a0b8-f671103d78e5",
				Type:  "communication",
			},
			ExtraButton{
				Name:  "Outlook",
				App:   "Outlook Graph",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Outlook_graph_d71641a57deeee8149df99080adebeb7.png",
				Link:  "https://shuffler.io/workflows/3862ed8f-7801-4393-8524-05de8f8a401d",
				Type:  "communication",
			},
		}
	} else if replacedName == "edr_to_ticket" {
		usecase.ExtraButtons = []ExtraButton{
			ExtraButton{
				Name:  "Velociraptor",
				App:   "Velociraptor",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/velociraptor_63de9fc91bcb4813d9c58cc6efd49b33.png",
				Link:  "https://shuffler.io/apps/63de9fc91bcb4813d9c58cc6efd49b33",
				Type:  "edr",
			},
			ExtraButton{
				Name:  "Carbon Black",
				App:   "Carbon Black",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Carbon_Black_Response_e9fa2602ea6baafffa4b5eec722095d3.png",
				Link:  "https://shuffler.io/apps/e9fa2602ea6baafffa4b5eec722095d3",
				Type:  "edr",
			},
			ExtraButton{
				Name:  "Crowdstrike",
				App:   "Crowdstrike",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Crowdstrike_Falcon_7a66ce3c26e0d724f31f1ebc9a7a41b4.png",
				Link:  "https://shuffler.io/apps/7a66ce3c26e0d724f31f1ebc9a7a41b4",
				Type:  "edr",
			},
		}
	} else if replacedName == "siem_to_ticket" {
		usecase.ExtraButtons = []ExtraButton{
			ExtraButton{
				Name:  "Wazuh",
				App:   "Wazuh",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Wazuh_fb715a176a192687e95e9d162186c97f.png",
				Link:  "https://shuffler.io/workflows/bb45124c-d39e-4acc-a5d9-f8aa526042b5",
				Type:  "siem",
			},
			ExtraButton{
				Name:  "Splunk",
				App:   "Splunk",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Splunk_Splunk_e352462c6d2f0a692281600d96002a45.png",
				Link:  "https://shuffler.io/apps/441a2d85f6c1e8408dd1ee1e804cd241",
				Type:  "siem",
			},
			ExtraButton{
				Name:  "QRadar",
				App:   "QRadar",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/QRadar_4fe358bd204f672d37c55b4f1d48ccdb.png",
				Link:  "https://shuffler.io/apps/96a3d95a2a73cfdb51ea4a394287ed33",
				Type:  "siem",
			},
		}
	} else if replacedName == "chatops" {
		usecase.ExtraButtons = []ExtraButton{
			ExtraButton{
				Name:  "Webex",
				App:   "Webex",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Webex_1f6f2fc4fd399597e98ff34f78f56c45.png",
				Link:  "https://shuffler.io/workflows/88e16093-37b7-41cf-b02b-d1ca0e737993",
				Type:  "communication",
			},
			ExtraButton{
				Name:  "Teams",
				App:   "Microsoft Teams",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Microsoft_Teams_User_Access_4826c529f8082205a4b926ac9f1dfcfb.png",
				Link:  "https://shuffler.io/apps/4826c529f8082205a4b926ac9f1dfcfb",
				Type:  "communication",
			},
			ExtraButton{
				Name:  "Slack",
				App:   "Slack",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Slack_Web_API_f63a65ddf0ee369845b6918575d47fc1.png",
				Link:  "https://shuffler.io/workflows/0a7eeca9-e056-40e5-9a70-f078937c6055",
				Type:  "communication",
			},
		}
	}

	newjson, err := json.Marshal(usecase)
	if err != nil {
		log.Printf("[ERROR] Failed marshal in get usecase: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking data"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func addPriority(org Org, priority Priority) (*Org, bool) {
	updated := false
	if len(org.Priorities) < 5 {
		org.Priorities = append(org.Priorities, priority)
		updated = true
	}

	//log.Printf("Priorities: %d", len(org.Priorities))

	return &org, updated
}

// Watch academy - Shuffle 101 if you're new
// Check notifications
// Check if all apps have been discovered
// Check if notification workflow is made
// Check workflows vs usecases
// Check based on org configuration (name, environments, apps...)
// Workflows not finished / without a parent workflow/trigger
// Workflows not in production

// Should just be based on cache, not queries - keep it fast!
func GetPriorities(ctx context.Context, user User, org *Org) ([]Priority, error) {
	// Get usecases -> Check which aren't done based on priorities
	// 1. Check what apps are selected. Are email, edr and siem in there?
	// If not - autocorrect based on workflows' apps?
	//log.Printf("[DEBUG] SecurityFramework: %#v", org.SecurityFramework)

	// First prio: Find these & attach usecases?
	// Only set these if cache is set for the user
	orgUpdated := false
	updated := false
	if project.CacheDb == false {
		// Not checking as cache is used for all checks
		return org.Priorities, nil
	}

	if len(org.Defaults.NotificationWorkflow) == 0 {
		org, updated = addPriority(*org, Priority{
			Name:        fmt.Sprintf("You haven't defined a notification workflow yet."),
			Description: "Notification workflows are used to automate your notification handling. These can be used to alert yourself in other systems when issues are found in your current- or sub-organizations",
			Type:        "notifications",
			Active:      true,
			URL:         fmt.Sprintf("/admin"),
		})

		if updated {
			orgUpdated = true
		}
	}

	var notifications []Notification
	cache, err := GetCache(ctx, fmt.Sprintf("notifications_%s", org.Id))
	if err == nil {
		cacheData := []byte(cache.([]uint8))
		//log.Printf("CACHEDATA: %#v", cacheData)
		err = json.Unmarshal(cacheData, &notifications)
		if err == nil && len(notifications) > 0 {
			org, updated = addPriority(*org, Priority{
				Name:        fmt.Sprintf("You have %d unhandled notifications.", len(notifications)),
				Description: "Notifications help make your workflow infrastructure stable. Click the notification icon in the top right to see all open ones.",
				Type:        "notifications",
				Active:      true,
				URL:         fmt.Sprintf("/notifications"),
			})

			if updated {
				orgUpdated = true
			}
		}
	} else {
		//log.Printf("[DEBUG] Failed getting cache for org: %s", err)
	}

	var workflows []Workflow
	cache, err = GetCache(ctx, fmt.Sprintf("%s_workflows", user.Id))
	if err == nil {
		cacheData := []byte(cache.([]uint8))
		err = json.Unmarshal(cacheData, &workflows)
		if err == nil && len(workflows) > 0 {
			if org.SecurityFramework.SIEM.Name == "" || org.SecurityFramework.EDR.Name == "" || org.SecurityFramework.Communication.Name == "" {
				//log.Printf("Should find siem, edr and comms based on apps in use in workflows")
				for _, workflow := range workflows {
					for _, action := range workflow.Actions {
						if len(action.Category) == 0 {
							continue
						}
						//log.Printf("%s:%s = %s", action.AppName, action.AppVersion, action.Category)
						if org.SecurityFramework.Communication.Name == "" && action.Category == "Communication" {
							orgUpdated = true
							org.SecurityFramework.Communication = Category{
								Name:        action.Name,
								Count:       1,
								Description: "",
								LargeImage:  action.LargeImage,
								ID:          action.AppID,
							}
						}

						if org.SecurityFramework.SIEM.Name == "" && action.Category == "SIEM" {
							orgUpdated = true
							org.SecurityFramework.SIEM = Category{
								Name:        action.Name,
								Count:       1,
								Description: "",
								LargeImage:  action.LargeImage,
								ID:          action.AppID,
							}
						}

						if org.SecurityFramework.EDR.Name == "" && action.Category == "EDR" {
							orgUpdated = true
							org.SecurityFramework.EDR = Category{
								Name:        action.Name,
								Count:       1,
								Description: "",
								LargeImage:  action.LargeImage,
								ID:          action.AppID,
							}
						}
					}
				}

				// Checking again to see if specifying either should be a priority
				if org.SecurityFramework.SIEM.Name == "" || org.SecurityFramework.EDR.Name == "" || org.SecurityFramework.Communication.Name == "" {
					org, updated = addPriority(*org, Priority{
						Name:        "Apps for Email, EDR & SIEM should be specified",
						Description: "The most common usecases are based on Email, EDR & SIEM. If these aren't specified Shuffle won't be used optimally.",
						Type:        "definition",
						Active:      true,
						URL:         fmt.Sprintf("/detectionframework"),
					})

					if updated {
						orgUpdated = true
					}
				}
			}

		}
	} else {
		//log.Printf("[INFO] Failed getting cache for workflows for user %s", user.Id)
	}

	if len(org.MainPriority) == 0 {
		// Just choosing something for them, e.g. basic usecase building

		org.MainPriority = "1. Collect"
		orgUpdated = true
	}

	// Matching org priority with usecases & previously built workflows
	if len(org.MainPriority) > 0 && len(workflows) > 0 {
		var usecases UsecaseLinks
		err = json.Unmarshal([]byte(usecaseData), &usecases)
		if err == nil {
			log.Printf("[DEBUG] Got parsed usecases for %s - should check priority vs mainpriority (%s)", org.Name, org.MainPriority)

			for usecaseIndex, usecase := range usecases {
				if usecase.Name != org.MainPriority {
					continue
				}

				// match them with usecases here
				for _, workflow := range workflows {
					if len(workflow.UsecaseIds) == 0 {
						continue
					}

					// Fidning matching usecase for workflow
					for _, workflowUsecase := range workflow.UsecaseIds {
						newUsecasename := strings.ToLower(workflowUsecase)

						for subusecaseIndex, subusecase := range usecase.List {
							if newUsecasename == strings.ToLower(subusecase.Name) {
								usecases[usecaseIndex].List[subusecaseIndex].Matches = append(usecases[usecaseIndex].List[subusecaseIndex].Matches, workflow)
								break
							}
						}
					}
				}

				// Sort sub-usecases by priority
				slice.Sort(usecase.List[:], func(i, j int) bool {
					return usecase.List[i].Priority > usecase.List[j].Priority
				})

				//log.Printf("[DEBUG] Priorities for %s", usecase.Name)
				for _, subusecase := range usecase.List {
					// Check if it has a workflow attached to it too?
					//log.Printf("%s = %d. Matches: %d", subusecase.Name, subusecase.Priority, len(subusecase.Matches))

					if len(subusecase.Matches) == 0 {
						continue
					}

					// Checking main type just in case, so it forces you to choose the app first (?)
					if len(subusecase.Type) > 0 {
						if strings.ToLower(subusecase.Type) == "siem" && org.SecurityFramework.SIEM.Name == "" {
							continue
						}

						if strings.ToLower(subusecase.Type) == "edr" && org.SecurityFramework.EDR.Name == "" {
							continue
						}

						if strings.ToLower(subusecase.Type) == "communication" && org.SecurityFramework.Communication.Name == "" {
							continue
						}
					}

					org, updated = addPriority(*org, Priority{
						Name:        fmt.Sprintf("Complete the prioritized usecase %#v", subusecase.Name),
						Description: fmt.Sprintf("Usecases are prioritized based on your Organizations Main Priority and matching priorities from Shuffle towards that priority. %#v is most likely one of your highest priorities. Dismiss this priority to get new priorities.", subusecase.Name),
						Type:        "usecase",
						Active:      true,
						URL:         fmt.Sprintf("/usecases?selected_object=%s", subusecase.Name),
					})

					if updated {
						orgUpdated = true
					}
				}
			}
		}
	}

	if orgUpdated {
		log.Printf("[DEBUG] Should update org with %d notifications", len(org.Priorities))
	}

	return org.Priorities, nil
	//return []Priority{}, nil
}
