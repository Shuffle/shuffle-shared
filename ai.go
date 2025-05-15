package shuffle

import (
	"os"
	"fmt"
	"log"
	"time"
	"sync"
	"bytes"
	"regexp"
	"reflect"
	"errors"
	"context"
	"strings"
	"strconv"
	"net/http"
	"math/rand"
	"io/ioutil"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"encoding/base64"

	uuid "github.com/satori/go.uuid"
	openai "github.com/sashabaranov/go-openai"
	option "google.golang.org/api/option"
	"google.golang.org/api/customsearch/v1"
	"github.com/algolia/algoliasearch-client-go/v3/algolia/search"

	"github.com/frikky/schemaless"
	"github.com/frikky/kin-openapi/openapi3"
)

//var model = "gpt-4-turbo-preview"
//var model = "gpt-4o-mini"
var standalone bool
var model = "o4-mini"
var fallbackModel = ""
var assistantId = os.Getenv("OPENAI_ASSISTANT_ID") 
var assistantModel = model

func GetKmsCache(ctx context.Context, auth AppAuthenticationStorage, key string) (string, error) {
	//log.Printf("\n\n[DEBUG] Getting KMS cache for key %s\n\n", key)

	hash := md5.New()
	hash.Write([]byte(key))
	hashInBytes := hash.Sum(nil)
	md5String := hex.EncodeToString(hashInBytes)
	encryptionKey := fmt.Sprintf("%s_%d_%s", auth.OrgId, auth.Created, md5String)

	rawCache, err := GetCache(ctx, md5String)
	if err != nil {
		//log.Printf("[ERROR] Failed to get KMS cache for key %s: %s", key, err)
		return "", err
	}

	value := []byte(rawCache.([]uint8))

	//log.Printf("\n\n[DEBUG] Got KMS cache for key %s with value %s\n\n", key, value)
	decrypted, err := HandleKeyDecryption(value, encryptionKey)
	if err != nil {
		log.Printf("[ERROR] Failed to decrypt KMS cache for key %s: %s", key, err)
		return "", err
	}

	return string(decrypted), nil
}

func SetKmsCache(ctx context.Context, auth AppAuthenticationStorage, key, value string, ttl int32) error {
	// 1. Encrypt it
	hash := md5.New()
	hash.Write([]byte(key))
	hashInBytes := hash.Sum(nil)
	md5String := hex.EncodeToString(hashInBytes)
	encryptionKey := fmt.Sprintf("%s_%d_%s", auth.OrgId, auth.Created, md5String)

	encrypted, err := handleKeyEncryption([]byte(value), encryptionKey) 
	if err != nil {
		log.Printf("[ERROR] Failed to encrypt KMS cache for key %s: %s", key, err)
		return err
	}

	// 2. Store it
	err = SetCache(ctx, md5String, encrypted, ttl)
	if err != nil {
		log.Printf("[ERROR] Failed to set KMS cache for key %s: %s", key, err)
		return err
	}

	return nil
}

// Should talk to the KMS and find the key we are looking for
// Uses normal OR execution auth (authorization: Bearer..)
func DecryptKMS(ctx context.Context, auth AppAuthenticationStorage, key, authorization, optionalExecutionId string) (string, error) {
	cachedOutput, err := GetKmsCache(ctx, auth, key) 
	if err == nil && len(cachedOutput) > 0 {
		log.Printf("[INFO] Found cached KMS key for key '%s'", key)
		return cachedOutput, nil
	}

	keys := []string{}
	if strings.Contains(key, "kms/") {
		keys = strings.Split(key, "/")
	} else if strings.Contains(key, "kms.") {
		keys = strings.Split(key, ".")
	} else if strings.Contains(key, "kms:") {
		keys = strings.Split(key, ":")
	} else {
		return "", errors.New(fmt.Sprintf("Invalid KMS key format for key '%s'. Must be in the format 'kms/key1/key2', 'kms.key1.key2.key3', or 'kms:key1:key2'", key))
	}

	// seeing as it has to start with kms(./:), we can remove the first element
	keys = keys[1:]


	// Associated key is a structure to help with e.g. Hashicorp Vault where keys are used as values (multiple key:values in one)
	// This is silly instead of just indexing & modifying keys ROFL
	// Doesn't matter with small for-loop
	newKeys := []string{}
	associatedKey := ""
	for keyIndex, keyPart := range keys {
		if keyIndex != len(keys) - 1 {
			newKeys = append(newKeys, keyPart)
			continue
		}

		if strings.HasPrefix(keyPart, "${") && strings.HasSuffix(keyPart, "}") {
			if len(keyPart) < 4 {
				break
			}

			associatedKey = keyPart[2:len(keyPart)-1]
			break
		}
	}


	keys = newKeys
	log.Printf("[INFO] Looking to decrypt KMS key '%s' with %d parts. Additional Key: %#v", key, len(keys), associatedKey)

	// 1. Prepare to make sure we have all we need (org, project, app, key)
	// 2. Decrypt the key
	// 3. Return the decrypted key

	// Maybe if in the key there is something like:
	// "<org>/<project>/<app>/<key>"
	// This could just be based on the REQUIRED variables of the action to run?
	// Could we go find the action based on:
	// category -> label -> action -> required params -> map in order?

	// 1. Get the app and check if it has a "get_kms_key" action

	app, err := GetApp(ctx, auth.App.ID, User{}, false)
	if err != nil {
		log.Printf("[ERROR] Failed to get app %s during KMS check: %s", auth.App.ID, err)
		return "", err
	}

	log.Printf("[DEBUG] Got app %s (%s) with %d actions for KMS auth", app.Name, app.ID, len(app.Actions))
	action := WorkflowAppAction{}
	for _, curaction := range app.Actions {
		if len(curaction.CategoryLabel) == 0 {
			continue
		}

		found := false
		for _, label := range curaction.CategoryLabel {
			label = strings.ToLower(strings.ReplaceAll(label, " ", "_"))
			if label == "get_kms_key" {
				found = true 
				break
			}
		}

		if !found {
			continue
		}

		action = curaction
		break
	}

	log.Printf("[DEBUG] Found action '%s' in app '%s' (%s) for handling KMS decryption", action.Name, app.Name, app.ID)
	requiredParams := []string{}
	for _, param := range action.Parameters {
		// Skip configurations, as they are handled with Auth
		if param.Configuration {
			continue
		}

		if !param.Required {
			continue
		}

		if strings.ToLower(param.Name) == "url" {
			continue
		}

		requiredParams = append(requiredParams, param.Name)
	}

	log.Printf("[DEBUG] Required params for action %s in app %s (%s): %s", action.Name, app.Name, app.ID, strings.Join(requiredParams, ", "))
	if len(requiredParams) == 0 {
		return "", errors.New(fmt.Sprintf("No required parameters found for action %s", action.Label))
	}

	// Now we need to map the required params to the keys. Order?
	// If we have a key like "kms/org/project/app/key", we can map the required params to the keys

	// If the keys are a path or something, we just throw them all in there without caring about keys <=> requiredParams 
	if len(keys) != len(requiredParams) {
		log.Printf("[ERROR] KMS: %#v and %#v are not the same length (%d vs %d)\n\n", keys, requiredParams, len(keys), len(requiredParams))

		if len(keys) < len(requiredParams) {
			return "", errors.New(fmt.Sprintf("Key %s and %s are not the same length. This may lead to grabbing the wrong KMS auth key.", strings.Join(keys, ","), strings.Join(requiredParams, ",")))
		}

		// Inject all extra keys into the last key by joining at length

		newkeys := []string{}
		for kIndex, key := range keys {
			if kIndex == len(requiredParams) - 1 {
				newkeys = append(newkeys, strings.Join(keys[kIndex:], "/"))
				break
			}

			newkeys = append(newkeys, key)
		}

		keys = newkeys
	}

	// Should prep to send request to the action
	// FIXME: Which should we do?
	// 1. Should we run the action directly?
	// 2. Or should we use the label?
	// #1 = faster, but #2 is general. Maybe #2 for first time, then fallback to #1? Problem with #1 again is that it can't also use workflows at that point
	categoryAction := CategoryAction{
		AppName: app.Name,
		Label: "get_kms_key",

		ActionName: action.Name,
		AuthenticationId: auth.Id,
		Fields: []Valuereplace{},

		SkipWorkflow: true,
		SkipOutputTranslation: true, // Manually done in the KMS case
		Environment: auth.Environment,
	}

	if len(app.Categories) > 0 {
		categoryAction.Category = app.Categories[0]
	}

	for i, param := range requiredParams {
		if len(keys) <= i {
			log.Printf("[ERROR] KMS (2): Key length is less than required params length (%d vs %d). SKipping: %s\n\n", len(keys), len(requiredParams), param)
			break
		}

		categoryAction.Fields = append(categoryAction.Fields, Valuereplace{
			Key: param,
			Value: keys[i],
		})
	}

	marshalledAction, err := json.Marshal(categoryAction)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal category action during KMS mapping: %s", err)
		return "", err
	}

	baseUrl := fmt.Sprintf("https://shuffler.io")
	if len(os.Getenv("BASE_URL")) > 0 {
		baseUrl = os.Getenv("BASE_URL")
	}

	if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
		baseUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
	}

	parsedUrl := fmt.Sprintf("%s/api/v1/apps/categories/run", baseUrl)
	if len(authorization) > 0 && len(optionalExecutionId) > 0 {
		parsedUrl += fmt.Sprintf("?authorization=%s&execution_id=%s", authorization, optionalExecutionId)
	}

	// Controls if automatic deletion of the execution should happen
	shouldDelete := "true"
	if kmsDebug {
		shouldDelete = "false"
	}

	if strings.Contains(parsedUrl, "?") {
		parsedUrl += fmt.Sprintf("&delete=%s", shouldDelete)
	} else {
		parsedUrl += fmt.Sprintf("?delete=%s", shouldDelete)
	}

	req, err := http.NewRequest(
		"POST", 
		parsedUrl,
		bytes.NewBuffer(marshalledAction),
	)

	if err != nil {
		log.Printf("[ERROR] Failed to create request for KMS action: %s", err)
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	if len(authorization) > 0 && len(optionalExecutionId) == 0 {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authorization))
	}

	client := &http.Client{
		Timeout: time.Second * 60,
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed to run KMS action: %s", err)
		return "", err
	}

	if resp.StatusCode >= 300 {
		log.Printf("[ERROR] Failed to run KMS action due to bad status: %s", resp.Status)
		return "", errors.New(fmt.Sprintf("Failed to run KMS action: %s", resp.Status))
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read response body from KMS action: %s", err)
		return "", err
	}

	authConfig := fmt.Sprintf("%s,%s,,%s", baseUrl, authorization, optionalExecutionId)
	output, err := RunKmsTranslation(ctx, body, authConfig, associatedKey)
	if err != nil {
		log.Printf("[ERROR] Failed to translate KMS response (1): %s", err)
		return "", err
	}

	// Encrypt & cache for the key for a few minutes
	err = SetKmsCache(ctx, auth, key, output, 5)
	if err != nil {
		log.Printf("[ERROR] Failed to set KMS cache: %s", err)
	}

	return output, nil
}

func FindHttpBody(fullBody []byte) (HTTPOutput, []byte, error) {
	kmsResponse := SubflowData{}
	httpOutput := &HTTPOutput{} 
	err := json.Unmarshal(fullBody, &kmsResponse)
	if err != nil {
		log.Printf("[ERROR] %s - Failed to unmarshal Schemaless response to match SubflowData struct (1): %s", string(fullBody), err)
		return *httpOutput, []byte{}, err
	}

	// Handled for weird empty bodies
	if strings.Contains(kmsResponse.Result, `"body": "",`) {
		kmsResponse.Result = strings.Replace(kmsResponse.Result, `"body": "",`, `"body": {},`, -1)
	}

	// Make result into a body as well
	err = json.Unmarshal([]byte(kmsResponse.Result), httpOutput)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal Schemaless HTTP Output response (2): %s. Data: %s", err, kmsResponse.Result)
		return *httpOutput, []byte{}, err
	}

	if httpOutput.Status >= 300 && httpOutput.Status != 404 {
		if debug { 
			log.Printf("[DEBUG] Translated action failed with status: %d. Rerun Autocorrecting feature!", httpOutput.Status)
		}

		return *httpOutput, []byte{}, errors.New(fmt.Sprintf("Status: %d", httpOutput.Status))
	}

	marshalledBody, err := json.Marshal(httpOutput.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal Schemaless HTTP Body response body back to byte: %s", err)
		return *httpOutput, []byte{}, err
	}

	return *httpOutput, marshalledBody, nil
}

// Translates the output of the KMS action to a usable format in the 
// { "kms_key": "key", "kms_value": "value" } format
func RunKmsTranslation(ctx context.Context, fullBody []byte, authConfig, paramName string) (string, error) {
	// We need to parse the response from the KMS action
	// 1. Find JUST the result data
	_, marshalledBody, err := FindHttpBody(fullBody)
	if err != nil {
		log.Printf("[ERROR] Failed to find HTTP body in KMS response: %s", err)
		return string(fullBody), err
	}

	// Added a filename_prefix to know which field each belongs to
	schemalessOutput, err := schemaless.Translate(ctx, "get_kms_key", marshalledBody, authConfig, fmt.Sprintf("filename_prefix:%s-", paramName))
	if err != nil {
		log.Printf("[ERROR] Failed to translate KMS response (2): %s", err)
		return string(fullBody), err
	}

	var labeledResponse map[string]string
	err = json.Unmarshal(schemalessOutput, &labeledResponse)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal KMS response (3): %s", err)
		return string(fullBody), err
	}


	// We need to check if the response is in the format we expect
	/*
	// Without key IS ok.
	if _, ok := labeledResponse["kms_key"]; !ok {
		log.Printf("[ERROR] KMS response does not contain the key 'kms_key'")
		return "", errors.New("KMS response does not contain the key 'kms_key'")
	}
	*/
	if _, ok := labeledResponse["kms_value"]; !ok {
		log.Printf("[ERROR] KMS response does not contain the key 'kms_value'")
		return "", errors.New("KMS response does not contain the key 'kms_value'")
	}

	// Key isn't even needed lol
	if len(paramName) > 0 {
		labeledResponse["kms_key"] = paramName
	}

	//foundKey := labeledResponse["kms_key"]
	//log.Printf("\n\n\n[DEBUG] Found KMS value for key: %s\n\n\n", labeledResponse["kms_value"])
	foundValue := labeledResponse["kms_value"]

	return foundValue, nil
}



func FindNextApiStep(action Action, stepOutput []byte, additionalInfo, inputdata, originalAppname string) (string, Action, error, string) {
	// 1. Find the result field in json
	// 2. Check the status code if it's a good one (<300). If it is, make the output correct based on it and add context based on output.
	// 3. If 400-499, check for error message and self-correct. e.g. if body says something is wrong, try to fix it. If status is 415, try to add content-type header.
	//log.Printf("[INFO] Output from app: %s", string(stepOutput))

	actionName := strings.Replace(action.Name, "_", " ", -1)

	// Unmarshal stepOutput to a map and find result field
	var stepOutputMap map[string]interface{}
	err := json.Unmarshal(stepOutput, &stepOutputMap)
	if err != nil {
		log.Printf("[ERROR] Error unmarshalling stepOutput: %s", err)
		return "", action, err, additionalInfo
	}

	success1, ok := stepOutputMap["success"]
	if !ok {
		log.Printf("[ERROR] No success field found in stepOutput")
	} else {
		// Check if bool
		if success1, ok := success1.(bool); ok {
			if success1 == false {
				log.Printf("[ERROR] Success field is false in stepOutput for finding the next thing to do. Most likely related to action not finishing / bad input: %s", string(stepOutput))
				return "", action, fmt.Errorf("Ran action towards App %s with Action %s, but it failed. Please try to re-authenticate the app or contact support@shuffler.io", action.AppName, actionName), additionalInfo
			}
		}
	}

	result1, ok := stepOutputMap["result"]
	if !ok {
		log.Printf("[ERROR] No result field found in stepOutput")
		return "", action, err, additionalInfo
	}

	result := result1.(string)
	//result = strings.Replace(result, "\\\"", "\"", -1)
	//log.Printf("[INFO] Result: %s", result)

	// Unmarshal result to a map and find status code
	var resultMap map[string]interface{}
	err = json.Unmarshal([]byte(result), &resultMap)
	if err != nil {
		log.Printf("[ERROR] Error unmarshalling result from string to map: %s", err)
		return "", action, err, additionalInfo
	}

	status := -1
	statusCode, ok := resultMap["status"]
	if !ok {
		//log.Printf("[ERROR] No status code found in stepOutput")
	} else {
		// Check if int
		if val, ok := statusCode.(int); ok {
			status = val
		} else if val, ok := statusCode.(float64); ok {
			status = int(val)
		}

		if status != -1 {
			//log.Printf("[INFO] Status code: %d", status)

			if status >= 200 && status < 300 {
				// Handle 200s
			} else if status == 401 {
				// Handle 401
				log.Printf("[ERROR] 401 status code. Most likely related to authentication. Asking for re-auth.")
				return "", action, errors.New(fmt.Sprintf("Ran action towards App %s with Action %s, but it failed. Try to re-authenticate the app or contact support@shuffler.io", action.AppName, actionName)), additionalInfo

			} else if status >= 400 && status < 500 {
				// Handle 400s, e.g. 415 that matches body

				// Based on body X and status Y, suggest what we should do next with this result
				// Our current fields are these:
			}
		}
	}

	if strings.Contains(result, "Max retries exceeded with url") {
		log.Printf("[ERROR] Max retries exceeded with url. Most likely related to authentication. Asking for re-auth.")
		return "", action, fmt.Errorf("Ran action towards App %s with Action %s, but it failed. Try to re-authenticate the app with the correct URL", action.AppName, actionName), additionalInfo
	}

	body := []byte{}
	body1, bodyOk := resultMap["body"]
	if !bodyOk {
		log.Printf("[ERROR] No body found in stepOutput. Setting body to be full request")

		// Checking for success and setting fake status
		// find success in resultMap
		success1, successOk := resultMap["success"]
		if successOk {
			log.Printf("[ERROR] No success field found in stepOutput")

			if success1, ok := success1.(bool); ok {
				body = []byte(result)

				log.Printf("In here? %v", success1)
				if success1 == true {
					status = 200
				} else {
					status = 400
				}

				bodyOk = true
			} else {
				log.Printf("[ERROR] No success field found in stepOutput")
			}
		}
	}

	if bodyOk {
		if val, ok := body1.(map[string]interface{}); ok {
			// Marshal
			body, err = json.Marshal(val)
			if err != nil {
				log.Printf("[ERROR] Error marshalling body in response: %s", err)
				return "", action, err, additionalInfo
			}
		} else if val, ok := body1.(string); ok {
			body = []byte(val)
		}

		if debug {
			log.Printf("[DEBUG] Inside body handler: %s", string(body))
		}

		// Should turn body into a string and check OpenAPI for problems if status is bad
		if status >= 0 && status < 300 {
			//useApp := action.AppName
			//if len(originalAppname) > 0 {
			//	useApp = originalAppname
			//}
			//outputString := HandleOutputFormatting(string(body), inputdata, useApp)
			//log.Printf("[INFO] Output string from OpenAI to be returned: %s", outputString)

			return string(body), action, nil, additionalInfo
		} else if status >= 400 {
			// Auto-correct
			// Auto-fix etc

			log.Printf("[INFO] Trying autocorrect. See body: %s", string(body))

			useApp := action.AppName
			if len(originalAppname) > 0 {
				useApp = originalAppname
			}

			action, additionalInfo, err := RunSelfCorrectingRequest(action, status, additionalInfo, string(body), useApp, inputdata)
			if err != nil {
				if !strings.Contains(err.Error(), "missing_fields") { 
					log.Printf("[ERROR] Error running self-correcting request: %s", err)
				}

				return "", action, err, additionalInfo
			}

			return "", action, nil, additionalInfo

			// Try to fix the request based on the body
		} else {
			log.Printf("[ERROR] Status code is not in the 200s or 400s. Status: %d", status)

			return "", action, errors.New(getBadOutputString(action, action.AppName, inputdata, string(body), status)), additionalInfo
		}
	}

	return "", action, errors.New(getBadOutputString(action, action.AppName, inputdata, string(body), status)), additionalInfo
}

func RunSelfCorrectingRequest(action Action, status int, additionalInfo, outputBody, appname, inputdata string) (Action, string, error) {
	// Add all fields with value from here
	additionalInfo = ""
	inputBody := "{\n"
	for _, param := range action.Parameters {
		//if param.Name == "headers" || param.Name == "ssl_verify" || param.Name == "to_file" || param.Name == "url" || strings.Contains(param.Name, "username_") || strings.Contains(param.Name, "password_") {
		if param.Name == "ssl_verify" || param.Name == "to_file" || param.Name == "url" || strings.Contains(param.Name, "username_") || strings.Contains(param.Name, "password_") {
			continue
		}

		// FIXME: Skip all other things for now for some reason?
		//if param.Name != "body" {
		//	continue
		//}

		checkValue := strings.TrimSpace(strings.Replace(param.Value, "\n", "", -1))
		if  (strings.HasPrefix(checkValue, "{") && strings.HasSuffix(checkValue, "}")) || (strings.HasPrefix(param.Value, "[") && strings.HasSuffix(param.Value, "]")) {
			inputBody += fmt.Sprintf("\"%s\": %s,\n", param.Name, param.Value)
			continue
		}

		// Check if number
		_, err := strconv.ParseFloat(param.Value, 64)
		if err == nil {
			inputBody += fmt.Sprintf("\"%s\": %s,\n", param.Name, param.Value)
			continue
		}

		// Check if bool
		if param.Value == "true" || param.Value == "false" {
			inputBody += fmt.Sprintf("\"%s\": %s,\n", param.Name, param.Value)
			continue
		}

		inputBody += fmt.Sprintf("\"%s\": \"%s\",\n", param.Name, param.Value)
	}

	// Remove comma at the end
	invalidFields := map[string]string{}
	invalidFieldsString := "The following are previous attempts at changing the field which failed. They are invalid fields that need to be fixed.\n"
	for _, param := range action.InvalidParameters {
		invalidFields[param.Name] = param.Value
		invalidFieldsString += fmt.Sprintf("%s: %s\n", param.Name, param.Value)
	}

	if len(invalidFieldsString) <= 68 {
		log.Printf("\n\n[INFO] Invalid fields not set from %d invalid params. Len: %d", len(action.InvalidParameters), len(invalidFieldsString))
		invalidFieldsString = ""
	}

	if strings.HasSuffix(inputBody, ",\n") {
		inputBody = inputBody[:len(inputBody)-2]
	}

	if !strings.HasSuffix(strings.TrimSpace(inputBody), "}") {
		inputBody += "\n}"
	}

	// Append previous problems too
	outputBodies := outputBody

	//log.Printf("[Critical] InputBody generated here: %s", inputBody)
	//log.Printf("[Critical] OutputBodies generated here: %s", outputBodies)

	//appendpoint := "/gmail/v1/users/{userId}/messages/send"
	if !strings.Contains(additionalInfo, "How the API works") && len(additionalInfo) > 0 {
		additionalInfo = fmt.Sprintf("How the API works: %s\n", additionalInfo)
	}

	//systemMessage := fmt.Sprintf("Return all fields from the last paragraph in the same JSON format they came in. Must be valid JSON as an output.")
	systemMessage := fmt.Sprintf(`Return all key:value pairs from the last paragraph, but with modified values to fix the HTTP error. Output must be valid JSON as an output. Don't add in any comments. Anything starting with $ is a variable and should be replaced with the correct value (Example if $helpful_function.parameter.value is present ANYWHERE in YOUR output -> This HAS to be replaced with the correct value provided by the user IF it exists at all, then make sure that you replace all values starting with $ with the correct output, else don't do anything about this).

	Strict output rules to follow:

	1. Validation Requirements:
	   - Modify ONLY the fields directly related to the HTTP error
	   - Use ONLY values derived from:
		 a) Error message context
		 b) Existing JSON structure
		 c) Minimal necessary changes to resolve the error
	
	2. Strict Constraints:
	   - NO invented values
	   - NO external data generation
	   - MUST use keys present in original JSON
	   - MUST maintain original JSON structure
	   - DON'T use older values or examples
	
	3. Output Format:
	   - Provide corrected JSON
	   - No comments. Must be valid JSON.

	4. User Error Handling:
	   - IF we are missing a value for the user to input, return the format {"success": false, "missing_fields": ["field1", "field2"]} to indicate the missing fields. ONLY do this if the field(s) are REQUIRED, and make the fields human readable.

	`)

	inputData := fmt.Sprintf(`Precise JSON Field Correction Instructions:
Given the HTTP API context for %s:
- HTTP Status: %d
- Detailed Error: %s

Input JSON Payload:
%s`, appname, status, outputBodies, inputBody)

	// Use this for debugging
	if debug {
		log.Printf("[DEBUG] INPUTDATA:\n\n\n\n'''%s''''\n\n\n\n", inputData)
	}

	contentOutput, err := RunAiQuery(systemMessage, inputData) 
	if err != nil {
		return action, additionalInfo, err
	}

	//log.Printf("\n\nTOKENS (AUTOFIX API~): In: %d, Out: %d\n\n", (len(systemMessage)+len(inputData))/4, len(contentOutput)/4)

	contentOutput = FixContentOutput(contentOutput)

	if debug { 
		log.Printf("[DEBUG] Autocorrected output: %s", contentOutput)
	}

	// Fix the params based on the contentOuput JSON
	// Parse output into JSOn
	var outputJSON map[string]interface{}
	err = json.Unmarshal([]byte(contentOutput), &outputJSON)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshalling data '%s'. Failed to unmarshal outputJSON in action fix for app %s with action %s: %s", contentOutput, appname, action.Name, err)

		return action, additionalInfo, errors.New(getBadOutputString(action, appname, inputdata, outputBody, status))
	}

	if strings.Contains(contentOutput, "missing_fields") {
		successField, ok := outputJSON["success"] 
		if ok {
			if successField, ok := successField.(bool); ok {
				if successField == false {
					return action, additionalInfo, errors.New(contentOutput)
				}
			}
		}

		log.Printf("[ERROR] Missing fields, but not skipping. Raw: %s", contentOutput)
	}

	sendNewRequest := false
	for paramIndex, param := range action.Parameters {
		// Check if inside outputJSON
		if val, ok := outputJSON[param.Name]; ok {

			//log.Printf("[INFO] Found param %s in outputJSON", param.Name)
			// Check if it's a string or not
			runString := false
			formattedVal := ""
			if _, ok := val.(string); ok {
				runString = true
				formattedVal = val.(string)
			}

			if !runString {
				// Make map from val and marshal to byte

				stringType := reflect.TypeOf(val).String()
				if stringType == "map[string]interface {}" {
					valByte, err := json.Marshal(val)
					if err != nil {
						log.Printf("[ERROR] Failed to marshal val in action fix for app %s with action %s: %s. Field: %s", appname, action.Name, err, param.Name)
					} else {
						formattedVal = string(valByte)
					}
				} else if valMap, ok := val.(map[string]interface{}); !ok {
					valByte, err := json.Marshal(valMap)
					if err != nil {
						log.Printf("[ERROR] Failed to marshal valMap in action fix for app %s with action %s: %s. Field: %s", appname, action.Name, err, param.Name)
						continue
					}

					formattedVal = string(valByte)
				} else {
					// Check if val is a map[string]interface{}, and not interface{} 
					log.Printf("[ERROR] Failed to convert val of %#v to map[string]interface{} in action fix for app %s with action %s. Field: %s. Type: %#v. Value: %#v", param.Name, appname, action.Name, param.Name, reflect.TypeOf(val), val)
				}
			}

			// Check if value is base64 and decode if no mention of base64 previously
			if param.Name == "body" && strings.HasSuffix(param.Value, "=") {
				// Try to base64 decode the value
				decoded, err := base64.StdEncoding.DecodeString(formattedVal)
				if err == nil {
					log.Printf("[INFO] Decoded base64 value for param %s in outputJSON", param.Name)
					formattedVal = string(decoded)
				}
			}

			if formattedVal != param.Value && len(formattedVal) > 0 {
				// Check if already in invalid as well
				// Stored here so we can use them for context
				// Update param
				//param.Value = fmt.Sprintf("%v", val)
				action.InvalidParameters = append(action.InvalidParameters, param)

				action.Parameters[paramIndex].Value = formattedVal
				sendNewRequest = true
			} else {
				//log.Printf("[INFO] Param %s is already same as new one, or wasn't formatted correctly. Type of val: %s", param.Name, reflect.TypeOf(val))

				// Fixme: In the future fix this. For now, we just spam it down until we got 200~ response
				//sendNewRequest = true
			}
		} else {
			reservedParams := []string{"ssl_verify", "to_file"}
			if !ArrayContains(reservedParams, param.Name) {
				//log.Printf("[ERROR] Param %s not found in outputJSON for app %s with action %s", param.Name, appname, action.Name)
			}
		}
	}

	if !sendNewRequest {
		// Should have a good output anyway, meaning to format the bad request

		// Make errorString work in json

		return action, additionalInfo, errors.New(getBadOutputString(action, appname, inputdata, outputBody, status))
	}

	return action, additionalInfo, nil
}

func getBadOutputString(action Action, appname, inputdata, outputBody string, status int) string {
	outputParams := ""
	for _, param := range action.Parameters {
		if param.Name == "headers" || param.Name == "ssl_verify" || param.Name == "to_file" {
			continue
		}

		if len(param.Value) > 0 {
			outputParams += fmt.Sprintf("\"%s\": \"%s\"", param.Name, param.Value)
		}
	}

	outputData := fmt.Sprintf("Fields: %s\n\nHTTP Status: %d\nHTTP error: %s", outputParams, status, outputBody)

	if debug { 
		log.Printf("[DEBUG] Skipping output formatting (bad output string)")
	}
	//errorString := HandleOutputFormatting(string(outputData), inputdata, appname)

	return outputData 
}

// Ask itself for information about the API in case it has it
// FIXMe: Add internet to search for the relevant API as well
func getOpenApiInformation(appname, action string) string {
	var err error
	var contentOutput string
	action = GetCorrectActionName(action)

	systemMessage := fmt.Sprintf("Output a valid JSON body format for a HTTP request %s in the %s API?", action, appname)

	//log.Printf("[INFO] System message (find API documentation): %s", systemMessage)
	contentOutput, err = RunAiQuery(systemMessage, "") 
	if err != nil {
		log.Printf("[ERROR] Failed to run API query: %s", err)
	}

	if strings.Contains(contentOutput, "success\": false") {
		return ""
	}

	return contentOutput
}

func UpdateActionBody(action WorkflowAppAction) (string, error) {
	currentParam := "body"
	if len(action.Name) == 0 {
		return "", errors.New("No action name found")
	}

	if len(action.AppName) == 0 {
		return "", errors.New("No app name found")
	}

	newName := strings.Replace(strings.Title(GetCorrectActionName(action.Name)), " ", "_", -1)

	systemMessage := fmt.Sprintf("Output a valid HTTP body to %s in %s. Only add required fields. Output ONLY JSON without explainers.", newName, action.AppName)
	userMessage := ""

	log.Printf("\n\nBODY CREATE SYSTEM MESSAGE: %s\n\n", systemMessage)

	contentOutput, err := RunAiQuery(systemMessage, userMessage)
	if err != nil {
		log.Printf("[ERROR] Failed to run API query: %s", err)
		return "", err
	}

	contentOutput = FixContentOutput(contentOutput)

	output := map[string]interface{}{}
	err = json.Unmarshal([]byte(contentOutput), &output)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal JSON in get action body for find http endpoint (8): %s", err)
		return "", errors.New("Failed to find JSON in output 2")
	} else {
		// Should save as new backup for the field? 
		// 1. Find the app
		// 2. Find the action
		// 3. Save the body as a backup for the action

		ctx := context.Background()
		app, err := GetApp(ctx, action.AppID, User{}, false)
		if err != nil {
			log.Printf("[ERROR] Failed to get app in get action body for find http endpoint (9): %s", err)
			return contentOutput, nil
		}

		for actionIndex, foundAction := range app.Actions {
			if foundAction.Name != action.Name {
				continue
			}

			log.Printf("[INFO] Found action %s in app %s", foundAction.Name, app.Name)
			for paramIndex, param := range foundAction.Parameters {
				if param.Name != currentParam {
					continue
				}

				if len(param.Value) > 0 && len(param.Example) > 0 {
					return contentOutput, nil
				}

				log.Printf("\n\n[INFO] Found body param %s in action %s in app %s. Setting action example.\n\n", param.Name, foundAction.Name, app.Name)

				param.Example = contentOutput
				param.Tags = []string{"Generated"}

				app.Actions[actionIndex].Parameters[paramIndex] = param
				go SetWorkflowAppDatastore(ctx, *app, app.ID)

				openapiWrapper, err := GetOpenApiDatastore(ctx, app.ID)
				if err != nil {
					log.Printf("[WARNING] Failed to get openapi datastore in get action body for find http endpoint (10): %s", err)
					return contentOutput, nil
				}

				// Update openapi with new body

				swaggerLoader := openapi3.NewSwaggerLoader()
				swaggerLoader.IsExternalRefsAllowed = true
				openapi, err := swaggerLoader.LoadSwaggerFromData([]byte(openapiWrapper.Body))
				if err != nil {
					log.Printf("[ERROR] Failed to unmarshal openapi in get action body for find http endpoint (11): %s", err)
					return contentOutput, nil
				}

				// Find the path
				actionName := GetCorrectActionName(foundAction.Name)

				updated := false
				for pathIndex, pathItem := range openapi.Paths {
					// Loop all path operations WITHOUT []string{method} and GetOperaiton().
					for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"} {
						operation := pathItem.GetOperation(method)
						if operation == nil {
							continue
						}

						correctName := strings.Replace(strings.ToLower(GetCorrectActionName(operation.Summary)), " ", "_", -1)
						if correctName != actionName {
							//log.Printf("[INFO] Skipping method %s with summary '%s' as it doesn't match action '%s'", method, correctName, actionName)
							continue
						}

						// RequestBody.Body.Example
						log.Printf("\n\n[INFO] Found method %s for action %s\n\n", method, action.Name)

						// Should set updated IF we find the correct operation
						// If DOESNT exist at all, write it from scratch
						// If content exists but example doesn't, overwrite it

						// propertypath: 
						// paths["/rest/api/3/issue"].post.requestBody.content.example.example
						if operation.RequestBody == nil {
							log.Printf("IN NEW BODY")
							operation.RequestBody = &openapi3.RequestBodyRef{
								Value: &openapi3.RequestBody{
									Description: "",
									Required:    true,
									Content:     map[string]*openapi3.MediaType{
										"example": {
											Example: contentOutput,
										},
									},
								},
							}

							updated = true
						} else {
							log.Printf("FOUND EXISTING BODY")

							foundContent := false
							for contentIndex, content := range operation.RequestBody.Value.Content {
								// Check if it's in the "example" content type
								if contentIndex == "example" {
									foundContent = true
								}

								log.Printf("[INFO] Found content %s in operation %s. Value: %#v", contentIndex, operation.Summary, content)
								if content.Example == nil {
									operation.RequestBody.Value.Content[contentIndex].Example = contentOutput
									updated = true
								} else {
									// Check if string length of example is 0
									if contentExample, ok := content.Example.(string); ok {
										log.Printf("[INFO] Found content %s in operation %s. Value: %s", contentIndex, operation.Summary, contentExample)
										if len(contentExample) < 5 {
											updated = true
											operation.RequestBody.Value.Content[contentIndex].Example = contentOutput
										}
									}
								}
							}

							if !foundContent {
								// Append
								updated = true
								operation.RequestBody.Value.Content["example"] = &openapi3.MediaType{
									Example: contentOutput,
								}
							}
						}

						if updated {
							// Update the path in openapi.paths
							openapi.Paths[pathIndex].SetOperation(method, operation)
						}
					}

					if updated {
						break
					} 
				}

				if updated {
					log.Printf("[INFO] Updated openapi with new body for action %s in app %s", action.Name, app.Name)

					// FIXME: Actually update it back in the database
					newBody, err := json.Marshal(openapi)
					if err != nil {
						log.Printf("[ERROR] Failed to marshal openapi in get action body for find http endpoint (12): %s", err)
					} else {
						openapiWrapper.Body = string(newBody)

						err = SetOpenApiDatastore(ctx, openapiWrapper.ID, openapiWrapper) 
						if err != nil {
							log.Printf("[ERROR] Failed to set openapi datastore in get action body for find http endpoint (12): %s", err)
						}
					}

					break
				}
			}
		}
	}

	return contentOutput, nil
}


// Uploads modifyable parameter data to file storage, as to be used in the future executions of the app
func UploadParameterBase(ctx context.Context, orgId, appId, actionName, paramName, paramValue string) error {
	timeNow := time.Now().Unix()

	// Check if the file already exists
	fileId := fmt.Sprintf("file_parameter_%s-%s-%s-%s.json", orgId, strings.ToLower(appId), strings.Replace(strings.ToLower(actionName), " ", "_", -1), strings.ToLower(paramName))

	category := "app_defaults"
	if standalone {
		fileId = fmt.Sprintf("%s/%s", category, fileId)
	}

	file, err := GetFileSingul(ctx, fileId)
	if err == nil && file.Status == "active" {
		if debug { 
			log.Printf("[DEBUG] Parameter file '{root}/singul/%s' already exists. NOT re-uploading", fileId)
		}

		return nil
	}

	filename := fileId
	folderPath := fmt.Sprintf("%s/%s/%s", basepath, orgId, "global")
	downloadPath := fmt.Sprintf("%s/%s", folderPath, fileId)

	newFile := File{
		Id:           fileId,
		CreatedAt:    timeNow,
		UpdatedAt:    timeNow,
		Description:  "",
		Status:       "created",
		Filename:     filename,
		OrgId:        orgId,
		WorkflowId:   "global",
		DownloadPath: downloadPath,
		Subflows:     []string{},
		StorageArea:  "local",
		Namespace:    category,
		Tags:         []string{"parameter base"},
	}

	err = SetFileSingul(ctx, newFile)
	if err != nil {
		log.Printf("[ERROR] Failed to set file in uploadParameterBase: %s", err)
		return err
	}

	// Upload to /api/v1/files/{fileId}/upload with the data from paramValue
	parsedKey := fmt.Sprintf("%s_%s", orgId, newFile.Id)
	fileId, err = UploadFileSingul(ctx, &newFile, parsedKey, []byte(paramValue))
	if err != nil {
		log.Printf("[ERROR] Failed to upload file in uploadParameterBase: %s", err)
		return err
	}

	return nil
}

func FixContentOutput(contentOutput string) string {
	if strings.Contains(contentOutput, "```json") {
		// Handle ```json
		start := strings.Index(contentOutput, "```json")
		end := strings.Index(contentOutput, "```")
		if start != -1 {
			end = strings.Index(contentOutput[start+7:], "```")

			// Shift it so the index is at the correct place
			end = end + start+7
		}


		if start != -1 && end != -1 {
			newend := end+7	
			newstart := start+7

			log.Printf("[INFO] Found ``` in content. Start: %d, end: %d", start, end)

			if newend > len(contentOutput) {
				newend = end
			}

			if newend > len(contentOutput) {
				newend = len(contentOutput)
			}

			if newstart > len(contentOutput) {
				newstart = start
			}

			if newstart > len(contentOutput) {
				newstart = len(contentOutput)
			}

			contentOutput = contentOutput[start+7 : newend]
		}
	}

	if strings.Contains(contentOutput, "```") {
		start := strings.Index(contentOutput, "```")
		end := strings.Index(contentOutput[start+3:], "```")
		if start != -1 {
			end = strings.Index(contentOutput[start+3:], "```")
			end = end + start+3
		}
			
		if start != -1 && end != -1 {
			contentOutput = contentOutput[start+3 : end+3]
		}
	}

	contentOutput = strings.Trim(contentOutput, " ")
	contentOutput = strings.Trim(contentOutput, "\n")
	contentOutput = strings.Trim(contentOutput, "\t")

	return contentOutput
}

func AutofixAppLabels(app WorkflowApp, label string, keys []string) (WorkflowApp, WorkflowAppAction) {
	if len(app.ID) == 0 || len(app.Name) == 0 {
		log.Printf("[ERROR] No app ID or name found in AutofixAppLabels")
		return app, WorkflowAppAction{}
	}

	if len(app.Actions) == 0 {
		log.Printf("[ERROR] No actions found in AutofixAppLabels for app %s (%s)", app.Name, app.ID)
		return app, WorkflowAppAction{}
	}

	// FIXME: This should NOT be necessary. 
	// If there is no label, we should automatically try to catch it
	// Maybe if category is not defined as well
	if len(label) == 0 {
		log.Printf("[ERROR] No label found in AutofixAppLabels for app %s (%s)", app.Name, app.ID)
		return app, WorkflowAppAction{}
	}

	// // Double check if it has it or not
	parsedLabel := strings.ToLower(strings.ReplaceAll(label, " ", "_"))
	for _, action := range app.Actions {
		for _, actionLabel := range action.CategoryLabel {
			parsedActionLabel := strings.ToLower(strings.ReplaceAll(actionLabel, " ", "_"))
			if parsedActionLabel == parsedLabel {
				return app, action
			}
		}
	}

	// Fix the label to be as it is in category (uppercase + spaces)
	// fml, there is no consistency to casing + underscores, so we keep the new

	log.Printf("[INFO][AI] Running app fix for label '%s' for app %s (%s) with %d actions", label, app.Name, app.ID, len(app.Actions))

	// Just a reset, as Other doesn't really achieve anything directly
	if len(app.Categories) > 0 && app.Categories[0] == "Other" {
		app.Categories = []string{}
	}

	// Check if the app has any actions
	foundCategory := AppCategory{}
	availableCategories := GetAppCategories()
	for _, category := range availableCategories {
		lowercaseCategory := strings.ToLower(category.Name)
		if len(app.Categories) == 0 {
			break
		}

		for _, appCategory := range app.Categories {
			if strings.ToLower(appCategory) != lowercaseCategory {
				continue
			}

			foundCategory = category
			break
		}

		if len(foundCategory.Name) > 0 {
			break
		}
	}

	updatedIndex := -1
	if len(foundCategory.ActionLabels) == 0 {
		for _, category := range availableCategories {
			for _, actionLabel := range category.ActionLabels {
				if strings.ToLower(actionLabel) != strings.ToLower(label) {
					continue
				}

				foundCategory = category
				app.Categories = append(app.Categories, category.Name)
				break
			}
		}

		if len(foundCategory.Name) == 0 {
			log.Printf("[DEBUG] No category found for app %s (%s). Checking based on input label, then using that category in app setup", app.Name, app.ID)
			systemMessage := `Your goal is to find the correct CATEGORY for the app to be in. Synonyms are accepted, and you should be very critical to not make mistakes. If none match, don't add any. A synonym example can be something like: cases = alerts = issues = tasks, or messages = chats = communicate. If it exists, return {"success": true, "category": "<category>"} where <category> is replaced with the category found. If it does not exist, return {"success": false, "category": "Other"}. Output as only JSON."`

			categories := ""
			for _, category := range availableCategories {
				categories += fmt.Sprintf("%s,", category.Name)	
			}

			userMessage := fmt.Sprintf("The app name is '%s'. Available categories are: %s. Here are SOME actions it can do:\n", app.Name, strings.Trim(categories, ","))
			for cnt, action := range app.Actions {
				userMessage += fmt.Sprintf("%s\n", action.Name)
				if cnt > 25 {
					break
				}
			}

			output, err := RunAiQuery(systemMessage, userMessage) 
			log.Printf("[DEBUG] Autocomplete output for category '%s' in '%s' (%d actions): %s", label, app.Name, len(app.Actions), output)
			if err != nil {
				log.Printf("[ERROR] Failed to run AI query in AutofixAppLabels for category with app %s (%s): %s", app.Name, app.ID, err)
				return app, WorkflowAppAction{}
			} 

			type ActionStruct struct {
				Category string `json:"category"`
			}

			output = FixContentOutput(output) 
			actionStruct := ActionStruct{}
			err = json.Unmarshal([]byte(output), &actionStruct)
			if err != nil {
				log.Printf("[ERROR] FAILED action mapping parsed output: %s", output)
			}

			if len(actionStruct.Category) == 0 {
				log.Printf("[ERROR] No category found for app %s (%s) based on label %s (1)", app.Name, app.ID, label)
				return app, WorkflowAppAction{}
			}

			app.Categories = append(app.Categories, actionStruct.Category)

			// Forces app to update
			if len(app.Actions) > 0 { 
				updatedIndex = 0
			}

			for _, category := range availableCategories {
				if category.Name != actionStruct.Category {
					continue
				}

				foundCategory = category
				break
			}
		}
	}

	if len(foundCategory.ActionLabels) == 0 { 

		log.Printf("[ERROR] No category found for app %s (%s) based on label %s", app.Name, app.ID, label)
		return app, WorkflowAppAction{}
	}

	var guessedAction WorkflowAppAction
	type ActionStruct struct {
		Action string `json:"action"`
	}

	actionStruct := ActionStruct{}
	var output string
	ctx := context.Background()

	tmpAppAction, cacheGeterr := GetAutofixAppLabelsCache(ctx, app, label, keys)
	if cacheGeterr == nil {
		if len(tmpAppAction.Label) == 0 {
			log.Printf("[ERROR] No label found in cache for app %s (%s) based on label %s", app.Name, app.ID, label)
			cacheGeterr = errors.New("No label found in cache")
		} else {
			guessedAction = tmpAppAction
			log.Printf("[INFO] Found app from cache in AutofixAppLabels for app %s (%s) based on label %s -- %#v", app.Name, app.ID, label, guessedAction)
			guessedActionString, err := json.Marshal(guessedAction)
			if err != nil {
				log.Printf("[ERROR] Failed to marshal guessed action in AutofixAppLabels for app %s (%s): %s", app.Name, app.ID, err)
				cacheGeterr = err
			}

			actionStruct.Action = string(guessedActionString)
		}
	} else {
		log.Printf("[ERROR] Failed to get app from cache in AutofixAppLabels for app %s (%s): %s", app.Name, app.ID, cacheGeterr)
	}

	// FIXME: Run AI here to check based on the label which action may be matching
	
	// Old attempts 
	//systemMessage := fmt.Sprintf(`Find which action is most likely to be used based on the label '%s'. If any match, return their exact name and if none match, write "none" as the name. Return in the JSON format {"action": "action name"}`, label)
	//userMessage := "The available actions are as follows:\n"

	if cacheGeterr != nil {
		systemMessage := `Your goal is to find the most correct action for a specific label from the actions. You have to pick the most likely action. Synonyms are accepted, and you should be very critical to not make mistakes. A synonym example can be something like: cases = alerts = issues = tasks, or messages = chats = communicate = contacts. Be extra careful of not confusing LIST and GET operations, based on the user query, respond with the most likely action. If it exists, return {"success": true, "action": "<action>"} where <action> is replaced with the action found. If it does not exist, Last case scenario is return {"success": false, "action": ""}. Output as only JSON."`
		userMessage := fmt.Sprintf("Out of the following actions, which action matches '%s'?\n", label)

		for _, action := range app.Actions {
			if action.Name == "custom_action" {
				continue
			}

			userMessage += fmt.Sprintf("%s\n", action.Name)	
		}

		if len(keys) > 0 {
			userMessage += fmt.Sprintf("\nUse the keys provided by the user. Your goal is to guess the action name with it's name as well. Keys: %s\n", strings.Join(keys, ", "))
		}

		log.Printf("[INFO] System message (find action): %s", systemMessage)
		log.Printf("[INFO] User message (find action): %s", userMessage)

		output, err := RunAiQuery(systemMessage, userMessage) 
		if err != nil {
			log.Printf("[ERROR] Failed to run AI query in AutofixAppLabels for app %s (%s): %s", app.Name, app.ID, err)
			return app, WorkflowAppAction{}
		} 

		output = FixContentOutput(output)

		log.Printf("[DEBUG] Autocomplete output for label '%s' in '%s' (%d actions): %s", label, app.Name, len(app.Actions), output)

		err = json.Unmarshal([]byte(output), &actionStruct)
		if err != nil {
			log.Printf("[ERROR] FAILED action mapping parsed output: %s", output)
		}

	}

	if len(actionStruct.Action) == 0 && cacheGeterr == nil {
		log.Printf("[ERROR] From LLM auto-label: No action found for app %s (%s) based on label %s (1). Output: %s", app.Name, app.ID, label, string(output))
		//return app
	} else {
		newname := strings.Trim(strings.ToLower(strings.Replace(GetCorrectActionName(actionStruct.Action), " ", "_", -1)), " ")

		//log.Printf("[DEBUG] Looking for action: %s\n\n\n\n", newname)

		for actionIndex, action := range app.Actions {
			searchName := strings.Trim(strings.ToLower(strings.Replace(GetCorrectActionName(action.Name), " ", "_", -1)), " ")

			// For some reason this doesn't find it properly
			if searchName != newname {
				continue
			}

			guessedAction = action

			log.Printf("[INFO] Found action %s in app %s based on label %s", action.Name, app.Name, label)

			// Avoid duplicates in case validation system fails
			foundLabel := false
			newLabels := []string{}
			for _, categoryLabel := range action.CategoryLabel {
				if strings.ToLower(categoryLabel) == "no label" {
					continue
				}

				newLabels = append(newLabels, categoryLabel)
				if strings.ToLower(categoryLabel) == strings.ToLower(label) {
					foundLabel = true
				}
			}

			app.Actions[actionIndex].CategoryLabel = newLabels
			if foundLabel {
				log.Printf("[INFO] %s already has label '%s' in app %s (%s)", action.Name, label, app.Name, app.ID)
				break
			}

			updatedIndex = actionIndex
			app.Actions[actionIndex].CategoryLabel = append(app.Actions[actionIndex].CategoryLabel, label)

			log.Printf("[DEBUG] Adding label %s to action %s in app %s (%s). New labels: %#v", label, action.Name, app.Name, app.ID, app.Actions[actionIndex].CategoryLabel)
			break
		}
	}

	// FIXME: Add the label to the OpenAPI action as well?
	if updatedIndex >= 0 {
		err := SetWorkflowAppDatastore(context.Background(), app, app.ID)
		if err != nil {
			log.Printf("[WARNING] Failed to set app datastore in AutofixAppLabels for app %s (%s): %s", app.Name, app.ID, err)
		}

		//log.Printf("\n\n\n[WARNING] Updated app %s (%s) with label %s. SHOULD update OpenAPI action as well\n\n\n", app.Name, app.ID, label)

		// Find the OpenAPI version and update it too
		openapiApp, err := GetOpenApiDatastore(context.Background(), app.ID)
		if err != nil {
			log.Printf("[WARNING] Failed to get openapi datastore in AutofixAppLabels for app %s (%s): %s", app.Name, app.ID, err)
			return app, WorkflowAppAction{}
		} 

		swaggerLoader := openapi3.NewSwaggerLoader()
		swaggerLoader.IsExternalRefsAllowed = true
		openapi, err := swaggerLoader.LoadSwaggerFromData([]byte(openapiApp.Body))
		if err != nil {
			log.Printf("[ERROR] Failed to unmarshal openapi in AutofixAppLabels for app %s (%s): %s", app.Name, app.ID, err)
			return app, WorkflowAppAction{}
		}


		// Overwrite categories no matter what?
		openapi.Info.Extensions["x-categories"] = app.Categories

		// Find the path
		actionName := GetCorrectActionName(app.Actions[updatedIndex].Name)
		changed := false
		_ = openapi
		log.Printf("OPENAPI, ACTIONNAME: %s", actionName)
		for pathIndex, path := range openapi.Paths {
			_ = pathIndex

			for method, operation := range path.Operations() {
				if operation == nil {
					continue
				}

				correctName := strings.Replace(strings.ToLower(GetCorrectActionName(operation.Summary)), " ", "_", -1)
				if correctName != actionName {
					//log.Printf("[INFO] Skipping method %s with summary '%s' as it doesn't match action '%s'", method, correctName, actionName)
					continue
				}

				log.Printf("[INFO] Found method %s for action %s (OPENAPI) during label mapping for '%s' in app '%s'", method, app.Actions[updatedIndex].Name, label, app.Name)
				if len(operation.Extensions) == 0 {
					operation.Extensions["x-label"] = label
				} else {
					if _, found := operation.Extensions["x-label"]; !found {
						operation.Extensions["x-label"] = label
					} else {
						// add to it with comma?
						operation.Extensions["x-label"] = fmt.Sprintf("%s,%s", operation.Extensions["x-label"], label)
					}
				}

				changed = true 
				openapi.Paths[pathIndex].SetOperation(method, operation)
			}

			if changed {
				break
			}
		}

		if changed {
			parsedOpenapi, err := openapi.MarshalJSON()
			if err != nil {
				log.Printf("[ERROR] Failed to marshal openapi in AutofixAppLabels for app %s (%s): %s", app.Name, app.ID, err)
			} else {
				openapiApp.Body = string(parsedOpenapi)

				log.Printf("[INFO] Updated openapi with new label for action %s in app %s", app.Actions[updatedIndex].Name, app.Name)
				err = SetOpenApiDatastore(context.Background(), openapiApp.ID, openapiApp)
				if err != nil {
					log.Printf("[ERROR] Failed to set openapi datastore in AutofixAppLabels for app %s (%s): %s", app.Name, app.ID, err)
				}
			}
		}

	} else {
		log.Printf("[ERROR] No action found for app %s (%s) based on label %s (2). GPT error most likely. Output: %s", app.Name, app.ID, label, output)
	}

	for paramIndex, param := range guessedAction.Parameters {
		if param.Name == "url" {
			param.Value = ""
		}

		guessedAction.Parameters[paramIndex] = param
	}

	SetAutofixAppLabelsCache(ctx, app, guessedAction, label, keys)
	return app, guessedAction
}

func GetActionAIResponse(ctx context.Context, resp http.ResponseWriter, user User, org Org, outputFormat string, input QueryInput) ([]byte, error) {
	standalone := false
	standaloneEnv := os.Getenv("STANDALONE")
	if standaloneEnv == "true" {
		standalone = true
	}

	respBody := []byte{}
	if project.Environment == "cloud" && !user.SupportAccess {
		//if org.SyncFeatures.ShuffleGPT.Active && org.SyncFeatures.ShuffleGPT.Usage < org.SyncFeatures.ShuffleGPT.Limit {
		if org.SyncFeatures.ShuffleGPT.Usage < 100 {
			log.Printf("[AUDIT] Org %#v (%s) has access to the auto feature. Allowing user %s to use it", org.Name, org.Id,  user.Username)
			org.SyncFeatures.ShuffleGPT.Usage += 1

			// Managing usage (this happens elsewhere as well apparently
			//IncrementCache(ctx, org.Id, "ai_executions", 1)

		} else {
			log.Printf("[AUDIT] User %s (%s) tried to use the auto feature but doesn't have support access. Checking if org has access", user.Username, user.Id)

			if !org.SyncFeatures.ShuffleGPT.Active {
				respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "The Shuffle AI feature is unavailable to your organisation for now. Contact support@shuffler.io if you want to try out this feature."}`))

				resp.WriteHeader(403)
				resp.Write(respBody)
				return respBody, errors.New("User doesn't have access to the feature")
			} else {
				respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "You are above your limits for the The Shuffle AI feature (%d/%d). Resets monthly. Contact support@shuffler.io if you need more credits. 100 AI runs per month are included by default."}`, org.SyncFeatures.ShuffleGPT.Usage, org.SyncFeatures.ShuffleGPT.Limit))
				resp.WriteHeader(429)
				resp.Write(respBody)
				return respBody, errors.New("User doesn't have access to the feature (2)")
			}
		}
	}

	inputQuery := input.Query
	if outputFormat == "raw" {
		relevancyOutput := findRelevantOutput(inputQuery, org, user)
		if len(relevancyOutput) > 0 && !strings.Contains(relevancyOutput, "cannot be answered") && !strings.Contains(relevancyOutput, "does not require") && !(strings.HasPrefix(relevancyOutput, "{") && strings.HasSuffix(relevancyOutput, "}")) {
			log.Printf("[INFO] Found relevant output for '%s': %s", inputQuery, relevancyOutput)
			resp.WriteHeader(500)
			resp.Write([]byte(relevancyOutput))
			return []byte(relevancyOutput), errors.New("Found relevant output")
		}
	}

	var err error
	/*
		googleResp, err := RunGoogleSearch(ctx, inputQuery)
		if err != nil {
			log.Printf("[ERROR] Failed to run google search: %s", err)
		}
		_ = googleResp
	*/

	// Here to fix categories for this part
	appCategories := GetAllAppCategories()
	for _, category := range appCategories {
		if category.Name == "Communication" {
			newCategory := category
			newCategory.Name = "Email"
			appCategories = append(appCategories, newCategory)
			break
		}
	}

	//appCategories := org.SecurityFramework
	parseCategories := "Categories:\n"
	categoryNames := []string{}
	for _, category := range appCategories {
		if category.Name == "Other" {
			continue
		}

		categoryNames = append(categoryNames, strings.ToLower(category.Name))

		parseCategories += fmt.Sprintf("category: %s, labels: ", category.Name)
		for _, actionLabel := range category.ActionLabels {
			parseCategories += fmt.Sprintf(actionLabel)

			// Check if actionLabel in RequiredFields map
			required, ok := category.RequiredFields[actionLabel]
			optional, ok2 := category.OptionalFields[actionLabel]
			if ok {
				parseCategories += fmt.Sprintf(" (%s), ", strings.Join(required, ","))

				if ok2 {
					// Add optional fields
					_ = optional
				}
				// , strings.Join(optional, ",")
			} else {
				parseCategories += ", "
			}
		}

		if len(category.ActionLabels) > 0 {
			parseCategories = parseCategories[:len(parseCategories)-2]
		}

		parseCategories += "\n"
	}

	// Check if appname is specified
	foundApp := WorkflowApp{}
	if len(input.AppId) > 0 {
		// Get app directly
		if standalone {
			newApp, err := GetSingulApp("", input.AppId) 
			if err == nil {
				foundApp = *newApp
			}
		} else {
			newApp, err := GetApp(ctx, input.AppId, user, false)
			if err == nil {
				foundApp = *newApp
			}
		}
	}

	appname := input.AppName
	category := input.Category
	actionName := input.ActionName

	originalAppname := input.AppName
	httpOutput := HTTPWrapper{}

	contentOutput := ""
	var output map[string]interface{}
	if len(appname) == 0 && !strings.Contains(inputQuery, "http://") && !strings.Contains(inputQuery, "https://") {

		//log.Printf("[INFO] Parsed labels: %s", parseCategories)
		systemMessage := "Check if the input categories match any of the categories and action labels. Return the matching category, action label and all required fields in JSON. Required fields are in paranethesis, and should be output in the 'fields' key. If appname is specified add it. If not, output as json {\"success\": false, \"appname\": \"\"} with the name of a brand or app that can answer the question"

		// Parses the input and returns the category and action label
		openaiClient := openai.NewClient(os.Getenv("OPENAI_API_KEY"))
		openaiResp, err := openaiClient.CreateChatCompletion(
			context.Background(),
			openai.ChatCompletionRequest{
				Model: model,
				Messages: []openai.ChatCompletionMessage{
					{
						Role:    openai.ChatMessageRoleSystem,
						Content: systemMessage,
					},
					{
						Role:    openai.ChatMessageRoleAssistant,
						Content: parseCategories,
					},
					{
						Role:    openai.ChatMessageRoleUser,
						Content: inputQuery,
					},
				},
			},
		)

		if err != nil {
			log.Printf("[ERROR] ChatCompletion error: %v\n", err)
			respBody = []byte(`{"success": false, "reason": "Failed to run AI query"}`)
			resp.WriteHeader(500)
			resp.Write(respBody)
			return respBody, err	
		}

		if len(openaiResp.Choices) > 0 {
			log.Printf("[INFO] Raw Output (1): %s", openaiResp.Choices[0].Message.Content)
			contentOutput = openaiResp.Choices[0].Message.Content

			// Used for debugging random inputs
			//contentOutput = `{"success": true, "category": "SIEM", "fields": {"query": "1.2.3.4"}}`

			// Used for analytics testing
			//contentOutput = `{"success": true, "category": "Assets", "action": "Search Assets", "fields": ["appname", "date_range", "asset_type"], "appname": "Google Analytics"}`
		}

		contentOutput = FixContentOutput(contentOutput)

		err = json.Unmarshal([]byte(contentOutput), &output)
		if err != nil {
			log.Printf("[ERROR] Failed to unmarshal output in runActionAI: %s", err)
			respBody = []byte(`{"success": false, "reason": "Failed to parse AI output"}`)
			resp.WriteHeader(500)
			resp.Write(respBody)
			return respBody, err
		}
	} else {
		if outputFormat != "action_parameters" && outputFormat != "action" {

			// Should try the HTTP app
			appname = "HTTP"
			//output["appname"] = "HTTP"
			category = ""

			// regex out the URL
			re := regexp.MustCompile(`(http[s]?:\/\/[^\s]+)`)
			matches := re.FindAllStringSubmatch(inputQuery, -1)
			if len(matches) > 0 {
				log.Printf("[INFO] Found HTTP URL: %s", matches[0][1])
				httpOutput.URL = matches[0][1]

				if strings.HasSuffix(httpOutput.URL, "?") {
					httpOutput.URL = httpOutput.URL[:len(httpOutput.URL)-1]
				}

				originalAppname = httpOutput.URL
			}

			log.Printf("[INFO] Trying to run HTTP app for query: %s. URL: %s", inputQuery, httpOutput.URL)
			httpOutput, err = findHTTPrequestInformation(inputQuery, httpOutput.URL)
			if err != nil {
				log.Printf("[ERROR] Failed to find HTTP request information (2): %s", err)
				respBody = []byte(`{"success": false}`)
				resp.WriteHeader(500)
				resp.Write(respBody)
				return respBody, err
			}

			actionName = strings.ToUpper(httpOutput.Method)
			jsonoutput, err := json.Marshal(httpOutput)
			if err == nil {
				inputQuery += "\n\n" + string(jsonoutput)
			}
		}
	}

	apps := []WorkflowApp{}
	if len(foundApp.ID) == 0 {
		apps, err = GetPrioritizedApps(ctx, user)
		if err != nil {
			log.Printf("[ERROR] Failed to get apps in runActionAI: %s", err)
			respBody = []byte(`{"success": false, "reason": "Failed to get apps for your organization. Please try again"}`)
			resp.WriteHeader(500)
			resp.Write(respBody)
			return respBody, err
		}
	}

	appname1, appok := output["appname"]
	if appok && len(appname) == 0 {
		appname = appname1.(string)
	}

	log.Printf("[INFO] Starting AI Translation with app '%s' and category '%s' for query '%s'", appname, category, inputQuery)

	if strings.Contains(contentOutput, "success\": false") {
		// Maybe look for a Workflow that does what they want?
		if appok && len(appname1.(string)) > 0 && !ArrayContains(categoryNames, strings.ToLower(appname1.(string))) {
			// 1. Check for the appname in Shuffle
			// 2. Check in GPT-4
			// 3. Check internet

			log.Printf("[INFO] Appname specified in success false. Find most likely apps for:'%s'", appname1.(string))
			foundApps, err := FindWorkflowAppByName(ctx, appname)
			if err != nil {
				log.Printf("[ERROR] Failed to find app by name in runActionAI: %s", err)
				resp.WriteHeader(500)
				respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "Failed to load app for name '%s'."}`, appname))
				resp.Write(respBody)
				return respBody, err
			}

			if len(foundApps) == 0 {
				// Use Algolia to find the app
				algoliaApp, err := HandleAlgoliaAppSearch(ctx, appname)
				if err == nil && len(algoliaApp.ObjectID) > 0 {

					log.Printf("[INFO] Found app by name in Algolia (1): %s (%s)", algoliaApp.Name, algoliaApp.ObjectID)
					// Get actual app based on objectID

					// Get the app
					discoveredApp := &WorkflowApp{}
					if standalone { 
						discoveredApp, err = GetSingulApp("", algoliaApp.ObjectID)
					} else {
						discoveredApp, err = GetApp(ctx, algoliaApp.ObjectID, user, false)
					}

					if err != nil {
						log.Printf("[ERROR] Failed to get app in runActionAI for ID app %s (%s) (2): %s", algoliaApp.Name, algoliaApp.ObjectID, err)
						respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "Failed to get app '%s' (1). Please be more specific."}`, algoliaApp.Name))
						resp.WriteHeader(500)
						resp.Write(respBody)
						return respBody, err
					}

					foundApp = *discoveredApp
				}

			} else {
				foundApp = foundApps[0]
			}

			if len(foundApp.Name) > 0 {
				if len(foundApp.Categories) > 0 {
					category = foundApp.Categories[0]
				}
			} else {
				relevantApps := findRelevantOpenAIAppsForCategory(appname1.(string))
				log.Println()
				selectedAppIndex := 0
				authHeader := "Bearer " + user.ApiKey
				for _, foundApp := range relevantApps {
					//log.Printf("[INFO] Discovered App: %s. Check whether it exists and try to run action in the background", foundApp.Name)

					// Send to function to validate if the app exists or not
					// Try to find an action for it as well

					go expandShuffleApps(authHeader, foundApp, apps, user)

					//break
				}

				//relevantApps = []WorkflowApp{
				//	WorkflowApp{
				//		Name: foundApp[0].Name,
				//	},
				//}

				// Using the first one to find how to run it as a HTTP request
				// "Fill in the following HTTP information with the API of 'Appname' based on the following information: 'CTA from user'"
				if len(relevantApps) > 0 {
					httpOutput, err = findHTTPrequestInformation(inputQuery, relevantApps[selectedAppIndex].Name)
					if err != nil {
						log.Printf("[ERROR] Failed to find HTTP request information (1): %s", err)
						respBody = []byte(`{"success": false, "reason": "Failed to find HTTP request information (1). Please be more specific."}`)
						resp.WriteHeader(500)
						resp.Write(respBody)
						return respBody, err
					}

					log.Printf("[INFO] Found HTTP request information (1) for app %s: %#v", relevantApps[0].Name, httpOutput)
					authMessage := fmt.Sprintf(`{"success": false, "reason": "API for %s requires auth, but it wasn't supplied. As %s is not fully supported by Shuffle yet, Authentication saving for it isn't available yet. Sample curl command:\n\n%s"}`, relevantApps[0].Name, relevantApps[0].Name, strings.Replace(httpOutput.CurlCommand, "\"", "\\'", -1))

					if strings.Contains(strings.ToLower(httpOutput.URL), "api_key") || strings.Contains(strings.ToLower(httpOutput.Headers), "api_key") {
						if httpOutput.Apikey != "" && httpOutput.Apikey != "API_KEY" {
							httpOutput.URL = strings.ReplaceAll(httpOutput.URL, "API_KEY", httpOutput.Apikey)
							httpOutput.URL = strings.ReplaceAll(httpOutput.URL, "APIKEY", httpOutput.Apikey)
							httpOutput.URL = strings.ReplaceAll(httpOutput.URL, "api_key", httpOutput.Apikey)
							httpOutput.Headers = strings.ReplaceAll(httpOutput.Headers, "API_KEY", httpOutput.Apikey)
							httpOutput.Headers = strings.ReplaceAll(httpOutput.Headers, "APIKEY", httpOutput.Apikey)
							httpOutput.Headers = strings.ReplaceAll(httpOutput.Headers, "api_key", httpOutput.Apikey)
						} else {
							log.Printf("[INFO] API for %s requires auth (2), but we don't have it. Returning error: %s", relevantApps[0].Name, err)

							if !strings.HasPrefix(outputFormat, "action") {
								respBody = []byte(fmt.Sprintf(authMessage))
								resp.WriteHeader(500)
								resp.Write(respBody)
								return respBody, err
							}
						}
					} else if httpOutput.Oauth2Auth {
						log.Printf("[INFO] API for %s requires Oauth2 auth (3), but we don't have it. Returning error: %s", relevantApps[0].Name, err)

						if !strings.HasPrefix(outputFormat, "action") {
							respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "API for '%s' uses Oauth2, which is not supported yet without a proper app.\n\nSample curl command: \n\n%s"}`, appname, httpOutput.CurlCommand))
							resp.WriteHeader(500)
							resp.Write(respBody)
							return respBody, err
						}
					}

					/*
						if httpOutput.RequiresAuthentication == true {
							log.Printf("[INFO] API for %s requires auth (1), but we don't have it. Returning error: %s", relevantApps[0].Name, err)
							resp.WriteHeader(500)
							resp.Write([]byte(fmt.Sprintf(authMessage)))
							return
						}
					*/

					// Translate the data into the HTTP app
					originalAppname = appname
					appname = "HTTP"
					appname1 = "HTTP"
					category = ""
					actionName = strings.ToUpper(httpOutput.Method)

					// Marshal output and overwrite to try to ONLY use the parsed command
					// to set the full HTTP output
					jsonoutput, err := json.Marshal(httpOutput)
					if err == nil {
						inputQuery += "\n\n" + string(jsonoutput)
					}

				}
			}

			log.Println()
		}

	}

	category1, ok := output["category"]
	if ok {
		category = category1.(string)
	} else {
		if appok && appname1.(string) != "" {
			category = appname1.(string)
		}
	}

	if appok && appname1.(string) != "" && len(appname) == 0 {
		appname = appname1.(string)
	}

	//log.Printf("[INFO] Running with app '%s' and category '%s'", appname, category)

	// Hardcoded for now. Appname should not be equal to category (farther down)
	if appok && len(appname1.(string)) > 0 && appname1.(string) != category {
		log.Printf("[INFO] Appname specified in runActionAI: %s", appname1)
		appname = appname1.(string)
	} else {
		fields, ok := output["fields"]
		if ok {
			// Check if appname is specified in fields
			fieldsMap, ok := fields.(map[string]interface{})
			if ok {
				appname1, appok := fieldsMap["appname"]
				appname2, platformok := fieldsMap["platform"]
				if appok {
					log.Printf("[INFO] Appname specified in runActionAI (3): %s", appname1)
					appname = appname1.(string)
					if len(category) == 0 {
						category = appname
					}
				} else if platformok {
					log.Printf("[INFO] Appname specified in runActionAI (2): %s", appname2)
					appname1 = appname2
					appname = appname2.(string)
					if len(category) == 0 {
						category = appname
					}
				}
			}
		}
	}

	// Check if appname is a category
	if len(appname) > 0 {
		//log.Printf("[INFO] Checking if appname '%s' is a category", appname)
		appnameLower := strings.ToLower(appname)
		for _, innercategory := range appCategories {
			if strings.ToLower(innercategory.Name) == appnameLower {
				category = innercategory.Name
				appname1 = nil
				appname = ""
				break
			}
		}
	}

	if len(category) == 0 && category1 != nil {
		category = strings.ToLower(category1.(string))
	}

	actionLabel := ""
	if len(appname) > 0 {
		// Pass :)
	} else if appname1 == nil || len(appname1.(string)) == 0 {
		// Should find the category and find active apps matching it
		for _, app := range apps {
			if app.Name == "Shuffle" || strings.ToLower(app.Name) == "email" {
				continue
			}

			// appnamesplit should match
			if strings.Contains(strings.ToLower(strings.Replace(inputQuery, "_", " ", -1)), strings.ToLower(strings.Replace(app.Name, "_", " ", -1))) {
				log.Printf("[INFO] Found app '%s' in input query '%s'", app.Name, inputQuery)
				appname = app.Name
				foundApp = app
				break
			}
		}

		if len(appname) == 0 {
			matchingApps := FindMatchingCategoryApps(category, apps, &org)

			if len(matchingApps) > 0 {
				appname = matchingApps[0].Name
			} else {
				log.Printf("[ERROR] No matching apps found in the org for category '%s' and action label '%s'", category, actionLabel)

				googleQuery := fmt.Sprintf(inputQuery)
				if !strings.Contains(inputQuery, "API") {
					googleQuery += "API for " + inputQuery
				}

				googleResp, err := RunGoogleSearch(ctx, googleQuery)
				if err != nil {
					log.Printf("[ERROR] Failed to run google search: %s", err)
				}

				_ = googleResp

				respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "No matching apps found. Be more specific about what app to use, or what you want to do."}`))
				resp.WriteHeader(400)
				resp.Write(respBody)
				return respBody, err
			}
		}
	} else {
		if len(appname) == 0 {
			appname = appname1.(string)
		}
	}

	appname = strings.Replace(appname, "_", " ", -1)
	//log.Printf("[INFO] Using app '%s' for action '%s' (1)", appname, actionName)

	actionLabel1, ok := output["action"]
	if !ok && len(actionName) == 0 {
		actionLabel1, ok = output["action_label"]

		if !ok {
			// Should search for it

			log.Printf("[ERROR] No actionLabel found in runActionAI for your input with app %s and category %s. Trying to find the action that matches the best anyway", appname, category)

			// Should run Action search in the correct app
			if len(appname) > 0 && foundApp.ID == "" {
				foundApps, err := FindWorkflowAppByName(ctx, appname)
				if err != nil {
					log.Printf("[ERROR] Failed to find app by name in runActionAI: %s", err)
					respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "Failed to load app for name '%s' in category '%s'"}`, appname, category))
					resp.WriteHeader(500)
					resp.Write(respBody)
					return respBody, err
				}

				if len(foundApps) == 0 {

					// Use Algolia to find the app
					algoliaApp, err := HandleAlgoliaAppSearch(ctx, appname)
					if err != nil || algoliaApp.ObjectID == "" {
						log.Printf("[ERROR] Failed to find app by name %s in runActionAI: %s", appname, err)
						respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "Failed to load app for name '%s' in category '%s' (2)"}`, appname, category))
						resp.WriteHeader(400)
						resp.Write(respBody)
						return respBody, err
					}

					log.Printf("[INFO] Found app by name in Algolia (3): %s (%s)", algoliaApp.Name, algoliaApp.ObjectID)
					// Get actual app based on objectID

					// Get the app
					discoveredApp, err := GetApp(ctx, algoliaApp.ObjectID, user, false)
					if err != nil {
						log.Printf("[ERROR] Failed to get app in runActionAI for ID app %s (%s) (2): %s", algoliaApp.Name, algoliaApp.ObjectID, err)
						respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "Failed to get app '%s' (2). Please be more specific."}`, algoliaApp.Name))
						resp.WriteHeader(500)
						resp.Write(respBody)
						return respBody, err
					}

					foundApp = *discoveredApp

				} else {
					foundApp = foundApps[0]
				}
			}
		} else {
			actionLabel = actionLabel1.(string)
		}

		// Check foundApp if the category matches the category we're looking for
		if category != "" && len(foundApp.Categories) > 0 && len(actionName) == 0 {
			if strings.ToLower(foundApp.Categories[0]) != strings.ToLower(category) {
				log.Printf("[ERROR] Found app by name, but category doesn't match: %s != %s", foundApp.Categories[0], category)
				category = ""
				actionLabel = ""
			}
		}

		if len(actionName) == 0 {
			log.Printf("[INFO] Finding action name for input '%s' in app '%s'", inputQuery, appname)
			actionName, err = findActionByInput(inputQuery, actionLabel, foundApp)
			if err != nil {
				log.Printf("[ERROR] Failed to find action by input in runActionAI (1): %s", err)
				respBody = []byte(`{"success": false, "reason": "Failed to find action for app. Please be more specific."}`)
				resp.WriteHeader(500)
				resp.Write(respBody)
				return respBody, err
			}
		}

		log.Printf("[INFO] Output in Action Name synonym for app %s: '%s'. If success: false, we ask directly to find it", foundApp.Name, actionName)
		if strings.Contains(actionName, `{"success": "false"}`) {
			/*
				contentOutput, err := findHTTPendpoint(inputQuery, foundApp)
				if err != nil {
					log.Printf("[ERROR] Failed to find HTTP endpoint in runActionAI for App %s: %s", foundApp.Name, err)
					resp.WriteHeader(500)
					resp.Write([]byte(`{"success": false, "reason": "Failed to find relevant API for your query"}`))
					return
				}

				log.Printf("[INFO] Output in HTTP endpoint synonym for app %s: %s. If false, we ask directly to find it", foundApp.Name, contentOutput)
			*/

			// FIXMe: Should check existing API for this url. Remove the start of it if it has http://

			log.Printf("[ERROR] No matching action (1) found for app '%s' with label '%s' in runActionAI. Actionname: %#v", appname, actionLabel, actionName)
			respBody = []byte(`{"success": false, "reason": "No matching action found. Please specify the app and action to use.", "action": "select_app"}`)
			resp.WriteHeader(400)
			resp.Write(respBody)
			return respBody, errors.New("No matching action found")
		}

		//log.Printf("[INFO] Found action by input in runActionAI: %s", actionName)

		if len(actionName) == 0 {
			log.Printf("[ERROR] No actionLabel found in runActionAI for your input with app %s and category '%s'", appname, category)
			respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "No matching action label found. Please try again with a different prompt. App: %s, category: %s"}`, appname, category))
			resp.WriteHeader(400)
			resp.Write(respBody)
			return respBody, errors.New("No matching action label found")
		}
	} else {
		if ok {
			actionLabel = actionLabel1.(string)
		}
	}

	if len(actionName) == 0 {
		log.Printf("[INFO] Found appname (1): %s (%s). Label: '%s'. Action: '%s'. Discovering action!", appname, foundApp.ID, actionLabel, actionName)
	}

	if actionName == "" && actionLabel1 != nil && len(actionLabel) == 0 {
		actionLabel = strings.Replace(strings.ToLower(actionLabel1.(string)), " ", "_", -1)
	}

	if strings.ToLower(category) == "email" {
		category = "communication"
	}

	// Check if appname is a category

	if foundApp.ID == "" || foundApp.Name == "" {
		for _, app := range apps {
			if strings.Replace(app.Name, " ", "_", -1) == strings.Replace(appname, " ", "_", -1) {
				foundApp = app
				break
			}
		}

		// 1. Search locally
		// 2. Get from Algolia
		foundApps, err := FindWorkflowAppByName(ctx, appname)
		if err != nil {
			log.Printf("[ERROR] Failed to find app by name in runActionAI: %s", err)
			respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "Failed to load app for name '%s' in category '%s' (3)"}`, appname, category))
			resp.WriteHeader(500)
			resp.Write(respBody)
			return respBody, err
		}

		if len(foundApps) == 0 {
			// Use Algolia to find the app
			algoliaApp, err := HandleAlgoliaAppSearch(ctx, appname)
			if err != nil {
				log.Printf("[ERROR] Failed to find app by name in runActionAI: %s", err)
				respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "Failed to load app for name '%s' in category '%s' (4)"}`, appname, category))
				resp.WriteHeader(400)
				resp.Write(respBody)
				return respBody, err
			}

			if len(algoliaApp.ObjectID) == 0 {
				log.Printf("[ERROR] Failed to find app by name in Algolia (4): %s", err)

				// Should try to search and build it out and make it into an HTTP app
				relevantApps := findRelevantOpenAIAppsForCategory(appname)
				log.Println()
				selectedAppIndex := 0
				authHeader := "Bearer " + user.ApiKey
				for _, loopedApp := range relevantApps {
					//log.Printf("[INFO] Discovered App: %s (2). Check whether it exists and try to run action in the background", loopedApp.Name)

					// Send to function to validate if the app exists or not
					// Try to find an action for it as well
					go expandShuffleApps(authHeader, loopedApp, apps, user)
				}

				// Using the first one to find how to run it as a HTTP request
				// "Fill in the following HTTP information with the API of 'Appname' based on the following information: 'CTA from user'"
				if len(relevantApps) > 0 {
					httpOutput, err = findHTTPrequestInformation(inputQuery, relevantApps[selectedAppIndex].Name)
					if err != nil {
						log.Printf("[ERROR] Failed to find HTTP request information (2): %s", err)
						respBody = []byte(`{"success": false, "reason": "Failed to find HTTP request information (2). Please be more specific."}`)
						resp.WriteHeader(500)
						resp.Write(respBody)
						return respBody, err
					}

					log.Printf("[INFO] Found HTTP request information (2) for app %s: %#v", relevantApps[0].Name, httpOutput)
					authMessage := fmt.Sprintf(`{"success": false, "reason": "API for %s requires auth, but it wasn't supplied. As %s is not fully supported by Shuffle yet, Authentication saving for it isn't available yet. Sample curl command:\n\n%s"}`, relevantApps[0].Name, relevantApps[0].Name, httpOutput.CurlCommand)

					if strings.Contains(strings.ToLower(httpOutput.URL), "api_key") || strings.Contains(strings.ToLower(httpOutput.Headers), "api_key") {
						if httpOutput.Apikey != "" && httpOutput.Apikey != "API_KEY" {
							httpOutput.URL = strings.ReplaceAll(httpOutput.URL, "API_KEY", httpOutput.Apikey)
							httpOutput.URL = strings.ReplaceAll(httpOutput.URL, "APIKEY", httpOutput.Apikey)
							httpOutput.URL = strings.ReplaceAll(httpOutput.URL, "api_key", httpOutput.Apikey)
							httpOutput.Headers = strings.ReplaceAll(httpOutput.Headers, "API_KEY", httpOutput.Apikey)
							httpOutput.Headers = strings.ReplaceAll(httpOutput.Headers, "APIKEY", httpOutput.Apikey)
							httpOutput.Headers = strings.ReplaceAll(httpOutput.Headers, "api_key", httpOutput.Apikey)
						} else {
							log.Printf("[INFO] API for %s requires auth (2), but we didn't get a key. Returning error: %s", relevantApps[0].Name, err)

							if !strings.HasPrefix(outputFormat, "action") {
								respBody = []byte(fmt.Sprintf(authMessage))
								resp.WriteHeader(500)
								resp.Write(respBody)
								return respBody, errors.New("API requires auth (2)")
							}
						}
					} else if httpOutput.Oauth2Auth {
						log.Printf("[INFO] API for %s requires Oauth2 auth (3), but we don't have it. Returning error: %s", relevantApps[0].Name, err)

						if !strings.HasPrefix(outputFormat, "action") {
							respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "API for '%s' uses Oauth2, which is not supported yet without a proper app.\n\nSample curl command: \n\n%s"}`, appname, httpOutput.CurlCommand))
							resp.WriteHeader(500)
							resp.Write(respBody)
							return respBody, err
						}
					}

					/*
						if httpOutput.RequiresAuthentication == true {
							log.Printf("[INFO] API for %s requires auth (1), but we don't have it. Returning error: %s", relevantApps[0].Name, err)
							resp.WriteHeader(500)
							resp.Write([]byte(fmt.Sprintf(authMessage)))
							return
						}
					*/

					// Translate the data into the HTTP app
					originalAppname = appname
					appname = "HTTP"
					appname1 = "HTTP"
					category = ""
					actionName = strings.ToUpper(httpOutput.Method)

					// Marshal output and overwrite to try to ONLY use the parsed command
					// to set the full HTTP output
					jsonoutput, err := json.Marshal(httpOutput)
					if err == nil {
						inputQuery += "\n\n" + string(jsonoutput)
					}

					// Making sure to load the HTTP app
					foundApps, err := FindWorkflowAppByName(ctx, appname)
					if err != nil {
						log.Printf("[ERROR] Failed to find app by name (5): %s", err)
						respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "Failed to load app for name '%s' in category '%s' (4)"}`, appname, category))
						resp.WriteHeader(500)
						resp.Write(respBody)
						return respBody, err
					}

					if len(foundApps) == 0 {
						log.Printf("[ERROR] Failed to find app by name (6): %s", err)
						respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "Failed to load app for name '%s' in category '%s' (6)"}`, appname, category))
						resp.WriteHeader(500)
						resp.Write(respBody)
						return respBody, errors.New("Failed to load app (6)")
					}

					foundApp = foundApps[0]
				} else {
					respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "Failed to load app for name '%s' in category '%s' (5)"}`, appname, category))
					resp.WriteHeader(400)
					resp.Write(respBody)
					return respBody, errors.New("Failed to load app (5)")
				}
			} else {
				log.Printf("[INFO] Found app by name in Algolia (4): %s (%s)", algoliaApp.Name, algoliaApp.ObjectID)
				// Get actual app based on objectID

				// Get the app
				discoveredApp, err := GetApp(ctx, algoliaApp.ObjectID, user, false)
				if err != nil {
					log.Printf("[ERROR] Failed to get app in runActionAI for ID app %s (%s) (2): %s", algoliaApp.Name, algoliaApp.ObjectID, err)
					respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "Failed to get app '%s' (3). Please be more specific."}`, algoliaApp.Name))
					resp.WriteHeader(500)
					resp.Write(respBody)
					return respBody, err
				}

				foundApp = *discoveredApp
			}

		} else {
			foundApp = foundApps[0]
		}
	}

	if len(actionName) == 0 {
		log.Printf("[INFO] Found appname (2): %s. Label: '%s'. Action: '%s'. Discovering action!", appname, actionLabel, actionName)
	}

	// Check foundApp if the category matches the category we're looking for
	if category != "" && len(foundApp.Categories) > 0 && len(actionName) == 0 {
		if strings.ToLower(foundApp.Categories[0]) != strings.ToLower(category) {
			log.Printf("[ERROR] Found app by name, but category doesn't match: %s != %s", foundApp.Categories[0], category)
			category = ""
			actionLabel = ""
		}
	}

	if len(actionName) == 0 {
		log.Printf("[INFO] Found appname (3): %s. Label: '%s'. Action: '%s'. Discovering action!", appname, actionLabel, actionName)
	}

	// Check for the right action label
	selectedAction := WorkflowAppAction{}
	newActionName := GetCorrectActionName(strings.ToLower(strings.Replace(actionName, " ", "_", -1)))
	for _, action := range foundApp.Actions {
		parsedName := strings.ToLower(strings.Replace(action.Name, " ", "_", -1))
		parsedName = GetCorrectActionName(parsedName)

		if len(newActionName) > 0 && parsedName == newActionName {
			selectedAction = action
			break
		}

		if len(action.CategoryLabel) == 0 {
			continue
		}

		if strings.Replace(strings.ToLower(action.CategoryLabel[0]), " ", "_", -1) == actionLabel {
			log.Printf("[INFO] Found action in runActionAI (1) with action %s and label %s", action.Name, action.Label)
			selectedAction = action
			break
		}
	}

	if len(selectedAction.Name) == 0 {
		log.Printf("[INFO] Found appname (4): %s. Label: '%s'. Action: '%s'. Discovering action!", appname, actionLabel, actionName)
	}

	if len(selectedAction.Name) == 0 {
		// Use OpenAI to find the right one based on name matches
		log.Printf("[INFO] Have existing action name: '%s', but no action found. Trying to find the right one with OpenAI.", actionName)

		if input.OutputFormat == "action_parameters" {
			log.Printf("[ERROR] Failed to find action with name '%s' and label '%s' in app '%s' (1). Critical!", actionName, actionLabel, appname)
		}

		// Do automatic name translation
		// Cases: alert = incident = case = issue = ticket
		// Track original names
		contentOutput, err := findActionByInput(inputQuery, actionLabel, foundApp)
		if err != nil {
			log.Printf("[ERROR] Failed to find action by input in runActionAI (2): %s", err)
			respBody = []byte(`{"success": false, "reason": "Couldn't find the action you were looking for. Please try with a more specific prompt."}`)
			resp.WriteHeader(500)
			resp.Write(respBody)
			return respBody, err
		}

		log.Printf("[INFO] Output in action synonym: %s", contentOutput)
		if strings.Contains(contentOutput, `{"success": "false"}`) {
			log.Printf("[ERROR] No matching action (2) found for app '%s' with label '%s' in runActionAI", foundApp.Name, actionLabel)
			respBody = []byte(`{"success": false, "reason": "No matching action found. Please try again with a more specific prompt (1)."}`)
			resp.WriteHeader(400)
			resp.Write(respBody)
			return respBody, errors.New("No matching action found (2)")
		}

		log.Printf("[INFO] Found action in runActionAI (2). Action '%s' and label '%s'", contentOutput, actionLabel)
		newActionName := GetCorrectActionName(strings.ToLower(strings.Replace(contentOutput, " ", "_", -1)))
		for _, action := range foundApp.Actions {
			parsedName := strings.ToLower(strings.Replace(action.Name, " ", "_", -1))
			parsedName = GetCorrectActionName(parsedName)

			log.Printf("'%s' with '%s'", newActionName, parsedName)
			if len(newActionName) > 0 && parsedName == newActionName {
				selectedAction = action
				break
			}

			if len(action.CategoryLabel) == 0 {
				continue
			}

			if len(actionLabel) > 0 && strings.Replace(strings.ToLower(action.CategoryLabel[0]), " ", "_", -1) == actionLabel {
				log.Printf("[INFO] Found action in runActionAI (1) with action %s and label %s", action.Name, action.Label)
				selectedAction = action
				break
			}
		}

		if len(selectedAction.Name) == 0 {
			log.Printf("[ERROR] No matching action label (3) found for app '%s' with label '%s' in runActionAI (2)", foundApp.Name, actionLabel)
			respBody = []byte(`{"success": false, "reason": "No matching action found. Please try again with a more specific prompt (2)."}`)
			resp.WriteHeader(400)
			resp.Write(respBody)
			return respBody, errors.New("No matching action found (3)")
		}
	}

	if len(input.Parameters) > 0 {
		selectedAction.Parameters = input.Parameters
	}

	input.Query = inputQuery
	selectedAction, err = getSelectedAppParameters(ctx, user, selectedAction, foundApp, appname, category, outputFormat, httpOutput, input)
	if err != nil {
		// Check if reason inside
		errString := err.Error()
		if strings.Contains(errString, "\"reason\"") {
			respBody = []byte(errString)
			resp.WriteHeader(400)
			resp.Write(respBody)
			return respBody, errors.New("Failed to get selected app parameters")
		}

		log.Printf("[ERROR] Failed to get selected app parameters in runActionAI: %s", err)

		// Sanitize err to work in json
		respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, errString))
		resp.WriteHeader(400)
		resp.Write(respBody)
		return respBody, err
	}

	if strings.HasPrefix(outputFormat, "action") {
		//log.Printf("[INFO] Skipping execution and returning action: %s", selectedAction.Name)

		//selectedAction.LargeImage = foundApp.LargeImage
		selectedAction.LargeImage = ""
		selectedAction.AppName = foundApp.Name
		selectedAction.AppID = foundApp.ID
		selectedAction.Environment = "cloud"

		if len(actionLabel) > 0 {
			selectedAction.Label = actionLabel
		}

		if len(selectedAction.Label) == 0 {
			selectedAction.Label = fmt.Sprintf("%s_%s", foundApp.Name, selectedAction.Name)
		}

		/*
			for _, param := range selectedAction.Parameters {
				log.Printf("[INFO] PRE RETURN: %s: '%s'", param.Name, param.Value)
			}
		*/

		// Marshal action and send it
		returnJSON, err := json.Marshal(selectedAction)
		if err != nil {
			log.Printf("[ERROR] Failed to marshal selectedAction: %s", err)
			respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "Failed to decode action. Please try again"}`))
			resp.WriteHeader(500)
			resp.Write(respBody)
			return respBody, err
		}

		resp.WriteHeader(200)
		resp.Write([]byte(returnJSON))
		return returnJSON, nil
	}

	cnt := 1
	selfCorrectAttempts := 3
	additionalInfo := ""
	outputString := ""
	outputAction := Action{}

	baseUrl := "https://shuffler.io"
	if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
		baseUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
	}

	if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
		baseUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
	}

	for {
		if cnt >= selfCorrectAttempts {
			// Should send error reply
			// And should never happen
			log.Printf("[ERROR] Failed to match output data for %s", appname)
			break
		}

		log.Printf("[INFO] Running attempt %d for app %s with action %s", cnt, appname, selectedAction.Name)

		newAction := Action{
			Name:              selectedAction.Name,
			Label:             selectedAction.Label,
			Parameters:        selectedAction.Parameters,
			InvalidParameters: selectedAction.InvalidParameters,
			AppName:           foundApp.Name,
			AppVersion:        foundApp.AppVersion,
			AppID:             foundApp.ID,
			Environment:       "cloud",
			AuthenticationId:  selectedAction.AuthenticationId,
		}

		sendBody, err := json.Marshal(newAction)
		if err != nil {
			log.Printf("[ERROR] Failed to marshal action in runActionAI: %s", err)
			respBody = []byte(`{"success": false, "reason": "Failed to marshal action in runActionAI"}`)
			resp.WriteHeader(500)
			resp.Write(respBody)
			return respBody, err
		}

		// Gut auth from request auth header and forward with the same one
		parsedUrl := fmt.Sprintf("%s/api/v1/apps/%s/run", baseUrl, foundApp.ID)

		// Could've used session token too, tho
		authHeader := "Bearer " + user.ApiKey
		returnValue, err := sendRequestToSelf(parsedUrl, authHeader, sendBody)
		if err != nil {
			if len(returnValue) > 0 {
				log.Printf("[ERROR] Response from self: %s", returnValue)
				resp.WriteHeader(400)
				resp.Write([]byte(returnValue))
				return returnValue, err
	 		}

			log.Printf("[ERROR] Failed to send run request to self: %s", err)
			if strings.Contains(fmt.Sprintf("%s", err), "Failed to run") {
				respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "Failed to run app %s with action %s. Please be more specific and try again."}`, newAction.AppName, newAction.Name))
				resp.WriteHeader(400)
				resp.Write(respBody)
				return respBody, err
			}

			resp.WriteHeader(400)
			//resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
			resp.Write([]byte(err.Error()))
			return []byte(err.Error()), err
		}

		// Find result field in json body from returnValue
		outputString, outputAction, err, additionalInfo = findNextAction(newAction, returnValue, additionalInfo, inputQuery, originalAppname)
		_ = additionalInfo
		if err != nil {
			// Check for auth and send auth in that case

			if strings.Contains(fmt.Sprintf("%s", err), "re-authenticate") {
				outputResult := fmt.Sprintf("Found existing auth for app %s in category %s, but failed to use it. Please re-authenticate below.", strings.Replace(strings.Replace(foundApp.Name, "_", " ", -1), "\"", "", -1), strings.Replace(strings.Replace(category, "_", " ", -1), "\"", "", -1))
				actionOutput := "app_authentication"
				if appname == "HTTP" {
					outputResult = fmt.Sprintf("Your API-key is invalid for the app '%s'. Please add a valid API-key to the prompt, and specify the type of auth to use.", originalAppname)
					actionOutput = ""
				}

				returnStruct := appAuthStruct{
					Success: false,
					Reason:  outputResult,
					Action:  actionOutput,
					Apps: []AppMini{
						{
							ActionName:             selectedAction.Name,
							Category:               category,
							Id:                     foundApp.ID,
							Name:                   foundApp.Name,
							Version:                foundApp.AppVersion,
							LargeImage:             foundApp.LargeImage,
							AuthenticationRequired: true,
							Authentication:         foundApp.Authentication,
						},
					},
				}

				returnJSON, err := json.Marshal(returnStruct)
				if err == nil {
					resp.Write(returnJSON)
					resp.WriteHeader(400)
					return returnJSON, nil 
				} else {
					log.Printf("[ERROR] Failed to marshal return struct: %s", err)
				}
			}

			if len(err.Error()) == 0 || err == nil {
				err = errors.New(fmt.Sprintf("Failed to run app '%s' with action '%s' in category '%s'. Please try again with a different query.", strings.Replace(strings.Replace(foundApp.Name, "_", " ", -1), "\"", "", -1), strings.Replace(strings.Replace(selectedAction.Name, "_", " ", -1), "\"", "", -1), strings.Replace(strings.Replace(category, "_", " ", -1), "\"", "", -1)))
			}

			log.Printf("[ERROR] Failed to find next action: %s", err)

			respBody = []byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err))
			resp.WriteHeader(500)
			resp.Write(respBody)
			return respBody, err
		}

		// Means success :)
		if len(outputString) > 0 {
			resp.WriteHeader(200)
			resp.Write([]byte(outputString))
			return []byte(outputString), nil
		}

		selectedAction.Name = outputAction.Name
		selectedAction.Label = outputAction.Label
		selectedAction.Parameters = outputAction.Parameters
		selectedAction.InvalidParameters = outputAction.InvalidParameters
		log.Printf("[INFO] Have %d invalid parameters and %d valid ones. Trying again", len(selectedAction.InvalidParameters), len(selectedAction.Parameters))

		cnt += 1
	}

	respBody = []byte(`{"success": true}`)
	resp.WriteHeader(200)
	resp.Write(respBody)
	return respBody, nil
}

// Used at first to answer general questions
func findRelevantOutput(inputQuery string, org Org, user User) string {
	// Based on the following info,
	usecasesString := GetUsecaseData()
	// Unmarshal this
	var usecases []map[string]interface{}
	usecasesOutput := fmt.Sprintf("Usecases by priority: ")
	err := json.Unmarshal([]byte(usecasesString), &usecases)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal JSON in runActionAI for usecases. Data & err %s: %s", usecasesString, err)
	} else {
		usecasePriority := map[int][]string{}
		for _, usecaseCategory := range usecases {

			// Find "list" inside it as a list
			usecaseList, ok := usecaseCategory["list"]
			if !ok {
				log.Printf("[ERROR] No list found in usecaseCategory")
				continue
			}

			usecaseList2, ok := usecaseList.([]interface{})
			if !ok {
				log.Printf("[ERROR] Failed to cast usecaseList to []interface{}. Type is %s", reflect.TypeOf(usecaseList))
				continue
			}

			for _, usecase := range usecaseList2 {
				// Find "name" and "priority" in it
				usecase2, ok := usecase.(map[string]interface{})
				if !ok {
					log.Printf("[ERROR] Failed to cast usecase to map[string]interface{}. Type is %s", reflect.TypeOf(usecase))
					continue
				}

				name, ok := usecase2["name"]
				if !ok {
					log.Printf("[ERROR] No name found in usecase2")
					continue
				}

				priority, ok := usecase2["priority"]
				if !ok {
					log.Printf("[ERROR] No priority found in usecase2")
					continue
				}

				priorityInt, ok := priority.(float64)
				if !ok {
					log.Printf("[ERROR] Failed to cast priority to float64. Type is %s", reflect.TypeOf(priority))
					continue
				}

				priorityInt2 := int(priorityInt)
				usecasePriority[priorityInt2] = append(usecasePriority[priorityInt2], name.(string))
			}
		}

		// Sort usecasePriority map[int][]string{} based on key from highest to lowest
		for key, value := range usecasePriority {
			if key <= 75 {
				continue
			}

			//log.Printf("[INFO] Usecase priority %d: %s", key, value)
			usecasesOutput += fmt.Sprintf("%s, ", value)
		}

	}

	if len(usecasesOutput) < 100 {
		usecasesOutput = ""
	}

	userMessage := fmt.Sprintf("Based on the prompt, answer the question directly. If it can't be directly answered, return {\"success\": false}\n\nWhat: ShuffleGPT is an AI built for automating API interactions and answering questions about them. You can ask automation, Usecases, Workflows, Apps, APIs or Documentation.\nOrganization name: %s\nUsers: %d\nMy Username: %s\n%s\nPrompt: %s", org.Name, len(org.Users), user.Username, usecasesOutput, inputQuery)

	//log.Printf("[INFO] User message (find relevant output type): %s", userMessage)

	contentOutput, err := RunAiQuery("", userMessage)
	if err != nil {
		log.Printf("[ERROR] Failed to run AI query in findRelevantOutput: %s", err)
		return ""
	}

	log.Printf("[INFO] Content output for initial relevancy check: %s", contentOutput)
	if strings.Contains(contentOutput, "\"success\": false") {
		return ""
	} else if contentOutput == `{"success": true}` {
		return ""
	}

	return contentOutput
}

func findHTTPrequestInformation(textInput string, appname string) (HTTPWrapper, error) {
	if len(textInput) == 0 {
		return HTTPWrapper{}, errors.New("No text input")
	}

	systemMessage := fmt.Sprintf("Fill in the following HTTP information with the API of '%s' based on the following information: '%s'. If an API_KEY is required and provided, use it. Otherwise, specify it as API_KEY with authentication required. Headers should be a string with newlines between each key value pair. Make sure the format is valid JSON.", appname, textInput)

	userMessage := fmt.Sprintf(`{"url": "", "headers": "Content-Type=application/json\nAccept=application/json", "body": "", "method": "GET", "requires_authentication": false, "oauth2_auth": false, "apikey": "", "curl_command": ""}`)

	log.Printf("[INFO] System message (find http request info): %s", systemMessage)
	log.Printf("[INFO] User message (find http request info - 1): %s", userMessage)

	// Parses the input and returns the category and action label
	var httpWrapper HTTPWrapper
	contentOutput, err := RunAiQuery(systemMessage, userMessage) 
	if err != nil {
		log.Printf("[DEBUG] Failed to run AI query in findHTTPrequestInformation: %s", err)
		return httpWrapper, err
	}

	// Parse out the output
	err = json.Unmarshal([]byte(contentOutput), &httpWrapper)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal http wrapper in runActionAI with data %s: %s. Return as per normal anyway and skipping invalid field.", contentOutput, err)
	}

	log.Printf("[INFO] Content output for HTTP parser: %s", contentOutput)
	return httpWrapper, nil
}

func findRelevantOpenAIAppsForCategory(category string) []WorkflowApp {
	newApps := []WorkflowApp{}

	systemMessage := fmt.Sprintf("Use this exact format: [{\"rank\": 1, \"name\": \"appname\", \"logo\": \"logo url\", \"api url\": \"api doc url\", \"requires_oauth2\": false}]. If no apps, return {\"success\": false}")
	userMessage := fmt.Sprintf("Create a list of the top three apps in the category '%s'", category)
	log.Printf("[INFO] System message (find relevant apps for category): %s. Usermsg: %s", systemMessage, userMessage)

	contentOutput, err := RunAiQuery(systemMessage, userMessage) 
	if err != nil {
		log.Printf("[ERROR] Failed to run AI query in findRelevantOpenAIAppsForCategory: %s", err)
		return newApps
	}

	log.Printf("[INFO] Content output for relevant apps: %s", contentOutput)

	// Map back to JSON and start building in the background?
	var apps []map[string]interface{}
	err = json.Unmarshal([]byte(contentOutput), &apps)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal JSON in runActionAI for relevant apps. Data & err %s: %s", contentOutput, err)

		var apps2 map[string]interface{}
		err := json.Unmarshal([]byte(contentOutput), &apps2)
		if err != nil {
			log.Printf("[ERROR] Failed to unmarshal JSON in runActionAI for relevant apps (2): %s", err)
			return []WorkflowApp{}
		}

		apps3, ok := apps2["apps"]
		if !ok {
			log.Printf("[ERROR] No key found for apps in output")
			return []WorkflowApp{}
		}

		apps, ok = apps3.([]map[string]interface{})
		if !ok {
			log.Printf("[ERROR] Failed to cast apps to []map[string]interface{}. Type is %s", reflect.TypeOf(apps3))
			return []WorkflowApp{}
		}
	}

	for _, appLoop := range apps {
		// Unmarshal JSON and validate
		/*
			rank, ok := appLoop["rank"]
			if !ok {
				log.Printf("[ERROR] No rank found in appLoop")
				continue
			}
		*/

		name, ok := appLoop["name"]
		if !ok {
			log.Printf("[ERROR] No name found in appLoop")
			continue
		}

		logo, ok := appLoop["logo"]
		if !ok {
			log.Printf("[ERROR] No logo found in appLoop")
			continue
		}

		apiURL, ok := appLoop["api url"]
		if !ok {
			log.Printf("[ERROR] No api url found in appLoop")
			continue
		}

		newApp := WorkflowApp{
			Name:       name.(string),
			LargeImage: logo.(string),
		}

		newApp.ReferenceInfo.DocumentationUrl = apiURL.(string)
		// add to a list of apps
		newApps = append(newApps, newApp)
	}

	return newApps
}

func expandShuffleApps(authHeader string, foundApp WorkflowApp, apps []WorkflowApp, user User) {
	ctx := context.Background()

	//foundApp.ReferenceInfo.DocumentationUrl = "https://shuffler.io/docs/API"

	//log.Printf("[INFO] Expanding shuffle apps for %s. Documentation URL: %s", foundApp.Name, foundApp.ReferenceInfo.DocumentationUrl)
	if len(foundApp.ReferenceInfo.DocumentationUrl) == 0 {
		log.Printf("[WARNING] No documentation URL found to scrape for %s. Should go to search Google for it (not implemented)", foundApp.Name)
		return
	}

	// Should check if app exists in Algolia
	algoliaApp, err := HandleAlgoliaAppSearch(ctx, foundApp.Name)
	if err == nil && len(algoliaApp.ObjectID) > 0 {
		log.Printf("[INFO] App %s already exists in Algolia and isn't necessary", foundApp.Name)
		return
	}

	// Check if app.Name is same as foundApp.Name and with lowercase and underscores in use
	appname := strings.ToLower(strings.Replace(foundApp.Name, " ", "_", -1))
	for _, app := range apps {
		if strings.ToLower(strings.Replace(app.Name, " ", "_", -1)) == appname {
			log.Printf("[INFO] Found existing app with name %s. Returning", app.Name)
			foundApp = app
			return
		}
	}

	// 1. Should find documentation page for app
	// 2. Should forward to documentation builder for the app
	// 3. If url is bad for 'api url' field, should search postman > rapidapi > google > zapier
	// mulesoft anypoint platform
	// ibm app connect
	// openapi hub~
	// integrately

	// Send post request to OpenAPI builder
	url := fmt.Sprintf("https://doc-to-openapi-stbuwivzoq-nw.a.run.app/doc_to_openapi")
	requestData := fmt.Sprintf(`{"url": "%s", "appname": "%s", "logo_url": "%s"}`, foundApp.ReferenceInfo.DocumentationUrl, foundApp.Name, foundApp.LargeImage)
	//log.Printf("[INFO] Sending request to %s with body %s", url, requestData)

	req, err := http.NewRequest(
		"POST",
		url,
		bytes.NewBuffer([]byte(requestData)),
	)

	client := &http.Client{
		Timeout: 1800 * time.Second,
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", authHeader)
	res, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed request to url %s (1): %s", url, err)
	}

	defer res.Body.Close()
	// Read response body
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[ERROR] Failed request to url %s (3): %s", url, err)
		return
	}

	// Check status code
	if res.StatusCode != 200 {
		log.Printf("[ERROR] Bad response from url %s (2): %s. Body: %s", url, res.Status, string(body))
		return
	}

	// Response here should be parsed into OpenAPI and built with the OpenAPI builder
	//log.Printf("[INFO] OpenAPI resp with URL %s: %s", foundApp.ReferenceInfo.DocumentationUrl, string(body))
	if strings.Contains("error", string(body)) && strings.Contains("No valid text", string(body)) {
		log.Printf("[ERROR] Skipping build with generated URL %s for app %s", foundApp.ReferenceInfo.DocumentationUrl, foundApp.Name)
		return
	}

	// Send this into verify_openapi?
	// Should it be built for the user that tried to use it first or our internal user?
	// Attaching to e.g. the 'Scheduler' user may be useful, but the thing
	// of you 'owning' an app if you first discover it for us may be very useful

	// I think letting individuals own it for now may be cool :)

	// Makes it so the app is available, but not built.
	//
	// Auto publish: &sharing=true
	appbuildUrl := "https://shuffler.io/api/v1/verify_openapi?skip_build=true"

	resp, err := sendRequestToSelf(appbuildUrl, authHeader, body)
	if err != nil {
		log.Printf("[ERROR] Failed to send request to build app %s to self: %s", foundApp.Name, err)
	} else {
		log.Printf("[INFO] Response from sending request to build app %s to self: %s", foundApp.Name, resp)
	}

	// Add notification for the user that it was built
	// Publish the app to be verified by us
	notificationTitle := fmt.Sprintf("A new app with name '%s' was generated!", foundApp.Name)
	err = CreateOrgNotification(
		ctx,
		notificationTitle,
		fmt.Sprintf("An app with the name %s was generated by your user based on your usage of ShuffleGPT. This may be under review by the Shuffle team before it is published.", foundApp.Name),
		fmt.Sprintf("/apps"),
		user.ActiveOrg.Id,
		true,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to create notification for user %s with title '%s': %s", user.Username, notificationTitle, err)
	}
}

// To self-learn about the correct answer
// Should use gpt-3.5 to find the right result, scrape, visit & answer question
func RunGoogleSearch(ctx context.Context, query string) (string, error) {
	// Hardcoded and not really used for anything rn.
	customsearchApikey := os.Getenv("GOOGLE_SEARCH_APIKEY")
	customsearchCx := os.Getenv("GOOGLE_SEARCH_CX")

	if len(customsearchApikey) == 0 || len(customsearchCx) == 0 {
		return "", errors.New("No GOOGLE_API_KEY or GOOGLE_CX found")
	}

	customsearchService, err := customsearch.NewService(ctx, option.WithAPIKey(customsearchApikey))
	if err != nil {
		log.Printf("[ERROR] Failed to create customsearch service: %s", err)
		return "", err
	}

	// Create search
	search := customsearchService.Cse.List()
	search.Cx(customsearchCx)
	search.Q(query)

	results, err := search.Do()
	if err != nil {
		log.Printf("[ERROR] Failed to search for '%s': %s", query, err)
		return "", err
	}

	if len(results.Items) == 0 {
		log.Printf("[INFO] No results found for '%s'", query)
		return "", nil
	}

	// Return the first result
	log.Printf("[INFO] Search results for '%s': %s", query, results.Items[0].Link)
	//for _, result := range results.Items {
	//	log.Printf("Result: %s", result.Link)
	//}

	return results.Items[0].Link, nil
}

func findActionByInput(inputQuery, actionLabel string, foundApp WorkflowApp) (string, error) {
	if len(actionLabel) > 0 {
		actionLabel = fmt.Sprintf("'%s' or ", actionLabel)
	}

	//inputQuery = "internal search elasticsearch"

	parsedNames := fmt.Sprintf("From the following list, which action sounds like it could do %s'%s'?\n", strings.ToLower(actionLabel), strings.ToLower(inputQuery))
	for actionCnt, action := range foundApp.Actions {
		if strings.ToLower(action.Name) == "curl" {
			continue
		}

		newAction := action.Name
		parsed := fmt.Sprintf(strings.Replace(strings.ToLower(newAction), "_", " ", -1))
		parsed = GetCorrectActionName(parsed)
		if len(parsed) > 30 {
			parsed = parsed[:30]
		}

		parsedNames += fmt.Sprintf("%d. %s\n", actionCnt+1, parsed)
		if actionCnt > 150 {
			log.Printf("[INFO] Break because of actionCnt")
			break
		}
	}

	actionLabel = strings.Replace(strings.ToLower(actionLabel), "_", " ", -1)
	additionalInfo := ""
	if foundApp.Name == "HTTP" {
		additionalInfo = "As the app is HTTP, you can also use the following actions: GET, POST, PUT, PATCH, DELETE, HEAD. Choose the most likely. "
	}

	systemMessage := fmt.Sprintf("%s. Return it as a string. If no match is found, return {\"success\": \"false\"}", additionalInfo)

	log.Printf("[INFO] No action found yet. Looking for synonyms of %s'%s'.", actionLabel, inputQuery)
	//log.Printf("[INFO] System message: %s", systemMessage)

	// Parses the input and returns the category and action label
	contentOutput, err := RunAiQuery(systemMessage, parsedNames) 
	if err != nil {
		log.Printf("[ERROR] Failed to run AI query in findActionByInput: %s", err)
		return "", err
	}

	if strings.Contains(contentOutput, "\n") {
		log.Printf("[INFO] Found newline in contentOutput. Removing: %s", contentOutput)
		contentOutput = strings.Split(contentOutput, "\n")[0]
	}

	// Check if contentOutput starts with the format number.
	// If so, return the action
	if strings.Contains(contentOutput, ". ") {
		actionNum := strings.Split(contentOutput, ". ")
		if len(actionNum) > 1 {
			contentOutput = strings.Join(actionNum[1:], ". ")
		}
	}

	log.Printf("[INFO] Content output for find action for %s'%s': %s", actionLabel, inputQuery, contentOutput)

	return contentOutput, nil
}

// Context aware parameter mapping
func getSelectedAppParameters(ctx context.Context, user User, selectedAction WorkflowAppAction, foundApp WorkflowApp, appname, category, outputFormat string, httpOutput HTTPWrapper, input QueryInput) (WorkflowAppAction, error) {

	inputQuery := input.Query
	appContext := input.AppContext

	for index, appContextItem := range appContext {
		appContext[index] = fixAppcontextExamples(appContextItem)
	}

	// Validating authentication usage
	selectedAction.AuthNotRequired = true
	for _, param := range selectedAction.Parameters {
		if param.Configuration {
			//log.Printf("[INFO] Found configuration parameter (auth): %s", param.Name)
			selectedAction.AuthNotRequired = false
		}
	}

	log.Printf("[INFO] Found app in runActionAI: %s. Actionname: %#v. Actions: %d. Auth required: %#v", foundApp.Name, selectedAction.Name, len(foundApp.Actions), !selectedAction.AuthNotRequired)

	// Maybe make special auth check for HTTP?

	foundAuth := AppAuthenticationStorage{}
	if !selectedAction.AuthNotRequired && len(input.Parameters) == 0 {
		log.Printf("[INFO] Running auth as it's in %s output / execute mode", outputFormat)

		// Check if authentication for the app exists (if necessary?)
		allAuth, err := GetAllWorkflowAppAuth(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("[ERROR] Failed to get auth for app %s: %s", foundApp.Name, err)

			return selectedAction, err
		}

		edited := int64(-1)
		for _, auth := range allAuth {
			if (auth.App.Name == foundApp.Name) || auth.App.ID == foundApp.ID {

				// Check if the auth newer than edited
				if auth.Edited > edited {
					edited = auth.Edited
					foundAuth = auth
				}
			}
		}

		if len(foundAuth.App.Name) == 0 && !strings.HasPrefix(outputFormat, "action") {
			log.Printf("\n\n[ERROR] No auth found for app %s in org %s (%s). Should ask for auth from the user\n\n", foundApp.Name, user.ActiveOrg.Name, user.ActiveOrg.Id)

			returnStruct := appAuthStruct{
				Success: false,
				Reason:  fmt.Sprintf("No auth found for app %s in category %s. Please authenticate it below, and we will continue the search.", strings.Replace(strings.Replace(foundApp.Name, "_", " ", -1), "\"", "", -1), strings.Replace(strings.Replace(category, "_", " ", -1), "\"", "", -1)),
				Action:  "app_authentication",
				Apps: []AppMini{
					{
						ActionName:             selectedAction.Name,
						Category:               category,
						Id:                     foundApp.ID,
						Name:                   foundApp.Name,
						Version:                foundApp.AppVersion,
						LargeImage:             foundApp.LargeImage,
						AuthenticationRequired: true,
						Authentication:         foundApp.Authentication,
					},
				},
			}

			// Marshal
			returnJSON, err := json.Marshal(returnStruct)
			if err != nil {
				log.Printf("[ERROR] Failed to marshal returnStruct: %s", err)

				return selectedAction, err
			}

			return selectedAction, errors.New(string(returnJSON))
		}

		log.Printf("[INFO] Found auth for app %s: %s (%s)", foundApp.Name, foundAuth.Label, foundAuth.Id)
		selectedAction.AuthenticationId = foundAuth.Id
	}

	sampleBody := ""
	bodyIndex := -1
	queryIndex := -1
	//log.Printf("[INFO] HttpOutput: %#v", httpOutput)
	if len(httpOutput.URL) > 0 && appname == "HTTP" {
		// Should parse httpOutput -> selectedAction
		// log.Printf("[INFO] Found HTTP output: %#v", httpOutput)

		for paramIndex, param := range selectedAction.Parameters {
			//log.Printf("[INFO] Checking parameter %s", param.Name)
			if param.Name == "url" {
				selectedAction.Parameters[paramIndex].Value = httpOutput.URL
			} else if param.Name == "headers" {
				selectedAction.Parameters[paramIndex].Value = httpOutput.Headers
			} else if param.Name == "body" {
				// bodyIndex = paramIndex
				// sampleBody =
				selectedAction.Parameters[paramIndex].Value = httpOutput.Body
			} else if param.Name == "query" || param.Name == "queries" {
				queryIndex = paramIndex
			}
		}
	} else {

		// Find the sample response
		requiredFields := []string{}
		authenticationFields := []string{}
		headersFound := false
		for paramIndex, param := range selectedAction.Parameters {
			if len(input.Parameters) > 0 {
				found := false
				for _, inputParam := range input.Parameters {
					if inputParam.Name == param.Name {
						found = true
					}
				}

				if !found {
					//log.Printf("[INFO] Parameter %s not found in input parameters", param.Name)
					continue
				}
			}

			if selectedAction.Name == "repeat_back_to_me" && param.Name == "call" {
				requiredFields = append(requiredFields, fmt.Sprintf("%s:Write python code that solves the problem of without any custom libraries '%s'", param.Name, inputQuery))
				continue
			}

			// bad hardcoding
			if param.Name == "field" || param.Name == "value" {
				param.Required = true
			}

			if param.Required {
				if param.Configuration {
					authenticationFields = append(authenticationFields, param.Name)
				} else {
					if len(param.Options) > 0 && len(param.Options) != 2 {
						parsedname := fmt.Sprintf("%s:OPTIONS->", param.Name)
						parsedname += strings.Join(param.Options, ",")
						requiredFields = append(requiredFields, parsedname)
					} else {
						requiredFields = append(requiredFields, fmt.Sprintf("%s:%s", param.Name, param.Description))
					}
				}
			}

			if param.Name == "body" {
				if len(param.Value) > 0 {
					sampleBody = param.Value
				} else {
					sampleBody = param.Example
				}

				bodyIndex = paramIndex
			}

			if param.Name == "headers" {
				selectedAction.Parameters[paramIndex].Value = "Content-Type=application/json\nAccept=application/json"
				headersFound = true
			}

			if param.Name == "query" || param.Name == "queries" {
				queryIndex = paramIndex
			}
		}

		if !headersFound && bodyIndex != -1 {
			selectedAction.Parameters = append(selectedAction.Parameters, WorkflowAppActionParameter{
				Name:  "headers",
				Value: "Content-Type=application/json\nAccept=application/json",
			})
		}

		if len(requiredFields) > 0 {
			// "For the app 'Gmail', fill in the following fields in JSON format based on our input. If a specific input is not supplied, make a guess. If you are unsure, leave it blank."
			formattedFields := `{`
			for _, field := range requiredFields {
				formattedFields += fmt.Sprintf(`"%s": "", `, field)
			}

			formattedFields = formattedFields[:len(formattedFields)-2] + `}`
			outputBody := ""
			if len(requiredFields) > 1 {
				outputBody = MatchRequiredFieldsWithInputdata(inputQuery, appname, selectedAction.Name, formattedFields)
			}

			var parsedBody map[string]interface{}
			err := json.Unmarshal([]byte(outputBody), &parsedBody)
			if len(outputBody) > 0 && err != nil {
				// Parsed outputbody to map and loop through field keys
				log.Printf("[INFO] IN REQUIRED FIELDS: %s", outputBody)
				for _, field := range requiredFields {
					// Check if ok first to make it string
					if parsedBody[field] == nil {
						continue
					}

					// find the index in selectedAction.Parameters
					foundIndex := -1
					for paramIndex, param := range selectedAction.Parameters {
						if param.Name == field {
							foundIndex = paramIndex
							break
						}
					}

					if foundIndex == -1 {
						log.Printf("[ERROR] Failed to find index for field %s", field)
						continue
					}

					// Check if it is a string
					if _, ok := parsedBody[field].(string); ok {
						if len(parsedBody[field].(string)) > 0 {
							selectedAction.Parameters[foundIndex].Value = parsedBody[field].(string)
						}
					} else {
						log.Printf("[ERROR] Field %s is not a string, skipping", field)
					}
				}

			} else {
				// Since we are trying to fill them in anyway :)
				if len(sampleBody) == 0 {
					log.Printf("[INFO] No matching body found for app %s. Err: %s", appname, err)
					sampleBody = formattedFields
				}
			}
		}
	}

	outputBody := ""
	outputQueries := ""
	var err error
	apps := []WorkflowApp{}
	newAppContext := []AppContext{}
	if len(sampleBody) == 0 {
		log.Printf("[ERROR] App %s doesn't have a valid body for action %s", appname, selectedAction.Name)

	} else if len(sampleBody) > 0 {
		//log.Printf("[INFO] Sample body:\n%s\n\nGot app context with '%d' items", sampleBody, len(appContext))

		// Automatically filling in missing info when not available
		for index, appContextItem := range appContext {
			//log.Printf("[INFO] App context item: %#v", appContextItem)
			// Set ExampleResponse to same as Example
			if len(appContextItem.Example) > 0 {
				appContext[index].ExampleResponse = appContextItem.Example
				appContextItem = appContext[index]
			}

			if len(appContextItem.ExampleResponse) > 0 {
				continue
			}

			newActionName := strings.ToLower(strings.ReplaceAll(appContextItem.ActionName, " ", "_"))
			if len(appContextItem.AppID) == 0 {
				if len(apps) == 0 {
					apps, err = GetPrioritizedApps(ctx, user)
					if err != nil {
						log.Printf("[ERROR] Failed to get prioritized apps during chat %s", err)
					}
				}

				log.Printf("[INFO] Finding item based on app name %s", appContextItem.AppName)

				// Find it and insert as it can use defaults
				for _, app := range apps {
					if app.Name == appContextItem.AppName {
						// Get the OpenAPI for it to find the sample response
						foundApi, err := GetOpenApiDatastore(ctx, app.ID)
						if err != nil {
							log.Printf("[ERROR] Failed to get OpenAPI for app %s", app.Name)
							continue
						}

						// Find the actual endpoint and get the sample response
						log.Printf("[DEBUG] Finding data based on the ID %s", app.ID)
						example, err := FindMatchingAction(foundApi, newActionName)
						if err != nil {
							log.Printf("[ERROR] Failed to find matching action for app %s", appContextItem.AppName)
						}

						// Set the example response
						appContext[index].ExampleResponse = example
						appContext[index].Example = example
						appContextItem = appContext[index]
						break
					}
				}
			} else {
				log.Printf("[DEBUG] Finding data based on the ID")
				foundApi, err := GetOpenApiDatastore(ctx, appContextItem.AppID)
				if err == nil {
					example, err := FindMatchingAction(foundApi, newActionName)
					if err != nil {
						log.Printf("[ERROR] Failed to find matching action for app %s", appContextItem.AppName)
					}

					appContext[index].ExampleResponse = example
					appContext[index].Example = example
					appContextItem = appContext[index]
				}
			}
		}

		// Use OpenAI to find the right one based on name matches
		for _, appContextItem := range appContext {
			newAppContext = append(newAppContext, fixAppcontextExamples(appContextItem))
		}

		// Uses the action to check if fields are already filled or not
		// FIXME: May cause weird bugs where same should be used multiple times
		inputQuery = fixInputQuery(inputQuery, selectedAction)
		outputBody = MatchBodyWithInputdata(inputQuery, appname, selectedAction.Name, sampleBody, newAppContext)
		//log.Printf("[INFO] Found output body to match input data (required fields): %s", outputBody)

		appContext = newAppContext

		// Unmarshal body to map
		var parsedBody map[string]interface{}
		err := json.Unmarshal([]byte(outputBody), &parsedBody)
		if err != nil {
			log.Printf("[ERROR] Failed to unmarshal required fields body to map: %s", err)
		} else {
			for key, value := range parsedBody {
				if strings.Contains(key, ":") {
					key = strings.Split(key, ":")[0]
				}

				if strings.Contains(key, ".") {
					key = strings.Split(key, ".")[0]
				}

				for paramIndex, param := range selectedAction.Parameters {
					if param.Name != key {
						continue
					}

					log.Printf("[INFO] Found matching key %s for param %s. Should replace (1).", key, param.Name)

					// Check type and map it to string either way
					if _, ok := value.(string); !ok {
						log.Printf("[INFO] Found non-string value in body parse value: %#v", value)
						selectedAction.Parameters[paramIndex].Value = fmt.Sprintf("%v", value)
					} else {
						selectedAction.Parameters[paramIndex].Value = value.(string)
					}
				}

				if key == "body" || key == "parameters" {
					//log.Printf("[INFO] Found matching key %s for param %s. Should replace (2).", key, "body")

					// Look for params in the body. Parse out the fields first
					body, ok := value.(map[string]interface{})
					if !ok {
						log.Printf("[ERROR] Failed to parse body to map")
						continue
					}

					for field, fieldValue := range body {
						for paramIndex, param := range selectedAction.Parameters {
							if param.Name == field {
								log.Printf("[INFO] Found matching key %s for param %s. Should replace (2).", field, param.Name)
								selectedAction.Parameters[paramIndex].Value = fieldValue.(string)

								// Just one example
								if key == "input_list" && strings.Contains(selectedAction.Parameters[paramIndex].Value, ".#") {
									// Remove anything after .#
									selectedAction.Parameters[paramIndex].Value = strings.Split(selectedAction.Parameters[paramIndex].Value, ".#")[0]
								}
							}
						}
					}
				}
			}
		}
	}

	if len(outputBody) > 0 && bodyIndex >= 0 {
		if debug { 
			log.Printf("\n\n\n[INFO] Found matching body FROM MatchBodyWithInputdata(): %s\n\n", outputBody)
		}
		selectedAction.Parameters[bodyIndex].Value = outputBody
	}

	if queryIndex >= 0 && bodyIndex < 0 {
		// FIXME: Queries disabled for now due to duplicates in use
		log.Printf("[INFO] Found matching query: %s", outputQueries)

		inputQuery = fixInputQuery(inputQuery, selectedAction)
		outputQueries = MatchBodyWithInputdata(inputQuery, appname, selectedAction.Name, sampleBody, newAppContext)

		// Marshal, then rebuild the query string
		var parsedBody map[string]interface{}
		err := json.Unmarshal([]byte(outputQueries), &parsedBody)
		if err == nil {
			newQueries := ""
			for key, value := range parsedBody {
				// Value could NOT be string too
				if _, ok := value.(string); !ok {
					log.Printf("[ERROR] Found non-string value in query parse value: %s", value)
					continue
				}

				newQueries += fmt.Sprintf("%s=%s&", key, value)
			}

			if len(newQueries) > 0 {
				newQueries = newQueries[:len(newQueries)-1]
				outputQueries = newQueries
			}
		}
	}

	if len(outputQueries) > 0 && queryIndex >= 0 {
		log.Printf("[INFO] Found matching query: %s", outputQueries)
		selectedAction.Parameters[queryIndex].Value = outputQueries
	}

	// Run through the rest of the params and search for and parse them based on other workflows
	// FIXMe: Then based on other peoples' uses of those workflows (anonymous values~)
	// Get workflows to be used
	// Don't run this part for shuffle tools specific stuff :3
	workflows, err := GetAllWorkflowsByQuery(ctx, user, 250, "")
	if err != nil {
		//log.Printf("[ERROR] Failed to get workflows to compare. Not fatal, and will continue without: %s", err)
	}

	currentWorkflow := Workflow{}
	if len(input.WorkflowId) > 0 {
		for _, workflow := range workflows {
			if workflow.ID == input.WorkflowId {
				currentWorkflow = workflow
				break
			}
		}

		if len(currentWorkflow.ID) > 0 {
			for _, action := range currentWorkflow.Actions {
				if action.AppID == foundApp.ID || action.AppName == foundApp.Name {

					for selectedParam, param := range selectedAction.Parameters {
						// If empty, send back suggestion
						if len(param.Value) != 0 {
							continue
						}

						if param.Configuration && strings.ToLower(param.Name) != "url" {
							continue
						}

						if strings.ToLower(appname) == "http" && (param.Name == "username" || param.Name == "password") {
							continue
						}

						// Find the same param in the current workflow
						// Which action doesn't really matter as there's usually a huge crossover
						for _, currentParam := range action.Parameters {
							if currentParam.Name == param.Name {
								selectedAction.Parameters[selectedParam].Value = currentParam.Value
								break
							}
						}
					}
				}
			}
		}
	}

	// Now check ALL workflows for the same action
	for _, currentWorkflow := range workflows {
		for _, action := range currentWorkflow.Actions {
			if action.AppID == foundApp.ID || action.AppName == foundApp.Name {

				for selectedParam, param := range selectedAction.Parameters {
					// If empty, send back suggestion
					if len(param.Value) != 0 {
						continue
					}

					if param.Configuration && strings.ToLower(param.Name) != "url" {
						continue
					}

					if strings.ToLower(appname) == "http" && (param.Name == "username" || param.Name == "password") {
						continue
					}

					// Find the same param in the current workflow
					// Which action doesn't really matter as there's usually a huge crossover
					for _, currentParam := range action.Parameters {
						if currentParam.Name == param.Name {
							selectedAction.Parameters[selectedParam].Value = currentParam.Value
							break
						}
					}
				}
			}
		}
	}

	return selectedAction, nil

}

func sendRequestToSelf(url, authHeader string, body []byte) ([]byte, error) {
	//log.Printf("[INFO] Sending action to %s with action: %s", url, string(body))
	log.Printf("[INFO] Sending action to %s", url)

	req, err := http.NewRequest(
		"POST",
		url,
		bytes.NewBuffer(body),
	)

	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", authHeader)
	res, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed request to url %s (1): %s", url, err)
	}

	defer res.Body.Close()
	// Read response body
	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[ERROR] Failed request to url %s (3): %s", url, err)
		return []byte{}, err
	}

	// Check status code
	if res.StatusCode != 200 {
		log.Printf("[ERROR] Bad response from url %s (2): %s. Body: %s", url, res.Status, string(body))
		return body, errors.New("Failed to run the app")
	}

	//log.Printf("[INFO] Successfully ran request sender to %s. Status: %d, Body output: %s", url, res.StatusCode, string(body))
	//log.Printf("[INFO] Successfully ran request sender to %s. Status: %d", url, res.StatusCode)
	return body, nil
}

func fixAppcontextExamples(appContext AppContext) AppContext {
	// Limiting the size of the examples, as they can be 100k++ characters

	maxLength := 1250

	//log.Printf("[INFO] Fixed appcontext examples to max %d characters. Current: %d", maxLength, len(appContext.Example))

	// Why don't we have a function for cleaning up fields already?
	// It doesn't need the values, just the keys
	output, _, err := RemoveJsonValues([]byte(appContext.Example), 0)
	if err != nil {
		log.Printf("[ERROR] Failed to remove JSON values in fixAppcontextExamples: %s", err)
	} else {
		appContext.Example = string(output)
	}

	log.Printf("[DEBUG] output length: %d", len(appContext.Example))

	// Remove any \t or \n characters
	appContext.Example = strings.ReplaceAll(appContext.Example, "\t", "")
	appContext.Example = strings.ReplaceAll(appContext.Example, "\n", "")

	if len(appContext.Example) > maxLength {
		appContext.Example = appContext.Example[0:maxLength]
	}
	appContext.ExampleResponse = ""
	//appContext.Example = appContext.Example[0:maxLength]

	return appContext
}

func findNextAction(action Action, stepOutput []byte, additionalInfo, inputdata, originalAppname string) (string, Action, error, string) {
	// 1. Find the result field in json
	// 2. Check the status code if it's a good one (<300). If it is, make the output correct based on it and add context based on output.
	// 3. If 400-499, check for error message and self-correct. e.g. if body says something is wrong, try to fix it. If status is 415, try to add content-type header.
	//log.Printf("[INFO] Output from app: %s", string(stepOutput))

	actionName := strings.Replace(action.Name, "_", " ", -1)

	// Unmarshal stepOutput to a map and find result field
	var stepOutputMap map[string]interface{}
	err := json.Unmarshal(stepOutput, &stepOutputMap)
	if err != nil {
		log.Printf("[ERROR] Error unmarshalling stepOutput: %s", err)
		return "", action, err, additionalInfo
	}

	success1, ok := stepOutputMap["success"]
	if !ok {
		log.Printf("[ERROR] No success field found in stepOutput")
	} else {
		// Check if bool
		if success1, ok := success1.(bool); ok {
			if success1 == false {
				log.Printf("[ERROR] Success field is false in stepOutput for finding the next thing to do. Most likely related to action not finishing / bad input: %s", string(stepOutput))
				return "", action, fmt.Errorf("Ran action towards App %s with Action %s, but it failed. Please try to re-authenticate the app or contact support@shuffler.io", action.AppName, actionName), additionalInfo
			}
		}
	}

	result1, ok := stepOutputMap["result"]
	if !ok {
		log.Printf("[ERROR] No result field found in stepOutput")
		return "", action, err, additionalInfo
	}

	result := result1.(string)
	//result = strings.Replace(result, "\\\"", "\"", -1)
	//log.Printf("[INFO] Result: %s", result)

	// Unmarshal result to a map and find status code
	var resultMap map[string]interface{}
	err = json.Unmarshal([]byte(result), &resultMap)
	if err != nil {
		log.Printf("[ERROR] Error unmarshalling result from string to map: %s", err)
		return "", action, err, additionalInfo
	}

	status := -1
	statusCode, ok := resultMap["status"]
	if !ok {
		//log.Printf("[ERROR] No status code found in stepOutput")
	} else {
		// Check if int
		if val, ok := statusCode.(int); ok {
			status = val
		} else if val, ok := statusCode.(float64); ok {
			status = int(val)
		}

		if status != -1 {
			//log.Printf("[INFO] Status code: %d", status)

			if status >= 200 && status < 300 {
				// Handle 200s
			} else if status == 401 {
				// Handle 401
				log.Printf("[ERROR] 401 status code. Most likely related to authentication. Asking for re-auth.")
				return "", action, errors.New(fmt.Sprintf("Ran action towards App %s with Action %s, but it failed. Try to re-authenticate the app or contact support@shuffler.io", action.AppName, actionName)), additionalInfo

			} else if status >= 400 && status < 500 {
				// Handle 400s, e.g. 415 that matches body

				// Based on body X and status Y, suggest what we should do next with this result
				// Our current fields are these:
			}
		}
	}

	if strings.Contains(result, "Max retries exceeded with url") {
		log.Printf("[ERROR] Max retries exceeded with url. Most likely related to authentication. Asking for re-auth.")
		return "", action, fmt.Errorf("Ran action towards App %s with Action %s, but it failed. Try to re-authenticate the app with the correct URL", action.AppName, actionName), additionalInfo
	}

	body := []byte{}
	body1, bodyOk := resultMap["body"]
	if !bodyOk {
		log.Printf("[ERROR] No body found in stepOutput. Setting body to be full request")

		// Checking for success and setting fake status
		// find success in resultMap
		success1, successOk := resultMap["success"]
		if successOk {
			log.Printf("[ERROR] No success field found in stepOutput")

			if success1, ok := success1.(bool); ok {
				body = []byte(result)

				log.Printf("In here? %v", success1)
				if success1 == true {
					status = 200
				} else {
					status = 400
				}

				bodyOk = true
			} else {
				log.Printf("[ERROR] No success field found in stepOutput")
			}
		}
	}

	log.Printf("[DEBUG] Status: %d, ok: %t", status, bodyOk)

	if bodyOk {
		if val, ok := body1.(map[string]interface{}); ok {
			// Marshal
			body, err = json.Marshal(val)
			if err != nil {
				log.Printf("[ERROR] Error marshalling body in response: %s", err)
				return "", action, err, additionalInfo
			}
		} else if val, ok := body1.(string); ok {
			body = []byte(val)
		}

		if debug { 
			log.Printf("[DEBUG] ERROR in body handler. Status: %#v: %s", string(body), status)
		}

		// Should turn body into a string and check OpenAPI for problems if status is bad
		if status >= 200 && status < 300 {
			useApp := action.AppName
			if len(originalAppname) > 0 {
				useApp = originalAppname
			}

			outputString := HandleOutputFormatting(string(body), inputdata, useApp)
			//log.Printf("[INFO] Output string from OpenAI to be returned: %s", outputString)

			return outputString, action, nil, additionalInfo
		} else if status >= 400 {
			// Auto-correct
			// Auto-fix etc

			log.Printf("[INFO] Trying autocorrect. See body: %s", string(body))

			useApp := action.AppName
			if len(originalAppname) > 0 {
				useApp = originalAppname
			}

			action, additionalInfo, err := runSelfCorrectingRequest(action, status, additionalInfo, string(body), useApp, inputdata)
			if err != nil {
				//log.Printf("[ERROR] Error running self-correcting request (2): %s", err)
				return "", action, err, additionalInfo
			}

			return "", action, nil, additionalInfo

			// Try to fix the request based on the body
		} else {
			return "", action, errors.New(getBadOutputString(action, action.AppName, inputdata, string(body), status)), additionalInfo
		}
	}

	return "", action, errors.New(getBadOutputString(action, action.AppName, inputdata, string(body), status)), additionalInfo
}

func MatchRequiredFieldsWithInputdata(inputdata, appname, inputAction, body string) string {
	actionInfo := ""
	if len(inputAction) > 1 {
		actionInfo = fmt.Sprintf(" action '%s'", inputAction)
	}

	systemMessage := fmt.Sprintf("For the %s API%s, fill in the following fields in JSON format based on our input. If a specific input is not supplied, make a guess. Don't add fields that haven't been supplied.", appname, actionInfo)
	log.Printf("[INFO] Required fields message: %s", systemMessage)

	contentOutput, err := RunAiQuery(systemMessage, inputdata) 
	if err != nil {
		log.Printf("[ERROR] Failed to run AI query in MatchRequiredFieldsWithInputdata: %s", err)
		return ""
	}

	log.Printf("[INFO] Required fields output match (1): %s", contentOutput)

	newResult := ResultChecker{
		Success: true,
		Reason:  contentOutput,
		Extra:   "Shuffle GPT used to generate your data. More about the app here: https://shuffler.io/apps/shuffle-ai",
	}

	jsonResult, err := json.Marshal(newResult)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal result in runActionAI: %s", err)
		return `{"success": false, "reason": "Failed to parse result"}`
	}

	return string(jsonResult)
}

func FindMatchingAction(foundApi ParsedOpenApi, newActionName string) (string, error) {
	var err error
	parsedOpenApi := openapi3.Swagger{}
	err = json.Unmarshal([]byte(foundApi.Body), &parsedOpenApi)
	if err != nil {
		log.Printf("[ERROR] Failed to parse OpenAPI for find matching action: %s", err)
		return "", err
	}

	foundExample := ""
	for _, path := range parsedOpenApi.Paths {
		// Check if name  is the same as the AppContextItem.ActionName
		//log.Printf("%#v", path)

		// Check if there is an example
		if path.Get != nil {
			name := strings.ToLower(strings.ReplaceAll(path.Get.Summary, " ", "_"))
			if name == newActionName {
				//log.Printf("[INFO] Found matching action %s", name)

				//log.Printf("%#v", path.Get.Responses)

				// Parse out the response from the "default" key
				if len(path.Get.Responses) > 0 {
					//response := path.Get.Responses[200]
					if defaultInfo, ok := path.Get.Responses["default"]; ok {
						if content, ok := defaultInfo.Value.Content["text/plain"]; ok {
							if content.Schema.Value.Example != nil {
								foundExample = fmt.Sprintf("%v", content.Schema.Value.Example)
							}
						}
					}
				}

				break
			}
		} else if path.Post != nil {
			name := strings.ToLower(strings.ReplaceAll(path.Post.Summary, " ", "_"))

			if name == newActionName {
				log.Printf("[INFO] Found matching action %s", name)

				// Parse out the response from the "default" key
				if len(path.Post.Responses) > 0 {
					//response := path.Get.Responses[200]
					if defaultInfo, ok := path.Post.Responses["default"]; ok {
						if content, ok := defaultInfo.Value.Content["text/plain"]; ok {
							if content.Schema.Value.Example != nil {
								foundExample = fmt.Sprintf("%v", content.Schema.Value.Example)
							}
						}
					}
				}

				break
			}

		} else if path.Delete != nil {
			name := strings.ToLower(strings.ReplaceAll(path.Delete.Summary, " ", "_"))

			if name == newActionName {
				log.Printf("[INFO] Found matching action %s", name)

				// Parse out the response from the "default" key
				if len(path.Delete.Responses) > 0 {
					//response := path.Get.Responses[200]
					if defaultInfo, ok := path.Delete.Responses["default"]; ok {
						if content, ok := defaultInfo.Value.Content["text/plain"]; ok {
							if content.Schema.Value.Example != nil {
								foundExample = fmt.Sprintf("%v", content.Schema.Value.Example)
							}
						}
					}
				}

				break
			}
		} else if path.Put != nil {
			name := strings.ToLower(strings.ReplaceAll(path.Put.Summary, " ", "_"))

			if name == newActionName {
				log.Printf("[INFO] Found matching action %s", name)

				// Parse out the response from the "default" key
				if len(path.Put.Responses) > 0 {
					//response := path.Get.Responses[200]
					if defaultInfo, ok := path.Put.Responses["default"]; ok {
						if content, ok := defaultInfo.Value.Content["text/plain"]; ok {
							if content.Schema.Value.Example != nil {
								foundExample = fmt.Sprintf("%v", content.Schema.Value.Example)
							}
						}
					}
				}

				break
			}
		} else if path.Patch != nil {
			name := strings.ToLower(strings.ReplaceAll(path.Patch.Summary, " ", "_"))

			if name == newActionName {
				log.Printf("[INFO] Found matching action %s", name)

				// Parse out the response from the "default" key
				if len(path.Patch.Responses) > 0 {
					//response := path.Get.Responses[200]
					if defaultInfo, ok := path.Patch.Responses["default"]; ok {
						if content, ok := defaultInfo.Value.Content["text/plain"]; ok {
							if content.Schema.Value.Example != nil {
								foundExample = fmt.Sprintf("%v", content.Schema.Value.Example)
							}
						}
					}
				}

				break
			}
		}
	}

	return foundExample, nil
}

func fixInputQuery(inputQuery string, selectedAction WorkflowAppAction) string {
	foundInputValues := []string{}
	fieldsplit1 := strings.Split(inputQuery, "fields '")
	if len(fieldsplit1) > 1 {
		fieldsplit2 := strings.Split(fieldsplit1[1], "' with")
		if len(fieldsplit2) > 1 {
			//log.Printf("[INFO] Found fieldsplit2: %s", fieldsplit2[0])

			for _, field := range strings.Split(fieldsplit2[0], "&") {
				foundInputValues = append(foundInputValues, field)

				/*
					foundKeys := strings.Split(field, "=")
					if len(foundKeys) == 2 {
						foundInputValues = append(foundInputValues, foundKeys[1])
					}
				*/
			}
		}
	}

	for _, param := range selectedAction.Parameters {
		for _, kv := range foundInputValues {
			if !strings.Contains(kv, "=") {
				continue
			}

			value := strings.Split(kv, "=")[1]
			if strings.Contains(param.Value, value) {
				// Remove the kv from inputQuery
				inputQuery = strings.Replace(inputQuery, kv+"&", "", -1)
				inputQuery = strings.Replace(inputQuery, kv, "", -1)
			}
		}
	}

	//log.Printf("[INFO] Fixed input query: %s", inputQuery)

	return inputQuery
}

func MatchBodyWithInputdata(inputdata, appname, actionName, body string, appContext []AppContext) string {
	actionName = strings.ReplaceAll(actionName, "_", " ")
	if strings.HasPrefix(actionName, "post ") {
		actionName = strings.ReplaceAll(actionName, "post ", "")
	} else if strings.HasPrefix(actionName, "patch ") {
		actionName = strings.ReplaceAll(actionName, "patch ", "")
	} else if strings.HasPrefix(actionName, "put ") {
		actionName = strings.ReplaceAll(actionName, "put ", "")
	}

	if strings.HasPrefix(inputdata, "//") {
		inputdata = inputdata[2:]
		inputdata = strings.TrimSpace(inputdata)
	}

	systemMessage := fmt.Sprintf("If the User Instruction tells you what to do, do exactly what it tells you. Match the JSON body exactly and fill in relevant data from the message '%s' only IF it looks like JSON. Match output format exactly for '%s' doing '%s'. Output valid JSON if the input looks like JSON, otherwise follow the format. Do NOT remove JSON fields - instead follow the format, or add to it. Don't tell us to provide more information. If it does not look like JSON, don't force it to be JSON. DO NOT use the example provided in your response. It is strictly just an example and has not much to do with what the user would want. If you see anything starting with $ in the example, just assume it to be a variable and needs to be ALWAYS populated by you like a template based on the user provided details. User Instruction to follow exactly: '%s'", inputdata, strings.Replace(appname, "_", " ", -1), actionName, inputdata)

	if debug {
		log.Printf("[DEBUG] System: %s", systemMessage)
	}

	assistantInfo := fmt.Sprintf(`Use JSON keys from the sources as additional context, and add values from it in the format '{{label.key.subkey}}' if it has no list, else '{{label.key[].subkey}}'. Example: the response of label 'shuffle tools 1' is '{"name": {"firstname": "", "lastname": ""}}' and you are looking for a lastname, then you get {{shuffle_tools_1.name.lastname}}. Don't randomly make fields empty for no reason. Add keys and values to ensure ALL input fields are included. Below is the body you should add to or modify for API '%s' in app '%s'. \n%s`, actionName, strings.ReplaceAll(appname, "_", " "), body)

	//assistantInfo := "Use JSON keys from the example responses below as additional context, and add values from it:"
	if len(appContext) > 0 {
		assistantInfo += "\n\nSources: "
		for _, context := range appContext {
			assistantInfo += fmt.Sprintf("\nsource: %s, Action: %s, Label: %s, Response: %s", context.AppName, strings.ReplaceAll(context.ActionName, "_", " "), strings.ReplaceAll(context.Label, "_", " "), context.Example)
		}
	}

	if debug { 
		log.Printf("[DEBUG] Assistant: %s", assistantInfo)
	}

	// FIXME: This MAY not work as we used to do this with 
	// Assistant instead of User for some reason
	contentOutput, err := RunAiQuery(systemMessage, assistantInfo) 
	if err != nil {
		log.Printf("[ERROR] Failed to run AI query in MatchBodyWithInputdata: %s", err)
		return ""
	}


	// Diff and find strings from body vs contentOutput
	// If there are any strings that are not in contentOutput, add them to the contentOutput
	// If there are any strings that are not in body, remove them from the contentOutput
	// If there are any strings that are in body but not in contentOutput, add them to the contentOutput
	if strings.Contains(contentOutput, ".#.") {
		// Making sure lists are now going to .#0. instead of .#. to not break stuff
		contentOutput = strings.Replace(contentOutput, ".#.", ".#0.", -1)
	}

	//contentOutput = `Instruction: send slack msg\n\nJSON Body: {\n"text": "send slack msg"}`

	//log.Printf("[INFO] Generated body based on input:\n%s", contentOutput)
	if strings.HasPrefix(strings.ToLower(contentOutput), "json body: ") {
		contentOutput = contentOutput[11:]
	}

	if !strings.HasPrefix(contentOutput, "{") && strings.Contains(contentOutput, "{") {
		//log.Printf("[DEBUG] Autoformatting output %s to only grab the JSON part", contentOutput)
		// Find { and go to it
		contentOutput = contentOutput[strings.Index(contentOutput, "{"):]
		// From this point, look for the LAST } and go to it

		// Look for tripple ticks and take from start until the ticks
		if strings.Contains(contentOutput, "```") {
			contentOutput = contentOutput[0:strings.Index(contentOutput, "```")]
		} else {
			// Find the last } and take from start until where it's found
			contentOutput = contentOutput[0 : strings.LastIndex(contentOutput, "}")+1]
		}

		//log.Printf("[DEBUG] Autoformatted output to %s", contentOutput)
	}

	sampleFields := []Valuereplace{
		Valuereplace{ 
			Key: "body",
			Value: contentOutput,
		},
	}

	sampleFields = TranslateBadFieldFormats(sampleFields) 
	if len(sampleFields) > 0 {
		contentOutput = sampleFields[0].Value
	}

	if debug { 
		log.Printf("\n\n[DEBUG] TOKENS (Inputdata~): In: %d~, Out: %d~\n\nRAW OUTPUT: %s\n\n", (len(systemMessage)+len(assistantInfo)+len(body))/4, len(contentOutput)/4, string(contentOutput))
	}

	return contentOutput
}

func HandleOutputFormatting(result, inputdata, appname string) string {
	if len(result) > 1000 {
		result = result[0:1000]
	}
	//systemMessage := fmt.Sprintf("Based on '%s', format the output to match what they asked for in any format they want. Specify what the format is, and output as JSON", inputdata)
	//systemMessage := fmt.Sprintf("Based on '%s', format the output to match what they asked for in any format they want. Make it a human readable string unless otherwise specified, and respond in the same language. Make sure to mention that we used the Appname '%s'", inputdata, appname)
	systemMessage := fmt.Sprintf("Based on '%s', format the output to match what they asked for in any format they want. Make it a human readable string in markdown format without HTML unless otherwise specified. If a url is present, add a curl command that matches the input at the bottom as a code-block.", inputdata)
	if strings.ToUpper(appname) != "HTTP" {
		systemMessage += fmt.Sprintf("Make sure to mention that we used the Appname '%s'", appname)
	}
	//log.Printf("[INFO] System message for output: %s", systemMessage)

	contentOutput, err := RunAiQuery(systemMessage, result)
	if err != nil {
		log.Printf("[ERROR] Failed to run AI query in HandleOutputFormatting: %s", err)
		return ""
	}

	if strings.Contains(contentOutput, "success\": false") {
		log.Printf("[ERROR] Failed to run AI query (2) in HandleOutputFormatting: %s", contentOutput)
		return ""
	}

	return contentOutput
}

func runSelfCorrectingRequest(action Action, status int, additionalInfo, outputBody, appname, inputdata string) (Action, string, error) {

	// FIX: Make it find shuffle internal docs as well for how an app works
	// Make it work with Shuffle tools, as now it's explicitly trying to fix fields for HTTP apps

	if len(action.InvalidParameters) == 0 && additionalInfo == "" && strings.ToUpper(appname) != "HTTP" && !strings.Contains(strings.ToUpper(appname), "SHUFFLE") {
		additionalInfo = getOpenApiInformation(strings.Replace(appname, " ", "", -1), strings.Replace(action.Name, "_", " ", -1))
	} else {
		log.Printf("\n\nGot %d invalid params and additional info of length %d", len(action.InvalidParameters), len(additionalInfo))
	}

	// Add all fields with value from here
	inputBody := "{\n"
	for _, param := range action.Parameters {
		if param.Name == "headers" || param.Name == "ssl_verify" || param.Name == "to_file" || param.Name == "url" {
			continue
		}

		/*
			if param.Name != "body" {
				continue
			}
		*/

		if (strings.HasPrefix(param.Value, "{") && strings.HasSuffix(param.Value, "}")) || (strings.HasPrefix(param.Value, "[") && strings.HasSuffix(param.Value, "]")) {
			inputBody += fmt.Sprintf("\"%s\": %s,\n", param.Name, param.Value)
			continue
		}

		// Check if number
		_, err := strconv.ParseFloat(param.Value, 64)
		if err == nil {
			inputBody += fmt.Sprintf("\"%s\": %s,\n", param.Name, param.Value)
			continue
		}

		// Check if bool
		if param.Value == "true" || param.Value == "false" {
			inputBody += fmt.Sprintf("\"%s\": %s,\n", param.Name, param.Value)
			continue
		}

		inputBody += fmt.Sprintf("\"%s\": \"%s\",\n", param.Name, param.Value)
		//break
	}

	// Remove comma at the end

	invalidFields := map[string]string{}
	invalidFieldsString := "Learn from these and change the output based on these field changes.\n"
	for _, param := range action.InvalidParameters {
		invalidFields[param.Name] = param.Value
		invalidFieldsString += fmt.Sprintf("%s: %s\n", param.Name, param.Value)
	}

	if len(invalidFieldsString) <= 68 {
		log.Printf("\n\n[INFO] Invalid fields not set from %d invalid params. Len: %d", len(action.InvalidParameters), len(invalidFieldsString))
		invalidFieldsString = ""
	}

	if strings.HasSuffix(inputBody, ",\n") {
		inputBody = inputBody[:len(inputBody)-2]
	}

	inputBody += "\n}"

	// Append previous problems too
	outputBodies := outputBody

	//appendpoint := "/gmail/v1/users/{userId}/messages/send"
	appendpoint := ""
	if !strings.Contains(additionalInfo, "How the API works") && len(additionalInfo) > 0 {
		additionalInfo = fmt.Sprintf("How the API works: %s\n", additionalInfo)
	}

	systemMessage := fmt.Sprintf("Return all fields from the last paragraph in the JSON format they came in. If the field is \"body\", make sure to format it accordingly, e.g. with RFC's, base64 or other formatting types. Must be valid JSON as an output.")

	inputData := fmt.Sprintf("Change the fields sent to the HTTP Rest API endpoint %s for service %s to work according to the error message in the body. Learn from the error information in the paragraphs to fix the fields in the last paragraph.\n\nHTTP Status: %d\nHTTP error: %s\n\n%s\n\n%s\n\nUpdate the following fields and output as JSON in the same format.\n%s", appendpoint, appname, status, outputBodies, additionalInfo, invalidFieldsString, inputBody)

	if debug {
		log.Printf("[DEBUG] INPUTDATA: %s\n\n\n", inputData)
		log.Printf("[DEBUG] Input body sent: %s", inputBody)
	}

	contentOutput, err := RunAiQuery(systemMessage, inputData) 
	if err != nil {
		log.Printf("[ERROR] Failed to run AI query in runActionAI: %s", err)
		return action, additionalInfo, err
	}

	log.Printf("[INFO] Content output for fixing app: %s", contentOutput)

	// Fix the params based on the contentOuput JSON
	// Parse output into JSOn
	var outputJSON map[string]interface{}
	err = json.Unmarshal([]byte(contentOutput), &outputJSON)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal outputJSON in action fix for app %s with action %s: %s", appname, action.Name, err)

		return action, additionalInfo, errors.New(getBadOutputString(action, appname, inputdata, outputBody, status))
	}

	sendNewRequest := false
	for paramIndex, param := range action.Parameters {
		// Check if inside outputJSON
		if val, ok := outputJSON[param.Name]; ok {

			//log.Printf("[INFO] Found param %s in outputJSON", param.Name)
			// Check if it's a string or not
			runString := false
			formattedVal := ""
			if _, ok := val.(string); ok {
				runString = true
				formattedVal = val.(string)
			}

			if !runString {
				// Make map from val and marshal to byte
				valMap := val.(map[string]interface{})
				valByte, err := json.Marshal(valMap)
				if err != nil {
					log.Printf("[ERROR] Failed to marshal valMap in action fix for app %s with action %s: %s. Field: %s", appname, action.Name, err, param.Name)
					continue
				}

				formattedVal = string(valByte)
			}

			if formattedVal != param.Value && len(formattedVal) > 0 {
				// Check if already in invalid as well
				// Stored here so we can use them for context
				// Update param
				//param.Value = fmt.Sprintf("%v", val)
				action.InvalidParameters = append(action.InvalidParameters, param)

				action.Parameters[paramIndex].Value = formattedVal
				sendNewRequest = true
			} else {
				//log.Printf("[INFO] Param %s is already same as new one, or wasn't formatted correctly. Type of val: %s", param.Name, reflect.TypeOf(val))

				// Fixme: In the future fix this. For now, we just spam it down until we got 200~ response
				//sendNewRequest = true
			}
		} else {
			reservedParams := []string{"ssl_verify", "to_file"}
			if !ArrayContains(reservedParams, param.Name) {
				//log.Printf("[ERROR] Param %s not found in outputJSON for app %s with action %s", param.Name, appname, action.Name)
			}
		}
	}

	if !sendNewRequest {
		// Should have a good output anyway, meaning to format the bad request

		// Make errorString work in json

		return action, additionalInfo, errors.New(getBadOutputString(action, appname, inputdata, outputBody, status))
	}

	return action, additionalInfo, nil
}

func GetSingulApp(sourcepath, appname string) (*WorkflowApp, error) {
	returnApp := &WorkflowApp{}
	if len(appname) == 0 {
		return returnApp, errors.New("Appname not set")
	}

	// Failover for handling default Singul setup
	if len(sourcepath) == 0 {
		sourcepath = "./files"
		fileLocation := os.Getenv("FILE_LOCATION")
		if len(fileLocation) > 0 {
			sourcepath = fileLocation
		}
	}

	// Look for the file sourcepath/apps/appname.json
	searchname := strings.ReplaceAll(strings.ToLower(appname), " ", "_")
	appPath := fmt.Sprintf("%s/apps/%s.json", sourcepath, searchname)

	var err error
	responseBody := []byte{}

	_, statErr := os.Stat(appPath) 
	if statErr == nil {
		// File exists, read it
		file, err := os.Open(appPath)
		if err != nil {
			return returnApp, err
		}

		defer file.Close()
		responseBody, err = os.ReadFile(appPath)
		if err != nil {
			log.Printf("[ERROR] Error reading file: %s", err)
			return returnApp, err
		}
	} else {
		algoliaPublicKey := os.Getenv("ALGOLIA_PUBLICKEY")
		if len(algoliaPublicKey) == 0 {
			return returnApp, errors.New("Algolia public key not set")
		}

		algoliaAppId := "JNSS5CFDZZ"
		algoliaclient := search.NewClient(algoliaAppId, algoliaPublicKey)

		index := algoliaclient.InitIndex("appsearch")
		res, err := index.Search(appname)
		if err != nil {
			log.Printf("[ERROR] Error searching for app in Algolia index: %s", err)
			return returnApp, err
		}

		appId := ""
		for _, hit := range res.Hits {
			checkObjectId := false
			if name, ok := hit["appname"]; ok {
				if !strings.Contains(strings.ToLower(name.(string)), searchname) {
					checkObjectId = true 
				}
			}

			if val, ok := hit["objectID"]; ok {
				if checkObjectId {
					if objectId, ok := val.(string); ok {
						if objectId != searchname {
							continue
						}
					} else {
						continue
					}
				}

				appId = val.(string)
				break
			} else {
				log.Printf("[ERROR] App not found in Algolia index: %s", appname)
			}
		}

		if appId == "" {
			log.Printf("[ERROR] App not found in Algolia index: %s", appname)
			return returnApp, errors.New("App not found")
		}

		//url := fmt.Sprintf("https://singul.io/apps/%s", appname)
		baseUrl := "https://shuffler.io/api/v1"
		url := fmt.Sprintf("%s/apps/%s/config", baseUrl, appId)
		req, err := http.NewRequest(
			"GET", 
			url, 
			nil,
		)

		if err != nil {
			log.Printf("[ERROR] Error in new request for singul app: %s", err)
			return returnApp, err
		}

		client := &http.Client{}
		newresp, err := client.Do(req)
		if err != nil {
			log.Printf("[ERROR] Error running request for singul app: %s. URL: %s", err, url)
			return returnApp, err
		}

		if newresp.StatusCode != 200 {
			log.Printf("[ERROR] Bad status code for app: %s. URL: %s", newresp.Status, url)
			return returnApp, errors.New("Failed getting app details from backend. Please try again. Appnames may be case sensitive.")
		}

		defer newresp.Body.Close()
		responseBody, err = ioutil.ReadAll(newresp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed reading body for singul app: %s", err)
			return returnApp, err
		}
	}

	// Unmarshal responseBody back to
	newApp := AppParser{}
	err = json.Unmarshal(responseBody, &newApp)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshalling body for singul app: %s %+v", err, string(responseBody))
		return returnApp, err
	}

	if !newApp.Success {
		return returnApp, errors.New("Failed getting app details from backend. Please try again. Appnames may be case sensitive.")
	}

	if len(newApp.App) == 0 {
		return returnApp, errors.New("Failed finding app for this ID")
	}

	// Unmarshal the newApp.App into workflowApp
	parsedApp := WorkflowApp{}
	err = json.Unmarshal(newApp.App, &parsedApp)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshalling app: %s", err)
		return &parsedApp, err
	}

	if len(parsedApp.ID) == 0 {
		log.Printf("[WARNING] Failed finding app for this ID")
		return &parsedApp, errors.New("Failed finding app for this ID")
	}

	if statErr != nil {
		err = os.MkdirAll(fmt.Sprintf("%s/apps", sourcepath), os.ModePerm)
		if err != nil {
			log.Printf("[ERROR] Error creating directory: %s", err)
			//return parsedApp, err
		}

		err = os.WriteFile(appPath, responseBody, 0644)
		if err != nil {
			log.Printf("[ERROR] Error writing file: %s", err)
			return &parsedApp, err
		} else {
			log.Printf("[DEBUG] Wrote app to file: %s", appPath)
		}
	}

	return &parsedApp, nil
}

func GetSingulStandaloneFilepath() string {
	singulFolder := os.Getenv("FILE_LOCATION") 
	if len(singulFolder) > 0 {
		singulFolder += "/"
	}

	singulFolder += "singul/"
	err := os.MkdirAll(singulFolder, os.ModePerm)
	if err != nil {
		log.Printf("[ERROR] Error creating directory %s: %s", singulFolder, err)
	}

	return singulFolder
}

func GetFileContentSingul(ctx context.Context, file *File, resp http.ResponseWriter) ([]byte, error) {
	if standalone {
		filepath := fmt.Sprintf("%s%s", GetSingulStandaloneFilepath(), file.Id)

		// File exists, read it
		file, err := os.Open(filepath)
		if err != nil {
			log.Printf("[ERROR] Problem opening Singul file '%s': %s", filepath, err)
			return []byte{}, err
		}

		defer file.Close()

		data, err := ioutil.ReadAll(file)
		if err != nil {
			log.Printf("[ERROR] Problem reading Singul file data for '%s': %s", filepath, err)
			return []byte{}, err
		}

		return data, nil 

		//log.Printf("\n\n\n[ERROR] GET FILE CONTENT FAILING\n\n\n")
		//return []byte{}, errors.New(fmt.Sprintf("GetContent: Standalone mode not supported/implemented YET for file CONTENT ID '%s'", file.Id))
	}

	return GetFileContent(ctx, file, resp)
}

func SetFileSingul(ctx context.Context, file File) error {
	if standalone {
		//log.Printf("\n\n\n[ERROR] SET FILE FAILING. ID: %#v, Name: %#v\n\n\n", file.Id, file.Filename)
		//return errors.New(fmt.Sprintf("SetFile: Standalone mode not supported/implemented YET for file ID '%s'", file.Id))
		return nil
	}

	return SetFile(ctx, file)
}

func UploadFileSingul(ctx context.Context, file *File, key string, data []byte) (string, error) {
	if standalone {
		if len(file.Id) == 0 {
			return "", errors.New("File ID required in the file")
		}

		filepath := fmt.Sprintf("%s%s", GetSingulStandaloneFilepath(), file.Id)
		if len(file.Namespace) > 0 && !strings.HasPrefix(file.Id, file.Namespace) {
			if strings.HasSuffix(file.Namespace, "/") {
				file.Namespace = strings.TrimSuffix(file.Namespace, "/")
			}

			filepath = fmt.Sprintf("%s%s/%s", GetSingulStandaloneFilepath(), file.Namespace, file.Id)
		}

		// Check if the filepath exists as folders, else make it
		folderpath := filepath[0:strings.LastIndex(filepath, "/")]
		_, statErr := os.Stat(folderpath)
		if statErr != nil {
			err := os.MkdirAll(folderpath, os.ModePerm)
			if err != nil {
				log.Printf("[ERROR] Error creating directory: %s", err)
				return "", err
			}
		}

		withFile, err := os.Create(filepath)
		if err != nil {
			log.Printf("[ERROR] Error creating file: %s", err)
			return "", err
		}

		defer withFile.Close()
		_, err = withFile.Write(data)
		if err != nil {
			log.Printf("[ERROR] Error writing file: %s", err)
			return "", err
		}

		return filepath, nil
	}

	return UploadFile(ctx, file, key, data)
}

func GetFileSingul(ctx context.Context, fileId string) (*File, error) {
	if standalone {

		filepath := fmt.Sprintf("%s%s", GetSingulStandaloneFilepath(), fileId)
		//if debug {
		//	log.Printf("[DEBUG] Looking for file ID %s locally.\n\nFull search path: %s", fileId, filepath)
		//}

		_, statErr := os.Stat(filepath) 
		if statErr == nil { 
			return &File{
				Status: "active",
				Id:    fileId,
				Filename: fileId,
			}, nil
		} 

		return &File{
			Status: "not found",
			Id:    fileId,
		}, errors.New(fmt.Sprintf("File not found locally for ID '%s'", fileId))
	}

	return GetFile(ctx, fileId)
}

func init() {
	if os.Getenv("STANDALONE") == "true" {
		standalone = true
	}

	if len(os.Getenv("AI_MODEL")) > 0 {
		model = os.Getenv("AI_MODEL")
	}

	if len(os.Getenv("FALLBACK_AI_MODEL")) > 0 {
		fallbackModel = os.Getenv("FALLBACK_AI_MODEL")
	}
}

func workerPool(jobs <-chan openai.ToolCall, results chan<- AtomicOutput, wg *sync.WaitGroup, user User, input QueryInput) {
	defer wg.Done()
	for toolCall := range jobs {
		//log.Printf("[DEBUG] Running job for toolCall: %+v", toolCall)

		// Your processing logic for each request goes here
		if len(toolCall.Function.Name) == 0 {
			log.Printf("[ERROR] No function found. Skipping.")

			results <- AtomicOutput{
				Success:    false,
				Reason:     fmt.Sprintf("No function name was found"),
				ToolCallID: toolCall.ID,
			}
			continue
		}

		functionName := toolCall.Function.Name
		newAction := CategoryAction{
			Query: input.Query,
			Label: functionName,
			OrgId: user.ActiveOrg.Id,
		}

		if len(input.AppName) > 0 {
			log.Printf("\n\n\n[DEBUG] App name found and appending: %s\n\n\n", input.AppName)
			newAction.AppName = input.AppName
		}

		// Making workflow based on thread
		if len(input.WorkflowId) > 0 {
			newAction.WorkflowId = input.WorkflowId
		} else {
			newAction.WorkflowId = input.ThreadId
		}

		if strings.Contains(functionName, ":") {
			itemsplit := strings.Split(functionName, ":")
			newAction.Category = itemsplit[0]
			newAction.Label = itemsplit[1]
		}

		// Map toolCall.Function.Arguments into map[string]interface{}
		// Then find what they are
		newfields := make(map[string]interface{})

		err := json.Unmarshal([]byte(toolCall.Function.Arguments), &newfields)
		if err != nil {
			log.Printf("[ERROR] Failed to unmarshal tool call arguments to JSON: %#v", string(toolCall.Function.Arguments))
			results <- AtomicOutput{
				Success:    true,
				Reason:     fmt.Sprintf("Parsing problem in Shuffle. Raw: %s", string(toolCall.Function.Arguments)),
				ToolCallID: toolCall.ID,
			}
			continue
		}

		foundApp := ""
		dryRun := false
		for key, value := range newfields {
			log.Printf("[DEBUG] Fields to parse: %s - %s", key, value)

			if key == "dryrun" {
				log.Printf("\n\n\n\n\n[DEBUG] TODO: Got dryrun key\n\n\n\n\n")
			}

			// Check if it's a string or whatever
			switch value.(type) {
			case string:
				if strings.ToLower(key) == "app" || strings.ToLower(key) == "app_name" || strings.ToLower(key) == "appname" {
					foundApp = value.(string)
				}

				if strings.ToLower(key) == "action" {
					newAction.Label = value.(string)
				}

				newAction.Fields = append(newAction.Fields, Valuereplace{
					Key:   key,
					Value: value.(string),
				})
			case float64:
				newAction.Fields = append(newAction.Fields, Valuereplace{
					Key:   key,
					Value: strconv.FormatFloat(value.(float64), 'f', -1, 64),
				})
			case bool:
				if key == "dryrun" {
					dryRun = value.(bool)
					continue
				}

				newAction.Fields = append(newAction.Fields, Valuereplace{
					Key:   key,
					Value: strconv.FormatBool(value.(bool)),
				})
			default:
				log.Printf("[ERROR] Unknown type for autocomplete value: %s", value)
			}
		}

		if functionName == "authenticate_app" || functionName == "discover_app" {
			functionName = "authenticate_app"

			// Check if "app" in newAction fields
			if len(foundApp) > 0 {
				newAction.AppName = foundApp
			} else {
				results <- AtomicOutput{
					Success:    false,
					Reason:     fmt.Sprintf("Could not find the app. Please be more specific"),
					ToolCallID: toolCall.ID,
				}
				return
			}
		} else {
			if len(foundApp) > 0 {
				newAction.AppName = foundApp
			}
		}

		// Send HTTP request to POST shuffler.io/api/v1/apps/categories with the newAction
		newAction.DryRun = dryRun

		parsedOutput, err := json.Marshal(newAction)
		if err != nil {
			log.Printf("[ERROR] Failed to marshal newAction: %s", err)

			results <- AtomicOutput{
				Success:    false,
				Reason:     fmt.Sprintf("Marshal action problem in Shuffle. Raw: %s", err.Error()),
				ToolCallID: toolCall.ID,
			}
			continue
		}

		// Need a dryrun thing here
		log.Printf("[DEBUG] New Action to send to category run from chat: %s", parsedOutput)

		//baseUrl := "http://localhost:5002"
		baseUrl := fmt.Sprintf("https://shuffler.io")
		if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
			baseUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
		}

		parsedUrl := baseUrl + "/api/v1/apps/categories/run"
		req, err := http.NewRequest(
			"POST",
			parsedUrl,
			bytes.NewBuffer(parsedOutput),
		)

		if err != nil {
			log.Printf("[ERROR] Failed to create new request: %s", err)
			results <- AtomicOutput{
				Success:    false,
				Reason:     fmt.Sprintf("Request setup problem in Shuffle. Raw: %s", err.Error()),
				ToolCallID: toolCall.ID,
			}

			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+user.ApiKey)

		client := &http.Client{
			Timeout: time.Second * 60,
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[ERROR] Failed to send request categories request: %s", err)
			results <- AtomicOutput{
				Success:    false,
				Reason:     fmt.Sprintf("Request problem in Shuffle. Raw: %s", err.Error()),
				ToolCallID: toolCall.ID,
			}

			continue
		}

		log.Printf("[DEBUG] Response Status: %s", resp.Status)
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed to read response body: %s", err)
			results <- AtomicOutput{
				Success:    false,
				Reason:     fmt.Sprintf("Body JSON marshal problem in Shuffle. Raw: %s", err.Error()),
				ToolCallID: toolCall.ID,
			}

			continue
		}

		// FIXME: Should add some error handling here
		// and notify the user properly
		if resp.StatusCode != 200 {
			if resp.StatusCode == 400 {
				// Unmarshal into StructuredCategoryAction
				// and then send back to the user
				var structuredAction StructuredCategoryAction
				err := json.Unmarshal(body, &structuredAction)
				if err != nil {
					//log.Printf("[ERROR] Failed to unmarshal structured action (4): %s", err)
					results <- AtomicOutput{
						Success:    false,
						Reason:     fmt.Sprintf("Failed unmarshalling structured return action in Shuffle. Raw: %s", err.Error()),
						ToolCallID: toolCall.ID,
					}

					continue
				}

				if len(input.ThreadId) > 0 {
					structuredAction.ThreadId = input.ThreadId
				}

				if len(input.RunId) > 0 {
					structuredAction.RunId = input.RunId
				}

				//log.Printf("[DEBUG] Structured action required with action: %#v", structuredAction.Action)
				results <- AtomicOutput{
					Success:    false,
					Reason:     string(body),
					ToolCallID: toolCall.ID,
				}

				continue
			}

			log.Printf("[ERROR] Failed to get 200 response from category run: %s", resp.Status)

			results <- AtomicOutput{
				Success:    false,
				Reason:     string(body),
				ToolCallID: toolCall.ID,
			}

			continue
		}

		log.Printf("\n\n[DEBUG] Got a 200 OK response back. Time to let OpenAI interpret it!.\n\n")

		// SubmitToolOutput
		results <- AtomicOutput{
			Success:    true,
			Reason:     string(body),
			ToolCallID: toolCall.ID,
		}
		//results <- openai.ToolOutput{
		//	ToolCallID: toolCall.ID,
		//	Output: string(body),
		//}
	}
}

func GetCategoryLabelParameters(ctx context.Context, category string, label string) string {
	systemMessage := fmt.Sprintf("Output as JSON")
	userMessage := fmt.Sprintf(`I need a programmatic output for the following:

Category: %s
Action: %s

Use the following format, and add fields according to what the action and the category would typically use. Add a maximum of 3 properties, minimum of 0. It doesn't need to have any required properties. Example: if the action is saying "list X", then it usually indicates an amount is required, and sometimes the ID of the parent type. "search" indicates a search query is required, etc.

{
	"name": "%s",
	"description": "The description for the action with info about the category",
	"parameters": {
		"type": "object",
		"required": ["fieldname"],
		"properties": {
			"fieldname": {
				"description": "Description to detail what to fill in the field",
				"type": "string",
			},
			"fieldname2": {
				"description": "Description to detail what to fill in the field",
				"type": "string",
			}
		}
	}
}`, category, label, label)
	//}`, category, label, category, label)

	contentOutput, err := RunAiQuery(systemMessage, userMessage)
	if err != nil {
		log.Printf("[ERROR] Failed to run AI query in GetCategoryLabelParameters: %s", err)
		return ""
	}

	contentOutput = strings.TrimSpace(contentOutput)

	log.Printf("[DEBUG] Content output (get label params): %s", contentOutput)

	return contentOutput
}

func ValidateLabelAvailability(category string, availableLabels []string) {
	log.Printf("\n\n[DEBUG] Label validity checking and updating is disabled. Contact frikky@shuffler.io if you want to know why or / if this limit should be removed.\n\n")
	return

	if len(category) == 0 {
		log.Printf("\n\n[DEBUG] No category provided. Skipping validation.\n\n")
	}

	category = strings.ToLower(category)
	if category == "communication" {
		log.Printf("[FIXME] Communication category casted to email for no reason")
		category = "email"
	}

	if category == "other" {
		log.Printf("[DEBUG] Other category to be skipped")
		return
	}

	// Should check the model if it has these functions available or not
	// 1. Get the assistant
	// 2. Check which of the labels are in there
	// 3. If they're not, run the following query for them
	// 4. Then add the result to the assistant if possible
	/*
			```
		I need a programmatic output for the following:

		Category: Email
		Action: List Messages

		Use the following format, and add fields according to what the action and the category would typically use. Add a maximum of 5 fields. It doesn't need to have any required fields in all cases.
		```
		[{
		   "name": "fieldname",
		   "description": "Description to detail what to fill in the field",
		    "type": "string",
		    "required": false
		  },
		  ...
		}]
		```
	*/

	ctx := context.Background()
	config := openai.DefaultConfig(os.Getenv("OPENAI_API_KEY"))
	config.AssistantVersion = "v2"
	openaiClient := openai.NewClientWithConfig(
		config,
	)

	assistant, err := openaiClient.RetrieveAssistant(
		ctx,
		assistantId,
	)

	if err != nil || assistant.ID == "" {
		log.Printf("[ERROR] Failed to retrieve assistant '%s': %s", assistantId, err)
		return
	}

	if len(assistant.Tools) == 0 {
		log.Printf("[ERROR] Assistant '%s' has no tools", assistantId)
		return
	}

	foundLabels := []string{}
	for _, tool := range assistant.Tools {
		if tool.Type != "function" {
			continue
		}

		foundCategory := ""
		foundLabel := tool.Function.Name
		if strings.Contains(tool.Function.Name, ":") {
			foundCategory = strings.Split(tool.Function.Name, ":")[0]
			foundLabel = strings.ReplaceAll(strings.ToLower(strings.Split(tool.Function.Name, ":")[1]), " ", "_")
		}

		if len(foundCategory) == 0 {
			continue
		}

		if strings.ToLower(foundCategory) != category {
			continue
		}

		// Look for the right label
		for i, label := range availableLabels {
			label = strings.ToLower(strings.ReplaceAll(label, " ", "_"))

			if strings.ToLower(foundLabel) == label {
				foundLabels = append(foundLabels, fmt.Sprintf("%s:%s", foundCategory, foundLabel))

				availableLabels = append(availableLabels[:i], availableLabels[i+1:]...)
				// Remove the label from the available labels
				// so we can check which ones are missing
				break
			}
		}

		//if strings.ToLower(foundLabel) != strings.ToLower(category) {
		//	log.Printf("[DEBUG] Wrong label '%s' in assistant '%s'", category, assistantId)
		//}

		// 	// You can pass json.RawMessage to describe the schema,
	}

	// Compare found vs not found
	if len(availableLabels) == 0 {
		log.Printf("[DEBUG] All labels are already available in assistant '%s'", assistantId)
		return
	}

	// Check category + action with the query thing
	oldLength := len(assistant.Tools)
	for _, label := range availableLabels {
		if len(label) == 0 {
			continue
		}

		log.Printf("[DEBUG] Adding label '%s' to assistant '%s'", label, assistantId)

		parsedParameters := GetCategoryLabelParameters(ctx, category, label)
		if len(parsedParameters) == 0 {
			log.Printf("[ERROR] Failed to parse parameters for category '%s' and label '%s'", category, label)
			continue
		}

		// Look for the "description" field inside the parsed parameters

		var tmpdata map[string]interface{}
		err = json.Unmarshal([]byte(parsedParameters), &tmpdata)
		if err != nil {
			log.Printf("[ERROR] Failed to unmarshal parsed parameters: %s", err)
			continue
		}

		foundDescription := ""
		paramsFound := false
		parsedRawmessage := json.RawMessage(parsedParameters)
		for key, value := range tmpdata {
			if key == "description" && value != nil {
				valueString, ok := value.(string)
				if ok {
					foundDescription = valueString
				}
			}

			if key == "parameters" {
				paramsFound = true
				// Make the raw data into a json.rawmessage
				// Overwrite parsedRawmessage

				properties, ok := value.(map[string]interface{})
				if !ok {
					log.Printf("[ERROR] Failed to parse properties")
					continue
				}

				// Check if "type" is in there and set it to be "object"
				for propertyKey, propertyValue := range properties {
					//log.Printf("[DEBUG] Checking property '%s' with value '%s'", propertyKey, propertyValue)

					if propertyKey == "type" {
						_, ok := propertyValue.(string)
						if ok {
							properties[propertyKey] = "object"
						}
					}
				}

				propertiesJson, err := json.Marshal(properties)
				if err != nil {
					log.Printf("[ERROR] Failed to marshal properties")
					continue
				}

				log.Printf("[DEBUG] Updating parsed raw message to: %s", propertiesJson)
				parsedRawmessage = json.RawMessage(propertiesJson)
			}
		}

		// Print raw message for it
		if !paramsFound {
			log.Printf("[ERROR] No properties field found for parsing of %s:%s!", category, label)
			continue
		}

		if strings.ReplaceAll(strings.ToLower(label), " ", "_") == "no_label" {
			log.Printf("[DEBUG] Skipping handler for %s:%s", category, label)
			continue
		}

		newAssistantTool := openai.AssistantTool{
			Type: "function",
			Function: &openai.FunctionDefinition{
				//Name: fmt.Sprintf("%s:%s", strings.ToLower(category), strings.ReplaceAll(strings.ToLower(label), " ", "_")),
				Name:        fmt.Sprintf("%s", strings.ReplaceAll(strings.ToLower(label), " ", "_")),
				Description: foundDescription,
				Parameters:  parsedRawmessage,
			},
		}

		assistant.Tools = append(assistant.Tools, newAssistantTool)
	}

	if len(assistant.Tools) <= oldLength {
		log.Printf("[ERROR] Failed to add any new labels to assistant '%s'", assistantId)
		return
	}

	if len(assistant.Tools) <= 0 {
		log.Printf("[DEBUG] No new labels to add to assistant '%s'", assistantId)
		return
	}

	log.Printf("[DEBUG] Updating assistant with new functions that were added!")
	assistantRequest := openai.AssistantRequest{
		Model:        assistant.Model,
		Name:         assistant.Name,
		Description:  assistant.Description,
		Instructions: assistant.Instructions,
		Tools:        assistant.Tools,
		FileIDs:      assistant.FileIDs,
		Metadata:     assistant.Metadata,
	}

	// Try to update the assistant
	assistant, err = openaiClient.ModifyAssistant(
		ctx,
		assistantId,
		assistantRequest,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to update assistant '%s' with %d new functions: %s", assistantId, len(assistant.Tools)-oldLength, err)
		return
	}

	log.Printf("[DEBUG] Successfully updated assistant '%s' with new functions!", assistantId)
}

func runAtomicChatRequest(ctx context.Context, user User, input QueryInput) (string, string, string, bool) {

	config := openai.DefaultConfig(os.Getenv("OPENAI_API_KEY"))
	config.AssistantVersion = "v2"
	openaiClient := openai.NewClientWithConfig(
		config,
	)

	cnt := 0

	if len(input.AppName) > 0 {
		newAppname := strings.ToLower(strings.ReplaceAll(input.AppName, "_", " "))
		if !strings.Contains(strings.ToLower(input.Query), newAppname) {
			input.Query = fmt.Sprintf("%s - Use the app %s", input.Query, newAppname)
		}
	}

	var err error
	thread := openai.Thread{}
	if len(input.ThreadId) == 0 {
		for {
			if cnt >= 5 {
				log.Printf("[ERROR] Failed to match Formatting in runActionAI after 5 tries (5)")

				return "Timed out during thread creation. Please try again.", input.ThreadId, input.RunId, true
			}

			thread, err = openaiClient.CreateThread(
				context.Background(),
				openai.ThreadRequest{
					Messages: []openai.ThreadMessage{
						{
							Role:    openai.ThreadMessageRoleUser,
							Content: input.Query,
						},
					},
				},
			)

			if err != nil {
				if strings.Contains(fmt.Sprintf("%s", err), "400") {
					log.Printf("[ERROR] Failed to create thread (1): %s", err)
					return "Failed to make thread: " + err.Error(), input.ThreadId, input.RunId, true
				}

				log.Printf("[ERROR] Failed to create thread (1): %s", err)
				time.Sleep(3 * time.Second)
				cnt += 1
				continue
			}

			//log.Printf("[DEBUG] OpenAI response: %s", thread)
			break
		}
	} else {
		thread.ID = input.ThreadId

		// We only get here when there's a followup.
		if len(input.ThreadId) > 0 && len(input.RunId) > 0 {
			// 1. Add the latest thing they wrote to the thread
			// 2. Run it!
			_, err := openaiClient.CreateMessage(ctx, thread.ID, openai.MessageRequest{
				Role:    "user",
				Content: input.Query,
			})

			if err != nil {
				if strings.Contains(err.Error(), "while a run") && strings.Contains(err.Error(), "is active") {
					log.Printf("[DEBUG] Run is active. Waiting for it to finish. Run: %s", input.RunId)

					if len(input.RunId) == 0 {
						errorSplit := strings.Split(err.Error(), "while a run ")
						if len(errorSplit) == 2 {
							runSplit2 := strings.Split(errorSplit[1], " is active")
							if len(runSplit2) == 2 {
								input.RunId = runSplit2[0]
							}
						}
					}
				}

				log.Printf("[ERROR] Failed to add message to thread: %s. If a run exists, this will try to continue the run anyway.", err)
				if len(input.RunId) == 0 {
					return "Failed to add message to thread. Please refresh and start over. Contact support@shuffler.io if this persists. Details: " + err.Error(), input.ThreadId, input.RunId, true
				}
			}

			// FIXME: Should we reset the run so that it runs again?
			input.RunId = ""
		}

	}

	if thread.ID == "" {
		log.Printf("[ERROR] Failed to create thread (2): %s", err)
		return "Failed to make thread: " + err.Error(), input.ThreadId, input.RunId, true
	}

	log.Printf("[DEBUG] Thread ID: %s", thread.ID)
	input.ThreadId = thread.ID

	// FIXME: Does this need tools? As in ALL the functions?
	// Or could we dynamically fill this in for the user based on what labels they have? This is interesting...
	runReply := openai.Run{}
	if len(input.RunId) == 0 {

		//instructions := "Figure out what they want to do based on their input using the available functions. If they ask what you can do, list out the available functions only. Always output valid Markdown. If the status code is not less than 300, make it clear that there was a bug and the user needs to modify it. If you can't find a matching function, use the discover_intent() function and ask if it's ok to run it to find their intent. If you see a workflow ID and execution ID, add a link at the bottom in following format: https://shuffler.io/workflows/{workflow_id}?execution_id={execution_id}"
		//instructions := fmt.Sprintf("If they ask what you can do, list out the available functions only. Always output valid Markdown. If the status code is not less than 300, make it clear that there was a bug and the user needs to modify the workflow. Output simple answers that are to the point with minimal text. If you see a workflow ID and execution ID, add a link at the bottom in following format: https://shuffler.io/workflows/{workflow_id}?execution_id={execution_id}, and don't mention anything about it otherwise. My username is %s and my organization is %s. Any function can get the parameter 'dryrun' even though it is not specified. Dryrun is used if they don't explicitly say to run the workflow.", user.Username, user.ActiveOrg.Name)

		// No dryrun
		instructions := fmt.Sprintf("If they ask what you can do, list out the available functions only. Always output valid Markdown. If the status code is not less than 300, make it clear that there was a bug and the user needs to modify the workflow. Output simple answers that are to the point with minimal text. If you see a workflow ID and execution ID, add a link at the bottom in following format: https://shuffler.io/workflows/{workflow_id}?execution_id={execution_id}, and don't mention anything about it otherwise. My username is %s and my organization is %s", user.Username, user.ActiveOrg.Name)

		runReply, err = openaiClient.CreateRun(ctx, thread.ID, openai.RunRequest{
			AssistantID:  assistantId,
			Model:        assistantModel,
			Instructions: instructions,
		})

		if len(runReply.ID) == 0 {
			log.Printf("[ERROR] Failed to create run: %s", err)
			return "Failed to create run: " + err.Error(), input.ThreadId, input.RunId, true
		}

		log.Printf("[DEBUG] Run ID: %#v", runReply.ID)

		if err != nil {
			log.Printf("[ERROR] Failed to create run (trying to autorecover): %s", err)
			if !strings.Contains(err.Error(), "already has an active") {
				return "Failed to create run. Please try again. Details: " + err.Error(), input.ThreadId, input.RunId, true
			}

			if len(input.RunId) == 0 {
				// Find it in the error message at the end
				errorSplit := strings.Split(err.Error(), "has an active run ")
				if len(errorSplit) == 2 {
					runReply.ID = errorSplit[1]
					if strings.HasSuffix(runReply.ID, ".") {
						runReply.ID = runReply.ID[:len(runReply.ID)-1]
					}
				}
			}
		}

		if len(runReply.ID) > 0 {
			input.RunId = runReply.ID
		}

		if len(input.RunId) == 0 {
			log.Printf("[ERROR] Failed to create or find run: %s", err)
			return "Failed to create run (2): " + err.Error(), input.ThreadId, input.RunId, true
		}
	}

	timeoutCnt := 0
	runSent := false

	// The data to return after the run is complete
	returnData := ""
	alreadySent := []string{}
	appAuthResults := []openai.ToolOutput{}
	for {
		timeoutCnt += 1

		runReply, err = openaiClient.RetrieveRun(ctx, input.ThreadId, input.RunId)
		if err != nil {
			log.Printf("[ERROR] Failed to retrieve run: %s", err)
			return "Failed to retrieve run. Please try again: " + err.Error(), input.ThreadId, input.RunId, true
		}

		// The current status of the fine-tuning job, which can be either validating_files, queued, running, succeeded, failed, or cancelled.
		if runReply.Status == "failed" {
			log.Printf("\n\n[ERROR] Run with thread %s and run %s failed unexpectedly.\n\n", input.ThreadId, input.RunId)
			return "Automation workflow builder failed unexpectedly. Please try again.", input.ThreadId, input.RunId, true
		} else if runReply.Status == "requires_action" {
			//log.Printf("[DEBUG] Run requires action. Time to run action AI.")

			// FIXME: Check if it's multiprocess or steps
			// steps: "get me a ticket and send it as an email"
			// multi: "send me 2 emails with this data"

			// Right now just doing 1 worker = steps

			// Create a wait group to wait for all workers to finish
			// in case there are more jobs than one
			numWorkers := 1
			if len(runReply.RequiredAction.SubmitToolOutputs.ToolCalls) < numWorkers {
				numWorkers = len(runReply.RequiredAction.SubmitToolOutputs.ToolCalls)
			}

			var wg sync.WaitGroup
			jobs := make(chan openai.ToolCall, len(runReply.RequiredAction.SubmitToolOutputs.ToolCalls))
			results := make(chan AtomicOutput, len(runReply.RequiredAction.SubmitToolOutputs.ToolCalls))

			// Start the workers
			finished := false
			for i := 0; i < numWorkers; i++ {
				wg.Add(1)
				go workerPool(jobs, results, &wg, user, input)
			}

			go func() {
				for _, toolCall := range runReply.RequiredAction.SubmitToolOutputs.ToolCalls {
					jobs <- toolCall
				}
				close(jobs)
			}()

			go func() {
				wg.Wait()
				close(results)
			}()

			validationRan := false
			output := openai.SubmitToolOutputsRequest{}
			for result := range results {
				if !result.Success {
					//log.Printf("\n\n[DEBUG] Failed ToolOutput automation. Data of length %d\n\n", len(result.Reason))
					var structuredAction StructuredCategoryAction
					err := json.Unmarshal([]byte(result.Reason), &structuredAction)
					if err != nil {
						log.Printf("[ERROR] Failed to unmarshal structured action (1). This may happen if it's not structured. RAW: %#v: %s", result.Reason, err)
					} else {
						log.Printf("[DEBUG] Failed action is: %#v", structuredAction.Action)

						if len(input.ThreadId) > 0 {
							structuredAction.ThreadId = input.ThreadId
						}

						if len(input.RunId) > 0 {
							structuredAction.RunId = input.RunId
						}

						returnData = result.Reason
					}

					if structuredAction.Action == "app_authentication" || structuredAction.Action == "discover_app" {
						log.Printf("[DEBUG] APPAUTH RESULTS: %d. Returndata: %d", len(appAuthResults), len(returnData))
						if len(structuredAction.AvailableLabels) > 0 && !validationRan {
							validationRan = true

							// Runs a label validity check & updates the assistant if needed
							go ValidateLabelAvailability(structuredAction.Category, structuredAction.AvailableLabels)
						}

						// To not use too many tokens
						//result.Reason = "Authentication required."
						appAuthResults = append(appAuthResults, openai.ToolOutput{
							ToolCallID: result.ToolCallID,
							Output:     result.Reason,
						})
						continue
					}
				}

				maxAmount := 5000
				if len(result.Reason) > maxAmount {
					log.Printf("[DEBUG] Truncating output from API to %d characters. Original: %d", maxAmount, len(result.Reason))
					result.Reason = result.Reason[:maxAmount]
				}

				output.ToolOutputs = append(output.ToolOutputs, openai.ToolOutput{
					ToolCallID: result.ToolCallID,
					Output:     result.Reason,
				})
			}

			// Should INTERPRET if there is more than one
			// If there is just one, it should send back to help with auth
			//log.Printf("\n\n\n\nAPPAUTHLENGET: %d\n\n\n", len(appAuthResults))
			if len(appAuthResults) == 1 {
				if !ArrayContains(alreadySent, appAuthResults[0].ToolCallID) {
					alreadySent = append(alreadySent, appAuthResults[0].ToolCallID)
					//appAuthResults[0].Output = "Authentication required."
					copiedAppauth := appAuthResults[0]
					copiedAppauth.Output = "Authentication or handling of labels"
					output.ToolOutputs = append(output.ToolOutputs, copiedAppauth)
				}
			} else if len(appAuthResults) > 1 {
				// FIXME: If in here, answering the query is more important.
				// So instead of just sending back labels and such, we actually try to answer (by setting returnData to nothing)
				log.Printf("[DEBUG] Multiple app auth results handler. Sending back to user.")

				additionalContext := ""
				for _, appAuthResult := range appAuthResults {
					var structuredAction StructuredCategoryAction

					tmpOutput, assertionSuccess := appAuthResult.Output.(string)
					if !assertionSuccess {
						// Handle the case where the assertion fails
						log.Printf("[ERROR] Failed to assert appAuthResult.Output to []byte. This may happen if it's not structured. RAW: %#v", appAuthResult.Output)
					}

					if ArrayContains(alreadySent, appAuthResult.ToolCallID) {
						log.Printf("[DEBUG] Skipping send of %s because it was already sent.", appAuthResult.ToolCallID)
						if !assertionSuccess {
							continue
						}

						// Check if it has AvailableLabels inside of it and add them to the validation

						err := json.Unmarshal([]byte(tmpOutput), &structuredAction)
						if err != nil {
							log.Printf("[ERROR] Failed to unmarshal structured action (2). This may happen if it's not structured. RAW: %#v: %s", appAuthResult.Output, err)
							continue
						}

						if len(input.ThreadId) > 0 {
							structuredAction.ThreadId = input.ThreadId
						}

						if len(input.RunId) > 0 {
							structuredAction.RunId = input.RunId
						}

						if len(structuredAction.AvailableLabels) > 0 && len(structuredAction.Apps) > 0 {
							additionalContext += fmt.Sprintf("Available actions for %s: \n", strings.ReplaceAll(structuredAction.Apps[0].Name, "_", " "))
							for _, label := range structuredAction.AvailableLabels {
								additionalContext += fmt.Sprintf("- %s\n", label)
							}
						} else {
							log.Printf("[DEBUG] No app or no available labels found in %s", appAuthResult.ToolCallID)
						}

						continue
					}

					err := json.Unmarshal([]byte(tmpOutput), &structuredAction)
					if err != nil {
						log.Printf("[ERROR] Failed to unmarshal structured action (3). This may happen if it's not structured. RAW: %#v: %s", appAuthResult.Output, err)
						continue
					}

					alreadySent = append(alreadySent, appAuthResult.ToolCallID)
					newOutput := ""
					log.Printf("[DEBUG] Labels: %d, apps: %d", len(structuredAction.AvailableLabels), len(structuredAction.Apps))
					if len(structuredAction.AvailableLabels) > 0 && len(structuredAction.Apps) > 0 {
						newOutput = fmt.Sprintf("Disregard previous outputs. Authentication is done, so don't mention it. Use the following actions and try to make usecases connecting the different ones from each app. Focus on moving data through all mentioned systems, from a source to a destination. Show a maximum of 2 usecases, and disregard similar ones. Available triggers: \n- Schedule\n\nAvailable actions for %s: \n", strings.ReplaceAll(structuredAction.Apps[0].Name, "_", " "))

						for _, label := range structuredAction.AvailableLabels {
							newOutput += fmt.Sprintf("- %s\n", label)
						}

						newOutput += "\n\n"
						newOutput += additionalContext
					}

					log.Printf("[DEBUG] New output: %#v. ASSERTION: %t", newOutput, assertionSuccess)
					if len(newOutput) == 0 || !assertionSuccess {
						output.ToolOutputs = append(output.ToolOutputs, appAuthResult)
					} else {
						output.ToolOutputs = append(output.ToolOutputs, openai.ToolOutput{
							ToolCallID: appAuthResult.ToolCallID,
							Output:     newOutput,
						})

					}
				}

				// Resetting to make sure interpreter gets used, not skipped
				returnData = ""
			}

			finished = true
			if len(output.ToolOutputs) > 0 {
				finished = true
				log.Printf("\n\n[DEBUG] Sending %d tool outputs to OpenAI", len(output.ToolOutputs))
				updatedRun, err := openaiClient.SubmitToolOutputs(ctx, input.ThreadId, input.RunId, output)
				if err != nil {
					log.Printf("\n\n\n[ERROR] Failed to submit tool output: %s\n\n\n", err)
					break
				}

				log.Printf("[DEBUG] Updated Run successfully with a response. New Run ID: %s", updatedRun.ID)

				// Resetting so that it can wait for a response again
				timeoutCnt = 0
				finished = false
				runSent = true

				// This continue makes it so it can do multiple in a row
				continue
			}

			if finished {
				break
			}

		} else if runReply.Status == "completed" {
			log.Printf("[DEBUG] Run completed. Time to verify messages.")
			break
		} else if runReply.Status == "queued" {
			log.Printf("[DEBUG] Queued")
		} else if runReply.Status == "in_progress" {
			log.Printf("[DEBUG] In progress")
		} else {
			log.Printf("\n[ERROR] Unhandled status in run %s: %s\n", input.RunId, runReply.Status)
		}

		if timeoutCnt > 120 {

			log.Printf("[ERROR] Failed to match Formatting in runActionAI after 5 tries (6)")
			return "Timed out while waiting for the LLM (2 min max). Please try again.", input.ThreadId, input.RunId, true
		}

		// Polling every 1 second to make it faster
		time.Sleep(1 * time.Second)
	}

	if len(returnData) > 0 && len(appAuthResults) < 2 {
		log.Printf("[DEBUG] Got some returndata to fix things instead of assistant response")

		var structuredAction StructuredCategoryAction
		err := json.Unmarshal([]byte(returnData), &structuredAction)
		if err == nil {
			log.Printf("[DEBUG] Got structured action. Thread ID: %s, Run ID: %s", input.ThreadId, input.RunId)

			structuredAction.ThreadId = input.ThreadId
			structuredAction.RunId = input.RunId

			returnData2, err := json.Marshal(structuredAction)
			if err != nil {
				log.Printf("[ERROR] Failed to marshal structured action: %s", err)
			} else {
				returnData = string(returnData2)
			}
		}

		return returnData, input.ThreadId, input.RunId, false
	}

	_ = runSent
	log.Printf("[DEBUG] Got run ID: %s. Status: %s", runReply.ID, runReply.Status)

	//messages, err := openaiClient.ListMessage(ctx, thread.ID, nil, nil, nil, nil)
	limit := 50
	order := ""
	after := ""
	before := ""
	runID := ""
	messages, err := openaiClient.ListMessage(ctx, thread.ID, &limit, &order, &after, &before, &runID)
	if err != nil {
		log.Printf("[ERROR] Failed to list messages: %s", err)
		return "Problem getting messages for your thread. Please reload. Details:: " + err.Error(), input.ThreadId, input.RunId, true
	}

	// List is reversed (newest first)
	lastAssistant := ""
	for _, message := range messages.Messages {
		if len(message.Content) == 0 {
			log.Printf("[DEBUG] Skipping empty message with ID: %s", message.ID)
			continue
		}

		//log.Printf("[DEBUG] Role: %s, Message: '%s'", message.Role, message.Content[0].Text.Value)
		if message.Role == "assistant" && len(lastAssistant) == 0 {
			//log.Printf("[DEBUG] Assistant message: %s", message.Content[0].Text.Value)
			lastAssistant = message.Content[0].Text.Value
		}
	}

	log.Printf("[DEBUG] Return assistant message: %s", lastAssistant)
	log.Printf("\n\n")

	// Start getting the thread itself
	return lastAssistant, input.ThreadId, input.RunId, true
}

func GetAtomicSuggestionAIResponse(ctx context.Context, resp http.ResponseWriter, user User, org Org, outputFormat string, input QueryInput) {
	log.Printf("[INFO] Getting support suggestion for query: %s", input.Query)

	reply, threadId, runId, sendResp := runAtomicChatRequest(ctx, user, input)
	if !sendResp {
		resp.WriteHeader(400)
		resp.Write([]byte(reply))
		//log.Printf("[DEBUG] Returning default response defined by atomic chat")
		return
	}

	if len(reply) == 0 {
		resp.WriteHeader(501)
		resp.Write([]byte(`{"success": false, "reason": "Failed to get atomic response"}`))
		return
	}

	newResponse := AtomicOutput{
		Success:  true,
		ThreadId: threadId,
		RunId:    runId,
		Reason:   reply,
	}

	// Marshal it
	output, err := json.Marshal(newResponse)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal response: %s", err)
		resp.WriteHeader(501)
		resp.Write([]byte(`{"success": false, "reason": "Failed to marshal response"}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(output)
}

// 1. Return list of top apps matching the category if no apps match
// 2. Make sure it actually runs the thing. Use this: api/v1/apps/categories/run
// 3. Make it translate the input fields to the correct JSON format
// 4. Make sure it handles auth
// 5. Find apps based on Algolia
// 5. Make sure bodies are filled in correctly
// 6. Run without category/label and directly find app + action
// 7. Auto-label actions based on available labels & action name
// 8. Get documentation from doc URL, scrape & auto-input for each action
// 9. Get context awareness of what to do: workflow (create,modify), app (run,return, add to workflow)...
// 10. Continuing with context: Understand if they want to use ANY of the Shuffle API's, e.g. for listing apps, workflows, auth etc. "What actions does the x app have?" "how many?"
// 11. e.g. for JIRA: Add a way to understand if we need more context. Sample: If we get a response that the project ID is wrong, look for an API to list projects (solve the problem), then: either ask the user which one, or just choose one.
// 12. Add vector db and save for individual users
// 13. Add synonyms for words. e.g. for cases: alert = incident = case = issue = ticket, search = find = query, ...
// 14. Go check App's documentation for answers if we don't have the right info directly
// 15. how many clicks did our website have last week
// 16. Oauth2 autorefresh on single-actions
// 17. Make it work without action label (1) & category (2), and do auto-tagging if it's correct
// 18. Check for continuity. e.g. for an gmail, listing mails isn't always enough, but and requires further searching into the contents
func runActionAI(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Failed to read body in runActionAI: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Input body is not valid JSON"}`))
		return
	}

	var input QueryInput
	err = json.Unmarshal(body, &input)
	if err != nil {
		log.Printf("[WARNING] Failed to unmarshal input in runActionAI: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Input data invalid"}`))
		return
	}

	if len(input.Query) < 8 && len(input.ThreadId) == 0 {
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Please be more specific and write full sentences for what you want to automate."}`))
		return
	}

	// Indicates to output an action, and the input data could be a large blob
	if len(input.Query) > 300 && !strings.Contains(input.OutputFormat, "action") && !strings.Contains(input.OutputFormat, "formatting") {
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Max input length exceeded."}`))
		return
	}

	if len(input.Query) > 5000 {
		log.Printf("[WARNING] Truncated input query from %d to %d characters for user %s (%s) in org %s", len(input.Query), 5000, input.UserId, input.Username, input.OrgId)
		input.Query = input.Query[:5000]
	}

	ctx := GetContext(request)
	user, err := HandleApiAuthentication(resp, request)

	if err != nil {
		//log.Printf("[INFO] Api authentication failed in runActionAI: %s", err)
		// Look for execution_id & authorization in queries
		executionId := request.URL.Query().Get("execution_id")
		authorization := request.URL.Query().Get("authorization")

		authReturnOrg := ""
		if len(executionId) > 0 && len(authorization) > 0 {
			exec, err := GetWorkflowExecution(ctx, executionId)
			if err != nil {
				log.Printf("[AUDIT] Error getting execution in ai auth: %s", err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "You need to log in first (execution)", "action": "login"}`))
				return
			}

			if exec.Authorization != authorization {
				log.Printf("[AUDIT] Error mapping exec.Auth to authorization in ai auth")
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "You need to log in first (execution - 2)", "action": "login"}`))
				return
			}

			authReturnOrg = exec.Workflow.OrgId

			log.Printf("[AUDIT] AI Execution auth success for org %s", authReturnOrg)
		} else {
			// Check if a sync key has the same one
			authReturn := SyncKey{}
			if project.Environment == "cloud" { 
				authReturn, err := HandleCloudSyncAuthentication(resp, request)
				if err != nil || authReturn.OrgId == "" {
					log.Printf("[AUDIT] Error in AI inference - missing api key (2): %s", err)
					resp.WriteHeader(401)
					resp.Write([]byte(`{"success": false, "reason": "You need to log in first (cloud sync)", "action": "login"}`))
					return
				}
			} else {
				log.Printf("[AUDIT] ONPREM: Error in AI inference - missing api key (3): %s", err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "You need to log in first (api key)", "action": "login"}`))
				return
			}

			authReturnOrg = authReturn.OrgId
		}

		// Get org for authReturn.OrgId
		org, err := GetOrg(ctx, authReturnOrg)
		if err != nil {
			log.Printf("[AUDIT] Error getting org in auth: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "You need to log in first (org)", "action": "login"}`))
			return
		}

		for _, inneruser := range org.Users {
			if inneruser.Role == "admin" {
				user = inneruser
				break
			}
		}

		user.ActiveOrg.Id = org.Id
		user.ActiveOrg.Name = org.Name
	}

	userAgent := request.Header.Get("User-Agent")
	if strings.Contains(userAgent, "openai") {

		ephemeralUser := request.Header.Get("Openai-Ephemeral-User-Id")
		if len(ephemeralUser) > 0 {
			log.Printf("Finding/Creating OPENAI EPHEMERAL USER: %s", ephemeralUser)

			// Check if the user exists
			// If not, create a new one
			newUser, err := GetUser(ctx, ephemeralUser)
			if err != nil || newUser.Id == "" {
				log.Printf("[INFO] Failed to get OpenAI user in runActionAI: %s", err)

				apikey := uuid.NewV4().String()
				newUser = &User{
					Id:       ephemeralUser,
					Username: fmt.Sprintf("OpenAI User"),
					ActiveOrg: OrgMini{
						Id:   ephemeralUser,
						Name: fmt.Sprintf("OpenAI - %s", ephemeralUser),
					},
					Orgs: []string{ephemeralUser},

					Role:   "admin",
					ApiKey: apikey,
				}

				newOrg := Org{
					Id:   ephemeralUser,
					Name: fmt.Sprintf("OpenAI Org"),
					Users: []User{
						{
							Id:       newUser.Id,
							Username: newUser.Username,
							Role:     "admin",
						},
					},
				}

				err = SetOrg(ctx, newOrg, newOrg.Id)
				if err != nil {
					log.Printf("[INFO] Failed to set OpenAI org in runActionAI: %s", err)
					resp.WriteHeader(500)
					resp.Write([]byte(`{"success": false, "reason": "Failed to create your user org. Please try again"}`))
					return
				}

				resp.Header().Set("Authorization", fmt.Sprintf("Bearer %s", apikey))
				resp.Header().Set("Org-Id", fmt.Sprintf("%s", newOrg.Id))

				err = SetUser(ctx, newUser, false)
				if err != nil {
					log.Printf("[INFO] Failed to set OpenAI user in runActionAI: %s", err)
					resp.WriteHeader(500)
					resp.Write([]byte(`{"success": false, "reason": "Failed to find your user. Please try again"}`))
					return
				}

				//resp.WriteHeader(400)
				//resp.Write([]byte(`{"success": false, "reason": "Failed to find your user. Please try again"}`))
				//return
			}

			log.Printf("[INFO] Found OpenAI user %s (%s) in org %s (%s)", newUser.Username, newUser.Id, newUser.ActiveOrg.Name, newUser.ActiveOrg.Id)
			user = *newUser

		} else {
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "No user ID found. Please try again."}`))
			return
		}
	}

	log.Printf("[INFO] Running AI query of length %s for user %s in org %s (%s)", strconv.Itoa(len(input.Query)), user.Username, user.ActiveOrg.Name, user.ActiveOrg.Id)
	IncrementCache(ctx, user.ActiveOrg.Id, "ai_executions")

	if len(input.Query) < 100 {
		log.Printf("[DEBUG] Query from user %s (%s): '%s'", user.Username, user.Id, input.Query)
	} else {
		log.Printf("[DEBUG] Query from user %s (%s) of length '%d'", user.Username, user.Id, len(input.Query))
	}

	if len(input.AppId) == 0 {
		go GetPrioritizedApps(ctx, user)
	}

	org, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[INFO] Failed to get org in runActionAI: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed find your organization. Please try again"}`))
		return
	}

	// Preloading to put in cache to make later steps faster

	// The type of response to send
	outputFormats := []string{
		"action",            // If you're looking for an action to put in a workflow. Also used by /api/v1/categories/run to autocomplete an app
		"action_parameters", // To autofill parameters for an action
		"action_tested",     // Not implemented. If you want it to run first to validate if it works
		"formatting",        // If you want it formatted
		"raw",               // Default - includes questions to be answered

		// Tests
		"workflow_suggestion", // For workflow suggestions (input -> how to build a workflow
		"support",             // For support questions
		"automic",             // For testing atomic functions with OpenAI
	}

	// "workflow",
	// "shuffle-python",
	outputFormat := "raw"
	if len(input.OutputFormat) > 0 && ArrayContains(outputFormats, outputFormat) {
		//log.Printf("[DEBUG] Output format: %s", input.OutputFormat)
		outputFormat = input.OutputFormat
	} else {
		outputFormat = "raw"
	}

	// The type of input to use to understand what to do
	contexts := []string{
		"external API",
		"shuffle API", // Shuffle keywords = Workflows, Apps
		"plaintext question",
	}

	_ = contexts

	// Remove items that they haven't added to app categories
	// Translate synonyms like tickets = cases...
	//parseCategories += fmt.Sprintf("\n\nInput: %s", input.Query)

	if len(input.Id) == 0 {
		input.Id = uuid.NewV4().String()
	}

	input.Username = user.Username
	input.UserId = user.Id
	input.OrgId = org.Id
	input.TimeStarted = time.Now().Unix()

	err = SetConversation(ctx, input)
	if err != nil {
		log.Printf("[WARNING] Failed to set conversation for query %s (1): %s", input.Query, err)
	}

	if outputFormat == "formatting" {
		log.Printf("[INFO] Formatting query: %s. Should be formatted with the following info: %s", input.Query, input.Formatting)

		response := getFormattingAIResponse(ctx, input)
		resp.Write([]byte(response))
		return
	} else if outputFormat == "workflow_suggestion" {
		getWorkflowSuggestionAIResponse(ctx, resp, user, *org, outputFormat, input)
	} else if outputFormat == "support" {
		getSupportSuggestionAIResponse(ctx, resp, user, *org, outputFormat, input)
	} else if outputFormat == "atomic" {
		GetAtomicSuggestionAIResponse(ctx, resp, user, *org, outputFormat, input)
	} else {
		GetActionAIResponse(ctx, resp, user, *org, outputFormat, input)
	}

	input.TimeEnded = time.Now().Unix()
	err = SetConversation(ctx, input)
	if err != nil {
		log.Printf("[WARNING] Failed to set conversation for query %s (2): %s", input.Query, err)
	}
}

func getFormattingAIResponse(ctx context.Context, input QueryInput) string {
	if len(input.Formatting) < 15 {
		return fmt.Sprintf(`{"success": false, "reason": "Formatting is too short. Please try again and be as descriptive as possible"}`)
	}

	contentOutput, err := RunAiQuery(input.Formatting, input.Query)
	if err != nil {
		log.Printf("[ERROR] Failed to run AI query in getFormattingAIResponse: %s", err)
		return ""
	}

	if strings.Contains(contentOutput, "success\": false") {
		log.Printf("[ERROR] Failed to run AI query in getFormattingAIResponse (2): %s", err)
		return ""
	}

	return contentOutput
}

func getWorkflowSuggestionAIResponse(ctx context.Context, resp http.ResponseWriter, user User, org Org, outputFormat string, input QueryInput) {
	log.Printf("[INFO] Getting workflow suggestion for query: %s", input.Query)

	reply := getWorkflowSuggestionAiResponse(ctx, input)
	if len(reply) == 0 {
		resp.WriteHeader(501)
		resp.Write([]byte(`{"success": false, "reason": "Failed to get workflow suggest response"}`))
		return
	}

	newResponse := AtomicOutput{
		Success: true,
		Reason:  reply,
	}

	// Marshal it
	output, err := json.Marshal(newResponse)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal response: %s", err)
		resp.WriteHeader(501)
		resp.Write([]byte(`{"success": false, "reason": "Failed to marshal response"}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(output)
}

// Todo:
func getSupportSuggestionAIResponse(ctx context.Context, resp http.ResponseWriter, user User, org Org, outputFormat string, input QueryInput) {
	log.Printf("[INFO] Getting support suggestion for query: %s", input.Query)

	reply := runSupportRequest(ctx, input)
	if len(reply) == 0 {
		resp.WriteHeader(501)
		resp.Write([]byte(`{"success": false, "reason": "Failed to get support response"}`))
		return
	}

	newResponse := AtomicOutput{
		Success: true,
		Reason:  reply,
	}

	// Marshal it
	output, err := json.Marshal(newResponse)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal response: %s", err)
		resp.WriteHeader(501)
		resp.Write([]byte(`{"success": false, "reason": "Failed to marshal response"}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(output)
}

func getWorkflowSuggestionAiResponse(ctx context.Context, input QueryInput) string {
	systemMessage := `Your job is to convert user input of a technical task into output of smaller, executable, and standalone technical tasks that can be executed by a computer based on one restriction. The one restriction is that all tasks will be executed using API-requests or Apps-actions. Thus, the output tasks should be either API-request based or App-actions based. Make sure that output tasks are specific in terms of what they do, and also generic in terms of how they do it.

For the App-action based tasks, every action falls under a category of actions. The categories and their actions that you have access to are listed below. Remember you only consider the steps that can be performed from predetermined actions and mention those actions. Remember anything that cannot be done by App-action based task is an API-request based task.

Predetermined actions for App-action based tasks:

communication category:
communication:list_messages
communication:send_message
communication:get_message
communication:search_messages
communication:list_attachments
communication:get_attachment
communication:get_contact

siem category:
siem:search
siem:list_alerts
siem:close_alert
siem:get_alert
siem:create_detection
siem:add_to_lookup_list
siem:isolate_endpoint

eradication category:
eradication:list_alerts
eradication:close_alert
eradication:get_alert
eradication:create_detection
eradication:block_hash
eradication:search_hosts
eradication:isolate_host
eradication:unisolate_host
eradication:trigger_host_scan

cases category:
cases:list_tickets
cases:get_ticket
cases:create_ticket
cases:close_ticket
cases:add_comment
cases:update_ticket
cases:search_tickets

assets category:
assets:list_assets
assets:get_asset
assets:search_assets
assets:search_users
assets:search_endpoints
assets:search_vulnerabilities

intel category:
intel:get_ioc
intel:search_ioc
intel:create_ioc
intel:update_ioc
intel:delete_ioc

iam category:
iam:reset_password
iam:enable_user
iam:disable_user
iam:get_identity
iam:get_asset
iam:search_identity

network category:
network:get_rules
network:allow_ip
network:block_ip

other category:
other:update_info
other:get_info
other:get_status
other:get_version
other:get_health
other:get_config
other:get_configs
other:get_configs_by_type
other:get_configs_by_name
other:run_script

Make sure that the output is short and crisp, in bullet points, specifies the type (API-request or App-action based), and gives small description of the task. Ignore Formatting.`

	contentOutput, err := RunAiQuery(systemMessage, input.Query) 
	if err != nil {
		log.Printf("[ERROR] Failed to run AI query in getWorkflowSuggestionAiResponse: %s", err)
		return ""
	}

	return contentOutput
}

/*
- Works (single):
search for the last email from anna in the last week and show it to me
Make a case in jira that says hello from fredrik
Send a message to jim on discord that says youre stupid why did you do this??
How many tickets did we get in the last week in jira?
lag en ticket i jira som sier hallo paa du
what was my last email from frikky?
how many tickets do we have in drift?

- Not working (single):
is the ip 1.2.3.4 in our threat intel?
how many clicks did our website have last week
how many tickets do we have in drift?
send an email to fredrik that says hello (gmail - worked once lol)


- Works (multiple):
TBD

- Not working (multiple):
*/

func runSupportRequest(ctx context.Context, input QueryInput) string {
	chatModel := os.Getenv("OPENAI_SUPPORT_MODEL")
	if len(chatModel) == 0 {
		chatModel = "ft:gpt-3.5-turbo-0613:shuffle::80d8lt3J"
	}


	sysMessage := "Introduce yourself as a support bot. Answer in less than 300 characters. Technical answers are best, with links. Make it clear that you are a bot, and that your answers are based on our documentation. If you don't have a good answer, say that you will find a human. If urls are in markdown format, make it easy to read. Focus most on the LAST question!! NEVER show a domain other than shuffler."

	contentOutput, err := RunAiQuery(sysMessage, input.Query)
	if err != nil {
		log.Printf("[ERROR] Failed to run AI query in runActionAI: %s", err)
		return contentOutput
	}

	return contentOutput
}

func HandleAiAgentExecutionStart(execution WorkflowExecution, startNode Action) (Action, error) {
	log.Printf("\n\nAI AGENT REWRITE (first request?). PARAMS: %d\n\n", len(startNode.Parameters))

	//openai "github.com/sashabaranov/go-openai"
	// Create the OpenAI body struct
	systemMessage := `You are a general AI agent. You can make decisions based on the user input. You should output a list of decisions based on the input. Available actions  within categories you can choose from: ask: ask for human help. singul: `
	userMessage := ""

	openaiAllowedApps := []string{"openai", "grok"}
	runOpenaiRequest := false
	appname := ""

	memorizationEngine := "shuffle_db"
	for _, param := range startNode.Parameters {
		if param.Name == "app_name" {
			appname = param.Value
			if ArrayContains(openaiAllowedApps, strings.ToLower(param.Value)) {
				runOpenaiRequest = true
			}
		}

		if param.Name == "input" {
			userMessage = param.Value
		}

		if param.Name == "action" {
			for _, actionStr := range strings.Split(param.Value, ",") {
				actionStr = strings.ToLower(strings.TrimSpace(actionStr))
				if actionStr == "nothing" {
					continue
				}

				systemMessage += fmt.Sprintf(", %s", strings.ReplaceAll(actionStr, " " , "_"))

			}
		}

		if param.Name == "memory" {
			// Handle memory injection (may use Singul?)
		}

		if param.Name == "storage" {
			// Handle storage injection (how?)
		}
	}

	// If the fields are edited, don't forget to edit the AgentDecision struct 
	// FIXME: Using a different reference format as these are common to reasoning models
	// such as: 
	// Prompt engineering (LangChain, LlamaIndex)
	// Web templating (Jinja2 in Flask/Django)
	// Frontend frameworks (Handlebars)

	// Will just have to make a translation system.
	//typeOptions := []string{"ask", "singul", "workflow", "agent"}
	typeOptions := []string{"ask", "singul"}
	systemMessage += fmt.Sprintf(`. Available categories (default: singul): %s. If you are unsure about a decision, always ask for user input. The output should be an ordered JSON list in the format [{"i": 0, "category": "singul", "action": "action_name", "tool": "appname", "confidence": 0.95, "runs": "1", "reason": "Short reason why", "fields": [{"key": "max_results", "value": "5"}, {"key": "body", "value": "$action_name"}] WITHOUT newlines. Indexes should be the same if they should run in parallell. The confidence is between 0 and 1. Runs are how many times it should run requests (default: 1, * for all looped items). Fields can be set manually, or use previous action output by adding them in the format {{action_name}}, such as {"key": "body": "value": "{{tickets[0].fieldname}}} to get the first ticket output from a previous decision. The {{action_name}} has to match EXACTLY the action name of a previous decision.`, strings.Join(typeOptions, ", "))

	systemMessage += `If you are missing information (such as emails) to make a list of decisions, just add a single decision which asks them to clarify the input better.`

	//contentOutput, err := RunAiQuery(systemMessage, userMessage)

	completionRequest := openai.ChatCompletionRequest{
		//Model: "gpt-4o-mini",
		//Model: "gpt-4o",
		Model: "o4-mini",
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleSystem,
				Content: systemMessage,
			},
			{
				Role:    openai.ChatMessageRoleUser,
				Content: userMessage,
			},
		},
		//Temperature: 0.95, // Adds a tiny bit of randomness
		Temperature: 1,

		// Reasoning control
		MaxCompletionTokens: 5000, 
		ResponseFormat: &openai.ChatCompletionResponseFormat{
			Type: "json_object",
		},
		ReasoningEffort: "low",
		Store: true,
	}

	ctx := context.Background()
	initialAgentRequestBody, err := json.MarshalIndent(completionRequest, "", "  ")
	if err != nil {
		log.Printf("[ERROR][%s] Failed marshalling input for action %s: %s", execution.ExecutionId, startNode.ID, err)

		execution.Status = "ABORTED"
		execution.Results = append(execution.Results, ActionResult{
			Status: "ABORTED",
			Result: fmt.Sprintf(`{"success": false, "reason": "Failed to start AI Agent (4): %s"}`, err),
			Action: startNode,
		})
		go SetWorkflowExecution(ctx, execution, true)

		return startNode, err
	}

	//go executeSpecificCloudApp(ctx, execution.ExecutionId, execution.Authorization, urls, startNode)
	if !runOpenaiRequest {

		log.Printf("[ERROR] Unhandled Singul BODY for OpenAI agent (first request): %s. AI APPNAME (can't be empty): %#v", string(initialAgentRequestBody), appname)

		execution.Status = "ABORTED"
		execution.Results = append(execution.Results, ActionResult{
			Status: "ABORTED",
			Result: fmt.Sprintf(`{"success": false, "reason": "Failed to start AI Agent (5): %s"}`, err),
			Action: startNode,
		})
		go SetWorkflowExecution(ctx, execution, true)

		return startNode, errors.New("Unhandled Singul BODY for OpenAI agent (first request)")
	}
	//log.Printf("\n\n\n[DEBUG] BODY for AI Agent (first request): %s\n\n\n", string(initialAgentRequestBody))

	// Hardcoded for now
	aiNode := Action{}
	aiNode.AppID = "5d19dd82517870c68d40cacad9b5ca91"
	aiNode.AppName = "openai"
	aiNode.Name = "post_generate_a_chat_response"

	// FIXME: Resetting auth as it should auto-pick (if possible)
	aiNode.AuthenticationId = ""
	aiNode.Parameters = []WorkflowAppActionParameter{
		WorkflowAppActionParameter{
			Name:  "url",
			Value: "",
		},
		//WorkflowAppActionParameter{
		//	Name:  "apikey",
		//	Value: "",
		//},
		WorkflowAppActionParameter{
			Name:  "body",
			Value: string(initialAgentRequestBody),
		},
		WorkflowAppActionParameter{
			Name:  "headers",
			Value: "Content-Type: application/json\nAccept: application/json",
		},
	}

	// To ensure we get the context of an execution properly
	// This gives it variables to run IN CONTEXT of the current execution,
	// meaning it has access to current variables
	aiNode.SourceWorkflow = execution.Workflow.ID
	aiNode.SourceExecution = execution.ExecutionId

	marshalledAction, err := json.Marshal(aiNode)
	if err != nil {
		log.Printf("[ERROR][%s] Failed marshalling action for AI Agent (first agent request): %s", execution.ExecutionId, err)

		execution.Status = "ABORTED"
		execution.Results = append(execution.Results, ActionResult{
			Status: "ABORTED",
			Result: fmt.Sprintf(`{"success": false, "reason": "Failed to start AI Agent (6): %s"}`, err),
			Action: startNode,
		})
		go SetWorkflowExecution(ctx, execution, true)

		return startNode, err
	}

	// Static URL
	//urls = []string{fmt.Sprintf("https://%s-%s.cloudfunctions.net/openai-5d19dd82517870c68d40cacad9b5ca91", location, gceProject)}

	//http://localhost:5002/api/v1/apps/5d19dd82517870c68d40cacad9b5ca91/run
	//apprunUrl := fmt.Sprintf("%s/api/v1/apps/%s/run?delete=%s", baseUrl, secondAction.AppID, shouldDelete)
	backendUrl := "https://shuffler.io"
	if len(os.Getenv("BASE_URL")) > 0 {
		backendUrl = os.Getenv("BASE_URL")
	}

	if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
		backendUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
	}

	fullUrl := fmt.Sprintf("%s/api/v1/apps/%s/run?execution_id=%s&authorization=%s", backendUrl, aiNode.AppID, execution.ExecutionId, execution.Authorization)
	client := GetExternalClient(fullUrl)
	req, err := http.NewRequest(
		"POST",
		fullUrl,
		bytes.NewBuffer([]byte(marshalledAction)),
	)

	if err != nil {
		log.Printf("[ERROR] Failed creating request during LLM setup: %s", err)


		execution.Status = "ABORTED"
		execution.Results = append(execution.Results, ActionResult{
			Status: "ABORTED",
			Result: fmt.Sprintf(`{"success": false, "reason": "Failed to start AI Agent (7): %s"}`, err),
			Action: startNode,
		})
		go SetWorkflowExecution(ctx, execution, true)

		return startNode, err
	}

	newresp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed sending request during LLM setup: %s", err)

		execution.Status = "ABORTED"
		execution.Results = append(execution.Results, ActionResult{
			Status: "ABORTED",
			Result: fmt.Sprintf(`{"success": false, "reason": "Failed to start AI Agent (8): %s"}`, err),
			Action: startNode,
		})
		go SetWorkflowExecution(ctx, execution, true)

		return startNode, err
	}

	// Set timestamp as soon as it's ready
	// https://pkg.go.dev/github.com/sashabaranov/go-openai#ChatCompletionMessage
	for messageIndex, _ := range completionRequest.Messages {
		if len(completionRequest.Messages[messageIndex].Name) == 0 {
			completionRequest.Messages[messageIndex].Name = string(time.Now().Unix())
		}
	}

	defer newresp.Body.Close()
	body, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading response from sending request for stream during SKIPPED user input: %s", err)

		execution.Status = "ABORTED"
		execution.Results = append(execution.Results, ActionResult{
			Status: "ABORTED",
			Result: fmt.Sprintf(`{"success": false, "reason": "Failed to start AI Agent (9): %s"}`, err),
			Action: startNode,
		})
		go SetWorkflowExecution(ctx, execution, true)

		return startNode, err
	}

	resultMapping := ActionResult{}
	err = json.Unmarshal(body, &resultMapping)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshalling response into decisions. Response from sending AI Agent request: %d - %s", newresp.StatusCode, string(body))
	}

	resultMapping.ExecutionId = execution.ExecutionId
	resultMapping.Authorization = execution.Authorization
	resultMapping.Status = "WAITING"
	resultMapping.Action = startNode
	resultMapping.Action.Name = "agent"


	// This exists for the single reason of tracking errors + parameters 
	// ActionResult{} is the type we are using to build the request, while
	// the LLM request ACTUALLY returns SingleResult{} 
	additionalResultMapping := SingleResult{}
	err = json.Unmarshal(body, &additionalResultMapping)

	parsedAgentInput := ""
	if err == nil {
		// Checking for errors in the Single Action run. 
		// They usually cause notifications to occur as well.
		if len(additionalResultMapping.Errors) > 0 {
			// Handle this.
			//log.Printf("\n\n[ERROR][%s] BODY LEN: %d. Got %d errors from Agent AI subrequest", resultMapping.ExecutionId, len(body), len(additionalResultMapping.Errors))
		}

		if len(additionalResultMapping.Parameters) > 0 {
			// FIXME: Check if the result somehow contains the input we sent in.
			// The reason for this is to ensure we can use the return params (somehow)
			//log.Printf("\n\n[WARNING][%s] BODY LEN: %d. Got %d params from Agent AI subrequest", resultMapping.ExecutionId, len(body), len(additionalResultMapping.Parameters))

			for _, param := range additionalResultMapping.Parameters {
				if param.Name != "body" {
					continue
				}

				log.Printf("[DEBUG][%s] AI Agent: Found body parameter which MAY contain the right user input. LEN: %d", execution.ExecutionId, len(param.Value))

				if len(param.Value) > 0 {
					parsedAgentInput  = param.Value
					break
				}
			}
		}
	}

	// Store the completion request in datastore?
	if len(resultMapping.Result) > 0 {
		// 1. Map it to a Shuffle HTTP Result
		// 2. Find the content: $ai_agent_1.body.choices.#.message.content
		// 3. Map the content into the AgentOutput struct
		//resultMapping.Result = openaiOutput
		outputMap := HTTPOutput{}
		err = json.Unmarshal([]byte(resultMapping.Result), &outputMap)
		if err != nil {
			log.Printf("[ERROR][%s] Failed unmarshalling response from sending request for stream during SKIPPED user input: %s. Body: %s", execution.ExecutionId, err, string(resultMapping.Result))

			execution.Status = "ABORTED"
			execution.Results = append(execution.Results, ActionResult{
				Status: "ABORTED",
				Result: fmt.Sprintf(`{"success": false, "reason": "Failed to start AI Agent (1): %s"}`, err),
				Action: startNode,
			})
			go SetWorkflowExecution(ctx, execution, true)

			return startNode, err
		}

		if outputMap.Status != 200 {
			log.Printf("[ERROR][%s] Failed to run AI agent with status code %d", execution.ExecutionId, outputMap.Status)
			//return startNode, errors.New(fmt.Sprintf("Failed to run AI agent with status code %d", outputMap.Status))
		}

		// Parse the outputMap.Result to OpenAI response
		choicesString := ""
		bodyString := []byte{}
		bodyMap, ok := outputMap.Body.(map[string]interface{})
		if !ok {
			log.Printf("[ERROR][%s] Failed to convert body to MAP in AI Agent response. Raw response: %s", execution.ExecutionId, string(resultMapping.Result))

			choicesString = fmt.Sprintf("LLM Response Error: %s", string(resultMapping.Result))
		} else {
			bodyString, err = json.Marshal(bodyMap)
			if err != nil {
				log.Printf("[ERROR] Failed marshalling body to string in AI Agent response: %s", err)

				execution.Status = "ABORTED"
				execution.Results = append(execution.Results, ActionResult{
					Status: "ABORTED",
					Result: fmt.Sprintf(`{"success": false, "reason": "Failed to start AI Agent (3): %s"}`, err),
					Action: startNode,
				})
				go SetWorkflowExecution(ctx, execution, true)

				return startNode, err
			}
		}

		openaiOutput := openai.ChatCompletionResponse{}
		err = json.Unmarshal(bodyString, &openaiOutput)
		if err != nil {
			log.Printf("[ERROR][%s] Failed unmarshalling response from OpenAI Agent request: %s", execution.ExecutionId, err)
		}

		// Edgecase handling for LLM not being available etc
		if len(choicesString) > 0 { 
		} else if len(openaiOutput.Choices) == 0 {

			// FIXME: This is specific to OpenAI, but may work for others :thinking:
			newOutput := openai.ErrorResponse{}
			err = json.Unmarshal(bodyString, &newOutput)
			if err == nil && len(newOutput.Error.Message) > 0 {
				choicesString = fmt.Sprintf("LLM Error: %s", newOutput.Error.Message)
		
				resultMapping.Status = "FAILURE" 
			} else {
				log.Printf("[ERROR][%s] No choices, nor error found in AI agent response. Status: %d. Raw: %s", execution.ExecutionId, outputMap.Status, bodyString)
				resultMapping.Status = "FAILURE" 
			}
		} else {
			choicesString = openaiOutput.Choices[0].Message.Content

			// Handles reasoning models for Refusal control edgecases
			// Not always sure why this is happening
			if len(choicesString) == 0 && len(openaiOutput.Choices[0].Message.Refusal) > 0 {
				choicesString = openaiOutput.Choices[0].Message.Refusal

				if strings.HasPrefix(choicesString, "JSON") {
					choicesString = strings.Replace(choicesString, "JSON", "", 1)
				}

				if strings.HasPrefix(choicesString, "json") {
					choicesString = strings.Replace(choicesString, "json", "", 1)
				}
			}
				
			choicesString = strings.TrimSpace(choicesString)
			//log.Printf("\n\n\nCONTENT: %#v\n\n\n", choicesString)
		}

		// Found random JSON issues with [{} and similar, due to LLM instability.
		mappedDecisions := []AgentDecision{}
		decisionString := FixContentOutput(choicesString)
		if strings.HasPrefix(decisionString, "[") && !strings.HasSuffix(decisionString, "]") {
			decisionString = fmt.Sprintf("%s]", decisionString)
		}

		// Set the raw response
		if !strings.HasPrefix(decisionString, `[`) || !strings.HasSuffix(decisionString, `]`) {
			decisionString = choicesString
		}

		errorMessage := ""
		err = json.Unmarshal([]byte(decisionString), &mappedDecisions)
		if err != nil {
			log.Printf("[ERROR][%s] Failed unmarshalling decisions in AI Agent response: %s", execution.ExecutionId, err)

			if len(mappedDecisions) == 0 { 
				decisionString = strings.Replace(decisionString, `\"`, `"`, -1)

				err = json.Unmarshal([]byte(decisionString), &mappedDecisions)
				if err != nil {
					log.Printf("[ERROR][%s] Failed unmarshalling decisions in AI Agent response (2): %s", execution.ExecutionId, err)
					resultMapping.Status = "FAILURE"

					// Updating the OUTPUT in some way to help the user a bit.
					errorMessage = fmt.Sprintf("The output from the LLM had no decisions. See the raw decisions tring for the response. Contact support@shuffler.io if you think this is wrong.")
				}
			}
		}

		completionRequest.Messages = append(completionRequest.Messages, openai.ChatCompletionMessage{
			Role: "assistant",
			Content: string(bodyString),
		})

		// Lool, this will be fun won't it
		/*
		for mapIndex, _ := range mappedDecisions {
			randomType := typeOptions[rand.Intn(len(typeOptions))]

			mappedDecisions[mapIndex].RunDetails.Type = randomType
			mappedDecisions[mapIndex].RunDetails.Status = ""
		}
		*/

		agentOutput := AgentOutput{
			Status:    "RUNNING",
			Input:     userMessage,
			Error: 	   errorMessage,
			Decisions: mappedDecisions,

			ExecutionId: execution.ExecutionId,
			NodeId: startNode.ID,
			StartedAt: time.Now().Unix(),

			Memory: memorizationEngine,
		}

		if resultMapping.Status == "FAILURE" {
			agentOutput.Status = "FAILURE"
			agentOutput.CompletedAt = time.Now().Unix()
		}

		if len(mappedDecisions) == 0 {
			agentOutput.DecisionString = decisionString
		}

		// Ensures we track them along the way
		if len(parsedAgentInput) > 0 { 
			agentOutput.Input = parsedAgentInput
		}

		for decisionIndex, decision := range agentOutput.Decisions {
			// Random generate an ID that's 10 chars long
			if len(decision.RunDetails.Id) == 0 {
				b := make([]byte, 6)
				_, err := rand.Read(b)
				if err != nil {
					log.Printf("[ERROR][%s] Failed generating random string for decision index %s-%d", execution.ExecutionId, decision.Tool, decision.I)
				} else {
					agentOutput.Decisions[decisionIndex].RunDetails.Id = base64.RawURLEncoding.EncodeToString(b)
				}

			}

			// Send a Singul job. 
			// Which do we use:
			// 1. Local Singul
			if decision.Action == "" {
				log.Printf("[ERROR] No action found in AI agent decision")
				continue
			}

			if decision.I != 0 {
				continue
			}

			// Do we run the singul action directly?
			agentOutput.Decisions[decisionIndex].RunDetails.StartedAt = time.Now().Unix()
			agentOutput.Decisions[decisionIndex].RunDetails.Status = "RUNNING"
			go RunAgentDecisionAction(execution, agentOutput, agentOutput.Decisions[decisionIndex])
		}

		marshalledAgentOutput, err := json.Marshal(agentOutput)
		if err != nil {
			log.Printf("[ERROR] Failed marshalling agent output in AI Agent response: %s", err)
			return startNode, err
		}

		resultMapping.Result = string(marshalledAgentOutput)

	} else {
		log.Printf("[ERROR] No result found in AI agent response. Status: %d. Body: %s", newresp.StatusCode, string(body))
	}

	if memorizationEngine == "shuffle_db" {
		requestKey := fmt.Sprintf("chat_%s_%s", execution.ExecutionId, startNode.ID)

		for messageIndex, _ := range completionRequest.Messages {
			if len(completionRequest.Messages[messageIndex].Name) == 0 {
				completionRequest.Messages[messageIndex].Name = string(time.Now().Unix())
			}
		}

		marshalledCompletionRequest, err := json.MarshalIndent(completionRequest, "", "  ")

		if err != nil {
			log.Printf("[ERROR][%s] Failed marshalling openai completion request: %s", execution.ExecutionId, err)
		} else {
			cacheData := CacheKeyData{
				Key: requestKey,
				Value: string(marshalledCompletionRequest),
				Category: "agent_requests",

				WorkflowId: execution.Workflow.ID,
				ExecutionId: execution.ExecutionId,
				Authorization: execution.Authorization,
				OrgId: execution.ExecutionOrg,
			}

			err := SetCacheKey(ctx, cacheData) 
			if err != nil {
				log.Printf("[ERROR][%s] Failed updating AI requests: %s", execution.ExecutionId, err)
			}
		}
	}

	// 1. Map the response back
	newResult, err := json.Marshal(resultMapping)
	if err != nil {
		log.Printf("[ERROR] Failed marshalling response from sending request for stream during SKIPPED user input: %s", err)
	}

	// Send the stream result to /api/v1/streams
	streamUrl := fmt.Sprintf("%s/api/v1/streams", backendUrl)
	streamReq, err := http.NewRequest(
		"POST",
		streamUrl,
		bytes.NewBuffer([]byte(newResult)),
	)

	if err != nil {
		log.Printf("[ERROR] Failed creating request for stream during SKIPPED user input: %s", err)
		return startNode, err
	}

	streamResp, err := client.Do(streamReq)
	if err != nil {
		log.Printf("[ERROR] Failed sending request for stream during SKIPPED user input: %s", err)
		return startNode, err
	}

	defer streamResp.Body.Close()
	streamBody, err := ioutil.ReadAll(streamResp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading response from sending request for stream during SKIPPED user input: %s", err)
		return startNode, err
	}

	log.Printf("[INFO] Response from sending request for stream during SKIPPED user input: %d - %s", streamResp.StatusCode, string(streamBody))

	return startNode, nil

}

func RunAiQuery(systemMessage, userMessage string) (string, error) {
	cnt := 0
	maxTokens := 5000
	maxCharacters := 100000
	openaiClient := openai.NewClient(os.Getenv("OPENAI_API_KEY"))

	if len(systemMessage) > maxCharacters {
		systemMessage = systemMessage[:maxCharacters]
	}

	if len(userMessage) > maxCharacters {
		log.Printf("[WARNING] User message too long. Cutting off from %d to %d characters", len(userMessage), maxCharacters)
		userMessage = userMessage[:maxCharacters]
	}
	//}

	chatCompletion := openai.ChatCompletionRequest{
		Model: model,
		Messages: []openai.ChatCompletionMessage{},
		MaxTokens:   maxTokens,
	}

	// Too specific, but.. :)
	if model == "o4-minii" {
		chatCompletion.MaxTokens = 0
		chatCompletion.MaxCompletionTokens = maxTokens
	}

	if len(systemMessage) > 0 {
		chatCompletion.Messages = append(chatCompletion.Messages, openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleSystem,
			Content: systemMessage,
		})
	}

	if len(userMessage) > 0 {
		chatCompletion.Messages = append(chatCompletion.Messages, openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleUser,
			Content: userMessage,
		})
	}

	if len(chatCompletion.Messages) == 0 {
		return "", errors.New("No messages to send to OpenAI. Pass systemmessage, usermessage")
	}

	maxRetries := 3
	sleepTimer := time.Duration(2)
	contentOutput := ""
	for {
		if cnt >= maxRetries {
			log.Printf("[ERROR] Failed to match JSON in runActionAI after 5 tries for openapi info")

			return "", errors.New("Failed to match JSON in runActionAI after 5 tries for openapi info")
		}

		openaiResp, err := openaiClient.CreateChatCompletion(
			context.Background(),
			chatCompletion,
		)

		if err != nil {
			cnt += 1

			if strings.Contains(err.Error(), "not supported MaxTokens") {
				chatCompletion.MaxTokens = 0
				chatCompletion.MaxCompletionTokens = maxTokens
				continue
			} else if strings.Contains(err.Error(), "does not exist") {
				if len(fallbackModel) == 0 {
					return "", errors.New(fmt.Sprintf("Model '%s' does not exist and no FALLBACK_AI_MODEL set: %s", model, err))
				}

				model = fallbackModel
				chatCompletion.Model = fallbackModel 
				log.Printf("[DEBUG] Changed default model to %s", model)
				continue
			}

			log.Printf("[ERROR] Failed to create AI chat completion. Retrying in 3 seconds (4): %s", err)
			time.Sleep(sleepTimer * time.Second)
			continue
		}

		if len(openaiResp.Choices) == 0 {
			return "", errors.New("No choices found in OpenAI response. This should be AT LEAST 1.")
		} 

		contentOutput = openaiResp.Choices[0].Message.Content
		if len(contentOutput) == 0 && len(openaiResp.Choices[0].Message.Refusal) > 0 {
			// Failover to refusal
			contentOutput = openaiResp.Choices[0].Message.Refusal
		}

		break
	}

	return contentOutput, nil
}
