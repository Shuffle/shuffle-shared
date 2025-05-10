package shuffle

import (
	"os"
	"fmt"
	"log"
	"time"
	"bytes"
	"reflect"
	"errors"
	"context"
	"strings"
	"strconv"
	"net/http"
	"io/ioutil"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"encoding/base64"

	"github.com/frikky/schemaless"
	"github.com/frikky/kin-openapi/openapi3"
	openai "github.com/sashabaranov/go-openai"
)

//var model = "gpt-4-turbo-preview"
//var model = "gpt-4o-mini"
var model = "gpt-4o"

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
		log.Printf("[ERROR] Schemaless action failed with status: %d. Trying Autocorrecting feature", httpOutput.Status)

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

	log.Printf("[DEBUG] Previous Status: %d, ok: %t", status, bodyOk)

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

		log.Printf("Inside body: %s", string(body))

		// Should turn body into a string and check OpenAPI for problems if status is bad
		if status >= 0 && status < 300 {
			//useApp := action.AppName
			//if len(originalAppname) > 0 {
			//	useApp = originalAppname
			//}
			//outputString := handleOutputFormatting(string(body), inputdata, useApp)
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
				log.Printf("[ERROR] Error running self-correcting request: %s", err)
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
	// FIX: Make it find shuffle internal docs as well for how an app works
	// Make it work with Shuffle tools, as now it's explicitly trying to fix fields for HTTP apps

	/*
	if len(action.InvalidParameters) == 0 && additionalInfo == "" && strings.ToUpper(appname) != "HTTP" && !strings.Contains(strings.ToUpper(appname), "SHUFFLE") {
		additionalInfo = getOpenApiInformation(strings.Replace(appname, " ", "", -1), strings.Replace(action.Name, "_", " ", -1))
	} else {

		log.Printf("\n\nGot %d invalid params and additional info of length %d", len(action.InvalidParameters), len(additionalInfo))

	}
	*/

	log.Printf("[DEBUG] additionalInfo: %s", additionalInfo)
	log.Printf("[DEBUG] outputBody: %s", outputBody)
	log.Printf("[DEBUG] inputdata: %s", inputdata)

	additionalInfo = ""
	openaiClient := openai.NewClient(os.Getenv("OPENAI_API_KEY"))
	cnt := 0

	// Add all fields with value from here
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
		//log.Printf("PARAM START: '%s'. END: '%s'", checkValue[:10], checkValue[len(checkValue)-10:])

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

	log.Printf("[Critical] InputBody generated here: %s", inputBody)
	log.Printf("[Critical] OutputBodies generated here: %s", outputBodies)

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
	   - IF we are missing a value for the user to input, return the format {"success": false, "missing_fields": ["field1", "field2"]} to indicate the missing fields. ONLY do this if the field(s) are REQUIRED.

	`)

	inputData := fmt.Sprintf(`Precise JSON Field Correction Instructions:
Given the HTTP API context for %s:
- HTTP Status: %d
- Detailed Error: %s

Input JSON Payload:
%s`, appname, status, outputBodies, inputBody)

	log.Printf("[INFO] INPUTDATA:\n\n\n\n'''%s''''\n\n\n\n", inputData)

	contentOutput := ""
	for {
		if cnt >= 3 {
			log.Printf("[ERROR] Failed to match JSON in runActionAI after 3 tries for self correcting")

			return action, additionalInfo, errors.New(getBadOutputString(action, appname, inputdata, outputBody, status))
		}

		openaiResp2, err := openaiClient.CreateChatCompletion(
			context.Background(),
			openai.ChatCompletionRequest{
				Model: model,
				Messages: []openai.ChatCompletionMessage{
					{
						Role:    openai.ChatMessageRoleSystem,
						Content: systemMessage,
					},
					{
						Role:    openai.ChatMessageRoleUser,
						Content: inputData,
					},
				},
				Temperature: 0.9,
			},
		)

		if err != nil {
			if strings.Contains(err.Error(), "status code: 401") || strings.Contains(err.Error(), "status code: 403") {
				return action, additionalInfo, errors.New(fmt.Sprintf("AI API key is invalid. Please check your key. Bad status code."))
			}

			log.Printf("[ERROR] Failed to create chat completion in run self correcting. Retrying in 3 seconds (5): %s", err)

			time.Sleep(2 * time.Second)
			cnt += 1
			continue
		}

		contentOutput = openaiResp2.Choices[0].Message.Content
		break
	}

	log.Printf("\n\nTOKENS (AUTOFIX API~): In: %d, Out: %d\n\n", (len(systemMessage)+len(inputData))/4, len(contentOutput)/4)

	contentOutput = FixContentOutput(contentOutput)

	log.Printf("[INFO] Autocorrected output: %s", contentOutput)

	// Fix the params based on the contentOuput JSON
	// Parse output into JSOn
	var outputJSON map[string]interface{}
	err := json.Unmarshal([]byte(contentOutput), &outputJSON)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshalling data '%s'. Failed to unmarshal outputJSON in action fix for app %s with action %s: %s", contentOutput, appname, action.Name, err)

		return action, additionalInfo, errors.New(getBadOutputString(action, appname, inputdata, outputBody, status))
	}

	if strings.Contains(contentOutput, "missing_fields") {
		log.Printf("Missing fields found!")

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

	log.Printf("[DEBUG] Skipping output formatting (bad output string)")
	//errorString := handleOutputFormatting(string(outputData), inputdata, appname)

	return outputData 
}

func RunAiQuery(systemMessage, userMessage string) (string, error) {
	maxTokens := 5000
	maxCharacters := 100000
	//if len(systemMessage) > maxTokens || len(userMessage) > maxTokens {
		// FIXME: Error or just cut it off?
		//return "", errors.New("Message too long for general usage. Max 10000 characters for system & user message")

	if len(systemMessage) > maxCharacters {
		systemMessage = systemMessage[:maxCharacters]
	}

	if len(userMessage) > maxCharacters {
		log.Printf("[WARNING] User message too long. Cutting off from %d to %d characters", len(userMessage), maxCharacters)
		userMessage = userMessage[:maxCharacters]
	}
	//}

	cnt := 0
	openaiClient := openai.NewClient(os.Getenv("OPENAI_API_KEY"))
	chatCompletion := openai.ChatCompletionRequest{
		Model: model,
		Messages: []openai.ChatCompletionMessage{},
		Temperature: 0.8, // A tiny bit of creativity 
		MaxTokens:   maxTokens,
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

	contentOutput := ""
	for {
		if cnt >= 3 {
			log.Printf("[ERROR] Failed to match JSON in runActionAI after 5 tries for openapi info")

			return "", errors.New("Failed to match JSON in runActionAI after 5 tries for openapi info")
		}

		openaiResp2, err := openaiClient.CreateChatCompletion(
			context.Background(),
			chatCompletion,
		)

		if err != nil {
			log.Printf("[ERROR] Failed to create chat completion for api info. Retrying in 3 seconds (4): %s", err)
			time.Sleep(3 * time.Second)
			cnt += 1
			continue
		}

		contentOutput = openaiResp2.Choices[0].Message.Content
		break
	}

	return contentOutput, nil
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
	//fileId := fmt.Sprintf("file_%s-%s-%s.json", strings.ToLower(appId), strings.Replace(strings.ToLower(actionName), " ", "_", -1), strings.ToLower(paramName))
	fileId := fmt.Sprintf("file_%s-%s-%s-%s.json", orgId, strings.ToLower(appId), strings.Replace(strings.ToLower(actionName), " ", "_", -1), strings.ToLower(paramName))
	file, err := GetFile(ctx, fileId)
	if err == nil && file.Status == "active" {
		//log.Printf("[INFO] File %s already exists. NOT re-uploading", fileId)
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
		Namespace:    "app_defaults",
		Tags:         []string{"parameter base"},
	}

	err = SetFile(ctx, newFile)
	if err != nil {
		log.Printf("[ERROR] Failed to set file in uploadParameterBase: %s", err)
		return err
	}

	log.Printf("SHOULD UPLOAD FILE TO ID %s", fileId)

	// Upload to /api/v1/files/{fileId}/upload with the data from paramValue
	parsedKey := fmt.Sprintf("%s_%s", orgId, newFile.Id)
	fileId, err = UploadFile(ctx, &newFile, parsedKey, []byte(paramValue))
	if err != nil {
		log.Printf("[ERROR] Failed to upload file in uploadParameterBase: %s", err)
		return err
	}

	log.Printf("UPLOADED FILE TO ID %s", fileId)

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

func GetActionAIResponse(ctx context.Context, resp http.ResponseWriter, user shuffle.User, org shuffle.Org, outputFormat string, input shuffle.QueryInput) {

	if !user.SupportAccess {
		//if org.SyncFeatures.ShuffleGPT.Active && org.SyncFeatures.ShuffleGPT.Usage < org.SyncFeatures.ShuffleGPT.Limit {
		if org.SyncFeatures.ShuffleGPT.Usage < 100 {
			log.Printf("[AUDIT] Org %s has access to the auto feature. Allowing user %s to use it", org.Name, user.Username)
			org.SyncFeatures.ShuffleGPT.Usage += 1

			// Managing usage (this happens elsewhere as well apparently
			//shuffle.IncrementCache(ctx, org.Id, "ai_executions", 1)

		} else {
			log.Printf("[AUDIT] User %s (%s) tried to use the auto feature but doesn't have support access. Checking if org has access", user.Username, user.Id)

			if !org.SyncFeatures.ShuffleGPT.Active {
				resp.WriteHeader(403)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "The Shuffle AI feature is unavailable to your organisation for now. Contact support@shuffler.io if you want to try out this feature."}`)))
				return
			} else {
				resp.WriteHeader(429)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "You are above your limits for the The Shuffle AI feature (%d/%d). Resets monthly. Contact support@shuffler.io if you need more credits. 100 AI runs per month are included by default."}`, org.SyncFeatures.ShuffleGPT.Usage, org.SyncFeatures.ShuffleGPT.Limit)))
				return
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
			return
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
	appCategories := shuffle.GetAllAppCategories()
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
	foundApp := shuffle.WorkflowApp{}
	if len(input.AppId) > 0 {
		// Get app directly
		newApp, err := shuffle.GetApp(ctx, input.AppId, user, false)
		if err == nil {
			foundApp = *newApp
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
				Temperature: 0.4,
			},
		)

		if err != nil {
			log.Printf("[ERROR] ChatCompletion error: %v\n", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		if len(openaiResp.Choices) > 0 {
			log.Printf("[INFO] Raw Output (1): %s", openaiResp.Choices[0].Message.Content)
			contentOutput = openaiResp.Choices[0].Message.Content

			// Used for debugging random inputs
			//contentOutput = `{"success": true, "category": "SIEM", "fields": {"query": "1.2.3.4"}}`

			// Used for analytics testing
			//contentOutput = `{"success": true, "category": "Assets", "action": "Search Assets", "fields": ["appname", "date_range", "asset_type"], "appname": "Google Analytics"}`
		}

		contentOutput = shuffle.FixContentOutput(contentOutput)

		err = json.Unmarshal([]byte(contentOutput), &output)
		if err != nil {
			log.Printf("[ERROR] Failed to unmarshal output in runActionAI: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false}`))
			return
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
				resp.WriteHeader(500)
				resp.Write([]byte(`{"success": false}`))
				return
			}

			actionName = strings.ToUpper(httpOutput.Method)
			jsonoutput, err := json.Marshal(httpOutput)
			if err == nil {
				inputQuery += "\n\n" + string(jsonoutput)
			}
		}
	}

	apps := []shuffle.WorkflowApp{}
	if len(foundApp.ID) == 0 {
		apps, err = shuffle.GetPrioritizedApps(ctx, user)
		if err != nil {
			log.Printf("[ERROR] Failed to get apps in runActionAI: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed to get apps for your organization. Please try again"}`))
			return
		}
	}

	appname1, appok := output["appname"]
	if appok && len(appname) == 0 {
		appname = appname1.(string)
	}

	log.Printf("[INFO] Starting AI Translation with app '%s' and category '%s' for query '%s'", appname, category, inputQuery)

	if strings.Contains(contentOutput, "success\": false") {
		// Maybe look for a Workflow that does what they want?
		if appok && len(appname1.(string)) > 0 && !shuffle.ArrayContains(categoryNames, strings.ToLower(appname1.(string))) {
			// 1. Check for the appname in Shuffle
			// 2. Check in GPT-4
			// 3. Check internet

			log.Printf("[INFO] Appname specified in success false. Find most likely apps for:'%s'", appname1.(string))
			foundApps, err := shuffle.FindWorkflowAppByName(ctx, appname)
			if err != nil {
				log.Printf("[ERROR] Failed to find app by name in runActionAI: %s", err)
				resp.WriteHeader(500)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to load app for name '%s'."}`, appname)))
				return
			}

			if len(foundApps) == 0 {
				// Use Algolia to find the app
				algoliaApp, err := shuffle.HandleAlgoliaAppSearch(ctx, appname)
				if err == nil && len(algoliaApp.ObjectID) > 0 {

					log.Printf("[INFO] Found app by name in Algolia (1): %s (%s)", algoliaApp.Name, algoliaApp.ObjectID)
					// Get actual app based on objectID

					// Get the app
					discoveredApp, err := shuffle.GetApp(ctx, algoliaApp.ObjectID, user, false)
					if err != nil {
						log.Printf("[ERROR] Failed to get app in runActionAI for ID app %s (%s) (2): %s", algoliaApp.Name, algoliaApp.ObjectID, err)
						resp.WriteHeader(500)
						resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to get app '%s' (1). Please be more specific."}`, algoliaApp.Name)))
						return
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

				//relevantApps = []shuffle.WorkflowApp{
				//	shuffle.WorkflowApp{
				//		Name: foundApp[0].Name,
				//	},
				//}

				// Using the first one to find how to run it as a HTTP request
				// "Fill in the following HTTP information with the API of 'Appname' based on the following information: 'CTA from user'"
				if len(relevantApps) > 0 {
					httpOutput, err = findHTTPrequestInformation(inputQuery, relevantApps[selectedAppIndex].Name)
					if err != nil {
						log.Printf("[ERROR] Failed to find HTTP request information (1): %s", err)
						resp.WriteHeader(500)
						resp.Write([]byte(`{"success": false}`))
						return
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
								resp.WriteHeader(500)
								resp.Write([]byte(fmt.Sprintf(authMessage)))
								return
							}
						}
					} else if httpOutput.Oauth2Auth {
						log.Printf("[INFO] API for %s requires Oauth2 auth (3), but we don't have it. Returning error: %s", relevantApps[0].Name, err)

						if !strings.HasPrefix(outputFormat, "action") {
							resp.WriteHeader(500)
							resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "API for '%s' uses Oauth2, which is not supported yet without a proper app.\n\nSample curl command: \n\n%s"}`, appname, httpOutput.CurlCommand)))
							return
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
			matchingApps := shuffle.FindMatchingCategoryApps(category, apps, &org)

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

				resp.WriteHeader(400)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "No matching apps found. Be more specific about what app to use, or what you want to do."}`)))
				return
			}
		}
	} else {
		if len(appname) == 0 {
			appname = appname1.(string)
		}
	}

	appname = strings.Replace(appname, "_", " ", -1)
	log.Printf("[INFO] Using app '%s' for action '%s' (1)", appname, actionName)

	actionLabel1, ok := output["action"]
	if !ok && len(actionName) == 0 {
		actionLabel1, ok = output["action_label"]

		if !ok {
			// Should search for it

			log.Printf("[ERROR] No actionLabel found in runActionAI for your input with app %s and category %s. Trying to find the action that matches the best anyway", appname, category)

			// Should run Action search in the correct app
			if len(appname) > 0 && foundApp.ID == "" {
				foundApps, err := shuffle.FindWorkflowAppByName(ctx, appname)
				if err != nil {
					log.Printf("[ERROR] Failed to find app by name in runActionAI: %s", err)
					resp.WriteHeader(500)
					resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to load app for name '%s' in category '%s'"}`, appname, category)))
					return
				}

				if len(foundApps) == 0 {

					// Use Algolia to find the app
					algoliaApp, err := shuffle.HandleAlgoliaAppSearch(ctx, appname)
					if err != nil || algoliaApp.ObjectID == "" {
						log.Printf("[ERROR] Failed to find app by name %s in runActionAI: %s", appname, err)
						resp.WriteHeader(400)
						resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to load app for name '%s' in category '%s' (2)"}`, appname, category)))
						return
					}

					log.Printf("[INFO] Found app by name in Algolia (3): %s (%s)", algoliaApp.Name, algoliaApp.ObjectID)
					// Get actual app based on objectID

					// Get the app
					discoveredApp, err := shuffle.GetApp(ctx, algoliaApp.ObjectID, user, false)
					if err != nil {
						log.Printf("[ERROR] Failed to get app in runActionAI for ID app %s (%s) (2): %s", algoliaApp.Name, algoliaApp.ObjectID, err)
						resp.WriteHeader(500)
						resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to get app '%s' (2). Please be more specific."}`, algoliaApp.Name)))
						return
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
				resp.WriteHeader(500)
				resp.Write([]byte(`{"success": false, "reason": "Failed to find action for app. Please be more specific."}`))
				return
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
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "No matching action found. Please specify the app and action to use.", "action": "select_app"}`))
			return
		}

		//log.Printf("[INFO] Found action by input in runActionAI: %s", actionName)

		if len(actionName) == 0 {
			log.Printf("[ERROR] No actionLabel found in runActionAI for your input with app %s and category '%s'", appname, category)
			resp.WriteHeader(400)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "No matching action label found. Please try again with a different prompt. App: %s, category: %s"}`, appname, category)))
			return
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
		foundApps, err := shuffle.FindWorkflowAppByName(ctx, appname)
		if err != nil {
			log.Printf("[ERROR] Failed to find app by name in runActionAI: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to load app for name '%s' in category '%s' (3)"}`, appname, category)))
			return
		}

		if len(foundApps) == 0 {
			// Use Algolia to find the app
			algoliaApp, err := shuffle.HandleAlgoliaAppSearch(ctx, appname)
			if err != nil {
				log.Printf("[ERROR] Failed to find app by name in runActionAI: %s", err)
				resp.WriteHeader(400)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to load app for name '%s' in category '%s' (4)"}`, appname, category)))
				return
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
						resp.WriteHeader(500)
						resp.Write([]byte(`{"success": false}`))
						return
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
								resp.WriteHeader(500)
								resp.Write([]byte(fmt.Sprintf(authMessage)))
								return
							}
						}
					} else if httpOutput.Oauth2Auth {
						log.Printf("[INFO] API for %s requires Oauth2 auth (3), but we don't have it. Returning error: %s", relevantApps[0].Name, err)

						if !strings.HasPrefix(outputFormat, "action") {
							resp.WriteHeader(500)
							resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "API for '%s' uses Oauth2, which is not supported yet without a proper app.\n\nSample curl command: \n\n%s"}`, appname, httpOutput.CurlCommand)))
							return
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
					foundApps, err := shuffle.FindWorkflowAppByName(ctx, appname)
					if err != nil {
						log.Printf("[ERROR] Failed to find app by name (5): %s", err)
						resp.WriteHeader(500)
						resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to load app for name '%s' in category '%s' (4)"}`, appname, category)))
						return
					}

					if len(foundApps) == 0 {
						log.Printf("[ERROR] Failed to find app by name (6): %s", err)
						resp.WriteHeader(500)
						resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to load app for name '%s' in category '%s' (6)"}`, appname, category)))
						return
					}

					foundApp = foundApps[0]
				} else {
					resp.WriteHeader(400)
					resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to load app for name '%s' in category '%s' (5)"}`, appname, category)))
					return
				}
			} else {
				log.Printf("[INFO] Found app by name in Algolia (4): %s (%s)", algoliaApp.Name, algoliaApp.ObjectID)
				// Get actual app based on objectID

				// Get the app
				discoveredApp, err := shuffle.GetApp(ctx, algoliaApp.ObjectID, user, false)
				if err != nil {
					log.Printf("[ERROR] Failed to get app in runActionAI for ID app %s (%s) (2): %s", algoliaApp.Name, algoliaApp.ObjectID, err)
					resp.WriteHeader(500)
					resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to get app '%s' (3). Please be more specific."}`, algoliaApp.Name)))
					return
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
	selectedAction := shuffle.WorkflowAppAction{}
	newActionName := shuffle.GetCorrectActionName(strings.ToLower(strings.Replace(actionName, " ", "_", -1)))
	for _, action := range foundApp.Actions {
		parsedName := strings.ToLower(strings.Replace(action.Name, " ", "_", -1))
		parsedName = shuffle.GetCorrectActionName(parsedName)

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
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Couldn't find the action you were looking for. Please try with a more specific prompt."}`))
			return
		}

		log.Printf("[INFO] Output in action synonym: %s", contentOutput)
		if strings.Contains(contentOutput, `{"success": "false"}`) {
			log.Printf("[ERROR] No matching action (2) found for app '%s' with label '%s' in runActionAI", foundApp.Name, actionLabel)
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "No matching action found. Please try again with a more specific prompt (1)."}`))
			return
		}

		log.Printf("[INFO] Found action in runActionAI (2). Action '%s' and label '%s'", contentOutput, actionLabel)
		newActionName := shuffle.GetCorrectActionName(strings.ToLower(strings.Replace(contentOutput, " ", "_", -1)))
		for _, action := range foundApp.Actions {
			parsedName := strings.ToLower(strings.Replace(action.Name, " ", "_", -1))
			parsedName = shuffle.GetCorrectActionName(parsedName)

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
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "No matching action found. Please try again with a more specific prompt (2)."}`))
			return
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
			resp.WriteHeader(400)
			resp.Write([]byte(errString))
			return
		}

		log.Printf("[ERROR] Failed to get selected app parameters in runActionAI: %s", err)

		// Sanitize err to work in json
		resp.WriteHeader(400)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, errString)))
		return
	}

	if strings.HasPrefix(outputFormat, "action") {
		log.Printf("[INFO] Skipping execution and returning action: %s", selectedAction.Name)
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
			resp.WriteHeader(500)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to decode action. Please try again"}`)))
			return
		}

		resp.WriteHeader(200)
		resp.Write([]byte(returnJSON))
		return
	}

	cnt := 1
	selfCorrectAttempts := 3
	additionalInfo := ""
	outputString := ""
	outputAction := shuffle.Action{}

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

		newAction := shuffle.Action{
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
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed to marshal action in runActionAI"}`))
			return
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
				return
			}

			log.Printf("[ERROR] Failed to send run request to self: %s", err)
			if strings.Contains(fmt.Sprintf("%s", err), "Failed to run") {
				resp.WriteHeader(400)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to run app %s with action %s. Please be more specific and try again."}`, newAction.AppName, newAction.Name)))
				return
			}

			resp.WriteHeader(400)
			//resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
			resp.Write([]byte(err.Error()))
			return
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
					Apps: []shuffle.AppMini{
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
					return
				} else {
					log.Printf("[ERROR] Failed to marshal return struct: %s", err)
				}
			}

			if len(err.Error()) == 0 || err == nil {
				err = errors.New(fmt.Sprintf("Failed to run app '%s' with action '%s' in category '%s'. Please try again with a different query.", strings.Replace(strings.Replace(foundApp.Name, "_", " ", -1), "\"", "", -1), strings.Replace(strings.Replace(selectedAction.Name, "_", " ", -1), "\"", "", -1), strings.Replace(strings.Replace(category, "_", " ", -1), "\"", "", -1)))
			}

			log.Printf("[ERROR] Failed to find next action: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
			return
		}

		// Means success :)
		if len(outputString) > 0 {
			resp.WriteHeader(200)
			resp.Write([]byte(outputString))
			return
		}

		selectedAction.Name = outputAction.Name
		selectedAction.Label = outputAction.Label
		selectedAction.Parameters = outputAction.Parameters
		selectedAction.InvalidParameters = outputAction.InvalidParameters
		log.Printf("[INFO] Have %d invalid parameters and %d valid ones. Trying again", len(selectedAction.InvalidParameters), len(selectedAction.Parameters))

		cnt += 1
	}

	/*







		Below here are test functions for OpenAPI3 interactions and searching








	*/

	// Check if we have all required fields
	//for _, field := range requiredFields {
	//	if _, ok := body[field]; !ok {
	//		log.Printf("[ERROR] Missing required field '%s' in runActionAI", field)

	/*
		// Check the JSON for the action with example response from openapi
		parsedApi, err := shuffle.GetOpenApiDatastore(ctx, foundApp.ID)
		if err != nil {
			log.Printf("[WARNING] Failed to get openapi data in runActionAI: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed to get openapi data in runActionAI"}`))
			return
		}

		// Unmarshal parsedApi.Body into swagger
			swagger := &openapi3.Swagger{}
			err = json.Unmarshal([]byte(parsedApi.Body), swagger)
			if err != nil {
				log.Printf("[WARNING] Failed to unmarshal openapi data in runActionAI: %s", err)
				resp.WriteHeader(500)
				resp.Write([]byte(`{"success": false, "reason": "Failed to unmarshal openapi data in runActionAI"}`))
				return
			}

			foundActionName := strings.ToLower(strings.Replace(selectedAction.Name, " ", "_", -1))
			foundActionName = shuffle.GetCorrectActionName(foundActionName)

			// Find the right action
			var foundAction *openapi3.Operation
			for _, urlItem := range swagger.Paths {
				for _, operation := range urlItem.Operations() {
					log.Printf("[INFO] Operation: %s - %s - %s", operation.OperationID, operation.Summary, foundActionName)

					if (strings.Replace(strings.ToLower(operation.OperationID), " ", "_", -1) == foundActionName) || (strings.Replace(strings.ToLower(operation.Summary), " ", "_", -1) == foundActionName) {
						foundAction = operation
						break
					}
				}
			}

			if foundAction == nil {
				log.Printf("[WARNING] Failed to find action %s in runActionAI", foundActionName)
				resp.WriteHeader(500)
				resp.Write([]byte(`{"success": false, "reason": "Failed to find action in runActionAI"}`))
				return
			}

			log.Printf("[INFO] Found action in runActionAI (3): %s", foundAction.OperationID)
	*/

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}


