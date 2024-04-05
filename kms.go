package shuffle

import (
	"fmt"
	"log"
	"time"
	"io/ioutil"
	"os"
	"net/http"
	"bytes"
	"errors"
	"context"
	"strings"
	"encoding/json"
	"crypto/md5"
	"encoding/hex"

	"github.com/frikky/schemaless"
)


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

	log.Printf("[INFO] Looking to decrypt KMS key '%s' with %d parts", key, len(keys))


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

		log.Printf("[DEBUG] %d vs %d", len(newkeys), len(requiredParams))
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
	if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
		baseUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
	}

	parsedUrl := fmt.Sprintf("%s/api/v1/apps/categories/run", baseUrl)
	if len(authorization) > 0 && len(optionalExecutionId) > 0 {
		parsedUrl += fmt.Sprintf("?authorization=%s&execution_id=%s", authorization, optionalExecutionId)
	}

	//log.Printf("\n\nKMS URL: %s\n\n", parsedUrl)
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
	output, err := RunKmsTranslation(ctx, body, authConfig)
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

func FindHttpBody(fullBody []byte) ([]byte, error) {
	kmsResponse := SubflowData{}
	err := json.Unmarshal(fullBody, &kmsResponse)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal Schemaless response (1): %s", err)
		return []byte{}, err
	}

	// Make result into a body as well
	httpOutput := &HTTPOutput{} 
	err = json.Unmarshal([]byte(kmsResponse.Result), httpOutput)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal Schemaless HTTP Output response (2): %s", err)
		return []byte{}, err
	}

	if httpOutput.Status >= 300 {
		log.Printf("[ERROR] Schemaless action failed with status: %d", httpOutput.Status)
		return []byte{}, errors.New(fmt.Sprintf("Schemaless action failed with status: %d", httpOutput.Status))
	}

	marshalledBody, err := json.Marshal(httpOutput.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal Schemaless HTTP Body response body back to byte: %s", err)
		return []byte{}, err
	}

	return marshalledBody, nil
}

// Translates the output of the KMS action to a usable format in the 
// { "kms_key": "key", "kms_value": "value" } format
func RunKmsTranslation(ctx context.Context, fullBody []byte, authConfig string) (string, error) {
	// We need to parse the response from the KMS action
	// 1. Find JUST the result data
	marshalledBody, err := FindHttpBody(fullBody)
	if err != nil {
		log.Printf("[ERROR] Failed to find HTTP body in KMS response: %s", err)
		return "", err
	}


	schemalessOutput, err := schemaless.Translate(ctx, "get_kms_key", marshalledBody, authConfig)
	if err != nil {
		log.Printf("[ERROR] Failed to translate KMS response (2): %s", err)
		return "", err
	}

	var labeledResponse map[string]string
	err = json.Unmarshal(schemalessOutput, &labeledResponse)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal KMS response (3): %s", err)
		return "", err
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
	//foundKey := labeledResponse["kms_key"]
	//log.Printf("\n\n\n[DEBUG] Found KMS value for key: %s\n\n\n", labeledResponse["kms_value"])
	foundValue := labeledResponse["kms_value"]

	return foundValue, nil
}
