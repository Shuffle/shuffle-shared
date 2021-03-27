package shuffle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func executeCloudAction(action CloudSyncJob, apikey string) error {
	data, err := json.Marshal(action)
	if err != nil {
		log.Printf("Failed cloud webhook action marshalling: %s", err)
		return err
	}

	client := &http.Client{}
	syncUrl := fmt.Sprintf("https://shuffler.io/api/v1/cloud/sync/handle_action")
	req, err := http.NewRequest(
		"POST",
		syncUrl,
		bytes.NewBuffer(data),
	)

	req.Header.Add("Authorization", fmt.Sprintf(`Bearer %s`, apikey))
	newresp, err := client.Do(req)
	if err != nil {
		return err
	}

	respBody, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		return err
	}

	type Result struct {
		Success bool   `json:"success"`
		Reason  string `json:"reason"`
	}

	//log.Printf("Data: %s", string(respBody))
	responseData := Result{}
	err = json.Unmarshal(respBody, &responseData)
	if err != nil {
		return err
	}

	if !responseData.Success {
		return errors.New(fmt.Sprintf("Cloud error from Shuffler: %s", responseData.Reason))
	}

	return nil
}
