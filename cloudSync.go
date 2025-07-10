package shuffle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	//"github.com/algolia/algoliasearch-client-go/v3/algolia/opt"
	"github.com/algolia/algoliasearch-client-go/v3/algolia/search"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	//"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"

	uuid "github.com/satori/go.uuid"
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

	defer newresp.Body.Close()
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

func HandleAlgoliaAppSearch(ctx context.Context, appname string) (AlgoliaSearchApp, error) {

	cacheTimer := int32(300)

	normalizedAppName := strings.TrimSpace(strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(appname, "_", " "), " ", "_")))
	cacheKey := fmt.Sprintf("appsearch_%s", normalizedAppName)

	cache, err := GetCache(ctx, cacheKey)
	if err == nil {
		if cacheData, ok := cache.([]byte); ok {
			var cachedApp AlgoliaSearchApp
			err = json.Unmarshal(cacheData, &cachedApp)
			if err == nil {
				return cachedApp, nil
			}

			log.Printf("[ERROR] Failed unmarshalling cached app search data in Handle algolia app search: %s", err)
		}
	}

	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")

	// Fallback to default Algolia keys
	if len(algoliaSecret) == 0 {
		algoliaClient = "JNSS5CFDZZ"
		algoliaSecret = os.Getenv("ALGOLIA_PUBLICKEY")
	}

	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[ERROR] ALGOLIA_CLIENT and ALGOLIA_SECRET/ALGOLIA_SECRET not defined (app discovery)")
		return AlgoliaSearchApp{}, errors.New("Algolia keys not defined")
	}

	returnApp := AlgoliaSearchApp{}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("appsearch")
	appname = strings.TrimSpace(strings.ToLower(strings.Replace(appname, "_", " ", -1)))
	res, err := algoliaIndex.Search(appname)
	if err != nil {
		log.Printf("[ERROR] Failed searching Algolia (%s): %s", appname, err)

		appData, err := json.Marshal(returnApp)
		if err == nil {
			SetCache(ctx, cacheKey, appData, cacheTimer)
		} else {
			log.Printf("[ERROR] Failed to marshal Algolia result in handle aloglia search (3): %s", err)
		}

		return returnApp, err
	}

	var newRecords []AlgoliaSearchApp
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia: %s", err)
		appData, err := json.Marshal(returnApp)
		if err == nil {
			SetCache(ctx, cacheKey, appData, cacheTimer)
		} else {
			log.Printf("[ERROR] Failed to marshal Algolia result in handle aloglia search (4): %s", err)
		}

		return returnApp, err
	}

	for _, newRecord := range newRecords {
		newApp := strings.TrimSpace(strings.ToLower(strings.Replace(newRecord.Name, "_", " ", -1)))
		if newApp == appname || newRecord.ObjectID == appname {
			//return newRecord.ObjectID, nil
			appData, err := json.Marshal(newRecord)
			if err == nil {
				SetCache(ctx, cacheKey, appData, cacheTimer)
			} else {
				log.Printf("[ERROR] Failed to marshal Algolia result in handle aloglia search (5): %s", err)
			}

			return newRecord, nil
		}
	}

	// Second try with contains
	for _, newRecord := range newRecords {
		newApp := strings.TrimSpace(strings.ToLower(strings.Replace(newRecord.Name, "_", " ", -1)))
		if strings.Contains(newApp, appname) {
			appData, err := json.Marshal(newRecord)
			if err == nil {
				SetCache(ctx, cacheKey, appData, cacheTimer)
			} else {
				log.Printf("[ERROR] Failed to marshal Algolia result in handle aloglia search (6): %s", err)
			}

			return newRecord, nil
		}
	}

	appData, err := json.Marshal(returnApp)
	if err == nil {
		SetCache(ctx, cacheKey, appData, cacheTimer)
	} else {
		log.Printf("[ERROR] Failed to marshal Algolia result in handle aloglia search (7): %s", err)
	}

	return returnApp, nil
}

func HandleAlgoliaWorkflowSearchByApp(ctx context.Context, appname string) ([]AlgoliaSearchWorkflow, error) {
	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return []AlgoliaSearchWorkflow{}, errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("workflows")

	appSearch := fmt.Sprintf("%s", appname)
	res, err := algoliaIndex.Search(appSearch)
	if err != nil {
		log.Printf("[WARNING] Failed app searching Algolia for creators: %s", err)
		return []AlgoliaSearchWorkflow{}, err
	}

	var newRecords []AlgoliaSearchWorkflow
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia with app creators: %s", err)
		return []AlgoliaSearchWorkflow{}, err
	}
	//log.Printf("[INFO] Algolia hits for %s: %d", appSearch, len(newRecords))

	allRecords := []AlgoliaSearchWorkflow{}
	for _, newRecord := range newRecords {
		allRecords = append(allRecords, newRecord)

	}

	return allRecords, nil
}

func HandleAlgoliaWorkflowSearchByUser(ctx context.Context, userId string) ([]AlgoliaSearchWorkflow, error) {
	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return []AlgoliaSearchWorkflow{}, errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("workflows")

	appSearch := fmt.Sprintf("%s", userId)
	res, err := algoliaIndex.Search(appSearch)
	if err != nil {
		log.Printf("[WARNING] Failed app searching Algolia for creators: %s", err)
		return []AlgoliaSearchWorkflow{}, err
	}

	var newRecords []AlgoliaSearchWorkflow
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia with app creators: %s", err)
		return []AlgoliaSearchWorkflow{}, err
	}
	//log.Printf("[INFO] Algolia hits for %s: %d", appSearch, len(newRecords))

	allRecords := []AlgoliaSearchWorkflow{}
	for _, newRecord := range newRecords {
		allRecords = append(allRecords, newRecord)

	}

	return allRecords, nil
}

func HandleAlgoliaAppSearchByUser(ctx context.Context, userId string) ([]AlgoliaSearchApp, error) {
	cacheKey := fmt.Sprintf("appsearch_user_%s", userId)
	cache, err := GetCache(ctx, cacheKey)
	if err == nil {
		if cacheData, ok := cache.([]byte); ok {
			var cachedApp []AlgoliaSearchApp
			err = json.Unmarshal(cacheData, &cachedApp)
			if err == nil {
				return cachedApp, nil
			}

			log.Printf("[ERROR] Failed unmarshalling cached app search data in Handle algolia app search for user (%s): %s", cacheKey, err)
		}
	}

	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaSecret) == 0 {
		algoliaClient = "JNSS5CFDZZ"
		algoliaSecret = os.Getenv("ALGOLIA_PUBLICKEY")
	}

	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return []AlgoliaSearchApp{}, errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("appsearch")

	returnApps := []AlgoliaSearchApp{}
	appSearch := fmt.Sprintf("%s", userId)
	res, err := algoliaIndex.Search(appSearch)
	if err != nil {
		log.Printf("[ERROR] Failed app searching Algolia for creators (%s): %s", appSearch, err)

		appData, err := json.Marshal(returnApps)
		if err == nil {
			SetCache(ctx, cacheKey, appData, 30)
		} else {
			log.Printf("[ERROR] Failed to marshal Algolia result in handle aloglia search (8): %s", err)
		}

		return returnApps, err
	}

	var newRecords []AlgoliaSearchApp
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshaling from Algolia with app creators: %s", err)

		appData, err := json.Marshal(returnApps)
		if err == nil {
			SetCache(ctx, cacheKey, appData, 30)
		} else {
			log.Printf("[ERROR] Failed to marshal Algolia result in handle aloglia search (9): %s", err)
		}

		return returnApps, err
	}

	for _, newRecord := range newRecords {
		newAppName := strings.TrimSpace(strings.Replace(newRecord.Name, "_", " ", -1))
		newRecord.Name = newAppName
		returnApps = append(returnApps, newRecord)
	}

	appData, err := json.Marshal(returnApps)
	if err == nil {
		SetCache(ctx, cacheKey, appData, 30)
	} else {
		log.Printf("[ERROR] Failed to marshal Algolia result in handle aloglia search (10): %s", err)
	}

	return returnApps, nil
}

func HandleAlgoliaCreatorSearch(ctx context.Context, username string) (AlgoliaSearchCreator, error) {
	tmpUsername, err := url.QueryUnescape(username)
	if err == nil {
		username = tmpUsername
	}

	if strings.HasPrefix(username, "@") {
		username = strings.Replace(username, "@", "", 1)
	}

	username = strings.ToLower(strings.TrimSpace(username))

	cacheKey := fmt.Sprintf("algolia_creator_%s", username)
	searchCreator := AlgoliaSearchCreator{}
	cache, err := GetCache(ctx, cacheKey)
	if err == nil {
		cacheData := []byte(cache.([]uint8))
		//log.Printf("CACHE: %d", len(cacheData))
		//log.Printf("CACHEDATA: %#v", cacheData)
		err = json.Unmarshal(cacheData, &searchCreator)
		if err == nil {
			return searchCreator, nil
		}
	}

	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return searchCreator, errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("creators")
	res, err := algoliaIndex.Search(username)
	if err != nil {
		log.Printf("[ERROR] Failed searching Algolia creators (%s): %s", username, err)
		return searchCreator, err
	}

	var newRecords []AlgoliaSearchCreator
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia creators: %s", err)
		return searchCreator, err
	}

	//log.Printf("RECORDS: %d", len(newRecords))
	foundUser := AlgoliaSearchCreator{}
	for _, newRecord := range newRecords {
		if strings.ToLower(newRecord.Username) == strings.ToLower(username) || newRecord.ObjectID == username || ArrayContainsLower(newRecord.Synonyms, username) {
			foundUser = newRecord
			break
		}
	}

	// Handling search within a workflow, and in the future, within apps
	if len(foundUser.ObjectID) == 0 {
		if len(username) == 36 {
			// Check workflows
			algoliaIndex := algClient.InitIndex("workflows")
			res, err := algoliaIndex.Search(username)
			if err != nil {
				log.Printf("[ERROR] Failed searching Algolia creator workflow (%s): %s", username, err)
				return searchCreator, err
			}

			var newRecords []AlgoliaSearchWorkflow
			err = res.UnmarshalHits(&newRecords)
			if err != nil {
				log.Printf("[WARNING] Failed unmarshaling from Algolia creator workflow: %s", err)

				if len(newRecords) > 0 && len(newRecords[0].ObjectID) > 0 {
					log.Printf("[INFO] Workflow search ID: %#v", newRecords[0].ObjectID)
				} else {
					return searchCreator, err
				}
			}

			//log.Printf("[DEBUG] Got %d records for workflow sub", len(newRecords))
			if len(newRecords) == 1 {
				if len(newRecords[0].Creator) > 0 && username != newRecords[0].Creator {
					foundCreator, err := HandleAlgoliaCreatorSearch(ctx, newRecords[0].Creator)
					if err != nil {
						return searchCreator, err
					}

					foundUser = foundCreator
				} else {
					return searchCreator, errors.New("User not found")
				}
			} else {
				return searchCreator, errors.New("User not found")
			}
		} else {
			return searchCreator, errors.New("User not found")
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(foundUser)
		if err != nil {
			return foundUser, nil
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed updating algolia username cache: %s", err)
		}
	}

	return foundUser, nil
}

func HandleAlgoliaPartnerSearch(ctx context.Context, orgId string) (AlgoliaSearchPartner, error) {

	cacheKey := fmt.Sprintf("algolia_partner_%s", orgId)
	searchPartner := AlgoliaSearchPartner{}
	cache, err := GetCache(ctx, cacheKey)
	if err == nil {
		cacheData := []byte(cache.([]uint8))
		err = json.Unmarshal(cacheData, &searchPartner)
		if err == nil {
			return searchPartner, nil
		}
	}

	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return AlgoliaSearchPartner{}, errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("partners")
	res, err := algoliaIndex.Search(orgId)
	if err != nil {
		log.Printf("[WARNING] Failed searching Algolia partners: %s", err)
		return AlgoliaSearchPartner{}, err
	}

	var newRecords []AlgoliaSearchPartner
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia partners: %s", err)
		return AlgoliaSearchPartner{}, err
	}

	foundPartner := AlgoliaSearchPartner{}
	for _, newRecord := range newRecords {
		if newRecord.OrgId == orgId {
			foundPartner = newRecord
			break
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(foundPartner)
		if err != nil {
			return foundPartner, nil
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed updating algolia partner cache: %s", err)
		}
	}

	return foundPartner, nil
}

func HandleAlgoliaCreatorUpload(ctx context.Context, user User, overwrite bool, isOrg bool) (string, error) {
	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return "", errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("creators")
	res, err := algoliaIndex.Search(user.Id)
	if err != nil {
		log.Printf("[ERROR] Failed searching Algolia creators (%s): %s", user.Id, err)
		return "", err
	}

	var newRecords []AlgoliaSearchCreator
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia creators: %s", err)
		return "", err
	}

	//log.Printf("RECORDS: %d", len(newRecords))
	for _, newRecord := range newRecords {
		if newRecord.ObjectID == user.Id {
			log.Printf("[INFO] Object %s already exists in Algolia", user.Id)

			if overwrite {
				break
			} else {
				return user.Id, errors.New("User ID already exists!")
			}
		}
	}

	timeNow := int64(time.Now().Unix())
	records := []AlgoliaSearchCreator{
		AlgoliaSearchCreator{
			ObjectID:   user.Id,
			TimeEdited: timeNow,
			Image:      user.PublicProfile.GithubAvatar,
			Username:   user.PublicProfile.GithubUsername,
			IsOrg:      isOrg,
		},
	}

	_, err = algoliaIndex.SaveObjects(records)
	if err != nil {
		log.Printf("[WARNING] Algolia Object put err: %s", err)
		return "", err
	}

	log.Printf("[INFO] SUCCESSFULLY UPLOADED creator %s with ID %s TO ALGOLIA!", user.Username, user.Id)
	return user.Id, nil
}

func HandleAlgoliaCreatorDeletion(ctx context.Context, userId string) error {
	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("creators")
	res, err := algoliaIndex.Search(userId)
	if err != nil {
		log.Printf("[ERROR] Failed searching Algolia creators (%s): %s", userId, err)
		return err
	}

	var newRecords []AlgoliaSearchCreator
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia creators: %s", err)
		return err
	}

	//log.Printf("RECORDS: %d", len(newRecords))
	foundItem := AlgoliaSearchCreator{}
	for _, newRecord := range newRecords {
		if newRecord.ObjectID == userId {
			foundItem = newRecord
			break
		}
	}

	// Should delete it?
	if len(foundItem.ObjectID) > 0 {
		_, err = algoliaIndex.DeleteObject(foundItem.ObjectID)
		if err != nil {
			log.Printf("[WARNING] Algolia Creator delete problem: %s", err)
			return err
		}

		log.Printf("[INFO] Successfully removed creator %s with ID %s FROM ALGOLIA!", foundItem.Username, userId)
	}

	return nil
}

// Usecase Algolia Upload
func HandleAlgoliaUsecaseUpload(ctx context.Context, usecase UsecaseInfo, overwrite bool) (string, error) {
	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return "", errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("usecases")
	res, err := algoliaIndex.Search(usecase.Id)
	if err != nil {
		log.Printf("[WARNING] Failed searching Algolia usecases: %s", err)
		return "", err
	}

	var newRecords []AlgoliaSearchUsecase
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia partners: %s", err)
		return "", err
	}

	//log.Printf("RECORDS: %d", len(newRecords))
	for _, newRecord := range newRecords {
		if newRecord.ObjectID == usecase.Id {
			log.Printf("[INFO] Object %s already exists in Algolia", usecase.Id)

			if overwrite {
				break
			} else {
				return usecase.Id, errors.New("Usecase ID already exists!")
			}
		}
	}

	timeNow := int64(time.Now().Unix())
	records := []AlgoliaSearchUsecase{
		AlgoliaSearchUsecase{
			ObjectID:           usecase.Id,
			PartnerName:        usecase.CompanyInfo.Name,
			PartnerId:          usecase.CompanyInfo.Id,
			Name:               usecase.MainContent.Title,
			Description:        usecase.MainContent.Description,
			Categories:         usecase.MainContent.Categories,
			SourceAppType:      usecase.MainContent.SourceAppType,
			DestinationAppType: usecase.MainContent.DestinationAppType,
			PublicWorkflowID:   usecase.MainContent.PublicWorkflowID,
			TimeEdited:         timeNow,
		},
	}

	_, err = algoliaIndex.SaveObjects(records)
	if err != nil {
		log.Printf("[WARNING] Algolia Object put err: %s", err)
		return "", err
	}

	log.Printf("[INFO] SUCCESSFULLY UPLOADED partner %s with ID %s TO ALGOLIA!", usecase.MainContent.Title, usecase.Id)
	return usecase.Id, nil
}

// Usecase deletion
func HandleAlgoliaUsecaseDeletion(ctx context.Context, usecaseId string) error {
	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("usecases")
	res, err := algoliaIndex.Search(usecaseId)
	if err != nil {
		log.Printf("[ERROR] Failed searching Algolia usecases (%s): %s", usecaseId, err)
		return err
	}

	var newRecords []AlgoliaSearchUsecase
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia usecases: %s", err)
		return err
	}

	//log.Printf("RECORDS: %d", len(newRecords))
	foundItem := AlgoliaSearchUsecase{}
	for _, newRecord := range newRecords {
		if newRecord.ObjectID == usecaseId {
			foundItem = newRecord
			break
		}
	}

	// Should delete it?
	if len(foundItem.ObjectID) > 0 {
		_, err = algoliaIndex.DeleteObject(foundItem.ObjectID)
		if err != nil {
			log.Printf("[WARNING] Algolia Usecase delete problem: %s", err)
			return err
		}

		log.Printf("[INFO] Successfully removed usecase %s with ID %s FROM ALGOLIA!", foundItem.Name, usecaseId)
	}

	return nil
}

// Shitty temorary system
// Adding schedule to run over with another algorithm
// as well as this one, as to increase priority based on popularity:
// searches, clicks & conversions (CTR)
func GetWorkflowPriority(workflow Workflow) int {
	prio := 0
	if len(workflow.Tags) > 2 {
		prio += 1
	}

	if len(workflow.Name) > 5 {
		prio += 1
	}

	if len(workflow.Description) > 100 {
		prio += 1
	}

	if len(workflow.WorkflowType) > 0 {
		prio += 1
	}

	if len(workflow.UsecaseIds) > 0 {
		prio += 3
	}

	if len(workflow.Comments) >= 2 {
		prio += 2
	}

	return prio
}

func handleAlgoliaWorkflowUpdate(ctx context.Context, workflow Workflow) (string, error) {
	log.Printf("[INFO] Should try to UPLOAD the Workflow to Algolia")

	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return "", errors.New("Algolia keys not defined")
	}

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	algoliaIndex := algClient.InitIndex("workflows")

	//res, err := algoliaIndex.Search("%s", api.ID)
	res, err := algoliaIndex.Search(workflow.ID)
	if err != nil {
		log.Printf("[ERROR] Failed searching Algolia (%s): %s", workflow.ID, err)
		return "", err
	}

	var newRecords []AlgoliaSearchWorkflow
	err = res.UnmarshalHits(&newRecords)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from Algolia workflow upload: %s", err)
		return "", err
	}

	found := false
	record := AlgoliaSearchWorkflow{}
	for _, newRecord := range newRecords {
		if newRecord.ObjectID == workflow.ID {
			log.Printf("[INFO] Workflow Object %s already exists in Algolia", workflow.ID)
			record = newRecord
			found = true
			break
		}
	}

	if !found {
		return "", errors.New(fmt.Sprintf("Couldn't find public workflow for ID %s", workflow.ID))
	}

	record.TimeEdited = int64(time.Now().Unix())
	categories := []string{}
	actions := []string{}
	triggers := []string{}
	actionRefs := []ActionReference{}
	for _, action := range workflow.Actions {
		if !ArrayContains(actions, action.AppName) {
			// Using this API as the original is kinda stupid
			foundApps, err := HandleAlgoliaAppSearchByUser(ctx, action.AppName)
			if err == nil && len(foundApps) > 0 {
				actionRefs = append(actionRefs, ActionReference{
					Name:       foundApps[0].Name,
					Id:         foundApps[0].ObjectID,
					ImageUrl:   foundApps[0].ImageUrl,
					ActionName: []string{action.Name},
				})
			}

			actions = append(actions, action.AppName)
		} else {
			for refIndex, ref := range actionRefs {
				if ref.Name == action.AppName {
					if !ArrayContains(ref.ActionName, action.Name) {
						actionRefs[refIndex].ActionName = append(actionRefs[refIndex].ActionName, action.Name)
					}
				}
			}
		}
	}

	for _, trigger := range workflow.Triggers {
		if !ArrayContains(triggers, trigger.TriggerType) {
			triggers = append(triggers, trigger.TriggerType)
		}
	}

	if workflow.WorkflowType != "" {
		record.Type = workflow.WorkflowType
	}

	record.Name = workflow.Name
	record.Description = workflow.Description
	record.UsecaseIds = workflow.UsecaseIds
	record.Triggers = triggers
	record.Actions = actions
	record.TriggerAmount = len(triggers)
	record.ActionAmount = len(actions)
	record.Tags = workflow.Tags
	record.Categories = categories
	record.ActionReferences = actionRefs

	record.Priority = GetWorkflowPriority(workflow)
	record.Validated = workflow.Validated

	records := []AlgoliaSearchWorkflow{
		record,
	}

	//log.Printf("[WARNING] Returning before upload with data %#v", records)
	//return records[0].ObjectID, nil
	//return "", errors.New("Not prepared yet!")

	_, err = algoliaIndex.SaveObjects(records)
	if err != nil {
		log.Printf("[WARNING] Algolia Object update err: %s", err)
		return "", err
	}

	return workflow.ID, nil
}

// Returns an error if the users' org is over quota
func ValidateExecutionUsage(ctx context.Context, orgId string) (*Org, error) {
	if len(orgId) == 0 {
		return nil, errors.New("Org ID is empty")
	}

	org, err := GetOrg(ctx, orgId)
	if err != nil {
		return org, errors.New(fmt.Sprintf("Failed getting the organization %s: %s", orgId, err))
	}

	orgStats, err := GetOrgStatistics(ctx, orgId)
	if err != nil {
		log.Printf("[WARNING] Failed getting org statistics for %s (%s): %s", org.Name, org.Id, err)
		return org, errors.New(fmt.Sprintf("Failed getting the organization statistics %s: %s", orgId, err))
	}

	if org.Billing.AppRunsHardLimit > 0 && orgStats.MonthlyAppExecutions > org.Billing.AppRunsHardLimit {
		log.Printf("[WARNING] Org %s (%s) has exceeded the app runs hard limit (%d/%d)", org.Name, org.Id, orgStats.MonthlyAppExecutions, org.Billing.AppRunsHardLimit)

		return org, errors.New(fmt.Sprintf("Org %s (%s) has exceeded the app runs hard limit (%d/%d)", org.Name, org.Id, orgStats.MonthlyAppExecutions, org.Billing.AppRunsHardLimit))
	}

	validationOrg := org
	validationOrgStats := orgStats

	if len(org.CreatorOrg) > 0 {
		validationOrg, err = GetOrg(ctx, org.CreatorOrg)
		if err != nil {
			return org, errors.New(fmt.Sprintf("Failed getting the creator organization %s: %s", org.CreatorOrg, err))
		}
		validationOrgStats, err = GetOrgStatistics(ctx, org.CreatorOrg)
		if err != nil {
			log.Printf("[WARNING] Failed getting creator org statistics for %s (%s): %s ", validationOrg.Name, validationOrg.Id, err)
			return org, errors.New(fmt.Sprintf("Failed getting the creator organization statistics %s: %s", validationOrg.CreatorOrg, err))
		}

		log.Printf("[INFO] Using creator org %s (%s) for org %s (%s)", validationOrg.Name, validationOrg.Id, org.CreatorOrg, org.Id)
	}

	// Allows partners and POV users to run workflows without limits
	if validationOrg.LeadInfo.POV || validationOrg.LeadInfo.Internal || validationOrg.LeadInfo.IntegrationPartner || validationOrg.LeadInfo.TechPartner || validationOrg.LeadInfo.DistributionPartner || validationOrg.LeadInfo.ServicePartner {
		return validationOrg, nil
	}

	// If enterprise customer then don't block them
	if validationOrg.LeadInfo.Customer && validationOrg.SyncFeatures.AppExecutions.Limit >= 300000 {
		return validationOrg, nil
	}

	totalAppExecutions := validationOrgStats.MonthlyAppExecutions + validationOrgStats.MonthlyChildAppExecutions

	if totalAppExecutions >= validationOrg.SyncFeatures.AppExecutions.Limit {
		log.Printf("[WARNING] Org %s (%s) has exceeded the monthly app executions limit (%d/%d)", validationOrg.Name, validationOrg.Id, totalAppExecutions, validationOrg.SyncFeatures.AppExecutions.Limit)
		return validationOrg, errors.New(fmt.Sprintf("Org %s (%s) has exceeded the monthly app executions limit (%d/%d)", validationOrg.Name, validationOrg.Id, totalAppExecutions, validationOrg.SyncFeatures.AppExecutions.Limit))
	}

	log.Printf("[INFO] Org %s (%s) has %d/%d app executions this month", validationOrg.Name, validationOrg.Id, totalAppExecutions, validationOrg.SyncFeatures.AppExecutions.Limit)

	return validationOrg, nil
}

func RedirectUserRequest(w http.ResponseWriter, req *http.Request) {
	if project.Environment == "cloud" && gceProject == "shuffler" {
		log.Printf("[ERROR] Recursive RedirectRequest for %s", req.RequestURI)
		w.WriteHeader(400)
		w.Write([]byte(`{"success": false, "reason": "Recursive redirect request detected"}`))
		return
	}

	proxyScheme := "https"
	proxyHost := fmt.Sprintf("shuffler.io")
	httpClient := &http.Client{
		Timeout: 120 * time.Second,
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Printf("[ERROR] Issue in SSR body proxy: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//req.Body = ioutil.NopCloser(bytes.NewReader(body))
	url := fmt.Sprintf("%s://%s%s", proxyScheme, proxyHost, req.RequestURI)

	if debug {
		log.Printf("[DEBUG] Request (%s) request URL: %s. More: %s", req.Method, url, req.URL.String())
	}

	proxyReq, err := http.NewRequest(req.Method, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[ERROR] Failed handling proxy request: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// We may want to filter some headers, otherwise we could just use a shallow copy
	proxyReq.Header = make(http.Header)
	for h, val := range req.Header {
		proxyReq.Header[h] = val
	}

	newresp, err := httpClient.Do(proxyReq)
	if err != nil {
		log.Printf("[ERROR] Issue in SSR newresp for %s - should retry: %s", url, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	defer newresp.Body.Close()
	urlbody, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	//log.Printf("RESP: %s", urlbody)
	for key, value := range newresp.Header {
		//log.Printf("%s %s", key, value)
		for _, item := range value {
			w.Header().Set(key, item)
		}
	}

	w.WriteHeader(newresp.StatusCode)
	w.Write(urlbody)

	// Need to clear cache in case user gets updated in db
	// with a new session and such. This only forces a new search,
	// and shouldn't get them logged out
	c, err := req.Cookie("session_token")
	if err != nil {
		c, err = req.Cookie("__session")
	}

	// FIXME: What is the point of this cookie checking?
	if err == nil {
		ctx := GetContext(req)
		DeleteCache(ctx, fmt.Sprintf("session_%s", c.Value))
	}
}

// Checks if a specific user should have "self" access to a creator user
// A creator user can be both a user and an org, so this got a bit tricky
func CheckCreatorSelfPermission(ctx context.Context, requestUser, creatorUser User, algoliaUser *AlgoliaSearchCreator) bool {
	if project.Environment != "cloud" {
		return false
	}

	if creatorUser.Id == requestUser.Id {
		return true
	} else {
		for _, user := range algoliaUser.Synonyms {
			if user == requestUser.Id {
				return true
			}
		}

		if algoliaUser.IsOrg {
			log.Printf("[AUDIT] User %s (%s) is an org. Checking if the current user should have access.", algoliaUser.Username, algoliaUser.ObjectID)
			// Get the org and check
			org, err := GetOrgByCreatorId(ctx, algoliaUser.ObjectID)
			if err != nil {
				log.Printf("[WARNING] Couldn't find org for creator %s (%s): %s", algoliaUser.Username, algoliaUser.ObjectID, err)
				return false
			}

			log.Printf("[AUDIT] Found org %s (%s) for creator %s (%s)", org.Name, org.Id, algoliaUser.Username, algoliaUser.ObjectID)
			for _, user := range org.Users {
				if user.Id == requestUser.Id {
					if user.Role == "admin" {
						return true
					}

					break
				}
			}

		}
	}

	return false
}

// Uploads updates for a workflow to a specific file on git
func SetGitWorkflow(ctx context.Context, workflow Workflow, org *Org) error {
	if workflow.BackupConfig.UploadRepo != "" || workflow.BackupConfig.UploadBranch != "" || workflow.BackupConfig.UploadUsername != "" || workflow.BackupConfig.UploadToken != "" {
		//log.Printf("\n\n\n[DEBUG] Using workflow backup config for org %s (%s)\n\n\n", org.Name, org.Id)

		org.Defaults.WorkflowUploadRepo = workflow.BackupConfig.UploadRepo
		org.Defaults.WorkflowUploadBranch = workflow.BackupConfig.UploadBranch
		org.Defaults.WorkflowUploadUsername = workflow.BackupConfig.UploadUsername
		org.Defaults.WorkflowUploadToken = workflow.BackupConfig.UploadToken

		// FIXME: Decrypt here
		if workflow.BackupConfig.TokensEncrypted {
			log.Printf("[DEBUG] Should realtime decrypt token for org %s (%s)", org.Name, org.Id)
			org.Defaults.TokensEncrypted = true
		} else {
			org.Defaults.TokensEncrypted = false
		}
	}

	if org.Defaults.TokensEncrypted == true {
		log.Printf("[DEBUG] Decrypting token for org %s (%s)", org.Name, org.Id)

		parsedKey := fmt.Sprintf("%s_upload_token", org.Id)
		newValue, err := HandleKeyDecryption([]byte(org.Defaults.WorkflowUploadToken), parsedKey)
		if err != nil {
			log.Printf("[ERROR] Failed decrypting token for org %s (%s): %s", org.Name, org.Id, err)
		} else {
			org.Defaults.WorkflowUploadToken = string(newValue)
		}

		parsedKey = fmt.Sprintf("%s_upload_username", org.Id)
		newValue, err = HandleKeyDecryption([]byte(org.Defaults.WorkflowUploadUsername), parsedKey)
		if err != nil {
			log.Printf("[ERROR] Failed decrypting username for org %s (%s): %s", org.Name, org.Id, err)
		} else {
			org.Defaults.WorkflowUploadUsername = string(newValue)
		}

		parsedKey = fmt.Sprintf("%s_upload_repo", org.Id)
		newValue, err = HandleKeyDecryption([]byte(org.Defaults.WorkflowUploadRepo), parsedKey)
		if err != nil {
			log.Printf("[ERROR] Failed decrypting repo for org %s (%s): %s", org.Name, org.Id, err)
		} else {
			org.Defaults.WorkflowUploadRepo = string(newValue)
		}

		parsedKey = fmt.Sprintf("%s_upload_branch", org.Id)
		newValue, err = HandleKeyDecryption([]byte(org.Defaults.WorkflowUploadBranch), parsedKey)
		if err != nil {
			log.Printf("[ERROR] Failed decrypting branch for org %s (%s): %s", org.Name, org.Id, err)
		} else {
			org.Defaults.WorkflowUploadBranch = string(newValue)
		}

		log.Printf("[DEBUG] Decrypted token for org %s (%s): %s", org.Name, org.Id, newValue)
	}

	if len(org.Defaults.WorkflowUploadBranch) == 0 {
		org.Defaults.WorkflowUploadBranch = "master"
	}

	if org.Defaults.WorkflowUploadRepo == "" || org.Defaults.WorkflowUploadToken == "" {
		//log.Printf("[DEBUG] Missing Repo/Token during Workflow backup upload for org %s (%s)", org.Name, org.Id)
		//return errors.New("Missing repo or token")
		return nil
	}

	org.Defaults.WorkflowUploadRepo = strings.TrimSpace(org.Defaults.WorkflowUploadRepo)
	if strings.HasPrefix(org.Defaults.WorkflowUploadRepo, "https://") {
		org.Defaults.WorkflowUploadRepo = strings.Replace(org.Defaults.WorkflowUploadRepo, "https://", "", 1)
		org.Defaults.WorkflowUploadRepo = strings.Replace(org.Defaults.WorkflowUploadRepo, "http://", "", 1)
	}

	if strings.HasSuffix(org.Defaults.WorkflowUploadRepo, ".git") {
		org.Defaults.WorkflowUploadRepo = strings.TrimSuffix(org.Defaults.WorkflowUploadRepo, ".git")
	}

	//log.Printf("[DEBUG] Uploading workflow %s to repo %s for org %s (%s)", workflow.ID, org.Defaults.WorkflowUploadRepo, org.Name, org.Id)

	// Remove images
	workflow.Image = ""
	for actionIndex, _ := range workflow.Actions {
		workflow.Actions[actionIndex].LargeImage = ""
		workflow.Actions[actionIndex].SmallImage = ""
	}

	for triggerIndex, _ := range workflow.Triggers {
		workflow.Triggers[triggerIndex].LargeImage = ""
		workflow.Triggers[triggerIndex].SmallImage = ""
	}

	// remove github backup info
	workflow.BackupConfig = BackupConfig{}

	// Use git to upload the workflow.
	workflowData, err := json.MarshalIndent(workflow, "", "  ")
	if err != nil {
		log.Printf("[ERROR] Failed marshalling workflow %s (%s) for git upload: %s", workflow.Name, workflow.ID, err)
		return err
	}

	commitMessage := fmt.Sprintf("User '%s' updated workflow '%s' with status '%s'", workflow.UpdatedBy, workflow.Name, workflow.Status)
	urlEncodedPassword := url.QueryEscape(org.Defaults.WorkflowUploadToken)
	location := fmt.Sprintf("https://%s:%s@%s.git", org.Defaults.WorkflowUploadUsername, urlEncodedPassword, org.Defaults.WorkflowUploadRepo)

	newRepoName := strings.Replace(strings.Replace(location, org.Defaults.WorkflowUploadToken, "****", -1), urlEncodedPassword, "****", -1)
	log.Printf("[DEBUG] Uploading workflow %s to repo: %s", workflow.ID, newRepoName)

	fs := memfs.New()
	if len(workflow.Status) == 0 {
		workflow.Status = "test"
	}

	//filePath := fmt.Sprintf("/%s/%s.json", workflow.Status, workflow.ID)
	filePath := fmt.Sprintf("%s/%s/%s_%s.json", workflow.ExecutingOrg.Id, workflow.Status, strings.ReplaceAll(workflow.Name, " ", "-"), workflow.ID)

	// Specify the file path within the repository
	repo, err := git.Clone(memory.NewStorage(), fs, &git.CloneOptions{
		URL: location,
	})
	if err != nil {
		newErr := strings.ReplaceAll(err.Error(), org.Defaults.WorkflowUploadToken, "****")
		newErr = strings.ReplaceAll(newErr, urlEncodedPassword, "****")

		log.Printf("[ERROR] Error cloning repo '%s' (workflow backup): %s", newRepoName, newErr)
		return err
	}

	// Initialize a new Git repository in memory
	w := &git.Worktree{}

	// Create a new commit with the in-memory file
	w, err = repo.Worktree()
	if err != nil {
		newErr := strings.ReplaceAll(err.Error(), org.Defaults.WorkflowUploadToken, "****")
		newErr = strings.ReplaceAll(newErr, urlEncodedPassword, "****")

		log.Printf("[ERROR] Error getting worktree for repo '%s' (2): %s", newRepoName, newErr)
		return err
	}

	// Write the byte blob to the in-memory file system
	file, err := fs.Create(filePath)
	if err != nil {
		newErr := strings.ReplaceAll(err.Error(), org.Defaults.WorkflowUploadToken, "****")

		log.Printf("[ERROR] Creating git file: %v", newErr)
		return err
	}

	defer file.Close()
	//_, err = io.Copy(file, bytes.NewReader(workflowData))
	_, err = io.Copy(file, bytes.NewReader(workflowData))
	if err != nil {
		log.Printf("[ERROR] Writing data to git file: %v", err)
		return err
	}

	// Add the file to the staging area
	_, err = w.Add(filePath)
	if err != nil {
		log.Printf("[ERROR] Error adding file to git staging area (2): %s", err)
		return err
	}

	// Commit the changes
	_, err = w.Commit(commitMessage, &git.CommitOptions{
		Author: &object.Signature{
			Name:  org.Defaults.WorkflowUploadUsername,
			Email: "",
			When:  time.Now(),
		},
	})
	if err != nil {
		log.Printf("[ERROR] Committing git changes: %v (2)", err)
		return err
	}

	//log.Printf("[DEBUG] Commit Hash: %s", commit)

	// Push the changes to a remote repository (replace URL with your repository URL)
	// fmt.Sprintf("refs/heads/%s:refs/heads/%s", org.Defaults.WorkflowUploadBranch, org.Defaults.WorkflowUploadBranch)},
	ref := fmt.Sprintf("refs/heads/%s:refs/heads/%s", org.Defaults.WorkflowUploadBranch, org.Defaults.WorkflowUploadBranch)
	err = repo.Push(&git.PushOptions{
		RemoteName: "origin",
		RefSpecs:   []config.RefSpec{config.RefSpec(ref)},
		RemoteURL:  location,
	})
	if err != nil {
		log.Printf("[ERROR] Change git Push issue: %v (2)", err)
		return err
	}

	log.Printf("[DEBUG] File uploaded successfully to '%s'!", newRepoName)

	return nil
}

// Creates osfs from folderpath with a basepath as directory base
func CreateFs(basepath, pathname string) (billy.Filesystem, error) {
	log.Printf("[INFO] MemFS base: %s, pathname: %s", basepath, pathname)

	fs := memfs.New()
	err := filepath.Walk(pathname,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if strings.Contains(path, ".git") {
				return nil
			}

			// Fix the inner path here
			newpath := strings.ReplaceAll(path, pathname, "")
			fullpath := fmt.Sprintf("%s%s", basepath, newpath)
			switch mode := info.Mode(); {
			case mode.IsDir():
				err = fs.MkdirAll(fullpath, 0644)
				if err != nil {
					log.Printf("Failed making folder: %s", err)
				}
			case mode.IsRegular():
				srcData, err := ioutil.ReadFile(path)
				if err != nil {
					log.Printf("Src error: %s", err)
					return err
				}

				dst, err := fs.Create(fullpath)
				if err != nil {
					log.Printf("Dst error: %s", err)
					return err
				}

				_, err = dst.Write(srcData)
				if err != nil {
					log.Printf("Dst write error: %s", err)
					return err
				}
			}

			return nil
		})

	return fs, err
}

func loadAppConfigFromMain(fileId string) {
	// Send request to /api/v1/apps/{fileId}/config
	// Parse out the config and add it to the database
	ctx := context.Background()

	app, err := GetApp(ctx, fileId, User{}, false)
	if err == nil && len(app.Name) > 0 && len(app.ID) > 0 {
		log.Printf("[INFO] Found app %s (%s) for config loading. Running cross-region DOWNLOAD shuffler.io->local", app.Name, app.ID)
	}

	app.ID = fileId

	backendHost := fmt.Sprintf("https://shuffler.io")
	appApi := fmt.Sprintf("%s/api/v1/apps/%s/config", backendHost, fileId)
	client := &http.Client{}
	req, err := http.NewRequest(
		"GET",
		appApi,
		nil,
	)

	if err != nil {
		log.Printf("[ERROR] Failed creating request for app config: %s", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed getting app config: %s", err)
		return
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Printf("[ERROR] Failed getting app config for ID %s: %d", fileId, resp.StatusCode)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading app config: %s", err)
		return
	}

	newApp := AppParser{}
	err = json.Unmarshal(body, &newApp)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshaling app config: %s", err)
		return
	}

	//log.Printf("[INFO] Got app config: %s", string(body))
	if !newApp.Success {
		log.Printf("[ERROR] No success in app config for id %s", fileId)
		return
	}

	if len(newApp.App) == 0 {
		log.Printf("[ERROR] No app found for id %s", app.ID)
	} else {

		err = json.Unmarshal(newApp.App, &app)
		if err != nil {
			log.Printf("[ERROR] Failed unmarshaling app for id %s: %s", app.ID, err)
			return
		}

		err = SetWorkflowAppDatastore(ctx, *app, app.ID)
		if err != nil {
			log.Printf("[ERROR] Failed saving app for id %s: %s", app.ID, err)
		}
	}

	if len(newApp.OpenAPI) == 0 {
		log.Printf("[ERROR] No openapi found for id %s", app.ID)
	} else {
		// Save the data to the database with the ParsedOpenApi struct
		parsedOpenApi := ParsedOpenApi{}
		err = json.Unmarshal(newApp.OpenAPI, &parsedOpenApi)
		if err != nil {
			log.Printf("[ERROR] Failed unmarshaling openapi for id %s: %s", app.ID, err)
			return
		}

		err = SetOpenApiDatastore(ctx, parsedOpenApi.ID, parsedOpenApi)
		if err != nil {
			log.Printf("[ERROR] Failed saving openapi for id %s: %s", app.ID, err)
		}

		// FIXME: Send it to get built as well as cloud function
		// What is the function for this? Maybe just send localhost/api/ request?
		// Run verify openapi here (?)

		baseurl := "http://localhost:5002"
		if os.Getenv("BASE_URL") != "" {
			baseurl = os.Getenv("BASE_URL")
		}

		if os.Getenv("SHUFFLE_CLOUDRUN_URL") != "" {
			baseurl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
		}

		fullUrl := fmt.Sprintf("%s/api/v1/verify_swagger", baseurl)
		req, err := http.NewRequest(
			"POST",
			fullUrl,
			bytes.NewBuffer(newApp.OpenAPI),
		)

		if err != nil {
			log.Printf("[ERROR] Failed creating request for openapi verification: %s", err)
			return
		}

		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[ERROR] Failed verifying openapi: %s", err)
			return
		}

		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			log.Printf("[ERROR] Failed building openapi for ID %s: %d", fileId, resp.StatusCode)
			return
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed reading openapi verification: %s", err)
			return
		}

		log.Printf("[INFO] OpenAPI build: %s", string(body))
	}
}

// Also deactivates. It's a toggle for off and on.
func ActivateWorkflowApp(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get active apps: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to activate workflow app (shared): %s (%s)", user.Username, user.Id)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	ctx := GetContext(request)
	location := strings.Split(request.URL.String(), "/")
	var fileId string
	activate := true
	shouldDistributeToLocation := false
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
		if strings.ToLower(location[5]) == "deactivate" {
			activate = false
		}

		if strings.ToLower(location[5]) == "distribute" {
			shouldDistributeToLocation = true
		}
	}

	app, err := GetApp(ctx, fileId, user, false)
	if err != nil {
		appName := request.URL.Query().Get("app_name")
		appVersion := request.URL.Query().Get("app_version")

		if len(appName) > 0 && len(appVersion) > 0 {
			apps, err := FindWorkflowAppByName(ctx, appName)
			//log.Printf("[INFO] Found %d apps for %s", len(apps), appName)
			if err != nil || len(apps) == 0 {
				log.Printf("[WARNING] Error getting app from name '%s' (app config): %s", appName, err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "App doesn't exist"}`))
				return
			}

			selectedApp := WorkflowApp{}
			for _, app := range apps {
				if !app.Sharing && !app.Public {
					continue
				}

				if app.Name == appName {
					selectedApp = app
				}

				if app.Name == appName && app.AppVersion == appVersion {
					selectedApp = app
				}
			}

			app = &selectedApp
		} else {
			log.Printf("[WARNING] Error getting app with ID %s (app config): %s", fileId, err)

			// Automatic propagation to cloud regions
			if project.Environment == "cloud" && gceProject != "shuffler" {
				app, err := HandleAlgoliaAppSearch(ctx, fileId)
				if err == nil {
					// this means that the app exists. so, let's
					// ask our propagator to proagate it further.
					log.Printf("[INFO] Found apps %s - %s in algolia", app.Name, app.ObjectID)

					if app.ObjectID != fileId {
						log.Printf("[WARNING] App %s doesn't exist in algolia", fileId)
						resp.WriteHeader(401)
						resp.Write([]byte(`{"success": false, "reason": "App doesn't exist"}`))
						return
					}
					// i can in theory, run this without using goroutines
					// and then recursively call the same function. but that
					// would make this request way too long.
					go func() {
						err = propagateApp(fileId, false)
						if err != nil {
							log.Printf("[WARNING] Error propagating app %s - %s: %s", app.Name, app.ObjectID, err)
						} else {
							log.Printf("[INFO] Propagated app %s - %s. Sending request again!", app.Name, app.ObjectID)
						}
					}()

					resp.WriteHeader(202)
					resp.Write([]byte(`{"success": false, "reason": "Taking care of some magic. Please try activation again in a few seconds!"}`))
					return
				} else {
					log.Printf("[WARNING] Error getting app %s (algolia): %s", appName, err)
				}
			} else if project.Environment == "cloud" && gceProject == "shuffler" {
				// Automatic deletion in the main region if the app doesn't exist
				if len(app.ID) == 0 {
					log.Printf("[INFO] Auto-Removing app %s from Algolia as it doesn't exist with the same ID anymore. Request source: %s (%s) in org %s (%s)", fileId, user.Username, user.Id, user.ActiveOrg.Name, user.ActiveOrg.Id)

					algoliaClient := os.Getenv("ALGOLIA_CLIENT")
					algoliaSecret := os.Getenv("ALGOLIA_SECRET")
					if len(algoliaClient) > 0 && len(algoliaSecret) > 0 {

						algClient := search.NewClient(algoliaClient, algoliaSecret)
						algoliaIndex := algClient.InitIndex("appsearch")
						_, err = algoliaIndex.DeleteObject(fileId)
						if err != nil {
							resp.WriteHeader(500)
							resp.Write([]byte(`{"success": false, "reason": "Failed removing the app from Algolia"}`))
							return
						}
					}
				}
			}

			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "App doesn't exist"}`))
			return
		}
	}

	if activate == false && app.ReferenceOrg == user.ActiveOrg.Id {
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Can't remove app from current org as it is the owner org."}`))
		return
	}

	org := &Org{}
	added := false
	if app.Sharing || app.Public || !activate {
		org, err = GetOrg(ctx, user.ActiveOrg.Id)
		if err == nil {
			if len(org.ActiveApps) > 150 {
				// No reason for it to be this big. Arbitrarily reducing.
				same := []string{}
				samecnt := 0
				for _, activeApp := range org.ActiveApps {
					if ArrayContains(same, activeApp) {
						samecnt += 1
						continue
					}

					same = append(same, activeApp)
				}

				added = true
				//log.Printf("Same: %d, total uniq: %d", samecnt, len(same))
				org.ActiveApps = org.ActiveApps[len(org.ActiveApps)-100 : len(org.ActiveApps)-1]
			}

			if activate {
				if !ArrayContains(org.ActiveApps, app.ID) {
					org.ActiveApps = append(org.ActiveApps, app.ID)
					added = true
				}
			} else {
				// Remove from the array
				newActiveApps := []string{}
				for _, activeApp := range org.ActiveApps {
					if activeApp == app.ID {
						continue
					}

					newActiveApps = append(newActiveApps, activeApp)
				}

				org.ActiveApps = newActiveApps
				added = true
			}

			if added {
				err = SetOrg(ctx, *org, org.Id)
				if err != nil {
					log.Printf("[WARNING] Failed setting org when autoadding apps on save: %s", err)
				} else {
					addRemove := "Added"
					if !activate {
						addRemove = "Removed"
					}

					log.Printf("[INFO] %s public app %s (%s) to/from org %s (%s). Activated apps: %d", addRemove, app.Name, app.ID, user.ActiveOrg.Name, user.ActiveOrg.Id, len(org.ActiveApps))
					DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
					DeleteCache(ctx, fmt.Sprintf("apps_%s", user.ActiveOrg.Id))

					if project.Environment == "cloud" && gceProject != "shuffler" {
						// propagate org.ActiveApps to the main region
						go func() {
							// wait for a second before propagating again
							log.Printf("[INFO] Propagating org %s after sleeping for a second!", user.ActiveOrg.Id)
							time.Sleep(1 * time.Second)
							err = propagateOrg(*org, true)
							if err != nil {
								log.Printf("[WARNING] Error propagating org %s: %s", user.ActiveOrg.Id, err)
							}
						}()
					}

				}
			}
		}
	} else {
		log.Printf("[WARNING] User is trying to activate %s which is NOT a public app", app.Name)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if shouldDistributeToLocation {
		// Distribute to runtime Locations
		allEnvironments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("[ERROR] Failed getting environments for org %s: %s", user.ActiveOrg.Id, err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed getting environments"}`))
			return
		}

		relevantEnvironments := []Environment{}
		for _, env := range allEnvironments {
			if strings.ToLower(env.Type) == "cloud" {
				continue
			}

			if env.Archived {
				continue
			}

			relevantEnvironments = append(relevantEnvironments, env)
		}

		if len(relevantEnvironments) == 0 {
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "No relevant environments"}`))
			return
		}

		appName := fmt.Sprintf("%s_%s", strings.ToLower(strings.ReplaceAll(app.Name, " ", "-")), app.AppVersion)
		if project.Environment == "cloud" {
			if app.Public == true {
			} else {
				appName = fmt.Sprintf("%s_%s", strings.ToLower(strings.ReplaceAll(app.Name, " ", "-")), app.ID)
			}
		}

		for _, env := range relevantEnvironments {
			//log.Printf("[INFO] Distributing app %s to environment %s", app.Name, env.Name)
			request := ExecutionRequest{
				Type:              "DOCKER_IMAGE_DOWNLOAD",
				ExecutionId:       uuid.NewV4().String(),
				ExecutionArgument: fmt.Sprintf("frikky/shuffle:%s", appName),
				Priority:          11,
			}

			parsedId := fmt.Sprintf("%s_%s", strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(env.Name, " ", "-"), "_", "-")), env.OrgId)
			err = SetWorkflowQueue(ctx, request, parsedId)
			if err != nil {
				log.Printf("[ERROR] Failed setting workflow queue for env: %s", err)
				continue
			}
		}

		resp.WriteHeader(200)
		resp.Write([]byte(`{"success": true, "reason": "Re-download request sent to all relevant environments"}`))
		return
	}

	if activate {
		log.Printf("[DEBUG] App %s (%s) activated for org %s by user %s (%s). Active apps: %d. Already existed: %t", app.Name, app.ID, user.ActiveOrg.Id, user.Username, user.Id, len(org.ActiveApps), !added)
	} else {
		log.Printf("[DEBUG] App %s (%s) deactivated for org %s by user %s (%s). Active apps: %d. Already existed: %t", app.Name, app.ID, user.ActiveOrg.Id, user.Username, user.Id, len(org.ActiveApps), !added)
	}

	DeleteCache(ctx, fmt.Sprintf("apps_%s", user.ActiveOrg.Id))
	DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
	DeleteCache(ctx, "all_apps")
	DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-100"))
	DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-500"))
	DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-1000"))

	// If onprem, it should autobuild the container(s) from here
	if project.Environment == "cloud" && gceProject != "shuffler" {
		go loadAppConfigFromMain(fileId)

		RedirectUserRequest(resp, request)
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

// For replicating HTTP request from schedule user
func HandleSuborgScheduleRun(request *http.Request, workflow *Workflow) {
	ctx := context.Background()
	if len(workflow.SuborgDistribution) == 0 {
		log.Printf("[WARNING] No suborgs to run for workflow %s", workflow.ID)
		return
	}

	// Finding first one.
	originalTriggerId := ""
	for _, trigger := range workflow.Triggers {
		if trigger.TriggerType == "SCHEDULE" {
			originalTriggerId = trigger.ID
			break
		}
	}

	if len(originalTriggerId) == 0 {
		return
	}

	// 1. Get child workflows of workflow
	// 2. Map to the right ones
	childWorkflows, err := ListChildWorkflows(ctx, workflow.ID)
	if err != nil {
		log.Printf("[ERROR] Failed getting child workflows for parent workflow %s: %s", workflow.ID, err)
		return
	}

	client := http.Client{}
	for _, childWorkflow := range childWorkflows {
		if childWorkflow.ID == workflow.ID {
			continue
		}

		if childWorkflow.OrgId == workflow.OrgId {
			continue
		}

		// Check if the OrgId is still in the workflow.Sub
		found := false
		for _, suborg := range workflow.SuborgDistribution {
			if childWorkflow.OrgId == suborg {
				found = true
				break
			}
		}

		if !found {
			continue
		}

		// Ensuring the trigger still exists in the child
		found = false
		for _, trigger := range childWorkflow.Triggers {
			if trigger.ReplacementForTrigger == originalTriggerId {
				found = true
				break
			}
		}

		if !found {
			continue
		}

		log.Printf("[DEBUG] Should be running %s schedule suborg workflows", childWorkflow.ID)
		go func(client http.Client, request *http.Request, childWorkflow Workflow) {
			baseurl := "https://shuffler.io"
			if os.Getenv("BASE_URL") != "" {
				baseurl = os.Getenv("BASE_URL")
			}

			if os.Getenv("SHUFFLE_CLOUDRUN_URL") != "" {
				baseurl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
			}

			body, err := ioutil.ReadAll(request.Body)
			if err != nil {
				log.Printf("[ERROR] Failed reading body from schedule request: %s", err)
				return
			}

			request.Body = io.NopCloser(bytes.NewBuffer(body))
			formattedUrl := fmt.Sprintf("%s/api/v1/workflows/%s/run", baseurl, childWorkflow.ID)
			req, err := http.NewRequest(
				"POST",
				formattedUrl,
				bytes.NewBuffer(body),
			)

			if err != nil {
				log.Printf("[WARNING] Failed mapping child workflow schedule: %s", err)
				return
			}

			for key, value := range request.Header {
				req.Header.Set(key, value[0])
			}

			newresp, err := client.Do(req)
			if err != nil {
				log.Printf("[ERROR] Failed running child workflow schedule: %s", err)
				return
			}

			defer newresp.Body.Close()
			if newresp.StatusCode == 200 {
				log.Printf("[DEBUG] Started suborg workflow from schedule. Parent: %s. Child: %s", childWorkflow.ParentWorkflowId, childWorkflow.ID)
			} else {
				respBody, err := ioutil.ReadAll(newresp.Body)
				if err != nil {
					log.Printf("[ERROR] Failed to read body from failed newresp")
					return
				}

				log.Printf("[ERROR] Failed to start suborg workflow from schedule with status %d. Parent: %s. Child: %s. Raw Body: %s", newresp.StatusCode, childWorkflow.ParentWorkflowId, childWorkflow.ID, string(respBody))
			}

		}(client, request, childWorkflow)
	}
}

// This is JUST for Singul actions with AI agents.
// As AI Agents can have multiple types of runs, this could change every time.
func RunAgentDecisionSingulActionHandler(execution WorkflowExecution, decision AgentDecision) ([]byte, string, error) {
	debugUrl := ""
	log.Printf("[DEBUG][%s] Running agent decision action %s with tool %s", execution.ExecutionId, decision.Action, decision.Tool)

	baseUrl := "https://shuffler.io"
	if os.Getenv("BASE_URL") != "" {
		baseUrl = os.Getenv("BASE_URL")
	}

	if os.Getenv("SHUFFLE_CLOUDRUN_URL") != "" {
		baseUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
	}

	url := fmt.Sprintf("%s/api/v1/apps/categories/run?authorization=%s&execution_id=%s", baseUrl, execution.Authorization, execution.ExecutionId)

	// Change timeout to be 30 seconds (just in case)
	client := GetExternalClient(url)
	client.Timeout = 60 * time.Second

	parsedFields := TranslateBadFieldFormats(decision.Fields)
	parsedAction := CategoryAction{
		AppName: decision.Tool,
		Label:   decision.Action,

		Fields: parsedFields,

		SkipWorkflow: true,
	}

	marshalledAction, err := json.Marshal(parsedAction)
	if err != nil {
		log.Printf("[ERROR][%s] Failed marshalling action in agent decision: %s", execution.ExecutionId, err)
		return []byte{}, debugUrl, err
	}

	req, err := http.NewRequest(
		"POST",
		url,
		bytes.NewBuffer(marshalledAction),
	)

	if err != nil {
		log.Printf("[ERROR][%s] Failed creating request for agent decision: %s", execution.ExecutionId, err)
		return []byte{}, debugUrl, err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR][%s] Failed running agent decision: %s", execution.ExecutionId, err)
		return []byte{}, debugUrl, err
	}

	for key, value := range resp.Header {
		if key != "X-Debug-Url" {
			continue
		}

		/*
			if !strings.HasPrefix(key, "X-") {
				continue
			}

			// Don't care about raw response
			if key == "X-Raw-Response-Url" || key == "X-Apprun-Url" {
				continue
			}
		*/

		foundValue := ""
		for _, val := range value {
			if len(val) > 0 {
				foundValue = val
				break
			}
		}

		debugUrl = foundValue
		/*
			returnHeaders = append(returnHeaders, Valuereplace{
				Key: key,
				Value: foundValue,
			})
		*/
	}

	originalBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR][%s] Failed reading body from agent decision: %s", execution.ExecutionId, err)
		return []byte{}, debugUrl, err
	}

	body := originalBody
	defer resp.Body.Close()

	log.Printf("\n\n\n[DEBUG][%s] Agent decision response: %s\n\n\n", execution.ExecutionId, string(body))
	// Try to map it into SchemalessOutput and grab "RawResponse"
	outputMapped := SchemalessOutput{}
	err = json.Unmarshal(body, &outputMapped)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshalling agent decision response: %s", err)
		return body, debugUrl, err
	}

	if val, ok := outputMapped.RawResponse.(string); ok {
		body = []byte(val)
	} else if val, ok := outputMapped.RawResponse.([]byte); ok {
		body = val
	} else if val, ok := outputMapped.RawResponse.(map[string]interface{}); ok {
		marshalledRawResp, err := json.MarshalIndent(val, "", "  ")
		if err != nil {
			log.Printf("[ERROR][%s] Failed marshalling agent decision response: %s", execution.ExecutionId, err)
		} else {
			body = marshalledRawResp
		}
	} else if outputMapped.RawResponse == nil {
		// Do nothing
	} else {
		log.Printf("[ERROR][%s] FAILED MAPPING RAW RESP INTERfACE. TYPE: %T\n\n\n", execution.ExecutionId, outputMapped.RawResponse)
	}

	if resp.StatusCode != 200 {
		log.Printf("[ERROR][%s] Failed running agent decision with status %d: %s", execution.ExecutionId, resp.StatusCode, string(body))
		return body, debugUrl, errors.New(fmt.Sprintf("Failed running agent decision. Status code %d", resp.StatusCode))
	}

	if outputMapped.Success == false {
		return originalBody, debugUrl, errors.New("Failed running agent decision. Success false for Singul action")
	}

	/*
		agentOutput.Decisions[decisionIndex].RunDetails.RawResponse = string(rawResponse)
		agentOutput.Decisions[decisionIndex].RunDetails.DebugUrl = debugUrl
		if err != nil {
			log.Printf("[ERROR] Failed to run agent decision %#v: %s", decision, err)
			agentOutput.Decisions[decisionIndex].RunDetails.Status = "FAILED"

			resultMapping.Status = "FAILURE"
			resultMapping.CompletedAt = time.Now().Unix()
			agentOutput.CompletedAt = time.Now().Unix()
		} else {
			agentOutput.Decisions[decisionIndex].RunDetails.Status = "RUNNING"
		}
	*/

	return body, debugUrl, nil
}

// Runs an Agent Decision -> returns the result from it
// FIXME: Handle types: https://www.figma.com/board/V6Kg7KxbmuhIUyTImb20t1/Shuffle-AI-Agent-system?node-id=0-1&p=f&t=yIGaSXQYsYReR8cI-0
// This function should handle:
// 1. Running the decided action (user input, Singul, Workflow, Other Agent, Custom HTTP function)
// 2. Taking the result and sending (?) it back
// 3. Ensuring cache for an action is kept up to date
func RunAgentDecisionAction(execution WorkflowExecution, agentOutput AgentOutput, decision AgentDecision) {

	// Check if it's already ran or not
	ctx := context.Background()
	decisionId := fmt.Sprintf("agent-%s-%s", execution.ExecutionId, decision.RunDetails.Id)
	cache, err := GetCache(ctx, decisionId)
	if err == nil {
		foundDecision := AgentDecision{}
		cacheData := []byte(cache.([]uint8))
		err = json.Unmarshal(cacheData, &foundDecision)
		if err != nil {
			log.Printf("[WARNING][%s] Failed agent decision unmarshal (not critical): %s", execution.ExecutionId, err)
		}

		if foundDecision.RunDetails.StartedAt > 0 {
			log.Printf("[DEBUG][%s] Decision %s already has status '%s'. Returning as it's already started..", execution.ExecutionId, decision.RunDetails.Id, foundDecision.RunDetails.Status)
			return
		}
	}

	// Set it to this at the start
	if decision.RunDetails.StartedAt <= 0 {
		decision.RunDetails.StartedAt = time.Now().Unix()
	}

	decision.RunDetails.Status = "RUNNING"
	marshalledDecision, err := json.Marshal(decision)
	if err != nil {
		log.Printf("[ERROR][%s] Failed marshalling decision %s", execution.ExecutionId, decision.RunDetails.Id)
	}

	go SetCache(ctx, decisionId, marshalledDecision, 60)

	rawResponse, debugUrl, err := RunAgentDecisionSingulActionHandler(execution, decision)
	decision.RunDetails.RawResponse = string(rawResponse)
	decision.RunDetails.DebugUrl = debugUrl
	if err != nil {
		log.Printf("[ERROR][%s] Failed to run agent decision %#v: %s", execution.ExecutionId, decision, err)
		decision.RunDetails.Status = "FAILURE"

		if len(decision.RunDetails.RawResponse) == 0 {
			decision.RunDetails.RawResponse = fmt.Sprintf("Failed to start action. Raw Error: %s", err)
		}
	} else {
		decision.RunDetails.Status = "FINISHED"
	}

	// 1. Send this back as a result for an action
	// Then the action itself should decide if it's done or not.
	// Would it work to send JUST this decision result?
	// This could start the next step(s) automatically?
	decision.RunDetails.CompletedAt = time.Now().Unix()
	marshalledDecision, err = json.Marshal(decision)
	if err != nil {
		log.Printf("[ERROR][%s] Failed marshalling completed decision %s", execution.ExecutionId, decision.RunDetails.Id)
	}

	go SetCache(ctx, decisionId, marshalledDecision, 60)

	// 1. Send an /api/v1/streams request? Due to concurrency, I think this is the only way (?)
	// 2. On the streams API, make sure to:
	//     1. Check if the execution(s) are finished
	//     2. Send the result through AI again to check if it changes (?). Should there be a verdict here?
	//     3: Start the next steps of decisions after updates

	baseUrl := "https://shuffler.io"
	if os.Getenv("BASE_URL") != "" {
		baseUrl = os.Getenv("BASE_URL")
	}

	if os.Getenv("SHUFFLE_CLOUDRUN_URL") != "" {
		baseUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
	}

	//url := fmt.Sprintf("%s/api/v1/apps/categories/run?authorization=%s&execution_id=%s", baseUrl, execution.Authorization, execution.ExecutionId)
	url := fmt.Sprintf("%s/api/v1/streams", baseUrl)

	log.Printf("[DEBUG][%s] Sending agent decision response %s with status %s. Node: %s. URL: %s", execution.ExecutionId, decision.RunDetails.Id, decision.RunDetails.Status, agentOutput.NodeId, url)

	//?authorization=%s&execution_id=%s", baseUrl, execution.Authorization, execution.ExecutionId)
	client := GetExternalClient(url)

	parsedAction := ActionResult{
		ExecutionId:   execution.ExecutionId,
		Authorization: execution.Authorization,

		// Map in the node ID (action ID) and decision ID to set/continue the right result
		Action: Action{
			AppName: "AI Agent",
			Label:   fmt.Sprintf("Agent Decision %s", decision.RunDetails.Id),
			ID:      agentOutput.NodeId,
		},
		Status: fmt.Sprintf("agent_%s", decision.RunDetails.Id),
		Result: string(marshalledDecision),
	}

	marshalledAction, err := json.Marshal(parsedAction)
	if err != nil {
		log.Printf("[ERROR][%s] Failed marshalling action in agent decision: %s", execution.ExecutionId, err)
		return
	}

	req, err := http.NewRequest(
		"POST",
		url,
		bytes.NewBuffer(marshalledAction),
	)

	if err != nil {
		log.Printf("[ERROR][%s] Failed agent decision request creation: %s", execution.ExecutionId, err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR][%s] Failed sending agent decision result: %s", execution.ExecutionId, err)
		return
	}

	foundBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR][%s] Failed reading body from agent decision: %s", execution.ExecutionId, err)
		return
	}

	if resp.StatusCode != 200 {
		log.Printf("[ERROR][%s] Status %d for decision %s. Body: %s", execution.ExecutionId, resp.StatusCode, decision.RunDetails.Id, string(foundBody))
	}
}

func HandleCloudSyncAuthentication(resp http.ResponseWriter, request *http.Request) (SyncKey, error) {
	apikey := request.Header.Get("Authorization")
	if len(apikey) > 0 {
		apikey = strings.Replace(apikey, "  ", " ", -1)
		if !strings.HasPrefix(apikey, "Bearer ") {
			log.Printf("[WARNING] Apikey doesn't start with bearer: %s", apikey)
			return SyncKey{}, errors.New("No bearer token for authorization header")
		}

		apikeyCheck := strings.Split(apikey, " ")
		if len(apikeyCheck) != 2 {
			log.Printf("[WARNING] Invalid format for apikey: %s", apikeyCheck)
			return SyncKey{}, errors.New("Invalid format for apikey")
		}

		newApikey := apikeyCheck[1]
		ctx := GetContext(request)
		org, err := getSyncApikey(ctx, newApikey)
		if err != nil {
			log.Printf("[WARNING] Error in sync check: %s", err)
			return SyncKey{}, errors.New(fmt.Sprintf("Error finding key: %s", err))
		}

		return SyncKey{Apikey: newApikey, OrgId: org}, nil
	}

	return SyncKey{}, errors.New("Missing authentication")
}

// Fixes potential decision return or reference problems:
// {{list_tickets}} -> $list_tickets
// {{list_tickets[0].description}} -> $list_tickets.#0.description
// {{ticket.description}} -> $ticket.description
func TranslateBadFieldFormats(fields []Valuereplace) []Valuereplace {
	for fieldIndex, _ := range fields {
		field := fields[fieldIndex]
		if !strings.Contains(field.Value, "{{") || !strings.Contains(field.Value, "}}") {
			continue
		}

		// Used for testing
		//field.Value = strings.ReplaceAll(field.Value, `{{list_tickets[0].summary}}`, `{{ list_tickets[].summary }}`)

		// Regex match {{list_tickets[0].description}} and {{ list_tickets[].description }} and {{ list_tickets[:] }}
		//re := regexp.MustCompile(`{{\s*([a-zA-Z0-9_]+)(\[[0-9]+\])?(\.[a-zA-Z0-9_]+)?\s*}}`)
		re := regexp.MustCompile(`{{\s*([a-zA-Z0-9_]+)(\[[0-9]*\])?(\.[a-zA-Z0-9_]+)?\s*}}`)
		matches := re.FindAllStringSubmatch(field.Value, -1)
		if len(matches) == 0 {
			continue
		}

		stringBuild := "$"
		for _, match := range matches {

			for i, matchValue := range match {
				if i == 0 {
					continue
				}

				if i != 1 {
					if len(matchValue) > 0 && !strings.HasPrefix(matchValue, ".") {
						stringBuild += "."
					}
				}

				if strings.HasPrefix(matchValue, "[") && strings.HasSuffix(matchValue, "]") {
					// Find the formats:
					// [] -> #
					// [:] -> #
					// [0] -> #0
					// [0:1] -> #0-1
					// [0:] -> #0-max
					if matchValue == "[]" || matchValue == "[:]" {
						stringBuild += "#"
					} else if strings.Contains(matchValue, ":") {
						parts := strings.Split(matchValue, ":")
						if len(parts) == 2 {
							stringBuild += fmt.Sprintf("#%s-%s", parts[0], parts[1])
						} else {
							stringBuild += fmt.Sprintf("#%s-max", parts[0])
						}

						stringBuild += fmt.Sprintf("#%s", matchValue)
					} else {
						// Remove the brackets
						matchValue = strings.ReplaceAll(matchValue, "[", "")
						matchValue = strings.ReplaceAll(matchValue, "]", "")
						stringBuild += fmt.Sprintf("#%s", matchValue)
					}

					continue
				}

				stringBuild += matchValue
			}

			if len(match) > 1 {
				field.Value = strings.ReplaceAll(field.Value, match[0], stringBuild)
				fields[fieldIndex].Value = field.Value
				//log.Printf("VALUE: %#v", field.Value)
			}

			stringBuild = "$"
		}
	}

	return fields
}

func HandleOrborusFailover(ctx context.Context, request *http.Request, resp http.ResponseWriter, env *Environment) error {
	if len(env.Id) == 0 || len(env.Name) == 0 {

		resp.WriteHeader(400)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Environment ID or Name is not set"}`)))
		return errors.New("Environment ID or Name is not set")

		// Avoiding this onprem as it doesn't make sense
		//if project.Environment == "cloud" {
		//}  else {
		//	return nil
		//}
	}

	orborusLabel := request.Header.Get("x-orborus-label")
	var orboruserr error
	var orborusData OrborusStats
	body, bodyerr := ioutil.ReadAll(request.Body)
	if bodyerr == nil {
		orboruserr := json.Unmarshal(body, &orborusData)
		if orboruserr == nil {
			if time.Now().Unix() > env.Checkin+120 {
				if debug {
					log.Printf("[DEBUG] Failover orborus to %s", orborusData.Uuid)
				}

				env.OrborusUuid = orborusData.Uuid
			}

			if env.OrborusUuid != orborusData.Uuid && len(env.OrborusUuid) > 0 {
				resp.WriteHeader(409)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Orborus UUID mismatch. This means another Orborus (Leader) is already handling this Runtime Location queue."}`)))
				return errors.New("Orborus UUID mismatch")
			} else {
				//env.Checkin = time.Now().Unix()
			}
		}
	}

	timeNow := time.Now().Unix()
	if request.Method == "POST" {

		// Updates every 90 seconds~
		if time.Now().Unix() > env.Checkin+90 {
			env.RunningIp = GetRequestIp(request)

			// Orborus label = custom label for Orborus
			if len(orborusLabel) > 0 {
				env.RunningIp = orborusLabel
			}

			// Set the checkin cache
			if bodyerr == nil && orboruserr == nil {
				orborusData.RunningIp = env.RunningIp

				env.OrborusUuid = orborusData.Uuid

				marshalled, err := json.Marshal(orborusData)
				if err == nil {
					// Store for a full day. It's reset anyway in the UI at a certain point
					cacheKey := fmt.Sprintf("queueconfig-%s-%s", env.Name, env.OrgId)
					go SetCache(context.Background(), cacheKey, marshalled, 1440)
				}

				if orborusData.Swarm {
					env.Licensed = true
					env.RunType = "docker"
				}

				if orborusData.Kubernetes {
					env.RunType = "k8s"
				}

				orborusData.DataLake = env.DataLake
			}

			env.Checkin = timeNow
			err := SetEnvironment(ctx, env)
			if err != nil {
				log.Printf("[ERROR] Failed updating environment: %s", err)
			}
		}
	}

	if env.Archived {
		resp.WriteHeader(400)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't use archived environments. Make a new environment or restore the existing one."}`)))
		return errors.New("Environment is archived")
	}

	return nil
}
