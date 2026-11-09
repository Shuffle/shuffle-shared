package shuffle

/*
	Handles files for Shuffle. Uses ID's to reference everything
*/

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/go-github/v28/github"
	uuid "github.com/satori/go.uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var basepath = os.Getenv("SHUFFLE_FILE_LOCATION")
var orgFileBucket = "shuffle_org_files"
var maxFileSize = 10000000                            // raw 10mb max filesize on cloud
var maxFileSizeCloudCustomer int64 = 5 * 1024 * 1024 * 1024 // 5GB max for custom cloud installs

func init() {
	if len(os.Getenv("SHUFFLE_ORG_BUCKET")) > 0 {
		orgFileBucket = os.Getenv("SHUFFLE_ORG_BUCKET")
	} else {
		// Using standard bucket
	}

	//log.Printf("[DEBUG] Inside Files Init with org bucket name %#v", orgFileBucket)
}

func fileExecutionAuthentication(request *http.Request) (string, error) {
	executionId, ok := request.URL.Query()["execution_id"]
	if ok && len(executionId) > 0 {
		ctx := GetContext(request)
		workflowExecution, err := GetWorkflowExecution(ctx, executionId[0])
		if err != nil {
			log.Printf("[ERROR] Couldn't find execution ID from '%s'", executionId)
			return "", err
		}

		apikey := request.Header.Get("Authorization")
		if !strings.HasPrefix(apikey, "Bearer ") {
			log.Printf("[ERROR} Apikey doesn't start with bearer (2)")
			return "", errors.New("No auth key found")
		}

		apikeyCheck := strings.Split(apikey, " ")
		if len(apikeyCheck) != 2 {
			log.Printf("[ERROR] Invalid format for apikey (2)")
			return "", errors.New("No space in authkey")
		}

		// This is annoying af and is done because of maxlength lol
		newApikey := apikeyCheck[1]
		if newApikey != workflowExecution.Authorization {
			//log.Printf("[ERROR] Bad apikey for execution %s. %s vs %s", executionId[0], apikey, workflowExecution.Authorization)
			log.Printf("[ERROR] Bad apikey for execution %s.", executionId[0])
			//%s vs %s", executionId[0], apikey, workflowExecution.Authorization)
			return "", errors.New("Bad authorization key")
		}

		//log.Printf("[INFO] Authorization is correct for execution %s!", executionId[0])
		//%s vs %s. Setting Org", executionId, apikey, workflowExecution.Authorization)
		if len(workflowExecution.ExecutionOrg) > 0 {
			return workflowExecution.ExecutionOrg, nil
		} else if len(workflowExecution.Workflow.ExecutingOrg.Id) > 0 {
			return workflowExecution.ExecutionOrg, nil
		} else {
			log.Printf("[ERROR] Couldn't find org for workflow execution, but auth was correct.")
		}
	}

	return "", errors.New("No execution id specified")
}

// https://golangcode.com/check-if-a-file-exists/
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func HandleGetFiles(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// 1. Check user directly
	// 2. Check workflow execution authorization
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] INITIAL Api authentication failed in file LIST: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role != "admin" {
		log.Printf("[AUTH] User isn't admin")
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Need to be admin to list files"}`)))
		return
	}

	ctx := GetContext(request)
	files, err := GetAllFiles(ctx, user.ActiveOrg.Id, "")
	if err != nil && len(files) == 0 {
		log.Printf("[ERROR] Failed to get files: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Error getting files."}`)))
		return
	}

	sort.Slice(files[:], func(i, j int) bool {
		return files[i].UpdatedAt > files[j].UpdatedAt
	})

	fileResponse := FileResponse{
		Success:    true,
		Files:      files,
		Namespaces: []string{"default"},
	}

	for _, file := range files {
		if file.Status != "active" {
			continue
		}

		if file.Namespace != "" && file.Namespace != "default" {
			if !ArrayContains(fileResponse.Namespaces, file.Namespace) {
				fileResponse.Namespaces = append(fileResponse.Namespaces, file.Namespace)
			}
		}
	}

	// Shitty way to build it, but works before scale. Need ES search mechanism for namespaces
	log.Printf("[INFO] Got %d files and %d namespace(s) for org %s", len(files), len(fileResponse.Namespaces), user.ActiveOrg.Id)
	newBody, err := json.Marshal(fileResponse)
	if err != nil {
		log.Printf("[ERROR] Failed marshaling files: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed to marshal files"}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(newBody))
}

func HandleGetFileMeta(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// 1. Check user directly
	// 2. Check workflow execution authorization
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] INITIAL Api authentication failed in file deletion: %s", err)

		orgId, err := fileExecutionAuthentication(request)
		if err != nil {
			log.Printf("[ERROR] Bad file authentication in get: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		user.ActiveOrg.Id = orgId
		user.Username = "Execution File API"
	}

	var fileId string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("[INFO] Path too short: %d", len(location))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	if strings.Contains(fileId, "?") {
		fileId = strings.Split(fileId, "?")[0]
	}

	if len(fileId) != 36 && !strings.HasPrefix(fileId, "file_") {
		log.Printf("[WARNING] Bad format for fileId %s", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Badly formatted fileId"}`))
		return
	}

	// 1. Verify if the user has access to the file: org_id and workflow
	log.Printf("[INFO] Should GET FILE META for %s if user has access", fileId)
	ctx := GetContext(request)
	file, err := GetFile(ctx, fileId)
	if err != nil {
		log.Printf("[INFO] File %s not found: %s", fileId, err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	found := false
	if file.OrgId == user.ActiveOrg.Id {
		found = true
	} else {
		for _, item := range user.Orgs {
			if item == file.OrgId {
				found = true
				break
			}
		}
	}

	if !found {
		log.Printf("[INFO] User %s doesn't have access to %s", user.Username, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	newBody, err := json.Marshal(file)
	if err != nil {
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed to marshal filedata"}`))
		return
	}

	log.Printf("[INFO] Successfully got file meta for %s", fileId)
	resp.WriteHeader(200)
	resp.Write([]byte(newBody))
}

func HandleDeleteFile(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// read query parameter "remove_metadata"
	removeMetadata := false
	removeMetadataQuery, ok := request.URL.Query()["remove_metadata"]
	if ok && len(removeMetadataQuery) > 0 {
		if removeMetadataQuery[0] == "true" {
			log.Printf("[INFO] Remove metadata is true")
			removeMetadata = true
		}
	}

	var fileId string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("[INFO] Path too short: %d", len(location))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	if strings.Contains(fileId, "?") {
		fileId = strings.Split(fileId, "?")[0]
	}

	if len(fileId) != 36 && !strings.HasPrefix(fileId, "file_") {
		log.Printf("[WARNING] Bad format for fileId %s", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Badly formatted fileId"}`))
		return
	}

	// 1. Check user directly
	// 2. Check workflow execution authorization
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] INITIAL Api authentication failed in file deletion: %s", err)

		orgId, err := fileExecutionAuthentication(request)
		if err != nil {
			log.Printf("[ERROR] Bad file authentication in delete: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		user.ActiveOrg.Id = orgId
		user.Username = "Execution File API"
	}

	log.Printf("[INFO] User %s (%s) is attempting to delete file %s", user.Username, user.Id, fileId)

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to delete files: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	// 1. Verify if the user has access to the file: org_id and workflow
	log.Printf("[INFO] Should DELETE file %s if user has access", fileId)
	ctx := GetContext(request)
	file, err := GetFile(ctx, fileId)
	if err != nil {
		log.Printf("[INFO] File %s not found: %s", fileId, err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	found := false
	if file.OrgId == user.ActiveOrg.Id {
		found = true
	} else {
		for _, item := range user.Orgs {
			if item == file.OrgId {
				found = true
				break
			}
		}
	}

	if !found {
		log.Printf("[INFO] User %s doesn't have access to %s", user.Username, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if file.Status == "deleted" {
		log.Printf("[INFO] File with ID %s is already deleted.", fileId)
		if !(removeMetadata) {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	} else {
		if project.Environment == "cloud" || file.StorageArea == "google_storage" {
			bucket := project.StorageClient.Bucket(orgFileBucket)
			obj := bucket.Object(file.DownloadPath)
			err := obj.Delete(ctx)
			if err != nil {
				log.Printf("[ERROR] FAILED to delete file %s from Google cloud storage. Removing frontend reference anyway. Err: %s", fileId, err)
			} else {
				log.Printf("[DEBUG] Deleted file %s from Google cloud storage", fileId)
			}

		} else {
			if FileExists(file.DownloadPath) {
				err = os.Remove(file.DownloadPath)
				if err != nil {
					log.Printf("[ERROR] Failed deleting file locally: %s", err)
					resp.WriteHeader(401)
					resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed deleting filein path %s"}`, file.DownloadPath)))
					return
				}

				log.Printf("[INFO] Deleted file %s locally. Next is database.", file.DownloadPath)
			} else {
				log.Printf("[ERROR] File doesn't exist. Can't delete. Should maybe delete file anyway?")
				resp.WriteHeader(200)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "File in location %s doesn't exist"}`, file.DownloadPath)))
				return
			}
		}
		file.Status = "deleted"

		if len(file.SuborgDistribution) > 0 {
			log.Printf("[INFO] File %s (%s) has suborg distribution, removing it from suborgs", file.Filename, file.Id)
			for _, suborg := range file.SuborgDistribution {
				cacheKey := fmt.Sprintf("files_%s_%s", suborg, file.Namespace)
				DeleteCache(ctx, cacheKey)
			}
			file.SuborgDistribution = []string{}
		}

		err = SetFile(ctx, *file)
		if err != nil {
			log.Printf("[ERROR] Failed setting file to deleted: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed setting file to deleted"}`))
			return
		}

		outputFiles, err := FindSimilarFile(ctx, file.Md5sum, file.OrgId)
		log.Printf("[INFO] Found %d similar files for Md5 '%s'", len(outputFiles), file.Md5sum)
		if len(outputFiles) > 0 {
			for _, item := range outputFiles {
				item.Status = "deleted"
				err = SetFile(ctx, item)
				if err != nil {
					log.Printf("[ERROR] Failed setting duplicate file %s to deleted", item.Id)
				}
			}
		}

		nameKey := "Files"
		DeleteCache(ctx, fmt.Sprintf("%s_%s_%s", nameKey, file.OrgId, file.Md5sum))
		DeleteCache(ctx, fmt.Sprintf("%s_%s", nameKey, file.OrgId))
	}

	if removeMetadata {
		//Actually delete it
		err = DeleteKey(ctx, "Files", fileId)
		if err != nil {
			log.Printf("Failed deleting file with ID %s: %s", fileId, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
		log.Printf("[INFO] Deleted file %s from database", fileId)

		// If we delete a file but keep its metadata, then the file is marked as deleted and cache is cleared,
		// but when we query for a list of files, all the files including those marked as deleted might be cached.
		// So next time when we try to delete the metadata of an already deleted file, those files might still show up
		// in the API response and in the UI because of caching.

		// Clear any caches for the deleted file to ensure immediate removal
		if len(file.SuborgDistribution) > 0 {
			log.Printf("[INFO] File %s (%s) has suborg distribution, clearing cache for suborgs", file.Filename, file.Id)
			for _, suborg := range file.SuborgDistribution {
				cacheKey := fmt.Sprintf("files_%s_%s", suborg, file.Namespace)
				DeleteCache(ctx, cacheKey)
			}
		}

		nameKey := "Files"
		DeleteCache(ctx, fmt.Sprintf("%s_%s_%s", nameKey, file.OrgId, file.Md5sum))
		DeleteCache(ctx, fmt.Sprintf("files_%s_%s", file.OrgId, file.Namespace))
	}

	log.Printf("[INFO] Successfully deleted file %s for org %s", fileId, user.ActiveOrg.Id)
	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func LoadStandardFromGithub(client *github.Client, owner, repo, path, filename string) ([]*github.RepositoryContent, error) {
	var err error

	ctx := context.Background()
	files := []*github.RepositoryContent{}

	cacheKey := fmt.Sprintf("github_%s_%s_%s_%s", owner, repo, path, filename)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &files)
			if err == nil && len(files) > 0 {
				return files, nil
			}
		}
	}

	if len(files) == 0 {
		_, files, _, err = client.Repositories.GetContents(ctx, owner, repo, path, nil)
		if err != nil {
			log.Printf("[WARNING] Failed getting standard list for namespace %s: %s", path, err)
			return []*github.RepositoryContent{}, err
		}
	}

	//log.Printf("\n\n[DEBUG] Got %d file(s): %s\n\n", len(files), path)

	if len(files) == 0 {
		log.Printf("[ERROR] No files found in namespace '%s' on Github - Used for integration framework", path)
		return []*github.RepositoryContent{}, nil
	}

	if len(filename) > 0 {
		matchingFiles := []*github.RepositoryContent{}
		for _, item := range files {
			if len(filename) > 0 && strings.HasPrefix(*item.Name, filename) {
				matchingFiles = append(matchingFiles, item)
			}
		}

		files = matchingFiles
	}

	if project.CacheDb {
		data, err := json.Marshal(files)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in get github files: %s", err)
			return files, nil
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getfiles on github '%s': %s", cacheKey, err)
		}
	}

	return files, nil
}

// Normal orborus auth. E.g. used for file downloads
func envOrborusAuth(request *http.Request) (string, error) {
	currentUrl := request.URL.String()
	orgId := request.Header.Get("Org-Id")
	if len(orgId) == 0 {
		log.Printf("[AUDIT] No Org-Id set for url %s", currentUrl)
		return "", errors.New("No org-id header set")
	}

	auth := request.Header.Get("Authorization")
	if len(auth) == 0 {
		log.Printf("[AUDIT] No Authorization header set for url %s", currentUrl)
		return "", errors.New("No authorization header set (environment auth)")
	}

	// Get the org
	ctx := GetContext(request)
	foundOrg, err := GetOrg(ctx, orgId)
	if err != nil {
		log.Printf("[AUDIT] Couldn't find org %s for url %s: %s", orgId, currentUrl, err)
		return "", errors.New("Couldn't find org")
	}

	foundEnvironments, err := GetEnvironments(ctx, foundOrg.Id)
	if err != nil {
		log.Printf("[AUDIT] Couldn't find environments for org %s for url %s: %s", foundOrg.Id, currentUrl, err)
		return "", errors.New("Couldn't find environments for org")
	}

	if strings.HasPrefix(auth, "Bearer ") {
		auth = strings.Split(auth, " ")[1]
	}

	for _, item := range foundEnvironments {
		// Check auth
		if item.Auth == auth && item.Archived == false {
			return item.OrgId, nil
		}
	}

	return "", errors.New("No environment matched")

}

func HandleGetFileNamespace(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	var namespace string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 5 {
			log.Printf("Path too short: %d", len(location))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		namespace = location[5]
	}

	if strings.Contains(namespace, "?") {
		namespace = strings.Split(namespace, "?")[0]
	}

	// URL decode namespace
	namespace, err := url.QueryUnescape(namespace)
	if err != nil {
		log.Printf("[WARNING] Failed to decode namespace value '%s': %s", namespace, err)
	}

	// 1. Check user directly
	// 2. Check workflow execution authorization
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		//log.Printf("[AUDIT] INITIAL Api authentication failed in file download: %s", err)
		var fileerr error
		var envErr error

		orgId := ""
		orgId, fileerr = fileExecutionAuthentication(request)
		if fileerr != nil {

			// Uses orborus env auth to check access to an org
			orgId, envErr = envOrborusAuth(request)
			if envErr != nil {
				log.Printf("[WARNING] Bad authentication in get namespace AFTER trying normal user auth AND file exec auth %s: %s & %s. Env err: %s", namespace, err, fileerr, envErr)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false}`))
				return
			}
		}

		user.ActiveOrg.Id = orgId
		user.Username = "Execution File API"
	}

	if len(user.Username) > 0 && len(user.Id) > 0 {
		log.Printf("[AUDIT] User '%s' (%s) is trying to get files from namespace %#v", user.Username, user.Id, namespace)
	}

	ctx := GetContext(request)
	files, err := GetAllFiles(ctx, user.ActiveOrg.Id, namespace)
	if err != nil && len(files) == 0 {
		log.Printf("[ERROR] Failed to get files: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Error getting files."}`)))
		return
	}

	sort.Slice(files[:], func(i, j int) bool {
		return files[i].UpdatedAt > files[j].UpdatedAt
	})

	fileResponse := FileResponse{
		Files:      []File{},
		Namespaces: []string{namespace},
		List:       []BaseFile{},
	}

	for _, file := range files {
		if file.Status != "active" {
			//log.Printf("[DEBUG] File %s (%s) is not active", file.Filename, file.Id)
			continue
		}

		if file.Namespace == "" {
			file.Namespace = "default"
		}

		//log.Printf("File namespace: %s", file.Namespace)
		if file.Namespace == namespace && file.OrgId == user.ActiveOrg.Id {

			// FIXME: This double control is silly
			fileResponse.Files = append(fileResponse.Files, file)
			fileResponse.List = append(fileResponse.List, BaseFile{
				Name:               file.Filename,
				ID:                 file.Id,
				Type:               file.Type,
				UpdatedAt:          file.UpdatedAt,
				Md5Sum:             file.Md5sum,
				Status:             file.Status,
				FileSize:           file.FileSize,
				OrgId:              file.OrgId,
				SuborgDistribution: file.SuborgDistribution,

				Tags: file.Tags,
			})
		}
	}

	// If current org is sub org and file suborg distributed is true than add file to list
	foundOrg, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err == nil && len(foundOrg.ChildOrgs) == 0 && len(foundOrg.CreatorOrg) > 0 {
		parentOrg, err := GetOrg(ctx, foundOrg.CreatorOrg)
		if err == nil {
			parentFiles, err := GetAllFiles(ctx, parentOrg.Id, namespace)
			if err == nil {
				for _, file := range parentFiles {

					if !ArrayContains(file.SuborgDistribution, user.ActiveOrg.Id) {
						continue
					}

					if file.Namespace == namespace {
						fileResponse.Files = append(fileResponse.Files, file)
						fileResponse.List = append(fileResponse.List, BaseFile{
							Name:               file.Filename,
							ID:                 file.Id,
							Type:               file.Type,
							UpdatedAt:          file.UpdatedAt,
							Md5Sum:             file.Md5sum,
							Status:             file.Status,
							FileSize:           file.FileSize,
							OrgId:              file.OrgId,
							SuborgDistribution: file.SuborgDistribution,

							Tags: file.Tags,
						})
					}
				}
			}
		}
	}

	//log.Printf("[DEBUG] Found %d (%d:%d) files in org %s (%s) for namespace '%s'", len(files), len(fileResponse.Files), len(fileResponse.List), user.ActiveOrg.Name, user.ActiveOrg.Id, namespace)

	// Standards to load directly from Github if applicable
	reservedCategoryNames := []string{
		"translation_input",
		"translation_output",
		"translation_standards",
		"translation_ai_queries",

		"detections",
	}

	// Dynamically loads special files directly from Github
	// For now it's using Shuffle's repo for standards, but this could
	// also be environment variables / input arguments
	filename, filenameOk := request.URL.Query()["filename"]
	if filenameOk && ArrayContains(reservedCategoryNames, namespace) {
		//log.Printf("[DEBUG] Filename '%s' in URL with reserved category name: %s. Listlength: %d", filename[0], namespace, len(fileResponse.List))

		// Load from Github repo https://github.com/Shuffle/standards
		filenameFound := false
		parsedFilename := strings.TrimSpace(strings.Replace(strings.ToLower(filename[0]), " ", "_", -1))
		if strings.HasSuffix(parsedFilename, ".json") {
			parsedFilename = strings.Replace(parsedFilename, ".json", "", -1)
		}

		// This is basically a unique handler
		for _, item := range fileResponse.List {
			itemName := strings.TrimSpace(strings.Replace(strings.ToLower(item.Name), " ", "_", -1))

			if itemName == parsedFilename || itemName == fmt.Sprintf("%s.json", parsedFilename) {
				filenameFound = true
				break
			}
		}

		// FIXME: How to handle files here?
		if !filenameFound && namespace != "translation_input" && namespace != "translation_ai_queries" && namespace != "translation_output" {

			client := github.NewClient(nil)
			owner := "shuffle"
			repo := "standards"

			foundFiles, err := LoadStandardFromGithub(client, owner, repo, namespace, filename[0])
			if err != nil {
				if !strings.Contains(err.Error(), "404") {
					log.Printf("[ERROR] Failed loading file %s in category %s from Github: %s", filename[0], namespace, err)
				}

				// Don't quit here as the standard may not exist in that repo
				//resp.WriteHeader(500)
				//resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed loading file from Github repo %s/%s"}`, owner, repo)))
				//return
			} else {
				log.Printf("[DEBUG] Found %d file(s) in category '%s' for filename '%s'", len(foundFiles), namespace, filename[0])
				for _, item := range foundFiles {
					log.Printf("[DEBUG] Found file from Github '%s'", *item.Name)

					fileContent, _, _, err := client.Repositories.GetContents(ctx, owner, repo, *item.Path, nil)
					if err != nil {
						log.Printf("[ERROR] Failed getting file %s: %s", *item.Path, err)
						continue
					}

					// Get the bytes of the file
					decoded, err := base64.StdEncoding.DecodeString(*fileContent.Content)
					if err != nil {
						log.Printf("[ERROR] Failed decoding standard file %s: %s", *item.Path, err)
						continue
					}

					//log.Printf("[DEBUG] Decoded Github file '%s' with content:\n%s", *item.Path, string(decoded))

					timeNow := time.Now().Unix()
					fileId := "file_" + uuid.NewV4().String()

					folderPath := fmt.Sprintf("%s/%s/%s", basepath, user.ActiveOrg.Id, "global")
					downloadPath := fmt.Sprintf("%s/%s", folderPath, fileId)
					file := File{
						Id:           fileId,
						CreatedAt:    timeNow,
						UpdatedAt:    timeNow,
						Description:  "",
						Status:       "active",
						Filename:     *item.Name,
						OrgId:        user.ActiveOrg.Id,
						WorkflowId:   "global",
						DownloadPath: downloadPath,
						Subflows:     []string{},
						StorageArea:  StorageAreaName(),
						Namespace:    namespace,
						Tags: []string{
							"standard",
						},
					}

					if project.Environment == "cloud" {
						file.StorageArea = "google_storage"
					}

					// Can be used for validation files for change
					var buf bytes.Buffer
					io.Copy(&buf, bytes.NewReader(decoded))
					contents := buf.Bytes()
					file.FileSize = int64(len(contents))
					file.ContentType = http.DetectContentType(contents)
					file.OriginalMd5sum = Md5sum(contents)

					buf.Reset()

					// Handle file encryption if an encryption key is set

					parsedKey := fmt.Sprintf("%s_%s", user.ActiveOrg.Id, file.Id)
					fileId, err = UploadFile(ctx, &file, parsedKey, contents)
					if err != nil {
						log.Printf("[ERROR] Failed to upload file %s: %s", fileId, err)
						continue
					}

					log.Printf("[DEBUG] Uploaded file %#v with ID %s in category %#v", file.Filename, fileId, namespace)

					fileResponse.List = append(fileResponse.List, BaseFile{
						Name:      file.Filename,
						ID:        fileId,
						Type:      file.Type,
						UpdatedAt: file.UpdatedAt,
						Md5Sum:    file.Md5sum,
						Status:    file.Status,
						FileSize:  file.FileSize,

						Tags: file.Tags,
					})
				}
			}
		}
	}

	ids, idsok := request.URL.Query()["ids"]
	if idsok {
		if ids[0] == "true" {
			fileResponse.Success = true
			fileResponse.Files = []File{}

			newBody, err := json.Marshal(fileResponse)
			if err != nil {
				log.Printf("[ERROR] Failed marshaling files (2) for user %s (%s): %s", user.Username, user.Id, err)
				resp.WriteHeader(500)
				resp.Write([]byte(`{"success": false, "reason": "Failed to marshal files (2)"}`))
				return
			}

			resp.WriteHeader(200)
			resp.Write([]byte(newBody))
			return
		}
	}

	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	// FIXME: Goroutine this + Cache it for future requests

	packed := 0
	for _, file := range fileResponse.Files {
		// Goroutine this get file section
		filedata, err := GetFileContent(ctx, &file, nil)
		if err != nil {
			log.Printf("[ERROR] Failed getting file content for %s (%s): %s", file.Filename, file.Id, err)
			continue
		}

		if len(filedata) == 0 {
			log.Printf("[ERROR] No data found for file %s (%s)", file.Filename, file.Id)
		}

		zipFile, err := zipWriter.Create(file.Filename)
		if err != nil {
			log.Printf("[WARNING] Packing failed for %s create zip file: %v", file.Filename, err)
			continue
		}

		if _, err := fmt.Fprintln(zipFile, string(filedata)); err != nil {
			log.Printf("[WARNING] Datapasting failed for %s when creating zip file from bucket: %v", file.Filename, err)
			continue
		}

		packed += 1
	}

	err = zipWriter.Close()
	if err != nil {
		log.Printf("[WARNING] Packing failed to close zip file writer: %v", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if packed == 0 {
		log.Printf("[WARNING] Couldn't find anything for namespace %s in org %s", namespace, user.ActiveOrg.Id)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	log.Printf("[DEBUG] Packed %d files from namespace %s into the zip for %s (%s)", packed, namespace, user.Username, user.Id)

	FileHeader := make([]byte, 512)
	FileContentType := http.DetectContentType(FileHeader)
	resp.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.zip", namespace))
	resp.Header().Set("Content-Type", FileContentType)
	io.Copy(resp, buf)
}

func HandleGetFileContent(resp http.ResponseWriter, request *http.Request) {
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

	if len(fileId) != 36 && !strings.HasPrefix(fileId, "file_") {
		log.Printf("[WARNING] Bad format for fileId %s", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Badly formatted fileId"}`))
		return
	}

	// 1. Check user directly
	// 2. Check workflow execution authorization
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {

		orgId, err := fileExecutionAuthentication(request)
		if err != nil {
			log.Printf("[WARNING] Bad user & file authentication in get for ID %s: %s", fileId, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		user.ActiveOrg.Id = orgId
		user.Username = "Execution File API"
	}

	log.Printf("[AUDIT] User '%s' (%s) downloading file %s in org %s", user.Username, user.Id, fileId, user.ActiveOrg.Id)

	// 1. Verify if the user has access to the file: org_id and workflow
	ctx := GetContext(request)
	file, err := GetFile(ctx, fileId)
	if err != nil {
		log.Printf("[ERROR] File %s not found: %s", fileId, err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "File not found"}`))
		return
	}

	found := false
	if file.OrgId == user.ActiveOrg.Id {
		found = true
	} else {
		for _, item := range user.Orgs {
			if item == file.OrgId {
				found = true
				break
			}
		}
	}

	if !found {
		log.Printf("[WARNING] User %s doesn't have access to %s", user.Username, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if file.Status != "active" {
		log.Printf("[WARNING] File status isn't active, but %s. Can't continue.", file.Status)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "The file isn't ready to be downloaded yet. Status required: active"}`))
		return
	}

	// Automatically downloads and returns the file through resp
	// GetFileContent() is used to return data, through resp if possible due to how we used to do it.

	if len(file.OrgId) == 0 {
		file.OrgId = user.ActiveOrg.Id
	}

	_, err = GetFileContent(ctx, file, resp)
	if err != nil {
		log.Printf("[ERROR] Failed getting file content for %s: %s", fileId, err)
	}

	//resp.WriteHeader(200)
	//resp.Write(content)
}

func GetFileContent(ctx context.Context, file *File, resp http.ResponseWriter) ([]byte, error) {
	downloadPath := file.DownloadPath
	if project.Environment == "cloud" || file.StorageArea == "google_storage" {
		bucket := project.StorageClient.Bucket(orgFileBucket)
		obj := bucket.Object(file.DownloadPath)
		fileReader, err := obj.NewReader(ctx)
		if err != nil {
			//log.Printf("[ERROR] Reader error for %s in bucket %s: %s", downloadPath, orgFileBucket, err)

			file.Status = "deleted"
			err = SetFile(ctx, *file)
			if err != nil {
				log.Printf("[ERROR] SetFile error while uploading")

				if resp != nil {
					resp.WriteHeader(500)
					resp.Write([]byte(`{"success": false, "reason": "Failed setting file to deleted"}`))
				}

				return []byte{}, err
			}

			//File not found, send 404
			if resp != nil {
				resp.WriteHeader(404)
				resp.Write([]byte(`{"success": false, "reason": "File doesn't exist in google cloud storage"}`))
			}

			return []byte{}, err
		}

		defer fileReader.Close()
		if file.Encrypted {
			allText := []byte{}
			buf := make([]byte, 1024)
			for {
				n, err := fileReader.Read(buf)
				if err == io.EOF {
					break
				}

				if err != nil {
					continue
				}

				if n > 0 {
					//fmt.Println(string(buf[:n]))
					allText = append(allText, buf[:n]...)
				}
			}

			// FIXME:
			// Editing in the following order fails:
			// url -> apikey

			// Editing in the following order works:
			// apikey -> url

			// This means apikey should be the reference file ID?
			// Problem: It shouldn't edit ALL files when one out of many are edited.

			//log.Printf("[DEBUG] MD5: %s, Original MD5:", file.Md5sum, file.OriginalMd5sum)
			// If file does not equal the original MD5, it's been edited

			passphrase := fmt.Sprintf("%s_%s", file.OrgId, file.Id)
			data, err := HandleKeyDecryption(allText, passphrase)
			if err != nil {
				// Reference File Id only used as fallback
				if len(file.ReferenceFileId) > 0 {
					passphrase = fmt.Sprintf("%s_%s", file.OrgId, file.ReferenceFileId)

					data, err = HandleKeyDecryption(allText, passphrase)
					if err != nil {
						log.Printf("[ERROR] Failed decrypting file (4): %s. Continuing anyway, but this WILL cause trouble for the user if the file is encrypted.", err)
					}

					allText = []byte(data)
				} else {
					log.Printf("[ERROR] Failed decrypting file (1): %s. Continuing anyway, but this WILL cause trouble for the user if the file is encrypted.", err)
				}

			} else {
				//log.Printf("[DEBUG] File size reduced from %d to %d after decryption (2)", len(allText), len(data))
				allText = []byte(data)
			}

			FileContentType := http.DetectContentType(allText)
			FileSize := strconv.FormatInt(int64(len(allText)), 10) //Get file size as a string
			//Send the headers
			//log.Printf("Content Type: %#v", FileContentType)

			if resp != nil {
				resp.Header().Set("Content-Disposition", "attachment; filename="+file.Filename)
				resp.Header().Set("Content-Type", FileContentType)
				resp.Header().Set("Content-Length", FileSize)
				reader := bytes.NewReader(allText)
				io.Copy(resp, reader)
			}

			return allText, nil

		}

		if resp != nil {
			FileHeader := make([]byte, 512)
			FileContentType := http.DetectContentType(FileHeader)

			resp.Header().Set("Content-Disposition", "attachment; filename="+file.Filename)
			resp.Header().Set("Content-Type", FileContentType)
			io.Copy(resp, fileReader)
		}

	} else if file.StorageArea == "s3" {
		log.Printf("[INFO] Downloading file %s from object storage", file.Id)
		allText, err := ReadStorageData(downloadPath)
		if err != nil {
			file.Status = "deleted"
			err = SetFile(ctx, *file)
			if err != nil {
				log.Printf("Failed setting file to uploading")
				if resp != nil {
					resp.WriteHeader(500)
					resp.Write([]byte(`{"success": false, "reason": "Failed setting file to deleted"}`))
				}

				return []byte{}, err
			}

			//File not found, send 404
			if resp != nil {
				resp.WriteHeader(400)
				resp.Write([]byte(`{"success": false, "reason": "File doesn't exist in object storage"}`))
			}

			return []byte{}, err
		}

		if file.Encrypted {
			passphrase := fmt.Sprintf("%s_%s", file.OrgId, file.Id)
			data, err := HandleKeyDecryption(allText, passphrase)
			if err != nil {
				if len(file.ReferenceFileId) > 0 {
					passphrase = fmt.Sprintf("%s_%s", file.OrgId, file.ReferenceFileId)
					data, err = HandleKeyDecryption(allText, passphrase)
					if err != nil {
						log.Printf("[ERROR] Failed decrypting file (5): %s", err)
					}

					allText = []byte(data)
				} else {
					log.Printf("[ERROR] Failed decrypting file (2): %s", err)
				}

			} else {
				//log.Printf("[DEBUG] File size reduced from %d to %d after decryption (s3)", len(allText), len(data))
				allText = []byte(data)
			}
		}

		FileContentType := http.DetectContentType(allText)
		FileSize := strconv.FormatInt(int64(len(allText)), 10)

		if resp != nil {
			resp.Header().Set("Content-Disposition", "attachment; filename="+file.Filename)
			resp.Header().Set("Content-Type", FileContentType)
			resp.Header().Set("Content-Length", FileSize)
			reader := bytes.NewReader(allText)
			io.Copy(resp, reader)
		}

		return allText, nil
	} else {
		log.Printf("[INFO] Downloadpath: %s", downloadPath)
		Openfile, err := os.Open(downloadPath)

		if err != nil {
			file.Status = "deleted"
			err = SetFile(ctx, *file)
			if err != nil {
				log.Printf("Failed setting file to uploading")
				if resp != nil {
					resp.WriteHeader(500)
					resp.Write([]byte(`{"success": false, "reason": "Failed setting file to deleted"}`))
				}

				return []byte{}, err
			}

			//File not found, send 404
			if resp != nil {
				resp.WriteHeader(400)
				resp.Write([]byte(`{"success": false, "reason": "File doesn't exist locally"}`))
			}

			return []byte{}, err
		}

		log.Printf("[DEBUG] Should handle file decryption of %s.", file.Id)
		allText := []byte{}

		buf := make([]byte, 1024)
		for {
			n, err := Openfile.Read(buf)
			if err == io.EOF {
				break
			}

			if err != nil {
				log.Printf("[WARNING] Problem in file loop: %#v", err)
				continue
			}

			if n > 0 {
				//fmt.Println(string(buf[:n]))
				allText = append(allText, buf[:n]...)
			}
		}

		Openfile.Close()

		if file.Encrypted {
			passphrase := fmt.Sprintf("%s_%s", file.OrgId, file.Id)
			data, err := HandleKeyDecryption(allText, passphrase)
			if err != nil {
				if len(file.ReferenceFileId) > 0 {
					passphrase = fmt.Sprintf("%s_%s", file.OrgId, file.ReferenceFileId)
					data, err = HandleKeyDecryption(allText, passphrase)
					if err != nil {
						log.Printf("[ERROR] Failed decrypting file (5): %s", err)
					}

					allText = []byte(data)
				} else {
					log.Printf("[ERROR] Failed decrypting file (2): %s", err)
				}

			} else {
				//log.Printf("[DEBUG] File size reduced from %d to %d after decryption (3)", len(allText), len(data))
				allText = []byte(data)
			}

		} else {
			log.Printf("[DEBUG] Not decrypting file before download of %s with length %d", file.Filename, len(allText))
		}

		FileContentType := http.DetectContentType(allText)
		FileSize := strconv.FormatInt(int64(len(allText)), 10) //Get file size as a string

		//Send the headers
		if resp != nil {
			resp.Header().Set("Content-Disposition", "attachment; filename="+file.Filename)
			resp.Header().Set("Content-Type", FileContentType)
			resp.Header().Set("Content-Length", FileSize)

			//log.Printf("Md5: %#v", md5)
			reader := bytes.NewReader(allText)
			_, err = io.Copy(resp, reader)
			if err != nil {
				log.Printf("[ERROR] Failed copying info to request in download of %s: %s", file.Filename, err)
			} else {
				log.Printf("[INFO] Downloading %d bytes from file %s", len(allText), file.Filename)
			}
		}

		return allText, nil
	}

	return nil, nil
}

func HandleEditFile(resp http.ResponseWriter, request *http.Request) {
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
		log.Printf("[AUDIT] INITIAL Api authentication failed in file upload: %s", err)
		orgId, err := fileExecutionAuthentication(request)
		if err != nil {
			log.Printf("[WARNING] Bad file authentication in edit file: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		user.ActiveOrg.Id = orgId
		user.Username = "Execution File API"
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to upload file: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	//log.Printf("[INFO] Should UPLOAD file %s if user has access", fileId)
	ctx := GetContext(request)
	file, err := GetFile(ctx, fileId)
	//log.Printf("file obj", file)
	if err != nil {
		log.Printf("[INFO] File %s not found: %s", fileId, err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if file.Status != "active" {
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "File must be active. Use /upload API first"}`))
		return
	}

	found := false
	if file.OrgId == user.ActiveOrg.Id {
		found = true
	} else {
		for _, item := range user.Orgs {
			if item == file.OrgId {
				found = true
				break
			}
		}
	}

	if !found {
		log.Printf("[AUDIT] User %s in org %s (%s) doesn't have access to file %s", user.Username, user.ActiveOrg.Name, user.ActiveOrg.Id, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading file body: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to read data"}`)))
		return
	}

	bodySize := len(body)
	if project.Environment == "cloud" && bodySize > maxFileSize {
		foundOrg, err := GetOrg(ctx, user.ActiveOrg.Id)
		if err == nil && foundOrg.LeadInfo.Customer || foundOrg.LeadInfo.Internal || foundOrg.LeadInfo.POV && int64(bodySize) < maxFileSizeCloudCustomer {
			log.Printf("[AUDIT] Allowing larger file for customer/internal/POV org %s (%s). Filesize: %d", foundOrg.Name, foundOrg.Id, bodySize)
		} else {
			log.Printf("[ERROR] Max default size limit is 10MB. Please contact support@shuffler.io with details about your usecase if you want this extended.")
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "File too large. Max is 10mb per file."}`))
			return
		}
	}

	file.FileSize = int64(bodySize)
	file.ContentType = http.DetectContentType(body)
	file.Encrypted = true // not sure about what this does, maybe it has something to do with datastore encrypted column and stores file as encrypted in cloud storage?
	file.LastEditor = user.Username
	file.IsEdited = true

	// Change filepath when a file is changed no matter what as to not screw up other files
	// This makes it so that referencing files are not overwritten even when replicas?
	// We still point to a reference IF the change goes to an md5sum that is the same as another file
	file.DownloadPath = fmt.Sprintf("files/%s/global/%s-edited", user.ActiveOrg.Id, file.Id)
	file.ReferenceFileId = ""

	parsedKey := fmt.Sprintf("%s_%s", user.ActiveOrg.Id, file.Id)
	if len(file.ReferenceFileId) > 0 {
		parsedKey = fmt.Sprintf("%s_%s", user.ActiveOrg.Id, file.ReferenceFileId)
	}

	if strings.HasPrefix(string(body), "--") && strings.Contains(string(body), "Content-Disposition") {
		body = []byte(strings.TrimSpace(string(body)))
		bodysplit := strings.Split(string(body), "\n")
		if len(bodysplit) > 3 {
			// Remove line 1, 2 and last
			body = []byte(strings.Join(bodysplit[2:len(bodysplit)-1], "\n"))
		}

		// Trim newlines
		body = []byte(strings.TrimSpace(string(body)))
		log.Printf("[DEBUG] Found multipart form data in the body itself - autocleanup ran.")
	}

	fileId, err = UploadFile(ctx, file, parsedKey, body)
	if err != nil {
		log.Printf("[ERROR] Failed to upload file with ID %s: %s", fileId, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed file upload in Shuffle"}`))
		return
	}

	log.Printf("[INFO] Successfully uploaded file ID %s. Namespace: %s", file.Id, file.Namespace)
	if file.Namespace == "sigma" {
		execType := "CATEGORY_UPDATE"
		err = SetDetectionOrborusRequest(ctx, user.ActiveOrg.Id, execType, file.Filename, "SIGMA", "SHUFFLE_DISCOVER")
		if err != nil {
			log.Printf("[ERROR] Failed setting workflow queue for env (3): %s", err)
			//resp.WriteHeader(500)
			//resp.Write([]byte(`{"success": false}`))
			//return
		}
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "file_id": "%s"}`, fileId)))
}

func HandleUploadFile(resp http.ResponseWriter, request *http.Request) {
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

	//if len(fileId) != 36 &&
	if !strings.HasPrefix(fileId, "file_") || len(fileId) > 64 {
		log.Printf("[WARNING] Bad format for fileId %s", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Badly formatted fileId"}`))
		return
	}

	// 1. Check user directly
	// 2. Check workflow execution authorization
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] INITIAL Api authentication failed in file upload: %s", err)

		orgId, err := fileExecutionAuthentication(request)
		if err != nil {
			log.Printf("[WARNING] Bad file authentication in upload file: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		user.ActiveOrg.Id = orgId
		user.Username = "Execution File API"
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to upload file: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	//log.Printf("[INFO] Should UPLOAD file %s if user has access", fileId)
	ctx := GetContext(request)
	file, err := GetFile(ctx, fileId)
	if err != nil {
		log.Printf("[INFO] File %s not found: %s", fileId, err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	found := false
	if file.OrgId == user.ActiveOrg.Id {
		found = true
	} else {
		for _, item := range user.Orgs {
			if item == file.OrgId {
				found = true
				break
			}
		}
	}

	if !found {
		log.Printf("[WARNING] User %s doesn't have access to %s", user.Username, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if file.Status != "created" {
		log.Printf("[WARNING] File status isn't created. Can't upload.")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "This file already has data."}`))
		return
	}

	// Read the file from the upload request
	request.ParseMultipartForm(32 << 20)
	parsedFile, _, err := request.FormFile("shuffle_file")
	if err != nil {
		log.Printf("[ERROR] Failed to upload file: '%s'", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Failed uploading file. Correct usage is: shuffle_file=@filepath"}`))
		return
	}

	defer parsedFile.Close()
	file.Status = "uploading"
	err = SetFile(ctx, *file)
	if err != nil {
		log.Printf("Failed setting file to uploading")
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed setting file to uploading"}`))
		return
	}

	// Can be used for validation files for change
	var buf bytes.Buffer
	io.Copy(&buf, parsedFile)
	contents := buf.Bytes()

	bodySize := len(contents)
	if project.Environment == "cloud" && len(contents) > maxFileSize {
		foundOrg, err := GetOrg(ctx, user.ActiveOrg.Id)
		if err == nil && foundOrg.LeadInfo.Customer || foundOrg.LeadInfo.Internal || foundOrg.LeadInfo.POV && int64(bodySize) < maxFileSizeCloudCustomer {
			log.Printf("[AUDIT] Allowing larger file for customer/internal/POV org %s (%s). Filesize: %d", foundOrg.Name, foundOrg.Id, bodySize)
		} else {
			log.Printf("[ERROR] Max default size limit is 10MB. Please contact support@shuffler.io with details about your usecase if you want this extended.")

			file.Status = "maxsize_exceeded"
			err = SetFile(ctx, *file)
			if err != nil {
				log.Printf("Failed setting file to uploading")
				resp.WriteHeader(500)
				resp.Write([]byte(`{"success": false, "reason": "Failed setting file to uploading"}`))
				return
			}

			log.Printf("[ERROR] Max filesize is 10MB in cloud environment (upload)")
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "File too large. Max is 10mb"}`))
			return
		}
	}

	//if len(contents) < 50 && strings.HasSuffix(file.Filename, ".json"){
	//	log.Printf("\n\n\n\n\nFILE (%s): '''\n%s\n'''\n\n\n\n", file.Filename, string(contents))
	//}
	//log.Printf("File content: %s\n%x", string(contents))

	file.FileSize = int64(len(contents))
	file.ContentType = http.DetectContentType(contents)
	file.OriginalMd5sum = Md5sum(contents)

	buf.Reset()

	// Handle file encryption if an encryption key is set

	parsedKey := fmt.Sprintf("%s_%s", user.ActiveOrg.Id, file.Id)
	fileId, err = UploadFile(ctx, file, parsedKey, contents)
	if err != nil {
		log.Printf("[ERROR] Failed to upload file %s: %s", fileId, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed file upload in Shuffle"}`))
		return
	}

	log.Printf("[INFO] Successfully uploaded file ID %s", file.Id)

	if file.Namespace == "sigma" {
		execType := "CATEGORY_UPDATE"
		err = SetDetectionOrborusRequest(ctx, user.ActiveOrg.Id, execType, file.Filename, "SIGMA", "SHUFFLE_DISCOVER")
		if err != nil {
			log.Printf("[ERROR] Failed setting workflow queue for env: %s. This is at the end of file upload for Sigma specifically.", err)
			//resp.WriteHeader(500)
			//resp.Write([]byte(`{"success": false}`))
			//return
		}
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "file_id": "%s"}`, fileId)))
}

func UploadFile(ctx context.Context, file *File, encryptionKey string, contents []byte) (string, error) {
	md5 := Md5sum(contents)
	sha256Sum := sha256.Sum256(contents)

	// Should look for another file with the same md5
	outputFiles, err := FindSimilarFile(ctx, md5, file.OrgId)
	if len(outputFiles) > 0 {
		outputFile := outputFiles[0]
		if debug {
			log.Printf("[DEBUG] Already found a file with the same Md5 '%s' for org '%s' in ID: %s. Referencing same location.", md5, file.OrgId, outputFile.Id)
		}

		file.Encrypted = outputFile.Encrypted
		file.FileSize = outputFile.FileSize
		file.StorageArea = outputFile.StorageArea
		file.DownloadPath = outputFile.DownloadPath

		// Makes sure we're always referencing the original in case of decryption
		if len(outputFile.ReferenceFileId) > 0 {
			file.ReferenceFileId = outputFile.ReferenceFileId
		} else {
			file.ReferenceFileId = outputFile.Id
		}
	} else {
		if debug { 
			log.Printf("[DEBUG] No similar file found with md5 %s. Original Md5: %s", md5, file.OriginalMd5sum)
		}

		if len(file.OriginalMd5sum) > 0 && file.OriginalMd5sum != md5 {
			if debug {
				log.Printf("[DEBUG] Md5 has changed for ID %s!", file.Id)
			}
		}

		if len(encryptionKey) > 0 {
			newContents := contents
			newFileValue, err := HandleKeyEncryption(contents, encryptionKey)
			if err != nil {
				log.Printf("[ERROR] Failed encrypting file to be stored correctly: %s", err)
				newContents = contents
			} else {
				newContents = []byte(newFileValue)
				file.Encrypted = true
			}

			contents = newContents

			file.FileSize = int64(len(contents))
		}

		if project.Environment == "cloud" || file.StorageArea == "google_storage" {
			//log.Printf("[INFO] SHOULD UPLOAD FILE TO GOOGLE STORAGE with ID %s. Content length: %d", file.Id, len(contents))
			file.StorageArea = "google_storage"

			//applocation := fmt.Sprintf("gs://%s/triggers/outlooktrigger.zip", bucketName)

			bucket := project.StorageClient.Bucket(orgFileBucket)
			obj := bucket.Object(file.DownloadPath)

			w := obj.NewWriter(ctx)
			if _, err := fmt.Fprintln(w, string(contents)); err != nil {
				log.Printf("[ERROR] Failed to write the file to datastore: %s", err)
				return file.Id, err
			}

			// Close, just like writing a file.
			defer w.Close()
		} else if file.StorageArea == "s3" {
			if !StorageS3Enabled() {
				file.Status = "created"
				SetFile(ctx, *file)
				backendErr := errors.New("file has StorageArea=s3 but SHUFFLE_STORAGE_BACKEND is local")
				log.Printf("[ERROR] Object storage backend unavailable for file %s: %s", file.Id, backendErr)
				return file.Id, backendErr
			}

			if appendErr := AppendStorageData(ctx, file.DownloadPath, contents); appendErr != nil {
				file.Status = "created"
				SetFile(ctx, *file)
				log.Printf("[ERROR] Failed uploading file to object storage %s: %s", file.DownloadPath, appendErr)
				return file.Id, appendErr
			}

			log.Printf("[INFO] Added %d bytes to object storage file %s", len(contents), file.DownloadPath)
		} else {
			f, err := os.OpenFile(file.DownloadPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.ModePerm)

			if err != nil {
				// Rolling back file
				file.Status = "created"
				SetFile(ctx, *file)

				log.Printf("[ERROR] Failed uploading and creating file: %s", err)
				return file.Id, err
			} else {
				log.Printf("[INFO] File path %#v was made. Next step is to upload bytes: %d", file.DownloadPath, len(contents))
			}

			defer f.Close()
			reader := bytes.NewReader(contents)
			_, err = io.Copy(f, reader)
			if err != nil {
				log.Printf("[ERROR] Failed loading file contents into file %#v: %s", file.DownloadPath, err)
			} else {
				log.Printf("[INFO] Added %d bytes to file %s", len(contents), file.DownloadPath)
			}
		}
	}

	file.Status = "active"
	file.Md5sum = md5
	file.Sha256sum = fmt.Sprintf("%x", sha256Sum)
	file.FileSize = int64(len(contents))
	file.ContentType = http.DetectContentType(contents)

	if debug { 
		log.Printf("[DEBUG] MD5 for file %s (%s) is %s Type: %s and size: %d", file.Filename, file.Id, file.Md5sum, file.ContentType, file.FileSize)
	}

	err = SetFile(ctx, *file)
	if err != nil {
		log.Printf("[ERROR] Failed setting file back to active")
		return file.Id, err
	}

	return file.Id, nil
}

func HandleCreateFile(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// 1. Check user directly
	// 2. Check workflow execution authorization
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		//log.Printf("[AUDIT] INITIAL Api authentication failed in file creation: %s", err)

		orgId, err := fileExecutionAuthentication(request)
		if err != nil {
			log.Printf("[ERROR] Bad file authentication in create file: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		user.ActiveOrg.Id = orgId
		user.Username = "Execution File API"
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to edit files: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Println("Failed reading body")
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to read data"}`)))
		return
	}

	type FileStructure struct {
		Filename   string   `json:"filename"`
		OrgId      string   `json:"org_id"`
		WorkflowId string   `json:"workflow_id"`
		Namespace  string   `json:"namespace"`
		Tags       []string `json:"tags"`
	}

	var executionId string
	executionId = request.URL.Query().Get("execution_id")

	var curfile FileStructure
	err = json.Unmarshal(body, &curfile)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshaling: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to unmarshal data"}`)))
		return
	}

	if len(curfile.OrgId) == 0 {
		curfile.OrgId = user.ActiveOrg.Id
	}

	// Loads of validation below
	if len(curfile.OrgId) == 0 {
		log.Printf("[ERROR] Missing field during fileupload. Required: filename, org_id, workflow_id")
		log.Printf("INPUT: %s", string(body))
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Missing field. Required: filename, org_id, workflow_id"}`)))
		return
	}

	ctx := GetContext(request)
	if user.ActiveOrg.Id != curfile.OrgId {
		log.Printf("[ERROR] User can't access org %s", curfile.OrgId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Not allowed to access this organization ID"}`))
		return
	}

	if len(curfile.Filename) == 0 {
		curfile.Filename = "no_name"
	}

	var workflow *Workflow
	if curfile.WorkflowId == "global" || curfile.WorkflowId == "" {
		curfile.WorkflowId = "global"
		// PS: Not a security issue.
		// Files are global anyway, but the workflow_id is used to identify origin
		if debug {
			log.Printf("[DEBUG] Uploading filename %s for org %s as global file in namespace '%s'.", curfile.Filename, curfile.OrgId, curfile.Namespace)
		}
	} else {
		// Try to get the org and workflow in case they don't exist
		workflow, err = GetWorkflow(ctx, curfile.WorkflowId)
		if err != nil {
			log.Printf("[ERROR] Workflow %s doesn't exist.", curfile.WorkflowId)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Error with workflow id or org id"}`))
			return
		}

		_, err = GetOrg(ctx, curfile.OrgId)
		if err != nil {
			log.Printf("[ERROR] Org %s doesn't exist.", curfile.OrgId)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Error with workflow id or org id"}`))
			return
		}

		if workflow.ExecutingOrg.Id != curfile.OrgId {
			found := false

			log.Printf("[DEBUG] Workflow executing org (%s) isn't file Org Id (%s) in file create. %d orgs have access to it.", workflow.ExecutingOrg.Id, curfile.OrgId, len(workflow.Org))
			if len(workflow.Org) == 0 && len(executionId) > 0 {
				log.Printf("[DEBUG] Trying to get workflow from execution %s and no orgs are set (workflow probably is deleted!)", executionId)
				execution, err := GetWorkflowExecution(ctx, executionId)
				if err != nil {
					log.Printf("[ERROR] Execution %s doesn't exist.", executionId)
				} else if (curfile.OrgId == execution.OrgId) && (curfile.WorkflowId == execution.WorkflowId) {
					{
						found = true
					}
				}
			} else {
				for _, curorg := range workflow.Org {
					if curorg.Id == curfile.OrgId {
						found = true
						break
					}
				}
			}

			if !found {
				log.Printf("[ERROR] Org %s doesn't have access to %s. %s org should instead.", curfile.OrgId, curfile.WorkflowId, curfile.OrgId)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "Error with workflow id or org id"}`))
				return
			}
		}
	}

	if strings.Contains(curfile.Filename, "/") || strings.Contains(curfile.Filename, `"`) || strings.Contains(curfile.Filename, "..") || strings.Contains(curfile.Filename, "~") {
		//resp.WriteHeader(401)
		//resp.Write([]byte(`{"success": false, "reason": "Invalid characters in filename"}`))
		//return
		log.Printf("[WARNING] Invalid characters in filename %s. URL escaping to make sure nothing breaks.", curfile.Filename)
		curfile.Filename = url.QueryEscape(curfile.Filename)

	}

	// 1. Create the file object.
	if len(basepath) == 0 {
		basepath = "files"
	}

	folderPath := fmt.Sprintf("%s/%s/%s", basepath, curfile.OrgId, curfile.WorkflowId)
	if project.Environment != "cloud" {
		// Try to make the full file location
		err = os.MkdirAll(folderPath, os.ModePerm)
		if err != nil {
			log.Printf("[ERROR] Writing issue for file location creation: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed creating upload location"}`))
			return
		}
	}

	// Check if the file already exists in the category if unique=true is set
	// If it does, we should just return the file ID in the {success: true, id: "file_id"} json format
	unique, uniqueOk := request.URL.Query()["unique"]
	if uniqueOk && len(unique) > 0 && strings.ToLower(unique[0]) == "true" && len(curfile.Namespace) > 0 && len(curfile.Filename) > 0 {
		//log.Printf("\n\nOnly adding unique filenames (%s) in namespace %s\n\n", curfile.Filename, curfile.Namespace)

		orgId := user.ActiveOrg.Id
		files, err := FindSimilarFilename(ctx, curfile.Filename, orgId)
		if err != nil {
			//log.Printf("[ERROR] Couldn't find any similar files: %s", err)
		} else {

			for _, item := range files {
				if item.OrgId == orgId && item.Namespace == curfile.Namespace && item.Filename == curfile.Filename && item.Status == "active" {
					resp.WriteHeader(200)
					resp.Write([]byte(fmt.Sprintf(`{"success": true, "id": "%s", "duplicate": true}`, item.Id)))
					return
				}
			}

		}
	}

	filename := curfile.Filename
	fileId := fmt.Sprintf("file_%s", uuid.NewV4().String())
	downloadPath := fmt.Sprintf("%s/%s", folderPath, fileId)

	duplicateWorkflows := []string{}
	if curfile.WorkflowId != "global" {
		for _, trigger := range workflow.Triggers {
			if trigger.AppName == "Shuffle Workflow" && trigger.TriggerType == "SUBFLOW" {
				for _, parameter := range trigger.Parameters {
					if parameter.Name == "workflow" && len(parameter.Value) > 0 {

						found := false
						for _, workflow := range duplicateWorkflows {
							if workflow == parameter.Value {
								found = true
								break
							}
						}

						if !found {
							duplicateWorkflows = append(duplicateWorkflows, parameter.Value)
						}

						break
					}
				}
			}
		}
	}

	timeNow := time.Now().Unix()
	newFile := File{
		Id:           fileId,
		CreatedAt:    timeNow,
		UpdatedAt:    timeNow,
		Description:  "",
		Status:       "created",
		Filename:     filename,
		OrgId:        curfile.OrgId,
		WorkflowId:   curfile.WorkflowId,
		DownloadPath: downloadPath,
		Subflows:     duplicateWorkflows,
		StorageArea:  StorageAreaName(),
		Namespace:    curfile.Namespace,
		Tags:         curfile.Tags,
	}

	if project.Environment == "cloud" {
		newFile.StorageArea = "google_storage"
	}

	err = SetFile(ctx, newFile)
	if err != nil {
		log.Printf("[ERROR] Failed setting file: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed setting file reference"}`))
		return
	} else {
		if debug {
			log.Printf("[DEBUG] Created file %s with namespace %#v", newFile.DownloadPath, newFile.Namespace)
		}
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "id": "%s"}`, fileId)))

}

func HandleDownloadRemoteFiles(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just need to be logged in
	// FIXME - should have some permissions?
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in load files: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role != "admin" {
		log.Printf("Wrong user (%s) when downloading from github", user.Username)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Downloading remotely requires admin"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Error with body read: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Field1 & 2 can be a lot of things..
	type tmpStruct struct {
		URL    string `json:"url"`
		Field1 string `json:"field_1"` // Username
		Field2 string `json:"field_2"` // Password
		Field3 string `json:"field_3"` // Branch
		Path   string `json:"path"`

		Namespace string `json:"namespace"`
	}

	var input tmpStruct
	err = json.Unmarshal(body, &input)
	if err != nil {
		log.Printf("[DEBUG] Error with unmarshal tmpBody: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Find from the input.URL
	client := github.NewClient(nil)
	urlSplit := strings.Split(input.URL, "/")
	if len(urlSplit) < 5 {
		log.Printf("[ERROR] Invalid URL when downloading: %s", input.URL)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := GetContext(request)
	owner := ""
	repo := ""
	path := input.Path

	treeIndex := -1
	newPath := ""
	for cnt, item := range urlSplit[3:] {
		// Auto parsing url
		if item == "tree" && treeIndex == -1 && cnt > 1 {
			treeIndex = cnt
		}

		if cnt == 0 {
			owner = item
		} else if cnt == 1 {
			repo = item
		} else {
			if treeIndex != -1 && (path == "" || path == "/") && cnt > treeIndex+1 {
				newPath = fmt.Sprintf("%s/%s", newPath, item)
			}
		}
	}

	if len(newPath) > 0 {
		newPath = strings.TrimPrefix(newPath, "/")
		path = newPath
	}

	log.Printf("[DEBUG] Loading standard with git: %s/%s/%s", owner, repo, path)
	files, err := LoadStandardFromGithub(client, owner, repo, path, "")
	if err != nil {
		log.Printf("[DEBUG] Failed to load standard from github: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	log.Printf("[DEBUG] Found %d files in %s/%s/%s", len(files), owner, repo, path)

	if len(files) > 50 {
		files = files[:50]
	}

	// Expects them in the root level... hmm
	// FIXME: Recurse
	for _, item := range files {
		log.Printf("[DEBUG] Downloading standard file %s", *item.Path)
		fileContent, _, _, err := client.Repositories.GetContents(ctx, owner, repo, *item.Path, nil)
		if err != nil {
			log.Printf("[ERROR] Failed getting file %s: %s", *item.Path, err)
			continue
		}

		if fileContent == nil || fileContent.Content == nil {
			log.Printf("[ERROR] No content in file %s", *item.Path)
			continue
		}

		// Get the bytes of the file
		decoded, err := base64.StdEncoding.DecodeString(*fileContent.Content)
		if err != nil {
			log.Printf("[ERROR] Failed decoding standard file %s: %s", *item.Path, err)
			continue
		}

		timeNow := time.Now().Unix()

		// Get fileId based on decoded data as seed
		fileId := uuid.NewV5(uuid.NamespaceOID, string(*item.Path)).String()
		folderPath := fmt.Sprintf("%s/%s/%s", basepath, user.ActiveOrg.Id, "global")
		downloadPath := fmt.Sprintf("%s/%s", folderPath, fileId)
		file := File{
			Id:           fileId,
			CreatedAt:    timeNow,
			UpdatedAt:    timeNow,
			Description:  "",
			Status:       "active",
			Filename:     *item.Name,
			OrgId:        user.ActiveOrg.Id,
			WorkflowId:   "global",
			DownloadPath: downloadPath,
			Subflows:     []string{},
			StorageArea:  StorageAreaName(),
			Namespace:    strings.ReplaceAll(strings.ReplaceAll(path, "/", "_"), "..", "_"),
			Tags: []string{
				input.URL,
				path,
			},
		}

		if len(input.Namespace) > 0 {
			file.Namespace = input.Namespace
		}

		if project.Environment == "cloud" {
			file.StorageArea = "google_storage"
		}

		// Can be used for validation files for change
		var buf bytes.Buffer
		io.Copy(&buf, bytes.NewReader(decoded))
		contents := buf.Bytes()
		file.FileSize = int64(len(contents))
		file.ContentType = http.DetectContentType(contents)
		file.OriginalMd5sum = Md5sum(contents)

		buf.Reset()

		// Handle file encryption if an encryption key is set

		parsedKey := fmt.Sprintf("%s_%s", user.ActiveOrg.Id, file.Id)
		fileId, err = UploadFile(ctx, &file, parsedKey, contents)
		if err != nil {
			log.Printf("[ERROR] Failed to upload file %s: %s", fileId, err)
			continue
		}

		log.Printf("[DEBUG] Uploaded file %s with ID %s in category %#v", file.Filename, fileId, path)
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true}`)))
}

func HandleShareNamespace(resp http.ResponseWriter, request *http.Request) {

	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in share namespace: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role != "admin" {
		log.Printf("User (%s) isn't admin during namespace share", user.Username)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "only admin can share namespace"}`))
		return
	}

	var namespace string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("Path too short: %d", len(location))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		namespace = location[5]
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Error with body read: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	type shareNamespace struct {
		SelectedFiles []string `json:"selectedFiles"`
	}

	var share shareNamespace
	err = json.Unmarshal(body, &share)
	if err != nil {
		log.Printf("Failed unmarshaling (appauth): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(namespace) == 0 {
		log.Printf("[ERROR] Missing namespace in share namespace")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Missing namespace"}`))
		return
	}

	if len(share.SelectedFiles) == 0 {
		log.Printf("[ERROR] Missing selectedFiles in share namespace")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Missing selectedFiles"}`))
		return
	}

	ctx := GetContext(request)
	for _, fileId := range share.SelectedFiles {
		file, err := GetFile(ctx, fileId)
		if err != nil {
			log.Printf("[INFO] File %s not found: %s", fileId, err)
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		file.Namespace = namespace
		err = SetFile(ctx, *file)
		if err != nil {
			log.Printf("[ERROR] Failed setting file back to active")
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed setting file to active"}`))
			return
		}
	}

	log.Printf("[INFO] Successfully shared namespace %s for %d files", namespace, len(share.SelectedFiles))
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Namespace shared successfully!"}`)))
}

// destribute files to all sub orgs of parent org
func HandleSetFileConfig(resp http.ResponseWriter, request *http.Request) {

	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in load files: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.ActiveOrg.Role != "admin" {
		log.Printf("User (%s) isn't admin during file edit config", user.Username)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "only admin can edit file config"}`))
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

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Error with body read: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	type configFile struct {
		Id             string   `json:"id"`
		Action         string   `json:"action"`
		SelectedSuborg []string `json:"selected_suborgs"`
	}

	var config configFile
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
	file, err := GetFile(ctx, fileId)
	if err != nil {
		log.Printf("[INFO] File %s not found: %s", fileId, err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if config.Action == "suborg_distribute" {

		if len(config.SelectedSuborg) == 0 {
			file.SuborgDistribution = []string{}
		} else {
			file.SuborgDistribution = config.SelectedSuborg
		}

		err = SetFile(ctx, *file)
		if err != nil {
			log.Printf("[ERROR] Failed setting file back to active")
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed setting file to active"}`))
			return
		}

	}

	//if current org is suborg and file is distributed, get the parent org file
	foundOrg, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err == nil {
		for _, childOrg := range foundOrg.ChildOrgs {
			cacheKey := fmt.Sprintf("files_%s_%s", childOrg.Id, file.Namespace)
			DeleteCache(ctx, cacheKey)
		}
	}

	log.Printf("[INFO] Successfully updated file: %s for org: %s", file.Id, user.ActiveOrg.Id)

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "File updated successfully!"}`)))

}

func GetStorageClient(ctx context.Context, projectID string) (storage.Client, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return storage.Client{}, fmt.Errorf("failed to create storage client: %v", err)
	}

	return *client, nil
}

/*
	Optional object storage for file data.

	Shuffle persists binary data (file uploads, oversized execution payloads,
	workflow parameters and app image metadata) under SHUFFLE_FILE_LOCATION.
	With SHUFFLE_STORAGE_BACKEND=s3, this data is stored in an S3-compatible
	bucket (AWS S3, MinIO, Wasabi, Ceph) instead, so deployments can run
	without persistent volumes for it.

	Configuration (environment variables):
	  SHUFFLE_STORAGE_BACKEND   "local" (default), "s3"
	  SHUFFLE_S3_ENDPOINT       S3-compatible endpoint, e.g. "s3.amazonaws.com" or
	                            "minio.default.svc.cluster.local:9000"
	  SHUFFLE_S3_BUCKET         Bucket name (required for s3)
	  SHUFFLE_S3_PREFIX         Optional key prefix inside the bucket
	  SHUFFLE_S3_REGION         Region (default "us-east-1")
	  SHUFFLE_S3_ACCESS_KEY     Access key (falls back to AWS_ACCESS_KEY_ID)
	  SHUFFLE_S3_SECRET_KEY     Secret key (falls back to AWS_SECRET_ACCESS_KEY)
	  SHUFFLE_S3_USE_PATH_STYLE Force path-style addressing (default true, required
	                            for MinIO and most self-hosted S3 implementations)
	  SHUFFLE_S3_INSECURE       Use http:// against the endpoint

	Keys are always relative to SHUFFLE_FILE_LOCATION (the same relative
	layout used on disk), so switching between backends does not change how
	paths are referenced in the database and no migration is needed. The
	local backend is rooted at SHUFFLE_FILE_LOCATION via os.Root, which
	refuses path traversal outside of the storage directory.
*/

// Storage backend selection. The backend is resolved once per process from
// SHUFFLE_STORAGE_BACKEND: "local" (default) or "s3". With the s3 backend,
// s3StorageInit additionally sets up a minio client and verifies bucket
// access; the resulting error is returned by every storage operation until
// the configuration is fixed.
var (
	storageBackendOnce sync.Once
	storageBackendName string
	storageBackendErr  error

	s3Client *minio.Client
	s3Bucket string
	s3Prefix string
)

func storageBackendInit() {
	storageBackendOnce.Do(func() {
		storageBackendName = strings.ToLower(strings.TrimSpace(os.Getenv("SHUFFLE_STORAGE_BACKEND")))
		switch storageBackendName {
		case "", "local", "filesystem":
			storageBackendName = "local"
		case "s3", "s3compatible", "minio":
			if err := s3StorageInit(); err != nil {
				storageBackendName = "local"
				storageBackendErr = err
			}
		default:
			storageBackendName = "local"
			storageBackendErr = fmt.Errorf("unknown SHUFFLE_STORAGE_BACKEND '%s' (supported: local, s3)", os.Getenv("SHUFFLE_STORAGE_BACKEND"))
		}
	})
}

// StorageS3Enabled returns true when the s3 backend is configured.
func StorageS3Enabled() bool {
	storageBackendInit()
	return storageBackendName == "s3"
}

// StorageAreaName returns the StorageArea metadata value for newly created
// files, based on the configured storage backend.
func StorageAreaName() string {
	if StorageS3Enabled() {
		return "s3"
	}
	return "local"
}

// storageKey converts an absolute or basepath-prefixed path into a
// backend-relative object key. Absolute paths under the file location are
// normalized; relative paths pass through unchanged.
func storageKey(path string) string {
	base := strings.TrimRight(basepath, "/")
	clean := filepath.ToSlash(path)

	if len(base) > 0 && strings.HasPrefix(clean, base+"/") {
		clean = strings.TrimPrefix(clean, base+"/")
	}

	return strings.TrimLeft(clean, "/")
}

// WriteStorageData persists data under the given path. The path is
// interpreted relative to SHUFFLE_FILE_LOCATION (basepath-prefixed or
// absolute paths are normalized), replacing any previous content.
func WriteStorageData(path string, data []byte) error {
	if err := storageBackendErr; err != nil {
		return err
	}

	if StorageS3Enabled() {
		return s3PutObject(storageKey(path), data)
	}

	return writeLocalStorageFile(storageKey(path), data)
}

// AppendStorageData adds data to the end of the object at the given path,
// creating it if missing. For the s3 backend this is a read-modify-write.
func AppendStorageData(ctx context.Context, path string, data []byte) error {
	if err := storageBackendErr; err != nil {
		return err
	}

	if StorageS3Enabled() {
		return s3AppendObject(ctx, storageKey(path), data)
	}

	return appendLocalStorageFile(storageKey(path), data)
}

// ReadStorageData reads data previously written by WriteStorageData. Not-found
// errors are always compatible with os.IsNotExist.
func ReadStorageData(path string) ([]byte, error) {
	if err := storageBackendErr; err != nil {
		return nil, err
	}

	if StorageS3Enabled() {
		return s3GetObject(storageKey(path))
	}

	return readLocalStorageFile(storageKey(path))
}

// DeleteStorageData removes data written by WriteStorageData.
func DeleteStorageData(path string) error {
	if err := storageBackendErr; err != nil {
		return err
	}

	if StorageS3Enabled() {
		return s3RemoveObject(context.Background(), storageKey(path))
	}

	return deleteLocalStorageFile(storageKey(path))
}

// The local backend stores objects on the filesystem under
// SHUFFLE_FILE_LOCATION, using os.Root so that keys cannot escape the
// storage directory. The root handle is opened per operation: basepath is a
// process constant in practice, and the open cost is negligible next to the
// I/O it wraps.
func openLocalStorageRoot() (*os.Root, error) {
	rootPath := basepath
	if len(rootPath) == 0 {
		rootPath = "files"
	}

	if err := os.MkdirAll(rootPath, 0755); err != nil {
		return nil, fmt.Errorf("create storage directory %s: %w", rootPath, err)
	}

	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open storage root %s: %w", rootPath, err)
	}

	return root, nil
}

func writeLocalStorageFile(key string, data []byte) error {
	root, err := openLocalStorageRoot()
	if err != nil {
		return err
	}
	defer root.Close()

	if dir := filepath.Dir(key); dir != "." {
		if err := root.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create directory for %s: %w", key, err)
		}
	}

	if err := root.WriteFile(key, data, 0644); err != nil {
		return fmt.Errorf("write %s: %w", key, err)
	}

	return nil
}

func appendLocalStorageFile(key string, data []byte) error {
	root, err := openLocalStorageRoot()
	if err != nil {
		return err
	}
	defer root.Close()

	if dir := filepath.Dir(key); dir != "." {
		if err := root.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create directory for %s: %w", key, err)
		}
	}

	f, err := root.OpenFile(key, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open %s for appending: %w", key, err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("append to %s: %w", key, err)
	}

	return nil
}

func readLocalStorageFile(key string) ([]byte, error) {
	root, err := openLocalStorageRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()

	data, err := root.ReadFile(key)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func deleteLocalStorageFile(key string) error {
	root, err := openLocalStorageRoot()
	if err != nil {
		return err
	}
	defer root.Close()

	return root.Remove(key)
}

// The s3 backend stores objects in an S3-compatible bucket using minio-go.
func s3StorageInit() error {
	endpoint := strings.TrimSpace(os.Getenv("SHUFFLE_S3_ENDPOINT"))
	bucket := strings.TrimSpace(os.Getenv("SHUFFLE_S3_BUCKET"))

	if len(bucket) == 0 {
		return errors.New("SHUFFLE_S3_BUCKET is required when SHUFFLE_STORAGE_BACKEND=s3")
	}

	accessKey := os.Getenv("SHUFFLE_S3_ACCESS_KEY")
	if len(accessKey) == 0 {
		accessKey = os.Getenv("AWS_ACCESS_KEY_ID")
	}

	secretKey := os.Getenv("SHUFFLE_S3_SECRET_KEY")
	if len(secretKey) == 0 {
		secretKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}

	region := strings.TrimSpace(os.Getenv("SHUFFLE_S3_REGION"))
	if len(region) == 0 {
		region = "us-east-1"
	}

	usePathStyle := true
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SHUFFLE_S3_USE_PATH_STYLE"))) {
	case "false", "0", "no":
		usePathStyle = false
	}

	secure := true
	if strings.HasPrefix(endpoint, "http://") {
		secure = false
		endpoint = strings.TrimPrefix(endpoint, "http://")
	} else if strings.HasPrefix(endpoint, "https://") {
		endpoint = strings.TrimPrefix(endpoint, "https://")
	} else if strings.EqualFold(strings.TrimSpace(os.Getenv("SHUFFLE_S3_INSECURE")), "true") {
		secure = false
	}

	if len(endpoint) == 0 {
		endpoint = "s3.amazonaws.com"
	}

	client, err := minio.New(endpoint, &minio.Options{
		// With empty keys, minio-go falls back to ambient credentials such
		// as IAM roles (e.g. IRSA on EKS).
		Creds:        credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:       secure,
		Region:       region,
		BucketLookup: bucketLookupType(usePathStyle),
	})
	if err != nil {
		return fmt.Errorf("initialize S3 client for endpoint '%s': %w", endpoint, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err = client.BucketExists(ctx, bucket); err != nil {
		return fmt.Errorf("verify access to S3 bucket '%s': %w", bucket, err)
	}

	s3Prefix = strings.Trim(os.Getenv("SHUFFLE_S3_PREFIX"), "/")
	if len(s3Prefix) > 0 {
		s3Prefix += "/"
	}

	log.Printf("[INFO] Using S3-compatible object storage: endpoint=%s bucket=%s prefix='%s' pathStyle=%t", endpoint, bucket, s3Prefix, usePathStyle)

	s3Client = client
	s3Bucket = bucket

	return nil
}

func bucketLookupType(usePathStyle bool) minio.BucketLookupType {
	if usePathStyle {
		return minio.BucketLookupPath
	}
	return minio.BucketLookupAuto
}

func s3ObjectKey(key string) string {
	return s3Prefix + strings.TrimLeft(key, "/")
}

// s3ObjectError wraps S3 errors so callers can keep using os.IsNotExist on them.
func s3ObjectError(key string, err error) error {
	resp := minio.ToErrorResponse(err)
	if resp.Code == "NoSuchKey" {
		return &os.PathError{Op: "open", Path: key, Err: os.ErrNotExist}
	}
	return fmt.Errorf("s3 object '%s': %w", key, err)
}

func s3GetObject(key string) ([]byte, error) {
	obj, err := s3Client.GetObject(context.Background(), s3Bucket, s3ObjectKey(key), minio.GetObjectOptions{})
	if err != nil {
		return nil, s3ObjectError(key, err)
	}
	defer obj.Close()

	// minio-go performs the actual request lazily; stat it so callers get a
	// not-found error from ReadStorageData rather than a body read error.
	if _, err = obj.Stat(); err != nil {
		return nil, s3ObjectError(key, err)
	}

	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, s3ObjectError(key, err)
	}

	return data, nil
}

func s3PutObject(key string, data []byte) error {
	_, err := s3Client.PutObject(context.Background(), s3Bucket, s3ObjectKey(key), bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return fmt.Errorf("put object '%s': %w", key, err)
	}

	return nil
}

// s3AppendObject emulates appends via read-modify-write, which is the best an
// object store can offer. The existing object is buffered in memory; file
// uploads using this path are bounded by maxFileSize (10MB on-prem).
func s3AppendObject(ctx context.Context, key string, data []byte) error {
	existing, err := s3GetObject(key)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("read object '%s' for append: %w", key, err)
		}
		existing = nil
	}

	merged := append(existing, data...)
	if err := s3PutObject(key, merged); err != nil {
		return fmt.Errorf("write appended object '%s': %w", key, err)
	}

	return nil
}

func s3RemoveObject(ctx context.Context, key string) error {
	return s3Client.RemoveObject(ctx, s3Bucket, s3ObjectKey(key), minio.RemoveObjectOptions{})
}
