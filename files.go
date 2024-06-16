package shuffle

/*
	Handles files for Shuffle. Uses ID's to reference everything
*/

import (
	"archive/zip"
	"encoding/base64"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
	"github.com/google/go-github/v28/github"
)

var basepath = os.Getenv("SHUFFLE_FILE_LOCATION")
var orgFileBucket = "shuffle_org_files"
var maxFileSize = 10000000 // raw 10mb max filesize on cloud

func init() {
	if len(os.Getenv("SHUFFLE_ORG_BUCKET")) > 0 {
		orgFileBucket = os.Getenv("SHUFFLE_ORG_BUCKET")
	} else {
		// Using standard bucket
	}

	log.Printf("[DEBUG] Inside Files Init with org bucket name %#v", orgFileBucket)
}

func fileAuthentication(request *http.Request) (string, error) {
	executionId, ok := request.URL.Query()["execution_id"]
	if ok && len(executionId) > 0 {
		ctx := GetContext(request)
		workflowExecution, err := GetWorkflowExecution(ctx, executionId[0])
		if err != nil {
			log.Printf("[ERROR] Couldn't find execution ID %s", executionId[0])
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
func fileExists(filename string) bool {
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

		orgId, err := fileAuthentication(request)
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

		orgId, err := fileAuthentication(request)
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
			if fileExists(file.DownloadPath) {
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
		err = DeleteKey(ctx, "files", fileId)
		if err != nil {
			log.Printf("Failed deleting file with ID %s: %s", fileId, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
		log.Printf("[INFO] Deleted file %s from database", fileId)
	}

	log.Printf("[INFO] Successfully deleted file %s for org %s", fileId, user.ActiveOrg.Id)
	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func LoadStandardFromGithub(client *github.Client, owner, repo, path, filename string) ([]*github.RepositoryContent, error) {
	var err error

	ctx := context.Background()
	files := []*github.RepositoryContent{}

	cacheKey := fmt.Sprintf("github_%s_%s_%s", owner, repo, path)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &files)
			if err == nil {
				//return files, nil
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

	if len(files) == 0 {
		log.Printf("[ERROR] No files found in namespace '%s' on Github - Used for integration framework", path)
		return []*github.RepositoryContent{}, nil
	}

	if len(filename) == 0 {
		return []*github.RepositoryContent{}, nil
	}

	matchingFiles := []*github.RepositoryContent{}
	for _, item := range files {
		if len(filename) > 0 && strings.HasPrefix(*item.Name, filename) {
			matchingFiles = append(matchingFiles, item)
		}
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

	return matchingFiles, nil
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

	namespace = strings.Replace(namespace, "%20", " ", -1)

	// 1. Check user directly
	// 2. Check workflow execution authorization
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		//log.Printf("[AUDIT] INITIAL Api authentication failed in file download: %s", err)
		orgId, err := fileAuthentication(request)
		if err != nil {
			log.Printf("[WARNING] Bad file authentication in get namespace %s: %s", namespace, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		user.ActiveOrg.Id = orgId
		user.Username = "Execution File API"
	}

	log.Printf("[AUDIT] User '%s' (%s) is trying to get files from namespace %#v", user.Username, user.Id, namespace)

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
				Name: file.Filename,
				ID:   file.Id,
				Type: file.Type,
				UpdatedAt: file.UpdatedAt,
				Md5Sum: file.Md5sum,
				Status: file.Status,
				FileSize: file.FileSize,
			})
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
					fileId := "file_"+uuid.NewV4().String()
	
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
						StorageArea:  "local",
						Namespace:    namespace,
						Tags:         []string{
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
					fileId, err = uploadFile(ctx, &file, parsedKey, contents)
					if err != nil {
						log.Printf("[ERROR] Failed to upload file %s: %s", fileId, err)
						continue
					}

					log.Printf("[DEBUG] Uploaded file %#v with ID %s in category %#v", file.Filename, fileId, namespace)

					fileResponse.List = append(fileResponse.List, BaseFile{
						Name: file.Filename,
						ID:   fileId,
						Type: file.Type,
						UpdatedAt: file.UpdatedAt,
						Md5Sum: file.Md5sum,
						Status: file.Status,
						FileSize: file.FileSize,
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

	//zipfile := fmt.Sprintf("%s.zip", namespace)
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	packed := 0
	for _, file := range fileResponse.Files {
		var filedata = []byte{}
		if file.Encrypted {
			if project.Environment == "cloud" || file.StorageArea == "google_storage" {
				log.Printf("[ERROR] No namespace handler for cloud decryption!")
			} else {
				Openfile, err := os.Open(file.DownloadPath)
				defer Openfile.Close() //Close after function return

				allText := []byte{}
				buf := make([]byte, 1024)
				for {
					n, err := Openfile.Read(buf)
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

				passphrase := fmt.Sprintf("%s_%s", user.ActiveOrg.Id, file.Id)
				if len(file.ReferenceFileId) > 0 {
					passphrase = fmt.Sprintf("%s_%s", user.ActiveOrg.Id, file.ReferenceFileId)
				}

				data, err := HandleKeyDecryption(allText, passphrase)
				if err != nil {
					log.Printf("[ERROR] Failed decrypting file (3): %s", err)
				} else {
					//log.Printf("[DEBUG] File size of %s reduced from %d to %d after decryption (1)", file.Id, len(allText), len(data))
					allText = []byte(data)
				}

				filedata = allText
			}
		} else {
			filedata, err = ioutil.ReadFile(file.DownloadPath)
			if err != nil {
				log.Printf("Filereading failed for %s create zip file : %v", file.Filename, err)
				continue
			}
		}

		//log.Printf("DATA: %s", string(filedata))

		zipFile, err := zipWriter.Create(file.Filename)
		if err != nil {
			log.Printf("[WARNING] Packing failed for %s create zip file: %v", file.Filename, err)
			continue
		}

		// Have to use Fprintln otherwise it tries to parse all strings etc.
		if _, err := fmt.Fprintln(zipFile, string(filedata)); err != nil {
			log.Printf("[WARNING] Datapasting failed for %s when creating zip file from bucket: %v", file.Filename, err)
			continue
		}

		packed += 1
	}

	err = zipWriter.Close()
	if err != nil {
		log.Printf("[WARNING] Packing failed to close zip file writer: %v", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if packed == 0 {
		log.Printf("[WARNING] Couldn't find anything for namespace %s in org %s", namespace, user.ActiveOrg.Id)
		resp.WriteHeader(401)
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

		orgId, err := fileAuthentication(request)
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
			log.Printf("[ERROR] Reader error for %s in bucket %s: %s", downloadPath, orgFileBucket, err)

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
		log.Printf("[INFO] Trying to download file %s from s3", file.Id)
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
		orgId, err := fileAuthentication(request)
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
		log.Println("[ERROR] Failed reading file body: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to read data"}`)))
		return
	}

	if project.Environment == "cloud" && len(body) > maxFileSize {
		log.Printf("[ERROR] Max filesize is 10MB in cloud environment")
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "File too large. Max is 10mb"}`))
		return
	}

	file.FileSize = int64(len(body))
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

	fileId, err = uploadFile(ctx, file, parsedKey, body)
	if err != nil {
		log.Printf("[ERROR] Failed to upload file with ID %s: %s", fileId, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed file upload in Shuffle"}`))
		return
	}

	log.Printf("[INFO] Successfully edited file ID %s", file.Id)
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

		orgId, err := fileAuthentication(request)
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

	if project.Environment == "cloud" && len(contents) > maxFileSize {
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
	fileId, err = uploadFile(ctx, file, parsedKey, contents)
	if err != nil {
		log.Printf("[ERROR] Failed to upload file %s: %s", fileId, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed file upload in Shuffle"}`))
		return
	}

	log.Printf("[INFO] Successfully uploaded file ID %s", file.Id)
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "file_id": "%s"}`, fileId)))
}

func uploadFile(ctx context.Context, file *File, encryptionKey string, contents []byte) (string, error) {
	md5 := Md5sum(contents)
	sha256Sum := sha256.Sum256(contents)

	// Should look for another file with the same md5
	outputFiles, err := FindSimilarFile(ctx, md5, file.OrgId)
	if len(outputFiles) > 0 {
		outputFile := outputFiles[0]
		log.Printf("[INFO] Already found a file with the same Md5 '%s' for org '%s' in ID: %s. Referencing same location.", md5, file.OrgId, outputFile.Id)

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
		log.Printf("[INFO] No similar file found with md5 %s. Original Md5: %s", md5, file.OriginalMd5sum)
		if len(file.OriginalMd5sum) > 0 && file.OriginalMd5sum != md5 {
			log.Printf("[DEBUG] Md5 has changed!")
		}

		if len(encryptionKey) > 0 {
			newContents := contents
			newFileValue, err := handleKeyEncryption(contents, encryptionKey)
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
			log.Printf("SHOULD UPLOAD TO S3!")
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

	log.Printf("[INFO] MD5 for file %s (%s) is %s Type: %s and size: %d", file.Filename, file.Id, file.Md5sum, file.ContentType, file.FileSize)

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

		orgId, err := fileAuthentication(request)
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
		log.Printf("[INFO] Uploading filename %s for org %s as global file in namespace '%s'.", curfile.Filename, curfile.OrgId, curfile.Namespace)
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
					} else if (curfile.OrgId == execution.OrgId) && (curfile.WorkflowId == execution.WorkflowId) {{
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
		StorageArea:  "local",
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
		log.Printf("[INFO] Created file %s with namespace %#v", newFile.DownloadPath, newFile.Namespace)
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
		Path  string `json:"path"` 

	}

	var input tmpStruct
	err = json.Unmarshal(body, &input)
	if err != nil {
		log.Printf("Error with unmarshal tmpBody: %s", err)
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

	for cnt, item := range urlSplit[3:] { 
		if cnt == 0 {
			owner = item
		} else if cnt == 1 {
			repo = item
		}
	}

	log.Printf("[DEBUG] Loading standard from github: %s/%s/%s", owner, repo, path)

	files, err := LoadStandardFromGithub(client, owner, repo, path, "") 
	if err != nil {
		log.Printf("[DEBUG] Failed to load standard from github: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(files) > 50 {
		files = files[:50]
	}

	for _, item := range files {
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
			StorageArea:  "local",
			Namespace:    path,
			Tags:         []string{
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
		fileId, err = uploadFile(ctx, &file, parsedKey, contents)
		if err != nil {
			log.Printf("[ERROR] Failed to upload file %s: %s", fileId, err)
			continue
		}

		log.Printf("[DEBUG] Uploaded file %s with ID %s in category %#v", file.Filename, fileId, path)
	}


	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true}`)))
}
