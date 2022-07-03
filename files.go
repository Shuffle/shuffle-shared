package shuffle

/*
	Handles files within Workflows.of Shuffle
*/

import (
	"archive/zip"
	//"bufio"
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

	"github.com/satori/go.uuid"
)

var basepath = os.Getenv("SHUFFLE_FILE_LOCATION")
var orgFileBucket = "shuffle_org_files"

func fileAuthentication(request *http.Request) (string, error) {
	executionId, ok := request.URL.Query()["execution_id"]
	if ok && len(executionId) > 0 {
		ctx := getContext(request)
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

		log.Printf("[INFO] Authorization is correct for execution %s!", executionId[0])
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
		log.Printf("[INFO] INITIAL Api authentication failed in file LIST: %s", err)
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

	ctx := getContext(request)
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
		Files:      files,
		Namespaces: []string{"default"},
	}
	for _, file := range files {
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
		log.Printf("[INFO] INITIAL Api authentication failed in file deletion: %s", err)

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

	log.Printf("\n\n[INFO] User is trying to GET File Meta for %s\n\n", fileId)

	// 1. Verify if the user has access to the file: org_id and workflow
	log.Printf("[INFO] Should GET FILE META for %s if user has access", fileId)
	ctx := getContext(request)
	file, err := GetFile(ctx, fileId)
	if err != nil {
		log.Printf("[INFO] File %s not found: %s", fileId, err)
		resp.WriteHeader(401)
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

	log.Printf("\n\n[INFO] User is trying to delete file %s\n\n", fileId)

	// 1. Check user directly
	// 2. Check workflow execution authorization
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[INFO] INITIAL Api authentication failed in file deletion: %s", err)

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

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to delete files: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	// 1. Verify if the user has access to the file: org_id and workflow
	log.Printf("[INFO] Should DELETE file %s if user has access", fileId)
	ctx := getContext(request)
	file, err := GetFile(ctx, fileId)
	if err != nil {
		log.Printf("[INFO] File %s not found: %s", fileId, err)
		resp.WriteHeader(401)
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
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// FIXME: Actually delete the file.
	if project.Environment == "cloud" || file.StorageArea == "google_storage" {
		log.Printf("[DEBUG] Deleted file %s from Google cloud storage", fileId)
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
		log.Printf("[ERROR] Failed setting file to deleted")
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed setting file to deleted"}`))
		return
	}

	/*
		//Actually delete it?
		err = DeleteKey(ctx, "files", fileId)
		if err != nil {
			log.Printf("Failed deleting file with ID %s: %s", fileId, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	*/

	log.Printf("[INFO] Successfully deleted file %s", fileId)
	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
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

	log.Printf("\n\n[INFO] User is trying to download files from namespace %s\n\n", namespace)

	// 1. Check user directly
	// 2. Check workflow execution authorization
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("INITIAL Api authentication failed in file download: %s", err)

		orgId, err := fileAuthentication(request)
		if err != nil {
			log.Printf("Bad file authentication in get namespace %s: %s", namespace, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		user.ActiveOrg.Id = orgId
		user.Username = "Execution File API"
	}

	ctx := getContext(request)
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
	}

	for _, file := range files {
		if file.Status != "active" {
			log.Printf("File %s (%s) is not active", file.Filename, file.Id)
			continue
		}

		if file.Namespace == namespace && file.OrgId == user.ActiveOrg.Id {
			fileResponse.Files = append(fileResponse.Files, file)
		}
	}

	log.Printf("Found %d (%d) files for namespace %s", len(files), len(fileResponse.Files), namespace)

	//zipfile := fmt.Sprintf("%s.zip", namespace)
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	packed := 0
	for _, file := range fileResponse.Files {
		var filedata = []byte{}
		if file.Encrypted {
			if project.Environment == "cloud" || file.StorageArea == "google_storage" {
				log.Printf("[WARNING] No namespace handler for cloud decryption!")
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
				data, err := HandleKeyDecryption(allText, passphrase)
				if err != nil {
					log.Printf("[ERROR] Failed decrypting file: %s", err)
				} else {
					log.Printf("[DEBUG] File size reduced from %d to %d after decryption", len(allText), len(data))
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
		log.Printf("Packing failed to close zip file writer: %v", err)
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

	log.Printf("Packed %d files from namespace %s into the zip", packed, namespace)
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
		log.Printf("INITIAL Api authentication failed in file download: %s", err)

		orgId, err := fileAuthentication(request)
		if err != nil {
			log.Printf("[WARNING] Bad file authentication in get for ID %s: %s", fileId, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		user.ActiveOrg.Id = orgId
		user.Username = "Execution File API"
	}

	log.Printf("[AUDIT] User %s (%s) downloading file %s for org %s", user.Username, user.Id, fileId, user.ActiveOrg.Id)

	// 1. Verify if the user has access to the file: org_id and workflow
	ctx := getContext(request)
	file, err := GetFile(ctx, fileId)
	if err != nil {
		log.Printf("[ERROR] File %s not found: %s", fileId, err)
		resp.WriteHeader(401)
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

	if file.Status != "active" {
		log.Printf("[WARNING] File status isn't active, but %s. Can't continue.", file.Status)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "The file isn't ready to be downloaded yet. Status required: active"}`))
		return
	}

	// Fixme: More auth: org and workflow!
	downloadPath := file.DownloadPath

	if project.Environment == "cloud" || file.StorageArea == "google_storage" {
		log.Printf("[AUDIT] %s (%s) downloaded file %s from google storage", user.Username, user.Id, file.Id)

		bucket := project.StorageClient.Bucket(orgFileBucket)
		obj := bucket.Object(file.DownloadPath)
		fileReader, err := obj.NewReader(ctx)
		if err != nil {
			log.Printf("[ERROR] Reader error: %s", err)

			file.Status = "deleted"
			err = SetFile(ctx, *file)
			if err != nil {
				log.Printf("[ERROR] SetFile error while uploading")
				resp.WriteHeader(500)
				resp.Write([]byte(`{"success": false, "reason": "Failed setting file to deleted"}`))
				return
			}

			//File not found, send 404
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "File doesn't exist in google cloud storage"}`))
			return
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

			passphrase := fmt.Sprintf("%s_%s", user.ActiveOrg.Id, file.Id)
			data, err := HandleKeyDecryption(allText, passphrase)
			if err != nil {
				log.Printf("[ERROR] Failed decrypting file: %s", err)
			} else {
				log.Printf("[DEBUG] File size reduced from %d to %d after decryption", len(allText), len(data))
				allText = []byte(data)
			}

			FileContentType := http.DetectContentType(allText)
			FileSize := strconv.FormatInt(int64(len(allText)), 10) //Get file size as a string
			//Send the headers
			log.Printf("Content Type: %#v", FileContentType)
			resp.Header().Set("Content-Disposition", "attachment; filename="+file.Filename)
			resp.Header().Set("Content-Type", FileContentType)
			resp.Header().Set("Content-Length", FileSize)

			reader := bytes.NewReader(allText)
			io.Copy(resp, reader)
			return

		}

		FileHeader := make([]byte, 512)
		FileContentType := http.DetectContentType(FileHeader)
		resp.Header().Set("Content-Disposition", "attachment; filename="+file.Filename)
		resp.Header().Set("Content-Type", FileContentType)

		io.Copy(resp, fileReader)

	} else if file.StorageArea == "s3" {
		log.Printf("[INFO] Trying to download file %s from s3", file.Id)
	} else {
		log.Printf("[INFO] Downloadpath: %s", downloadPath)
		Openfile, err := os.Open(downloadPath)
		defer Openfile.Close() //Close after function return
		if err != nil {
			file.Status = "deleted"
			err = SetFile(ctx, *file)
			if err != nil {
				log.Printf("Failed setting file to uploading")
				resp.WriteHeader(500)
				resp.Write([]byte(`{"success": false, "reason": "Failed setting file to deleted"}`))
				return
			}

			//File not found, send 404
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "File doesn't exist locally"}`))
			return
		}

		if file.Encrypted {
			log.Printf("[DEBUG] Should handle file decryption of %s.", fileId)
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
			data, err := HandleKeyDecryption(allText, passphrase)
			if err != nil {
				log.Printf("[ERROR] Failed decrypting file: %s", err)
			} else {
				log.Printf("[DEBUG] File size reduced from %d to %d after decryption", len(allText), len(data))
				allText = []byte(data)
			}

			FileContentType := http.DetectContentType(allText)
			FileSize := strconv.FormatInt(int64(len(allText)), 10) //Get file size as a string
			//Send the headers
			resp.Header().Set("Content-Disposition", "attachment; filename="+file.Filename)
			resp.Header().Set("Content-Type", FileContentType)
			resp.Header().Set("Content-Length", FileSize)

			reader := bytes.NewReader(allText)
			io.Copy(resp, reader)
			return
		} else {
			log.Printf("[DEBUG] Not decrypting file before download.")
		}

		//File is found, create and send the correct headers
		//Get the Content-Type of the file
		//Create a buffer to store the header of the file in
		//Copy the headers into the FileHeader buffer
		//Get content type of file
		FileHeader := make([]byte, 512)
		Openfile.Read(FileHeader)
		FileContentType := http.DetectContentType(FileHeader)

		//Get the file size
		FileStat, _ := Openfile.Stat()                     //Get info from file
		FileSize := strconv.FormatInt(FileStat.Size(), 10) //Get file size as a string

		//Send the headers
		resp.Header().Set("Content-Disposition", "attachment; filename="+file.Filename)
		resp.Header().Set("Content-Type", FileContentType)
		resp.Header().Set("Content-Length", FileSize)

		//Send the file
		//We read 512 bytes from the file already, so we reset the offset back to 0
		Openfile.Seek(0, 0)
		io.Copy(resp, Openfile) //'Copy' the file to the client
	}
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
		log.Printf("INITIAL Api authentication failed in file upload: %s", err)

		orgId, err := fileAuthentication(request)
		if err != nil {
			log.Printf("Bad file authentication in create file: %s", err)
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

	log.Printf("[INFO] Should UPLOAD file %s if user has access", fileId)
	ctx := getContext(request)
	file, err := GetFile(ctx, fileId)
	if err != nil {
		log.Printf("File %s not found: %s", fileId, err)
		resp.WriteHeader(401)
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
		log.Printf("User %s doesn't have access to %s", user.Username, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	log.Printf("[INFO] STATUS: %s", file.Status)
	if file.Status != "created" {
		log.Printf("File status isn't created. Can't upload.")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "This file already has data."}`))
		return
	}

	// Read the file from the upload request
	request.ParseMultipartForm(32 << 20)
	parsedFile, _, err := request.FormFile("shuffle_file")
	if err != nil {
		log.Printf("[ERROR] Couldn't upload file: %s", err)
		resp.WriteHeader(401)
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
	//log.Printf("File content: %s\n%x", string(contents))

	file.FileSize = int64(len(contents))
	file.ContentType = http.DetectContentType(contents)

	buf.Reset()

	// Handle file encryption if an encryption key is set
	newContents := contents
	parsedKey := fmt.Sprintf("%s_%s", user.ActiveOrg.Id, file.Id)
	newFileValue, err := handleKeyEncryption(contents, parsedKey)
	if err != nil {
		log.Printf("[ERROR] Failed encrypting file to be stored correctly: %s", err)
		newContents = contents
	} else {
		newContents = []byte(newFileValue)
		file.Encrypted = true
	}

	log.Printf("[DEBUG] Got old length %d vs encrypted length %d", len(contents), len(newFileValue))

	err = uploadFile(ctx, file, newContents)
	if err != nil {
		log.Printf("[ERROR] Failed to upload file: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed file upload in Shuffle"}`))
		return
	}

	log.Printf("[INFO] Successfully uploaded file ID %s", file.Id)
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true}`)))
}

func uploadFile(ctx context.Context, file *File, contents []byte) error {
	md5 := Md5sum(contents)
	sha256Sum := sha256.Sum256(contents)

	if project.Environment == "cloud" || file.StorageArea == "google_storage" {
		log.Printf("[INFO] SHOULD UPLOAD FILE TO GOOGLE STORAGE with ID %s. Content length: %d", file.Id, len(contents))
		file.StorageArea = "google_storage"

		//applocation := fmt.Sprintf("gs://%s/triggers/outlooktrigger.zip", bucketName)

		bucket := project.StorageClient.Bucket(orgFileBucket)
		obj := bucket.Object(file.DownloadPath)

		w := obj.NewWriter(ctx)
		if _, err := fmt.Fprintln(w, string(contents)); err != nil {
			log.Printf("[ERROR] Failed to write the file to datastore: %s", err)
			return err
		}

		// Close, just like writing a file.
		defer w.Close()
	} else if file.StorageArea == "s3" {
		log.Printf("SHOULD UPLOAD TO S3!")
	} else {
		f, err := os.OpenFile(file.DownloadPath, os.O_WRONLY|os.O_CREATE, os.ModePerm)
		if err != nil {
			// Rolling back file
			file.Status = "created"
			SetFile(ctx, *file)

			log.Printf("[ERROR] Failed uploading and creating file: %s", err)
			return err
		}

		defer f.Close()
		reader := bytes.NewReader(contents)
		io.Copy(f, reader)
	}

	// FIXME: Set this one to 200 anyway? Can't download file then tho..
	file.Status = "active"
	file.Md5sum = md5
	file.Sha256sum = fmt.Sprintf("%x", sha256Sum)
	file.FileSize = int64(len(contents))
	file.ContentType = http.DetectContentType(contents)

	log.Printf("[INFO] MD5 for file %s (%s) is %s and SHA256 is %s. Type: %s and size: %d", file.Filename, file.Id, file.Md5sum, file.Sha256sum, file.ContentType, file.FileSize)

	err := SetFile(ctx, *file)
	if err != nil {
		log.Printf("[ERROR] Failed setting file back to active")
		return err
	}

	return nil
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
		log.Printf("[INFO] INITIAL Api authentication failed in file creation: %s", err)

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
		Filename   string `json:"filename"`
		OrgId      string `json:"org_id"`
		WorkflowId string `json:"workflow_id"`
		Namespace  string `json:"namespace"`
	}

	var curfile FileStructure
	err = json.Unmarshal(body, &curfile)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshaling: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to unmarshal data"}`)))
		return
	}

	// Loads of validation below
	if len(curfile.OrgId) == 0 || len(curfile.WorkflowId) == 0 {
		log.Printf("[ERROR] Missing field during fileupload. Required: filename, org_id, workflow_id")
		log.Printf("INPUT: %s", string(body))
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Missing field. Required: filename, org_id, workflow_id"}`)))
		return
	}

	ctx := getContext(request)
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
	if curfile.WorkflowId == "global" {
		// PS: Not a security issue.
		// Files are global anyway, but the workflow_id is used to identify origin
		log.Printf("[INFO] Uploading filename %s for org %s as global file.", curfile.Filename, curfile.OrgId)
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
			for _, curorg := range workflow.Org {
				if curorg.Id == curfile.OrgId {
					found = true
					break
				}
			}

			if !found {
				log.Printf("[ERROR] Org %s doesn't have access to %s.", curfile.OrgId, curfile.WorkflowId)
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
