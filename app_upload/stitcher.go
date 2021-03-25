package main

import (
	"github.com/frikky/shuffle-shared"

	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"archive/tar"
	//"cloud.google.com/go/iam"
	"cloud.google.com/go/storage"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"google.golang.org/api/cloudfunctions/v1"
	"gopkg.in/yaml.v2"
)

var gceProject = "shuffler"
var bucketName = "shuffler.appspot.com"
var publicBucket = "shuffle_public"
var appSearchIndex = "appsearch"

// CONFIGURE APP LOCATIONS TO USE
// ALSO REQUIRES ACCESS TO UPLOAD TO CLOUD
var appbasefile = "/home/frikky/git/shuffle/backend/app_sdk/app_base.py"
var appfolder = "/home/frikky/git/shuffle-apps"
var baseUrl = ""
var apikey = ""

// Allows for overwriting if the user has access
var overwriteExistingApps = "true"

type AlgoliaSearchApp struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	ObjectID     string   `json:"objectID"`
	Actions      int      `json:"actions"`
	Tags         []string `json:"tags"`
	Categories   []string `json:"categories"`
	AccessibleBy []string `json:"accessible_by"`
	ImageUrl     string   `json:"image_url"`
	TimeEdited   int64    `json:"time_edited"`
	Generated    bool     `json:"generated"`
	Invalid      bool     `json:"invalid"`
	Creator      string   `json:"creator"`
}

func getRunner(classname string) string {
	return fmt.Sprintf(`
# Run the actual thing after we've checked params
def run(request):
	print(request.data)
	try:
		action = request.get_json(force=True)
	except:
		return f'Error parsing JSON'

	print(f'ACTION: {action}')
	if action == None:
		print("Returning because no action defined")
		return f'No JSON detected'

	#authorization_key = action.get("authorization")
	#current_execution_id = action.get("execution_id")
	
	if action and "name" in action and "app_name" in action:
		asyncio.run(%s.run(action=action))
		return f'Attempting to execute function {action["name"]} in app {action["app_name"]}' 

	return f'Action ran!'

	`, classname)
}

// Could use some kind of linting system too for this, but meh
func formatAppfile(filedata []byte) (string, []byte) {
	lines := strings.Split(string(filedata), "\n")

	newfile := []string{}
	classname := ""
	for _, line := range lines {
		if strings.Contains(line, "walkoff_app_sdk") {
			continue
		}

		// Remap logging. CBA this right now
		// This issue also persists in onprem apps because of await thingies.. :(
		// FIXME
		if strings.Contains(line, "console_logger") && strings.Contains(line, "await") {
			continue
			//line = strings.Replace(line, "console_logger", "logger", -1)
			//log.Println(line)
		}

		// Might not work with different import names
		// Could be fucked up with spaces everywhere? Idk
		if strings.Contains(line, "class") && strings.Contains(line, "(AppBase)") {
			items := strings.Split(line, " ")
			if len(items) > 0 && strings.Contains(items[1], "(AppBase)") {
				classname = strings.Split(items[1], "(")[0]
			} else {
				log.Println("Something wrong :( (horrible programming right here)")
				return classname, filedata
			}
		}

		if strings.Contains(line, "if __name__ ==") {
			break
		}

		// asyncio.run(HelloWorld.run(), debug=True)

		newfile = append(newfile, line)
	}

	filedata = []byte(strings.Join(newfile, "\n"))
	return classname, filedata
}

// https://stackoverflow.com/questions/21060945/simple-way-to-copy-a-file-in-golang
func Copy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}
func ZipFiles(filename string, files []string) error {
	newZipFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer newZipFile.Close()

	zipWriter := zip.NewWriter(newZipFile)
	defer zipWriter.Close()

	// Add files to zip
	for _, file := range files {
		zipfile, err := os.Open(file)
		if err != nil {
			return err
		}
		defer zipfile.Close()

		// Get the file information
		info, err := zipfile.Stat()
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		// Using FileInfoHeader() above only uses the basename of the file. If we want
		// to preserve the folder structure we can overwrite this with the full path.
		filesplit := strings.Split(file, "/")
		if len(filesplit) > 1 {
			header.Name = filesplit[len(filesplit)-1]
		} else {
			header.Name = file
		}

		// Change to deflate to gain better compression
		// see http://golang.org/pkg/archive/zip/#pkg-constants
		header.Method = zip.Deflate

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}
		if _, err = io.Copy(writer, zipfile); err != nil {
			return err
		}
	}

	return nil
}

func getAppbase(filepath string) []string {
	appBase, err := ioutil.ReadFile(filepath)
	if err != nil {
		log.Printf("Readerror: %s", err)
		return []string{}
	}

	record := true
	validLines := []string{}
	for _, line := range strings.Split(string(appBase), "\n") {
		//if strings.Contains(line, "#STOPCOPY") {
		//	log.Println("Stopping copy")
		//	break
		//}

		if record {
			validLines = append(validLines, line)
		}

		//if strings.Contains(line, "#STARTCOPY") {
		//	log.Println("Starting copy")
		//	record = true
		//}
	}

	return validLines
}

// Puts together ./static_baseline.py, onprem/app_sdk_app_base.py and the
// appcode in a generated_app folder based on appname+version
func stitcher(appname string, appversion string) string {
	//baselinefile := "static_baseline.py"

	//baseline, err := ioutil.ReadFile(baselinefile)
	//if err != nil {
	//	log.Printf("Readerror: %s", err)
	//	return ""
	//}
	baseline := ""

	sourceappfile := fmt.Sprintf("%s/%s/%s/src/app.py", appfolder, appname, appversion)
	appfile, err := ioutil.ReadFile(sourceappfile)
	if err != nil {
		log.Printf("App readerror: %s", err)
		return ""
	}

	classname, appfile := formatAppfile(appfile)
	if len(classname) == 0 {
		log.Println("Failed finding classname in file.")
		return ""
	}

	runner := getRunner(classname)
	appBase := getAppbase(appbasefile)

	foldername := fmt.Sprintf("generated_apps/%s_%s", appname, appversion)
	err = os.Mkdir(foldername, os.ModePerm)
	if err != nil {
		log.Println("Failed making temporary app folder. Probably already exists. Remaking")
		os.RemoveAll(foldername)
		os.MkdirAll(foldername, os.ModePerm)
	}

	stitched := []byte(string(baseline) + strings.Join(appBase, "\n") + string(appfile) + string(runner))
	err = Copy(fmt.Sprintf("%s/%s/%s/requirements.txt", appfolder, appname, appversion), fmt.Sprintf("%s/requirements.txt", foldername))
	if err != nil {
		log.Println("Failed writing to requirement: %s", err)
		return ""
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/main.py", foldername), stitched, os.ModePerm)
	if err != nil {
		log.Println("Failed writing to stitched: %s", err)
		return ""
	}

	files := []string{
		fmt.Sprintf("%s/requirements.txt", foldername),
		fmt.Sprintf("%s/main.py", foldername),
	}

	folderPath := fmt.Sprintf("%s/%s/%s/src", appfolder, appname, appversion)
	log.Printf("CHECKING FOLDER %s", folderPath)
	allFiles, err := ioutil.ReadDir(folderPath)
	if err != nil {
		log.Printf("Failed getting src files")
		return ""
	}

	for _, f := range allFiles {
		if f.IsDir() {
			continue
		}

		if f.Name() == "app.py" {
			continue
		}

		err = Copy(fmt.Sprintf("%s/%s/%s/src/%s", appfolder, appname, appversion, f.Name()), fmt.Sprintf("%s/%s", foldername, f.Name()))
		if err != nil {
			log.Println("Failed writing to %s: %s", f.Name(), err)
			continue
		}

		files = append(files, fmt.Sprintf("%s/%s", foldername, f.Name()))
	}

	//os.Exit(3)
	log.Printf("Successfully stitched files in %s/main.py", foldername)
	outputfile := fmt.Sprintf("%s.zip", foldername)

	err = ZipFiles(outputfile, files)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Creates a client.
	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Printf("Failed to create client: %v", err)
		return ""
	}

	// Create bucket handle
	bucket := client.Bucket(bucketName)

	remotePath := fmt.Sprintf("apps/%s_%s.zip", appname, appversion)
	err = createFileFromFile(bucket, remotePath, outputfile)
	if err != nil {
		log.Printf("Failed to upload to bucket: %v", err)
		return ""
	}

	os.Remove(outputfile)
	return fmt.Sprintf("gs://%s/apps/%s_%s.zip", bucketName, appname, appversion)
}

func createFileFromFile(bucket *storage.BucketHandle, remotePath, localPath string) error {
	ctx := context.Background()
	// [START upload_file]
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()

	wc := bucket.Object(remotePath).NewWriter(ctx)
	if _, err = io.Copy(wc, f); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	// [END upload_file]
	return nil
}

// Deploy to google cloud function :)
func deployFunction(appname, localization, applocation string, environmentVariables map[string]string) error {
	ctx := context.Background()
	service, err := cloudfunctions.NewService(ctx)
	if err != nil {
		return err
	}

	// ProjectsLocationsListCall
	appname = strings.ToLower(appname)
	projectsLocationsFunctionsService := cloudfunctions.NewProjectsLocationsFunctionsService(service)
	location := fmt.Sprintf("projects/%s/locations/%s", gceProject, localization)
	functionName := fmt.Sprintf("%s/functions/%s", location, appname)

	cloudFunction := &cloudfunctions.CloudFunction{
		AvailableMemoryMb:    128,
		EntryPoint:           "run",
		EnvironmentVariables: environmentVariables,
		HttpsTrigger:         &cloudfunctions.HttpsTrigger{},
		MaxInstances:         0,
		Name:                 functionName,
		Runtime:              "python38",
		SourceArchiveUrl:     applocation,
		ServiceAccountEmail:  "shuffle-apps@shuffler.iam.gserviceaccount.com",
	}

	createCall := projectsLocationsFunctionsService.Create(location, cloudFunction)
	_, err = createCall.Do()
	if err != nil {
		log.Println("Failed creating new function. Attempting patch, as it might exist already")

		patchCall := projectsLocationsFunctionsService.Patch(fmt.Sprintf("%s/functions/%s", location, appname), cloudFunction)
		_, err = patchCall.Do()
		if err != nil {
			log.Printf("Failed patching function: %s", err)
			return err
		}

		log.Printf("Successfully patched %s to %s", appname, localization)
	} else {
		log.Printf("Successfully deployed %s to %s", appname, localization)
	}

	// FIXME - use response to define the HTTPS entrypoint. It's default to an easy one tho
	log.Printf("[INFO] Adding allUsers access to execute function")
	//log.Printf("Createcall: %#v", createCall)

	binding := cloudfunctions.Binding{
		Members: []string{"allUsers"},
		Role:    "roles/cloudfunctions.invoker",
	}

	policy := &cloudfunctions.Policy{
		Bindings: []*cloudfunctions.Binding{&binding},
	}

	setIamPolicyRequest := &cloudfunctions.SetIamPolicyRequest{
		Policy: policy,
	}

	iamPatchCall := projectsLocationsFunctionsService.SetIamPolicy(functionName, setIamPolicyRequest)
	_, err = iamPatchCall.Do()
	if err != nil {
		log.Printf("[ERROR] Failed adding allUsers access to invoke function: %s", err)
		return err
	} else {
		log.Printf("[INFO] Successfully added allUsers access to invoke function")
	}

	return nil
}

func deployAppCloudFunc(appname string, appversion string) {
	_ = os.Mkdir("generated_apps", os.ModePerm)

	fullAppname := fmt.Sprintf("%s-%s", strings.Replace(appname, "_", "-", -1), strings.Replace(appversion, ".", "-", -1))
	locations := []string{"europe-west2"}

	// Deploys the app to all locations
	bucketname := stitcher(appname, appversion)
	if bucketname == "" {
		log.Printf("Returning because no bucket name")
		return
	}

	//"FUNCTION_APIKEY": apikey,
	environmentVariables := map[string]string{}

	for _, location := range locations {
		err := deployFunction(fullAppname, location, bucketname, environmentVariables)
		if err != nil {
			log.Printf("Failed to deploy: %s", err)
			return
			os.Exit(3)
		}
	}
}

func loadYaml(fileLocation string) (shuffle.WorkflowApp, error) {
	action := shuffle.WorkflowApp{}

	yamlFile, err := ioutil.ReadFile(fileLocation)
	if err != nil {
		log.Printf("yamlFile.Get err: %s", err)
		return shuffle.WorkflowApp{}, err
	}

	//log.Printf(string(yamlFile))
	err = yaml.Unmarshal([]byte(yamlFile), &action)
	if err != nil {
		return shuffle.WorkflowApp{}, err
	}

	if action.ID == "" {
		hasher := md5.New()
		hasher.Write([]byte(action.Name + action.AppVersion))

		newmd5 := hex.EncodeToString(hasher.Sum(nil))
		action.ID = newmd5
	}

	return action, nil
}

// FIXME - deploy to backend (YAML config)
func deployConfigToBackend(basefolder, appname, appversion string) error {
	// FIXME - no static path pls
	location := fmt.Sprintf("%s/%s/%s/api.yaml", basefolder, appname, appversion)
	log.Printf("FILE LOCATION: %s", location)
	action, err := loadYaml(location)
	if err != nil {
		log.Println(err)
		return err
	}

	action.Sharing = true
	action.Public = true

	data, err := json.Marshal(action)
	if err != nil {
		return err
	}

	log.Printf("Starting file upload to backend")
	url := fmt.Sprintf("%s/api/v1/workflows/apps?overwrite=%s&sharing=true", baseUrl, overwriteExistingApps)
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apikey))

	ret, err := client.Do(req)
	if err != nil {
		return err
	}

	log.Printf("Status: %s", ret.Status)
	body, err := ioutil.ReadAll(ret.Body)
	if err != nil {
		return err
	}

	type datastruct struct {
		Success bool   `json:"success"`
		ID      string `json:"ID"`
	}

	datareturn := datastruct{}
	err = json.Unmarshal(body, &datareturn)
	if err != nil {
		return err
	}

	if ret.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Status %s. App probably already exists. Raw:\n%s", ret.Status, string(body)))
	}

	log.Println(string(body))
	return nil
}

func tarDirectory(filecontext string) (io.Reader, error) {

	// Create a filereader
	//dockerFileReader, err := os.Open(dockerfile)
	//if err != nil {
	//	return err
	//}

	//// Read the actual Dockerfile
	//readDockerFile, err := ioutil.ReadAll(dockerFileReader)
	//if err != nil {
	//	return err
	//}

	// Make a TAR header for the file
	tarHeader := &tar.Header{
		Name:     filecontext,
		Typeflag: tar.TypeDir,
	}

	// Writes the header described for the TAR file
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	defer tw.Close()
	err := tw.WriteHeader(tarHeader)
	if err != nil {
		return nil, err
	}

	dockerFileTarReader := bytes.NewReader(buf.Bytes())
	return dockerFileTarReader, nil
}

func tarDir(source string, target string) (*bytes.Reader, error) {
	filename := filepath.Base(source)
	target = filepath.Join(target, fmt.Sprintf("%s.tar", filename))
	tarfile, err := os.Create(target)
	if err != nil {
		return nil, err
	}

	defer tarfile.Close()

	buf := new(bytes.Buffer)
	_ = buf
	tarball := tar.NewWriter(tarfile)
	defer tarball.Close()

	info, err := os.Stat(source)
	if err != nil {
		return nil, err
	}

	var baseDir string
	if info.IsDir() {
		baseDir = filepath.Base(source)
	}

	_ = filepath.Walk(source,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			header, err := tar.FileInfoHeader(info, info.Name())
			if err != nil {
				return err
			}

			if baseDir != "" {
				header.Name = filepath.Join(baseDir, strings.TrimPrefix(path, source))
			}

			if err := tarball.WriteHeader(header); err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(tarball, file)
			return nil
		})

	dockerFileTarReader := bytes.NewReader(buf.Bytes())
	return dockerFileTarReader, nil
}

func buildImage(client *client.Client, tags []string, dockerBuildCtxDir string) error {
	dockerBuildContext, err := tarDir(dockerBuildCtxDir, ".")
	if err != nil {
		log.Printf("Error in taring the docker root folder - %s", err.Error())
		return err
	}

	imageBuildResponse, err := client.ImageBuild(
		context.Background(),
		dockerBuildContext,
		types.ImageBuildOptions{
			Dockerfile: "Dockerfile",
			PullParent: true,
			Remove:     true,
			Tags:       tags,
		},
	)

	if err != nil {
		return err
	}

	// Read the STDOUT from the build process
	defer imageBuildResponse.Body.Close()
	_, err = io.Copy(os.Stdout, imageBuildResponse.Body)
	if err != nil {
		return err
	}

	return nil
}

// FIXME - deploy to dockerhub
func deployWorker(appname, appversion string) error {
	// Get dockerfile from ./apps/appname/appversion/Dockerfile
	client, err := client.NewEnvClient()
	if err != nil {
		return err
	}

	tags := []string{fmt.Sprintf("%s-%s", appname, appversion)}
	err = buildImage(client, tags, fmt.Sprintf("./apps/%s/%s", appname, appversion))
	if err != nil {
		log.Printf("Build error: %s", err)
		return err
	}

	return nil
}

// Deploys all cloud functions. Onprem thooo :(
func deployAll() {
	//allapps := []string{
	//	"hoxhunt",
	//	"secureworks",
	//	"servicenow",
	//	"lastline",
	//	"netcraft",
	//	"misp",
	//	"email",
	//	"testing",
	//	"http",
	//	"recordedfuture",
	//	"passivetotal",
	//	"carbon_black",
	//	"thehive",
	//	"cortex",
	//	"splunk",
	//}
	allapps := []string{}
	files, err := ioutil.ReadDir(appfolder)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		if strings.Contains(f.Name(), ".") {
			log.Printf("Skipping %s", f.Name())
			continue
		}

		allapps = append(allapps, f.Name())
	}

	for _, appname := range allapps {
		appversion := "1.0.0"

		err := deployConfigToBackend(appfolder, appname, appversion)
		if err != nil {
			log.Printf("Failed uploading config: %s", err)
			continue
		}

		deployAppCloudFunc(appname, appversion)
	}
}

func main() {
	if len(os.Args) < 3 {
		log.Printf("Missing arguments. Required: go run stitcher.go APIKEY URL")
		return
	}

	baseUrl = os.Args[2]
	apikey = os.Args[1]
	log.Printf("\n\nRunning with: \nUrl: %s\nApikey: %s\n\n", baseUrl, apikey)

	appname := "Microsoft-Teams"
	appversion := "1.0.0"

	deployAll()
	return

	err := deployConfigToBackend(appfolder, appname, appversion)
	if err != nil {
		log.Printf("Failed uploading config: %s", err)
		os.Exit(1)
	}

	log.Printf("Starting cloud function deploy")
	deployAppCloudFunc(appname, appversion)
}
