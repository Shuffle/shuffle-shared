package main

import (
	"github.com/frikky/shuffle-shared"

	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"archive/tar"
	//"cloud.google.com/go/iam"
	"cloud.google.com/go/storage"
	"github.com/algolia/algoliasearch-client-go/v3/algolia/search"
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
var appbasefile = "/home/frikky/git/shuffle/backend/app_sdk/app_base.py"
var appfolder = "/home/frikky/git/shuffle-apps"
var baseUrl = "http://localhost:5002"
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
}

type WorkflowAppActionParameter struct {
	Description string `json:"description" datastore:"description"`
	ID          string `json:"id" datastore:"id"`
	Name        string `json:"name" datastore:"name"`
	Example     string `json:"example" datastore:"example"`
	Value       string `json:"value" datastore:"value"`
	Multiline   bool   `json:"multiline" datastore:"multiline"`
	ActionField string `json:"action_field" datastore:"action_field"`
	Variant     string `json:"variant", datastore:"variant"`
	Required    bool   `json:"required" datastore:"required"`
	Schema      struct {
		Type string `json:"type" datastore:"type"`
	} `json:"schema"`
}

type Authentication struct {
	Required   bool                   `json:"required" datastore:"required" yaml:"required" `
	Parameters []AuthenticationParams `json:"parameters" datastore:"parameters" yaml:"parameters"`
}

type AuthenticationParams struct {
	Description string `json:"description" datastore:"description" yaml:"description"`
	ID          string `json:"id" datastore:"id" yaml:"id"`
	Name        string `json:"name" datastore:"name" yaml:"name"`
	Example     string `json:"example" datastore:"example" yaml:"example"`
	Value       string `json:"value" datastore:"value" yaml:"value"`
	Multiline   bool   `json:"multiline" datastore:"multiline" yaml:"multiline"`
	Required    bool   `json:"required" datastore:"required" yaml:"required"`
}

type WorkflowApp struct {
	Name          string `json:"name" yaml:"name" required:true datastore:"name"`
	IsValid       bool   `json:"is_valid" yaml:"is_valid" required:true datastore:"is_valid"`
	ID            string `json:"id" yaml:"id,omitempty" required:false datastore:"id"`
	Link          string `json:"link" yaml:"link" required:false datastore:"link,noindex"`
	AppVersion    string `json:"app_version" yaml:"app_version" required:true datastore:"app_version"`
	SharingConfig string `json:"sharing_config" yaml:"sharing_config" datastore:"sharing_config"`
	Generated     bool   `json:"generated" yaml:"generated" required:false datastore:"generated"`
	Downloaded    bool   `json:"downloaded" yaml:"downloaded" required:false datastore:"downloaded"`
	Sharing       bool   `json:"sharing" yaml:"sharing" required:false datastore:"sharing"`
	Verified      bool   `json:"verified" yaml:"verified" required:false datastore:"verified"`
	Invalid       bool   `json:"invalid" yaml:"invalid" required:false datastore:"invalid"`
	Activated     bool   `json:"activated" yaml:"activated" required:false datastore:"activated"`
	Tested        bool   `json:"tested" yaml:"tested" required:false datastore:"tested"`
	Owner         string `json:"owner" datastore:"owner" yaml:"owner"`
	Hash          string `json:"hash" datastore:"hash" yaml:"hash"` // api.yaml+dockerfile+src/app.py for apps
	PrivateID     string `json:"private_id" yaml:"private_id" required:false datastore:"private_id"`
	Description   string `json:"description" datastore:"description,noindex" required:false yaml:"description"`
	Environment   string `json:"environment" datastore:"environment" required:true yaml:"environment"`
	SmallImage    string `json:"small_image" datastore:"small_image,noindex" required:false yaml:"small_image"`
	LargeImage    string `json:"large_image" datastore:"large_image,noindex" yaml:"large_image" required:false`
	ContactInfo   struct {
		Name string `json:"name" datastore:"name" yaml:"name"`
		Url  string `json:"url" datastore:"url" yaml:"url"`
	} `json:"contact_info" datastore:"contact_info" yaml:"contact_info" required:false`
	Actions        []WorkflowAppAction `json:"actions" yaml:"actions" required:true datastore:"actions,noindex"`
	Authentication Authentication      `json:"authentication" yaml:"authentication" required:false datastore:"authentication"`
	Tags           []string            `json:"tags" yaml:"tags" required:false datastore:"activated"`
	Categories     []string            `json:"categories" yaml:"categories" required:false datastore:"categories"`
	Created        int64               `json:"created" datastore:"created"`
	Edited         int64               `json:"edited" datastore:"edited"`
	LastRuntime    int64               `json:"last_runtime" datastore:"last_runtime"`
}

type AuthenticationStore struct {
	Key   string `json:"key" datastore:"key"`
	Value string `json:"value" datastore:"value"`
}

type WorkflowAppAction struct {
	Description    string                       `json:"description" datastore:"description"`
	ID             string                       `json:"id" datastore:"id"`
	Name           string                       `json:"name" datastore:"name"`
	NodeType       string                       `json:"node_type" datastore:"node_type"`
	Environment    string                       `json:"environment" datastore:"environment"`
	Parameters     []WorkflowAppActionParameter `json:"parameters" datastore: "parameters"`
	Authentication []AuthenticationStore        `json:"authentication" datastore:"authentication"`
	Returns        struct {
		Description string `json:"description" datastore:"returns"`
		ID          string `json:"id" datastore:"id"`
		Schema      struct {
			Type string `json:"type" datastore:"type"`
		} `json:"schema" datastore:"schema"`
	} `json:"returns" datastore:"returns"`
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
	err = ioutil.WriteFile(fmt.Sprintf("%s/main.py", foldername), stitched, os.ModePerm)
	if err != nil {
		log.Println("Failed writing to stitched: %s", err)
		return ""
	}

	err = Copy(fmt.Sprintf("%s/%s/%s/requirements.txt", appfolder, appname, appversion), fmt.Sprintf("%s/requirements.txt", foldername))
	if err != nil {
		log.Println("Failed writing to requirement: %s", err)
		return ""
	}

	log.Printf("Successfully stitched files in %s/main.py", foldername)
	// Zip the folder
	files := []string{
		fmt.Sprintf("%s/main.py", foldername),
		fmt.Sprintf("%s/requirements.txt", foldername),
	}
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
		Runtime:              "python37",
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

func handleAlgoliaUpload(ctx context.Context, api shuffle.WorkflowApp) {
	log.Printf("[INFO] Should try to parse base64 to img and upload")
	if len(api.LargeImage) > 100000 {
		log.Printf("[WARNING] Too large image (>100kb): %d", len(api.LargeImage))
		return
	}

	algoliaClient := os.Getenv("ALGOLIA_CLIENT")
	algoliaSecret := os.Getenv("ALGOLIA_SECRET")
	if len(algoliaClient) == 0 || len(algoliaSecret) == 0 {
		log.Printf("[WARNING] ALGOLIA_CLIENT or ALGOLIA_SECRET not defined")
		return
	}

	datasplit := strings.Split(api.LargeImage, ",")
	log.Printf("LEN: %d", len(datasplit))
	if len(datasplit) <= 1 {
		log.Printf("[WARNING] No imagedata to handle")
		return
	}

	data := strings.Join(datasplit[1:], ",")
	reader := base64.NewDecoder(base64.StdEncoding, strings.NewReader(data))
	m, _, err := image.Decode(reader)
	if err != nil {
		log.Printf("[WARNING] Image DecodeError: %s", err)
		return
	}

	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Printf("[WARNING] Failed to create client (storage - algolia img): %s", err)
		return
	}

	newName := strings.Replace(api.Name, " ", "_", -1)

	filename := fmt.Sprintf("app_images/%s_%s.%s", newName, api.ID, "png")
	if strings.Contains(api.LargeImage, "png") {
		filename = fmt.Sprintf("app_images/%s_%s.%s", newName, api.ID, "png")
	} else if strings.Contains(api.LargeImage, "jpg") || strings.Contains(api.LargeImage, "jpeg") {
		filename = fmt.Sprintf("app_images/%s_%s.%s", newName, api.ID, "png")
	} else {
		log.Printf("[WARNING] Can only handle base64 type jpg and png")
		return
	}

	bucket := client.Bucket(publicBucket)
	obj := bucket.Object(filename)
	w := obj.NewWriter(ctx)

	if strings.Contains(api.LargeImage, "png") {
		err = png.Encode(w, m)
		if err != nil {
			log.Printf("[WARNING] PNG encode write error: %s", err)
			return
		}
	} else if strings.Contains(api.LargeImage, "jpg") || strings.Contains(api.LargeImage, "jpeg") {
		jpegOptions := jpeg.Options{}
		err = jpeg.Encode(w, m, &jpegOptions)
		if err != nil {
			log.Printf("[WARNING] JPG encode write error: %s", err)
			return
		}
	}

	if err := w.Close(); err != nil {
		log.Printf("[WARNING] Image close error: %s", err)
		return
	}

	publicUrl := fmt.Sprintf("https://storage.googleapis.com/%s/%s", publicBucket, filename)
	log.Printf("PUBLIC URL: %s", publicUrl)

	algClient := search.NewClient(algoliaClient, algoliaSecret)
	timeNow := int64(time.Now().Unix())
	records := []AlgoliaSearchApp{
		AlgoliaSearchApp{
			Name:         api.Name,
			Description:  api.Description,
			ImageUrl:     publicUrl,
			Actions:      len(api.Actions),
			Tags:         api.Tags,
			Categories:   api.Categories,
			AccessibleBy: []string{},
			ObjectID:     api.ID,
			TimeEdited:   timeNow,
			Generated:    api.Generated,
			Invalid:      api.Invalid,
		},
	}

	algoliaIndex := algClient.InitIndex(appSearchIndex)
	_, err = algoliaIndex.SaveObjects(records)
	if err != nil {
		log.Printf("[WARNING] Algolia Object put err: %s", err)
		return
	}

	log.Printf("[INFO] SUCCESSFULLY UPLOADED %s_%s TO ALGOLIA!", newName, api.ID)
}

// FIXME - deploy to backend (YAML config)
func deployConfigToBackend(basefolder, appname, appversion string) error {
	// FIXME - no static path pls
	action, err := loadYaml(fmt.Sprintf("%s/%s/%s/api.yaml", basefolder, appname, appversion))
	if err != nil {
		log.Println(err)
		return err
	}

	action.Sharing = true

	data, err := json.Marshal(action)
	if err != nil {
		return err
	}

	if len(action.LargeImage) > 0 {
		//ctx := context.Background()
		//handleAlgoliaUpload(ctx, action)
	}

	log.Printf("Starting file upload to backend")
	url := fmt.Sprintf("%s/api/v1/workflows/apps?overwrite=%s", baseUrl, overwriteExistingApps)
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
	deployAll()
	return

	appname := "testing"
	appversion := "1.0.0"

	err := deployConfigToBackend("apps", appname, appversion)
	if err != nil {
		log.Printf("Failed uploading config: %s", err)
		os.Exit(1)
	}

	deployAppCloudFunc(appname, appversion)
}
