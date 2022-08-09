package shuffle

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/frikky/kin-openapi/openapi3"
	//"github.com/satori/go.uuid"
	"gopkg.in/yaml.v2"
)

func CopyFile(fromfile, tofile string) error {
	from, err := os.Open(fromfile)
	if err != nil {
		return err
	}
	defer from.Close()

	to, err := os.OpenFile(tofile, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer to.Close()

	_, err = io.Copy(to, from)
	if err != nil {
		return err
	}

	return nil
}

func FormatAppfile(filedata string) (string, string) {
	lines := strings.Split(filedata, "\n")

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
				// This could break something..
				classname = "TMP"
			}
		}

		if strings.Contains(line, "if __name__ ==") {
			break
		}

		// asyncio.run(HelloWorld.run(), debug=True)

		newfile = append(newfile, line)
	}

	filedata = strings.Join(newfile, "\n")
	return classname, filedata
}

// Streams the data into a zip to be used for a cloud function
func StreamZipdata(ctx context.Context, identifier, pythoncode, requirements, bucketName string) (string, error) {
	filename := fmt.Sprintf("generated_cloudfunctions/%s.zip", identifier)

	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	if project.Environment == "cloud" {
		client, err := storage.NewClient(ctx)
		if err != nil {
			log.Printf("Failed to create datastore client: %v", err)
			return filename, err
		}

		bucket := client.Bucket(bucketName)

		obj := bucket.Object(filename)
		storageWriter := obj.NewWriter(ctx)
		defer storageWriter.Close()

		zipWriter = zip.NewWriter(storageWriter)
	}

	zipFile, err := zipWriter.Create("main.py")
	if err != nil {
		log.Printf("Packing failed to create zip file from bucket: %v", err)
		return filename, err
	}

	// Have to use Fprintln otherwise it tries to parse all strings etc.
	if _, err := fmt.Fprintln(zipFile, pythoncode); err != nil {
		return filename, err
	}

	//log.Printf("Merging requirements: %s", requirements)

	zipFile, err = zipWriter.Create("requirements.txt")
	if err != nil {
		log.Printf("Packing failed to create zip file from bucket: %v", err)
		return filename, err
	}
	if _, err := fmt.Fprintln(zipFile, requirements); err != nil {
		return filename, err
	}

	err = zipWriter.Close()
	if err != nil {
		log.Printf("Packing failed to close zip file writer from bucket: %v", err)
		return filename, err
	}

	//src := client.Bucket(bucketName).Object(fmt.Sprintf("%s/baseline/%s", basePath, file))
	//dst := client.Bucket(bucketName).Object(fmt.Sprintf("%s/%s", appPath, file))
	//if _, err := dst.CopierFrom(src).Run(ctx); err != nil {
	//	return "", err
	//}

	//log.Printf("Finished upload")
	return filename, nil
}

func GetAppbase() ([]byte, []byte, error) {
	// 1. Have baseline in bucket/generated_apps/baseline
	// 2. Copy the baseline to a new folder with identifier name
	appbase := "../app_sdk/app_base.py"

	//static := "../app_sdk/static_baseline.py"
	//staticData, err := ioutil.ReadFile(static)
	//if err != nil {
	//	return []byte{}, []byte{}, err
	//}
	staticData := []byte{}

	appbaseData, err := ioutil.ReadFile(appbase)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	return appbaseData, staticData, nil
}

// Builds the structure for the new generated app in storage (copying baseline files)
func GetAppbaseGCP(ctx context.Context, client *storage.Client, bucketName string) ([]byte, []byte, error) {
	// 1. Have baseline in bucket/generated_apps/baseline
	// 2. Copy the baseline to a new folder with identifier name
	basePath := "generated_apps/baseline"
	appbase, err := client.Bucket(bucketName).Object(fmt.Sprintf("%s/app_base.py", basePath)).NewReader(ctx)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	defer appbase.Close()

	appbaseData, err := ioutil.ReadAll(appbase)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	return appbaseData, []byte{}, nil
}

func FixAppbase(appbase []byte) []string {
	record := true
	validLines := []string{}
	// Used to use static_baseline + app_base. Now it's only appbase :O
	for _, line := range strings.Split(string(appbase), "\n") {
		//if strings.Contains(line, "#STOPCOPY") {
		//	//log.Println("Stopping copy")
		//	break
		//}

		if record {
			validLines = append(validLines, line)
		}

		//if strings.Contains(line, "#STARTCOPY") {
		//	//log.Println("Starting copy")
		//	record = true
		//}
	}

	return validLines
}

// Builds the structure for the new generated app in storage (copying baseline files)
func BuildStructureGCP(ctx context.Context, client *storage.Client, identifier, bucketName string) (string, error) {
	// 1. Have baseline in bucket/generated_apps/baseline
	// 2. Copy the baseline to a new folder with identifier name

	basePath := "generated_apps"
	//identifier := fmt.Sprintf("%s-%s", swagger.Info.Title, curHash)
	appPath := fmt.Sprintf("%s/%s", basePath, identifier)
	fileNames := []string{"Dockerfile", "requirements.txt"}
	for _, file := range fileNames {
		src := client.Bucket(bucketName).Object(fmt.Sprintf("%s/baseline/%s", basePath, file))
		dst := client.Bucket(bucketName).Object(fmt.Sprintf("%s/%s", appPath, file))
		if _, err := dst.CopierFrom(src).Run(ctx); err != nil {
			return "", err
		}
	}

	return appPath, nil
}

// Builds the base structure for the app that we're making
// Returns error if anything goes wrong. This has to work if
// the python code is supposed to be generated
func BuildStructure(swagger *openapi3.Swagger, curHash string) (string, error) {
	//log.Printf("%#v", swagger)

	// adding md5 based on input data to not overwrite earlier data.
	generatedPath := "generated"
	subpath := "../app_gen/openapi/"
	identifier := fmt.Sprintf("%s-%s", swagger.Info.Title, curHash)
	appPath := fmt.Sprintf("%s/%s", generatedPath, identifier)

	os.MkdirAll(appPath, os.ModePerm)
	os.Mkdir(fmt.Sprintf("%s/src", appPath), os.ModePerm)

	err := CopyFile(fmt.Sprintf("%sbaseline/Dockerfile", subpath), fmt.Sprintf("%s/%s", appPath, "Dockerfile"))
	if err != nil {
		log.Println("Failed to move Dockerfile")
		return appPath, err
	}

	err = CopyFile(fmt.Sprintf("%sbaseline/requirements.txt", subpath), fmt.Sprintf("%s/%s", appPath, "requirements.txt"))
	if err != nil {
		log.Println("Failed to move requrements.txt")
		return appPath, err
	}

	return appPath, nil
}

// This function generates the python code that's being used.
// This is really meta when you program it. Handling parameters is hard here.
func MakePythoncode(swagger *openapi3.Swagger, name, url, method string, parameters, optionalQueries, headers []string, fileField string, api WorkflowApp, handleFile bool) (string, string) {

	method = strings.ToLower(method)
	queryString := ""
	queryData := ""

	extraHeaders := ""
	extraQueries := ""
	reservedKeys := []string{"BearerAuth", "ApiKeyAuth", "Oauth2", "BasicAuth", "JWT"}

	if swagger.Components.SecuritySchemes != nil {
		for key, value := range swagger.Components.SecuritySchemes {
			if ArrayContains(reservedKeys, key) {
				continue
			}

			//parsedKey := strings.Replace(key, "-", "_", -1)
			parsedKey := FixFunctionName(key, "")

			if value.Value.In == "header" {
				queryString += fmt.Sprintf(", %s=\"\"", parsedKey)
				if len(extraHeaders) > 0 {
					extraHeaders += "\n        "
				}

				extraHeaders += fmt.Sprintf(`if %s != " ": request_headers["%s"] = %s`, parsedKey, key, parsedKey)
			} else if value.Value.In == "query" {
				log.Printf("Handling extra queries for %#v", value.Value)
				queryString += fmt.Sprintf(", %s=\"\"", parsedKey)
				if len(extraQueries) > 0 {
					extraQueries += "\n        "
				}
				extraQueries += fmt.Sprintf(`if %s != " ": params["%s"] = %s`, parsedKey, key, parsedKey)
			} else {
				//log.Printf("[WARNING] Can't handle type %s", value.Value.In)
			}
		}
	}

	// FIXME - this might break - need to check if ? or & should be set as query
	parameterData := ""
	if len(optionalQueries) > 0 {
		//if len(queryString
		queryString += ", "
		for index, query := range optionalQueries {
			// Check if it's a part of the URL already

			parsedQuery := FixFunctionName(query, "")
			queryString += fmt.Sprintf("%s=\"\"", parsedQuery)

			if index != len(optionalQueries)-1 {
				queryString += ", "
			}

			/*
							queryData += fmt.Sprintf(`
				        if %s:
				            url += f"&%s={%s}"`, query, query, query)
			*/
			queryData += fmt.Sprintf(`
        if %s:
            if isinstance(%s, list) or isinstance(%s, dict):
                try:
                    %s = json.dumps(%s)
                except:
                    pass

            params[requests.utils.quote("%s")] = requests.utils.quote(%s)`, parsedQuery, parsedQuery, parsedQuery, parsedQuery, parsedQuery, query, parsedQuery)
		}
	} else {
		//log.Printf("No optional queries?")
	}

	// api.Authentication.Parameters[0].Value = "BearerAuth"
	authenticationParameter := ""
	authenticationSetup := ""
	authenticationAddin := ""
	// Python configuration code that should work :)
	if swagger.Components.SecuritySchemes != nil {
		if swagger.Components.SecuritySchemes["BearerAuth"] != nil {
			authenticationParameter = ", apikey"
			authenticationSetup = "if apikey != \" \" and not apikey.startswith(\"Bearer\"): request_headers[\"Authorization\"] = f\"Bearer {apikey}\""

		} else if swagger.Components.SecuritySchemes["BasicAuth"] != nil {
			authenticationParameter = ", username_basic, password_basic"
			authenticationAddin = ", auth=(username_basic, password_basic)"

		} else if swagger.Components.SecuritySchemes["ApiKeyAuth"] != nil {
			authenticationParameter = ", apikey"

			//if len(securitySchemes["ApiKeyAuth"].Value.Description) > 0 {
			//	//log.Printf("UPDATING AUTH!")
			//	extraParam.Description = fmt.Sprintf("Start with %s", securitySchemes["ApiKeyAuth"].Value.Description)

			if swagger.Components.SecuritySchemes["ApiKeyAuth"].Value.In == "header" {
				// This is a way to bypass apikeys by passing " "
				authenticationSetup = fmt.Sprintf(`if apikey != " ": request_headers["%s"] = apikey`, swagger.Components.SecuritySchemes["ApiKeyAuth"].Value.Name)

				// Fixes token prefixes (e.g. Token.. or SSWS..)
				if len(swagger.Components.SecuritySchemes["ApiKeyAuth"].Value.Description) > 0 {
					trimmedDescription := strings.Trim(swagger.Components.SecuritySchemes["ApiKeyAuth"].Value.Description, " ")

					authenticationSetup = fmt.Sprintf("if apikey != \" \":\n            if apikey.startswith(\"%s\"):\n                request_headers[\"%s\"] = apikey\n            else:\n                apikey = apikey.replace(\"%s\", \"\", -1).strip()\n                request_headers[\"%s\"] = f\"%s{apikey}\"", trimmedDescription, swagger.Components.SecuritySchemes["ApiKeyAuth"].Value.Name, swagger.Components.SecuritySchemes["ApiKeyAuth"].Value.Description, swagger.Components.SecuritySchemes["ApiKeyAuth"].Value.Name, swagger.Components.SecuritySchemes["ApiKeyAuth"].Value.Description)
				}

			} else if swagger.Components.SecuritySchemes["ApiKeyAuth"].Value.In == "query" {
				// This might suck lol
				//key := "?"
				//if strings.Contains(url, "?") {
				//	key = "&"
				//}

				//authenticationSetup = fmt.Sprintf("if apikey != \" \": url+=f\"%s%s={apikey}\"", key, swagger.Components.SecuritySchemes["ApiKeyAuth"].Value.Name)
				authenticationSetup = fmt.Sprintf("if apikey != \" \": params[\"%s\"] = requests.utils.quote(apikey)", swagger.Components.SecuritySchemes["ApiKeyAuth"].Value.Name)
			}

		} else if swagger.Components.SecuritySchemes["Oauth2"] != nil {
			//log.Printf("[DEBUG] Appending Oauth2 code")
			authenticationParameter = ", access_token"
			authenticationSetup = fmt.Sprintf("if access_token != \" \": request_headers[\"Authorization\"] = f\"Bearer {access_token}\"\n        request_headers[\"Content-Type\"] = \"application/json\"")

		} else if swagger.Components.SecuritySchemes["jwt"] != nil {
			//log.Printf("[DEBUG] Appending Oauth2 code")
			authenticationParameter = ", username_basic, password_basic"
			//api.Authentication.TokenUri = securitySchemes["jwt"].Value.In
			authenticationSetup = fmt.Sprintf("authret = requests.get(f\"{url}%s\", headers=request_headers, auth=(username_basic, password_basic), verify=False)\n        request_headers[\"Authorization\"] = f\"Bearer {authret.text}\"\n        print(f\"{authret.text}\")", api.Authentication.TokenUri)
		}
	}

	//baseUrl := fmt.Sprintf("%s%s", api.Link, actualPath)
	// This is a quickfix for onpremises stuff. Does work, but should really be
	// part of the authentication scheme from openapi3
	//urlParameter := ""
	//urlInline := ""
	//log.Printf("URL: %s", url)
	//if !strings.HasPrefix(strings.ToLower(url), "http") {

	// Modifies url to have the right path and such
	//log.Printf("URL: %s", urlSplit)
	//if len(swagger.Servers) > 0 {
	//	log.Printf("SwaggerURL: %#v", swagger.Servers[0].URL)
	//}

	urlSplit := strings.Split(url, "/")
	if strings.HasPrefix(url, "http") && len(urlSplit) > 2 {
		tmpUrl := strings.Join(urlSplit[3:len(urlSplit)], "/")
		if len(tmpUrl) > 0 {
			url = "/" + tmpUrl
		} else {
			if strings.HasSuffix(url, "/") {
				url = "/"
			} else {
				url = ""
			}
		}
	} else {
		tmpUrl := ""
		if len(urlSplit) > 2 {
			tmpUrl = "/" + strings.Join(urlSplit[3:len(urlSplit)], "/")
		}
		if !strings.HasPrefix(url, "/") {
			url = tmpUrl
		}
	}

	urlParameter := ", url"
	urlInline := "{url}"

	// Specific check for SSL verification
	// This is critical for onprem stuff.
	//verifyParam := ""
	//verifyWrapper := ""
	//verifyAddin := ""
	// Added to_file as of July 2022
	verifyParam := ", ssl_verify=False, to_file=False"
	verifyWrapper := `if type(ssl_verify) == str: ssl_verify = False if ssl_verify.lower() == "false" or ssl_verify == "0" else True`
	verifyAddin := ", verify=ssl_verify"

	// Codegen for headers
	headerParserCode := ""
	queryParserCode := ""
	if len(parameters) > 0 {
		parameterData = fmt.Sprintf(", %s", strings.Join(parameters, ", "))
		//log.Printf("Params: %#v", parameters)

		// This is gibberish :)
		for _, param := range parameters {
			if strings.Contains(param, "headers=") {
				headerParserCode = "if len(headers) > 0:\n            for header in headers.split(\"\\n\"):\n                if '=' in header:\n                    headersplit=header.split('=')\n                    request_headers[headersplit[0].strip()] = headersplit[1].strip()\n                elif ':' in header:\n                    headersplit=header.split(':')\n                    request_headers[headersplit[0].strip()] = headersplit[1].strip()"
			} else if strings.Contains(param, "queries=") {
				queryParserCode = "\n        if len(queries) > 0:\n            if queries[0] == \"?\" or queries[0] == \"&\":\n                queries = queries[1:len(queries)]\n            if queries[len(queries)-1] == \"?\" or queries[len(queries)-1] == \"&\":\n                queries = queries[0:-1]\n            for query in queries.split(\"&\"):\n                 if isinstance(query, list) or isinstance(query, dict):\n                    try:\n                        query = json.dumps(query)\n                    except:\n                        pass\n                 if '=' in query:\n                    headersplit=query.split('=')\n                    params[requests.utils.quote(headersplit[0].strip())] = requests.utils.quote(headersplit[1].strip())\n                 else:\n                    params[requests.utils.quote(query.strip())] = None\n        params = '&'.join([k if v is None else f\"{k}={v}\" for k, v in params.items()])"
			} else {
				if !strings.Contains(url, fmt.Sprintf("{%s}", param)) {
					queryData += fmt.Sprintf(`
        if %s:
            if isinstance(%s, list) or isinstance(%s, dict):
                try:
                    %s = json.dumps(%s)
                except:
                    pass

            params[requests.utils.quote("%s")] = requests.utils.quote(%s)`, param, param, param, param, param, param, param)
				}
			}
		}
	}

	functionname := strings.ToLower(fmt.Sprintf("%s_%s", method, name))
	if strings.Contains(strings.ToLower(name), strings.ToLower(method)) {
		functionname = strings.ToLower(name)
	}

	bodyParameter := ""
	bodyAddin := ""
	bodyFormatter := ""
	postParameters := []string{"post", "patch", "put"}
	for _, item := range postParameters {
		if method == item {
			bodyParameter = ", body=\"\""
			bodyAddin = ", data=body"

			// FIXME: Does JSON data work?
			bodyFormatter = "try:\n            body = \" \".join(body.strip().split()).encode(\"utf-8\")\n        except:\n            pass"
		}
	}

	preparedHeaders := "request_headers={}"
	if len(headers) > 0 {
		if method == "post" && len(fileField) > 0 {
		} else {
			preparedHeaders = "request_headers={"
			for count, header := range headers {
				headerSplit := strings.Split(header, "=")
				added := false
				if len(headerSplit) == 2 {
					if strings.Contains(preparedHeaders, headerSplit[0]) {
						continue
					}

					headerSplit[0] = strings.Replace(headerSplit[0], "\"", "", -1)
					headerSplit[0] = strings.Replace(headerSplit[0], "'", "", -1)
					headerSplit[1] = strings.Replace(headerSplit[1], "\"", "", -1)
					headerSplit[1] = strings.Replace(headerSplit[1], "'", "", -1)

					preparedHeaders += fmt.Sprintf(`"%s": "%s"`, headerSplit[0], headerSplit[1])
					added = true
				}

				if count != len(headers)-1 && added {
					preparedHeaders += ","
				}
			}

			preparedHeaders += "}"
		}
	}

	fileBalance := ""
	fileAdder := ``
	fileGrabber := ``
	fileParameter := ``
	if method == "post" && len(fileField) > 0 {
		fileParameter = ", file_id"
		fileGrabber = `filedata = self.get_file(file_id)`

		// This indentation is confusing (but correct) ROFL
		fileAdder = fmt.Sprintf(`if not filedata["success"]:
            return {"success": False, "reason": f"{file_id} is not a valid File ID"}

        files = {"%s": (filedata["filename"], filedata["data"])}`, fileField)
		fileBalance = ", files=files"
	}

	// Extra param for url if it's changeable
	// Extra param for authentication scheme(s)
	// The last weird one is the body.. Tabs & spaces sucks.
	parsedParameters := fmt.Sprintf("%s%s%s%s%s%s%s",
		authenticationParameter,
		urlParameter,
		fileParameter,
		parameterData,
		queryString,
		bodyParameter,
		verifyParam,
	)

	// Handles default return value
	handleFileString := "try:\n            print(ret.json())\n            return ret.json()\n        except json.decoder.JSONDecodeError as e:\n            print(f\"[WARNING] JSON Exception in return: {e}\")\n            return ret.text\n        except Exception as e:\n            print(f\"[WARNING] Exception in return: {e}\")\n            return ret.text"
	//if handleFile {
	//	handleFileString = fmt.Sprintf("new_file = [{\"filename\": \"%s_generated\", \"data\": ret.text}]\n        return_value = self.set_files(new_file)\n        return json.dumps({\"success\": True, \"file_id\": return_value[0], \"file_size\": len(ret.text)})", swagger.Info.Title)
	//}

	parsedDataCurlParser := ""
	if method == "post" || method == "patch" || method == "put" {
		parsedDataCurlParser = `parsed_curl_command += f""" -d '{body}'""" if isinstance(body, str) else f""" -d '{body.decode("utf-8")}'"""`
	}

	data := fmt.Sprintf(`    def %s(self%s):
        params={}
        %s
        url=f"%s%s"
        %s
        %s
        %s
        %s
        %s
        %s
        %s
        %s
        %s
        %s
        if str(to_file).lower() == "true":
            to_file = True
        else:
            to_file = False

        if "http:/" in url and not "http://" in url:
            url = url.replace("http:/", "http://", -1)
        if "https:/" in url and not "https://" in url:
            url = url.replace("https:/", "https://", -1)
        if "http:///" in url:
            url = url.replace("http:///", "http://", -1)
        if "https:///" in url:
            url = url.replace("https:///", "https://", -1)
        if not "http://" in url and not "http" in url:
            url = f"http://{url}" 

        try:
            body = json.dumps(body)
        except:
            pass

       	found = False
       	for key, value in request_headers.items():
            if key.lower() == "user-agent": 
               	found = True 
               	break	

       	if not found:	
            request_headers["User-Agent"] = "Shuffle Automation"

        try:
            #parsed_headers = [sys.stdout.write(f" -H \"{key}: {value}\"") for key, value in request_headers.items()]
            parsed_headers = ""
            parsed_curl_command = f"curl -X%s {url} {parsed_headers}"
            %s

            self.action["parameters"].append({
                "name": "shuffle_request_url",
                "value": f"{url}",
            })
            self.action["parameters"].append({
                "name": "shuffle_request_curl",
                "value": f"{parsed_curl_command}",
            })
            self.action["parameters"].append({
                "name": "shuffle_request_headers",
                "value": f"{json.dumps(parsed_headers)}",
            })

            self.action_result["action"] = self.action
            print("[DEBUG] Updated values in self.action_result from OpenAPI app! (1)") 
        except Exception as e:
            print(f"[WARNING] Something went wrong when adding extra returns (1). {e}")

        session = requests.Session()
        ret = session.%s(url, headers=request_headers, params=params%s%s%s%s)
        try:
            found = False
            for item in self.action["parameters"]:
                if item["name"] == "shuffle_response_status":
                    found = True
                    break

            if not found:
                self.action["parameters"].append({
                    "name": "shuffle_response_status",
                    "value": f"{ret.status_code}",
                })
                self.action["parameters"].append({
                    "name": "shuffle_response_length",
                    "value": f"{len(ret.text)}",
                })
                self.action["parameters"].append({
                    "name": "shuffle_request_cookies",
                    "value": f"{json.dumps(session.cookies.get_dict())}",
                })
                print("[DEBUG] Updated values in self.action_result from OpenAPI app! (2)") 

        except Exception as e:
            print(f"[WARNING] Something went wrong when adding extra returns (2). {e}")

        if to_file:
            filedata = {
                "filename": "response",
                "data": ret.content,
            }
    
            fileret = self.set_files([filedata])
            if len(fileret) == 1:
                return {"success": True, "file_id": fileret[0], "status": ret.status_code}
    
            return fileret

        %s
		`,
		functionname,
		parsedParameters,
		preparedHeaders,
		urlInline,
		url,
		verifyWrapper,
		authenticationSetup,
		extraHeaders,
		extraQueries,
		headerParserCode,
		queryData,
		queryParserCode,
		bodyFormatter,
		fileGrabber,
		fileAdder,
		strings.ToUpper(method),
		parsedDataCurlParser,
		method,
		authenticationAddin,
		bodyAddin,
		verifyAddin,
		fileBalance,
		handleFileString,
	)

	// Use lowercase when checking
	if strings.Contains(strings.ToLower(functionname), "scan") {
		log.Printf("\n%s", data)
	}

	return functionname, data
}

func GenerateYaml(swagger *openapi3.Swagger, newmd5 string) (*openapi3.Swagger, WorkflowApp, []string, error) {
	api := WorkflowApp{}
	//log.Printf("%#v", swagger.Info)

	if len(swagger.Info.Title) == 0 {
		return swagger, WorkflowApp{}, []string{}, errors.New("Swagger.Info.Title can't be empty.")
	}

	if len(swagger.Servers) == 0 {
		//return swagger, WorkflowApp{}, []string{}, errors.New("Swagger.Servers can't be empty. Add 'servers':[{'url':'hostname.com'}'")
		//return swagger, WorkflowApp{}, []string{}, errors.New("Swagger.Servers can't be empty. Add 'servers':[{'url':'hostname.com'}'")
		swagger.Servers = openapi3.Servers{
			&openapi3.Server{
				URL: "https://hostname.com",
			},
		}
	}

	api.Name = swagger.Info.Title
	api.Description = swagger.Info.Description

	// FIXME: Versioning issue?
	api.ID = newmd5
	//uuid.NewV4().String()

	api.IsValid = true
	api.Link = swagger.Servers[0].URL // host does not exist lol
	if strings.HasSuffix(api.Link, "/") {
		api.Link = api.Link[:len(api.Link)-1]
	}

	example := "https://api-url"
	if len(api.Link) > 0 {
		example = api.Link
		linkSplit := strings.Split(api.Link, "/")
		if len(linkSplit) > 3 {
			example = strings.Join(linkSplit[0:3], "/")
		}

		//log.Printf("EXAMPLE: %s", example)
	}

	api.AppVersion = "1.0.0"
	api.Environment = "Shuffle"
	api.SmallImage = ""
	api.LargeImage = ""
	api.Sharing = false
	api.Verified = false
	api.Tested = false
	api.Invalid = false
	api.PrivateID = newmd5
	api.Generated = true
	api.Activated = true
	// Setting up security schemes
	extraParameters := []WorkflowAppActionParameter{}

	if val, ok := swagger.Info.ExtensionProps.Extensions["x-logo"]; ok {
		j, err := json.Marshal(&val)
		if err == nil {
			if j[0] == 0x22 && j[len(j)-1] == 0x22 {
				j = j[1 : len(j)-1]
			}

			//log.Printf("%s", j)
			api.SmallImage = string(j)
			api.LargeImage = string(j)
		}
	}

	// Jesus what a clusterfuck.
	// Handles parsing of categories from OpenApi3 custom field
	if val, ok := swagger.Info.ExtensionProps.Extensions["x-categories"]; ok {
		//log.Printf("Categories: %#v", val)
		j, err := json.Marshal(&val)
		if err == nil {
			if j[0] == 0x22 && j[len(j)-1] == 0x22 {
				j = j[1 : len(j)-1]
			}

			parsedCategories := fmt.Sprintf(`{"categories": %s}`, string(j))
			type parsed struct {
				Categories []string `json:"categories"`
			}

			var parse parsed
			err := json.Unmarshal([]byte(parsedCategories), &parse)
			if err != nil {
				log.Printf("Failed unmarshaling categories: %s", err)
			} else {
				api.Categories = parse.Categories
			}
		}
	}

	if len(swagger.Tags) > 0 {
		newTags := []string{}
		for _, tag := range swagger.Tags {
			newTags = append(newTags, tag.Name)
		}

		api.Tags = newTags
	}

	securitySchemes := swagger.Components.SecuritySchemes
	reservedKeys := []string{"BearerAuth", "ApiKeyAuth", "Oauth2", "BasicAuth", "jwt"}

	if securitySchemes != nil {
		//log.Printf("%#v", securitySchemes)

		api.Authentication = Authentication{
			Required:   true,
			Parameters: []AuthenticationParams{},
		}

		// Used for python code generation lol
		// Not sure how this should work with oauth
		if securitySchemes["BearerAuth"] != nil {
			api.Authentication.Parameters = append(api.Authentication.Parameters, AuthenticationParams{
				Name:        "apikey",
				Value:       "",
				Example:     "******",
				Description: securitySchemes["BearerAuth"].Value.Description,
				In:          securitySchemes["BearerAuth"].Value.In,
				Scheme:      securitySchemes["BearerAuth"].Value.Scheme,
				Schema: SchemaDefinition{
					Type: securitySchemes["BearerAuth"].Value.Scheme,
				},
			})

			//log.Printf("HANDLE BEARER AUTH")
			extraParameters = append(extraParameters, WorkflowAppActionParameter{
				Name:          "apikey",
				Description:   "The apikey to use",
				Multiline:     false,
				Required:      true,
				Example:       "The API key to use. Space = skip",
				Configuration: true,
				Schema: SchemaDefinition{
					Type: "string",
				},
			})
		} else if securitySchemes["ApiKeyAuth"] != nil {
			//log.Printf("AUTH:%#v", securitySchemes["ApiKeyAuth"].Value)
			newAuthParam := AuthenticationParams{
				Name:        "apikey",
				Value:       "",
				Example:     "******",
				Description: securitySchemes["ApiKeyAuth"].Value.Description,
				In:          securitySchemes["ApiKeyAuth"].Value.In,
				Scheme:      securitySchemes["ApiKeyAuth"].Value.Scheme,
				Schema: SchemaDefinition{
					Type: securitySchemes["ApiKeyAuth"].Value.Scheme,
				},
			}

			//Example:     securitySchemes["ApiKeyAuth"].Value.Example,

			//log.Printf("HANDLE APIKEY AUTH")
			extraParam := WorkflowAppActionParameter{
				Name:          "apikey",
				Description:   "The apikey to use",
				Multiline:     false,
				Required:      true,
				Example:       "**********",
				Configuration: true,
				Schema: SchemaDefinition{
					Type: "string",
				},
			}

			if len(securitySchemes["ApiKeyAuth"].Value.Description) > 0 {
				//log.Printf("UPDATING AUTH!")
				extraParam.Description = fmt.Sprintf("Start with %s", securitySchemes["ApiKeyAuth"].Value.Description)
				newAuthParam.Description = fmt.Sprintf("Start with %s", securitySchemes["ApiKeyAuth"].Value.Description)
			}

			api.Authentication.Parameters = append(api.Authentication.Parameters, newAuthParam)
			extraParameters = append(extraParameters, extraParam)
		} else if securitySchemes["Oauth2"] != nil {
			api.Authentication.Type = "oauth2"
			if val, ok := securitySchemes["Oauth2"].Value.ExtensionProps.Extensions["flow"]; ok {
				//log.Printf("VAL:: %#v", val.(json.RawMessage))
				newValue := string(fmt.Sprintf("%s", string(val.(json.RawMessage))))
				//log.Printf("DATA: %s", newValue)

				var parsed Oauth2Openapi
				err := json.Unmarshal([]byte(newValue), &parsed)
				if err != nil {
					log.Printf("[WARNING] Failed to unmarshal Oauth2 data for app %s", api.Name)
				} else {
					log.Printf("[DEBUG] Set up Oauth2 config for app %s during generation", api.Name)
					api.Authentication.Type = "oauth2"
					api.Authentication.RedirectUri = parsed.AuthorizationCode.AuthorizationUrl
					api.Authentication.TokenUri = parsed.AuthorizationCode.TokenUrl
					api.Authentication.RefreshUri = parsed.AuthorizationCode.RefreshUrl
					api.Authentication.Scope = parsed.AuthorizationCode.Scopes
				}
			} else {
				log.Printf("[ERROR] No Oauth2 data to parse for app %s - bad parsing?", api.Name)
				return swagger, WorkflowApp{}, []string{}, errors.New("Missing Oauth2 refreshUrl, scope, authorization URL or Token URL")
			}

			api.Authentication.Parameters = append(api.Authentication.Parameters, AuthenticationParams{
				Name:        "client_id",
				Value:       "",
				Example:     "client_id",
				Description: securitySchemes["Oauth2"].Value.Description,
				In:          securitySchemes["Oauth2"].Value.In,
				Scheme:      securitySchemes["Oauth2"].Value.Scheme,
				Schema: SchemaDefinition{
					Type: securitySchemes["Oauth2"].Value.Scheme,
				},
			})

			//if val, ok := param.Value.ExtensionProps.Extensions["multiline"]; ok {
			//.AuthorizationUrl
			api.Authentication.Parameters = append(api.Authentication.Parameters, AuthenticationParams{
				Name:        "client_id",
				Value:       "",
				Example:     "client_id",
				Description: securitySchemes["Oauth2"].Value.Description,
				In:          securitySchemes["Oauth2"].Value.In,
				Scheme:      securitySchemes["Oauth2"].Value.Scheme,
				Schema: SchemaDefinition{
					Type: securitySchemes["Oauth2"].Value.Scheme,
				},
			})
			api.Authentication.Parameters = append(api.Authentication.Parameters, AuthenticationParams{
				Name:        "client_secret",
				Value:       "",
				Example:     "client_secret",
				Description: securitySchemes["Oauth2"].Value.Description,
				In:          securitySchemes["Oauth2"].Value.In,
				Scheme:      securitySchemes["Oauth2"].Value.Scheme,
				Schema: SchemaDefinition{
					Type: securitySchemes["Oauth2"].Value.Scheme,
				},
			})
		} else if securitySchemes["jwt"] != nil {
			if len(securitySchemes["jwt"].Value.In) > 0 {
				api.Authentication.TokenUri = securitySchemes["jwt"].Value.In
			}

			api.Authentication.Parameters = append(api.Authentication.Parameters, AuthenticationParams{
				Name:        "username_basic",
				Value:       "",
				Example:     "username",
				Description: "",
				In:          "",
				Scheme:      "",
				Schema: SchemaDefinition{
					Type: securitySchemes["jwt"].Value.Scheme,
				},
			})

			api.Authentication.Parameters = append(api.Authentication.Parameters, AuthenticationParams{
				Name:        "password_basic",
				Value:       "",
				Example:     "*****",
				Description: "",
				In:          "",
				Scheme:      "",
				Schema: SchemaDefinition{
					Type: securitySchemes["jwt"].Value.Scheme,
				},
			})

			extraParameters = append(extraParameters, WorkflowAppActionParameter{
				Name:          "username_basic",
				Description:   "The username to use",
				Multiline:     false,
				Required:      true,
				Example:       "The username to use",
				Configuration: true,
				Schema: SchemaDefinition{
					Type: "string",
				},
			})
			extraParameters = append(extraParameters, WorkflowAppActionParameter{
				Name:          "password_basic",
				Description:   "The password to use",
				Multiline:     false,
				Required:      true,
				Example:       "***********",
				Configuration: true,
				Schema: SchemaDefinition{
					Type: "string",
				},
			})
		} else if securitySchemes["BasicAuth"] != nil {
			api.Authentication.Parameters = append(api.Authentication.Parameters, AuthenticationParams{
				Name:        "username_basic",
				Value:       "",
				Example:     "username",
				Description: securitySchemes["BasicAuth"].Value.Description,
				In:          securitySchemes["BasicAuth"].Value.In,
				Scheme:      securitySchemes["BasicAuth"].Value.Scheme,
				Schema: SchemaDefinition{
					Type: securitySchemes["BasicAuth"].Value.Scheme,
				},
			})

			api.Authentication.Parameters = append(api.Authentication.Parameters, AuthenticationParams{
				Name:        "password_basic",
				Value:       "",
				Example:     "*****",
				Description: securitySchemes["BasicAuth"].Value.Description,
				In:          securitySchemes["BasicAuth"].Value.In,
				Scheme:      securitySchemes["BasicAuth"].Value.Scheme,
				Schema: SchemaDefinition{
					Type: securitySchemes["BasicAuth"].Value.Scheme,
				},
			})

			extraParameters = append(extraParameters, WorkflowAppActionParameter{
				Name:          "username_basic",
				Description:   "The username to use",
				Multiline:     false,
				Required:      true,
				Example:       "The username to use",
				Configuration: true,
				Schema: SchemaDefinition{
					Type: "string",
				},
			})
			extraParameters = append(extraParameters, WorkflowAppActionParameter{
				Name:          "password_basic",
				Description:   "The password to use",
				Multiline:     false,
				Required:      true,
				Example:       "***********",
				Configuration: true,
				Schema: SchemaDefinition{
					Type: "string",
				},
			})
		}
	}

	for key, value := range securitySchemes {
		if ArrayContains(reservedKeys, key) {
			continue
		}

		//log.Printf("%s: %#v", key, value.Value)
		exampleData := fmt.Sprintf("Extra auth field (%s)", value.Value.In)
		api.Authentication.Parameters = append(api.Authentication.Parameters, AuthenticationParams{
			Name:        key,
			Value:       "",
			Example:     exampleData,
			Description: exampleData,
			In:          value.Value.In,
			Scheme:      "",
			Schema: SchemaDefinition{
				Type: "string",
			},
		})

		extraParameters = append(extraParameters, WorkflowAppActionParameter{
			Name:          key,
			Multiline:     false,
			Required:      true,
			Description:   exampleData,
			Example:       exampleData,
			Configuration: true,
			Schema: SchemaDefinition{
				Type: "string",
			},
		})
	}

	// Adds a link parameter if it's not already defined
	api.Authentication.Parameters = append(api.Authentication.Parameters, AuthenticationParams{
		Name:        "url",
		Description: "The URL of the app",
		Value:       example,
		Example:     example,
		Multiline:   false,
		Required:    true,
		Schema: SchemaDefinition{
			Type: "string",
		},
	})

	extraParameters = append(extraParameters, WorkflowAppActionParameter{
		Name:          "url",
		Description:   "The URL of the API",
		Value:         example,
		Example:       example,
		Multiline:     false,
		Required:      true,
		Configuration: true,
		Schema: SchemaDefinition{
			Type: "string",
		},
	})

	// This is the python code to be generated
	// Could just as well be go at this point lol
	pythonFunctions := []string{}

	optionalParameters := []WorkflowAppActionParameter{}
	headerParam := WorkflowAppActionParameter{
		Name:        "headers",
		Description: "Add or edit headers",
		Multiline:   true,
		Required:    false,
		Example:     "Content-Type=application/json\nAccept=application/json",
		Schema: SchemaDefinition{
			Type: "string",
		},
	}

	optionalParameters = append(optionalParameters, headerParam)
	optionalParameters = append(optionalParameters, WorkflowAppActionParameter{
		Name:        "queries",
		Description: "Add or edit queries",
		Multiline:   true,
		Required:    false,
		Example:     "view=basic&redirect=test",
		Schema: SchemaDefinition{
			Type: "string",
		},
	})

	// Not validating by default, due to lots of people having issues with
	// SSL things
	optionalParameters = append(optionalParameters, WorkflowAppActionParameter{
		Name:        "ssl_verify",
		Description: "Check if you want to verify request",
		Multiline:   false,
		Required:    false,
		Example:     "True",
		Options: []string{
			"False",
			"True",
		},
		Schema: SchemaDefinition{
			Type: "string",
		},
	})

	optionalParameters = append(optionalParameters, WorkflowAppActionParameter{
		Name:        "to_file",
		Description: "Choose if we should write the result straight to a file or not",
		Multiline:   false,
		Required:    false,
		Example:     "False",
		Options: []string{
			"False",
			"True",
		},
		Schema: SchemaDefinition{
			Type: "string",
		},
	})

	//Verified      bool   `json:"verified" yaml:"verified" required:false datastore:"verified"`
	for actualPath, path := range swagger.Paths {
		actualPath = strings.Replace(actualPath, " ", "_", -1)
		//actualPath = strings.Replace(actualPath, ".", "", -1)
		actualPath = strings.Replace(actualPath, "\\", "", -1)
		if !api.Invalid && strings.HasPrefix(actualPath, "tmp") {
			log.Printf("[WARNING] Set api %s to invalid because of path %s", swagger.Info.Title, actualPath)
			api.Invalid = true
		}

		// FIXME: Handle everything behind questionmark (?) with dots as well.
		// https://godoc.org/github.com/getkin/kin-openapi/openapi3#PathItem
		if path.Get != nil {
			action, curCode := HandleGet(swagger, api, extraParameters, path, actualPath, optionalParameters)
			api.Actions = append(api.Actions, action)
			pythonFunctions = append(pythonFunctions, curCode)
		}
		if path.Connect != nil {
			action, curCode := HandleConnect(swagger, api, extraParameters, path, actualPath, optionalParameters)
			api.Actions = append(api.Actions, action)
			pythonFunctions = append(pythonFunctions, curCode)
		}
		if path.Head != nil {
			action, curCode := HandleHead(swagger, api, extraParameters, path, actualPath, optionalParameters)
			api.Actions = append(api.Actions, action)
			pythonFunctions = append(pythonFunctions, curCode)
		}
		if path.Delete != nil {
			action, curCode := HandleDelete(swagger, api, extraParameters, path, actualPath, optionalParameters)
			api.Actions = append(api.Actions, action)
			pythonFunctions = append(pythonFunctions, curCode)
		}
		if path.Post != nil {
			action, curCode := HandlePost(swagger, api, extraParameters, path, actualPath, optionalParameters)
			api.Actions = append(api.Actions, action)
			pythonFunctions = append(pythonFunctions, curCode)
		}
		if path.Patch != nil {
			action, curCode := HandlePatch(swagger, api, extraParameters, path, actualPath, optionalParameters)
			api.Actions = append(api.Actions, action)
			pythonFunctions = append(pythonFunctions, curCode)
		}
		if path.Put != nil {
			action, curCode := HandlePut(swagger, api, extraParameters, path, actualPath, optionalParameters)
			api.Actions = append(api.Actions, action)
			pythonFunctions = append(pythonFunctions, curCode)
		}

		// Has to be here because its used differently above.
		// FIXING this is done during export instead?
		//log.Printf("OLDPATH: %s", actualPath)
		//if strings.Contains(actualPath, "?") {
		//	actualPath = strings.Split(actualPath, "?")[0]
		//}

		//log.Printf("NEWPATH: %s", actualPath)
		//newPaths[actualPath] = path
	}

	return swagger, api, pythonFunctions, nil
}

// FIXME - have this give a real version?
func VerifyApi(api WorkflowApp) WorkflowApp {
	if api.AppVersion == "" {
		api.AppVersion = "1.0.0"
	}

	return api
}

func GetBasePython() string {
	baseString := `import requests
import asyncio
import json
import urllib3

from walkoff_app_sdk.app_base import AppBase

class %s(AppBase):
    """
    Autogenerated class by Shuffler
    """
    
    __version__ = "%s"
    app_name = "%s"
    
    def __init__(self, redis, logger, console_logger=None):
    	self.verify = False
    	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    	super().__init__(redis, logger, console_logger)

%s

if __name__ == "__main__":
    %s.run()
`
	//#asyncio.run(%s.run(), debug=True)
	return baseString

}

func DumpPythonGCP(ctx context.Context, client *storage.Client, basePath, name, version string, pythonFunctions []string, bucketName string) (string, error) {
	parsedCode := fmt.Sprintf(GetBasePython(), name, version, name, strings.Join(pythonFunctions, "\n"), name)

	// Create bucket handle
	bucket := client.Bucket(bucketName)
	obj := bucket.Object(fmt.Sprintf("%s/src/app.py", basePath))
	w := obj.NewWriter(ctx)
	if _, err := fmt.Fprintln(w, parsedCode); err != nil {
		return "", err
	}
	// Close, just like writing a file.
	if err := w.Close(); err != nil {
		return "", err
	}

	return parsedCode, nil
}

func DumpPython(basePath, name, version string, pythonFunctions []string) (string, error) {
	//log.Printf("%#v", api)
	//log.Printf(strings.Join(pythonFunctions, "\n"))

	parsedCode := fmt.Sprintf(GetBasePython(), name, version, name, strings.Join(pythonFunctions, "\n"), name)

	err := ioutil.WriteFile(fmt.Sprintf("%s/src/app.py", basePath), []byte(parsedCode), os.ModePerm)
	if err != nil {
		return "", err
	}
	//fmt.Println(parsedCode)
	//log.Println(string(data))
	return parsedCode, nil
}

func DumpApiGCP(ctx context.Context, client *storage.Client, swagger *openapi3.Swagger, basePath string, api WorkflowApp, bucketName string) error {
	//log.Printf("%#v", api)
	data, err := yaml.Marshal(api)
	if err != nil {
		log.Printf("Error with yaml marshal: %s", err)
		return err
	}

	// Create bucket handle
	bucket := client.Bucket(bucketName)
	obj := bucket.Object(fmt.Sprintf("%s/app.yaml", basePath))
	w := obj.NewWriter(ctx)
	if _, err := fmt.Fprintln(w, string(data)); err != nil {
		return err
	}
	// Close, just like writing a file.
	if err := w.Close(); err != nil {
		return err
	}

	openapidata, err := yaml.Marshal(swagger)
	if err != nil {
		log.Printf("Error with yaml marshal: %s", err)
		return err
	}
	obj = bucket.Object(fmt.Sprintf("%s/openapi.yaml", basePath))
	//log.Println(string(openapidata))
	w = obj.NewWriter(ctx)
	if _, err := fmt.Fprintln(w, string(openapidata)); err != nil {
		return err
	}
	// Close, just like writing a file.
	if err := w.Close(); err != nil {
		return err
	}

	//log.Println(string(data))
	return nil
}

func DumpApi(basePath string, api WorkflowApp) error {
	//log.Printf("%#v", api)
	data, err := yaml.Marshal(api)
	if err != nil {
		log.Printf("Error with yaml marshal: %s", err)
		return err
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/api.yaml", basePath), []byte(data), os.ModePerm)
	if err != nil {
		return err
	}

	//log.Println(string(data))
	return nil
}

func GetRunnerOnprem(classname string) string {
	return fmt.Sprintf(`
# Run the actual thing after we've checked params
def run(request):
    print("Started execution!")
    action = request.get_json() 
    #print(action)
    #print(type(action))
    authorization_key = action.get("authorization")
    current_execution_id = action.get("execution_id")
	
    if action and "name" in action and "app_name" in action:
        %s.run(action=action)
        return f'Attempting to execute function {action["name"]} in app {action["app_name"]}' 
    else:
        return f'Invalid action'

	`, classname)
}

func GetRunnerGCP(classname string) string {
	return fmt.Sprintf(`
# Run the actual thing after we've checked params
def run(request):
	#print(request.data)
	try:
		action = request.get_json(force=True)
	except:
		return f'Error parsing JSON'

	#print(f'ACTION: {action}')
	if action == None:
		print("Returning because no action defined")
		return f'No JSON detected'

	#authorization_key = action.get("authorization")
	#current_execution_id = action.get("execution_id")
	
	if action and "name" in action and "app_name" in action:
		%s.run(action=action)
		return f'Attempting to execute function {action["name"]} in app {action["app_name"]}' 

	return f'Action ran!'

	`, classname)
}

func DeployAppToDatastore(ctx context.Context, workflowapp WorkflowApp) error {
	err := SetWorkflowAppDatastore(ctx, workflowapp, workflowapp.ID)
	if err != nil {
		log.Printf("[ERROR] Failed setting workflowapp: %s", err)
		return err
	} else {
		log.Printf("[INFO] Added %s:%s to the database", workflowapp.Name, workflowapp.AppVersion)
	}

	return nil
}

// FIXME:
// https://docs.python.org/3.2/reference/lexical_analysis.html#identifiers
// This is used to build the python functions.
func FixFunctionName(functionName, actualPath string) string {
	if len(functionName) == 0 {
		functionName = actualPath
	}

	// REGEX THIS SHIT
	// ROFL

	//log.Printf("Fixing function name for %s", functionName)
	functionName = strings.Replace(functionName, ".", "", -1)
	functionName = strings.Replace(functionName, ",", "", -1)
	functionName = strings.Replace(functionName, ".", "", -1)
	functionName = strings.Replace(functionName, "&", "", -1)
	functionName = strings.Replace(functionName, "/", "", -1)
	functionName = strings.Replace(functionName, "\\", "", -1)

	functionName = strings.Replace(functionName, "!", "", -1)
	functionName = strings.Replace(functionName, "?", "", -1)
	functionName = strings.Replace(functionName, "@", "", -1)
	functionName = strings.Replace(functionName, "#", "", -1)
	functionName = strings.Replace(functionName, "$", "", -1)
	functionName = strings.Replace(functionName, "&", "", -1)
	functionName = strings.Replace(functionName, "*", "", -1)
	functionName = strings.Replace(functionName, "(", "", -1)
	functionName = strings.Replace(functionName, ")", "", -1)
	functionName = strings.Replace(functionName, "[", "", -1)
	functionName = strings.Replace(functionName, "]", "", -1)
	functionName = strings.Replace(functionName, "{", "", -1)
	functionName = strings.Replace(functionName, "}", "", -1)
	functionName = strings.Replace(functionName, `"`, "", -1)
	functionName = strings.Replace(functionName, `'`, "", -1)
	functionName = strings.Replace(functionName, `|`, "", -1)
	functionName = strings.Replace(functionName, `~`, "", -1)

	functionName = strings.Replace(functionName, " ", "_", -1)
	functionName = strings.Replace(functionName, "-", "_", -1)

	functionName = strings.ToLower(functionName)

	return functionName
}

// Returns a valid param name
func ValidateParameterName(name string) string {
	invalid := []string{"False",
		"await",
		"else",
		"import",
		"pass",
		"None",
		"break",
		"except",
		"in",
		"raise",
		"True",
		"class",
		"finally",
		"is",
		"return",
		"and",
		"continue",
		"for",
		"lambda",
		"try",
		"as",
		"def",
		"from",
		"nonlocal",
		"while",
		"assert",
		"del",
		"global",
		"not",
		"with",
		"async",
		"elif",
		"if",
		"or",
		"yield",
	}

	newname := name
	for _, item := range invalid {
		if item == name {
			//log.Printf("%s is NOT a valid parameter name!", item)
			newname = fmt.Sprintf("%s_shuffle", item)
			break
		}
	}

	newname = strings.Replace(newname, " ", "_", -1)
	newname = strings.Replace(newname, ",", "_", -1)
	newname = strings.Replace(newname, ".", "_", -1)
	newname = strings.Replace(newname, "|", "_", -1)
	newname = strings.Replace(newname, "-", "_", -1)

	return newname
}

func HandleConnect(swagger *openapi3.Swagger, api WorkflowApp, extraParameters []WorkflowAppActionParameter, path *openapi3.PathItem, actualPath string, optionalParameters []WorkflowAppActionParameter) (WorkflowAppAction, string) {
	// What to do with this, hmm
	functionName := FixFunctionName(path.Connect.Summary, actualPath)

	baseUrl := fmt.Sprintf("%s%s", api.Link, actualPath)
	newDesc := fmt.Sprintf("%s\n\n%s", path.Connect.Description, baseUrl)
	action := WorkflowAppAction{
		Description: newDesc,
		Name:        fmt.Sprintf("%s %s", "Connect", path.Connect.Summary),
		Label:       fmt.Sprintf(path.Connect.Summary),
		NodeType:    "action",
		Environment: api.Environment,
		Parameters:  extraParameters,
	}

	action.Returns.Schema.Type = "string"
	if strings.Contains(baseUrl, "_shuffle_replace_") {
		//log.Printf("[DEBUG] : %s", baseUrl)
		m := regexp.MustCompile(`_shuffle_replace_\d`)
		baseUrl = m.ReplaceAllString(baseUrl, "")
	}
	handleFile := false

	//log.Println(path.Parameters)

	// Parameters:  []WorkflowAppActionParameter{},
	//firstQuery := true
	optionalQueries := []string{}
	parameters := []string{}

	headersFound := []string{}
	if len(path.Connect.Parameters) > 0 {
		for counter, param := range path.Connect.Parameters {
			if param.Value.Schema == nil {
				continue
			} else if param.Value.In == "header" {
				headersFound = append(headersFound, fmt.Sprintf("%s=%s", param.Value.Name, param.Value.Example))
				continue
			}

			parsedName := param.Value.Name
			parsedName = strings.Replace(parsedName, " ", "_", -1)
			parsedName = strings.Replace(parsedName, ",", "_", -1)
			parsedName = strings.Replace(parsedName, ".", "_", -1)
			parsedName = strings.Replace(parsedName, "|", "_", -1)
			parsedName = strings.Replace(parsedName, "-", "_", -1)
			parsedName = ValidateParameterName(parsedName)
			param.Value.Name = parsedName
			path.Connect.Parameters[counter].Value.Name = parsedName

			curParam := WorkflowAppActionParameter{
				Name:        parsedName,
				Description: param.Value.Description,
				Multiline:   false,
				Required:    param.Value.Required,
				Schema: SchemaDefinition{
					Type: param.Value.Schema.Value.Type,
				},
			}

			// FIXME: Example & Multiline
			if param.Value.Example != nil {
				curParam.Example = param.Value.Example.(string)

				if param.Value.Name == "body" {
					curParam.Value = param.Value.Example.(string)
				}
			}
			if val, ok := param.Value.ExtensionProps.Extensions["multiline"]; ok {
				j, err := json.Marshal(&val)
				if err == nil {
					b, err := strconv.ParseBool(string(j))
					if err == nil {
						curParam.Multiline = b
					}
				}
			}

			if param.Value.Required {
				action.Parameters = append(action.Parameters, curParam)
			} else {
				optionalParameters = append(optionalParameters, curParam)
			}

			if param.Value.In == "path" {
				parameters = append(parameters, curParam.Name)
				//baseUrl = fmt.Sprintf("%s%s", baseUrl)
			} else if param.Value.In == "query" {
				//log.Printf("QUERY!: %s", param.Value.Name)
				if !param.Value.Required {
					optionalQueries = append(optionalQueries, param.Value.Name)
					continue
				}

				parameters = append(parameters, param.Value.Name)

				if strings.Contains(baseUrl, fmt.Sprintf("%s={%s}", param.Value.Name, param.Value.Name)) {
					continue
				}

				if strings.Contains(baseUrl, fmt.Sprintf("{%s}", param.Value.Name)) {
					continue
				}

				//if firstQuery && !strings.Contains(baseUrl, "?") {
				//	baseUrl = fmt.Sprintf("%s?%s={%s}", baseUrl, param.Value.Name, param.Value.Name)
				//} else {
				//	baseUrl = fmt.Sprintf("%s&%s={%s}", baseUrl, param.Value.Name, param.Value.Name)
				//}
				//firstQuery = false
			}

		}
	}

	if len(headersFound) > 0 {
		setIndex := -1
		for paramIndex, param := range optionalParameters {
			if param.Name == "headers" {
				setIndex = paramIndex
				break
			}
		}

		if setIndex >= 0 {
			for _, header := range headersFound {
				if !strings.Contains(header, "=") {
					continue
				}

				headerKey := strings.Split(header, "=")[0]
				if strings.Contains(optionalParameters[setIndex].Value, headerKey) {
					continue
				}

				optionalParameters[setIndex].Value = fmt.Sprintf("%s%s\n", optionalParameters[setIndex].Value, header)
			}

			//log.Printf("What: %#v", optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-1])
			//log.Printf("HI: %s",
			//optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-2])
			// Removing newlines at the end
			if len(optionalParameters[setIndex].Value) > 0 && optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-1] == 0xa {
				optionalParameters[setIndex].Value = optionalParameters[setIndex].Value[0 : len(optionalParameters[setIndex].Value)-1]
			}

			log.Printf("%#v", optionalParameters[setIndex].Value)
		}
	}

	// Must be here 'cus they should be last
	headerKey := `headers=""`
	if !ArrayContains(parameters, headerKey) {
		parameters = append(parameters, headerKey)
	}

	queryKey := `queries=""`
	if !ArrayContains(parameters, queryKey) {
		parameters = append(parameters, queryKey)
	}

	// ensuring that they end up last in the specification
	// (order is ish important for optional params) - they need to be last.
	for _, optionalParam := range optionalParameters {
		action.Parameters = append(action.Parameters, optionalParam)
	}

	functionname, curCode := MakePythoncode(swagger, functionName, baseUrl, "connect", parameters, optionalQueries, headersFound, "", api, handleFile)

	if len(functionname) > 0 {
		action.Name = functionname
	}

	return action, curCode
}

func HandleGet(swagger *openapi3.Swagger, api WorkflowApp, extraParameters []WorkflowAppActionParameter, path *openapi3.PathItem, actualPath string, optionalParameters []WorkflowAppActionParameter) (WorkflowAppAction, string) {
	// What to do with this, hmm
	functionName := FixFunctionName(path.Get.Summary, actualPath)

	baseUrl := fmt.Sprintf("%s%s", api.Link, actualPath)
	newDesc := fmt.Sprintf("%s\n\n%s", path.Get.Description, baseUrl)
	action := WorkflowAppAction{
		Description: newDesc,
		Name:        fmt.Sprintf("%s %s", "Get", path.Get.Summary),
		Label:       fmt.Sprintf(path.Get.Summary),
		NodeType:    "action",
		Environment: api.Environment,
		Parameters:  extraParameters,
	}

	action.Returns.Schema.Type = "string"
	if strings.Contains(baseUrl, "_shuffle_replace_") {
		//log.Printf("[DEBUG] : %s", baseUrl)
		m := regexp.MustCompile(`_shuffle_replace_\d`)
		baseUrl = m.ReplaceAllString(baseUrl, "")
	}

	// Check if it should return as file (binary)
	// FIXME: Don't JUST specif text/plain to allow this.
	handleFile := false
	if strings.Contains(path.Get.Summary, "Download") {
		if defaultInfo, ok := path.Get.Responses["default"]; ok {

			if content, ok := defaultInfo.Value.Content["text/plain"]; ok {
				if content.Schema.Value.Type == "string" && content.Schema.Value.Format == "binary" {
					handleFile = true
				}
			}
		}
	}

	// Parameters:  []WorkflowAppActionParameter{},
	//firstQuery := true
	optionalQueries := []string{}

	// FIXME - remove this when authentication is properly introduced
	parameters := []string{}
	headersFound := []string{}
	if len(path.Get.Parameters) > 0 {
		for counter, param := range path.Get.Parameters {
			if param.Value.Schema == nil {
				continue
			} else if param.Value.In == "header" {
				headersFound = append(headersFound, fmt.Sprintf("%s=%s", param.Value.Name, param.Value.Example))
				continue
			}

			parsedName := param.Value.Name
			parsedName = strings.Replace(parsedName, " ", "_", -1)
			parsedName = strings.Replace(parsedName, ",", "_", -1)
			parsedName = strings.Replace(parsedName, ".", "_", -1)
			parsedName = strings.Replace(parsedName, "|", "_", -1)
			parsedName = ValidateParameterName(parsedName)
			param.Value.Name = parsedName
			path.Get.Parameters[counter].Value.Name = parsedName

			curParam := WorkflowAppActionParameter{
				Name:        parsedName,
				Description: param.Value.Description,
				Multiline:   false,
				Required:    param.Value.Required,
				Schema: SchemaDefinition{
					Type: param.Value.Schema.Value.Type,
				},
			}

			// FIXME: Example & Multiline
			if param.Value.Example != nil {
				curParam.Example = param.Value.Example.(string)

				if param.Value.Name == "body" {
					curParam.Value = param.Value.Example.(string)
				}
			}
			if val, ok := param.Value.ExtensionProps.Extensions["multiline"]; ok {
				j, err := json.Marshal(&val)
				if err == nil {
					b, err := strconv.ParseBool(string(j))
					if err == nil {
						curParam.Multiline = b
					}
				}
			}

			if param.Value.Required {
				action.Parameters = append(action.Parameters, curParam)
			} else {
				optionalParameters = append(optionalParameters, curParam)
			}

			if param.Value.In == "path" {
				parameters = append(parameters, curParam.Name)
				//baseUrl = fmt.Sprintf("%s%s", baseUrl)
			} else if param.Value.In == "query" {
				//log.Printf("QUERY!: %s", param.Value.Name)
				if !param.Value.Required {
					optionalQueries = append(optionalQueries, param.Value.Name)
					continue
				}

				parameters = append(parameters, param.Value.Name)

				// Skipping simial
				if strings.Contains(baseUrl, fmt.Sprintf("%s={%s}", param.Value.Name, param.Value.Name)) {
					continue
				}

				if strings.Contains(baseUrl, fmt.Sprintf("{%s}", param.Value.Name)) {
					continue
				}

				//if firstQuery && !strings.Contains(baseUrl, "?") {
				//	baseUrl = fmt.Sprintf("%s?%s={%s}", baseUrl, param.Value.Name, param.Value.Name)
				//} else {
				//	baseUrl = fmt.Sprintf("%s&%s={%s}", baseUrl, param.Value.Name, param.Value.Name)
				//}
				//firstQuery = false
			}

		}
	}

	if len(headersFound) > 0 {
		setIndex := -1
		for paramIndex, param := range optionalParameters {
			if param.Name == "headers" {
				setIndex = paramIndex
				break
			}
		}

		if setIndex >= 0 {
			for _, header := range headersFound {
				if !strings.Contains(header, "=") {
					continue
				}

				headerKey := strings.Split(header, "=")[0]
				if strings.Contains(optionalParameters[setIndex].Value, headerKey) {
					continue
				}

				optionalParameters[setIndex].Value = fmt.Sprintf("%s%s\n", optionalParameters[setIndex].Value, header)
			}

			if len(optionalParameters[setIndex].Value) > 0 && optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-1] == 0xa {
				optionalParameters[setIndex].Value = optionalParameters[setIndex].Value[0 : len(optionalParameters[setIndex].Value)-1]

				//optionalParameters[setIndex].Example = optionalParameters[setIndex].Example[0 : len(optionalParameters[setIndex].Example)-1]
			}

			//log.Printf("%#v", optionalParameters[setIndex].Value)
		}
	} else {
		//log.Printf("No headers found for %s", functionName)
	}

	// Must be here 'cus they should be last
	headerKey := `headers=""`
	if !ArrayContains(parameters, headerKey) {
		parameters = append(parameters, headerKey)
	}

	queryKey := `queries=""`
	if !ArrayContains(parameters, queryKey) {
		parameters = append(parameters, queryKey)
	}

	// ensuring that they end up last in the specification
	// (order is ish important for optional params) - they need to be last.
	for _, optionalParam := range optionalParameters {
		action.Parameters = append(action.Parameters, optionalParam)
	}

	functionname, curCode := MakePythoncode(swagger, functionName, baseUrl, "get", parameters, optionalQueries, headersFound, "", api, handleFile)

	if len(functionname) > 0 {
		action.Name = functionname
	}

	return action, curCode
}

func HandleHead(swagger *openapi3.Swagger, api WorkflowApp, extraParameters []WorkflowAppActionParameter, path *openapi3.PathItem, actualPath string, optionalParameters []WorkflowAppActionParameter) (WorkflowAppAction, string) {
	// What to do with this, hmm
	functionName := FixFunctionName(path.Head.Summary, actualPath)

	baseUrl := fmt.Sprintf("%s%s", api.Link, actualPath)
	newDesc := fmt.Sprintf("%s\n\n%s", path.Head.Description, baseUrl)
	action := WorkflowAppAction{
		Description: newDesc,
		Name:        fmt.Sprintf("%s %s", "Head", path.Head.Summary),
		Label:       fmt.Sprintf(path.Head.Summary),
		NodeType:    "action",
		Environment: api.Environment,
		Parameters:  extraParameters,
	}

	action.Returns.Schema.Type = "string"
	if strings.Contains(baseUrl, "_shuffle_replace_") {
		//log.Printf("[DEBUG] : %s", baseUrl)
		m := regexp.MustCompile(`_shuffle_replace_\d`)
		baseUrl = m.ReplaceAllString(baseUrl, "")
	}
	handleFile := false

	//log.Println(path.Parameters)

	// Parameters:  []WorkflowAppActionParameter{},
	//firstQuery := true
	optionalQueries := []string{}
	parameters := []string{}
	headersFound := []string{}
	if len(path.Head.Parameters) > 0 {
		for counter, param := range path.Head.Parameters {
			if param.Value.Schema == nil {
				continue
			} else if param.Value.In == "header" {
				headersFound = append(headersFound, fmt.Sprintf("%s=%s", param.Value.Name, param.Value.Example))
				continue
			}

			parsedName := param.Value.Name
			parsedName = strings.Replace(parsedName, " ", "_", -1)
			parsedName = strings.Replace(parsedName, ",", "_", -1)
			parsedName = strings.Replace(parsedName, ".", "_", -1)
			parsedName = strings.Replace(parsedName, "|", "_", -1)
			parsedName = ValidateParameterName(parsedName)
			param.Value.Name = parsedName
			path.Head.Parameters[counter].Value.Name = parsedName

			curParam := WorkflowAppActionParameter{
				Name:        parsedName,
				Description: param.Value.Description,
				Multiline:   false,
				Required:    param.Value.Required,
				Schema: SchemaDefinition{
					Type: param.Value.Schema.Value.Type,
				},
			}

			// FIXME: Example & Multiline
			if param.Value.Example != nil {
				curParam.Example = param.Value.Example.(string)

				if param.Value.Name == "body" {
					curParam.Value = param.Value.Example.(string)
				}
			}
			if val, ok := param.Value.ExtensionProps.Extensions["multiline"]; ok {
				j, err := json.Marshal(&val)
				if err == nil {
					b, err := strconv.ParseBool(string(j))
					if err == nil {
						curParam.Multiline = b
					}
				}
			}

			if param.Value.Required {
				action.Parameters = append(action.Parameters, curParam)
			} else {
				optionalParameters = append(optionalParameters, curParam)
			}

			if param.Value.In == "path" {
				parameters = append(parameters, curParam.Name)
				//baseUrl = fmt.Sprintf("%s%s", baseUrl)
			} else if param.Value.In == "query" {
				//log.Printf("QUERY!: %s", param.Value.Name)
				if !param.Value.Required {
					optionalQueries = append(optionalQueries, param.Value.Name)
					continue
				}

				parameters = append(parameters, param.Value.Name)

				if strings.Contains(baseUrl, fmt.Sprintf("%s={%s}", param.Value.Name, param.Value.Name)) {
					continue
				}

				if strings.Contains(baseUrl, fmt.Sprintf("{%s}", param.Value.Name)) {
					continue
				}

				//if firstQuery && !strings.Contains(baseUrl, "?") {
				//	baseUrl = fmt.Sprintf("%s?%s={%s}", baseUrl, param.Value.Name, param.Value.Name)
				//} else {
				//	baseUrl = fmt.Sprintf("%s&%s={%s}", baseUrl, param.Value.Name, param.Value.Name)
				//}
				//firstQuery = false
			}
		}
	}

	if len(headersFound) > 0 {
		setIndex := -1
		for paramIndex, param := range optionalParameters {
			if param.Name == "headers" {
				setIndex = paramIndex
				break
			}
		}

		if setIndex >= 0 {
			for _, header := range headersFound {
				if !strings.Contains(header, "=") {
					continue
				}

				headerKey := strings.Split(header, "=")[0]
				if strings.Contains(optionalParameters[setIndex].Value, headerKey) {
					continue
				}

				optionalParameters[setIndex].Value = fmt.Sprintf("%s%s\n", optionalParameters[setIndex].Value, header)
			}

			//log.Printf("What: %#v", optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-1])
			//log.Printf("HI: %s",
			//optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-2])
			// Removing newlines at the end
			if len(optionalParameters[setIndex].Value) > 0 && optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-1] == 0xa {
				optionalParameters[setIndex].Value = optionalParameters[setIndex].Value[0 : len(optionalParameters[setIndex].Value)-1]
			}

			//log.Printf("%#v", optionalParameters[setIndex].Value)
		}
	}

	// Must be here 'cus they should be last
	headerKey := `headers=""`
	if !ArrayContains(parameters, headerKey) {
		parameters = append(parameters, headerKey)
	}

	queryKey := `queries=""`
	if !ArrayContains(parameters, queryKey) {
		parameters = append(parameters, queryKey)
	}

	// ensuring that they end up last in the specification
	// (order is ish important for optional params) - they need to be last.
	for _, optionalParam := range optionalParameters {
		action.Parameters = append(action.Parameters, optionalParam)
	}

	functionname, curCode := MakePythoncode(swagger, functionName, baseUrl, "head", parameters, optionalQueries, headersFound, "", api, handleFile)

	if len(functionname) > 0 {
		action.Name = functionname
	}

	return action, curCode
}

func HandleDelete(swagger *openapi3.Swagger, api WorkflowApp, extraParameters []WorkflowAppActionParameter, path *openapi3.PathItem, actualPath string, optionalParameters []WorkflowAppActionParameter) (WorkflowAppAction, string) {
	// What to do with this, hmm
	functionName := FixFunctionName(path.Delete.Summary, actualPath)

	baseUrl := fmt.Sprintf("%s%s", api.Link, actualPath)
	newDesc := fmt.Sprintf("%s\n\n%s", path.Delete.Description, baseUrl)
	action := WorkflowAppAction{
		Description: newDesc,
		Name:        fmt.Sprintf("%s %s", "Delete", path.Delete.Summary),
		Label:       fmt.Sprintf(path.Delete.Summary),
		NodeType:    "action",
		Environment: api.Environment,
		Parameters:  extraParameters,
	}

	action.Returns.Schema.Type = "string"
	if strings.Contains(baseUrl, "_shuffle_replace_") {
		//log.Printf("[DEBUG] : %s", baseUrl)
		m := regexp.MustCompile(`_shuffle_replace_\d`)
		baseUrl = m.ReplaceAllString(baseUrl, "")
	}
	handleFile := false

	//log.Println(path.Parameters)

	// Parameters:  []WorkflowAppActionParameter{},
	//firstQuery := true
	optionalQueries := []string{}
	parameters := []string{}
	headersFound := []string{}
	if len(path.Delete.Parameters) > 0 {
		for counter, param := range path.Delete.Parameters {
			if param.Value.Schema == nil {
				continue
			} else if param.Value.In == "header" {
				headersFound = append(headersFound, fmt.Sprintf("%s=%s", param.Value.Name, param.Value.Example))
				continue
			}

			parsedName := param.Value.Name
			parsedName = strings.Replace(parsedName, " ", "_", -1)
			parsedName = strings.Replace(parsedName, ",", "_", -1)
			parsedName = strings.Replace(parsedName, ".", "_", -1)
			parsedName = strings.Replace(parsedName, "|", "_", -1)
			parsedName = ValidateParameterName(parsedName)
			param.Value.Name = parsedName
			path.Delete.Parameters[counter].Value.Name = parsedName

			curParam := WorkflowAppActionParameter{
				Name:        parsedName,
				Description: param.Value.Description,
				Multiline:   false,
				Required:    param.Value.Required,
				Schema: SchemaDefinition{
					Type: param.Value.Schema.Value.Type,
				},
			}

			// FIXME: Example & Multiline
			if param.Value.Example != nil {
				curParam.Example = param.Value.Example.(string)

				if param.Value.Name == "body" {
					curParam.Value = param.Value.Example.(string)
				}
			}
			if val, ok := param.Value.ExtensionProps.Extensions["multiline"]; ok {
				j, err := json.Marshal(&val)
				if err == nil {
					b, err := strconv.ParseBool(string(j))
					if err == nil {
						curParam.Multiline = b
					}
				}
			}

			if param.Value.Required {
				action.Parameters = append(action.Parameters, curParam)
			} else {
				optionalParameters = append(optionalParameters, curParam)
			}

			if param.Value.In == "path" {
				parameters = append(parameters, curParam.Name)
				//baseUrl = fmt.Sprintf("%s%s", baseUrl)
			} else if param.Value.In == "query" {
				//log.Printf("QUERY!: %s", param.Value.Name)
				if !param.Value.Required {
					optionalQueries = append(optionalQueries, param.Value.Name)
					continue
				}

				parameters = append(parameters, param.Value.Name)

				if strings.Contains(baseUrl, fmt.Sprintf("%s={%s}", param.Value.Name, param.Value.Name)) {
					continue
				}

				if strings.Contains(baseUrl, fmt.Sprintf("{%s}", param.Value.Name)) {
					continue
				}

				//if firstQuery && !strings.Contains(baseUrl, "?") {
				//	baseUrl = fmt.Sprintf("%s?%s={%s}", baseUrl, param.Value.Name, param.Value.Name)
				//} else {
				//	baseUrl = fmt.Sprintf("%s&%s={%s}", baseUrl, param.Value.Name, param.Value.Name)
				//}
				//firstQuery = false
			}

		}
	}

	if len(headersFound) > 0 {
		setIndex := -1
		for paramIndex, param := range optionalParameters {
			if param.Name == "headers" {
				setIndex = paramIndex
				break
			}
		}

		if setIndex >= 0 {
			for _, header := range headersFound {
				if !strings.Contains(header, "=") {
					continue
				}

				headerKey := strings.Split(header, "=")[0]
				if strings.Contains(optionalParameters[setIndex].Value, headerKey) {
					continue
				}

				optionalParameters[setIndex].Value = fmt.Sprintf("%s%s\n", optionalParameters[setIndex].Value, header)
			}

			//log.Printf("What: %#v", optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-1])
			//log.Printf("HI: %s",
			//optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-2])
			// Removing newlines at the end
			if len(optionalParameters[setIndex].Value) > 0 && optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-1] == 0xa {
				optionalParameters[setIndex].Value = optionalParameters[setIndex].Value[0 : len(optionalParameters[setIndex].Value)-1]
			}

			//log.Printf("%#v", optionalParameters[setIndex].Value)
		}
	}

	// Must be here 'cus they should be last
	headerKey := `headers=""`
	if !ArrayContains(parameters, headerKey) {
		parameters = append(parameters, headerKey)
	}

	queryKey := `queries=""`
	if !ArrayContains(parameters, queryKey) {
		parameters = append(parameters, queryKey)
	}

	// ensuring that they end up last in the specification
	// (order is ish important for optional params) - they need to be last.
	for _, optionalParam := range optionalParameters {
		action.Parameters = append(action.Parameters, optionalParam)
	}

	functionname, curCode := MakePythoncode(swagger, functionName, baseUrl, "delete", parameters, optionalQueries, headersFound, "", api, handleFile)

	if len(functionname) > 0 {
		action.Name = functionname
	}

	return action, curCode
}

func HandlePost(swagger *openapi3.Swagger, api WorkflowApp, extraParameters []WorkflowAppActionParameter, path *openapi3.PathItem, actualPath string, optionalParameters []WorkflowAppActionParameter) (WorkflowAppAction, string) {
	// What to do with this, hmm
	//log.Printf("PATH: %s", actualPath)
	functionName := FixFunctionName(path.Post.Summary, actualPath)

	baseUrl := fmt.Sprintf("%s%s", api.Link, actualPath)
	newDesc := fmt.Sprintf("%s\n\n%s", path.Post.Description, baseUrl)
	action := WorkflowAppAction{
		Description: newDesc,
		Name:        fmt.Sprintf("%s %s", "Post", path.Post.Summary),
		Label:       fmt.Sprintf(path.Post.Summary),
		NodeType:    "action",
		Environment: api.Environment,
		Parameters:  extraParameters,
	}

	action.Returns.Schema.Type = "string"
	if strings.Contains(baseUrl, "_shuffle_replace_") {
		//log.Printf("[DEBUG] : %s", baseUrl)
		m := regexp.MustCompile(`_shuffle_replace_\d`)
		baseUrl = m.ReplaceAllString(baseUrl, "")
	}
	handleFile := false

	// Parameters:  []WorkflowAppActionParameter{},
	// FIXME - add data for POST stuff
	//firstQuery := true
	optionalQueries := []string{}
	parameters := []string{}

	fileField := ""
	if path.Post.RequestBody != nil {
		value := path.Post.RequestBody.Value
		if val, ok := value.Content["multipart/form-data"]; ok {
			if val.Schema.Value != nil {
				if innerval, ok := val.Schema.Value.Properties["fieldname"]; ok {
					if extensionvalue, ok := innerval.Value.ExtensionProps.Extensions["value"]; ok {
						fieldname := extensionvalue.(json.RawMessage)
						newName := string(fmt.Sprintf("%s", string(fieldname)))
						if newName[0] == 0x22 && newName[len(newName)-1] == 0x22 {
							parsedName := newName[1 : len(newName)-1]
							//log.Printf("Parse name: %s", parsedName)
							fileField = parsedName

							curParam := WorkflowAppActionParameter{
								Name:        "file_id",
								Description: "Files to be uploaded",
								Multiline:   false,
								Required:    true,
								Schema: SchemaDefinition{
									Type: "string",
								},
							}

							action.Parameters = append(action.Parameters, curParam)
						}
					}
				}
			}
		}
	}

	headersFound := []string{}
	if len(path.Post.Parameters) > 0 {
		for counter, param := range path.Post.Parameters {
			if param.Value.Schema == nil {
				continue
			} else if param.Value.In == "header" {
				headersFound = append(headersFound, fmt.Sprintf("%s=%s", param.Value.Name, param.Value.Example))
				continue
			}

			parsedName := param.Value.Name
			parsedName = strings.Replace(parsedName, " ", "_", -1)
			parsedName = strings.Replace(parsedName, ",", "_", -1)
			parsedName = strings.Replace(parsedName, ".", "_", -1)
			parsedName = strings.Replace(parsedName, "|", "_", -1)
			parsedName = ValidateParameterName(parsedName)
			param.Value.Name = parsedName
			path.Post.Parameters[counter].Value.Name = parsedName

			curParam := WorkflowAppActionParameter{
				Name:        parsedName,
				Description: param.Value.Description,
				Multiline:   false,
				Required:    param.Value.Required,
				Schema: SchemaDefinition{
					Type: param.Value.Schema.Value.Type,
				},
			}

			// FIXME: Example & Multiline
			if param.Value.Example != nil {
				curParam.Example = param.Value.Example.(string)

				if parsedName == "body" {
					curParam.Value = param.Value.Example.(string)
				}
			}
			if val, ok := param.Value.ExtensionProps.Extensions["multiline"]; ok {
				j, err := json.Marshal(&val)
				if err == nil {
					b, err := strconv.ParseBool(string(j))
					if err == nil {
						curParam.Multiline = b
					}
				}
			}

			if param.Value.Required {
				action.Parameters = append(action.Parameters, curParam)
			} else {
				optionalParameters = append(optionalParameters, curParam)
			}

			if param.Value.In == "path" {
				parameters = append(parameters, curParam.Name)
				//baseUrl = fmt.Sprintf("%s%s", baseUrl)
			} else if param.Value.In == "query" {
				//log.Printf("QUERY!: %s", param.Value.Name)
				if !param.Value.Required {
					optionalQueries = append(optionalQueries, param.Value.Name)
					continue
				}

				parameters = append(parameters, param.Value.Name)

				if strings.Contains(baseUrl, fmt.Sprintf("%s={%s}", param.Value.Name, param.Value.Name)) {
					continue
				}

				if strings.Contains(baseUrl, fmt.Sprintf("{%s}", param.Value.Name)) {
					continue
				}

				//if firstQuery && !strings.Contains(baseUrl, "?") {
				//	baseUrl = fmt.Sprintf("%s?%s={%s}", baseUrl, param.Value.Name, param.Value.Name)
				//} else {
				//	baseUrl = fmt.Sprintf("%s&%s={%s}", baseUrl, param.Value.Name, param.Value.Name)
				//}
				//firstQuery = false
			}
		}
	}

	if len(headersFound) > 0 {
		setIndex := -1
		for paramIndex, param := range optionalParameters {
			if param.Name == "headers" {
				setIndex = paramIndex
				break
			}
		}

		if setIndex >= 0 {
			for _, header := range headersFound {
				if !strings.Contains(header, "=") {
					continue
				}

				headerKey := strings.Split(header, "=")[0]
				if strings.Contains(optionalParameters[setIndex].Value, headerKey) {
					continue
				}

				optionalParameters[setIndex].Value = fmt.Sprintf("%s%s\n", optionalParameters[setIndex].Value, header)
			}

			//log.Printf("What: %#v", optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-1])
			//log.Printf("HI: %s",
			//optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-2])
			// Removing newlines at the end
			if len(optionalParameters[setIndex].Value) > 0 && optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-1] == 0xa {
				optionalParameters[setIndex].Value = optionalParameters[setIndex].Value[0 : len(optionalParameters[setIndex].Value)-1]
			}

			//log.Printf("%#v", optionalParameters[setIndex].Value)
		}
	}

	// Must be here 'cus they should be last
	headerKey := `headers=""`
	if !ArrayContains(parameters, headerKey) {
		parameters = append(parameters, headerKey)
	}

	queryKey := `queries=""`
	if !ArrayContains(parameters, queryKey) {
		parameters = append(parameters, queryKey)
	}

	// ensuring that they end up last in the specification
	// (order is ish important for optional params) - they need to be last.
	for _, optionalParam := range optionalParameters {
		action.Parameters = append(action.Parameters, optionalParam)
	}

	functionname, curCode := MakePythoncode(swagger, functionName, baseUrl, "post", parameters, optionalQueries, headersFound, fileField, api, handleFile)

	if len(functionname) > 0 {
		action.Name = functionname
	}

	//log.Printf("PARAMS: %d", len(action.Parameters))
	//for _, param := range action.Parameters {
	//	log.Printf("%#v", param)
	//}

	return action, curCode
}

func HandlePatch(swagger *openapi3.Swagger, api WorkflowApp, extraParameters []WorkflowAppActionParameter, path *openapi3.PathItem, actualPath string, optionalParameters []WorkflowAppActionParameter) (WorkflowAppAction, string) {
	// What to do with this, hmm
	functionName := FixFunctionName(path.Patch.Summary, actualPath)

	baseUrl := fmt.Sprintf("%s%s", api.Link, actualPath)
	newDesc := fmt.Sprintf("%s\n\n%s", path.Patch.Description, baseUrl)
	action := WorkflowAppAction{
		Description: newDesc,
		Name:        fmt.Sprintf("%s %s", "Patch", path.Patch.Summary),
		Label:       fmt.Sprintf(path.Patch.Summary),
		NodeType:    "action",
		Environment: api.Environment,
		Parameters:  extraParameters,
	}

	action.Returns.Schema.Type = "string"
	if strings.Contains(baseUrl, "_shuffle_replace_") {
		//log.Printf("[DEBUG] : %s", baseUrl)
		m := regexp.MustCompile(`_shuffle_replace_\d`)
		baseUrl = m.ReplaceAllString(baseUrl, "")
	}
	handleFile := false

	//log.Println(path.Parameters)

	// Parameters:  []WorkflowAppActionParameter{},
	//firstQuery := true
	optionalQueries := []string{}
	parameters := []string{}

	headersFound := []string{}
	if len(path.Patch.Parameters) > 0 {
		for counter, param := range path.Patch.Parameters {
			if param.Value.Schema == nil {
				continue
			} else if param.Value.In == "header" {
				headersFound = append(headersFound, fmt.Sprintf("%s=%s", param.Value.Name, param.Value.Example))
				continue
			}

			parsedName := param.Value.Name
			parsedName = strings.Replace(parsedName, " ", "_", -1)
			parsedName = strings.Replace(parsedName, ",", "_", -1)
			parsedName = strings.Replace(parsedName, ".", "_", -1)
			parsedName = strings.Replace(parsedName, "|", "_", -1)
			parsedName = ValidateParameterName(parsedName)
			param.Value.Name = parsedName
			path.Patch.Parameters[counter].Value.Name = parsedName

			curParam := WorkflowAppActionParameter{
				Name:        parsedName,
				Description: param.Value.Description,
				Multiline:   false,
				Required:    param.Value.Required,
				Schema: SchemaDefinition{
					Type: param.Value.Schema.Value.Type,
				},
			}

			// FIXME: Example & Multiline
			if param.Value.Example != nil {
				curParam.Example = param.Value.Example.(string)

				if param.Value.Name == "body" {
					curParam.Value = param.Value.Example.(string)
				}
			}
			if val, ok := param.Value.ExtensionProps.Extensions["multiline"]; ok {
				j, err := json.Marshal(&val)
				if err == nil {
					b, err := strconv.ParseBool(string(j))
					if err == nil {
						curParam.Multiline = b
					}
				}
			}

			if param.Value.Required {
				action.Parameters = append(action.Parameters, curParam)
			} else {
				optionalParameters = append(optionalParameters, curParam)
			}

			if param.Value.In == "path" {
				parameters = append(parameters, curParam.Name)
				//baseUrl = fmt.Sprintf("%s%s", baseUrl)
			} else if param.Value.In == "query" {
				//log.Printf("QUERY!: %s", param.Value.Name)
				if !param.Value.Required {
					optionalQueries = append(optionalQueries, param.Value.Name)
					continue
				}

				parameters = append(parameters, param.Value.Name)

				if strings.Contains(baseUrl, fmt.Sprintf("%s={%s}", param.Value.Name, param.Value.Name)) {
					continue
				}

				if strings.Contains(baseUrl, fmt.Sprintf("{%s}", param.Value.Name)) {
					continue
				}

				//if firstQuery && !strings.Contains(baseUrl, "?") {
				//	baseUrl = fmt.Sprintf("%s?%s={%s}", baseUrl, param.Value.Name, param.Value.Name)
				//} else {
				//	baseUrl = fmt.Sprintf("%s&%s={%s}", baseUrl, param.Value.Name, param.Value.Name)
				//}
				//firstQuery = false
			}
		}
	}

	if len(headersFound) > 0 {
		setIndex := -1
		for paramIndex, param := range optionalParameters {
			if param.Name == "headers" {
				setIndex = paramIndex
				break
			}
		}

		if setIndex >= 0 {
			for _, header := range headersFound {
				if !strings.Contains(header, "=") {
					continue
				}

				headerKey := strings.Split(header, "=")[0]
				if strings.Contains(optionalParameters[setIndex].Value, headerKey) {
					continue
				}

				optionalParameters[setIndex].Value = fmt.Sprintf("%s%s\n", optionalParameters[setIndex].Value, header)
			}

			//log.Printf("What: %#v", optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-1])
			//log.Printf("HI: %s",
			//optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-2])
			// Removing newlines at the end
			if len(optionalParameters[setIndex].Value) > 0 && optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-1] == 0xa {
				optionalParameters[setIndex].Value = optionalParameters[setIndex].Value[0 : len(optionalParameters[setIndex].Value)-1]
			}

			//log.Printf("%#v", optionalParameters[setIndex].Value)
		}
	}

	// Must be here 'cus they should be last
	headerKey := `headers=""`
	if !ArrayContains(parameters, headerKey) {
		parameters = append(parameters, headerKey)
	}

	queryKey := `queries=""`
	if !ArrayContains(parameters, queryKey) {
		parameters = append(parameters, queryKey)
	}

	// ensuring that they end up last in the specification
	// (order is ish important for optional params) - they need to be last.
	for _, optionalParam := range optionalParameters {
		action.Parameters = append(action.Parameters, optionalParam)
	}

	functionname, curCode := MakePythoncode(swagger, functionName, baseUrl, "patch", parameters, optionalQueries, headersFound, "", api, handleFile)

	if len(functionname) > 0 {
		action.Name = functionname
	}

	return action, curCode
}

func HandlePut(swagger *openapi3.Swagger, api WorkflowApp, extraParameters []WorkflowAppActionParameter, path *openapi3.PathItem, actualPath string, optionalParameters []WorkflowAppActionParameter) (WorkflowAppAction, string) {
	// What to do with this, hmm
	functionName := FixFunctionName(path.Put.Summary, actualPath)

	baseUrl := fmt.Sprintf("%s%s", api.Link, actualPath)
	newDesc := fmt.Sprintf("%s\n\n%s", path.Put.Description, baseUrl)
	action := WorkflowAppAction{
		Description: newDesc,
		Name:        fmt.Sprintf("%s %s", "Put", path.Put.Summary),
		Label:       fmt.Sprintf(path.Put.Summary),
		NodeType:    "action",
		Environment: api.Environment,
		Parameters:  extraParameters,
	}

	action.Returns.Schema.Type = "string"
	if strings.Contains(baseUrl, "_shuffle_replace_") {
		//log.Printf("[DEBUG] : %s", baseUrl)
		m := regexp.MustCompile(`_shuffle_replace_\d`)
		baseUrl = m.ReplaceAllString(baseUrl, "")
	}
	handleFile := false

	//log.Println(path.Parameters)

	// Parameters:  []WorkflowAppActionParameter{},
	//firstQuery := true
	optionalQueries := []string{}
	parameters := []string{}

	headersFound := []string{}
	if len(path.Put.Parameters) > 0 {
		for counter, param := range path.Put.Parameters {
			if param.Value.Schema == nil {
				continue
			} else if param.Value.In == "header" {
				headersFound = append(headersFound, fmt.Sprintf("%s=%s", param.Value.Name, param.Value.Example))
				continue
			}

			parsedName := param.Value.Name
			parsedName = strings.Replace(parsedName, " ", "_", -1)
			parsedName = strings.Replace(parsedName, ",", "_", -1)
			parsedName = strings.Replace(parsedName, ".", "_", -1)
			parsedName = strings.Replace(parsedName, "|", "_", -1)
			parsedName = ValidateParameterName(parsedName)
			param.Value.Name = parsedName
			path.Put.Parameters[counter].Value.Name = parsedName

			curParam := WorkflowAppActionParameter{
				Name:        parsedName,
				Description: param.Value.Description,
				Multiline:   false,
				Required:    param.Value.Required,
				Schema: SchemaDefinition{
					Type: param.Value.Schema.Value.Type,
				},
			}

			// FIXME: Example & Multiline
			if param.Value.Example != nil {
				curParam.Example = param.Value.Example.(string)

				if param.Value.Name == "body" {
					curParam.Value = param.Value.Example.(string)
				}
			}
			if val, ok := param.Value.ExtensionProps.Extensions["multiline"]; ok {
				j, err := json.Marshal(&val)
				if err == nil {
					b, err := strconv.ParseBool(string(j))
					if err == nil {
						curParam.Multiline = b
					}
				}
			}

			if param.Value.Required {
				action.Parameters = append(action.Parameters, curParam)
			} else {
				optionalParameters = append(optionalParameters, curParam)
			}

			if param.Value.In == "path" {
				parameters = append(parameters, param.Value.Name)
				//baseUrl = fmt.Sprintf("%s%s", baseUrl)
			} else if param.Value.In == "query" {
				//log.Printf("QUERY!: %s", param.Value.Name)
				if !param.Value.Required {
					optionalQueries = append(optionalQueries, param.Value.Name)
					continue
				}

				parameters = append(parameters, param.Value.Name)

				if strings.Contains(baseUrl, fmt.Sprintf("%s={%s}", param.Value.Name, param.Value.Name)) {
					continue
				}

				if strings.Contains(baseUrl, fmt.Sprintf("{%s}", param.Value.Name)) {
					continue
				}

				//if firstQuery && !strings.Contains(baseUrl, "?") {
				//	baseUrl = fmt.Sprintf("%s?%s={%s}", baseUrl, param.Value.Name, param.Value.Name)
				//} else {
				//	baseUrl = fmt.Sprintf("%s&%s={%s}", baseUrl, param.Value.Name, param.Value.Name)
				//}
				//firstQuery = false
			}

		}
	}

	if len(headersFound) > 0 {
		setIndex := -1
		for paramIndex, param := range optionalParameters {
			if param.Name == "headers" {
				setIndex = paramIndex
				break
			}
		}

		if setIndex >= 0 {
			for _, header := range headersFound {
				if !strings.Contains(header, "=") {
					continue
				}

				headerKey := strings.Split(header, "=")[0]
				if strings.Contains(optionalParameters[setIndex].Value, headerKey) {
					continue
				}

				optionalParameters[setIndex].Value = fmt.Sprintf("%s%s\n", optionalParameters[setIndex].Value, header)
			}

			//log.Printf("What: %#v", optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-1])
			//log.Printf("HI: %s",
			//optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-2])
			// Removing newlines at the end
			if len(optionalParameters[setIndex].Value) > 0 && optionalParameters[setIndex].Value[len(optionalParameters[setIndex].Value)-1] == 0xa {
				optionalParameters[setIndex].Value = optionalParameters[setIndex].Value[0 : len(optionalParameters[setIndex].Value)-1]
			}

			//log.Printf("%#v", optionalParameters[setIndex].Value)
		}
	}

	// Must be here 'cus they should be last
	headerKey := `headers=""`
	if !ArrayContains(parameters, headerKey) {
		parameters = append(parameters, headerKey)
	}

	queryKey := `queries=""`
	if !ArrayContains(parameters, queryKey) {
		parameters = append(parameters, queryKey)
	}

	// ensuring that they end up last in the specification
	// (order is ish important for optional params) - they need to be last.
	for _, optionalParam := range optionalParameters {
		action.Parameters = append(action.Parameters, optionalParam)
	}

	functionname, curCode := MakePythoncode(swagger, functionName, baseUrl, "put", parameters, optionalQueries, headersFound, "", api, handleFile)

	if len(functionname) > 0 {
		action.Name = functionname
	}

	return action, curCode
}
