package shuffle

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	_ "encoding/base32"
	_ "encoding/base64"
	_ "encoding/binary"
	_ "encoding/hex"
	"encoding/json"
	_ "encoding/xml"

	_ "crypto/aes"
	_ "crypto/cipher"
	_ "crypto/hmac"
	_ "crypto/md5"
	_ "crypto/rand"
	_ "crypto/sha1"

	_ "github.com/bradfitz/slice"
	_ "github.com/skip2/go-qrcode"

	_ "github.com/frikky/kin-openapi/openapi2"
	_ "github.com/frikky/kin-openapi/openapi2conv"
	_ "github.com/frikky/kin-openapi/openapi3"

	_ "github.com/satori/go.uuid"
	_ "google.golang.org/appengine"
)

func GetOpenapi(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just here to verify that the user is logged in
	_, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in validate swagger: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")
	var id string
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("Missing parts of API in request!")
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		id = location[4]
	}

	/*
		if len(id) != 32 {
			log.Printf("Missing parts of API in request!")
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	*/
	//_, err = GetApp(ctx, id)
	//if err == nil {
	//	log.Println("You're supposed to be able to continue now.")
	//}

	// FIXME - FIX AUTH WITH APP
	ctx := GetContext(request)
	parsedApi, err := GetOpenApiDatastore(ctx, id)
	if err != nil {
		log.Printf("[ERROR] Failed getting OpenAPI: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	log.Printf("[INFO] API LENGTH GET: %d, ID: %s", len(parsedApi.Body), id)

	parsedApi.Success = true
	data, err := json.Marshal(parsedApi)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshaling OpenAPI: %s", err)
		resp.WriteHeader(422)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed marshalling parsed swagger: %s"}`, err)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(data)
}

func EchoOpenapiData(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just here to verify that the user is logged in
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[DEBUG] Api authentication failed in download Yaml echo: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to echo OpenAPI data: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Bodyreader err: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	newbody := string(body)
	newbody = strings.TrimSpace(newbody)
	if strings.HasPrefix(newbody, "\"") {
		newbody = newbody[1:len(newbody)]
	}

	if strings.HasSuffix(newbody, "\"") {
		newbody = newbody[0 : len(newbody)-1]
	}

	// Rewrite to download proper one from Github even without raw path
	if strings.Contains(newbody, "https://github.com/") {
		// https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml
		// https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/openapi/openapi.yaml
		// https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/openapi/openapi.yaml

		urlsplit := strings.Split(newbody, "/")
		if len(urlsplit) > 6 {
			log.Printf("[DEBUG] Rewriting github URL %s.", newbody)
			ghuser := urlsplit[3]
			repo := urlsplit[4]
			branch := urlsplit[6]
			path := strings.Join(urlsplit[7:len(urlsplit)], "/")
			newbody = fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", ghuser, repo, branch, path)
		}
	}

	log.Printf("[DEBUG] Downloading content from %s", newbody)

	req, err := http.NewRequest("GET", newbody, nil)
	if err != nil {
		log.Printf("[ERROR] Requestbuilder err: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed building request"}`))
		return
	}

	httpClient := &http.Client{}
	newresp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("[ERROR] Grabbing error: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed making remote request to get the data"}`)))
		return
	}
	defer newresp.Body.Close()

	urlbody, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		log.Printf("[ERROR] URLbody error: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't get data from selected uri"}`)))
		return
	}

	if newresp.StatusCode >= 400 {
		resp.WriteHeader(201)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, urlbody)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(urlbody)
}
