package shuffle


import (
	// "bytes"
	// "context"
	// "errors"
	"fmt"
	// "gopkg.in/yaml.v3"
	// "io"
	"io/ioutil"
	"log"
	"net/http"
	// "net/url"
	// "os"
	// "os/exec"
	// "regexp"
	// "strconv"
	// "strings"
	// "time"

	// "encoding/base32"
	// "encoding/base64"
	// "encoding/binary"
	// "encoding/hex"
	"encoding/json"
	// "encoding/xml"

	// "crypto/aes"
	// "crypto/cipher"
	// "crypto/hmac"
	// "crypto/md5"
	// "crypto/rand"
	// "crypto/sha1"

	// "github.com/bradfitz/slice"
	// qrcode "github.com/skip2/go-qrcode"

	// "github.com/frikky/kin-openapi/openapi2"
	// "github.com/frikky/kin-openapi/openapi2conv"
	// "github.com/frikky/kin-openapi/openapi3"

	// "github.com/google/go-github/v28/github"
	"github.com/satori/go.uuid"
	// "golang.org/x/crypto/bcrypt"
	// "google.golang.org/appengine"
)

func HandleSetEnvironments(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// FIXME: Overhaul the top part.
	// Only admin can change environments, but if there are no users, anyone can make (first)
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't handle set env auth"}`))
		return
	}

	if user.Role != "admin" {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't set environment without being admin"}`))
		return
	}

	ctx := GetContext(request)
	environments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Println("[WARNING] Failed getting environments: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't get environments when setting"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Println("[WARNING] Failed reading environment body: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to read data"}`)))
		return
	}

	var newEnvironments []Environment
	err = json.Unmarshal(body, &newEnvironments)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshaling: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to unmarshal data"}`)))
		return
	}

	log.Printf("[WARNING] Got %d new environments to be added", len(newEnvironments))

	if len(newEnvironments) < 1 {
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "One environment is required"}`)))
		return
	}

	if project.Environment == "cloud" {
		//foundOrg, err := GetOrg(ctx, user.ActiveOrg.Id)
		//if err != nil {
		//	resp.WriteHeader(401)
		//	resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed find your organization"}`)))
		//	return
		//}

		// FIXME: Removed need for syncfeatures to be enabled
		// September 2022
		//_ = foundOrg

		//if !foundOrg.SyncFeatures.MultiEnv.Active {
		//	resp.WriteHeader(401)
		//	resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Adding multiple environments requires an active hybrid, enterprise or MSSP subscription"}`)))
		//	return
		//}
	}

	// Validate input here
	defaults := 0
	parsedEnvs := []Environment{}
	for _, env := range newEnvironments {
		if env.Type == "cloud" && env.Archived {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Can't disable cloud environments"}`))
			return
		}

		if env.Default && env.Archived {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Can't disable default environment"}`))
			return
		}

		//if project.Environment == "cloud" && env.Type != "cloud" && len(env.Name) < 10 {
		//	log.Printf("[ERROR] Skipping env %s because length is shorter than 10", env.Name)
		//	continue
		//}

		if defaults > 0 {
			env.Default = false
		}

		if env.Default {
			defaults += 1
		}

		parsedEnvs = append(parsedEnvs, env)
	}

	newEnvironments = parsedEnvs

	openEnvironments := 0
	for _, item := range newEnvironments {
		if !item.Archived {
			openEnvironments += 1
		}
	}

	if openEnvironments < 1 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't archive all environments. Not deleting."}`))
		return
	}

	// Clear old data? Removed for archiving purpose. No straight deletion
	log.Printf("[INFO] Deleting %d original environments before resetting. To be added: %d!", len(environments), len(newEnvironments))
	nameKey := "Environments"
	for _, item := range environments {
		DeleteKey(ctx, nameKey, item.Id)
		DeleteKey(ctx, nameKey, item.Name)
	}

	for _, item := range newEnvironments {
		for _, subenv := range environments {
			if item.Name == subenv.Name || item.Id == subenv.Id {
				item.Auth = subenv.Auth
				break
			}
		}

		item.RunningIp = ""
		if item.OrgId != user.ActiveOrg.Id {
			item.OrgId = user.ActiveOrg.Id
		}

		if len(item.Id) == 0 {
			item.Id = uuid.NewV4().String()
		}

		if len(item.Auth) == 0 {
			item.Auth = uuid.NewV4().String()
		}

		err = SetEnvironment(ctx, &item)
		if err != nil {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed setting environment variable"}`))
			return
		}
	}

	cacheKey := fmt.Sprintf("Environments_%s", user.ActiveOrg.Id)
	DeleteCache(ctx, cacheKey)

	log.Printf("[INFO] Set %d new environments for org %s", len(newEnvironments), user.ActiveOrg.Id)

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleGetEnvironments(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get environments: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := GetContext(request)
	environments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Failed getting environments")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't get environments"}`))
		return
	}

	// Always make Cloud the default environment
	// If there are multiple
	if project.Environment == "cloud" {
		defaults := []int{}
		for envIndex, environment := range environments {
			if environment.Default {
				defaults = append(defaults, envIndex)
			}
		}

		if len(defaults) > 1 {
			for _, index := range defaults {
				if environments[index].Name == "Cloud" {
					continue
				} else {
					environments[index].Default = false
				}
			}
		}

	}

	newEnvironments := []Environment{}
	for _, environment := range environments {
		if len(environment.Id) == 0 {
			environment.Id = uuid.NewV4().String()
		}

		found := false
		for _, oldEnv := range newEnvironments {
			if oldEnv.Name == environment.Name {
				found = true
			}
		}

		if !found {
			newEnvironments = append(newEnvironments, environment)
		}
	}

	newjson, err := json.Marshal(newEnvironments)
	if err != nil {
		log.Printf("Failed unmarshal: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking environments"}`)))
		return
	}

	//log.Printf("Existing environments: %s", string(newjson))

	resp.WriteHeader(200)
	resp.Write(newjson)
}