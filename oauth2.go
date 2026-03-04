package shuffle

// Shuffle is an automation platform for security and IT. This app and the associated scopes enables us to get information about a user, their mailbox and eventually subscribing them to send pub/sub requests to our platform to handle their emails in real-time, before controlling how to handle the data themselves.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"

	//"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/go-querystring/query"
	"golang.org/x/oauth2"

	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

var handledIds []string

/*
func fetchUserInfoFromToken(ctx context.Context, accessToken string, issuer string, openIdAuthUrl string) (map[string]interface{}, error) {
	// Get well-known config to find userinfo endpoint
	config, err := fetchWellKnownConfig(ctx, issuer, openIdAuthUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to get OIDC config: %w", err)
	}

	// Get userinfo endpoint
	userinfoEndpoint, ok := config["userinfo_endpoint"].(string)
	if !ok {
		return nil, fmt.Errorf("no userinfo_endpoint in OIDC config")
	}

	// Handle Microsoft Azure AD userinfo endpoint issues
	if strings.Contains(userinfoEndpoint, "login.microsoftonline.com") {
		userinfoEndpoint = "https://graph.microsoft.com/v1.0/me"
		log.Printf("Using Microsoft Graph /me endpoint instead of: %s", userinfoEndpoint)
	}

	// Call userinfo/me endpoint with access token
	req, err := http.NewRequest("GET", userinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}

	if len(accessToken) == 0 {
		return nil, fmt.Errorf("access token is empty")
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call userinfo endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse userinfo response
	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode userinfo response: %w", err)
	}

	// Normalize Microsoft Graph fields to standard OIDC fields
	if mail, ok := userInfo["mail"].(string); ok && userInfo["email"] == nil {
		userInfo["email"] = mail
	}
	if displayName, ok := userInfo["displayName"].(string); ok && userInfo["name"] == nil {
		userInfo["name"] = displayName
	}
	if id, ok := userInfo["id"].(string); ok && userInfo["sub"] == nil {
		userInfo["sub"] = id
	}

	return userInfo, nil
}
*/

func GetOutlookAttachmentList(client *http.Client, emailId string) (MailDataOutlookList, error) {
	requestUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/me/messages/%s/attachments", emailId)
	//log.Printf("Outlook email URL: %#v", requestUrl)

	ret, err := client.Get(requestUrl)
	if err != nil {
		log.Printf("[INFO] OutlookErr: %s", err)
		return MailDataOutlookList{}, err
	}

	body, err := ioutil.ReadAll(ret.Body)
	if err != nil {
		log.Printf("[WARNING] Failed body decoding from outlook email")
		return MailDataOutlookList{}, err
	}

	//type FullEmail struct {
	//log.Printf("[INFO] Attachment List Body: %s", string(body))
	//log.Printf("[INFO] Status email: %d", ret.StatusCode)
	if ret.StatusCode != 200 {
		return MailDataOutlookList{}, err
	}

	var list MailDataOutlookList
	err = json.Unmarshal(body, &list)
	if err != nil {
		log.Printf("[INFO] Email unmarshal error: %s", err)
		return MailDataOutlookList{}, err
	}

	return list, nil
}

func GetOutlookAttachment(client *http.Client, emailId, attachmentId string) (OutlookAttachment, []byte, error) {
	//requestUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/ec03b4f2-fccf-4c35-b0eb-be85a0f5dd43/mailFolders")

	requestUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/me/messages/%s/attachments/%s", emailId, attachmentId)
	//log.Printf("Outlook email URL: %#v", requestUrl)
	body := []byte{}

	ret, err := client.Get(requestUrl)
	if err != nil {
		log.Printf("[INFO] OutlookErr: %s", err)
		return OutlookAttachment{}, body, err
	}

	body, err = ioutil.ReadAll(ret.Body)
	if err != nil {
		log.Printf("[WARNING] Failed body decoding from outlook email")
		return OutlookAttachment{}, body, err
	}

	//type FullEmail struct {
	//log.Printf("[INFO] Attachment Body (1): %s", string(body))
	//log.Printf("[INFO] Status email (1): %d", ret.StatusCode)
	if ret.StatusCode != 200 {
		return OutlookAttachment{}, body, err
	}

	// Gets the data
	var attachment OutlookAttachment
	err = json.Unmarshal(body, &attachment)
	if err != nil {
		log.Printf("[INFO] Email unmarshal error: %s", err)
		return OutlookAttachment{}, body, err
	}

	requestUrl = fmt.Sprintf("https://graph.microsoft.com/v1.0/me/messages/%s/attachments/%s/$value", emailId, attachmentId)
	//log.Printf("Outlook email URL: %#v", requestUrl)

	ret, err = client.Get(requestUrl)
	if err != nil {
		log.Printf("[INFO] OutlookErr: %s", err)
		return OutlookAttachment{}, body, err
	}

	body, err = ioutil.ReadAll(ret.Body)
	if err != nil {
		log.Printf("[WARNING] Failed body decoding from outlook email")
		return OutlookAttachment{}, body, err
	}

	//type FullEmail struct {
	//log.Printf("[INFO] Attachment Body (2): %s", string(body))
	//log.Printf("[INFO] Status email (2): %d", ret.StatusCode)
	if ret.StatusCode != 200 {
		return OutlookAttachment{}, body, err
	}

	return attachment, body, nil
}

func GetOutlookEmail(client *http.Client, maildata MailDataOutlook) ([]FullEmail, error) {
	//requestUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/ec03b4f2-fccf-4c35-b0eb-be85a0f5dd43/mailFolders")

	emails := []FullEmail{}
	for _, email := range maildata.Value {
		//messageId := email.Resourcedata.ID
		//requestUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/me/%s", messageId)
		requestUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/%s", email.Resource)
		//log.Printf("Outlook email URL: %#v", requestUrl)

		ret, err := client.Get(requestUrl)
		if err != nil {
			log.Printf("[INFO] OutlookErr: %s", err)
			return []FullEmail{}, err
		}

		body, err := ioutil.ReadAll(ret.Body)
		if err != nil {
			log.Printf("[WARNING] Failed body decoding from outlook email")
			return []FullEmail{}, err
		}

		//type FullEmail struct {
		//log.Printf("[INFO] EMAIL Body: %s", string(body))
		//log.Printf("[INFO] Status email: %d", ret.StatusCode)
		if ret.StatusCode != 200 {
			return []FullEmail{}, err
		}

		//log.Printf("Body: %s", string(body))

		parsedmail := FullEmail{}
		err = json.Unmarshal(body, &parsedmail)
		if err != nil {
			log.Printf("[INFO] Email unmarshal error: %s", err)
			return []FullEmail{}, err
		}

		emails = append(emails, parsedmail)
	}

	return emails, nil
}

// FIXME:
// 1. Should find contributions to Shuffle repo's for the user
// 2. Should save tokens to continuously check this
func HandleNewGithubRegister(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[INFO] Api authentication failed in setting gmail: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Error with body read in github auth: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	log.Printf("BODY: %s", string(body))
	type GithubAuth struct {
		User string `json:"user"`
		Type string `json:"github"`
		Code string `json:"code"`
	}

	var authInfo GithubAuth
	err = json.Unmarshal(body, &authInfo)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling (githubauth): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Bad data received"}`))
		return
	}

	if authInfo.User != user.Id {
		log.Printf("[WARNING] Bad user - not matching with auth: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Bad user ID - not matching"}`))
		return
	}

	ctx := GetContext(request)
	url := fmt.Sprintf("http://%s%s/set_authentication", request.Host, request.URL.EscapedPath())
	if project.Environment == "cloud" && os.Getenv("CLOUD_ENVIRONMENT") != "local" {
		url = fmt.Sprintf("https://%s%s/set_authentication", request.Host, request.URL.EscapedPath())
	}

	log.Printf("URI: %s", url)

	client, accessToken, err := GetGithubClient(ctx, authInfo.Code, OauthToken{}, url)
	if err != nil {
		log.Printf("[WARNING] Failed setting up github client for %s (%s): %s", user.Username, user.Id, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ghuser, err := GetGithubProfile(ctx, client)
	if err != nil {
		log.Printf("[WARNING] Failed setting github profile for %s (%s): %s", user.Username, user.Id, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	user.PublicProfile.Public = true
	user.PublicProfile.GithubUsername = ghuser.Login
	user.PublicProfile.GithubUserid = strconv.Itoa(ghuser.ID)
	user.PublicProfile.GithubAvatar = ghuser.AvatarURL

	if len(user.PublicProfile.GithubAvatar) == 0 {
		user.PublicProfile.GithubAvatar = ghuser.AvatarURL
	}

	user.PublicProfile.GithubLocation = ghuser.Location
	user.PublicProfile.GithubUrl = ghuser.Blog
	user.PublicProfile.GithubBio = ghuser.Bio
	user.PublicProfile.GithubTwitter = ghuser.TwitterUsername

	//GET /repos/{owner}/{repo}/contributors
	repositories := map[string]string{
		"frikky/shuffle":           "core",
		"frikky/shuffle-shared":    "core",
		"shuffle/shuffle-docs":     "docs",
		"shuffle/shuffle-apps":     "apps",
		"shuffle/openapi-apps":     "apps",
		"shuffle/shuffle-usecases": "workflows",
	}

	// Reset
	user.PublicProfile.GithubContributions = GithubContributions{}
	for repo, repoType := range repositories {
		contributors, err := GetGithubRepoContributors(ctx, client, repo)
		if err != nil {
			log.Printf("[ERROR] Failed getting user repo contributions for %s", user.Username)
			continue
		}

		for _, contributor := range contributors {
			if contributor.Login == user.PublicProfile.GithubUsername {
				log.Printf("Contrib! Repo: %s, user: %s, contributions: %d", repo, contributor.Login, contributor.Contributions)

				if repoType == "core" {
					user.PublicProfile.GithubContributions.Core.Count += contributor.Contributions
				} else if repoType == "docs" {
					user.PublicProfile.GithubContributions.Docs.Count += contributor.Contributions

				} else if repoType == "apps" {
					user.PublicProfile.GithubContributions.Apps.Count += contributor.Contributions

				} else if repoType == "workflows" {
					user.PublicProfile.GithubContributions.Workflows.Count += contributor.Contributions

				} else {
					log.Printf("[WARNING] No handler for repotype %s (%s)", repoType, repo)
				}

				break
			}
		}
	}

	log.Printf("CONTRIB: %#v", user.PublicProfile.GithubContributions)

	err = SetUser(ctx, &user, false)
	if err != nil {
		log.Printf("[WARNING] Failed setting user data for %s: %s (github)", user.Username, err)
		resp.WriteHeader(401)
		return
	}

	trigger := TriggerAuth{}
	trigger.Id = fmt.Sprintf("github_%s", user.Id)
	trigger.Username = fmt.Sprintf("%s", user.Username)
	trigger.OrgId = user.ActiveOrg.Id
	trigger.Owner = user.Id
	trigger.Type = "github"
	trigger.Code = authInfo.Code
	trigger.OauthToken = OauthToken{
		AccessToken:  accessToken.AccessToken,
		TokenType:    accessToken.TokenType,
		RefreshToken: accessToken.RefreshToken,
		Expiry:       accessToken.Expiry,
	}

	err = SetTriggerAuth(ctx, trigger)
	if err != nil {
		log.Printf("[WARNING] Failed to set trigger auth for %s - %s (github)", trigger.Username, err)
		resp.WriteHeader(401)
		return
	}

	_, err = HandleAlgoliaCreatorUpload(ctx, user, false, false)
	if err != nil {
		log.Printf("[ERROR] Failed making user %s' information public", user.Username)
	}

	log.Printf("Successful client setup for github?")

	//if project.Environment == "cloud" && os.Getenv("CLOUD_ENVIRONMENT") != "local" {
	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleNewGmailRegister(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in getting specific trigger: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to register gmail: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	code := request.URL.Query().Get("code")
	if len(code) == 0 {
		log.Println("No code")
		resp.WriteHeader(403)
		return
	}

	url := fmt.Sprintf("http://%s%s", request.Host, request.URL.EscapedPath())
	if project.Environment == "cloud" && os.Getenv("CLOUD_ENVIRONMENT") != "local" {
		url = fmt.Sprintf("https://%s%s", request.Host, request.URL.EscapedPath())
	}

	ctx := GetContext(request)
	_, accessToken, err := GetGmailClient(ctx, code, OauthToken{}, url)
	if err != nil {
		log.Printf("[WARNING] Oauth client failure - gmail register: %s", err)
		resp.WriteHeader(401)
		return
	}

	// This should be possible, and will also give the actual username

	/*
		profile, err := getOutlookProfile(client)
		if err != nil {
			log.Printf("Outlook profile failure: %s", err)
			resp.WriteHeader(401)
			return
		}
	*/

	// This is a state workaround, which should really be for CSRF checks lol
	state := request.URL.Query().Get("state")
	if len(state) == 0 {
		log.Println("No state")
		resp.WriteHeader(401)
		return
	}

	stateitems := strings.Split(state, "%26")
	if len(stateitems) == 1 {
		stateitems = strings.Split(state, "&")
	}

	// FIXME - trigger auth
	senderUser := ""
	trigger := TriggerAuth{}
	for _, item := range stateitems {
		itemsplit := strings.Split(item, "%3D")
		if len(itemsplit) == 1 {
			itemsplit = strings.Split(item, "=")
		}

		if len(itemsplit) != 2 {
			continue
		}

		//log.Printf("ITEM: %#v", itemsplit)

		// Do something here
		if itemsplit[0] == "workflow_id" {
			trigger.WorkflowId = itemsplit[1]
		} else if itemsplit[0] == "trigger_id" {
			trigger.Id = itemsplit[1]
		} else if itemsplit[0] == "type" {
			trigger.Type = itemsplit[1]
		} else if itemsplit[0] == "start" {
			trigger.Start = itemsplit[1]
		} else if itemsplit[0] == "username" {
			trigger.Username = itemsplit[1]
			trigger.Owner = itemsplit[1]
			senderUser = itemsplit[1]
		}
	}

	if len(trigger.OrgId) == 0 {
		//trigger.OrgId = user.OrgId
		trigger.OrgId = user.ActiveOrg.Id
	}

	// THis is an override based on the user in oauth return
	/*
		if len(profile.Mail) > 0 {
			trigger.Username = profile.Mail
		}
	*/

	trigger.Code = code
	trigger.OauthToken = OauthToken{
		AccessToken:  accessToken.AccessToken,
		TokenType:    accessToken.TokenType,
		RefreshToken: accessToken.RefreshToken,
		Expiry:       accessToken.Expiry,
	}

	//log.Printf("Done with client: %#v", accessToken)
	//log.Printf("Done with client2: %#v", trigger.OauthToken)
	//resp.WriteHeader(401)
	//return

	//log.Printf("%#v", trigger)
	//log.Println(trigger.WorkflowId)
	//log.Println(trigger.Id)
	//log.Println(senderUser)
	//log.Println(trigger.Type)
	log.Printf("[INFO] Attempting to set up gmail trigger for %s", senderUser)
	if trigger.WorkflowId == "" || trigger.Id == "" || senderUser == "" || trigger.Type == "" {
		log.Printf("[INFO] All oauth items need to contain data to register a new state")
		resp.WriteHeader(401)
		return
	}

	// Should also update the user
	Userdata, err := GetUser(ctx, user.Id)
	if err != nil {
		log.Printf("[INFO] Username %s doesn't exist (oauth2): %s", trigger.Username, err)
		resp.WriteHeader(401)
		return
	}

	Userdata.Authentication = append(Userdata.Authentication, UserAuth{
		Name:        "Gmail",
		Description: "oauth2",
		Workflows:   []string{trigger.WorkflowId},
		Username:    trigger.Username,
		Fields: []UserAuthField{
			UserAuthField{
				Key:   "trigger_id",
				Value: trigger.Id,
			},
			UserAuthField{
				Key:   "username",
				Value: trigger.Username,
			},
			UserAuthField{
				Key:   "code",
				Value: code,
			},
			UserAuthField{
				Key:   "type",
				Value: trigger.Type,
			},
		},
	})

	// Set apikey for the user if they don't have one
	err = SetUser(ctx, Userdata, false)
	if err != nil {
		log.Printf("[WARNING] Failed setting user data for %s: %s (gmail)", Userdata.Username, err)
		resp.WriteHeader(401)
		return
	}

	err = SetTriggerAuth(ctx, trigger)
	if err != nil {
		log.Printf("[WARNING] Failed to set trigger auth for %s - %s (gmail)", trigger.Username, err)
		resp.WriteHeader(401)
		return
	}

	// Webhook is never added..?
	/*
		hook := Hook{
			Id:        trigger.Id,
			Start:     trigger.Start,
			Workflows: []string{trigger.WorkflowId},
			Info: Info{
				Name:        "Gmail Cloud Subscription",
				Description: "",
				Url:         notificationURL,
			},
			Type:   "gmail",
			Owner:  "",
			Status: "running",
			Actions: []HookAction{
				HookAction{
					Type:  "workflow",
					Name:  "",
					Id:    workflowId,
					Field: "",
				},
			},
			Running:     true,
			OrgId:       org.Id,
			Environment: "cloud",
		}

		err = SetHook(ctx, hook)
		if err != nil {
			log.Printf("[WARNING] Failed setting hook FOR Gmail from CLOUD org %s: %s", org.Id, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		} else {
			log.Printf("[INFO] Successfully set up CLOUD hook FOR OUTLOOK")
		}
	*/

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleNewOutlookRegister(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[INFO] Api authentication failed in getting specific trigger: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to register outlook: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	code := request.URL.Query().Get("code")
	if len(code) == 0 {
		log.Println("No code")
		resp.WriteHeader(401)
		return
	}

	url := fmt.Sprintf("http://%s%s", request.Host, request.URL.EscapedPath())
	if project.Environment == "cloud" && os.Getenv("CLOUD_ENVIRONMENT") != "local" {
		url = fmt.Sprintf("https://%s%s", request.Host, request.URL.EscapedPath())
	}

	ctx := GetContext(request)
	_, accessToken, err := GetOutlookClient(ctx, code, OauthToken{}, url)
	if err != nil {
		log.Printf("[WARNING] Oauth client failure - outlook register: %s", err)
		resp.WriteHeader(401)
		return
	}

	// This should be possible, and will also give the actual username

	/*
		profile, err := getOutlookProfile(client)
		if err != nil {
			log.Printf("Outlook profile failure: %s", err)
			resp.WriteHeader(401)
			return
		}
	*/

	// This is a state workaround, which should really be for CSRF checks lol
	state := request.URL.Query().Get("state")
	if len(state) == 0 {
		log.Println("No state")
		resp.WriteHeader(401)
		return
	}

	log.Printf("STATE: %s", state)
	stateitems := strings.Split(state, "%26")
	if len(stateitems) == 1 {
		stateitems = strings.Split(state, "&")
	}

	// FIXME - trigger auth
	senderUser := ""
	trigger := TriggerAuth{}
	for _, item := range stateitems {
		itemsplit := strings.Split(item, "%3D")
		if len(itemsplit) == 1 {
			itemsplit = strings.Split(item, "=")
		}

		if len(itemsplit) != 2 {
			continue
		}

		//log.Printf("ITEM: %#v", itemsplit)

		// Do something here
		if itemsplit[0] == "workflow_id" {
			trigger.WorkflowId = itemsplit[1]
		} else if itemsplit[0] == "trigger_id" {
			trigger.Id = itemsplit[1]
		} else if itemsplit[0] == "type" {
			trigger.Type = itemsplit[1]
		} else if itemsplit[0] == "start" {
			trigger.Start = itemsplit[1]
		} else if itemsplit[0] == "username" {
			trigger.Username = itemsplit[1]
			trigger.Owner = itemsplit[1]
			senderUser = itemsplit[1]
		}
	}

	// THis is an override based on the user in oauth return
	/*
		if len(profile.Mail) > 0 {
			trigger.Username = profile.Mail
		}
	*/

	if len(trigger.OrgId) == 0 {
		trigger.OrgId = user.ActiveOrg.Id
	}

	trigger.Code = code
	trigger.OauthToken = OauthToken{
		AccessToken:  accessToken.AccessToken,
		TokenType:    accessToken.TokenType,
		RefreshToken: accessToken.RefreshToken,
		Expiry:       accessToken.Expiry,
	}

	//log.Printf("%#v", trigger)
	log.Println(trigger.WorkflowId)
	log.Println(trigger.Id)
	log.Println(senderUser)
	log.Println(trigger.Type)

	log.Printf("[INFO] Attempting to set up outlook trigger for %s", senderUser)
	if trigger.WorkflowId == "" || trigger.Id == "" || senderUser == "" || trigger.Type == "" {
		log.Printf("[INFO] All oauth items need to contain data to register a new state")
		resp.WriteHeader(401)
		return
	}

	// Should also update the user
	Userdata, err := GetUser(ctx, user.Id)
	if err != nil {
		log.Printf("[INFO] Username %s doesn't exist (oauth2): %s", trigger.Username, err)
		resp.WriteHeader(401)
		return
	}

	Userdata.Authentication = append(Userdata.Authentication, UserAuth{
		Name:        "Outlook",
		Description: "oauth2",
		Workflows:   []string{trigger.WorkflowId},
		Username:    trigger.Username,
		Fields: []UserAuthField{
			UserAuthField{
				Key:   "trigger_id",
				Value: trigger.Id,
			},
			UserAuthField{
				Key:   "username",
				Value: trigger.Username,
			},
			UserAuthField{
				Key:   "code",
				Value: code,
			},
			UserAuthField{
				Key:   "type",
				Value: trigger.Type,
			},
		},
	})

	// Set apikey for the user if they don't have one
	err = SetUser(ctx, Userdata, false)
	if err != nil {
		log.Printf("[WARNING] Failed setting user data for %s: %s (outlook)", Userdata.Username, err)
		resp.WriteHeader(401)
		return
	}

	err = SetTriggerAuth(ctx, trigger)
	if err != nil {
		log.Printf("[WARNING] Failed to set trigger auth for %s - %s (outlook)", trigger.Username, err)
		resp.WriteHeader(401)
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleGetSpecificTrigger(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("Api authentication failed in getting specific workflow: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")

	var workflowId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		workflowId = location[5]
	}

	if strings.Contains(workflowId, "?") {
		workflowId = strings.Split(workflowId, "?")[0]
	}

	ctx := GetContext(request)
	trigger, err := GetTriggerAuth(ctx, workflowId)
	if err != nil {
		log.Printf("[INFO] Trigger %s doesn't exist - specific trigger.", workflowId)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": ""}`))
		return
	}

	if user.Username != trigger.Owner && user.Role != "admin" {
		log.Printf("[AUDIT] Wrong user (%s) for trigger %s", user.Username, trigger.Id)
		resp.WriteHeader(403)
		return
	}

	trigger.OauthToken = OauthToken{}
	trigger.Code = ""

	b, err := json.Marshal(trigger)
	if err != nil {
		log.Println("Failed to marshal data")
		resp.WriteHeader(401)
		return
	}

	resp.WriteHeader(200)
	resp.Write(b)
}

// Lists the users current subscriptions
func getOutlookSubscriptions(outlookClient *http.Client) (SubscriptionsWrapper, error) {
	fullUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/subscriptions")
	req, err := http.NewRequest(
		"GET",
		fullUrl,
		nil,
	)
	req.Header.Add("Content-Type", "application/json")
	res, err := outlookClient.Do(req)
	if err != nil {
		log.Printf("suberror Client: %s", err)
		return SubscriptionsWrapper{}, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("Suberror Body: %s", err)
		return SubscriptionsWrapper{}, err
	}

	newSubs := SubscriptionsWrapper{}
	err = json.Unmarshal(body, &newSubs)
	if err != nil {
		return SubscriptionsWrapper{}, err
	}

	return newSubs, nil
}

type SubscriptionsWrapper struct {
	OdataContext string                `json:"@odata.context"`
	Value        []OutlookSubscription `json:"value"`
}

type OutlookSubscription struct {
	ChangeType         string `json:"changeType"`
	NotificationURL    string `json:"notificationUrl"`
	Resource           string `json:"resource"`
	ExpirationDateTime string `json:"expirationDateTime"`
	ClientState        string `json:"clientState"`
	Id                 string `json:"id"`
}

type GmailSubscription struct {
	TopicName         string   `json:"topicName"`
	LabelIds          []string `json:"labelIds"`
	LabelFilterAction []string `json:"labelFilterAction"`
}

func GetGmailMessageAttachment(ctx context.Context, gmailClient *http.Client, userId, messageId, attachmentId string) (GmailAttachment, error) {
	//fullUrl := fmt.Sprintf("https://gmail.googleapis.com/gmail/v1/users/%s/messages/%s?format=full", userId, messageId)
	fullUrl := fmt.Sprintf("https://gmail.googleapis.com/gmail/v1/users/%s/messages/%s/attachments/%s", userId, messageId, attachmentId)

	//fullUrl := fmt.Sprintf("https://gmail.googleapis.com/gmail/v1/users/me/messages/%s?format=full", messageId)
	req, err := http.NewRequest(
		"GET",
		fullUrl,
		nil,
	)
	req.Header.Add("Content-Type", "application/json")
	res, err := gmailClient.Do(req)
	if err != nil {
		log.Printf("[WARNING] GMAIL get msg (4): %s", err)
		return GmailAttachment{}, err
	}

	defer res.Body.Close()
	log.Printf("[INFO] Get GMAIL attachment %#v Status: %d", messageId, res.StatusCode)
	if res.StatusCode == 404 {
		return GmailAttachment{}, errors.New(fmt.Sprintf("Failed to find mail for %s: %d", messageId, res.StatusCode))
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] Gmail get msg (5): %s", err)
		return GmailAttachment{}, err
	}

	var message GmailAttachment
	err = json.Unmarshal(body, &message)
	if err != nil {
		log.Printf("[WARNING] Failed body read unmarshal for gmail msg: %s", err)
		return GmailAttachment{}, err
	}

	//log.Printf("ATTACHMENT MAIL WITH SIZE %d", message.Size)

	//if len(profile.EmailAddress) == 0 {
	//	return GmailMessageStruct{}, errors.New("Couldn't find your email profile")
	//}

	//log.Printf("\n\nUSER BODY: %s", string(body))
	return message, nil
}

func GetGithubRepoContributors(ctx context.Context, githubClient *http.Client, repo string) ([]GithubProfile, error) {
	fullUrl := fmt.Sprintf("https://api.github.com/repos/%s/contributors", repo)
	req, err := http.NewRequest(
		"GET",
		fullUrl,
		nil,
	)

	req.Header.Add("Content-Type", "application/json")
	res, err := githubClient.Do(req)
	if err != nil {
		log.Printf("[WARNING] Github user get (4): %s", err)
		return []GithubProfile{}, err
	}

	defer res.Body.Close()
	if res.StatusCode == 404 {
		return []GithubProfile{}, errors.New(fmt.Sprintf("No repo contributors to get"))
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] Gmail get msg (5): %s", err)
		return []GithubProfile{}, err
	}

	//log.Printf("PROFILE: %s", string(body))
	var message []GithubProfile
	err = json.Unmarshal(body, &message)
	if err != nil {
		log.Printf("[WARNING] Failed body read unmarshal for gmail msg: %s", err)
		return []GithubProfile{}, err
	}

	return message, nil
}

func GetGithubProfile(ctx context.Context, githubClient *http.Client) (GithubProfile, error) {
	fullUrl := fmt.Sprintf("https://api.github.com/user")
	req, err := http.NewRequest(
		"GET",
		fullUrl,
		nil,
	)
	req.Header.Add("Content-Type", "application/json")
	res, err := githubClient.Do(req)
	if err != nil {
		log.Printf("[WARNING] Github user get (4): %s", err)
		return GithubProfile{}, err
	}

	defer res.Body.Close()
	if res.StatusCode == 404 {
		return GithubProfile{}, errors.New(fmt.Sprintf("No user to get"))
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] Gmail get msg (5): %s", err)
		return GithubProfile{}, err
	}

	//log.Printf("PROFILE: %s", string(body))
	var message GithubProfile
	err = json.Unmarshal(body, &message)
	if err != nil {
		log.Printf("[WARNING] Failed body read unmarshal for gmail msg: %s", err)
		return GithubProfile{}, err
	}

	return message, nil
}

func GetGmailThread(ctx context.Context, gmailClient *http.Client, userId, messageId string) (GmailThreadStruct, error) {
	fullUrl := fmt.Sprintf("https://gmail.googleapis.com/gmail/v1/users/%s/threads/%s?format=full", userId, messageId)
	//fullUrl := fmt.Sprintf("https://gmail.googleapis.com/gmail/v1/users/me/messages/%s?format=full", messageId)
	req, err := http.NewRequest(
		"GET",
		fullUrl,
		nil,
	)
	req.Header.Add("Content-Type", "application/json")
	res, err := gmailClient.Do(req)
	if err != nil {
		log.Printf("[WARNING] GMAIL get msg (4): %s", err)
		return GmailThreadStruct{}, err
	}

	defer res.Body.Close()
	log.Printf("[INFO] Get GMAIL thread %#v Status: %d", messageId, res.StatusCode)
	if res.StatusCode == 404 {
		return GmailThreadStruct{}, errors.New(fmt.Sprintf("Failed to find gmail thread for %s: %d", messageId, res.StatusCode))
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] Gmail get msg (5): %s", err)
		return GmailThreadStruct{}, err
	}

	//log.Printf("THREAD: %s", string(body))
	var message GmailThreadStruct
	err = json.Unmarshal(body, &message)
	if err != nil {
		log.Printf("[WARNING] Failed body read unmarshal for gmail msg: %s", err)
		return GmailThreadStruct{}, err
	}

	//if len(profile.EmailAddress) == 0 {
	//	return GmailMessageStruct{}, errors.New("Couldn't find your email profile")
	//}

	//log.Printf("\n\nUSER BODY: %s", string(body))
	return message, nil
}

func GetGmailMessage(ctx context.Context, gmailClient *http.Client, userId, messageId string) (GmailMessageStruct, error) {
	fullUrl := fmt.Sprintf("https://gmail.googleapis.com/gmail/v1/users/%s/messages/%s?format=full", userId, messageId)
	//fullUrl := fmt.Sprintf("https://gmail.googleapis.com/gmail/v1/users/me/messages/%s?format=full", messageId)
	req, err := http.NewRequest(
		"GET",
		fullUrl,
		nil,
	)
	req.Header.Add("Content-Type", "application/json")
	res, err := gmailClient.Do(req)
	if err != nil {
		log.Printf("[WARNING] GMAIL get msg (4): %s", err)
		return GmailMessageStruct{}, err
	}

	defer res.Body.Close()
	log.Printf("[INFO] Get GMAIL msg %#v Status: %d. User: %s", messageId, res.StatusCode, userId)
	if res.StatusCode == 404 {
		return GmailMessageStruct{}, errors.New(fmt.Sprintf("Failed to find mail for %s: %d", messageId, res.StatusCode))
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] Gmail get msg (5): %s", err)
		return GmailMessageStruct{}, err
	}

	//log.Printf("MAIL: %s", string(body))

	var message GmailMessageStruct
	err = json.Unmarshal(body, &message)
	if err != nil {
		log.Printf("[WARNING] Failed body read unmarshal for gmail msg: %s", err)
		return GmailMessageStruct{}, err
	}

	for _, header := range message.Payload.Headers {
		if header.Name == "Subject" {
			message.Payload.Subject = header.Value
		}
		if header.Name == "To" {
			message.Payload.Recipient = header.Value
		}
		if header.Name == "From" {
			message.Payload.Sender = header.Value
		}
		if header.Name == "Message-ID" {
			message.Payload.MessageID = header.Value

			if len(message.Payload.PartID) == 0 {
				message.Payload.PartID = header.Value
			}
		}
	}

	message.Payload.Sender = strings.Replace(message.Payload.Sender, "\"", `'`, -1)
	message.Payload.Subject = strings.Replace(message.Payload.Subject, "'", `'`, -1)

	// Finding a parsed payload
	for _, payload := range message.Payload.Parts {
		//parsedBody = mess
		//log.Printf("[DEBUG] Data to be decoded (%s): %d", payload.MimeType, len(payload.Body.Data))
		if payload.MimeType == "text/plain" && payload.Filename == "" {
			payload.Body.Data = strings.Replace(payload.Body.Data, "-", "+", -1)
			payload.Body.Data = strings.Replace(payload.Body.Data, "_", "/", -1)

			parsedData, err := base64.StdEncoding.DecodeString(payload.Body.Data)
			if err != nil {
				log.Printf("[WARNING] Failed base64 decode of parsedbody (text/plain): %s. New data length: %d. Using it anyway.", err, len(parsedData))
				if len(parsedData) > 0 {
					message.Payload.ParsedBody = string(parsedData)
					continue
					//break
				}

				if len(message.Payload.ParsedBody) == 0 {
					message.Payload.ParsedBody = string(parsedData)
				}

				continue
			}

			message.Payload.ParsedBody = string(parsedData)
		} else {
			if len(payload.Filename) > 0 {
				message.Payload.Filename = payload.Filename
				message.Payload.FileMimeType = payload.MimeType
			} else if len(message.Payload.ParsedBody) == 0 {
				message.Payload.ParsedBody = string(payload.Body.Data)
			}
		}

		if len(message.Payload.ParsedBody) > 0 && message.Payload.FileMimeType == "" {
			message.Payload.FileMimeType = payload.MimeType
		}
	}

	//log.Printf("\n\nUSER BODY: %s", string(body))
	return message, nil
}

type CodeVerifier struct {
	Value string
}

const (
	length = 32
)

func CreateCodeVerifierFromBytes(b []byte) (*CodeVerifier, error) {
	return &CodeVerifier{
		Value: base64URLEncode(b),
	}, nil
}

func base64URLEncode(str []byte) string {
	encoded := base64.StdEncoding.EncodeToString(str)
	encoded = strings.Replace(encoded, "+", "-", -1)
	encoded = strings.Replace(encoded, "/", "_", -1)
	encoded = strings.Replace(encoded, "=", "", -1)
	return encoded
}

func (v *CodeVerifier) CodeChallengeS256() string {
	h := sha256.New()
	h.Write([]byte(v.Value))
	return base64URLEncode(h.Sum(nil))
}

// https://dev-18062.okta.com/oauth2/default/v1/authorize?client_id=0oa3&response_type=code&scope=openid&redirect_uri=http%3A%2F%2Flocalhost%3A5002%2Fapi%2Fv1%2Flogin_openid&state=state-296bc9a0-a2a2-4a57-be1a-d0e2fd9bb601&code_challenge_method=S256&code_challenge=codechallenge
func RunOpenidLogin(ctx context.Context, clientId, baseUrl, redirectUri, code, codeChallenge, clientSecret string) ([]byte, error) {
	if len(codeChallenge) == 0 {
		return []byte{}, errors.New("code challenge is required")
	}

	client := &http.Client{}
	data := fmt.Sprintf("client_id=%s&grant_type=authorization_code&redirect_uri=%s&code=%s&code_verifier=%s", clientId, redirectUri, code, codeChallenge)
	if len(clientSecret) > 0 {
		data += fmt.Sprintf("&client_secret=%s", clientSecret)
	}

	req, err := http.NewRequest(
		"POST",
		baseUrl,
		bytes.NewBuffer([]byte(data)),
	)

	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Add("accept", "application/json")
	req.Header.Add("cache-control", "no-cache")
	res, err := client.Do(req)
	if err != nil {
		log.Printf("[WARNING] OpenID Client: %s", err)
		return []byte{}, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] OpenID client Body: %s", err)
		return []byte{}, err
	}

	log.Printf("OpenID return BODY: %s", body)

	return body, nil
}

func GetGithubClient(ctx context.Context, code string, accessToken OauthToken, redirectUri string) (*http.Client, *oauth2.Token, error) {
	//fullUrl := fmt.Sprintf("https://github.com/login/oauth/access_token?client_id=%s&client_secret=%s&code=%s&token_type=bearer", os.Getenv("GITHUB_CLIENT"), os.Getenv("GITHUB_SECRET"), code)
	//log.Printf("Posting to URL %s for github", fullUrl)
	//client := &http.Client{
	//	Timeout: 1 * time.Second,
	//}
	//req, err := http.NewRequest(
	//	"POST",
	//	fullUrl,
	//	nil,
	//)

	//req.Header.Add("Content-Type", "application/json")
	//res, err := client.Do(req)
	//if err != nil {
	//	log.Printf("[WARNING] GMAIL Client: %s", err)
	//	return &http.Client{}, &oauth2.Token{}, err
	//}

	//body, err := ioutil.ReadAll(res.Body)
	//if err != nil {
	//	log.Printf("[WARNING] Gmail subscription Body: %s", err)
	//	return &http.Client{}, &oauth2.Token{}, err
	//}

	//log.Printf("BODY: %s", body)

	//return &http.Client{}, &oauth2.Token{}, err

	//RedirectURL: "http://localhost:3002/set_authentication",
	conf := &oauth2.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT"),
		ClientSecret: os.Getenv("GITHUB_SECRET"),
		Scopes: []string{
			"read:user",
			//"repo",
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
	}

	log.Printf("CONF: %#v", conf)

	if len(code) > 0 {
		access_token, err := conf.Exchange(ctx, code)
		if err != nil {
			log.Printf("[WARNING] Access_token issue for Github: %s", err)
			return &http.Client{}, access_token, err
		}

		client := conf.Client(ctx, access_token)
		return client, access_token, nil
	}

	// Manually recreate the oauthtoken
	access_token := &oauth2.Token{
		AccessToken:  accessToken.AccessToken,
		TokenType:    accessToken.TokenType,
		RefreshToken: accessToken.RefreshToken,
		Expiry:       accessToken.Expiry,
	}

	client := conf.Client(ctx, access_token)
	return client, access_token, nil
}

// THis all of a sudden became really horrible.. fml
func GetGmailClient(ctx context.Context, code string, accessToken OauthToken, redirectUri string) (*http.Client, *oauth2.Token, error) {
	clientId := os.Getenv("GMAIL_CLIENT_ID")
	clientSecret := os.Getenv("GMAIL_CLIENT_SECRET")

	conf := &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Scopes: []string{
			"https://www.googleapis.com/auth/gmail.readonly",
		},
		RedirectURL: redirectUri,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://accounts.google.com/o/oauth2/token",
		},
	}

	if len(code) > 0 {
		access_token, err := conf.Exchange(ctx, code)
		if err != nil {
			log.Printf("[WARNING] Access_token issue for Gmail: %s", err)
			return &http.Client{}, access_token, err
		}

		client := conf.Client(ctx, access_token)
		return client, access_token, nil
	}

	// Manually recreate the oauthtoken
	access_token := &oauth2.Token{
		AccessToken:  accessToken.AccessToken,
		TokenType:    accessToken.TokenType,
		RefreshToken: accessToken.RefreshToken,
		Expiry:       accessToken.Expiry,
	}

	client := conf.Client(ctx, access_token)
	return client, access_token, nil
}

// THis all of a sudden became really horrible.. fml
func GetOutlookClient(ctx context.Context, code string, accessToken OauthToken, redirectUri string) (*http.Client, *oauth2.Token, error) {
	conf := &oauth2.Config{
		ClientID:     os.Getenv("OFFICE365_CLIENT_ID"),
		ClientSecret: os.Getenv("OFFICE365_CLIENT_SECRET"),
		Scopes: []string{
			"Mail.Read",
		},
		RedirectURL: redirectUri,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.microsoftonline.com/common/oauth2/authorize",
			TokenURL: "https://login.microsoftonline.com/common/oauth2/token",
		},
	}

	if len(code) > 0 {
		access_token, err := conf.Exchange(ctx, code)
		if err != nil {
			log.Printf("[ERROR] Access_token issue for Outlook: %s", err)
			return &http.Client{}, access_token, err
		}

		client := conf.Client(ctx, access_token)
		return client, access_token, nil
	}

	// Manually recreate the oauthtoken
	access_token := &oauth2.Token{
		AccessToken:  accessToken.AccessToken,
		TokenType:    accessToken.TokenType,
		RefreshToken: accessToken.RefreshToken,
		Expiry:       accessToken.Expiry,
	}

	client := conf.Client(ctx, access_token)
	return client, access_token, nil
}

func GetGmailFolders(client *http.Client) (OutlookFolders, error) {
	//requestUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/ec03b4f2-fccf-4c35-b0eb-be85a0f5dd43/mailFolders")
	requestUrl := fmt.Sprintf("https://gmail.googleapis.com/gmail/v1/users/me/labels")

	ret, err := client.Get(requestUrl)
	if err != nil {
		log.Printf("[INFO] FolderErr gmail: %s", err)
		return OutlookFolders{}, err
	}

	body, err := ioutil.ReadAll(ret.Body)
	if err != nil {
		log.Printf("[WARNING] Failed body decoding from mailfolders")
		return OutlookFolders{}, err
	}

	//log.Printf("Folders: %s", string(body))
	//log.Printf("[INFO] Folder Body: %s", string(body))
	if ret.StatusCode != 200 {
		log.Printf("[INFO] Bad Status for GMAIL folders (Labels): %d. Body: %s", ret.StatusCode, string(body))
		return OutlookFolders{}, err
	}

	labels := GmailLabels{}
	err = json.Unmarshal(body, &labels)
	if err != nil {
		log.Printf("[WARNING] GMAIL folder Unmarshal: %s", err)
		return OutlookFolders{}, err
	}

	// Casting to Outlook for frontend usability reasons
	log.Printf("[DEBUG] Found %d labels", len(labels.Labels))
	mailfolders := OutlookFolders{}
	for _, label := range labels.Labels {
		if label.MessageListVisibility == "hide" {
			continue
		}

		mailfolders.Value = append(mailfolders.Value, OutlookFolder{
			ID:          label.ID,
			DisplayName: label.Name,
		})
	}

	//fmt.Printf("%#v", mailfolders)
	// FIXME - recursion for subfolders
	// Recursive struct
	// folderEndpoint := fmt.Sprintf("%s/%s/childfolders?$top=40", requestUrl, parentId)
	//for _, folder := range mailfolders.Value {
	//	log.Println(folder.DisplayName)
	//}

	return mailfolders, nil
}

func getOutlookFolders(client *http.Client) (OutlookFolders, error) {
	//requestUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/ec03b4f2-fccf-4c35-b0eb-be85a0f5dd43/mailFolders")
	//requestUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/me/mailFolders")

	// Include hidden folders
	requestUrl := fmt.Sprintf("https://graph.microsoft.com/beta/me/mailFolders?$top=100&$expand=childFolders")

	ret, err := client.Get(requestUrl)
	if err != nil {
		log.Printf("[INFO] FolderErr: %s", err)
		return OutlookFolders{}, err
	}

	body, err := ioutil.ReadAll(ret.Body)
	if err != nil {
		log.Printf("[WARNING] Failed body decoding from mailfolders")
		return OutlookFolders{}, err
	}

	//log.Printf("[INFO] Folder Body: %s", string(body))
	log.Printf("[INFO] Status Outlook folders: %d. Reason: %s", ret.StatusCode, string(body))
	if ret.StatusCode != 200 {
		return OutlookFolders{}, err
	}

	//log.Printf("Body: %s", string(body))

	mailfolders := OutlookFolders{}
	err = json.Unmarshal(body, &mailfolders)
	if err != nil {
		log.Printf("Unmarshal: %s", err)
		return OutlookFolders{}, err
	}

	//fmt.Printf("%#v", mailfolders)
	// FIXME - recursion for subfolders
	// Recursive struct
	// folderEndpoint := fmt.Sprintf("%s/%s/childfolders?$top=40", requestUrl, parentId)
	//for _, folder := range mailfolders.Value {
	//	log.Println(folder.DisplayName)
	//}

	return mailfolders, nil
}

func GetOauth2ApplicationPermissionToken(ctx context.Context, user User, appAuth AppAuthenticationStorage) (AppAuthenticationStorage, error) {
	transport := http.DefaultTransport.(*http.Transport)
	transport.MaxIdleConnsPerHost = 100
	transport.ResponseHeaderTimeout = time.Second * 10
	transport.Proxy = nil

	clientId := ""
	clientSecret := ""
	tokenUrl := ""
	scope := ""

	grantType := "client_credentials"
	username := ""
	password := ""

	//log.Printf("[DEBUG] Got %d auth fields (%s)", len(appAuth.Fields), appAuth.Id)
	for _, field := range appAuth.Fields {
		if field.Key == "client_secret" {
			clientSecret = field.Value
		} else if field.Key == "client_id" {
			clientId = field.Value
		} else if field.Key == "scope" {
			scope = field.Value
		} else if field.Key == "token_uri" {
			tokenUrl = field.Value
		} else if field.Key == "grant_type" {
			grantType = field.Value
		} else if field.Key == "username" {
			username = field.Value
		} else if field.Key == "password" {
			password = field.Value
		} else {
		}
	}

	if len(tokenUrl) == 0 || len(clientId) == 0 || len(clientSecret) == 0 {
		return appAuth, fmt.Errorf("Missing oauth2 fields. Required: token_uri, client_id, client_secret, scopes")
	}

	zscalerAuth := strings.Contains(tokenUrl, ".zslogin.net")
	if zscalerAuth && len(scope) == 0 {
		scope = "https://api.zscaler.com"
	}

	refreshData := fmt.Sprintf("grant_type=client_credentials")
	if len(grantType) > 0 {
		refreshData = fmt.Sprintf("grant_type=%s", grantType)
	}

	if grantType == "password" {
		if len(username) > 0 {
			refreshData += fmt.Sprintf("&username=%s", username)
		}

		if len(password) > 0 {
			refreshData += fmt.Sprintf("&password=%s", password)
		}

		refreshData += fmt.Sprintf("&client_id=%s", clientId)
		refreshData += fmt.Sprintf("&client_secret=%s", clientSecret)
	}

	if grantType == "client_credentials" && zscalerAuth {
		refreshData += fmt.Sprintf("&client_id=%s", clientId)
		refreshData += fmt.Sprintf("&client_secret=%s", clientSecret)
	}

	if len(scope) > 0 {
		if zscalerAuth {
			refreshData += fmt.Sprintf("&audience=%s", strings.Replace(scope, ",", " ", -1))
		} else {
			refreshData += fmt.Sprintf("&scope=%s", strings.Replace(scope, ",", " ", -1))
		}
	}

	if strings.Contains(refreshData, "user_impersonation") && strings.Contains(refreshData, "azure") && !strings.Contains(refreshData, "resource=") {
		// Add "resource" for microsoft hings
		refreshData += "&resource=https://management.azure.com"
	}

	// Not necessary for refresh
	log.Printf("[DEBUG] Oauth2 REFRESH DATA: %#v. URL: %#v", refreshData, tokenUrl)

	client := GetExternalClient(tokenUrl)
	req, err := http.NewRequest(
		"POST",
		tokenUrl,
		bytes.NewBuffer([]byte(refreshData)),
	)

	if err != nil {
		return appAuth, err
	}

	// Basic auth handler for client_credentials. May not always be the case, it's currently used by default
	if grantType == "client_credentials" && !zscalerAuth {
		authHeader := fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", clientId, clientSecret))))
		req.Header.Set("Authorization", authHeader)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")
	newresp, err := client.Do(req)
	if err != nil {
		return appAuth, err
	}

	defer newresp.Body.Close()
	body, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		log.Printf("[ERROR] Oauth2 application auth: Failed to read response body: %s", err)
		return appAuth, err
	}

	log.Printf("[DEBUG] Oauth2 application auth Response for %s: %d", tokenUrl, newresp.StatusCode)

	if newresp.StatusCode >= 300 {
		// Printing on error to handle in future instances
		log.Printf("[ERROR] Oauth2 application data for %s: %#v", tokenUrl, string(body))

		// Autocorrecting scopes -> audience
		if strings.Contains(string(body), "error") && strings.Contains(string(body), "audience") && len(scope) > 0 {
			log.Printf("[INFO] Oauth2 application auth: Autocorrecting scopes -> audience")

			refreshData = fmt.Sprintf("grant_type=client_credentials")
			if len(grantType) > 0 {
				refreshData = fmt.Sprintf("grant_type=%s", grantType)
			}

			refreshData += fmt.Sprintf("&audience=%s", strings.Replace(scope, ",", " ", -1))
			req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(refreshData)))
			req.ContentLength = int64(len(refreshData))

			if !zscalerAuth {
				authHeader := fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", clientId, clientSecret))))
				req.Header.Set("Authorization", authHeader)
			}

			newresp, err = client.Do(req)
			if err != nil {
				log.Printf("[ERROR] Oauth2 application auth (2): Failed to autocorrect scopes -> audience: %s", err)
				return appAuth, err
			}

			defer newresp.Body.Close()
			body, err = ioutil.ReadAll(newresp.Body)
			if err != nil {
				log.Printf("[ERROR] Oauth2 application auth (3): Failed to read response body: %s", err)
				return appAuth, err
			}
		}

		// Takes care of both old and new request
		if newresp.StatusCode >= 300 {
			return appAuth, errors.New(fmt.Sprintf("Bad status code when getting access token for token URL %s: %d. Message: %s", tokenUrl, newresp.StatusCode, body))
		}
	}

	if strings.Contains(string(body), "error") {
		log.Printf("\n\n[ERROR] Oauth2 app RESPONSE: %s\n\n", string(body))
	}

	// Parse out data like {"access_token":"ddpGSlBV4GhNhToPTLjHZSwbqRH6JUIv0QYPo6CW62NfAr","token_type":"Bearer","expires_in":1870}
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return appAuth, err
	}

	//log.Printf("[DEBUG] Oauth2 data for %s: %d", tokenUrl, newresp.StatusCode)
	// Check if access_token is in data
	foundToken := ""
	if _, ok := data["access_token"]; !ok {
		return appAuth, errors.New(fmt.Sprintf("Missing access_token in response from %s", tokenUrl))
	} else {
		foundToken = data["access_token"].(string)
	}

	if len(foundToken) == 0 {
		return appAuth, errors.New(fmt.Sprintf("Empty access_token in response from %s", tokenUrl))
	}

	appAuth.Fields = append(appAuth.Fields, AuthenticationStore{
		Key:   "access_token",
		Value: foundToken,
	})

	return appAuth, nil
}

func RunOauth2Request(ctx context.Context, user User, appAuth AppAuthenticationStorage, refresh bool) (AppAuthenticationStorage, error) {

	//transport := http.DefaultTransport.(*http.Transport).Clone()
	transport := http.DefaultTransport.(*http.Transport)
	transport.MaxIdleConnsPerHost = 100
	transport.ResponseHeaderTimeout = time.Second * 10
	transport.Proxy = nil

	requestData := DataToSend{
		GrantType: "authorization_code",
	}

	url := ""
	oauthUrl := ""
	refreshUrl := ""
	refreshToken := ""

	for _, field := range appAuth.Fields {
		// Try decryption here as well just in case
		// In some cases, it's already decrypted at this point, but it doesn't matter much to re-do it in case, as this function is used multiple places
		decryptionKey := fmt.Sprintf("%s_%d_%s_%s", appAuth.OrgId, appAuth.Created, appAuth.Label, field.Key)
		newValue, err := HandleKeyDecryption([]byte(field.Value), decryptionKey)
		if err == nil {
			field.Value = string(newValue)
		} else {
			//log.Printf("[DEBUG] Failed decrypting field %s: %s", field.Key, err)
		}

		if field.Key == "authentication_url" {
			url = field.Value
		} else if field.Key == "code" {
			requestData.Code = field.Value
		} else if field.Key == "client_secret" {
			requestData.ClientSecret = field.Value
		} else if field.Key == "client_id" {
			requestData.ClientId = field.Value
		} else if field.Key == "scopes" {
			requestData.Scope = field.Value
		} else if field.Key == "scope" {
			requestData.Scope = field.Value
		} else if field.Key == "redirect_uri" {

			requestData.RedirectUri = field.Value
		} else if field.Key == "refresh_uri" || field.Key == "refresh_url" {
			refreshUrl = field.Value
		} else if field.Key == "refresh_token" {
			//log.Printf("[DEBUG] Got refresh token %s", field.Value)
			refreshToken = field.Value
		} else if field.Key == "oauth_url" {
			oauthUrl = field.Value
		} else {
			if field.Key == "url" {
			} else {
			}
		}
	}

	if len(requestData.ClientSecret) == 0 && len(requestData.ClientId) > 0 {
		oauth2data, err := GetHostedOAuth(ctx, requestData.ClientId)
		if err == nil && len(oauth2data.ClientSecret) > 0 {
			requestData.ClientSecret = oauth2data.ClientSecret
		}
	}

	//log.Printf("[DEBUG] Making request with auth %s to %s for Oauth2 token. User: '%s' ('%s')", appAuth.Id, url, user.Username, user.Id)
	//log.Printf("[DEBUG] Verbose Requestdata: Sending request to %#v with requestdata %#v", url, requestData)
	if len(url) == 0 {
		return appAuth, errors.New("No authentication URL provided in Oauth2 request")
	}

	if len(requestData.Resource) == 0 {
		if strings.Contains(url, "microsoft") {
			//log.Printf("[DEBUG] Should look to add add resource to the query data for URL %s. Resource: %#v", url, requestData.Resource)
			foundScope := ""
			for _, scope := range strings.Split(requestData.Scope, " ") {
				if strings.Contains(string(scope), "https://") {
					foundScope = string(scope)
					break
				}
			}

			if len(foundScope) > 0 {
				scopeSplit := strings.Split(foundScope, "/")

				if len(scopeSplit) > 2 {
					//requestData.Resource = "https://management.azure.com/"
					requestData.Resource = strings.Join(scopeSplit[0:3], "/") + "/"
					log.Printf("[DEBUG] Set resource to be %#v from SCOPES: %#v", requestData.Resource, requestData.Scope)
				}
			}
		}
	}

	// To send: POST
	// URL sample: https://login.microsoftonline.com/b6eb57ed-ecfc-4af2-b0ff-467a2e2c806f/oauth2/v2.0/token
	// Data to be sent: requestData formatted?
	v, err := query.Values(requestData)
	if err != nil {
		log.Printf("[ERROR] Failed parsing Oauth2 values: %s", err)
		return appAuth, err
	}

	if len(refreshToken) == 0 && refresh {
		refresh = false
	}

	// Look for {tenant in the URL. If it's found, find the next } after it, then replace it with 'common'
	// This is to make sure to handle tenant things for microsoft
	if strings.Contains(strings.ToLower(url), "{tenant") {
		//log.Printf("[DEBUG] Found tenant in URL: %s", url)
		tenantPos := strings.Index(strings.ToLower(url), "{tenant")

		if tenantPos >= 0 {
			tenantEnd := strings.Index(url[tenantPos:], "}")
			if tenantEnd >= 0 {
				url = url[:tenantPos] + "common" + url[tenantPos+tenantEnd+1:]
				//log.Printf("[DEBUG] Replaced tenant in URL: %s", url)
			}
		}
	}

	client := GetExternalClient(url)
	newresp := &http.Response{}
	respBody := []byte{}
	if !refresh {
		req, err := http.NewRequest(
			"POST",
			url,
			bytes.NewBuffer([]byte(v.Encode())),
		)

		if err != nil {
			log.Printf("[ERROR] Failed setting up Oauth2 request for %s: %s", url, err)
			return appAuth, err
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("Accept", "application/json")
		newresp, err = client.Do(req)
		if err != nil {
			log.Printf("[ERROR] Failed running Oauth2 request for %s: %s", url, err)
			return appAuth, err
		}

		//log.Printf("Data: %#v", newresp)
		//log.Printf("Data: %d", newresp.StatusCode)

		defer newresp.Body.Close()
		body, err := ioutil.ReadAll(newresp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed unmarshalling body from Oauth2 request for %s: %s", url, err)
			return appAuth, err
		}

		respBody = body
		if newresp.StatusCode >= 300 {
			return appAuth, errors.New(fmt.Sprintf("Bad status code for URL (NOT refresh) %s: %d. Message: %s", url, newresp.StatusCode, respBody))
		}
	} else {

		if len(refreshToken) == 0 {
			log.Printf("[ERROR] No refresh token acquired for %s", refreshUrl)
			return appAuth, errors.New("No refresh token specified during initial auth.")
		}

		requestRefreshUrl := fmt.Sprintf("%s", refreshUrl)
		refreshData := fmt.Sprintf("grant_type=refresh_token&refresh_token=%s&scope=%s&client_id=%s&client_secret=%s", refreshToken, strings.Replace(requestData.Scope, " ", "%20", -1), requestData.ClientId, requestData.ClientSecret)

		// This is to make sure to handle tenant things for microsoft
		if strings.Contains(strings.ToLower(requestRefreshUrl), "{tenant") {
			//log.Printf("[DEBUG] Found tenant in URL: %s", url)
			tenantPos := strings.Index(strings.ToLower(requestRefreshUrl), "{tenant")

			if tenantPos >= 0 {
				tenantEnd := strings.Index(requestRefreshUrl[tenantPos:], "}")
				if tenantEnd >= 0 {
					requestRefreshUrl = requestRefreshUrl[:tenantPos] + "common" + requestRefreshUrl[tenantPos+tenantEnd+1:]
					//log.Printf("[DEBUG] Replaced tenant in URL: %s", requestRefreshUrl)
				}
			}
		}

		//log.Printf("[DEBUG] Refresh URL: %s?%s", requestRefreshUrl, refreshData)
		req, err := http.NewRequest(
			"POST",
			requestRefreshUrl,
			bytes.NewBuffer([]byte(refreshData)),
		)

		if err != nil {
			return appAuth, err
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("Accept", "application/json")
		newresp, err = client.Do(req)
		if err != nil {
			return appAuth, err
		}

		defer newresp.Body.Close()
		body, err := ioutil.ReadAll(newresp.Body)
		if err != nil {
			return appAuth, err
		}

		respBody = body

		if newresp.StatusCode >= 300 {
			// Printing on error to handle in future instances
			//log.Printf("[ERROR] Oauth2 data for %s: %#v", requestRefreshUrl, newresp)
			return appAuth, errors.New(fmt.Sprintf("Bad status code in refresh for URL (refresh) %s: %d. Message: %s", url, newresp.StatusCode, respBody))
		}

		// Overwriting auth
		newAuth := []AuthenticationStore{}
		for _, item := range appAuth.Fields {
			if item.Key == "access_token" || item.Value == "expiration" || item.Value == "expires_in" {
				continue
			}

			newAuth = append(newAuth, item)
		}

		appAuth.Fields = newAuth
	}

	if strings.Contains(string(respBody), "error") {
		//log.Printf("\n\n[ERROR] Oauth2 RESPONSE: %s\n\nencoded: %#v\n", string(respBody), v.Encode())
		log.Printf("[ERROR] Bad Oauth2 RESPONSE (%d) from %s: %s. Auth ID: %s", newresp.StatusCode, url, string(respBody), appAuth.Id)

		go CreateOrgNotification(
			context.Background(),
			fmt.Sprintf("Oauth2 error during refresh of URL %s at the start of workflow", url),
			fmt.Sprintf("Error during Oauth2 refresh (%d): %s", newresp.StatusCode, string(respBody)),
			fmt.Sprintf("/admin?admin_tab=notifications"),
			appAuth.OrgId,
			true,
			"HIGH",
			"oauth",
		)

		if newresp.StatusCode >= 300 {
			return appAuth, errors.New(fmt.Sprintf("Bad response from Oauth2 request for %s: %s", url, string(respBody)))
		}
	}

	// Check if we have an authentication token and pre-set it
	var oauthResp Oauth2Resp
	for _, field := range appAuth.Fields {
		if field.Key == "access_token" {
			oauthResp.AccessToken = field.Value
			break
		}
	}

	err = json.Unmarshal(respBody, &oauthResp)
	if err != nil {
		if len(oauthResp.AccessToken) == 0 {
			log.Printf("[ERROR] Failed unmarshaling (appauth oauth2 refresh). URL: %#v: %s. Data: %s. Trying to map to oauthResp anyway", url, respBody, err)
			changed := false
			if strings.Contains(string(respBody), "access_token") {
				for _, item := range strings.Split(string(respBody), "&") {
					if !strings.Contains(item, "=") {
						continue
					}

					changed = true
					if strings.Contains(item, "access_token") {
						oauthResp.AccessToken = strings.Split(item, "=")[1]
					}

					if strings.Contains(item, "scope") {
						oauthResp.Scope = strings.Split(item, "=")[1]
					}

					if strings.Contains(item, "token_type") {
						oauthResp.TokenType = strings.Split(item, "=")[1]
					}

					if strings.Contains(item, "refresh_token") || strings.Contains(item, "refresh") {
						oauthResp.RefreshToken = strings.Split(item, "=")[1]
					}
				}
			}

			if !changed {
				return appAuth, err
			}
		} else {
			log.Printf("[ERROR] Failed unmarshaling (appauth oauth2) (2): %s. Continuing anyway as we have an access token", err)
		}
	}

	// Need to refresh the "code"? Is that a thing?
	//log.Printf("[INFO] Response: %#v", oauthResp)

	// Cleans up the existing keys before adding new ones
	if len(oauthResp.AccessToken) > 0 {
		newauth := []AuthenticationStore{}
		for _, item := range appAuth.Fields {
			if item.Key == "access_token" {
				continue
			}

			newauth = append(newauth, item)
		}

		newauth = append(newauth, AuthenticationStore{
			Key:   "access_token",
			Value: oauthResp.AccessToken,
		})

		appAuth.Fields = newauth
	}

	/*
		if len(oauthResp.RefreshToken) > 0 {
			//log.Printf("[DEBUG] Got NEW refresh token %s", oauthResp.RefreshToken)

			newauth := []AuthenticationStore{}
			for _, item := range appAuth.Fields {
				if item.Key == "refresh_token" {
					continue
				}

				newauth = append(newauth, item)
			}

			// Tested March 2024. Works to hotswap refresh tokens
			// 4. M.C515_BL2.0.U.-Cot3MTbxsV8lXPwxLHd8Q1g1p49Mm31MamCfxBEHhXX1tGq2IDFBQ24dcX2RjC*cJW0Qdah9rO*2cEximZVVH0lBgjSEQckYrpv*9h1k1TWQCxmdatJGYjYxMVnflUtEL*dykvv4wEVvV2cdk!vSNih7BATGKrLoqB4ix38ufUjR4ynJxUcJS2hnIntqUPVHOsvXkFHncxDARAIrp7ZnvtXzR9gydhb*FkI!GaF8OIQwJgjqa7p0x8yhyJYLY0k1aAdFg8ehVsK6MzMVLB*dFQTBFzUdnF0tF09xAwsBbL0aWITXIEF*cPC5ghY07n!5H1Q8eOdcc*qOAFMQ!ov0wejM4eddXl*pytEt91IXC3b2
	*/

	if len(oauthResp.RefreshToken) > 0 {
		appAuth.Fields = append(appAuth.Fields, AuthenticationStore{
			Key:   "refresh_token",
			Value: oauthResp.RefreshToken,
		})

		//appAuth.Fields = newauth
	}

	if len(oauthUrl) > 0 {
		// Check if url already exists with a good value
		validUrl := false
		for _, item := range appAuth.Fields {
			if item.Key == "url" && len(item.Value) > 0 {
				if strings.Contains(item.Value, "https://") || strings.Contains(item.Value, "http://") {
					validUrl = true
					break
				}
			}
		}

		if !validUrl {
			log.Printf("\n\n[DEBUG] Appending Oauth2 API URL %s\n\n", oauthUrl)

			newAuth := []AuthenticationStore{}
			for _, item := range appAuth.Fields {
				if item.Key == "url" || item.Key == "expiration" {
					continue
				}

				newAuth = append(newAuth, item)
			}

			appAuth.Fields = newAuth
			appAuth.Fields = append(appAuth.Fields, AuthenticationStore{
				Key:   "url",
				Value: oauthUrl,
			})
		}
	} else {
		log.Printf("[DEBUG] No app API URL to attach to Oauth2 auth?")
	}

	// FIXME: Does this work with string?
	//https://stackoverflow.com/questions/43870554/microsoft-oauth2-authentication-not-returning-refresh-token
	parsedTime := strconv.FormatInt(int64(time.Now().Unix())+int64(oauthResp.ExpiresIn), 10)
	if oauthResp.ExpiresIn > 0 {
		newauth := []AuthenticationStore{}
		for _, item := range appAuth.Fields {
			if item.Key == "expiration" {
				continue
			}

			newauth = append(newauth, item)
		}

		newauth = append(newauth, AuthenticationStore{
			Key:   "expiration",
			Value: parsedTime,
		})

		appAuth.Fields = newauth
	}

	if len(refreshUrl) > 0 && !refresh {
		log.Printf("[DEBUG] Appending Oauth2 Refresh URL %s", refreshUrl)
		appAuth.Fields = append(appAuth.Fields, AuthenticationStore{
			Key:   "refresh_url",
			Value: refreshUrl,
		})
		//} else {
		//log.Printf("[DEBUG] No refresh URL to attach to Oauth2 auth?")
	}

	// FIXME: Set up auth for this with oauth2 in app?
	// How does this work with the SDK?
	appAuth.OrgId = user.ActiveOrg.Id
	appAuth.Defined = true
	appAuth.Active = true
	err = SetWorkflowAppAuthDatastore(ctx, appAuth, appAuth.Id)
	if err != nil {
		log.Printf("[WARNING] Failed setting up app auth %s for refresh: %s (oauth2)", appAuth.Id, err)
		return appAuth, err
	}

	//log.Printf("%#v", oauthResp)
	return appAuth, nil
}

/*
func fetchWellKnownConfig(ctx context.Context, issuer string, openIdAuthUrl string) (map[string]interface{}, error) {
	// Clean issuer URL and construct well-known endpoint
	issuer = strings.TrimSuffix(issuer, "/")
	wellKnownURL := issuer + "/.well-known/openid-configuration"

	// trying to check for keyclock edgecases
	if len(openIdAuthUrl) > 0 && openIdAuthUrl != "none" {
		openIdAuthUrl = strings.TrimSuffix(openIdAuthUrl, "/")
		if idx := strings.Index(openIdAuthUrl, "/realms/"); idx != -1 {
			realmStart := idx + len("/realms/")
			realmEnd := strings.Index(openIdAuthUrl[realmStart:], "/")
			if realmEnd != -1 {
				realmBase := openIdAuthUrl[:realmStart+realmEnd]
				wellKnownURL = realmBase + "/.well-known/openid-configuration"
			}
		}
	}

	resp, err := http.Get(wellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch well-known config from %s: %w", wellKnownURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("well-known endpoint returned status %d: %s", resp.StatusCode, wellKnownURL)
	}

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode well-known config: %w, %s", err, wellKnownURL)
	}

	return config, nil
}

// VerifyIdTokenWithOIDC verifies an ID token using the go-oidc library and extracts claims
// This performs proper signature verification via JWKS, expiry check, issuer and audience validation
func VerifyIdTokenWithOIDC(ctx context.Context, idToken string, issuer string, clientID string) (*OpenidUserinfo, error) {
	if idToken == "" {
		return nil, fmt.Errorf("id token is empty")
	}
	if issuer == "" {
		return nil, fmt.Errorf("issuer is empty")
	}
	if clientID == "" {
		return nil, fmt.Errorf("client ID is empty")
	}

	// Create OIDC provider (fetches JWKS automatically from .well-known/openid-configuration)
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider for issuer %s: %w", issuer, err)
	}

	// Create verifier with expected audience (client_id)
	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	// Verify the token (signature, expiry, issuer, audience)
	token, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Extract claims
	var claims OpenidUserinfo
	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims from ID token: %w", err)
	}

	// Set sub from the verified token
	claims.Sub = token.Subject

	return &claims, nil
}

// ExtractRolesFromIdToken verifies an ID token and extracts roles from various claim formats
// Returns a deduplicated list of roles from: roles, groups, realm_access.roles (Keycloak)
func ExtractRolesFromIdToken(ctx context.Context, idToken string, issuer string, clientID string) ([]string, error) {
	claims, err := VerifyIdTokenWithOIDC(ctx, idToken, issuer, clientID)
	if err != nil {
		return nil, err
	}

	// Collect roles from all possible sources
	roleSet := make(map[string]bool)

	for _, role := range claims.Roles {
		roleSet[role] = true
	}
	for _, group := range claims.Groups {
		roleSet[group] = true
	}
	for _, role := range claims.RealmAccess.Roles {
		roleSet[role] = true
	}

	// Convert to slice
	roles := make([]string, 0, len(roleSet))
	for role := range roleSet {
		roles = append(roles, role)
	}

	return roles, nil
}
*/

func VerifyIdToken(ctx context.Context, idToken string) (IdTokenCheck, error) {
	// Check org in nonce -> check if ID points back to an org
	outerSplit := strings.Split(string(idToken), ".")
	for _, innerstate := range outerSplit {
		log.Printf("[DEBUG] OpenID STATE (temporary): %s", innerstate)
		decoded, err := base64.StdEncoding.DecodeString(innerstate)
		if err != nil {
			log.Printf("[DEBUG] Failed base64 decode of state (1): %s", err)

			// Random padding problems
			innerstate += "="
			decoded, err = base64.StdEncoding.DecodeString(innerstate)
			if err != nil {
				log.Printf("[DEBUG] Failed base64 decode of state (2): %s", err)

				// Double padding problem fix lol (this actually works)
				innerstate += "="
				decoded, err = base64.StdEncoding.DecodeString(innerstate)
				if err != nil {
					log.Printf("[ERROR] Failed base64 decode of state (3): %s", err)
					continue
				}
			}
		}

		var token IdTokenCheck
		err = json.Unmarshal([]byte(decoded), &token)
		if err != nil {
			log.Printf("[INFO] IDToken unmarshal error: %s", err)
			continue
		}

		// Aud = client secret
		// Nonce = contains all the info
		if len(token.Aud) <= 0 {
			log.Printf("[WARNING] Couldn't find AUD in JSON (required) - continuing to check. Current: %s", string(decoded))
			continue
		}

		if len(token.Nonce) > 0 {
			parsedState, err := base64.StdEncoding.DecodeString(token.Nonce)
			if err != nil {
				log.Printf("[ERROR] Failed state split: %s", err)
			}

			foundOrg := ""
			foundChallenge := ""
			stateSplit := strings.Split(string(parsedState), "&")
			regexPattern := `EXTRA string=([A-Za-z0-9~.]+)`
			re := regexp.MustCompile(regexPattern)
			for _, innerstate := range stateSplit {
				itemsplit := strings.SplitN(innerstate, "=", 2)
				if len(itemsplit) <= 1 {
					log.Printf("[WARNING] No key:value: %s", innerstate)
					continue
				}

				key := strings.TrimSpace(itemsplit[0])
				value := strings.TrimSpace(itemsplit[1])
				if itemsplit[0] == "org" {
					foundOrg = value
				}

				if key == "challenge" {
					// Extract the "extra string" value from the challenge value
					matches := re.FindStringSubmatch(value)
					if len(matches) > 1 {
						extractedString := matches[1]
						foundChallenge = extractedString
						log.Printf("Extracted 'extra string' value is: %s", extractedString)
					} else {
						foundChallenge = strings.TrimSpace(itemsplit[1])
						log.Printf("No 'extra string' value found in challenge: %s", value)
					}
				}
			}

			if len(foundOrg) == 0 {
				log.Printf("[ERROR] No org specified in state (2)")
				return IdTokenCheck{}, err
			}
			org, err := GetOrg(ctx, foundOrg)
			if err != nil {
				log.Printf("[WARNING] Error getting org in OpenID (2): %s", err)
				return IdTokenCheck{}, err
			}
			// Validating the user itself
			if token.Aud == org.SSOConfig.OpenIdClientId || foundChallenge == org.SSOConfig.OpenIdClientSecret {
				log.Printf("[DEBUG] Correct token aud & challenge - successful login!")
				token.Org = *org
				return token, nil
			} else {
			}
		}
	}

	return IdTokenCheck{}, errors.New("Couldn't verify nonce")
}

func IsRunningInCluster() bool {
	_, existsHost := os.LookupEnv("KUBERNETES_SERVICE_HOST")
	_, existsPort := os.LookupEnv("KUBERNETES_SERVICE_PORT")
	return existsHost && existsPort
}

func GetPodName() string {
	if len(os.Getenv("MY_POD_NAME")) > 0 {
		return os.Getenv("MY_POD_NAME")
	}

	log.Printf("[DEBUG] No podname found to attach to")

	return ""
}

func GetKubernetesNamespace() (string, error) {
	namespaceFile := "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

	namespaceFilepathEnv := os.Getenv("KUBERNETES_NAMESPACE_FILEPATH")
	if namespaceFilepathEnv != "" {
		namespaceFile = namespaceFilepathEnv
	}

	file, err := os.Open(namespaceFile)
	if err != nil {
		return "", err
	}

	defer file.Close()
	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		return scanner.Text(), nil
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("namespace file is empty")
}

func GetKubernetesClient() (*kubernetes.Clientset, *rest.Config, error) {

	config := &rest.Config{}
	var err error

	/*
		// Not in use for now. This is a in-cluster override from orborus
		kubeconfigContent := os.Getenv("KUBERNETES_CONFIG")
		if len(kubeconfigContent) > 0 {
			log.Printf("[INFO] Using KUBERNETES_CONFIG to set up Kubernetes client: %#v", os.Getenv("KUBERNETES_CONFIG"))
			config, err := rest.InClusterConfig()
			if err != nil {
				log.Printf("[ERROR] Failed to create Kubernetes client from in-cluster config: %s", err)
			} else {
				// Replace client configuration with kubeconfig content
				config, err = clientcmd.RESTConfigFromKubeConfig([]byte(kubeconfigContent))
				if err != nil {
					log.Printf("[ERROR] Failed to create Kubernetes client from KUBERNETES_CONFIG: %s", err)
				} else {
					// Create Kubernetes client
					clientset, err := kubernetes.NewForConfig(config)
					if err != nil {
						return nil, config, err
					}

					return clientset, config, nil
				}
			}
		}
	*/

	// Look for the kubernetes serviceaccount path  /var/run/secrets/kubernetes.io/serviceaccount
	// If it exists, use it to create the client
	// /var/run/secrets/kubernetes.io/serviceaccount
	path := "/var/run/secrets/kubernetes.io/serviceaccount"
	if _, err := os.Stat(path); err == nil {
		//log.Printf("[DEBUG] Using service account filepath to create kubernetes client")
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, config, err
		}

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			return nil, config, err
		}

		return clientset, config, nil
	}

	if IsRunningInCluster() {
		config, err := rest.InClusterConfig()
		if err != nil {
			return nil, config, err
		}

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			return nil, config, err
		}

		return clientset, config, nil
	}

	home := homedir.HomeDir()
	kubeconfigPath := filepath.Join(home, ".kube", "config")
	config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, config, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, config, err
	}

	return clientset, config, nil
}

func GetCurrentPodNetworkConfig(ctx context.Context, clientset *kubernetes.Clientset, namespace, podName string) (*corev1.PodStatus, error) {
	pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return &pod.Status, nil
}
