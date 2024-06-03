package shuffle

// Shuffle is an automation platform for security and IT. This app and the associated scopes enables us to get information about a user, their mailbox and eventually subscribing them to send pub/sub requests to our platform to handle their emails in real-time, before controlling how to handle the data themselves.

import (
	"bytes"
	"context"
	"regexp"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"bufio"
	"strconv"

	//"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/go-querystring/query"
	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"

	"path/filepath"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

)

var handledIds []string

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

func GetOutlookBody(ctx context.Context, hook Hook, body []byte) string {
	var maildata MailDataOutlook
	err := json.Unmarshal(body, &maildata)
	if err != nil {
		log.Printf("[WARNING] Maildata unmarshal error: %s", err)
		return string(body)
	}

	hookId := hook.Id
	trigger, err := GetTriggerAuth(ctx, hookId)
	if err != nil {
		log.Printf("[WARNING] Failed getting trigger %s (callback cloud): %s", hookId, err)
		return string(body)
	}

	outlookClient, _, err := GetOutlookClient(ctx, "", trigger.OauthToken, "")
	if err != nil {
		log.Printf("[WARNING] Oauth client failure - triggerauth: %s", err)
		return string(body)
	}

	go ExtendOutlookSubscription(outlookClient, trigger.SubscriptionId)

	emails, err := GetOutlookEmail(outlookClient, maildata)
	if err != nil {
		log.Printf("[WARNING] Outlook email error - webhook transfer: %s", err)
		return string(body)
	}

	for _, email := range emails {
		if !email.Hasattachments {
			continue
		}

		list, err := GetOutlookAttachmentList(outlookClient, email.ID)
		if err != nil {
			log.Printf("[WARNING] Failed getting attachments for email ID %s", email.ID)
			continue
		}

		if len(list.Value) == 0 {
			log.Printf("[WARNING] Couldn't find attachments for email ID %s", email.ID)
			continue
		}

		for _, attachment := range list.Value {
			attachment, content, err := GetOutlookAttachment(outlookClient, email.ID, attachment.ID)
			if err != nil {
				log.Printf("[WARNING] Failed to get fileId for attachment %s", attachment.ID)
				continue
			}

			timeNow := time.Now().Unix()
			var basepath = os.Getenv("SHUFFLE_FILE_LOCATION")
			if len(basepath) == 0 {
				basepath = "files"
			}

			folderPath := fmt.Sprintf("%s/%s/%s", basepath, trigger.OrgId, trigger.WorkflowId)
			fileId := uuid.NewV4().String()
			downloadPath := fmt.Sprintf("%s/%s", folderPath, fileId)
			newFile := File{
				Id:           fileId,
				CreatedAt:    timeNow,
				UpdatedAt:    timeNow,
				Description:  fmt.Sprintf("File found in outlook message %s with ID %s. This is from an Outlook Trigger.", email.ID, attachment.ID),
				Status:       "uploading",
				Filename:     attachment.Name,
				OrgId:        trigger.OrgId,
				WorkflowId:   trigger.WorkflowId,
				DownloadPath: downloadPath,
				Subflows:     []string{},
				Namespace:    "",
				StorageArea:  "local",
			}

			if project.Environment == "cloud" {
				newFile.StorageArea = "google_storage"
			}

			err = SetFile(ctx, newFile)
			if err != nil {
				log.Printf("[WARNING] Failed setting outlook file for ID %s in message %s", fileId, email.ID)
				continue
			}

			//parsedKey := fmt.Sprintf("%s_%s", user.ActiveOrg.Id, file.Id)
			_, err = uploadFile(ctx, &newFile, "", content)
			if err != nil {
				log.Printf("[WARNING] Failed uploading outlook attachment %s in message %s", attachment.ID, email.ID)
				continue
			}

			email.FileIds = append(email.FileIds, fileId)
		}

		// FIXME: Is this break a bad thing?
		//email.FileIds = fileIds
		break
	}

	// FIXME: prevents multiple emails. Split into multiple hooks & executions?
	parsedEmail := FullEmail{}
	if len(emails) > 0 {
		parsedEmail = emails[0]
	}

	log.Printf("ATTACHMENT IDS: %d", len(parsedEmail.FileIds))

	body, err = json.Marshal(parsedEmail)
	if err != nil {
		log.Println("[WARNING] Failed to marshal data from emails: %s", err)
		return string(body)
	}

	return string(body)
}

func getOutlookProfile(client *http.Client) (OutlookProfile, error) {
	requestUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/me?$select=mail")

	ret, err := client.Get(requestUrl)
	if err != nil {
		log.Printf("[INFO] Folder error: %s", err)
		return OutlookProfile{}, err
	}

	log.Printf("[INFO] Status profile: %d", ret.StatusCode)
	body, err := ioutil.ReadAll(ret.Body)
	if err != nil {
		log.Printf("[INFO] Body: %s", err)
		return OutlookProfile{}, err
	}

	log.Printf("[INFO] BODY: %s", string(body))

	profile := OutlookProfile{}
	err = json.Unmarshal(body, &profile)
	if err != nil {
		log.Printf("Unmarshal: %s", err)
		return OutlookProfile{}, err
	}

	return profile, nil
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
	trigger.Username = fmt.Sprintf(user.Username)
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
		log.Printf("[ERROR] Failed making user %s' information public")
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

func MakeGmailSubscription(ctx context.Context, client *http.Client, folderIds []string) (SubResponse, error) {
	fullUrl := "https://www.googleapis.com/gmail/v1/users/me/watch"

	// FIXME - this expires rofl
	//t := time.Now().Local().Add(time.Minute * time.Duration(4200))
	//timeFormat := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d.0000000Z", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())

	log.Printf("[INFO] Canceling gmail subscription before remaking it")
	err := cancelGmailSubscription(ctx, client)
	if err != nil {
		log.Printf("[WARNING] Failed to cancel gmail subscription before remaking it: %s", err)
	}

	resource := "projects/shuffler/topics/gmail_testing"
	//log.Printf("[INFO] Subscription resource to get for gmail: %s", resource)
	sub := GmailSubscription{
		TopicName: resource,
		LabelIds:  folderIds,
	}
	// https://stackoverflow.com/questions/31718427/receive-gmail-push-notification-only-when-a-new-message-arrives
	// TopicName: CATEGORY_PERSONAL
	//LabelFilterAction: "exclude"

	data, err := json.Marshal(sub)
	if err != nil {
		log.Printf("[WARNING] Marshal error: %s", err)
		return SubResponse{}, err
	}

	req, err := http.NewRequest(
		"POST",
		fullUrl,
		bytes.NewBuffer(data),
	)
	req.Header.Add("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		log.Printf("[WARNING] GMAIL Client for subscription: %s", err)
		return SubResponse{}, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] Gmail subscription Body: %s", err)
		return SubResponse{}, err
	}

	//log.Printf("GMAIL RESP: %s", string(body))

	if res.StatusCode != 200 && res.StatusCode != 201 {
		log.Printf("[INFO] GMAIL Subscription Status: %d. Body: %s", res.StatusCode, string(body))
		return SubResponse{}, errors.New(fmt.Sprintf("Subscription failed: %s", string(body)))
	}

	// Use data from body here to create thingy
	newSub := SubResponse{}
	err = json.Unmarshal(body, &newSub)
	if err != nil {
		log.Printf("[WARNING] Error in JSON unmarshal for gmail client: %s", err)
		return SubResponse{}, err
	}

	log.Printf("[INFO] GMAIL Subscription created. Response (%d): %s", res.StatusCode, string(body))

	return newSub, nil
}

// https://docs.microsoft.com/en-us/previous-versions/office/office-365-api/api/version-2.0/notify-rest-operations#RenewSub
func ExtendOutlookSubscription(client *http.Client, subscriptionId string) error {
	fullUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/subscriptions/%s", subscriptionId)

	t := time.Now().Local().Add(time.Minute * time.Duration(4200))
	timeFormat := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d.0000000Z", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())

	sub := OutlookSubscription{
		ExpirationDateTime: timeFormat,
	}
	//ClientState:        "This is a test",

	data, err := json.Marshal(sub)
	if err != nil {
		log.Printf("[ERROR] Marshal problem in sub extension: %s", err)
		return err
	}

	req, err := http.NewRequest(
		"PATCH",
		fullUrl,
		bytes.NewBuffer(data),
	)
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		log.Printf("[WARNING] Client: %s", err)
		return err
	}

	//log.Printf("[INFO] Subscription Status: %d", res.StatusCode)
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("Body: %s", err)
		return err
	}

	if res.StatusCode != 200 && res.StatusCode != 201 {
		log.Printf("[ERROR] Outlook Re-subscription failed. Status: %d", res.StatusCode)
		return errors.New(fmt.Sprintf("RE-subscription failed: %s", string(body)))
	}

	return nil
}

func MakeOutlookSubscription(client *http.Client, folderIds []string, notificationURL string) (string, error) {
	fullUrl := "https://graph.microsoft.com/v1.0/subscriptions"

	// FIXME - this expires rofl
	t := time.Now().Local().Add(time.Minute * time.Duration(4200))
	timeFormat := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d.0000000Z", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())

	//resource := fmt.Sprintf("me/mailfolders('%s')/messages", strings.Join(folderIds, "','"))
	resource := fmt.Sprintf("me/mailfolders('%s')/messages", strings.Join(folderIds, "','"))
	log.Printf("[INFO] Subscription resource to get(s): %s with time %s", resource, timeFormat)
	sub := OutlookSubscription{
		ChangeType:         "created",
		ClientState:        "Shuffle subscription",
		NotificationURL:    notificationURL,
		ExpirationDateTime: timeFormat,
		Resource:           resource,
	}
	//ClientState:        "This is a test",

	data, err := json.Marshal(sub)
	if err != nil {
		log.Printf("Marshal: %s", err)
		return "", err
	}

	req, err := http.NewRequest(
		"POST",
		fullUrl,
		bytes.NewBuffer(data),
	)
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		log.Printf("Client: %s", err)
		return "", err
	}

	log.Printf("[INFO] Subscription Status: %d", res.StatusCode)
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("Body: %s", err)
		return "", err
	}

	if res.StatusCode != 200 && res.StatusCode != 201 {
		return "", errors.New(fmt.Sprintf("Subscription failed: %s", string(body)))
	}

	// Use data from body here to create thingy
	newSub := OutlookSubscription{}
	err = json.Unmarshal(body, &newSub)
	if err != nil {
		return "", err
	}

	return newSub.Id, nil
}

func removeOutlookSubscription(outlookClient *http.Client, subscriptionId string) error {
	// DELETE https://graph.microsoft.com/v1.0/subscriptions/{id}
	fullUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/subscriptions/%s", subscriptionId)
	req, err := http.NewRequest(
		"DELETE",
		fullUrl,
		nil,
	)
	req.Header.Add("Content-Type", "application/json")
	res, err := outlookClient.Do(req)
	if err != nil {
		log.Printf("Client: %s", err)
		return err
	}

	defer res.Body.Close()
	if res.StatusCode != 200 && res.StatusCode != 201 && res.StatusCode != 204 {
		return errors.New(fmt.Sprintf("Bad status code when deleting subscription: %d", res.StatusCode))
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("Body: %s", err)
		return err
	}

	_ = body

	return nil
}

func cancelGmailSubscription(ctx context.Context, gmailClient *http.Client) error {
	// bytes.NewBuffer(data)
	fullUrl := "https://www.googleapis.com/gmail/v1/users/me/stop"
	req, err := http.NewRequest(
		"POST",
		fullUrl,
		nil,
	)
	req.Header.Add("Content-Type", "application/json")
	res, err := gmailClient.Do(req)
	if err != nil {
		log.Printf("[WARNING] GMAIL Client (2): %s", err)
		return err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] Gmail subscription Body (2): %s", err)
		return err
	}

	log.Printf("[INFO] Stop subscription on GMAIL Status: %d. Resp: %s", res.StatusCode, string(body))
	//log.Printf("GMAIL RESP (%d): %s", res.StatusCode, string(body))

	if res.StatusCode != 200 && res.StatusCode != 201 && res.StatusCode != 204 {
		return errors.New(fmt.Sprintf("Subscription failed: %s", string(body)))
	}
	//notificationURL := fmt.Sprintf("%s/api/v1/hooks/webhook_%s", project.CloudUrl, trigger.Id)
	//curSubscriptions, err := getOutlookSubscriptions(outlookClient)
	//if err == nil {
	//	for _, sub := range curSubscriptions.Value {
	//		if sub.NotificationURL == notificationURL {
	//			log.Printf("[INFO] Removing subscription %s from gmail for %s", sub.Id, workflowId)
	//			removeOutlookSubscription(outlookClient, sub.Id)
	//		}
	//	}
	//} else {
	//	log.Printf("Failed to get subscriptions - need to overwrite")
	//}

	return nil
}

func HandleGmailSubRemoval(ctx context.Context, user User, workflowId, triggerId string) error {
	// 1. Get the auth for trigger
	// 2. Stop the subscription
	// 3. Remove the function
	// 4. Remove the database entry for auth
	trigger, err := GetTriggerAuth(ctx, triggerId)
	if err != nil {
		log.Printf("[WARNING] Trigger auth %s doesn't exist - gmail sub removal.", triggerId)
		return err
	}

	if project.Environment != "cloud" {
		log.Printf("[INFO] SHOULD STOP GMAIL SUB ONPREM SYNC WITH CLOUD for workflow ID %s", workflowId)
		org, err := GetOrg(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("[INFO] Failed finding org %s during gmail removal: %s", org.Id, err)
			return err
		}

		log.Printf("[INFO] Stopping cloud configuration for gmail trigger %s in org %s for workflow %s", trigger.Id, org.Id, trigger.WorkflowId)
		action := CloudSyncJob{
			Type:          "gmail",
			Action:        "stop",
			OrgId:         org.Id,
			PrimaryItemId: trigger.Id,
			SecondaryItem: trigger.Start,
			ThirdItem:     trigger.WorkflowId,
		}

		err = executeCloudAction(action, org.SyncConfig.Apikey)
		if err != nil {
			log.Printf("[INFO] Failed cloud action STOP gmail execution: %s", err)
			return err
		} else {
			log.Printf("[INFO] Successfully set STOPPED gmail execution trigger")
		}
	} else {
		log.Printf("[INFO] SHOULD STOP GMAIL SUB IN CLOUD")
	}

	// Actually delete the thing
	//redirectDomain := "localhost:5001"
	//url := fmt.Sprintf("http://%s/api/v1/triggers/outlook/register", redirectDomain)
	//gmailClient, _, err := GetGmailClient(ctx, "", trigger.OauthToken, url)
	gmailClient, err := RefreshGmailClient(ctx, *trigger)
	if err != nil {
		log.Printf("[WARNING] Oauth client failure - gmail delete: %s", err)
		return err
	}

	return cancelGmailSubscription(ctx, gmailClient)
}

// Remove AUTH
// Remove function
// Remove subscription
func HandleOutlookSubRemoval(ctx context.Context, user User, workflowId, triggerId string) error {
	// 1. Get the auth for trigger
	// 2. Stop the subscription
	// 3. Remove the function
	// 4. Remove the database entry for auth
	trigger, err := GetTriggerAuth(ctx, triggerId)
	if err != nil {
		log.Printf("Trigger auth %s doesn't exist - outlook sub removal.", triggerId)
		return err
	}

	if project.Environment != "cloud" {
		log.Printf("[INFO] SHOULD STOP OUTLOOK SUB ONPREM SYNC WITH CLOUD for workflow ID %s", workflowId)
		org, err := GetOrg(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("[INFO] Failed finding org %s during outlook removal: %s", org.Id, err)
			return err
		}

		log.Printf("[INFO] Stopping cloud configuration for trigger %s in org %s for workflow %s", trigger.Id, org.Id, trigger.WorkflowId)
		action := CloudSyncJob{
			Type:          "outlook",
			Action:        "stop",
			OrgId:         org.Id,
			PrimaryItemId: trigger.Id,
			SecondaryItem: trigger.Start,
			ThirdItem:     trigger.WorkflowId,
		}

		err = executeCloudAction(action, org.SyncConfig.Apikey)
		if err != nil {
			log.Printf("[INFO] Failed cloud action STOP outlook execution: %s", err)
			return err
		} else {
			log.Printf("[INFO] Successfully set STOPPED outlook execution trigger")
		}
	} else {
		log.Printf("[INFO] SHOULD STOP OUTLOOK SUB IN CLOUD")
	}

	// Actually delete the thing
	redirectDomain := "localhost:5001"
	url := fmt.Sprintf("http://%s/api/v1/triggers/outlook/register", redirectDomain)
	outlookClient, _, err := GetOutlookClient(ctx, "", trigger.OauthToken, url)
	if err != nil {
		log.Printf("[WARNING] Oauth client failure - outlook folders: %s", err)
		return err
	}
	notificationURL := fmt.Sprintf("%s/api/v1/hooks/webhook_%s", project.CloudUrl, trigger.Id)
	curSubscriptions, err := getOutlookSubscriptions(outlookClient)
	if err == nil {
		for _, sub := range curSubscriptions.Value {
			if sub.NotificationURL == notificationURL {
				log.Printf("[INFO] Removing subscription %s from o365 for workflow %s", sub.Id, workflowId)
				removeOutlookSubscription(outlookClient, sub.Id)
			}
		}
	} else {
		log.Printf("Failed to get subscriptions - need to overwrite")
	}

	return nil
}

func HandleDeleteGmailSub(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	location := strings.Split(request.URL.String(), "/")

	var workflowId string
	var triggerId string
	if location[1] == "api" {
		if len(location) <= 6 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		workflowId = location[4]
		triggerId = location[6]
	}

	if len(workflowId) == 0 || len(triggerId) == 0 {
		log.Printf("Ids can't be zero when deleting %s", workflowId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := GetContext(request)
	workflow, err := GetWorkflow(ctx, workflowId)
	if err != nil {
		log.Printf("[WARNING] Failed getting the workflow locally (delete outlook): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in outlook deploy: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access delete gmail sub: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	if user.Id != workflow.Owner || len(user.Id) == 0 {
		if workflow.OrgId == user.ActiveOrg.Id && user.Role == "admin" {
			log.Printf("[INFO] User %s is accessing %s as admin (delete gmail sub)", user.Username, workflow.ID)
		} else {
			log.Printf("[WARNING] Wrong user (%s) for workflow %s when deleting gmail ", user.Username, workflow.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	trigger, err := GetTriggerAuth(ctx, triggerId)
	if err != nil {
		log.Printf("[WARNING] Wrong user (%s) for workflow %s when deleting gmail (2)", user.Username, workflow.ID)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	err = HandleGmailSubRemoval(ctx, user, workflowId, triggerId)
	if err == nil {
		// FIXME: Actually delete the hook, not just the data
		DeleteKey(ctx, "gmail_subscription", trigger.AssociatedUser)

		// NOT deleting trigger, since it's just stopped, not removed
		//DeleteKey(ctx, "trigger_auth", triggerId)
	} else {
		log.Printf("[WARNING] Failed deleting gmail sub: %s", err)
	}

	err = DeleteKey(ctx, "hooks", triggerId)
	if err != nil {
		log.Printf("[ERROR] Failed deleting webhook %s - still active: %s", triggerId, err)
		//resp.WriteHeader(401)
		//resp.Write([]byte(`{"success": false, "reason": "Failed deleting webhook"}`))
		//return
	} else {
		log.Printf("[INFO] Successfully delete webhook %s!", triggerId)
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleDeleteOutlookSub(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	location := strings.Split(request.URL.String(), "/")

	var workflowId string
	var triggerId string
	if location[1] == "api" {
		if len(location) <= 6 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		workflowId = location[4]
		triggerId = location[6]
	}

	if len(workflowId) == 0 || len(triggerId) == 0 {
		log.Printf("Ids can't be zero when deleting %s", workflowId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := GetContext(request)
	workflow, err := GetWorkflow(ctx, workflowId)
	if err != nil {
		log.Printf("[WARNING] Failed getting the workflow locally (delete outlook): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in outlook delete: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to delete outlook (shared): %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	// FIXME - have a check for org etc too..
	if user.Id != workflow.Owner || len(user.Id) == 0 {
		if workflow.OrgId == user.ActiveOrg.Id && user.Role == "admin" {
			log.Printf("[INFO] User %s is accessing %s as admin (delete outlook sub)", user.Username, workflow.ID)
		} else {
			log.Printf("[WARNING] Wrong user (%s) for workflow %s when deploying outlook", user.Username, workflow.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	// Check what kind of sub it is
	err = HandleOutlookSubRemoval(ctx, user, workflowId, triggerId)
	if err != nil {
		log.Printf("[ERROR] Failed sub removal: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

// This sets up the sub with outlook itself
// Parses data from the workflow to see whether access is right to subscribe it
// Creates the cloud function for outlook return
// Wait for it to be available, then schedule a workflow to it
func HandleCreateOutlookSub(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
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

		workflowId = location[4]
	}

	ctx := GetContext(request)
	workflow, err := GetWorkflow(ctx, workflowId)
	if err != nil {
		log.Printf("[WARNING] Failed getting the workflow locally (outlook sub): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("Api authentication failed in outlook deploy: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to create outlook sub (shared): %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	// FIXME - have a check for org etc too..
	if user.Id != workflow.Owner && user.Role != "admin" {
		log.Printf("[WARNING] Wrong user (%s) for workflow %s when deploying outlook", user.Username, workflow.ID)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	log.Println("[INFO] Handle outlook subscription for trigger")

	// Should already be authorized at this point, as the workflow is shared
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Failed body read for workflow %s", workflow.ID)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Based on the input data from frontend
	type CurTrigger struct {
		Name    string   `json:"name"`
		Folders []string `json:"folders"`
		ID      string   `json:"id"`
	}

	//log.Println(string(body))
	var curTrigger CurTrigger
	err = json.Unmarshal(body, &curTrigger)
	if err != nil {
		log.Printf("Failed body read unmarshal for trigger %s", workflow.ID)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(curTrigger.Folders) == 0 {
		log.Printf("Error for %s. Choosing folders is required, currently 0", workflow.ID)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Now that it's deployed - wait a few seconds before generating:
	// 1. Oauth2 token thingies for outlook.office.com
	// 2. Set the url to have the right mailboxes (probably ID?) ("https://outlook.office.com/api/v2.0/me/mailfolders('inbox')/messages")
	// 3. Set the callback URL to be the new trigger
	// 4. Run subscription test
	// 5. Set the subscriptionId to the trigger object

	// First - lets regenerate an oauth token for outlook.office.com from the original items
	trigger, err := GetTriggerAuth(ctx, curTrigger.ID)
	if err != nil {
		log.Printf("[INFO] Trigger %s doesn't exist - outlook sub.", curTrigger.ID)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": ""}`))
		return
	}

	outlookClient, _, err := GetOutlookClient(ctx, "", trigger.OauthToken, "")
	if err != nil {
		log.Printf("[WARNING] Oauth client failure for gmail - triggerauth: %s", err)
		resp.Write([]byte(`{"success": false, "reason": ""}`))
		resp.WriteHeader(401)
		return
	}

	// Location +

	// This is here simply to let the function start
	// Usually takes 10 attempts minimum :O
	// 10 * 5 = 50 seconds. That's waaay too much :(
	notificationURL := fmt.Sprintf("%s/api/v1/hooks/webhook_%s", project.CloudUrl, trigger.Id)

	//log.Printf("\n\nNOTIFICATION URL: %s\n\n", notificationURL)
	org, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Failed finding org when setting up outlook trigger: %s", err)
		resp.Write([]byte(`{"success": false, "reason": "Failed finding your organization"}`))
		resp.WriteHeader(401)
		return

	}

	trigger.Folders = curTrigger.Folders
	if project.Environment != "cloud" {

		log.Printf("[INFO] Starting cloud configuration TO START trigger %s in org %s for workflow %s", trigger.Id, org.Id, trigger.WorkflowId)

		action := CloudSyncJob{
			Type:          "outlook",
			Action:        "start",
			OrgId:         org.Id,
			PrimaryItemId: trigger.Id,
			SecondaryItem: trigger.Start,
			ThirdItem:     workflowId,
		}

		err = executeCloudAction(action, org.SyncConfig.Apikey)
		if err != nil {
			log.Printf("[INFO] Failed cloud action START outlook execution: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
			return
		} else {
			log.Printf("[INFO] Successfully set up cloud (Hybrid) action trigger")
		}
	} else {

		hook := Hook{
			Id:        trigger.Id,
			Start:     trigger.Start,
			Workflows: []string{workflowId},
			Info: Info{
				Name:        "Used onprem",
				Description: "",
				Url:         notificationURL,
			},
			Type:   "outlook",
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
			log.Printf("[WARNING] Failed setting hook FOR OUTLOOK from CLOUD org %s: %s", org.Id, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		} else {
			log.Printf("[INFO] Successfully set up CLOUD hook FOR OUTLOOK")
		}
	}

	curSubscriptions, err := getOutlookSubscriptions(outlookClient)
	if err == nil {
		for _, sub := range curSubscriptions.Value {
			if sub.NotificationURL == notificationURL {
				log.Printf("[INFO] Removing existing subscription %s", sub.Id)
				removeOutlookSubscription(outlookClient, sub.Id)
			}
		}
	} else {
		log.Printf("[INFO] Failed to get subscriptions - need to overwrite")
	}

	maxFails := 5
	failCnt := 0
	log.Printf("[INFO] Folders: %#v", curTrigger.Folders)
	for {
		subId, err := MakeOutlookSubscription(outlookClient, curTrigger.Folders, notificationURL)
		if err != nil {
			failCnt += 1

			log.Printf("[WARNING] Failed making oauth subscription for outlook, retrying in 5 seconds: %s", err)

			time.Sleep(5 * time.Second)
			if failCnt == maxFails {
				log.Printf("[WARNING] Failed to set up subscription %d times.", maxFails)
				resp.WriteHeader(401)
				return
			}

			continue
		}

		// Set the ID somewhere here
		trigger.SubscriptionId = subId
		err = SetTriggerAuth(ctx, *trigger)
		if err != nil {
			log.Printf("[WARNING] Failed setting triggerauth (gmail): %s", err)
		}

		break
	}

	log.Printf("[INFO] Successfully handled outlook subscription for trigger %s in workflow %s", curTrigger.ID, workflow.ID)

	//log.Printf("%#v", user)
	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func GetGmailUserProfile(ctx context.Context, gmailClient *http.Client) (GmailProfile, error) {
	fullUrl := "https://gmail.googleapis.com/gmail/v1/users/me/profile"
	req, err := http.NewRequest(
		"GET",
		fullUrl,
		nil,
	)
	req.Header.Add("Content-Type", "application/json")
	res, err := gmailClient.Do(req)
	if err != nil {
		log.Printf("[WARNING] GMAIL profile (3): %s", err)
		return GmailProfile{}, err
	}

	defer res.Body.Close()
	log.Printf("[INFO] Stop subscription on GMAIL Status: %d", res.StatusCode)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] Gmail profile (3): %s", err)
		return GmailProfile{}, err
	}

	var profile GmailProfile
	err = json.Unmarshal(body, &profile)
	if err != nil {
		log.Printf("[WARNING] Failed body read unmarshal for gmail profile: %s", err)
		return GmailProfile{}, err
	}

	if len(profile.EmailAddress) == 0 {
		return GmailProfile{}, errors.New("Couldn't find your email profile")
	}

	//log.Printf("\n\nUSER BODY: %s", string(body))
	return profile, nil
}

// This sets up the sub with outlook itself
// Parses data from the workflow to see whether access is right to subscribe it
// Creates the cloud function for outlook return
// Wait for it to be available, then schedule a workflow to it
func HandleCreateGmailSub(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
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

		workflowId = location[4]
	}

	ctx := GetContext(request)
	workflow, err := GetWorkflow(ctx, workflowId)
	if err != nil {
		log.Printf("[WARNING] Failed getting the workflow locally (gmail sub): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in gmail deploy: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access create gmail sub: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	// FIXME - have a check for org etc too..
	if user.Id != workflow.Owner && user.Role != "admin" {
		log.Printf("[WARNING] Wrong user (%s) for workflow %s when deploying outlook", user.Username, workflow.ID)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	log.Println("[INFO] Handle gmail subscription for trigger!")

	// Should already be authorized at this point, as the workflow is shared
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Failed body read for workflow %s", workflow.ID)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Based on the input data from frontend
	type CurTrigger struct {
		Name    string   `json:"name"`
		Folders []string `json:"folders"`
		ID      string   `json:"id"`
	}

	//log.Println(string(body))
	var curTrigger CurTrigger
	err = json.Unmarshal(body, &curTrigger)
	if err != nil {
		log.Printf("Failed body read unmarshal for trigger %s", workflow.ID)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(curTrigger.Folders) == 0 {
		log.Printf("[WARNING] Error for %s. Choosing folders is required, currently 0", workflow.ID)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Now that it's deployed - wait a few seconds before generating:
	// 1. Oauth2 token thingies for outlook.office.com
	// 2. Set the url to have the right mailboxes (probably ID?) ("https://outlook.office.com/api/v2.0/me/mailfolders('inbox')/messages")
	// 3. Set the callback URL to be the new trigger
	// 4. Run subscription test
	// 5. Set the subscriptionId to the trigger object

	// First - lets regenerate an oauth token for outlook.office.com from the original items
	trigger, err := GetTriggerAuth(ctx, curTrigger.ID)
	if err != nil {
		log.Printf("[INFO] Trigger %s doesn't exist - gmail sub.", curTrigger.ID)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": ""}`))
		return
	}

	//gmailClient, _, err := GetGmailClient(ctx, "", trigger.OauthToken, "")
	gmailClient, err := RefreshGmailClient(ctx, *trigger)
	if err != nil {
		log.Printf("[WARNING] Oauth client failure in gmail - triggerauth: %s", err)
		resp.Write([]byte(`{"success": false, "reason": ""}`))
		resp.WriteHeader(401)
		return
	}

	userProfile, err := GetGmailUserProfile(ctx, gmailClient)
	if err != nil {
		log.Printf("[WARNING] Gmail profile grab error: %s", err)
		resp.Write([]byte(`{"success": false, "reason": "Unable to get your profile"}`))
		resp.WriteHeader(401)
		return
	}

	trigger.AssociatedUser = userProfile.EmailAddress
	trigger.Folders = curTrigger.Folders

	for {
		sub, err := MakeGmailSubscription(ctx, gmailClient, curTrigger.Folders)
		if err != nil {
			log.Printf("[WARNING] Failed making oauth subscription for gmail - cancelling request: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		// May not need a new one; could just do this in triggerId with search tbh
		newSub := SubscriptionRecipient{
			HistoryId:    sub.HistoryId,
			TriggerId:    trigger.Id,
			Edited:       int(time.Now().Unix()),
			Expiration:   sub.Expiration,
			LastSync:     int(time.Now().Unix()),
			WorkflowId:   trigger.WorkflowId,
			Startnode:    trigger.Start,
			IsCloud:      false,
			EmailAddress: userProfile.EmailAddress,
		}

		if project.Environment == "cloud" {
			newSub.IsCloud = true
		}

		log.Printf("[DEBUG] Created email subscription with ID %s. %#v", newSub.HistoryId, newSub)
		err = SetSubscriptionRecipient(ctx, newSub, newSub.EmailAddress)
		if err != nil {
			log.Printf("[WARNING] Failed setting sub ID (gmail): %s", newSub.EmailAddress)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		// Set the ID somewhere here
		trigger.SubscriptionId = sub.HistoryId

		callbackUrl := "https://shuffler.io"
		if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
			callbackUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
		}

		if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
			callbackUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
		}

		returnUrl := fmt.Sprintf("%s/api/v1/hooks/webhook_%s", callbackUrl, trigger.Id)
		hook := Hook{
			Id:        trigger.Id,
			Start:     trigger.Start,
			Workflows: []string{trigger.WorkflowId},
			Info: Info{
				Name:        "Gmail Trigger",
				Description: "",
				Url:         returnUrl,
			},
			Type:   "gmail",
			Owner:  "",
			Status: "running",
			Actions: []HookAction{
				HookAction{
					Type:  "workflow",
					Name:  "",
					Id:    trigger.WorkflowId,
					Field: "",
				},
			},
			Running:     true,
			OrgId:       user.ActiveOrg.Id,
			Environment: "onprem",
		}
		// user, err := HandleApiAuthentication(resp, request)

		if project.Environment == "cloud" {
			hook.Environment = "cloud"
		} else {

			log.Printf("[INFO] Starting cloud configuration TO START gmail trigger %s in org %s for workflow %s", trigger.Id, user.ActiveOrg.Id, trigger.WorkflowId)

			action := CloudSyncJob{
				Type:          "gmail",
				Action:        "start",
				OrgId:         user.ActiveOrg.Id,
				PrimaryItemId: trigger.Id,
				SecondaryItem: trigger.Start,
				ThirdItem:     workflowId,
			}

			org, err := GetOrg(ctx, user.ActiveOrg.Id)
			if err != nil {
				log.Printf("[INFO] Failed finding org %s during gmail setup: %s", org.Id, err)
				resp.WriteHeader(401)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed getting org"}`)))
				return
			}

			err = executeCloudAction(action, org.SyncConfig.Apikey)
			if err != nil {
				log.Printf("[INFO] Failed cloud action START gmail execution: %s", err)
				resp.WriteHeader(401)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
				return
			} else {
				log.Printf("[INFO] Successfully set up cloud (Hybrid) action trigger for gmail")
			}
		}

		err = SetTriggerAuth(ctx, *trigger)
		if err != nil {
			log.Printf("[WARNING] Failed setting triggerauth (gmail): %s", err)
		}

		log.Printf("[DEBUG] Setting hook with ID %s with URL %s", trigger.Id, returnUrl)
		err = SetHook(ctx, hook)
		if err != nil {
			log.Printf("[ERROR] Failed setting hook FOR GMAIL for org %s: %s", user.ActiveOrg.Id, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		} else {
			log.Printf("[INFO] Successfully set up onprem hook FOR gmail with URL %s", returnUrl)
		}

		break
	}

	log.Printf("[INFO] Successfully handled gmail subscription for trigger %s in workflow %s", curTrigger.ID, workflow.ID)

	//log.Printf("%#v", user)
	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
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

func GetGmailProfile(ctx context.Context, gmailClient *http.Client, userId string) (GmailHistoryStruct, error) {

	fullUrl := fmt.Sprintf("https://gmail.googleapis.com/gmail/v1/users/%s/profile", userId)
	req, err := http.NewRequest(
		"GET",
		fullUrl,
		nil,
	)

	req.Header.Add("Content-Type", "application/json")
	res, err := gmailClient.Do(req)
	if err != nil {
		log.Printf("[WARNING] GMAIL get profile (5): %s", err)
		return GmailHistoryStruct{}, err
	}

	defer res.Body.Close()
	//log.Printf("[INFO] Get history status: %d", res.StatusCode)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] Gmail get profile (6): %s", err)
		return GmailHistoryStruct{}, err
	}

	//log.Printf("Body: %s", string(body))

	//log.Printf("Body: %s", string(body))
	var history GmailHistoryStruct
	err = json.Unmarshal(body, &history)
	if err != nil {
		log.Printf("[WARNING] Failed body read unmarshal for gmail history: %s", err)
		return GmailHistoryStruct{}, err
	}

	// log.Printf("[DEBUG] HISTORY INFO: %s", string(body))
	if len(history.History) == 0 {
		return GmailHistoryStruct{}, errors.New(fmt.Sprintf("Couldn't find the history to be mapped. Maybe not consequential data: %s", string(body)))
	}

	//log.Printf("\n\nUSER BODY: %s", string(body))
	return history, nil
}

func GetGmailMessages(ctx context.Context, gmailClient *http.Client, userId string) (GmailMessagesStruct, error) {

	//&historyType=messageAdded
	//fullUrl := fmt.Sprintf("https://gmail.googleapis.com/gmail/v1/users/%s/history?startHistoryId=%s", userId, historyId)
	fullUrl := fmt.Sprintf("https://gmail.googleapis.com/gmail/v1/users/%s/messages?maxResults=5", userId)
	req, err := http.NewRequest(
		"GET",
		fullUrl,
		nil,
	)

	req.Header.Add("Content-Type", "application/json")
	res, err := gmailClient.Do(req)
	if err != nil {
		log.Printf("[WARNING] GMAIL get messages (5): %s", err)
		return GmailMessagesStruct{}, err
	}

	defer res.Body.Close()
	//log.Printf("[INFO] Get history status: %d", res.StatusCode)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] Gmail get messages (6): %s", err)
		return GmailMessagesStruct{}, err
	}

	//log.Printf("Messages: %s", string(body))
	var messages GmailMessagesStruct
	err = json.Unmarshal(body, &messages)
	if err != nil {
		log.Printf("[WARNING] Failed body read unmarshal for gmail messages: %s", err)
		return GmailMessagesStruct{}, err
	}

	// log.Printf("[DEBUG] HISTORY INFO: %s", string(body))
	/*
		if len(history.History) == 0 {
			return GmailHistoryStruct{}, errors.New(fmt.Sprintf("Couldn't find the history to be mapped. Maybe not consequential data: %s", string(body)))
		}
	*/

	//log.Printf("\n\nUSER BODY: %s", string(body))
	return messages, nil
}

func GetGmailHistory(ctx context.Context, gmailClient *http.Client, userId, historyId string) (GmailHistoryStruct, error) {

	//&historyType=messageAdded
	//fullUrl := fmt.Sprintf("https://gmail.googleapis.com/gmail/v1/users/%s/history?startHistoryId=%s", userId, historyId)
	fullUrl := fmt.Sprintf("https://gmail.googleapis.com/gmail/v1/users/%s/history?startHistoryId=%s&historyType=messageAdded&labelId=UNREAD", userId, historyId)
	req, err := http.NewRequest(
		"GET",
		fullUrl,
		nil,
	)

	req.Header.Add("Content-Type", "application/json")
	res, err := gmailClient.Do(req)
	if err != nil {
		log.Printf("[WARNING] GMAIL get history (5): %s", err)
		return GmailHistoryStruct{}, err
	}

	defer res.Body.Close()
	//log.Printf("[INFO] Get history status: %d", res.StatusCode)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] Gmail get history (6): %s", err)
		return GmailHistoryStruct{}, err
	}

	//log.Printf("Body: %s", string(body))
	var history GmailHistoryStruct
	err = json.Unmarshal(body, &history)
	if err != nil {
		log.Printf("[WARNING] Failed body read unmarshal for gmail history: %s", err)
		return GmailHistoryStruct{}, err
	}

	// log.Printf("[DEBUG] HISTORY INFO: %s", string(body))
	if len(history.History) == 0 {
		return GmailHistoryStruct{}, errors.New(fmt.Sprintf("Couldn't find the history to be mapped. Maybe not consequential data: %s", string(body)))
	}

	//log.Printf("\n\nUSER BODY: %s", string(body))
	return history, nil
}

func handleIndividualEmailUploads(ctx context.Context, gmailClient *http.Client, trigger *TriggerAuth, mail GmailMessageStruct, findHistory ParsedMessage, message MessageAddedMessage) (MessageAddedMessage, error) {

	timeNow := time.Now().Unix()
	var basepath = os.Getenv("SHUFFLE_FILE_LOCATION")
	if len(basepath) == 0 {
		basepath = "files"
	}
	folderPath := fmt.Sprintf("%s/%s/%s", basepath, trigger.OrgId, trigger.WorkflowId)
	for _, part := range mail.Payload.Parts {
		if len(part.Filename) == 0 {
			//log.Printf("[DEBUG] Skipping part number %s of email (attachments)", part.PartID)
			continue
		}

		if len(part.Body.AttachmentID) == 0 {
			log.Printf("[WARNING] PART: %#v", part)
			continue
		}

		attachment, err := GetGmailMessageAttachment(ctx, gmailClient, findHistory.EmailAddress, message.ID, part.Body.AttachmentID)
		if len(attachment.Data) == 0 {
			continue
		}

		fileId := uuid.NewV4().String()
		downloadPath := fmt.Sprintf("%s/%s", folderPath, fileId)
		newFile := File{
			Id:           fileId,
			CreatedAt:    timeNow,
			UpdatedAt:    timeNow,
			Description:  fmt.Sprintf("File found in email message %s with ID %s", message.ID, part.Body.AttachmentID),
			Status:       "uploading",
			Filename:     part.Filename,
			OrgId:        trigger.OrgId,
			WorkflowId:   trigger.WorkflowId,
			DownloadPath: downloadPath,
			Subflows:     []string{},
			Namespace:    "",
			StorageArea:  "local",
		}

		if project.Environment == "cloud" {
			newFile.StorageArea = "google_storage"
		}

		err = SetFile(ctx, newFile)
		if err != nil {
			log.Printf("[ERROR] Failed setting gmail file for ID %s in message %s (1): %s", part.Body.AttachmentID, message.ID, err)
			continue
		}

		parsedData, err := base64.URLEncoding.DecodeString(attachment.Data)
		if err != nil {
			log.Printf("[ERROR] Failed base64 decoding file bytes for attachment ID %s in message %s. Attachment size: %d. err: %s (1)", part.Body.AttachmentID, message.ID, len(attachment.Data), err)
			if len(parsedData) == 0 {
				continue
			}
		}

		_, err = uploadFile(ctx, &newFile, "", parsedData)
		if err != nil {
			log.Printf("[ERROR] Failed uploading gmail attachment %s in message %s (1): %s", part.Body.AttachmentID, message.ID, err)
			continue
		}

		log.Printf("[DEBUG] Added file ID %s for attachment %s", newFile.Id, message.ID)
		mail.FileIds = append(mail.FileIds, newFile.Id)
	}

	if len(mail.FileIds) == 0 {
		mail.FileIds = []string{}
	}

	//if mail.ID == message.ThreadID {
	mail.Type = "new"
	mappedData, err := json.Marshal(mail)
	if err != nil {
		log.Println("[WARNING] Failed to Marshal mail to send to webhook: %s", err)
		return message, err
	}

	callbackUrl := "https://shuffler.io"
	if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
		callbackUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
	}

	if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
		callbackUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
	}

	webhookUrl := fmt.Sprintf("%s/api/v1/hooks/webhook_%s", callbackUrl, trigger.Id)
	err = MakeGmailWebhookRequest(ctx, webhookUrl, mappedData)
	if err != nil {
		log.Printf("[WARNING] Failed making webhook request to %s: %s", webhookUrl, err)
	} else {
		log.Printf("[INFO] Successfully sent webhook request to %s", webhookUrl)
		//callSub = true
		//break
	}

	return message, nil
}

// Returns 200 no matter what since these are received by GOOGLE PUB/SUB
func HandleGmailRouting(resp http.ResponseWriter, request *http.Request) {
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Body read error for gmail message: %s", err)
		resp.WriteHeader(200)
		return
	}

	parsedMessage := Inputdata{}
	err = json.Unmarshal(body, &parsedMessage)
	if err != nil {
		log.Printf("[ERROR] Unmarshal error for gmail message %s: %s", string(body), err)
		resp.WriteHeader(200)
		return
	}

	//log.Printf("[DEBUG] GMAIL BODY: %s", string(body))
	parsedData, err := base64.StdEncoding.DecodeString(parsedMessage.Message.Data)
	if err != nil {
		log.Printf("[WARNING] Failed base64 decode in gmail routing: %s", err)
		resp.WriteHeader(200)
		return
	}

	//log.Printf("[DEBUG] Parsed data: %s", string(parsedData))
	findHistory := ParsedMessage{}
	err = json.Unmarshal(parsedData, &findHistory)
	if err != nil {
		log.Printf("[WARNING] Unmarshal error for gmail message (2): %s", err)
		resp.WriteHeader(200)
		return
	}

	// This History ID will match the ID that is received when the subscription is configured.
	findHistory.MessageId = parsedMessage.Message.MessageId
	ctx := GetContext(request)
	subscription, err := GetSubscriptionRecipient(ctx, findHistory.EmailAddress)
	if err != nil {
		log.Printf("[WARNING] Failed finding gmail history for email %s: %s. Cancel subscription?", findHistory.EmailAddress, err)
		resp.WriteHeader(200)
		return
	}

	trigger, err := GetTriggerAuth(ctx, subscription.TriggerId)
	if err != nil {
		log.Printf("[INFO] Trigger %s doesn't exist - message.", subscription.TriggerId)
		resp.WriteHeader(200)
		return
	}

	//log.Printf("SUB: %#v", subscription)
	//gmailClient, _, err := GetGmailClient(ctx, "", trigger.OauthToken, "")
	gmailClient, err := RefreshGmailClient(ctx, *trigger)
	if err != nil {
		log.Printf("[WARNING] Oauth client failure - gmail new msg parse: %s", err)
		resp.WriteHeader(200)
		return
	}

	// Grabbing the last ID of the user
	//log.Printf("ID: %s:%d", findHistory.EmailAddress, findHistory.HistoryId)
	gmailUserInfo := fmt.Sprintf("gmail_%s", findHistory.EmailAddress)

	// Uses cache to attempt getting the old one
	newHistoryId := ""
	cache, err := GetCache(ctx, gmailUserInfo)
	if err == nil {
		newHistoryId = string(cache.([]uint8))
	} else {
		// Syncing to find the last ID, e.g. related to a thread
		log.Printf("[DEBUG] No previous history found for %s (%d) - running without cache and finding the last email. Running full sync.", findHistory.EmailAddress, findHistory.HistoryId)

		lastMessage := GmailMessageStruct{}
		lastMessageHistory := 0
		time.Sleep(2 * time.Second)
		msgParsed, err := GetGmailMessages(ctx, gmailClient, findHistory.EmailAddress)
		if err == nil {
			handledThreads := []string{}
			for _, msg := range msgParsed.Messages {
				if !ArrayContains(handledThreads, msg.ThreadID) {
					handledThreads = append(handledThreads, msg.ThreadID)

					thread, err := GetGmailThread(ctx, gmailClient, findHistory.EmailAddress, msg.ThreadID)

					if err == nil {
						for _, message := range thread.Messages {
							/*
								parsedHistoryId, err := strconv.Atoi(message.HistoryID)
								if err != nil {
									continue
								}

								if parsedHistoryId > lastMessageHistory {
									lastMessage = message
									lastMessageHistory = parsedHistoryId
								}
							*/

							parsedTimestamp, err := strconv.Atoi(message.InternalDate)
							if err != nil {
								continue
							}

							if parsedTimestamp > lastMessageHistory {
								lastMessage = message
								lastMessageHistory = parsedTimestamp
							}
						}
					}
				}
			}
		}

		if lastMessage.HistoryID != "0" && lastMessage.HistoryID != "" {
			//newHistoryId = fmt.Sprintf(lastMessage.HistoryID)
			log.Printf("[DEBUG] Got last message: %s with snippet %s!", newHistoryId, lastMessage.Snippet)

			handledIds = append(handledIds, fmt.Sprintf("%d", findHistory.HistoryId))
			err = SetCache(ctx, gmailUserInfo, []byte(fmt.Sprintf("%d", findHistory.HistoryId)), 1440)
			if err != nil {
				log.Printf("[WARNING] Failed updating gmail user %s cache: %s (2)", gmailUserInfo, err)
			} else {

			}

			newMail, err := GetGmailMessage(ctx, gmailClient, findHistory.EmailAddress, lastMessage.ID)
			if err == nil {
				lastMessage = newMail
			} else {
				log.Printf("[ERROR] Failed to find last gmail ID WITHOUT cache: %s", err)
			}

			message := MessageAddedMessage{}
			_, err = handleIndividualEmailUploads(ctx, gmailClient, trigger, lastMessage, findHistory, message)
			if err != nil {
				log.Printf("[ERROR] Failed to handle individual gmail WITHOUT cache: %s", err)
			}

			resp.WriteHeader(200)
			return
		} else {
			newHistoryId = fmt.Sprintf("%d", findHistory.HistoryId)
		}

		log.Printf("[DEBUG] Failed getting cache for %s - setting to %d.", gmailUserInfo, findHistory.HistoryId)
	}

	//log.Printf("Found new history ID %s", newHistoryId)
	err = SetCache(ctx, gmailUserInfo, []byte(fmt.Sprintf("%d", findHistory.HistoryId)), 30)
	if err != nil {
		log.Printf("[WARNING] Failed updating gmail user %s cache: %s", gmailUserInfo, err)
	}

	if len(handledIds) >= 1000 {
		log.Printf("[DEBUG] Cleaning up 1000 Ids")
		handledIds = handledIds[900:999]
	}

	log.Printf("[DEBUG] HistoryId in request: %d. HistoryId to get: %s. Email: %s", findHistory.HistoryId, newHistoryId, findHistory.EmailAddress)

	//if !ArrayContains(handledIds, newHistoryId) {
	//if len(handledIds) >= 1000 || len(handledIds) == 0 {

	// FIXME: Is this necessary? Seems to add a lot of stability
	//time.Sleep(250 * time.Millisecond)
	history := GmailHistoryStruct{}
	history, err = GetGmailHistory(ctx, gmailClient, findHistory.EmailAddress, newHistoryId)

	if err != nil {
		log.Printf("[WARNING] Failed getting data for history update %s (%s): %s", newHistoryId, findHistory.EmailAddress, err)
		resp.WriteHeader(200)
		return
	} else {
		handledIds = append(handledIds, fmt.Sprintf("%d", findHistory.HistoryId))
	}
	//} else {
	//	log.Printf("[DEBUG] Email HistoryID %d for %s has already been handled", findHistory.HistoryId, findHistory.EmailAddress)
	//	resp.WriteHeader(200)
	//	return
	//}

	callSub := false
	handled := []string{}
	for _, item := range history.History {
		// New messages
		for _, addedMsg := range item.MessagesAdded {
			message := addedMsg.Message

			// FIXME: Could this have an overlap for each user?
			// Hurr, may lose some?
			if ArrayContains(handled, message.ID) {
				//log.Printf("[DEBUG] Email %s is already handled", message.ID)
				continue
			}

			// Suboptimal, but ok for now
			if len(handled) > 500 {
				handled = []string{}
			}
			handled = append(handled, message.ID)

			//if len(item.Messages) == 0 {
			//	log.Printf("[WARNING] No messages to handle")
			//	continue
			//}

			//if len(item.Messages) > 1 {
			//	log.Printf("[WARNING] More than 1 message: %d", len(item.Messages))
			//}
			log.Printf("[DEBUG] Sending message %s with labels %#v", message.ID, message.LabelIds)

			mail, err := GetGmailMessage(ctx, gmailClient, findHistory.EmailAddress, message.ID)
			if err != nil {
				log.Printf("[WARNING] Failed getting message: %s", err)
				continue
			}

			message, err = handleIndividualEmailUploads(ctx, gmailClient, trigger, mail, findHistory, message)
			if err != nil {
				log.Printf("[WARNING] Failed to handle individual message: %s", message)
			}
		}

		if len(item.Messages) <= 3 {
			callbackUrl := "https://shuffler.io"
			if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
				callbackUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
			}

			if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
				callbackUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
			}

			for _, message := range item.Messages {
				if ArrayContains(handled, message.ID) {
					//log.Printf("[DEBUG] Email %s is already handled", message.ID)
					continue
				}

				if len(handled) > 500 {
					handled = []string{}
				}
				handled = append(handled, message.ID)

				mail, err := GetGmailMessage(ctx, gmailClient, findHistory.EmailAddress, message.ID)
				if err != nil {
					log.Printf("[WARNING] Failed getting thread message %s: %s", message.ID, err)
					continue
				}

				timeNow := time.Now().Unix()

				var basepath = os.Getenv("SHUFFLE_FILE_LOCATION")
				if len(basepath) == 0 {
					basepath = "files"
				}
				folderPath := fmt.Sprintf("%s/%s/%s", basepath, trigger.OrgId, trigger.WorkflowId)
				for _, part := range mail.Payload.Parts {
					if len(part.Filename) == 0 {
						//log.Printf("[DEBUG] Skipping part number %s of email (attachments)", part.PartID)
						continue
					}

					if len(part.Body.AttachmentID) == 0 {
						log.Printf("[WARNING] PART: %#v", part)
						continue
					}

					attachment, err := GetGmailMessageAttachment(ctx, gmailClient, findHistory.EmailAddress, message.ID, part.Body.AttachmentID)
					if len(attachment.Data) == 0 {
						continue
					}

					fileId := uuid.NewV4().String()
					downloadPath := fmt.Sprintf("%s/%s", folderPath, fileId)
					newFile := File{
						Id:           fileId,
						CreatedAt:    timeNow,
						UpdatedAt:    timeNow,
						Description:  fmt.Sprintf("File found in email message %s with ID %s", message.ID, part.Body.AttachmentID),
						Status:       "uploading",
						Filename:     part.Filename,
						OrgId:        trigger.OrgId,
						WorkflowId:   trigger.WorkflowId,
						DownloadPath: downloadPath,
						Subflows:     []string{},
						Namespace:    "",
						StorageArea:  "local",
					}

					if project.Environment == "cloud" {
						newFile.StorageArea = "google_storage"
					}

					err = SetFile(ctx, newFile)
					if err != nil {
						log.Printf("[WARNING] Failed setting gmail file for ID %s in message %s (2)", part.Body.AttachmentID, message.ID)
						continue
					}

					parsedData, err := base64.URLEncoding.DecodeString(attachment.Data)
					if err != nil {
						log.Printf("[WARNING] Failed base64 decoding bytes %s in message %s: %s. Continuing anyway (2)", part.Body.AttachmentID, message.ID, err)
						if len(parsedData) == 0 {
							continue
						}
					}

					_, err = uploadFile(ctx, &newFile, "", parsedData)
					if err != nil {
						log.Printf("[WARNING] Failed uploading gmail attachment %s in message %s (2)", part.Body.AttachmentID, message.ID)
						continue
					}

					log.Printf("[DEBUG] Added file ID %s for attachment %s", newFile.Id, message.ID)
					mail.FileIds = append(mail.FileIds, newFile.Id)
				}

				if len(mail.FileIds) == 0 {
					mail.FileIds = []string{}
				}

				mail.Type = "thread"
				mappedData, err := json.Marshal(mail)
				if err != nil {
					log.Println("[WARNING] Failed to Marshal mail to send to webhook: %s (2)", err)
					resp.WriteHeader(401)
					continue
				}

				webhookUrl := fmt.Sprintf("%s/api/v1/hooks/webhook_%s", callbackUrl, trigger.Id)
				err = MakeGmailWebhookRequest(ctx, webhookUrl, mappedData)
				if err != nil {
					log.Printf("[WARNING] Failed making webhook request to %s: %s", webhookUrl, err)
				} else {
					log.Printf("[INFO] Successfully sent webhook request to %s", webhookUrl)
					callSub = true
				}
			}
		}
	}

	if callSub {
		MakeGmailSubscription(ctx, gmailClient, trigger.Folders)
	}

	resp.WriteHeader(200)
}

// Sending request to not complicate the use of webhooks vs non-webhooks, and dragging the execution model into shared area
func MakeGmailWebhookRequest(ctx context.Context, webhookUrl string, mappedData []byte) error {
	log.Printf("[INFO] Sending %d bytes to webhook %s", len(mappedData), webhookUrl)
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest(
		"POST",
		webhookUrl,
		bytes.NewBuffer(mappedData),
	)

	req.Header.Add("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		log.Printf("[WARNING] Failed request to webhook: %s", err)
		return err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] Gmail subscription Body: %s", err)
		return err
	}

	log.Printf("[DEBUG] Webhook RESP to %s (%d): %s", webhookUrl, res.StatusCode, string(body))
	return nil
}

func RefreshOutlookClient(ctx context.Context, auth TriggerAuth) (error) {
	// Manually recreate the oauthtoken
	conf := &oauth2.Config{
		ClientID: os.Getenv("OFFICE365_CLIENT_ID"),
		ClientSecret: os.Getenv("OFFICE365_CLIENT_SECRET"),
		Scopes: []string{
			"Mail.Read",
		},
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://login.microsoftonline.com/common/oauth2/token",
		},
	}

	// save new access_token, expiry, refresh_token to database
	trigger, err := GetTriggerAuth(ctx, auth.Id)
	if err != nil {
		log.Printf("[WARNING] Failed getting trigger auth for outlook: %s", err)
		return err
	}

	token, err := conf.TokenSource(ctx, &oauth2.Token{
		RefreshToken: auth.OauthToken.RefreshToken,
	}).Token()

	if err != nil {
		log.Printf("[WARNING] Failed getting token for outlook: %s", err)
		return err
	}

	log.Printf("[INFO] Token %s refreshed successfully from outlook. Proceeding to save..", auth.Id)

	trigger.OauthToken.AccessToken = token.AccessToken
	trigger.OauthToken.RefreshToken = token.RefreshToken
	trigger.OauthToken.Expiry = token.Expiry

	err = SetTriggerAuth(ctx, *trigger)
	if err != nil {
		log.Printf("[WARNING] Failed setting trigger auth for outlook: %s", err)
		return err
	}

	log.Printf("[INFO] Successfully refreshed outlook token for trigger %s and user %s", auth.Id, auth.Owner)

	return nil
}

func RefreshGmailClient(ctx context.Context, auth TriggerAuth) (*http.Client, error) {
	// Manually recreate the oauthtoken
	conf := &oauth2.Config{
		ClientID:     os.Getenv("GMAIL_CLIENT_ID"),
		ClientSecret: os.Getenv("GMAIL_CLIENT_SECRET"),
		Scopes: []string{
			"https://www.googleapis.com/auth/gmail.readonly",
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://accounts.google.com/o/oauth2/token",
		},
	}

	token := new(oauth2.Token)
	token.AccessToken = auth.OauthToken.AccessToken
	token.RefreshToken = auth.OauthToken.RefreshToken
	token.Expiry = auth.OauthToken.Expiry
	token.TokenType = auth.OauthToken.TokenType

	// FIXME: BAD workaround.
	token.Expiry = time.Now().Add(time.Minute * -1)

	client := conf.Client(ctx, token)
	return client, nil
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

func HandleGetGmailFolders(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[INFO] Api authentication failed in getting gmail folders: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Exchange every time hmm
	// FIXME
	// Should really just get the code from the trigger that's being used OR the user
	//log.Printf("[DEBUG] In gmail folders")
	triggerId := request.URL.Query().Get("trigger_id")
	if len(triggerId) == 0 {
		log.Println("[WARNING] No trigger_id supplied")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "No trigger ID supplied"}`))
		return
	}

	ctx := GetContext(request)
	triggerAuth, err := GetTriggerAuth(ctx, triggerId)
	if err != nil {
		log.Printf("[AUDIT] Trigger %s doesn't exist - gmail folders.", triggerId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Trigger doesn't exist."}`))
		return
	}

	if triggerAuth.OrgId != user.ActiveOrg.Id {
		log.Printf("[AUDIT] User %s is accessing trigger auth %s without permission.", user.ActiveOrg.Id, triggerId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Trigger doesn't exist."}`))
		return
	}

	//log.Printf("AUTH: %#v", triggerAuth)
	//gmailClient, _, err := GetGmailClient(ctx, "", triggerAuth.OauthToken, "")
	gmailClient, err := RefreshGmailClient(ctx, *triggerAuth)
	if err != nil {
		log.Printf("[WARNING] Oauth client failure - outlook folders: %s", err)
		resp.Write([]byte(`{"success": false, "reason": "Failed creating outlook client"}`))
		resp.WriteHeader(401)
		return
	}

	folders, err := GetGmailFolders(gmailClient)
	if err != nil {
		log.Printf("[WARNING] Failed setting gmail folders: %s", err)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting gmail folders"}`))
		resp.WriteHeader(401)
		return
	}

	b, err := json.Marshal(folders.Value)
	if err != nil {
		log.Println("[INFO] Failed to marshal folderdata")
		resp.Write([]byte(`{"success": false, "reason": "Failed decoding JSON"}`))
		resp.WriteHeader(401)
		return
	}

	resp.WriteHeader(200)
	resp.Write(b)
}

func HandleGetOutlookFolders(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[INFO] Api authentication failed in getting outlook folders: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Exchange every time hmm
	// FIXME
	// Should really just get the code from the trigger that's being used OR the user
	triggerId := request.URL.Query().Get("trigger_id")
	if len(triggerId) == 0 {
		log.Println("[WARNING] No trigger_id supplied")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "No trigger ID supplied"}`))
		return
	}

	ctx := GetContext(request)
	trigger, err := GetTriggerAuth(ctx, triggerId)
	if err != nil {
		log.Printf("[AUDIT] Trigger %s doesn't exist - outlook folders.", triggerId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Trigger doesn't exist."}`))
		return
	}

	if trigger.OrgId != user.ActiveOrg.Id {
		log.Printf("[AUDIT] User %s is accessing trigger %s without permission.", user.ActiveOrg.Id, triggerId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Trigger doesn't exist."}`))
		return
	}

	//client, accessToken, err := getOutlookClient(ctx, code, OauthToken{}, url)
	//if err != nil {
	//	log.Printf("Oauth client failure - outlook register: %s", err)
	//	resp.WriteHeader(401)
	//	return
	//}

	callbackUrl := "https://shuffler.io"
	if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
		callbackUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
	}

	if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
		callbackUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
	}

	url := fmt.Sprintf("%s/api/v1/triggers/gmail/register", callbackUrl)

	outlookClient, _, err := GetOutlookClient(ctx, "", trigger.OauthToken, url)
	if err != nil {
		log.Printf("[WARNING] Oauth client failure - outlook folders: %s", err)
		resp.Write([]byte(`{"success": false, "reason": "Failed creating outlook client"}`))
		resp.WriteHeader(400)
		return
	}

	//profile, err := getOutlookProfile(outlookClient)
	//if err != nil {
	//	log.Printf("[WARNING] Outlook profile failure: %s", err)
	//}
	//log.Printf("PROFILE: %#v", profile)

	folders, err := getOutlookFolders(outlookClient)
	if err != nil {
		log.Printf("[WARNING] Failed setting outlook folders: %s", err)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting outlook folders"}`))
		resp.WriteHeader(400)
		return
	}

	//log.Printf("Got folders: %#v", folders)
	if len(folders.Value) == 0 {
		folders.Value = []OutlookFolder{}
	}

	b, err := json.Marshal(folders.Value)
	if err != nil {
		log.Println("[INFO] Failed to marshal folderdata")
		resp.Write([]byte(`{"success": false, "reason": "Failed decoding JSON"}`))
		resp.WriteHeader(401)
		return
	}

	resp.WriteHeader(200)
	resp.Write(b)
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

	log.Printf("[DEBUG] Got %d auth fields (%s)", len(appAuth.Fields), appAuth.Id)
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

	if len(tokenUrl) == 0 || len(clientId) == 0 || len(clientSecret) == 0  {
		return appAuth, fmt.Errorf("Missing oauth2 fields. Required: token_uri, client_id, client_secret, scopes")
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

	if len(scope) > 0 {
		refreshData += fmt.Sprintf("&scope=%s", strings.Replace(scope, ",", " ", -1))
	}

	if strings.Contains(refreshData, "user_impersonation") && strings.Contains (refreshData, "azure.com") && !strings.Contains(refreshData, "resource="){
		// Add "resource" for microsoft hings
		refreshData += "&resource=https://management.azure.com"
	}


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
	if grantType == "client_credentials" {
		authHeader := fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", clientId, clientSecret))))
		req.Header.Set("Authorization", authHeader)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")
	newresp, err := client.Do(req)
	if err != nil {
		return appAuth, err
	}

	log.Printf("[DEBUG] Oauth2 application auth Response for %s: %d", tokenUrl, newresp.StatusCode)

	defer newresp.Body.Close()
	body, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		return appAuth, err
	}

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
		log.Printf("\n\n[ERROR] Oauth2 app RESPONSE: %s\n\nencoded: %#v", string(body))
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
		Key: "access_token",
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

	client := GetExternalClient(url)

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
		newresp, err := client.Do(req)
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
		//log.Printf("[DEBUG] AUTH %s Ran refresh for URL %s.", appAuth.Id, refreshUrl)

		if len(refreshToken) == 0 {
			log.Printf("[ERROR] No refresh token acquired for %s", refreshUrl)
			return appAuth, errors.New("No refresh token specified during initial auth.")
		}

		requestRefreshUrl := fmt.Sprintf("%s", refreshUrl)
		refreshData := fmt.Sprintf("grant_type=refresh_token&refresh_token=%s&scope=%s&client_id=%s&client_secret=%s", refreshToken, strings.Replace(requestData.Scope, " ", "%20", -1), requestData.ClientId, requestData.ClientSecret)

		//log.Printf("[DEBUG] Refresh URL: %s?%s", refreshUrl, refreshData)

		//log.Printf("[DEBUG] Refresh URL: %s\n", requestRefreshUrl)
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
		newresp, err := client.Do(req)
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
		log.Printf("\n\n[ERROR] Oauth2 RESPONSE: %s\n\nencoded: %#v", string(respBody), v.Encode())
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
			// respBody as queries -> oauthResp
			// access_token=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&scope=notifications%2Cproject%2Crepo%2Cuser&token_type=bearer.
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

		newauth = append(newauth, AuthenticationStore{
			Key:   "refresh_token",
			Value: oauthResp.RefreshToken,
		})

		appAuth.Fields = newauth
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
				continue
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
			if token.Aud == org.SSOConfig.OpenIdClientId && foundChallenge == org.SSOConfig.OpenIdClientSecret {
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
