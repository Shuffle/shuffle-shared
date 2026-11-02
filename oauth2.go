package shuffle

// Shuffle is an automation platform for security and IT. This app and the associated scopes enables us to get information about a user, their mailbox and eventually subscribing them to send pub/sub requests to our platform to handle their emails in real-time, before controlling how to handle the data themselves.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"

	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	uuid "github.com/satori/go.uuid"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/go-querystring/query"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

var handledIds []string

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
	client := &http.Client{}
	data := fmt.Sprintf("client_id=%s&grant_type=authorization_code&redirect_uri=%s&code=%s", clientId, redirectUri, code)

	if len(codeChallenge) > 0 {
		data += fmt.Sprintf("&code_verifier=%s", codeChallenge)
	}

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

	log.Printf("OpenID return BODY: %s (status: %d)", body, res.StatusCode)

	if res.StatusCode >= 400 {
		log.Printf("[WARNING] OpenID returned %d with body: %s", res.StatusCode, body)
		return []byte{}, fmt.Errorf("OpenID token request failed with status %d: %s", res.StatusCode, body)
	}

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
	// transport := http.DefaultTransport.(*http.Transport)
	transport := http.DefaultTransport.(*http.Transport).Clone()
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
	mimecastAuth := false
	if parsedTokenURL, err := url.Parse(tokenUrl); err == nil {
		tokenHostname := strings.ToLower(parsedTokenURL.Hostname())
		mimecastAuth = tokenHostname == "api.services.mimecast.com" || strings.HasSuffix(tokenHostname, "-api.services.mimecast.com")
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

	if grantType == "client_credentials" && mimecastAuth {
		refreshData += fmt.Sprintf("&client_id=%s", url.QueryEscape(clientId))
		refreshData += fmt.Sprintf("&client_secret=%s", url.QueryEscape(clientSecret))
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
	log.Printf("[DEBUG] Oauth2 application auth URL: %#v", tokenUrl)

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
	if grantType == "client_credentials" && !zscalerAuth && !mimecastAuth {
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
			if mimecastAuth {
				refreshData += fmt.Sprintf("&client_id=%s", url.QueryEscape(clientId))
				refreshData += fmt.Sprintf("&client_secret=%s", url.QueryEscape(clientSecret))
			}
			req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(refreshData)))
			req.ContentLength = int64(len(refreshData))

			if !zscalerAuth && !mimecastAuth {
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

	transport := http.DefaultTransport.(*http.Transport).Clone()
	// transport := http.DefaultTransport.(*http.Transport)
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
			log.Printf("[DEBUG] Failed decrypting field %s: %s", field.Key, err)
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

// IdTokenClaims represents the claims extracted from a verified ID token
func DecodeIdTokenClaims(idToken string) (*IdTokenClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid id_token: expected 3 parts, got %d", len(parts))
	}

	payload := parts[1]
	if m := len(payload) % 4; m != 0 {
		payload += strings.Repeat("=", 4-m)
	}

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode id_token payload: %w", err)
	}

	var claims IdTokenClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal id_token claims: %w", err)
	}

	return &claims, nil
}

type IdTokenClaims struct {
	Issuer        string   `json:"iss"`
	Sub           string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Roles         []string `json:"roles"`
	Groups        []string `json:"groups"`
	RealmAccess   struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"` // Keycloak format
}

// VerifyIdTokenWithOIDC verifies an ID token using the go-oidc library and extracts claims
// This performs proper signature verification via JWKS, expiry check, issuer and audience validation
func VerifyIdTokenWithOIDC(ctx context.Context, idToken string, issuer string, clientID string) (*IdTokenClaims, error) {
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
	var claims IdTokenClaims
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

// returns apikey, url based on project
func GetGeminiCredentials(ctx context.Context) (string, string, string) { 
	foundModel := "google/gemini-3.7-flash"  

	projectID := os.Getenv("SHUFFLE_GCEPROJECT")
	if len(projectID) == 0 { 
		projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
	}

	location := os.Getenv("SHUFFLE_GCE_LOCATION")
	if len(projectID) == 0 || len(location) == 0 {
		return "", "", foundModel
	}

	// 1. Get Application Default Credentials (ADC) with Cloud Platform scope
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		log.Printf("[ERROR] Failed to find GCP credentials: %v", err)
		return "", "", foundModel
	}

	// 2. TokenSource caches tokens in memory automatically.
	// Reuse this tokenSource across your entire application lifecycle.
	tok, err := creds.TokenSource.Token()
	if err != nil {
		log.Printf("[ERROR] Failed to get token from TokenSource: %v", err)
		return "", "", foundModel
	}

	parsedUrl := fmt.Sprintf("https://aiplatform.googleapis.com/v1/projects/%s/locations/%s/endpoints/openapi", projectID, location)
	return tok.AccessToken, parsedUrl, foundModel
}

// resolveOAuthBaseURL determines the canonical scheme://host for the current request,
// stripping multi-hop proxy comma-separated suffixes and trailing slashes.
func resolveOAuthBaseURL(request *http.Request) string {
	scheme := "https"
	if proto := strings.TrimSpace(request.Header.Get("X-Forwarded-Proto")); proto != "" {
		if idx := strings.Index(proto, ","); idx != -1 {
			proto = strings.TrimSpace(proto[:idx])
		}
		if proto != "" {
			scheme = strings.ToLower(proto)
		}
	} else if request.TLS == nil && (strings.HasPrefix(request.Host, "localhost") || strings.HasPrefix(request.Host, "127.0.0.1")) {
		scheme = "http"
	}

	host := strings.TrimSpace(request.Host)
	if forwardedHost := strings.TrimSpace(request.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
		if idx := strings.Index(forwardedHost, ","); idx != -1 {
			forwardedHost = strings.TrimSpace(forwardedHost[:idx])
		}
		if forwardedHost != "" {
			host = forwardedHost
		}
	}

	return strings.TrimSuffix(fmt.Sprintf("%s://%s", scheme, host), "/")
}

// normalizeOAuthIssuerURL validates and normalizes an http/https issuer URL to scheme://host.
func normalizeOAuthIssuerURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme != "https" && scheme != "http" {
		return ""
	}
	return fmt.Sprintf("%s://%s", scheme, strings.TrimSpace(u.Host))
}

// resolveProtectedResourceScopes derives the minimal, context-appropriate OAuth scopes
// for a protected resource path or URL (RFC 9728). Instead of hardcoding "workflow:edit"
// for every connection, it inspects the target resource path:
//   - /api/v1/apps/{app}/mcp, /api/v1/mcp/{app}, or /mcp/{app} -> app:<app> mcp:execute
//   - /api/v1/mcp, /mcp, /api/v1/agent, /api/v1/agents -> mcp:execute
//   - /api/v1/apps/{app}/run or /api/v1/apps/{app}/execute -> app:<app> apps:run
//   - /api/v1/apps/... -> apps:read apps:run
//   - /api/v1/workflows/.../run or /api/v1/run -> workflow:run
//   - /api/v1/workflows -> workflow:read workflow:run workflow:edit
//   - default -> mcp:execute
func appendSplitAppScopes(target string, suffixScopes ...string) []string {
	scopes := []string{}
	seen := map[string]bool{}
	for _, seg := range strings.Split(target, ",") {
		seg = strings.TrimSpace(seg)
		if seg == "" || seg == "categories" || seg == "search" || seg == "mcp" || seg == "agent" || seg == "agents" {
			continue
		}
		if strings.EqualFold(seg, "workflow-edit") || strings.EqualFold(seg, "workflow_edit") {
			if !seen["workflow:edit"] {
				seen["workflow:edit"] = true
				scopes = append(scopes, "workflow:edit")
			}
			continue
		}
		if strings.EqualFold(seg, "workflow-run") || strings.EqualFold(seg, "workflow_run") {
			if !seen["workflow:run"] {
				seen["workflow:run"] = true
				scopes = append(scopes, "workflow:run")
			}
			continue
		}
		appScope := "app:" + seg
		if !seen[appScope] {
			seen[appScope] = true
			scopes = append(scopes, appScope)
		}
	}
	for _, s := range suffixScopes {
		if !seen[s] {
			seen[s] = true
			scopes = append(scopes, s)
		}
	}
	return scopes
}

func resolveProtectedResourceScopes(resourcePathOrURL string) []string {
	clean := strings.TrimSpace(resourcePathOrURL)
	if strings.HasPrefix(clean, "http://") || strings.HasPrefix(clean, "https://") {
		if u, err := url.Parse(clean); err == nil {
			clean = u.Path
		}
	}
	clean = strings.TrimPrefix(clean, "/.well-known/oauth-protected-resource")
	clean = "/" + strings.Trim(clean, "/")
	if clean == "/" {
		return []string{"mcp:execute"}
	}

	parts := strings.Split(strings.Trim(clean, "/"), "/")

	// Check for /api/v1/apps/{app}/mcp or /api/v1/apps/{app}/run
	if len(parts) >= 4 && parts[0] == "api" && strings.HasPrefix(parts[1], "v") && parts[2] == "apps" {
		appSeg := strings.TrimSpace(parts[3])
		if len(parts) >= 5 && strings.EqualFold(parts[4], "mcp") {
			if appSeg != "" && appSeg != "categories" && appSeg != "search" {
				return appendSplitAppScopes(appSeg, "mcp:execute")
			}
			return []string{"mcp:execute"}
		}
		if len(parts) >= 5 && (strings.EqualFold(parts[4], "run") || strings.EqualFold(parts[4], "execute")) {
			if appSeg != "" && appSeg != "categories" && appSeg != "search" {
				return appendSplitAppScopes(appSeg, "apps:run")
			}
			return []string{"apps:run"}
		}
		if appSeg != "" && appSeg != "categories" && appSeg != "search" && appSeg != "summary" && appSeg != "actions" && appSeg != "authentication" {
			return appendSplitAppScopes(appSeg, "apps:read", "apps:run")
		}
		return []string{"apps:read", "apps:run"}
	}

	// Check for /api/v1/mcp/{target} or /api/v1/mcp
	if len(parts) >= 3 && parts[0] == "api" && strings.HasPrefix(parts[1], "v") && (parts[2] == "mcp" || parts[2] == "agent" || parts[2] == "agents") {
		if len(parts) >= 4 {
			target := strings.TrimSpace(parts[3])
			if target != "" && target != "mcp" && target != "agent" && target != "agents" {
				return appendSplitAppScopes(target, "mcp:execute")
			}
		}
		return []string{"mcp:execute"}
	}

	// Check for /mcp/{target} or /mcp
	if len(parts) >= 1 && (parts[0] == "mcp" || parts[0] == "agent" || parts[0] == "agents") {
		if len(parts) >= 2 {
			target := strings.TrimSpace(parts[1])
			if target != "" && target != "mcp" && target != "agent" && target != "agents" {
				return appendSplitAppScopes(target, "mcp:execute")
			}
		}
		return []string{"mcp:execute"}
	}

	// Check for /api/v1/workflows/...
	if len(parts) >= 3 && parts[0] == "api" && strings.HasPrefix(parts[1], "v") && parts[2] == "workflows" {
		if len(parts) >= 5 && (strings.EqualFold(parts[4], "run") || strings.EqualFold(parts[4], "execute")) {
			return []string{"workflow:run"}
		}
		return []string{"workflow:read", "workflow:run", "workflow:edit"}
	}

	if len(parts) >= 3 && parts[0] == "api" && strings.HasPrefix(parts[1], "v") && (parts[2] == "run" || parts[2] == "executions" || parts[2] == "streams") {
		return []string{"workflow:run", "workflow:read"}
	}

	if len(parts) >= 3 && parts[0] == "api" && strings.HasPrefix(parts[1], "v") && parts[2] == "files" {
		return []string{"files:read", "files:write"}
	}

	return []string{"mcp:execute"}
}

// resolveDefaultOAuthScope determines the smart default scope when an OAuth client or consent request
// does not explicitly provide a scope string.
func resolveDefaultOAuthScope(client *OAuthClient, resourceHint string) string {
	if client != nil {
		if clientScope := strings.TrimSpace(client.Scope); clientScope != "" {
			if client.IsDynamic || strings.HasPrefix(client.ClientID, "shuffle_client_") {
				if cleaned, _ := sanitizeDynamicOAuthScope(clientScope); cleaned != "" {
					return cleaned
				}
			} else {
				return clientScope
			}
		}
	}
	if strings.TrimSpace(resourceHint) != "" {
		inferred := resolveProtectedResourceScopes(resourceHint)
		if len(inferred) > 0 {
			return strings.Join(inferred, " ")
		}
	}
	return "mcp:execute"
}

// Handles requests to OAuth-protected resources. Point being to find if 
// oauth2 is available for what you are trying. First goal is MCP focus 
func HandleOAuthProtectedResource(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	baseURL := resolveOAuthBaseURL(request)

	prefix := "/.well-known/oauth-protected-resource"
	subPath := strings.TrimPrefix(request.URL.Path, prefix)
	subPath = strings.TrimPrefix(subPath, "/")

	resourceURL := baseURL
	if len(subPath) > 0 {
		resourceURL = fmt.Sprintf("%s/%s", baseURL, subPath)
	} else {
		// Fallback default or read from ?resource= query parameter if provided
		if target := request.URL.Query().Get("resource"); target != "" {
			resourceURL = target
		}
	}

	scopesSupported := resolveProtectedResourceScopes(subPath)
	if len(subPath) == 0 && request.URL.Query().Get("resource") != "" {
		scopesSupported = resolveProtectedResourceScopes(request.URL.Query().Get("resource"))
	}

	if len(subPath) > 0 || request.URL.Query().Get("resource") != "" {
		ctx := GetContext(request)
		joinedScopes := strings.Join(scopesSupported, " ")
		if joinedScopes != "" && joinedScopes != "mcp:execute" {
			clientIP := extractRequestClientIP(request)
			if clientIP != "" {
				_ = SetCache(ctx, "oauth_last_resource_scopes_"+clientIP, []byte(joinedScopes), 2)
			}
		}
	}

	metadata := map[string]interface{}{
		"resource":                 resourceURL,
		"scopes_supported":         scopesSupported,
		"authorization_servers":    []string{baseURL},
		"bearer_methods_supported": []string{"header"},
	}

	parsedMeta, err := json.Marshal(metadata)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal metadata: %v", err)
	}

	if debug {
		log.Printf("[DEBUG] HandleOAuthProtectedResource: %s %s. Resp: %s", request.Method, request.URL.Path, string(parsedMeta))
	}

	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(http.StatusOK)
	resp.Write(parsedMeta)
}

// Attempts to figure out the base URL of the Shuffle instance based on the request headers and environment variables.
func HandleOAuthAuthorizationServer(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	baseURL := resolveOAuthBaseURL(request)

	// Dynamic frontend URL where authorization UI lives
	frontendURL := os.Getenv("SHUFFLE_FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = os.Getenv("FRONTEND_URL")
	}

	if frontendURL == "" {
		frontendURL = "https://shuffle.security"
	}

	frontendURL = strings.TrimSuffix(frontendURL, "/")

	oauthPrefix := os.Getenv("SHUFFLE_OAUTH_API_PREFIX")
	if oauthPrefix == "" {
		oauthPrefix = "/api/v1"
	} else if oauthPrefix == "none" || oauthPrefix == "/" {
		oauthPrefix = ""
	} else {
		oauthPrefix = strings.TrimSuffix(oauthPrefix, "/")
		if !strings.HasPrefix(oauthPrefix, "/") && len(oauthPrefix) > 0 {
			oauthPrefix = "/" + oauthPrefix
		}
	}

	authEndpoint := fmt.Sprintf("%s/oauth2/authorize", baseURL)
	if os.Getenv("SHUFFLE_OAUTH_DIRECT_FRONTEND") == "true" {
		authEndpoint = fmt.Sprintf("%s/oauth2/authorize", frontendURL)
	}

	issSupported := os.Getenv("SHUFFLE_OAUTH_ISS_SUPPORTED") == "true"

	metadata := map[string]interface{}{
		"issuer":                                         baseURL,
		"authorization_endpoint":                         authEndpoint,
		"token_endpoint":                                 fmt.Sprintf("%s%s/oauth2/token", baseURL, oauthPrefix),
		"userinfo_endpoint":                              fmt.Sprintf("%s%s/oauth2/userinfo", baseURL, oauthPrefix),
		"registration_endpoint":                          fmt.Sprintf("%s%s/oauth2/register", baseURL, oauthPrefix),
		"revocation_endpoint":                            fmt.Sprintf("%s%s/oauth2/revoke", baseURL, oauthPrefix),
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":               []string{"S256"},
		"authorization_response_iss_parameter_supported": issSupported,
		"scopes_supported":                               []string{"openid", "email", "profile", "mcp:execute", "apps:read", "apps:run", "workflow:read", "workflow:run", "workflow:edit", "files:read", "files:write"},
		"claims_supported":                               []string{"sub", "email", "email_verified", "name", "preferred_username", "username", "org_id", "org_name"},
	}

	parsedMeta, err := json.Marshal(metadata)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal auth server metadata: %v", err)
	}

	if debug {
		log.Printf("[DEBUG] HandleOAuthAuthorizationServer: %s %s. Resp: %s", request.Method, request.URL.Path, string(parsedMeta))
	}

	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(http.StatusOK)
	resp.Write(parsedMeta)
}

type OAuthClientRegistrationRequest struct {
	ClientID                string   `json:"client_id,omitempty"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
	RedirectUris            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

type OAuthClientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
	RedirectUris            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at,omitempty"`
}

// HandleOAuthRegister implements OAuth 2.0 Dynamic Client Registration (RFC 7591).
// ChatGPT and other dynamic MCP clients call this endpoint to automatically register a client_id.
func HandleOAuthRegister(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	if err := ValidateRequestOverload(resp, request, 30); err != nil {
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(http.StatusTooManyRequests)
		resp.Write([]byte(`{"error": "slow_down", "error_description": "Too many requests"}`))
		return
	}

	if request.Method != "POST" {
		resp.WriteHeader(http.StatusMethodNotAllowed)
		resp.Write([]byte(`{"error": "invalid_request", "error_description": "Only POST is allowed"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		if debug {
			log.Printf("[DEBUG] HandleOAuthRegister: failed to read body: %v", err)
		}
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte(`{"error": "invalid_request", "error_description": "Failed to read body"}`))
		return
	}

	if debug {
		log.Printf("[DEBUG] HandleOAuthRegister: incoming %s %s from %s (body len: %d)", request.Method, request.URL.Path, request.RemoteAddr, len(body))
	}

	var regReq OAuthClientRegistrationRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &regReq); err != nil {
			if debug {
				log.Printf("[DEBUG] HandleOAuthRegister: failed to parse JSON: %v (raw: %s)", err, string(body))
			}
			log.Printf("[WARNING] Failed to parse OAuth client registration request: %s", err)
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "Invalid JSON format"}`))
			return
		}
	}

	if len(regReq.RedirectUris) == 0 {
		if debug {
			log.Printf("[DEBUG] HandleOAuthRegister: rejected - no redirect_uris provided in registration request")
		}
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte(`{"error": "invalid_redirect_uri", "error_description": "At least one redirect_uri is required"}`))
		return
	}

	cleanedRedirectUris := []string{}
	for _, rURI := range regReq.RedirectUris {
		trimmedURI := strings.TrimSpace(rURI)
		if trimmedURI == "" {
			continue
		}
		if !isValidConfiguredOAuthRedirectURI(trimmedURI) {
			if debug {
				log.Printf("[DEBUG] HandleOAuthRegister: rejected - invalid redirect_uri '%s' in registration request", trimmedURI)
			}
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_redirect_uri", "error_description": "All redirect_uris must use HTTPS, loopback (localhost/127.0.0.1), or a supported application URI scheme"}`))
			return
		}
		cleanedRedirectUris = append(cleanedRedirectUris, trimmedURI)
	}
	if len(cleanedRedirectUris) == 0 {
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte(`{"error": "invalid_redirect_uri", "error_description": "At least one valid redirect_uri is required"}`))
		return
	}
	regReq.RedirectUris = cleanedRedirectUris

	ctx := GetContext(request)

	// Use explicit client_id if provided, otherwise generate a unique client_id for this registration.
	// SECURITY: Never allow an unauthenticated dynamic registration request to overwrite an existing client_id!
	clientID := strings.TrimSpace(regReq.ClientID)
	if clientID != "" {
		if existing, gErr := GetOAuthClient(ctx, clientID); gErr == nil && existing != nil && existing.ClientID != "" {
			if debug {
				log.Printf("[DEBUG] HandleOAuthRegister: rejected - client_id '%s' is already registered", clientID)
			}
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_client_metadata", "error_description": "client_id is already registered"}`))
			return
		}
	} else {
		clientID = fmt.Sprintf("shuffle_client_%s", uuid.NewV4().String())
	}

	// Default grant types and response types if omitted
	if len(regReq.GrantTypes) == 0 {
		regReq.GrantTypes = []string{"authorization_code"}
	}
	if len(regReq.ResponseTypes) == 0 {
		regReq.ResponseTypes = []string{"code"}
	}
	if len(regReq.TokenEndpointAuthMethod) == 0 {
		if strings.TrimSpace(regReq.ClientSecret) != "" {
			regReq.TokenEndpointAuthMethod = "client_secret_post"
		} else {
			regReq.TokenEndpointAuthMethod = "none"
		}
	}

	now := time.Now().Unix()
	primaryRedirect := ""
	if len(regReq.RedirectUris) > 0 {
		primaryRedirect = strings.TrimSpace(regReq.RedirectUris[0])
	}
	rawClientName := strings.TrimSpace(regReq.ClientName)
	rawClientURI := strings.TrimSpace(regReq.ClientURI)
	rawLogoURI := strings.TrimSpace(regReq.LogoURI)
	regUA := strings.TrimSpace(request.Header.Get("User-Agent"))
	regOrigin := extractRequestOrigin(request)
	regIP := extractRequestClientIP(request)

	eval := EvaluateOAuthVendorIdentity(
		clientID,
		rawClientName,
		primaryRedirect,
		rawClientURI,
		rawLogoURI,
		strings.TrimSpace(regReq.SoftwareID),
		regUA,
		"",
	)

	effectiveLogoURI := rawLogoURI
	if effectiveLogoURI == "" {
		effectiveLogoURI = eval.LogoURI
	}

	sanitizedRegScope, _ := sanitizeDynamicOAuthScope(regReq.Scope)
	if sanitizedRegScope == "" && regIP != "" {
		if cachedRaw, cErr := GetCache(ctx, "oauth_last_resource_scopes_"+regIP); cErr == nil {
			if cachedBytes, ok := cachedRaw.([]byte); ok && len(cachedBytes) > 0 {
				sanitizedRegScope, _ = sanitizeDynamicOAuthScope(string(cachedBytes))
			}
		}
	}

	client := OAuthClient{
		ID:                      clientID,
		ClientID:                clientID,
		ClientName:              eval.ClientName,
		ClientURI:               rawClientURI,
		LogoURI:                 effectiveLogoURI,
		SoftwareID:              strings.TrimSpace(regReq.SoftwareID),
		SoftwareVersion:         strings.TrimSpace(regReq.SoftwareVersion),
		RedirectUris:            regReq.RedirectUris,
		GrantTypes:              regReq.GrantTypes,
		ResponseTypes:           regReq.ResponseTypes,
		TokenEndpointAuthMethod: regReq.TokenEndpointAuthMethod,
		Scope:                   sanitizedRegScope,
		CreatedAt:               now,
		IsDynamic:               true,
		VendorID:                eval.VendorID,
		VendorName:              eval.VendorName,
		ImageID:                 eval.ImageID,
		VendorVerified:          eval.VendorVerified,
		VerificationStatus:      eval.VerificationStatus,
		VerificationReason:      eval.VerificationReason,
		VerifiedDomain:          eval.VerifiedDomain,
		ClaimedVendorID:         eval.ClaimedVendorID,
		ClaimedVendorName:       eval.ClaimedVendorName,
		VendorSpoofWarning:      eval.VendorSpoofWarning,
		RawClientName:           rawClientName,
		RawRedirectURI:          primaryRedirect,
		RawClientURI:            rawClientURI,
		RawLogoURI:              rawLogoURI,
		UserAgent:               regUA,
		Origin:                  regOrigin,
		Issuer:                  resolveOAuthBaseURL(request),
		RemoteAddr:              regIP,
	}

	// Only bind OrgId / UserId on registration if the caller is actually authenticated
	if regUser, uErr := getOAuthUser(resp, request); uErr == nil && len(regUser.Id) > 0 {
		client.UserId = regUser.Id
		if regUser.ActiveOrg.Id != "" {
			client.OrgId = regUser.ActiveOrg.Id
		}
	}

	clientSecret := strings.TrimSpace(regReq.ClientSecret)
	if clientSecret != "" {
		client.ClientSecret = clientSecret
	} else if regReq.TokenEndpointAuthMethod == "client_secret_post" || regReq.TokenEndpointAuthMethod == "client_secret_basic" {
		clientSecret = fmt.Sprintf("shf_secret_%s", strings.ReplaceAll(uuid.NewV4().String(), "-", ""))
		client.ClientSecret = clientSecret
	}

	err = SetOAuthClient(ctx, client)
	if err != nil {
		log.Printf("[ERROR] Failed to save OAuth client %s: %v", clientID, err)
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(`{"error": "server_error", "error_description": "Failed to persist client registration"}`))
		return
	}

	regResp := OAuthClientRegistrationResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientName:              eval.ClientName,
		ClientURI:               client.ClientURI,
		LogoURI:                 client.LogoURI,
		SoftwareID:              client.SoftwareID,
		SoftwareVersion:         client.SoftwareVersion,
		RedirectUris:            regReq.RedirectUris,
		GrantTypes:              regReq.GrantTypes,
		ResponseTypes:           regReq.ResponseTypes,
		TokenEndpointAuthMethod: regReq.TokenEndpointAuthMethod,
		ClientIDIssuedAt:        now,
	}

	parsedResp, err := json.Marshal(regResp)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal client registration response: %v", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	if debug {
		log.Printf("[DEBUG] HandleOAuthRegister: successfully registered client '%s' (name: '%s', redirect_uris: %v, grant_types: %v, auth_method: '%s')",
			clientID, regReq.ClientName, regReq.RedirectUris, regReq.GrantTypes, regReq.TokenEndpointAuthMethod)
	}

	resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
	resp.Header().Set("Cache-Control", "no-store")
	resp.WriteHeader(http.StatusCreated)
	resp.Write(parsedResp)
}

// =============================================================================
// OAuth 2.0 / 2.1 Scope Registry & Extensible Consent Handlers
// =============================================================================

// GetSupportedOAuthScopes returns all globally known OAuth scopes supported by Shuffle.
// Extensible design: to support new features (e.g. app management, alerts, audit logs),
// simply add new scope entries here.
func GetSupportedOAuthScopes() map[string]OAuthScopeInfo {
	return map[string]OAuthScopeInfo{
		"openid": {
			Scope:       "openid",
			Name:        "OpenID Identity",
			Description: "Verify your Shuffle account identity.",
			Category:    "Identity",
		},
		"email": {
			Scope:       "email",
			Name:        "Account Email",
			Description: "Read your Shuffle account email / username.",
			Category:    "Identity",
		},
		"profile": {
			Scope:       "profile",
			Name:        "Account Profile",
			Description: "Read your Shuffle account username and organization metadata.",
			Category:    "Identity",
		},
		"mcp:execute": {
			Scope:       "mcp:execute",
			Name:        "Execute MCP Tools",
			Description: "Call and execute MCP tools, autonomous actions, and model context queries on your behalf.",
			Category:    "Model Context Protocol",
		},
		"apps:read": {
			Scope:       "apps:read",
			Name:        "Read App Integrations",
			Description: "View connected apps, OpenAPI specifications, and available action definitions.",
			Category:    "Apps",
		},
		"apps:run": {
			Scope:       "apps:run",
			Name:        "Run App Actions",
			Description: "Execute actions inside authorized apps on your behalf.",
			Category:    "Apps",
		},
		"workflow:read": {
			Scope:       "workflow:read",
			Name:        "Read Workflows",
			Description: "View existing workflows and configurations.",
			Category:    "Workflows",
		},
		"workflow:run": {
			Scope:       "workflow:run",
			Name:        "Run Workflows",
			Description: "Execute workflows and inspect execution results.",
			Category:    "Workflows",
		},
		"workflow:edit": {
			Scope:       "workflow:edit",
			Name:        "Edit Workflows",
			Description: "Create, view, and modify workflows in your organization.",
			Category:    "Workflows",
		},
		"files:read": {
			Scope:       "files:read",
			Name:        "Read Files",
			Description: "Download or view files in your organization.",
			Category:    "Files",
		},
		"files:write": {
			Scope:       "files:write",
			Name:        "Write Files",
			Description: "Upload or edit files in your organization.",
			Category:    "Files",
		},
	}
}

// ParseOAuthScopes converts a space-separated scope string into structured scope metadata.
// Edgecase: Unknown or custom scopes requested by clients fall back to a generic description
// rather than failing, ensuring future compatibility without breaking existing clients.
func ParseOAuthScopes(scopeStr string) []OAuthScopeInfo {
	supported := GetSupportedOAuthScopes()
	scopes := []OAuthScopeInfo{}
	parts := strings.Fields(strings.TrimSpace(scopeStr))
	if len(parts) == 0 {
		// Default to mcp:execute (instead of workflow:edit) if none specified
		parts = []string{"mcp:execute"}
	}

	seen := map[string]bool{}
	for _, part := range parts {
		if seen[part] {
			continue
		}
		seen[part] = true
		if info, ok := supported[part]; ok {
			scopes = append(scopes, info)
		} else if strings.HasPrefix(strings.ToLower(part), "app:") {
			appTarget := strings.TrimPrefix(part, "app:")
			scopes = append(scopes, OAuthScopeInfo{
				Scope:       part,
				Name:        fmt.Sprintf("Access App: %s", appTarget),
				Description: fmt.Sprintf("Discover and execute actions for %s via MCP or API.", appTarget),
				Category:    "Apps",
			})
		} else {
			// Edgecase: Graceful fallback for dynamically defined or custom scopes
			scopes = append(scopes, OAuthScopeInfo{
				Scope:       part,
				Name:        part,
				Description: fmt.Sprintf("Access permission for %s", part),
				Category:    "Custom",
			})
		}
	}
	return scopes
}

// getOAuthUser attempts to authenticate the user from either:
// 1. Authorization: Bearer <token/apikey>
// 2. Cookie session: session_token, __session, or shuffle_session
// Returns the authenticated User or an error if unauthenticated.
func getOAuthUser(resp http.ResponseWriter, request *http.Request) (User, error) {
	ctx := GetContext(request)

	// 1. Try standard Shuffle API authentication (Bearer token / API key)
	// Reject OAuth access tokens (shfl_...) here so special OAuth identities cannot call
	// user/admin consent or token management endpoints (/oauth2/authorize, /oauth2/tokens).
	if authHeader := request.Header.Get("Authorization"); len(authHeader) > 0 {
		trimmedBearer := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer"))
		if strings.HasPrefix(trimmedBearer, "shfl_") {
			if debug {
				log.Printf("[DEBUG] getOAuthUser: rejected OAuth access token (shfl_...) on user-only OAuth endpoint %s", request.URL.Path)
			}
			return User{}, errors.New("OAuth tokens cannot authenticate as a direct user session on this endpoint")
		}
		user, err := HandleApiAuthentication(resp, request)
		if err == nil && len(user.Id) > 0 {
			if debug {
				log.Printf("[DEBUG] getOAuthUser: authenticated via Authorization header for user '%s' (id: '%s')", user.Username, user.Id)
			}
			return user, nil
		}
		if debug {
			log.Printf("[DEBUG] getOAuthUser: Authorization header present but HandleApiAuthentication failed: %v", err)
		}
	}

	// 2. Fall back to cookie-based session tokens used by the Shuffle web frontend
	cookieNames := []string{"session_token", "__session", "shuffle_session"}
	for _, name := range cookieNames {
		cookie, cErr := request.Cookie(name)
		if cErr == nil && len(strings.TrimSpace(cookie.Value)) > 0 {
			sessionUser, sErr := GetSessionNew(ctx, strings.TrimSpace(cookie.Value))
			if sErr == nil && len(sessionUser.Id) > 0 {
				if debug {
					log.Printf("[DEBUG] getOAuthUser: authenticated via cookie '%s' for user '%s' (id: '%s')", name, sessionUser.Username, sessionUser.Id)
				}
				return sessionUser, nil
			}
			if debug {
				log.Printf("[DEBUG] getOAuthUser: cookie '%s' present but GetSessionNew failed: %v", name, sErr)
			}
		}
	}

	if debug {
		log.Printf("[DEBUG] getOAuthUser: unauthenticated - no valid Authorization header or session cookie found")
	}
	return User{}, errors.New("User is not authenticated")
}

// HandleOAuthAuthorize handles the OAuth 2.0 / 2.1 authorization and consent endpoint.
//
// Routes:
//   GET  /oauth2/authorize         - Browser navigation or API consent metadata
//   POST /oauth2/authorize         - Process user consent decision (approve/deny)
//   GET  /api/v1/oauth2/authorize  - Frontend API to fetch consent UI details
//   POST /api/v1/oauth2/authorize  - Frontend API to submit consent decision
//
// Edgecases handled & documented:
//   - Rate limiting: Prevents credential stuffing / overload on authorization endpoint
//   - CORS handling: Required for frontend SPA interactions
//   - Method check: Only GET, POST, and OPTIONS are allowed
//   - Client ID: Validates client existence in Datastore / OpenSearch
//   - Open Redirector Protection: Validates redirect_uri strictly matches pre-registered URIs
//   - Response Type: Must be 'code' (OAuth 2.1 forbids implicit 'token' flow)
//   - PKCE Mandatory: RFC 7636 code_challenge is enforced; code_challenge_method must be S256 or plain
//   - CSRF State: Preserved and echoed back in all response redirects
//   - Auth check: Detects logged-in session (cookie/Bearer); returns login redirect or 401
//   - Inactive user: Accounts that are disabled are blocked with 403 Forbidden
//   - Multi-org selection: Ensures user belongs to requested organization before code issuance
//   - Consent denial: If user clicks Cancel, redirects to client with error=access_denied
// isUserOrgAdmin checks if the user is an administrator of the specified organization.
// An admin is someone with:
// 1. user.Role == "admin" or user.Role == "global_admin"
// 2. user.SupportAccess == true
// 3. Listed in org.Users with Role == "admin"
// 4. Listed in parent org (org.CreatorOrg) with Role == "admin"
// safeGetUserForOAuth retrieves a User by ID while recovering from any uninitialized
// Datastore client panics in unit-test or cache-only environments.
func safeGetUserForOAuth(ctx context.Context, userId string) (user *User, err error) {
	if strings.TrimSpace(userId) == "" {
		return nil, errors.New("empty user id")
	}
	defer func() {
		if r := recover(); r != nil {
			user = nil
			err = fmt.Errorf("GetUser panic recovered: %v", r)
		}
	}()
	return GetUser(ctx, userId)
}

// safeGetOrgForOAuth retrieves an Org by ID while recovering from any uninitialized
// Datastore client panics in unit-test or cache-only environments.
func safeGetOrgForOAuth(ctx context.Context, orgId string) (org *Org, err error) {
	if strings.TrimSpace(orgId) == "" {
		return nil, errors.New("empty org id")
	}
	defer func() {
		if r := recover(); r != nil {
			org = nil
			err = fmt.Errorf("GetOrg panic recovered: %v", r)
		}
	}()
	return GetOrg(ctx, orgId)
}

// safeGetAppForOAuth retrieves a WorkflowApp by ID while recovering from any uninitialized
// Datastore/OpenSearch panics in unit-test or cache-only environments.
func safeGetAppForOAuth(ctx context.Context, appId string, user User) (app *WorkflowApp, err error) {
	appId = strings.TrimSpace(appId)
	if appId == "" {
		return nil, errors.New("empty app id")
	}
	for _, ck := range []string{fmt.Sprintf("workflowapp_%s", appId), appId} {
		if cached, cerr := GetCache(ctx, ck); cerr == nil && cached != nil {
			if cacheData, ok := cached.([]uint8); ok && len(cacheData) > 0 {
				var cachedApp WorkflowApp
				if uerr := json.Unmarshal(cacheData, &cachedApp); uerr == nil && cachedApp.ID != "" {
					return &cachedApp, nil
				}
			}
		}
	}
	defer func() {
		if r := recover(); r != nil {
			app = nil
			err = fmt.Errorf("GetApp panic recovered: %v", r)
		}
	}()
	return GetApp(ctx, appId, user, false)
}

// safeFindAppByNameForOAuth searches for a WorkflowApp by name/slug while recovering from panics.
func safeFindAppByNameForOAuth(ctx context.Context, name string) (apps []WorkflowApp, err error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("empty app name")
	}
	defer func() {
		if r := recover(); r != nil {
			apps = nil
			err = fmt.Errorf("FindWorkflowAppByName panic recovered: %v", r)
		}
	}()
	return FindWorkflowAppByName(ctx, name)
}

// resolveSingleOAuthApp attempts to resolve an app identifier (32-char ID, "app:<id>:<slug>", or name/slug)
// into a WorkflowApp. If the app is not found in storage, it returns a synthetic fallback WorkflowApp
// so the user still sees the requested app target and its default MCP tool.
func resolveSingleOAuthApp(ctx context.Context, user User, rawTarget string) *WorkflowApp {
	target := strings.TrimSpace(rawTarget)
	target = strings.TrimPrefix(target, "app:")
	target = strings.TrimPrefix(target, "apps:")
	if target == "" || target == "*" || target == "all" || target == "mcp" {
		return nil
	}

	appIDCandidate := target
	slugCandidate := ""
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		appIDCandidate = strings.TrimSpace(parts[0])
		if len(parts) > 1 {
			slugCandidate = strings.TrimSpace(parts[1])
		}
	}

	if len(appIDCandidate) == 32 || len(appIDCandidate) == 36 {
		if found, err := safeGetAppForOAuth(ctx, appIDCandidate, user); err == nil && found != nil && found.ID != "" {
			return found
		}
	}

	lookupName := slugCandidate
	if lookupName == "" {
		lookupName = appIDCandidate
	}
	if lookupName != "" {
		if candidates, err := safeFindAppByNameForOAuth(ctx, lookupName); err == nil && len(candidates) > 0 {
			for i := range candidates {
				if len(candidates[i].Actions) > 0 && (strings.EqualFold(candidates[i].Name, lookupName) || strings.EqualFold(strings.ReplaceAll(candidates[i].Name, " ", "_"), lookupName) || candidates[i].ID == appIDCandidate) {
					return &candidates[i]
				}
			}
			for i := range candidates {
				if len(candidates[i].Actions) > 0 {
					return &candidates[i]
				}
			}
			return &candidates[0]
		}
	}

	// Synthetic fallback so the OAuth consent and settings UI always display the chosen app even if
	// the app catalog is not loaded in memory.
	displayName := lookupName
	if displayName == "" {
		displayName = target
	}
	displayName = strings.ReplaceAll(displayName, "_", " ")
	displayName = strings.ReplaceAll(displayName, "-", " ")
	words := strings.Fields(displayName)
	for i, w := range words {
		if len(w) > 0 && len(w) != 32 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	if len(words) > 0 {
		displayName = strings.Join(words, " ")
	}
	return &WorkflowApp{
		ID:          appIDCandidate,
		Name:        displayName,
		Description: fmt.Sprintf("Authorized Shuffle integration for %s.", displayName),
	}
}

// ConvertMCPToolsToOAuthPermissions maps MCPTool definitions from HandleMCPMethodInitialize into
// OAuthToolPermission entries, optionally filtering by allowedTools if non-empty.
func ConvertMCPToolsToOAuthPermissions(tools []MCPTool, appID, appName string, allowedTools []string) []OAuthToolPermission {
	perms := []OAuthToolPermission{}
	for _, t := range tools {
		if len(allowedTools) > 0 && !IsToolAllowedForOAuth(allowedTools, t.Name, appID, appName) {
			continue
		}
		readOnly := false
		destructive := false
		if t.Annotations != nil {
			if t.Annotations.ReadOnlyHint != nil {
				readOnly = *t.Annotations.ReadOnlyHint
			}
			if t.Annotations.DestructiveHint != nil {
				destructive = *t.Annotations.DestructiveHint
			}
		}
		perms = append(perms, OAuthToolPermission{
			Name:        t.Name,
			Title:       t.Title,
			Description: t.Description,
			AppID:       appID,
			AppName:     appName,
			ReadOnly:    readOnly,
			Destructive: destructive,
		})
	}
	return perms
}

// IsToolAllowedForOAuth checks whether a specific MCP tool name is permitted by the allowedTools list.
// If allowedTools is empty or contains "*", all tools are permitted.
// Entries in allowedTools can be either "<tool_name>" or "<app_id_or_name>:<tool_name>".
func IsToolAllowedForOAuth(allowedTools []string, toolName, appID, appName string) bool {
	if len(allowedTools) == 0 {
		return true
	}
	toolLower := strings.ToLower(strings.TrimSpace(toolName))
	if toolLower == "" {
		return true
	}
	appIDLower := strings.ToLower(strings.TrimSpace(appID))
	appNameLower := strings.ToLower(strings.TrimSpace(appName))
	appSlugLower := strings.ReplaceAll(appNameLower, " ", "_")

	for _, entry := range allowedTools {
		entryLower := strings.ToLower(strings.TrimSpace(entry))
		if entryLower == "*" || entryLower == "all" {
			return true
		}
		if entryLower == toolLower {
			return true
		}
		if strings.Contains(entryLower, ":") {
			parts := strings.SplitN(entryLower, ":", 2)
			prefix := strings.TrimSpace(parts[0])
			suffix := strings.TrimSpace(parts[1])
			if suffix == toolLower || suffix == "*" {
				if prefix == "" || prefix == appIDLower || prefix == appNameLower || prefix == appSlugLower {
					return true
				}
			}
		}
	}
	return false
}

// ResolveOAuthAppsAndTools resolves the requested apps and their individual MCP tools from
// the OAuth scope string, explicit allowedApps list, and optional resource URL hint.
// It also enriches the returned OAuthScopeInfo slice so app:<id> scopes show the resolved app name and tool count.
func ResolveOAuthAppsAndTools(ctx context.Context, user User, scopeStr string, allowedApps []string, allowedTools []string, resourceHint string) ([]OAuthAppPermission, []OAuthScopeInfo) {
	effectiveScope := scopeStr
	if strings.TrimSpace(effectiveScope) == "" && strings.TrimSpace(resourceHint) != "" {
		inferred := resolveProtectedResourceScopes(resourceHint)
		if len(inferred) > 0 {
			effectiveScope = strings.Join(inferred, " ")
		}
	}

	rawTargets := []string{}
	addRawTarget := func(t string) {
		for _, sub := range strings.Split(t, ",") {
			sub = strings.TrimSpace(sub)
			sub = strings.TrimPrefix(sub, "app:")
			sub = strings.TrimPrefix(sub, "apps:")
			if sub != "" && sub != "*" && sub != "all" && sub != "mcp" && !ArrayContains(rawTargets, sub) {
				rawTargets = append(rawTargets, sub)
			}
		}
	}

	for _, a := range allowedApps {
		addRawTarget(a)
	}
	for _, a := range parseAllowedAppsFromScope(effectiveScope) {
		addRawTarget(a)
	}
	if strings.TrimSpace(resourceHint) != "" {
		for _, s := range resolveProtectedResourceScopes(resourceHint) {
			if strings.HasPrefix(s, "app:") {
				addRawTarget(strings.TrimPrefix(s, "app:"))
			}
		}
	}

	appPerms := []OAuthAppPermission{}
	seenAppIDs := map[string]bool{}
	targetToAppPerm := map[string]OAuthAppPermission{}

	for _, target := range rawTargets {
		resolvedApp := resolveSingleOAuthApp(ctx, user, target)
		if resolvedApp == nil {
			continue
		}
		dedupKey := strings.ToLower(strings.TrimSpace(resolvedApp.ID))
		if dedupKey == "" {
			dedupKey = strings.ToLower(strings.TrimSpace(resolvedApp.Name))
		}
		if seenAppIDs[dedupKey] {
			continue
		}
		seenAppIDs[dedupKey] = true

		initResp, err := HandleMCPMethodInitialize(MCPRequest{}, user, *resolvedApp)
		var toolPerms []OAuthToolPermission
		if err == nil {
			toolPerms = ConvertMCPToolsToOAuthPermissions(initResp.Result.Tools, resolvedApp.ID, resolvedApp.Name, allowedTools)
		}

		img := strings.TrimSpace(resolvedApp.LargeImage)
		if img == "" {
			img = strings.TrimSpace(resolvedApp.SmallImage)
		}
		desc := strings.TrimSpace(resolvedApp.Description)
		if len(desc) > 220 {
			desc = strings.TrimSpace(desc[:217]) + "..."
		}

		perm := OAuthAppPermission{
			ID:          resolvedApp.ID,
			Name:        resolvedApp.Name,
			Image:       img,
			Description: desc,
			Tools:       toolPerms,
		}
		appPerms = append(appPerms, perm)
		targetToAppPerm[strings.ToLower(target)] = perm
		if resolvedApp.ID != "" {
			targetToAppPerm[strings.ToLower(resolvedApp.ID)] = perm
		}
		if resolvedApp.Name != "" {
			targetToAppPerm[strings.ToLower(resolvedApp.Name)] = perm
			targetToAppPerm[strings.ToLower(strings.ReplaceAll(resolvedApp.Name, " ", "_"))] = perm
		}
	}

	scopes := ParseOAuthScopes(effectiveScope)
	for i, sc := range scopes {
		if strings.HasPrefix(strings.ToLower(sc.Scope), "app:") {
			rawApp := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(sc.Scope, "app:")))
			if strings.Contains(rawApp, ":") {
				rawApp = strings.Split(rawApp, ":")[0]
			}
			if perm, ok := targetToAppPerm[rawApp]; ok && perm.Name != "" {
				toolCount := len(perm.Tools)
				if toolCount > 0 {
					scopes[i].Name = fmt.Sprintf("Access App: %s (%d tools)", perm.Name, toolCount)
					toolNames := []string{}
					for idx, tp := range perm.Tools {
						if idx >= 4 {
							break
						}
						label := tp.Title
						if label == "" {
							label = tp.Name
						}
						toolNames = append(toolNames, label)
					}
					summary := strings.Join(toolNames, ", ")
					if toolCount > 4 {
						summary += fmt.Sprintf(", and %d more", toolCount-4)
					}
					scopes[i].Description = fmt.Sprintf("Execute %d MCP tools in %s (%s).", toolCount, perm.Name, summary)
				} else {
					scopes[i].Name = fmt.Sprintf("Access App: %s", perm.Name)
					scopes[i].Description = fmt.Sprintf("Discover and execute actions for %s via MCP or API.", perm.Name)
				}
			}
		}
	}

	return appPerms, scopes
}

// RecordMCPTokenAppAndTools records the resolved WorkflowApp and MCP tools onto an active OAuthToken
// when an MCP client initializes or lists tools on an app-specific MCP endpoint.
func RecordMCPTokenAppAndTools(ctx context.Context, accessToken string, app WorkflowApp, tools []MCPTool) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" || !strings.HasPrefix(accessToken, "shfl_") {
		return
	}
	if app.ID == "" && app.Name == "" && len(tools) == 0 {
		return
	}

	tok, err := GetOAuthToken(ctx, accessToken)
	if err != nil || tok == nil || tok.AccessToken == "" {
		return
	}

	toolPerms := ConvertMCPToolsToOAuthPermissions(tools, app.ID, app.Name, tok.AllowedTools)
	appID := strings.TrimSpace(app.ID)
	appName := strings.TrimSpace(app.Name)
	if appName == "" {
		appName = "Shuffle MCP"
	}
	if appID == "" {
		appID = strings.ToLower(strings.ReplaceAll(appName, " ", "_"))
	}

	img := strings.TrimSpace(app.LargeImage)
	if img == "" {
		img = strings.TrimSpace(app.SmallImage)
	}
	desc := strings.TrimSpace(app.Description)
	if len(desc) > 220 {
		desc = strings.TrimSpace(desc[:217]) + "..."
	}

	newPerm := OAuthAppPermission{
		ID:          appID,
		Name:        appName,
		Image:       img,
		Description: desc,
		Tools:       toolPerms,
	}

	updated := false
	foundExisting := false
	for i, existing := range tok.AppPermissions {
		if (appID != "" && strings.EqualFold(existing.ID, appID)) || (appName != "" && strings.EqualFold(existing.Name, appName)) {
			foundExisting = true
			if len(existing.Tools) != len(newPerm.Tools) || existing.Name != newPerm.Name {
				tok.AppPermissions[i] = newPerm
				updated = true
			}
			break
		}
	}
	if !foundExisting {
		tok.AppPermissions = append(tok.AppPermissions, newPerm)
		updated = true
	}

	if app.ID != "" || app.Name != "" {
		targetIdentifier := app.Name
		if targetIdentifier == "" {
			targetIdentifier = app.ID
		}
		if len(tok.AllowedApps) == 0 {
			tok.AllowedApps = []string{targetIdentifier}
			updated = true
		}
		appScopeToken := "app:" + strings.ToLower(strings.ReplaceAll(targetIdentifier, " ", "_"))
		if !strings.Contains(strings.ToLower(tok.Scope), "app:") {
			if strings.TrimSpace(tok.Scope) == "" {
				tok.Scope = appScopeToken + " mcp:execute"
			} else {
				tok.Scope = appScopeToken + " " + strings.TrimSpace(tok.Scope)
			}
			updated = true
		}
	}

	if updated {
		_ = SetOAuthToken(ctx, *tok)
	}
}

func isUserOrgAdmin(ctx context.Context, user User, orgId string) bool {
	if (user.ActiveOrg.Id == orgId && user.Role == "admin") || user.SupportAccess {
		return true
	}

	if orgId == "" {
		return false
	}

	org, err := safeGetOrgForOAuth(ctx, orgId)
	if err != nil || org == nil {
		return false
	}

	for _, orgUser := range org.Users {
		if (orgUser.Id == user.Id || (len(user.Username) > 0 && orgUser.Username == user.Username)) && orgUser.Role == "admin" {
			return true
		}
	}

	if org.CreatorOrg != "" && org.CreatorOrg != orgId {
		parentOrg, pErr := safeGetOrgForOAuth(ctx, org.CreatorOrg)
		if pErr == nil && parentOrg != nil {
			for _, orgUser := range parentOrg.Users {
				if (orgUser.Id == user.Id || (len(user.Username) > 0 && orgUser.Username == user.Username)) && orgUser.Role == "admin" {
					return true
				}
			}
		}
	}

	return false
}

// isLoopbackURI checks whether a URI is a local loopback address (127.0.0.1, localhost, or [::1]).
func isLoopbackURI(rawURI string) bool {
	rawURI = strings.TrimSpace(rawURI)
	if rawURI == "" {
		return false
	}
	u, err := url.Parse(rawURI)
	if err != nil {
		return false
	}
	hostname := strings.ToLower(u.Hostname())
	return hostname == "127.0.0.1" || hostname == "localhost" || hostname == "::1"
}

// isMatchingLoopbackURI verifies if two loopback URIs match according to RFC 8252 Section 7.3
// (allowing any dynamic port allocation on loopback interfaces).
func isMatchingLoopbackURI(uriA, uriB string) bool {
	if !isLoopbackURI(uriA) || !isLoopbackURI(uriB) {
		return false
	}
	uA, errA := url.Parse(strings.TrimSpace(uriA))
	uB, errB := url.Parse(strings.TrimSpace(uriB))
	if errA != nil || errB != nil {
		return false
	}
	return uA.Path == uB.Path
}

// isDynamicShuffleClient determines if the client ID or redirect URI corresponds to a Shuffle Agent
// or dynamic native loopback client.
func isDynamicShuffleClient(clientID, redirectURI string) bool {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return false
	}
	if strings.HasPrefix(clientID, "shuffle_client_") || clientID == "shuffle-agent" || strings.Contains(clientID, "shuffle_agent") {
		return true
	}
	if isLoopbackURI(redirectURI) && (strings.Contains(strings.ToLower(clientID), "shuffle") || strings.Contains(strings.ToLower(clientID), "agent")) {
		return true
	}
	return false
}

// OAuthVendorSpec defines a known OAuth / MCP client vendor, its canonical display metadata,
// image mapping, and official callback domains/schemes used for anti-spoofing verification.
type OAuthVendorSpec struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	VendorName      string   `json:"vendor_name"`
	ImageID         string   `json:"image_id"`
	LogoURI         string   `json:"logo_uri"`
	OfficialDomains []string `json:"official_domains"`
	OfficialSchemes []string `json:"official_schemes"`
	ClaimKeywords   []string `json:"claim_keywords"`
	CloudOnly       bool     `json:"cloud_only"`
}

// OAuthVendorEvaluation holds the cross-referenced result of comparing a client's claimed identity
// against its cryptographic/network callback URI.
type OAuthVendorEvaluation struct {
	ClientName         string `json:"client_name"`
	DisplayName        string `json:"display_name"`
	VendorID           string `json:"vendor_id"`
	VendorName         string `json:"vendor_name"`
	ImageID            string `json:"image_id"`
	LogoURI            string `json:"logo_uri"`
	VendorVerified     bool   `json:"vendor_verified"`
	VerificationStatus string `json:"verification_status"` // "verified", "loopback", "mismatch", "unverified"
	VerificationReason string `json:"verification_reason"`
	VerifiedDomain     string `json:"verified_domain,omitempty"`
	ClaimedVendorID    string `json:"claimed_vendor_id,omitempty"`
	ClaimedVendorName  string `json:"claimed_vendor_name,omitempty"`
	VendorSpoofWarning string `json:"vendor_spoof_warning,omitempty"`
}

// sanitizeDynamicOAuthScope removes superuser wildcard scopes ("*", "admin", "all") from a scope string
// requested by a dynamic OAuth2 client, returning the cleaned scope string and whether any forbidden
// superuser scope was stripped.
func sanitizeDynamicOAuthScope(scopeStr string) (string, bool) {
	parts := strings.Fields(strings.TrimSpace(scopeStr))
	if len(parts) == 0 {
		return "", false
	}
	cleaned := []string{}
	stripped := false
	for _, p := range parts {
		lower := strings.ToLower(strings.TrimSpace(p))
		if lower == "*" || lower == "admin" || lower == "all" {
			stripped = true
			continue
		}
		cleaned = append(cleaned, p)
	}
	return strings.Join(cleaned, " "), stripped
}

// canAppendDynamicRedirectURI determines whether an existing OAuth client is allowed to accept
// and append a new redirectURI that was not in its initial client.RedirectUris slice.
// Security policy:
//   - If the client has no registered RedirectUris yet, allow if valid.
//   - If the client is a loopback client ("shuffle-agent" or registered solely with loopback URIs)
//     and the new redirectURI is also a loopback URI, allow (for local MCP tools changing callback paths/ports).
//   - If the client is a domain-verified vendor (e.g. ChatGPT on chatgpt.com) and the new redirectURI
//     is ALSO verified to belong to the exact same official vendor (e.g. chat.openai.com), allow.
//   - Never allow an existing client to append an arbitrary cross-domain redirect_uri (prevents redirect_uri hijacking).
func canAppendDynamicRedirectURI(client *OAuthClient, redirectURI string) bool {
	if client == nil || !isValidConfiguredOAuthRedirectURI(redirectURI) {
		return false
	}
	if len(client.RedirectUris) == 0 {
		return true
	}
	if isLoopbackURI(redirectURI) {
		allLoopback := true
		for _, r := range client.RedirectUris {
			if !isLoopbackURI(r) {
				allLoopback = false
				break
			}
		}
		if allLoopback || client.ClientID == "shuffle-agent" || strings.Contains(client.ClientID, "shuffle_agent") {
			return true
		}
	}
	if client.VendorVerified && client.VendorID != "" {
		redirectVendor, _, _ := matchVendorByRedirectURI(redirectURI)
		if redirectVendor != nil && strings.EqualFold(redirectVendor.VendorName, client.VendorName) {
			return true
		}
	}
	return false
}

// GetOAuthVendorRegistry returns the canonical registry of MCP and OAuth vendors,
// mapping each vendor to its official callback domains, URI schemes, and shared image identifier.
func GetOAuthVendorRegistry() []OAuthVendorSpec {
	return []OAuthVendorSpec{
		{
			ID:              "chatgpt",
			Name:            "ChatGPT",
			VendorName:      "OpenAI",
			ImageID:         "OpenAI",
			LogoURI:         "https://www.google.com/s2/favicons?domain=chatgpt.com&sz=128",
			OfficialDomains: []string{"chatgpt.com", "chat.openai.com", "openai.com", "platform.openai.com", "api.openai.com"},
			OfficialSchemes: []string{"chatgpt", "openai"},
			ClaimKeywords:   []string{"chatgpt", "openai", "gpt-actions", "openai-mcp"},
			CloudOnly:       true,
		},
		{
			ID:              "claude_code",
			Name:            "Claude Code",
			VendorName:      "Anthropic",
			ImageID:         "Anthropic",
			LogoURI:         "https://www.google.com/s2/favicons?domain=claude.ai&sz=128",
			OfficialDomains: []string{"claude.ai", "anthropic.com", "console.anthropic.com", "api.anthropic.com"},
			OfficialSchemes: []string{"claude-code", "claude"},
			ClaimKeywords:   []string{"claude-code", "claude code", "claudecode"},
			CloudOnly:       false,
		},
		{
			ID:              "claude",
			Name:            "Claude",
			VendorName:      "Anthropic",
			ImageID:         "Anthropic",
			LogoURI:         "https://www.google.com/s2/favicons?domain=claude.ai&sz=128",
			OfficialDomains: []string{"claude.ai", "anthropic.com", "console.anthropic.com", "api.anthropic.com"},
			OfficialSchemes: []string{"claude", "anthropic"},
			ClaimKeywords:   []string{"claude", "anthropic", "claude-ai", "claude-desktop"},
			CloudOnly:       false,
		},
		{
			ID:              "gemini",
			Name:            "Google Gemini",
			VendorName:      "Google",
			ImageID:         "Google Gemini",
			LogoURI:         "https://www.google.com/s2/favicons?domain=gemini.google.com&sz=128",
			OfficialDomains: []string{"gemini.google.com", "aistudio.google.com", "makersuite.google.com", "vertexai.google.com", "console.cloud.google.com", "googleapis.com", "google.com"},
			OfficialSchemes: []string{"gemini", "google-gemini"},
			ClaimKeywords:   []string{"gemini", "google gemini", "aistudio", "vertexai", "vertex ai", "makersuite", "gemini-cli"},
			CloudOnly:       false,
		},
		{
			ID:              "cursor",
			Name:            "Cursor",
			VendorName:      "Anysphere",
			ImageID:         "Cursor",
			LogoURI:         "https://www.google.com/s2/favicons?domain=cursor.com&sz=128",
			OfficialDomains: []string{"cursor.com", "cursor.sh", "anysphere.inc"},
			OfficialSchemes: []string{"cursor", "cursor-agent"},
			ClaimKeywords:   []string{"cursor", "anysphere", "cursor-mcp", "cursor-vscode"},
			CloudOnly:       false,
		},
		{
			ID:              "vscode",
			Name:            "VS Code",
			VendorName:      "Microsoft",
			ImageID:         "Visual Studio Code",
			LogoURI:         "https://www.google.com/s2/favicons?domain=code.visualstudio.com&sz=128",
			OfficialDomains: []string{"vscode.dev", "insiders.vscode.dev", "code.visualstudio.com", "visualstudio.com"},
			OfficialSchemes: []string{"vscode", "vscode-insiders", "code-oss"},
			ClaimKeywords:   []string{"vscode", "visual studio code", "vs code", "vscode-insiders"},
			CloudOnly:       false,
		},
		{
			ID:              "copilot",
			Name:            "GitHub Copilot",
			VendorName:      "GitHub",
			ImageID:         "GitHub",
			LogoURI:         "https://www.google.com/s2/favicons?domain=github.com&sz=128",
			OfficialDomains: []string{"github.com", "githubcopilot.com", "api.githubcopilot.com", "copilot.github.com"},
			OfficialSchemes: []string{"github-copilot", "github"},
			ClaimKeywords:   []string{"github copilot", "github-copilot", "githubcopilot", "copilot", "github"},
			CloudOnly:       false,
		},
		{
			ID:              "microsoft_copilot",
			Name:            "Microsoft Copilot",
			VendorName:      "Microsoft",
			ImageID:         "Microsoft Copilot",
			LogoURI:         "https://www.google.com/s2/favicons?domain=copilot.microsoft.com&sz=128",
			OfficialDomains: []string{"copilot.microsoft.com", "microsoft.com", "azure.com", "office.com", "botframework.com", "powerplatform.com", "powerautomate.com"},
			OfficialSchemes: []string{"mscopilot", "ms-copilot"},
			ClaimKeywords:   []string{"microsoft copilot", "copilot studio", "m365 copilot", "power platform"},
			CloudOnly:       true,
		},
		{
			ID:              "windsurf",
			Name:            "Windsurf",
			VendorName:      "Codeium",
			ImageID:         "Windsurf",
			LogoURI:         "https://www.google.com/s2/favicons?domain=windsurf.com&sz=128",
			OfficialDomains: []string{"windsurf.com", "windsurf.ai", "codeium.com", "exafunction.com"},
			OfficialSchemes: []string{"windsurf", "windsurf-next", "codeium"},
			ClaimKeywords:   []string{"windsurf", "codeium", "exafunction"},
			CloudOnly:       false,
		},
		{
			ID:              "raycast",
			Name:            "Raycast",
			VendorName:      "Raycast",
			ImageID:         "Raycast",
			LogoURI:         "https://www.google.com/s2/favicons?domain=raycast.com&sz=128",
			OfficialDomains: []string{"raycast.com", "www.raycast.com"},
			OfficialSchemes: []string{"raycast"},
			ClaimKeywords:   []string{"raycast"},
			CloudOnly:       false,
		},
		{
			ID:              "cline",
			Name:            "Cline",
			VendorName:      "Cline",
			ImageID:         "Cline",
			LogoURI:         "https://www.google.com/s2/favicons?domain=cline.bot&sz=128",
			OfficialDomains: []string{"cline.bot", "app.cline.bot"},
			OfficialSchemes: []string{"cline"},
			ClaimKeywords:   []string{"cline", "claude-dev", "saoudrizwan.claude-dev"},
			CloudOnly:       false,
		},
		{
			ID:              "roocode",
			Name:            "Roo Code",
			VendorName:      "Roo Code",
			ImageID:         "Roo Code",
			LogoURI:         "https://www.google.com/s2/favicons?domain=roocode.com&sz=128",
			OfficialDomains: []string{"roocode.com", "app.roocode.com"},
			OfficialSchemes: []string{"roocode", "roo-cline"},
			ClaimKeywords:   []string{"roo code", "roocode", "roo-cline", "rooveterinaryinc.roo-cline"},
			CloudOnly:       false,
		},
		{
			ID:              "continue",
			Name:            "Continue",
			VendorName:      "Continue",
			ImageID:         "Continue",
			LogoURI:         "https://www.google.com/s2/favicons?domain=continue.dev&sz=128",
			OfficialDomains: []string{"continue.dev", "hub.continue.dev"},
			OfficialSchemes: []string{"continue"},
			ClaimKeywords:   []string{"continue.dev", "continue-mcp", "continuedev"},
			CloudOnly:       false,
		},
		{
			ID:              "zed",
			Name:            "Zed",
			VendorName:      "Zed Industries",
			ImageID:         "Zed",
			LogoURI:         "https://www.google.com/s2/favicons?domain=zed.dev&sz=128",
			OfficialDomains: []string{"zed.dev"},
			OfficialSchemes: []string{"zed"},
			ClaimKeywords:   []string{"zed", "zed.dev", "zed-industries"},
			CloudOnly:       false,
		},
		{
			ID:              "goose",
			Name:            "Goose",
			VendorName:      "Block",
			ImageID:         "Goose",
			LogoURI:         "https://www.google.com/s2/favicons?domain=block.xyz&sz=128",
			OfficialDomains: []string{"block.xyz", "squareup.com"},
			OfficialSchemes: []string{"goose"},
			ClaimKeywords:   []string{"goose", "codename-goose", "block-goose", "mcp-goose"},
			CloudOnly:       false,
		},
		{
			ID:              "perplexity",
			Name:            "Perplexity",
			VendorName:      "Perplexity AI",
			ImageID:         "Perplexity",
			LogoURI:         "https://www.google.com/s2/favicons?domain=perplexity.ai&sz=128",
			OfficialDomains: []string{"perplexity.ai", "www.perplexity.ai", "labs.perplexity.ai"},
			OfficialSchemes: []string{"perplexity"},
			ClaimKeywords:   []string{"perplexity", "perplexity.ai", "pplx"},
			CloudOnly:       true,
		},
		{
			ID:              "mistral",
			Name:            "Mistral Le Chat",
			VendorName:      "Mistral AI",
			ImageID:         "Mistral",
			LogoURI:         "https://www.google.com/s2/favicons?domain=mistral.ai&sz=128",
			OfficialDomains: []string{"mistral.ai", "chat.mistral.ai", "console.mistral.ai"},
			OfficialSchemes: []string{"mistral", "lechat"},
			ClaimKeywords:   []string{"mistral", "le chat", "lechat", "codestral"},
			CloudOnly:       true,
		},
		{
			ID:              "grok",
			Name:            "Grok",
			VendorName:      "xAI",
			ImageID:         "xAI",
			LogoURI:         "https://www.google.com/s2/favicons?domain=x.ai&sz=128",
			OfficialDomains: []string{"grok.com", "x.ai", "console.x.ai", "x.com"},
			OfficialSchemes: []string{"grok", "xai"},
			ClaimKeywords:   []string{"grok", "x.ai", "xai"},
			CloudOnly:       true,
		},
		{
			ID:              "deepseek",
			Name:            "DeepSeek",
			VendorName:      "DeepSeek",
			ImageID:         "DeepSeek",
			LogoURI:         "https://www.google.com/s2/favicons?domain=deepseek.com&sz=128",
			OfficialDomains: []string{"deepseek.com", "chat.deepseek.com", "platform.deepseek.com"},
			OfficialSchemes: []string{"deepseek"},
			ClaimKeywords:   []string{"deepseek"},
			CloudOnly:       true,
		},
		{
			ID:              "lovable",
			Name:            "Lovable",
			VendorName:      "Lovable",
			ImageID:         "Lovable",
			LogoURI:         "https://www.google.com/s2/favicons?domain=lovable.dev&sz=128",
			OfficialDomains: []string{"lovable.dev", "lovable.app", "gptengineer.app"},
			OfficialSchemes: []string{"lovable"},
			ClaimKeywords:   []string{"lovable", "lovable.dev", "gptengineer"},
			CloudOnly:       true,
		},
		{
			ID:              "bolt",
			Name:            "Bolt.new",
			VendorName:      "StackBlitz",
			ImageID:         "Bolt",
			LogoURI:         "https://www.google.com/s2/favicons?domain=bolt.new&sz=128",
			OfficialDomains: []string{"bolt.new", "stackblitz.com"},
			OfficialSchemes: []string{"bolt", "stackblitz"},
			ClaimKeywords:   []string{"bolt.new", "stackblitz"},
			CloudOnly:       true,
		},
		{
			ID:              "v0",
			Name:            "v0",
			VendorName:      "Vercel",
			ImageID:         "Vercel",
			LogoURI:         "https://www.google.com/s2/favicons?domain=v0.dev&sz=128",
			OfficialDomains: []string{"v0.dev", "v0.app", "vercel.com", "sdk.vercel.ai"},
			OfficialSchemes: []string{"v0", "vercel"},
			ClaimKeywords:   []string{"v0.dev", "vercel"},
			CloudOnly:       true,
		},
		{
			ID:              "replit",
			Name:            "Replit",
			VendorName:      "Replit",
			ImageID:         "Replit",
			LogoURI:         "https://www.google.com/s2/favicons?domain=replit.com&sz=128",
			OfficialDomains: []string{"replit.com", "replit.app"},
			OfficialSchemes: []string{"replit"},
			ClaimKeywords:   []string{"replit", "replit-agent"},
			CloudOnly:       true,
		},
		{
			ID:              "devin",
			Name:            "Devin",
			VendorName:      "Cognition",
			ImageID:         "Devin",
			LogoURI:         "https://www.google.com/s2/favicons?domain=devin.ai&sz=128",
			OfficialDomains: []string{"devin.ai", "app.devin.ai", "cognition.ai"},
			OfficialSchemes: []string{"devin"},
			ClaimKeywords:   []string{"devin", "cognition", "devin.ai"},
			CloudOnly:       true,
		},
		{
			ID:              "amazon_q",
			Name:            "Amazon Q / Kiro",
			VendorName:      "AWS",
			ImageID:         "AWS",
			LogoURI:         "https://www.google.com/s2/favicons?domain=aws.amazon.com&sz=128",
			OfficialDomains: []string{"aws.amazon.com", "kiro.dev", "amazon.com", "amazonaws.com"},
			OfficialSchemes: []string{"kiro", "amazon-q", "aws"},
			ClaimKeywords:   []string{"amazon q", "amazon-q", "kiro", "kiro.dev", "aws-q"},
			CloudOnly:       false,
		},
		{
			ID:              "jetbrains",
			Name:            "JetBrains AI",
			VendorName:      "JetBrains",
			ImageID:         "JetBrains",
			LogoURI:         "https://www.google.com/s2/favicons?domain=jetbrains.com&sz=128",
			OfficialDomains: []string{"jetbrains.com", "account.jetbrains.com"},
			OfficialSchemes: []string{"jetbrains", "idea", "pycharm", "webstorm", "goland", "clion", "rider", "phpstorm", "rubymine", "rustrover"},
			ClaimKeywords:   []string{"jetbrains", "junie", "intellij", "pycharm", "webstorm", "goland"},
			CloudOnly:       false,
		},
		{
			ID:              "sourcegraph",
			Name:            "Sourcegraph Amp / Cody",
			VendorName:      "Sourcegraph",
			ImageID:         "Sourcegraph",
			LogoURI:         "https://www.google.com/s2/favicons?domain=sourcegraph.com&sz=128",
			OfficialDomains: []string{"sourcegraph.com", "ampcode.com"},
			OfficialSchemes: []string{"sourcegraph", "cody", "amp"},
			ClaimKeywords:   []string{"sourcegraph", "cody", "ampcode"},
			CloudOnly:       false,
		},
		{
			ID:              "warp",
			Name:            "Warp",
			VendorName:      "Warp",
			ImageID:         "Warp",
			LogoURI:         "https://www.google.com/s2/favicons?domain=warp.dev&sz=128",
			OfficialDomains: []string{"warp.dev", "app.warp.dev"},
			OfficialSchemes: []string{"warp"},
			ClaimKeywords:   []string{"warp", "warp.dev", "warp-terminal"},
			CloudOnly:       false,
		},
		{
			ID:              "librechat",
			Name:            "LibreChat",
			VendorName:      "LibreChat",
			ImageID:         "LibreChat",
			LogoURI:         "https://www.google.com/s2/favicons?domain=librechat.ai&sz=128",
			OfficialDomains: []string{"librechat.ai"},
			OfficialSchemes: []string{"librechat"},
			ClaimKeywords:   []string{"librechat"},
			CloudOnly:       false,
		},
		{
			ID:              "open_webui",
			Name:            "Open WebUI",
			VendorName:      "Open WebUI",
			ImageID:         "Open WebUI",
			LogoURI:         "https://www.google.com/s2/favicons?domain=openwebui.com&sz=128",
			OfficialDomains: []string{"openwebui.com"},
			OfficialSchemes: []string{"open-webui", "openwebui"},
			ClaimKeywords:   []string{"open-webui", "openwebui", "open webui"},
			CloudOnly:       false,
		},
		{
			ID:              "anythingllm",
			Name:            "AnythingLLM",
			VendorName:      "Mintplex Labs",
			ImageID:         "AnythingLLM",
			LogoURI:         "https://www.google.com/s2/favicons?domain=anythingllm.com&sz=128",
			OfficialDomains: []string{"anythingllm.com", "useanything.com"},
			OfficialSchemes: []string{"anythingllm"},
			ClaimKeywords:   []string{"anythingllm", "anything-llm"},
			CloudOnly:       false,
		},
		{
			ID:              "cherry_studio",
			Name:            "Cherry Studio",
			VendorName:      "Cherry Studio",
			ImageID:         "Cherry Studio",
			LogoURI:         "https://www.google.com/s2/favicons?domain=cherry-ai.com&sz=128",
			OfficialDomains: []string{"cherry-ai.com", "cherrystudio.ai"},
			OfficialSchemes: []string{"cherrystudio", "cherry-studio"},
			ClaimKeywords:   []string{"cherry studio", "cherrystudio", "cherry-studio"},
			CloudOnly:       false,
		},
		{
			ID:              "lmstudio",
			Name:            "LM Studio",
			VendorName:      "LM Studio",
			ImageID:         "LM Studio",
			LogoURI:         "https://www.google.com/s2/favicons?domain=lmstudio.ai&sz=128",
			OfficialDomains: []string{"lmstudio.ai"},
			OfficialSchemes: []string{"lmstudio", "lm-studio"},
			ClaimKeywords:   []string{"lm studio", "lmstudio", "lm-studio"},
			CloudOnly:       false,
		},
		{
			ID:              "ollama",
			Name:            "Ollama",
			VendorName:      "Ollama",
			ImageID:         "Ollama",
			LogoURI:         "https://www.google.com/s2/favicons?domain=ollama.com&sz=128",
			OfficialDomains: []string{"ollama.com"},
			OfficialSchemes: []string{"ollama"},
			ClaimKeywords:   []string{"ollama"},
			CloudOnly:       false,
		},
		{
			ID:              "jan",
			Name:            "Jan",
			VendorName:      "Jan AI",
			ImageID:         "Jan",
			LogoURI:         "https://www.google.com/s2/favicons?domain=jan.ai&sz=128",
			OfficialDomains: []string{"jan.ai"},
			OfficialSchemes: []string{"jan"},
			ClaimKeywords:   []string{"jan.ai", "jan-ai"},
			CloudOnly:       false,
		},
		{
			ID:              "msty",
			Name:            "Msty",
			VendorName:      "Msty",
			ImageID:         "Msty",
			LogoURI:         "https://www.google.com/s2/favicons?domain=msty.app&sz=128",
			OfficialDomains: []string{"msty.app"},
			OfficialSchemes: []string{"msty"},
			ClaimKeywords:   []string{"msty", "msty.app"},
			CloudOnly:       false,
		},
		{
			ID:              "highlight",
			Name:            "Highlight AI",
			VendorName:      "Highlight",
			ImageID:         "Highlight",
			LogoURI:         "https://www.google.com/s2/favicons?domain=highlightai.com&sz=128",
			OfficialDomains: []string{"highlightai.com", "highlight.ing"},
			OfficialSchemes: []string{"highlight"},
			ClaimKeywords:   []string{"highlight ai", "highlightai"},
			CloudOnly:       false,
		},
		{
			ID:              "dust",
			Name:            "Dust",
			VendorName:      "Dust",
			ImageID:         "Dust",
			LogoURI:         "https://www.google.com/s2/favicons?domain=dust.tt&sz=128",
			OfficialDomains: []string{"dust.tt"},
			OfficialSchemes: []string{"dust"},
			ClaimKeywords:   []string{"dust.tt", "dust-mcp"},
			CloudOnly:       true,
		},
		{
			ID:              "glean",
			Name:            "Glean",
			VendorName:      "Glean",
			ImageID:         "Glean",
			LogoURI:         "https://www.google.com/s2/favicons?domain=glean.com&sz=128",
			OfficialDomains: []string{"glean.com", "app.glean.com"},
			OfficialSchemes: []string{"glean"},
			ClaimKeywords:   []string{"glean"},
			CloudOnly:       true,
		},
		{
			ID:              "cohere",
			Name:            "Cohere",
			VendorName:      "Cohere",
			ImageID:         "Cohere",
			LogoURI:         "https://www.google.com/s2/favicons?domain=cohere.com&sz=128",
			OfficialDomains: []string{"cohere.com", "coral.cohere.com", "dashboard.cohere.com"},
			OfficialSchemes: []string{"cohere"},
			ClaimKeywords:   []string{"cohere"},
			CloudOnly:       true,
		},
		{
			ID:              "huggingface",
			Name:            "Hugging Face",
			VendorName:      "Hugging Face",
			ImageID:         "Hugging Face",
			LogoURI:         "https://www.google.com/s2/favicons?domain=huggingface.co&sz=128",
			OfficialDomains: []string{"huggingface.co", "hf.co"},
			OfficialSchemes: []string{"huggingface"},
			ClaimKeywords:   []string{"huggingface", "hugging face", "hf-mcp"},
			CloudOnly:       false,
		},
		{
			ID:              "langchain",
			Name:            "LangChain",
			VendorName:      "LangChain",
			ImageID:         "LangChain",
			LogoURI:         "https://www.google.com/s2/favicons?domain=langchain.com&sz=128",
			OfficialDomains: []string{"langchain.com", "smith.langchain.com", "langchain.dev"},
			OfficialSchemes: []string{"langchain"},
			ClaimKeywords:   []string{"langchain", "langgraph", "langsmith"},
			CloudOnly:       false,
		},
		{
			ID:              "n8n",
			Name:            "n8n",
			VendorName:      "n8n",
			ImageID:         "n8n",
			LogoURI:         "https://www.google.com/s2/favicons?domain=n8n.io&sz=128",
			OfficialDomains: []string{"n8n.io", "n8n.cloud", "app.n8n.cloud"},
			OfficialSchemes: []string{"n8n"},
			ClaimKeywords:   []string{"n8n"},
			CloudOnly:       false,
		},
		{
			ID:              "zapier",
			Name:            "Zapier",
			VendorName:      "Zapier",
			ImageID:         "Zapier",
			LogoURI:         "https://www.google.com/s2/favicons?domain=zapier.com&sz=128",
			OfficialDomains: []string{"zapier.com", "mcp.zapier.com"},
			OfficialSchemes: []string{"zapier"},
			ClaimKeywords:   []string{"zapier"},
			CloudOnly:       true,
		},
		{
			ID:              "make",
			Name:            "Make",
			VendorName:      "Make",
			ImageID:         "Make",
			LogoURI:         "https://www.google.com/s2/favicons?domain=make.com&sz=128",
			OfficialDomains: []string{"make.com", "integromat.com"},
			OfficialSchemes: []string{"make"},
			ClaimKeywords:   []string{"make.com", "integromat"},
			CloudOnly:       true,
		},
		{
			ID:              "postman",
			Name:            "Postman",
			VendorName:      "Postman",
			ImageID:         "Postman",
			LogoURI:         "https://www.google.com/s2/favicons?domain=postman.com&sz=128",
			OfficialDomains: []string{"postman.com", "oauth.pstmn.io", "getitem.pstmn.io"},
			OfficialSchemes: []string{"postman"},
			ClaimKeywords:   []string{"postman", "pstmn"},
			CloudOnly:       false,
		},
		{
			ID:              "insomnia",
			Name:            "Insomnia",
			VendorName:      "Kong",
			ImageID:         "Insomnia",
			LogoURI:         "https://www.google.com/s2/favicons?domain=insomnia.rest&sz=128",
			OfficialDomains: []string{"insomnia.rest", "app.insomnia.rest"},
			OfficialSchemes: []string{"insomnia"},
			ClaimKeywords:   []string{"insomnia"},
			CloudOnly:       false,
		},
		{
			ID:              "mcp_inspector",
			Name:            "MCP Inspector",
			VendorName:      "Model Context Protocol",
			ImageID:         "MCP Inspector",
			LogoURI:         "https://www.google.com/s2/favicons?domain=modelcontextprotocol.io&sz=128",
			OfficialDomains: []string{"modelcontextprotocol.io"},
			OfficialSchemes: []string{"mcp-inspector"},
			ClaimKeywords:   []string{"mcp-inspector", "mcp inspector", "@modelcontextprotocol/inspector"},
			CloudOnly:       false,
		},
		{
			ID:              "slack",
			Name:            "Slack",
			VendorName:      "Salesforce",
			ImageID:         "Slack",
			LogoURI:         "https://storage.googleapis.com/shuffle_public/app_images/Slack_9a528623b378c8d8b9ba582e6ef92be1.png",
			OfficialDomains: []string{"slack.com", "api.slack.com"},
			OfficialSchemes: []string{"slack"},
			ClaimKeywords:   []string{"slack"},
			CloudOnly:       true,
		},
		{
			ID:              "notion",
			Name:            "Notion",
			VendorName:      "Notion",
			ImageID:         "Notion",
			LogoURI:         "https://www.google.com/s2/favicons?domain=notion.so&sz=128",
			OfficialDomains: []string{"notion.so", "api.notion.com", "www.notion.so"},
			OfficialSchemes: []string{"notion"},
			ClaimKeywords:   []string{"notion"},
			CloudOnly:       true,
		},
		{
			ID:              "linear",
			Name:            "Linear",
			VendorName:      "Linear",
			ImageID:         "Linear",
			LogoURI:         "https://www.google.com/s2/favicons?domain=linear.app&sz=128",
			OfficialDomains: []string{"linear.app", "api.linear.app"},
			OfficialSchemes: []string{"linear"},
			ClaimKeywords:   []string{"linear", "linear.app"},
			CloudOnly:       true,
		},
		{
			ID:              "shuffle_agent",
			Name:            "Shuffle Agent",
			VendorName:      "Shuffle",
			ImageID:         "Shuffle",
			LogoURI:         "https://www.google.com/s2/favicons?domain=shuffler.io&sz=128",
			OfficialDomains: []string{"shuffler.io", "shuffle.security"},
			OfficialSchemes: []string{"shuffle"},
			ClaimKeywords:   []string{"shuffle-agent", "shuffle_agent", "shuffle agent", "singul"},
			CloudOnly:       false,
		},
	}
}

func extractRequestClientIP(request *http.Request) string {
	if request == nil {
		return ""
	}
	if xff := strings.TrimSpace(request.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 && strings.TrimSpace(parts[0]) != "" {
			return strings.TrimSpace(parts[0])
		}
	}
	if xrip := strings.TrimSpace(request.Header.Get("X-Real-Ip")); xrip != "" {
		return xrip
	}
	return strings.TrimSpace(request.RemoteAddr)
}

func extractRequestOrigin(request *http.Request) string {
	if request == nil {
		return ""
	}
	if origin := strings.TrimSpace(request.Header.Get("Origin")); origin != "" {
		return origin
	}
	return strings.TrimSpace(request.Header.Get("Referer"))
}

func matchesOfficialDomain(host string, domains []string) (string, bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimPrefix(host, "www.")
	if host == "" {
		return "", false
	}
	for _, d := range domains {
		cleanD := strings.ToLower(strings.TrimSpace(d))
		cleanD = strings.TrimPrefix(cleanD, "www.")
		if cleanD == "" {
			continue
		}
		if host == cleanD || strings.HasSuffix(host, "."+cleanD) {
			return host, true
		}
	}
	return "", false
}

func matchVendorByRedirectURI(rawURI string) (*OAuthVendorSpec, string, string) {
	rawURI = strings.TrimSpace(rawURI)
	if rawURI == "" {
		return nil, "", ""
	}
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, "", rawURI
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	hostname := strings.ToLower(strings.TrimSpace(u.Hostname()))

	registry := GetOAuthVendorRegistry()
	if scheme != "" && scheme != "http" && scheme != "https" {
		for i := range registry {
			for _, s := range registry[i].OfficialSchemes {
				if scheme == strings.ToLower(strings.TrimSpace(s)) {
					return &registry[i], scheme + "://", scheme + "://" + hostname
				}
			}
		}
		return nil, "", scheme + "://" + hostname
	}

	if hostname != "" {
		for i := range registry {
			if matchedDomain, ok := matchesOfficialDomain(hostname, registry[i].OfficialDomains); ok {
				return &registry[i], matchedDomain, hostname
			}
		}
	}
	return nil, "", hostname
}

func matchVendorByClaims(signals ...string) *OAuthVendorSpec {
	combined := strings.ToLower(strings.Join(signals, " "))
	combined = strings.TrimSpace(combined)
	if combined == "" {
		return nil
	}
	registry := GetOAuthVendorRegistry()
	for i := range registry {
		for _, kw := range registry[i].ClaimKeywords {
			kwLower := strings.ToLower(strings.TrimSpace(kw))
			if kwLower != "" && strings.Contains(combined, kwLower) {
				return &registry[i]
			}
		}
		for _, dom := range registry[i].OfficialDomains {
			domLower := strings.ToLower(strings.TrimSpace(dom))
			if domLower != "" && strings.Contains(combined, domLower) {
				return &registry[i]
			}
		}
	}
	return nil
}

// EvaluateOAuthVendorIdentity cross-references the raw source claims (raw_client_name, client_uri,
// software_id, user_agent, mcp_client_name) against the actual cryptographic redirect_uri target.
// This ensures a user can immediately distinguish a real vendor (e.g. ChatGPT on chatgpt.com)
// from an unverified or spoofed client claiming to be that vendor on an unrelated domain or localhost.
func EvaluateOAuthVendorIdentity(
	clientID,
	rawClientName,
	redirectURI,
	rawClientURI,
	rawLogoURI,
	softwareID,
	userAgent,
	mcpClientName string,
) OAuthVendorEvaluation {
	rawClientName = strings.TrimSpace(rawClientName)
	redirectURI = strings.TrimSpace(redirectURI)
	rawClientURI = strings.TrimSpace(rawClientURI)
	rawLogoURI = strings.TrimSpace(rawLogoURI)
	softwareID = strings.TrimSpace(softwareID)
	userAgent = strings.TrimSpace(userAgent)
	mcpClientName = strings.TrimSpace(mcpClientName)

	lowerExplicit := strings.ToLower(rawClientName)
	lowerID := strings.ToLower(strings.TrimSpace(clientID))
	isGenericExplicit := rawClientName == "" ||
		lowerExplicit == lowerID ||
		strings.HasPrefix(lowerExplicit, "shuffle_client_") ||
		lowerExplicit == "application" ||
		lowerExplicit == "external application" ||
		lowerExplicit == "external-app" ||
		lowerExplicit == "mcp client" ||
		lowerExplicit == "local mcp client"

	isLoopback := isLoopbackURI(redirectURI)
	redirectVendor, verifiedTarget, redirectDisplayTarget := matchVendorByRedirectURI(redirectURI)

	// Avoid matching "shuffle_client_..." random IDs as "shuffle_agent"
	cleanIDForClaim := lowerID
	if strings.HasPrefix(cleanIDForClaim, "shuffle_client_") {
		cleanIDForClaim = ""
	}
	claimedVendor := matchVendorByClaims(rawClientName, rawClientURI, rawLogoURI, softwareID, mcpClientName, cleanIDForClaim)
	if claimedVendor == nil && userAgent != "" && !strings.HasPrefix(strings.ToLower(userAgent), "mozilla/") {
		claimedVendor = matchVendorByClaims(userAgent)
	}

	// Case 1: Redirect URI matches an official vendor domain or native URI scheme
	if redirectVendor != nil {
		chosenVendor := redirectVendor
		// Allow subtype refinement within the same vendor family (e.g. Claude vs Claude Code on claude.ai)
		if claimedVendor != nil && strings.EqualFold(claimedVendor.VendorName, redirectVendor.VendorName) {
			chosenVendor = claimedVendor
		}
		eval := OAuthVendorEvaluation{
			ClientName:         chosenVendor.Name,
			DisplayName:        chosenVendor.Name,
			VendorID:           chosenVendor.ID,
			VendorName:         chosenVendor.VendorName,
			ImageID:            chosenVendor.ImageID,
			LogoURI:            chosenVendor.LogoURI,
			VendorVerified:     true,
			VerificationStatus: "verified",
			VerificationReason: fmt.Sprintf("Verified via official %s callback (%s)", chosenVendor.VendorName, verifiedTarget),
			VerifiedDomain:     verifiedTarget,
		}
		if claimedVendor != nil {
			eval.ClaimedVendorID = claimedVendor.ID
			eval.ClaimedVendorName = claimedVendor.Name
		}
		if claimedVendor != nil && !strings.EqualFold(claimedVendor.VendorName, redirectVendor.VendorName) {
			eval.VendorVerified = false
			eval.VerificationStatus = "mismatch"
			eval.VendorSpoofWarning = fmt.Sprintf(
				"Client metadata claims %s (%s), but redirect_uri points to %s (%s).",
				claimedVendor.Name,
				claimedVendor.VendorName,
				redirectDisplayTarget,
				redirectVendor.Name,
			)
		}
		return eval
	}

	// Case 2: Client claims to be a known vendor, but redirect_uri is NOT an official domain/scheme for that vendor
	if claimedVendor != nil {
		eval := OAuthVendorEvaluation{
			ClientName:        claimedVendor.Name,
			DisplayName:       claimedVendor.Name,
			VendorID:          claimedVendor.ID,
			VendorName:        claimedVendor.VendorName,
			ImageID:           claimedVendor.ImageID,
			LogoURI:           claimedVendor.LogoURI,
			VendorVerified:    false,
			ClaimedVendorID:   claimedVendor.ID,
			ClaimedVendorName: claimedVendor.Name,
		}
		officialList := strings.Join(claimedVendor.OfficialDomains, ", ")
		if isLoopback {
			if claimedVendor.CloudOnly {
				eval.VerificationStatus = "mismatch"
				eval.VerificationReason = fmt.Sprintf("Unverified loopback redirect (%s) for cloud vendor %s", redirectDisplayTarget, claimedVendor.Name)
				eval.VendorSpoofWarning = fmt.Sprintf(
					"Client claims to be %s (%s), which is a cloud service, but redirects to a local loopback address (%s) instead of an official %s domain (%s).",
					claimedVendor.Name,
					claimedVendor.VendorName,
					redirectDisplayTarget,
					claimedVendor.VendorName,
					officialList,
				)
			} else {
				eval.VerificationStatus = "loopback"
				eval.VerificationReason = fmt.Sprintf(
					"Local loopback callback (%s). Self-reported as %s; local loopback clients cannot be domain-verified.",
					redirectDisplayTarget,
					claimedVendor.Name,
				)
			}
		} else if redirectDisplayTarget != "" {
			eval.VerificationStatus = "mismatch"
			eval.VerificationReason = fmt.Sprintf("Redirect host %s does not match official %s domains", redirectDisplayTarget, claimedVendor.VendorName)
			eval.VendorSpoofWarning = fmt.Sprintf(
				"Client claims to be %s (%s), but redirect_uri points to an unverified host (%s) instead of an official %s domain (%s).",
				claimedVendor.Name,
				claimedVendor.VendorName,
				redirectDisplayTarget,
				claimedVendor.VendorName,
				officialList,
			)
		} else {
			eval.VerificationStatus = "unverified"
			eval.VerificationReason = fmt.Sprintf("Self-reported as %s without a verified domain callback.", claimedVendor.Name)
		}
		return eval
	}

	// Case 3: Unrecognized / Custom Third-Party or Local Client
	displayName := rawClientName
	if isGenericExplicit {
		if isLoopback {
			displayName = "Local MCP Client"
		} else if redirectDisplayTarget != "" {
			displayName = redirectDisplayTarget
		} else if strings.HasPrefix(lowerID, "shuffle_client_") {
			displayName = "MCP Client"
		} else if clientID != "" {
			displayName = clientID
		} else {
			displayName = "Application"
		}
	}

	logoURI := rawLogoURI
	if logoURI == "" && redirectDisplayTarget != "" && !isLoopback && !strings.Contains(redirectDisplayTarget, "://") {
		logoURI = fmt.Sprintf("https://www.google.com/s2/favicons?domain=%s&sz=128", redirectDisplayTarget)
	}

	if isLoopback {
		return OAuthVendorEvaluation{
			ClientName:         displayName,
			DisplayName:        displayName,
			VendorID:           "local_mcp",
			VendorName:         "Local Loopback Client",
			ImageID:            displayName,
			LogoURI:            logoURI,
			VendorVerified:     false,
			VerificationStatus: "loopback",
			VerificationReason: fmt.Sprintf("Local loopback callback (%s). Self-reported client name: %q.", redirectDisplayTarget, rawClientName),
		}
	}

	return OAuthVendorEvaluation{
		ClientName:         displayName,
		DisplayName:        displayName,
		VendorID:           "custom",
		VendorName:         redirectDisplayTarget,
		ImageID:            displayName,
		LogoURI:            logoURI,
		VendorVerified:     false,
		VerificationStatus: "unverified",
		VerificationReason: fmt.Sprintf("Unverified third-party callback (%s).", redirectDisplayTarget),
	}
}

// RecordMCPClientMetadata enriches an active OAuthToken and its OAuthClient with the raw MCP
// clientInfo (name, version) and User-Agent observed during MCP JSON-RPC requests.
func RecordMCPClientMetadata(ctx context.Context, accessToken, mcpClientName, mcpClientVersion, userAgent, remoteAddr string) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" || !strings.HasPrefix(accessToken, "shfl_") {
		return
	}
	mcpClientName = strings.TrimSpace(mcpClientName)
	mcpClientVersion = strings.TrimSpace(mcpClientVersion)
	userAgent = strings.TrimSpace(userAgent)
	remoteAddr = strings.TrimSpace(remoteAddr)
	if mcpClientName == "" && userAgent == "" {
		return
	}

	tok, err := GetOAuthToken(ctx, accessToken)
	if err != nil || tok == nil || tok.AccessToken == "" {
		return
	}

	tokChanged := false
	if mcpClientName != "" && tok.MCPClientName != mcpClientName {
		tok.MCPClientName = mcpClientName
		tokChanged = true
	}
	if mcpClientVersion != "" && tok.MCPClientVersion != mcpClientVersion {
		tok.MCPClientVersion = mcpClientVersion
		tokChanged = true
	}
	if userAgent != "" && tok.MCPUserAgent != userAgent {
		tok.MCPUserAgent = userAgent
		tokChanged = true
	}
	if remoteAddr != "" && tok.TokenRemoteAddr == "" {
		tok.TokenRemoteAddr = remoteAddr
		tokChanged = true
	}

	if tokChanged {
		eval := EvaluateOAuthVendorIdentity(
			tok.ClientID,
			tok.RawClientName,
			tok.RedirectURI,
			tok.RawClientURI,
			tok.RawLogoURI,
			tok.SoftwareID,
			tok.UserAgent,
			tok.MCPClientName,
		)
		if tok.VendorID == "" || tok.VendorID == "custom" || tok.VendorID == "local_mcp" {
			tok.VendorID = eval.VendorID
			tok.VendorName = eval.VendorName
			tok.ImageID = eval.ImageID
		}
		if tok.VendorSpoofWarning == "" && eval.VendorSpoofWarning != "" {
			tok.VendorSpoofWarning = eval.VendorSpoofWarning
			tok.VerificationStatus = eval.VerificationStatus
		}
		_ = SetOAuthToken(ctx, *tok)
	}

	if tok.ClientID != "" {
		if client, cErr := GetOAuthClient(ctx, tok.ClientID); cErr == nil && client != nil && client.ClientID != "" {
			clientChanged := false
			if mcpClientName != "" && client.MCPClientName != mcpClientName {
				client.MCPClientName = mcpClientName
				clientChanged = true
			}
			if mcpClientVersion != "" && client.MCPClientVersion != mcpClientVersion {
				client.MCPClientVersion = mcpClientVersion
				clientChanged = true
			}
			if userAgent != "" && client.MCPUserAgent != userAgent {
				client.MCPUserAgent = userAgent
				clientChanged = true
			}
			if clientChanged {
				_ = SetOAuthClient(ctx, *client)
			}
		}
	}
}

// isValidConfiguredOAuthRedirectURI checks whether a redirect_uri is a valid callback URI
// for a manually configured OAuth2 client or server-based OAuth2 integration (HTTPS, loopback, or native app scheme).
func isValidConfiguredOAuthRedirectURI(rawURI string) bool {
	rawURI = strings.TrimSpace(rawURI)
	if rawURI == "" {
		return false
	}
	if isLoopbackURI(rawURI) {
		return true
	}
	u, err := url.Parse(rawURI)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme == "https" && strings.TrimSpace(u.Host) != "" {
		return true
	}
	for _, v := range GetOAuthVendorRegistry() {
		for _, allowedScheme := range v.OfficialSchemes {
			if scheme == strings.ToLower(strings.TrimSpace(allowedScheme)) {
				return true
			}
		}
	}
	return false
}

// isConfiguredOAuthClient checks whether a client_id + redirect_uri pair represents a valid
// configured OAuth2 client (client-based or server-based) that did not use dynamic registration (/oauth2/register).
func isConfiguredOAuthClient(clientID, redirectURI string) bool {
	clientID = strings.TrimSpace(clientID)
	redirectURI = strings.TrimSpace(redirectURI)
	if clientID == "" || redirectURI == "" {
		return false
	}
	for _, envKey := range []string{"SHUFFLE_OAUTH_CLIENT_ID", "OAUTH_CLIENT_ID"} {
		if raw := strings.TrimSpace(os.Getenv(envKey)); raw != "" {
			for _, part := range strings.Split(raw, ",") {
				if strings.TrimSpace(part) == clientID {
					return true
				}
			}
		}
	}
	return isValidConfiguredOAuthRedirectURI(redirectURI)
}

// inferOAuthClientName resolves a human-friendly OAuth client display name from explicit registration
// metadata, redirect_uri, client_uri, or client_id without misclassifying third-party dynamic clients
// (e.g. ChatGPT, Claude, Gemini, Copilot, Cursor) as "Shuffle Agent".
func inferOAuthClientName(clientID, explicitName, redirectURI, clientURI string) string {
	eval := EvaluateOAuthVendorIdentity(clientID, explicitName, redirectURI, clientURI, "", "", "", "")
	return eval.ClientName
}

func HandleOAuthAuthorize(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		if debug {
			log.Printf("[DEBUG] HandleOAuthAuthorize: handled CORS preflight for %s %s", request.Method, request.URL.Path)
		}
		return
	}

	if debug {
		log.Printf("[DEBUG] HandleOAuthAuthorize: incoming %s %s (remote: %s, rawQuery: %s, contentType: %s)",
			request.Method, request.URL.Path, request.RemoteAddr, request.URL.RawQuery, request.Header.Get("Content-Type"))
	}

	// Rate limiting: Protect against automated consent brute-forcing or DoS
	if err := ValidateRequestOverload(resp, request, 30); err != nil {
		if debug {
			log.Printf("[DEBUG] HandleOAuthAuthorize: rate limited: %v", err)
		}
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(http.StatusTooManyRequests)
		resp.Write([]byte(`{"error": "slow_down", "error_description": "Too many requests"}`))
		return
	}

	ctx := GetContext(request)

	// Dynamically determine frontend URL where the authorization UI lives
	frontendURL := os.Getenv("SHUFFLE_FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = os.Getenv("FRONTEND_URL")
	}
	if frontendURL == "" {
		frontendURL = "https://shuffle.security"
	}
	frontendURL = strings.TrimSuffix(frontendURL, "/")

	// Calculate base issuer URL for RFC 9207 iss parameter
	baseURL := resolveOAuthBaseURL(request)

	// =========================================================================
	// GET REQUEST: Render Consent Info or Redirect Browser to Frontend UI
	// =========================================================================
	if request.Method == "GET" {
		clientID := strings.TrimSpace(request.URL.Query().Get("client_id"))
		redirectURI := strings.TrimSpace(request.URL.Query().Get("redirect_uri"))
		responseType := strings.TrimSpace(request.URL.Query().Get("response_type"))
		scope := strings.TrimSpace(request.URL.Query().Get("scope"))
		resource := strings.TrimSpace(request.URL.Query().Get("resource"))
		state := strings.TrimSpace(request.URL.Query().Get("state"))
		codeChallenge := strings.TrimSpace(request.URL.Query().Get("code_challenge"))
		codeChallengeMethod := strings.TrimSpace(request.URL.Query().Get("code_challenge_method"))
		qIssuer := normalizeOAuthIssuerURL(request.URL.Query().Get("issuer"))
		if qIssuer == "" {
			qIssuer = normalizeOAuthIssuerURL(request.URL.Query().Get("iss"))
		}

		if debug {
			log.Printf("[DEBUG] HandleOAuthAuthorize GET params: client_id='%s', redirect_uri='%s', response_type='%s', scope='%s', state='%s', code_challenge_len=%d, code_challenge_method='%s'",
				clientID, redirectURI, responseType, scope, state, len(codeChallenge), codeChallengeMethod)
		}

		// Edgecase 1: Missing client_id
		if clientID == "" {
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize GET: rejected - client_id query parameter is required")
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "client_id query parameter is required"}`))
			return
		}

		// Edgecase 2: Unknown or invalid client_id
		client, err := GetOAuthClient(ctx, clientID)
		qClientName := strings.TrimSpace(request.URL.Query().Get("client_name"))
		if qClientName == "" {
			qClientName = strings.TrimSpace(request.URL.Query().Get("app_name"))
		}
		if qClientName == "" {
			qClientName = strings.TrimSpace(request.URL.Query().Get("name"))
		}
		qRawClientName := strings.TrimSpace(request.URL.Query().Get("raw_client_name"))
		if qRawClientName == "" {
			qRawClientName = qClientName
		}
		qClientURI := strings.TrimSpace(request.URL.Query().Get("client_uri"))
		qLogoURI := strings.TrimSpace(request.URL.Query().Get("logo_uri"))

		if (err != nil || client == nil || client.ClientID == "") && (isDynamicShuffleClient(clientID, redirectURI) || isConfiguredOAuthClient(clientID, redirectURI)) {
			// Auto-register / accept dynamic or configured OAuth2 client
			now := time.Now().Unix()
			reqUA := strings.TrimSpace(request.Header.Get("User-Agent"))
			reqOrigin := extractRequestOrigin(request)
			reqIP := extractRequestClientIP(request)
			eval := EvaluateOAuthVendorIdentity(clientID, qRawClientName, redirectURI, qClientURI, qLogoURI, "", reqUA, "")
			resolvedLogo := qLogoURI
			if resolvedLogo == "" {
				resolvedLogo = eval.LogoURI
			}
			initialIssuer := qIssuer
			if initialIssuer == "" {
				initialIssuer = baseURL
			}
			newClient := OAuthClient{
				ID:                      clientID,
				ClientID:                clientID,
				ClientName:              eval.ClientName,
				ClientURI:               qClientURI,
				LogoURI:                 resolvedLogo,
				RedirectUris:            []string{redirectURI},
				GrantTypes:              []string{"authorization_code", "refresh_token"},
				ResponseTypes:           []string{"code"},
				TokenEndpointAuthMethod: "none",
				CreatedAt:               now,
				IsDynamic:               true,
				VendorID:                eval.VendorID,
				VendorName:              eval.VendorName,
				ImageID:                 eval.ImageID,
				VendorVerified:          eval.VendorVerified,
				VerificationStatus:      eval.VerificationStatus,
				VerificationReason:      eval.VerificationReason,
				VerifiedDomain:          eval.VerifiedDomain,
				ClaimedVendorID:         eval.ClaimedVendorID,
				ClaimedVendorName:       eval.ClaimedVendorName,
				VendorSpoofWarning:      eval.VendorSpoofWarning,
				RawClientName:           qRawClientName,
				RawRedirectURI:          redirectURI,
				RawClientURI:            qClientURI,
				RawLogoURI:              qLogoURI,
				UserAgent:               reqUA,
				Origin:                  reqOrigin,
				Issuer:                  initialIssuer,
				RemoteAddr:              reqIP,
			}
			_ = SetOAuthClient(ctx, newClient)
			client = &newClient
			err = nil
		}
		if err != nil || client == nil || client.ClientID == "" {
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize GET: rejected - client_id '%s' not found or error: %v", clientID, err)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_client", "error_description": "Unknown or invalid client_id"}`))
			return
		}

		// Edgecase 3: Missing redirect_uri
		if redirectURI == "" {
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize GET: rejected - redirect_uri query parameter is required for client '%s'", clientID)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "redirect_uri query parameter is required"}`))
			return
		}

		// Edgecase 4: Redirect URI mismatch (Open Redirector Protection)
		// SECURITY: Never redirect to an unregistered redirect_uri if validation fails!
		uriMatched := false
		for _, regURI := range client.RedirectUris {
			if regURI == redirectURI || isMatchingLoopbackURI(regURI, redirectURI) {
				uriMatched = true
				break
			}
		}
		if !uriMatched && (client.IsDynamic || strings.HasPrefix(clientID, "shuffle_client_") || isDynamicShuffleClient(clientID, redirectURI)) && canAppendDynamicRedirectURI(client, redirectURI) {
			uriMatched = true
			client.RedirectUris = append(client.RedirectUris, redirectURI)
			_ = SetOAuthClient(ctx, *client)
		}
		if !uriMatched {
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize GET: rejected - redirect_uri '%s' does not match registered URIs %v for client '%s'",
					redirectURI, client.RedirectUris, clientID)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "redirect_uri does not match any registered redirect_uris for this client"}`))
			return
		}

		// Ensure client name/metadata and raw source are enriched AFTER redirect_uri has been verified
		rawNameForEval := client.RawClientName
		if rawNameForEval == "" {
			if qRawClientName != "" {
				rawNameForEval = qRawClientName
			} else if client.ClientName != "" && client.ClientName != "Shuffle Agent" && client.ClientName != "MCP Client" {
				rawNameForEval = client.ClientName
			}
		}
		rawClientURIForEval := client.RawClientURI
		if rawClientURIForEval == "" {
			if client.ClientURI != "" {
				rawClientURIForEval = client.ClientURI
			} else {
				rawClientURIForEval = qClientURI
			}
		}
		rawLogoURIForEval := client.RawLogoURI
		if rawLogoURIForEval == "" {
			rawLogoURIForEval = qLogoURI
		}
		eval := EvaluateOAuthVendorIdentity(client.ClientID, rawNameForEval, redirectURI, rawClientURIForEval, rawLogoURIForEval, client.SoftwareID, client.UserAgent, client.MCPClientName)

		clientUpdated := false
		if client.RawClientName == "" && qRawClientName != "" {
			client.RawClientName = qRawClientName
			clientUpdated = true
		}
		if client.RawRedirectURI == "" && redirectURI != "" {
			client.RawRedirectURI = redirectURI
			clientUpdated = true
		}
		if client.ClientName == "" || (client.ClientName == "Shuffle Agent" && eval.ClientName != "Shuffle Agent") || (client.ClientName == "MCP Client" && eval.ClientName != "MCP Client") {
			client.ClientName = eval.ClientName
			clientUpdated = true
		}
		if client.LogoURI == "" {
			if qLogoURI != "" {
				client.LogoURI = qLogoURI
				clientUpdated = true
			} else if eval.LogoURI != "" {
				client.LogoURI = eval.LogoURI
				clientUpdated = true
			}
		}
		if client.ClientURI == "" && qClientURI != "" {
			client.ClientURI = qClientURI
			clientUpdated = true
		}
		if client.VendorID != eval.VendorID || client.VerificationStatus != eval.VerificationStatus {
			client.VendorID = eval.VendorID
			client.VendorName = eval.VendorName
			client.ImageID = eval.ImageID
			client.VendorVerified = eval.VendorVerified
			client.VerificationStatus = eval.VerificationStatus
			client.VerificationReason = eval.VerificationReason
			client.VerifiedDomain = eval.VerifiedDomain
			client.ClaimedVendorID = eval.ClaimedVendorID
			client.ClaimedVendorName = eval.ClaimedVendorName
			client.VendorSpoofWarning = eval.VendorSpoofWarning
			clientUpdated = true
		}
		isAPIRequest := strings.Contains(request.URL.Path, "/api/v1/") ||
			strings.Contains(request.Header.Get("Accept"), "application/json") ||
			request.URL.Query().Get("format") == "json"

		// Record the originating issuer on the client when hit directly on /oauth2/authorize
		effectiveGETIssuer := qIssuer
		if effectiveGETIssuer == "" {
			if !isAPIRequest {
				effectiveGETIssuer = baseURL
			} else if normClientIss := normalizeOAuthIssuerURL(client.Issuer); normClientIss != "" {
				effectiveGETIssuer = normClientIss
			} else {
				effectiveGETIssuer = baseURL
			}
		}
		if effectiveGETIssuer != "" && (client.Issuer == "" || (!isAPIRequest && client.Issuer != effectiveGETIssuer)) {
			client.Issuer = effectiveGETIssuer
			clientUpdated = true
		}
		if clientUpdated {
			_ = SetOAuthClient(ctx, *client)
		}

		if debug {
			log.Printf("[DEBUG] HandleOAuthAuthorize GET: found client '%s' (name: '%s', issuer: '%s', registered redirect_uris: %v)",
				client.ClientID, client.ClientName, client.Issuer, client.RedirectUris)
		}

		// Edgecase 5: Invalid response_type (OAuth 2.1 requires 'code', disallows implicit 'token')
		if responseType != "" && responseType != "code" {
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize GET: rejected - unsupported response_type '%s' (only 'code' supported)", responseType)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "unsupported_response_type", "error_description": "Only response_type=code is supported"}`))
			return
		}

		// Edgecase 6: PKCE validation (RFC 7636)
		// Enforced when code_challenge is provided; optional when omitted by configured client/server OAuth2 flows.
		if codeChallenge != "" && codeChallengeMethod != "" && codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize GET: rejected - invalid code_challenge_method '%s'", codeChallengeMethod)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "code_challenge_method must be S256 or plain"}`))
			return
		} else if codeChallenge == "" && debug {
			log.Printf("[DEBUG] HandleOAuthAuthorize GET: no PKCE code_challenge provided for client '%s' (configured client/server OAuth2 flow)", clientID)
		}

		// Enrich query parameters with registered client metadata and issuer for frontend consent UI
		enrichedQuery := request.URL.Query()
		if scope == "" {
			scope = resolveDefaultOAuthScope(client, resource)
			if scope != "" && enrichedQuery.Get("scope") == "" {
				enrichedQuery.Set("scope", scope)
			}
		} else if client.IsDynamic || strings.HasPrefix(client.ClientID, "shuffle_client_") || isDynamicShuffleClient(client.ClientID, redirectURI) {
			cleanedScope, _ := sanitizeDynamicOAuthScope(scope)
			if cleanedScope != "" {
				scope = cleanedScope
				enrichedQuery.Set("scope", scope)
			}
		}
		resolvedClientName := eval.ClientName
		if resolvedClientName == "" {
			resolvedClientName = inferOAuthClientName(client.ClientID, client.ClientName, redirectURI, client.ClientURI)
		}
		resolvedLogoURI := client.LogoURI
		if resolvedLogoURI == "" {
			resolvedLogoURI = eval.LogoURI
		}
		if resolvedClientName != "" && enrichedQuery.Get("client_name") == "" {
			enrichedQuery.Set("client_name", resolvedClientName)
		}
		if client.RawClientName != "" && enrichedQuery.Get("raw_client_name") == "" {
			enrichedQuery.Set("raw_client_name", client.RawClientName)
		}
		if eval.VendorID != "" && enrichedQuery.Get("vendor_id") == "" {
			enrichedQuery.Set("vendor_id", eval.VendorID)
		}
		if resolvedLogoURI != "" && enrichedQuery.Get("logo_uri") == "" {
			enrichedQuery.Set("logo_uri", resolvedLogoURI)
		}
		if client.ClientURI != "" && enrichedQuery.Get("client_uri") == "" {
			enrichedQuery.Set("client_uri", client.ClientURI)
		}
		if effectiveGETIssuer != "" && enrichedQuery.Get("issuer") == "" {
			enrichedQuery.Set("issuer", effectiveGETIssuer)
		}

		rawSource := &OAuthRawSource{
			ClientID:         client.ClientID,
			RawClientName:    client.RawClientName,
			RawRedirectURI:   redirectURI,
			RawClientURI:     rawClientURIForEval,
			RawLogoURI:       rawLogoURIForEval,
			RawRedirectURIs:  client.RedirectUris,
			SoftwareID:       client.SoftwareID,
			SoftwareVersion:  client.SoftwareVersion,
			UserAgent:        client.UserAgent,
			Origin:           client.Origin,
			RemoteAddr:       client.RemoteAddr,
			MCPClientName:    client.MCPClientName,
			MCPClientVersion: client.MCPClientVersion,
			MCPUserAgent:     client.MCPUserAgent,
			IsDynamic:        client.IsDynamic,
			AuthMethod:       client.TokenEndpointAuthMethod,
		}

		isSameOriginAsFrontend := strings.EqualFold(strings.TrimSuffix(baseURL, "/"), strings.TrimSuffix(frontendURL, "/"))

		// Direct browser navigation to a separate backend / tunnel /oauth2/authorize:
		// Redirect to the frontend consent SPA with enriched metadata so the frontend
		// can verify the user's session on its own origin and render the true client profile.
		if !isAPIRequest && !isSameOriginAsFrontend && request.Header.Get("Authorization") == "" {
			consentRedirect := fmt.Sprintf("%s/oauth2/authorize?%s", frontendURL, enrichedQuery.Encode())
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize GET: browser redirecting 302 to frontend consent UI: %s", consentRedirect)
			}
			http.Redirect(resp, request, consentRedirect, http.StatusFound)
			return
		}

		// Edgecase 7: Check User Authentication Status for API consent metadata requests (or same-origin requests)
		user, userErr := getOAuthUser(resp, request)
		if userErr != nil || len(user.Id) == 0 {
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize GET: user is unauthenticated (userErr: %v, isAPIRequest: %v)", userErr, isAPIRequest)
			}
			loginURL := fmt.Sprintf("%s/login?redirect=%s", frontendURL, url.QueryEscape(fmt.Sprintf("/oauth2/authorize?%s", enrichedQuery.Encode())))
			if !isAPIRequest {
				targetRedirect := fmt.Sprintf("%s/oauth2/authorize?%s", frontendURL, enrichedQuery.Encode())
				if isSameOriginAsFrontend {
					targetRedirect = loginURL
				}
				http.Redirect(resp, request, targetRedirect, http.StatusFound)
				return
			}
			// Frontend API call: Return 401 with login prompt URL AND public client metadata
			// so the Sign In Required view can still display the right application name and icon.
			unauthAppPerms, unauthScopes := ResolveOAuthAppsAndTools(ctx, User{}, scope, nil, nil, resource)
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusUnauthorized)
			unauthResp := map[string]interface{}{
				"error":                "unauthorized",
				"login_url":            loginURL,
				"client_id":            client.ClientID,
				"client_name":          resolvedClientName,
				"client_uri":           client.ClientURI,
				"logo_uri":             resolvedLogoURI,
				"issuer":               effectiveGETIssuer,
				"scopes":               unauthScopes,
				"app_permissions":      unauthAppPerms,
				"vendor_id":            eval.VendorID,
				"vendor_name":          eval.VendorName,
				"image_id":             eval.ImageID,
				"vendor_verified":      eval.VendorVerified,
				"verification_status":  eval.VerificationStatus,
				"verification_reason":  eval.VerificationReason,
				"verified_domain":      eval.VerifiedDomain,
				"claimed_vendor_id":    eval.ClaimedVendorID,
				"claimed_vendor_name":  eval.ClaimedVendorName,
				"vendor_spoof_warning": eval.VendorSpoofWarning,
				"raw_source":           rawSource,
			}
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize GET: returning 401 with login_url: %s", loginURL)
			}
			unauthBytes, _ := json.Marshal(unauthResp)
			resp.Write(unauthBytes)
			return
		}

		// Edgecase 8: User account is inactive / suspended
		if !user.Active {
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize GET: rejected - user '%s' account is inactive", user.Id)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusForbidden)
			resp.Write([]byte(`{"error": "access_denied", "error_description": "User account is inactive"}`))
			return
		}

		if debug {
			log.Printf("[DEBUG] HandleOAuthAuthorize GET: user '%s' (%s) authenticated, activeOrg: '%s', user.Orgs: %v",
				user.Username, user.Id, user.ActiveOrg.Id, user.Orgs)
		}

		// Build available organizations list for the user (only orgs where user is admin)
		availableOrgs := []OrgMini{}
		for _, orgId := range user.Orgs {
			isAdmin := isUserOrgAdmin(ctx, user, orgId)
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize GET: checking isUserOrgAdmin for user %s, org %s -> %v", user.Id, orgId, isAdmin)
			}
			if isAdmin {
				orgData, oErr := safeGetOrgForOAuth(ctx, orgId)
				if oErr == nil && orgData != nil && orgData.Id != "" {
					availableOrgs = append(availableOrgs, OrgMini{
						Id:   orgData.Id,
						Name: orgData.Name,
					})
				} else {
					availableOrgs = append(availableOrgs, OrgMini{
						Id:   orgId,
						Name: orgId,
					})
				}
			}
		}

		selectedOrg := ""
		if isUserOrgAdmin(ctx, user, user.ActiveOrg.Id) {
			selectedOrg = user.ActiveOrg.Id
		} else if len(availableOrgs) > 0 {
			selectedOrg = availableOrgs[0].Id
		}

		resolvedAppPerms, resolvedScopes := ResolveOAuthAppsAndTools(ctx, user, scope, nil, nil, resource)

		consentResponse := OAuthConsentInfoResponse{
			ClientID:           client.ClientID,
			ClientName:         resolvedClientName,
			ClientURI:          client.ClientURI,
			LogoURI:            resolvedLogoURI,
			Issuer:             effectiveGETIssuer,
			Scopes:             resolvedScopes,
			AppPermissions:     resolvedAppPerms,
			User:               OAuthUserInfo{ID: user.Id, Username: user.Username},
			AvailableOrgs:      availableOrgs,
			SelectedOrgId:      selectedOrg,
			RedirectURI:        redirectURI,
			State:              state,
			VendorID:           eval.VendorID,
			VendorName:         eval.VendorName,
			ImageID:            eval.ImageID,
			VendorVerified:     eval.VendorVerified,
			VerificationStatus: eval.VerificationStatus,
			VerificationReason: eval.VerificationReason,
			VerifiedDomain:     eval.VerifiedDomain,
			ClaimedVendorID:    eval.ClaimedVendorID,
			ClaimedVendorName:  eval.ClaimedVendorName,
			VendorSpoofWarning: eval.VendorSpoofWarning,
			RawSource:          rawSource,
		}

		data, mErr := json.Marshal(consentResponse)
		if mErr != nil {
			log.Printf("[ERROR] HandleOAuthAuthorize GET: marshal consentResponse failed: %v", mErr)
			resp.WriteHeader(http.StatusInternalServerError)
			return
		}
		if debug {
			log.Printf("[DEBUG] HandleOAuthAuthorize GET: returning 200 OK consent metadata for user %s (selectedOrg: %s, availableOrgs: %d): %s",
				user.Id, selectedOrg, len(availableOrgs), string(data))
		}
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(http.StatusOK)
		resp.Write(data)
		return
	}

	// =========================================================================
	// POST REQUEST: User Submits Consent Decision (Approve / Deny)
	// =========================================================================
	if request.Method == "POST" {
		contentType := request.Header.Get("Content-Type")
		if debug {
			log.Printf("[DEBUG] HandleOAuthAuthorize POST: incoming consent decision from %s, content-type: '%s'",
				request.RemoteAddr, contentType)
		}

		// Authenticate user
		user, userErr := getOAuthUser(resp, request)
		if userErr != nil || len(user.Id) == 0 {
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize POST: rejected - unauthenticated user: %v", userErr)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusUnauthorized)
			resp.Write([]byte(`{"error": "unauthorized", "error_description": "User session is invalid or expired"}`))
			return
		}

		if debug {
			log.Printf("[DEBUG] HandleOAuthAuthorize POST: user authenticated: %s (id: %s, role: %s, activeOrg: %s)",
				user.Username, user.Id, user.Role, user.ActiveOrg.Id)
		}

		// Parse request body (supports JSON or Form-encoded)
		var authReq OAuthAuthorizeRequest
		var rawMap map[string]interface{}
		isApproved := true // Default to true: calling POST /authorize is an affirmative authorization action!

		if strings.Contains(contentType, "application/json") {
			body, rErr := ioutil.ReadAll(request.Body)
			if rErr != nil {
				if debug {
					log.Printf("[DEBUG] HandleOAuthAuthorize POST: rejected - failed to read body: %v", rErr)
				}
				resp.Header().Set("Content-Type", "application/json")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write([]byte(`{"error": "invalid_request", "error_description": "Failed to read body"}`))
				return
			}

			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize POST rawBody: %s", string(body))
			}

			if len(body) > 0 {
				if err := json.Unmarshal(body, &authReq); err != nil {
					if debug {
						log.Printf("[DEBUG] HandleOAuthAuthorize POST: rejected - JSON unmarshal error: %v, rawBody: %s", err, string(body))
					}
					resp.Header().Set("Content-Type", "application/json")
					resp.WriteHeader(http.StatusBadRequest)
					resp.Write([]byte(`{"error": "invalid_request", "error_description": "Invalid JSON format"}`))
					return
				}
				_ = json.Unmarshal(body, &rawMap)
			}

			// Check for explicit denial or approval in JSON payload
			if rawMap != nil {
				if val, exists := rawMap["approved"]; exists {
					switch v := val.(type) {
					case bool:
						isApproved = v
					case string:
						vLower := strings.ToLower(strings.TrimSpace(v))
						if vLower == "false" || vLower == "0" || vLower == "deny" || vLower == "reject" {
							isApproved = false
						} else if vLower == "true" || vLower == "1" || vLower == "approve" || vLower == "authorize" {
							isApproved = true
						}
					}
				}

				// Explicit denial signals
				if val, exists := rawMap["deny"]; exists {
					if v, ok := val.(bool); ok && v {
						isApproved = false
					} else if s, ok := val.(string); ok && (strings.ToLower(s) == "true" || s == "1") {
						isApproved = false
					}
				}
				if val, exists := rawMap["denied"]; exists {
					if v, ok := val.(bool); ok && v {
						isApproved = false
					} else if s, ok := val.(string); ok && (strings.ToLower(s) == "true" || s == "1") {
						isApproved = false
					}
				}
				if val, exists := rawMap["reject"]; exists {
					if v, ok := val.(bool); ok && v {
						isApproved = false
					} else if s, ok := val.(string); ok && (strings.ToLower(s) == "true" || s == "1") {
						isApproved = false
					}
				}
				if val, exists := rawMap["action"]; exists {
					if s, ok := val.(string); ok {
						sLower := strings.ToLower(strings.TrimSpace(s))
						if sLower == "deny" || sLower == "cancel" || sLower == "reject" || sLower == "decline" {
							isApproved = false
						} else if sLower == "approve" || sLower == "authorize" || sLower == "allow" || sLower == "accept" {
							isApproved = true
						}
					}
				}
				if val, exists := rawMap["status"]; exists {
					if s, ok := val.(string); ok {
						sLower := strings.ToLower(strings.TrimSpace(s))
						if sLower == "deny" || sLower == "denied" || sLower == "cancel" || sLower == "cancelled" || sLower == "rejected" {
							isApproved = false
						}
					}
				}
			}
		} else {
			// Form-encoded fallback
			if err := request.ParseForm(); err != nil {
				if debug {
					log.Printf("[DEBUG] HandleOAuthAuthorize POST: rejected - failed to parse form: %v", err)
				}
				resp.Header().Set("Content-Type", "application/json")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write([]byte(`{"error": "invalid_request", "error_description": "Failed to parse form"}`))
				return
			}
			authReq.ClientID = strings.TrimSpace(request.FormValue("client_id"))
			authReq.RedirectURI = strings.TrimSpace(request.FormValue("redirect_uri"))
			authReq.ResponseType = strings.TrimSpace(request.FormValue("response_type"))
			authReq.Scope = strings.TrimSpace(request.FormValue("scope"))
			authReq.State = strings.TrimSpace(request.FormValue("state"))
			authReq.CodeChallenge = strings.TrimSpace(request.FormValue("code_challenge"))
			authReq.CodeChallengeMethod = strings.TrimSpace(request.FormValue("code_challenge_method"))
			authReq.OrgId = strings.TrimSpace(request.FormValue("org_id"))
			authReq.Issuer = strings.TrimSpace(request.FormValue("issuer"))

			action := strings.ToLower(strings.TrimSpace(request.FormValue("action")))
			if action == "deny" || action == "cancel" || action == "reject" || action == "decline" {
				isApproved = false
			}
			if request.FormValue("deny") == "true" || request.FormValue("deny") == "1" || request.FormValue("denied") == "true" {
				isApproved = false
			}
			if request.FormValue("approved") == "false" || request.FormValue("approved") == "0" {
				isApproved = false
			}
			if action == "approve" || action == "authorize" || action == "allow" || request.FormValue("approved") == "true" || request.FormValue("approved") == "1" {
				isApproved = true
			}
		}

		// Fallback to query params if omitted in POST body
		if authReq.ClientID == "" {
			authReq.ClientID = strings.TrimSpace(request.URL.Query().Get("client_id"))
		}
		if authReq.RedirectURI == "" {
			authReq.RedirectURI = strings.TrimSpace(request.URL.Query().Get("redirect_uri"))
		}
		if authReq.ResponseType == "" {
			authReq.ResponseType = strings.TrimSpace(request.URL.Query().Get("response_type"))
		}
		if authReq.Scope == "" {
			authReq.Scope = strings.TrimSpace(request.URL.Query().Get("scope"))
		}
		if authReq.State == "" {
			authReq.State = strings.TrimSpace(request.URL.Query().Get("state"))
		}
		if authReq.CodeChallenge == "" {
			authReq.CodeChallenge = strings.TrimSpace(request.URL.Query().Get("code_challenge"))
		}
		if authReq.CodeChallengeMethod == "" {
			authReq.CodeChallengeMethod = strings.TrimSpace(request.URL.Query().Get("code_challenge_method"))
		}
		if authReq.OrgId == "" {
			authReq.OrgId = strings.TrimSpace(request.URL.Query().Get("org_id"))
		}
		if authReq.Issuer == "" {
			authReq.Issuer = strings.TrimSpace(request.URL.Query().Get("issuer"))
			if authReq.Issuer == "" {
				authReq.Issuer = strings.TrimSpace(request.URL.Query().Get("iss"))
			}
		}

		// Also check query parameter fallback for denial (?action=deny, ?deny=true)
		qAction := strings.ToLower(strings.TrimSpace(request.URL.Query().Get("action")))
		if qAction == "deny" || qAction == "cancel" || qAction == "reject" || request.URL.Query().Get("deny") == "true" || request.URL.Query().Get("approved") == "false" {
			isApproved = false
		}

		authReq.Approved = isApproved

		if debug {
			log.Printf("[DEBUG] HandleOAuthAuthorize POST params: client_id='%s', redirect_uri='%s', approved=%v, org_id='%s', scope='%s', state='%s', code_challenge_len=%d, code_challenge_method='%s'",
				authReq.ClientID, authReq.RedirectURI, authReq.Approved, authReq.OrgId, authReq.Scope, authReq.State, len(authReq.CodeChallenge), authReq.CodeChallengeMethod)
		}

		// Edgecase 9: Validate Client existence
		client, err := GetOAuthClient(ctx, authReq.ClientID)
		reqClientName := strings.TrimSpace(authReq.ClientName)
		if reqClientName == "" {
			reqClientName = strings.TrimSpace(request.URL.Query().Get("client_name"))
		}
		if reqClientName == "" {
			reqClientName = strings.TrimSpace(request.URL.Query().Get("app_name"))
		}
		if reqClientName == "" {
			reqClientName = strings.TrimSpace(request.URL.Query().Get("name"))
		}
		reqClientURI := strings.TrimSpace(authReq.ClientURI)
		if reqClientURI == "" {
			reqClientURI = strings.TrimSpace(request.URL.Query().Get("client_uri"))
		}
		reqLogoURI := strings.TrimSpace(authReq.LogoURI)
		if reqLogoURI == "" {
			reqLogoURI = strings.TrimSpace(request.URL.Query().Get("logo_uri"))
		}

		if (err != nil || client == nil || client.ClientID == "") && (isDynamicShuffleClient(authReq.ClientID, authReq.RedirectURI) || isConfiguredOAuthClient(authReq.ClientID, authReq.RedirectURI)) {
			// Auto-register / accept dynamic or configured OAuth2 client
			now := time.Now().Unix()
			reqUA := strings.TrimSpace(request.Header.Get("User-Agent"))
			reqOrigin := extractRequestOrigin(request)
			reqIP := extractRequestClientIP(request)
			eval := EvaluateOAuthVendorIdentity(authReq.ClientID, reqClientName, authReq.RedirectURI, reqClientURI, reqLogoURI, "", reqUA, "")
			resolvedLogo := reqLogoURI
			if resolvedLogo == "" {
				resolvedLogo = eval.LogoURI
			}
			newClient := OAuthClient{
				ID:                      authReq.ClientID,
				ClientID:                authReq.ClientID,
				ClientName:              eval.ClientName,
				ClientURI:               reqClientURI,
				LogoURI:                 resolvedLogo,
				RedirectUris:            []string{authReq.RedirectURI},
				GrantTypes:              []string{"authorization_code", "refresh_token"},
				ResponseTypes:           []string{"code"},
				TokenEndpointAuthMethod: "none",
				CreatedAt:               now,
				IsDynamic:               true,
				VendorID:                eval.VendorID,
				VendorName:              eval.VendorName,
				ImageID:                 eval.ImageID,
				VendorVerified:          eval.VendorVerified,
				VerificationStatus:      eval.VerificationStatus,
				VerificationReason:      eval.VerificationReason,
				VerifiedDomain:          eval.VerifiedDomain,
				ClaimedVendorID:         eval.ClaimedVendorID,
				ClaimedVendorName:       eval.ClaimedVendorName,
				VendorSpoofWarning:      eval.VendorSpoofWarning,
				RawClientName:           reqClientName,
				RawRedirectURI:          authReq.RedirectURI,
				RawClientURI:            reqClientURI,
				RawLogoURI:              reqLogoURI,
				UserAgent:               reqUA,
				Origin:                  reqOrigin,
				RemoteAddr:              reqIP,
			}
			_ = SetOAuthClient(ctx, newClient)
			client = &newClient
			err = nil
		}
		if err != nil || client == nil || client.ClientID == "" {
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize POST: rejected - client_id '%s' not found or error: %v", authReq.ClientID, err)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_client", "error_description": "Client does not exist"}`))
			return
		}

		// Edgecase 10: Validate Redirect URI matches registered list BEFORE persisting metadata updates
		uriMatched := false
		for _, regURI := range client.RedirectUris {
			if regURI == authReq.RedirectURI || isMatchingLoopbackURI(regURI, authReq.RedirectURI) {
				uriMatched = true
				break
			}
		}
		if !uriMatched && (client.IsDynamic || strings.HasPrefix(authReq.ClientID, "shuffle_client_") || isDynamicShuffleClient(authReq.ClientID, authReq.RedirectURI)) && canAppendDynamicRedirectURI(client, authReq.RedirectURI) {
			uriMatched = true
			client.RedirectUris = append(client.RedirectUris, authReq.RedirectURI)
			_ = SetOAuthClient(ctx, *client)
		}
		if !uriMatched {
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize POST: rejected - redirect_uri '%s' does not match registered URIs %v for client '%s'",
					authReq.RedirectURI, client.RedirectUris, client.ClientID)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "redirect_uri is not registered for this client"}`))
			return
		}

		// Update client metadata if previously empty or generic placeholder while preserving original RawClientName
		rawNameForPostEval := client.RawClientName
		if rawNameForPostEval == "" {
			if reqClientName != "" && reqClientName != "Shuffle Agent" && reqClientName != "MCP Client" {
				rawNameForPostEval = reqClientName
			} else if client.ClientName != "" && client.ClientName != "Shuffle Agent" && client.ClientName != "MCP Client" {
				rawNameForPostEval = client.ClientName
			}
		}
		rawClientURIForPost := client.RawClientURI
		if rawClientURIForPost == "" {
			if client.ClientURI != "" {
				rawClientURIForPost = client.ClientURI
			} else {
				rawClientURIForPost = reqClientURI
			}
		}
		rawLogoURIForPost := client.RawLogoURI
		if rawLogoURIForPost == "" {
			rawLogoURIForPost = reqLogoURI
		}
		postEval := EvaluateOAuthVendorIdentity(client.ClientID, rawNameForPostEval, authReq.RedirectURI, rawClientURIForPost, rawLogoURIForPost, client.SoftwareID, client.UserAgent, client.MCPClientName)

		postClientUpdated := false
		if client.RawClientName == "" && rawNameForPostEval != "" {
			client.RawClientName = rawNameForPostEval
			postClientUpdated = true
		}
		if client.RawRedirectURI == "" && authReq.RedirectURI != "" {
			client.RawRedirectURI = authReq.RedirectURI
			postClientUpdated = true
		}
		if client.ClientName == "" || (client.ClientName == "Shuffle Agent" && postEval.ClientName != "Shuffle Agent") || (client.ClientName == "MCP Client" && postEval.ClientName != "MCP Client") {
			client.ClientName = postEval.ClientName
			postClientUpdated = true
		}
		if client.LogoURI == "" {
			if reqLogoURI != "" {
				client.LogoURI = reqLogoURI
				postClientUpdated = true
			} else if postEval.LogoURI != "" {
				client.LogoURI = postEval.LogoURI
				postClientUpdated = true
			}
		}
		if client.ClientURI == "" && reqClientURI != "" {
			client.ClientURI = reqClientURI
			postClientUpdated = true
		}
		if client.VendorID != postEval.VendorID || client.VerificationStatus != postEval.VerificationStatus {
			client.VendorID = postEval.VendorID
			client.VendorName = postEval.VendorName
			client.ImageID = postEval.ImageID
			client.VendorVerified = postEval.VendorVerified
			client.VerificationStatus = postEval.VerificationStatus
			client.VerificationReason = postEval.VerificationReason
			client.VerifiedDomain = postEval.VerifiedDomain
			client.ClaimedVendorID = postEval.ClaimedVendorID
			client.ClaimedVendorName = postEval.ClaimedVendorName
			client.VendorSpoofWarning = postEval.VendorSpoofWarning
			postClientUpdated = true
		}
		if postClientUpdated {
			_ = SetOAuthClient(ctx, *client)
		}

		// Edgecase 11: Validate PKCE when code_challenge is provided (optional for configured client/server OAuth2 flows)
		if authReq.CodeChallenge != "" {
			if authReq.CodeChallengeMethod == "" {
				authReq.CodeChallengeMethod = "S256"
			}
			if authReq.CodeChallengeMethod != "S256" && authReq.CodeChallengeMethod != "plain" {
				if debug {
					log.Printf("[DEBUG] HandleOAuthAuthorize POST: rejected - invalid code_challenge_method '%s'", authReq.CodeChallengeMethod)
				}
				resp.Header().Set("Content-Type", "application/json")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write([]byte(`{"error": "invalid_request", "error_description": "code_challenge_method must be S256 or plain"}`))
				return
			}
		} else {
			authReq.CodeChallengeMethod = ""
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize POST: no PKCE code_challenge provided for client '%s' (configured client/server OAuth2 flow)", authReq.ClientID)
			}
		}

		// Resolve canonical RFC 9207 issuer: prefer explicit issuer passed from consent UI,
		// then the issuer persisted on the OAuth client during registration / initial GET /authorize,
		// and finally the current request's baseURL.
		effectiveIssuer := normalizeOAuthIssuerURL(authReq.Issuer)
		if effectiveIssuer == "" && client != nil {
			effectiveIssuer = normalizeOAuthIssuerURL(client.Issuer)
		}
		if effectiveIssuer == "" {
			effectiveIssuer = baseURL
		}

		// Helper to format redirect response based on client request type
		returnRedirect := func(targetURL string, issuedCode string) {
			if strings.Contains(contentType, "application/json") || request.URL.Query().Get("format") == "json" {
				if debug {
					log.Printf("[DEBUG] HandleOAuthAuthorize POST: returning 200 OK JSON with redirect_url: '%s'", targetURL)
				}
				resp.Header().Set("Content-Type", "application/json")
				resp.WriteHeader(http.StatusOK)
				respData, _ := json.Marshal(OAuthAuthorizeResponse{
					RedirectURL: targetURL,
					Code:        issuedCode,
					State:       authReq.State,
					Issuer:      effectiveIssuer,
				})
				resp.Write(respData)
			} else {
				if debug {
					log.Printf("[DEBUG] HandleOAuthAuthorize POST: redirecting 302 Found to '%s'", targetURL)
				}
				http.Redirect(resp, request, targetURL, http.StatusFound)
			}
		}

		// Edgecase 12: User Denied Consent
		if !authReq.Approved {
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize POST: user '%s' denied consent for client '%s'", user.Id, client.ClientID)
			}
			redirectURL, pErr := url.Parse(authReq.RedirectURI)
			deniedURL := ""
			if pErr == nil {
				q := redirectURL.Query()
				q.Set("error", "access_denied")
				q.Set("error_description", "User denied access")
				if authReq.State != "" {
					q.Set("state", authReq.State)
				}
				q.Set("iss", effectiveIssuer)
				redirectURL.RawQuery = q.Encode()
				deniedURL = redirectURL.String()
			} else {
				sep := "?"
				if strings.Contains(authReq.RedirectURI, "?") {
					sep = "&"
				}
				deniedURL = fmt.Sprintf("%s%serror=access_denied&error_description=%s&iss=%s",
					authReq.RedirectURI, sep, url.QueryEscape("User denied access"), url.QueryEscape(effectiveIssuer))
				if authReq.State != "" {
					deniedURL += fmt.Sprintf("&state=%s", url.QueryEscape(authReq.State))
				}
			}
			returnRedirect(deniedURL, "")
			return
		}

		// Edgecase 13: Resolve & Verify Org Membership
		selectedOrgId := strings.TrimSpace(authReq.OrgId)
		if selectedOrgId != "" {
			// Verify user actually belongs to this org
			userBelongs := false
			for _, o := range user.Orgs {
				if o == selectedOrgId {
					userBelongs = true
					break
				}
			}
			if !userBelongs && !user.SupportAccess {
				if debug {
					log.Printf("[DEBUG] HandleOAuthAuthorize POST: rejected - user '%s' does not belong to requested org '%s' (user.Orgs: %v)",
						user.Id, selectedOrgId, user.Orgs)
				}
				resp.Header().Set("Content-Type", "application/json")
				resp.WriteHeader(http.StatusForbidden)
				resp.Write([]byte(`{"error": "unauthorized_client", "error_description": "User is not authorized for the requested organization"}`))
				return
			}
		} else {
			// Default to user's active org
			selectedOrgId = user.ActiveOrg.Id
			if selectedOrgId == "" && len(user.Orgs) > 0 {
				selectedOrgId = user.Orgs[0]
			}
		}

		// Edgecase 14: User has no valid organization
		if selectedOrgId == "" {
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize POST: rejected - user '%s' has no valid org", user.Id)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "User must belong to at least one organization"}`))
			return
		}

		// Edgecase 18: Organization Admin Privilege Verification
		isAdmin := isUserOrgAdmin(ctx, user, selectedOrgId)
		if debug {
			log.Printf("[DEBUG] HandleOAuthAuthorize POST: isUserOrgAdmin check for user '%s' in org '%s' -> %v", user.Id, selectedOrgId, isAdmin)
		}
		if !isAdmin {
			if debug {
				log.Printf("[DEBUG] HandleOAuthAuthorize POST: rejected - user '%s' is not an admin of org '%s'", user.Id, selectedOrgId)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusForbidden)
			resp.Write([]byte(`{"error": "access_denied", "error_description": "Only organization administrators can authorize OAuth integrations for this organization"}`))
			return
		}

		// Edgecase 15: Scope defaults, Dynamic OAuth2 privilege escalation protection, and AllowedApps extraction
		postResource := strings.TrimSpace(request.URL.Query().Get("resource"))
		if postResource == "" && rawMap != nil {
			if rVal, ok := rawMap["resource"].(string); ok {
				postResource = strings.TrimSpace(rVal)
			}
		}
		if postResource == "" {
			postResource = strings.TrimSpace(request.FormValue("resource"))
		}
		if client.IsDynamic || strings.HasPrefix(client.ClientID, "shuffle_client_") || isDynamicShuffleClient(client.ClientID, authReq.RedirectURI) {
			cleanedScope, _ := sanitizeDynamicOAuthScope(authReq.Scope)
			authReq.Scope = cleanedScope
		}
		if authReq.Scope == "" {
			authReq.Scope = resolveDefaultOAuthScope(client, postResource)
		}

		allowedApps := authReq.AllowedApps
		if len(allowedApps) == 0 {
			allowedApps = parseAllowedAppsFromScope(authReq.Scope)
		}
		allowedTools := authReq.AllowedTools
		resolvedPostAppPerms, _ := ResolveOAuthAppsAndTools(ctx, user, authReq.Scope, allowedApps, allowedTools, postResource)

		// Generate cryptographically secure authorization code
		codeStr := fmt.Sprintf("shuffle_code_%s", strings.ReplaceAll(uuid.NewV4().String(), "-", ""))

		// Edgecase 16: Code lifetime window
		// Standard RFC recommends short-lived authorization codes (maximum 10 minutes)
		expiresAt := time.Now().Add(10 * time.Minute)

		authCode := OAuthAuthCode{
			ID:                  codeStr,
			Code:                codeStr,
			ClientID:            client.ClientID,
			RedirectURI:         authReq.RedirectURI,
			CodeChallenge:       authReq.CodeChallenge,
			CodeChallengeMethod: authReq.CodeChallengeMethod,
			Scope:               authReq.Scope,
			AllowedApps:         allowedApps,
			AllowedTools:        allowedTools,
			AppPermissions:      resolvedPostAppPerms,
			OrgId:               selectedOrgId,
			UserId:              user.Id,
			ExpiresAt:           expiresAt,
			Used:                false,
			CreatedAt:           time.Now().Unix(),
			RawClientName:       client.RawClientName,
			RawClientURI:        rawClientURIForPost,
			RawLogoURI:          rawLogoURIForPost,
			UserAgent:           client.UserAgent,
			Origin:              client.Origin,
			RemoteAddr:          client.RemoteAddr,
		}

		// Store code in Datastore / OpenSearch
		if err := SetOAuthAuthCode(ctx, authCode); err != nil {
			log.Printf("[ERROR] HandleOAuthAuthorize POST: Failed to persist OAuth authorization code: %v", err)
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusInternalServerError)
			resp.Write([]byte(`{"error": "server_error", "error_description": "Failed to generate authorization code"}`))
			return
		}

		// Edgecase 17: Query parameter concatenation with RFC 9207 iss
		targetRedirect := ""
		redirectURL, pErr := url.Parse(authReq.RedirectURI)
		if pErr == nil {
			q := redirectURL.Query()
			q.Set("code", codeStr)
			if authReq.State != "" {
				q.Set("state", authReq.State)
			}
			q.Set("iss", effectiveIssuer)
			redirectURL.RawQuery = q.Encode()
			targetRedirect = redirectURL.String()
		} else {
			sep := "?"
			if strings.Contains(authReq.RedirectURI, "?") {
				sep = "&"
			}
			targetRedirect = fmt.Sprintf("%s%scode=%s&iss=%s", authReq.RedirectURI, sep, url.QueryEscape(codeStr), url.QueryEscape(effectiveIssuer))
			if authReq.State != "" {
				targetRedirect += fmt.Sprintf("&state=%s", url.QueryEscape(authReq.State))
			}
		}

		if debug {
			log.Printf("[DEBUG] HandleOAuthAuthorize POST: successfully issued code '%s' for client '%s', user '%s', org '%s', allowedApps=%v -> redirecting to: %s",
				codeStr, client.ClientID, user.Id, selectedOrgId, allowedApps, targetRedirect)
		}

		returnRedirect(targetRedirect, codeStr)
		return
	}

	if debug {
		log.Printf("[DEBUG] HandleOAuthAuthorize: unsupported method '%s'", request.Method)
	}
	resp.WriteHeader(http.StatusMethodNotAllowed)
	resp.Write([]byte(`{"error": "invalid_request", "error_description": "Method not allowed"}`))
}

// verifyPKCE validates an RFC 7636 PKCE code_verifier against a code_challenge using the specified method (S256 or plain).
func verifyPKCE(codeVerifier, codeChallenge, method string) bool {
	codeVerifier = strings.TrimSpace(codeVerifier)
	codeChallenge = strings.TrimSpace(codeChallenge)
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "S256"
	}

	if codeVerifier == "" || codeChallenge == "" {
		return false
	}

	if method == "PLAIN" {
		return subtle.ConstantTimeCompare([]byte(codeVerifier), []byte(codeChallenge)) == 1
	}

	if method == "S256" {
		h := sha256.New()
		h.Write([]byte(codeVerifier))
		computedChallenge := base64URLEncode(h.Sum(nil))
		return subtle.ConstantTimeCompare([]byte(computedChallenge), []byte(codeChallenge)) == 1
	}

	return false
}

// parseAllowedAppsFromScope extracts app names or IDs from OAuth scope strings.
// Supports: "app:jira app:slack", "apps:jira,slack", "jira,slack".
func parseAllowedAppsFromScope(scopeStr string) []string {
	apps := []string{}
	parts := strings.Fields(strings.TrimSpace(scopeStr))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "app:") {
			app := strings.TrimPrefix(part, "app:")
			if len(app) > 0 && !ArrayContains(apps, app) {
				apps = append(apps, app)
			}
		} else if strings.HasPrefix(part, "apps:") {
			subParts := strings.Split(strings.TrimPrefix(part, "apps:"), ",")
			for _, sp := range subParts {
				sp = strings.TrimSpace(sp)
				if len(sp) > 0 && !ArrayContains(apps, sp) {
					apps = append(apps, sp)
				}
			}
		}
	}
	return apps
}

// IsAppAllowedForOAuth checks if a given app is permitted under the allowedApps slice.
// If allowedApps is empty or contains "*", all apps are allowed.
func IsAppAllowedForOAuth(allowedApps []string, app WorkflowApp) bool {
	if len(allowedApps) == 0 {
		return true
	}

	appName := strings.ToLower(strings.TrimSpace(app.Name))
	appSlug := strings.ToLower(strings.ReplaceAll(appName, " ", "_"))
	appId := strings.ToLower(strings.TrimSpace(app.ID))

	for _, allowed := range allowedApps {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		if allowed == "*" || allowed == "all" || allowed == "mcp" {
			return true
		}
		if allowed == appId || allowed == appName || allowed == appSlug {
			return true
		}
		cleanAllowed := strings.TrimPrefix(allowed, "app:")
		if cleanAllowed == appId || cleanAllowed == appName || cleanAllowed == appSlug {
			return true
		}
		if strings.Contains(cleanAllowed, ":") {
			for _, seg := range strings.Split(cleanAllowed, ":") {
				seg = strings.TrimSpace(seg)
				if len(seg) > 0 && (seg == appId || seg == appName || seg == appSlug) {
					return true
				}
			}
		}
	}

	return false
}

// validateOAuthClientSecret validates confidential / server-based OAuth2 client credentials
// (client_secret_basic or client_secret_post) when a client has a configured ClientSecret
// or when SHUFFLE_OAUTH_CLIENT_SECRET is set.
func validateOAuthClientSecret(ctx context.Context, clientID, providedSecret string) error {
	clientID = strings.TrimSpace(clientID)
	providedSecret = strings.TrimSpace(providedSecret)
	if clientID == "" {
		return nil
	}

	envSecret := strings.TrimSpace(os.Getenv("SHUFFLE_OAUTH_CLIENT_SECRET"))

	client, err := GetOAuthClient(ctx, clientID)
	if err == nil && client != nil && client.ClientSecret != "" {
		requiresSecret := client.TokenEndpointAuthMethod == "client_secret_basic" ||
			client.TokenEndpointAuthMethod == "client_secret_post" ||
			providedSecret != ""
		if requiresSecret {
			if providedSecret == "" {
				return errors.New("client_secret is required for confidential client")
			}
			matchesClient := subtle.ConstantTimeCompare([]byte(providedSecret), []byte(client.ClientSecret)) == 1
			matchesEnv := envSecret != "" && subtle.ConstantTimeCompare([]byte(providedSecret), []byte(envSecret)) == 1
			if !matchesClient && !matchesEnv {
				return errors.New("Invalid client_secret")
			}
		}
		return nil
	}

	if envSecret != "" && providedSecret != "" {
		if subtle.ConstantTimeCompare([]byte(providedSecret), []byte(envSecret)) != 1 {
			return errors.New("Invalid client_secret")
		}
	}

	return nil
}

// HandleOAuthToken handles the OAuth 2.0 / 2.1 token issuance and refresh endpoint.
//
// Routes:
//   POST /oauth2/token
//   POST /api/v1/oauth2/token
//
// Grant Types Supported:
//   - authorization_code: Exchanges a temporary authorization code + PKCE code_verifier for an access_token.
//   - refresh_token: Rotates an existing refresh token for a fresh access_token.
func HandleOAuthToken(resp http.ResponseWriter, request *http.Request) {
	if debug {
		log.Printf("[DEBUG] HandleOAuthToken: incoming %s %s from %s (contentType: '%s', AuthHeaderLen: %d)",
			request.Method, request.URL.Path, request.RemoteAddr, request.Header.Get("Content-Type"), len(request.Header.Get("Authorization")))
	}

	cors := HandleCors(resp, request)
	if cors {
		if debug {
			log.Printf("[DEBUG] HandleOAuthToken: handled CORS preflight for %s %s", request.Method, request.URL.Path)
		}
		return
	}

	// Rate limiting: Protect against automated brute-forcing or DoS
	if err := ValidateRequestOverload(resp, request, 30); err != nil {
		if debug {
			log.Printf("[DEBUG] HandleOAuthToken: rate limited: %v", err)
		}
		resp.Header().Set("Content-Type", "application/json")
		resp.Header().Set("Cache-Control", "no-store")
		resp.WriteHeader(http.StatusTooManyRequests)
		resp.Write([]byte(`{"error": "slow_down", "error_description": "Too many requests"}`))
		return
	}

	if request.Method != "POST" {
		if debug {
			log.Printf("[DEBUG] HandleOAuthToken: rejected - invalid method '%s' (only POST allowed)", request.Method)
		}
		resp.Header().Set("Content-Type", "application/json")
		resp.Header().Set("Cache-Control", "no-store")
		resp.WriteHeader(http.StatusMethodNotAllowed)
		resp.Write([]byte(`{"error": "invalid_request", "error_description": "Only POST method is allowed"}`))
		return
	}

	ctx := GetContext(request)

	// Parse parameters from JSON or Form-URL-Encoded body
	var tokenReq OAuthTokenRequest
	contentType := request.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		body, rErr := ioutil.ReadAll(request.Body)
		if rErr != nil {
			if debug {
				log.Printf("[DEBUG] HandleOAuthToken: rejected - failed to read request body: %v", rErr)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "Failed to read request body"}`))
			return
		}
		if err := json.Unmarshal(body, &tokenReq); err != nil {
			if debug {
				log.Printf("[DEBUG] HandleOAuthToken: rejected - JSON unmarshal error: %v, rawBody: %s", err, string(body))
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "Invalid JSON payload"}`))
			return
		}
	} else {
		if err := request.ParseForm(); err != nil {
			if debug {
				log.Printf("[DEBUG] HandleOAuthToken: rejected - failed to parse form data: %v", err)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "Failed to parse form data"}`))
			return
		}
		tokenReq.GrantType = strings.TrimSpace(request.FormValue("grant_type"))
		tokenReq.Code = strings.TrimSpace(request.FormValue("code"))
		tokenReq.RedirectURI = strings.TrimSpace(request.FormValue("redirect_uri"))
		tokenReq.ClientID = strings.TrimSpace(request.FormValue("client_id"))
		tokenReq.ClientSecret = strings.TrimSpace(request.FormValue("client_secret"))
		tokenReq.CodeVerifier = strings.TrimSpace(request.FormValue("code_verifier"))
		tokenReq.RefreshToken = strings.TrimSpace(request.FormValue("refresh_token"))
		tokenReq.Scope = strings.TrimSpace(request.FormValue("scope"))
	}

	// Support HTTP Basic Authentication for Client Credentials (client_secret_basic)
	basicUser, basicPass, hasBasic := request.BasicAuth()
	if hasBasic {
		if decodedUser, err := url.QueryUnescape(basicUser); err == nil {
			basicUser = decodedUser
		}
		if decodedPass, err := url.QueryUnescape(basicPass); err == nil {
			basicPass = decodedPass
		}
		if tokenReq.ClientID == "" {
			tokenReq.ClientID = strings.TrimSpace(basicUser)
		}
		if tokenReq.ClientSecret == "" {
			tokenReq.ClientSecret = strings.TrimSpace(basicPass)
		}
		if debug {
			log.Printf("[DEBUG] HandleOAuthToken: extracted credentials for client_id '%s' from HTTP Basic Auth", tokenReq.ClientID)
		}
	}

	if debug {
		log.Printf("[DEBUG] HandleOAuthToken parsed: grant_type='%s', client_id='%s', redirect_uri='%s', code='%s', code_verifier_len=%d, refresh_token_len=%d, scope='%s'",
			tokenReq.GrantType, tokenReq.ClientID, tokenReq.RedirectURI, tokenReq.Code, len(tokenReq.CodeVerifier), len(tokenReq.RefreshToken), tokenReq.Scope)
	}

	switch tokenReq.GrantType {
	case "authorization_code":
		// Edgecase 1: Missing code
		if tokenReq.Code == "" {
			if debug {
				log.Printf("[DEBUG] HandleOAuthToken [authorization_code]: rejected - missing 'code' parameter")
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "code parameter is required"}`))
			return
		}

		// Edgecase 2: Missing redirect_uri
		if tokenReq.RedirectURI == "" {
			if debug {
				log.Printf("[DEBUG] HandleOAuthToken [authorization_code]: rejected - missing 'redirect_uri' parameter for code '%s'", tokenReq.Code)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "redirect_uri parameter is required"}`))
			return
		}

		// Retrieve and validate Authorization Code
		if debug {
			log.Printf("[DEBUG] HandleOAuthToken [authorization_code]: looking up auth code '%s' in datastore", tokenReq.Code)
		}
		authCode, err := GetOAuthAuthCode(ctx, tokenReq.Code)
		if err != nil || authCode == nil || authCode.Code == "" {
			if debug {
				log.Printf("[DEBUG] HandleOAuthToken [authorization_code]: rejected - auth code '%s' not found or error: %v", tokenReq.Code, err)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_grant", "error_description": "Authorization code is invalid or not found"}`))
			return
		}

		if debug {
			log.Printf("[DEBUG] HandleOAuthToken [authorization_code]: retrieved authCode: code='%s', client_id='%s', redirect_uri='%s', used=%v, expiresAt=%v, user='%s', org='%s', challenge_len=%d, challenge_method='%s'",
				authCode.Code, authCode.ClientID, authCode.RedirectURI, authCode.Used, authCode.ExpiresAt, authCode.UserId, authCode.OrgId, len(authCode.CodeChallenge), authCode.CodeChallengeMethod)
		}

		// Edgecase 3: Single-Use Protection (Replay Prevention)
		if authCode.Used {
			if debug {
				log.Printf("[DEBUG] HandleOAuthToken [authorization_code]: rejected - auth code '%s' was already used", authCode.Code)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_grant", "error_description": "Authorization code has already been used"}`))
			return
		}

		// Edgecase 4: Expiration Check
		if !authCode.ExpiresAt.IsZero() && time.Now().After(authCode.ExpiresAt) {
			if debug {
				log.Printf("[DEBUG] HandleOAuthToken [authorization_code]: rejected - auth code '%s' expired at %v (current time %v)",
					authCode.Code, authCode.ExpiresAt, time.Now())
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_grant", "error_description": "Authorization code has expired"}`))
			return
		}

		// Edgecase 5: Client ID Mismatch & Confidential Client Secret Verification
		if authCode.ClientID != "" {
			if tokenReq.ClientID == "" {
				if debug {
					log.Printf("[DEBUG] HandleOAuthToken [authorization_code]: rejected - client_id is required but was empty in request (authCode client_id='%s')", authCode.ClientID)
				}
				resp.Header().Set("Content-Type", "application/json")
				resp.Header().Set("Cache-Control", "no-store")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write([]byte(`{"error": "invalid_client", "error_description": "client_id is required"}`))
				return
			}
			if tokenReq.ClientID != authCode.ClientID {
				if debug {
					log.Printf("[DEBUG] HandleOAuthToken [authorization_code]: rejected - client_id mismatch: request has '%s', authCode requires '%s'",
						tokenReq.ClientID, authCode.ClientID)
				}
				resp.Header().Set("Content-Type", "application/json")
				resp.Header().Set("Cache-Control", "no-store")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write([]byte(`{"error": "invalid_client", "error_description": "client_id does not match authorization code"}`))
				return
			}
			if secretErr := validateOAuthClientSecret(ctx, tokenReq.ClientID, tokenReq.ClientSecret); secretErr != nil {
				if debug {
					log.Printf("[DEBUG] HandleOAuthToken [authorization_code]: rejected - client_secret validation failed for '%s': %v", tokenReq.ClientID, secretErr)
				}
				resp.Header().Set("Content-Type", "application/json")
				resp.Header().Set("Cache-Control", "no-store")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write([]byte(fmt.Sprintf(`{"error": "invalid_client", "error_description": %q}`, secretErr.Error())))
				return
			}
		}

		// Edgecase 6: Redirect URI Mismatch
		if tokenReq.RedirectURI != "" && authCode.RedirectURI != "" && tokenReq.RedirectURI != authCode.RedirectURI {
			if debug {
				log.Printf("[DEBUG] HandleOAuthToken [authorization_code]: rejected - redirect_uri mismatch: tokenReq.RedirectURI='%s' vs authCode.RedirectURI='%s'",
					tokenReq.RedirectURI, authCode.RedirectURI)
			}
			// Invalidate the authorization code on redirect_uri mismatch so an intercepted code cannot be replayed
			_ = DeleteOAuthAuthCode(ctx, authCode.Code)
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_grant", "error_description": "redirect_uri does not match original authorization request"}`))
			return
		}

		// Edgecase 7: PKCE Verification
		if authCode.CodeChallenge != "" {
			if tokenReq.CodeVerifier == "" {
				if debug {
					log.Printf("[DEBUG] HandleOAuthToken [authorization_code]: rejected - code_verifier is required for PKCE validation")
				}
				resp.Header().Set("Content-Type", "application/json")
				resp.Header().Set("Cache-Control", "no-store")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write([]byte(`{"error": "invalid_request", "error_description": "code_verifier is required for PKCE validation"}`))
				return
			}

			pkcePassed := verifyPKCE(tokenReq.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod)
			if !pkcePassed {
				if debug {
					log.Printf("[DEBUG] HandleOAuthToken [authorization_code]: rejected - PKCE verification failed for code_verifier (len: %d) against challenge '%s' (method: '%s')",
						len(tokenReq.CodeVerifier), authCode.CodeChallenge, authCode.CodeChallengeMethod)
				}
				// Invalidate the authorization code on PKCE verification failure so an attacker cannot brute-force or retry it
				_ = DeleteOAuthAuthCode(ctx, authCode.Code)
				resp.Header().Set("Content-Type", "application/json")
				resp.Header().Set("Cache-Control", "no-store")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write([]byte(`{"error": "invalid_grant", "error_description": "PKCE verification failed: invalid code_verifier"}`))
				return
			}
			if debug {
				log.Printf("[DEBUG] HandleOAuthToken [authorization_code]: PKCE verification passed (method: '%s')", authCode.CodeChallengeMethod)
			}
		}

		// Delete code to guarantee single-use
		if debug {
			log.Printf("[DEBUG] HandleOAuthToken [authorization_code]: deleting used auth code '%s'", authCode.Code)
		}
		_ = DeleteOAuthAuthCode(ctx, authCode.Code)

		// Generate Access Token and Refresh Token
		accessToken := fmt.Sprintf("shfl_mcp_%s", strings.ReplaceAll(uuid.NewV4().String(), "-", ""))
		refreshToken := fmt.Sprintf("shfl_mcp_refresh_%s", strings.ReplaceAll(uuid.NewV4().String(), "-", ""))
		expiresIn := int64(30 * 24 * 3600) // 30 days
		expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

		tokenUA := strings.TrimSpace(request.Header.Get("User-Agent"))
		tokenIP := extractRequestClientIP(request)
		tokenOrigin := extractRequestOrigin(request)

		var regClient *OAuthClient
		if authCode.ClientID != "" {
			if c, cErr := GetOAuthClient(ctx, authCode.ClientID); cErr == nil && c != nil {
				regClient = c
			}
		}

		rawClientName := authCode.RawClientName
		rawRedirectURI := authCode.RedirectURI
		rawClientURI := authCode.RawClientURI
		rawLogoURI := authCode.RawLogoURI
		softwareID := ""
		softwareVer := ""
		origUA := authCode.UserAgent
		origOrigin := authCode.Origin
		origIP := authCode.RemoteAddr
		mcpClientName := ""
		mcpClientVer := ""
		mcpUA := ""

		if regClient != nil {
			if rawClientName == "" {
				rawClientName = regClient.RawClientName
			}
			if rawRedirectURI == "" {
				rawRedirectURI = regClient.RawRedirectURI
				if rawRedirectURI == "" && len(regClient.RedirectUris) > 0 {
					rawRedirectURI = regClient.RedirectUris[0]
				}
			}
			if rawClientURI == "" {
				rawClientURI = regClient.RawClientURI
				if rawClientURI == "" {
					rawClientURI = regClient.ClientURI
				}
			}
			if rawLogoURI == "" {
				rawLogoURI = regClient.RawLogoURI
			}
			softwareID = regClient.SoftwareID
			softwareVer = regClient.SoftwareVersion
			if origUA == "" {
				origUA = regClient.UserAgent
			}
			if origOrigin == "" {
				origOrigin = regClient.Origin
			}
			if origIP == "" {
				origIP = regClient.RemoteAddr
			}
			mcpClientName = regClient.MCPClientName
			mcpClientVer = regClient.MCPClientVersion
			mcpUA = regClient.MCPUserAgent
		}
		if origOrigin == "" {
			origOrigin = tokenOrigin
		}

		evalUA := origUA
		if evalUA == "" || strings.HasPrefix(strings.ToLower(evalUA), "mozilla/") {
			if tokenUA != "" && !strings.HasPrefix(strings.ToLower(tokenUA), "mozilla/") {
				evalUA = tokenUA
			}
		}

		eval := EvaluateOAuthVendorIdentity(
			authCode.ClientID,
			rawClientName,
			rawRedirectURI,
			rawClientURI,
			rawLogoURI,
			softwareID,
			evalUA,
			mcpClientName,
		)

		oauthToken := OAuthToken{
			ID:                 fmt.Sprintf("mcp_conn_%s", strings.ReplaceAll(uuid.NewV4().String(), "-", "")),
			AccessToken:        accessToken,
			RefreshToken:       refreshToken,
			TokenType:          "Bearer",
			Scope:              authCode.Scope,
			AllowedApps:        authCode.AllowedApps,
			AllowedTools:       authCode.AllowedTools,
			AppPermissions:     authCode.AppPermissions,
			ExpiresIn:          expiresIn,
			ExpiresAt:          expiresAt,
			ClientID:           authCode.ClientID,
			OrgId:              authCode.OrgId,
			UserId:             authCode.UserId,
			CreatedAt:          time.Now().Unix(),
			RedirectURI:        authCode.RedirectURI,
			VendorID:           eval.VendorID,
			VendorName:         eval.VendorName,
			ImageID:            eval.ImageID,
			VendorVerified:     eval.VendorVerified,
			VerificationStatus: eval.VerificationStatus,
			VerificationReason: eval.VerificationReason,
			VerifiedDomain:     eval.VerifiedDomain,
			ClaimedVendorID:    eval.ClaimedVendorID,
			ClaimedVendorName:  eval.ClaimedVendorName,
			VendorSpoofWarning: eval.VendorSpoofWarning,
			RawClientName:      rawClientName,
			RawRedirectURI:     rawRedirectURI,
			RawClientURI:       rawClientURI,
			RawLogoURI:         rawLogoURI,
			SoftwareID:         softwareID,
			SoftwareVersion:    softwareVer,
			UserAgent:          origUA,
			TokenUserAgent:     tokenUA,
			Origin:             origOrigin,
			RemoteAddr:         origIP,
			TokenRemoteAddr:    tokenIP,
			MCPClientName:      mcpClientName,
			MCPClientVersion:   mcpClientVer,
			MCPUserAgent:       mcpUA,
		}

		if err := SetOAuthToken(ctx, oauthToken); err != nil {
			log.Printf("[ERROR] HandleOAuthToken [authorization_code]: Failed to persist OAuth token: %v", err)
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusInternalServerError)
			resp.Write([]byte(`{"error": "server_error", "error_description": "Failed to persist OAuth token"}`))
			return
		}

		userEmail := ""
		if authCode.UserId != "" {
			if userObj, uErr := safeGetUserForOAuth(ctx, authCode.UserId); uErr == nil && userObj != nil && len(userObj.Username) > 0 {
				userEmail = userObj.Username
			}
		}

		tokenResp := OAuthTokenResponse{
			AccessToken:  accessToken,
			TokenType:    "Bearer",
			ExpiresIn:    expiresIn,
			RefreshToken: refreshToken,
			Scope:        authCode.Scope,
			Email:        userEmail,
			Username:     userEmail,
		}

		respData, err := json.Marshal(tokenResp)
		if err != nil {
			log.Printf("[ERROR] HandleOAuthToken [authorization_code]: Failed to marshal token response: %v", err)
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusInternalServerError)
			return
		}

		if debug {
			masked := accessToken
			if len(masked) > 12 {
				masked = masked[:12] + "..."
			}
			log.Printf("[DEBUG] HandleOAuthToken [authorization_code]: SUCCESS issued token %s (connID: %s) for user %s, org %s, scopes: '%s', allowedApps: %v, expiresIn: %d",
				masked, oauthToken.ID, authCode.UserId, authCode.OrgId, authCode.Scope, authCode.AllowedApps, expiresIn)
		}

		resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
		resp.Header().Set("Cache-Control", "no-store")
		resp.Header().Set("Pragma", "no-cache")
		resp.WriteHeader(http.StatusOK)
		resp.Write(respData)
		return

	case "refresh_token":
		// Edgecase 8: Missing refresh_token
		if tokenReq.RefreshToken == "" {
			if debug {
				log.Printf("[DEBUG] HandleOAuthToken [refresh_token]: rejected - missing refresh_token")
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "refresh_token parameter is required"}`))
			return
		}

		// Retrieve existing token by refresh token
		if debug {
			log.Printf("[DEBUG] HandleOAuthToken [refresh_token]: looking up refresh_token (len: %d)", len(tokenReq.RefreshToken))
		}
		oldToken, err := GetOAuthTokenByRefreshToken(ctx, tokenReq.RefreshToken)
		if err != nil || oldToken == nil || oldToken.AccessToken == "" {
			// Grace period check: if a client retried a refresh request due to a network blip or
			// sent concurrent refresh requests within 60s of rotation, return the rotated token response
			// so the handoff/refresh never fails with invalid_grant.
			cachedGraceData, gErr := GetCache(ctx, "oauth_refresh_grace_"+tokenReq.RefreshToken)
			graceData, ok := cachedGraceData.([]byte)
			if gErr == nil && ok && len(graceData) > 0 {
				if tokenReq.ClientID != "" {
					if cachedClientRaw, cErr := GetCache(ctx, "oauth_refresh_grace_client_"+tokenReq.RefreshToken); cErr == nil {
						if cachedClientBytes, cOk := cachedClientRaw.([]byte); cOk && len(cachedClientBytes) > 0 {
							expectedClientID := strings.TrimSpace(string(cachedClientBytes))
							if expectedClientID != "" && tokenReq.ClientID != expectedClientID {
								resp.Header().Set("Content-Type", "application/json")
								resp.Header().Set("Cache-Control", "no-store")
								resp.WriteHeader(http.StatusBadRequest)
								resp.Write([]byte(`{"error": "invalid_client", "error_description": "client_id does not match refresh token"}`))
								return
							}
						}
					}
				}
				if tokenReq.ClientID != "" && tokenReq.ClientSecret != "" {
					if secretErr := validateOAuthClientSecret(ctx, tokenReq.ClientID, tokenReq.ClientSecret); secretErr != nil {
						resp.Header().Set("Content-Type", "application/json")
						resp.Header().Set("Cache-Control", "no-store")
						resp.WriteHeader(http.StatusBadRequest)
						resp.Write([]byte(fmt.Sprintf(`{"error": "invalid_client", "error_description": %q}`, secretErr.Error())))
						return
					}
				}
				if debug {
					log.Printf("[DEBUG] HandleOAuthToken [refresh_token]: serving grace-period cached response for recently rotated refresh_token")
				}
				resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
				resp.Header().Set("Cache-Control", "no-store")
				resp.Header().Set("Pragma", "no-cache")
				resp.WriteHeader(http.StatusOK)
				resp.Write(graceData)
				return
			}

			if debug {
				log.Printf("[DEBUG] HandleOAuthToken [refresh_token]: rejected - refresh token not found or error: %v", err)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_grant", "error_description": "Invalid or expired refresh token"}`))
			return
		}

		if debug {
			log.Printf("[DEBUG] HandleOAuthToken [refresh_token]: found old token (ID: %s, user: %s, org: %s, client: %s, expiresAt: %v)",
				oldToken.ID, oldToken.UserId, oldToken.OrgId, oldToken.ClientID, oldToken.ExpiresAt)
		}

		// Edgecase 9: Client ID mismatch & Confidential Client Secret Verification on refresh
		if tokenReq.ClientID != "" && oldToken.ClientID != "" && tokenReq.ClientID != oldToken.ClientID {
			if debug {
				log.Printf("[DEBUG] HandleOAuthToken [refresh_token]: rejected - client_id mismatch: request has '%s', token has '%s'",
					tokenReq.ClientID, oldToken.ClientID)
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_client", "error_description": "client_id does not match refresh token"}`))
			return
		}
		effectiveRefreshClientID := tokenReq.ClientID
		if effectiveRefreshClientID == "" {
			effectiveRefreshClientID = oldToken.ClientID
		}
		// Only validate client_secret on refresh when the caller actually provides one, so clients
		// that omit client_secret (or client_id) during refresh_token rotation never fail unexpectedly.
		if effectiveRefreshClientID != "" && tokenReq.ClientSecret != "" {
			if secretErr := validateOAuthClientSecret(ctx, effectiveRefreshClientID, tokenReq.ClientSecret); secretErr != nil {
				if debug {
					log.Printf("[DEBUG] HandleOAuthToken [refresh_token]: rejected - client_secret validation failed for '%s': %v", effectiveRefreshClientID, secretErr)
				}
				resp.Header().Set("Content-Type", "application/json")
				resp.Header().Set("Cache-Control", "no-store")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write([]byte(fmt.Sprintf(`{"error": "invalid_client", "error_description": %q}`, secretErr.Error())))
				return
			}
		}

		// Edgecase 10: Validate Scope Downscoping (RFC 6749 Section 6)
		// SECURITY: Every requested scope (both non-app and app: scopes) must be a subset of oldToken.Scope.
		// Never allow a refresh_token request to escalate privileges (e.g. workflow:read -> workflow:edit or admin).
		effectiveScope := oldToken.Scope
		effectiveAllowedApps := oldToken.AllowedApps

		if tokenReq.Scope != "" && tokenReq.Scope != oldToken.Scope {
			oldScopeParts := strings.Fields(strings.ToLower(strings.TrimSpace(oldToken.Scope)))
			hasWildcardOldScope := false
			for _, op := range oldScopeParts {
				if op == "*" || op == "admin" || op == "all" {
					hasWildcardOldScope = true
					break
				}
			}

			for _, reqPart := range strings.Fields(strings.TrimSpace(tokenReq.Scope)) {
				reqLower := strings.ToLower(strings.TrimSpace(reqPart))
				if strings.HasPrefix(reqLower, "app:") || strings.HasPrefix(reqLower, "apps:") {
					continue
				}
				if hasWildcardOldScope {
					continue
				}
				foundInOld := false
				for _, op := range oldScopeParts {
					if op == reqLower {
						foundInOld = true
						break
					}
				}
				if !foundInOld {
					if debug {
						log.Printf("[DEBUG] HandleOAuthToken [refresh_token]: rejected - requested scope '%s' not permitted by original granted scopes '%s'",
							reqPart, oldToken.Scope)
					}
					resp.Header().Set("Content-Type", "application/json")
					resp.Header().Set("Cache-Control", "no-store")
					resp.WriteHeader(http.StatusBadRequest)
					resp.Write([]byte(`{"error": "invalid_scope", "error_description": "Requested scope contains permissions not granted in original authorization"}`))
					return
				}
			}

			requestedApps := parseAllowedAppsFromScope(tokenReq.Scope)
			if len(requestedApps) > 0 {
				for _, app := range requestedApps {
					allowed := false
					for _, oldApp := range oldToken.AllowedApps {
						if oldApp == "*" || oldApp == "all" || strings.EqualFold(oldApp, app) {
							allowed = true
							break
						}
					}
					if !allowed {
						if debug {
							log.Printf("[DEBUG] HandleOAuthToken [refresh_token]: rejected - requested app '%s' not permitted by original granted apps %v",
								app, oldToken.AllowedApps)
						}
						resp.Header().Set("Content-Type", "application/json")
						resp.Header().Set("Cache-Control", "no-store")
						resp.WriteHeader(http.StatusBadRequest)
						resp.Write([]byte(`{"error": "invalid_scope", "error_description": "Requested scope contains permissions not granted in original authorization"}`))
						return
					}
				}
				effectiveAllowedApps = requestedApps
			}
			effectiveScope = tokenReq.Scope
		}

		// Rotate token: Issue new access token and refresh token
		newAccessToken := fmt.Sprintf("shfl_mcp_%s", strings.ReplaceAll(uuid.NewV4().String(), "-", ""))
		newRefreshToken := fmt.Sprintf("shfl_mcp_refresh_%s", strings.ReplaceAll(uuid.NewV4().String(), "-", ""))
		expiresIn := int64(30 * 24 * 3600) // 30 days
		expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

		connID := oldToken.ID
		if connID == "" {
			connID = fmt.Sprintf("mcp_conn_%s", strings.ReplaceAll(uuid.NewV4().String(), "-", ""))
		}

		refreshUA := strings.TrimSpace(request.Header.Get("User-Agent"))
		if refreshUA == "" {
			refreshUA = oldToken.TokenUserAgent
		}
		refreshIP := extractRequestClientIP(request)
		if refreshIP == "" {
			refreshIP = oldToken.TokenRemoteAddr
		}

		newToken := OAuthToken{
			ID:                 connID,
			AccessToken:        newAccessToken,
			RefreshToken:       newRefreshToken,
			TokenType:          "Bearer",
			Scope:              effectiveScope,
			AllowedApps:        effectiveAllowedApps,
			AllowedTools:       oldToken.AllowedTools,
			AppPermissions:     oldToken.AppPermissions,
			ExpiresIn:          expiresIn,
			ExpiresAt:          expiresAt,
			ClientID:           oldToken.ClientID,
			OrgId:              oldToken.OrgId,
			UserId:             oldToken.UserId,
			CreatedAt:          time.Now().Unix(),
			RedirectURI:        oldToken.RedirectURI,
			VendorID:           oldToken.VendorID,
			VendorName:         oldToken.VendorName,
			ImageID:            oldToken.ImageID,
			VendorVerified:     oldToken.VendorVerified,
			VerificationStatus: oldToken.VerificationStatus,
			VerificationReason: oldToken.VerificationReason,
			VerifiedDomain:     oldToken.VerifiedDomain,
			ClaimedVendorID:    oldToken.ClaimedVendorID,
			ClaimedVendorName:  oldToken.ClaimedVendorName,
			VendorSpoofWarning: oldToken.VendorSpoofWarning,
			RawClientName:      oldToken.RawClientName,
			RawRedirectURI:     oldToken.RawRedirectURI,
			RawClientURI:       oldToken.RawClientURI,
			RawLogoURI:         oldToken.RawLogoURI,
			SoftwareID:         oldToken.SoftwareID,
			SoftwareVersion:    oldToken.SoftwareVersion,
			UserAgent:          oldToken.UserAgent,
			TokenUserAgent:     refreshUA,
			Origin:             oldToken.Origin,
			RemoteAddr:         oldToken.RemoteAddr,
			TokenRemoteAddr:    refreshIP,
			MCPClientName:      oldToken.MCPClientName,
			MCPClientVersion:   oldToken.MCPClientVersion,
			MCPUserAgent:       oldToken.MCPUserAgent,
		}

		// Persist the new token BEFORE deleting the old token so a transient storage failure
		// can never leave the client without a valid token.
		if err := SetOAuthToken(ctx, newToken); err != nil {
			log.Printf("[ERROR] HandleOAuthToken [refresh_token]: Failed to persist refreshed OAuth token: %v", err)
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusInternalServerError)
			resp.Write([]byte(`{"error": "server_error", "error_description": "Failed to persist refreshed OAuth token"}`))
			return
		}

		refreshedUserEmail := ""
		if oldToken.UserId != "" {
			if userObj, uErr := safeGetUserForOAuth(ctx, oldToken.UserId); uErr == nil && userObj != nil && len(userObj.Username) > 0 {
				refreshedUserEmail = userObj.Username
			}
		}

		tokenResp := OAuthTokenResponse{
			AccessToken:  newAccessToken,
			TokenType:    "Bearer",
			ExpiresIn:    expiresIn,
			RefreshToken: newRefreshToken,
			Scope:        effectiveScope,
			Email:        refreshedUserEmail,
			Username:     refreshedUserEmail,
		}

		respData, err := json.Marshal(tokenResp)
		if err != nil {
			log.Printf("[ERROR] HandleOAuthToken [refresh_token]: Failed to marshal refresh token response: %v", err)
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Cache the new token response under a 60-second grace key for the old refresh token
		// before invalidating the old token records.
		_ = SetCache(ctx, "oauth_refresh_grace_"+tokenReq.RefreshToken, respData, 60)
		if oldToken.ClientID != "" {
			_ = SetCache(ctx, "oauth_refresh_grace_client_"+tokenReq.RefreshToken, []byte(oldToken.ClientID), 60)
		}

		// Invalidate old access token and old refresh token index
		if debug {
			log.Printf("[DEBUG] HandleOAuthToken [refresh_token]: deleting old access token")
		}
		_ = DeleteOAuthToken(ctx, oldToken.AccessToken)
		if oldToken.RefreshToken != "" && oldToken.RefreshToken != newRefreshToken {
			_ = DeleteKey(ctx, "oauth_refresh", oldToken.RefreshToken)
		}

		if debug {
			masked := newAccessToken
			if len(masked) > 12 {
				masked = masked[:12] + "..."
			}
			log.Printf("[DEBUG] HandleOAuthToken [refresh_token]: SUCCESS refreshed token %s (connID: %s) for user %s, org %s, scopes: '%s'",
				masked, newToken.ID, oldToken.UserId, oldToken.OrgId, effectiveScope)
		}

		resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
		resp.Header().Set("Cache-Control", "no-store")
		resp.Header().Set("Pragma", "no-cache")
		resp.WriteHeader(http.StatusOK)
		resp.Write(respData)
		return

	default:
		if debug {
			log.Printf("[DEBUG] HandleOAuthToken: rejected - unsupported grant_type '%s'", tokenReq.GrantType)
		}
		resp.Header().Set("Content-Type", "application/json")
		resp.Header().Set("Cache-Control", "no-store")
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte(`{"error": "unsupported_grant_type", "error_description": "grant_type must be authorization_code or refresh_token"}`))
		return
	}
}

// HandleOAuthRevoke implements RFC 7009 OAuth 2.0 Token Revocation.
//
// Routes:
//   POST /oauth2/revoke
//   POST /api/v1/oauth2/revoke
//
// Parameters (JSON or application/x-www-form-urlencoded):
//   - token: The token to revoke (access token or refresh token)
//   - token_type_hint: "access_token" or "refresh_token" (optional)
//   - client_id / client_secret: Optional client credentials
//
// Also supports Shuffle frontend user revocation when called by an authenticated user.
func HandleOAuthRevoke(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	if err := ValidateRequestOverload(resp, request, 30); err != nil {
		resp.Header().Set("Content-Type", "application/json")
		resp.Header().Set("Cache-Control", "no-store")
		resp.WriteHeader(http.StatusTooManyRequests)
		resp.Write([]byte(`{"error": "slow_down", "error_description": "Too many requests"}`))
		return
	}

	if request.Method != "POST" {
		resp.Header().Set("Content-Type", "application/json")
		resp.Header().Set("Cache-Control", "no-store")
		resp.WriteHeader(http.StatusMethodNotAllowed)
		resp.Write([]byte(`{"error": "invalid_request", "error_description": "Only POST is allowed"}`))
		return
	}

	ctx := GetContext(request)

	var revokeReq OAuthRevokeRequest
	contentType := request.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		body, rErr := ioutil.ReadAll(request.Body)
		if rErr != nil {
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "Failed to read body"}`))
			return
		}
		if err := json.Unmarshal(body, &revokeReq); err != nil {
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "Invalid JSON format"}`))
			return
		}
	} else {
		request.ParseForm()
		revokeReq.Token = strings.TrimSpace(request.FormValue("token"))
		revokeReq.TokenTypeHint = strings.TrimSpace(request.FormValue("token_type_hint"))
		revokeReq.ClientID = strings.TrimSpace(request.FormValue("client_id"))
		revokeReq.ClientSecret = strings.TrimSpace(request.FormValue("client_secret"))
	}

	basicUser, basicPass, hasBasic := request.BasicAuth()
	if hasBasic && revokeReq.ClientID == "" {
		revokeReq.ClientID = strings.TrimSpace(basicUser)
		revokeReq.ClientSecret = strings.TrimSpace(basicPass)
	}

	if revokeReq.Token == "" {
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte(`{"error": "invalid_request", "error_description": "token parameter is required"}`))
		return
	}

	// 1. First, check if the token can be found as an AccessToken
	token, err := GetOAuthToken(ctx, revokeReq.Token)
	if err != nil || token == nil || token.AccessToken == "" {
		// 2. Fall back to search as a RefreshToken
		token, err = GetOAuthTokenByRefreshToken(ctx, revokeReq.Token)
	}
	if err != nil || token == nil || token.AccessToken == "" {
		// 3. Fall back to search by Connection ID (mcp_conn_...) or masked token prefix
		if currentUser, uErr := getOAuthUser(resp, request); uErr == nil && len(currentUser.Id) > 0 {
			matchesRevokeTarget := func(ot OAuthToken) bool {
				if ot.ID == revokeReq.Token {
					return true
				}
				if len(ot.AccessToken) > 12 && ot.AccessToken[:12]+"..." == revokeReq.Token {
					return true
				}
				return false
			}

			// Search user's own tokens first
			if userTokens, tErr := GetOAuthTokensByUser(ctx, currentUser.Id); tErr == nil {
				for _, ot := range userTokens {
					if matchesRevokeTarget(ot) {
						tokCopy := ot
						token = &tokCopy
						break
					}
				}
			}

			// Search active org and user's orgs if not yet found
			if token == nil || token.AccessToken == "" {
				orgsToSearch := []string{}
				if currentUser.ActiveOrg.Id != "" {
					orgsToSearch = append(orgsToSearch, currentUser.ActiveOrg.Id)
				}
				for _, o := range currentUser.Orgs {
					if o != "" && !ArrayContains(orgsToSearch, o) {
						orgsToSearch = append(orgsToSearch, o)
					}
				}
				for _, searchOrgId := range orgsToSearch {
					if orgTokens, tErr := GetOAuthTokensByOrg(ctx, searchOrgId); tErr == nil {
						for _, ot := range orgTokens {
							if matchesRevokeTarget(ot) {
								tokCopy := ot
								token = &tokCopy
								break
							}
						}
					}
					if token != nil && token.AccessToken != "" {
						break
					}
				}
			}
		}
	}

	// RFC 7009 Section 2.2:
	// "The authorization server responds with HTTP status code 200 if the token has been revoked successfully
	// or if the client submitted an invalid token."
	if token != nil && token.AccessToken != "" {
		// If client_id was passed, verify match
		if revokeReq.ClientID != "" && token.ClientID != "" && revokeReq.ClientID != token.ClientID {
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_client", "error_description": "client_id does not match token"}`))
			return
		}

		// Check user session if calling from frontend UI
		currentUser, userErr := getOAuthUser(resp, request)
		if userErr == nil && len(currentUser.Id) > 0 {
			// Verify user belongs to the token's Org or has support access
			userAllowed := false
			if currentUser.ActiveOrg.Id == token.OrgId || currentUser.Id == token.UserId || currentUser.SupportAccess {
				userAllowed = true
			} else {
				for _, org := range currentUser.Orgs {
					if org == token.OrgId {
						userAllowed = true
						break
					}
				}
			}
			if !userAllowed {
				resp.Header().Set("Content-Type", "application/json")
				resp.WriteHeader(http.StatusForbidden)
				resp.Write([]byte(`{"error": "forbidden", "error_description": "Not authorized to revoke this token"}`))
				return
			}
		}

		// Invalidate access token and refresh token
		_ = DeleteOAuthToken(ctx, token.AccessToken)
		if len(token.RefreshToken) > 0 {
			_ = DeleteKey(ctx, "oauth_refresh", token.RefreshToken)
		}

		if debug {
			log.Printf("[DEBUG] HandleOAuthRevoke: revoked token for client %s, user %s, org %s", token.ClientID, token.UserId, token.OrgId)
		}
	}

	resp.Header().Set("Content-Type", "application/json")
	resp.Header().Set("Cache-Control", "no-store")
	resp.WriteHeader(http.StatusOK)
	resp.Write([]byte(`{"status": "success", "revoked": true}`))
}

// HandleListOAuthTokens allows authenticated users / admins to list active OAuth tokens for their account and active organization.
//
// Route:
//   GET /api/v1/oauth2/tokens
func HandleListOAuthTokens(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	if request.Method != "GET" {
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(http.StatusMethodNotAllowed)
		resp.Write([]byte(`{"error": "invalid_request", "error_description": "Only GET is allowed"}`))
		return
	}

	ctx := GetContext(request)

	user, userErr := getOAuthUser(resp, request)
	if userErr != nil || len(user.Id) == 0 {
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(http.StatusUnauthorized)
		resp.Write([]byte(`{"error": "unauthorized", "error_description": "Authentication required"}`))
		return
	}

	explicitOrg := strings.TrimSpace(request.URL.Query().Get("org_id"))
	orgId := user.ActiveOrg.Id
	if explicitOrg != "" {
		for _, o := range user.Orgs {
			if o == explicitOrg {
				orgId = explicitOrg
				break
			}
		}
		if user.SupportAccess {
			orgId = explicitOrg
		}
	}

	tokens := []OAuthToken{}
	seenAccessTokens := map[string]bool{}
	addToken := func(tok OAuthToken) {
		if tok.AccessToken == "" || seenAccessTokens[tok.AccessToken] {
			return
		}
		if !tok.ExpiresAt.IsZero() && time.Now().After(tok.ExpiresAt) {
			return
		}
		seenAccessTokens[tok.AccessToken] = true
		tokens = append(tokens, tok)
	}

	// 1. Always include tokens directly associated with this user account (unless filtered to a specific org)
	if userTokens, uErr := GetOAuthTokensByUser(ctx, user.Id); uErr == nil {
		for _, tok := range userTokens {
			if explicitOrg != "" && tok.OrgId != explicitOrg {
				continue
			}
			addToken(tok)
		}
	}

	// 2. Also include tokens in the active/requested organization if the user belongs to it
	if orgId != "" {
		isAdmin := isUserOrgAdmin(ctx, user, orgId) || user.SupportAccess
		if orgTokens, err := GetOAuthTokensByOrg(ctx, orgId); err == nil {
			for _, tok := range orgTokens {
				if isAdmin || tok.UserId == user.Id || tok.UserId == "" {
					addToken(tok)
				}
			}
		} else if len(tokens) == 0 {
			log.Printf("[ERROR] Failed to list OAuth tokens for org %s: %v", orgId, err)
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusInternalServerError)
			resp.Write([]byte(`{"error": "server_error", "error_description": "Failed to list OAuth tokens"}`))
			return
		}
	}

	// 3. When no explicit org filter is passed, also check other orgs in user.Orgs for tokens owned by this user
	if explicitOrg == "" {
		for _, memberOrgId := range user.Orgs {
			if memberOrgId == "" || memberOrgId == orgId {
				continue
			}
			if orgTokens, err := GetOAuthTokensByOrg(ctx, memberOrgId); err == nil {
				for _, tok := range orgTokens {
					if tok.UserId == user.Id {
						addToken(tok)
					}
				}
			}
		}
	}

	tokenViews := []OAuthTokenView{}
	for _, tok := range tokens {
		maskedToken := tok.AccessToken
		if len(maskedToken) > 12 {
			maskedToken = maskedToken[:12] + "..."
		}

		rawClientName := tok.RawClientName
		rawRedirectURI := tok.RawRedirectURI
		if rawRedirectURI == "" {
			rawRedirectURI = tok.RedirectURI
		}
		rawClientURI := tok.RawClientURI
		rawLogoURI := tok.RawLogoURI
		softwareID := tok.SoftwareID
		softwareVer := tok.SoftwareVersion
		userAgent := tok.UserAgent
		tokenUA := tok.TokenUserAgent
		origin := tok.Origin
		remoteAddr := tok.RemoteAddr
		tokenRemoteAddr := tok.TokenRemoteAddr
		mcpClientName := tok.MCPClientName
		mcpClientVer := tok.MCPClientVersion
		mcpUA := tok.MCPUserAgent
		var registeredURIs []string
		isDynamic := false
		authMethod := ""
		clientURI := ""
		logoURI := ""

		if client, cErr := GetOAuthClient(ctx, tok.ClientID); cErr == nil && client != nil {
			registeredURIs = client.RedirectUris
			isDynamic = client.IsDynamic
			authMethod = client.TokenEndpointAuthMethod
			clientURI = client.ClientURI
			logoURI = client.LogoURI
			if rawClientName == "" {
				if client.RawClientName != "" {
					rawClientName = client.RawClientName
				} else if client.ClientName != "" && client.ClientName != "Shuffle Agent" && client.ClientName != "MCP Client" {
					rawClientName = client.ClientName
				}
			}
			if rawRedirectURI == "" {
				if client.RawRedirectURI != "" {
					rawRedirectURI = client.RawRedirectURI
				} else if len(client.RedirectUris) > 0 {
					rawRedirectURI = client.RedirectUris[0]
				}
			}
			if rawClientURI == "" {
				if client.RawClientURI != "" {
					rawClientURI = client.RawClientURI
				} else {
					rawClientURI = client.ClientURI
				}
			}
			if rawLogoURI == "" {
				rawLogoURI = client.RawLogoURI
			}
			if softwareID == "" {
				softwareID = client.SoftwareID
			}
			if softwareVer == "" {
				softwareVer = client.SoftwareVersion
			}
			if userAgent == "" {
				userAgent = client.UserAgent
			}
			if origin == "" {
				origin = client.Origin
			}
			if remoteAddr == "" {
				remoteAddr = client.RemoteAddr
			}
			if mcpClientName == "" {
				mcpClientName = client.MCPClientName
			}
			if mcpClientVer == "" {
				mcpClientVer = client.MCPClientVersion
			}
			if mcpUA == "" {
				mcpUA = client.MCPUserAgent
			}
		}

		evalUA := userAgent
		if evalUA == "" || strings.HasPrefix(strings.ToLower(evalUA), "mozilla/") {
			if mcpUA != "" && !strings.HasPrefix(strings.ToLower(mcpUA), "mozilla/") {
				evalUA = mcpUA
			} else if tokenUA != "" && !strings.HasPrefix(strings.ToLower(tokenUA), "mozilla/") {
				evalUA = tokenUA
			}
		}

		eval := EvaluateOAuthVendorIdentity(
			tok.ClientID,
			rawClientName,
			rawRedirectURI,
			rawClientURI,
			rawLogoURI,
			softwareID,
			evalUA,
			mcpClientName,
		)

		clientName := eval.ClientName
		if logoURI == "" {
			logoURI = eval.LogoURI
		}

		connID := tok.ID
		if connID == "" {
			connID = maskedToken
		}

		rawSource := &OAuthRawSource{
			ClientID:         tok.ClientID,
			RawClientName:    rawClientName,
			RawRedirectURI:   rawRedirectURI,
			RawClientURI:     rawClientURI,
			RawLogoURI:       rawLogoURI,
			RawRedirectURIs:  registeredURIs,
			SoftwareID:       softwareID,
			SoftwareVersion:  softwareVer,
			UserAgent:        userAgent,
			TokenUserAgent:   tokenUA,
			Origin:           origin,
			RemoteAddr:       remoteAddr,
			TokenRemoteAddr:  tokenRemoteAddr,
			MCPClientName:    mcpClientName,
			MCPClientVersion: mcpClientVer,
			MCPUserAgent:     mcpUA,
			IsDynamic:        isDynamic,
			AuthMethod:       authMethod,
		}

		appPerms := tok.AppPermissions
		if len(appPerms) == 0 && (len(tok.AllowedApps) > 0 || strings.Contains(strings.ToLower(tok.Scope), "app:")) {
			appPerms, _ = ResolveOAuthAppsAndTools(ctx, user, tok.Scope, tok.AllowedApps, tok.AllowedTools, "")
		}

		tokenViews = append(tokenViews, OAuthTokenView{
			ID:                 connID,
			ClientID:           tok.ClientID,
			ClientName:         clientName,
			ClientURI:          clientURI,
			LogoURI:            logoURI,
			TokenType:          tok.TokenType,
			Scope:              tok.Scope,
			AllowedApps:        tok.AllowedApps,
			AllowedTools:       tok.AllowedTools,
			AppPermissions:     appPerms,
			OrgId:              tok.OrgId,
			UserId:             tok.UserId,
			CreatedAt:          tok.CreatedAt,
			ExpiresAt:          tok.ExpiresAt,
			TokenMasked:        maskedToken,
			RedirectURI:        rawRedirectURI,
			VendorID:           eval.VendorID,
			VendorName:         eval.VendorName,
			ImageID:            eval.ImageID,
			VendorVerified:     eval.VendorVerified,
			VerificationStatus: eval.VerificationStatus,
			VerificationReason: eval.VerificationReason,
			VerifiedDomain:     eval.VerifiedDomain,
			ClaimedVendorID:    eval.ClaimedVendorID,
			ClaimedVendorName:  eval.ClaimedVendorName,
			VendorSpoofWarning: eval.VendorSpoofWarning,
			RawSource:          rawSource,
		})
	}

	respData, err := json.Marshal(tokenViews)
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(http.StatusOK)
	resp.Write(respData)
}

// HandleOAuthUserInfo implements the OpenID Connect Core 1.0 Section 5.3 UserInfo Endpoint.
//
// Routes:
//   GET  /oauth2/userinfo
//   POST /oauth2/userinfo
//   GET  /api/v1/oauth2/userinfo
//   POST /api/v1/oauth2/userinfo
//
// Only accepts OAuth 2.0 access tokens (Bearer shfl_...) so external OAuth / MCP clients
// (e.g. ChatGPT, Claude) can resolve the account email (user.Username) for the connected identity.
func HandleOAuthUserInfo(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	if request.Method != "GET" && request.Method != "POST" {
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(http.StatusMethodNotAllowed)
		resp.Write([]byte(`{"error": "invalid_request", "error_description": "Only GET and POST are allowed"}`))
		return
	}

	authHeader := strings.TrimSpace(request.Header.Get("Authorization"))
	accessToken := ""
	if strings.HasPrefix(authHeader, "Bearer ") || strings.HasPrefix(authHeader, "bearer ") {
		accessToken = strings.TrimSpace(authHeader[7:])
	} else if request.Method == "POST" {
		_ = request.ParseForm()
		accessToken = strings.TrimSpace(request.FormValue("access_token"))
	}

	if accessToken == "" || !strings.HasPrefix(accessToken, "shfl_") {
		resp.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Valid OAuth access token required"`)
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(http.StatusUnauthorized)
		resp.Write([]byte(`{"error": "invalid_token", "error_description": "Valid OAuth access token is required"}`))
		return
	}

	ctx := GetContext(request)
	oauthTok, oErr := GetOAuthToken(ctx, accessToken)
	if oErr != nil || oauthTok == nil || oauthTok.AccessToken == "" {
		resp.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Invalid or expired OAuth token"`)
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(http.StatusUnauthorized)
		resp.Write([]byte(`{"error": "invalid_token", "error_description": "Invalid or expired OAuth token"}`))
		return
	}

	if !oauthTok.ExpiresAt.IsZero() && time.Now().After(oauthTok.ExpiresAt) {
		resp.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="OAuth token has expired"`)
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(http.StatusUnauthorized)
		resp.Write([]byte(`{"error": "invalid_token", "error_description": "OAuth token has expired"}`))
		return
	}

	userObj, uErr := safeGetUserForOAuth(ctx, oauthTok.UserId)
	if uErr != nil || userObj == nil || (len(userObj.Id) == 0 && len(userObj.Username) == 0) {
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(http.StatusUnauthorized)
		resp.Write([]byte(`{"error": "invalid_token", "error_description": "User associated with OAuth token not found"}`))
		return
	}

	email := strings.TrimSpace(userObj.Username)
	sub := userObj.Id
	if sub == "" {
		sub = email
	}

	orgName := ""
	if oauthTok.OrgId != "" {
		if orgData, orgErr := safeGetOrgForOAuth(ctx, oauthTok.OrgId); orgErr == nil && orgData != nil {
			orgName = orgData.Name
		}
	}

	userInfo := OAuthUserInfoResponse{
		Sub:               sub,
		Email:             email,
		EmailVerified:     true,
		Name:              email,
		PreferredUsername: email,
		Username:          email,
		OrgId:             oauthTok.OrgId,
		OrgName:           orgName,
	}

	respData, err := json.Marshal(userInfo)
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
	resp.Header().Set("Cache-Control", "no-store")
	resp.Header().Set("Pragma", "no-cache")
	resp.WriteHeader(http.StatusOK)
	resp.Write(respData)
}

// =============================================================================
// Extensible OAuth 2.0 / MCP Endpoint Authorization Engine
// =============================================================================

// OAuthEndpointRule defines the authorization criteria for an HTTP endpoint
// when accessed using an OAuth 2.0 / MCP access token.
type OAuthEndpointRule struct {
	Name           string                                                                    `json:"name"`            // Descriptive name of the rule (e.g. "Workflows: Edit")
	PathPrefix     string                                                                    `json:"path_prefix"`     // Base path prefix (e.g. "/api/v1/workflows")
	PathRegex      *regexp.Regexp                                                            `json:"-"`               // Optional regex for finer route matching
	Methods        []string                                                                  `json:"methods"`         // Allowed HTTP methods (e.g. ["GET", "POST"]); empty means all methods
	RequiredScopes []string                                                                  `json:"required_scopes"` // Token must possess at least one of these scopes
	CheckAppAccess bool                                                                      `json:"check_app_access"` // If true, extracts app ID and enforces token.AllowedApps
	AppExtractor   func(request *http.Request) string                                        `json:"-"`               // Optional custom app extractor function
	Blocked        bool                                                                      `json:"blocked"`          // If true, endpoint is blocked for OAuth tokens (e.g. admin/billing)
	CustomCheck    func(ctx context.Context, token *OAuthToken, request *http.Request) error `json:"-"`               // Optional custom validator
	Description    string                                                                    `json:"description"`
}

var (
	oauthRulesLock     sync.RWMutex
	oauthEndpointRules []OAuthEndpointRule
	defaultRulesInit   sync.Once
)

// RegisterOAuthEndpointRule registers a new endpoint authorization rule for OAuth tokens.
// Custom rules registered here are evaluated before default rules.
func RegisterOAuthEndpointRule(rule OAuthEndpointRule) {
	initDefaultOAuthRules()
	oauthRulesLock.Lock()
	defer oauthRulesLock.Unlock()
	oauthEndpointRules = append([]OAuthEndpointRule{rule}, oauthEndpointRules...)
}

// GetOAuthEndpointRules returns a snapshot of all currently active endpoint rules.
func GetOAuthEndpointRules() []OAuthEndpointRule {
	initDefaultOAuthRules()
	oauthRulesLock.RLock()
	defer oauthRulesLock.RUnlock()
	rulesCopy := make([]OAuthEndpointRule, len(oauthEndpointRules))
	copy(rulesCopy, oauthEndpointRules)
	return rulesCopy
}

// HasOAuthScope checks if tokenScope contains at least one of requiredScopes,
// or has superuser scopes ("*" or "admin").
func HasOAuthScope(tokenScope string, requiredScopes ...string) bool {
	if len(requiredScopes) == 0 {
		return true
	}
	parts := strings.Fields(strings.ToLower(tokenScope))
	for _, p := range parts {
		if p == "*" || p == "admin" || p == "all" {
			return true
		}
		for _, req := range requiredScopes {
			if strings.EqualFold(p, req) {
				return true
			}
		}
	}
	return false
}

// ExtractAppFromRequest extracts the targeted app identifier from an HTTP request
// by inspecting query parameters and REST path segments.
func ExtractAppFromRequest(request *http.Request) string {
	if request == nil || request.URL == nil {
		return ""
	}

	// 1. Query parameters
	if app := request.URL.Query().Get("app_name"); app != "" {
		return strings.ToLower(strings.TrimSpace(app))
	}
	if app := request.URL.Query().Get("app"); app != "" {
		return strings.ToLower(strings.TrimSpace(app))
	}
	if app := request.URL.Query().Get("app_id"); app != "" {
		return strings.ToLower(strings.TrimSpace(app))
	}

	// 2. REST path segments: /api/v1/apps/{app_id}/...
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	for i, part := range parts {
		if part == "apps" && i+1 < len(parts) {
			candidate := parts[i+1]
			if candidate != "categories" && candidate != "search" {
				return strings.ToLower(strings.TrimSpace(candidate))
			}
		}
	}

	return ""
}

// IsAppNameAllowedForOAuth checks whether an app name or ID is permitted under allowedApps.
func IsAppNameAllowedForOAuth(allowedApps []string, appIdentifier string) bool {
	return IsAppAllowedForOAuth(allowedApps, WorkflowApp{
		ID:   appIdentifier,
		Name: appIdentifier,
	})
}

// initDefaultOAuthRules populates the default rule engine for Shuffle API endpoints.
func initDefaultOAuthRules() {
	defaultRulesInit.Do(func() {
		oauthEndpointRules = []OAuthEndpointRule{
			// 1. Blocked administrative & destructive endpoints
			{
				Name:        "Blocked: Admin Panel",
				PathPrefix:  "/api/v1/admin",
				Blocked:     true,
				Description: "Internal administration endpoints cannot be accessed via OAuth tokens",
			},
			{
				Name:        "Blocked: Billing",
				PathPrefix:  "/api/v1/billing",
				Blocked:     true,
				Description: "Billing endpoints cannot be accessed via OAuth tokens",
			},
			{
				Name:        "Blocked: Cloud Sync Settings",
				PathPrefix:  "/api/v1/cloud_sync",
				Blocked:     true,
				Description: "Cloud sync configuration cannot be modified via OAuth tokens",
			},
			{
				Name:        "Blocked: Org User Management",
				PathRegex:   regexp.MustCompile(`^/api/v1/orgs/[^/]+/users(?:/.*)?$`),
				Blocked:     true,
				Description: "User membership within an organization cannot be altered via OAuth tokens",
			},
			{
				Name:        "Blocked: Org Deletion",
				PathRegex:   regexp.MustCompile(`^/api/v1/orgs/[^/]+/delete$`),
				Blocked:     true,
				Description: "Organizations cannot be deleted via OAuth tokens",
			},

			// 2. Safe self-identification, discovery & health endpoints (always permitted for valid tokens)
			{
				Name:        "Safe: MCP Entrypoints",
				PathPrefix:  "/api/v1/mcp",
				Description: "MCP protocol handling",
			},
			{
				Name:           "Safe: App MCP Entrypoints",
				PathRegex:      regexp.MustCompile(`^/api/v1/apps/[^/]+/mcp/?$`),
				CheckAppAccess: true,
				Description:    "App-scoped MCP protocol handling",
			},
			{
				Name:        "Safe: Agent MCP Entrypoints",
				PathPrefix:  "/api/v1/agent",
				Description: "Agent and MCP protocol handling",
			},
			{
				Name:        "Safe: MCP Root",
				PathPrefix:  "/mcp",
				Description: "MCP protocol handling",
			},
			{
				Name:        "Safe: API Health",
				PathPrefix:  "/api/v1/health",
				Description: "Healthcheck inspection",
			},
			{
				Name:        "Safe: API Info",
				PathPrefix:  "/api/v1/info",
				Description: "API metadata and environment information",
			},
			{
				Name:        "Safe: Validate Token/Session",
				PathPrefix:  "/api/v1/validate",
				Description: "Token verification endpoint",
			},
			{
				Name:        "Safe: Current User Profile",
				PathPrefix:  "/api/v1/users/me",
				Description: "User identity introspection",
			},
			{
				Name:        "Safe: User Profile",
				PathPrefix:  "/api/v1/profile",
				Description: "User identity introspection",
			},
			{
				Name:        "Safe: OAuth UserInfo",
				PathPrefix:  "/oauth2/userinfo",
				Methods:     []string{"GET", "POST"},
				Description: "OIDC UserInfo identity introspection",
			},
			{
				Name:        "Safe: API OAuth UserInfo",
				PathPrefix:  "/api/v1/oauth2/userinfo",
				Methods:     []string{"GET", "POST"},
				Description: "OIDC UserInfo identity introspection",
			},
			{
				Name:        "Blocked: OAuth Authorization & Token Management",
				PathPrefix:  "/oauth2/",
				Blocked:     true,
				Description: "OAuth consent and token management endpoints cannot be accessed via OAuth tokens",
			},
			{
				Name:        "Blocked: API OAuth Authorization & Token Management",
				PathPrefix:  "/api/v1/oauth2/",
				Blocked:     true,
				Description: "OAuth consent and token management endpoints cannot be accessed via OAuth tokens",
			},
			{
				Name:        "Safe: Well Known Discovery",
				PathPrefix:  "/.well-known",
				Description: "OAuth and MCP metadata discovery",
			},

			// 3. Apps Execution & Actions
			{
				Name:           "Apps: Run Action",
				PathRegex:      regexp.MustCompile(`^/api/v1/apps/[^/]+/(?:run|execute)$`),
				Methods:        []string{"POST"},
				RequiredScopes: []string{"apps:run", "apps:execute", "mcp:execute", "workflow:run", "workflow:edit"},
				CheckAppAccess: true,
				Description:    "Execute actions inside a specific app",
			},
			{
				Name:           "Apps: Categories Run",
				PathPrefix:     "/api/v1/apps/categories/run",
				Methods:        []string{"POST"},
				RequiredScopes: []string{"apps:run", "apps:execute", "mcp:execute", "workflow:run", "workflow:edit"},
				CheckAppAccess: true,
				Description:    "Execute app actions via categorized routing",
			},
			{
				Name:           "Apps: Categories Run Legacy",
				PathPrefix:     "/api/v1/categories/run",
				Methods:        []string{"POST"},
				RequiredScopes: []string{"apps:run", "apps:execute", "mcp:execute", "workflow:run", "workflow:edit"},
				CheckAppAccess: true,
				Description:    "Execute app actions via category runner",
			},

			// 4. Apps Read / Discovery
			{
				Name:           "Apps: Read & List",
				PathPrefix:     "/api/v1/apps",
				Methods:        []string{"GET"},
				RequiredScopes: []string{"apps:read", "apps:run", "apps:execute", "mcp:execute", "workflow:read", "workflow:edit", "workflow:run"},
				CheckAppAccess: true,
				Description:    "List and inspect available apps",
			},

			// 5. Workflows Execution / Run
			{
				Name:           "Workflows: Run Workflow",
				PathRegex:      regexp.MustCompile(`^/api/v1/workflows/[^/]+/(?:run|execute)$`),
				Methods:        []string{"POST"},
				RequiredScopes: []string{"workflow:run", "workflow:edit"},
				Description:    "Trigger execution of a specific workflow",
			},
			{
				Name:           "Workflows: General Run Endpoint",
				PathPrefix:     "/api/v1/run",
				Methods:        []string{"POST"},
				RequiredScopes: []string{"workflow:run", "workflow:edit"},
				Description:    "Direct workflow run endpoint",
			},

			// 6. Workflows Modification (Create / Edit / Delete)
			{
				Name:           "Workflows: Modify",
				PathPrefix:     "/api/v1/workflows",
				Methods:        []string{"POST", "PUT", "DELETE", "PATCH"},
				RequiredScopes: []string{"workflow:edit"},
				Description:    "Create, update, or delete workflows",
			},

			// 7. Workflows Read
			{
				Name:           "Workflows: Read",
				PathPrefix:     "/api/v1/workflows",
				Methods:        []string{"GET"},
				RequiredScopes: []string{"workflow:read", "workflow:edit", "workflow:run"},
				Description:    "View workflow definitions and layouts",
			},

			// 8. Executions & Streams
			{
				Name:           "Executions: Read & Manage",
				PathPrefix:     "/api/v1/executions",
				RequiredScopes: []string{"workflow:run", "workflow:read", "workflow:edit"},
				Description:    "Inspect workflow executions and execution history",
			},
			{
				Name:           "Streams: Read & Manage",
				PathPrefix:     "/api/v1/streams",
				RequiredScopes: []string{"workflow:run", "workflow:read", "workflow:edit"},
				Description:    "Inspect streaming execution logs",
			},

			// 9. Files
			{
				Name:           "Files: Read",
				PathPrefix:     "/api/v1/files",
				Methods:        []string{"GET"},
				RequiredScopes: []string{"files:read", "workflow:read", "workflow:edit", "workflow:run"},
				Description:    "Download or view files",
			},
			{
				Name:           "Files: Write",
				PathPrefix:     "/api/v1/files",
				Methods:        []string{"POST", "PUT", "DELETE"},
				RequiredScopes: []string{"files:write", "workflow:edit"},
				Description:    "Upload or edit files",
			},

			// 10. Organization Read-Only Info
			{
				Name:           "Orgs: Read Info",
				PathRegex:      regexp.MustCompile(`^/api/v1/orgs/[^/]+$`),
				Methods:        []string{"GET"},
				RequiredScopes: []string{"workflow:read", "workflow:edit", "workflow:run"},
				Description:    "Read organization details",
			},
		}
	})
}

// ValidateOAuthTokenAccess validates that the provided OAuth token is permitted to access
// the target endpoint represented by request. It performs:
//  1. Token expiration check
//  2. Organization boundary enforcement (query param, Org-Id header, and REST path)
//  3. Extensible URL path & HTTP method matching
//  4. Scope validation against required scopes (including app-level scopes)
//  5. AllowedApps validation if the endpoint interacts with an app
//  6. Execution of any custom rule validator callbacks
func ValidateOAuthTokenAccess(ctx context.Context, token *OAuthToken, request *http.Request) error {
	if token == nil || token.AccessToken == "" {
		return errors.New("invalid_token: missing OAuth token")
	}

	// 1. Expiration validation
	if !token.ExpiresAt.IsZero() && time.Now().After(token.ExpiresAt) {
		return errors.New("token_expired: OAuth token has expired")
	}

	if request == nil || request.URL == nil {
		return nil
	}

	rawPath := request.URL.Path
	method := strings.ToUpper(request.Method)

	// 2. Organization Boundary Enforcement
	if token.OrgId != "" {
		reqOrg := request.Header.Get("Org-Id")
		if reqOrg == "" {
			reqOrg = request.Header.Get("OrgId")
		}
		if reqOrg == "" {
			reqOrg = request.URL.Query().Get("org_id")
		}
		if reqOrg == "" {
			parts := strings.Split(strings.Trim(rawPath, "/"), "/")
			for i, part := range parts {
				if part == "orgs" && i+1 < len(parts) {
					reqOrg = parts[i+1]
					break
				}
			}
		}

		if reqOrg != "" && reqOrg != token.OrgId {
			return fmt.Errorf("org_mismatch: OAuth token is bound to organization %s, cannot access organization %s", token.OrgId, reqOrg)
		}
	}

	// 3. Match against extensible endpoint rules
	initDefaultOAuthRules()
	oauthRulesLock.RLock()
	rules := oauthEndpointRules
	oauthRulesLock.RUnlock()

	var matchedRule *OAuthEndpointRule
	for i := range rules {
		rule := &rules[i]

		// Check HTTP Method
		if len(rule.Methods) > 0 {
			methodMatches := false
			for _, m := range rule.Methods {
				if strings.EqualFold(m, method) {
					methodMatches = true
					break
				}
			}
			if !methodMatches {
				continue
			}
		}

		// Check Path regex
		if rule.PathRegex != nil {
			if rule.PathRegex.MatchString(rawPath) {
				matchedRule = rule
				break
			}
			continue
		}

		// Check Path prefix
		if rule.PathPrefix != "" {
			if strings.HasPrefix(rawPath, rule.PathPrefix) {
				matchedRule = rule
				break
			}
			continue
		}
	}

	// Target app extraction for app-specific checking
	targetApp := ExtractAppFromRequest(request)

	if matchedRule != nil {
		// A. Blocked endpoints
		if matchedRule.Blocked {
			if !HasOAuthScope(token.Scope, "admin", "*") {
				return fmt.Errorf("forbidden_endpoint: endpoint %s cannot be accessed via OAuth token", rawPath)
			}
		}

		// B. Required scopes check
		if len(matchedRule.RequiredScopes) > 0 {
			hasScope := HasOAuthScope(token.Scope, matchedRule.RequiredScopes...)
			if !hasScope && targetApp != "" {
				// App-specific scope allowance (e.g. scope "app:jira" or "jira:run")
				if HasOAuthScope(token.Scope, "app:"+targetApp, targetApp+":run", targetApp+":read") {
					hasScope = true
				}
			}
			if !hasScope && len(token.AllowedApps) > 0 && targetApp != "" && IsAppNameAllowedForOAuth(token.AllowedApps, targetApp) {
				// Token is specifically scoped to this app in AllowedApps
				hasScope = true
			}

			if !hasScope {
				return fmt.Errorf("insufficient_scope: endpoint requires one of [%s], but token only has scopes: %s",
					strings.Join(matchedRule.RequiredScopes, ", "), token.Scope)
			}
		}

		// C. App Access check
		if matchedRule.CheckAppAccess {
			if matchedRule.AppExtractor != nil {
				targetApp = matchedRule.AppExtractor(request)
			}
			if targetApp != "" && len(token.AllowedApps) > 0 {
				if !IsAppNameAllowedForOAuth(token.AllowedApps, targetApp) {
					return fmt.Errorf("unauthorized_app: access to app '%s' is not permitted by this OAuth token's allowed_apps", targetApp)
				}
			}
		}

		// D. Custom validator callback
		if matchedRule.CustomCheck != nil {
			if err := matchedRule.CustomCheck(ctx, token, request); err != nil {
				return err
			}
		}

		return nil
	}

	// 4. Fallback for unmapped / extended endpoints:
	// Read-only operations allowed with read/edit scopes; modifying operations require edit/run scopes.
	switch method {
	case "GET", "HEAD", "OPTIONS":
		if !HasOAuthScope(token.Scope, "workflow:read", "workflow:edit", "workflow:run", "mcp:execute", "*", "admin") {
			return fmt.Errorf("insufficient_scope: access to %s requires 'workflow:read' or 'workflow:edit' scope", rawPath)
		}
	default:
		if !HasOAuthScope(token.Scope, "workflow:edit", "workflow:run", "mcp:execute", "*", "admin") {
			return fmt.Errorf("insufficient_scope: modifying endpoint %s requires 'workflow:edit' scope", rawPath)
		}
	}

	// Verify app if targetApp detected in fallback
	if targetApp != "" && len(token.AllowedApps) > 0 {
		if !IsAppNameAllowedForOAuth(token.AllowedApps, targetApp) {
			return fmt.Errorf("unauthorized_app: access to app '%s' is not permitted by this OAuth token's allowed_apps", targetApp)
		}
	}

	return nil
}


