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

// Handles requests to OAuth-protected resources. Point being to find if 
// oauth2 is available for what you are trying. First goal is MCP focus 
func HandleOAuthProtectedResource(resp http.ResponseWriter, request *http.Request) {
    cors := HandleCors(resp, request)
    if cors {
        return
    }

    scheme := "https"
    if proto := request.Header.Get("X-Forwarded-Proto"); proto != "" {
        scheme = proto
    } else if request.TLS == nil && strings.HasPrefix(request.Host, "localhost") {
        scheme = "http"
    }

    host := request.Host
    if forwardedHost := request.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
        host = forwardedHost
    }

    baseURL := fmt.Sprintf("%s://%s", scheme, host)

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

	// For now
	scopesSupported := []string{"workflow:edit"}
    metadata := map[string]interface{}{
        "resource":              resourceURL,
    	"scopes_supported":      scopesSupported,
        "authorization_servers": []string{baseURL},
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

	scheme := "https"
	if proto := request.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if request.TLS == nil && strings.HasPrefix(request.Host, "localhost") {
		scheme = "http"
	}

	host := request.Host
	if forwardedHost := request.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
		host = forwardedHost
	}

	baseURL := fmt.Sprintf("%s://%s", scheme, host)

	// Dynamic frontend URL where authorization UI lives
	frontendURL := os.Getenv("SHUFFLE_FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = os.Getenv("FRONTEND_URL")
	}

	if frontendURL == "" {
		frontendURL = "https://shuffle.security"
	}

	frontendURL = strings.TrimSuffix(frontendURL, "/")
	metadata := map[string]interface{}{
		"issuer":                                baseURL,
		"authorization_endpoint":                fmt.Sprintf("%s/oauth2/authorize", frontendURL),
		"token_endpoint":                        fmt.Sprintf("%s/oauth2/token", baseURL),
		"registration_endpoint":                 fmt.Sprintf("%s/oauth2/register", baseURL),
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
		"authorization_response_iss_parameter_supported": true,
		"scopes_supported":                      []string{"workflow:edit"},
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
	ClientName              string   `json:"client_name"`
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
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte(`{"error": "invalid_request", "error_description": "Failed to read body"}`))
		return
	}

	var regReq OAuthClientRegistrationRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &regReq); err != nil {
			log.Printf("[WARNING] Failed to parse OAuth client registration request: %s", err)
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "Invalid JSON format"}`))
			return
		}
	}

	if len(regReq.RedirectUris) == 0 {
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte(`{"error": "invalid_redirect_uri", "error_description": "At least one redirect_uri is required"}`))
		return
	}

	// Generate a unique client_id for this registration
	clientID := fmt.Sprintf("shuffle_client_%s", uuid.NewV4().String())

	// Default grant types and response types if omitted
	if len(regReq.GrantTypes) == 0 {
		regReq.GrantTypes = []string{"authorization_code"}
	}
	if len(regReq.ResponseTypes) == 0 {
		regReq.ResponseTypes = []string{"code"}
	}
	if len(regReq.TokenEndpointAuthMethod) == 0 {
		regReq.TokenEndpointAuthMethod = "none"
	}

	now := time.Now().Unix()

	ctx := GetContext(request)
	client := OAuthClient{
		ID:                      clientID,
		ClientID:                clientID,
		ClientName:              regReq.ClientName,
		RedirectUris:            regReq.RedirectUris,
		GrantTypes:              regReq.GrantTypes,
		ResponseTypes:           regReq.ResponseTypes,
		TokenEndpointAuthMethod: regReq.TokenEndpointAuthMethod,
		Scope:                   regReq.Scope,
		CreatedAt:               now,
		IsDynamic:               true,
	}

	// Capture OrgId and UserId if passed in request header or query
	if orgId := request.Header.Get("Org-Id"); len(orgId) > 0 {
		client.OrgId = orgId
	} else if orgId := request.Header.Get("Org_Id"); len(orgId) > 0 {
		client.OrgId = orgId
	} else if orgId := request.URL.Query().Get("org_id"); len(orgId) > 0 {
		client.OrgId = orgId
	}

	if userId := request.Header.Get("User-Id"); len(userId) > 0 {
		client.UserId = userId
	} else if userId := request.Header.Get("User_Id"); len(userId) > 0 {
		client.UserId = userId
	} else if userId := request.URL.Query().Get("user_id"); len(userId) > 0 {
		client.UserId = userId
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
		ClientName:              regReq.ClientName,
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
		log.Printf("[DEBUG] HandleOAuthRegister registered client: %s (%s)", clientID, regReq.ClientName)
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
		"workflow:edit": {
			Scope:       "workflow:edit",
			Name:        "Edit Workflows",
			Description: "Create, view, and modify workflows in your organization.",
			Category:    "Workflows",
		},
		"workflow:run": {
			Scope:       "workflow:run",
			Name:        "Run Workflows",
			Description: "Execute workflows and inspect execution results.",
			Category:    "Workflows",
		},
		"workflow:read": {
			Scope:       "workflow:read",
			Name:        "Read Workflows",
			Description: "View existing workflows and configurations.",
			Category:    "Workflows",
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
		// Default to workflow:edit if none specified
		parts = []string{"workflow:edit"}
	}

	for _, part := range parts {
		if info, ok := supported[part]; ok {
			scopes = append(scopes, info)
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
	if authHeader := request.Header.Get("Authorization"); len(authHeader) > 0 {
		user, err := HandleApiAuthentication(resp, request)
		if err == nil && len(user.Id) > 0 {
			return user, nil
		}
	}

	// 2. Fall back to cookie-based session tokens used by the Shuffle web frontend
	cookieNames := []string{"session_token", "__session", "shuffle_session"}
	for _, name := range cookieNames {
		cookie, cErr := request.Cookie(name)
		if cErr == nil && len(strings.TrimSpace(cookie.Value)) > 0 {
			sessionUser, sErr := GetSessionNew(ctx, strings.TrimSpace(cookie.Value))
			if sErr == nil && len(sessionUser.Id) > 0 {
				return sessionUser, nil
			}
		}
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
//   - Expiry window: Auth codes are set to expire in 10 minutes
//   - Single use: Handled upon token exchange
func HandleOAuthAuthorize(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Rate limiting: Protect against automated consent brute-forcing or DoS
	if err := ValidateRequestOverload(resp, request, 30); err != nil {
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

	// =========================================================================
	// GET REQUEST: Render Consent Info or Redirect Browser to Frontend UI
	// =========================================================================
	if request.Method == "GET" {
		clientID := strings.TrimSpace(request.URL.Query().Get("client_id"))
		redirectURI := strings.TrimSpace(request.URL.Query().Get("redirect_uri"))
		responseType := strings.TrimSpace(request.URL.Query().Get("response_type"))
		scope := strings.TrimSpace(request.URL.Query().Get("scope"))
		state := strings.TrimSpace(request.URL.Query().Get("state"))
		codeChallenge := strings.TrimSpace(request.URL.Query().Get("code_challenge"))
		codeChallengeMethod := strings.TrimSpace(request.URL.Query().Get("code_challenge_method"))

		// Edgecase 1: Missing client_id
		if clientID == "" {
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "client_id query parameter is required"}`))
			return
		}

		// Edgecase 2: Unknown or invalid client_id
		client, err := GetOAuthClient(ctx, clientID)
		if err != nil || client == nil || client.ClientID == "" {
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_client", "error_description": "Unknown or invalid client_id"}`))
			return
		}

		// Edgecase 3: Missing redirect_uri
		if redirectURI == "" {
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "redirect_uri query parameter is required"}`))
			return
		}

		// Edgecase 4: Redirect URI mismatch (Open Redirector Protection)
		// SECURITY: Never redirect to an unregistered redirect_uri if validation fails!
		uriMatched := false
		for _, regURI := range client.RedirectUris {
			if regURI == redirectURI {
				uriMatched = true
				break
			}
		}
		if !uriMatched {
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "redirect_uri does not match any registered redirect_uris for this client"}`))
			return
		}

		// Edgecase 5: Invalid response_type (OAuth 2.1 requires 'code', disallows implicit 'token')
		if responseType != "" && responseType != "code" {
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "unsupported_response_type", "error_description": "Only response_type=code is supported"}`))
			return
		}

		// Edgecase 6: PKCE validation (RFC 7636 / OAuth 2.1 requires code_challenge)
		if codeChallenge == "" {
			log.Printf("[WARNING] OAuth authorize request missing PKCE code_challenge from client %s", clientID)
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "code_challenge is required (RFC 7636 PKCE)"}`))
			return
		}
		if codeChallengeMethod != "" && codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "code_challenge_method must be S256 or plain"}`))
			return
		}

		// Edgecase 7: Check User Authentication Status
		user, userErr := getOAuthUser(resp, request)
		isAPIRequest := strings.Contains(request.URL.Path, "/api/v1/") ||
			strings.Contains(request.Header.Get("Accept"), "application/json") ||
			request.URL.Query().Get("format") == "json"

		if userErr != nil || len(user.Id) == 0 {
			// User is NOT logged in
			if isAPIRequest {
				// Frontend API call: Return 401 with login prompt URL
				resp.Header().Set("Content-Type", "application/json")
				resp.WriteHeader(http.StatusUnauthorized)
				loginURL := fmt.Sprintf("%s/login?redirect=%s", frontendURL, url.QueryEscape(request.URL.String()))
				resp.Write([]byte(fmt.Sprintf(`{"error": "unauthorized", "login_url": "%s"}`, loginURL)))
				return
			}

			// Direct browser GET: Redirect user to the frontend login page with return redirect
			targetLogin := fmt.Sprintf("%s/login?redirect=%s", frontendURL, url.QueryEscape(request.URL.String()))
			http.Redirect(resp, request, targetLogin, http.StatusFound)
			return
		}

		// Edgecase 8: User account is inactive / suspended
		if !user.Active {
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusForbidden)
			resp.Write([]byte(`{"error": "access_denied", "error_description": "User account is inactive"}`))
			return
		}

		// If user IS authenticated:
		// If this is the frontend API calling to fetch consent details:
		if isAPIRequest {
			// Build available organizations list for the user
			availableOrgs := []OrgMini{}
			for _, orgId := range user.Orgs {
				orgData, oErr := GetOrg(ctx, orgId)
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

			selectedOrg := user.ActiveOrg.Id
			if selectedOrg == "" && len(user.Orgs) > 0 {
				selectedOrg = user.Orgs[0]
			}

			clientName := client.ClientName
			if clientName == "" {
				clientName = client.ClientID
			}

			consentResponse := OAuthConsentInfoResponse{
				ClientID:      client.ClientID,
				ClientName:    clientName,
				Scopes:        ParseOAuthScopes(scope),
				User:          OAuthUserInfo{ID: user.Id, Username: user.Username},
				AvailableOrgs: availableOrgs,
				SelectedOrgId: selectedOrg,
				RedirectURI:   redirectURI,
				State:         state,
			}

			data, mErr := json.Marshal(consentResponse)
			if mErr != nil {
				resp.WriteHeader(http.StatusInternalServerError)
				return
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusOK)
			resp.Write(data)
			return
		}

		// Direct browser navigation to backend /oauth2/authorize:
		// Redirect to frontend consent page preserving all query parameters
		consentRedirect := fmt.Sprintf("%s/oauth2/authorize?%s", frontendURL, request.URL.RawQuery)
		http.Redirect(resp, request, consentRedirect, http.StatusFound)
		return
	}

	// =========================================================================
	// POST REQUEST: User Submits Consent Decision (Approve / Deny)
	// =========================================================================
	if request.Method == "POST" {
		// Authenticate user
		user, userErr := getOAuthUser(resp, request)
		if userErr != nil || len(user.Id) == 0 {
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusUnauthorized)
			resp.Write([]byte(`{"error": "unauthorized", "error_description": "User session is invalid or expired"}`))
			return
		}

		// Parse request body (supports JSON or Form-encoded)
		var authReq OAuthAuthorizeRequest
		contentType := request.Header.Get("Content-Type")

		if strings.Contains(contentType, "application/json") {
			body, rErr := ioutil.ReadAll(request.Body)
			if rErr != nil {
				resp.Header().Set("Content-Type", "application/json")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write([]byte(`{"error": "invalid_request", "error_description": "Failed to read body"}`))
				return
			}
			if err := json.Unmarshal(body, &authReq); err != nil {
				resp.Header().Set("Content-Type", "application/json")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write([]byte(`{"error": "invalid_request", "error_description": "Invalid JSON format"}`))
				return
			}
		} else {
			// Form-encoded fallback
			request.ParseForm()
			authReq.ClientID = strings.TrimSpace(request.FormValue("client_id"))
			authReq.RedirectURI = strings.TrimSpace(request.FormValue("redirect_uri"))
			authReq.ResponseType = strings.TrimSpace(request.FormValue("response_type"))
			authReq.Scope = strings.TrimSpace(request.FormValue("scope"))
			authReq.State = strings.TrimSpace(request.FormValue("state"))
			authReq.CodeChallenge = strings.TrimSpace(request.FormValue("code_challenge"))
			authReq.CodeChallengeMethod = strings.TrimSpace(request.FormValue("code_challenge_method"))
			authReq.OrgId = strings.TrimSpace(request.FormValue("org_id"))
			authReq.Approved = request.FormValue("approved") == "true" || request.FormValue("approved") == "1"
		}

		// Edgecase 9: Validate Client existence
		client, err := GetOAuthClient(ctx, authReq.ClientID)
		if err != nil || client == nil || client.ClientID == "" {
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_client", "error_description": "Client does not exist"}`))
			return
		}

		// Edgecase 10: Validate Redirect URI matches registered list
		uriMatched := false
		for _, regURI := range client.RedirectUris {
			if regURI == authReq.RedirectURI {
				uriMatched = true
				break
			}
		}
		if !uriMatched {
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "redirect_uri is not registered for this client"}`))
			return
		}

		// Edgecase 11: Validate PKCE
		if authReq.CodeChallenge == "" {
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "code_challenge is required"}`))
			return
		}
		if authReq.CodeChallengeMethod == "" {
			authReq.CodeChallengeMethod = "S256"
		}

		// Helper to format redirect response based on client request type
		returnRedirect := func(targetURL string) {
			if strings.Contains(contentType, "application/json") || request.URL.Query().Get("format") == "json" {
				resp.Header().Set("Content-Type", "application/json")
				resp.WriteHeader(http.StatusOK)
				respData, _ := json.Marshal(OAuthAuthorizeResponse{
					RedirectURL: targetURL,
					State:       authReq.State,
				})
				resp.Write(respData)
			} else {
				http.Redirect(resp, request, targetURL, http.StatusFound)
			}
		}

		// Edgecase 12: User Denied Consent
		if !authReq.Approved {
			sep := "?"
			if strings.Contains(authReq.RedirectURI, "?") {
				sep = "&"
			}
			deniedURL := fmt.Sprintf("%s%serror=access_denied&error_description=%s&state=%s",
				authReq.RedirectURI, sep, url.QueryEscape("User denied access"), url.QueryEscape(authReq.State))
			returnRedirect(deniedURL)
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
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "User must belong to at least one organization"}`))
			return
		}

		// Edgecase 15: Scope defaults and AllowedApps extraction
		if authReq.Scope == "" {
			authReq.Scope = "workflow:edit"
		}

		allowedApps := authReq.AllowedApps
		if len(allowedApps) == 0 {
			allowedApps = parseAllowedAppsFromScope(authReq.Scope)
		}

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
			OrgId:               selectedOrgId,
			UserId:              user.Id,
			ExpiresAt:           expiresAt,
			Used:                false,
			CreatedAt:           time.Now().Unix(),
		}

		// Store code in Datastore / OpenSearch
		if err := SetOAuthAuthCode(ctx, authCode); err != nil {
			log.Printf("[ERROR] Failed to persist OAuth authorization code: %v", err)
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusInternalServerError)
			resp.Write([]byte(`{"error": "server_error", "error_description": "Failed to generate authorization code"}`))
			return
		}

		// Edgecase 17: Query parameter concatenation
		sep := "?"
		if strings.Contains(authReq.RedirectURI, "?") {
			sep = "&"
		}
		targetRedirect := fmt.Sprintf("%s%scode=%s&state=%s",
			authReq.RedirectURI, sep, url.QueryEscape(codeStr), url.QueryEscape(authReq.State))

		if debug {
			log.Printf("[DEBUG] HandleOAuthAuthorize: issued code for client %s, user %s, org %s -> %s",
				client.ClientID, user.Id, selectedOrgId, targetRedirect)
		}

		returnRedirect(targetRedirect)
		return
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
	}

	return false
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
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Rate limiting: Protect against automated brute-forcing or DoS
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
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "Failed to read request body"}`))
			return
		}
		if err := json.Unmarshal(body, &tokenReq); err != nil {
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "Invalid JSON payload"}`))
			return
		}
	} else {
		if err := request.ParseForm(); err != nil {
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

	// Support HTTP Basic Authentication for Client Credentials
	basicUser, basicPass, hasBasic := request.BasicAuth()
	if hasBasic && tokenReq.ClientID == "" {
		tokenReq.ClientID = strings.TrimSpace(basicUser)
		tokenReq.ClientSecret = strings.TrimSpace(basicPass)
	}

	switch tokenReq.GrantType {
	case "authorization_code":
		// Edgecase 1: Missing code
		if tokenReq.Code == "" {
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "code parameter is required"}`))
			return
		}

		// Edgecase 2: Missing redirect_uri
		if tokenReq.RedirectURI == "" {
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "redirect_uri parameter is required"}`))
			return
		}

		// Retrieve and validate Authorization Code
		authCode, err := GetOAuthAuthCode(ctx, tokenReq.Code)
		if err != nil || authCode == nil || authCode.Code == "" {
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_grant", "error_description": "Authorization code is invalid or not found"}`))
			return
		}

		// Edgecase 3: Single-Use Protection (Replay Prevention)
		if authCode.Used {
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_grant", "error_description": "Authorization code has already been used"}`))
			return
		}

		// Edgecase 4: Expiration Check
		if !authCode.ExpiresAt.IsZero() && time.Now().After(authCode.ExpiresAt) {
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_grant", "error_description": "Authorization code has expired"}`))
			return
		}

		// Edgecase 5: Client ID Mismatch
		if tokenReq.ClientID != "" && authCode.ClientID != "" && tokenReq.ClientID != authCode.ClientID {
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_client", "error_description": "client_id does not match authorization code"}`))
			return
		}

		// Edgecase 6: Redirect URI Mismatch
		if tokenReq.RedirectURI != "" && authCode.RedirectURI != "" && tokenReq.RedirectURI != authCode.RedirectURI {
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_grant", "error_description": "redirect_uri does not match original authorization request"}`))
			return
		}

		// Edgecase 7: PKCE Verification
		if authCode.CodeChallenge != "" {
			if tokenReq.CodeVerifier == "" {
				resp.Header().Set("Content-Type", "application/json")
				resp.Header().Set("Cache-Control", "no-store")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write([]byte(`{"error": "invalid_request", "error_description": "code_verifier is required for PKCE validation"}`))
				return
			}

			if !verifyPKCE(tokenReq.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
				resp.Header().Set("Content-Type", "application/json")
				resp.Header().Set("Cache-Control", "no-store")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write([]byte(`{"error": "invalid_grant", "error_description": "PKCE verification failed: invalid code_verifier"}`))
				return
			}
		}

		// Delete code to guarantee single-use
		_ = DeleteOAuthAuthCode(ctx, authCode.Code)

		// Generate Access Token and Refresh Token
		accessToken := fmt.Sprintf("shfl_mcp_%s", strings.ReplaceAll(uuid.NewV4().String(), "-", ""))
		refreshToken := fmt.Sprintf("shfl_mcp_refresh_%s", strings.ReplaceAll(uuid.NewV4().String(), "-", ""))
		expiresIn := int64(30 * 24 * 3600) // 30 days
		expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

		oauthToken := OAuthToken{
			ID:           accessToken,
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			TokenType:    "Bearer",
			Scope:        authCode.Scope,
			AllowedApps:  authCode.AllowedApps,
			ExpiresIn:    expiresIn,
			ExpiresAt:    expiresAt,
			ClientID:     authCode.ClientID,
			OrgId:        authCode.OrgId,
			UserId:       authCode.UserId,
			CreatedAt:    time.Now().Unix(),
		}

		if err := SetOAuthToken(ctx, oauthToken); err != nil {
			log.Printf("[ERROR] Failed to persist OAuth token: %v", err)
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusInternalServerError)
			resp.Write([]byte(`{"error": "server_error", "error_description": "Failed to persist OAuth token"}`))
			return
		}

		tokenResp := OAuthTokenResponse{
			AccessToken:  accessToken,
			TokenType:    "Bearer",
			ExpiresIn:    expiresIn,
			RefreshToken: refreshToken,
			Scope:        authCode.Scope,
		}

		respData, err := json.Marshal(tokenResp)
		if err != nil {
			log.Printf("[ERROR] Failed to marshal token response: %v", err)
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusInternalServerError)
			return
		}

		if debug {
			log.Printf("[DEBUG] HandleOAuthToken: issued token %s for user %s, org %s", accessToken, authCode.UserId, authCode.OrgId)
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
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_request", "error_description": "refresh_token parameter is required"}`))
			return
		}

		// Retrieve existing token by refresh token
		oldToken, err := GetOAuthTokenByRefreshToken(ctx, tokenReq.RefreshToken)
		if err != nil || oldToken == nil || oldToken.AccessToken == "" {
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_grant", "error_description": "Invalid or expired refresh token"}`))
			return
		}

		// Edgecase 9: Client ID mismatch on refresh
		if tokenReq.ClientID != "" && oldToken.ClientID != "" && tokenReq.ClientID != oldToken.ClientID {
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"error": "invalid_client", "error_description": "client_id does not match refresh token"}`))
			return
		}

		// Invalidate old access token
		_ = DeleteOAuthToken(ctx, oldToken.AccessToken)

		// Rotate token: Issue new access token and refresh token
		newAccessToken := fmt.Sprintf("shfl_mcp_%s", strings.ReplaceAll(uuid.NewV4().String(), "-", ""))
		newRefreshToken := fmt.Sprintf("shfl_mcp_refresh_%s", strings.ReplaceAll(uuid.NewV4().String(), "-", ""))
		expiresIn := int64(30 * 24 * 3600) // 30 days
		expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

		newToken := OAuthToken{
			ID:           newAccessToken,
			AccessToken:  newAccessToken,
			RefreshToken: newRefreshToken,
			TokenType:    "Bearer",
			Scope:        oldToken.Scope,
			AllowedApps:  oldToken.AllowedApps,
			ExpiresIn:    expiresIn,
			ExpiresAt:    expiresAt,
			ClientID:     oldToken.ClientID,
			OrgId:        oldToken.OrgId,
			UserId:       oldToken.UserId,
			CreatedAt:    time.Now().Unix(),
		}

		if err := SetOAuthToken(ctx, newToken); err != nil {
			log.Printf("[ERROR] Failed to persist refreshed OAuth token: %v", err)
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusInternalServerError)
			resp.Write([]byte(`{"error": "server_error", "error_description": "Failed to persist refreshed OAuth token"}`))
			return
		}

		tokenResp := OAuthTokenResponse{
			AccessToken:  newAccessToken,
			TokenType:    "Bearer",
			ExpiresIn:    expiresIn,
			RefreshToken: newRefreshToken,
			Scope:        oldToken.Scope,
		}

		respData, err := json.Marshal(tokenResp)
		if err != nil {
			log.Printf("[ERROR] Failed to marshal refresh token response: %v", err)
			resp.Header().Set("Content-Type", "application/json")
			resp.Header().Set("Cache-Control", "no-store")
			resp.WriteHeader(http.StatusInternalServerError)
			return
		}

		if debug {
			log.Printf("[DEBUG] HandleOAuthToken: refreshed token %s for user %s, org %s", newAccessToken, oldToken.UserId, oldToken.OrgId)
		}

		resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
		resp.Header().Set("Cache-Control", "no-store")
		resp.Header().Set("Pragma", "no-cache")
		resp.WriteHeader(http.StatusOK)
		resp.Write(respData)
		return

	default:
		resp.Header().Set("Content-Type", "application/json")
		resp.Header().Set("Cache-Control", "no-store")
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte(`{"error": "unsupported_grant_type", "error_description": "grant_type must be authorization_code or refresh_token"}`))
		return
	}
}

