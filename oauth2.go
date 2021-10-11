package shuffle

// Shuffle is an automation platform for security and IT. This app and the associated scopes enables us to get information about a user, their mailbox and eventually subscribing them to send pub/sub requests to our platform to handle their emails in real-time, before controlling how to handle the data themselves.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	//"net/url"
	"os"
	"strings"
	"time"

	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"
)

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

		//log.Printf("[DEBUG] Email %s has attachments!!", email.ID)
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
				Description:  fmt.Sprintf("File found in outlook message %s with ID %s", email.ID, attachment.ID),
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

			err = uploadFile(ctx, &newFile, content, nil)
			if err != nil {
				log.Printf("[WARNING] Failed uploading outlook attachment %s in message %s", attachment.ID, email.ID)
				continue
			}

			log.Printf("[DEBUG] Added fileId %s to email msg %s", fileId, email.ID)
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

func HandleNewGmailRegister(resp http.ResponseWriter, request *http.Request) {
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

	log.Printf("[DEBUG] Redirect URI: %s", url)
	ctx := getContext(request)
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
	//log.Printf("STARTNODE: %s", trigger.Start)
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

	log.Printf("[DEBUG] REDIRECT URI: %s", url)
	ctx := getContext(request)
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
	log.Printf("STARTNODE: %s", trigger.Start)

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

	ctx := getContext(request)
	trigger, err := GetTriggerAuth(ctx, workflowId)
	if err != nil {
		log.Printf("[INFO] Trigger %s doesn't exist - specific trigger.", workflowId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": ""}`))
		return
	}

	if user.Username != trigger.Owner && user.Role != "admin" {
		log.Printf("Wrong user (%s) for trigger %s", user.Username, trigger.Id)
		resp.WriteHeader(401)
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

func makeGmailSubscription(client *http.Client, folderIds []string) (SubResponse, error) {
	fullUrl := "https://www.googleapis.com/gmail/v1/users/me/watch"

	// FIXME - this expires rofl
	//t := time.Now().Local().Add(time.Minute * time.Duration(4200))
	//timeFormat := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d.0000000Z", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())

	resource := "projects/shuffler/topics/gmail_testing"
	log.Printf("[INFO] Subscription resource to get(s) for gmail: %s", resource)
	sub := GmailSubscription{
		TopicName: resource,
		LabelIds:  folderIds,
	}
	// https://stackoverflow.com/questions/31718427/receive-gmail-push-notification-only-when-a-new-message-arrives
	// TopicName: CATEGORY_PERSONAL
	//LabelFilterAction: "exclude"

	data, err := json.Marshal(sub)
	if err != nil {
		log.Printf("Marshal: %s", err)
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
		log.Printf("[WARNING] GMAIL Client: %s", err)
		return SubResponse{}, err
	}

	log.Printf("[INFO] Subscription on GMAIL Status: %d", res.StatusCode)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] Gmail subscription Body: %s", err)
		return SubResponse{}, err
	}

	//log.Printf("GMAIL RESP: %s", string(body))

	if res.StatusCode != 200 && res.StatusCode != 201 {
		log.Printf("[ERROR] WATCH ERROR: %s", body)
		return SubResponse{}, errors.New(fmt.Sprintf("Subscription failed: %s", string(body)))
	}

	// Use data from body here to create thingy
	newSub := SubResponse{}
	err = json.Unmarshal(body, &newSub)
	if err != nil {
		return SubResponse{}, err
	}

	return newSub, nil
}

// https://docs.microsoft.com/en-us/previous-versions/office/office-365-api/api/version-2.0/notify-rest-operations#RenewSub
func ExtendOutlookSubscription(client *http.Client, subscriptionId string) error {
	fullUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/subscriptions/%s", subscriptionId)

	req, err := http.NewRequest(
		"PATCH",
		fullUrl,
		nil,
	)
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		log.Printf("[WARNING] Client: %s", err)
		return err
	}

	//log.Printf("[INFO] Subscription Status: %d", res.StatusCode)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("Body: %s", err)
		return err
	}

	if res.StatusCode != 200 && res.StatusCode != 201 {
		log.Printf("[ERROR] Re-subscription failed. Status: %d", res.StatusCode)
		return errors.New(fmt.Sprintf("RE-subscription failed: %s", string(body)))
	}

	return nil
}

func makeOutlookSubscription(client *http.Client, folderIds []string, notificationURL string) (string, error) {
	fullUrl := "https://graph.microsoft.com/v1.0/subscriptions"

	// FIXME - this expires rofl
	t := time.Now().Local().Add(time.Minute * time.Duration(4200))
	timeFormat := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d.0000000Z", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())

	resource := fmt.Sprintf("me/mailfolders('%s')/messages", strings.Join(folderIds, "','"))
	log.Printf("[INFO] Subscription resource to get(s): %s", resource)
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
	// if project.Environment != "cloud" {
	//	log.Printf("[INFO] SHOULD STOP OUTLOOK SUB ONPREM SYNC WITH CLOUD for workflow ID %s", workflowId)
	//	org, err := GetOrg(ctx, user.ActiveOrg.Id)
	//	if err != nil {
	//		log.Printf("[INFO] Failed finding org %s during outlook removal: %s", org.Id, err)
	//		return err
	//	}

	//	log.Printf("[INFO] Stopping cloud configuration for trigger %s in org %s for workflow %s", trigger.Id, org.Id, trigger.WorkflowId)
	//	action := CloudSyncJob{
	//		Type:          "outlook",
	//		Action:        "stop",
	//		OrgId:         org.Id,
	//		PrimaryItemId: trigger.Id,
	//		SecondaryItem: trigger.Start,
	//		ThirdItem:     trigger.WorkflowId,
	//	}

	//	err = executeCloudAction(action, org.SyncConfig.Apikey)
	//	if err != nil {
	//		log.Printf("[INFO] Failed cloud action STOP outlook execution: %s", err)
	//		return err
	//	} else {
	//		log.Printf("[INFO] Successfully set STOPPED outlook execution trigger")
	//	}
	//} else {
	//	log.Printf("SHOULD STOP OUTLOOK SUB IN CLOUD")
	//}

	// Actually delete the thing
	redirectDomain := "localhost:5001"
	url := fmt.Sprintf("http://%s/api/v1/triggers/outlook/register", redirectDomain)
	gmailClient, _, err := GetGmailClient(ctx, "", trigger.OauthToken, url)
	if err != nil {
		log.Printf("[WARNING] Oauth client failure - gmail delete: %s", err)
		return err
	}

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

	log.Printf("[INFO] Stop subscription on GMAIL Status: %d", res.StatusCode)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] Gmail subscription Body (2): %s", err)
		return err
	}

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
		log.Printf("SHOULD STOP OUTLOOK SUB IN CLOUD")
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

	ctx := getContext(request)
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

	ctx := getContext(request)
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
		log.Printf("Failed sub removal: %s", err)
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

	ctx := getContext(request)
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
		log.Printf("[INFO] Trigger %s doesn't exist - gmail sub.", curTrigger.ID)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": ""}`))
		return
	}

	// url doesn't really matter here
	//url := fmt.Sprintf("https://shuffler.io")
	//redirectDomain := "localhost:5001"
	//url := fmt.Sprintf("http://%s/api/v1/triggers/outlook/register", redirectDomain)
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
		log.Printf("[DEBUG] Should configure a running Office365 environment for CLOUD")

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

	log.Printf("[DEBUG] NOTIFICATION URL OUTLOOK TRIGGER: %s", notificationURL)
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
		subId, err := makeOutlookSubscription(outlookClient, curTrigger.Folders, notificationURL)
		if err != nil {
			failCnt += 1

			log.Printf("[WARNING] Failed making oauth subscription for outlook, retrying in 5 seconds: %s", err)

			time.Sleep(5 * time.Second)
			if failCnt == maxFails {
				log.Printf("Failed to set up subscription %d times.", maxFails)
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

	ctx := getContext(request)
	workflow, err := GetWorkflow(ctx, workflowId)
	if err != nil {
		log.Printf("[WARNING] Failed getting the workflow locally (gmail sub): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in gmail deploy: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
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

	gmailClient, _, err := GetGmailClient(ctx, "", trigger.OauthToken, "")
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

	//notificationURL := fmt.Sprintf("%s/api/v1/hooks/webhook_%s", project.CloudUrl, trigger.Id)
	//log.Printf("[DEBUG] Starting with notificationURL %s", notificationURL)
	//log.Println("[INFO] Folders: %#v", curTrigger.Folders)
	for {
		sub, err := makeGmailSubscription(gmailClient, curTrigger.Folders)
		if err != nil {
			//failCnt += 1

			log.Printf("[WARNING] Failed making oauth subscription for gmail, retrying in 5 seconds: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return

			//time.Sleep(5 * time.Second)
			//if failCnt == maxFails {
			//	log.Printf("Failed to set up subscription %d times.", maxFails)
			//	resp.WriteHeader(401)
			//	return
			//}

			//continue
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
		err = SetTriggerAuth(ctx, *trigger)
		if err != nil {
			log.Printf("[WARNING] Failed setting triggerauth (gmail): %s", err)
		}

		returnUrl := fmt.Sprintf("https://shuffler.io/api/v1/hooks/webhook_%s", trigger.Id)
		hook := Hook{
			Id:        trigger.Id,
			Start:     trigger.Start,
			Workflows: []string{trigger.WorkflowId},
			Info: Info{
				Name:        "Used onprem",
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
		}

		log.Printf("[DEBUG] Setting hook with ID %s with URL %s", trigger.Id, returnUrl)
		err = SetHook(ctx, hook)
		if err != nil {
			log.Printf("[WARNING] Failed setting hook FOR GMAIL for org %s: %s", user.ActiveOrg.Id, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		} else {
			log.Printf("[INFO] Successfully set up onprem hook FOR gmail")
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

	log.Printf("[INFO] Get GMAIL attachment %#v Status: %d", messageId, res.StatusCode)
	if res.StatusCode == 404 {
		return GmailAttachment{}, errors.New(fmt.Sprintf("Failed to find mail for %s: %d", messageId, res.StatusCode))
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] Gmail get msg (5): %s", err)
		return GmailAttachment{}, err
	}

	log.Printf("ATTACHMENT MAIL: %s", string(body))

	var message GmailAttachment
	err = json.Unmarshal(body, &message)
	if err != nil {
		log.Printf("[WARNING] Failed body read unmarshal for gmail msg: %s", err)
		return GmailAttachment{}, err
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

	log.Printf("[INFO] Get GMAIL msg %#v Status: %d", messageId, res.StatusCode)
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

	//if len(profile.EmailAddress) == 0 {
	//	return GmailMessageStruct{}, errors.New("Couldn't find your email profile")
	//}

	//log.Printf("\n\nUSER BODY: %s", string(body))
	return message, nil
}

func GetGmailHistory(ctx context.Context, gmailClient *http.Client, userId, historyId string) (GmailHistoryStruct, error) {

	//fullUrl := fmt.Sprintf("https://gmail.googleapis.com/gmail/v1/users/%s/history?startHistoryId=%s", userId, historyId)
	fullUrl := fmt.Sprintf("https://gmail.googleapis.com/gmail/v1/users/%s/history?startHistoryId=%s&historyType=messageAdded", userId, historyId)
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

	//log.Printf("[INFO] Get history status: %d", res.StatusCode)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] Gmail get history (6): %s", err)
		return GmailHistoryStruct{}, err
	}

	var history GmailHistoryStruct
	err = json.Unmarshal(body, &history)
	if err != nil {
		log.Printf("[WARNING] Failed body read unmarshal for gmail history: %s", err)
		return GmailHistoryStruct{}, err
	}

	// log.Printf("[DEBUG] HISTORY INFO: %s", string(body))
	if len(history.History) == 0 {
		return GmailHistoryStruct{}, errors.New("Couldn't find the history to be mapped. Maybe not consequential data?")
	}

	//log.Printf("\n\nUSER BODY: %s", string(body))
	return history, nil
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
		log.Printf("[WARNING] Unmarshal error for gmail message: %s", err)
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
	//log.Printf("HistoryId: %d. Email: %s", findHistory.HistoryId, findHistory.EmailAddress)
	ctx := getContext(request)
	subscription, err := GetSubscriptionRecipient(ctx, findHistory.EmailAddress)
	if err != nil {
		log.Printf("[WARNING] Failed finding gmail history for ID %d: %s. Should the subscription be cancelled?", findHistory.HistoryId, err)
		resp.WriteHeader(200)
		return
	}

	trigger, err := GetTriggerAuth(ctx, subscription.TriggerId)
	if err != nil {
		log.Printf("[INFO] Trigger %s doesn't exist - message.", subscription.TriggerId)
		resp.WriteHeader(200)
		resp.Write([]byte(`{"success": false, "reason": ""}`))
		return
	}

	//log.Printf("SUB: %#v", subscription)
	gmailClient, _, err := GetGmailClient(ctx, "", trigger.OauthToken, "")
	if err != nil {
		log.Printf("[WARNING] Oauth client failure - gmail new msg parse: %s", err)
		resp.WriteHeader(200)
		resp.Write([]byte(`{"success": false, "reason": ""}`))
		return
	}

	//time.Sleep(2 * time.Second)
	history, err := GetGmailHistory(ctx, gmailClient, findHistory.EmailAddress, fmt.Sprintf("%d", findHistory.HistoryId))
	if err != nil {
		//log.Printf("[DEBUG] Failed getting history for update: %s", err)
		resp.WriteHeader(200)
		resp.Write([]byte(`{"success": false, "reason": ""}`))
		return
	}

	subCalled := false

	for _, item := range history.History {
		for _, addedMsg := range item.MessagesAdded {
			message := addedMsg.Message

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

			timeNow := time.Now().Unix()

			var basepath = os.Getenv("SHUFFLE_FILE_LOCATION")
			if len(basepath) == 0 {
				basepath = "files"
			}
			folderPath := fmt.Sprintf("%s/%s/%s", basepath, trigger.OrgId, trigger.WorkflowId)
			for _, part := range mail.Payload.Parts {
				if len(part.Filename) == 0 {
					log.Printf("[DEBUG] Skipping part number %s of email", part.PartID)
					continue
				}

				if len(part.Body.AttachmentID) == 0 {
					log.Printf("PART: %#v", part)
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
					log.Printf("[WARNING] Failed setting gmail file for ID %s in message %s", part.Body.AttachmentID, message.ID)
					continue
				}

				parsedData, err := base64.StdEncoding.DecodeString(attachment.Data)
				if err != nil {
					log.Printf("[WARNING] Failed base64 decoding bytes %s in message %s", part.Body.AttachmentID, message.ID)
					continue
				}

				err = uploadFile(ctx, &newFile, parsedData, nil)
				if err != nil {
					log.Printf("[WARNING] Failed uploading gmail attachment %s in message %s", part.Body.AttachmentID, message.ID)
					continue
				}

				log.Printf("[DEBUG] Added file ID %s for attachment %s", newFile.Id, message.ID)
				mail.FileIds = append(mail.FileIds, newFile.Id)
			}

			//if mail.ID == message.ThreadID {
			mappedData, err := json.Marshal(mail)
			if err != nil {
				log.Println("[WARNING] Failed to Marshal mail to send to webhook: %s", err)
				resp.WriteHeader(401)
				continue
			}

			//webhookUrl := fmt.Sprintf("https://729d-84-214-96-67.ngrok.io/api/v1/hooks/webhook_%s", trigger.Id)
			webhookUrl := fmt.Sprintf("https://shuffler.io/api/v1/hooks/webhook_%s", trigger.Id)
			err = MakeGmailWebhookRequest(ctx, webhookUrl, mappedData)
			if err != nil {
				log.Printf("[WARNING] Failed making webhook request to %s: %s", webhookUrl, err)
			} else {
				log.Printf("[INFO] Successfully sent webhook request to %s", webhookUrl)
				//break
			}
			//}
		}
	}

	if !subCalled {
		makeGmailSubscription(gmailClient, trigger.Folders)
		subCalled = true
	}

	resp.WriteHeader(200)
}

// Sending request to not complicate the use of webhooks vs non-webhooks, and dragging the execution model into shared area
func MakeGmailWebhookRequest(ctx context.Context, webhookUrl string, mappedData []byte) error {
	log.Printf("[INFO] Sending %d bytes to webhook %s", len(mappedData), webhookUrl)
	client := &http.Client{
		Timeout: 2 * time.Second,
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

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[WARNING] Gmail subscription Body: %s", err)
		return err
	}

	log.Printf("[DEBUG] Webhook RESP: %s", string(body))
	return nil
}

// THis all of a sudden became really horrible.. fml
func GetGmailClient(ctx context.Context, code string, accessToken OauthToken, redirectUri string) (*http.Client, *oauth2.Token, error) {
	conf := &oauth2.Config{
		ClientID:     os.Getenv("GMAIL_CLIENT_ID"),
		ClientSecret: os.Getenv("GMAIL_CLIENT_SECRET"),
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
			log.Printf("[WARNING] Access_token issue for gmail: %s", err)
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

func getGmailFolders(client *http.Client) (OutlookFolders, error) {
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
	log.Printf("[INFO] Status for GMAIL folders (Labels): %d", ret.StatusCode)
	if ret.StatusCode != 200 {
		return OutlookFolders{}, err
	}

	//log.Printf("Body: %s", string(body))

	labels := GmailLabels{}
	err = json.Unmarshal(body, &labels)
	if err != nil {
		log.Printf("[WARNING] GMAIL Unmarshal: %s", err)
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
	requestUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/me/mailFolders")

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
	log.Printf("[INFO] Status folders: %d", ret.StatusCode)
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

	ctx := getContext(request)
	trigger, err := GetTriggerAuth(ctx, triggerId)
	if err != nil {
		log.Printf("[AUDIT] Trigger %s doesn't exist - gmail folders.", triggerId)
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

	// FIXME - should be shuffler in literally every case except testing lol
	//log.Printf("TRIGGER: %#v", trigger)
	redirectDomain := "localhost:5001"
	url := fmt.Sprintf("http://%s/api/v1/triggers/gmail/register", redirectDomain)
	if project.Environment == "cloud" {
		url = fmt.Sprintf("https://shuffler.io/api/v1/triggers/gmail/register", redirectDomain)
	}
	gmailClient, _, err := GetGmailClient(ctx, "", trigger.OauthToken, url)
	if err != nil {
		log.Printf("[WARNING] Oauth client failure - outlook folders: %s", err)
		resp.Write([]byte(`{"success": false, "reason": "Failed creating outlook client"}`))
		resp.WriteHeader(401)
		return
	}

	// This should be possible, and will also give the actual username
	/*
		profile, err := getOutlookProfile(outlookClient)
		if err != nil {
			log.Printf("Outlook profile failure: %s", err)
			resp.WriteHeader(401)
			return
		}
		log.Printf("PROFILE: %#v", profile)
	*/

	folders, err := getGmailFolders(gmailClient)
	if err != nil {
		log.Printf("[WARNING] Failed setting outlook folders: %s", err)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting outlook folders"}`))
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

	ctx := getContext(request)
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

	// FIXME - should be shuffler in literally every case except testing lol
	//log.Printf("TRIGGER: %#v", trigger)
	redirectDomain := "localhost:5001"
	url := fmt.Sprintf("http://%s/api/v1/triggers/gmail/register", redirectDomain)
	if project.Environment == "cloud" {
		url = fmt.Sprintf("https://shuffler.io/api/v1/triggers/gmail/register", redirectDomain)
	}
	outlookClient, _, err := GetOutlookClient(ctx, "", trigger.OauthToken, url)
	if err != nil {
		log.Printf("[WARNING] Oauth client failure - outlook folders: %s", err)
		resp.Write([]byte(`{"success": false, "reason": "Failed creating outlook client"}`))
		resp.WriteHeader(401)
		return
	}

	// This should be possible, and will also give the actual username
	/*
		profile, err := getOutlookProfile(outlookClient)
		if err != nil {
			log.Printf("Outlook profile failure: %s", err)
			resp.WriteHeader(401)
			return
		}
		log.Printf("PROFILE: %#v", profile)
	*/

	folders, err := getOutlookFolders(outlookClient)
	if err != nil {
		log.Printf("[WARNING] Failed setting outlook folders: %s", err)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting outlook folders"}`))
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
