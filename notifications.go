package shuffle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/satori/go.uuid"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Standalone to make it work many places
func markNotificationRead(ctx context.Context, notification *Notification) error {
	notification.Read = true
	err := SetNotification(ctx, *notification)
	if err != nil {
		return err
	}

	return nil
}

func HandleMarkAsRead(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	var fileId string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("Path too short: %d", len(location))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	if len(fileId) != 36 {
		log.Printf("[WARNING] Bad format for fileId in notification %s", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Badly formatted ID"}`))
		return
	}

	// 1. Check user directly
	// 2. Check workflow execution authorization
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[INFO] INITIAL Api authentication failed in notification mark: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := GetContext(request)
	notification, err := GetNotification(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Failed getting notification %s for user %s: %s", fileId, user.Id, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Bad userId or notification doesn't exist"}`))
		return
	}

	if notification.UserId != user.Id {
		log.Printf("[WARNING] Bad user for notification. %s (wanted) vs %s", notification.UserId, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Bad userId or notification doesn't exist"}`))
		return
	}

	err = markNotificationRead(ctx, notification)
	if err != nil {
		log.Printf("[WARNING] Failed updating notification %s (%s) to read: %s", notification.Title, notification.Id, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed to mark it as read"}`))
		return
	}

	log.Printf("[AUDIT] Marked %s as read by user %s (%s)", notification.Id, user.Username, user.Id)

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))

	return
}

func HandleClearNotifications(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// 1. Check user directly
	// 2. Check workflow execution authorization
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[INFO] INITIAL Api authentication failed in notification list: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	/*
		if user.Role != "admin" {
			log.Printf("[AUTH] User isn't admin")
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Need to be admin to list files"}`)))
			return
		}
	*/

	ctx := GetContext(request)
	notifications, err := GetUserNotifications(ctx, user.Id)
	if err != nil && len(notifications) == 0 {
		log.Printf("[ERROR] Failed to get notifications (clear): %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Error getting notifications."}`)))
		return
	}

	for _, notification := range notifications {
		err = markNotificationRead(ctx, &notification)
		if err != nil {
			log.Printf("[WARNING] Failed updating notification %s (%s) to read (clear): %s", notification.Title, notification.Id, err)
			continue
			//resp.WriteHeader(500)
			//resp.Write([]byte(`{"success": false, "reason": "Failed to mark it as read"}`))
			//return
		}
	}

	log.Printf("[AUDIT] Cleared all notifications for user %s (%s)", user.Username, user.Id)
	cacheKey := fmt.Sprintf("notifications_%s", user.ActiveOrg.Id)
	DeleteCache(ctx, cacheKey)

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleGetNotifications(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// 1. Check user directly
	// 2. Check workflow execution authorization
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[INFO] INITIAL Api authentication failed in notification list: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	/*
		if user.Role != "admin" {
			log.Printf("[AUTH] User isn't admin")
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Need to be admin to list files"}`)))
			return
		}
	*/

	// Should be made org-wide instead? Right now, it's cross org
	ctx := GetContext(request)
	notifications, err := GetUserNotifications(ctx, user.Id)
	if err != nil && len(notifications) == 0 {
		log.Printf("[ERROR] Failed to get notifications: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Error getting notifications."}`)))
		return
	}

	//log.Printf("[AUDIT] Got %d notifications for user %s (%s)", len(notifications), user.Username, user.Id)

	newNotifications := []Notification{}
	for _, notification := range notifications {
		// Check how long ago?
		if notification.Read {
			//log.Printf("[DEBUG] Skipping read notification %s", notification.Title)
			continue
		}

		notification.UserId = ""
		//notification.OrgId = ""
		newNotifications = append(newNotifications, notification)
	}

	sort.Slice(notifications[:], func(i, j int) bool {
		return notifications[i].UpdatedAt > notifications[j].UpdatedAt
	})

	notificationResponse := NotificationResponse{
		Success:       true,
		Notifications: newNotifications,
	}

	//log.Printf("[DEBUG] Got %d notifications for user %s", len(notifications), user.Id)
	newBody, err := json.Marshal(notificationResponse)
	if err != nil {
		log.Printf("[ERROR] Failed marshaling files: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed to marshal files"}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(newBody))
}

func sendToNotificationWorkflow(ctx context.Context, notification Notification, userApikey, workflowId string) error {
	log.Printf("[DEBUG] Should send notifications to workflow %s", workflowId)

	if strings.Contains(strings.ToLower(notification.ReferenceUrl), strings.ToLower(workflowId)) {
		log.Printf("[WARNING] Notification NOT being sent to workflow as it's the same Workflow ID as failed!")
		return errors.New("Same workflow ID as notification ID. Stopped for infinite loop")
	}

	backendUrl := os.Getenv("BASE_URL")
	if project.Environment == "cloud" {
		// Doesn't work multi-region
		backendUrl = "https://shuffler.io"
	}

	// Callback to itself
	if len(backendUrl) == 0 {
		backendUrl = "http://localhost:5001"
	}

	if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
		backendUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
	}

	b, err := json.Marshal(notification)
	if err != nil {
		log.Printf("[DEBUG] Failed marshaling notification: %s", err)
		return err
	}

	executionUrl := fmt.Sprintf("%s/api/v1/workflows/%s/execute", backendUrl, workflowId)
	client := &http.Client{}
	req, err := http.NewRequest(
		"POST",
		executionUrl,
		bytes.NewBuffer(b),
	)

	req.Header.Add("Authorization", fmt.Sprintf(`Bearer %s`, userApikey))
	newresp, err := client.Do(req)
	if err != nil {
		return err
	}

	respBody, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Finished notification request to %s with status %d. Data: %s", executionUrl, newresp.StatusCode, string(respBody))
	if newresp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Got status code %d when sending notification for org %s", newresp.StatusCode, notification.OrgId))
	}

	return nil
}

func CreateOrgNotification(ctx context.Context, title, description, referenceUrl, orgId string, adminsOnly bool) error {
	if project.Environment == "" || project.Environment == "worker" {
		log.Printf("\n\n\n[ERROR] Not generating notification, as worker environment has been detected: %#v", project.Environment)
		return nil
	}

	notifications, err := GetOrgNotifications(ctx, orgId)
	if err != nil {
		log.Printf("\n\n\n[ERROR] Failed getting org notifications for %s: %s", orgId, err)
		return err
	}

	log.Printf("[DEBUG] Found %d notifications for org %s. Merge?", len(notifications), orgId)
	foundNotifications := []Notification{}
	for _, notification := range notifications {
		// notification.Title == title &&
		//log.Printf("%s vs %s", notification.ReferenceUrl, referenceUrl)
		if notification.Title == title && notification.Description == description {
			foundNotifications = append(foundNotifications, notification)
		}
	}

	org, err := GetOrg(ctx, orgId)
	if err != nil {
		log.Printf("[WARNING] Error getting org %s in createOrgNotification: %s", orgId, err)
		return err
	}


	generatedId := uuid.NewV4().String()
	mainNotification := Notification{
		Title:             title,
		Description:       description,
		Id:                generatedId,
		OrgId:             orgId,
		OrgName:           org.Name,
		UserId:            "",
		Tags:              []string{},
		Amount:            1,
		ReferenceUrl:      referenceUrl,
		OrgNotificationId: "",
		Dismissable:       true,
		Personal:          false,
		Read:              false,
		CreatedAt:         int64(time.Now().Unix()),
		UpdatedAt:         int64(time.Now().Unix()),
	}

	selectedApikey := ""

	authOrg := org
	if org.Defaults.NotificationWorkflow == "parent" && org.CreatorOrg != "" {
		log.Printf("[DEBUG] Sending notification to parent org %s' notification workflow", org.CreatorOrg)

		parentOrg, err := GetOrg(ctx, org.CreatorOrg)
		if err != nil {
			log.Printf("[WARNING] Error getting parent org %s in createOrgNotification: %s", orgId, err)
			return err
		}

		// Overwriting to make sure access rights are correct
		authOrg = parentOrg
		org.Defaults.NotificationWorkflow = parentOrg.Defaults.NotificationWorkflow
	}

	for _, user := range authOrg.Users {
		if user.Role == "admin" && len(user.ApiKey) > 0 && len(selectedApikey) == 0 {
			// Checking if it's the right active org
			// FIXME: Should it need to be in the active org? Shouldn't matter? :thinking:
			foundUser, err := GetUser(ctx, user.Id)
			if err == nil {
				if foundUser.ActiveOrg.Id == orgId {
					log.Printf("[DEBUG] Using the apikey of user %s (%s) for notification for org %s", foundUser.Username, foundUser.Id, orgId)
					selectedApikey = user.ApiKey
				}
			}
		}
	}

	//log.Printf("[DEBUG] New found length: %d", len(foundNotifications))
	if len(foundNotifications) > 0 {
		// FIXME: This may have bugs for old workflows with new users (not being rediscovered)
		//log.Printf("[DEBUG] Found %d notifications for org %s. Merging...", len(foundNotifications), orgId)

		usersHandled := []string{}
		// Make sure to only reopen one per user
		for _, notification := range foundNotifications {
			if ArrayContains(usersHandled, notification.UserId) {
				//log.Printf("[DEBUG] Skipping notification %s for user %s as it's already been handled", notification.Title, notification.UserId)

				continue
			}

			if notification.Read == false {
				//log.Printf("[DEBUG] Skipping notification %s for user %s as it's already been read", notification.Title, notification.UserId)

				usersHandled = append(usersHandled, notification.UserId)
				continue
			}

			notification.Read = false
			notification.Amount += 1
			err = SetNotification(ctx, notification)
			if err != nil {
				log.Printf("[WARNING] Failed to reopen notification %s for user %s", notification.Title, notification.UserId)
			} else {
				log.Printf("[INFO] Reopened notification %s for %s", notification.Title, notification.UserId)
				usersHandled = append(usersHandled, notification.UserId)
			}
		}


		err = sendToNotificationWorkflow(ctx, mainNotification, selectedApikey, org.Defaults.NotificationWorkflow)
		if err != nil {
			log.Printf("[ERROR] Failed sending notification to workflowId %s for reference %s (2): %s", org.Defaults.NotificationWorkflow, mainNotification.Id, err)
		}

		return nil
	} else {
		log.Printf("[INFO] Notification with title %#v is being made for users in org %s", title, orgId)





		err = SetNotification(ctx, mainNotification)
		if err != nil {
			log.Printf("[WARNING] Failed making org notification with title %#v for org %s", title, orgId)
			return err
		}

		// 1. Find users in org
		// 2. Make notification for each of them
		// 3. Make reference to org notification

		//NotificationWorkflow   string `json:"notification_workflow" datastore:"notification_workflow"`

		filteredUsers := []User{}
		if adminsOnly == false {
			filteredUsers = org.Users
		} else {
			for _, user := range org.Users {
				if user.Role == "admin" {
					filteredUsers = append(filteredUsers, user)
				}
			}
		}

		selectedApikey := ""
		for _, user := range filteredUsers {
			if user.Role == "admin" && len(user.ApiKey) > 0 && len(selectedApikey) == 0 {
				// Checking if it's the right active org
				// FIXME: Should it need to be in the active org? Shouldn't matter? :thinking:
				foundUser, err := GetUser(ctx, user.Id)
				if err == nil {
					if foundUser.ActiveOrg.Id == orgId {
						log.Printf("[DEBUG] Using the apikey of user %s (%s) for notification for org %s", foundUser.Username, foundUser.Id, orgId)
						selectedApikey = user.ApiKey
					}
				}
			}

			//log.Printf("[DEBUG] Made notification for user %s (%s)", user.Username, user.Id)
			newNotification := mainNotification
			newNotification.Id = uuid.NewV4().String()
			newNotification.UserId = user.Id
			newNotification.OrgNotificationId = generatedId
			newNotification.Personal = true

			err = SetNotification(ctx, newNotification)
			if err != nil {
				log.Printf("[WARNING] Failed making USER notification with title %#v for user %s in org %s", title, user.Id, orgId)
			}
		}

		if len(org.Defaults.NotificationWorkflow) > 0 {
			if len(selectedApikey) == 0 {
				log.Printf("[ERROR] Didn't find an apikey to use when sending notifications for org %s to workflow %s", org.Id, org.Defaults.NotificationWorkflow)
			}

			workflow, err := GetWorkflow(ctx, org.Defaults.NotificationWorkflow)
			if err != nil {
				log.Printf("[WARNING] Failed getting workflow with ID %s: %s", org.Defaults.NotificationWorkflow, err)
				return err
			}

			if workflow.OrgId != mainNotification.OrgId {
				log.Printf("[WARNING] Can't access workflow %s with org ID %s (%s): %s", workflow.ID, mainNotification.OrgId, workflow.Org)

				// Get parent org if it exists and check too
				if len(org.ManagerOrgs) > 0 {
					parentOrg, err := GetOrg(ctx, org.ManagerOrgs[0].Id)
					if err != nil {
						log.Printf("[WARNING] Error getting parent org %s in createOrgNotification (2): %s", orgId, err)
						return err
					}

					if org.Defaults.NotificationWorkflow != parentOrg.Defaults.NotificationWorkflow {
						return errors.New(fmt.Sprintf("Org %s does not have access to workflow with ID %s", mainNotification.OrgId, workflow.ID))
					} else {
						log.Printf("[DEBUG] Running with parent orgs' notification workflow")
					}
				} else {
					return errors.New(fmt.Sprintf("Org %s does not have access to workflow with ID %s", mainNotification.OrgId, workflow.ID))
				}
			}

			err = sendToNotificationWorkflow(ctx, mainNotification, selectedApikey, org.Defaults.NotificationWorkflow)
			if err != nil {
				log.Printf("[ERROR] Failed sending notification to workflowId %s for reference %s: %s", org.Defaults.NotificationWorkflow, mainNotification.Id, err)
			}
		}
	}

	return nil
}
