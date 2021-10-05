package shuffle

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/satori/go.uuid"
	"log"
	"net/http"
	"sort"
	"strings"
)

// Standalone to make it work many places
func markNotificationRead(ctx context.Context, notification *Notification) error {
	notification.Read = true
	err = SetNotification(ctx, *notification)
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

	ctx := getContext(request)
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

	ctx := getContext(request)
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

	ctx := getContext(request)
	notifications, err := GetUserNotifications(ctx, user.Id)
	if err != nil && len(notifications) == 0 {
		log.Printf("[ERROR] Failed to get notifications: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Error getting notifications."}`)))
		return
	}

	newNotifications := []Notification{}
	for _, notification := range notifications {
		if notification.Read {
			continue
		}

		notification.UserId = ""
		notification.OrgId = ""
		newNotifications = append(newNotifications, notification)
	}

	sort.Slice(notifications[:], func(i, j int) bool {
		return notifications[i].UpdatedAt > notifications[j].UpdatedAt
	})

	notificationResponse := NotificationResponse{
		Success:       true,
		Notifications: newNotifications,
	}
	//for _, file := range files {
	//	if file.Namespace != "" && file.Namespace != "default" {
	//		if !ArrayContains(fileResponse.Namespaces, file.Namespace) {
	//			fileResponse.Namespaces = append(fileResponse.Namespaces, file.Namespace)
	//		}
	//	}
	//}

	// Shitty way to build it, but works before scale. Need ES search mechanism for namespaces

	log.Printf("[INFO] Got %d notifications for user %s", len(notifications), user.Id)
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

func createOrgNotification(ctx context.Context, title, description, referenceUrl, orgId string, adminsOnly bool) error {
	notifications, err := GetOrgNotifications(ctx, orgId)
	if err != nil {
		log.Printf("[WARNING] Failed getting org notifications for %s: %s", orgId, err)
		return err
	}

	//log.Printf("[DEBUG] Found %d notifications for org %s. Merge?", len(notifications), orgId)
	foundNotifications := []Notification{}
	for _, notification := range notifications {
		// notification.Title == title &&
		//log.Printf("%s vs %s", notification.ReferenceUrl, referenceUrl)
		if notification.Title == title && notification.Description == description {
			foundNotifications = append(foundNotifications, notification)
		}
	}

	//log.Printf("[DEBUG] New found length: %d", len(foundNotifications))
	if len(foundNotifications) > 0 {
		// FIXME: This may have bugs for old workflows with new users (not being rediscovered)
		usersHandled := []string{}
		// Make sure to only reopen one per user
		for _, notification := range foundNotifications {
			if ArrayContains(usersHandled, notification.UserId) {
				continue
			}

			if notification.Read == false {
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

		return nil
	} else {
		log.Printf("[INFO] Notification with title %#v is being made for users in org %s", title, orgId)
		generatedId := uuid.NewV4().String()
		mainNotification := Notification{
			Title:             title,
			Description:       description,
			Id:                generatedId,
			OrgId:             orgId,
			UserId:            "",
			Tags:              []string{},
			Amount:            1,
			ReferenceUrl:      referenceUrl,
			OrgNotificationId: "",
			Dismissable:       true,
			Personal:          false,
			Read:              false,
		}

		err = SetNotification(ctx, mainNotification)
		if err != nil {
			log.Printf("[WARNING] Failed making org notification with title %#v for org %s", title, orgId)
			return err
		}

		// 1. Find users in org
		// 2. Make notification for each of them
		// 3. Make reference to org notification

		org, err := GetOrg(ctx, orgId)
		if err != nil {
			log.Printf("[WARNING] Error getting org %s in createOrgNotification: %s", orgId, err)
			return err
		}

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

		for _, user := range filteredUsers {
			log.Printf("[DEBUG] Made notification for user %s (%s)", user.Username, user.Id)
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
	}

	return nil
}
