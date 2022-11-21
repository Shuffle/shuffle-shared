package shuffle

// This file contains all the function
// related to managing workflows

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	//"os/exec"
	"strings"
	"time"

	"encoding/json"

	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

func HandleUpdateUser(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	if project.Environment == "cloud" {
		// Checking if it's a special region. All user-specific requests should
		// go through shuffler.io and not subdomains
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting Update User request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
	}

	userInfo, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("Api authentication failed in update user: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Println("Failed reading body")
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Missing field: user_id"}`)))
		return
	}

	// NEVER allow the user to set all the data themselves
	type newUserStruct struct {
		Tutorial    string   `json:"tutorial" datastore:"tutorial"`
		Firstname   string   `json:"firstname"`
		Lastname    string   `json:"lastname"`
		Role        string   `json:"role"`
		Username    string   `json:"username"`
		UserId      string   `json:"user_id"`
		EthInfo     EthInfo  `json:"eth_info"`
		CompanyRole string   `json:"company_role"`
		Suborgs     []string `json:"suborgs"`
	}

	ctx := GetContext(request)
	var t newUserStruct
	err = json.Unmarshal(body, &t)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling userId: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unmarshaling. Missing field: user_id"}`)))
		return
	}

	// Should this role reflect the users' org access?
	// When you change org -> change user role
	if userInfo.Role != "admin" && userInfo.Id != t.UserId {
		log.Printf("[WARNING] User %s tried to update user %s. Role: %s", userInfo.Username, t.UserId, userInfo.Role)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "You need to be admin to change other users"}`)))
		return
	}

	foundUser, err := GetUser(ctx, t.UserId)
	if err != nil {
		log.Printf("[WARNING] Can't find user %s (update user): %s", t.UserId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false}`)))
		return
	}

	defaultRole := foundUser.Role
	orgFound := false
	for _, item := range foundUser.Orgs {
		if item == userInfo.ActiveOrg.Id {
			orgFound = true
			break
		}
	}

	if !orgFound {
		log.Printf("[AUDIT] User %s is admin, but can't edit users outside their own org.", userInfo.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't change users outside your org."}`)))
		return
	}

	orgUpdater := true
	log.Printf("Role: %#v", t.Role)
	if len(t.Role) > 0 && (t.Role != "admin" && t.Role != "user" && t.Role != "org-reader") {
		log.Printf("[WARNING] %s tried and failed to update user %s", userInfo.Username, t.UserId)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can only change to roles user, admin and org-reader"}`)))
		return
	} else {
		// Same user - can't edit yourself?
		if len(t.Role) > 0 && (userInfo.Id == t.UserId || userInfo.Username == t.UserId) {
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't update the role of your own user"}`)))
			return
		}

		if len(t.Role) > 0 {
			log.Printf("[INFO] Updated user %s from %s to %#v in org %s. If role is empty, not updating", foundUser.Username, foundUser.Role, t.Role, userInfo.ActiveOrg.Id)
			orgUpdater = false

			// Realtime update if the user is in the same org
			if userInfo.ActiveOrg.Id == foundUser.ActiveOrg.Id {
				foundUser.Role = t.Role
				foundUser.Roles = []string{t.Role}
			}

			// Getting the specific org and just updating the user in that one
			foundOrg, err := GetOrg(ctx, userInfo.ActiveOrg.Id)
			if err != nil {
				log.Printf("[WARNING] Failed to get org in edit role to %s for %s (%s): %s", t.Role, foundUser.Username, foundUser.Id, err)
			} else {
				users := []User{}
				for _, user := range foundOrg.Users {
					if user.Id == foundUser.Id {
						user.Role = t.Role
						user.Roles = []string{t.Role}
					}

					users = append(users, user)
				}

				foundOrg.Users = users
				err = SetOrg(ctx, *foundOrg, foundOrg.Id)
				if err != nil {
					log.Printf("[WARNING] Failed setting org when changing role to %s for %s (%s): %s", t.Role, foundUser.Username, foundUser.Id, err)
				}
			}
		}
	}

	if len(t.Username) > 0 && project.Environment != "cloud" {
		users, err := FindUser(ctx, strings.ToLower(strings.TrimSpace(t.Username)))
		if err != nil && len(users) == 0 {
			log.Printf("[WARNING] Failed getting user %s: %s", t.Username, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Username and/or password is incorrect"}`))
			return
		}

		found := false
		for _, item := range users {
			if item.Username == t.Username {
				found = true
				break
			}
		}

		if found {
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "User with username %s already exists"}`, t.Username)))
			return
		}

		foundUser.Username = t.Username
		if foundUser.Role == "" {
			foundUser.Role = defaultRole
		}
	}

	if len(t.Tutorial) > 0 {
		if !ArrayContains(foundUser.PersonalInfo.Tutorials, t.Tutorial) {
			foundUser.PersonalInfo.Tutorials = append(foundUser.PersonalInfo.Tutorials, t.Tutorial)
		}
	}

	if len(t.Firstname) > 0 {
		foundUser.PersonalInfo.Firstname = t.Firstname
	}

	if len(t.Lastname) > 0 {
		foundUser.PersonalInfo.Lastname = t.Lastname
	}

	if len(t.CompanyRole) > 0 {
		foundUser.PersonalInfo.Role = t.CompanyRole
	}

	if len(t.EthInfo.Account) > 0 {
		log.Printf("[DEBUG] Should set ethinfo to %#v", t.EthInfo)
		foundUser.EthInfo = t.EthInfo
	}

	if len(t.Suborgs) > 0 && foundUser.Id != userInfo.Id {
		log.Printf("[DEBUG] Got suborg change: %#v", t.Suborgs)
		// 1. Check if current users' active org is admin in same parent org as user
		// 2. Make sure the user should have access to suborg
		// 3. Make sure it's ONLY changing orgs based on parent org
		addedOrgs := []string{}
		for _, suborg := range t.Suborgs {
			if suborg == "REMOVE" {
				continue
			}

			if ArrayContains(foundUser.Orgs, suborg) {
				log.Printf("[DEBUG] Skipping %s as it already exists", suborg)
				continue
			}

			if !ArrayContains(userInfo.Orgs, suborg) {
				log.Printf("[ERROR] Skipping org %s as user %s (%s) can't edit this one. Should never happen unless direct API usage.", suborg, userInfo.Username, userInfo.Id)
				continue
			}

			foundOrg, err := GetOrg(ctx, suborg)
			if err != nil {
				log.Printf("[WARNING] Failed to get suborg in user edit for %s (%s): %s", foundUser.Username, foundUser.Id, err)
				continue
			}

			// Slower but easier :)
			parsedOrgs := []string{}
			for _, item := range foundOrg.ManagerOrgs {
				parsedOrgs = append(parsedOrgs, item.Id)
			}

			if !ArrayContains(parsedOrgs, userInfo.ActiveOrg.Id) {
				log.Printf("[ERROR] The Org %s SHOULD NOT BE ADDED for %s (%s): %s. This may indicate a test of the API, as the frontend shouldn't allow it.", suborg, foundUser.Username, foundUser.Id, err)
				continue
			}

			addedOrgs = append(addedOrgs, suborg)
		}

		// After done, check if ANY of the users' orgs are suborgs of active parent org. If they are, remove.
		// Update: This piece runs anyway, in case the job is to REMOVE any suborg
		//if len(addedOrgs) > 0 {
		log.Printf("[DEBUG] Orgs to be added: %#v. Existing: %#v", addedOrgs, foundUser.Orgs)
		newUserOrgs := []string{}
		for _, suborg := range foundUser.Orgs {
			if suborg == userInfo.ActiveOrg.Id {
				newUserOrgs = append(newUserOrgs, suborg)
				continue
			}

			foundOrg, err := GetOrg(ctx, suborg)
			if err != nil {
				log.Printf("[WARNING] Failed to get suborg in user edit (2) for %s (%s): %s", foundUser.Username, foundUser.Id, err)
				newUserOrgs = append(newUserOrgs, suborg)
				continue
			}

			// Slower but easier :)
			parsedOrgs := []string{}
			for _, item := range foundOrg.ManagerOrgs {
				parsedOrgs = append(parsedOrgs, item.Id)
			}

			//if !ArrayContains(parsedOrgs, userInfo.ActiveOrg.Id) {
			if !ArrayContains(parsedOrgs, suborg) {
				if ArrayContains(t.Suborgs, suborg) {
					log.Printf("[DEBUG] Reappending org %s", suborg)
					newUserOrgs = append(newUserOrgs, suborg)
				} else {
					log.Printf("[DEBUG] Skipping org %s", suborg)
				}
				//continue
			}

			log.Printf("[DEBUG] Should remove user %s (%s) from org %s if it doesn't exist in t.Suborgs", foundUser.Username, foundUser.Id, suborg)
			newUsers := []User{}
			for _, user := range foundOrg.Users {
				if user.Id == foundUser.Id {
					continue
				}

				newUsers = append(newUsers, user)
			}

			foundOrg.Users = newUsers
			err = SetOrg(ctx, *foundOrg, foundOrg.Id)
			if err != nil {
				log.Printf("[WARNING] Failed setting org when changing user access: %s", err)
			}

		}

		foundUser.Orgs = append(newUserOrgs, addedOrgs...)
		log.Printf("[DEBUG] New orgs for %s (%s) is %#v", foundUser.Username, foundUser.Id, foundUser.Orgs)
		/*
			for _, suborg := range addedOrgs {
				foundOrg, err := GetOrg(ctx, suborg)
				if err != nil {
					continue
				}

				found := false
				for _, user := range foundOrg.Users {
					if user.Id == foundUser.Id {
						found = true
						break
					}
				}

				if !found {
					// FIXME: Use the same roles as in parent
					foundOrg.Users = append(foundorg.Users, UserMini{
						Username: foundUser.Username,
						Id:       foundUser.Id,
						Role:     foundUser.Role,
					})
				}
			}
		*/
	}

	err = SetUser(ctx, foundUser, orgUpdater)
	if err != nil {
		log.Printf("[WARNING] Error patching user %s: %s", foundUser.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true}`)))
}

func HandleGetUsers(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get users: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role != "admin" {
		log.Printf("[AUDIT] User isn't admin (%s) and can't list users.", user.Role)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Not admin"}`))
		return
	}

	ctx := GetContext(request)
	org, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Failed getting org in get users: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting org when listing users"}`))
		return
	}

	newUsers := []User{}
	for _, item := range org.Users {
		if len(item.Username) == 0 {
			continue
		}

		//for _, tmpUser := range newUsers {
		//	if tmpUser.Name
		//}

		if item.Username != user.Username && (len(item.Orgs) > 1 || item.Role == "admin") {
			//log.Printf("[DEBUG] Orgs for the user: %#v", item.Orgs)
			item.ApiKey = ""
		}

		item.Password = ""
		item.Session = ""
		item.VerificationToken = ""
		item.Orgs = []string{}
		item.EthInfo = EthInfo{}

		// Will get from cache 2nd time so this is fine.
		if user.Id == item.Id {
			item.Orgs = user.Orgs
			item.Active = user.Active
			item.MFA = user.MFA
		} else {
			foundUser, err := GetUser(ctx, item.Id)
			if err == nil {
				// Only add IF the admin querying it has access, meaning only show what you yourself have access toMFAInfo
				allOrgs := []string{}
				for _, orgname := range foundUser.Orgs {
					found := false

					for _, userOrg := range user.Orgs {
						if userOrg == orgname {
							found = true
							break
						}
					}

					if found {
						allOrgs = append(allOrgs, orgname)
					}
				}

				//log.Printf("[DEBUG] Added %d org(s) for user %s (%s) - get users", len(allOrgs), foundUser.Username, foundUser.Id)

				item.MFA = foundUser.MFA
				item.Verified = foundUser.Verified
				item.Active = foundUser.Active
				item.Orgs = allOrgs
			}
		}

		if len(item.Orgs) == 0 {
			item.Orgs = append(item.Orgs, user.ActiveOrg.Id)
		}

		newUsers = append(newUsers, item)
	}

	newjson, err := json.Marshal(newUsers)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshal in getusers: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func HandlePasswordChange(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	if project.Environment == "cloud" {
		// Checking if it's a special region. All user-specific requests should
		// go through shuffler.io and not subdomains
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting Password Change request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
	}

	if request.Body == nil {
		resp.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Println("[WARNING] Failed reading body")
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false}`)))
		return
	}

	// Get the current user - check if they're admin or the "username" user.
	var t PasswordChange
	err = json.Unmarshal(body, &t)
	if err != nil {
		log.Println("Failed unmarshaling")
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false}`)))
		return
	}

	userInfo, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in password change: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	log.Printf("[AUDIT] Handling password change for %s from %s (%s)", t.Username, userInfo.Username, userInfo.Id)

	curUserFound := false
	if t.Username != userInfo.Username {
		log.Printf("[WARNING] Bad username during password change for %s.", t.Username)

		if project.Environment == "cloud" {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Not allowed to change others' passwords in cloud"}`))
			return
		}
	} else if t.Username == userInfo.Username {
		curUserFound = true
	}

	if userInfo.Role != "admin" {
		if t.Newpassword != t.Newpassword2 {
			err := "Passwords don't match"
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
			return
		}

		if project.Environment == "cloud" {
			if len(t.Newpassword) < 10 || len(t.Newpassword2) < 10 {
				err := "Passwords too short - 2"
				resp.WriteHeader(401)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
				return
			}
		}
	} else {
		// Check ORG HERE?
	}

	// Current password
	err = CheckPasswordStrength(t.Newpassword)
	if err != nil {
		log.Printf("[INFO] Bad password strength: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
		return
	}

	ctx := GetContext(request)
	foundUser := User{}
	if !curUserFound {
		users, err := FindUser(ctx, strings.ToLower(strings.TrimSpace(t.Username)))
		if err != nil && len(users) == 0 {
			log.Printf("[WARNING] Failed getting user %s: %s", t.Username, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Username and/or password is incorrect"}`))
			return
		}

		if len(users) != 1 {
			log.Printf(`[WARNING] Found multiple or no users with the same username: %s: %d`, t.Username, len(users))
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Found %d users with the same username: %s"}`, len(users), t.Username)))
			return
		}

		foundUser = users[0]
		orgFound := false
		if userInfo.ActiveOrg.Id == foundUser.ActiveOrg.Id {
			orgFound = true
		} else {
			for _, item := range foundUser.Orgs {
				if item == userInfo.ActiveOrg.Id {
					orgFound = true
					break
				}
			}
		}

		if !orgFound {
			log.Printf("[AUDIT] User %s (%s) is admin, but can't change user's (%s) password outside their own org.", userInfo.Username, userInfo.Id, foundUser.Username)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't change users outside your org."}`)))
			return
		}
	} else {
		// Admins can re-generate others' passwords as well.
		if userInfo.Role != "admin" {
			err = bcrypt.CompareHashAndPassword([]byte(userInfo.Password), []byte(t.Currentpassword))
			if err != nil {
				log.Printf("[WARNING] Bad password for %s: %s", userInfo.Username, err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "Username and/or password is incorrect"}`))
				return
			}
		}

		// log.Printf("FOUND: %#v", curUserFound)
		foundUser = userInfo
		//userInfo, err := HandleApiAuthentication(resp, request)
	}

	if len(foundUser.Id) == 0 {
		log.Printf("[WARNING] Something went wrong in password reset: couldn't find user.")
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(t.Newpassword), 8)
	if err != nil {
		log.Printf("New password failure for %s: %s", userInfo.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Username and/or password is incorrect"}`))
		return
	}

	foundUser.Password = string(hashedPassword)
	err = SetUser(ctx, &foundUser, true)
	if err != nil {
		log.Printf("Error fixing password for user %s: %s", userInfo.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Username and/or password is incorrect"}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true}`)))
}

// Can check against HIBP etc?
// Removed for localhost
func CheckPasswordStrength(password string) error {
	// Check password strength here
	if len(password) < 4 {
		return errors.New("Minimum password length is 4.")
	}

	//if len(password) > 128 {
	//	return errors.New("Maximum password length is 128.")
	//}

	//re := regexp.MustCompile("[0-9]+")
	//if len(re.FindAllString(password, -1)) == 0 {
	//	return errors.New("Password must contain a number")
	//}

	//re = regexp.MustCompile("[a-z]+")
	//if len(re.FindAllString(password, -1)) == 0 {
	//	return errors.New("Password must contain a lower case char")
	//}

	//re = regexp.MustCompile("[A-Z]+")
	//if len(re.FindAllString(password, -1)) == 0 {
	//	return errors.New("Password must contain an upper case char")
	//}

	return nil
}

func DeleteUser(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	userInfo, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("[WARNING] Api authentication failed in delete user: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if userInfo.Role != "admin" {
		log.Printf("Wrong user (%s) when deleting - must be admin", userInfo.Username)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Must be admin"}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")
	var userId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		userId = location[4]
	}

	ctx := GetContext(request)
	userId, err := url.QueryUnescape(userId)
	if err != nil {
		log.Printf("[WARNING] Failed decoding user %s: %s", userId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false}`)))
		return
	}

	if userId == userInfo.Id {
		log.Printf("[WARNING] Can't change activation of your own user %s (%s)", userInfo.Username, userInfo.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't change activation of your own user"}`)))
		return
	}

	foundUser, err := GetUser(ctx, userId)
	if err != nil {
		log.Printf("[WARNING] Can't find user %s (delete user): %s", userId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false}`)))
		return
	}

	orgFound := false
	if userInfo.ActiveOrg.Id == foundUser.ActiveOrg.Id {
		orgFound = true
	} else {
		log.Printf("FoundUser: %#v", foundUser.Orgs)
		for _, item := range foundUser.Orgs {
			if item == userInfo.ActiveOrg.Id {
				orgFound = true
				break
			}
		}
	}

	if !orgFound {
		log.Printf("[AUDIT] User %s is admin, but can't delete users outside their own org.", userInfo.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't change users outside your org."}`)))
		return
	}

	// OLD: Invert. No user deletion.
	//if foundUser.Active {
	//	foundUser.Active = false
	//} else {
	//	foundUser.Active = true
	//}

	// NEW
	neworgs := []string{}
	for _, orgid := range foundUser.Orgs {
		if orgid == userInfo.ActiveOrg.Id {
			continue
		} else {
			// Automatically setting to first one
			if foundUser.ActiveOrg.Id == userInfo.ActiveOrg.Id {
				foundUser.ActiveOrg.Id = orgid
			}
		}

		neworgs = append(neworgs, orgid)
	}

	if foundUser.ActiveOrg.Id == userInfo.ActiveOrg.Id {
		log.Printf("[ERROR] User %s (%s) doesn't have an org anymore after being deleted. Give them one (NOT SET UP)", foundUser.Username, foundUser.Id)
		foundUser.ActiveOrg.Id = ""
	}

	foundUser.Orgs = neworgs
	err = SetUser(ctx, foundUser, false)
	if err != nil {
		log.Printf("[WARNING] Failed removing user %s (%s) from org %s", foundUser.Username, foundUser.Id, orgFound)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false}`)))
		return
	}

	org, err := GetOrg(ctx, userInfo.ActiveOrg.Id)
	if err != nil {
		log.Printf("[DEBUG] Failed getting org %s in delete user: %s", userInfo.ActiveOrg.Id, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false}`)))
		return
	}

	users := []User{}
	for _, user := range org.Users {
		if user.Id == foundUser.Id {
			continue
		}

		users = append(users, user)
	}

	org.Users = users
	err = SetOrg(ctx, *org, org.Id)
	if err != nil {
		log.Printf("[WARNING] Failed updating org (delete user %s) %s: %s", foundUser.Username, org.Id, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Removed their access but failed updating own user list"}`)))
		return
	}

	log.Printf("[INFO] Successfully removed %s from org %s", foundUser.Username, userInfo.ActiveOrg.Id)

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func RedirectUserRequest(w http.ResponseWriter, req *http.Request) {
	proxyScheme := "https"
	proxyHost := fmt.Sprintf("shuffler.io")

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	//fmt.Fprint(resp, "OK")
	//http.Redirect(resp, request, "https://europe-west2-shuffler.cloudfunctions.net/ShuffleSSR", 303)
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Printf("[ERROR] Issue in SSR body proxy: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//req.Body = ioutil.NopCloser(bytes.NewReader(body))
	url := fmt.Sprintf("%s://%s%s", proxyScheme, proxyHost, req.RequestURI)
	log.Printf("[DEBUG] Request (%s) Proxy request URL: %s. More: %s", req.Method, url, req.URL.String())

	proxyReq, err := http.NewRequest(req.Method, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[ERROR] Failed handling proxy request: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// We may want to filter some headers, otherwise we could just use a shallow copy
	proxyReq.Header = make(http.Header)
	for h, val := range req.Header {
		proxyReq.Header[h] = val
	}

	newresp, err := httpClient.Do(proxyReq)
	if err != nil {
		log.Printf("[ERROR] Issue in SSR newresp for %s - should retry: %s", url, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	defer newresp.Body.Close()

	urlbody, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	//log.Printf("RESP: %s", urlbody)
	for key, value := range newresp.Header {
		//log.Printf("%s %s", key, value)
		for _, item := range value {
			w.Header().Set(key, item)
		}
	}

	w.WriteHeader(newresp.StatusCode)
	w.Write(urlbody)

	// Need to clear cache in case user gets updated in db
	// with a new session and such. This only forces a new search,
	// and shouldn't get them logged out
	ctx := GetContext(req)
	c, err := req.Cookie("session_token")
	if err != nil {
		c, err = req.Cookie("__session")
	}

	if err == nil {
		DeleteCache(ctx, fmt.Sprintf("session_%s", c.Value))
	}
}

func HandleLogin(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	if project.Environment == "cloud" {
		// Checking if it's a special region. All user-specific requests should
		// go through shuffler.io and not subdomains
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting LOGIN request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
	}

	// Gets a struct of Username, password
	data, err := ParseLoginParameters(resp, request)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
		return
	}

	log.Printf("[AUDIT] Handling login of %s", data.Username)

	data.Username = strings.ToLower(strings.TrimSpace(data.Username))
	err = checkUsername(data.Username)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
		return
	}

	ctx := GetContext(request)
	users, err := FindUser(ctx, data.Username)
	if err != nil && len(users) == 0 {
		log.Printf("[WARNING] Failed getting user %s during login", data.Username)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Username and/or password is incorrect"}`))
		return
	}

	userdata := User{}
	if len(users) != 1 {
		log.Printf("[WARNING] Username %s has multiple or no users (%d). Checking if it matches any.", data.Username, len(users))

		for _, user := range users {
			if user.Id == "" && user.Username == "" {
				log.Printf(`[WARNING] Username %s (%s) isn't valid. Amount of users checked: %d (1)`, user.Username, user.Id, len(users))
				continue
			}

			if user.ActiveOrg.Id != "" {
				err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(data.Password))
				if err != nil {
					log.Printf("[WARNING] Bad password: %s", err)
					continue
				}

				userdata = user
				break
			}
		}
	} else {
		userdata = users[0]
	}

	/*
		// FIXME: Reenable activation?
			if !userdata.Active {
				log.Printf("[DEBUG] %s is not active, but tried to login. Error: %v", data.Username, err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "This user is deactivated"}`))
				return
			}
	*/

	updateUser := false
	if project.Environment == "cloud" {
		//log.Printf("[DEBUG] Are they using SSO?")
		// If it fails, allow login if password correct?
		// Check if suborg -> Get parent & check SSO
		baseOrg, err := GetOrg(ctx, userdata.ActiveOrg.Id)
		if err == nil {
			//log.Printf("Got org during signin: %s - checking SAML SSO", baseOrg.Id)
			org := baseOrg
			if len(baseOrg.ManagerOrgs) > 0 {

				// Use auth from parent org if user is also in that one
				newOrg, err := GetOrg(ctx, baseOrg.ManagerOrgs[0].Id)
				if err == nil {

					found := false
					for _, user := range newOrg.Users {
						if user.Username == userdata.Username {
							found = true
						}
					}

					if found {
						log.Printf("[WARNING] Using parent org of %s as org %s", baseOrg.Id, newOrg.Id)
						org = newOrg
					}
				}
			}

			if len(org.SSOConfig.SSOEntrypoint) > 0 {
				log.Printf("[DEBUG] Should redirect user %s in org %s to SSO login at %s", userdata.Username, userdata.ActiveOrg.Id, org.SSOConfig.SSOEntrypoint)
				// https://trial-7276434.okta.com/app/trial-7276434_shuffle_1/exk10dgh8tZNCaXGC697/sso/saml

				// Check if the user has other orgs that can be swapped to - if so SWAP
				userDomain := strings.Split(userdata.Username, "@")
				for _, tmporg := range userdata.Orgs {
					innerorg, err := GetOrg(ctx, tmporg)
					if err != nil {
						continue
					}

					if innerorg.Id == userdata.ActiveOrg.Id {
						continue
					}

					if len(innerorg.ManagerOrgs) > 0 {
						continue
					}

					// Not your own org
					if innerorg.Org == userdata.Username || strings.Contains(innerorg.Name, "@") {
						continue
					}

					if len(userDomain) >= 2 {
						if strings.Contains(strings.ToLower(innerorg.Org), strings.ToLower(userDomain[1])) {
							continue
						}
					}

					// Shouldn't contain the domain of the users' email
					log.Printf("[DEBUG] Found org for %s (%s) to check into instead of running SSO: %s", userdata.Username, userdata.Id, innerorg.Name)
					userdata.ActiveOrg.Id = innerorg.Id
					userdata.ActiveOrg.Name = innerorg.Name

					updateUser = true
					break

				}

				// user controllable field hmm :)
				if !updateUser {
					resp.WriteHeader(401)
					resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "SSO_REDIRECT", "url": "%s"}`, org.SSOConfig.SSOEntrypoint)))
					return
				}
			}
		}
	}

	if len(users) == 1 {
		err = bcrypt.CompareHashAndPassword([]byte(userdata.Password), []byte(data.Password))
		if err != nil {
			userdata = User{}
			log.Printf("[WARNING] Bad password: %s", err)
		} else {
			log.Printf("[DEBUG] Correct password with single user!")
		}
	}

	if userdata.Id == "" && userdata.Username == "" {
		log.Printf(`[ERROR] Username %s isn't valid. Amount of users checked: %d (2)`, data.Username, len(users))
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Username and/or password is incorrect"}`)))
		return
	}

	if updateUser {
		err = SetUser(ctx, &userdata, false)
		if err != nil {
			log.Printf("[WARNING] Failed updating user when auto-setting new org: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Something went wrong with the SSO redirect system"}`)))
			return
		}
	}

	if userdata.LoginType == "SSO" {
		log.Printf(`[WARNING] Username %s (%s) has login type set to SSO (single sign-on).`, userdata.Username, userdata.Id)
		//resp.WriteHeader(401)
		//resp.Write([]byte(`{"success": false, "reason": "This user can only log in with SSO"}`))
		//return
	}

	if userdata.LoginType == "OpenID" {
		log.Printf(`[WARNING] Username %s (%s) has login type set to OpenID (single sign-on).`, userdata.Username, userdata.Id)
	}

	if userdata.MFA.Active && len(data.MFACode) == 0 {
		log.Printf(`[DEBUG] Username %s (%s) has MFA activated. Redirecting.`, userdata.Username, userdata.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "MFA_REDIRECT"}`)))
		return
	}

	if len(data.MFACode) > 0 && userdata.MFA.Active {
		interval := time.Now().Unix() / 30
		HOTP, err := getHOTPToken(userdata.MFA.ActiveCode, interval)
		if err != nil {
			log.Printf("[ERROR] Failed generating a HOTP token: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed generating token. Please try again."}`))
			return
		}

		if HOTP != data.MFACode {
			log.Printf("[DEBUG] Bad code sent for user %s (%s). Sent: %s, Want: %s", userdata.Username, userdata.Id, data.MFACode, HOTP)
			resp.WriteHeader(500)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Wrong 2-factor code (%s). Please try again with a 6-digit code. If this persists, please contact support."}`, data.MFACode)))
			return
		}

		log.Printf("[DEBUG] MFA login for user %s (%s)!", userdata.Username, userdata.Id)
	}

	//tutorialsFinished := userdata.PersonalInfo.Tutorials
	//if len(org.SecurityFramework.SIEM.Name) > 0 || len(org.SecurityFramework.Network.Name) > 0 || len(org.SecurityFramework.EDR.Name) > 0 || len(org.SecurityFramework.Cases.Name) > 0 || len(org.SecurityFramework.IAM.Name) > 0 || len(org.SecurityFramework.Assets.Name) > 0 || len(org.SecurityFramework.Intel.Name) > 0 || len(org.SecurityFramework.Communication.Name) > 0 {
	//	tutorialsFinished = append(tutorialsFinished, "find_integrations")
	//}

	userdata.LoginInfo = append(userdata.LoginInfo, LoginInfo{
		IP:        request.RemoteAddr,
		Timestamp: time.Now().Unix(),
	})

	returnValue := HandleInfo{
		Success:   true,
		Tutorials: []Tutorial{},
	}

	loginData := `{"success": true}`
	newData, err := json.Marshal(returnValue)
	if err == nil {
		loginData = string(newData)
	}

	if len(userdata.Session) != 0 {
		log.Println("[INFO] User session exists - resetting session")
		expiration := time.Now().Add(3600 * time.Second)

		newCookie := &http.Cookie{
			Name:    "session_token",
			Value:   userdata.Session,
			Expires: expiration,
		}

		if project.Environment == "cloud" {
			newCookie.Domain = ".shuffler.io"
			newCookie.Secure = true
			newCookie.HttpOnly = true
		}

		http.SetCookie(resp, newCookie)

		newCookie.Name = "__session"
		http.SetCookie(resp, newCookie)

		//log.Printf("SESSION LENGTH MORE THAN 0 IN LOGIN: %s", userdata.Session)
		returnValue.Cookies = append(returnValue.Cookies, SessionCookie{
			Key:        "session_token",
			Value:      userdata.Session,
			Expiration: expiration.Unix(),
		})

		returnValue.Cookies = append(returnValue.Cookies, SessionCookie{
			Key:        "__session",
			Value:      userdata.Session,
			Expiration: expiration.Unix(),
		})

		loginData = fmt.Sprintf(`{"success": true, "cookies": [{"key": "session_token", "value": "%s", "expiration": %d}]}`, userdata.Session, expiration.Unix())
		newData, err := json.Marshal(returnValue)
		if err == nil {
			loginData = string(newData)
		}

		err = SetSession(ctx, userdata, userdata.Session)
		if err != nil {
			log.Printf("[WARNING] Error adding session to database: %s", err)
		} else {
			//log.Printf("[DEBUG] Updated session in backend")
		}

		err = SetUser(ctx, &userdata, false)
		if err != nil {
			log.Printf("[ERROR] Failed updating user when setting session (2): %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		resp.WriteHeader(200)
		resp.Write([]byte(loginData))
		return
	} else {
		log.Printf("[INFO] User session is empty - create one!")

		sessionToken := uuid.NewV4().String()
		expiration := time.Now().Add(3600 * time.Second)
		newCookie := &http.Cookie{
			Name:    "session_token",
			Value:   sessionToken,
			Expires: expiration,
		}

		if project.Environment == "cloud" {
			newCookie.Domain = ".shuffler.io"
			newCookie.Secure = true
			newCookie.HttpOnly = true
		}

		http.SetCookie(resp, newCookie)

		// ADD TO DATABASE
		err = SetSession(ctx, userdata, sessionToken)
		if err != nil {
			log.Printf("Error adding session to database: %s", err)
		}

		userdata.Session = sessionToken
		err = SetUser(ctx, &userdata, true)
		if err != nil {
			log.Printf("Failed updating user when setting session: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		returnValue.Cookies = append(returnValue.Cookies, SessionCookie{
			Key:        "session_token",
			Value:      sessionToken,
			Expiration: expiration.Unix(),
		})

		returnValue.Cookies = append(returnValue.Cookies, SessionCookie{
			Key:        "__session",
			Value:      sessionToken,
			Expiration: expiration.Unix(),
		})

		loginData = fmt.Sprintf(`{"success": true, "cookies": [{"key": "session_token", "value": "%s", "expiration": %d}]}`, sessionToken, expiration.Unix())
		newData, err := json.Marshal(returnValue)
		if err == nil {
			loginData = string(newData)
		}
	}

	log.Printf("[INFO] %s SUCCESSFULLY LOGGED IN with session %s", data.Username, userdata.Session)

	resp.WriteHeader(200)
	resp.Write([]byte(loginData))
}

func ParseLoginParameters(resp http.ResponseWriter, request *http.Request) (loginStruct, error) {
	if request.Body == nil {
		return loginStruct{}, errors.New("Failed to parse login params, body is empty")
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		return loginStruct{}, err
	}

	var t loginStruct

	err = json.Unmarshal(body, &t)
	if err != nil {
		return loginStruct{}, err
	}

	return t, nil
}

func checkUsername(Username string) error {
	// Stupid first check of email loool
	//if !strings.Contains(Username, "@") || !strings.Contains(Username, ".") {
	//	return errors.New("Invalid Username")
	//}

	if len(Username) < 3 {
		return errors.New("Minimum Username length is 3")
	}

	return nil
}

