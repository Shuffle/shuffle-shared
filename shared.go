package shuffle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"

	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/frikky/kin-openapi/openapi2"
	"github.com/frikky/kin-openapi/openapi2conv"
	"github.com/frikky/kin-openapi/openapi3"

	"github.com/google/go-github/v28/github"
	"github.com/google/go-querystring/query"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/appengine"
)

var project ShuffleStorage
var baseDockerName = "frikky/shuffle"
var SSOUrl = ""

func getContext(request *http.Request) context.Context {
	if project.Environment == "cloud" {
		return appengine.NewContext(request)
	}

	return context.Background()
}

func HandleCors(resp http.ResponseWriter, request *http.Request) bool {

	// FIXME - this is to handle multiple frontends in test rofl
	origin := request.Header["Origin"]
	resp.Header().Set("Vary", "Origin")
	if len(origin) > 0 {
		resp.Header().Set("Access-Control-Allow-Origin", origin[0])
	} else {
		resp.Header().Set("Access-Control-Allow-Origin", "http://localhost:4201")
	}
	//resp.Header().Set("Access-Control-Allow-Origin", "http://localhost:8000")
	resp.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, X-Requested-With, remember-me")
	resp.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, POST, PATCH")
	resp.Header().Set("Access-Control-Allow-Credentials", "true")

	if request.Method == "OPTIONS" {
		resp.WriteHeader(200)
		resp.Write([]byte("OK"))
		return true
	}

	return false
}

func Md5sum(data []byte) string {
	hasher := md5.New()
	hasher.Write(data)
	newmd5 := hex.EncodeToString(hasher.Sum(nil))
	return newmd5
}

func Md5sumfile(filepath string) string {
	dat, err := ioutil.ReadFile(filepath)
	if err != nil {
		log.Printf("Error in dat: %s", err)
	}

	hasher := md5.New()
	hasher.Write(dat)
	newmd5 := hex.EncodeToString(hasher.Sum(nil))

	log.Printf("%s: %s", filepath, newmd5)
	return newmd5
}

func randStr(strSize int, randType string) string {

	var dictionary string

	if randType == "alphanum" {
		dictionary = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	if randType == "alpha" {
		dictionary = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	if randType == "number" {
		dictionary = "0123456789"
	}

	var bytes = make([]byte, strSize)
	rand.Read(bytes)
	for k, v := range bytes {
		bytes[k] = dictionary[v%byte(len(dictionary))]
	}

	return string(bytes)
}

func HandleSet2fa(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[ERROR] Api authentication failed in get 2fa: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	var fileId string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("[ERROR] Path too short: %d", len(location))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Error with body read: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	type parsedValue struct {
		Code   string `json:"code"`
		UserId string `json:"user_id"`
	}

	var tmpBody parsedValue
	err = json.Unmarshal(body, &tmpBody)
	if err != nil {
		log.Printf("[WARNING] Error with unmarshal tmpBody in verify 2fa: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(tmpBody.Code) != 6 {
		log.Printf("[WARNING] Length of code isn't 6: %s", tmpBody.Code)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Length of code must be 6"}`)))
		return
	}

	// FIXME: Everything should match?
	// || user.Id != tmpBody.UserId
	if user.Id != fileId {
		log.Printf("[WARNING] Bad ID: %s vs %s", user.Id, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can only set 2fa for your own user. Pass field user_id in JSON."}`)))
		return
	}

	ctx := getContext(request)
	foundUser, err := GetUser(ctx, user.Id)
	if err != nil {
		log.Printf("[ERROR] Can't find user %s (set 2fa): %s", user.Id, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed getting your user."}`)))
		return
	}

	//https://www.gojek.io/blog/a-diy-two-factor-authenticator-in-golang
	interval := time.Now().Unix() / 30
	HOTP, err := getHOTPToken(foundUser.MFA.PreviousCode, interval)
	if err != nil {
		log.Printf("[ERROR] Failed generating a HOTP token: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if HOTP != tmpBody.Code {
		log.Printf("[DEBUG] Bad code sent for user %s (%s). Sent: %s, Want: %s", user.Username, user.Id, tmpBody.Code, HOTP)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Wrong code. Try again"}`))
		return
	}

	foundUser.MFA.Active = true
	foundUser.MFA.ActiveCode = foundUser.MFA.PreviousCode
	foundUser.MFA.PreviousCode = ""
	err = SetUser(ctx, foundUser, true)
	if err != nil {
		log.Printf("[WARNING] Failed SETTING MFA for user %s (%s): %s", foundUser.Username, foundUser.Id, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed updating your user. Please try again."}`))
		return
	}

	log.Printf("[DEBUG] Successfully enabled 2FA for user %s (%s)", foundUser.Username, foundUser.Id)

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true, "reason": "Correct code. MFA is now required for this user."}`))
}

func getHOTPToken(secret string, interval int64) (string, error) {

	//Converts secret to base32 Encoding. Base32 encoding desires a 32-character
	//subset of the twenty-six letters A–Z and ten digits 0–9
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}

	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(interval))

	//Signing the value using HMAC-SHA1 Algorithm
	hash := hmac.New(sha1.New, key)
	hash.Write(bs)
	h := hash.Sum(nil)

	// We're going to use a subset of the generated hash.
	// Using the last nibble (half-byte) to choose the index to start from.
	// This number is always appropriate as it's maximum decimal 15, the hash will
	// have the maximum index 19 (20 bytes of SHA1) and we need 4 bytes.
	o := (h[19] & 15)

	var header uint32
	//Get 32 bit chunk from hash starting at the o
	r := bytes.NewReader(h[o : o+4])
	err = binary.Read(r, binary.BigEndian, &header)
	if err != nil {
		return "", err
	}

	//Ignore most significant bits as per RFC 4226.
	//Takes division from one million to generate a remainder less than < 7 digits
	h12 := (int(header) & 0x7fffffff) % 1000000

	//Converts number as a string
	otp := strconv.Itoa(int(h12))

	// Dumb solutions <3
	// This works well, as the numbers are small ^_^
	if len(otp) == 0 {
		otp = "000000"
	} else if len(otp) == 1 {
		otp = fmt.Sprintf("00000%s", otp)
	} else if len(otp) == 2 {
		otp = fmt.Sprintf("0000%s", otp)
	} else if len(otp) == 3 {
		otp = fmt.Sprintf("000%s", otp)
	} else if len(otp) == 4 {
		otp = fmt.Sprintf("00%s", otp)
	} else if len(otp) == 5 {
		otp = fmt.Sprintf("0%s", otp)
	}

	return otp, nil
}

func HandleGet2fa(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[ERROR] Api authentication failed in get 2fa: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	var fileId string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("[ERROR] Path too short: %d", len(location))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	if user.Id != fileId {
		log.Printf("[WARNING] Bad ID: %s vs %s", user.Id, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can only set 2fa for your own user"}`)))
		return
	}

	// https://socketloop.com/tutorials/golang-generate-qr-codes-for-google-authenticator-app-and-fix-cannot-interpret-qr-code-error

	// generate a random string - preferably 6 or 8 characters
	randomStr := randStr(8, "alphanum")
	//fmt.Println(randomStr)

	// For Google Authenticator purpose
	// for more details see
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	secret := base32.StdEncoding.EncodeToString([]byte(randomStr))

	// authentication link. Remember to replace SocketLoop with yours.
	// for more details see
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	authLink := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=Shuffle", user.Username, secret)
	png, err := qrcode.Encode(authLink, qrcode.Medium, 256)
	if err != nil {
		log.Printf("[ERROR] Failed PNG encoding: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed image encoding"}`)))
		return
	}

	dataURI := fmt.Sprintf("data:image/png;base64,%s", base64.StdEncoding.EncodeToString([]byte(png)))
	newres := ResultChecker{
		Success: true,
		Reason:  dataURI,
		Extra:   randomStr,
	}

	newjson, err := json.Marshal(newres)
	if err != nil {
		log.Printf("[ERROR] Failed marshal in get OTP: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking data"}`)))
		return
	}

	ctx := getContext(request)
	//user.MFA.PreviousCode = authLink
	user.MFA.PreviousCode = secret
	err = SetUser(ctx, &user, true)
	if err != nil {
		log.Printf("[WARNING] Failed updating MFA for user: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed updating your user"}`))
		return
	}

	log.Printf("[DEBUG] Sent new MFA update for user %s (%s)", user.Username, user.Id)
	//log.Printf("%s", newjson)

	resp.WriteHeader(200)
	resp.Write([]byte(newjson))
}

func HandleGetOrgs(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get orgs: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := getContext(request)
	if user.Role != "global_admin" {
		orgs := []OrgMini{}
		for _, item := range user.Orgs {
			// FIXM: Should return normal orgs, but hidden if the user isn't admin
			org, err := GetOrg(ctx, item)
			if err == nil {
				orgs = append(orgs, OrgMini{
					Id:         org.Id,
					Name:       org.Name,
					CreatorOrg: org.CreatorOrg,
					Image:      org.Image,
				})
				// Role:       "admin",
			}
		}

		newjson, err := json.Marshal(orgs)
		if err != nil {
			log.Printf("[WARNING] Failed marshal in get orgs: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking"}`)))
			return
		}

		//log.Printf("[AUDIT] User %s (%s) isn't global admin and can't list orgs. Returning list of local orgs.", user.Username, user.Id)
		resp.WriteHeader(200)
		resp.Write([]byte(newjson))
		return
	}

	orgs, err := GetAllOrgs(ctx)
	if err != nil || len(orgs) == 0 {
		log.Printf("[WARNING] Failed getting orgs: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't get orgs"}`))
		return
	}

	newjson, err := json.Marshal(orgs)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshal in get orgs: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func HandleGetOrg(resp http.ResponseWriter, request *http.Request) {
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

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get org: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := getContext(request)
	org, err := GetOrg(ctx, fileId)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting org users"}`))
		return
	}

	admin := false
	userFound := false
	for _, inneruser := range org.Users {
		if inneruser.Id == user.Id {
			userFound = true

			if inneruser.Role == "admin" {
				admin = true
			}

			break
		}
	}

	_ = admin
	if !userFound {
		log.Printf("[WARNING] User %s isn't a part of org %s (get)", user.Id, org.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "User doesn't have access to org"}`))
		return

	}

	org.Users = []User{}
	org.SyncConfig.Apikey = ""
	org.SyncConfig.Source = ""

	if !admin {
		org.Defaults = Defaults{}
		org.SSOConfig = SSOConfig{}
		org.Subscriptions = []PaymentSubscription{}
		org.ManagerOrgs = []OrgMini{}
		org.ChildOrgs = []OrgMini{}
		org.Invites = []string{}
	}

	newjson, err := json.Marshal(org)
	if err != nil {
		log.Printf("Failed unmarshal of org: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func HandleLogout(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	c, err := request.Cookie("session_token")
	if err == nil {
		http.SetCookie(resp, &http.Cookie{
			Name:    "session_token",
			Value:   c.Value,
			Expires: time.Now().Add(-100 * time.Hour),
			MaxAge:  -1,
		})
	} else {
		http.SetCookie(resp, &http.Cookie{
			Name:    "session_token",
			Value:   "",
			Expires: time.Now().Add(-100 * time.Hour),
			MaxAge:  -1,
		})
	}

	userInfo, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in handleLogout: %s", err)
		resp.WriteHeader(200)
		resp.Write([]byte(`{"success": true, "reason": "Not logged in"}`))
		return
	}

	ctx := getContext(request)
	session, err := GetSession(ctx, userInfo.Session)
	if err != nil {
		log.Printf("[WARNING] Session %#v doesn't exist: %s", session, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "No session"}`))
		return
	}

	err = SetSession(ctx, userInfo, "")
	if err != nil {
		log.Printf("[WARNING] Error removing session in logout: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reseting sessions"}`))
		return
	}

	err = DeleteKey(ctx, "sessions", userInfo.Session)
	if err != nil {
		log.Printf("Error deleting key %s for %s: %s", userInfo.Session, userInfo.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Username and/or password is incorrect"}`))
		return
	}

	cacheKey := fmt.Sprintf("user_%s", strings.ToLower(userInfo.Username))
	DeleteCache(ctx, cacheKey)
	DeleteCache(ctx, userInfo.Session)

	userInfo.Session = ""
	err = SetUser(ctx, &userInfo, true)
	if err != nil {
		log.Printf("Failed updating user: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed updating apikey"}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": false, "reason": "Successfully logged out"}`))
}

// Basically a search for apps that aren't activated yet
func GetSpecificApps(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just need to be logged in
	// FIXME - should have some permissions?
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in set new app: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// FIXME - shouldn't return everything :)
	// Used for searching
	returnData := fmt.Sprintf(`{"success": true, "reason": []}`)
	resp.WriteHeader(200)
	resp.Write([]byte(returnData))
	return

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Error with body read: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	type tmpStruct struct {
		Search string `json:"search"`
	}

	var tmpBody tmpStruct
	err = json.Unmarshal(body, &tmpBody)
	if err != nil {
		log.Printf("[WARNING] Error with unmarshal tmpBody specific apps: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// FIXME - continue the search here with github repos etc.
	// Caching might be smart :D
	ctx := getContext(request)
	workflowapps, err := GetPrioritizedApps(ctx, user)
	if err != nil {
		log.Printf("[WARNING] Error: Failed getting workflowapps: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	returnValues := []WorkflowApp{}
	search := strings.ToLower(tmpBody.Search)
	for _, app := range workflowapps {
		if !app.Activated && app.Generated {
			// This might be heavy with A LOT
			// Not too worried with todays tech tbh..
			appName := strings.ToLower(app.Name)
			appDesc := strings.ToLower(app.Description)
			if strings.Contains(appName, search) || strings.Contains(appDesc, search) {
				//log.Printf("Name: %s, Generated: %s, Activated: %s", app.Name, strconv.FormatBool(app.Generated), strconv.FormatBool(app.Activated))
				returnValues = append(returnValues, app)
			}
		}
	}

	newbody, err := json.Marshal(returnValues)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking workflow executions"}`)))
		return
	}

	returnData = fmt.Sprintf(`{"success": true, "reason": %s}`, string(newbody))
	resp.WriteHeader(200)
	resp.Write([]byte(returnData))
}

func GetAppAuthentication(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("[WARNING] Api authentication failed in get all apps: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// FIXME: Auth to get the right ones only
	//if user.Role != "admin" {
	//	log.Printf("User isn't admin")
	//	resp.WriteHeader(401)
	//	resp.Write([]byte(`{"success": false}`))
	//	return
	//}
	ctx := getContext(request)
	allAuths, err := GetAllWorkflowAppAuth(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get all app auth: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(allAuths) == 0 {
		resp.WriteHeader(200)
		resp.Write([]byte(`{"success": true, "data": []}`))
		return
	}

	//for _, env := range allworkflowappAuths {
	//	for _, param := range env.Fields {
	//		log.Printf("ENV: %#v", param)
	//	}
	//}

	// Cleanup for frontend
	newAuth := []AppAuthenticationStorage{}
	for _, auth := range allAuths {
		newAuthField := auth
		for index, _ := range auth.Fields {
			newAuthField.Fields[index].Value = "Secret. Replaced during app execution!"
		}

		newAuth = append(newAuth, newAuthField)
	}

	type returnStruct struct {
		Success bool                       `json:"success"`
		Data    []AppAuthenticationStorage `json:"data"`
	}

	allAuth := returnStruct{
		Success: true,
		Data:    allAuths,
	}

	newbody, err := json.Marshal(allAuth)
	if err != nil {
		log.Printf("Failed unmarshalling all app auths: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking workflow app auth"}`)))
		return
	}

	//data := fmt.Sprintf(`{"success": true, "data": %s}`, string(newbody))

	resp.WriteHeader(200)
	resp.Write([]byte(newbody))
}

func RunOauth2Request(ctx context.Context, user User, appAuth AppAuthenticationStorage, refresh bool) (AppAuthenticationStorage, error) {

	//transport := http.DefaultTransport.(*http.Transport).Clone()
	transport := http.DefaultTransport.(*http.Transport)
	transport.MaxIdleConnsPerHost = 100
	transport.ResponseHeaderTimeout = time.Second * 10
	transport.Proxy = nil
	client := &http.Client{
		Transport: transport,
	}

	requestData := DataToSend{
		GrantType: "authorization_code",
	}

	url := ""
	oauthUrl := ""
	refreshUrl := ""
	refreshToken := ""
	for _, field := range appAuth.Fields {
		if field.Key == "authentication_url" {
			log.Printf("[DEBUG] Make request to %s for Oauth2. User: %s (%s)", field.Value, user.Username, user.Id)
			url = field.Value
		}

		if field.Key == "code" {
			requestData.Code = field.Value
		}

		if field.Key == "client_secret" {
			requestData.ClientSecret = field.Value
		}

		if field.Key == "client_id" {
			requestData.ClientId = field.Value
		}

		if field.Key == "scope" {
			requestData.Scope = field.Value
		}

		if field.Key == "redirect_uri" {
			requestData.RedirectUri = field.Value
		}

		if field.Key == "refresh_uri" || field.Key == "refresh_url" {
			//log.Printf("[DEBUG] Got refresh URL %s", field.Value)
			refreshUrl = field.Value
		}

		if field.Key == "refresh_token" {
			//log.Printf("[DEBUG] Got refresh token %s", field.Value)
			refreshToken = field.Value
		}

		if field.Key == "oauth_url" {
			//log.Printf("[DEBUG] Got Oauth2 URL %s", field.Value)
			oauthUrl = field.Value
		}
	}

	if len(url) == 0 {
		return appAuth, errors.New("No authentication URL provided in Oauth2 request")
	}

	v, err := query.Values(requestData)
	if err != nil {
		return appAuth, err
	}

	respBody := []byte{}
	if !refresh {
		req, err := http.NewRequest(
			"POST",
			url,
			bytes.NewBuffer([]byte(v.Encode())),
		)

		if err != nil {
			return appAuth, err
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		newresp, err := client.Do(req)
		if err != nil {
			return appAuth, err
		}

		//log.Printf("Data: %#v", newresp)
		//log.Printf("Data: %d", newresp.StatusCode)

		body, err := ioutil.ReadAll(newresp.Body)
		if err != nil {
			return appAuth, err
		}
		respBody = body

		if newresp.StatusCode >= 300 {
			return appAuth, errors.New(fmt.Sprintf("Bad status code: %d. Message: %s", newresp.StatusCode, respBody))
		}
	} else {
		// bytes.NewBuffer([]byte(v.Encode())),
		requestRefreshUrl := fmt.Sprintf("%s?grant_type=refresh_token&refresh_token=%s&scope=%s&client_id=%s&client_secret=%s", refreshUrl, refreshToken, requestData.Scope, requestData.ClientId, requestData.ClientSecret)
		//log.Printf("[DEBUG] Making refresh request to %s", requestRefreshUrl)
		req, err := http.NewRequest(
			"POST",
			requestRefreshUrl,
			nil,
		)

		if err != nil {
			return appAuth, err
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		newresp, err := client.Do(req)
		if err != nil {
			return appAuth, err
		}

		//log.Printf("Data: %#v", newresp)
		//log.Printf("Data: %d", newresp.StatusCode)

		body, err := ioutil.ReadAll(newresp.Body)
		if err != nil {
			return appAuth, err
		}

		respBody = body

		if newresp.StatusCode >= 300 {
			return appAuth, errors.New(fmt.Sprintf("Bad status code in refresh: %d. Message: %s", newresp.StatusCode, respBody))
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

	//log.Printf("\n\nRESPONSE: %s\n\n", string(respBody))
	var oauthResp Oauth2Resp
	err = json.Unmarshal(respBody, &oauthResp)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling (appauth oauth2): %s", err)
		return appAuth, err
	}

	if len(oauthResp.AccessToken) > 0 {
		appAuth.Fields = append(appAuth.Fields, AuthenticationStore{
			Key:   "access_token",
			Value: oauthResp.AccessToken,
		})
	}

	if len(oauthResp.RefreshToken) > 0 {
		appAuth.Fields = append(appAuth.Fields, AuthenticationStore{
			Key:   "refresh_token",
			Value: oauthResp.RefreshToken,
		})
	}

	if len(oauthUrl) > 0 {
		log.Printf("[DEBUG] Appending Oauth2 API URL %s", oauthUrl)

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
	} else {
		log.Printf("[DEBUG] No app API URL to attach to Oauth2 auth?")
	}

	// FIXME: Does this work with string?
	//https://stackoverflow.com/questions/43870554/microsoft-oauth2-authentication-not-returning-refresh-token
	parsedTime := strconv.FormatInt(int64(time.Now().Unix())+int64(oauthResp.ExpiresIn), 10)
	appAuth.Fields = append(appAuth.Fields, AuthenticationStore{
		Key:   "expiration",
		Value: parsedTime,
	})

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
	err = SetWorkflowAppAuthDatastore(ctx, appAuth, appAuth.Id)
	if err != nil {
		log.Printf("[WARNING] Failed setting up app auth %s: %s (oauth2)", appAuth.Id, err)
		return appAuth, err
	}

	//log.Printf("%#v", oauthResp)
	return appAuth, nil
}

func AddAppAuthentication(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("[WARNING] Api authentication failed in add app auth: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to set new workflowapp: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	log.Printf("[AUDIT] Setting new authentication for user %s (%s)", user.Username, user.Id)

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Error with body read in new app auth: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	var appAuth AppAuthenticationStorage
	err = json.Unmarshal(body, &appAuth)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling (appauth): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := getContext(request)
	if len(appAuth.Id) == 0 {
		appAuth.Id = uuid.NewV4().String()
	} else {
		auth, err := GetWorkflowAppAuthDatastore(ctx, appAuth.Id)
		if err == nil {
			// OrgId         string                `json:"org_id" datastore:"org_id"`
			if auth.OrgId != user.ActiveOrg.Id {
				log.Printf("[WARNING] User isn't a part of the right org during auth edit")
				resp.WriteHeader(409)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": ":("}`)))
				return
			}

			if user.Role != "admin" {
				log.Printf("[AUDIT] User isn't admin during auth edit")
				resp.WriteHeader(409)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": ":("}`)))
				return
			}

			if !auth.Active {
				log.Printf("[WARNING] Auth isn't active for edit")
				resp.WriteHeader(409)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't update an inactive auth"}`)))
				return
			}

			if auth.App.Name != appAuth.App.Name {
				log.Printf("[WARNING] User tried to modify auth")
				resp.WriteHeader(409)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Bad app configuration: need to specify correct name"}`)))
				return
			}

			// Setting this to ensure that any new config is encrypted anew
			auth.Encrypted = false
		}
	}

	if len(appAuth.Label) == 0 {
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Label can't be empty"}`)))
		return
	}

	// Super basic check
	if len(appAuth.App.ID) != 36 && len(appAuth.App.ID) != 32 {
		log.Printf("[WARNING] Bad ID for app: %s", appAuth.App.ID)
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "App has to be defined"}`)))
		return
	}

	app, err := GetApp(ctx, appAuth.App.ID, user, false)
	if err != nil {
		log.Printf("[DEBUG] Failed finding app %s (%s) while setting auth. Finding it by looping apps.", appAuth.App.Name, appAuth.App.ID)
		workflowapps, err := GetPrioritizedApps(ctx, user)
		if err != nil {
			resp.WriteHeader(409)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
			return
		}

		foundIndex := -1
		for i, workflowapp := range workflowapps {
			if workflowapp.Name == appAuth.App.Name {
				foundIndex = i
				break
			}
		}

		if foundIndex >= 0 {
			log.Printf("[INFO] Found app %s (%s) by looping auth with %d parameters", workflowapps[foundIndex].Name, workflowapps[foundIndex].ID, len(workflowapps[foundIndex].Authentication.Parameters))
			app = &workflowapps[foundIndex]
			//appAuth.App.Name, appAuth.App.ID, len(appAuth.Fields)))
		} else {
			log.Printf("[ERROR] Failed finding app %s which has auth after looping", appAuth.App.ID)
			resp.WriteHeader(409)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed finding app %s (%s)"}`, appAuth.App.Name, appAuth.App.ID)))
			return
		}
	} else {
		org, err := GetOrg(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("[WARNING] Failed getting org %s during app auth: %s", user.ActiveOrg.Id, err)
		} else {
			if !ArrayContains(org.ActiveApps, app.ID) {
				org.ActiveApps = append(org.ActiveApps, app.ID)
				err = SetOrg(ctx, *org, org.Id)
				if err != nil {
					log.Printf("[WARNING] Failed setting app %s for org %s during appauth", org.Id)
				} else {
					cacheKey := fmt.Sprintf("apps_%s", user.Id)
					DeleteCache(ctx, cacheKey)
				}
			} else {
				log.Printf("[INFO] Org %s already has app %s active.", user.ActiveOrg.Id, app.ID)
			}
		}
	}

	//log.Printf("[INFO] TYPE: %s", appAuth.Type)
	if appAuth.Type == "oauth2" {
		log.Printf("[DEBUG] OAUTH2 for workflow %s. User: %s (%s)", appAuth.ReferenceWorkflow, user.Username, user.Id)
		workflow, err := GetWorkflow(ctx, appAuth.ReferenceWorkflow)
		if err != nil {
			log.Printf("[WARNING] WorkflowId %s doesn't exist (set oauth2)", appAuth.ReferenceWorkflow)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		if user.Id != workflow.Owner || len(user.Id) == 0 {
			if workflow.OrgId == user.ActiveOrg.Id && user.Role == "admin" {
				log.Printf("[AUDIT] User %s is accessing workflow %s as admin (set oauth2)", user.Username, workflow.ID)
			} else if workflow.Public {
				log.Printf("[AUDIT] Letting user %s access workflow %s FOR AUTH because it's public", user.Username, workflow.ID)
			} else {
				log.Printf("[AUDIT] Wrong user (%s) for workflow %s (set oauth2)", user.Username, workflow.ID)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false}`))
				return
			}
		}

		// Finding count in same workflow & setting large image if missing
		count := 0
		for _, action := range workflow.Actions {
			if action.AppName == appAuth.App.Name {
				count += 1

				if len(appAuth.App.LargeImage) == 0 && len(action.LargeImage) > 0 {
					appAuth.App.LargeImage = action.LargeImage
				}

			}
		}

		appAuth.NodeCount = int64(count)
		appAuth.WorkflowCount = 1

		_, err = RunOauth2Request(ctx, user, appAuth, false)
		if err != nil {
			log.Printf("[WARNING] Failed oauth2 request: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed authorization: %s"}`, err)))
			return
		}

		resp.WriteHeader(200)
		resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Successfully set up authentication", "id": "%s"}`, appAuth.Id)))
		return
	}

	// Check if the items are correct
	for _, field := range appAuth.Fields {
		found := false
		for _, param := range app.Authentication.Parameters {
			//log.Printf("Fields: %#v - %s", field, param.Name)
			if field.Key == param.Name {
				found = true
			}
		}

		if !found {
			log.Printf("[WARNING] Failed finding field %s in appauth fields for %s", field.Key, appAuth.App.Name)
			resp.WriteHeader(409)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "All auth fields required"}`)))
			return
		}
	}

	// FIXME: encryption
	//for _, param := range appAuth.Fields {
	//}

	//appAuth.LargeImage = ""
	appAuth.OrgId = user.ActiveOrg.Id
	appAuth.Defined = true
	err = SetWorkflowAppAuthDatastore(ctx, appAuth, appAuth.Id)
	if err != nil {
		log.Printf("[WARNING] Failed setting up app auth %s: %s", appAuth.Id, err)
		resp.WriteHeader(409)

		resultData := ResultChecker{
			Success: false,
			Reason:  fmt.Sprintf("%s", err),
		}

		newjson, err := json.Marshal(resultData)
		if err != nil {
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
		} else {
			resp.Write(newjson)
		}

		return
	}

	log.Printf("[INFO] Set new workflow auth for %s (%s) with ID %s", app.Name, app.ID, appAuth.Id)
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "id": "%s"}`, appAuth.Id)))
}

func DeleteAppAuthentication(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("[WARNING] Api authentication failed in delete app auth: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role != "admin" {
		log.Printf("[WARNING] Need to be admin to delete appauth")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")
	var fileId string
	if location[1] == "api" {
		if len(location) <= 5 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[5]
	}

	ctx := getContext(request)
	nameKey := "workflowappauth"
	auth, err := GetWorkflowAppAuthDatastore(ctx, fileId)
	if err != nil {
		// Deleting cache here, as it seems to be a constant issue
		cacheKey := fmt.Sprintf("%s_%s", nameKey, user.ActiveOrg.Id)
		DeleteCache(ctx, cacheKey)

		log.Printf("[WARNING] Authget error (DELETE): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": ":("}`))
		return
	}

	if auth.OrgId != user.ActiveOrg.Id {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "User can't edit this org"}`))
		return
	}

	// FIXME: Set affected workflows to have errors
	// 1. Get the auth
	// 2. Loop the workflows (.Usage) and set them to have errors
	// 3. Loop the nodes in workflows and do the same
	err = DeleteKey(ctx, nameKey, fileId)
	if err != nil {
		log.Printf("Failed deleting workflowapp")
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed deleting workflow app"}`)))
		return
	}

	cacheKey := fmt.Sprintf("%s_%s", nameKey, user.ActiveOrg.Id)
	DeleteCache(ctx, cacheKey)
	cacheKey = fmt.Sprintf("%s_%s", nameKey, fileId)
	DeleteCache(ctx, cacheKey)

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

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

	ctx := getContext(request)
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
		log.Printf("Failed unmarshaling: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to unmarshal data"}`)))
		return
	}

	if len(newEnvironments) < 1 {
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "One environment is required"}`)))
		return
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

		if defaults > 0 {
			env.Default = false
		}

		if env.Default {
			defaults += 1
		}

		parsedEnvs = append(parsedEnvs, env)
	}

	newEnvironments = parsedEnvs

	// Clear old data? Removed for archiving purpose. No straight deletion
	log.Printf("[INFO] Deleting %d environments before resetting!", len(environments))
	nameKey := "Environments"
	for _, item := range environments {
		DeleteKey(ctx, nameKey, item.Id)
		DeleteKey(ctx, nameKey, item.Name)
	}

	openEnvironments := 0
	for _, item := range newEnvironments {
		if !item.Archived {
			openEnvironments += 1
		}
	}

	if openEnvironments < 1 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't archive all environments"}`))
		return
	}

	for _, item := range newEnvironments {
		if item.OrgId != user.ActiveOrg.Id {
			item.OrgId = user.ActiveOrg.Id
		}

		if len(item.Id) == 0 {
			item.Id = uuid.NewV4().String()
		}

		err = SetEnvironment(ctx, &item)
		if err != nil {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed setting environment variable"}`))
			return
		}
	}

	log.Printf("[INFO] Set %d new environments for org %s", len(newEnvironments), user.ActiveOrg.Id)

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleRerunExecutions(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in stop executions: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")
	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	if user.Role != "admin" {
		log.Printf("[AUDIT] User isn't admin during stop executions")
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Must be admin to perform this action"}`)))
		return
	}

	ctx := getContext(request)
	//env, err := GetEnvironment(ctx, fileId, user.ActiveOrg.Id)
	//if err != nil {
	//	log.Printf("[WARNING] Failed to get environment %s for org %s", fileId, user.ActiveOrg.Id)
	//	resp.WriteHeader(401)
	//	resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to get environment %s"}`, fileId)))
	//	return
	//}

	//log.Printf("%#v", env)
	//if env.OrgId != user.ActiveOrg.Id {
	//	log.Printf("[WARNING] %s (%s) doesn't have permission to stop all executions for environment %s", user.Username, user.Id, fileId)
	//	resp.WriteHeader(401)
	//	resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "You don't have permission to stop environment executions for ID %s"}`, fileId)))
	//	return
	//}

	// 1: Loop all workflows
	// 2: Stop all running executions (manually abort)
	workflows, err := GetAllWorkflowsByQuery(ctx, user)
	if err != nil {
		log.Printf("[WARNING] Failed getting workflows for user %s (0): %s", user.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	total := 0
	for _, workflow := range workflows {
		if workflow.OrgId != user.ActiveOrg.Id {
			//log.Printf("[DEBUG] Skipping workflow for org %s (user: %s)", workflow.OrgId, user.Username)
			continue
		}

		cnt, _ := RerunExecution(ctx, fileId, workflow)
		total += cnt
	}

	log.Printf("[DEBUG] Stopped %d executions in total for environment %s for org %s", total, fileId, user.ActiveOrg.Id)
	resp.WriteHeader(200)
	//resp.Write(newjson)
}

// Send in deleteall=true to delete ALL executions for the environment ID
func HandleStopExecutions(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in stop executions: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")
	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
		if strings.Contains(fileId, "?") {
			fileId = strings.Split(fileId, "?")[0]
		}
	}

	if user.Role != "admin" {
		log.Printf("[AUDIT] User isn't admin during stop executions")
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Must be admin to perform this action"}`)))
		return
	}

	ctx := getContext(request)
	cleanAll := false
	deleteAll, ok := request.URL.Query()["deleteall"]
	if ok {
		if deleteAll[0] == "true" {
			cleanAll = true

			if project.Environment != "cloud" {
				log.Printf("[DEBUG] Deleting and aborting ALL executions for this environment and org %s!", user.ActiveOrg.Id)

				env, err := GetEnvironment(ctx, fileId, user.ActiveOrg.Id)
				if err != nil {
					log.Printf("[WARNING] Failed to get environment %s for org %s", fileId, user.ActiveOrg.Id)
					resp.WriteHeader(401)
					resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to get environment %s"}`, fileId)))
					return
				}

				if env.OrgId != user.ActiveOrg.Id {
					log.Printf("[WARNING] %s (%s) doesn't have permission to stop all executions for environment %s", user.Username, user.Id, fileId)
					resp.WriteHeader(401)
					resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "You don't have permission to stop environment executions for ID %s"}`, fileId)))
					return
				}

				// If here, it should DEFINITELY clean up all executions
				// Runs on 10.000 workflows max
				maxAmount := 1000
				for i := 0; i < 10; i++ {
					executionRequests, err := GetWorkflowQueue(ctx, env.Name, maxAmount)
					if err != nil {
						log.Printf("[WARNING] Jumping out of workflowqueue delete handler: %s", err)
						break
					}

					if len(executionRequests.Data) == 0 {
						break
					}

					ids := []string{}
					for _, execution := range executionRequests.Data {
						if !ArrayContains(execution.Environments, env.Name) {
							continue
						}

						ids = append(ids, execution.ExecutionId)
					}

					parsedId := fmt.Sprintf("workflowqueue-%s", strings.ToLower(env.Name))
					err = DeleteKeys(ctx, parsedId, ids)
					if err != nil {
						log.Printf("[ERROR] Failed deleting %d execution keys for org %s during force stop: %s", len(ids), env.Name, err)
					} else {
						log.Printf("[INFO] Deleted %d keys from org %s during force stop", len(ids), parsedId)
					}

					if len(executionRequests.Data) != maxAmount {
						log.Printf("[DEBUG] Less than 1000 in queue. Not querying more")
						break
					}
				}
			}
		}
	}

	// 1: Loop all workflows
	// 2: Stop all running executions (manually abort)
	workflows, err := GetAllWorkflowsByQuery(ctx, user)
	if err != nil {
		log.Printf("[WARNING] Failed getting workflows for user %s (0): %s", user.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	total := 0
	for _, workflow := range workflows {
		if workflow.OrgId != user.ActiveOrg.Id {
			//log.Printf("[DEBUG] Skipping workflow for org %s (user: %s)", workflow.OrgId, user.Username)
			continue
		}

		cnt, _ := CleanupExecutions(ctx, fileId, workflow, cleanAll)
		total += cnt
	}

	if total > 0 {
		log.Printf("[DEBUG] Stopped %d executions in total for environment %s for org %s", total, fileId, user.ActiveOrg.Id)
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Successfully deleted and stopped %d executions"}`, total)))
}

func RerunExecution(ctx context.Context, environment string, workflow Workflow) (int, error) {
	executions, err := GetUnfinishedExecutions(ctx, workflow.ID)
	if err != nil {
		log.Printf("[DEBUG] Failed getting executions for workflow %s", workflow.ID)
		return 0, err
	}

	if len(executions) == 0 {
		return 0, nil
	}

	//log.Printf("[DEBUG] Found %d POTENTIALLY unfinished executions for workflow %s (%s) with environment %s that are more than 30 minutes old", len(executions), workflow.Name, workflow.ID, environment)
	//log.Printf("[DEBUG] Found %d unfinished executions for workflow %s (%s) with environment %s that are more than 30 minutes old", len(executions), workflow.Name, workflow.ID, environment)

	backendUrl := os.Getenv("BASE_URL")
	if project.Environment == "cloud" {
		backendUrl = "https://shuffler.io"
	} else {
		backendUrl = "http://127.0.0.1:5001"
	}

	topClient := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}

	//StartedAt           int64          `json:"started_at" datastore:"started_at"`
	timeNow := int64(time.Now().Unix())
	cnt := 0
	for _, execution := range executions {
		if timeNow < execution.StartedAt+1800 {
			//log.Printf("Bad timing: %d", execution.StartedAt)
			continue
		}

		if execution.Status != "EXECUTING" {
			//log.Printf("Bad status: %s", execution.Status)
			continue
		}

		found := false
		environments := []string{}
		for _, action := range execution.Workflow.Actions {
			if action.Environment == environment {
				environments = append(environments, action.Environment)
				found = true
				break
			}
		}

		if len(environments) == 0 {
			found = true
		}

		if !found {
			continue
		}

		//log.Printf("[DEBUG] Got execution with status %s!", execution.Status)
		streamUrl := fmt.Sprintf("%s/api/v1/workflows/%s/executions/%s/abort", backendUrl, execution.Workflow.ID, execution.ExecutionId)
		/*
			data = {
				"start": execution.Start,
				"execution_argument": execution.ExecutionArgument,
			}
		*/
		resultData := ""
		req, err := http.NewRequest(
			"GET",
			streamUrl,
			bytes.NewBuffer([]byte(resultData)),
		)

		if err != nil {
			log.Printf("[ERROR] Error in auto-abort request: %s", err)
			continue
		}

		req.Header.Add("Authorization", fmt.Sprintf(`Bearer %s`, execution.Authorization))
		newresp, err := topClient.Do(req)
		if err != nil {
			log.Printf("[ERROR] Error auto-running workflow: %s", err)
			continue
		}

		body, err := ioutil.ReadAll(newresp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed reading parent body (rerun exec): %s", err)
			continue
		}
		//log.Printf("BODY (%d): %s", newresp.StatusCode, string(body))

		if newresp.StatusCode != 200 {
			log.Printf("[ERROR] Bad statuscode in rerun exec: %d, %s", newresp.StatusCode, string(body))
			continue
		}

		cnt += 1
		log.Printf("[DEBUG] Result from rerunning %s: %s", execution.ExecutionId, string(body))
	}

	return cnt, nil
}

func CleanupExecutions(ctx context.Context, environment string, workflow Workflow, cleanAll bool) (int, error) {
	executions, err := GetUnfinishedExecutions(ctx, workflow.ID)
	if err != nil {
		log.Printf("[DEBUG] Failed getting executions for workflow %s", workflow.ID)
		return 0, err
	}

	if len(executions) == 0 {
		return 0, nil
	}

	//log.Printf("[DEBUG] Found %d POTENTIALLY unfinished executions for workflow %s (%s) with environment %s that are more than 30 minutes old", len(executions), workflow.Name, workflow.ID, environment)
	//log.Printf("[DEBUG] Found %d unfinished executions for workflow %s (%s) with environment %s that are more than 30 minutes old", len(executions), workflow.Name, workflow.ID, environment)

	backendUrl := os.Getenv("BASE_URL")
	// Redundant, but working ;)
	if project.Environment == "cloud" {
		backendUrl = "https://shuffler.io"
	} else {
		backendUrl = "http://127.0.0.1:5001"
	}

	topClient := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}

	//StartedAt           int64          `json:"started_at" datastore:"started_at"`
	timeNow := int64(time.Now().Unix())
	cnt := 0
	for _, execution := range executions {
		if cleanAll {
		} else if timeNow < execution.StartedAt+1800 {
			//log.Printf("Bad timing: %d", execution.StartedAt)
			continue
		}

		if execution.Status != "EXECUTING" {
			//log.Printf("Bad status: %s", execution.Status)
			continue
		}

		found := false
		environments := []string{}
		for _, action := range execution.Workflow.Actions {
			if action.Environment == environment {
				environments = append(environments, action.Environment)
				found = true
				break
			}
		}

		if len(environments) == 0 {
			found = true
		}

		if !found {
			continue
		}

		//log.Printf("[DEBUG] Got execution with status %s!", execution.Status)

		streamUrl := fmt.Sprintf("%s/api/v1/workflows/%s/executions/%s/abort?reason=%s", backendUrl, execution.Workflow.ID, execution.ExecutionId, url.QueryEscape("Cleanup-crew stopped this execution"))
		//log.Printf("Url: %s", streamUrl)
		req, err := http.NewRequest(
			"GET",
			streamUrl,
			nil,
		)

		if err != nil {
			log.Printf("[ERROR] Error in auto-abort request: %s", err)
			continue
		}

		req.Header.Add("Authorization", fmt.Sprintf(`Bearer %s`, execution.Authorization))
		newresp, err := topClient.Do(req)
		if err != nil {
			log.Printf("[ERROR] Error auto-aborting workflow: %s", err)
			continue
		}

		body, err := ioutil.ReadAll(newresp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed reading parent body: %s", err)
			continue
		}
		//log.Printf("BODY (%d): %s", newresp.StatusCode, string(body))

		if newresp.StatusCode != 200 {
			log.Printf("[ERROR] Bad statuscode in auto-abort: %d, %s", newresp.StatusCode, string(body))
			continue
		}

		cnt += 1
		log.Printf("[DEBUG] Result from aborting %s: %s", execution.ExecutionId, string(body))
	}

	return cnt, nil
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

	ctx := getContext(request)
	environments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Failed getting environments")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't get environments"}`))
		return
	}

	newEnvironments := []Environment{}
	for _, environment := range environments {
		if len(environment.Id) == 0 {
			environment.Id = uuid.NewV4().String()
		}

		newEnvironments = append(newEnvironments, environment)
		//if environment.Default {
		//	break
		//}
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

func HandleApiAuthentication(resp http.ResponseWriter, request *http.Request) (User, error) {
	apikey := request.Header.Get("Authorization")

	user := &User{}
	if len(apikey) > 0 {
		if !strings.HasPrefix(apikey, "Bearer ") {
			log.Printf("[WARNING] Apikey doesn't start with bearer")
			return User{}, errors.New("No bearer token for authorization header")
		}

		apikeyCheck := strings.Split(apikey, " ")
		if len(apikeyCheck) != 2 {
			log.Printf("[WARNING] Invalid format for apikey.")
			return User{}, errors.New("Invalid format for apikey")
		}

		// fml
		//log.Println(apikeyCheck)

		// This is annoying af
		newApikey := apikeyCheck[1]
		if len(newApikey) > 249 {
			newApikey = newApikey[0:248]
		}

		ctx := getContext(request)
		cache, err := GetCache(ctx, newApikey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &user)
			if err == nil {
				//log.Printf("[WARNING] Got user from cache: %s", err)

				if len(user.Id) == 0 && len(user.Username) == 0 {
					return User{}, errors.New(fmt.Sprintf("Couldn't find user"))
				}

				return *user, nil
			}
		} else {
			//log.Printf("[WARNING] Error getting authentication cache for %s: %v", newApikey, err)
		}

		// Make specific check for just service user?
		// Get the user based on APIkey here
		//log.Println(apikeyCheck[1])
		userdata, err := GetApikey(ctx, apikeyCheck[1])
		if err != nil {
			log.Printf("[WARNING] Apikey %s doesn't exist: %s", apikey, err)
			return User{}, err
		}

		if len(userdata.Id) == 0 && len(userdata.Username) == 0 {
			log.Printf("[WARNING] Apikey %s doesn't exist or the user doesn't have an ID/Username", apikey)
			return User{}, errors.New("Couldn't find the user")
		}

		// Caching both bad and good apikeys :)
		b, err := json.Marshal(userdata)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling: %s", err)
			return User{}, err
		}

		err = SetCache(ctx, newApikey, b)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for apikey: %s", err)
		}

		return userdata, nil
	}

	// One time API keys
	authorizationArr, ok := request.URL.Query()["authorization"]
	ctx := getContext(request)
	if ok {
		authorization := ""
		if len(authorizationArr) > 0 {
			authorization = authorizationArr[0]
		}
		_ = authorization
		log.Printf("[ERROR] WHAT ARE ONE TIME KEYS USED FOR?")
	}

	c, err := request.Cookie("session_token")
	if err == nil {
		sessionToken := c.Value
		session, err := GetSession(ctx, sessionToken)
		if err != nil {
			http.SetCookie(resp, &http.Cookie{
				Name:    "session_token",
				Value:   sessionToken,
				Expires: time.Now().Add(-100 * time.Hour),
				MaxAge:  -1,
			})

			return User{}, err
		}

		user, err := GetUser(ctx, session.UserId)
		if err != nil {
			log.Printf("[INFO] User with Identifier %s doesn't exist: %s", session.UserId, err)
			http.SetCookie(resp, &http.Cookie{
				Name:    "session_token",
				Value:   sessionToken,
				Expires: time.Now().Add(-100 * time.Hour),
				MaxAge:  -1,
			})

			return User{}, err
		}

		if len(user.Id) == 0 && len(user.Username) == 0 {
			http.SetCookie(resp, &http.Cookie{
				Name:    "session_token",
				Value:   sessionToken,
				Expires: time.Now().Add(-100 * time.Hour),
				MaxAge:  -1,
			})

			return User{}, errors.New(fmt.Sprintf("Couldn't find user"))
		}

		// We're using the session to find the user anyway, which is NOT user controlled
		// This means that this is redundant, but MAY allow users
		// to have access past session timeouts
		//if user.Session != sessionToken {
		//	return User{}, errors.New("[WARNING] Wrong session token")
		//}

		// Means session exists, but
		return *user, nil
	}

	// Key = apikey
	return User{}, errors.New("Missing authentication")
}

func GetOpenapi(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just here to verify that the user is logged in
	_, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("Api authentication failed in validate swagger: %s", err)
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
	ctx := getContext(request)
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

func GetResult(workflowExecution WorkflowExecution, id string) ActionResult {
	for _, actionResult := range workflowExecution.Results {
		if actionResult.Action.ID == id {
			return actionResult
		}
	}

	return ActionResult{}
}

func GetAction(workflowExecution WorkflowExecution, id, environment string) Action {
	for _, action := range workflowExecution.Workflow.Actions {
		if action.ID == id {
			return action
		}
	}

	for _, trigger := range workflowExecution.Workflow.Triggers {
		if trigger.ID == id {
			return Action{
				ID:          trigger.ID,
				AppName:     trigger.AppName,
				Name:        trigger.AppName,
				Environment: environment,
				Label:       trigger.Label,
			}
			log.Printf("FOUND TRIGGER: %#v!", trigger)
		}
	}

	return Action{}
}

func ArrayContains(visited []string, id string) bool {
	found := false
	for _, item := range visited {
		if item == id {
			found = true
		}
	}

	return found
}

func GetWorkflowExecutions(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in getting workflow executions: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")

	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	if len(fileId) != 36 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID when getting workflow executions is not valid"}`))
		return
	}

	ctx := getContext(request)
	workflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Failed getting the workflow %s locally (get executions): %s", fileId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// FIXME - have a check for org etc too..
	if user.Id != workflow.Owner || len(user.Id) == 0 {
		if workflow.OrgId == user.ActiveOrg.Id && (user.Role == "admin" || user.Role == "org-reader") {
			log.Printf("[AUDIT] User %s is accessing %s executions as %s (get executions)", user.Username, workflow.ID, user.Role)
		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (get workflow)", user.Username, workflow.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	// Query for the specifci workflowId
	//q := datastore.NewQuery("workflowexecution").Filter("workflow_id =", fileId).Order("-started_at").Limit(30)
	//q := datastore.NewQuery("workflowexecution").Filter("workflow_id =", fileId)
	workflowExecutions, err := GetAllWorkflowExecutions(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Failed getting executions for %s", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	//log.Printf("[DEBUG] Got %d executions", len(workflowExecutions))

	if len(workflowExecutions) == 0 {
		resp.WriteHeader(200)
		resp.Write([]byte("[]"))
		return
	}

	for index, execution := range workflowExecutions {
		newResults := []ActionResult{}
		for _, result := range execution.Results {
			newParams := []WorkflowAppActionParameter{}
			for _, param := range result.Action.Parameters {
				//log.Printf("PARAM: %#v", param)
				if param.Configuration || strings.Contains(strings.ToLower(param.Name), "user") || strings.Contains(strings.ToLower(param.Name), "key") || strings.Contains(strings.ToLower(param.Name), "pass") {
					param.Value = ""
					//log.Printf("FOUND CONFIG: %s!!", param.Name)
				}

				newParams = append(newParams, param)
			}

			result.Action.Parameters = newParams
			newResults = append(newResults, result)
		}

		workflowExecutions[index].Results = newResults
	}

	newjson, err := json.Marshal(workflowExecutions)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking workflow executions"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func GetWorkflows(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in getworkflows: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := getContext(request)
	var workflows []Workflow

	cacheKey := fmt.Sprintf("%s_workflows", user.Id)
	cache, err := GetCache(ctx, cacheKey)
	if err == nil {
		cacheData := []byte(cache.([]uint8))
		err = json.Unmarshal(cacheData, &workflows)
		if err == nil {
			resp.WriteHeader(200)
			resp.Write(cacheData)
			return
		}
	} else {
		//log.Printf("[INFO] Failed getting cache for workflows for user %s", user.Id)
	}

	workflows, err = GetAllWorkflowsByQuery(ctx, user)
	if err != nil {
		log.Printf("[WARNING] Failed getting workflows for user %s (0): %s", user.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(workflows) == 0 {
		log.Printf("[INFO] No workflows found for user %s", user.Username)
		resp.WriteHeader(200)
		resp.Write([]byte("[]"))
		return
	}

	newWorkflows := []Workflow{}
	for _, workflow := range workflows {
		if workflow.OrgId != user.ActiveOrg.Id {
			//log.Printf("[DEBUG] Skipping workflow for org %s (user: %s)", workflow.OrgId, user.Username)
			continue
		}

		newActions := []Action{}
		for _, action := range workflow.Actions {
			//log.Printf("Image: %s", action.LargeImage)
			// Removed because of exports. These are needed there.
			//action.LargeImage = ""
			//action.SmallImage = ""
			newActions = append(newActions, action)
		}

		workflow.Actions = newActions

		// Skipping these as they're related to onprem workflows in cloud
		//log.Printf("ENVIRONMENT: %s", workflow.ExecutionEnvironment)
		if project.Environment == "cloud" && workflow.ExecutionEnvironment == "onprem" {
			continue
		}

		newWorkflows = append(newWorkflows, workflow)
	}

	//log.Printf("[INFO] Returning %d workflows", len(newWorkflows))
	newjson, err := json.Marshal(newWorkflows)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking workflows"}`)))
		return
	}

	if project.CacheDb {
		err = SetCache(ctx, cacheKey, newjson)
		if err != nil {
			log.Printf("[WARNING] Failed updating workflow cache: %s", err)
		}
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

/*
func DeleteWorkflows(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("Api authentication failed in deleting workflow: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")

	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	if len(fileId) != 36 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID to delete is not valid"}`))
		return
	}

	ctx := getContext(request)
	workflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("Failed getting the workflow locally: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// FIXME - have a check for org etc too..
	if user.Id != workflow.Owner || len(user.Id) == 0 {
		if workflow.OrgId == user.ActiveOrg.Id && user.Role == "admin" {
			log.Printf("[INFO] User %s is accessing %s executions as admin", user.Username, workflow.ID)
		} else {
		log.Printf("Wrong user (%s) for workflow %s", user.Username, workflow.ID)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
		}
	}

	// Clean up triggers and executions
	for _, item := range workflow.Triggers {
		if item.TriggerType == "SCHEDULE" {
			err = deleteSchedule(ctx, item.ID)
			if err != nil {
				log.Printf("Failed to delete schedule: %s", err)
			}
		} else if item.TriggerType == "WEBHOOK" {
			err = removeWebhookFunction(ctx, item.ID)
			if err != nil {
				log.Printf("Failed to delete webhook: %s", err)
			}
		} else if item.TriggerType == "EMAIL" {
			err = handleOutlookSubRemoval(ctx, workflow.ID, item.ID)
			if err != nil {
				log.Printf("Failed to delete email sub: %s", err)
			}
		}
	}

	// FIXME - maybe delete workflow executions
	log.Printf("Should delete workflow %s", fileId)
	err = DeleteKey(ctx, "workflow", fileId)
	if err != nil {
		log.Printf("Failed deleting key %s", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed deleting key"}`))
		return
	}

	DeleteCache(ctx, fmt.Sprintf("%s_workflows", user.Id))
	DeleteCache(ctx, fmt.Sprintf("%s_%s", user.Username, fileId))

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}
*/

func SetAuthenticationConfig(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("Api authentication failed in get all apps: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role != "admin" {
		log.Printf("[AUDIT] User isn't admin during auth edit config")
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Must be admin to perform this action"}`)))
		return
	}

	var fileId string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 5 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[5]
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Error with body read: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	type configAuth struct {
		Id     string `json:"id"`
		Action string `json:"action"`
	}

	var config configAuth
	err = json.Unmarshal(body, &config)
	if err != nil {
		log.Printf("Failed unmarshaling (appauth): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if config.Id != fileId {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Bad ID match"}`))
		return
	}

	ctx := getContext(request)
	auth, err := GetWorkflowAppAuthDatastore(ctx, fileId)
	if err != nil {
		log.Printf("Authget error: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": ":("}`))
		return
	}

	if auth.OrgId != user.ActiveOrg.Id {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "User can't edit this org"}`))
		return
	}

	if config.Action == "assign_everywhere" {
		log.Printf("[INFO] Should set authentication config")
		baseWorkflows, err := GetAllWorkflowsByQuery(ctx, user)
		if err != nil && len(baseWorkflows) == 0 {
			log.Printf("Getall error in auth update: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed getting workflows to update"}`))
			return
		}

		workflows := []Workflow{}
		for _, workflow := range baseWorkflows {
			if workflow.OrgId == user.ActiveOrg.Id {
				workflows = append(workflows, workflow)
			}
		}

		// FIXME: Add function to remove auth from other auth's
		actionCnt := 0
		workflowCnt := 0
		authenticationUsage := []AuthenticationUsage{}
		for _, workflow := range workflows {
			newActions := []Action{}
			edited := false
			usage := AuthenticationUsage{
				WorkflowId: workflow.ID,
				Nodes:      []string{},
			}

			for _, action := range workflow.Actions {
				if action.AppName == auth.App.Name {
					action.AuthenticationId = auth.Id

					edited = true
					actionCnt += 1
					usage.Nodes = append(usage.Nodes, action.ID)
				}

				newActions = append(newActions, action)
			}

			workflow.Actions = newActions
			if edited {
				//auth.Usage = usage
				authenticationUsage = append(authenticationUsage, usage)
				err = SetWorkflow(ctx, workflow, workflow.ID)
				if err != nil {
					log.Printf("Failed setting (authupdate) workflow: %s", err)
					continue
				}

				cacheKey := fmt.Sprintf("%s_workflows", user.Id)

				DeleteCache(ctx, cacheKey)

				workflowCnt += 1
			}
		}

		//Usage         []AuthenticationUsage `json:"usage" datastore:"usage"`
		log.Printf("[INFO] Found %d workflows, %d actions", workflowCnt, actionCnt)
		if actionCnt > 0 && workflowCnt > 0 {
			auth.WorkflowCount = int64(workflowCnt)
			auth.NodeCount = int64(actionCnt)
			auth.Usage = authenticationUsage
			auth.Defined = true

			err = SetWorkflowAppAuthDatastore(ctx, *auth, auth.Id)
			if err != nil {
				log.Printf("Failed setting appauth: %s", err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "Failed setting app auth for all workflows"}`))
				return
			} else {
				// FIXME: Remove ALL workflows from other auths using the same
			}
		}
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
	//var config configAuth

	//log.Printf("Should set %s
}

func HandleGetSchedules(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get schedules: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role != "admin" {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Admin required"}`))
		return
	}

	ctx := getContext(request)
	schedules, err := GetAllSchedules(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Failed getting schedules: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Couldn't get schedules"}`))
		return
	}

	newjson, err := json.Marshal(schedules)
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

func HandleUpdateUser(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
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
		Role     string   `json:"role"`
		Username string   `json:"username"`
		UserId   string   `json:"user_id"`
		EthInfo  EthInfo  `json:"eth_info"`
		Suborgs  []string `json:"suborgs"`
	}

	ctx := getContext(request)
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
			log.Printf("[INFO] Updated user %s from %s to %#v. If role is empty, not updating", foundUser.Username, foundUser.Role, t.Role)
			foundUser.Role = t.Role
			foundUser.Roles = []string{t.Role}
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
		log.Printf("orgs to be added: %#v", addedOrgs)
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

			if !ArrayContains(parsedOrgs, userInfo.ActiveOrg.Id) {
				log.Printf("[DEBUG] Reappending org %s", suborg)
				newUserOrgs = append(newUserOrgs, suborg)
				continue
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

	err = SetUser(ctx, foundUser, true)
	if err != nil {
		log.Printf("[WARNING] Error patching user %s: %s", foundUser.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true}`)))
}

func GenerateApikey(ctx context.Context, userInfo User) (User, error) {
	// Generate UUID
	// Set uuid to apikey in backend (update)
	userInfo.ApiKey = uuid.NewV4().String()
	err := SetApikey(ctx, userInfo)
	if err != nil {
		log.Printf("[WARNING] Failed updating apikey: %s", err)
		return userInfo, err
	}

	// Updating user
	log.Printf("[INFO] Adding apikey to user %s", userInfo.Username)
	err = SetUser(ctx, &userInfo, true)
	if err != nil {
		log.Printf("[WARNING] Failed updating users' apikey: %s", err)
		return userInfo, err
	}

	return userInfo, nil
}

func SetNewWorkflow(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in set new workflow: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to set new workflow: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Error with body read: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	var workflow Workflow
	err = json.Unmarshal(body, &workflow)
	if err != nil {
		log.Printf("Failed unmarshaling: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	workflow.ID = uuid.NewV4().String()
	workflow.Owner = user.Id
	workflow.Sharing = "private"
	user.ActiveOrg.Users = []UserMini{}
	workflow.ExecutingOrg = user.ActiveOrg
	workflow.OrgId = user.ActiveOrg.Id
	//log.Printf("TRIGGERS: %d", len(workflow.Triggers))

	ctx := getContext(request)
	//err = increaseStatisticsField(ctx, "total_workflows", workflow.ID, 1, workflow.OrgId)
	//if err != nil {
	//	log.Printf("Failed to increase total workflows stats: %s", err)
	//}

	if len(workflow.Actions) == 0 {
		workflow.Actions = []Action{}
	}
	if len(workflow.Branches) == 0 {
		workflow.Branches = []Branch{}
	}
	if len(workflow.Triggers) == 0 {
		workflow.Triggers = []Trigger{}
	}
	if len(workflow.Errors) == 0 {
		workflow.Errors = []string{}
	}

	newActions := []Action{}
	for _, action := range workflow.Actions {
		if action.Environment == "" {
			//action.Environment = baseEnvironment
			if project.Environment == "cloud" {
				action.Environment = "Cloud"
			}

			action.IsValid = true
		}

		//action.LargeImage = ""
		newActions = append(newActions, action)
	}

	// Initialized without functions = adding a hello world node.
	if len(newActions) == 0 {
		//log.Printf("APPENDING NEW APP FOR NEW WORKFLOW")

		// Adds the Testing app if it's a new workflow
		workflowapps, err := GetPrioritizedApps(ctx, user)
		envName := "cloud"
		if project.Environment != "cloud" {
			workflowapps, err = GetAllWorkflowApps(ctx, 1000)
			envName = "Shuffle"
		}

		//log.Printf("[DEBUG] Got %d apps. Err: %s", len(workflowapps), err)
		if err == nil {
			environments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
			if err == nil {
				for _, env := range environments {
					if env.Default {
						envName = env.Name
						break
					}
				}
			}

			for _, item := range workflowapps {
				//log.Printf("NAME: %s", item.Name)
				if (item.Name == "Shuffle Tools" || item.Name == "Shuffle-Tools") && item.AppVersion == "1.1.0" {
					//nodeId := "40447f30-fa44-4a4f-a133-4ee710368737"
					nodeId := uuid.NewV4().String()
					workflow.Start = nodeId
					newActions = append(newActions, Action{
						Label:       "Change Me",
						Name:        "repeat_back_to_me",
						Environment: envName,
						Parameters: []WorkflowAppActionParameter{
							WorkflowAppActionParameter{
								Name:      "call",
								Value:     "Hello world",
								Example:   "Repeating: Hello World",
								Multiline: true,
							},
						},
						Position: struct {
							X float64 "json:\"x,omitempty\" datastore:\"x\""
							Y float64 "json:\"y,omitempty\" datastore:\"y\""
						}{X: 449.5, Y: 446},
						Priority:    0,
						Errors:      []string{},
						ID:          nodeId,
						IsValid:     true,
						IsStartNode: true,
						Sharing:     true,
						PrivateID:   "",
						SmallImage:  "",
						AppName:     item.Name,
						AppVersion:  item.AppVersion,
						AppID:       item.ID,
						LargeImage:  item.LargeImage,
					})

					break
				}
			}
		}
	} else {
		log.Printf("[INFO] Has %d actions already", len(newActions))
		// FIXME: Check if they require authentication and if they exist locally
		//log.Printf("\n\nSHOULD VALIDATE AUTHENTICATION")
		//AuthenticationId string `json:"authentication_id,omitempty" datastore:"authentication_id"`
		//allAuths, err := GetAllWorkflowAppAuth(ctx, user.ActiveOrg.Id)
		//if err == nil {
		//	log.Printf("AUTH: %#v", allAuths)
		//	for _, action := range newActions {
		//		log.Printf("ACTION: %#v", action)
		//	}
		//}
	}

	workflow.Actions = []Action{}
	for _, item := range workflow.Actions {
		oldId := item.ID
		sourceIndexes := []int{}
		destinationIndexes := []int{}
		for branchIndex, branch := range workflow.Branches {
			if branch.SourceID == oldId {
				sourceIndexes = append(sourceIndexes, branchIndex)
			}

			if branch.DestinationID == oldId {
				destinationIndexes = append(destinationIndexes, branchIndex)
			}
		}

		item.ID = uuid.NewV4().String()
		for _, index := range sourceIndexes {
			workflow.Branches[index].SourceID = item.ID
		}

		for _, index := range destinationIndexes {
			workflow.Branches[index].DestinationID = item.ID
		}

		newActions = append(newActions, item)
	}

	newTriggers := []Trigger{}
	for _, item := range workflow.Triggers {
		oldId := item.ID
		sourceIndexes := []int{}
		destinationIndexes := []int{}
		for branchIndex, branch := range workflow.Branches {
			if branch.SourceID == oldId {
				sourceIndexes = append(sourceIndexes, branchIndex)
			}

			if branch.DestinationID == oldId {
				destinationIndexes = append(destinationIndexes, branchIndex)
			}
		}

		item.ID = uuid.NewV4().String()
		for _, index := range sourceIndexes {
			workflow.Branches[index].SourceID = item.ID
		}

		for _, index := range destinationIndexes {
			workflow.Branches[index].DestinationID = item.ID
		}

		item.Status = "uninitialized"
		newTriggers = append(newTriggers, item)
	}

	newSchedules := []Schedule{}
	for _, item := range workflow.Schedules {
		item.Id = uuid.NewV4().String()
		newSchedules = append(newSchedules, item)
	}

	timeNow := int64(time.Now().Unix())
	workflow.Actions = newActions
	workflow.Triggers = newTriggers
	workflow.Schedules = newSchedules
	workflow.IsValid = true
	workflow.Configuration.ExitOnError = false
	workflow.Created = timeNow

	workflowjson, err := json.Marshal(workflow)
	if err != nil {
		log.Printf("Failed workflow json setting marshalling: %s", err)
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	err = SetWorkflow(ctx, workflow, workflow.ID)
	if err != nil {
		log.Printf("[WARNING] Failed setting workflow: %s (Set workflow)", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Cleans up cache for the users
	org, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err == nil {
		for _, loopUser := range org.Users {
			cacheKey := fmt.Sprintf("%s_workflows", loopUser.Id)
			DeleteCache(ctx, cacheKey)
		}
	} else {
		cacheKey := fmt.Sprintf("%s_workflows", user.Id)
		DeleteCache(ctx, cacheKey)
	}

	log.Printf("[INFO] Saved new workflow %s with name %s", workflow.ID, workflow.Name)

	resp.WriteHeader(200)
	//log.Println(string(workflowjson))
	resp.Write(workflowjson)
}

// Saves a workflow to an ID
func SaveWorkflow(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	//log.Println("Start")
	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("[WARNING] Api authentication failed in save workflow: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to save workflow (2): %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	//log.Println("PostUser")
	location := strings.Split(request.URL.String(), "/")

	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
		if strings.Contains(fileId, "?") {
			fileId = strings.Split(fileId, "?")[0]
		}
	}

	if len(fileId) != 36 {
		log.Printf(`[WARNING] Workflow ID %s is not valid`, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID to save is not valid"}`))
		return
	}

	// Here to check access rights
	ctx := getContext(request)
	tmpworkflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Failed getting the workflow locally (save workflow): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	workflow := Workflow{}
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Failed workflow body read: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	err = json.Unmarshal([]byte(body), &workflow)
	if err != nil {
		log.Printf(string(body))
		log.Printf("[ERROR] Failed workflow unmarshaling: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
		return
	}

	if user.Id != tmpworkflow.Owner {
		if tmpworkflow.OrgId == user.ActiveOrg.Id && user.Role == "admin" {
			log.Printf("[AUDIT] User %s is accessing workflow %s as admin (save workflow)", user.Username, tmpworkflow.ID)
			workflow.ID = tmpworkflow.ID
		} else if tmpworkflow.Public {
			//log.Printf("\n\nSHOULD CREATE A NEW WORKFLOW FOR THE USER :O\n\n")

			log.Printf("[INFO] User %s is saving the public workflow %s", user.Username, tmpworkflow.ID)
			workflow = *tmpworkflow
			workflow.ID = uuid.NewV4().String()
			workflow.Public = false
			workflow.Owner = user.Id
			workflow.Org = []OrgMini{
				user.ActiveOrg,
			}
			workflow.ExecutingOrg = user.ActiveOrg
			workflow.OrgId = user.ActiveOrg.Id
			workflow.PreviouslySaved = false

			err = SetWorkflow(ctx, workflow, workflow.ID)
			if err != nil {
				log.Printf("[WARNING] Failed saving NEW version of public %s for user %s: %s", tmpworkflow.ID, user.Username, err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false}`))
				return
			}

			resp.WriteHeader(200)
			resp.Write([]byte(fmt.Sprintf(`{"success": true, "new_id": "%s"}`, workflow.ID)))
			return
		} else {
			log.Printf("[WARNING] Wrong user (%s) for workflow %s (save)", user.Username, tmpworkflow.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	} else {

		if workflow.Public {
			log.Printf("[WARNING] Rolling back public as the user set it to true themselves")
			workflow.Public = false
		}

		if len(workflow.PublishedId) > 0 {
			log.Printf("[INFO] Workflow %s has the published ID %s", workflow.ID, workflow.PublishedId)
		}
	}

	if fileId != workflow.ID {
		log.Printf("[WARNING] Path and request ID are not matching in workflow save: %s != %s.", fileId, workflow.ID)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(workflow.Name) == 0 {
		log.Printf("[WARNING] Can't save workflow without a name.")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow needs a name"}`))
		return
	}

	if len(workflow.Actions) == 0 {
		log.Printf("[WARNING] Can't save workflow without a single action.")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow needs at least one action"}`))
		return
	}

	// Resetting subflows as they shouldn't be entirely saved. Used just for imports/exports
	if len(workflow.Subflows) > 0 {
		log.Printf("[DEBUG] Got %d subflows saved in %s (to be saved and removed)", len(workflow.Subflows), workflow.ID)
	}

	workflow.Subflows = []Workflow{}
	if len(workflow.DefaultReturnValue) > 0 && len(workflow.DefaultReturnValue) < 200 {
		log.Printf("[INFO] Set default return value to on failure to (%s): %s", workflow.ID, workflow.DefaultReturnValue)
		//workflow.DefaultReturnValue
	}

	log.Printf("[INFO] Saving workflow %s with %d actions and %d triggers", workflow.Name, len(workflow.Actions), len(workflow.Triggers))
	if len(workflow.ExecutingOrg.Id) == 0 {
		log.Printf("[INFO] Setting executing org for workflow")
		user.ActiveOrg.Users = []UserMini{}
		workflow.ExecutingOrg = user.ActiveOrg
	}

	newActions := []Action{}
	allNodes := []string{}
	workflow.Categories = Categories{}

	environments := []Environment{
		Environment{
			Name:       "Cloud",
			Type:       "cloud",
			Archived:   false,
			Registered: true,
			Default:    false,
			OrgId:      user.ActiveOrg.Id,
			Id:         uuid.NewV4().String(),
		},
	}

	if project.Environment != "cloud" {
		environments, err = GetEnvironments(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("[WARNING] Failed getting environments for org %s", user.ActiveOrg.Id)
			environments = []Environment{}
		}
	}

	//log.Printf("ENVIRONMENTS: %#v", environments)
	defaultEnv := ""
	for _, env := range environments {
		if env.Default {
			defaultEnv = env.Name
			break
		}
	}

	if defaultEnv == "" {
		if project.Environment == "cloud" {
			defaultEnv = "Cloud"
		} else {
			defaultEnv = "Shuffle"
		}
	}

	startnodeFound := false
	workflowapps, apperr := GetPrioritizedApps(ctx, user)
	newOrgApps := []string{}
	for _, action := range workflow.Actions {
		if action.SourceWorkflow != workflow.ID && len(action.SourceWorkflow) > 0 {
			continue
		}

		allNodes = append(allNodes, action.ID)
		if workflow.Start == action.ID {
			//log.Printf("[INFO] FOUND STARTNODE %d", workflow.Start)
			startnodeFound = true
			action.IsStartNode = true
		}

		if len(action.Errors) > 0 || !action.IsValid {
			action.IsValid = true
			action.Errors = []string{}
		}

		if action.Environment == "" {
			if project.Environment == "cloud" {
				action.Environment = defaultEnv
			} else {
				if len(environments) > 0 {
					for _, env := range environments {
						if !env.Archived && env.Default {
							//log.Printf("FOUND ENV %#v", env)
							action.Environment = env.Name
							break
						}
					}
				}

				if action.Environment == "" {
					action.Environment = defaultEnv
				}

				action.IsValid = true
			}
		} else {
			warned := []string{}
			for _, env := range environments {
				found := false
				if env.Name == action.Environment {
					found = false
					if env.Archived {
						log.Printf("[DEBUG] Environment %s is archived. Changing to default.")
						action.Environment = defaultEnv
					}

					break
				}

				if !found {
					if ArrayContains(warned, action.Environment) {
						log.Printf("[DEBUG] Environment %s isn't available. Changing to default.", action.Environment)
						warned = append(warned, action.Environment)
					}

					action.Environment = defaultEnv
				}
			}
		}

		// Fixing apps with bad IDs. This can happen a lot because of
		// autogeneration of app IDs, and export/imports of workflows
		idFound := false
		nameVersionFound := false
		nameFound := false
		for _, innerApp := range workflowapps {
			if innerApp.ID == action.AppID {
				//log.Printf("[INFO] ID, Name AND version for %s:%s (%s) was FOUND", action.AppName, action.AppVersion, action.AppID)
				action.Sharing = innerApp.Sharing
				action.Public = innerApp.Public
				action.Generated = innerApp.Generated
				action.ReferenceUrl = innerApp.ReferenceUrl
				idFound = true
				break
			}

			if innerApp.Name == action.AppName && innerApp.AppVersion == action.AppVersion {
				//log.Printf("NAME AND VERSION FOUND (overwritten)!")
				action.AppID = innerApp.ID
				action.Sharing = innerApp.Sharing
				action.Public = innerApp.Public
				action.Generated = innerApp.Generated
				action.ReferenceUrl = innerApp.ReferenceUrl
				nameVersionFound = true
				break
			}

			if innerApp.Name == action.AppName {
				action.AppID = innerApp.ID
				action.Sharing = innerApp.Sharing
				action.Public = innerApp.Public
				action.Generated = innerApp.Generated
				action.ReferenceUrl = innerApp.ReferenceUrl

				nameFound = true
				break
			}
		}

		if !idFound {
			if nameVersionFound {
			} else if nameFound {
			} else {
				log.Printf("[WARNING] ID, Name AND version for %s:%s (%s) was NOT found", action.AppName, action.AppVersion, action.AppID)
				handled := false
				if project.Environment == "cloud" {
					appid, err := handleAlgoliaAppSearch(ctx, action.AppName)
					if err == nil && len(appid) > 0 {
						//log.Printf("[INFO] Found NEW appid %s for app %s", appid, action.AppName)
						tmpApp, err := GetApp(ctx, appid, user, false)
						if err == nil {
							handled = true
							action.AppID = tmpApp.ID
							newOrgApps = append(newOrgApps, action.AppID)

							workflowapps = append(workflowapps, *tmpApp)
						}
					} else {
						log.Printf("[WARNING] Failed finding name %s in Algolia", action.AppName)
					}
				}

				if !handled {
					action.IsValid = false
					action.Errors = []string{fmt.Sprintf("Couldn't find app %s:%s", action.AppName, action.AppVersion)}
				}
			}
		}

		if !action.IsValid && len(action.Errors) > 0 {
			log.Printf("[INFO] Node %s is invalid and needs to be remade. Errors: %s", action.Label, strings.Join(action.Errors, "\n"))

			//if workflow.PreviouslySaved {
			//	resp.WriteHeader(401)
			//	resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Node %s is invalid and needs to be remade."}`, action.Label)))
			//	return
			//}
			//action.IsValid = true
			//action.Errors = []string{}
		}

		workflow.Categories = HandleCategoryIncrease(workflow.Categories, action, workflowapps)
		//log.Printf("ENVIRONMENT: %s", action.Environment)
		newActions = append(newActions, action)
	}

	if !startnodeFound {
		log.Printf("[WARNING] No startnode found during save of %s!!", workflow.ID)
	}

	// Automatically adding new apps
	if len(newOrgApps) > 0 {
		log.Printf("Adding new apps to org: %#v", newOrgApps)
		org, err := GetOrg(ctx, user.ActiveOrg.Id)
		if err == nil {
			added := false
			for _, newApp := range newOrgApps {
				if !ArrayContains(org.ActiveApps, newApp) {
					org.ActiveApps = append(org.ActiveApps, newApp)
					added = true
				}
			}

			if added {
				err = SetOrg(ctx, *org, org.Id)
				if err != nil {
					log.Printf("[WARNING] Failed setting org when autoadding apps on save: %s", err)
				} else {
					cacheKey := fmt.Sprintf("apps_%s", user.Id)
					DeleteCache(ctx, cacheKey)
				}
			}
		}
	}

	workflow.Actions = newActions

	newTriggers := []Trigger{}
	for _, trigger := range workflow.Triggers {
		if trigger.SourceWorkflow != workflow.ID && len(trigger.SourceWorkflow) > 0 {
			continue
		}

		log.Printf("[INFO] Workflow: %s, Trigger %s: %s", workflow.ID, trigger.TriggerType, trigger.Status)

		// Check if it's actually running
		// FIXME: Do this for other triggers too
		if trigger.TriggerType == "SCHEDULE" && trigger.Status != "uninitialized" {
			schedule, err := GetSchedule(ctx, trigger.ID)
			if err != nil {
				trigger.Status = "stopped"
			} else if schedule.Id == "" {
				trigger.Status = "stopped"
			}
		} else if trigger.TriggerType == "SUBFLOW" {
			for index, param := range trigger.Parameters {
				//log.Printf("PARAMS: %#v", param)
				if param.Name == "workflow" {
					// Validate workflow exists
					_, err := GetWorkflow(ctx, param.Value)
					if err != nil {
						workflow.Errors = append(workflow.Errors, fmt.Sprintf("Workflow %s in Subflow %s (%s) doesn't exist", workflow.ID, trigger.Label, trigger.ID))
						log.Printf("[WARNING] Couldn't find subflow %s for workflow %s (%s)", param.Value, workflow.Name, workflow.ID)
					}
				}

				//if len(param.Value) == 0 && param.Name != "argument" {
				if param.Name == "user_apikey" {
					apikey := ""
					if len(user.ApiKey) > 0 {
						apikey = user.ApiKey
					} else {
						user, err = GenerateApikey(ctx, user)
						if err != nil {
							workflow.IsValid = false
							workflow.Errors = []string{"Trigger is missing a parameter: %s", param.Name}

							log.Printf("[DEBUG] No type specified for subflow node")

							if workflow.PreviouslySaved {
								resp.WriteHeader(401)
								resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Trigger %s is missing the parameter %s"}`, trigger.Label, param.Name)))
								return
							}
						}

						apikey = user.ApiKey
					}

					log.Printf("[INFO] Set apikey in subflow trigger for user during save")
					if len(apikey) > 0 {
						trigger.Parameters[index].Value = apikey
					}
				}
				//} else {

				//	workflow.IsValid = false
				//	workflow.Errors = []string{"Trigger is missing a parameter: %s", param.Name}

				//	log.Printf("[WARNING] No type specified for user input node")
				//	if workflow.PreviouslySaved {
				//		resp.WriteHeader(401)
				//		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Trigger %s is missing the parameter %s"}`, trigger.Label, param.Name)))
				//		return
				//	}
				//}
				//}
			}
		} else if trigger.TriggerType == "WEBHOOK" {
			if trigger.Status != "uninitialized" && trigger.Status != "stopped" {
				hook, err := GetHook(ctx, trigger.ID)
				if err != nil {
					log.Printf("[WARNING] Failed getting webhook %s (%s)", trigger.ID, trigger.Status)
					trigger.Status = "stopped"
				} else if hook.Id == "" {
					trigger.Status = "stopped"
				}
			}

			//log.Printf("WEBHOOK: %d", len(trigger.Parameters))
			if len(trigger.Parameters) < 2 {
				log.Printf("[WARNING] Issue with parameters in webhook %s - missing params", trigger.ID)
			} else {
				if !strings.Contains(trigger.Parameters[0].Value, trigger.ID) {
					log.Printf("[INFO] Fixing webhook URL for %s", trigger.ID)
					baseUrl := "https://shuffler.io"
					if project.Environment != "cloud" {
						baseUrl = "http://localhost:3001"
					}

					newTriggerName := fmt.Sprintf("webhook_%s", trigger.ID)
					trigger.Parameters[0].Value = fmt.Sprintf("%s/api/v1/hooks/%s", baseUrl, newTriggerName)
					trigger.Parameters[1].Value = newTriggerName
				}
			}
		} else if trigger.TriggerType == "USERINPUT" {
			// E.g. check email
			log.Printf("[INFO] Validating USERINPUT during SAVING")
			sms := ""
			email := ""
			subflow := ""
			triggerType := ""
			triggerInformation := ""
			for _, item := range trigger.Parameters {
				if item.Name == "alertinfo" {
					triggerInformation = item.Value
				} else if item.Name == "type" {
					triggerType = item.Value
				} else if item.Name == "email" {
					email = item.Value
				} else if item.Name == "sms" {
					sms = item.Value
				} else if item.Name == "subflow" {
					subflow = item.Value
				}
			}

			if len(triggerType) == 0 {
				log.Printf("[DEBUG] No type specified for user input node")
				if workflow.PreviouslySaved {
					resp.WriteHeader(401)
					resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "No contact option specified in user input"}`)))
					return
				}
			}

			// FIXME: This is not the right time to send them, BUT it's well served for testing. Save -> send email / sms
			_ = triggerInformation
			if strings.Contains(triggerType, "email") {
				if email == "test@test.com" {
					log.Printf("Email isn't specified during save.")
					if workflow.PreviouslySaved {
						resp.WriteHeader(401)
						resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Email field in user input can't be empty"}`)))
						return
					}
				}

				log.Printf("[DEBUG] Should send email to %s during execution.", email)
			}
			if strings.Contains(triggerType, "sms") {
				if sms == "0000000" {
					log.Printf("Email isn't specified during save.")
					if workflow.PreviouslySaved {
						resp.WriteHeader(401)
						resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "SMS field in user input can't be empty"}`)))
						return
					}
				}

				log.Printf("[DEBUG] Should send SMS to %s during execution.", sms)
			}
			if strings.Contains(triggerType, "subflow") {
				if len(subflow) != 36 {
					log.Printf("[WARNING] Subflow isn't specified!")
					if workflow.PreviouslySaved {
						resp.WriteHeader(401)
						resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Subflow in User Input Trigger isn't specified"}`)))
						return
					}
				}

				log.Printf("[DEBUG] Should send SMS to %s during execution.", sms)
			}
		}

		//log.Println("TRIGGERS")
		allNodes = append(allNodes, trigger.ID)
		newTriggers = append(newTriggers, trigger)
	}

	newComments := []Comment{}
	for _, comment := range workflow.Comments {
		if comment.Height < 50 {
			comment.Height = 150
		}

		if comment.Width < 50 {
			comment.Height = 150
		}

		if len(comment.BackgroundColor) == 0 {
			comment.BackgroundColor = "#1f2023"
		}

		if len(comment.Color) == 0 {
			comment.Color = "#ffffff"
		}

		newComments = append(newComments, comment)
	}

	workflow.Comments = newComments
	workflow.Triggers = newTriggers

	if len(workflow.Actions) == 0 {
		workflow.Actions = []Action{}
	}
	if len(workflow.Branches) == 0 {
		workflow.Branches = []Branch{}
	}
	if len(workflow.Triggers) == 0 {
		workflow.Triggers = []Trigger{}
	}
	if len(workflow.Errors) == 0 {
		workflow.Errors = []string{}
	}
	if len(workflow.Comments) == 0 {
		workflow.Comments = []Comment{}
	}

	//log.Printf("PRE VARIABLES")
	for _, variable := range workflow.WorkflowVariables {
		if len(variable.Value) == 0 {
			log.Printf("[WARNING] Variable %s is empty!", variable.Name)
			workflow.Errors = append(workflow.Errors, fmt.Sprintf("Variable %s is empty!", variable.Name))
			//resp.WriteHeader(401)
			//resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Variable %s can't be empty"}`, variable.Name)))
			//return
			//} else {
			//	log.Printf("VALUE OF VAR IS %s", variable.Value)
		}
	}

	if len(workflow.ExecutionVariables) > 0 {
		log.Printf("[INFO] Found %d execution variable(s) for workflow %s", len(workflow.ExecutionVariables), workflow.ID)
	}

	if len(workflow.WorkflowVariables) > 0 {
		log.Printf("[INFO] Found %d workflow variable(s) for workflow %s", len(workflow.WorkflowVariables), workflow.ID)
	}

	// Nodechecks
	foundNodes := []string{}
	for _, node := range allNodes {
		for _, branch := range workflow.Branches {
			//log.Println("branch")
			//log.Println(node)
			//log.Println(branch.DestinationID)
			if node == branch.DestinationID || node == branch.SourceID {
				foundNodes = append(foundNodes, node)
				break
			}
		}
	}

	// FIXME - append all nodes (actions, triggers etc) to one single array here
	//log.Printf("PRE VARIABLES")
	if len(foundNodes) != len(allNodes) || len(workflow.Actions) <= 0 {
		// This shit takes a few seconds lol
		if !workflow.IsValid {
			oldworkflow, err := GetWorkflow(ctx, fileId)
			if err != nil {
				log.Printf("[WARNING] Workflow %s doesn't exist - oldworkflow.", fileId)
				if workflow.PreviouslySaved {
					resp.WriteHeader(401)
					resp.Write([]byte(`{"success": false, "reason": "Item already exists."}`))
					return
				}
			}

			oldworkflow.IsValid = false
			err = SetWorkflow(ctx, *oldworkflow, fileId)
			if err != nil {
				log.Printf("[WARNING] Failed saving workflow to database: %s", err)
				if workflow.PreviouslySaved {
					resp.WriteHeader(401)
					resp.Write([]byte(`{"success": false}`))
					return
				}
			}

			cacheKey := fmt.Sprintf("%s_workflows", user.Id)
			DeleteCache(ctx, cacheKey)
		}
	}

	// FIXME - might be a sploit to run someone elses app if getAllWorkflowApps
	// doesn't check sharing=true
	// Have to do it like this to add the user's apps
	//log.Println("Apps set starting")
	//log.Printf("EXIT ON ERROR: %#v", workflow.Configuration.ExitOnError)

	// Started getting the single apps, but if it's weird, this is faster
	// 1. Check workflow.Start
	// 2. Check if any node has "isStartnode"
	//if len(workflow.Actions) > 0 {
	//	index := -1
	//	for indexFound, action := range workflow.Actions {
	//		//log.Println("Apps set done")
	//		if workflow.Start == action.ID {
	//			index = indexFound
	//		}
	//	}

	//	if index >= 0 {
	//		workflow.Actions[0].IsStartNode = true
	//	} else {
	//		log.Printf("[WARNING] Couldn't find startnode %s!", workflow.Start)
	//		if workflow.PreviouslySaved {
	//			resp.WriteHeader(401)
	//			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "You need to set a startnode."}`)))
	//			return
	//		}
	//	}
	//}

	/*
		allAuths, err := GetAllWorkflowAppAuth(ctx, user.ActiveOrg.Id)
		if userErr != nil {
			log.Printf("Api authentication failed in get all apps: %s", userErr)
			if workflow.PreviouslySaved {
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false}`))
				return
			}
		}
	*/

	// Check every app action and param to see whether they exist
	//log.Printf("PRE ACTIONS 2")
	allAuths, autherr := GetAllWorkflowAppAuth(ctx, user.ActiveOrg.Id)
	newActions = []Action{}
	for _, action := range workflow.Actions {
		reservedApps := []string{
			"0ca8887e-b4af-4e3e-887c-87e9d3bc3d3e",
		}

		//log.Printf("%s Action execution var: %s", action.Label, action.ExecutionVariable.Name)

		builtin := false
		for _, id := range reservedApps {
			if id == action.AppID {
				builtin = true
				break
			}
		}

		// Check auth
		// 1. Find the auth in question
		// 2. Update the node and workflow info in the auth
		// 3. Get the values in the auth and add them to the action values
		handleOauth := false
		if len(action.AuthenticationId) > 0 {
			//log.Printf("\n\nLen: %d", len(allAuths))
			authFound := false
			for _, auth := range allAuths {
				if auth.Id == action.AuthenticationId {
					authFound = true

					if strings.ToLower(auth.Type) == "oauth2" {
						handleOauth = true
					}

					// Updates the auth item itself IF necessary
					go UpdateAppAuth(ctx, auth, workflow.ID, action.ID, true)
					break
				}
			}

			if !authFound {
				log.Printf("[WARNING] App auth %s doesn't exist. Setting error", action.AuthenticationId)

				errorMsg := fmt.Sprintf("App authentication %s for app %s doesn't exist!", action.AuthenticationId, action.AppName)
				if !ArrayContains(workflow.Errors, errorMsg) {
					workflow.Errors = append(workflow.Errors, errorMsg)
				}
				workflow.IsValid = false

				action.Errors = append(action.Errors, "App authentication doesn't exist")
				action.IsValid = false
				action.AuthenticationId = ""
				//resp.WriteHeader(401)
				//resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "App auth %s doesn't exist"}`, action.AuthenticationId)))
				//return
			}
		}

		if builtin {
			newActions = append(newActions, action)
		} else {
			curapp := WorkflowApp{}
			for _, app := range workflowapps {
				if app.ID == action.AppID {
					curapp = app
					break
				}

				// Has to NOT be generated
				if app.Name == action.AppName {
					if app.AppVersion == action.AppVersion {
						curapp = app
						break
					} else if ArrayContains(app.LoopVersions, action.AppVersion) {
						// Get the real app
						for _, item := range app.Versions {
							if item.Version == action.AppVersion {
								//log.Printf("Should get app %s - %s", item.Version, item.ID)

								tmpApp, err := GetApp(ctx, item.ID, user, false)
								if err != nil && tmpApp.ID == "" {
									log.Printf("[WARNING] Failed getting app %s (%s): %s", app.Name, item.ID, err)
								}

								curapp = *tmpApp
								break
							}
						}

						//curapp = app
						break
					}
				}
			}

			//log.Printf("CURAPP: %#v:%s", curapp.Name, curapp.AppVersion)

			if curapp.Name != action.AppName {
				workflow.Errors = append(workflow.Errors, fmt.Sprintf("App %s:%s doesn't exist", action.AppName, action.AppVersion))
				action.Errors = append(action.Errors, "This app doesn't exist.")
				action.IsValid = false
				workflow.IsValid = false

				// Append with errors
				newActions = append(newActions, action)
				log.Printf("[WARNING] App %s:%s doesn't exist. Adding as error.", action.AppName, action.AppVersion)
				//resp.WriteHeader(401)
				//resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "App %s doesn't exist"}`, action.AppName)))
				//return
			} else {
				// Check tosee if the appaction is valid
				curappaction := WorkflowAppAction{}
				for _, curAction := range curapp.Actions {
					if action.Name == curAction.Name {
						curappaction = curAction
						break
					}
				}

				// Check to see if the action is valid
				if curappaction.Name != action.Name {
					log.Printf("[ERROR] Action %s in app %s doesn't exist.", action.Name, curapp.Name)
					thisError := fmt.Sprintf("%s: Action %s in app %s doesn't exist", action.Label, action.Name, action.AppName)
					workflow.Errors = append(workflow.Errors, thisError)
					workflow.IsValid = false
					action.Errors = append(action.Errors, thisError)
					action.IsValid = false
					//if workflow.PreviouslySaved {
					//	resp.WriteHeader(401)
					//	resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Action %s in app %s doesn't exist"}`, action.Name, curapp.Name)))
					//	return
					//}
				}

				// FIXME - check all parameters to see if they're valid
				// Includes checking required fields

				selectedAuth := AppAuthenticationStorage{}
				if len(action.AuthenticationId) > 0 && autherr == nil {
					for _, auth := range allAuths {
						if auth.Id == action.AuthenticationId {
							selectedAuth = auth
							break
						}
					}
				}

				newParams := []WorkflowAppActionParameter{}
				for _, param := range curappaction.Parameters {
					paramFound := false

					// Handles check for parameter exists + value not empty in used fields
					for _, actionParam := range action.Parameters {
						if actionParam.Name == param.Name {
							paramFound = true

							if actionParam.Value == "" && actionParam.Variant == "STATIC_VALUE" && actionParam.Required == true {
								// Validating if the field is an authentication field
								if len(selectedAuth.Id) > 0 {
									authFound := false
									for _, field := range selectedAuth.Fields {
										if field.Key == actionParam.Name {
											authFound = true
											//log.Printf("FOUND REQUIRED KEY %s IN AUTH", field.Key)
											break
										}
									}

									if authFound {
										newParams = append(newParams, actionParam)
										continue
									}
								}

								//log.Printf("[WARNING] Appaction %s with required param '%s' is empty. Can't save.", action.Name, param.Name)
								thisError := fmt.Sprintf("%s is missing required parameter %s", action.Label, param.Name)
								if handleOauth {
									log.Printf("[WARNING] Handling oauth2 app saving, hence not throwing warnings (1)")
									workflow.Errors = append(workflow.Errors, fmt.Sprintf("Debug: Handling one Oauth2 app (%s). May cause issues during initial configuration (1)", action.Name))
								} else {
									action.Errors = append(action.Errors, thisError)
									workflow.Errors = append(workflow.Errors, thisError)
									action.IsValid = false
								}
							}

							if actionParam.Variant == "" {
								actionParam.Variant = "STATIC_VALUE"
							}

							newParams = append(newParams, actionParam)
							break
						}
					}

					// Handles check for required params
					if !paramFound && param.Required {
						if handleOauth {
							log.Printf("[WARNING] Handling oauth2 app saving, hence not throwing warnings (2)")
							workflow.Errors = append(workflow.Errors, fmt.Sprintf("Debug: Handling one Oauth2 app (%s). May cause issues during initial configuration (2)", action.Name))
						} else {
							thisError := fmt.Sprintf("Parameter %s is required", param.Name)
							action.Errors = append(action.Errors, thisError)

							workflow.Errors = append(workflow.Errors, thisError)
							action.IsValid = false
						}

						//newActions = append(newActions, action)
						//resp.WriteHeader(401)
						//resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Appaction %s with required param '%s' is empty."}`, action.Name, param.Name)))
						//return
					}

				}

				action.Parameters = newParams
				newActions = append(newActions, action)
			}
		}
	}

	if !workflow.PreviouslySaved {
		log.Printf("[WORKFLOW INIT] NOT PREVIOUSLY SAVED - SET ACTION AUTH!")

		if autherr == nil && len(workflowapps) > 0 && apperr == nil {
			//log.Printf("Setting actions")
			actionFixing := []Action{}
			appsAdded := []string{}
			for _, action := range newActions {
				setAuthentication := false
				if len(action.AuthenticationId) > 0 {
					//found := false
					authenticationFound := false
					for _, auth := range allAuths {
						if auth.Id == action.AuthenticationId {
							authenticationFound = true
							break
						}
					}

					if !authenticationFound {
						setAuthentication = true
					}
				} else {
					// FIXME: 1. Validate if the app needs auth
					// 1. Validate if auth for the app exists
					// var appAuth AppAuthenticationStorage
					setAuthentication = true

					//App           WorkflowApp           `json:"app" datastore:"app,noindex"`
				}

				if setAuthentication {
					authSet := false
					for _, auth := range allAuths {
						if !auth.Active {
							continue
						}

						if !auth.Defined {
							continue
						}

						if auth.App.Name == action.AppName {
							//log.Printf("FOUND AUTH FOR APP %s: %s", auth.App.Name, auth.Id)
							action.AuthenticationId = auth.Id
							authSet = true
							break
						}
					}

					// FIXME: Only o this IF there isn't another one for the app already
					if !authSet {
						//log.Printf("Validate if the app NEEDS auth or not")
						outerapp := WorkflowApp{}
						for _, app := range workflowapps {
							if app.Name == action.AppName {
								outerapp = app
								break
							}
						}

						if len(outerapp.ID) > 0 && outerapp.Authentication.Required {
							found := false
							for _, auth := range allAuths {
								if auth.App.ID == outerapp.ID {
									found = true
									break
								}
							}

							for _, added := range appsAdded {
								if outerapp.ID == added {
									found = true
								}
							}

							// FIXME: Add app auth
							if !found {
								timeNow := int64(time.Now().Unix())
								authFields := []AuthenticationStore{}
								for _, param := range outerapp.Authentication.Parameters {
									authFields = append(authFields, AuthenticationStore{
										Key:   param.Name,
										Value: "",
									})
								}

								appAuth := AppAuthenticationStorage{
									Active:        true,
									Label:         fmt.Sprintf("default_%s", outerapp.Name),
									Id:            uuid.NewV4().String(),
									App:           outerapp,
									Fields:        authFields,
									Usage:         []AuthenticationUsage{},
									WorkflowCount: 0,
									NodeCount:     0,
									OrgId:         user.ActiveOrg.Id,
									Created:       timeNow,
									Edited:        timeNow,
								}

								err = SetWorkflowAppAuthDatastore(ctx, appAuth, appAuth.Id)
								if err != nil {
									log.Printf("Failed setting appauth for with name %s", appAuth.Label)
								} else {
									appsAdded = append(appsAdded, outerapp.ID)
								}
							}

							action.Errors = append(action.Errors, "Requires authentication")
							action.IsValid = false
							workflow.IsValid = false
						}
					}
				}

				actionFixing = append(actionFixing, action)
			}

			newActions = actionFixing
		} else {
			log.Printf("FirstSave error: %s - %s", err, apperr)
			//allAuths, err := GetAllWorkflowAppAuth(ctx, user.ActiveOrg.Id)
		}

		skipSave, skipSaveOk := request.URL.Query()["skip_save"]
		if skipSaveOk && len(skipSave) > 0 {
			//log.Printf("INSIDE SKIPSAVE: %s", skipSave[0])
			if strings.ToLower(skipSave[0]) != "true" {
				workflow.PreviouslySaved = true
			}
		} else {
			workflow.PreviouslySaved = true
		}
	}
	//log.Printf("SAVED: %#v", workflow.PreviouslySaved)

	workflow.Actions = newActions
	workflow.IsValid = true

	// TBD: Is this too drastic? May lead to issues in the future.
	if workflow.OrgId != user.ActiveOrg.Id {
		log.Printf("[WARNING] Editing workflow to be owned by org %s", user.ActiveOrg.Id)
		workflow.OrgId = user.ActiveOrg.Id
		workflow.ExecutingOrg = user.ActiveOrg
		workflow.Org = append(workflow.Org, user.ActiveOrg)
	}

	err = SetWorkflow(ctx, workflow, fileId)
	if err != nil {
		log.Printf("[WARNING] Failed saving workflow to database: %s", err)
		if workflow.PreviouslySaved {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	cacheKey := fmt.Sprintf("%s_workflows", user.Id)
	DeleteCache(ctx, cacheKey)

	//totalOldActions := len(tmpworkflow.Actions)
	//totalNewActions := len(workflow.Actions)
	//err = increaseStatisticsField(ctx, "total_workflow_actions", workflow.ID, int64(totalNewActions-totalOldActions), workflow.OrgId)
	//if err != nil {
	//	log.Printf("Failed to change total actions data: %s", err)
	//}

	type returnData struct {
		Success bool     `json:"success"`
		Errors  []string `json:"errors"`
	}

	returndata := returnData{
		Success: true,
		Errors:  workflow.Errors,
	}

	// Really don't know why this was happening
	//cacheKey := fmt.Sprintf("workflowapps-sorted-100")
	//requestCache.Delete(cacheKey)
	//cacheKey = fmt.Sprintf("workflowapps-sorted-500")
	//requestCache.Delete(cacheKey)

	log.Printf("[INFO] Saved new version of workflow %s (%s) for org %s. Actions: %d, Triggers: %d", workflow.Name, fileId, workflow.OrgId, len(workflow.Actions), len(workflow.Triggers))
	resp.WriteHeader(200)
	newBody, err := json.Marshal(returndata)
	if err != nil {
		resp.Write([]byte(`{"success": true}`))
		return
	}

	resp.Write(newBody)
}

func HandleCategoryIncrease(categories Categories, action Action, workflowapps []WorkflowApp) Categories {
	if action.Category == "" {
		appName := action.AppName
		for _, app := range workflowapps {
			if appName != strings.ToLower(app.Name) {
				continue
			}

			if len(app.Categories) > 0 {
				log.Printf("[INFO] Setting category for %s: %s", app.Name, app.Categories)
				action.Category = app.Categories[0]
				break
			}
		}

		//log.Printf("Should find app's categories as it's empty during save")
		return categories
	}

	//log.Printf("Action: %s, category: %s", action.AppName, action.Category)
	// FIXME: Make this an "autodiscover" that's controlled by the category itself
	// Should just be a list that's looped against :)
	newCategory := strings.ToLower(action.Category)
	if strings.Contains(newCategory, "case") || strings.Contains(newCategory, "ticket") || strings.Contains(newCategory, "alert") || strings.Contains(newCategory, "mssp") {
		categories.Cases.Count += 1
	} else if strings.Contains(newCategory, "siem") || strings.Contains(newCategory, "event") || strings.Contains(newCategory, "log") || strings.Contains(newCategory, "search") {
		categories.SIEM.Count += 1
	} else if strings.Contains(newCategory, "sms") || strings.Contains(newCategory, "comm") || strings.Contains(newCategory, "phone") || strings.Contains(newCategory, "call") || strings.Contains(newCategory, "chat") || strings.Contains(newCategory, "mail") || strings.Contains(newCategory, "phish") {
		categories.Communication.Count += 1
	} else if strings.Contains(newCategory, "intel") || strings.Contains(newCategory, "crim") || strings.Contains(newCategory, "ti") {
		categories.Intel.Count += 1
	} else if strings.Contains(newCategory, "sand") || strings.Contains(newCategory, "virus") || strings.Contains(newCategory, "malware") || strings.Contains(newCategory, "scan") || strings.Contains(newCategory, "edr") || strings.Contains(newCategory, "endpoint detection") {
		// Sandbox lol
		categories.EDR.Count += 1
	} else if strings.Contains(newCategory, "vuln") || strings.Contains(newCategory, "fim") || strings.Contains(newCategory, "fim") || strings.Contains(newCategory, "integrity") {
		categories.Assets.Count += 1
	} else if strings.Contains(newCategory, "network") || strings.Contains(newCategory, "firewall") || strings.Contains(newCategory, "waf") || strings.Contains(newCategory, "switch") {
		categories.Network.Count += 1
	} else {
		categories.Other.Count += 1
	}

	return categories
}

// Adds app auth tracking
func UpdateAppAuth(ctx context.Context, auth AppAuthenticationStorage, workflowId, nodeId string, add bool) error {
	workflowFound := false
	workflowIndex := 0
	nodeFound := false
	for index, workflow := range auth.Usage {
		if workflow.WorkflowId == workflowId {
			// Check if node exists
			workflowFound = true
			workflowIndex = index
			for _, actionId := range workflow.Nodes {
				if actionId == nodeId {
					nodeFound = true
					break
				}
			}

			break
		}
	}

	// FIXME: Add a way to use !add to remove
	updateAuth := false
	if !workflowFound && add {
		//log.Printf("[INFO] Adding workflow things to auth!")
		usageItem := AuthenticationUsage{
			WorkflowId: workflowId,
			Nodes:      []string{nodeId},
		}

		auth.Usage = append(auth.Usage, usageItem)
		auth.WorkflowCount += 1
		auth.NodeCount += 1
		updateAuth = true
	} else if !nodeFound && add {
		//log.Printf("[INFO] Adding node things to auth!")
		auth.Usage[workflowIndex].Nodes = append(auth.Usage[workflowIndex].Nodes, nodeId)
		auth.NodeCount += 1
		updateAuth = true
	}

	if updateAuth {
		//log.Printf("[INFO] Updating auth!")
		err := SetWorkflowAppAuthDatastore(ctx, auth, auth.Id)
		if err != nil {
			log.Printf("[WARNING] Failed UPDATING app auth %s: %s", auth.Id, err)
			return err
		}
	}

	return nil
}

func HandleApiGeneration(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	userInfo, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in apigen: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	//log.Printf("IN APIKEY GENERATION")
	ctx := getContext(request)
	if request.Method == "GET" {
		newUserInfo, err := GenerateApikey(ctx, userInfo)
		if err != nil {
			log.Printf("[WARNING] Failed to generate apikey for user %s: %s", userInfo.Username, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": ""}`))
			return
		}

		userInfo = newUserInfo
		log.Printf("[INFO] Updated apikey for user %s", userInfo.Username)
	} else if request.Method == "POST" {
		if request.Body == nil {
			resp.WriteHeader(http.StatusBadRequest)
			return
		}

		body, err := ioutil.ReadAll(request.Body)
		if err != nil {
			log.Println("Failed reading body")
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Missing field: user_id"}`)))
			return
		}

		type userId struct {
			UserId string `json:"user_id"`
		}

		var t userId
		err = json.Unmarshal(body, &t)
		if err != nil {
			log.Printf("Failed unmarshaling userId: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unmarshaling. Missing field: user_id"}`)))
			return
		}

		log.Printf("[INFO] Handling post for APIKEY gen FROM user %s. Userchange: %s!", userInfo.Username, t.UserId)

		if userInfo.Role != "admin" {
			log.Printf("[AUDIT] %s tried and failed to change apikey for %s (2)", userInfo.Username, t.UserId)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "You need to be admin to change others' apikey"}`)))
			return
		}

		foundUser, err := GetUser(ctx, t.UserId)
		if err != nil {
			log.Printf("[INFO] Can't find user %s (apikey gen): %s", t.UserId, err)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false}`)))
			return
		}

		// FIXME: May not be good due to different roles in different organizations.
		if foundUser.Role == "admin" {
			log.Printf("[AUDIT] %s tried and failed to change apikey for %s. Skipping because users' role is admin", userInfo.Username, t.UserId)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't change the apikey of another admin"}`)))
			return
		}

		newUserInfo, err := GenerateApikey(ctx, *foundUser)
		if err != nil {
			log.Printf("Failed to generate apikey for user %s: %s", foundUser.Username, err)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
			return
		}

		foundUser = &newUserInfo

		resp.WriteHeader(200)
		resp.Write([]byte(fmt.Sprintf(`{"success": true, "username": "%s", "verified": %t, "apikey": "%s"}`, foundUser.Username, foundUser.Verified, foundUser.ApiKey)))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "username": "%s", "verified": %t, "apikey": "%s"}`, userInfo.Username, userInfo.Verified, userInfo.ApiKey)))
}

func HandleSettings(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	userInfo, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in settings: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "username": "%s", "verified": %t, "apikey": "%s"}`, userInfo.Username, userInfo.Verified, userInfo.ApiKey)))
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

	ctx := getContext(request)
	org, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Failed getting org in get users: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting org users"}`))
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
		} else {
			foundUser, err := GetUser(ctx, item.Id)
			if err == nil {
				// Only add IF the admin querying it has access, meaning only show what you yourself have access to
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

	ctx := getContext(request)
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
			log.Printf("FoundUser: %#v", foundUser.Orgs)
			for _, item := range foundUser.Orgs {
				if item == userInfo.ActiveOrg.Id {
					orgFound = true
					break
				}
			}
		}

		if !orgFound {
			log.Printf("[INFO] User %s is admin, but can't change user's password outside their own org.", userInfo.Id)
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

func SendHookResult(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in send hook results: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}
	_ = user

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

	if len(workflowId) != 32 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "message": "ID not valid"}`))
		return
	}

	ctx := getContext(request)
	hook, err := GetHook(ctx, workflowId)
	if err != nil {
		log.Printf("[WARNING] Failed getting hook %s (send): %s", workflowId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Body data error: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	log.Printf("SET the hook results for %s to %s", workflowId, body)
	// FIXME - set the hook result in the DB somehow as interface{}
	// FIXME - should the hook do the transform? Hmm

	b, err := json.Marshal(hook)
	if err != nil {
		log.Printf("Failed marshalling: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(b))
	return
}

func HandleGetHook(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get hook: %s", err)
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

		workflowId = location[4]
	}

	if len(workflowId) != 36 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "message": "ID not valid"}`))
		return
	}

	ctx := getContext(request)
	hook, err := GetHook(ctx, workflowId)
	if err != nil {
		log.Printf("[WARNING] Failed getting hook %s (get hook): %s", workflowId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Id != hook.Owner && user.Role != "scheduler" {
		log.Printf("Wrong user (%s) for hook %s", user.Username, hook.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	b, err := json.Marshal(hook)
	if err != nil {
		log.Printf("Failed marshalling: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(b))
	return
}

func GetSpecificWorkflow(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Removed check here as it may be a public workflow
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in getting specific workflow: %s. Continuing because it may be public.", err)
	}

	location := strings.Split(request.URL.String(), "/")

	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	if strings.Contains(fileId, "?") {
		fileId = strings.Split(fileId, "?")[0]
	}

	if len(fileId) != 36 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID when getting workflow is not valid"}`))
		return
	}

	ctx := getContext(request)
	workflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Workflow %s doesn't exist.", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Item already exists."}`))
		return
	}

	//log.Printf("\n\nGetting workflow %s. Data: %#v\nPublic: %#v\n", fileId, workflow, workflow.Public)

	// CHECK orgs of user, or if user is owner
	// FIXME - add org check too, and not just owner
	// Check workflow.Sharing == private / public / org  too
	if user.Id != workflow.Owner || len(user.Id) == 0 {
		// Added org-reader as the user should be able to read everything in an org
		if workflow.OrgId == user.ActiveOrg.Id && (user.Role == "admin" || user.Role == "org-reader") {
			log.Printf("[AUDIT] User %s is accessing workflow %s as admin (get workflow)", user.Username, workflow.ID)
		} else if workflow.Public {
			log.Printf("[AUDIT] Letting user %s access workflow %s because it's public", user.Username, workflow.ID)
		} else if project.Environment == "cloud" && user.Verified == true && user.SupportAccess == true && user.Role == "admin" {
			log.Printf("[AUDIT] Letting verified support admin %s access workflow %s", user.Username, workflow.ID)
		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (get workflow)", user.Username, workflow.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	if len(workflow.Actions) == 0 {
		workflow.Actions = []Action{}
	}
	if len(workflow.Branches) == 0 {
		workflow.Branches = []Branch{}
	}
	if len(workflow.Triggers) == 0 {
		workflow.Triggers = []Trigger{}
	}
	if len(workflow.Errors) == 0 {
		workflow.Errors = []string{}
	}

	//for _, action := range workflow.Actions {
	//	log.Printf("Environment: %s", action.Environment)
	//}

	body, err := json.Marshal(workflow)
	if err != nil {
		log.Printf("Failed workflow GET marshalling: %s", err)
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(body)
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

	ctx := getContext(request)
	userId, err = url.QueryUnescape(userId)
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
		log.Printf("User %s is admin, but can't delete users outside their own org.", userInfo.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't change users outside your org."}`)))
		return
	}

	// Invert. No user deletion.
	if foundUser.Active {

		foundUser.Active = false
	} else {
		foundUser.Active = true
	}

	err = SetUser(ctx, foundUser, true)
	if err != nil {
		log.Printf("Failed swapping active for user %s (%s)", foundUser.Username, foundUser.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false}`)))
		return
	}

	log.Printf("[INFO] Successfully inverted activation for %s", foundUser.Username)

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

// Only used for onprem :/
func UpdateWorkflowAppConfig(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("Api authentication failed in get all apps: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to edit apps")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")
	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	ctx := getContext(request)
	app, err := GetApp(ctx, fileId, user, false)
	if err != nil {
		log.Printf("[WARNING] Error getting app (update app): %s", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Id != app.Owner {
		log.Printf("[WARNING] Wrong user (%s) for app %s in update app", user.Username, app.Name)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Error with body read in update app: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Public means it's literally public to anyone right away.
	type updatefields struct {
		Sharing       bool   `json:"sharing"`
		SharingConfig string `json:"sharing_config"`
		Public        bool   `json:"public"`
	}

	var tmpfields updatefields
	err = json.Unmarshal(body, &tmpfields)
	if err != nil {
		log.Printf("[WARNING] Error with unmarshal body in update app: %s\n%s", err, string(body))
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if tmpfields.Sharing != app.Sharing {
		log.Printf("[INFO] Changing app sharing for %s to %#v", app.ID, tmpfields.Sharing)
		app.Sharing = tmpfields.Sharing

		if project.Environment != "cloud" {
			log.Printf("[INFO] Set app %s to share everywhere (PUBLIC=true/false), because running onprem", app.Name, app.ID)
			app.Public = app.Sharing
		}
	}

	if tmpfields.SharingConfig != app.SharingConfig {
		log.Printf("[INFO] Changing app sharing CONFIG for %s to %s", app.ID, tmpfields.SharingConfig)
		app.SharingConfig = tmpfields.SharingConfig
	}

	if tmpfields.Public != app.Public {
		log.Printf("[INFO] Changing app %s to PUBLIC (THIS IS DEACTIVATED!)", app.ID)
		//app.Public = tmpfields.Public
	}

	err = SetWorkflowAppDatastore(ctx, *app, app.ID)
	if err != nil {
		log.Printf("[WARNING] Failed patching workflowapp: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	changed := false
	for index, privateApp := range user.PrivateApps {
		if privateApp.ID == app.ID {
			user.PrivateApps[index] = *app
			changed = true
			break
		}
	}

	if changed {
		err = SetUser(ctx, &user, true)
		if err != nil {
			log.Printf("[WARNING] Failed updating privateapp %s for user %s: %s", app.ID, user.Username, err)
		}
	}

	cacheKey := fmt.Sprintf("workflowapps-sorted-100")
	DeleteCache(ctx, cacheKey)
	cacheKey = fmt.Sprintf("workflowapps-sorted-500")
	DeleteCache(ctx, cacheKey)
	cacheKey = fmt.Sprintf("workflowapps-sorted-1000")
	DeleteCache(ctx, cacheKey)
	DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))

	log.Printf("[INFO] Changed App configuration for %s (%s)", app.Name, app.ID)
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true}`)))
}

func deactivateApp(ctx context.Context, user User, app *WorkflowApp) error {
	//log.Printf("Should deactivate app %#v\n for user %s", app, user)
	org, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[DEBUG] Failed getting org %s: %s", user.ActiveOrg.Id, err)
		return err
	}

	if !ArrayContains(org.ActiveApps, app.ID) {
		log.Printf("[WARNING] App %s isn't active for org %s", app.ID, user.ActiveOrg.Id)
		return errors.New(fmt.Sprintf("App %s isn't active for this org.", app.ID))
	}

	newApps := []string{}
	for _, appId := range org.ActiveApps {
		if appId == app.ID {
			continue
		}

		newApps = append(newApps, appId)
	}

	org.ActiveApps = newApps
	err = SetOrg(ctx, *org, org.Id)
	if err != nil {
		log.Printf("[WARNING] Failed updating org (deactive app %s) %s: %s", app.ID, org.Id, err)
		return err
	}

	return nil
}

func DeleteWorkflowApp(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("[WARNING] Api authentication failed in delete app: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to delete apps: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")
	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	ctx := getContext(request)
	app, err := GetApp(ctx, fileId, user, false)
	if err != nil {
		log.Printf("[WARNING] Error getting app %s: %s", app.Name, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Id != app.Owner {
		if user.Role == "admin" && app.Owner == "" {
			log.Printf("[INFO] Anyone can edit %s (%s), since it doesn't have an owner (DELETE).", app.Name, app.ID)
		} else {
			if user.Role == "admin" {
				err = deactivateApp(ctx, user, app)
				if err == nil {
					log.Printf("[INFO] App %s was deactivated for org %s", app.ID, user.ActiveOrg.Id)
					DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-100"))
					DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-500"))
					DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-1000"))
					DeleteCache(ctx, "all_apps")
					DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
					DeleteCache(ctx, fmt.Sprintf("user_%s", user.Username))
					DeleteCache(ctx, fmt.Sprintf("user_%s", user.Id))
					resp.WriteHeader(200)
					resp.Write([]byte(`{"success": true}`))
					return
				}
			}

			log.Printf("[WARNING] Wrong user (%s) for app %s (%s) when DELETING app", user.Username, app.Name, app.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	if (app.Public || app.Sharing) && project.Environment == "cloud" {
		log.Printf("[WARNING] App %s being deleted is public. Shouldn't be allowed. Public: %#v, Sharing: %#v", app.Name, app.Public, app.Sharing)

		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't delete public apps. Stop sharing it first, then delete it."}`))
		return
	}

	// Not really deleting it, just removing from user cache
	var privateApps []WorkflowApp
	for _, item := range user.PrivateApps {
		if item.ID == fileId {
			continue
		}

		privateApps = append(privateApps, item)
	}

	user.PrivateApps = privateApps

	err = SetUser(ctx, &user, true)
	if err != nil {
		log.Printf("[WARNING] Failed removing %s app for user %s: %s", app.Name, user.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false"}`)))
		return
	}

	err = DeleteKey(ctx, "workflowapp", app.ID)
	if err != nil {
		log.Printf("[WARNING] Failed deleting %s (%s) for by %s: %s", app.Name, app.ID, user.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false"}`)))
		return
	}

	// This is getting stupid :)
	DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-100"))
	DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-500"))
	DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-1000"))
	DeleteCache(ctx, "all_apps")
	DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
	DeleteCache(ctx, fmt.Sprintf("user_%s", user.Username))
	DeleteCache(ctx, fmt.Sprintf("user_%s", user.Id))

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleKeyValueCheck(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	// Append: Checks if the value should be appended
	// WorkflowCheck: Checks if the value should only check for workflow in org, or entire org
	// Authorization: the Authorization to use
	// ExecutionRef: Ref for the execution
	// Values: The values to use
	type DataValues struct {
		App             string
		Actions         string
		ParameterNames  []string
		ParameterValues []string
	}

	type ReturnData struct {
		Append        bool         `json:"append"`
		WorkflowCheck bool         `json:"workflow_check"`
		Authorization string       `json:"authorization"`
		ExecutionRef  string       `json:"execution_ref"`
		OrgId         string       `json:"org_id"`
		Values        []DataValues `json:"values"`
	}

	//for key, value := range data.Apps {
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

	var tmpData ReturnData
	err = json.Unmarshal(body, &tmpData)
	if err != nil {
		log.Printf("Failed unmarshalling test: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if tmpData.OrgId != fileId {
		log.Printf("[INFO] OrgId %s and %s don't match", tmpData.OrgId, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "Organization ID's don't match"}`))
		return
	}

	ctx := getContext(request)

	org, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("[INFO] Organization doesn't exist: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	workflowExecution, err := GetWorkflowExecution(ctx, tmpData.ExecutionRef)
	if err != nil {
		log.Printf("[INFO] User can't edit the org")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "No permission to get execution"}`))
		return
	}

	if workflowExecution.Authorization != tmpData.Authorization {
		// Get the user?

		log.Printf("[INFO] Execution auth %s and %s don't match", workflowExecution.Authorization, tmpData.Authorization)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "Auth doesn't match"}`))
		return
	}

	if workflowExecution.Status != "EXECUTING" {
		log.Printf("[INFO] Workflow isn't executing and shouldn't be searching", workflowExecution.ExecutionId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "Workflow isn't executing"}`))
		return
	}

	if workflowExecution.ExecutionOrg != org.Id {
		log.Printf("[INFO] Org %s wasn't used to execute %s", org.Id, workflowExecution.ExecutionId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "Bad organization specified"}`))
		return
	}

	// Prepared for the future~
	if len(tmpData.Values) != 1 {
		log.Printf("[INFO] Filter data can only hande 1 value right now, not %d", len(tmpData.Values))
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "Can't handle multiple apps yet, just one"}`))
		return
	}

	value := tmpData.Values[0]

	// FIXME: Alphabetically sort the parameternames
	// FIXME: Add organization wide search, not just workflow based

	found := []string{}
	notFound := []string{}

	dbKey := fmt.Sprintf("app_execution_values")
	parameterNames := fmt.Sprintf("%s_%s", value.App, strings.Join(value.ParameterNames, "_"))
	log.Printf("[INFO] PARAMNAME: %s", parameterNames)
	if tmpData.WorkflowCheck {
		// FIXME: Make this alphabetical
		for _, value := range value.ParameterValues {
			if len(value) == 0 {
				log.Printf("Shouldn't have value of length 0!")
				continue
			}

			log.Printf("[INFO] Looking for value %s in Workflow %s of ORG %s", value, workflowExecution.Workflow.ID, org.Id)

			executionValues, err := GetAppExecutionValues(ctx, parameterNames, org.Id, workflowExecution.Workflow.ID, value)
			if err != nil {
				log.Printf("[WARNING] Failed getting key %s: %s", dbKey, err)
				notFound = append(notFound, value)
				//found = append(found, value)
				continue
			}

			foundCount := len(executionValues)

			if foundCount > 0 {
				found = append(found, value)
			} else {
				log.Printf("[INFO] Found for %s: %d", dbKey, foundCount)
				notFound = append(notFound, value)
			}
		}
	} else {
		log.Printf("[INFO] Should validate if value %s is in workflow id %s", value, workflowExecution.Workflow.ID)
		for _, value := range value.ParameterValues {
			if len(value) == 0 {
				log.Printf("Shouldn't have value of length 0!")
				continue
			}

			log.Printf("[INFO] Looking for value %s in ORG %s", value, org.Id)

			executionValues, err := GetAppExecutionValues(ctx, parameterNames, org.Id, workflowExecution.Workflow.ID, value)
			if err != nil {
				log.Printf("[WARNING] Failed getting key %s: %s", dbKey, err)
				notFound = append(notFound, value)
				//found = append(found, value)
				continue
			}

			foundCount := len(executionValues)

			if foundCount > 0 {
				found = append(found, value)
			} else {
				log.Printf("[INFO] Found for %s: %d", dbKey, foundCount)
				notFound = append(notFound, value)
			}
		}
	}

	//App             string
	//Actions         string
	//ParameterNames  string
	//ParamererValues []string

	appended := 0
	if tmpData.Append {
		log.Printf("[INFO] Should append %d value(s) in K:V for %s_%s!", len(notFound), org.Id, workflowExecution.ExecutionId)

		//parameterNames := strings.Join(value.ParameterNames, "_")
		for _, notFoundValue := range notFound {
			newRequest := NewValue{
				OrgId:               org.Id,
				WorkflowExecutionId: workflowExecution.ExecutionId,
				ParameterName:       parameterNames,
				Value:               notFoundValue,
			}

			// WorkflowId:          workflowExecution.Workflow.Id,
			if tmpData.WorkflowCheck {
				newRequest.WorkflowId = workflowExecution.Workflow.ID
			}

			err = SetNewValue(ctx, newRequest)
			if err != nil {
				log.Printf("Error adding %s to appvalue: %s", notFoundValue, err)
				continue
			}

			appended += 1
			log.Printf("[INFO] Added %s as new appvalue to datastore", notFoundValue)
		}
	}

	type returnStruct struct {
		Success  bool     `json:"success"`
		Appended int      `json:"appended"`
		Found    []string `json:"found"`
	}

	returnData := returnStruct{
		Success:  true,
		Appended: appended,
		Found:    found,
	}

	b, _ := json.Marshal(returnData)
	resp.WriteHeader(200)
	resp.Write(b)
}

// Used for swapping your own organization to a new one IF it's eligible
func HandleChangeUserOrg(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed change org: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	//if user.Role != "admin" {
	//	log.Printf("Not admin.")
	//	resp.WriteHeader(401)
	//	resp.Write([]byte(`{"success": false, "reason": "Not admin"}`))
	//	return
	//}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	type ReturnData struct {
		OrgId string `json:"org_id" datastore:"org_id"`
		//Name  string `json:"name" datastore:"name"`
	}

	var tmpData ReturnData
	err = json.Unmarshal(body, &tmpData)
	if err != nil {
		log.Printf("Failed unmarshalling test: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
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

	ctx := getContext(request)
	foundOrg := false
	for _, org := range user.Orgs {
		if org == tmpData.OrgId {
			foundOrg = true
			break
		}
	}

	if !foundOrg || tmpData.OrgId != fileId {
		log.Printf("[WARNING] User swap to the org \"%s\" - access denied", tmpData.OrgId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "No permission to change to this org"}`))
		return
	}

	org, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("[WARNING] Organization %s doesn't exist: %s", tmpData.OrgId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	userFound := false
	usr := User{}
	for _, orgUsr := range org.Users {
		//log.Printf("Usr: %#v", orgUsr)
		if user.Id == orgUsr.Id {
			usr = orgUsr
			userFound = true
			break
		}
	}

	if !userFound {
		log.Printf("[WARNING] User can't edit the org \"%s\" (2)", tmpData.OrgId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "No permission to edit this org"}`))
		return
	}

	user.ActiveOrg = OrgMini{
		Name: org.Name,
		Id:   org.Id,
		Role: usr.Role,
	}

	user.Role = usr.Role

	err = SetUser(ctx, &user, false)
	if err != nil {
		log.Printf("[WARNING] Failed updating user when changing org: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Cleanup cache for the user
	cacheKey := fmt.Sprintf("%s_workflows", user.Id)
	DeleteCache(ctx, cacheKey)
	cacheKey = fmt.Sprintf("apps_%s", user.Id)
	DeleteCache(ctx, cacheKey)
	DeleteCache(ctx, fmt.Sprintf("user_%s", user.Username))
	DeleteCache(ctx, fmt.Sprintf("user_%s", user.Id))

	log.Printf("[INFO] User %s (%s) successfully changed org to %s (%s)", user.Username, user.Id, org.Name, org.Id)
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Successfully updated user"}`)))

}

func HandleCreateSubOrg(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in creating sub org: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role != "admin" {
		log.Printf("[WARNING] Not admin: %s (%s).", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Not admin"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	type ReturnData struct {
		OrgId string `json:"org_id" datastore:"org_id"`
		Name  string `json:"name" datastore:"name"`
	}

	var tmpData ReturnData
	err = json.Unmarshal(body, &tmpData)
	if err != nil {
		log.Printf("Failed unmarshalling test: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(tmpData.Name) < 3 {
		log.Printf("[WARNING] Suborgname too short (min 3) %s", tmpData.Name)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Name must at least be 3 characters."}`))
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

	if tmpData.OrgId != user.ActiveOrg.Id || fileId != user.ActiveOrg.Id {
		log.Printf("[WARNING] User can't edit the org \"%s\"", tmpData.OrgId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "No permission to edit this org"}`))
		return
	}

	ctx := getContext(request)
	parentOrg, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("[WARNING] Organization %s doesn't exist: %s", tmpData.OrgId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(parentOrg.ManagerOrgs) > 0 {
		log.Printf("[WARNING] Organization %s can't have suborgs, as it's as suborg: %s", tmpData.OrgId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't make suborg of suborg."}`))
		return
	}

	if project.Environment == "cloud" {
		if !parentOrg.SyncFeatures.MultiTenant.Active {
			log.Printf("[WARNING] Org %s is not allowed to make a sub-organization: %s", tmpData.OrgId, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Sub-organizations require an active subscription with access to multi-tenancy. Contact support to try it out."}`))
			return
		}

		if parentOrg.SyncUsage.MultiTenant.Counter >= parentOrg.SyncFeatures.MultiTenant.Limit || len(parentOrg.ChildOrgs) > int(parentOrg.SyncFeatures.MultiTenant.Limit) {
			log.Printf("[WARNING] Org %s is not allowed to make ANOTHER sub-organization. Limit reached!: %s", tmpData.OrgId, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Your limit of sub-organizations has been reached. Contact support to increase."}`))
			return
		}

		parentOrg.SyncUsage.MultiTenant.Counter += 1
		log.Printf("[DEBUG] Allowing suborg for %s because they have %d vs %d limit", parentOrg.Id, len(parentOrg.ChildOrgs), parentOrg.SyncFeatures.MultiTenant.Limit)
	}

	orgId := uuid.NewV4().String()
	newOrg := Org{
		Name:        tmpData.Name,
		Description: fmt.Sprintf("Sub-org by user %s in parent-org %s", user.Username, parentOrg.Name),
		Image:       parentOrg.Image,
		Id:          orgId,
		Org:         tmpData.Name,
		Users: []User{
			user,
		},
		Roles:     []string{"admin", "user"},
		CloudSync: false,
		ManagerOrgs: []OrgMini{
			OrgMini{
				Id:   tmpData.OrgId,
				Name: parentOrg.Name,
			},
		},
		SyncFeatures:    parentOrg.SyncFeatures,
		CloudSyncActive: parentOrg.CloudSyncActive,
		CreatorOrg:      tmpData.OrgId,
	}

	parentOrg.ChildOrgs = append(parentOrg.ChildOrgs, OrgMini{
		Name: tmpData.Name,
		Id:   orgId,
	})

	err = SetOrg(ctx, newOrg, newOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Failed setting new org %s: %s", newOrg.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	err = SetOrg(ctx, *parentOrg, parentOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Failed updating parent org %s: %s", newOrg.Id, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Update all admins to have access to this suborg
	for _, loopUser := range parentOrg.Users {
		if loopUser.Role != "admin" {
			continue
		}

		if loopUser.Id == user.Id {
			continue
		}

		foundUser, err := GetUser(ctx, loopUser.Id)
		if err != nil {
			log.Printf("[WARNING] User with Identifier %s doesn't exist: %s (update admins - create)", loopUser.Id, err)
			continue
		}

		foundUser.Orgs = append(foundUser.Orgs, newOrg.Id)
		err = SetUser(ctx, foundUser, false)
		if err != nil {
			log.Printf("[WARNING] Failed updating user when setting creating suborg (update admins - update): %s ", err)
			continue
		}
	}

	user.Orgs = append(user.Orgs, newOrg.Id)
	log.Printf("[INFO] Usr: %#v (%d)", user.Orgs, len(user.Orgs))
	err = SetUser(ctx, &user, false)
	if err != nil {
		log.Printf("[WARNING] Failed updating user when setting creating suborg: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	log.Printf("[INFO] User %s SUCCESSFULLY ADDED child org %s (%s) for parent %s (%s)", user.Username, newOrg.Name, newOrg.Id, parentOrg.Name, parentOrg.Id)
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Successfully updated org"}`)))

}

func HandleEditOrg(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in edit org: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role != "admin" {
		log.Printf("[WARNING] Not admin: %s (%s).", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Not admin"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	type ReturnData struct {
		Image       string    `json:"image" datastore:"image"`
		Name        string    `json:"name" datastore:"name"`
		Description string    `json:"description" datastore:"description"`
		OrgId       string    `json:"org_id" datastore:"org_id"`
		Defaults    Defaults  `json:"defaults" datastore:"defaults"`
		SSOConfig   SSOConfig `json:"sso_config" datastore:"sso_config"`
	}

	var tmpData ReturnData
	err = json.Unmarshal(body, &tmpData)
	if err != nil {
		log.Printf("Failed unmarshalling test: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}
	//log.Printf("SSO: %#v", tmpData.SSOConfig)

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

	if tmpData.OrgId != user.ActiveOrg.Id || fileId != user.ActiveOrg.Id {
		log.Printf("User can't edit the org")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "No permission to edit this org"}`))
		return
	}

	ctx := getContext(request)
	org, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("Organization doesn't exist: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	admin := false
	userFound := false
	for _, inneruser := range org.Users {
		if inneruser.Id == user.Id {
			userFound = true
			if inneruser.Role == "admin" {
				admin = true
			}

			break
		}
	}

	if !userFound {
		log.Printf("User %s doesn't exist in organization for edit %s", user.Id, org.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if !admin {
		log.Printf("User %s doesn't have edit rights to %s", user.Id, org.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	org.Image = tmpData.Image
	org.Name = tmpData.Name
	org.Description = tmpData.Description
	org.Defaults = tmpData.Defaults

	savedCert := fixCertificate(tmpData.SSOConfig.SSOCertificate)

	log.Printf("[INFO] Stripped down cert from %d to %d", len(tmpData.SSOConfig.SSOCertificate), len(savedCert))

	org.SSOConfig = tmpData.SSOConfig
	org.SSOConfig.SSOCertificate = savedCert

	if len(org.Defaults.NotificationWorkflow) > 0 && len(org.Defaults.NotificationWorkflow) != 36 {
		log.Printf("[WARNING] Notification Workflow ID %s is not valid.", org.Defaults.NotificationWorkflow)
	}

	// if requestdata.Environment == "cloud" && project.Environment != "cloud" {
	if project.Environment != "cloud" && len(org.SSOConfig.SSOEntrypoint) > 0 && len(org.ManagerOrgs) == 0 {
		log.Printf("[INFO] Should set SSO entrypoint to %s", org.SSOConfig.SSOEntrypoint)
		SSOUrl = org.SSOConfig.SSOEntrypoint
	}

	//log.Printf("Org: %#v", org)
	err = SetOrg(ctx, *org, org.Id)
	if err != nil {
		log.Printf("User %s doesn't have edit rights to %s", user.Id, org.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	log.Printf("[INFO] Successfully updated org %s (%s)", org.Name, org.Id)
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Successfully updated org"}`)))

}

func CheckWorkflowApp(workflowApp WorkflowApp) error {
	// Validate fields
	if workflowApp.Name == "" {
		return errors.New("App field name doesn't exist")
	}

	if workflowApp.Description == "" {
		return errors.New("App field description doesn't exist")
	}

	if workflowApp.AppVersion == "" {
		return errors.New("App field app_version doesn't exist")
	}

	if workflowApp.ContactInfo.Name == "" {
		return errors.New("App field contact_info.name doesn't exist")
	}

	return nil
}

func AbortExecution(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	//log.Printf("\n\nINSIDE ABORT\n\n")

	location := strings.Split(request.URL.String(), "/")
	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	if len(fileId) != 36 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID to abort is not valid"}`))
		return
	}

	executionId := location[6]
	if len(executionId) != 36 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "ExecutionID not valid"}`))
		return
	}

	ctx := getContext(request)
	workflowExecution, err := GetWorkflowExecution(ctx, executionId)
	if err != nil {
		log.Printf("[ERROR] Failed getting execution (abort) %s: %s", executionId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed getting execution ID %s because it doesn't exist (abort)."}`, executionId)))
		return
	}

	apikey := request.Header.Get("Authorization")
	parsedKey := ""
	if strings.HasPrefix(apikey, "Bearer ") {
		apikeyCheck := strings.Split(apikey, " ")
		if len(apikeyCheck) == 2 {
			parsedKey = apikeyCheck[1]
		}
	}

	// Checks the users' role and such if the key fails
	//log.Printf("Abort info: %#v vs %#v", workflowExecution.Authorization, parsedKey)
	if workflowExecution.Authorization != parsedKey {
		user, err := HandleApiAuthentication(resp, request)
		if err != nil {
			log.Printf("[AUDIT] Api authentication failed in abort workflow: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		//log.Printf("User: %s, org: %s vs %s", user.Role, workflowExecution.Workflow.OrgId, user.ActiveOrg.Id)
		if user.Id != workflowExecution.Workflow.Owner {
			if workflowExecution.Workflow.OrgId == user.ActiveOrg.Id && user.Role == "admin" {
				log.Printf("[AUDIT] User %s is aborting execution %s as admin", user.Username, workflowExecution.Workflow.ID)
			} else {
				log.Printf("[AUDIT] Wrong user (%s) for ABORT of workflowexecution workflow %s", user.Username, workflowExecution.Workflow.ID)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false}`))
				return
			}
		}
	} else {
		//log.Printf("[INFO] API key to abort/finish execution %s is correct.", executionId)
	}

	if workflowExecution.Status == "ABORTED" || workflowExecution.Status == "FAILURE" || workflowExecution.Status == "FINISHED" {
		//err = SetWorkflowExecution(ctx, *workflowExecution, true)
		//if err != nil {
		//}
		log.Printf("[INFO] Stopped execution of %s with status %s", executionId, workflowExecution.Status)
		if len(workflowExecution.ExecutionParent) > 0 {
		}

		//ExecutionSource    string         `json:"execution_source" datastore:"execution_source"`
		//ExecutionParent    string         `json:"execution_parent" datastore:"execution_parent"`

		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Status for %s is %s, which can't be aborted."}`, executionId, workflowExecution.Status)))
		return
	}

	topic := "workflowexecution"

	workflowExecution.CompletedAt = int64(time.Now().Unix())
	workflowExecution.Status = "ABORTED"
	log.Printf("[INFO] Running shutdown (abort) of execution %s", workflowExecution.ExecutionId)

	lastResult := ""
	newResults := []ActionResult{}
	// type ActionResult struct {
	for _, result := range workflowExecution.Results {
		if result.Status == "EXECUTING" {
			result.Status = "ABORTED"
			result.Result = "Aborted because of error in another node (1)"
		}

		if len(result.Result) > 0 {
			lastResult = result.Result
		}

		newResults = append(newResults, result)
	}

	workflowExecution.Results = newResults
	if len(workflowExecution.Result) == 0 {
		workflowExecution.Result = lastResult
	}

	addResult := true
	for _, result := range workflowExecution.Results {
		if result.Status != "SKIPPED" {
			addResult = false
		}
	}

	extra := 0
	for _, trigger := range workflowExecution.Workflow.Triggers {
		//log.Printf("Appname trigger (0): %s", trigger.AppName)
		if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
			extra += 1
		}
	}

	parsedReason := "An error occurred during execution of this node"
	reason, reasonok := request.URL.Query()["reason"]
	if reasonok {
		parsedReason = reason[0]
	}

	if len(workflowExecution.Results) == 0 || addResult {
		newaction := Action{
			ID: workflowExecution.Start,
		}

		for _, action := range workflowExecution.Workflow.Actions {
			if action.ID == workflowExecution.Start {
				newaction = action
				break
			}
		}

		workflowExecution.Results = append(workflowExecution.Results, ActionResult{
			Action:        newaction,
			ExecutionId:   workflowExecution.ExecutionId,
			Authorization: workflowExecution.Authorization,
			Result:        parsedReason,
			StartedAt:     workflowExecution.StartedAt,
			CompletedAt:   workflowExecution.StartedAt,
			Status:        "FAILURE",
		})
	} else if len(workflowExecution.Results) >= len(workflowExecution.Workflow.Actions)+extra {
		log.Printf("[INFO] DONE - Nothing to add during abort!")
	} else {
		//log.Printf("VALIDATING INPUT!")
		node, nodeok := request.URL.Query()["node"]
		if nodeok {
			nodeId := node[0]
			log.Printf("[INFO] Found abort node %s", nodeId)
			newaction := Action{
				ID: nodeId,
			}

			// Check if result exists first
			found := false
			for _, result := range workflowExecution.Results {
				if result.Action.ID == nodeId {
					found = true
					break
				}
			}

			if !found {
				for _, action := range workflowExecution.Workflow.Actions {
					if action.ID == nodeId {
						newaction = action
						break
					}
				}

				workflowExecution.Results = append(workflowExecution.Results, ActionResult{
					Action:        newaction,
					ExecutionId:   workflowExecution.ExecutionId,
					Authorization: workflowExecution.Authorization,
					Result:        parsedReason,
					StartedAt:     workflowExecution.StartedAt,
					CompletedAt:   workflowExecution.StartedAt,
					Status:        "FAILURE",
				})
			}
		}
	}

	for resultIndex, result := range workflowExecution.Results {
		for parameterIndex, param := range result.Action.Parameters {
			if param.Configuration {
				workflowExecution.Results[resultIndex].Action.Parameters[parameterIndex].Value = ""
			}
		}
	}

	for actionIndex, action := range workflowExecution.Workflow.Actions {
		for parameterIndex, param := range action.Parameters {
			if param.Configuration {
				//log.Printf("Cleaning up %s in %s", param.Name, action.Name)
				workflowExecution.Workflow.Actions[actionIndex].Parameters[parameterIndex].Value = ""
			}
		}
	}

	err = SetWorkflowExecution(ctx, *workflowExecution, true)
	if err != nil {
		log.Printf("[WARNING] Error saving workflow execution for updates when aborting %s: %s", topic, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed setting workflowexecution status to abort"}`)))
		return
	} else {
		log.Printf("[INFO] Set workflowexecution %s to aborted.", workflowExecution.ExecutionId)
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true}`)))
}

func SanitizeWorkflow(workflow Workflow) Workflow {
	log.Printf("[INFO] Sanitizing workflow %s", workflow.ID)

	for _, trigger := range workflow.Triggers {
		_ = trigger
	}

	for _, action := range workflow.Actions {
		_ = action
	}

	for _, variable := range workflow.WorkflowVariables {
		_ = variable
	}

	workflow.Owner = ""
	workflow.Org = []OrgMini{}
	workflow.OrgId = ""
	workflow.ExecutingOrg = OrgMini{}
	workflow.PreviouslySaved = false

	// Add Gitguardian or similar secrets discovery
	return workflow
}

// Starts a new webhook
func HandleNewHook(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in set new hook: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to make new hook: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	type requestData struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		Id          string `json:"id"`
		Name        string `json:"name"`
		Workflow    string `json:"workflow"`
		Start       string `json:"start"`
		Environment string `json:"environment"`
		Auth        string `json:"auth"`
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Body data error in webhook set: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := getContext(request)
	var requestdata requestData
	err = yaml.Unmarshal([]byte(body), &requestdata)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling inputdata for webhook: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	newId := requestdata.Id
	if len(newId) != 36 {
		log.Printf("[WARNING] Bad webhook ID: %s", newId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Invalid Webhook ID: bad formatting"}`))
		return
	}

	if requestdata.Id == "" || requestdata.Name == "" {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Required fields id and name can't be empty"}`))
		return

	}

	validTypes := []string{
		"webhook",
	}

	isTypeValid := false
	for _, thistype := range validTypes {
		if requestdata.Type == thistype {
			isTypeValid = true
			break
		}
	}

	if !(isTypeValid) {
		log.Printf("Type %s is not valid. Try any of these: %s", requestdata.Type, strings.Join(validTypes, ", "))
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Let remote endpoint handle access checks (shuffler.io)
	currentUrl := fmt.Sprintf("https://shuffler.io/api/v1/hooks/webhook_%s", newId)
	startNode := requestdata.Start
	if requestdata.Environment == "cloud" && project.Environment != "cloud" {
		// https://shuffler.io/v1/hooks/webhook_80184973-3e82-4852-842e-0290f7f34d7c
		log.Printf("[INFO] Should START a cloud webhook for url %s for startnode %s", currentUrl, startNode)
		org, err := GetOrg(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("Failed finding org %s: %s", org.Id, err)
			return
		}

		action := CloudSyncJob{
			Type:          "webhook",
			Action:        "start",
			OrgId:         org.Id,
			PrimaryItemId: newId,
			SecondaryItem: startNode,
			ThirdItem:     requestdata.Workflow,
			FourthItem:    requestdata.Auth,
		}

		err = executeCloudAction(action, org.SyncConfig.Apikey)
		if err != nil {
			log.Printf("[WARNING] Failed cloud action START webhook execution: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
			return
		} else {
			log.Printf("[INFO] Successfully set up cloud action schedule")
		}
	}

	hook := Hook{
		Id:        newId,
		Start:     startNode,
		Workflows: []string{requestdata.Workflow},
		Info: Info{
			Name:        requestdata.Name,
			Description: requestdata.Description,
			Url:         fmt.Sprintf("https://shuffler.io/api/v1/hooks/webhook_%s", newId),
		},
		Type:   "webhook",
		Owner:  user.Username,
		Status: "uninitialized",
		Actions: []HookAction{
			HookAction{
				Type:  "workflow",
				Name:  requestdata.Name,
				Id:    requestdata.Workflow,
				Field: "",
			},
		},
		Running:     false,
		OrgId:       user.ActiveOrg.Id,
		Environment: requestdata.Environment,
		Auth:        requestdata.Auth,
	}

	hook.Status = "running"
	hook.Running = true
	err = SetHook(ctx, hook)
	if err != nil {
		log.Printf("[WARNING] Failed setting hook: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	log.Printf("[INFO] Set up a new hook with ID %s and environment %s", newId, hook.Environment)
	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleDeleteHook(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in delete hook: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to delete hook: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")

	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	if len(fileId) != 36 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID when deleting hook is not valid"}`))
		return
	}

	ctx := getContext(request)
	hook, err := GetHook(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Failed getting hook %s (delete): %s", fileId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Id != hook.Owner && user.ActiveOrg.Id != hook.OrgId {
		log.Printf("[WARNING] Wrong user (%s) for workflow %s", user.Username, hook.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(hook.Workflows) > 0 {
		//err = increaseStatisticsField(ctx, "total_workflow_triggers", hook.Workflows[0], -1, user.ActiveOrg.Id)
		//if err != nil {
		//	log.Printf("Failed to increase total workflows: %s", err)
		//}
	}

	hook.Status = "stopped"
	err = SetHook(ctx, *hook)
	if err != nil {
		log.Printf("[WARNING] Failed setting hook: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if hook.Environment == "cloud" && project.Environment != "cloud" {
		log.Printf("[INFO] Should STOP cloud webhook https://shuffler.io/api/v1/hooks/webhook_%s", hook.Id)
		org, err := GetOrg(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("Failed finding org %s: %s", org.Id, err)
			return
		}

		action := CloudSyncJob{
			Type:          "webhook",
			Action:        "stop",
			OrgId:         org.Id,
			PrimaryItemId: hook.Id,
		}

		if len(hook.Workflows) > 0 {
			action.SecondaryItem = hook.Workflows[0]
		}

		err = executeCloudAction(action, org.SyncConfig.Apikey)
		if err != nil {
			log.Printf("Failed cloud action STOP execution: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
			return
		}
		// https://shuffler.io/v1/hooks/webhook_80184973-3e82-4852-842e-0290f7f34d7c
	}

	err = DeleteKey(ctx, "hooks", fileId)
	if err != nil {
		log.Printf("[WARNING] Error deleting hook %s for %s: %s", fileId, user.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed deleting the hook."}`))
		return
	}

	log.Printf("[INFO] Successfully deleted webhook %s", fileId)
	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true, "reason": "Stopped webhook"}`))
}

func ParseVersions(versions []string) []string {
	log.Printf("Versions: %#v", versions)

	//versions = sort.Sort(semver.Collection(versions))
	return versions
}

func GetWorkflowAppConfig(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	ctx := getContext(request)

	location := strings.Split(request.URL.String(), "/")
	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	app, err := GetApp(ctx, fileId, User{}, false)
	if err != nil {
		log.Printf("[WARNING] Error getting app %s (app config): %s", fileId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "App doesn't exist"}`))
		return
	}

	//if IsValid       bool   `json:"is_valid" yaml:"is_valid" required:true datastore:"is_valid"`
	// Sharing       bool   `json:"sharing" yaml:"sharing" required:false datastore:"sharing"`
	//log.Printf("Sharing: %s", app.Sharing)
	//log.Printf("Generated: %s", app.Generated)
	//log.Printf("Downloaded: %s", app.Downloaded)

	type AppParser struct {
		Success bool   `json:"success"`
		OpenAPI []byte `json:"openapi"`
		App     []byte `json:"app"`
	}

	//app.Activate = true
	data, err := json.Marshal(app)
	if err != nil {
		resp.WriteHeader(422)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed marshalling new parsed APP: %s"}`, err)))
		return
	}

	appReturn := AppParser{
		Success: true,
		App:     data,
	}

	appdata, err := json.Marshal(appReturn)
	if err != nil {
		log.Printf("[WARNING] Error parsing appReturn for app (INIT): %s", err)
		resp.WriteHeader(422)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed marshalling: %s"}`, err)))
		return
	}

	user, userErr := HandleApiAuthentication(resp, request)
	//log.Printf("USER: %s", user.Id)

	openapi, openapiok := request.URL.Query()["openapi"]
	//if app.Sharing || app.Public || (project.Environment == "cloud" && user.Id == "what") {
	//log.Printf("SHARING: %#v. PUBLIC: %#v", app.Sharing, app.Public)
	if app.Sharing || app.Public {
		if openapiok && len(openapi) > 0 && strings.ToLower(openapi[0]) == "false" {
			log.Printf("Should return WITHOUT openapi")
		} else {
			//log.Printf("CAN SHARE APP!")
			parsedApi, err := GetOpenApiDatastore(ctx, fileId)
			if err != nil {
				log.Printf("[WARNING] OpenApi doesn't exist for (0): %s - err: %s. Returning basic app", fileId, err)
				resp.WriteHeader(200)
				resp.Write(appdata)
				return
			}

			if len(parsedApi.ID) > 0 {
				parsedApi.Success = true
			} else {
				parsedApi.Success = false
			}

			//log.Printf("PARSEDAPI: %#v", parsedApi)
			openapidata, err := json.Marshal(parsedApi)
			if err != nil {
				log.Printf("[WARNING] Error parsing api json: %s", err)
				resp.WriteHeader(422)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed marshalling new parsed swagger: %s"}`, err)))
				return
			}

			appReturn.OpenAPI = openapidata
		}

		appdata, err = json.Marshal(appReturn)
		if err != nil {
			log.Printf("[WARNING] Error parsing appReturn for app: %s", err)
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed marshalling: %s"}`, err)))
			return
		}

		resp.WriteHeader(200)
		resp.Write(appdata)
		return
	}

	if userErr != nil {
		log.Printf("[WARNING] Api authentication failed in get app: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Id != app.Owner {
		if user.Role == "admin" && app.Owner == "" {
			log.Printf("[AUDIT] Any admin can GET %s (%s), since it doesn't have an owner (GET).", app.Name, app.ID)
		} else {
			log.Printf("[AUDIT] Wrong user (%s) for app %s", user.Username, app.Name)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	if openapiok && len(openapi) > 0 && strings.ToLower(openapi[0]) == "false" {
		//log.Printf("Should return WITHOUT openapi")
	} else {
		log.Printf("[INFO] Getting app %s (OpenAPI)", fileId)
		parsedApi, err := GetOpenApiDatastore(ctx, fileId)
		if err != nil {
			log.Printf("[INFO] OpenApi doesn't exist for (1): %s - err: %s. Returning basic app.", fileId, err)
			resp.WriteHeader(200)
			resp.Write(appdata)
			return
		}

		//log.Printf("Parsed API: %#v", parsedApi)
		if len(parsedApi.ID) > 0 {
			parsedApi.Success = true
		} else {
			parsedApi.Success = false
		}

		openapidata, err := json.Marshal(parsedApi)
		if err != nil {
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed marshalling new parsed swagger: %s"}`, err)))
			return
		}

		appReturn.OpenAPI = openapidata
	}
	log.Printf("5")

	appdata, err = json.Marshal(appReturn)
	if err != nil {
		log.Printf("[WARNING] Error parsing appReturn for app: %s", err)
		resp.WriteHeader(422)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed marshalling: %s"}`, err)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(appdata)
}

func HandleLogin(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Gets a struct of Username, password
	data, err := ParseLoginParameters(resp, request)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
		return
	}

	log.Printf("[INFO] Handling login of %s", data.Username)

	data.Username = strings.ToLower(strings.TrimSpace(data.Username))
	err = checkUsername(data.Username)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
		return
	}

	ctx := getContext(request)
	users, err := FindUser(ctx, data.Username)
	if err != nil && len(users) == 0 {
		log.Printf("[WARNING] Failed getting user %s during login", data.Username)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Username and/or password is incorrect"}`))
		return
	}

	if len(users) > 1 {
		log.Printf("[WARNING] Username %s has multiple users (%d). Checking if it matches any.", data.Username, len(users))
	}

	userdata := User{}
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

	if userdata.Id == "" && userdata.Username == "" {
		log.Printf(`[WARNING] Username %s isn't valid. Amount of users checked: %d (2)`, data.Username, len(users))
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Username and/or password is incorrect"}`)))
		return
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

	if userdata.LoginType == "SSO" {
		log.Printf(`[WARNING] Username %s (%s) has login type set to SSO (single sign-on).`, userdata.Username, userdata.Id)
		//resp.WriteHeader(401)
		//resp.Write([]byte(`{"success": false, "reason": "This user can only log in with SSO"}`))
		//return
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

	loginData := `{"success": true}`
	if len(userdata.Session) != 0 {
		log.Println("[INFO] User session exists - resetting session")
		expiration := time.Now().Add(3600 * time.Second)

		http.SetCookie(resp, &http.Cookie{
			Name:    "session_token",
			Value:   userdata.Session,
			Expires: expiration,
		})

		//log.Printf("SESSION LENGTH MORE THAN 0 IN LOGIN: %s", userdata.Session)
		loginData = fmt.Sprintf(`{"success": true, "cookies": [{"key": "session_token", "value": "%s", "expiration": %d}]}`, userdata.Session, expiration.Unix())
		err = SetSession(ctx, userdata, userdata.Session)
		if err != nil {
			log.Printf("[WARNING] Error adding session to database: %s", err)
		} else {
			//log.Printf("[DEBUG] Updated session in backend")
		}

		resp.WriteHeader(200)
		resp.Write([]byte(loginData))
		return
	} else {
		log.Printf("[INFO] User session is empty - create one!")

		sessionToken := uuid.NewV4().String()
		expiration := time.Now().Add(3600 * time.Second)
		http.SetCookie(resp, &http.Cookie{
			Name:    "session_token",
			Value:   sessionToken,
			Expires: expiration,
		})

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

		loginData = fmt.Sprintf(`{"success": true, "cookies": [{"key": "session_token", "value": "%s", "expiration": %d}]}`, sessionToken, expiration.Unix())
	}

	log.Printf("[INFO] %s SUCCESSFULLY LOGGED IN with session %s", data.Username, userdata.Session)

	resp.WriteHeader(200)
	resp.Write([]byte(loginData))
}

func ParseLoginParameters(resp http.ResponseWriter, request *http.Request) (loginStruct, error) {
	if request.Body == nil {
		return loginStruct{}, errors.New("Failed to parse loing params, body is empty")
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

// Handles workflow executions across systems (open source, worker, cloud)
// getWorkflow
// GetWorkflow
// executeWorkflow

// This should happen locally.. Meaning, polling may be stupid.
// Let's do it anyway, since it seems like the best way to scale
// without remoting problems and the like.
func updateExecutionParent(executionParent, returnValue, parentAuth, parentNode string) error {
	log.Printf("[INFO] PARENTEXEC: %s, AUTH: %s, parentNode: %s, VALUE: %s", executionParent, parentAuth, parentNode, returnValue)

	// Was an error here. Now defined to run with http://shuffle-backend:5001 by default
	backendUrl := os.Getenv("BASE_URL")
	if project.Environment == "cloud" {
		//backendUrl = "https://729d-84-214-96-67.ngrok.io"
		backendUrl = "https://shuffler.io"
	}

	// FIXME: This MAY fail at scale due to not being able to get the right worker
	// Maybe we need to pass the worker's real id, and not its VIP?
	if os.Getenv("SHUFFLE_SWARM_CONFIG") == "run" && (project.Environment == "" || project.Environment == "worker") {
		backendUrl = "http://shuffle-workers:33333"
		log.Printf("\n\n[DEBUG] Sending request for shuffle-subflow result to %s\n\n", backendUrl)
	}

	// Callback to itself
	if len(backendUrl) == 0 {
		backendUrl = "http://localhost:5001"
	}

	resultUrl := fmt.Sprintf("%s/api/v1/streams/results", backendUrl)
	//log.Printf("[DEBUG] ResultURL: %s", backendUrl)
	topClient := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}
	newExecution := WorkflowExecution{}

	httpProxy := os.Getenv("HTTP_PROXY")
	httpsProxy := os.Getenv("HTTPS_PROXY")
	if len(httpProxy) > 0 || len(httpsProxy) > 0 {
		topClient = &http.Client{}
	} else {
		if len(httpProxy) > 0 {
			log.Printf("Running with HTTP proxy %s (env: HTTP_PROXY)", httpProxy)
		}
		if len(httpsProxy) > 0 {
			log.Printf("Running with HTTPS proxy %s (env: HTTPS_PROXY)", httpsProxy)
		}
	}

	requestData := ActionResult{
		Authorization: parentAuth,
		ExecutionId:   executionParent,
	}

	data, err := json.Marshal(requestData)
	if err != nil {
		log.Printf("[WARNING] Failed parent init marshal: %s", err)
		return err
	}

	req, err := http.NewRequest(
		"POST",
		resultUrl,
		bytes.NewBuffer([]byte(data)),
	)

	newresp, err := topClient.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed making parent request: %s. Is URL valid: %s", err, backendUrl)
		return err
	}

	body, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading parent body: %s", err)
		return err
	}
	//log.Printf("BODY (%d): %s", newresp.StatusCode, string(body))

	if newresp.StatusCode != 200 {
		log.Printf("[ERROR] Bad statuscode setting subresult: %d, %s", newresp.StatusCode, string(body))
		return errors.New(fmt.Sprintf("Bad statuscode: %s", newresp.StatusCode))
	}

	err = json.Unmarshal(body, &newExecution)
	if err != nil {
		log.Printf("[ERROR] Failed newexecutuion parent unmarshal: %s", err)
		return err
	}

	foundResult := ActionResult{}
	for _, result := range newExecution.Results {
		if result.Action.ID == parentNode {
			foundResult = result
			break
		}
	}

	//log.Printf("FOUND RESULT: %#v", foundResult)
	isLooping := false
	selectedTrigger := Trigger{}
	for _, trigger := range newExecution.Workflow.Triggers {
		if trigger.ID == parentNode {
			selectedTrigger = trigger
			for _, param := range trigger.Parameters {
				if param.Name == "argument" && strings.Contains(param.Value, ".#") {
					isLooping = true
					break
				}
			}

			break
		}
	}

	if isLooping {
		log.Printf("[DEBUG] ITS LOOPING!")
	} else {
		//log.Printf("\n\n[DEBUG] ITS _NOT_ LOOPING!\n\n")
	}

	// 1. Get result of parentnode's subflow (foundResult.Result)
	// 2. Try to marshal parent into a loop.
	// 3. If possible, loop through and find the one matching SubflowData.ExecutionId with "executionParent"
	// 4. If it's matching, update ONLY that one.
	sendRequest := false
	resultData := []byte{}
	var subflowDataLoop []SubflowData
	err = json.Unmarshal([]byte(foundResult.Result), &subflowDataLoop)
	if err == nil {
		for subflowIndex, subflowData := range subflowDataLoop {
			if subflowData.ExecutionId == executionParent {
				log.Printf("[DEBUG] Updating execution Id %s with subflow info", subflowData.ExecutionId)
				subflowDataLoop[subflowIndex].Result = returnValue
			}
		}

		//bytes.NewBuffer([]byte(resultData)),
		resultData, err = json.Marshal(subflowDataLoop)
		if err != nil {
			log.Printf("[WARNING] Failed updating resultData: %s", err)
			return err
		}

		sendRequest = true
	} else {
		actionValue := SubflowData{
			Success:       true,
			ExecutionId:   executionParent,
			Authorization: parentAuth,
			Result:        returnValue,
		}

		parsedActionValue, err := json.Marshal(actionValue)
		if err != nil {
			return err
		}

		// This is probably bad for loops
		if len(foundResult.Action.ID) == 0 {
			//log.Printf("Couldn't find the result!")
			parsedAction := Action{
				Label:       selectedTrigger.Label,
				ID:          selectedTrigger.ID,
				Name:        "run_subflow",
				AppName:     "shuffle-subflow",
				AppVersion:  "1.0.0",
				Environment: selectedTrigger.Environment,
				Parameters:  []WorkflowAppActionParameter{},
			}

			timeNow := time.Now().Unix()
			newResult := ActionResult{
				Action:        parsedAction,
				ExecutionId:   executionParent,
				Authorization: parentAuth,
				Result:        string(parsedActionValue),
				StartedAt:     timeNow,
				CompletedAt:   timeNow,
				Status:        "SUCCESS",
			}

			resultData, err = json.Marshal(newResult)
			if err != nil {
				return err
			}

			sendRequest = true
		} else {
			//log.Printf("[DEBUG] Should UPDATE parentResult: %s", string(parsedActionValue))
			foundResult.Result = string(parsedActionValue)
			resultData, err = json.Marshal(foundResult)
			if err != nil {
				return err
			}

			sendRequest = true
		}
	}

	if sendRequest && len(resultData) > 0 {
		//log.Printf("SHOULD SEND REQUEST!")
		streamUrl := fmt.Sprintf("%s/api/v1/streams", backendUrl)
		req, err := http.NewRequest(
			"POST",
			streamUrl,
			bytes.NewBuffer([]byte(resultData)),
		)

		if err != nil {
			log.Printf("Error building subflow request: %s", err)
			return err
		}

		newresp, err := topClient.Do(req)
		if err != nil {
			log.Printf("Error running subflow request: %s", err)
			return err
		}

		//body, err := ioutil.ReadAll(newresp.Body)
		//if err != nil {
		//	log.Printf("Failed reading body when waiting: %s", err)
		//	return err
		//}
		//log.Printf("[INFO] ADDED NEW ACTION RESULT (%d): %s", newresp.StatusCode, body)
		//_ = body
		_ = newresp
	} else {
		log.Printf("[INFO] NOT sending request because data len is %d and request is %#v", len(resultData), sendRequest)
	}

	return nil

	//log.Printf("Results: %d, status: %s, result: %s", len(newExecution.Results), newExecution.Status, newExecution.Result)
	//if newExecution.Status == "FINISHED" || newExecution.Status == "SUCCESS" {
	//	subflowResults[subflowIndex].Result = newExecution.Result
	//	updated = true
	//	finished += 1
	//}
}

// Updateparam is a check to see if the execution should be continuously validated
func ParsedExecutionResult(ctx context.Context, workflowExecution WorkflowExecution, actionResult ActionResult, updateParam bool) (*WorkflowExecution, bool, error) {

	if actionResult.Action.ID == "" {
		//log.Printf("[ERROR] Failed handling EMPTY action %#v", actionResult)
		return &workflowExecution, true, err
	}

	//log.Printf("ACTIONRESULT: %#v", actionResult)

	dbSave := false
	startAction, extra, children, parents, visited, executed, nextActions, environments := GetExecutionVariables(ctx, workflowExecution.ExecutionId)

	//log.Printf("RESULT: %#v", actionResult.Action.ExecutionVariable)
	// Shitty workaround as it may be missing it at times
	for _, action := range workflowExecution.Workflow.Actions {
		if action.ID == actionResult.Action.ID {
			//log.Printf("HAS EXEC VARIABLE: %#v", action.ExecutionVariable)
			actionResult.Action.ExecutionVariable = action.ExecutionVariable
			break
		}
	}

	if len(actionResult.Action.ExecutionVariable.Name) > 0 && (actionResult.Status == "SUCCESS" || actionResult.Status == "FINISHED") {
		log.Printf("\n\nSETTING RESULTS: %#v", workflowExecution.Results)
		if len(workflowExecution.Results) > 0 {
			lastResult := workflowExecution.Results[len(workflowExecution.Results)-1].Result
			log.Printf("LAST: %s", lastResult)
		}

		//for _, item := range workflowExecution.Results {

		//}
		//workflowExecution.Result = workflowExecution.Workflow.DefaultReturnValue
		actionResult.Action.ExecutionVariable.Value = actionResult.Result

		foundIndex := -1
		for i, executionVariable := range workflowExecution.ExecutionVariables {
			if executionVariable.Name == actionResult.Action.ExecutionVariable.Name {
				foundIndex = i
				break
			}
		}

		if foundIndex >= 0 {
			workflowExecution.ExecutionVariables[foundIndex] = actionResult.Action.ExecutionVariable
		} else {
			workflowExecution.ExecutionVariables = append(workflowExecution.ExecutionVariables, actionResult.Action.ExecutionVariable)
		}
	}

	actionResult.Action = Action{
		AppName:           actionResult.Action.AppName,
		AppVersion:        actionResult.Action.AppVersion,
		Label:             actionResult.Action.Label,
		Name:              actionResult.Action.Name,
		ID:                actionResult.Action.ID,
		Parameters:        actionResult.Action.Parameters,
		ExecutionVariable: actionResult.Action.ExecutionVariable,
	}

	// Cleaning up result authentication
	for paramIndex, param := range actionResult.Action.Parameters {
		if param.Configuration {
			//log.Printf("[INFO] Deleting param %s (auth)", param.Name)
			actionResult.Action.Parameters[paramIndex].Value = ""
		}
	}

	// Used for testing subflow shit
	//if strings.Contains(actionResult.Action.Label, "Shuffle Workflow_30") {
	//	log.Printf("RESULT FOR %s: %#v", actionResult.Action.Label, actionResult.Result)
	//	if !strings.Contains(actionResult.Result, "\"result\"") {
	//		log.Printf("NO RESULT - RETURNING!")
	//		return &workflowExecution, false, nil
	//	}
	//}

	// Fills in data from subflows, whether they're loops or not
	// Deprecated! Now runs updateExecutionParent() instead
	// Update: handling this farther down the function
	if actionResult.Status == "SUCCESS" && actionResult.Action.AppName == "shuffle-subflow" {
		//runCheck := false
		//for _, param := range actionResult.Action.Parameters {
		//	if param.Name == "check_result" {
		//		//log.Printf("[INFO] RESULT: %#v", param)
		//		if param.Value == "true" {
		//			runCheck = true
		//		}

		//		break
		//	}
		//}

		//_ = runCheck
		////log.Printf("\n\nRUNCHECK: %#v\n\n", runCheck)
		//if runCheck {
		//	log.Printf("[WARNING] Sinkholing request IF the subflow-result DOESNT have result. Value: %s", actionResult.Result)
		//	var subflowData SubflowData
		//	err = json.Unmarshal([]byte(actionResult.Result), &subflowData)
		//	if err == nil {
		//		if len(subflowData.Result) == 0 {
		//			//func updateExecutionParent(executionParent, returnValue, parentAuth, parentNode string) error {
		//			log.Printf("\n\nNO RESULT FOR SUBFLOW RESULT - RETURNING\n\n")
		//			return &workflowExecution, false, nil
		//		}
		//	}
		//	//type SubflowData struct {
		//}
		//	log.Printf("[INFO] Validating subflow result in workflow %s", workflowExecution.ExecutionId)

		//	// WAY lower timeout in cloud
		//	// Should probably change it for enterprise customers?
		//	// Idk how to handle this in cloud yet.
		//	// FIXME: Check "if finished {" location, and the ExecutionParent for realtime data
		//	// E.g. the subitem itself updating it
		//	// 60*30 = 1800 = 30 minutes of waiting potentially
		//	// This is NOT ideal.
		//	subflowTimeout := 1800
		//	if project.Environment == "cloud" {
		//		subflowTimeout = 120
		//	}

		//	subflowResult := SubflowData{}
		//	subflowResults := []SubflowData{}
		//	err = json.Unmarshal([]byte(actionResult.Result), &subflowResult)

		//	// This is just in case it's running in the worker
		//	backendUrl := os.Getenv("BASE_URL")
		//	resultUrl := fmt.Sprintf("%s/api/v1/streams/results", backendUrl)
		//	log.Printf("[DEBUG] ResultURL: %s", backendUrl)
		//	topClient := &http.Client{
		//		Transport: &http.Transport{
		//			Proxy: nil,
		//		},
		//	}
		//	newExecution := WorkflowExecution{}

		//	httpProxy := os.Getenv("HTTP_PROXY")
		//	httpsProxy := os.Getenv("HTTPS_PROXY")
		//	if len(httpProxy) > 0 || len(httpsProxy) > 0 {
		//		topClient = &http.Client{}
		//	} else {
		//		if len(httpProxy) > 0 {
		//			log.Printf("Running with HTTP proxy %s (env: HTTP_PROXY)", httpProxy)
		//		}
		//		if len(httpsProxy) > 0 {
		//			log.Printf("Running with HTTPS proxy %s (env: HTTPS_PROXY)", httpsProxy)
		//		}
		//	}

		//	if err != nil {
		//		subflowResults = []SubflowData{}
		//		err = json.Unmarshal([]byte(actionResult.Result), &subflowResults)
		//		if err == nil {
		//			//log.Printf("[INFO] Should get data for %d subflow executions", len(subflowResults))
		//			count := 0
		//			updated := false
		//			//newResult := ""

		//			for {
		//				time.Sleep(3 * time.Second)

		//				finished := 0
		//				for subflowIndex, subflowResult := range subflowResults {
		//					if !subflowResult.Success || len(subflowResult.Result) != 0 {
		//						finished += 1
		//						continue
		//					}

		//					// Have to get from backend IF no environment (worker, onprem)
		//					// "worker"
		//					if project.Environment == "" {
		//						data, err := json.Marshal(subflowResult)
		//						if err != nil {
		//							log.Printf("[WARNING] Failed init marshal: %s", err)
		//							continue
		//						}

		//						req, err := http.NewRequest(
		//							"POST",
		//							resultUrl,
		//							bytes.NewBuffer([]byte(data)),
		//						)

		//						newresp, err := topClient.Do(req)
		//						if err != nil {
		//							log.Printf("[ERROR] Failed making request: %s", err)
		//							continue
		//						}

		//						body, err := ioutil.ReadAll(newresp.Body)
		//						if err != nil {
		//							log.Printf("[ERROR] Failed reading body: %s", err)
		//							continue
		//						}

		//						if newresp.StatusCode != 200 {
		//							log.Printf("[ERROR] Bad statuscode getting subresult: %d, %s", newresp.StatusCode, string(body))
		//							continue
		//						}

		//						err = json.Unmarshal(body, &newExecution)
		//						if err != nil {
		//							log.Printf("[ERROR] Failed newexecutuion unmarshal: %s", err)
		//							continue
		//						}

		//						//log.Printf("Results: %d, status: %s, result: %s", len(newExecution.Results), newExecution.Status, newExecution.Result)
		//						if newExecution.Status == "FINISHED" || newExecution.Status == "SUCCESS" {
		//							subflowResults[subflowIndex].Result = newExecution.Result
		//							updated = true
		//							finished += 1
		//						}

		//					} else {
		//						tmpExecution, err := GetWorkflowExecution(ctx, subflowResult.ExecutionId)
		//						newExecution := *tmpExecution
		//						if err != nil {
		//							log.Printf("[WARNING] Error getting subflow data: %s", err)
		//						} else {
		//							//log.Printf("Results: %d, status: %s", len(workflowExecution.Results), workflowExecution.Status)
		//							if newExecution.Status == "FINISHED" || newExecution.Status == "ABORTED" {
		//								subflowResults[subflowIndex].Result = newExecution.Result
		//								updated = true
		//								finished += 1
		//							}
		//						}
		//					}
		//				}

		//				if finished == len(subflowResults) {
		//					break
		//				}

		//				if count >= subflowTimeout/3 {
		//					break
		//				}

		//				count += 1
		//			}

		//			if updated {
		//				newJson, err := json.Marshal(subflowResults)
		//				if err == nil {
		//					actionResult.Result = string(newJson)
		//				} else {
		//					log.Printf("[WARNING] Failed marshalling subflowresultS: %s", err)
		//				}
		//			}
		//		}
		//	}

		//	if err == nil && subflowResult.Success == true && len(subflowResult.ExecutionId) > 0 {
		//		log.Printf("[DEBUG] Should get data for subflow execution %s", subflowResult.ExecutionId)
		//		count := 0
		//		for {
		//			time.Sleep(3 * time.Second)

		//			if count >= subflowTimeout/3 {
		//				break
		//			}

		//			// Worker & onprem
		//			if project.Environment == "" {
		//				data, err := json.Marshal(subflowResult)
		//				if err != nil {
		//					log.Printf("[WARNING] Failed init marshal: %s", err)
		//					count += 1
		//					continue
		//				}

		//				req, err := http.NewRequest(
		//					"POST",
		//					resultUrl,
		//					bytes.NewBuffer([]byte(data)),
		//				)

		//				newresp, err := topClient.Do(req)
		//				if err != nil {
		//					log.Printf("[ERROR] Failed making request: %s", err)
		//					count += 1
		//					continue
		//				}

		//				body, err := ioutil.ReadAll(newresp.Body)
		//				if err != nil {
		//					log.Printf("[ERROR] Failed reading body: %s", err)
		//					count += 1
		//					continue
		//				}

		//				if newresp.StatusCode != 200 {
		//					log.Printf("[ERROR] Bad statuscode getting subresult: %d, %s", newresp.StatusCode, string(body))
		//					count += 1
		//					continue
		//				}

		//				err = json.Unmarshal(body, &newExecution)
		//				if err != nil {
		//					log.Printf("[ERROR] Failed workflowExecution unmarshal: %s", err)
		//					count += 1
		//					continue
		//				}

		//				//log.Printf("Results: %d, status: %s, result: %s", len(newExecution.Results), newExecution.Status, newExecution.Result)
		//				if newExecution.Status == "FINISHED" || newExecution.Status == "SUCCESS" {
		//					subflowResult.Result = newExecution.Result
		//					break
		//					//subflowResults[subflowIndex].Result = workflowExecution.Result
		//					//updated = true
		//					//finished += 1
		//				}
		//			} else {
		//				tmpExecution, err := GetWorkflowExecution(ctx, subflowResult.ExecutionId)
		//				newExecution = *tmpExecution
		//				if err != nil {
		//					log.Printf("[WARNING] Error getting subflow data: %s", err)
		//				} else {
		//					//log.Printf("Results: %d, status: %s", len(newExecution.Results), newExecution.Status)
		//					if newExecution.Status == "FINISHED" || newExecution.Status == "ABORTED" {
		//						subflowResult.Result = newExecution.Result
		//						break
		//					}

		//				}
		//			}

		//			count += 1
		//		}
		//	}

		//	if len(subflowResult.Result) > 0 {
		//		newJson, err := json.Marshal(subflowResult)
		//		if err == nil {
		//			actionResult.Result = string(newJson)
		//		} else {
		//			log.Printf("[WARNING] Failed marshalling subflowresult: %s", err)
		//		}
		//	}
		//} else {
		//	log.Printf("[WARNING] Skipping subresult check!")
		//}

		// Updating in case the execution got more info
		//if project.Environment != "" {
		//	parsedExecution, err := GetWorkflowExecution(ctx, workflowExecution.ExecutionId)
		//	if err != nil {
		//		log.Printf("[ERROR] FAILED to reload execution after subflow check: %s", err)
		//	} else {
		//		log.Printf("[DEBUG] Re-updated execution after subflow check!")
		//	}

		//	workflowExecution = *parsedExecution
		//} else {
		//	if updateParam {
		//		return &workflowExecution, false, errors.New("Rerun this transaction with updated values")
		//	}

		//	log.Printf("[INFO] Skipping updateparam with %d results", len(workflowExecution.Results))
		//	// return &workflowExecution, dbSave, err
		//	//return
		//	//func ParsedExecutionResult(ctx context.Context, workflowExecution WorkflowExecution, actionResult ActionResult) (*WorkflowExecution, bool, error) {

		//	//type SubflowData struct {
		//	//	Success       bool   `json:"success"`
		//	//	ExecutionId   string `json:"execution_id"`
		//	//	Authorization string `json:"authorization"`
		//	//	Result        string `json:"result"`
		//	//}
		//	//log.Printf("[DEBUG] NOT validating updated workflowExecution because worker")
		//}

	}

	if actionResult.Status == "ABORTED" || actionResult.Status == "FAILURE" {
		IncrementCache(ctx, workflowExecution.ExecutionOrg, "app_executions_failed")
		if workflowExecution.Workflow.Configuration.SkipNotifications == false {
			// Add an else for HTTP request errors with success "false"
			// These could be "silent" issues
			if actionResult.Status == "FAILURE" {
				log.Printf("[DEBUG] Result is %s. Making notification.", actionResult.Status)
				err = CreateOrgNotification(
					ctx,
					fmt.Sprintf("Error in Workflow %#v", workflowExecution.Workflow.Name),
					fmt.Sprintf("Node %s in Workflow %s was found to have an error. Click to investigate", actionResult.Action.Label, workflowExecution.Workflow.Name),
					fmt.Sprintf("/workflows/%s?execution_id=%s&view=executions&node=%s", workflowExecution.Workflow.ID, workflowExecution.ExecutionId, actionResult.Action.ID),
					workflowExecution.ExecutionOrg,
					true,
				)

				if err != nil {
					log.Printf("[WARNING] Failed making org notification: %s", err)
				}
			}
		}

		newResults := []ActionResult{}
		childNodes := []string{}
		if workflowExecution.Workflow.Configuration.ExitOnError {
			// Find underlying nodes and add them
			log.Printf("[WARNING] Actionresult is %s for node %s in %s. Should set workflowExecution and exit all running functions", actionResult.Status, actionResult.Action.ID, workflowExecution.ExecutionId)
			workflowExecution.Status = actionResult.Status
			workflowExecution.LastNode = actionResult.Action.ID

			if len(workflowExecution.Workflow.DefaultReturnValue) > 0 {
				workflowExecution.Result = workflowExecution.Workflow.DefaultReturnValue
			}

			IncrementCache(ctx, workflowExecution.ExecutionOrg, "workflow_executions_failed")
		} else {
			log.Printf("[WARNING] Actionresult is %s for node %s in %s. Continuing anyway because of workflow configuration.", actionResult.Status, actionResult.Action.ID, workflowExecution.ExecutionId)
			// Finds ALL childnodes to set them to SKIPPED
			// Remove duplicates
			//log.Printf("CHILD NODES: %d", len(childNodes))
			childNodes = FindChildNodes(workflowExecution, actionResult.Action.ID)
			//log.Printf("\n\nFOUND %d CHILDNODES\n\n", len(childNodes))
			for _, nodeId := range childNodes {
				if nodeId == actionResult.Action.ID {
					continue
				}

				// 1. Find the action itself
				// 2. Create an actionresult
				curAction := Action{ID: ""}
				for _, action := range workflowExecution.Workflow.Actions {
					if action.ID == nodeId {
						curAction = action
						break
					}
				}

				isTrigger := false
				if len(curAction.ID) == 0 {
					for _, trigger := range workflowExecution.Workflow.Triggers {
						//log.Printf("%s : %s", trigger.ID, nodeId)
						if trigger.ID == nodeId {
							isTrigger = true
							name := "shuffle-subflow"
							curAction = Action{
								AppName:    name,
								AppVersion: trigger.AppVersion,
								Label:      trigger.Label,
								Name:       trigger.Name,
								ID:         trigger.ID,
							}

							//log.Printf("SET NODE!!")
							break
						}
					}

					if len(curAction.ID) == 0 {
						log.Printf("Couldn't find subnode %s", nodeId)
						continue
					}
				}

				resultExists := false
				for _, result := range workflowExecution.Results {
					if result.Action.ID == curAction.ID {
						resultExists = true
						break
					}
				}

				if !resultExists {
					// Check parents are done here. Only add it IF all parents are skipped
					skipNodeAdd := false
					for _, branch := range workflowExecution.Workflow.Branches {
						if branch.DestinationID == nodeId && !isTrigger {
							// If the branch's source node is NOT in childNodes, it's not a skipped parent
							// Checking if parent is a trigger
							parentTrigger := false
							for _, trigger := range workflowExecution.Workflow.Triggers {
								if trigger.ID == branch.SourceID {
									if trigger.AppName != "User Input" && trigger.AppName != "Shuffle Workflow" {
										parentTrigger = true
									}
								}
							}

							if parentTrigger {
								continue
							}

							sourceNodeFound := false
							for _, item := range childNodes {
								if item == branch.SourceID {
									sourceNodeFound = true
									break
								}
							}

							if !sourceNodeFound {
								// FIXME: Shouldn't add skip for child nodes of these nodes. Check if this node is parent of upcoming nodes.
								log.Printf("\n\n NOT setting node %s to SKIPPED", nodeId)
								skipNodeAdd = true

								if !ArrayContains(visited, nodeId) && !ArrayContains(executed, nodeId) {
									nextActions = append(nextActions, nodeId)
									log.Printf("[INFO] SHOULD EXECUTE NODE %s. Next actions: %s", nodeId, nextActions)
								}
								break
							}
						}
					}

					if !skipNodeAdd {
						newResult := ActionResult{
							Action:        curAction,
							ExecutionId:   actionResult.ExecutionId,
							Authorization: actionResult.Authorization,
							Result:        "Skipped because of previous node - 2",
							StartedAt:     0,
							CompletedAt:   0,
							Status:        "SKIPPED",
						}

						newResults = append(newResults, newResult)

						visited = append(visited, curAction.ID)
						executed = append(executed, curAction.ID)

						UpdateExecutionVariables(ctx, workflowExecution.ExecutionId, startAction, children, parents, visited, executed, nextActions, environments, extra)
					} else {
						//log.Printf("\n\nNOT adding %s as skipaction - should add to execute?", nodeId)
						//var visited []string
						//var executed []string
						//var nextActions []string
					}
				}
			}
		}

		// Cleans up aborted, and always gives a result
		lastResult := ""
		// type ActionResult struct {
		for _, result := range workflowExecution.Results {
			if actionResult.Action.ID == result.Action.ID {
				continue
			}

			if result.Status == "EXECUTING" {
				result.Status = actionResult.Status
				result.Result = "Aborted because of error in another node (2)"
			}

			if len(result.Result) > 0 {
				lastResult = result.Result
			}

			newResults = append(newResults, result)
		}

		if workflowExecution.LastNode == "" {
			workflowExecution.LastNode = actionResult.Action.ID
		}

		workflowExecution.Result = lastResult
		workflowExecution.Results = newResults
	}

	if actionResult.Status == "SKIPPED" {
		//unfinishedNodes := []string{}
		childNodes := FindChildNodes(workflowExecution, actionResult.Action.ID)
		//log.Printf("childnodes: %d", len(childNodes)

		appendBadResults := true
		appendResults := []ActionResult{}
		for _, nodeId := range childNodes {
			if nodeId == actionResult.Action.ID {
				continue
			}

			curAction := Action{ID: ""}
			for _, action := range workflowExecution.Workflow.Actions {
				if action.ID == nodeId {
					curAction = action
					break
				}
			}

			if len(curAction.ID) == 0 {
				log.Printf("Couldn't find subnode (0) %s as action. Checking triggers.", nodeId)
				for _, trigger := range workflowExecution.Workflow.Triggers {
					//if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
					if trigger.ID == nodeId {
						curAction = Action{
							ID:      trigger.ID,
							AppName: trigger.AppName,
							Name:    trigger.AppName,
							Label:   trigger.Label,
						}

						if trigger.AppName == "Shuffle Workflow" {
							curAction.AppName = "shuffle-subflow"
						}

						break
					}
				}

				if len(curAction.ID) == 0 {
					log.Printf("Couldn't find subnode (1) %s", nodeId)
					continue
				}
			}

			resultExists := false
			for _, result := range workflowExecution.Results {
				if result.Action.ID == curAction.ID {
					resultExists = true
					break
				}
			}

			// Finds sub-nodes to be skipped if a parent node condition fails
			skipIdCheck := false
			if !resultExists {
				// Check parents are done here. Only add it IF all parents are skipped
				skipNodeAdd := false

				// Find parent nodes that are also a child node of SKIPPED
				parentNodes := []string{}
				for _, branch := range workflowExecution.Workflow.Branches {
					if branch.DestinationID == curAction.ID {

						for _, childnode := range childNodes {
							if childnode == branch.SourceID {
								parentNodes = append(parentNodes, branch.SourceID)
								break
							}
						}
					}
				}

				//log.Printf("Parents: %#v", parentNodes)

				for _, branch := range workflowExecution.Workflow.Branches {

					// FIXME: Make this dynamic to curAction.ID's parent that we're checking from
					//if branch.SourceID == actionResult.Action.ID {
					if ArrayContains(parentNodes, branch.SourceID) {
						// Check if the node has more destinations
						// branch = old branch (original?)
						ids := []string{}
						for _, innerbranch := range workflowExecution.Workflow.Branches {
							if innerbranch.DestinationID == branch.DestinationID {
								ids = append(ids, innerbranch.SourceID)
							}

							//if innerbranch.ID == "70104246-45cf-4fa3-8b03-323d3cdf6434" {
							//	log.Printf("Branch: %#v", innerbranch)
							//}
						}

						//if curAction.Label == "Shuffle Tools_4" {
						//}

						foundIds := []string{actionResult.Action.ID}
						foundSuccess := []string{}
						foundSkipped := []string{actionResult.Action.ID}

						//log.Printf("\n\nAction: %s (%s). Branches: %d\n\n", curAction.Label, curAction.ID, len(ids))
						// If more than one source branch for the target is found;
						// Look for the result of the parent
						if len(ids) > 1 {
							for _, thisId := range ids {
								if thisId == actionResult.Action.ID {
									continue
								}

								for _, result := range workflowExecution.Results {
									if result.Action.ID == thisId {
										log.Printf("[DEBUG] Found result for %s (%s): %s", result.Action.Label, thisId, result.Status)

										foundIds = append(foundIds, thisId)
										if result.Status == "SUCCESS" {
											foundSuccess = append(foundSuccess, thisId)
										} else {
											foundSkipped = append(foundSkipped, thisId)
										}
									}
								}
							}
						} else {
							appendBadResults = true
							skipIdCheck = true
						}

						if skipIdCheck {
							// Pass here, as it's just here to skip the next part
						} else if (len(foundSkipped) == len(foundIds)) && len(foundSkipped) == len(ids) {
							appendBadResults = true
						} else {
							appendBadResults = false
						}

						//if len(foundIds) == len(ids) {
						//	// Means you can continue
						//	appendBadResults = false
						//	break
						//}
					}
				}

				if !appendBadResults {
					break
				}

				if !skipNodeAdd {
					//log.Printf("[DEBUG] Appending skip for node %s (%s)", curAction.Name, curAction.Label)
					newResult := ActionResult{
						Action:        curAction,
						ExecutionId:   actionResult.ExecutionId,
						Authorization: actionResult.Authorization,
						Result:        "Skipped because of previous node - 1",
						StartedAt:     0,
						CompletedAt:   0,
						Status:        "SKIPPED",
					}

					appendResults = append(appendResults, newResult)
				} else {
					//log.Printf("\n\nNOT adding %s as skipaction - should add to execute?", nodeId)
					//var visited []string
					//var executed []string
					//var nextActions []string
				}
			}
		}

		//log.Printf("Append skipped results: %#v", appendBadResults)
		if len(appendResults) > 0 {
			dbSave = true
			for _, res := range appendResults {
				workflowExecution.Results = append(workflowExecution.Results, res)
			}
		}
	}

	// Related to notifications
	if actionResult.Status == "SUCCESS" && workflowExecution.Workflow.Configuration.SkipNotifications == false {
		// Marshal default failures
		resultCheck := ResultChecker{}
		err = json.Unmarshal([]byte(actionResult.Result), &resultCheck)
		if err == nil {
			//log.Printf("Unmarshal success!")
			if resultCheck.Success == false && strings.Contains(actionResult.Result, "success") && strings.Contains(actionResult.Result, "false") {
				err = CreateOrgNotification(
					ctx,
					fmt.Sprintf("Potential error in Workflow %#v", workflowExecution.Workflow.Name),
					fmt.Sprintf("Node %s in Workflow %s failed silently. Click to see more. Reason: %#v", actionResult.Action.Label, workflowExecution.Workflow.Name, resultCheck.Reason),
					fmt.Sprintf("/workflows/%s?execution_id=%s&view=executions&node=%s", workflowExecution.Workflow.ID, workflowExecution.ExecutionId, actionResult.Action.ID),
					workflowExecution.ExecutionOrg,
					true,
				)

				if err != nil {
					log.Printf("[WARNING] Failed making org notification for %s: %s", workflowExecution.ExecutionOrg, err)
				}
			}
		} else {
			//log.Printf("[ERROR] Failed unmarshaling result into resultChecker (%s): %#v", err, actionResult)
		}

		//log.Printf("[DEBUG] Ran marshal on silent failure")
	}

	// FIXME rebuild to be like this or something
	// workflowExecution/ExecutionId/Nodes/NodeId
	// Find the appropriate action
	if len(workflowExecution.Results) > 0 {
		// FIXME
		skip := false
		found := false
		outerindex := 0
		for index, item := range workflowExecution.Results {
			if item.Action.ID == actionResult.Action.ID {
				found = true
				if item.Status == actionResult.Status {
					skip = true
				}

				outerindex = index
				break
			}
		}

		if skip {
			//log.Printf("[DEBUG] Both results are %s. Skipping this node", item.Status)
		} else if found {
			// If result exists and execution variable exists, update execution value
			//log.Printf("Exec var backend: %s", workflowExecution.Results[outerindex].Action.ExecutionVariable.Name)
			actionVarName := workflowExecution.Results[outerindex].Action.ExecutionVariable.Name
			// Finds potential execution arguments
			if len(actionVarName) > 0 {
				log.Printf("EXECUTION VARIABLE LOCAL: %s", actionVarName)
				for index, execvar := range workflowExecution.ExecutionVariables {
					if execvar.Name == actionVarName {
						// Sets the value for the variable
						workflowExecution.ExecutionVariables[index].Value = actionResult.Result
						break
					}
				}
			}

			log.Printf("[INFO] Updating %s in workflow %s from %s to %s", actionResult.Action.ID, workflowExecution.ExecutionId, workflowExecution.Results[outerindex].Status, actionResult.Status)
			workflowExecution.Results[outerindex] = actionResult
		} else {
			log.Printf("[INFO] Setting value of %s (%s) in workflow %s to %s (%d)", actionResult.Action.Label, actionResult.Action.ID, workflowExecution.ExecutionId, actionResult.Status, len(workflowExecution.Results))
			workflowExecution.Results = append(workflowExecution.Results, actionResult)
			//if subresult.Status == "SKIPPED" subresult.Status != "FAILURE" {
		}
	} else {
		log.Printf("[INFO] Setting value of %s (INIT - %s) in workflow %s to %s (%d)", actionResult.Action.Label, actionResult.Action.ID, workflowExecution.ExecutionId, actionResult.Status, len(workflowExecution.Results))
		workflowExecution.Results = append(workflowExecution.Results, actionResult)
	}

	// FIXME: Have a check for skippednodes and their parents
	/*
		for resultIndex, result := range workflowExecution.Results {
			if result.Status != "SKIPPED" {
				continue
			}

			// Checks if all parents are skipped or failed. Otherwise removes them from the results
			for _, branch := range workflowExecution.Workflow.Branches {
				if branch.DestinationID == result.Action.ID {
					for _, subresult := range workflowExecution.Results {
						if subresult.Action.ID == branch.SourceID {
							if subresult.Status != "SKIPPED" && subresult.Status != "FAILURE" {
								log.Printf("SUBRESULT PARENT STATUS: %s", subresult.Status)
								log.Printf("Should remove resultIndex: %d", resultIndex)

								workflowExecution.Results = append(workflowExecution.Results[:resultIndex], workflowExecution.Results[resultIndex+1:]...)

								break
							}
						}
					}
				}
			}
		}
	*/

	extraInputs := 0
	for _, trigger := range workflowExecution.Workflow.Triggers {
		if trigger.Name == "User Input" && trigger.AppName == "User Input" {
			extraInputs += 1
		} else if trigger.Name == "Shuffle Workflow" && trigger.AppName == "Shuffle Workflow" {
			extraInputs += 1
		}
	}

	//log.Printf("EXTRA: %d", extraInputs)
	//log.Printf("LENGTH: %d - %d", len(workflowExecution.Results), len(workflowExecution.Workflow.Actions)+extraInputs)
	updateParentRan := false
	if len(workflowExecution.Results) == len(workflowExecution.Workflow.Actions)+extraInputs {
		//log.Printf("\nIN HERE WITH RESULTS %d vs %d\n", len(workflowExecution.Results), len(workflowExecution.Workflow.Actions)+extraInputs)
		finished := true
		lastResult := ""

		// Doesn't have to be SUCCESS and FINISHED everywhere anymore.
		//skippedNodes := false
		for _, result := range workflowExecution.Results {
			if result.Status == "EXECUTING" {
				finished = false
				break
			}

			// FIXME: Check if ALL parents are skipped or if its just one. Otherwise execute it
			//if result.Status == "SKIPPED" {
			//	skippedNodes = true

			//	// Checks if all parents are skipped or failed. Otherwise removes them from the results
			//	for _, branch := range workflowExecution.Workflow.Branches {
			//		if branch.DestinationID == result.Action.ID {
			//			for _, subresult := range workflowExecution.Results {
			//				if subresult.Action.ID == branch.SourceID {
			//					if subresult.Status != "SKIPPED" && subresult.Status != "FAILURE" {
			//						//log.Printf("SUBRESULT PARENT STATUS: %s", subresult.Status)
			//						//log.Printf("Should remove resultIndex: %d", resultIndex)
			//						finished = false
			//						break
			//					}
			//				}
			//			}
			//		}

			//		if !finished {
			//			break
			//		}
			//	}
			//}

			lastResult = result.Result
		}

		//log.Printf("[debug] Finished? %#v", finished)
		if finished {
			dbSave = true
			log.Printf("[INFO] Execution of %s in workflow %s finished.", workflowExecution.ExecutionId, workflowExecution.Workflow.ID)

			for actionIndex, action := range workflowExecution.Workflow.Actions {
				for parameterIndex, param := range action.Parameters {
					if param.Configuration {
						//log.Printf("Cleaning up %s in %s", param.Name, action.Name)
						workflowExecution.Workflow.Actions[actionIndex].Parameters[parameterIndex].Value = ""
					}
				}
			}

			//log.Println("Might be finished based on length of results and everything being SUCCESS or FINISHED - VERIFY THIS. Setting status to finished.")

			workflowExecution.Result = lastResult
			workflowExecution.Status = "FINISHED"
			IncrementCache(ctx, workflowExecution.ExecutionOrg, "workflow_executions_finished")
			workflowExecution.CompletedAt = int64(time.Now().Unix())
			if workflowExecution.LastNode == "" {
				workflowExecution.LastNode = actionResult.Action.ID
			}

			// 1. Check if the LAST node is FAILURE or ABORTED or SKIPPED
			// 2. If it's either of those, set the executionResult default value to DefaultReturnValue
			//log.Printf("\n\n===========\nSETTING VALUE TO %#v\n============\nPARENT: %s\n\n", lastResult, workflowExecution.ExecutionParent)
			//log.Printf("\n\n===========\nSETTING VALUE TO %#v\n============\nPARENT: %s\n\n", lastResult, workflowExecution.ExecutionParent)
			//log.Printf("%#v", workflowExecution)

			valueToReturn := ""
			if len(workflowExecution.Workflow.DefaultReturnValue) > 0 {
				valueToReturn = workflowExecution.Workflow.DefaultReturnValue
				//log.Printf("\n\nCHECKING RESULT FOR LAST NODE %s with value \"%s\". Executionparent: %s\n\n", workflowExecution.ExecutionSourceNode, workflowExecution.Workflow.DefaultReturnValue, workflowExecution.ExecutionParent)
				for _, result := range workflowExecution.Results {
					if result.Action.ID == workflowExecution.LastNode {
						if result.Status == "ABORTED" || result.Status == "FAILURE" || result.Status == "SKIPPED" {
							workflowExecution.Result = workflowExecution.Workflow.DefaultReturnValue
							if len(workflowExecution.ExecutionParent) > 0 {
								log.Printf("FOUND SUBFLOW WITH EXECUTIONPARENT %s!", workflowExecution.ExecutionParent)

								// 1. Find the parent workflow
								// 2. Find the parent's existing value
							}
						}
						break
					}
				}
			} else {
				valueToReturn = workflowExecution.Result
			}

			//log.Printf("%#v, %#v, %#v", workflowExecution.ExecutionParent, workflowExecution.ExecutionSourceAuth, workflowExecution.ExecutionSourceNode)
			if len(workflowExecution.ExecutionParent) > 0 && len(workflowExecution.ExecutionSourceAuth) > 0 && len(workflowExecution.ExecutionSourceNode) > 0 {
				log.Printf("[DEBUG] Found execution parent %s for workflow %#v", workflowExecution.ExecutionParent, workflowExecution.Workflow.Name)

				err = updateExecutionParent(workflowExecution.ExecutionParent, valueToReturn, workflowExecution.ExecutionSourceAuth, workflowExecution.ExecutionSourceNode)
				if err != nil {
					log.Printf("[ERROR] Failed running update execution parent: %s", err)
				} else {
					updateParentRan = true
				}
			}
		}
	}

	// Had to move this to run AFTER "updateExecutionParent()", as it's controlling whether a subflow should be updated or not
	if actionResult.Status == "SUCCESS" && actionResult.Action.AppName == "shuffle-subflow" && !updateParentRan {
		runCheck := false
		for _, param := range actionResult.Action.Parameters {
			if param.Name == "check_result" {
				//log.Printf("[INFO] RESULT: %#v", param)
				if param.Value == "true" {
					runCheck = true
				}

				break
			}
		}

		//if runCheck && project.Environment != "" && project.Environment != "worker" {
		if runCheck {
			log.Printf("[WARNING] Sinkholing request of %#v IF the subflow-result DOESNT have result. Value: %s", actionResult.Action.Label, actionResult.Result)
			var subflowData SubflowData
			err = json.Unmarshal([]byte(actionResult.Result), &subflowData)
			if err == nil && len(subflowData.Result) == 0 && !strings.Contains(actionResult.Result, "\"result\"") {
				//func updateExecutionParent(executionParent, returnValue, parentAuth, parentNode string) error {
				log.Printf("\n\nNO RESULT FOR SUBFLOW RESULT - SETTING TO EXECUTING\n\n")

				// This means it's started, hence executing :)
				IncrementCache(ctx, workflowExecution.ExecutionOrg, "subflow_executions")
				//return &workflowExecution, false, nil

				// Finding the result, and removing it if it exists. "Sinkholing"
				workflowExecution.Status = "EXECUTING"
				newResults := []ActionResult{}
				for _, result := range workflowExecution.Results {
					if result.Action.ID == actionResult.Action.ID {
						continue
					}

					newResults = append(newResults, result)
				}

				workflowExecution.Results = newResults

				//for _, result := range
			} else {
				var subflowDataList []SubflowData
				err = json.Unmarshal([]byte(actionResult.Result), &subflowDataList)
				if err != nil || len(subflowDataList) == 0 {
					log.Printf("\n\nNOT sinkholed")
					for resultIndex, result := range workflowExecution.Results {
						if result.Action.ID == actionResult.Action.ID {
							workflowExecution.Results[resultIndex] = actionResult
							break
						}
					}
				} else {
					log.Printf("\n\nLIST NOT sinkholed (%d) - Should apply list setup for same as subflow without result!\n\n", len(subflowDataList))

					workflowExecution.Status = "EXECUTING"

					for resultIndex, result := range workflowExecution.Results {
						if result.Action.ID == actionResult.Action.ID {
							workflowExecution.Results[resultIndex] = actionResult
							break
						}
					}

					/*
						for _, subflowItem := range subflowDataList {
							log.Printf("%s == %s", subflowItem.ExecutionId, workflowExecution.ExecutionId)

							if len(subflowItem.Result) == 0 {
								subflowItem.Result = workflowExecution.Result

								//if subflowItem.ExecutionId == workflowExecution.ExecutionId {
								//	log.Printf("FOUND EXECUTION ID IN SUBFLOW: %s", subflowItem.ExecutionId)
								//tmpJson, err := json.Marshal(workflowExecution)
								//if strings.Contains(
							}
						}
					*/
				}

				dbSave = true
			}
		}
	}

	//GetApp(ctx context.Context, id string, user User) (*WorkflowApp, error) {
	tmpJson, err := json.Marshal(workflowExecution)
	if err == nil {
		if project.DbType != "elasticsearch" {
			if len(tmpJson) >= 1000000 {
				dbSave = true
				log.Printf("[ERROR] Result length is too long (%d)! Need to reduce result size", len(tmpJson))

				//gs://shuffler.appspot.com/extra_specs/0373ed696a3a2cba0a2b6838068f2b80
				//log.Printf("[WARNING] Couldn't find  for %s. Should check filepath gs://%s/%s (size too big)", innerApp.ID, internalBucket, fullParsedPath)

				// Result        string `json:"result" datastore:"result,noindex"`
				// Arbitrary reduction size
				maxSize := 250000
				newResults := []ActionResult{}
				bucketName := "shuffler.appspot.com"
				//shuffle-large-executions
				for _, item := range workflowExecution.Results {
					if len(item.Result) > maxSize {
						itemSize := len(item.Result)
						baseResult := fmt.Sprintf(`{
							"success": False,
							"reason": "Result too large to handle (https://github.com/frikky/shuffle/issues/171)."
							"size": %d,
							"extra": "",
							"id": "%s_%s"
						}`, itemSize, workflowExecution.ExecutionId, item.Action.ID)

						fullParsedPath := fmt.Sprintf("large_executions/%s/%s_%s", workflowExecution.ExecutionOrg, workflowExecution.ExecutionId, item.Action.ID)
						log.Printf("[DEBUG] Saving value of %s to storage path %s", item.Action.ID, fullParsedPath)
						bucket := project.StorageClient.Bucket(bucketName)
						obj := bucket.Object(fullParsedPath)
						w := obj.NewWriter(ctx)
						if _, err := fmt.Fprintf(w, item.Result); err != nil {
							log.Printf("[WARNING] Failed writing new exec file: %s", err)
							item.Result = baseResult
							newResults = append(newResults, item)
							continue
						}

						// Close, just like writing a file.
						if err := w.Close(); err != nil {
							log.Printf("[WARNING] Failed closing new exec file: %s", err)
							item.Result = baseResult
							newResults = append(newResults, item)
							continue
						}

						item.Result = fmt.Sprintf(`{
							"success": False,
							"reason": "Result too large to handle (https://github.com/frikky/shuffle/issues/171).",
							"size": %d,
							"extra": "replace",
							"id": "%s_%s"
						}`, itemSize, workflowExecution.ExecutionId, item.Action.ID)
						// Setting an arbitrary decisionpoint to get it
						// Backend will use this ID + action ID to get the data back
						//item.Result = fmt.Sprintf("EXECUTION=%s", workflowExecution.ExecutionId)
					}

					newResults = append(newResults, item)
				}

				workflowExecution.Results = newResults
			}
		}
	}

	return &workflowExecution, dbSave, err
}

// Finds the child nodes of a node in execution and returns them
// Used if e.g. a node in a branch is exited, and all children have to be stopped
func FindChildNodes(workflowExecution WorkflowExecution, nodeId string) []string {
	//log.Printf("\nNODE TO FIX: %s\n\n", nodeId)
	allChildren := []string{nodeId}
	//log.Printf("\n\n")

	// 1. Find children of this specific node
	// 2. Find the children of those nodes etc.
	for _, branch := range workflowExecution.Workflow.Branches {
		if branch.SourceID == nodeId {
			//log.Printf("NODE: %s, SRC: %s, CHILD: %s\n", nodeId, branch.SourceID, branch.DestinationID)
			allChildren = append(allChildren, branch.DestinationID)

			childNodes := FindChildNodes(workflowExecution, branch.DestinationID)
			for _, bottomChild := range childNodes {
				found := false
				for _, topChild := range allChildren {
					if topChild == bottomChild {
						found = true
						break
					}
				}

				if !found {
					allChildren = append(allChildren, bottomChild)
				}
			}
		}
	}

	// Remove potential duplicates
	newNodes := []string{}
	for _, tmpnode := range allChildren {
		found := false
		for _, newnode := range newNodes {
			if newnode == tmpnode {
				found = true
				break
			}
		}

		if !found {
			newNodes = append(newNodes, tmpnode)
		}
	}

	return newNodes
}

func ActivateWorkflowApp(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get active apps: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to activate workflow app (shared): %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	ctx := getContext(request)
	location := strings.Split(request.URL.String(), "/")
	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	app, err := GetApp(ctx, fileId, user, false)
	if err != nil {
		appName := request.URL.Query().Get("app_name")
		appVersion := request.URL.Query().Get("app_version")

		if len(appName) > 0 && len(appVersion) > 0 {
			apps, err := FindWorkflowAppByName(ctx, appName)
			//log.Printf("[INFO] Found %d apps for %s", len(apps), appName)
			if err != nil || len(apps) == 0 {
				log.Printf("[WARNING] Error getting app %s (app config): %s", appName, err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "App doesn't exist"}`))
				return
			}

			selectedApp := WorkflowApp{}
			for _, app := range apps {
				if !app.Sharing && !app.Public {
					continue
				}

				if app.Name == appName {
					selectedApp = app
				}

				if app.Name == appName && app.AppVersion == appVersion {
					selectedApp = app
				}
			}

			app = &selectedApp
		} else {
			log.Printf("[WARNING] Error getting app with ID %s (app config): %s", fileId, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "App doesn't exist"}`))
			return
		}
	}

	if app.Sharing || app.Public {
		org, err := GetOrg(ctx, user.ActiveOrg.Id)
		if err == nil {
			added := false
			if !ArrayContains(org.ActiveApps, app.ID) {
				org.ActiveApps = append(org.ActiveApps, app.ID)
				added = true
			}

			if added {
				err = SetOrg(ctx, *org, org.Id)
				if err != nil {
					log.Printf("[WARNING] Failed setting org when autoadding apps on save: %s", err)
				} else {
					log.Printf("[INFO] Added public app %s (%s) to org %s (%s)", app.Name, app.ID, user.ActiveOrg.Name, user.ActiveOrg.Id)
					cacheKey := fmt.Sprintf("apps_%s", user.Id)
					DeleteCache(ctx, cacheKey)
				}
			}
		}
	} else {
		log.Printf("[WARNING] User is trying to activate %s which is NOT public", app.Name)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	log.Printf("[DEBUG] App %s (%s) activated for org %s by user %s", app.Name, app.ID, user.ActiveOrg.Id, user.Username)

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func GetExecutionbody(body []byte) string {
	parsedBody := string(body)
	if strings.Contains(parsedBody, "choice") {
		if strings.Count(parsedBody, `\\n`) > 2 {
			parsedBody = strings.Replace(parsedBody, `\\n`, "", -1)
		}
		if strings.Count(parsedBody, `\u0022`) > 2 {
			parsedBody = strings.Replace(parsedBody, `\u0022`, `"`, -1)
		}
		if strings.Count(parsedBody, `\\"`) > 2 {
			parsedBody = strings.Replace(parsedBody, `\\"`, `"`, -1)
		}

		if strings.Contains(parsedBody, `"extra": "{`) {
			parsedBody = strings.Replace(parsedBody, `"extra": "{`, `"extra": {`, 1)
			parsedBody = strings.Replace(parsedBody, `}"}`, `}}`, 1)
		}
	}

	// Replaces dots in string. Bad regex :D
	pattern := regexp.MustCompile(`\"(\w+)\.(\w+)\":`)
	found := pattern.FindAllString(parsedBody, -1)
	for _, item := range found {
		newItem := strings.Replace(item, ".", "_", -1)
		parsedBody = strings.Replace(parsedBody, item, newItem, -1)
	}

	if !strings.HasPrefix(parsedBody, "{") && !strings.HasPrefix(parsedBody, "[") && strings.Contains(parsedBody, "=") {
		log.Printf("[DEBUG] Trying to make string %s to json", parsedBody)

		newbody := map[string]string{}
		for _, item := range strings.Split(parsedBody, "&") {
			//log.Printf("Handling item: %s", item)

			if !strings.Contains(item, "=") {
				newbody[item] = ""
				continue
			}

			bodySplit := strings.Split(item, "=")
			if len(bodySplit) == 2 {
				newbody[bodySplit[0]] = bodySplit[1]
			} else {
				newbody[item] = ""
			}
		}

		jsonString, err := json.Marshal(newbody)
		if err != nil {
			log.Printf("[ERROR] Failed marshaling queries: %#v: %s", newbody, err)
		} else {
			parsedBody = string(jsonString)
		}
		//fmt.Println(err)
		//log.Printf("BODY: %#v", newbody)
	}

	return parsedBody
}

func ValidateSwagger(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just here to verify that the user is logged in
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("Api authentication failed in validate swagger: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to validate swagger (shared): %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	type versionCheck struct {
		Swagger        string `datastore:"swagger" json:"swagger" yaml:"swagger"`
		SwaggerVersion string `datastore:"swaggerVersion" json:"swaggerVersion" yaml:"swaggerVersion"`
		OpenAPI        string `datastore:"openapi" json:"openapi" yaml:"openapi"`
	}

	//body = []byte(`swagger: "2.0"`)
	//body = []byte(`swagger: '1.0'`)
	//newbody := string(body)
	//newbody = strings.TrimSpace(newbody)
	//body = []byte(newbody)
	//log.Println(string(body))
	//tmpbody, err := yaml.YAMLToJSON(body)
	//log.Println(err)
	//log.Println(string(tmpbody))

	// This has to be done in a weird way because Datastore doesn't
	// support map[string]interface and similar (openapi3.Swagger)
	var version versionCheck

	re := regexp.MustCompile("[[:^ascii:]]")
	//re := regexp.MustCompile("[[:^unicode:]]")
	t := re.ReplaceAllLiteralString(string(body), "")
	log.Printf("[DEBUG] App build API length: %d. Cleanup length: %d", len(string(body)), len(t))
	body = []byte(t)

	isJson := false
	err = json.Unmarshal(body, &version)
	if err != nil {
		log.Printf("Json err: %s", err)
		err = yaml.Unmarshal(body, &version)
		if err != nil {
			log.Printf("Yaml error (3): %s", err)
			//if len(string(body)) < 500 {
			//	log.Printf("%s",
			//}
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed reading openapi to json and yaml. Is version defined?: %s"}`, err)))
			return
		} else {
			log.Printf("[INFO] Successfully parsed YAML (3)!")
		}
	} else {
		isJson = true
		log.Printf("[INFO] Successfully parsed JSON!")
	}

	if len(version.SwaggerVersion) > 0 && len(version.Swagger) == 0 {
		version.Swagger = version.SwaggerVersion
	}
	log.Printf("[INFO] Version: %#v", version)
	log.Printf("[INFO] OpenAPI: %s", version.OpenAPI)

	if strings.HasPrefix(version.Swagger, "3.") || strings.HasPrefix(version.OpenAPI, "3.") {
		log.Println("[INFO] Handling v3 API")
		swaggerLoader := openapi3.NewSwaggerLoader()
		swaggerLoader.IsExternalRefsAllowed = true
		swagger, err := swaggerLoader.LoadSwaggerFromData(body)
		if err != nil {
			log.Printf("[WARNING] Failed to convert v3 API: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
			return
		}

		hasher := md5.New()
		hasher.Write(body)
		idstring := hex.EncodeToString(hasher.Sum(nil))

		log.Printf("[INFO] Swagger v3 validation success with ID %s and %d paths!", idstring, len(swagger.Paths))

		if !isJson {
			log.Printf("[INFO] NEED TO TRANSFORM FROM YAML TO JSON for %s", idstring)
		}

		swaggerdata, err := json.Marshal(swagger)
		if err != nil {
			log.Printf("Failed unmarshaling v3 data: %s", err)
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed marshalling swaggerv3 data: %s"}`, err)))
			return
		}
		parsed := ParsedOpenApi{
			ID:   idstring,
			Body: string(swaggerdata),
		}

		ctx := getContext(request)
		err = SetOpenApiDatastore(ctx, idstring, parsed)
		if err != nil {
			log.Printf("Failed uploading openapi to datastore: %s", err)
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed reading openapi2: %s"}`, err)))
			return
		}

		log.Printf("[INFO] Successfully set OpenAPI with ID %s", idstring)
		resp.WriteHeader(200)
		resp.Write([]byte(fmt.Sprintf(`{"success": true, "id": "%s"}`, idstring)))
		return
	} else { //strings.HasPrefix(version.Swagger, "2.") || strings.HasPrefix(version.OpenAPI, "2.") {
		// Convert
		log.Println("Handling v2 API")
		swagger := openapi2.Swagger{}
		//log.Println(string(body))
		err = json.Unmarshal(body, &swagger)
		if err != nil {
			log.Printf("Json error for v2 - trying yaml: %s", err)
			err = yaml.Unmarshal([]byte(body), &swagger)
			if err != nil {
				log.Printf("Yaml error (4): %s", err)

				resp.WriteHeader(422)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed reading openapi2: %s"}`, err)))
				return
			} else {
				log.Printf("Found valid yaml!")
			}

		}

		swaggerv3, err := openapi2conv.ToV3Swagger(&swagger)
		if err != nil {
			log.Printf("Failed converting from openapi2 to 3: %s", err)
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed converting from openapi2 to openapi3: %s"}`, err)))
			return
		}

		swaggerdata, err := json.Marshal(swaggerv3)
		if err != nil {
			log.Printf("[WARNING] Failed unmarshaling v3 from v2 data: %s", err)
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed marshalling swaggerv3 data: %s"}`, err)))
			return
		}

		hasher := md5.New()
		hasher.Write(swaggerdata)
		idstring := hex.EncodeToString(hasher.Sum(nil))
		if !isJson {
			log.Printf("[WARNING] FIXME: NEED TO TRANSFORM FROM YAML TO JSON for %s?", idstring)
		}
		log.Printf("[INFO] Swagger v2 -> v3 validation success with ID %s!", idstring)

		parsed := ParsedOpenApi{
			ID:   idstring,
			Body: string(swaggerdata),
		}

		ctx := context.Background()
		err = SetOpenApiDatastore(ctx, idstring, parsed)
		if err != nil {
			log.Printf("[WARNING] Failed uploading openapi2 to datastore: %s", err)
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed reading openapi2: %s"}`, err)))
			return
		}

		resp.WriteHeader(200)
		resp.Write([]byte(fmt.Sprintf(`{"success": true, "id": "%s"}`, idstring)))
		return
	}
	/*
		else {
			log.Printf("Swagger / OpenAPI version %s is not supported or there is an error.", version.Swagger)
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Swagger version %s is not currently supported"}`, version.Swagger)))
			return
		}
	*/

	// save the openapi ID
	resp.WriteHeader(422)
	resp.Write([]byte(`{"success": false}`))
}

// Recursively finds child nodes inside sub workflows
func GetReplacementNodes(ctx context.Context, execution WorkflowExecution, trigger Trigger, lastTriggerName string) ([]Action, []Branch, string) {
	if execution.ExecutionOrg == "" {
		execution.ExecutionOrg = execution.Workflow.OrgId
	}

	selectedWorkflow := ""
	workflowAction := ""
	for _, param := range trigger.Parameters {
		if param.Name == "workflow" {
			selectedWorkflow = param.Value
		}

		if param.Name == "startnode" {
			workflowAction = param.Value
		}
	}

	if len(selectedWorkflow) == 0 {
		return []Action{}, []Branch{}, ""
	}

	// Authenticating and such
	workflow, err := GetWorkflow(ctx, selectedWorkflow)
	if err != nil {
		return []Action{}, []Branch{}, ""
	}

	orgFound := false
	if workflow.ExecutingOrg.Id == execution.ExecutionOrg {
		orgFound = true
	} else if workflow.OrgId == execution.ExecutionOrg {
		orgFound = true
	} else {
		for _, org := range workflow.Org {
			if org.Id == execution.ExecutionOrg {
				orgFound = true
				break
			}
		}
	}

	if !orgFound {
		log.Printf("[WARNING] Auth for subflow is bad. %s (orig) vs %s", execution.ExecutionOrg, workflow.OrgId)
		return []Action{}, []Branch{}, ""
	}

	//childNodes = FindChildNodes(workflowExecution, actionResult.Action.ID)
	log.Printf("FIND CHILDNODES OF STARTNODE %s", workflowAction)
	workflowExecution := WorkflowExecution{
		Workflow: *workflow,
	}

	childNodes := FindChildNodes(workflowExecution, workflowAction)
	log.Printf("Found %d childnodes of %s", len(childNodes), workflowAction)
	newActions := []Action{}
	branches := []Branch{}

	// FIXME: Bad lastnode check. Need to go to the bottom of workflows and check max steps away from parent
	lastNode := ""
	for _, nodeId := range childNodes {
		for _, action := range workflow.Actions {
			if nodeId == action.ID {
				newActions = append(newActions, action)
				break
			}
		}

		for _, branch := range workflow.Branches {
			if branch.SourceID == nodeId {
				branches = append(branches, branch)
			}
		}

		lastNode = nodeId
	}

	found := false
	for actionIndex, action := range newActions {
		if lastNode == action.ID {
			//actions[actionIndex].Name = trigger.Name
			newActions[actionIndex].Label = lastTriggerName
			//trigger.Label
			found = true
		}
	}

	if !found {
		log.Printf("SHOULD CHECK TRIGGERS FOR LASTNODE!")
	}

	log.Printf("[INFO] Found %d actions and %d branches in subflow", len(newActions), len(branches))
	if len(newActions) == len(childNodes) {
		return newActions, branches, lastNode
	} else {
		log.Printf("\n\n[WARNING] Bad length of actions and nodes in subflow (subsubflow?): %d vs %d", len(newActions), len(childNodes))

		// Adding information about triggers if subflow
		changed := false
		for _, nodeId := range childNodes {
			for triggerIndex, trigger := range workflow.Triggers {
				if trigger.AppName == "Shuffle Workflow" {
					if nodeId == trigger.ID {
						replaceActions := false
						workflowAction := ""
						for _, param := range trigger.Parameters {
							if param.Name == "argument" && !strings.Contains(param.Value, ".#") {
								replaceActions = true
							}

							if param.Name == "startnode" {
								workflowAction = param.Value
							}
						}

						if replaceActions {
							replacementNodes, newBranches, lastNode := GetReplacementNodes(ctx, workflowExecution, trigger, lastTriggerName)
							log.Printf("SUB REPLACEMENTS: %d, %d", len(replacementNodes), len(newBranches))
							log.Printf("\n\nNEW LASTNODE: %s\n\n", lastNode)
							if len(replacementNodes) > 0 {
								//workflowExecution.Workflow.Actions = append(workflowExecution.Workflow.Actions, action)

								//lastnode = replacementNodes[0]
								// Have to validate in case it's the same workflow and such
								for _, action := range replacementNodes {
									found := false
									for subActionIndex, subaction := range newActions {
										if subaction.ID == action.ID {
											found = true
											//newActions[subActionIndex].Name = action.Name
											newActions[subActionIndex].Label = action.Label
											break
										}
									}

									if !found {
										action.SubAction = true
										newActions = append(newActions, action)
									}
								}

								for _, branch := range newBranches {
									workflowExecution.Workflow.Branches = append(workflowExecution.Workflow.Branches, branch)
								}

								// Append branches:
								// parent -> new inner node (FIRST one)
								for branchIndex, branch := range workflowExecution.Workflow.Branches {
									if branch.DestinationID == trigger.ID {
										log.Printf("REPLACE DESTINATION WITH %s!!", workflowAction)
										workflowExecution.Workflow.Branches[branchIndex].DestinationID = workflowAction
										branches = append(branches, workflowExecution.Workflow.Branches[branchIndex])
									}

									if branch.SourceID == trigger.ID {
										log.Printf("REPLACE SOURCE WITH LASTNODE %s!!", lastNode)
										workflowExecution.Workflow.Branches[branchIndex].SourceID = lastNode
										branches = append(branches, workflowExecution.Workflow.Branches[branchIndex])
									}
								}

								// Remove the trigger
								workflowExecution.Workflow.Triggers = append(workflowExecution.Workflow.Triggers[:triggerIndex], workflowExecution.Workflow.Triggers[triggerIndex+1:]...)
								workflow.Triggers = append(workflow.Triggers[:triggerIndex], workflow.Triggers[triggerIndex+1:]...)
								changed = true
							}
						}
					}
				}

			}
		}

		log.Printf("NEW ACTION LENGTH %d, Branches: %d. LASTNODE: %s\n\n", len(newActions), len(branches), lastNode)
		if changed {
			return newActions, branches, lastNode
		}
	}

	return []Action{}, []Branch{}, ""
}

/*
func HandleGetSpecificStats(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	_, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("Api authentication failed in getting specific workflow: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")

	var statsId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		statsId = location[4]
	}

	ctx := context.Background()
	statisticsId := "global_statistics"
	nameKey := statsId
	key := datastore.NameKey(statisticsId, nameKey, nil)
	statisticsItem := StatisticsItem{}
	if err := project.Dbclient.Get(ctx, key, &statisticsItem); err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	b, err := json.Marshal(statisticsItem)
	if err != nil {
		log.Printf("Failed to marshal data: %s", err)
		resp.WriteHeader(401)
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(b))
}
*/

/*
func CleanupExecutions(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[INFO] Api authentication failed in cleanup executions: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "message": "Not authenticated"}`))
		return
	}

	if user.Role != "admin" {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "message": "Insufficient permissions"}`))
		return
	}

	ctx := context.Background()

	// Removes three months from today
	timestamp := int64(time.Now().AddDate(0, -2, 0).Unix())
	log.Println(timestamp)
	q := datastore.NewQuery("workflowexecution").Filter("started_at <", timestamp)
	var workflowExecutions []WorkflowExecution
	_, err = project.Dbclient.GetAll(ctx, q, &workflowExecutions)
	if err != nil {
		log.Printf("Error getting workflowexec (cleanup): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed getting all workflowexecutions"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}
*/

// Uses a simple way to be able to modify the encryption key being used
// FIXME: Investigate better ways of handling EVERYTHING related to encryption
// E.g. rolling keys and such
func create32Hash(key string) ([]byte, error) {
	encryptionModifier := os.Getenv("SHUFFLE_ENCRYPTION_MODIFIER")
	if len(encryptionModifier) == 0 {
		return []byte{}, errors.New(fmt.Sprintf("No encryption modifier set. Define SHUFFLE_ENCRYPTION_MODIFIER and NEVER change it to start encrypting auth."))
	}

	key += encryptionModifier
	hasher := md5.New()
	hasher.Write([]byte(key))
	return []byte(hex.EncodeToString(hasher.Sum(nil))), nil
}

func handleKeyEncryption(data string, passphrase string) (string, error) {
	key, err := create32Hash(passphrase)
	if err != nil {
		log.Printf("[WARNING] Failed hashing in encrypt: %s", err)
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("[WARNING] Error generating ciphertext: %s", err)
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("[WARNING] Error creating new GCM from block: %s", err)
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Printf("[WARNING] Error reading GCM nonce: %s", err)
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)

	// base64 encoding to ensure we can store it as a string
	parsedValue := base64.StdEncoding.EncodeToString(ciphertext)
	return parsedValue, nil
}

func HandleKeyDecryption(data string, passphrase string) (string, error) {
	key, err := create32Hash(passphrase)
	if err != nil {
		log.Printf("[WARNING] Failed hashing in decrypt: %s", err)
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("[WARNING] Error creating cipher from key in decryption: %s", err)
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("[WARNING] Error creating new GCM block in decryption: %s", err)
		return "", err
	}

	parsedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		log.Printf("[ERROR] Failed base64 decode for an auth key %s: %s", data, err)
		return "", err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := parsedData[:nonceSize], parsedData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Printf("[WARNING] Error reading decryptionkey: %s", err)
		return "", err
	}

	return string(plaintext), nil
}

func HandleGetCacheKey(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	//for key, value := range data.Apps {
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

	var tmpData CacheKeyData
	err = json.Unmarshal(body, &tmpData)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshalling in GET value: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if tmpData.OrgId != fileId {
		log.Printf("[INFO] OrgId %s and %s don't match", tmpData.OrgId, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Organization ID's don't match"}`))
		return
	}

	ctx := getContext(request)

	org, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("[INFO] Organization doesn't exist: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	workflowExecution, err := GetWorkflowExecution(ctx, tmpData.ExecutionId)
	if err != nil {
		log.Printf("[INFO] User can't edit the org")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "No permission to get execution"}`))
		return
	}

	// Allows for execution auth AND user auth
	if workflowExecution.Authorization != tmpData.Authorization {
		// Get the user?
		user, err := HandleApiAuthentication(resp, request)
		if err != nil {
			log.Printf("[INFO] Execution auth %s and %s don't match", workflowExecution.Authorization, tmpData.Authorization)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
			return
		} else {
			if user.ActiveOrg.Id != org.Id {
				log.Printf("[INFO] Execution auth %s and %s don't match (2)", workflowExecution.Authorization, tmpData.Authorization)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
				return
			}
		}

		_ = user
	}

	if workflowExecution.Status != "EXECUTING" {
		log.Printf("[INFO] Workflow %s isn't executing and shouldn't be searching", workflowExecution.ExecutionId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow isn't executing"}`))
		return
	}

	if workflowExecution.ExecutionOrg != org.Id {
		log.Printf("[INFO] Org %s wasn't used to execute %s", org.Id, workflowExecution.ExecutionId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Bad organization specified"}`))
		return
	}

	cacheId := fmt.Sprintf("%s_%s_%s", tmpData.OrgId, tmpData.WorkflowId, tmpData.Key)
	cacheData, err := GetCacheKey(ctx, cacheId)
	if err != nil {
		log.Printf("[WARNING] Failed to GET cache key %s for org %s", tmpData.Key, tmpData.OrgId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed to get key. Does it exist?"}`))
		return
	}

	cacheData.Success = true
	cacheData.ExecutionId = ""
	cacheData.Authorization = ""
	cacheData.OrgId = ""

	log.Printf("[INFO] Successfully GOT key %#v for org %s", tmpData.Key, tmpData.OrgId)
	b, err := json.Marshal(cacheData)
	if err != nil {
		log.Printf("[WARNING] Failed to GET cache key %s for org %s", tmpData.Key, tmpData.OrgId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed to get key. Does it exist?"}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(b)
}

func HandleSetCacheKey(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	//for key, value := range data.Apps {
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

	var tmpData CacheKeyData
	err = json.Unmarshal(body, &tmpData)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshalling in setvalue: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if tmpData.OrgId != fileId {
		log.Printf("[INFO] OrgId %s and %s don't match", tmpData.OrgId, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Organization ID's don't match"}`))
		return
	}

	ctx := getContext(request)

	org, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("[INFO] Organization doesn't exist: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	workflowExecution, err := GetWorkflowExecution(ctx, tmpData.ExecutionId)
	if err != nil {
		log.Printf("[INFO] User can't edit the org")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "No permission to get execution"}`))
		return
	}

	// Allows for execution auth AND user auth
	if workflowExecution.Authorization != tmpData.Authorization {
		// Get the user?
		user, err := HandleApiAuthentication(resp, request)
		if err != nil {
			log.Printf("[INFO] Execution auth %s and %s don't match", workflowExecution.Authorization, tmpData.Authorization)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
			return
		} else {
			if user.ActiveOrg.Id != org.Id {
				log.Printf("[INFO] Execution auth %s and %s don't match (2)", workflowExecution.Authorization, tmpData.Authorization)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
				return
			}
		}

		_ = user
	}

	if workflowExecution.Status != "EXECUTING" {
		log.Printf("[INFO] Workflow %s isn't executing and shouldn't be searching", workflowExecution.ExecutionId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow isn't executing"}`))
		return
	}

	if workflowExecution.ExecutionOrg != org.Id {
		log.Printf("[INFO] Org %s wasn't used to execute %s", org.Id, workflowExecution.ExecutionId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Bad organization specified"}`))
		return
	}

	if len(tmpData.Value) == 0 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Value can't be empty"}`))
		return
	}

	err = SetCacheKey(ctx, tmpData)
	if err != nil {
		log.Printf("[WARNING] Failed to set cache key %s for org %s", tmpData.Key, tmpData.OrgId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "Failed to set data"}`))
		return
	}

	log.Printf("[INFO] Successfully set key %#v for org %s (%s)", tmpData.Key, org.Name, tmpData.OrgId)
	type returnStruct struct {
		Success bool `json:"success"`
	}

	returnData := returnStruct{
		Success: true,
	}

	b, err := json.Marshal(returnData)
	if err != nil {
		b = []byte(`{"success": true}`)
	}

	resp.WriteHeader(200)
	resp.Write(b)
}

// Checks authentication string for Webhooks
func CheckHookAuth(request *http.Request, auth string) error {
	if len(auth) == 0 {
		return nil
	}

	authSplit := strings.Split(auth, "\n")
	for _, line := range authSplit {
		lineSplit := strings.Split(line, "=")
		if strings.Contains(line, ":") {
			lineSplit = strings.Split(line, "=")
		}

		if len(lineSplit) == 2 {
			validationHeader := strings.ToLower(strings.TrimSpace(lineSplit[0]))
			found := false
			for key, value := range request.Header {
				if strings.ToLower(key) == validationHeader && len(value) > 0 {
					//log.Printf("FOUND KEY %#v. Value: %s", validationHeader, value)
					if value[0] == strings.TrimSpace(lineSplit[1]) {
						found = true
						break
					}
				}
			}

			if !found {
				return errors.New(fmt.Sprintf("Missing or bad header: %#v", validationHeader))
			}

			//log.Printf("Find header %#v", validationHeader)
			//itemHeader := request.Header[validationHeader]
			//log.Printf("LINE: %s. Header: %s", line, itemHeader)
		} else {
			log.Printf("[WARNING] Bad auth line: %s. NOT checking auth.", line)
		}
	}

	//return errors.New("Bad auth!")
	return nil
}

// Fileid = the app to execute
// Body = The action body received from the user to test.
func PrepareSingleAction(ctx context.Context, user User, fileId string, body []byte) (WorkflowExecution, error) {
	var action Action
	workflowExecution := WorkflowExecution{}
	err = json.Unmarshal(body, &action)
	if err != nil {
		log.Printf("[WARNING] Failed action single execution unmarshaling: %s", err)
		return workflowExecution, err
	}

	/*
		if len(workflow.Name) > 0 || len(workflow.Owner) > 0 || len(workflow.OrgId) > 0 || len(workflow.Actions) != 1 {
			log.Printf("[WARNING] Bad length for some characteristics in single execution of %s", fileId)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	*/

	if fileId != action.AppID {
		log.Printf("[WARNING] Bad appid in single execution of App %s", fileId)
		return workflowExecution, err
	}

	if len(action.ID) == 0 {
		action.ID = uuid.NewV4().String()
	}

	app, err := GetApp(ctx, fileId, user, false)
	if err != nil {
		log.Printf("[WARNING] Error getting app (execute SINGLE workflow): %s", fileId)
		return workflowExecution, err
	}

	if app.Authentication.Required && len(action.AuthenticationId) == 0 {
		log.Printf("[WARNING] Tried to execute SINGLE %s WITHOUT auth (missing)", app.Name)

		found := false
		for _, param := range action.Parameters {
			if param.Configuration {
				found = true
				break
			}
		}

		if !found {
			return workflowExecution, errors.New("You must authenticate the app first")
		}
	}

	newParams := []WorkflowAppActionParameter{}
	if len(action.AuthenticationId) > 0 {
		log.Printf("[INFO] Adding auth in single execution!")
		curAuth, err := GetWorkflowAppAuthDatastore(ctx, action.AuthenticationId)

		if err != nil {
			log.Printf("[WARNING] Failed getting authentication for your org: %s", err)
			return workflowExecution, err
		}

		if user.ActiveOrg.Id != curAuth.OrgId {
			log.Printf("[WARNING] User %s tried to use bad auth %s", user.Id, action.AuthenticationId)
			return workflowExecution, err
		}

		// Rebuild params with the right data. This is to prevent issues on the frontend
		for _, auth := range curAuth.Fields {
			newParam := WorkflowAppActionParameter{
				Name:  auth.Key,
				ID:    action.AuthenticationId,
				Value: auth.Value,
			}

			newParams = append(newParams, newParam)
		}

		action.Parameters = newParams
	}

	for _, param := range action.Parameters {
		if param.Required && len(param.Value) == 0 {
			log.Printf("Param: %#v", param)

			value := fmt.Sprintf("Param %s can't be empty. Fill all required parameters.", param.Name)
			log.Printf("[WARNING] During single exec: %s", value)
			return workflowExecution, errors.New(value)
		}

		newParams = append(newParams, param)
	}

	action.Sharing = app.Sharing
	action.Public = app.Public
	action.Generated = app.Generated
	action.Parameters = newParams

	workflow := Workflow{
		Actions: []Action{
			action,
		},
		Start: action.ID,
		ID:    uuid.NewV4().String(),
	}

	//log.Printf("Sharing: %#v, Public: %#v, Generated: %#v. Start: %#v", action.Sharing, action.Public, action.Generated, workflow.Start)

	workflowExecution = WorkflowExecution{
		Workflow:      workflow,
		Start:         workflow.Start,
		ExecutionId:   uuid.NewV4().String(),
		WorkflowId:    workflow.ID,
		StartedAt:     int64(time.Now().Unix()),
		CompletedAt:   0,
		Authorization: uuid.NewV4().String(),
		Status:        "EXECUTING",
	}

	if user.ActiveOrg.Id != "" {
		workflow.ExecutingOrg = user.ActiveOrg
		workflowExecution.ExecutionOrg = user.ActiveOrg.Id
		workflowExecution.OrgId = user.ActiveOrg.Id
	}

	err = SetWorkflowExecution(ctx, workflowExecution, true)
	if err != nil {
		log.Printf("[WARNING] Failed handling single execution setup: %s", err)
		return workflowExecution, err
	}

	return workflowExecution, nil
}

func HandleRetValidation(ctx context.Context, workflowExecution WorkflowExecution) []byte {
	cnt := 0
	type retStruct struct {
		Success       bool   `json:"success"`
		Id            string `json:"id"`
		Authorization string `json:"authorization"`
		Result        string `json:"result"`
	}

	returnBody := retStruct{
		Success:       true,
		Id:            workflowExecution.ExecutionId,
		Authorization: workflowExecution.Authorization,
		Result:        "",
	}

	// VERY short sleeptime here on purpose
	maxSeconds := 10
	sleeptime := 25
	for {
		time.Sleep(25 * time.Millisecond)
		newExecution, err := GetWorkflowExecution(ctx, workflowExecution.ExecutionId)
		if err != nil {
			log.Printf("[WARNING] Failed getting single execution data: %s", err)
			break
		}

		if len(newExecution.Results) > 0 {
			if len(newExecution.Results[0].Result) > 0 {
				returnBody.Result = newExecution.Results[0].Result
				break
			}
		}

		cnt += 1
		//log.Println("Cnt: %d", cnt)
		if cnt == (maxSeconds * (maxSeconds * 100 / sleeptime)) {
			break
		}
	}

	if len(returnBody.Result) == 0 {
		returnBody.Success = false
	}

	returnBytes, err := json.Marshal(returnBody)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal retStruct in single execution: %s", err)
		return []byte{}
	}

	return returnBytes
}

func GetDocs(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	location := strings.Split(request.URL.String(), "/")
	if len(location) != 5 {
		resp.WriteHeader(404)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Bad path. Use e.g. /api/v1/docs/workflows.md"`)))
		return
	}

	ctx := getContext(request)
	cacheKey := fmt.Sprintf("docs_%s", location[4])
	cache, err := GetCache(ctx, cacheKey)
	if err == nil {
		cacheData := []byte(cache.([]uint8))
		resp.WriteHeader(200)
		resp.Write(cacheData)
		return
	}

	owner := "shuffle"
	repo := "shuffle-docs"
	path := "docs"
	docPath := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/master/%s/%s.md", owner, repo, path, location[4])

	httpClient := &http.Client{}
	req, err := http.NewRequest(
		"GET",
		docPath,
		nil,
	)

	if err != nil {
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Bad path. Use e.g. /api/v1/docs/workflows.md"}`)))
		resp.WriteHeader(404)
		return
	}

	newresp, err := httpClient.Do(req)
	if err != nil {
		resp.WriteHeader(404)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Bad path. Use e.g. /api/v1/docs/workflows.md"}`)))
		return
	}

	body, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't parse data"}`)))
		return
	}

	commitOptions := &github.CommitsListOptions{
		Path: fmt.Sprintf("%s/%s.md", path, location[4]),
	}

	client := github.NewClient(nil)
	githubResp := GithubResp{
		Name:         location[4],
		Contributors: []GithubAuthor{},
		Edited:       "",
		ReadTime:     len(body) / 10 / 250,
		Link:         fmt.Sprintf("https://github.com/%s/%s/blob/master/%s/%s.md", owner, repo, path, location[4]),
	}

	if githubResp.ReadTime == 0 {
		githubResp.ReadTime = 1
	}

	info, _, err := client.Repositories.ListCommits(ctx, owner, repo, commitOptions)
	if err != nil {
		log.Printf("[WARNING] Failed getting commit info: %s", err)
	} else {
		//log.Printf("Info: %#v", info)
		for _, commit := range info {
			//log.Printf("Commit: %#v", commit.Author)
			newAuthor := GithubAuthor{}
			if commit.Author != nil && commit.Author.AvatarURL != nil {
				newAuthor.ImageUrl = *commit.Author.AvatarURL
			}

			if commit.Author != nil && commit.Author.HTMLURL != nil {
				newAuthor.Url = *commit.Author.HTMLURL
			}

			found := false
			for _, contributor := range githubResp.Contributors {
				if contributor.Url == newAuthor.Url {
					found = true
					break
				}
			}

			if !found && len(newAuthor.Url) > 0 && len(newAuthor.ImageUrl) > 0 {
				githubResp.Contributors = append(githubResp.Contributors, newAuthor)
			}
		}
	}

	type Result struct {
		Success bool       `json:"success"`
		Reason  string     `json:"reason"`
		Meta    GithubResp `json:"meta"`
	}

	var result Result
	result.Success = true
	result.Meta = githubResp

	//applog.Infof(ctx, string(body))
	//applog.Infof(ctx, "Url: %s", docPath)
	//log.Printf("[INFO] GOT BODY OF LENGTH %d", len(string(body)))

	result.Reason = string(body)
	b, err := json.Marshal(result)
	if err != nil {
		http.Error(resp, err.Error(), 500)
		return
	}

	err = SetCache(ctx, cacheKey, b)
	if err != nil {
		log.Printf("[WARNING] Failed setting cache for doc %s: %s", location[4], err)
	}

	resp.WriteHeader(200)
	resp.Write(b)
}

func GetDocList(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	ctx := getContext(request)
	cacheKey := "docs_list"
	cache, err := GetCache(ctx, cacheKey)
	result := FileList{}
	if err == nil {
		cacheData := []byte(cache.([]uint8))
		resp.WriteHeader(200)
		resp.Write(cacheData)
		return
	}

	client := github.NewClient(nil)
	owner := "shuffle"
	repo := "shuffle-docs"
	path := "docs"
	_, item1, _, err := client.Repositories.GetContents(ctx, owner, repo, path, nil)
	if err != nil {
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Error listing directory"}`)))
		return
	}

	if len(item1) == 0 {
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "No docs available."}`)))
		return
	}

	names := []GithubResp{}
	for _, item := range item1 {
		if !strings.HasSuffix(*item.Name, "md") {
			continue
		}

		// Average word length = 5. Space = 1. 5+1 = 6 avg.
		// Words = *item.Size/6/250
		//250 = average read time / minute
		// Doubling this for bloat removal in Markdown~
		// Should fix this lol
		githubResp := GithubResp{
			Name:         (*item.Name)[0 : len(*item.Name)-3],
			Contributors: []GithubAuthor{},
			Edited:       "",
			ReadTime:     *item.Size / 6 / 250,
			Link:         fmt.Sprintf("https://github.com/%s/%s/blob/master/%s/%s", owner, repo, path, *item.Name),
		}

		names = append(names, githubResp)
	}

	//log.Println(names)
	result.Success = true
	result.Reason = "Success"
	result.List = names
	b, err := json.Marshal(result)
	if err != nil {
		http.Error(resp, err.Error(), 500)
		return
	}

	err = SetCache(ctx, cacheKey, b)
	if err != nil {
		log.Printf("[WARNING] Failed setting cache for cachekey %s: %s", cacheKey, err)
	}

	resp.WriteHeader(200)
	resp.Write(b)
}

func md5sum(data []byte) string {
	hasher := md5.New()
	hasher.Write(data)
	newmd5 := hex.EncodeToString(hasher.Sum(nil))
	return newmd5
}

// Checks if data is sent from Worker >0.8.51, which sends a full execution
// instead of individial results
func ValidateNewWorkerExecution(body []byte) error {
	ctx := context.Background()
	var execution WorkflowExecution
	err := json.Unmarshal(body, &execution)
	if err != nil {
		log.Printf("[WARNING] Failed execution unmarshaling: %s", err)
		return err
	}
	//log.Printf("\n\nGOT EXEC WITH RESULT %#v (%d)\n\n", execution.Status, len(execution.Results))

	baseExecution, err := GetWorkflowExecution(ctx, execution.ExecutionId)
	if err != nil {
		log.Printf("[ERROR] Failed getting execution (workflowqueue) %s: %s", execution.ExecutionId, err)
		return err
	}

	if baseExecution.Authorization != execution.Authorization {
		return errors.New("Bad authorization when validating execution")
	}

	// used to validate if it's actually the right marshal
	if len(baseExecution.Workflow.Actions) != len(execution.Workflow.Actions) {
		return errors.New(fmt.Sprintf("Bad length of actions (probably normal app): %d", len(execution.Workflow.Actions)))
	}

	if len(baseExecution.Workflow.Triggers) != len(execution.Workflow.Triggers) {
		return errors.New(fmt.Sprintf("Bad length of trigger: %d (probably normal app)", len(execution.Workflow.Triggers)))
	}

	//if len(baseExecution.Results) >= len(execution.Results) {
	if len(baseExecution.Results) > len(execution.Results) {
		return errors.New(fmt.Sprintf("Can't have less actions in a full execution than what exists: %d (old) vs %d (new)", len(baseExecution.Results), len(execution.Results)))
	}

	//if baseExecution.Status != "WAITING" && baseExecution.Status != "EXECUTING" {
	//	return errors.New(fmt.Sprintf("Workflow is already finished or failed. Can't update"))
	//}

	if execution.Status == "EXECUTING" {
		//log.Printf("[INFO] Inside executing.")
		extra := 0
		for _, trigger := range execution.Workflow.Triggers {
			//log.Printf("Appname trigger (0): %s", trigger.AppName)
			if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
				extra += 1
			}
		}

		if len(execution.Workflow.Actions)+extra == len(execution.Results) {
			execution.Status = "FINISHED"
		}
	}

	// Finds if subflow HAS a value when it should, otherwise it's not being set
	//log.Printf("\n\nUpdating worker execution info")
	for _, result := range execution.Results {
		//log.Printf("%s = %s", result.Action.AppName, result.Status)
		if result.Action.AppName == "shuffle-subflow" {
			if result.Status == "SKIPPED" {
				continue
			}

			log.Printf("\n\nFound SUBFLOW in full result send \n\n")
			for _, trigger := range baseExecution.Workflow.Triggers {
				if trigger.ID == result.Action.ID {
					log.Printf("Found SUBFLOW id: %s", trigger.ID)

					for _, param := range trigger.Parameters {
						if param.Name == "check_result" && param.Value == "true" {
							log.Printf("Found check as true!")

							var subflowData SubflowData
							err = json.Unmarshal([]byte(result.Result), &subflowData)
							if err != nil {
								log.Printf("Failed unmarshal in subflow check for %s: %s", result.Result, err)
							} else if len(subflowData.Result) == 0 {
								log.Printf("There is no result yet. Don't save?")
							} else {
								log.Printf("There is is a result: %s", result.Result)
							}

							break
						}
					}

					break
				}
			}
		}
	}

	// FIXME: Add extra here
	//executionLength := len(baseExecution.Workflow.Actions)
	//if executionLength != len(execution.Results) {
	//	return errors.New(fmt.Sprintf("Bad length of actions vs results: want: %d have: %d", executionLength, len(execution.Results)))
	//}

	err = SetWorkflowExecution(ctx, execution, true)
	if err == nil {
		log.Printf("[INFO] Set workflowexecution based on new worker (>0.8.53) for execution %s. Actions: %d, Triggers: %d, Results: %d, Status: %s", execution.ExecutionId, len(execution.Workflow.Actions), len(execution.Workflow.Triggers), len(execution.Results), execution.Status) //, execution.Result)
	} else {
		log.Printf("[WARNING] Failed setting the execution for new worker (>0.8.53) - retrying once: %s. ExecutionId: %s, Actions: %d, Triggers: %d, Results: %d, Status: %s", err, execution.ExecutionId, len(execution.Workflow.Actions), len(execution.Workflow.Triggers), len(execution.Results), execution.Status)
		// Retrying
		time.Sleep(5 * time.Second)
		err = SetWorkflowExecution(ctx, execution, true)
		if err != nil {
			log.Printf("[ERROR] Failed setting the execution for new worker (>0.8.53) - 2nd attempt: %s. ExecutionId: %s, Actions: %d, Triggers: %d, Results: %d, Status: %s", err, execution.ExecutionId, len(execution.Workflow.Actions), len(execution.Workflow.Triggers), len(execution.Results), execution.Status)
		}
	}

	return nil
}

func fixCertificate(parsedX509Key string) string {
	parsedX509Key = strings.Replace(parsedX509Key, "&#13;", "", -1)
	if strings.Contains(parsedX509Key, "BEGIN CERT") && strings.Contains(parsedX509Key, "END CERT") {
		parsedX509Key = strings.Replace(parsedX509Key, "-----BEGIN CERTIFICATE-----\n", "", -1)
		parsedX509Key = strings.Replace(parsedX509Key, "-----BEGIN CERTIFICATE-----", "", -1)
		parsedX509Key = strings.Replace(parsedX509Key, "-----END CERTIFICATE-----\n", "", -1)
		parsedX509Key = strings.Replace(parsedX509Key, "-----END CERTIFICATE-----", "", -1)
	}

	// PingOne issue
	parsedX509Key = strings.Replace(parsedX509Key, "\r\n", "", -1)
	parsedX509Key = strings.Replace(parsedX509Key, "\n", "", -1)
	parsedX509Key = strings.Replace(parsedX509Key, "\r", "", -1)
	parsedX509Key = strings.Replace(parsedX509Key, " ", "", -1)
	parsedX509Key = strings.TrimSpace(parsedX509Key)
	//log.Printf("Len: %d", len(parsedX509Key))
	//log.Printf("%#v", parsedX509Key)
	return parsedX509Key
}

// Example implementation of SSO, including a redirect for the user etc
// Should make this stuff only possible after login
func HandleSSO(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	//log.Printf("SSO LOGIN: %#v", request)
	// Deserialize
	// Serialize

	// SAML
	//entryPoint := "https://dev-23367303.okta.com/app/dev-23367303_shuffletest_1/exk1vg1j7bYUYEG0k5d7/sso/saml"
	redirectUrl := "http://localhost:3001/workflows"
	backendUrl := os.Getenv("BASE_URL")
	if len(backendUrl) > 0 {
		redirectUrl = fmt.Sprintf("%s/workflows", backendUrl)
	}

	if project.Environment == "cloud" {
		redirectUrl = "https://shuffler.io/workflows"
	}

	log.Printf("[DEBUG] Using %s as redirectUrl in SSO", backendUrl)

	//backendUrl := os.Getenv("BASE_URL")
	//if project.Environment == "cloud" {
	//	backendUrl = "https://shuffler.io"
	//}
	//if len(backendUrl) == 0 {
	//	backendUrl = "http://127.0.0.1:5001"
	//}

	//log.Printf("URL: %#v", request.URL)
	//log.Printf("REDIRECT: %s", redirectUrl)
	//_ = entryPoint

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Error with body read of SSO: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Parsing out without using Field
	parsedSAML := ""
	for _, item := range strings.Split(string(body), "&") {
		if strings.Contains(item, "SAMLResponse") {
			equalsplit := strings.Split(item, "=")
			if len(equalsplit) == 2 {
				//log.Printf("ITEM: %s", equalsplit[1])

				decodedValue, err := url.QueryUnescape(equalsplit[1])
				if err != nil {
					log.Printf("[WARNING] Failed url query escape: %s", err)
					resp.WriteHeader(401)
					resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed decoding saml value"}`)))
					return
				}

				parsedSAML = decodedValue
				break
			}
		}
	}

	bytesXML, err := base64.StdEncoding.DecodeString(parsedSAML)
	if err != nil {
		log.Printf("[WARNING] Failed base64 decode of SAML: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed base64 decoding in SAML"}`)))
		return
	}

	var samlResp SAMLResponse
	err = xml.Unmarshal(bytesXML, &samlResp)
	if err != nil {
		log.Printf("[WARNING] Failed XML unmarshal: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed XML unpacking in SAML"}`)))
		return
	}

	baseCertificate := samlResp.Signature.KeyInfo.X509Data.X509Certificate
	if len(baseCertificate) == 0 {
		//log.Printf("%#v", samlResp.Signature.KeyInfo.X509Data)
		baseCertificate = samlResp.Assertion.Signature.KeyInfo.X509Data.X509Certificate
	}

	//log.Printf("\n\n%d - CERT: %s\n\n", len(baseCertificate), baseCertificate)
	parsedX509Key := fixCertificate(baseCertificate)

	ctx := getContext(request)
	matchingOrgs, err := GetOrgByField(ctx, "sso_config.sso_certificate", parsedX509Key)
	if err != nil {
		log.Printf("[DEBUG] BYTES FROM REQUEST (DEBUG): %s", string(bytesXML))

		log.Printf("[WARNING] Bad certificate (%d): Failed to find a org with certificate matching the SSO", len(parsedX509Key))
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed finding an org with the right certificate"}`)))
		return
	}

	// Validating the orgs
	if len(matchingOrgs) >= 1 {
		newOrgs := []Org{}
		for _, org := range matchingOrgs {
			if org.SSOConfig.SSOCertificate == parsedX509Key {
				newOrgs = append(newOrgs, org)
			} else {
				log.Printf("[WARNING] Skipping org append because bad cert: %d vs %d", len(org.SSOConfig.SSOCertificate), len(parsedX509Key))

				//log.Printf(parsedX509Key)
				//log.Printf(org.SSOConfig.SSOCertificate)
			}
		}

		matchingOrgs = newOrgs
	}

	if len(matchingOrgs) != 1 {
		log.Printf("[DEBUG] BYTES FROM REQUEST (2 - DEBUG): %s", string(bytesXML))
		log.Printf("[WARNING] Bad certificate (%d). Original orgs: %d: X509 doesnt match certificate for any organization", len(parsedX509Key), len(matchingOrgs))
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Certificate for SSO doesn't match any organization"}`)))
		return
	}

	foundOrg := matchingOrgs[0]
	userName := samlResp.Assertion.Subject.NameID.Text
	if len(userName) == 0 {
		log.Printf("[WARNING] Failed finding user - No name: %#v", samlResp.Assertion.Subject)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed finding a user to authenticate"}`)))
		return
	}

	// Start actually fixing the user
	// 1. Check if the user exists - if it does - give it a valid cookie
	// 2. If it doesn't, find the correct org to connect them with, then register them

	if project.Environment == "cloud" {
		log.Printf("[WARNING] SAML SSO implemented for cloud yet")
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Cloud SSO not available for you"}`)))
		return
	}

	users, err := FindGeneratedUser(ctx, strings.ToLower(strings.TrimSpace(userName)))
	if err == nil && len(users) > 0 {
		for _, user := range users {
			log.Printf("%s - %s", user.GeneratedUsername, userName)
			if user.GeneratedUsername == userName {
				log.Printf("[AUDIT] Found user %s (%s) which matches SSO info for %s. Redirecting to login!", user.Username, user.Id, userName)

				//log.Printf("SESSION: %s", user.Session)

				expiration := time.Now().Add(3600 * time.Second)
				//if len(user.Session) == 0 {
				log.Printf("[INFO] User does NOT have session - creating")
				sessionToken := uuid.NewV4().String()
				http.SetCookie(resp, &http.Cookie{
					Name:    "session_token",
					Value:   sessionToken,
					Expires: expiration,
				})

				err = SetSession(ctx, user, sessionToken)
				if err != nil {
					log.Printf("[WARNING] Error creating session for user: %s", err)
					resp.WriteHeader(401)
					resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed setting session"}`)))
					return
				}

				user.Session = sessionToken
				err = SetUser(ctx, &user, false)
				if err != nil {
					log.Printf("[WARNING] Failed updating user when setting session: %s", err)
					resp.WriteHeader(401)
					resp.Write([]byte(`{"success": false, "reason": "Failed user update during session storage (2)"}`))
					return
				}

				//redirectUrl = fmt.Sprintf("%s?source=SSO&id=%s", redirectUrl, session)
				http.Redirect(resp, request, redirectUrl, http.StatusSeeOther)
				return
			}
		}
	}

	// Normal user. Checking because of backwards compatibility. Shouldn't break anything as we have unique names
	users, err = FindUser(ctx, strings.ToLower(strings.TrimSpace(userName)))
	if err == nil && len(users) > 0 {
		for _, user := range users {
			if user.Username == userName {
				log.Printf("[AUDIT] Found user %s (%s) which matches SSO info for %s. Redirecting to login!", user.Username, user.Id, userName)

				//log.Printf("SESSION: %s", user.Session)

				expiration := time.Now().Add(3600 * time.Second)
				//if len(user.Session) == 0 {
				log.Printf("[INFO] User does NOT have session - creating")
				sessionToken := uuid.NewV4().String()
				http.SetCookie(resp, &http.Cookie{
					Name:    "session_token",
					Value:   sessionToken,
					Expires: expiration,
				})

				err = SetSession(ctx, user, sessionToken)
				if err != nil {
					log.Printf("[WARNING] Error creating session for user: %s", err)
					resp.WriteHeader(401)
					resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed setting session"}`)))
					return
				}

				user.Session = sessionToken
				err = SetUser(ctx, &user, false)
				if err != nil {
					log.Printf("[WARNING] Failed updating user when setting session: %s", err)
					resp.WriteHeader(401)
					resp.Write([]byte(`{"success": false, "reason": "Failed user update during session storage (2)"}`))
					return
				}

				//redirectUrl = fmt.Sprintf("%s?source=SSO&id=%s", redirectUrl, session)
				http.Redirect(resp, request, redirectUrl, http.StatusSeeOther)
				return
			}
		}
	}

	/*
		orgs, err := GetAllOrgs(ctx)
		if err != nil {
			log.Printf("[WARNING] Failed finding orgs during SSO setup: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed getting valid organizations"}`)))
			return
		}

		foundOrg := Org{}
		for _, org := range orgs {
			if len(org.ManagerOrgs) == 0 {
				foundOrg = org
				break
			}
		}
	*/

	if len(foundOrg.Id) == 0 {
		log.Printf("[WARNING] Failed finding a valid org (default) without suborgs during SSO setup")
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed finding valid SSO auto org"}`)))
		return
	}

	log.Printf("[AUDIT] Adding user %s to org %s (%s) through single sign-on", userName, foundOrg.Name, foundOrg.Id)
	newUser := new(User)
	// Random password to ensure its not empty
	newUser.Password = uuid.NewV4().String()
	newUser.Username = userName
	newUser.GeneratedUsername = userName
	newUser.Verified = true
	newUser.Active = true
	newUser.CreationTime = time.Now().Unix()
	newUser.Orgs = []string{foundOrg.Id}
	newUser.LoginType = "SSO"
	newUser.Role = "user"
	newUser.Session = uuid.NewV4().String()

	verifyToken := uuid.NewV4()
	ID := uuid.NewV4()
	newUser.Id = ID.String()
	newUser.VerificationToken = verifyToken.String()

	expiration := time.Now().Add(3600 * time.Second)
	//if len(user.Session) == 0 {
	log.Printf("[INFO] User does NOT have session - creating")
	sessionToken := uuid.NewV4().String()
	http.SetCookie(resp, &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: expiration,
	})

	err = SetSession(ctx, *newUser, sessionToken)
	if err != nil {
		log.Printf("[WARNING] Error creating session for user: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed setting session"}`)))
		return
	}

	newUser.Session = sessionToken
	err = SetUser(ctx, newUser, true)
	if err != nil {
		log.Printf("[WARNING] Failed setting new user in DB: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed updating the user"}`)))
		return
	}

	http.Redirect(resp, request, redirectUrl, http.StatusSeeOther)
	return
}

// Downloads documentation from Github to be placed in an app/workflow as markdown
// Caching no matter what, with no retries
func DownloadFromUrl(ctx context.Context, url string) ([]byte, error) {
	cacheKey := fmt.Sprintf("docs_%s", url)
	cache, err := GetCache(ctx, cacheKey)
	if err == nil {
		cacheData := []byte(cache.([]uint8))
		return cacheData, nil
	}

	httpClient := &http.Client{}
	req, err := http.NewRequest(
		"GET",
		url,
		nil,
	)

	if err != nil {
		SetCache(ctx, cacheKey, []byte{})
		return []byte{}, err
	}

	newresp, err := httpClient.Do(req)
	if err != nil {
		return []byte{}, err
	}

	log.Printf("URL %#v, RESP: %d", url, newresp.StatusCode)
	if newresp.StatusCode != 200 {
		SetCache(ctx, cacheKey, []byte{})

		return []byte{}, errors.New(fmt.Sprintf("No body to handle for %#v. Status: %d", url, newresp.StatusCode))
	}

	body, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		SetCache(ctx, cacheKey, []byte{})
		return []byte{}, err
	}

	//log.Printf("Documentation: %#v", string(body))
	if len(body) > 0 {
		err = SetCache(ctx, cacheKey, body)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for workflow/app doc %s: %s", url, err)
		}
		return body, nil
	}

	SetCache(ctx, cacheKey, []byte{})
	return []byte{}, errors.New(fmt.Sprintf("No body to handle for %#v", url))
}

//// New execution with firestore
func PrepareWorkflowExecution(ctx context.Context, workflow Workflow, request *http.Request, maxExecutionDepth int64) (WorkflowExecution, ExecInfo, string, error) {

	workflowBytes, err := json.Marshal(workflow)
	if err != nil {
		log.Printf("Failed workflow unmarshal in execution: %s", err)
		return WorkflowExecution{}, ExecInfo{}, "", err
	}

	//log.Println(workflow)
	var workflowExecution WorkflowExecution
	err = json.Unmarshal(workflowBytes, &workflowExecution.Workflow)
	if err != nil {
		log.Printf("Failed execution unmarshaling: %s", err)
		return WorkflowExecution{}, ExecInfo{}, "Failed unmarshal during execution", err
	}

	makeNew := true
	start, startok := request.URL.Query()["start"]
	if request.Method == "POST" {
		body, err := ioutil.ReadAll(request.Body)
		if err != nil {
			log.Printf("[ERROR] Failed request POST read: %s", err)
			return WorkflowExecution{}, ExecInfo{}, "Failed getting body", err
		}

		// This one doesn't really matter.
		log.Printf("[INFO] Running POST execution with body of length %d for workflow %s", len(string(body)), workflowExecution.Workflow.ID)

		if len(body) >= 4 {
			if body[0] == 34 && body[len(body)-1] == 34 {
				body = body[1 : len(body)-1]
			}
			if body[0] == 34 && body[len(body)-1] == 34 {
				body = body[1 : len(body)-1]
			}
		}

		sourceAuth, sourceAuthOk := request.URL.Query()["source_auth"]
		if sourceAuthOk {
			//log.Printf("\n\n\nSETTING SOURCE WORKFLOW AUTH TO %s!!!\n\n\n", sourceAuth[0])
			workflowExecution.ExecutionSourceAuth = sourceAuth[0]
		} else {
			//log.Printf("Did NOT get source workflow")
		}

		sourceNode, sourceNodeOk := request.URL.Query()["source_node"]
		if sourceNodeOk {
			//log.Printf("\n\n\nSETTING SOURCE WORKFLOW NODE TO %s!!!\n\n\n", sourceNode[0])
			workflowExecution.ExecutionSourceNode = sourceNode[0]
		} else {
			//log.Printf("Did NOT get source workflow")
		}

		//workflowExecution.ExecutionSource = "default"
		sourceWorkflow, sourceWorkflowOk := request.URL.Query()["source_workflow"]
		if sourceWorkflowOk {
			//log.Printf("Got source workflow %s", sourceWorkflow)
			workflowExecution.ExecutionSource = sourceWorkflow[0]
		} else {
			//log.Printf("Did NOT get source workflow")
		}

		sourceExecution, sourceExecutionOk := request.URL.Query()["source_execution"]
		if sourceExecutionOk {
			//log.Printf("[INFO] Got source execution%s", sourceExecution)
			workflowExecution.ExecutionParent = sourceExecution[0]

			// FIXME: Get the execution and check count
			//workflowExecution.SubExecutionCount += 1

			log.Printf("\n\n[INFO] PARENT!!: %#v\n\n", workflowExecution.ExecutionParent)
			parentExecution, err := GetWorkflowExecution(ctx, workflowExecution.ExecutionParent)
			if err == nil {
				workflowExecution.SubExecutionCount = parentExecution.SubExecutionCount + 1
			}

			// Subflow are JUST lower than manual executions
			if workflowExecution.Priority == 0 {
				workflowExecution.Priority = 9
			}
		} else {
			//log.Printf("Did NOT get source execution")
		}

		if len(string(body)) < 50 {
			//log.Println(body)
			// String in string
			//log.Println(body)

			//if string(body)[0] == "\"" && string(body)[string(body)
			log.Printf("[DEBUG] Body: %#v", string(body))
		}

		var execution ExecutionRequest
		err = json.Unmarshal(body, &execution)
		if err != nil {
			log.Printf("[WARNING] Failed execution POST unmarshaling - continuing anyway: %s", err)
			//return WorkflowExecution{}, "", err
		}

		// Ensuring it works even if startpoint isn't defined
		if execution.Start == "" && len(body) > 0 && len(execution.ExecutionSource) == 0 {
			execution.ExecutionArgument = string(body)
		}

		// FIXME - this should have "execution_argument" from executeWorkflow frontend
		//log.Printf("EXEC: %#v", execution)
		if len(execution.ExecutionArgument) > 0 {
			workflowExecution.ExecutionArgument = execution.ExecutionArgument
		}

		if len(execution.ExecutionSource) > 0 {
			workflowExecution.ExecutionSource = execution.ExecutionSource

			if workflowExecution.Priority == 0 {
				workflowExecution.Priority = 5
			}
		}

		//log.Printf("Execution data: %#v", execution)
		if len(execution.Start) == 36 && len(workflow.Actions) > 0 {
			log.Printf("[INFO] Should start execution on node %s", execution.Start)
			workflowExecution.Start = execution.Start

			found := false
			for _, action := range workflow.Actions {
				if action.ID == execution.Start {
					found = true
					break
				}
			}

			if !found {
				log.Printf("[ERROR] Action %s was NOT found! Exiting execution.", execution.Start)
				return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Startnode %s was not found in actions", workflow.Start), errors.New(fmt.Sprintf("Startnode %s was not found in actions", workflow.Start))
			}
		} else if len(execution.Start) > 0 {
			//log.Printf("[INFO] !")
			//log.Printf("[ERROR] START ACTION %s IS WRONG ID LENGTH %d!", execution.Start, len(execution.Start))
			//return WorkflowExecution{}, fmt.Sprintf("Startnode %s was not found in actions", execution.Start), errors.New(fmt.Sprintf("Startnode %s was not found in actions", execution.Start))
		}

		if len(execution.ExecutionId) == 36 {
			workflowExecution.ExecutionId = execution.ExecutionId
		} else {
			sessionToken := uuid.NewV4()
			workflowExecution.ExecutionId = sessionToken.String()
		}
	} else {
		// Check for parameters of start and ExecutionId
		// This is mostly used for user input trigger

		answer, answerok := request.URL.Query()["answer"]
		referenceId, referenceok := request.URL.Query()["reference_execution"]
		if answerok && referenceok {
			// If answer is false, reference execution with result
			log.Printf("[INFO] Answer is OK AND reference is OK!")
			if answer[0] == "false" {
				log.Printf("Should update reference and return, no need for further execution!")

				// Get the reference execution
				oldExecution, err := GetWorkflowExecution(ctx, referenceId[0])
				if err != nil {
					log.Printf("Failed getting execution (execution) %s: %s", referenceId[0], err)
					return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Failed getting execution ID %s because it doesn't exist.", referenceId[0]), err
				}

				if oldExecution.Workflow.ID != workflow.ID {
					log.Println("Wrong workflowid!")
					return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Bad ID %s", referenceId), errors.New("Bad ID")
				}

				newResults := []ActionResult{}
				//log.Printf("%#v", oldExecution.Results)
				for _, result := range oldExecution.Results {
					log.Printf("%s - %s", result.Action.ID, start[0])
					if result.Action.ID == start[0] {
						note, noteok := request.URL.Query()["note"]
						if noteok {
							result.Result = fmt.Sprintf("User note: %s", note[0])
						} else {
							result.Result = fmt.Sprintf("User clicked %s", answer[0])
						}

						// Stopping the whole thing
						result.CompletedAt = int64(time.Now().Unix())
						result.Status = "ABORTED"
						oldExecution.Status = result.Status
						oldExecution.Result = result.Result
						oldExecution.LastNode = result.Action.ID
					}

					newResults = append(newResults, result)
				}

				oldExecution.Results = newResults
				err = SetWorkflowExecution(ctx, *oldExecution, true)
				if err != nil {
					log.Printf("Error saving workflow execution actionresult setting: %s", err)
					return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Failed setting workflowexecution actionresult in execution: %s", err), err
				}

				return WorkflowExecution{}, ExecInfo{}, "", nil
			}
		}

		if referenceok {
			log.Printf("Handling an old execution continuation!")
			// Will use the old name, but still continue with NEW ID
			oldExecution, err := GetWorkflowExecution(ctx, referenceId[0])
			if err != nil {
				log.Printf("Failed getting execution (execution) %s: %s", referenceId[0], err)
				return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Failed getting execution ID %s because it doesn't exist.", referenceId[0]), err
			}

			workflowExecution = *oldExecution

			// A previously stopped workflow. Same priority as subflow.
			workflowExecution.Priority = 9
		}

		if len(workflowExecution.ExecutionId) == 0 {
			sessionToken := uuid.NewV4()
			workflowExecution.ExecutionId = sessionToken.String()
		} else {
			log.Printf("Using the same executionId as before: %s", workflowExecution.ExecutionId)
			makeNew = false
		}

		// Don't override workflow defaults
	}

	if workflowExecution.SubExecutionCount == 0 {
		workflowExecution.SubExecutionCount = 1
	}

	//log.Printf("\n\nExecution count: %d", workflowExecution.SubExecutionCount)
	if workflowExecution.SubExecutionCount >= maxExecutionDepth {
		return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Max subflow of %d reached"), err
	}

	if workflowExecution.Priority == 0 {
		//log.Printf("\n\n[DEBUG] Set priority to 10 as it's manual?\n\n")
		workflowExecution.Priority = 10
	}

	if startok {
		//log.Printf("\n\n[INFO] Setting start to %s based on query!\n\n", start[0])
		//workflowExecution.Workflow.Start = start[0]
		workflowExecution.Start = start[0]
	}

	// FIXME - regex uuid, and check if already exists?
	if len(workflowExecution.ExecutionId) != 36 {
		log.Printf("Invalid uuid: %s", workflowExecution.ExecutionId)
		return WorkflowExecution{}, ExecInfo{}, "Invalid uuid", err
	}

	// FIXME - find owner of workflow
	// FIXME - get the actual workflow itself and build the request
	// MAYBE: Don't send the workflow within the pubsub, as this requires more data to be sent
	// Check if a worker already exists for company, else run one with:
	// locations, project IDs and subscription names

	// When app is executed:
	// Should update with status execution (somewhere), which will trigger the next node
	// IF action.type == internal, we need the internal watcher to be running and executing
	// This essentially means the WORKER has to be the responsible party for new actions in the INTERNAL landscape
	// Results are ALWAYS posted back to cloud@execution_id?
	if makeNew {
		workflowExecution.Type = "workflow"
		//workflowExecution.Stream = "tmp"
		//workflowExecution.WorkflowQueue = "tmp"
		//workflowExecution.SubscriptionNameNodestream = "testcompany-nodestream"
		//workflowExecution.Locations = []string{"europe-west2"}
		//workflowExecution.ProjectId = gceProject
		workflowExecution.WorkflowId = workflow.ID
		workflowExecution.StartedAt = int64(time.Now().Unix())
		workflowExecution.CompletedAt = 0
		workflowExecution.Authorization = uuid.NewV4().String()

		// Status for the entire workflow.
		workflowExecution.Status = "EXECUTING"
	}

	if len(workflowExecution.ExecutionSource) == 0 {
		log.Printf("[INFO] No execution source (trigger) specified. Setting to default")
		workflowExecution.ExecutionSource = "default"
	} else {
		log.Printf("[INFO] Execution source is %s for execution ID %s in workflow %s", workflowExecution.ExecutionSource, workflowExecution.ExecutionId, workflowExecution.Workflow.ID)
	}

	workflowExecution.ExecutionVariables = workflow.ExecutionVariables
	if len(workflowExecution.Start) == 0 && len(workflowExecution.Workflow.Start) > 0 {
		workflowExecution.Start = workflowExecution.Workflow.Start
	}

	startnodeFound := false
	newStartnode := ""
	for _, item := range workflowExecution.Workflow.Actions {
		if item.ID == workflowExecution.Start {
			startnodeFound = true
		}

		if item.IsStartNode {
			newStartnode = item.ID
		}
	}

	if !startnodeFound {
		log.Printf("[INFO] Couldn't find startnode %s. Remapping to %#v", workflowExecution.Start, newStartnode)

		if len(newStartnode) > 0 {
			workflowExecution.Start = newStartnode
		} else {
			return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Startnode couldn't be found"), errors.New("Startnode isn't defined in this workflow..")
		}
	}

	childNodes := FindChildNodes(workflowExecution, workflowExecution.Start)

	//topic := "workflows"
	startFound := false
	// FIXME - remove this?
	newActions := []Action{}
	defaultResults := []ActionResult{}

	allAuths := []AppAuthenticationStorage{}
	for _, action := range workflowExecution.Workflow.Actions {
		//action.LargeImage = ""
		if action.ID == workflowExecution.Start {
			startFound = true
		}
		//log.Println(action.Environment)

		if action.Environment == "" {
			return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Environment is not defined for %s", action.Name), errors.New("Environment not defined!")
		}

		// FIXME: Authentication parameters
		if len(action.AuthenticationId) > 0 {
			if len(allAuths) == 0 {
				allAuths, err = GetAllWorkflowAppAuth(ctx, workflow.ExecutingOrg.Id)
				if err != nil {
					log.Printf("Api authentication failed in get all app auth: %s", err)
					return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Api authentication failed in get all app auth: %s", err), err
				}
			}

			curAuth := AppAuthenticationStorage{Id: ""}
			authIndex := -1
			for innerIndex, auth := range allAuths {
				if auth.Id == action.AuthenticationId {
					authIndex = innerIndex
					curAuth = auth
					break
				}
			}

			if len(curAuth.Id) == 0 {
				return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Auth ID %s doesn't exist", action.AuthenticationId), errors.New(fmt.Sprintf("Auth ID %s doesn't exist", action.AuthenticationId))
			}

			if curAuth.Encrypted {
				setField := true
				newFields := []AuthenticationStore{}
				for _, field := range curAuth.Fields {
					parsedKey := fmt.Sprintf("%s_%d_%s_%s", curAuth.OrgId, curAuth.Created, curAuth.Label, field.Key)
					newValue, err := HandleKeyDecryption(field.Value, parsedKey)
					if err != nil {
						log.Printf("[ERROR] Failed decryption for %s: %s", field.Key, err)
						setField = false
						break
					}

					field.Value = newValue
					newFields = append(newFields, field)
				}

				if setField {
					curAuth.Fields = newFields
				}
			} else {
				log.Printf("[INFO] AUTH IS NOT ENCRYPTED - attempting auto-encrypting if key is set!")
				err = SetWorkflowAppAuthDatastore(ctx, curAuth, curAuth.Id)
				if err != nil {
					log.Printf("[WARNING] Failed running encryption during execution: %s", err)
				}
			}

			newParams := []WorkflowAppActionParameter{}
			if strings.ToLower(curAuth.Type) == "oauth2" {
				//log.Printf("[DEBUG] Should replace auth parameters (Oauth2)")

				runRefresh := false
				refreshUrl := ""
				for _, param := range curAuth.Fields {
					if param.Key == "expiration" {
						val, err := strconv.Atoi(param.Value)
						timeNow := int64(time.Now().Unix())
						if err == nil {
							//log.Printf("Checking expiration vs timenow: %d %d. Err: %s", timeNow, int64(val)+120, err)
							if timeNow >= int64(val)+120 {
								log.Printf("[DEBUG] Should run refresh of Oauth2 for %s!!", curAuth.Id)
								runRefresh = true
							}

						}

						continue
					}

					if param.Key == "refresh_url" {
						refreshUrl = param.Value
						continue
					}

					if param.Key != "url" && param.Key != "access_token" {
						//log.Printf("Skipping key %s", param.Key)
						continue
					}

					newParams = append(newParams, WorkflowAppActionParameter{
						Name:  param.Key,
						Value: param.Value,
					})
				}

				if runRefresh {
					user := User{
						Username: "refresh",
						ActiveOrg: OrgMini{
							Id: curAuth.OrgId,
						},
					}

					if len(refreshUrl) == 0 {
						log.Printf("[ERROR] No Oauth2 request to run, as no refresh url is set!")
					} else {
						log.Printf("[INFO] Running Oauth2 request with URL %s", refreshUrl)

						newAuth, err := RunOauth2Request(ctx, user, curAuth, true)
						if err != nil {
							log.Printf("[ERROR] Failed running oauth request to refresh oauth2 tokens: %s", err)
						} else {
							log.Printf("[DEBUG] Setting new auth to index: %d and curauth", authIndex)
							allAuths[authIndex] = newAuth
							newParams = []WorkflowAppActionParameter{}
							for _, param := range curAuth.Fields {
								if param.Key != "url" && param.Key != "access_token" {
									//log.Printf("Skipping key %s (2)", param.Key)
									continue
								}

								newParams = append(newParams, WorkflowAppActionParameter{
									Name:  param.Key,
									Value: param.Value,
								})

							}
						}
					}

				}

				for _, param := range action.Parameters {
					//log.Printf("Param: %#v", param)
					if param.Configuration {
						continue
					}

					newParams = append(newParams, param)
				}
			} else {
				// Rebuild params with the right data. This is to prevent issues on the frontend
				for _, param := range action.Parameters {

					for _, authparam := range curAuth.Fields {
						if param.Name == authparam.Key {
							param.Value = authparam.Value
							//log.Printf("Name: %s - value: %s", param.Name, param.Value)
							//log.Printf("Name: %s - value: %s\n", param.Name, param.Value)
							break
						}
					}

					newParams = append(newParams, param)
				}
			}

			action.Parameters = newParams
		}

		action.LargeImage = ""
		if len(action.Label) == 0 {
			action.Label = action.ID
		}
		//log.Printf("LABEL: %s", action.Label)
		newActions = append(newActions, action)

		// If the node is NOT found, it's supposed to be set to SKIPPED,
		// as it's not a childnode of the startnode
		// This is a configuration item for the workflow itself.
		if len(workflowExecution.Results) > 0 {
			defaultResults = []ActionResult{}
			for _, result := range workflowExecution.Results {
				if result.Status == "WAITING" {
					result.Status = "FINISHED"
					result.Result = "Continuing"
				}

				defaultResults = append(defaultResults, result)
			}
		} else if len(workflowExecution.Results) == 0 && !workflowExecution.Workflow.Configuration.StartFromTop {
			found := false
			for _, nodeId := range childNodes {
				if nodeId == action.ID {
					//log.Printf("Found %s", action.ID)
					found = true
				}
			}

			if !found {
				if action.ID == workflowExecution.Start {
					continue
				}

				//log.Printf("[WARNING] Set %s to SKIPPED as it's NOT a childnode of the startnode.", action.ID)
				curaction := Action{
					AppName:    action.AppName,
					AppVersion: action.AppVersion,
					Label:      action.Label,
					Name:       action.Name,
					ID:         action.ID,
				}
				//action
				//curaction.Parameters = []
				defaultResults = append(defaultResults, ActionResult{
					Action:        curaction,
					ExecutionId:   workflowExecution.ExecutionId,
					Authorization: workflowExecution.Authorization,
					Result:        "Skipped because it's not under the startnode",
					StartedAt:     0,
					CompletedAt:   0,
					Status:        "SKIPPED",
				})
			}
		}
	}

	removeTriggers := []string{}
	for triggerIndex, trigger := range workflowExecution.Workflow.Triggers {
		//log.Printf("[INFO] ID: %s vs %s", trigger.ID, workflowExecution.Start)
		if trigger.ID == workflowExecution.Start {
			if trigger.AppName == "User Input" {
				startFound = true
				break
			}
		}

		if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
			found := false
			for _, node := range childNodes {
				if node == trigger.ID {
					found = true
					break
				}
			}

			if !found {
				//log.Printf("SHOULD SET TRIGGER %s TO BE SKIPPED", trigger.ID)

				curaction := Action{
					AppName:    "shuffle-subflow",
					AppVersion: trigger.AppVersion,
					Label:      trigger.Label,
					Name:       trigger.Name,
					ID:         trigger.ID,
				}

				defaultResults = append(defaultResults, ActionResult{
					Action:        curaction,
					ExecutionId:   workflowExecution.ExecutionId,
					Authorization: workflowExecution.Authorization,
					Result:        "Skipped because it's not under the startnode",
					StartedAt:     0,
					CompletedAt:   0,
					Status:        "SKIPPED",
				})
			} else {
				// Replaces trigger with the subflow
				//if trigger.AppName == "Shuffle Workflow" {
				//	replaceActions := false
				//	workflowAction := ""
				//	for _, param := range trigger.Parameters {
				//		if param.Name == "argument" && !strings.Contains(param.Value, ".#") {
				//			replaceActions = true
				//		}

				//		if param.Name == "startnode" {
				//			workflowAction = param.Value
				//		}
				//	}

				//	if replaceActions {
				//		replacementNodes, newBranches, lastnode := GetReplacementNodes(ctx, workflowExecution, trigger, trigger.Label)
				//		log.Printf("REPLACEMENTS: %d, %d", len(replacementNodes), len(newBranches))
				//		if len(replacementNodes) > 0 {
				//			for _, action := range replacementNodes {
				//				found := false

				//				for subActionIndex, subaction := range newActions {
				//					if subaction.ID == action.ID {
				//						found = true
				//						//newActions[subActionIndex].Name = action.Name
				//						newActions[subActionIndex].Label = action.Label
				//						break
				//					}
				//				}

				//				if !found {
				//					action.SubAction = true
				//					newActions = append(newActions, action)
				//				}

				//				// Check if it's already set to have a value
				//				for resultIndex, result := range defaultResults {
				//					if result.Action.ID == action.ID {
				//						defaultResults = append(defaultResults[:resultIndex], defaultResults[resultIndex+1:]...)
				//						break
				//					}
				//				}
				//			}

				//			for _, branch := range newBranches {
				//				workflowExecution.Workflow.Branches = append(workflowExecution.Workflow.Branches, branch)
				//			}

				//			// Append branches:
				//			// parent -> new inner node (FIRST one)
				//			for branchIndex, branch := range workflowExecution.Workflow.Branches {
				//				if branch.DestinationID == trigger.ID {
				//					log.Printf("REPLACE DESTINATION WITH %s!!", workflowAction)
				//					workflowExecution.Workflow.Branches[branchIndex].DestinationID = workflowAction
				//				}

				//				if branch.SourceID == trigger.ID {
				//					log.Printf("REPLACE SOURCE WITH LASTNODE %s!!", lastnode)
				//					workflowExecution.Workflow.Branches[branchIndex].SourceID = lastnode
				//				}
				//			}

				//			// Remove the trigger
				//			removeTriggers = append(removeTriggers, workflowExecution.Workflow.Triggers[triggerIndex].ID)
				//		}

				//		log.Printf("NEW ACTION LENGTH %d, RESULT: %d, Triggers: %d, BRANCHES: %d", len(newActions), len(defaultResults), len(workflowExecution.Workflow.Triggers), len(workflowExecution.Workflow.Branches))
				//	}
				//}
				_ = triggerIndex
			}
		}
	}

	//newTriggers := []Trigger{}
	//for _, trigger := range workflowExecution.Workflow.Triggers {
	//	found := false
	//	for _, triggerId := range removeTriggers {
	//		if trigger.ID == triggerId {
	//			found = true
	//			break
	//		}
	//	}

	//	if found {
	//		log.Printf("[WARNING] Removed trigger %s during execution", trigger.ID)
	//		continue
	//	}

	//	newTriggers = append(newTriggers, trigger)
	//}
	//workflowExecution.Workflow.Triggers = newTriggers
	_ = removeTriggers

	if !startFound {
		if len(workflowExecution.Start) == 0 && len(workflowExecution.Workflow.Start) > 0 {
			workflowExecution.Start = workflow.Start
		} else if len(workflowExecution.Workflow.Actions) > 0 {
			workflowExecution.Start = workflowExecution.Workflow.Actions[0].ID
		} else {
			log.Printf("[ERROR] Startnode %s doesn't exist!!", workflowExecution.Start)
			return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Workflow action %s doesn't exist in workflow", workflowExecution.Start), errors.New(fmt.Sprintf(`Workflow start node "%s" doesn't exist. Exiting!`, workflowExecution.Start))
		}
	}

	//log.Printf("EXECUTION START: %s", workflowExecution.Start)

	// Verification for execution environments
	workflowExecution.Results = defaultResults
	workflowExecution.Workflow.Actions = newActions
	onpremExecution := true
	environments := []string{}

	if len(workflowExecution.ExecutionOrg) == 0 && len(workflow.ExecutingOrg.Id) > 0 {
		workflowExecution.ExecutionOrg = workflow.ExecutingOrg.Id
	}

	var allEnvs []Environment
	if len(workflowExecution.ExecutionOrg) > 0 {
		//log.Printf("[INFO] Executing ORG: %s", workflowExecution.ExecutionOrg)

		allEnvironments, err := GetEnvironments(ctx, workflowExecution.ExecutionOrg)
		if err != nil {
			log.Printf("Failed finding environments: %s", err)
			return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Workflow environments not found for this org"), errors.New(fmt.Sprintf("Workflow environments not found for this org"))
		}

		for _, curenv := range allEnvironments {
			if curenv.Archived {
				continue
			}

			allEnvs = append(allEnvs, curenv)
		}
	} else {
		log.Printf("[ERROR] No org identified for execution of %s. Returning", workflowExecution.Workflow.ID)
		return WorkflowExecution{}, ExecInfo{}, "No org identified for execution", errors.New("No org identified for execution")
	}

	if len(allEnvs) == 0 {
		log.Printf("[ERROR] No active environments found for org: %s", workflowExecution.ExecutionOrg)
		return WorkflowExecution{}, ExecInfo{}, "No active environments found", errors.New(fmt.Sprintf("No active env found for org %s", workflowExecution.ExecutionOrg))
	}

	// Check if the actions are children of the startnode?
	imageNames := []string{}
	cloudExec := false
	for _, action := range workflowExecution.Workflow.Actions {
		// Verify if the action environment exists and append
		found := false
		for _, env := range allEnvs {
			if env.Name == action.Environment {
				found = true

				if env.Type == "cloud" {
					cloudExec = true
				} else if env.Type == "onprem" {
					onpremExecution = true
				} else {
					log.Printf("[ERROR] No handler for environment type %s", env.Type)
					return WorkflowExecution{}, ExecInfo{}, "No active environments found", errors.New(fmt.Sprintf("No handler for environment type %s", env.Type))
				}
				break
			}
		}

		if !found {
			if strings.ToLower(action.Environment) == "cloud" && project.Environment == "cloud" {
				log.Printf("[DEBUG] Couldn't find environment %s in cloud for some reason.", action.Environment)
			} else {
				log.Printf("[WARNING] Couldn't find environment %s. Maybe it's inactive?", action.Environment)
				return WorkflowExecution{}, ExecInfo{}, "Couldn't find the environment", errors.New(fmt.Sprintf("Couldn't find env %s in org %s", action.Environment, workflowExecution.ExecutionOrg))
			}
		}

		found = false
		for _, env := range environments {
			if env == action.Environment {

				found = true
				break
			}
		}

		// Check if the app exists?
		newName := action.AppName
		newName = strings.Replace(newName, " ", "-", -1)
		imageNames = append(imageNames, fmt.Sprintf("%s:%s_%s", baseDockerName, newName, action.AppVersion))

		if !found {
			environments = append(environments, action.Environment)
		}
	}

	//b, err := json.Marshal(workflowExecution)
	//if err == nil {
	//	log.Printf("LEN: %d", len(string(b)))
	//	//workflowExecution.ExecutionOrg.SyncFeatures = Org{}
	//}

	workflowExecution.Workflow.ExecutingOrg = OrgMini{
		Id: workflowExecution.Workflow.ExecutingOrg.Id,
	}
	workflowExecution.Workflow.Org = []OrgMini{
		workflowExecution.Workflow.ExecutingOrg,
	}

	return workflowExecution, ExecInfo{OnpremExecution: onpremExecution, Environments: environments, CloudExec: cloudExec, ImageNames: imageNames}, "", nil
}

func HealthCheckHandler(resp http.ResponseWriter, request *http.Request) {
	fmt.Fprint(resp, "OK")
}

func GetAppRequirements() string {
	return "requests==2.25.1\nurllib3==1.25.9\nliquidpy==0.7.3\nMarkupSafe==2.0.1\nflask[async]==2.0.2\n"
}

// Extra validation sample to be used for workflow executions based on parent workflow instead of users' auth

// Check if the execution data has correct info in it! Happens based on subflows.
// 1. Parent workflow contains this workflow ID in the source trigger?
// 2. Parent workflow's owner is same org?
// 3. Parent execution auth is correct
func RunExecuteAccessValidation(request *http.Request, workflow *Workflow) (bool, string) {
	log.Printf("[DEBUG] Inside execute validation!")

	if request.Method == "POST" {
		body, err := ioutil.ReadAll(request.Body)
		if err != nil {
			log.Printf("[ERROR] Failed request POST read: %s", err)
			return false, ""
		}

		// This one doesn't really matter.
		//log.Printf("[INFO] Running POST execution with body of length %d for workflow %s", len(string(body)), workflowExecution.Workflow.ID)

		if len(body) >= 4 {
			if body[0] == 34 && body[len(body)-1] == 34 {
				body = body[1 : len(body)-1]
			}
			if body[0] == 34 && body[len(body)-1] == 34 {
				body = body[1 : len(body)-1]
			}
		}

		ctx := getContext(request)
		workflowExecution := &WorkflowExecution{}
		sourceExecution, sourceExecutionOk := request.URL.Query()["source_execution"]
		if sourceExecutionOk {
			log.Printf("[DEBUG] Got source exec %s", sourceExecution)
			workflowExecution, err = GetWorkflowExecution(ctx, sourceExecution[0])
			if err != nil {
				log.Printf("[INFO] Failed getting source_execution in test validation based on %#v", sourceExecution[0])
				return false, ""
			}

		} else {
			return false, ""
		}

		if workflowExecution.ExecutionId == "" {
			log.Printf("[WARNING] No execution ID found. Bad auth.")
			return false, ""
		}

		sourceAuth, sourceAuthOk := request.URL.Query()["source_auth"]
		if sourceAuthOk {
			log.Printf("[DEBUG] Got auth %s", sourceAuth)

			if sourceAuth[0] != workflowExecution.Authorization {
				log.Printf("[WARNING] Bad authorization for workflowexecution defined.")
				return false, ""
			}
		} else {
			return false, ""
		}

		// When reaching here, authentication is done, but not authorization.
		// Need to verify the workflow, and whether it SHOULD have access to execute it.
		sourceWorkflow, sourceWorkflowOk := request.URL.Query()["source_workflow"]
		if sourceWorkflowOk {
			log.Printf("[DEBUG] Got source workflow %s", sourceWorkflow)

			// Source workflow = parent
			// This workflow = child

			//if sourceWorkflow[0] != workflow.ID {
			//	log.Printf("[DEBUG] Bad workflow in execution.")
			//	return false, ""
			//}

		} else {
			//log.Printf("Did NOT get source workflow")
			return false, ""
		}

		if workflow.OrgId != workflowExecution.Workflow.OrgId || workflow.ExecutingOrg.Id != workflowExecution.Workflow.ExecutingOrg.Id || workflow.OrgId == "" {
			//e9274e37e53631a2321747b1be088f4d2631a6300a309eec9b4515c8528c35f4
			return false, ""
		}

		// 1. Parent workflow contains this workflow ID in the source trigger?
		// 2. Parent workflow's owner is same org?
		// 3. Parent execution auth is correct

		sourceNode, sourceNodeOk := request.URL.Query()["source_node"]
		if sourceNodeOk {
			log.Printf("[DEBUG] Got source node %s", sourceNode)
			//workflowExecution.ExecutionSourceNode = sourceNode[0]
		} else {
			return false, ""
		}

		// SHOULD be executed by a trigger in the parent.
		for _, trigger := range workflowExecution.Workflow.Triggers {
			if sourceNode[0] == trigger.ID {
				return true, workflowExecution.ExecutionOrg
			}
		}
	}

	return false, ""
}

func findReferenceAppDocs(ctx context.Context, allApps []WorkflowApp) []WorkflowApp {
	newApps := []WorkflowApp{}
	for _, app := range allApps {
		if len(app.ReferenceInfo.DocumentationUrl) > 0 && strings.HasPrefix(app.ReferenceInfo.DocumentationUrl, "https://raw.githubusercontent.com/Shuffle") && strings.Contains(app.ReferenceInfo.DocumentationUrl, ".md") {
			// Should find documentation from the github (only if github?) and add it to app.Documentation before caching
			log.Printf("DOCS: %#v", app.ReferenceInfo.DocumentationUrl)
			documentationData, err := DownloadFromUrl(ctx, app.ReferenceInfo.DocumentationUrl)
			if err != nil {
				log.Printf("[ERROR] Failed getting data: %#v", err)
			} else {
				app.Documentation = string(documentationData)
			}
		}

		if app.Documentation == "" && strings.ToLower(app.Name) == "discord" {
			log.Printf("Trying to find documentation for %#v", app.Name)
			referenceUrl := ""

			if app.Generated {
				log.Printf("[DEBUG] Should look in the OpenAPI folder")
				baseUrl := "https://raw.githubusercontent.com/Shuffle/openapi-apps/master/docs"

				newName := strings.ToLower(strings.Replace(strings.Replace(app.Name, " ", "_", -1), "-", "_", -1))
				referenceUrl = fmt.Sprintf("%s/%s.md", baseUrl, newName)
			} else {
				log.Printf("[DEBUG] Should look in the Python-apps folder")
			}

			if len(referenceUrl) > 0 {
				log.Printf("REF: %#v", referenceUrl)

				documentationData, err := DownloadFromUrl(ctx, referenceUrl)
				if err != nil {
					log.Printf("[ERROR] Failed getting data for app %#v: %#v", app.Name, err)
				} else {
					app.Documentation = string(documentationData)
				}
			}
		}

		newApps = append(newApps, app)
	}

	return newApps
}
