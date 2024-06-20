package shuffle

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"sync"

	"gopkg.in/yaml.v3"

	//"os/exec"
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
	mathrand "math/rand"

	"github.com/bradfitz/slice"
	uuid "github.com/satori/go.uuid"
	"github.com/sendgrid/sendgrid-go"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/frikky/kin-openapi/openapi2"
	"github.com/frikky/kin-openapi/openapi2conv"
	"github.com/frikky/kin-openapi/openapi3"

	"github.com/frikky/schemaless"
	"github.com/google/go-github/v28/github"
	"golang.org/x/crypto/bcrypt"

	"github.com/Masterminds/semver"
)

var project ShuffleStorage
var baseDockerName = "frikky/shuffle"
var SSOUrl = ""
var kmsDebug = false

func RequestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		next.ServeHTTP(w, r)
	})
}

var sandboxProject = "shuffle-sandbox-337810"

func GetContext(request *http.Request) context.Context {
	return context.Background()

	if project.Environment == "cloud" && len(memcached) == 0 {
		// No longer prevalent due to Appengine update and running pure Go backend
		//return appengine.NewContext(request)
	}

	return context.Background()
}

func HandleCors(resp http.ResponseWriter, request *http.Request) bool {
	origin := request.Header["Origin"]
	resp.Header().Set("Vary", "Origin")

	if len(origin) > 0 {
		resp.Header().Set("Access-Control-Allow-Origin", origin[0])

		// Location testing
		//resp.Header().Set("Access-Control-Allow-Origin", "https://ca.shuffler.io")
		//resp.Header().Set("Access-Control-Allow-Origin", "https://us.shuffler.io")
		//resp.Header().Set("Access-Control-Allow-Origin", "https://eu.shuffler.io")
		//resp.Header().Set("Access-Control-Allow-Origin", "https://in.shuffler.io")
		//resp.Header().Set("Access-Control-Allow-Origin", "http://localhost:3002")
	} else {
		resp.Header().Set("Access-Control-Allow-Origin", "http://localhost:4201")
	}

	//resp.Header().Set("Access-Control-Allow-Origin", "http://localhost:8000")
	resp.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, X-Requested-With, remember-me, Org-Id, Authorization, X-Debug-Url")
	resp.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, PATCH")
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

	ctx := GetContext(request)
	var user User
	var userId string
	userSettingUpMfa := false
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		parts := strings.Split(request.URL.Path, "/")
		if len(parts) < 5 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Invalid URL path."}`))
			return
		}

		MFACode := parts[4]

		// Retrieve user ID and unique code from cache
		cacheUserId, err := GetCache(ctx, fmt.Sprintf("user_id_%s", MFACode))
		if err != nil {
			log.Printf("[ERROR] Failed to retrieve user ID from cache: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed to retrieve user ID from cache."}`))
			return
		}

		cacheUniqueCode, err := GetCache(ctx, fmt.Sprintf("mfa_code_%s", MFACode))
		if err != nil {
			log.Printf("[ERROR] Failed to retrieve mfa code from cache: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed to retrieve MFA code from cache."}`))
			return
		}

		//if user id and unique code are not empty, user is setting up MFA
		if len(cacheUserId.([]byte)) > 0 && len(cacheUniqueCode.([]byte)) > 0 {
			userSettingUpMfa = true
		}

		if mfaCodeBytes, ok := cacheUniqueCode.([]byte); ok {
			cacheUniqueCode = string(mfaCodeBytes)
		}

		//Both unique code present in cache and MFA code token present in url request must match
		if cacheUniqueCode != MFACode {
			log.Printf("[ERROR] user_id or uniqueId does not match")
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"success": false, "reason": "user_id or uniqueId does not match."}`))
			return
		}

		if userIdBytes, ok := cacheUserId.([]byte); ok {
			userId = string(userIdBytes)
		}
	}

	var cacheUser *User

	// check if user id received from cache is not empty
	if len(userId) > 0 && userSettingUpMfa == true {
		cacheUser, err = GetUser(ctx, userId)
		if err != nil {
			log.Printf("[ERROR] Failed to retrieve user from cache: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed to retrieve user from cache."}`))
			return
		}
	}

	//if user id is empty, use the user data from cache
	if len(user.Id) == 0 {
		user = *cacheUser
	}

	if project.Environment == "cloud" {
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting SET 2fa request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)

			DeleteCache(ctx, fmt.Sprintf("Organizations_%s", user.ActiveOrg.Id))
			DeleteCache(ctx, fmt.Sprintf("user_%s", strings.ToLower(user.Username)))
			DeleteCache(ctx, fmt.Sprintf("user_%s", strings.ToLower(user.Id)))
			return
		}
	}

	var fileId string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 && userSettingUpMfa == false {
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

	org, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[ERROR] Failed getting org %s: %s", user.ActiveOrg.Id, err)
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting your org."}`))
		return
	}

	// FIXME: Everything should match?
	// || user.Id != tmpBody.UserId
	if user.Id != fileId && userSettingUpMfa == false {
		log.Printf("[WARNING] Bad ID: %s vs %s", user.Id, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can only set 2fa for your own user. Pass field user_id in JSON."}`)))
		return
	}

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

	MFAActive := false
	if foundUser.MFA.Active == true {
		foundUser.MFA.Active = false
		foundUser.MFA.PreviousCode = foundUser.MFA.ActiveCode
		foundUser.MFA.ActiveCode = ""
		MFAActive = false
		log.Printf("[DEBUG] Successfully disable 2FA authentication for user %s (%s)", foundUser.Username, foundUser.Id)
	} else {
		foundUser.MFA.Active = true
		foundUser.MFA.ActiveCode = foundUser.MFA.PreviousCode
		foundUser.MFA.PreviousCode = ""
		MFAActive = true
		log.Printf("[DEBUG] Successfully Enable 2FA authentication for user %s (%s)", foundUser.Username, foundUser.Id)
	}

	err = SetUser(ctx, foundUser, true)
	if err != nil {
		log.Printf("[WARNING] Failed SETTING MFA for user %s (%s): %s", foundUser.Username, foundUser.Id, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed updating your user. Please try again."}`))
		return
	}

	// log.Printf("[DEBUG] Successfully enabled 2FA for user %s (%s)", foundUser.Username, foundUser.Id)

	// If user is setting up MFA, than reset the user session or create a new one
	if userSettingUpMfa {
		user.LoginInfo = append(user.LoginInfo, LoginInfo{
			IP:        GetRequestIp(request),
			Timestamp: time.Now().Unix(),
		})

		tutorialsFinished := []Tutorial{}
		for _, tutorial := range user.PersonalInfo.Tutorials {
			tutorialsFinished = append(tutorialsFinished, Tutorial{
				Name: tutorial,
			})
		}

		if len(org.SecurityFramework.SIEM.Name) > 0 || len(org.SecurityFramework.Network.Name) > 0 || len(org.SecurityFramework.EDR.Name) > 0 || len(org.SecurityFramework.Cases.Name) > 0 || len(org.SecurityFramework.IAM.Name) > 0 || len(org.SecurityFramework.Assets.Name) > 0 || len(org.SecurityFramework.Intel.Name) > 0 || len(org.SecurityFramework.Communication.Name) > 0 {
			tutorialsFinished = append(tutorialsFinished, Tutorial{
				Name: "find_integrations",
			})
		}

		for _, tutorial := range org.Tutorials {
			tutorialsFinished = append(tutorialsFinished, tutorial)
		}

		//log.Printf("[INFO] Tutorials finished: %v", tutorialsFinished)

		returnValue := HandleInfo{
			Success:   true,
			Tutorials: tutorialsFinished,
		}

		loginData := `{"success": true}`
		newData, err := json.Marshal(returnValue)
		if err == nil {
			loginData = string(newData)
		}

		if len(user.Session) != 0 {
			log.Printf("[INFO] User session exists - resetting session")
			expiration := time.Now().Add(3600 * time.Second)

			newCookie := &http.Cookie{
				Name:    "session_token",
				Value:   user.Session,
				Expires: expiration,
				Path:    "/",
			}

			if project.Environment == "cloud" {
				newCookie.Domain = ".shuffler.io"
				newCookie.Secure = true
				newCookie.HttpOnly = true
			}

			http.SetCookie(resp, newCookie)

			newCookie.Name = "__session"
			http.SetCookie(resp, newCookie)

			//log.Printf("SESSION LENGTH MORE THAN 0 IN LOGIN: %s", user.Session)
			returnValue.Cookies = append(returnValue.Cookies, SessionCookie{
				Key:        "session_token",
				Value:      user.Session,
				Expiration: expiration.Unix(),
			})

			returnValue.Cookies = append(returnValue.Cookies, SessionCookie{
				Key:        "__session",
				Value:      user.Session,
				Expiration: expiration.Unix(),
			})

			loginData = fmt.Sprintf(`{"success": true, "cookies": [{"key": "session_token", "value": "%s", "expiration": %d}]}`, user.Session, expiration.Unix())
			newData, err := json.Marshal(returnValue)
			if err == nil {
				loginData = string(newData)
			}

			err = SetSession(ctx, user, user.Session)
			if err != nil {
				log.Printf("[WARNING] Error adding session to database: %s", err)
			} else {
				//log.Printf("[DEBUG] Updated session in backend")
			}

			user.MFA = foundUser.MFA

			err = SetUser(ctx, &user, false)
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

			log.Printf("[INFO] User session for %s (%s) is empty - create one!", user.Username, user.Id)
			sessionToken := uuid.NewV4().String()
			expiration := time.Now().Add(3600 * time.Second)
			newCookie := &http.Cookie{
				Name:    "session_token",
				Value:   sessionToken,
				Expires: expiration,
				Path:    "/",
			}

			if project.Environment == "cloud" {
				newCookie.Domain = ".shuffler.io"
				newCookie.Secure = true
				newCookie.HttpOnly = true
			}

			// Does it not set both?
			http.SetCookie(resp, newCookie)

			newCookie.Name = "__session"
			http.SetCookie(resp, newCookie)

			// ADD TO DATABASE
			err = SetSession(ctx, user, sessionToken)
			if err != nil {
				log.Printf("[DEBUG] Error adding session to database: %s", err)
			}

			user.Session = sessionToken

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
			user.MFA = foundUser.MFA
			err = SetUser(ctx, &user, true)
			if err != nil {
				log.Printf("[ERROR] Failed updating user when setting session: %s", err)
				resp.WriteHeader(500)
				resp.Write([]byte(`{"success": false}`))
				return
			}

			loginData = fmt.Sprintf(`{"success": true, "cookies": [{"key": "session_token", "value": "%s", "expiration": %d}]}`, sessionToken, expiration.Unix())
			newData, err := json.Marshal(returnValue)
			if err == nil {
				loginData = string(newData)
			}
		}

		log.Printf("[INFO] %s SUCCESSFULLY LOGGED IN with session %s", user.Username, user.Session)

		resp.WriteHeader(200)
		resp.Write([]byte(loginData))
		return
	}

	response := fmt.Sprintf(`{"success": true, "reason": "Correct code. MFA is now required for this user.", "MFAActive": %v}`, MFAActive)
	resp.WriteHeader(200)
	resp.Write([]byte(response))
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

	if project.Environment == "cloud" {
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting GET 2fa request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
	}

	ctx := GetContext(request)
	var user User
	var userId string
	userSettingUpMfa := false

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {

		// Attempt to retrieve user data from cache
		parts := strings.Split(request.URL.Path, "/")
		if len(parts) < 5 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Invalid URL path."}`))
			return
		}

		MFACode := parts[4]

		// Retrieve user ID and unique code from cache
		cacheUserId, err := GetCache(ctx, fmt.Sprintf("user_id_%s", MFACode))
		if err != nil {
			log.Printf("[ERROR] Failed to retrieve user ID from cache: %s", err)
			resp.WriteHeader(404)
			resp.Write([]byte(`{"success": false, "reason": "Failed to retrieve user ID from cache."}`))
			return
		}

		cacheUniqueCode, err := GetCache(ctx, fmt.Sprintf("mfa_code_%s", MFACode))
		if err != nil {
			log.Printf("[ERROR] Failed to retrieve mfa code from cache: %s", err)
			resp.WriteHeader(404)
			resp.Write([]byte(`{"success": false, "reason": "Failed to retrieve MFA code from cache."}`))
			return
		}

		//if user id and unique code are not empty, user is setting up MFA
		if len(cacheUserId.([]byte)) > 0 && len(cacheUniqueCode.([]byte)) > 0 {
			userSettingUpMfa = true
		}

		if mfaCodeBytes, ok := cacheUniqueCode.([]byte); ok {
			cacheUniqueCode = string(mfaCodeBytes)
		}

		if userIdBytes, ok := cacheUserId.([]byte); ok {
			userId = string(userIdBytes)
		}

		//Both unique code present in cache and MFA code token present in url request must match
		if cacheUniqueCode != MFACode {
			log.Printf("[ERROR] Invalid user for the MFA code %s", MFACode)
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(`{"success": false, "reason": "Invalid user for the MFA code."}`))
			return
		}
	}

	var cacheUser *User

	// check if user id received from cache is not empty
	if len(userId) > 0 && userSettingUpMfa == true {
		cacheUser, err = GetUser(ctx, userId)
		if err != nil {
			log.Printf("[ERROR] Failed to retrieve user from cache: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed to retrieve user from cache."}`))
			return
		}
	}

	//if user id is empty, use the user data from cache
	if len(user.Id) == 0 {
		user = *cacheUser
	}

	var fileId string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" && userSettingUpMfa == false {
		if len(location) <= 4 {
			log.Printf("[ERROR] Path too short: %d", len(location))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
		fileId = location[4]
	}

	if user.Id != fileId && userSettingUpMfa == false {
		log.Printf("[WARNING] Bad ID: %s vs %s", user.Id, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can only set 2fa for your own user"}`)))
		return
	}

	// https://socketloop.com/tutorials/golang-generate-qr-codes-for-google-authenticator-app-and-fix-cannot-interpret-qr-code-error

	// generate a random string - preferably 6 or 8 characters
	randomStr := randStr(8, "alphanum")

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
		Extra:   strings.ReplaceAll(secret, "=", "A"),
	}

	newjson, err := json.Marshal(newres)
	if err != nil {
		log.Printf("[ERROR] Failed marshal in get OTP: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking data"}`)))
		return
	}
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

	if project.Environment == "cloud" {
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting GET ORGS request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get orgs: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := GetContext(request)
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

	// Checking if it's a special region. All user-specific requests should
	// go through shuffler.io and not subdomains
	// Commented out because of org distribution working?
	if project.Environment == "cloud" {
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting GET ORG request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
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

	if strings.Contains(fileId, "?") {
		fileId = strings.Split(fileId, "?")[0]
	}

	ctx := GetContext(request)
	sanitizeOrg := false
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {

		// This is specifically for public workflows
		referenceId, referenceok := request.URL.Query()["reference_execution"]
		authorization, authorizationok := request.URL.Query()["authorization"]
		if referenceok && authorizationok {
			workflowExecution, err := GetWorkflowExecution(ctx, referenceId[0])
			if err == nil && authorization[0] == workflowExecution.Authorization {
				sanitizeOrg = true
			}
		}

		if sanitizeOrg != true {
			log.Printf("[WARNING] Api authentication failed in get org: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	org, err := GetOrg(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Failed getting org '%s': %s", fileId, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting org details"}`))
		return
	}

	if org.OrgAuth.Token == "" {
		org.OrgAuth.Token = uuid.NewV4().String()
		org.OrgAuth.Expires = time.Now().AddDate(0, 0, 1)

		SetOrg(ctx, *org, org.Id)
	}

	// Check if orgauth is expired
	if org.OrgAuth.Expires.Before(time.Now()) {
		log.Printf("[DEBUG] Refreshing org token for %s (%s)", org.Name, org.Id)
		org.OrgAuth.Token = uuid.NewV4().String()
		org.OrgAuth.Expires = time.Now().AddDate(0, 0, 1)

		SetOrg(ctx, *org, org.Id)
	}

	admin := false
	if user.SupportAccess == true {
		admin = true
		sanitizeOrg = false

		// Update active org for user to this one?
		// This makes it possible to walk around in the UI for the org
		if user.ActiveOrg.Id != org.Id {
			log.Printf("[AUDIT] User %s (%s) is admin and has access to org %s. Updating active org to this one.", user.Username, user.Id, org.Id)
			user.ActiveOrg.Id = org.Id
			user.ActiveOrg.Name = org.Name
			user.Role = "admin"

			SetUser(ctx, &user, false)

			DeleteCache(ctx, fmt.Sprintf("%s_workflows", user.ActiveOrg.Id))
			DeleteCache(ctx, fmt.Sprintf("%s_workflows", user.Id))
			DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
			DeleteCache(ctx, fmt.Sprintf("apps_%s", user.ActiveOrg.Id))
			DeleteCache(ctx, fmt.Sprintf("user_%s", user.Username))
			DeleteCache(ctx, fmt.Sprintf("user_%s", user.Id))
		}

	} else {
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

		if !userFound && !sanitizeOrg {
			log.Printf("[ERROR] User '%s' (%s) isn't a part of org %s (get)", user.Username, user.Id, org.Id)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "User doesn't have access to org"}`))
			return

		}
	}

	if !admin {
		org.Defaults = Defaults{}
		org.SSOConfig = SSOConfig{}
		org.Subscriptions = []PaymentSubscription{}
		org.ManagerOrgs = []OrgMini{}
		org.ChildOrgs = []OrgMini{}
		org.Invites = []string{}

		org.OrgAuth = OrgAuth{}
		org.Billing = Billing{}

	} else {
		org.SyncFeatures.AppExecutions.Description = "The amount of Apps within Workflows you can run per month. This limit can be exceeded when running workflows without a trigger (manual execution). Usage resets monthly."
		org.SyncFeatures.WorkflowExecutions.Description = "N/A. See App Executions"
		org.SyncFeatures.Webhook.Description = "Webhooks are Triggers that take an HTTP input to start a workflow. Read docs for more."
		org.SyncFeatures.Schedules.Description = "Schedules are Triggers that run on an interval defined by you. Read docs for more."
		org.SyncFeatures.MultiEnv.Description = "Multiple Environments are used to run automation in different physical locations. Change from /admin?tab=environments"
		org.SyncFeatures.MultiTenant.Description = "Multiple Tenants can be used to segregate information for each MSSP Customer. Change from /admin?tab=suborgs"
		org.SyncFeatures.MultiRegion.Description = "Multiregion allows you to change region to our other data centers around the world."
		org.SyncFeatures.SendSms.Description = "Allows you to send SMS through Shuffle Tools or our API. Usage resets monthly."
		org.SyncFeatures.SendMail.Description = "Allows you to send email through Shuffle Tools or our API. Usage resets monthly."
		//org.SyncFeatures.MultiTenant.Description = "Multiple Tenants can be used to segregate information for each MSSP Customer. Change from /admin?tab=suborgs"

		//log.Printf("LIMIT: %s", org.SyncFeatures.AppExecutions.Limit)
		orgChanged := false
		if org.SyncFeatures.AppExecutions.Limit == 0 || org.SyncFeatures.AppExecutions.Limit == 1500 {
			org.SyncFeatures.AppExecutions.Limit = 10000
			orgChanged = true
		}

		if org.SyncFeatures.SendMail.Limit == 0 {
			org.SyncFeatures.SendMail.Limit = 100
			orgChanged = true
		}

		if org.SyncFeatures.SendSms.Limit == 0 {
			org.SyncFeatures.SendSms.Limit = 30
			orgChanged = true
		}

		org.SyncFeatures.EmailTrigger.Limit = 0
		if org.SyncFeatures.MultiEnv.Limit == 0 {
			org.SyncFeatures.MultiEnv.Limit = 1
			orgChanged = true
		}

		org.SyncFeatures.EmailTrigger.Limit = 0

		if orgChanged {
			log.Printf("[DEBUG] Org features for %s (%s) changed. Updating.", org.Name, org.Id)
			err = SetOrg(ctx, *org, org.Id)
			if err != nil {
				log.Printf("[WARNING] Failed updating org during org loading")
			}
		}

		info, err := GetOrgStatistics(ctx, fileId)
		if err == nil {
			org.SyncFeatures.AppExecutions.Usage = info.MonthlyAppExecutions
		}

		org.SyncFeatures.MultiTenant.Usage = int64(len(org.ChildOrgs) + 1)
		envs, err := GetEnvironments(ctx, fileId)
		if err == nil {
			//log.Printf("Envs: %s", len(envs))
			org.SyncFeatures.MultiEnv.Usage = int64(len(envs))
		}

		if len(org.Subscriptions) == 0 && project.Environment == "cloud" {
			gotSig := getSignatureSample(*org)
			if len(gotSig.Eula) > 0 {
				org.Subscriptions = append(org.Subscriptions, gotSig)
			}
		} else {
			for i, sub := range org.Subscriptions {
				if !sub.EulaSigned {
					continue
				}

				alertFound := false
				for featIndex, feature := range sub.Features {
					if strings.Contains(feature, "alert@shuffler.io") {
						alertFound = true
					}

					if strings.Contains(strings.ToLower(feature), "nightly worker") {
						org.Subscriptions[i].Features[featIndex] = strings.Replace(feature, "Sign EULA first", os.Getenv("NIGHTLY_WORKER_URL"), -1)
					}

					if strings.Contains(strings.ToLower(feature), "stable worker") {
						org.Subscriptions[i].Features[featIndex] = strings.Replace(feature, "Sign EULA first", os.Getenv("LICENSED_WORKER_URL"), -1)
					}
				}

				if !alertFound {
					org.Subscriptions[i].Features = append(org.Subscriptions[i].Features, "Critical events: alert@shuffler.io")
				}
			}
		}
	}

	// Make sure to add all orgs that are childs if you have access
	org.ChildOrgs = []OrgMini{}
	for _, orgloop := range user.Orgs {
		suborg, err := GetOrg(ctx, orgloop)
		if err != nil {
			continue
		}

		// Check if current user is in that org
		found := false
		for _, userloop := range suborg.Users {
			if userloop.Id == user.Id {
				found = true
			}
		}

		if !found {
			continue
		}

		if suborg.CreatorOrg == org.Id {
			org.ChildOrgs = append(org.ChildOrgs, OrgMini{
				Id:         suborg.Id,
				Name:       suborg.Name,
				CreatorOrg: suborg.CreatorOrg,
				Image:      suborg.Image,
				RegionUrl:  suborg.RegionUrl,
			})
		}
	}

	org.Users = []User{}
	org.SyncConfig.Apikey = ""
	org.SyncConfig.Source = ""

	// This is for sending branding information
	// to those who need it
	if sanitizeOrg {
		newOrg := org
		org = &Org{}
		org.Name = newOrg.Name
		org.Id = newOrg.Id
		org.Image = newOrg.Image
		org.RegionUrl = newOrg.RegionUrl
		org.Org = newOrg.Org

	}

	if len(org.ManagerOrgs) > 0 {
		org.LeadInfo.SubOrg = true
	}

	if !user.SupportAccess {
		org.LeadInfo = LeadInfo{}
	}

	newjson, err := json.Marshal(org)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshal of org %s (%s): %s", org.Name, org.Id, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func HandleGetSubOrgs(resp http.ResponseWriter, request *http.Request) {

	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Checking if it's a special region. All user-specific requests should
	// go through shuffler.io and not subdomains

	if project.Environment == "cloud" {
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting GET ORG request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
	}

	ctx := GetContext(request)
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get org: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	var orgId string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("Path too short: %d", len(location))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		orgId = location[4]
	}

	if strings.Contains(orgId, "?") {
		orgId = strings.Split(orgId, "?")[0]
	}

	org, err := GetOrg(ctx, orgId)
	if err != nil {
		log.Printf("[WARNING] Failed getting org '%s': %s", orgId, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting org details"}`))
		return
	}

	userFound := false
	parentUser := false // to check if the user belongs to the parent
	for _, inneruser := range org.Users {
		if inneruser.Id == user.Id {
			userFound = true
			break
		}
	}

	parentOrg := &Org{}
	isParentAdmin := false
	if org.CreatorOrg != "" {
		parentOrg, err = GetOrg(ctx, org.CreatorOrg)
		if err != nil {
			log.Printf("[ERROR] Failed getting parent org '%s': %s", org.CreatorOrg, err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed getting parent org details"}`))
			return
		}

	} else {
		parentOrg = org
	}

	for _, inneruser := range parentOrg.Users {
		if inneruser.Id == user.Id {
			parentUser = true

			if inneruser.Role == "admin" {
				isParentAdmin = true
			}

			break
		}
	}

	if !userFound && !parentUser && !user.SupportAccess {
		log.Printf("[ERROR] User '%s' (%s) isn't a part of org %s (get)", user.Username, user.Id, orgId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "User doesn't have access to org"}`))
		return
	}

	isSupportOrAdmin := user.SupportAccess || isParentAdmin

	childorgs, err := GetAllChildOrgs(ctx, parentOrg.Id)
	if err != nil || len(childorgs) == 0 {
		if len(childorgs) != 0 {
			log.Printf("[ERROR] Failed getting child orgs for %s. Got %d: %s", parentOrg.Id, len(childorgs), err)
		}
	} else {
		parentOrg.ChildOrgs = []OrgMini{}
		for _, childorg := range childorgs {
			parentOrg.ChildOrgs = append(parentOrg.ChildOrgs, OrgMini{
				Id:         childorg.Id,
				Name:       childorg.Name,
				Role:       childorg.Role,
				CreatorOrg: childorg.CreatorOrg,
				Image:      childorg.Image,
				RegionUrl:  childorg.RegionUrl,
			})
		}
	}

	subOrgs := []OrgMini{}
	if isSupportOrAdmin {
		for _, orgloop := range parentOrg.ChildOrgs {
			childorg, err := GetOrg(ctx, orgloop.Id)
			if err != nil {
				continue
			}

			subOrgs = append(subOrgs, OrgMini{
				Id:         childorg.Id,
				Name:       childorg.Name,
				Role:       childorg.Role,
				CreatorOrg: childorg.CreatorOrg,
				Image:      childorg.Image,
				RegionUrl:  childorg.RegionUrl,
			})
		}

	} else {
		for _, orgloop := range user.Orgs {
			childorg, err := GetOrg(ctx, orgloop)
			if err != nil {
				continue
			}
			found := false
			for _, userloop := range childorg.Users {
				if userloop.Id == user.Id {
					found = true
				}
			}

			if !found {
				continue
			}

			if childorg.CreatorOrg == org.Id {
				subOrgs = append(subOrgs, OrgMini{
					Id:         childorg.Id,
					Name:       childorg.Name,
					Role:       childorg.Role,
					CreatorOrg: childorg.CreatorOrg,
					Image:      childorg.Image,
					RegionUrl:  childorg.RegionUrl,
				})
			}
		}
	}

	returnParent := OrgMini{}
	//if parentOrg.CreatorOrg != "" && (parentUser || user.SupportAccess) {
	returnParent = OrgMini{
		Id:         parentOrg.Id,
		Name:       parentOrg.Name,
		Role:       parentOrg.Role,
		CreatorOrg: parentOrg.CreatorOrg,
		Image:      parentOrg.Image,
		RegionUrl:  parentOrg.RegionUrl,
	}
	//}

	data := map[string]interface{}{
		"subOrgs":   subOrgs,
		"parentOrg": returnParent,
	}

	if len(parentOrg.Id) == 0 || !parentUser {
		data["parentOrg"] = nil
	}

	finalResponse, err := json.Marshal(data)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal JSON response: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed marshaling JSON response"}`))
		return
	}

	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(200)
	resp.Write(finalResponse)

}

func HandleLogout(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	ctx := GetContext(request)

	runReturn := false
	userInfo, usererr := HandleApiAuthentication(resp, request)
	log.Printf("[AUDIT] Logging out user %s (%s)", userInfo.Username, userInfo.Id)
	if project.Environment == "cloud" {
		// Checking if it's a special region. All user-specific requests should
		// go through shuffler.io and not subdomains
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting LOGOUT request to main site handler (shuffler.io)")
			DeleteCache(ctx, fmt.Sprintf("%s_workflows", userInfo.ActiveOrg.Id))
			DeleteCache(ctx, fmt.Sprintf("%s_workflows", userInfo.Id))
			DeleteCache(ctx, fmt.Sprintf("apps_%s", userInfo.Id))
			DeleteCache(ctx, fmt.Sprintf("apps_%s", userInfo.ActiveOrg.Id))
			DeleteCache(ctx, fmt.Sprintf("user_%s", strings.ToLower(userInfo.Username)))
			DeleteCache(ctx, fmt.Sprintf("user_%s", userInfo.Id))
			DeleteCache(ctx, fmt.Sprintf("session_%s", userInfo.Session))

			RedirectUserRequest(resp, request)

			// Wait 1 second to ensure that the redirect is handled
			time.Sleep(1 * time.Second)

			DeleteCache(ctx, fmt.Sprintf("%s_workflows", userInfo.ActiveOrg.Id))
			DeleteCache(ctx, fmt.Sprintf("%s_workflows", userInfo.Id))
			DeleteCache(ctx, fmt.Sprintf("apps_%s", userInfo.Id))
			DeleteCache(ctx, fmt.Sprintf("apps_%s", userInfo.ActiveOrg.Id))
			DeleteCache(ctx, fmt.Sprintf("user_%s", strings.ToLower(userInfo.Username)))
			DeleteCache(ctx, fmt.Sprintf("user_%s", userInfo.Id))
			DeleteCache(ctx, fmt.Sprintf("session_%s", userInfo.Session))

			// FIXME: Allow superfluous cleanups?
			// Point is: should it continue running the logout to ensure cookies are cleared?
			// Keeping it for now to ensure cleanup.
			return
		}
	}

	c, err := request.Cookie("session_token")
	if err != nil {
		c, err = request.Cookie("__session")
	}

	if err == nil {
		newCookie := &http.Cookie{
			Name:    "session_token",
			Value:   c.Value,
			Expires: time.Now().Add(-100 * time.Hour),
			MaxAge:  -1,
			Path:    "/",
		}
		if project.Environment == "cloud" {
			newCookie.Domain = ".shuffler.io"
			newCookie.Secure = true
			newCookie.HttpOnly = true
		}

		http.SetCookie(resp, newCookie)

		newCookie.Name = "__session"
		http.SetCookie(resp, newCookie)

	} else {
		newCookie := &http.Cookie{
			Name:    "session_token",
			Value:   "",
			Expires: time.Now().Add(-100 * time.Hour),
			MaxAge:  -1,
			Path:    "/",
		}

		if project.Environment == "cloud" {
			newCookie.Domain = ".shuffler.io"
			newCookie.Secure = true
			newCookie.HttpOnly = true
		}

		http.SetCookie(resp, newCookie)

		newCookie.Name = "__session"
		http.SetCookie(resp, newCookie)
	}

	DeleteCache(ctx, fmt.Sprintf("%s_workflows", userInfo.ActiveOrg.Id))
	DeleteCache(ctx, fmt.Sprintf("%s_workflows", userInfo.Id))
	DeleteCache(ctx, fmt.Sprintf("apps_%s", userInfo.Id))
	DeleteCache(ctx, fmt.Sprintf("apps_%s", userInfo.ActiveOrg.Id))
	if runReturn == true {
		DeleteCache(ctx, fmt.Sprintf("user_%s", strings.ToLower(userInfo.Username)))
		DeleteCache(ctx, fmt.Sprintf("session_%s", userInfo.Session))
		DeleteCache(ctx, userInfo.Session)

		log.Printf("[INFO] Returning from logout request after cache cleanup")

		return
	}

	if usererr != nil {
		log.Printf("[WARNING] Api authentication failed in handleLogout: %s", err)
		resp.WriteHeader(200)
		resp.Write([]byte(`{"success": true, "reason": "Not logged in"}`))
		return
	}

	DeleteCache(ctx, fmt.Sprintf("user_%s", strings.ToLower(userInfo.Username)))
	DeleteCache(ctx, fmt.Sprintf("session_%s", userInfo.Session))
	DeleteCache(ctx, userInfo.Session)

	userInfo.Session = ""
	userInfo.ValidatedSessionOrgs = []string{}
	err = SetUser(ctx, &userInfo, false)
	if err != nil {
		log.Printf("Failed updating user: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed updating apikey"}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": false, "reason": "Successfully logged out"}`))
}

// A search for apps based on name and such
// This was before Algolia
func GetSpecificApps(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just need to be logged in
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in set new app: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

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
	ctx := GetContext(request)
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
		log.Printf("[AUDIT] Api authentication failed in get app auth: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := GetContext(request)
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

func AddAppAuthentication(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {

		if session, err := request.Cookie("__session"); err == nil {
			//log.Printf("\n\n[DEBUG]: Found session token that failed. Should search org auth for %#v", session)

			// Gets a sample user to use
			ctx := GetContext(request)
			user, err = GetOrgAuth(ctx, session.Value)
			if err != nil {
				log.Printf("[WARNING] Failed getting org auth for session: %s", err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false}`))
				return
			}
		}

		if user.Id == "" || user.Role != "admin" {
			log.Printf("[WARNING] Api authentication failed in add app auth: %s", userErr)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to set new workflowapp: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

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

	log.Printf("[AUDIT] Setting new app authentication for app %s with user %s (%s) in org %s (%s)", appAuth.App.Name, user.Username, user.Id, user.ActiveOrg.Name, user.ActiveOrg.Id)

	ctx := GetContext(request)
	org := &Org{}
	originalAuth := &AppAuthenticationStorage{}
	originalId := appAuth.Id
	if len(appAuth.Id) == 0 {
		// To not override, we should use an md5 based on the input fields + org to create the ID
		fielddata := fmt.Sprintf("%s_%s", user.ActiveOrg.Id, appAuth.Label)
		for _, field := range appAuth.Fields {
			fielddata += field.Key
			fielddata += field.Value
		}

		// Happens in very rare circumstances
		hasher := md5.New()
		hasher.Write([]byte(fielddata))
		appAuth.Id = hex.EncodeToString(hasher.Sum(nil))
	} else {
		originalAuth, err = GetWorkflowAppAuthDatastore(ctx, appAuth.Id)
		if err == nil {
			// OrgId         string                `json:"org_id" datastore:"org_id"`
			if originalAuth.OrgId != user.ActiveOrg.Id {
				log.Printf("[WARNING] User %s (%s) isn't a part of the right org during auth edit", user.Username, user.Id)
				resp.WriteHeader(403)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": ":("}`)))
				return
			}

			if user.Role != "admin" {
				log.Printf("[AUDIT] User %s (%s) isn't admin during auth edit", user.Username, user.Id)
				resp.WriteHeader(403)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": ":("}`)))
				return
			}

			if !originalAuth.Active {

				// Forcing it active
				appAuth.Active = true

				/*
					log.Printf("[WARNING] Auth isn't active for edit")
					resp.WriteHeader(409)
					resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't update an inactive auth"}`)))
					return
				*/
			}

			if originalAuth.App.Name != appAuth.App.Name {
				log.Printf("[AUDIT] User %s (%s) tried to modify auth, but appname was wrong", user.Username, user.Id)
				resp.WriteHeader(409)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Bad app configuration: need to specify correct name"}`)))
				return
			}

			if appAuth.Type != "oauth2" && appAuth.Type != "oauth" && appAuth.Type != "oauth2-app" {
				for fieldIndex, field := range appAuth.Fields {
					if !strings.Contains(field.Value, "Secret. Replaced") {
						continue
					}

					//log.Printf("Field '%s' has secret. Replace with the real value", field.Key)
					for _, existingField := range originalAuth.Fields {
						if existingField.Key != field.Key {
							continue
						}

						//log.Printf("Replacing field %s with value '%s'", field.Key, existingField.Value)

						//field.Value = existingField.Value
						appAuth.Fields[fieldIndex].Value = existingField.Value

						if originalAuth.Encrypted {
							// Decrypt it here
							parsedKey := fmt.Sprintf("%s_%d_%s_%s", originalAuth.OrgId, originalAuth.Created, originalAuth.Label, field.Key)
							newValue, err := HandleKeyDecryption([]byte(existingField.Value), parsedKey)
							if err != nil {
								log.Printf("[WARNING] Failed decrypting field %s: %s", field.Key, err)
							} else {
								//log.Printf("Decrypted value: %s", newValue)
								appAuth.Fields[fieldIndex].Value = string(newValue)
							}
						}

						break
					}
				}

				if len(appAuth.Fields) == 0 {
					appAuth.Fields = originalAuth.Fields
				}

				// Decrypt with old label to ensure re-encryption with new label
				for fieldIndex, field := range appAuth.Fields {

					if len(field.Value) == 0 || strings.Contains(field.Value, "Secret. Replaced") {
						for _, existingField := range originalAuth.Fields {
							if existingField.Key != field.Key {
								continue
							}

							//log.Printf("Replacing field %s with value '%s'", field.Key, existingField.Value)

							// Decrypt it based on auth
							parsedKey := fmt.Sprintf("%s_%d_%s_%s", originalAuth.OrgId, originalAuth.Created, originalAuth.Label, field.Key)
							newValue, err := HandleKeyDecryption([]byte(existingField.Value), parsedKey)
							if err != nil {
								log.Printf("[WARNING] Failed decrypting field %s: %s", field.Key, err)
							} else {
								//log.Printf("Decrypted value: %s", newValue)
								appAuth.Fields[fieldIndex].Value = string(newValue)
								field.Value = string(newValue)
							}
						}
					}

					//log.Printf("Default value: %s", field.Value)

					parsedKey := fmt.Sprintf("%s_%d_%s_%s", originalAuth.OrgId, originalAuth.Created, originalAuth.Label, field.Key)
					newValue, err := HandleKeyDecryption([]byte(field.Value), parsedKey)
					if err != nil {
						log.Printf("[WARNING] Failed decrypting field %s: %s", field.Key, err)
					} else {
						//log.Printf("Decrypted value: %s", newValue)
						appAuth.Fields[fieldIndex].Value = string(newValue)
					}
				}

				// Setting this to ensure that any new config is encrypted anew
				appAuth.Encrypted = false
			} else {
			}
		} else {
			// ID sometimes used in creation as well

			//log.Printf("[WARNING] Failed finding existing auth: %s", err)
			//resp.WriteHeader(409)
			//resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't find existing auth"}`)))
			//return
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
					DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
					DeleteCache(ctx, fmt.Sprintf("apps_%s", user.ActiveOrg.Id))
					DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-100"))
					DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-500"))
					DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-1000"))
					DeleteCache(ctx, "all_apps")
					DeleteCache(ctx, fmt.Sprintf("user_%s", user.Username))
					DeleteCache(ctx, fmt.Sprintf("user_%s", user.Id))
				}
			} else {
				log.Printf("[INFO] Org %s (%s) already has app %s active.", user.ActiveOrg.Name, user.ActiveOrg.Id, app.ID)
			}
		}
	}

	// Only in this one if NEW oauth2 auth
	if appAuth.Type == "oauth2" && len(originalId) == 0 {
		log.Printf("[DEBUG] OAUTH2 for workflow %s. User: %s (%s)", appAuth.ReferenceWorkflow, user.Username, user.Id)

		if len(appAuth.ReferenceWorkflow) > 0 {
			workflow, err := GetWorkflow(ctx, appAuth.ReferenceWorkflow)
			if err != nil {
				log.Printf("[WARNING] WorkflowId %s doesn't exist (set oauth2)", appAuth.ReferenceWorkflow)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false}`))
				return
			}

			if user.Id != workflow.Owner || len(user.Id) == 0 {
				if workflow.OrgId == user.ActiveOrg.Id && user.Role != "org-reader" {
					log.Printf("[AUDIT] User %s is accessing workflow '%s' as admin (set oauth2)", user.Username, workflow.ID)
				} else if workflow.Public {
					log.Printf("[AUDIT] Letting user %s access workflow %s FOR AUTH because it's public", user.Username, workflow.ID)
				} else {
					log.Printf("[AUDIT] Wrong user (%s) for workflow %s (set oauth2)", user.Username, workflow.ID)
					resp.WriteHeader(403)
					resp.Write([]byte(`{"success": false, "reason": "Your user is not allowed to set authentication for this workflow in Shuffle."}`))
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
		}

		_, err = RunOauth2Request(ctx, user, appAuth, false)
		if err != nil {
			parsederror := strings.Replace(fmt.Sprintf("%s", err), "\"", "\\\"", -1)
			log.Printf("[WARNING] Failed oauth2 request (3): %s", err)

			if strings.Contains(fmt.Sprintf("%s", err), "not consented") {
				log.Printf("Return the user to the URL with admin consent")
			}

			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed authorization: %s"}`, parsederror)))
			return
		}

		resp.WriteHeader(200)
		resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Successfully set up authentication", "id": "%s"}`, appAuth.Id)))
		return

	} else if appAuth.Type == "oauth2-app" && len(originalId) == 0 {
		// For application permissions set in Oauth2 frontend
		// This should contain client-id, client-secret, scopes, token-url
		// May need to also know how the auth actually works (e.g. basic auth or something else)

		appAuth.App.AppVersion = app.AppVersion
		log.Printf("[DEBUG] OAUTH2-APP for workflow %s. User: %s (%s). App: %s (%s)", appAuth.ReferenceWorkflow, user.Username, user.Id, appAuth.App.Name, appAuth.App.ID)

		// Testing if the auth works
		_, err := GetOauth2ApplicationPermissionToken(ctx, user, appAuth)
		if err != nil {
			log.Printf("\n[WARNING] Failed getting oauth2 application permission token: %s\n\n", err)
			resp.WriteHeader(400)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed authorization. Is your client ID, client secret and scope correct? Raw: %s"}`, strings.Replace(err.Error(), "\"", "\\\"", -1))))
			return
		}

	} else {
		// Edgecases for oauth2 as they need reauth
		if appAuth.Type == "oauth2" || appAuth.Type == "oauth2-app" {
			for _, field := range appAuth.Fields {
				if field.Key != "url" {
					continue
				}

				if len(field.Value) == 0 {
					log.Printf("[WARNING] Failed finding field 'url' in appauth fields for %s", appAuth.App.Name)

					resp.WriteHeader(400)
					resp.Write([]byte(`{"success": false, "reason": "Field can't be empty: url"}`))
					return
				}

				// Trim
				field.Value = strings.TrimSpace(field.Value)

				// Valid: https://example.com
				// Invalid: http://example.com/
				// Invalid: example.com
				if !strings.HasPrefix(field.Value, "http") || strings.HasSuffix(field.Value, "/") || !strings.Contains(field.Value, "://") || strings.Contains(field.Value, " ") || strings.Contains(field.Value, "\n") {
					log.Printf("[WARNING] Invalid URL for field 'url' in appauth edit: %#v", field.Value)
					resp.WriteHeader(400)
					resp.Write([]byte(`{"success": false, "reason": "Field must be a valid URL, and NOT end with /"}`))
					return
				}

				found := false
				for paramIndex, param := range originalAuth.Fields {
					if param.Key != field.Key {
						continue
					}

					// Encrypt the url field?
					// Skipping for now as it's not as sensitive a field, and we may even add editing possibilities to it in the future.
					found = true
					log.Printf("[DEBUG] Replacing URL field in appauth for %s from %#v to %#v", appAuth.App.Name, originalAuth.Fields[paramIndex].Value, field.Value)
					originalAuth.Fields[paramIndex].Value = field.Value
				}

				if !found {
					log.Printf("[WARNING] Failed finding field '%s' in OAUTH2 appauth fields for %s", field.Key, appAuth.App.Name)
					continue
				}

			}

			appAuth.Fields = originalAuth.Fields
		} else {
			// Check if the items are correct
			for _, field := range appAuth.Fields {
				found := false
				for _, param := range app.Authentication.Parameters {
					//log.Printf("Fields: %s - %s", field, param.Name)
					if field.Key == param.Name {
						found = true
					}
				}

				if !found {
					log.Printf("[WARNING] Failed finding field '%s' in appauth fields for %s", field.Key, appAuth.App.Name)
					resp.WriteHeader(409)
					resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "All auth fields required"}`)))
					return
				}
			}
		}
	}

	if len(appAuth.App.LargeImage) == 0 && len(app.LargeImage) > 0 {
		appAuth.App.LargeImage = app.LargeImage
	}

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

	if appAuth.AutoDistribute {
		log.Printf("[DEBUG] Auto distributing auth %s for app %s (%s) in org %s (%s) to all workflows.", appAuth.Id, appAuth.App.Name, appAuth.App.ID, user.ActiveOrg.Name, user.ActiveOrg.Id)

		err := AssignAuthEverywhere(ctx, &appAuth, user)
		if err != nil {
			log.Printf("[ERROR] Failed assigning auth everywhere (2): %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed getting workflows to update"}`))
		} else {
			log.Printf("[INFO] Assigned auth everywhere")
		}
	}

	// Set it as the default app in the org as it's the "latest" of it's kind.
	// This just means adding it to the app framework if a category exists
	if len(app.Categories) > 0 {
		// Get org
		org, err := GetOrg(ctx, user.ActiveOrg.Id)
		if err == nil {
			lowercased := strings.ToLower(app.Categories[0])
			if lowercased == "communication" || lowercased == "email" {
				org.SecurityFramework.Communication.ID = app.ID
				org.SecurityFramework.Communication.Name = app.Name
				org.SecurityFramework.Communication.LargeImage = app.LargeImage
				org.SecurityFramework.Communication.Description = app.Description
			} else if lowercased == "siem" {
				org.SecurityFramework.SIEM.ID = app.ID
				org.SecurityFramework.SIEM.Name = app.Name
				org.SecurityFramework.SIEM.LargeImage = app.LargeImage
				org.SecurityFramework.SIEM.Description = app.Description
			} else if lowercased == "assets" {
				org.SecurityFramework.Assets.ID = app.ID
				org.SecurityFramework.Assets.Name = app.Name
				org.SecurityFramework.Assets.LargeImage = app.LargeImage
				org.SecurityFramework.Assets.Description = app.Description
			} else if lowercased == "cases" {
				org.SecurityFramework.Cases.ID = app.ID
				org.SecurityFramework.Cases.Name = app.Name
				org.SecurityFramework.Cases.LargeImage = app.LargeImage
				org.SecurityFramework.Cases.Description = app.Description
			} else if lowercased == "network" {
				org.SecurityFramework.Network.ID = app.ID
				org.SecurityFramework.Network.Name = app.Name
				org.SecurityFramework.Network.LargeImage = app.LargeImage
				org.SecurityFramework.Network.Description = app.Description
			} else if lowercased == "intel" {
				org.SecurityFramework.Intel.ID = app.ID
				org.SecurityFramework.Intel.Name = app.Name
				org.SecurityFramework.Intel.LargeImage = app.LargeImage
				org.SecurityFramework.Intel.Description = app.Description
			} else if lowercased == "edr" {
				org.SecurityFramework.EDR.ID = app.ID
				org.SecurityFramework.EDR.Name = app.Name
				org.SecurityFramework.EDR.LargeImage = app.LargeImage
				org.SecurityFramework.EDR.Description = app.Description
			} else if lowercased == "iam" {
				org.SecurityFramework.IAM.ID = app.ID
				org.SecurityFramework.IAM.Name = app.Name
				org.SecurityFramework.IAM.LargeImage = app.LargeImage
				org.SecurityFramework.IAM.Description = app.Description
			} else {
				log.Printf("[ERROR] Unknown category %s for app %s (%s)", lowercased, app.Name, app.ID)
			}

			// Set the org
			err = SetOrg(ctx, *org, org.Id)
			if err != nil {
				log.Printf("[WARNING] Failed setting org after setting default app: %s", err)
			}
		}
	}

	if appAuth.SuborgDistributed {
		// Clear auth cache for all suborgs

		//nameKey := "workflowappauth"
		//cacheKey := fmt.Sprintf("%s_%s", nameKey, orgId)
		if len(org.Id) == 0 {
			org, err = GetOrg(ctx, user.ActiveOrg.Id)
			if err != nil {
				log.Printf("[ERROR] Failed getting org for suborg auth clear: %s", err)
			}
		}

		for _, childOrg := range org.ChildOrgs {
			cacheKey := fmt.Sprintf("workflowappauth_%s", childOrg.Id)
			DeleteCache(ctx, cacheKey)
		}
	}

	log.Printf("[INFO] Set new app auth for %s (%s) with ID %s", app.Name, app.ID, appAuth.Id)
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "id": "%s"}`, appAuth.Id)))
}

func AddAppAuthenticationGroup(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("[WARNING] Api authentication failed in add app auth group: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role != "admin" {
		log.Printf("[WARNING] Need to be admin to add appauth group")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Error with body read in new app auth group: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	var appAuthGroup AppAuthenticationGroup
	if err := json.Unmarshal(body, &appAuthGroup); err != nil {
		log.Printf("[WARNING] Failed unmarshaling (appauthgroup): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := GetContext(request)
	if len(appAuthGroup.Id) > 0 {
		// Get group and check if it's in the org

		authGroup, err := GetAppAuthGroup(ctx, appAuthGroup.Id)
		if err != nil {
			log.Printf("[WARNING] Failed finding app auth group %s: %s", appAuthGroup.Id, err)
			resp.WriteHeader(409)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't find existing app auth group"}`)))
			return
		}

		if authGroup.OrgId != user.ActiveOrg.Id {
			log.Printf("[WARNING] User %s (%s) isn't a part of the right org during auth group edit", user.Username, user.Id)
			resp.WriteHeader(403)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "No access"}`)))
			return
		}
	}

	log.Printf("[AUDIT] Setting new app authentication group for %s with user %s (%s) in org %s (%s)", appAuthGroup.Label, user.Username, user.Id, user.ActiveOrg.Name, user.ActiveOrg.Id)

	if len(appAuthGroup.Label) == 0 {
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Label can't be empty"}`)))
		return
	}

	// Super basic check
	if len(appAuthGroup.AppAuths) == 0 {
		log.Printf("[WARNING] Empty appauths for appauthgroup")
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Apps have to be defined"}`)))
		return
	}

	appAuthGroup.OrgId = user.ActiveOrg.Id
	appAuthGroup.Active = true

	if len(appAuthGroup.Id) == 0 {
		appAuthGroup.Id = uuid.NewV4().String()
	}

	err = SetAuthGroupDatastore(ctx, appAuthGroup, appAuthGroup.Id)
	if err != nil {
		log.Printf("[WARNING] Failed setting up app auth group %s: %s", appAuthGroup.Id, err)
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "id": "%s"}`, appAuthGroup.Id)))
}

func GetAppAuthenticationGroup(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("[AUDIT] Api authentication failed in get app auth group: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := GetContext(request)
	allAuthGroups, err := GetAuthGroups(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get all app auth group: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(allAuthGroups) == 0 {
		resp.WriteHeader(200)
		resp.Write([]byte(`{"success": true, "data": []}`))
		return
	}

	// Cleanup for frontend
	newAuthGroups := []AppAuthenticationGroup{}
	for _, authGroup := range allAuthGroups {
		newAuthGroup := authGroup
		newAuthGroups = append(newAuthGroups, newAuthGroup)
	}

	type returnStruct struct {
		Success bool                     `json:"success"`
		Data    []AppAuthenticationGroup `json:"data"`
	}

	allAuth := returnStruct{
		Success: true,
		Data:    allAuthGroups,
	}

	newbody, err := json.Marshal(allAuth)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshalling all app auth groups: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking workflow app auth group"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(newbody))
}

func DeleteAppAuthenticationGroup(resp http.ResponseWriter, request *http.Request) {
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

	log.Printf("[AUDIT] Deleting app auth group %s with user %s (%s) in org %s (%s)", fileId, user.Username, user.Id, user.ActiveOrg.Name, user.ActiveOrg.Id)

	ctx := GetContext(request)
	nameKey := "workflowappauthgroup"
	auth, err := GetAppAuthGroup(ctx, fileId)
	if err != nil {
		// Deleting cache here, as it seems to be a constant issue
		cacheKey := fmt.Sprintf("%s_%s", nameKey, user.ActiveOrg.Id)
		DeleteCache(ctx, cacheKey)

		log.Printf("[WARNING] Authget group error (DELETE): %s", err)
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

	ctx := GetContext(request)
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
		log.Printf("[WARNING] Failed getting environments: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't get environments when setting"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Failed reading environment body: %s", err)
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
		if project.Environment == "cloud" && env.Type == "cloud" && env.Archived {
			log.Printf("[WARNING] User %s (%s) tried to disable the cloud environment", user.Username, user.Id)
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

func HandleRerunExecutions(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in Rerun executions: %s", err)
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

	if strings.ToLower(os.Getenv("SHUFFLE_DISABLE_RERUN_AND_ABORT")) == "true" {
		log.Printf("[AUDIT] Rerunning is disabled by the SHUFFLE_DISABLE_RERUN_AND_ABORT argument. Stopping.")
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "SHUFFLE_DISABLE_RERUN_AND_ABORT is active. Won't rerun executions."}`)))
		return
	}

	ctx := GetContext(request)
	environmentName := fileId
	if len(fileId) != 36 {
		log.Printf("[DEBUG] Environment length %d for %s is not good for reruns. Attempting to find the actual ID for it", len(fileId), fileId)

		environments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("[WARNING] Failed getting environments to validate: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed to validate environment"}`))
			return
		}

		for _, environment := range environments {
			if environment.Name == fileId && len(environment.Id) > 0 {
				environmentName = fileId
				fileId = environment.Id

				break
			}
		}

		if len(fileId) != 36 {
			log.Printf("[WARNING] Failed getting environments to validate. New FileId: %s", fileId)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed updating environment"}`))
			return
		}
	}

	// 1: Loop all workflows
	workflows, err := GetAllWorkflowsByQuery(ctx, user)
	if err != nil {
		log.Printf("[WARNING] Failed getting workflows for user %s (0): %s", user.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	total := 0
	maxTotalReruns := 100
	for _, workflow := range workflows {
		if workflow.OrgId != user.ActiveOrg.Id {
			//log.Printf("[DEBUG] Skipping workflow for org %s (user: %s)", workflow.OrgId, user.Username)
			continue
		}

		if total > maxTotalReruns {
			log.Printf("[DEBUG] Stopping because more than %d (%d) executions are pending. Checking reruns again on next iteration", maxTotalReruns, total)
			break
		}

		cnt, err := RerunExecution(ctx, environmentName, workflow)
		if err != nil {
			log.Printf("[ERROR] Failed rerunning execution for workflow %s: %s", workflow.ID, err)
		}

		total += cnt
	}

	//log.Printf("[DEBUG] RERAN %d execution(s) in total for environment %s for org %s", total, fileId, user.ActiveOrg.Id)
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Successfully RERAN %d executions"}`, total)))
}

// Send in deleteall=true to delete ALL executions for the environment ID
func HandleStopExecutions(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in ABORT dangling executions: %s", err)
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

	// Fix here by allowing cleanup from UI anyway :)
	if strings.ToLower(os.Getenv("SHUFFLE_DISABLE_RERUN_AND_ABORT")) == "true" {
		log.Printf("[AUDIT] Rerunning is disabled by the SHUFFLE_DISABLE_RERUN_AND_ABORT argument. Stopping. (abort)")
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "SHUFFLE_DISABLE_RERUN_AND_ABORT is active. Won't rerun executions (abort)"}`)))
		return
	}

	ctx := GetContext(request)
	environmentName := fileId
	if len(fileId) != 36 {
		log.Printf("[DEBUG] Environment length %d for %s is not good for executions aborts. Attempting to find the actual ID for it", len(fileId), fileId)

		environments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("[WARNING] Failed getting environments to validate: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed to validate environment"}`))
			return
		}

		for _, environment := range environments {
			if environment.Name == fileId && len(environment.Id) > 0 {
				environmentName = fileId
				fileId = environment.Id
				break
			}
		}

		if len(fileId) != 36 {
			log.Printf("[WARNING] Failed getting environments to validate. New FileId: %s", fileId)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed updating environment"}`))
			return
		}
	}

	cleanAll := false
	deleteAll, ok := request.URL.Query()["deleteall"]

	if ok {
		if deleteAll[0] == "true" {
			cleanAll = true

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
			queueName := env.Name
			if project.Environment == "cloud" {
				queueName = fmt.Sprintf("%s_%s", strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(env.Name, " ", "-"), "_", "-")), user.ActiveOrg.Id)
			}

			for i := 0; i < 10; i++ {
				executionRequests, err := GetWorkflowQueue(ctx, queueName, maxAmount)
				log.Printf("[DEBUG] Got %d item(s) from queue %s to be deleted", len(executionRequests.Data), queueName)
				if err != nil {
					log.Printf("[WARNING] Jumping out of workflowqueue delete handler: %s", err)
					break
				}

				if len(executionRequests.Data) == 0 {
					//log.Printf("[DEBUG] No more executions in queue. Stopping")
					break
				}

				ids := []string{}
				for _, execution := range executionRequests.Data {
					if project.Environment != "cloud" {
						if !ArrayContains(execution.Environments, env.Name) {
							continue
						}
					}

					ids = append(ids, execution.ExecutionId)
				}

				log.Printf("[DEBUG] Deleting %d execution keys for org %s", len(ids), env.Name)

				parsedId := fmt.Sprintf("workflowqueue-%s", queueName)

				err = DeleteKeys(ctx, parsedId, ids)
				if err != nil {
					log.Printf("[ERROR] Failed deleting %d execution keys for org %s during force stop: %s", len(ids), env.Name, err)
				} else {
					log.Printf("[INFO] Deleted %d keys from org %s during force stop", len(ids), parsedId)
				}

				if len(executionRequests.Data) != maxAmount {
					log.Printf("[DEBUG] Less than 1000 in queue. Stopping search requests")
					break
				}
			}

			// Delete the index entirely
			indexName := "workflowqueue-" + queueName
			err = DeleteDbIndex(ctx, indexName)
			if err != nil {
				log.Printf("[ERROR] Failed deleting index %s: %s", indexName, err)
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
			log.Printf("[DEBUG] Skipping workflow for org %s (user: %s)", workflow.OrgId, user.Username)
			continue
		}

		cnt, _ := CleanupExecutions(ctx, environmentName, workflow, cleanAll)
		total += cnt
	}

	if total > 0 {
		log.Printf("[DEBUG] Stopped %d executions in total for environment %s for org %s", total, fileId, user.ActiveOrg.Id)
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Successfully deleted and stopped %d executions"}`, total)))
}

func RerunExecution(ctx context.Context, environment string, workflow Workflow) (int, error) {
	maxReruns := 100

	executions, err := GetUnfinishedExecutions(ctx, workflow.ID)
	if err != nil {
		log.Printf("[DEBUG] Failed getting executions for workflow %s", workflow.ID)
		return 0, err
	}

	if len(executions) == 0 {
		return 0, nil
	}

	//if project.Environment == "cloud" {
	//	backendUrl = "https://shuffler.io"
	//} else {
	//	backendUrl = "http://127.0.0.1:5001"
	//}

	//topClient := &http.Client{
	//	Transport: &http.Transport{
	//		Proxy: nil,
	//	},
	//}
	//_ = backendUrl
	//_ = topClient

	//StartedAt           int64          `json:"started_at" datastore:"started_at"`
	timeNow := int64(time.Now().Unix())
	cnt := 0

	// Rerun after 570 seconds (9.5 minutes), ensuring it can check 3 times before
	// automated aborting of the execution happens
	waitTime := 270
	//waitTime := 0
	executed := []string{}
	for _, execution := range executions {
		if timeNow < execution.StartedAt+int64(waitTime) {
			continue
		}

		if execution.Status != "EXECUTING" {
			continue
		}

		if ArrayContains(executed, execution.ExecutionId) {
			continue
		}

		executed = append(executed, execution.ExecutionId)

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

		if cnt > maxReruns {
			log.Printf("[DEBUG] Breaking because more than 100 executions are executing")
			break
		}

		if project.Environment != "cloud" {
			executionRequest := ExecutionRequest{
				ExecutionId:   execution.ExecutionId,
				WorkflowId:    execution.Workflow.ID,
				Authorization: execution.Authorization,
				Environments:  environments,
			}

			executionRequest.Priority = execution.Priority
			err = SetWorkflowQueue(ctx, executionRequest, environment)
			if err != nil {
				log.Printf("[ERROR] Failed re-adding execution to db: %s", err)
			}
		} else {
			//log.Printf("[DEBUG] Rerunning executions is not available in cloud yet.")
			//if len(environments) != 1 || strings.ToLower(environments[0]) != "cloud" {
			//	log.Printf("[DEBUG][%s] Skipping execution for workflow %s because it's not for JUST the cloud env. Org: %s", execution.ExecutionId, execution.Workflow.ID, execution.OrgId)
			//	continue
			//}

			streamUrl := fmt.Sprintf("https://shuffler.io")
			if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
				streamUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
			}

			if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
				streamUrl = fmt.Sprintf("%s", os.Getenv("SHUFFLE_CLOUDRUN_URL"))
			}

			streamUrl = fmt.Sprintf("%s/api/v1/workflows/%s/executions/%s/rerun", streamUrl, execution.Workflow.ID, execution.ExecutionId)

			client := &http.Client{
				Timeout: 5 * time.Second,
			}
			req, err := http.NewRequest(
				"POST",
				streamUrl,
				nil,
			)

			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", execution.Authorization))
			if err != nil {
				log.Printf("[WARNING] Error in new request for manual rerun: %s", err)
				continue
			}

			newresp, err := client.Do(req)
			if err != nil {
				log.Printf("[WARNING] Error running body for manual rerun: %s", err)
				continue
			}

			defer newresp.Body.Close()
			body, err := ioutil.ReadAll(newresp.Body)
			if err != nil {
				log.Printf("[WARNING] Failed reading body for manual rerun: %s", err)
				continue
			}

			log.Printf("[DEBUG] Rerun response: %s", string(body))
		}

		cnt += 1
		log.Printf("[DEBUG] Should rerun execution %s (%s - Workflow: %s) with environments %s", execution.ExecutionId, execution.Status, execution.Workflow.ID, environments)
		//log.Printf("[DEBUG] Result from rerunning %s: %s", execution.ExecutionId, string(body))
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

		if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
			backendUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
		}

		if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
			backendUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
		}

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
			//log.Printf("[ERROR][%s] Bad status for execution: %s", execution.ExecutionId, execution.Status)
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

		streamUrl := fmt.Sprintf("%s/api/v1/workflows/%s/executions/%s/abort?reason=%s", backendUrl, execution.Workflow.ID, execution.ExecutionId, url.QueryEscape(`{"success": False, "reason": "Shuffle's automated cleanup bot stopped this execution as it didn't finish within 30 minutes."}`))
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

		defer newresp.Body.Close()
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

	ctx := GetContext(request)
	environments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Failed getting environments")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't get environments"}`))
		return
	}

	// Always make Cloud the default environment
	// If there are multiple and none are chosen
	if project.Environment == "cloud" {
		defaults := []int{}
		cloudFound := false
		for envIndex, environment := range environments {
			if environment.Default {
				defaults = append(defaults, envIndex)
			}

			if strings.ToLower(environment.Name) == "cloud" {
				cloudFound = true
			}
		}

		// Ensure it's attached. When they click "set as default", it will become activated forever :>
		// Found by seeing a user from early on that didn't have the env
		if !cloudFound {
			setDefault := false
			if len(environments) == 1 || len(defaults) == 0 {
				setDefault = true
			}

			environments = append(environments, Environment{
				Name:       "Cloud",
				Type:       "cloud",
				Archived:   false,
				Registered: true,
				Default:    setDefault,
				OrgId:      user.ActiveOrg.Id,
				Id:         uuid.NewV4().String(),
			})

			defaults = append(defaults, len(environments)-1)
		}

		// Fallback to cloud for now
		if len(defaults) > 1 {
			for _, index := range defaults {
				if strings.ToLower(environments[index].Name) == "cloud" {
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
			// Get the current Queue for it
			environment.Queue = -1
			if len(environments) < 10 && environment.Type != "cloud" {
				//log.Printf("\n\nShould get queue for env %s (%s)\n\n", environment.Name, environment.Id)
				//executionRequests, err := GetWorkflowQueue(ctx, environment.Id, 100)

				foundName := environment.Name
				if project.Environment == "cloud" {
					foundName = fmt.Sprintf("%s_%s", strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(environment.Name, " ", "-"), "_", "-")), user.ActiveOrg.Id)
				}

				executionRequests, err := GetWorkflowQueue(ctx, foundName, 100)
				if err != nil {
					// Skipping as this comes up over and over
					log.Printf("[ERROR] (2) Failed reading body for workflowqueue: %s", err)
				} else {
					environment.Queue = len(executionRequests.Data)
				}

				//log.Printf("[DEBUG] Got %d executions for env %s", len(executionRequests.Data), environment.Name)
			}

			newEnvironments = append(newEnvironments, environment)
		}
	}

	// Resets ips and such within 90 seconds
	// Here as well as in db-connector due to cache handling
	timenow := time.Now().Unix()
	for envIndex, env := range newEnvironments {
		if newEnvironments[envIndex].Type == "onprem" {
			if env.Checkin > 0 && timenow-env.Checkin > 90 {
				newEnvironments[envIndex].RunningIp = ""
				newEnvironments[envIndex].Licensed = false
			}
		}
	}

	newjson, err := json.Marshal(newEnvironments)
	if err != nil {
		log.Printf("[DEBUG] Failed unmarshal: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking environments"}`)))
		return
	}

	//log.Printf("Existing environments: %s", string(newjson))

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func HandleApiAuthentication(resp http.ResponseWriter, request *http.Request) (User, error) {
	var err error
	apikey := request.Header.Get("Authorization")

	org_id := request.Header.Get("Org-Id")
	if len(org_id) == 0 {
		org_id = request.URL.Query().Get("org_id")

		if len(org_id) == 0 {
			org_id = request.Header.Get("OrgId")
		}
	}

	user := &User{}
	org := &Org{}
	ctx := GetContext(request)
	if len(org_id) > 0 {
		// Get the org
		org, err = GetOrg(ctx, org_id)
		if err != nil || org.Id != org_id {
			return User{}, errors.New("Invalid org id specified")
		}
	}

	// Loop headers
	if len(apikey) > 0 {
		if !strings.HasPrefix(apikey, "Bearer ") {
			return User{}, errors.New("No bearer token for authorization header")
		}

		apikeyCheck := strings.Split(apikey, " ")
		if len(apikeyCheck) != 2 {
			log.Printf("[WARNING] Invalid format for apikey: %s", apikeyCheck)
			return User{}, errors.New("Invalid format for apikey")
		}

		if len(apikeyCheck[1]) < 36 {
			return User{}, errors.New("Apikey must be at least 36 characters long (UUID)")
		}

		// This is annoying af
		newApikey := apikeyCheck[1]
		if len(newApikey) > 249 {
			newApikey = newApikey[0:248]
		}

		cache, err := GetCache(ctx, newApikey+org_id)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &user)
			if err == nil {
				//log.Printf("[WARNING] Got user from cache: %s", err)

				if len(user.Id) == 0 && len(user.Username) == 0 {
					return User{}, errors.New(fmt.Sprintf("Couldn't find user"))
				}

				user.ApiKey = newApikey
				user.SessionLogin = false

				// Increment API usage
				go IncrementCache(ctx, user.ActiveOrg.Id, "api_usage")

				return *user, nil
			}
		} else {
			//log.Printf("[WARNING] Error getting authentication cache for %s: %v", newApikey, err)
		}

		// Make specific check for just service user?
		// Get the user based on APIkey here
		userdata, err := GetApikey(ctx, apikeyCheck[1])
		if err != nil {
			//log.Printf("[WARNING] Apikey %s doesn't exist: %s", apikey, err)
			return User{}, err
		}

		if len(userdata.Id) == 0 && len(userdata.Username) == 0 {
			//log.Printf("[WARNING] Apikey %s doesn't exist or the user doesn't have an ID/Username", apikey)
			return User{}, errors.New("Couldn't find the user")
		}

		// Caching both bad and good apikeys :)

		if len(org_id) > 0 && userdata.ActiveOrg.Id != org_id {
			found := false
			for _, org := range userdata.Orgs {
				if org == org_id {
					found = true
					break
				}
			}

			if !found {
				return User{}, errors.New("User doesn't have access to this org")
			}

			log.Printf("[AUDIT] Setting user %s (%s) org to %#v FROM %#v for one request", userdata.Username, userdata.Id, org_id, userdata.ActiveOrg.Id)
			userdata.ActiveOrg.Id = org_id
			userdata.ActiveOrg.Name = org.Name
			userdata.ActiveOrg.Image = org.Image
		}

		userdata.SessionLogin = false
		userdata.ApiKey = newApikey

		b, err := json.Marshal(userdata)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling: %s", err)
			return User{}, err
		}

		err = SetCache(ctx, newApikey+org_id, b, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for apikey: %s", err)
		}

		go IncrementCache(ctx, userdata.ActiveOrg.Id, "api_usage")
		return userdata, nil
	}

	// One time API keys
	//authorizationArr, ok := request.URL.Query()["authorization"]
	//if ok {
	//	//authorization := ""
	//	//if len(authorizationArr) > 0 {
	//	//	authorization = authorizationArr[0]
	//	//}
	//	//_ = authorization
	//	//log.Printf("[ERROR] WHAT ARE ONE TIME KEYS USED FOR? User input?")
	//}

	// __session first due to Compatibility issues
	c, err := request.Cookie("__session")
	if err != nil {
		c, err = request.Cookie("session_token")
	}

	if err == nil {
		sessionToken := c.Value

		newCookie := &http.Cookie{
			Name:    "session_token",
			Value:   sessionToken,
			Expires: time.Now().Add(-100 * time.Hour),
			MaxAge:  -1,
			Path:    "/",
		}

		if project.Environment == "cloud" {
			newCookie.Domain = ".shuffler.io"
			newCookie.Secure = true
			newCookie.HttpOnly = true
		}

		user, err := GetSessionNew(ctx, sessionToken)
		if err != nil {
			log.Printf("[WARNING] No valid session token for ID %s. Setting cookie to expire. May cause fallback problems.", sessionToken)

			if resp != nil {
				http.SetCookie(resp, newCookie)

				newCookie.Name = "__session"
				http.SetCookie(resp, newCookie)
			}

			return User{}, err
		} else {
			// Check if both session tokens are set
			// Compatibility issues
			//expiration := time.Now().Add(3600 * time.Second)
			newCookie.Expires = c.Expires
			newCookie.MaxAge = c.MaxAge

			_, err1 := request.Cookie("session_token")
			if err1 != nil {
				//log.Printf("[DEBUG] Setting missing session_token for user %s (%s) (1)", user.Username, user.Id)
				newCookie.Name = "session_token"
				if resp != nil {
					http.SetCookie(resp, newCookie)
				}
			}

			_, err2 := request.Cookie("__session")
			if err2 != nil {
				//log.Printf("[DEBUG] Setting missing __session for user %s (%s) (2)", user.Username, user.Id)
				newCookie.Name = "__session"
				if resp != nil {
					http.SetCookie(resp, newCookie)
				}
			}
		}

		if len(user.Id) == 0 && len(user.Username) == 0 {

			newCookie := &http.Cookie{
				Name:    "session_token",
				Value:   sessionToken,
				Expires: time.Now().Add(-100 * time.Hour),
				MaxAge:  -1,
				Path:    "/",
			}

			if project.Environment == "cloud" {
				newCookie.Domain = ".shuffler.io"
				newCookie.Secure = true
				newCookie.HttpOnly = true
			}

			if resp != nil {
				http.SetCookie(resp, newCookie)

				newCookie.Name = "__session"
				http.SetCookie(resp, newCookie)
			}

			return User{}, errors.New(fmt.Sprintf("Couldn't find user"))
		}

		// This is to be able to overwrite access with available orgs
		// Org needs to match one the user already has access to
		if len(org_id) > 0 {
			found := false
			for _, org := range user.Orgs {
				if org == org_id {
					found = true
					break
				}
			}

			if !found {
				return User{}, errors.New("User doesn't have access to this org")
			}

			log.Printf("[AUDIT] Setting user %s (%s) org to %s for one request", user.Username, user.Id, org_id)
			user.ActiveOrg.Id = org_id
			user.ActiveOrg.Name = org.Name
			user.ActiveOrg.Image = org.Image
		}

		// We're using the session to find the user anyway, which is NOT user controlled
		// This means that this is redundant, but MAY allow users
		// to have access past session timeouts
		//if user.Session != sessionToken {
		//	return User{}, errors.New("[WARNING] Wrong session token")
		//}

		user.SessionLogin = true

		// Means session exists, but
		return user, nil
	}

	// Key = apikey
	return User{}, errors.New("Missing authentication")
}

func HandleGetUserApps(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	ctx := context.Background()
	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("[WARNING] Api authentication failed in get user apps - this does NOT require auth in the cloud.: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
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

	if userId == "me" {
		userId = user.Id
	}

	if user.Id != userId || len(userId) == 0 {
		log.Printf("[WARNING] No user ID supplied")
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Supply a valid user ID: /api/v1/users/{userId}/apps"}`))
		return
	}

	userapps, err := GetUserApps(ctx, user.Id)
	if err != nil {
		log.Printf("[WARNING] Failed getting apps (userapps): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	newbody, err := json.Marshal(userapps)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshalling user apps: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking workflow apps"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newbody)
}

func GetOpenapi(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just here to verify that the user is logged in
	_, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in validate swagger: %s", err)
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
	//}

	// FIXME - FIX AUTH WITH APP
	ctx := GetContext(request)
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

func GetActionResult(ctx context.Context, workflowExecution WorkflowExecution, id string) (WorkflowExecution, ActionResult) {
	// Get workflow execution to make sure we have the latest
	for _, actionResult := range workflowExecution.Results {
		if actionResult.Action.ID != id {
			continue
		}

		// ALWAYS relying on cache due to looping subflow issues
		if actionResult.Status == "WAITING" && actionResult.Action.AppName == "User Input" {
			break
		}

		if actionResult.Action.AppName == "shuffle-subflow" && project.Environment == "cloud" {
			//if os.Getenv("SHUFFLE_SWARM_CONFIG") == "run" && (project.Environment == "" || project.Environment == "worker") {
			//log.Printf("[INFO] Skipping due to cache requirement for subflow")
			break
		}

		return workflowExecution, actionResult
	}

	//log.Printf("[WARNING] No result found for %s - add here too?", id)
	cacheId := fmt.Sprintf("%s_%s_result", workflowExecution.ExecutionId, id)
	cache, err := GetCache(ctx, cacheId)
	if err == nil {
		actionResult := ActionResult{}
		cacheData := []byte(cache.([]uint8))
		// Just ensuring the data is good
		err = json.Unmarshal(cacheData, &actionResult)
		if err == nil {
			workflowExecution.Results = append(workflowExecution.Results, actionResult)
			SetWorkflowExecution(ctx, workflowExecution, false)
			return workflowExecution, actionResult
		}
	}

	return workflowExecution, ActionResult{}
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
				ID:             trigger.ID,
				AppName:        trigger.AppName,
				Name:           trigger.AppName,
				Environment:    environment,
				Label:          trigger.Label,
				ExecutionDelay: trigger.ExecutionDelay,
			}
			log.Printf("[DEBUG] Found trigger to be ran as app (?): %s!", trigger)
		}
	}

	return Action{}
}

func ArrayContainsLower(visited []string, id string) bool {
	found := false
	for _, item := range visited {
		if strings.ToLower(item) == strings.ToLower(id) {
			found = true
		}
	}

	return found
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

func HandleGetWorkflowRunCount(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in getting workflow execution count: %s", err)
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
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID when getting workflow execution count is not valid"}`))
		return
	}

	// get workflow and verify that it belongs to user
	ctx := GetContext(request)
	workflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Failed getting workflow %s while getting runcount: %s", fileId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Id != workflow.Owner || len(user.Id) == 0 {
		if workflow.OrgId == user.ActiveOrg.Id {
			//log.Printf("[AUDIT] User %s is accessing workflow count for '%s' (%s) as %s (get count) in org %s", user.Username, workflow.Name, workflow.ID, user.Role, user.ActiveOrg.Id)

		} else if project.Environment == "cloud" && user.Verified == true && user.Active == true && user.SupportAccess == true && strings.HasSuffix(user.Username, "@shuffler.io") {
			log.Printf("[AUDIT] Letting verified support admin %s access workflow run count for %s", user.Username, workflow.ID)

		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (get workflow run count)", user.Username, workflow.ID)
			resp.WriteHeader(403)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	// FIXME: This is not used yet

	// Get the "start_time" and "end_time" query params
	// They will be in this format: 2023-12-31T23:00:00.000Z
	// By default 30 days back -> 1 day in the future (with 00:00:00 timestamp)
	startTimeInt := time.Now().AddDate(0, 0, -30)
	endTimeInt := time.Now().AddDate(0, 0, 1)

	// Normalize startTimeInt & endTimeInt to be at 00:00:00
	startTimeInt = time.Date(startTimeInt.Year(), startTimeInt.Month(), startTimeInt.Day(), 0, 0, 0, 0, startTimeInt.Location())
	endTimeInt = time.Date(endTimeInt.Year(), endTimeInt.Month(), endTimeInt.Day(), 0, 0, 0, 0, endTimeInt.Location())

	startTime := request.URL.Query().Get("start_time")
	endTime := request.URL.Query().Get("end_time")
	if len(startTime) != 0 {
		// Check if url decode is necessary
		if strings.Contains(startTime, "%") {
			startTime, err = url.QueryUnescape(startTime)
			if err != nil {
				log.Printf("[WARNING] Failed url decoding start time '%s': %s", startTime, err)
			}
		}

		// Make starttime 1 year ago
		startTimeInt, err = time.Parse(time.RFC3339, startTime)
		if err != nil {
			log.Printf("[WARNING] Failed parsing start time: %s", err)
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "Failed parsing start time"}`))
			return
		}
	}

	if len(endTime) != 0 {
		// Check if url decode is necessary
		if strings.Contains(endTime, "%") {
			endTime, err = url.QueryUnescape(endTime)
			if err != nil {
				log.Printf("[WARNING] Failed url decoding end time '%s': %s", endTime, err)
			}
		}

		// Make endtime today
		endTimeInt, err = time.Parse(time.RFC3339, endTime)
		if err != nil {
			log.Printf("[WARNING] Failed parsing start time: %s", err)
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "Failed parsing start time"}`))
			return
		}

	}

	// Convert to unix timestamp
	startTimeNew := startTimeInt.Unix()
	endTimeNew := endTimeInt.Unix()

	//log.Printf("Start time: %#v, end time: %#v", startTimeNew, endTimeNew)

	workflowCount, err := GetWorkflowRunCount(ctx, fileId, startTimeNew, endTimeNew)
	if err != nil {
		log.Printf("[WARNING] Failed getting workflow count for %s", fileId)
		if err.Error() == "Not authorized" {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "User doesn't belong in this org"}`))
			return
		}

		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "count": %d}`, workflowCount)))
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

	ctx := GetContext(request)

	workflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Failed getting the workflow %s locally (get executions): %s", fileId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Id != workflow.Owner || len(user.Id) == 0 {
		if workflow.OrgId == user.ActiveOrg.Id {
			log.Printf("[AUDIT] User %s is accessing workflow '%s' (%s) executions as %s (get executions)", user.Username, workflow.Name, workflow.ID, user.Role)
		} else if project.Environment == "cloud" && user.Verified == true && user.Active == true && user.SupportAccess == true && strings.HasSuffix(user.Username, "@shuffler.io") {
			log.Printf("[AUDIT] Letting verified support admin %s access workflow execs for %s", user.Username, workflow.ID)
		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (get workflow execs)", user.Username, workflow.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	// Query for the specifci workflowId
	//q := datastore.NewQuery("workflowexecution").Filter("workflow_id =", fileId).Order("-started_at").Limit(30)
	//q := datastore.NewQuery("workflowexecution").Filter("workflow_id =", fileId)
	maxAmount := 100
	top, topOk := request.URL.Query()["top"]
	if topOk && len(top) > 0 {
		val, err := strconv.Atoi(top[0])
		if err == nil {
			maxAmount = val
		}
	}

	if maxAmount > 1000 {
		maxAmount = 1000
	}

	workflowExecutions, err := GetAllWorkflowExecutions(ctx, fileId, maxAmount)
	if err != nil {
		log.Printf("[WARNING] Failed getting executions for %s", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	//log.Printf("[DEBUG] Found %d executions for workflow %s", len(workflowExecutions), fileId)

	if len(workflowExecutions) == 0 {
		resp.WriteHeader(200)
		resp.Write([]byte("[]"))
		return
	}

	for index, execution := range workflowExecutions {
		newResults := []ActionResult{}
		newActions := []Action{}
		newTriggers := []Trigger{}

		// Results
		for _, result := range execution.Results {
			newParams := []WorkflowAppActionParameter{}
			for _, param := range result.Action.Parameters {
				if param.Configuration || strings.Contains(strings.ToLower(param.Name), "user") || strings.Contains(strings.ToLower(param.Name), "key") || strings.Contains(strings.ToLower(param.Name), "pass") {
					param.Value = ""
					//log.Printf("FOUND CONFIG: %s!!", param.Name)
				}

				newParams = append(newParams, param)
			}

			result.Action.Parameters = newParams
			newResults = append(newResults, result)
		}

		// Actions
		for _, action := range execution.Workflow.Actions {
			newParams := []WorkflowAppActionParameter{}
			for _, param := range action.Parameters {
				if param.Configuration || strings.Contains(strings.ToLower(param.Name), "user") || strings.Contains(strings.ToLower(param.Name), "key") || strings.Contains(strings.ToLower(param.Name), "pass") {
					param.Value = ""
					//log.Printf("FOUND CONFIG: %s!!", param.Name)
				}

				newParams = append(newParams, param)
			}

			action.Parameters = newParams
			newActions = append(newActions, action)
		}

		for _, trigger := range execution.Workflow.Triggers {
			trigger.LargeImage = ""
			trigger.SmallImage = ""
			newTriggers = append(newTriggers, trigger)
		}

		workflowExecutions[index].Results = newResults
		workflowExecutions[index].Workflow.Actions = newActions
		workflowExecutions[index].Workflow.Image = ""
		workflowExecutions[index].Workflow.Triggers = newTriggers
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

func GetWorkflowExecutionsV2(resp http.ResponseWriter, request *http.Request) {
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

	ctx := GetContext(request)
	checkExecOrg := false
	workflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Failed getting the workflow %s locally (get executions v2): %s", fileId, err)
		checkExecOrg = true
		//resp.WriteHeader(401)
		//resp.Write([]byte(`{"success": false}`))
		//return
	}

	if user.Id != workflow.Owner || len(user.Id) == 0 {
		if workflow.OrgId == user.ActiveOrg.Id {
			log.Printf("[AUDIT] User %s (%s) is accessing workflow '%s' (%s) executions as %s (get executions)", user.Username, user.Id, workflow.Name, workflow.ID, user.Role)
		} else if project.Environment == "cloud" && user.Verified == true && user.Active == true && user.SupportAccess == true && strings.HasSuffix(user.Username, "@shuffler.io") {
			log.Printf("[AUDIT] Letting verified support admin %s access workflow execs for %s", user.Username, workflow.ID)
			checkExecOrg = false
		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (get workflow execs)", user.Username, workflow.ID)
			checkExecOrg = true
			//resp.WriteHeader(401)
			//resp.Write([]byte(`{"success": false}`))
			//return
		}
	}

	// Query for the specifci workflowId
	maxAmount := 50
	top, topOk := request.URL.Query()["top"]
	if topOk && len(top) > 0 {
		val, err := strconv.Atoi(top[0])
		if err == nil {
			maxAmount = val
		}
	}

	if maxAmount > 1000 {
		maxAmount = 1000
	}

	// Add timeout of 6 seconds to the ctx
	ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()

	cursor := ""
	cursorList, cursorOk := request.URL.Query()["cursor"]
	if cursorOk && len(cursorList) > 0 {
		cursor = cursorList[0]
	}

	if maxAmount != 50 {
		log.Printf("[DEBUG] Getting %d executions for workflow %s (V2). Org %s (%s).", maxAmount, fileId, user.ActiveOrg.Name, user.ActiveOrg.Id)
	}

	workflowExecutions, newCursor, err := GetAllWorkflowExecutionsV2(ctx, fileId, maxAmount, cursor)
	if err != nil {
		log.Printf("[WARNING] Failed getting executions for %s", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if checkExecOrg {
		if len(workflowExecutions) != 1 {
			log.Printf("[WARNING] Wrong user (%s) for workflow %s (get workflow execs) - not 1", user.Username, workflow.ID)
			resp.WriteHeader(403)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		if workflowExecutions[0].OrgId != user.ActiveOrg.Id {
			log.Printf("[WARNING] Wrong user (%s) for workflow %s (get workflow execs) - execution orgid", user.Username, workflow.ID)
			resp.WriteHeader(403)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	if len(workflowExecutions) != maxAmount {
		//log.Printf("[DEBUG] Got %d executions for workflow %s (V2). Org %s (%s).", len(workflowExecutions), fileId, user.ActiveOrg.Name, user.ActiveOrg.Id)
	}

	if len(workflowExecutions) == 0 {
		resp.WriteHeader(200)
		resp.Write([]byte(`{"success": true, "executions": [], "cursor": ""}`))
		return
	}

	for index, execution := range workflowExecutions {
		newResults := []ActionResult{}
		newActions := []Action{}
		newTriggers := []Trigger{}

		// Results
		for _, result := range execution.Results {
			newParams := []WorkflowAppActionParameter{}
			for _, param := range result.Action.Parameters {
				if param.Configuration || strings.Contains(strings.ToLower(param.Name), "user") || strings.Contains(strings.ToLower(param.Name), "key") || strings.Contains(strings.ToLower(param.Name), "pass") {
					param.Value = ""
					//log.Printf("FOUND CONFIG: %s!!", param.Name)
				}

				newParams = append(newParams, param)
			}

			result.Action.Parameters = newParams
			newResults = append(newResults, result)
		}

		// Actions
		for _, action := range execution.Workflow.Actions {
			newParams := []WorkflowAppActionParameter{}
			for _, param := range action.Parameters {
				if param.Configuration || strings.Contains(strings.ToLower(param.Name), "user") || strings.Contains(strings.ToLower(param.Name), "key") || strings.Contains(strings.ToLower(param.Name), "pass") {
					param.Value = ""
					//log.Printf("FOUND CONFIG: %s!!", param.Name)
				}

				newParams = append(newParams, param)
			}

			action.Parameters = newParams
			newActions = append(newActions, action)
		}

		for _, trigger := range execution.Workflow.Triggers {
			trigger.LargeImage = ""
			trigger.SmallImage = ""
			newTriggers = append(newTriggers, trigger)
		}

		workflowExecutions[index].Results = newResults

		workflowExecutions[index].Workflow.Actions = newActions
		workflowExecutions[index].Workflow.Image = ""
		workflowExecutions[index].Workflow.Triggers = newTriggers

		// Would like to omit the whole thing :thinking:
		//workflowExecutions[index].Workflow = Workflow{}
	}

	newReturn := ExecutionReturn{
		Success:    true,
		Cursor:     newCursor,
		Executions: workflowExecutions,
	}

	newjson, err := json.Marshal(newReturn)
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

	ctx := GetContext(request)
	var workflows []Workflow

	workflows, err = GetAllWorkflowsByQuery(ctx, user)
	if err != nil {
		log.Printf("[WARNING] Failed getting workflows for user %s (0): %s", user.Username, err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(workflows) == 0 {
		log.Printf("[INFO] No workflows found for user %s (%s) in org %s (%s)", user.Username, user.Id, user.ActiveOrg.Name, user.ActiveOrg.Id)
		resp.WriteHeader(200)
		resp.Write([]byte("[]"))
		return
	}

	usecaseIds := []string{}
	newWorkflows := []Workflow{}
	for _, workflow := range workflows {
		if workflow.OrgId != user.ActiveOrg.Id {
			if !ArrayContains(workflow.SuborgDistribution, user.ActiveOrg.Id) {
				continue
			}
		}

		if workflow.Hidden {
			continue
		}

		if project.Environment == "cloud" && workflow.ExecutionEnvironment == "onprem" {
			continue
		}

		newActions := []Action{}
		for _, action := range workflow.Actions {
			// Removed because of exports. These are needed there.
			//action.LargeImage = ""
			//action.SmallImage = ""
			action.ReferenceUrl = ""
			newActions = append(newActions, action)
		}

		//workflow.Actions = newActions

		// Skipping these as they're related to onprem workflows in cloud (orborus)

		usecaseIds = append(usecaseIds, workflow.UsecaseIds...)
		newWorkflows = append(newWorkflows, workflow)
	}

	//log.Printf("[DEBUG] Env: %s, workflows: %d", project.Environment, len(newWorkflows))
	if project.Environment == "cloud" && len(newWorkflows) > 30 {
		log.Printf("[DEBUG] Removed workflow actions & images for user %s (%s) in org %s (%s)", user.Username, user.Id, user.ActiveOrg.Name, user.ActiveOrg.Id)

		// Check for "subflow" query
		isSubflow := false
		if subflow, subflowOk := request.URL.Query()["subflow"]; subflowOk && len(subflow) > 0 {
			if subflow[0] == "true" {
				isSubflow = true
			}
		}

		for workflowIndex, _ := range newWorkflows {
			if workflowIndex < 4 {
				continue
			}

			if !isSubflow {
				newWorkflows[workflowIndex].Actions = []Action{}
				newWorkflows[workflowIndex].Image = ""
			}

			newWorkflows[workflowIndex].Branches = []Branch{}
			newWorkflows[workflowIndex].VisualBranches = []Branch{}

			newWorkflows[workflowIndex].Description = ""
			newWorkflows[workflowIndex].Blogpost = ""

			if len(newWorkflows[workflowIndex].Org) > 0 {
				for orgIndex, _ := range newWorkflows[workflowIndex].Org {
					newWorkflows[workflowIndex].Org[orgIndex].Image = ""
				}
			}

			newWorkflows[workflowIndex].ExecutingOrg.Image = ""
		}

		// Add header that this is a limited response
		resp.Header().Set("X-Shuffle-Truncated", "true")
	} else {
		//log.Printf("[DEBUG] Loading workflows without truncating for user %s (%s) in org %s (%s)", user.Username, user.Id, user.ActiveOrg.Name, user.ActiveOrg.Id)
	}

	// Get the org as well to manage priorities
	// Only happens on first load, so it's like once per session~
	if len(usecaseIds) > 0 {
		org, err := GetOrg(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("[WARNING] Failed getting org %s for user %s during workflow load: %s", user.ActiveOrg.Id, user.Username, err)
		} else {
			for prioIndex, priority := range org.Priorities {
				if priority.Type != "usecase" || priority.Active != true {
					continue
				}

				for _, usecaseId := range usecaseIds {
					if strings.Contains(strings.ToLower(priority.Name), strings.ToLower(usecaseId)) {
						//log.Printf("\n\n[DEBUG] Found usecase %s in priority %s\n\n", usecaseId, priority.Name)
						org.Priorities[prioIndex].Active = false

						SetOrg(ctx, *org, org.Id)
						break
					}
				}
			}
		}
	}

	// Fix parent/child workflow loading to only load EITHER parent OR child
	removeIds := []string{}
	newParsedWorkflows := []Workflow{}
	for _, workflow := range newWorkflows {
		if len(workflow.ChildWorkflowIds) > 0 {
			found := false
			for _, childId := range workflow.ChildWorkflowIds {
				for _, checkWorkflow := range newWorkflows {
					if checkWorkflow.ID == childId {
						found = true
						break
					}
				}

				if found {
					break
				}
			}

			if found {
				continue
			}
		}

		if len(workflow.ParentWorkflowId) > 0 {
			removeIds = append(removeIds, workflow.ParentWorkflowId)
		}

		newParsedWorkflows = append(newParsedWorkflows, workflow)
	}

	// Bleh
	if len(removeIds) > 0 {
		anotherNewOne := []Workflow{}
		for _, newParsed := range newParsedWorkflows {
			if ArrayContains(removeIds, newParsed.ID) {
				continue
			}

			anotherNewOne = append(anotherNewOne, newParsed)
		}

		newParsedWorkflows = anotherNewOne
	}

	newWorkflows = newParsedWorkflows

	//log.Printf("[INFO] Returning %d workflows", len(newWorkflows))
	newjson, err := json.Marshal(newWorkflows)
	if err != nil {
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking workflows"}`)))
		return
	}

	/*
		if project.CacheDb {
			err = SetCache(ctx, cacheKey, newjson, 30)
			if err != nil {
				log.Printf("[ERROR] Failed updating workflow cache for org %s: %s", user.ActiveOrg.Id, err)
			}
		}
	*/

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func SetAuthenticationConfig(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("[AUDIT] Api authentication failed in get all apps: %s", userErr)
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

	ctx := GetContext(request)
	auth, err := GetWorkflowAppAuthDatastore(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Authget error: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": ":("}`))
		return
	}

	if auth.OrgId != user.ActiveOrg.Id {
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "User can't edit this org"}`))
		return
	}

	if config.Action == "assign_everywhere" {

		err := AssignAuthEverywhere(ctx, auth, user)
		if err != nil {
			log.Printf("[ERROR] Failed assigning auth everywhere: %s", err)

			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed getting workflows to update"}`))
		} else {
			log.Printf("[INFO] Assigned auth everywhere")

		}
	} else if config.Action == "suborg_distribute" {
		org, err := GetOrg(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("[ERROR] Failed getting org %s: %s", auth.OrgId, err)
			resp.WriteHeader(403)
			resp.Write([]byte(`{"success": false, "reason": "Failed getting org"}`))
			return
		}

		// Check if org doesn't have a creator org
		if len(org.CreatorOrg) != 0 {
			log.Printf("[INFO] Org %s has creator org %s, can't distribute", org.Id, org.CreatorOrg)
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "Can't distribute auth for suborgs"}`))
			return
		}

		if auth.SuborgDistributed {
			auth.SuborgDistributed = false
		} else {
			auth.SuborgDistributed = true
		}

		err = SetWorkflowAppAuthDatastore(ctx, *auth, auth.Id)
		if err != nil {
			log.Printf("[ERROR] Failed setting auth for org %s (%s): %s", org.Name, org.Id, err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed updating auth. Please try again."}`))
			return
		}
	} else {
		log.Printf("[WARNING] Unknown auth change action %s", config.Action)
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
	//var config configAuth

	//log.Printf("Should set %s
}

func HandleGetTriggers(resp http.ResponseWriter, request *http.Request) {

	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get schedules: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success":false}`))
		return
	}

	ctx := GetContext(request)

	workflowsChan := make(chan []Workflow)
	schedulesChan := make(chan []ScheduleOld)
	hooksChan := make(chan []Hook)
	pipelinesChan := make(chan []Pipeline)

	errChan := make(chan error)

	wg := sync.WaitGroup{}
	wg.Add(4)

	go func() {
		workflows, err := GetAllWorkflowsByQuery(ctx, user)
		if err != nil {
			wg.Done()
			errChan <- err
			return
		}
		wg.Done()
		workflowsChan <- workflows

	}()

	go func() {
		schedules, err := GetAllSchedules(ctx, user.ActiveOrg.Id)
		if err != nil {
			wg.Done()
			errChan <- err
			return
		}
		wg.Done()
		schedulesChan <- schedules

	}()

	go func() {
		hooks, err := GetHooks(ctx, user.ActiveOrg.Id)
		if err != nil {
			wg.Done()
			errChan <- err
			return
		}
		wg.Done()
		hooksChan <- hooks
	}()

	go func() {
		pipelines, err := GetPipelines(ctx, user.ActiveOrg.Id)
		if err != nil {
			wg.Done()
			errChan <- err
			return
		}
		wg.Done()
		pipelinesChan <- pipelines
	}()

	wg.Wait()

	// Checks if we got any errors without blocking the entire process
	select {
	case err := <-errChan:
		if err != nil {
			log.Printf("[ERROR] Failed to fetch data: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success":false}`))
			return
		}
	default:
		//log.Println("[INFO] No errors received within Go routines, proceeding with further logic")
	}

	hooks := <-hooksChan
	schedules := <-schedulesChan
	workflows := <-workflowsChan
	pipelines := <-pipelinesChan

	hookMap := map[string]Hook{}
	scheduleMap := map[string]ScheduleOld{}
	pipelineMap := map[string]Pipeline{}

	for _, hook := range hooks {
		hookMap[hook.Id] = hook
	}
	for _, schedule := range schedules {
		scheduleMap[schedule.Id] = schedule
	}
	for _, pipeline := range pipelines {
		pipelineMap[pipeline.TriggerId] = pipeline
	}

	allHooks := []Hook{}
	allSchedules := []ScheduleOld{}
	allPipelines := []Pipeline{}
	// Now loop through the workflow triggers to see if anything is not in sync
	for _, workflow := range workflows {
		for _, trigger := range workflow.Triggers {

			if trigger.Status == "uninitialized" {
				continue
			}

			switch trigger.TriggerType {
			case "WEBHOOK":
				{
					hook := Hook{}
					storedHook, exist := hookMap[trigger.ID]
					if !exist {

						auth := ""
						version := ""
						customBody := ""
						startNode := ""

						hook.Id = trigger.ID
						hook.Environment = trigger.Environment
						hook.Workflows = []string{workflow.ID}
						hook.Owner = workflow.Owner
						hook.OrgId = workflow.OrgId

						hookInfo := Info{}
						for _, param := range trigger.Parameters {
							if param.Name == "url" {
								hookInfo.Url = param.Value
								hookInfo.Name = trigger.Label
							} else if param.Name == "auth_headers" {
								auth = param.Value
							} else if param.Name == "await_response" {
								version = param.Value
							} else if param.Name == "custom_response_body" {
								customBody = param.Value
							}
						}
						hook.Info = hookInfo

						// searching for start node
						if len(workflow.Branches) != 0 {
							for _, branch := range workflow.Branches {
								if branch.SourceID == trigger.ID {
									startNode = branch.DestinationID
								}
							}
						}
						if startNode == "" {
							startNode = workflow.Start
						}
						hook.Start = startNode
						hook.Status = "stopped"
						hook.Running = false

						hook.Auth = auth
						hook.Version = version
						hook.CustomResponse = customBody
						allHooks = append(allHooks, hook)
					} else {
						hookValue := storedHook
						hookValue.Status = "running"
						for _, param := range trigger.Parameters {
							if param.Name == "url" {
								hookValue.Info.Url = param.Value
								hookValue.Info.Name = trigger.Label
							}
						}

						allHooks = append(allHooks, hookValue)
					}
				}
			case "SCHEDULE":
				{
					schedule := ScheduleOld{}
					storedschedule, exist := scheduleMap[trigger.ID]
					if !exist {

						startNode := ""

						schedule.Id = trigger.ID
						schedule.WorkflowId = workflow.ID
						schedule.Environment = trigger.Environment
						schedule.Org = workflow.OrgId
						schedule.Name = trigger.Label

						for _, param := range trigger.Parameters {
							if param.Name == "cron" {
								schedule.Frequency = param.Value
							} else if param.Name == "execution_argument" {
								schedule.Argument = param.Value
							}
						}

						for _, branch := range workflow.Branches {
							if branch.SourceID == schedule.Id {
								startNode = branch.DestinationID
							}
						}

						if startNode == "" {
							startNode = workflow.Start
						}
						schedule.StartNode = startNode
						Wrapper := fmt.Sprintf(`{"start": "%s", "execution_source": "schedule", "execution_argument": "%s"}`, startNode, schedule.Argument)
						schedule.WrappedArgument = Wrapper
						schedule.Status = "stopped"

						allSchedules = append(allSchedules, schedule)
					} else {
						scheduleValue := storedschedule
						scheduleValue.Name = trigger.Label
						scheduleValue.Status = "running"

						allSchedules = append(allSchedules, scheduleValue)
					}
				}
			case "PIPELINE":
				{

					storedPipeline, exist := pipelineMap[trigger.ID]
					if exist && storedPipeline.Status != "uninitialized" {
						startNode := ""

						storedPipeline.WorkflowId = workflow.ID

						if len(workflow.Branches) != 0 {
							for _, branch := range workflow.Branches {
								if branch.SourceID == trigger.ID {
									startNode = branch.DestinationID
								}
							}
						}
						if startNode == "" {
							startNode = workflow.Start
						}
						storedPipeline.StartNode = startNode
						allPipelines = append(allPipelines, storedPipeline)

					}
				}
			}
		}
	}

	sort.SliceStable(allHooks, func(i, j int) bool {
		return allHooks[i].Info.Name < allHooks[j].Info.Name
	})
	sort.SliceStable(allSchedules, func(i, j int) bool {
		return allSchedules[i].Name < allSchedules[j].Name
	})
	sort.SliceStable(pipelines, func(i, j int) bool {
		return pipelines[i].Name < pipelines[j].Name
	})

	allTriggersWrapper := AllTriggersWrapper{}

	allTriggersWrapper.WebHooks = allHooks
	allTriggersWrapper.Schedules = allSchedules
	allTriggersWrapper.Pipelines = allPipelines

	newjson, err := json.Marshal(allTriggersWrapper)
	if err != nil {
		log.Printf("Failed unmarshal: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed unpacking environments"}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
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

	ctx := GetContext(request)
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

func HandleGetHooks(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get hooks: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role != "admin" {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Admin required"}`))
		return
	}

	ctx := GetContext(request)
	hooks, err := GetHooks(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Failed getting hooks: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Couldn't get hooks"}`))
		return
	}

	newjson, err := json.Marshal(hooks)
	if err != nil {
		log.Printf("Failed unmarshal: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking environments"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func HandleUpdateUser(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	if project.Environment == "cloud" {
		// Checking if it's a special region. All user-specific requests should
		// go through shuffler.io and not subdomains

		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting Update User request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
	}

	userInfo, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in update user: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Failed reading body in update user: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Required field: user_id"}`)))
		return
	}

	// NEVER allow the user to set all the data themselves
	type newUserStruct struct {
		UserId string `json:"user_id"`

		Tutorial    string   `json:"tutorial" datastore:"tutorial"`
		Firstname   string   `json:"firstname"`
		Lastname    string   `json:"lastname"`
		Role        string   `json:"role"`
		Username    string   `json:"username"`
		EthInfo     EthInfo  `json:"eth_info"`
		CompanyRole string   `json:"company_role"`
		Suborgs     []string `json:"suborgs"`

		CreatorDescription string          `json:"creator_description"`
		CreatorUrl         string          `json:"creator_url"`
		CreatorLocation    string          `json:"creator_location"`
		CreatorSkills      string          `json:"creator_skills"`
		CreatorWorkStatus  string          `json:"creator_work_status"`
		CreatorSocial      string          `json:"creator_social"`
		SpecializedApps    []MinimizedApps `json:"specialized_apps"`
	}

	ctx := GetContext(request)
	var t newUserStruct
	err = json.Unmarshal(body, &t)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling userId: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unmarshaling. Required field: user_id"}`)))
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
		isSelf := false
		if project.Environment == "cloud" && len(foundUser.Id) == 32 {
			isSelf = CheckCreatorSelfPermission(ctx, userInfo, *foundUser, &AlgoliaSearchCreator{ObjectID: foundUser.Id, IsOrg: true})
		}

		if (!isSelf || len(foundUser.Id) != 32) && !userInfo.SupportAccess {
			log.Printf("[AUDIT] User %s (%s) is admin, but can't edit users outside their own org (%s).", userInfo.Username, userInfo.Id, foundUser.Id)
			resp.WriteHeader(400)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "You don't have access to modify this user. Contact support@shuffler.io if you think this is wrong."}`)))
			return
		}
	}

	orgUpdater := true
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
			log.Printf("[INFO] Updated user %s from %s to %s in org %s. If role is empty, not updating", foundUser.Username, foundUser.Role, t.Role, userInfo.ActiveOrg.Id)
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

	if project.Environment == "cloud" {
		if len(t.EthInfo.Account) > 0 {
			log.Printf("[DEBUG] Should set ethinfo to %s", t.EthInfo)
			foundUser.EthInfo = t.EthInfo
		}

		// Check if UserID is different?
		/*
			if len(t.UserId) > 0 && t.UserId != foundUser.Id {
				log.Printf("[DEBUG] Should set userid to %s", t.UserId)
				newUser, err := GetUser(ctx, t.UserId)
				if err != nil {
					log.Printf("[WARNING] Failed getting user %s: %s", t.UserId, err)
					resp.WriteHeader(401)
					resp.Write([]byte(`{"success": false, "reason": "Username and/or password is incorrect"}`))
					return
				}

				log.Printf("[DEBUG] Found the user with username %s", newUser.Username)
			}
		*/

		log.Printf("[DEBUG] Found github username %s. ID to look for: %s", foundUser.PublicProfile.GithubUsername, t.UserId)

		username := foundUser.PublicProfile.GithubUsername
		creator, err := HandleAlgoliaCreatorSearch(ctx, username)

		// the same field within Algolia itself.
		if err == nil {
			// Related to creators
			if len(t.CreatorDescription) > 0 {
				foundUser.PublicProfile.GithubBio = t.CreatorDescription
			}

			if len(t.CreatorUrl) > 0 {
				foundUser.PublicProfile.GithubUrl = t.CreatorUrl
			}

			if len(t.CreatorLocation) > 0 {
				foundUser.PublicProfile.GithubLocation = t.CreatorLocation
			}

			if len(t.CreatorSkills) > 0 {
				foundUser.PublicProfile.Skills = strings.Split(t.CreatorSkills, ",")
			}

			if len(t.CreatorWorkStatus) > 0 {
				foundUser.PublicProfile.WorkStatus = t.CreatorWorkStatus
			}

			if len(t.CreatorSocial) > 0 {
				foundUser.PublicProfile.Social = strings.Split(t.CreatorSocial, ",")
			}

			if len(t.SpecializedApps) > 0 {
				// FIXME: Update the user in algolia here. Currently just updating existing user
				for _, app := range t.SpecializedApps {
					found := false
					for _, currentApp := range creator.SpecializedApps {
						if currentApp.Name == app.Name {
							found = true
							break
						}
					}

					if !found {
						creator.SpecializedApps = append(creator.SpecializedApps, app)
					}
				}

				for _, creatorApp := range creator.SpecializedApps {
					// If not found in foundUser.PublicProfile
					found := false
					for _, userApp := range foundUser.PublicProfile.SpecializedApps {
						if userApp.Name == creatorApp.Name {
							found = true
							break
						}
					}

					if !found {
						foundUser.PublicProfile.SpecializedApps = append(foundUser.PublicProfile.SpecializedApps, creatorApp)
					}
				}

				//foundUser.PublicProfile.SpecializedApps = creator.SpecializedApps
			}
		}
	}

	if len(t.Suborgs) > 0 && foundUser.Id != userInfo.Id {
		//log.Printf("[DEBUG] Got suborg change: %s", t.Suborgs)
		// 1. Check if current users' active org is admin in same parent org as user
		// 2. Make sure the user should have access to suborg
		// 3. Make sure it's ONLY changing orgs based on parent org

		// Check which ones the current user has access to
		parentOrgId := userInfo.ActiveOrg.Id
		newSuborgs := []string{}
		for _, suborg := range t.Suborgs {
			if suborg == "REMOVE" {
				newSuborgs = append(newSuborgs, suborg)
				continue
			}

			found := false
			org, err := GetOrg(ctx, suborg)
			if err != nil {
				continue
			}

			if org.CreatorOrg != parentOrgId {
				continue
			}

			for _, userOrg := range org.Users {
				if userOrg.Id == userInfo.Id {
					found = true
					break
				}
			}

			if found {
				newSuborgs = append(newSuborgs, suborg)
			}
		}

		t.Suborgs = newSuborgs

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
			parsedOrgs := []string{foundOrg.CreatorOrg}
			for _, item := range foundOrg.ManagerOrgs {
				parsedOrgs = append(parsedOrgs, item.Id)
			}

			if !ArrayContains(parsedOrgs, userInfo.ActiveOrg.Id) {
				log.Printf("[ERROR] The Org %s (%s) SHOULD NOT BE ADDED for %s (%s): %s. This may indicate a test of the API, as the frontend shouldn't allow it.", foundOrg.Name, suborg, foundUser.Username, foundUser.Id, err)
				continue
			}

			addedOrgs = append(addedOrgs, suborg)
		}

		// After done, check if ANY of the users' orgs are suborgs of active parent org. If they are, remove.
		// Update: This piece runs anyway, in case the job is to REMOVE any suborg
		//if len(addedOrgs) > 0 {
		log.Printf("[DEBUG] Orgs to be added: %s. Existing: %s.", addedOrgs, foundUser.Orgs)

		// Removed for now due to multi-org chain deleting you from other org chains
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

			// Check if it has anything to do with the parent org, otherwise don't touch it
			// CreatorOrg, ManagerOrgs, Suborgs
			orgRelevancies := []string{foundOrg.CreatorOrg}
			for _, item := range foundOrg.ManagerOrgs {
				orgRelevancies = append(orgRelevancies, item.Id)
			}
			for _, item := range foundOrg.ChildOrgs {
				orgRelevancies = append(orgRelevancies, item.Id)
			}
			if !ArrayContains(orgRelevancies, userInfo.ActiveOrg.Id) {
				newUserOrgs = append(newUserOrgs, suborg)
				log.Printf("[DEBUG] Org %s (%s) is not relevant to parent org %s (%s). Skipping.", foundOrg.Name, foundOrg.Id, userInfo.ActiveOrg.Name, userInfo.ActiveOrg.Id)
				continue
			}

			// Slower but easier :)
			parsedOrgs := []string{foundOrg.CreatorOrg}
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

		log.Printf("[DEBUG] New orgs for %s (%s) is %s", foundUser.Username, foundUser.Id, foundUser.Orgs)
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

	// Overwriting all settings as a just in case
	workflow.ID = uuid.NewV4().String()
	workflow.Owner = user.Id
	workflow.Sharing = "private"
	user.ActiveOrg.Users = []UserMini{}
	workflow.ExecutingOrg = user.ActiveOrg
	workflow.OrgId = user.ActiveOrg.Id

	ctx := GetContext(request)
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

			// FIXME: Still necessary? This hinders hybrid mode cloud -> onprem
			//if project.Environment == "cloud" {
			//	action.Environment = "Cloud"
			//}

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
			workflowapps, err = GetAllWorkflowApps(ctx, 1000, 0)
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
				if (item.Name == "Shuffle Tools" || item.Name == "Shuffle-Tools") && item.AppVersion == "1.2.0" {
					//nodeId := "40447f30-fa44-4a4f-a133-4ee710368737"
					nodeId := uuid.NewV4().String()
					workflow.Start = nodeId
					newAction := Action{
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
					}
					newAction.Position = Position{
						X: 449.5,
						Y: 446,
					}

					newActions = append(newActions, newAction)

					break
				}
			}
		}
	} else {
		//log.Printf("[INFO] Has %d actions already", len(newActions))
		// FIXME: Check if they require authentication and if they exist locally
		//log.Printf("\n\nSHOULD VALIDATE AUTHENTICATION")
		//AuthenticationId string `json:"authentication_id,omitempty" datastore:"authentication_id"`
		//allAuths, err := GetAllWorkflowAppAuth(ctx, user.ActiveOrg.Id)
		//if err == nil {
		//	log.Printf("AUTH: %s", allAuths)
		//	for _, action := range newActions {
		//		log.Printf("ACTION: %s", action)
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

	auth, authOk := request.URL.Query()["set_auth"]
	//log.Printf("\n\n\n[DEBUG] AUTH: %#v\n\n\n", auth)
	if authOk && len(auth) > 0 && auth[0] == "true" {
		allAuths, autherr := GetAllWorkflowAppAuth(ctx, user.ActiveOrg.Id)
		workflowapps, apperr := GetPrioritizedApps(ctx, user)
		if autherr != nil || apperr != nil {
			log.Printf("[ERROR] Failed to get auths/app: %s/%s", autherr, apperr)
		} else {
			for actionIndex, action := range workflow.Actions {
				if action.AuthenticationId != "" {
					continue
				}

				// Check if auth is required
				outerapp := WorkflowApp{}
				for _, app := range workflowapps {
					if app.Name != action.AppName {
						continue
					}

					outerapp = app
					break
				}

				if len(outerapp.ID) > 0 && outerapp.Authentication.Required {
					for _, auth := range allAuths {
						if auth.App.ID == outerapp.ID || auth.App.Name == outerapp.Name {
							log.Printf("[DEBUG] Automatically setting authentication for action %s (%s) in workflow %s (%s)", action.Name, action.ID, workflow.Name, workflow.ID)

							workflow.Actions[actionIndex].AuthenticationId = auth.Id
						}
					}
				}
			}
		}
	}

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
		//log.Printf("Getting Org workflows")

		workflows, err := GetAllWorkflowsByQuery(ctx, user)
		if err == nil {
			updated := false
			for tutorialIndex, tutorial := range org.Tutorials {
				if tutorial.Name == "Discover Usecases" {
					org.Tutorials[tutorialIndex].Description = fmt.Sprintf("%d workflows created. Find more using Workflow Templates or public Workflows.", len(workflows)+1)
					if len(workflows) > 0 {
						org.Tutorials[tutorialIndex].Done = true
						//org.Tutorials[tutorialIndex].Link = "/search?tab=workflows"
						//org.Tutorials[tutorialIndex].Link = "/usecases"
						org.Tutorials[tutorialIndex].Link = "/welcome?tab=3"
					}

					updated = true
					break
				}
			}

			if updated {
				SetOrg(ctx, *org, org.Id)
			}
		} else {
			log.Printf("[ERROR] Failed getting workflows during new workflow creation for updating stats: %s", err)
		}

		//for _, loopUser := range org.Users {
		//	cacheKey := fmt.Sprintf("%s_workflows", loopUser.Id)
		//	DeleteCache(ctx, cacheKey)
		//}
	} else {
		//cacheKey := fmt.Sprintf("%s_workflows", user.Id)
		//DeleteCache(ctx, cacheKey)
	}

	log.Printf("[INFO] Saved new workflow %s with name %s", workflow.ID, workflow.Name)

	resp.WriteHeader(200)
	resp.Write(workflowjson)
}

func hasBranchChanged(newBranch Branch, oldBranch Branch) (string, bool) {
	// Check if there is a difference in parameters, and what they are
	if newBranch.Label != oldBranch.Label {
		return "label", true
	}

	if len(newBranch.Conditions) != len(oldBranch.Conditions) {
		return "condition_amount", true
	}

	for _, param := range newBranch.Conditions {
		found := false
		for _, oldParam := range oldBranch.Conditions {
			if param.Condition.ID != oldParam.Condition.ID {
				continue
			}

			if param.Condition.Value != oldParam.Condition.Value {
				return "condition_value_type", true
			}

			if param.Source.Value != oldParam.Source.Value {
				return "condition_source", true
			}

			if param.Destination.Value != oldParam.Destination.Value {
				return "condition_destination", true
			}

			found = true
			break
		}

		if !found {
			return "param_not_found", true
		}
	}

	return "", false
}

func hasTriggerChanged(newAction Trigger, oldAction Trigger) (string, bool) {
	// Check if there is a difference in parameters, and what they are
	if newAction.Name != oldAction.Name {
		return "name", true
	}

	if newAction.Label != oldAction.Label {
		return "label", true
	}

	if newAction.Position.X != oldAction.Position.X || newAction.Position.Y != oldAction.Position.Y {
		return "position", true
	}

	if newAction.AppVersion != oldAction.AppVersion {
		return "app_version", true
	}

	if newAction.IsStartNode != oldAction.IsStartNode {
		return "startnode", true
	}

	for _, param := range newAction.Parameters {
		found := false
		for _, oldParam := range oldAction.Parameters {
			if param.Name == oldParam.Name {
				if param.Value != oldParam.Value {
					return "param_value", true
				}

				found = true
				break
			}
		}

		if !found {
			return "param_not_found", true
		}
	}

	return "", false
}

func hasActionChanged(newAction Action, oldAction Action) (string, bool) {
	// Check if there is a difference in parameters, and what they are
	if newAction.Name != oldAction.Name {
		return "name", true
	}

	if newAction.Label != oldAction.Label {
		return "label", true
	}

	if newAction.Position.X != oldAction.Position.X || newAction.Position.Y != oldAction.Position.Y {
		return "position", true
	}

	if newAction.AppVersion != oldAction.AppVersion {
		return "app_version", true
	}

	if newAction.AppID != oldAction.AppID {
		return "app_id", true
	}

	if newAction.IsStartNode != oldAction.IsStartNode {
		return "startnode", true
	}

	for _, param := range newAction.Parameters {
		found := false
		for _, oldParam := range oldAction.Parameters {
			if param.Name == oldParam.Name {
				if param.Value != oldParam.Value {
					return "param_value", true
				}

				found = true
				break
			}
		}

		if !found {
			return "param_not_found", true
		}
	}

	return "", false
}

func diffWorkflowWrapper(newWorkflow Workflow) Workflow {
	// Actually load the child workflows directly from DB
	ctx := context.Background()
	childWorkflows, err := ListChildWorkflows(ctx, newWorkflow.ID)
	if err != nil {
		return newWorkflow
	}

	//log.Printf("\n\n\nCHILD WORKFLOWS (1): %d\n\n\n", len(childWorkflows))

	// Taking care of dedup in case there is a reduction in orgs
	newChildWorkflows := []Workflow{}
	for _, childWorkflow := range childWorkflows {
		if !ArrayContains(newWorkflow.SuborgDistribution, childWorkflow.OrgId) {
			continue
		}

		newChildWorkflows = append(newChildWorkflows, childWorkflow)
	}

	childWorkflows = newChildWorkflows
	//log.Printf("\n\n\nCHILD WORKFLOWS (2): %d\n\n\n", len(childWorkflows))

	if len(childWorkflows) < len(newWorkflow.SuborgDistribution) {
		for _, suborgId := range newWorkflow.SuborgDistribution {
			found := false

			for _, childWorkflow := range childWorkflows {
				if childWorkflow.OrgId == suborgId {
					found = true
					break
				}
			}

			if !found {
				log.Printf("\n\n[WARNING] Child workflow of %s (%s) for org %s is not distributed yet. Creating...", newWorkflow.Name, newWorkflow.ID, suborgId)

				childWorkflow, err := GenerateWorkflowFromParent(ctx, newWorkflow, newWorkflow.OrgId, suborgId)
				if err != nil {
					log.Printf("[WARNING] Failed to generate child workflow %s (%s) for %s (%s): %s", childWorkflow.Name, childWorkflow.ID, newWorkflow.Name, newWorkflow.ID, err)
				} else {
					log.Printf("[INFO] Generated child workflow %s (%s) for %s (%s)", childWorkflow.Name, childWorkflow.ID, newWorkflow.Name, newWorkflow.ID)

					childWorkflows = append(childWorkflows, *childWorkflow)
				}
			}
		}
	}

	//log.Printf("\n\n\nCHILD WORKFLOWS (3): %d\n\n\n", len(childWorkflows))
	waitgroup := sync.WaitGroup{}
	for _, childWorkflow := range childWorkflows {
		// Skipping distrib to old ones~
		if !ArrayContains(newWorkflow.SuborgDistribution, childWorkflow.OrgId) {
			continue
		}

		if len(childWorkflow.Name) == 0 && len(newWorkflow.ID) == 0 {
			continue
		}

		if len(childWorkflow.ID) == 0 {
			continue
		}

		if childWorkflow.ParentWorkflowId != newWorkflow.ID {
			log.Printf("[WARNING] Child workflow '%s' has a different parent than %s", childWorkflow.ID, newWorkflow.ID)
			continue
		}

		//diffWorkflows(childWorkflow, newWorkflow, true)
		waitgroup.Add(1)
		go func(childWorkflow Workflow, newWorkflow Workflow, update bool) {
			diffWorkflows(childWorkflow, newWorkflow, update)
			waitgroup.Done()
		}(childWorkflow, newWorkflow, true)
	}

	waitgroup.Wait()

	return newWorkflow
}

func diffWorkflows(oldWorkflow Workflow, newWorkflow Workflow, update bool) {
	// Check if there is a difference in actions, and what they are
	// Check if there is a difference in triggers, and what they are
	// Check if there is a difference in branches, and what they are

	nameChanged := false
	descriptionChanged := false
	tagsChanged := false

	backupsChanged := false
	inputfieldsChanged := false
	discoveredEnvironment := ""

	addedActions := []string{}
	removedActions := []string{}
	updatedActions := []Action{}

	addedTriggers := []string{}
	removedTriggers := []string{}
	updatedTriggers := []Trigger{}

	addedBranches := []string{}
	removedBranches := []string{}
	updatedBranches := []Branch{}

	if oldWorkflow.Name != newWorkflow.Name {
		nameChanged = true
	}

	if oldWorkflow.Description != newWorkflow.Description {
		descriptionChanged = true
	}

	if oldWorkflow.BackupConfig.UploadRepo != newWorkflow.BackupConfig.UploadRepo || oldWorkflow.BackupConfig.UploadBranch != newWorkflow.BackupConfig.UploadBranch || oldWorkflow.BackupConfig.UploadUsername != newWorkflow.BackupConfig.UploadUsername || oldWorkflow.BackupConfig.UploadToken != newWorkflow.BackupConfig.UploadToken {
		backupsChanged = true
	}

	if len(oldWorkflow.Tags) != len(newWorkflow.Tags) {
		tagsChanged = true
	}

	if len(oldWorkflow.InputQuestions) != len(newWorkflow.InputQuestions) {
		inputfieldsChanged = true
	}

	// Child workflow env & auth id mapping
	newWorkflowEnvironment := "cloud"
	for actionIndex, action := range newWorkflow.Actions {
		if len(action.Environment) > 0 {
			discoveredEnvironment = action.Environment
		}

		// In case of replication
		newWorkflow.Actions[actionIndex].AuthenticationId = ""

		idFound := false
		for _, oldWorkflowAction := range oldWorkflow.Actions {
			if oldWorkflowAction.ID == action.ID {
				idFound = true
				newWorkflow.Actions[actionIndex].AuthenticationId = oldWorkflowAction.AuthenticationId
			}
		}

		if !idFound {
			for _, oldWorkflowAction := range oldWorkflow.Actions {
				if oldWorkflowAction.AppID == action.AppID {
					newWorkflow.Actions[actionIndex].AuthenticationId = oldWorkflowAction.AuthenticationId
					break
				}
			}
		}
	}

	for _, action := range oldWorkflow.Actions {
		if action.Environment != newWorkflowEnvironment {
			discoveredEnvironment = newWorkflowEnvironment
			break
		}
	}

	if len(discoveredEnvironment) == 0 {
		discoveredEnvironment = newWorkflowEnvironment
	}

	for _, newAction := range newWorkflow.Actions {
		found := false

		if !newAction.ParentControlled {
			continue
		}

		for _, oldAction := range oldWorkflow.Actions {
			if !oldAction.ParentControlled {
				continue
			}

			if newAction.ID == oldAction.ID {
				found = true
				break
			}
		}

		if !found {
			addedActions = append(addedActions, newAction.ID)
		}
	}

	for _, oldAction := range oldWorkflow.Actions {
		found := false

		if !oldAction.ParentControlled {
			continue
		}

		for _, newAction := range newWorkflow.Actions {
			if !newAction.ParentControlled {
				continue
			}

			if oldAction.ID == newAction.ID {
				found = true
				break
			}
		}

		if !found {
			removedActions = append(removedActions, oldAction.ID)
		}
	}

	for _, newAction := range newWorkflow.Actions {
		if !newAction.ParentControlled {
			continue
		}

		if ArrayContains(addedActions, newAction.ID) || ArrayContains(removedActions, newAction.ID) {
			continue
		}

		for _, oldAction := range oldWorkflow.Actions {
			if !oldAction.ParentControlled {
				continue
			}

			if newAction.ID != oldAction.ID {
				continue
			}

			changeType, changed := hasActionChanged(newAction, oldAction)
			if changed {
				log.Printf("[DEBUG] Action %s (%s) has changed in '%s'", newAction.Label, newAction.ID, changeType)
				updatedActions = append(updatedActions, newAction)
			}
		}
	}

	// Triggers
	for _, newAction := range newWorkflow.Triggers {
		if !newAction.ParentControlled {
			continue
		}

		found := false
		for _, oldAction := range oldWorkflow.Triggers {
			if !oldAction.ParentControlled {
				continue
			}

			if newAction.ID == oldAction.ID {
				found = true
				break
			}
		}

		if !found {
			addedTriggers = append(addedTriggers, newAction.ID)
		}
	}

	for _, oldAction := range oldWorkflow.Triggers {
		if !oldAction.ParentControlled {
			continue
		}

		found := false
		for _, newAction := range newWorkflow.Triggers {
			if !newAction.ParentControlled {
				continue
			}

			if oldAction.ID == newAction.ID {
				found = true
				break
			}
		}

		if !found {
			removedTriggers = append(removedTriggers, oldAction.ID)
		}
	}

	for _, newAction := range newWorkflow.Triggers {
		if !newAction.ParentControlled {
			continue
		}

		if ArrayContains(addedTriggers, newAction.ID) || ArrayContains(removedTriggers, newAction.ID) {
			continue
		}

		for _, oldAction := range oldWorkflow.Triggers {
			if !oldAction.ParentControlled {
				continue
			}

			if newAction.ID != oldAction.ID {
				continue
			}

			changeType, changed := hasTriggerChanged(newAction, oldAction)
			if changed {
				log.Printf("[DEBUG] Trigger %s (%s) has changed in '%s'", newAction.Label, newAction.ID, changeType)
				updatedTriggers = append(updatedTriggers, newAction)
			}
		}
	}

	// Branches
	for _, newBranch := range newWorkflow.Branches {
		if !newBranch.ParentControlled {
			continue
		}

		found := false
		for _, oldBranch := range oldWorkflow.Branches {
			if !oldBranch.ParentControlled {
				continue
			}

			if newBranch.ID == oldBranch.ID {
				found = true
				break
			}
		}

		if !found {
			addedBranches = append(addedBranches, newBranch.ID)
		}
	}

	for _, oldBranch := range oldWorkflow.Branches {
		if !oldBranch.ParentControlled {
			continue
		}

		found := false
		for _, newBranch := range newWorkflow.Branches {
			if !newBranch.ParentControlled {
				continue
			}

			if oldBranch.ID == newBranch.ID {
				found = true
				break
			}
		}

		if !found {
			removedBranches = append(removedBranches, oldBranch.ID)
		}
	}

	for _, newBranch := range newWorkflow.Branches {
		if !newBranch.ParentControlled {
			continue
		}

		if ArrayContains(addedBranches, newBranch.ID) || ArrayContains(removedBranches, newBranch.ID) {
			continue
		}

		for _, oldBranch := range oldWorkflow.Branches {
			if !oldBranch.ParentControlled {
				continue
			}

			if newBranch.ID != oldBranch.ID {
				continue
			}

			changeType, changed := hasBranchChanged(newBranch, oldBranch)
			if changed {
				log.Printf("[DEBUG] Trigger %s (%s) has changed in '%s'", newBranch.Label, newBranch.ID, changeType)
				updatedBranches = append(updatedBranches, newBranch)
			}
		}
	}

	// Create / Delete / Modify
	//log.Printf("\n ===== Parent: %#v, Child: %#v =====", newWorkflow.ID, oldWorkflow.ID)
	//log.Printf("\n Changes: c | d | m\n Action:  %d | %d | %d\n Trigger: %d | %d | %d\n Branch:  %d | %d | %d", len(addedActions), len(removedActions), len(updatedActions), len(addedTriggers), len(removedTriggers), len(updatedTriggers), len(addedBranches), len(removedBranches), len(updatedBranches))

	if update {
		// FIXME: This doesn't work does it?
		childWorkflow := oldWorkflow

		//log.Printf("\n\nSTART")
		//log.Printf("[DEBUG] CHILD ACTIONS START: %d", len(childWorkflow.Actions))
		//log.Printf("[DEBUG] CHILD TRIGGERS START: %d", len(childWorkflow.Triggers))
		//log.Printf("[DEBUG] CHILD BRANCHES START: %d\n\n", len(childWorkflow.Branches))

		if nameChanged {
			childWorkflow.Name = newWorkflow.Name
		}

		if descriptionChanged {
			childWorkflow.Description = newWorkflow.Description
		}

		if tagsChanged {
			childWorkflow.Tags = newWorkflow.Tags
		}

		if backupsChanged {
			childWorkflow.BackupConfig = newWorkflow.BackupConfig
		}

		if inputfieldsChanged {
			childWorkflow.InputQuestions = newWorkflow.InputQuestions
		}

		childActions := []Action{}
		for _, action := range oldWorkflow.Actions {
			// Check if it SHOULD be parent controlled
			for _, newAction := range newWorkflow.Actions {
				if newAction.ID == action.ID {
					action.ParentControlled = true
					break
				}
			}

			if action.ParentControlled {
				continue
			}

			childActions = append(childActions, action)
		}

		childTriggers := []Trigger{}
		for _, trigger := range oldWorkflow.Triggers {
			for _, newTrigger := range newWorkflow.Triggers {
				if newTrigger.ID == trigger.ID {
					trigger.ParentControlled = true
					break
				}
			}

			if trigger.ParentControlled {
				continue
			}

			childTriggers = append(childTriggers, trigger)
		}

		childBranches := []Branch{}
		for _, branch := range oldWorkflow.Branches {
			for _, newBranch := range newWorkflow.Branches {
				if newBranch.ID == branch.ID {
					branch.ParentControlled = true
					break
				}
			}

			if branch.ParentControlled {
				continue
			}

			childBranches = append(childBranches, branch)
		}

		if len(addedActions) > 0 {
			actions := childActions
			for _, action := range newWorkflow.Actions {
				if !ArrayContains(addedActions, action.ID) {
					continue
				}

				actions = append(actions, action)
			}

			childWorkflow.Actions = append(childWorkflow.Actions, actions...)
			childActions = childWorkflow.Actions
		}

		if len(removedActions) > 0 {
			newChildActions := childActions
			for _, action := range childWorkflow.Actions {
				if ArrayContains(removedActions, action.ID) {
					continue
				}

				newChildActions = append(newChildActions, action)
			}

			childWorkflow.Actions = newChildActions
			childActions = childWorkflow.Actions
		}

		if len(updatedActions) > 0 {
			for _, action := range updatedActions {
				for index, childAction := range childWorkflow.Actions {
					if childAction.ID != action.ID {
						continue
					}

					// FIXME:
					// Make sure it changes things such as environment & app auth appropriately

					childWorkflow.Actions[index] = action
					break
				}
			}
		}

		if len(addedTriggers) > 0 {
			triggers := childTriggers
			for _, trigger := range newWorkflow.Triggers {
				if !ArrayContains(addedTriggers, trigger.ID) {
					continue
				}

				triggers = append(triggers, trigger)
			}

			childWorkflow.Triggers = append(childWorkflow.Triggers, triggers...)
			childTriggers = childWorkflow.Triggers
		}

		if len(removedTriggers) > 0 {
			newChildTriggers := childTriggers
			for _, trigger := range childWorkflow.Triggers {
				if ArrayContains(removedTriggers, trigger.ID) {
					continue
				}

				newChildTriggers = append(newChildTriggers, trigger)
			}

			childWorkflow.Triggers = newChildTriggers
			childTriggers = childWorkflow.Triggers
		}

		if len(updatedTriggers) > 0 {
			for _, action := range updatedTriggers {
				for index, childAction := range childWorkflow.Triggers {
					if childAction.ID != action.ID {
						continue
					}

					// FIXME:
					// Make sure it changes things such as URL & references properly

					childWorkflow.Triggers[index] = action
					break
				}
			}
		}

		if len(addedBranches) > 0 {
			branches := childBranches
			for _, branch := range newWorkflow.Branches {
				if !ArrayContains(addedBranches, branch.ID) {
					continue
				}

				branches = append(branches, branch)
			}

			childWorkflow.Branches = append(childWorkflow.Branches, branches...)
			childBranches = childWorkflow.Branches
		}

		if len(removedBranches) > 0 {
			newChildBranches := childBranches
			for _, branch := range childWorkflow.Branches {
				if ArrayContains(removedBranches, branch.ID) {
					continue
				}

				newChildBranches = append(newChildBranches, branch)
			}

			childWorkflow.Branches = newChildBranches
			childBranches = childWorkflow.Branches
		}

		if len(updatedBranches) > 0 {
			for _, action := range updatedBranches {
				for index, childAction := range childWorkflow.Branches {
					if childAction.ID != action.ID {
						continue
					}

					childWorkflow.Branches[index] = action
					break
				}
			}
		}

		// Dedup actions, triggers & branches
		newActions := []Action{}
		newTriggers := []Trigger{}
		newBranches := []Branch{}
		for childActionIndex, childAction := range childWorkflow.Actions {
			childWorkflow.Actions[childActionIndex].Environment = discoveredEnvironment
			// Check if the parent workflow has it, and make sure parent controlled is set
			for _, newAction := range newWorkflow.Actions {
				if newAction.ID == childAction.ID {
					newAction.ParentControlled = true
					childWorkflow.Actions[childActionIndex].ParentControlled = true
					break
				}
			}

			idFound := false
			for _, oldWorkflowAction := range oldWorkflow.Actions {
				if oldWorkflowAction.ID == childAction.ID {
					idFound = true
					childWorkflow.Actions[childActionIndex].AuthenticationId = oldWorkflowAction.AuthenticationId
				}
			}

			if !idFound {
				for _, oldWorkflowAction := range oldWorkflow.Actions {
					if oldWorkflowAction.AppID == childAction.AppID {
						childWorkflow.Actions[childActionIndex].AuthenticationId = oldWorkflowAction.AuthenticationId
						break
					}
				}
			}

			found := false
			for _, newAction := range newActions {
				if newAction.ID == childAction.ID {
					found = true
					continue
				}
			}

			if !found {
				newActions = append(newActions, childAction)
			}
		}

		for childTriggerIndex, childTrigger := range childWorkflow.Triggers {
			childWorkflow.Triggers[childTriggerIndex].Environment = discoveredEnvironment

			for _, newTrigger := range newWorkflow.Triggers {
				if newTrigger.ID == childTrigger.ID {
					childTrigger.ParentControlled = true
					childWorkflow.Triggers[childTriggerIndex].ParentControlled = true
					break
				}
			}

			// FIXME: Add specific handlers for each type based on oldWorkflow params that may have been locally configured
			// FIXME: THIS DOES NOT WORK YET FOR TRIGGER FIELD MAPPING TO OLD SETTING
			if childTrigger.ParentControlled {
				/*
					for _, oldTrigger := range oldWorkflow.Triggers {
						if oldTrigger.ID != childTrigger.ID {
							continue
						}

						childTrigger.Status = oldTrigger.Status

						reservedArguments := []string{}
						if oldTrigger.TriggerType == "SUBFLOW" {
							reservedArguments = []string{"workflow", "user_apikey", "startnode"}
						} else if oldTrigger.TriggerType == "USERINPUT" {
							reservedArguments = []string{"subflow", "sms", "email", "type"}
						} else if oldTrigger.TriggerType == "SCHEDULE" {
						} else if oldTrigger.TriggerType == "WEBHOOK" {
							reservedArguments = []string{"url", "tmp", "auth_headers"}
						} else if oldTrigger.TriggerType == "PIPELINE" {
							reservedArguments = []string{"pipeline"}
						}

						fieldsFound := []string{}
						for paramIndex, param := range childTrigger.Parameters {
							if !ArrayContains(reservedArguments, param.Name) {
								continue
							}

							fieldsFound = append(fieldsFound, param.Name)
							for _, oldParam := range oldTrigger.Parameters {
								if oldParam.Name != param.Name {
									continue
								}

								childWorkflow.Triggers[childTriggerIndex].Parameters[paramIndex].Value = oldParam.Value
								childTrigger.Parameters[paramIndex].Value = oldParam.Value
								break
							}
						}

						if len(fieldsFound) != len(reservedArguments) {
							for _, field := range reservedArguments {
								if ArrayContains(fieldsFound, field) {
									continue
								}

								oldParamFound := false
								for _, oldParam := range oldTrigger.Parameters {
									if oldParam.Name != field {
										continue
									}

									oldParamFound = true
									childTrigger.Parameters = append(childTrigger.Parameters, oldParam)
									childWorkflow.Triggers[childTriggerIndex].Parameters = append(childWorkflow.Triggers[childTriggerIndex].Parameters, oldParam)
								}

								if !oldParamFound {
									//log.Printf("[DEBUG] MISSING IN OLDPARAM TOO: %s", field)
								}
							}
						}
					}
				*/
			}

			found := false
			for _, newTrigger := range newTriggers {
				if newTrigger.ID == childTrigger.ID {
					found = true
					continue
				}
			}

			if !found {
				newTriggers = append(newTriggers, childTrigger)
			}
		}

		for childBranchIndex, childBranch := range childWorkflow.Branches {
			for _, newBranch := range newWorkflow.Branches {
				if newBranch.ID == childBranch.ID || (newBranch.SourceID == childBranch.SourceID && newBranch.DestinationID == childBranch.DestinationID) {
					childBranch.ParentControlled = true
					childWorkflow.Branches[childBranchIndex].ParentControlled = true
					break
				}
			}

			found := false
			for _, newBranch := range newBranches {
				if newBranch.ID == childBranch.ID {
					found = true
					continue
				}
			}

			if !found {
				newBranches = append(newBranches, childBranch)
			}
		}

		childWorkflow.Actions = newActions
		childWorkflow.Triggers = newTriggers
		childWorkflow.Branches = newBranches

		//log.Printf("\n\nEND")
		//log.Printf("[DEBUG] CHILD ACTIONS END: %d", len(childWorkflow.Actions))
		//log.Printf("[DEBUG] CHILD TRIGGERS END: %d", len(childWorkflow.Triggers))
		//log.Printf("[DEBUG] CHILD BRANCHES END: %d\n\n", len(childWorkflow.Branches))

		ctx := context.Background()
		err := SetWorkflow(ctx, childWorkflow, childWorkflow.ID)
		if err != nil {
			log.Printf("[WARNING] Failed updating child workflow %s: %s", childWorkflow.ID, err)
		} else {
			log.Printf("[INFO] Updated child workflow '%s' based on parent %s", childWorkflow.ID, oldWorkflow.ID)

			SetWorkflowRevision(ctx, childWorkflow)
			passedOrg := Org{
				Id:   childWorkflow.ExecutingOrg.Id,
				Name: childWorkflow.ExecutingOrg.Name,
			}
			SetGitWorkflow(ctx, childWorkflow, &passedOrg)
		}

		DeleteCache(ctx, fmt.Sprintf("workflow_%s_childworkflows", oldWorkflow.ID))
		DeleteCache(ctx, fmt.Sprintf("workflow_%s_childworkflows", childWorkflow.ID))
		DeleteCache(ctx, fmt.Sprintf("workflow_%s_childworkflows", newWorkflow.ID))
	}
}

// Saves a workflow to an ID
func SaveWorkflow(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

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
	ctx := GetContext(request)
	tmpworkflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Failed getting the workflow %s locally (save workflow): %s", fileId, err)
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
		//log.Printf(string(body))
		log.Printf("[ERROR] Failed workflow unmarshaling (save): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
		return
	}

	if project.Environment == "cloud" && tmpworkflow.Validated == false {
		if workflow.Validated == true {

			if !user.SupportAccess {
				workflow.Validated = false
			} else {
				//log.Printf("[INFO] User %s is validating workflow %s", user.Username, tmpworkflow.ID)
			}
		}
	}

	type PublicCheck struct {
		UserEditing bool   `json:"user_editing"`
		Public      bool   `json:"public"`
		Owner       string `json:"owner"`
	}

	/*
		if len(workflow.ParentWorkflowId) > 0 || len(tmpworkflow.ParentWorkflowId) > 0 {
			resp.WriteHeader(403)
			resp.Write([]byte(`{"success": false, "reason": "Can't save a workflow distributed from your parent org"}`))
			return
		}
	*/

	correctUser := false
	if user.Id != tmpworkflow.Owner || tmpworkflow.Public == true {
		log.Printf("[AUDIT] User %s is accessing workflow %s (save workflow)", user.Username, tmpworkflow.ID)

		// if,ifelse: Public, Org owns it, or user owns it
		if tmpworkflow.Public {
			// FIXME:
			// If the user Id is part of the creator: DONT update this way.
			// /users/creators/username
			// Just making sure
			if project.Environment == "cloud" {
				//algoliaUser, err := HandleAlgoliaCreatorSearch(ctx, username)
				algoliaUser, err := HandleAlgoliaCreatorSearch(ctx, tmpworkflow.ID)
				if err != nil {
					allowList := os.Getenv("GITHUB_USER_ALLOWLIST")
					log.Printf("[WARNING] User with ID %s for Workflow %s could not be found (workflow update): %s. Username: %s. ACL controlled with GITHUB_USER_ALLOWLIST environment variable. Allowed users: %#v", user.Id, tmpworkflow.ID, err, user.PublicProfile.GithubUsername, allowList)

					// Check if current user is one of the few allowed
					// This can only happen if the workflow doesn't already have an owner
					found := false
					if user.PublicProfile.Public && len(allowList) > 0 {
						allowListSplit := strings.Split(allowList, ",")
						for _, username := range allowListSplit {
							if username != user.PublicProfile.GithubUsername {
								continue
							}

							algoliaUser, err = HandleAlgoliaCreatorSearch(ctx, user.PublicProfile.GithubUsername)
							if err != nil {
								log.Printf("[ERROR] Algolia Creator search error in public workflow edit: %s", err)
								continue
							}

							found = true
							break
						}
					}

					if !found {
						resp.WriteHeader(403)
						resp.Write([]byte(`{"success": false}`))
						return
					}
				}

				wf2 := PublicCheck{}
				err = json.Unmarshal([]byte(body), &wf2)
				if err != nil {
					log.Printf("[ERROR] Failed workflow unmarshaling (save - 2): %s", err)
				}

				if algoliaUser.ObjectID == user.Id || ArrayContains(algoliaUser.Synonyms, user.Id) {
					log.Printf("[WARNING] User %s (%s) has access to edit %s! Keep it public!!", user.Username, user.Id, workflow.ID)

					// Means the owner is using the workflow for their org
					if wf2.UserEditing == false {
						correctUser = false
					} else {
						correctUser = true
						tmpworkflow.Public = true
						workflow.Public = true
					}
				}
			}

			// FIX: Should check if this workflow has already been saved?
			if !correctUser {
				log.Printf("[INFO] User %s is saving the public workflow %s", user.Username, tmpworkflow.ID)
				workflow = *tmpworkflow
				workflow.PublishedId = workflow.ID
				workflow.ID = uuid.NewV4().String()
				workflow.Public = false
				workflow.Owner = user.Id
				workflow.Org = []OrgMini{
					user.ActiveOrg,
				}
				workflow.ExecutingOrg = user.ActiveOrg
				workflow.OrgId = user.ActiveOrg.Id
				workflow.PreviouslySaved = false

				newTriggers := []Trigger{}
				changedIds := map[string]string{}
				for _, trigger := range workflow.Triggers {
					newId := uuid.NewV4().String()
					trigger.Environment = "cloud"

					hookAuth := ""
					customResponse := ""
					for paramIndex, param := range trigger.Parameters {
						if param.Name == "url" {
							trigger.Parameters[paramIndex].Value = fmt.Sprintf("https://shuffler.io/api/v1/hooks/webhook_%s", newId)
						}

						if param.Name == "auth_headers" {
							hookAuth = param.Value
						}

						if param.Name == "custom_response_body" {
							customResponse = param.Value
						}
					}

					if trigger.TriggerType != "SCHEDULE" {

						trigger.Status = "running"

						if trigger.TriggerType == "WEBHOOK" {
							hook := Hook{
								Id:        newId,
								Start:     workflow.Start,
								Workflows: []string{workflow.ID},
								Info: Info{
									Name:        trigger.Name,
									Description: trigger.Description,
									Url:         fmt.Sprintf("https://shuffler.io/api/v1/hooks/webhook_%s", newId),
								},
								Type:   "webhook",
								Owner:  user.Username,
								Status: "running",
								Actions: []HookAction{
									HookAction{
										Type:  "workflow",
										Name:  trigger.Name,
										Id:    workflow.ID,
										Field: "",
									},
								},
								Running:        true,
								OrgId:          workflow.OrgId,
								Environment:    "cloud",
								Auth:           hookAuth,
								CustomResponse: customResponse,
							}

							log.Printf("[DEBUG] Starting hook %s for user %s (%s) during Workflow Save for %s", hook.Id, user.Username, user.Id, workflow.ID)
							err = SetHook(ctx, hook)
							if err != nil {
								log.Printf("[WARNING] Failed setting hook during workflow copy of %s: %s", workflow.ID, err)
								resp.WriteHeader(401)
								resp.Write([]byte(`{"success": false}`))
								return
							}
						}
					}

					changedIds[trigger.ID] = newId

					trigger.ID = newId
					//log.Printf("New id for %s: %s", trigger.TriggerType, trigger.ID)
					newTriggers = append(newTriggers, trigger)
				}

				newBranches := []Branch{}
				for _, branch := range workflow.Branches {
					for key, value := range changedIds {
						if branch.SourceID == key {
							branch.SourceID = value
						}

						if branch.DestinationID == key {
							branch.DestinationID = value
						}
					}

					newBranches = append(newBranches, branch)
				}

				workflow.Branches = newBranches
				workflow.Triggers = newTriggers

				err = SetWorkflow(ctx, workflow, workflow.ID)
				if err != nil {
					log.Printf("[WARNING] Failed saving NEW version of public %s for user %s: %s", tmpworkflow.ID, user.Username, err)
					resp.WriteHeader(401)
					resp.Write([]byte(`{"success": false}`))
					return
				}
				org, err := GetOrg(ctx, user.ActiveOrg.Id)
				if err != nil {
					log.Printf("[WARNING] Failed getting org for cache release for public wf: %s", err)
				} else {
					for _, loopUser := range org.Users {
						//DeleteCache(ctx, fmt.Sprintf("%s_workflows", org.Id)
						//DeleteCache(ctx, fmt.Sprintf("%s_workflows", loopUser.Id))
						//DeleteCache(ctx, fmt.Sprintf("apps_%s", loopUser.Id))
						//DeleteCache(ctx, fmt.Sprintf("apps_%s", org.Id)
						DeleteCache(ctx, fmt.Sprintf("user_%s", loopUser.Id))
					}

					// Activate all that aren't already there
					changed := false
					for _, action := range workflow.Actions {
						//log.Printf("App: %s, Public: %s", action.AppID, action.Public)
						if !ArrayContains(org.ActiveApps, action.AppID) {
							org.ActiveApps = append(org.ActiveApps, action.AppID)
							changed = true
						}
					}

					if changed {
						err = SetOrg(ctx, *org, org.Id)
						if err != nil {
							log.Printf("[ERROR] Failed updating active app list for org %s (%s): %s", org.Name, org.Id, err)
						} else {
							//DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
							//DeleteCache(ctx, fmt.Sprintf("apps_%s", org.Id))
							DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-100"))
							DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-500"))
							DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-1000"))
							DeleteCache(ctx, "all_apps")
							DeleteCache(ctx, fmt.Sprintf("user_%s", user.Username))
							DeleteCache(ctx, fmt.Sprintf("user_%s", user.Id))
						}
					}
				}

				resp.WriteHeader(200)
				resp.Write([]byte(fmt.Sprintf(`{"success": true, "new_id": "%s"}`, workflow.ID)))
				return
			}
		} else if tmpworkflow.OrgId == user.ActiveOrg.Id && user.Role != "org-reader" {
			log.Printf("[AUDIT] User %s is accessing workflow %s (save workflow)", user.Username, tmpworkflow.ID)
			workflow.ID = tmpworkflow.ID
		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (save)", user.Username, tmpworkflow.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Wrong user for workflow. Do you have write access?"}`))
			return
		}
	} else {
		log.Printf("[AUDIT] User %s is creating or modifying workflow with ID %s as they are the owner / it's public", user.Username, workflow.ID)

		if workflow.Public {
			log.Printf("[WARNING] Rolling back public as the user set it to true themselves")
			workflow.Public = false
		}

		if len(workflow.PublishedId) > 0 {
			log.Printf("[INFO] Workflow %s has the published ID %s", workflow.ID, workflow.PublishedId)

			// Overwrite ID here?
		}
	}

	if fileId != workflow.ID {
		log.Printf("[WARNING] Path and request ID are not matching in workflow save: %s != %s.", fileId, workflow.ID)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "ID in workflow data and path are not matching"}`))
		return
	}

	if len(workflow.Name) == 0 {
		log.Printf("[WARNING] Can't save workflow without a name.")
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Workflow needs a name"}`))
		return
	}

	if len(workflow.Actions) == 0 {
		log.Printf("[WARNING] Can't save a workflow without a single action.")
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Workflow needs at least one action"}`))
		return
	}

	newsuborgs := []string{}
	for _, suborg := range workflow.SuborgDistribution {
		if len(suborg) != 36 {
			continue
		}

		newsuborgs = append(newsuborgs, suborg)
	}

	workflow.SuborgDistribution = newsuborgs

	if len(workflow.SuborgDistribution) != len(tmpworkflow.SuborgDistribution) {
		log.Printf("[AUDIT] Suborg distribution changed by user %s (%s) for workflow %s (%s) in org %s (%s). Clearing cache for suborgs.", user.Username, user.Id, workflow.Name, workflow.ID, user.ActiveOrg.Name, user.ActiveOrg.Id)

		// Clear workflow cache
		for _, suborg := range workflow.SuborgDistribution {
			cacheKey := fmt.Sprintf("%s_workflows", suborg)
			DeleteCache(ctx, cacheKey)
		}

		for _, suborg := range tmpworkflow.SuborgDistribution {
			cacheKey := fmt.Sprintf("%s_workflows", suborg)
			DeleteCache(ctx, cacheKey)
		}
	}

	// Resetting subflows as they shouldn't be entirely saved. Used just for imports/exports
	if len(workflow.Subflows) > 0 {
		log.Printf("[DEBUG] Got %d subflows saved in %s (to be saved and removed)", len(workflow.Subflows), workflow.ID)

		for _, subflow := range workflow.Subflows {
			SetWorkflow(ctx, subflow, subflow.ID)
		}

		workflow.Subflows = []Workflow{}
	}

	if strings.ToLower(workflow.Status) == "test" {
		workflow.Status = "test"
	} else if strings.ToLower(workflow.Status) == "prod" {
		workflow.Status = "production"
	} else {
		if len(workflow.Status) == 0 {
			workflow.Status = "test"
		}

		// Custom statuses allowed with API
		if len(workflow.Status) > 255 {
			workflow.Status = workflow.Status[:255]
		}
	}

	workflow.Subflows = []Workflow{}
	if len(workflow.DefaultReturnValue) > 0 && len(workflow.DefaultReturnValue) < 200 {
		log.Printf("[INFO] Set default return value to on failure to (%s): %s", workflow.ID, workflow.DefaultReturnValue)
		//workflow.DefaultReturnValue
	}

	log.Printf("[INFO] Saving workflow '%s' with %d action(s) and %d trigger(s). Org: %s", workflow.Name, len(workflow.Actions), len(workflow.Triggers), workflow.OrgId)

	if len(workflow.OrgId) == 0 && len(user.ActiveOrg.Id) > 0 {
		if len(workflow.ExecutingOrg.Id) == 0 {
			log.Printf("[INFO] Setting executing org for workflow to %s", user.ActiveOrg.Id)
			user.ActiveOrg.Users = []UserMini{}
			workflow.ExecutingOrg = user.ActiveOrg
		}

		if len(workflow.OrgId) == 0 {
			workflow.OrgId = user.ActiveOrg.Id
		}
	} else if len(workflow.OrgId) != 0 && len(workflow.ExecutingOrg.Id) == 0 {
		log.Printf("[INFO] Setting executing org for workflow to %s", workflow.OrgId)
		workflow.ExecutingOrg.Id = workflow.OrgId
		workflow.ExecutingOrg.Name = ""
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

	environments, err = GetEnvironments(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Failed getting environments for org %s", user.ActiveOrg.Id)
		environments = []Environment{}
	}

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

	orgUpdated := false
	startnodeFound := false
	newOrgApps := []string{}
	org := &Org{}

	workflowapps, apperr := GetPrioritizedApps(ctx, user)
	allNames := []string{}
	for _, action := range workflow.Actions {
		if action.AppID == "integration" {
			if action.IsStartNode {
				startnodeFound = true
			}

			newActions = append(newActions, action)
			continue
		}

		if action.SourceWorkflow != workflow.ID && len(action.SourceWorkflow) > 0 {
			continue
		}

		newLabelName := strings.Replace(strings.ToLower(action.Label), " ", "_", -1)
		if len(action.Label) > 0 && ArrayContains(allNames, newLabelName) {
			parsedError := fmt.Sprintf("Multiple actions with name '%s'. May cause problems unless changed.", action.Label)
			if !ArrayContains(workflow.Errors, parsedError) {
				workflow.Errors = append(workflow.Errors, parsedError)
			}
		}

		allNames = append(allNames, newLabelName)
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

		if action.ExecutionDelay > 86400 {
			parsedError := fmt.Sprintf("Max execution delay for an action is 86400 (1 day)")
			if !ArrayContains(workflow.Errors, parsedError) {
				workflow.Errors = append(workflow.Errors, parsedError)
			}

			action.ExecutionDelay = 86400
		}

		if action.Environment == "" {
			if project.Environment == "cloud" {
				action.Environment = defaultEnv
			} else {
				if len(environments) > 0 {
					for _, env := range environments {
						if !env.Archived && env.Default {
							//log.Printf("FOUND ENV %s", env)
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
			found := false
			for _, env := range environments {
				if env.Name == action.Environment {
					found = true
					if env.Archived {
						log.Printf("[DEBUG] Environment %s is archived. Changing to default.")
						action.Environment = defaultEnv
					}

					break
				}
			}

			if !found {
				if ArrayContains(warned, action.Environment) {
					log.Printf("[DEBUG] Environment %s isn't available. Changing to default.", action.Environment)
					warned = append(warned, action.Environment)
				}

				action.Environment = defaultEnv
			}
		}

		// Fixing apps with bad IDs. This can happen a lot because of
		// autogeneration of app IDs, and export/imports of workflows
		idFound := false
		nameVersionFound := false
		nameFound := false

		discoveredApp := WorkflowApp{}
		for _, innerApp := range workflowapps {
			if innerApp.ID == action.AppID {
				discoveredApp = innerApp
				//log.Printf("[INFO] ID, Name AND version for %s:%s (%s) was FOUND", action.AppName, action.AppVersion, action.AppID)
				action.Sharing = innerApp.Sharing
				action.Public = innerApp.Public
				action.Generated = innerApp.Generated
				action.ReferenceUrl = innerApp.ReferenceUrl

				idFound = true
				break
			}
		}

		if !idFound {
			for _, innerApp := range workflowapps {
				if innerApp.Name == action.AppName && innerApp.AppVersion == action.AppVersion {
					discoveredApp = innerApp

					action.AppID = innerApp.ID
					action.Sharing = innerApp.Sharing
					action.Public = innerApp.Public
					action.Generated = innerApp.Generated
					action.ReferenceUrl = innerApp.ReferenceUrl
					nameVersionFound = true
					break
				}
			}
		}

		if !idFound {
			for _, innerApp := range workflowapps {
				if innerApp.Name == action.AppName {
					discoveredApp = innerApp

					action.AppID = innerApp.ID
					action.Sharing = innerApp.Sharing
					action.Public = innerApp.Public
					action.Generated = innerApp.Generated
					action.ReferenceUrl = innerApp.ReferenceUrl

					nameFound = true
					break
				}
			}
		}

		// Handles backend labeling
		if len(action.CategoryLabel) == 0 && len(discoveredApp.ID) > 0 {
			for _, discoveredAction := range discoveredApp.Actions {
				if action.Name != discoveredAction.Name {
					continue
				}

				if len(discoveredAction.CategoryLabel) == 0 {
					break
				}

				action.CategoryLabel = discoveredAction.CategoryLabel
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
					appid, err := HandleAlgoliaAppSearch(ctx, action.AppName)
					if err == nil && len(appid.ObjectID) > 0 {
						//log.Printf("[INFO] Found NEW appid %s for app %s", appid, action.AppName)
						tmpApp, err := GetApp(ctx, appid.ObjectID, user, false)
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
		}

		workflow.Categories = HandleCategoryIncrease(workflow.Categories, action, workflowapps)
		newActions = append(newActions, action)

		// FIXMe: Should be authenticated first?
		if len(discoveredApp.Categories) > 0 {
			category := discoveredApp.Categories[0]

			if org.Id == "" {
				org, err = GetOrg(ctx, user.ActiveOrg.Id)
				if err != nil {
					log.Printf("[WARNING] Failed getting org: %s", err)
					continue
				}
			}

			if strings.ToLower(category) == "siem" && org.SecurityFramework.SIEM.ID == "" {
				org.SecurityFramework.SIEM.Name = discoveredApp.Name
				org.SecurityFramework.SIEM.Description = discoveredApp.Description
				org.SecurityFramework.SIEM.ID = discoveredApp.ID
				org.SecurityFramework.SIEM.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "network" && org.SecurityFramework.Network.ID == "" {
				org.SecurityFramework.Network.Name = discoveredApp.Name
				org.SecurityFramework.Network.Description = discoveredApp.Description
				org.SecurityFramework.Network.ID = discoveredApp.ID
				org.SecurityFramework.Network.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "edr" || strings.ToLower(category) == "edr & av" && org.SecurityFramework.EDR.ID == "" {
				org.SecurityFramework.EDR.Name = discoveredApp.Name
				org.SecurityFramework.EDR.Description = discoveredApp.Description
				org.SecurityFramework.EDR.ID = discoveredApp.ID
				org.SecurityFramework.EDR.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "cases" && org.SecurityFramework.Cases.ID == "" {
				org.SecurityFramework.Cases.Name = discoveredApp.Name
				org.SecurityFramework.Cases.Description = discoveredApp.Description
				org.SecurityFramework.Cases.ID = discoveredApp.ID
				org.SecurityFramework.Cases.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "iam" && org.SecurityFramework.IAM.ID == "" {
				org.SecurityFramework.IAM.Name = discoveredApp.Name
				org.SecurityFramework.IAM.Description = discoveredApp.Description
				org.SecurityFramework.IAM.ID = discoveredApp.ID
				org.SecurityFramework.IAM.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "assets" && org.SecurityFramework.Assets.ID == "" {
				log.Printf("Setting assets?")
				org.SecurityFramework.Assets.Name = discoveredApp.Name
				org.SecurityFramework.Assets.Description = discoveredApp.Description
				org.SecurityFramework.Assets.ID = discoveredApp.ID
				org.SecurityFramework.Assets.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "intel" && org.SecurityFramework.Intel.ID == "" {
				org.SecurityFramework.Intel.Name = discoveredApp.Name
				org.SecurityFramework.Intel.Description = discoveredApp.Description
				org.SecurityFramework.Intel.ID = discoveredApp.ID
				org.SecurityFramework.Intel.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "comms" && org.SecurityFramework.Communication.ID == "" {
				org.SecurityFramework.Communication.Name = discoveredApp.Name
				org.SecurityFramework.Communication.Description = discoveredApp.Description
				org.SecurityFramework.Communication.ID = discoveredApp.ID
				org.SecurityFramework.Communication.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else {
				//log.Printf("[WARNING] No handler for type %s in app framework", category)
			}

		}
	}

	// Handle app versions & upgrades
	for _, action := range workflow.Actions {
		if action.AppID == "integration" {
			if action.IsStartNode {
				startnodeFound = true
			}

			continue
		}

		actionApp := strings.ToLower(strings.Replace(action.AppName, " ", "", -1))

		for _, app := range workflowapps {
			if strings.ToLower(strings.Replace(app.Name, " ", "", -1)) != actionApp {
				continue
			}

			if len(app.Versions) <= 1 {
				continue
			}

			v2, err := semver.NewVersion(action.AppVersion)
			if err != nil {
				log.Printf("[ERROR] Failed parsing original app version %s: %s", app.AppVersion, err)
				continue
			}

			newVersion := ""
			for _, loopedApp := range app.Versions {
				if action.AppVersion == loopedApp.Version {
					continue
				}

				appConstraint := fmt.Sprintf("< %s", loopedApp.Version)
				c, err := semver.NewConstraint(appConstraint)
				if err != nil {
					log.Printf("[ERROR] Failed preparing constraint %s: %s", appConstraint, err)
					continue
				}

				if c.Check(v2) {
					newVersion = loopedApp.Version
					action.AppVersion = loopedApp.Version
				}
			}

			if len(newVersion) > 0 {
				newError := fmt.Sprintf("App %s has version %s available.", app.Name, newVersion)
				if !ArrayContains(workflow.Errors, newError) {
					workflow.Errors = append(workflow.Errors, newError)
				}
			}
		}
	}

	if !startnodeFound {
		log.Printf("[WARNING] No startnode found during save of %s!!", workflow.ID)

		// Select the first action as startnode
		if len(newActions) > 0 {
			workflow.Start = newActions[0].ID
			newActions[0].IsStartNode = true
			startnodeFound = true
		}
	}

	// Automatically adding new apps
	if len(newOrgApps) > 0 {
		log.Printf("[WARNING] Adding new apps to org: %s", newOrgApps)

		if org.Id == "" {
			org, err = GetOrg(ctx, user.ActiveOrg.Id)
			if err != nil {
				log.Printf("[WARNING] Failed getting org during new app update for %s: %s", user.ActiveOrg.Id, err)
			}
		}

		if org.Id != "" {
			added := false
			for _, newApp := range newOrgApps {
				if !ArrayContains(org.ActiveApps, newApp) {
					org.ActiveApps = append(org.ActiveApps, newApp)
					added = true
				}
			}

			if added {
				orgUpdated = true
				//err = SetOrg(ctx, *org, org.Id)
				//if err != nil {
				//	log.Printf("[WARNING] Failed setting org when autoadding apps on save: %s", err)
				//} else {
				//DeleteCache(ctx, fmt.Sprintf("apps_%s", user.ActiveOrg.Id))
				//DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
				DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-100"))
				DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-500"))
				DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-1000"))
				DeleteCache(ctx, "all_apps")
				DeleteCache(ctx, fmt.Sprintf("user_%s", user.Username))
				DeleteCache(ctx, fmt.Sprintf("user_%s", user.Id))
			}
			//}
		}
	}

	workflow.Actions = newActions

	newTriggers := []Trigger{}
	for _, trigger := range workflow.Triggers {
		if trigger.SourceWorkflow != workflow.ID && len(trigger.SourceWorkflow) > 0 {
			continue
		}

		// Check if it's actually running
		if trigger.TriggerType == "SCHEDULE" && trigger.Status != "uninitialized" {
			schedule, err := GetSchedule(ctx, trigger.ID)
			if err != nil {
				trigger.Status = "stopped"
			} else if schedule.Id == "" {
				trigger.Status = "stopped"
			}
		} else if trigger.TriggerType == "SUBFLOW" {
			for _, param := range trigger.Parameters {
				if param.Name == "workflow" {
					// Validate workflow exists
					_, err := GetWorkflow(ctx, param.Value)
					if err != nil {
						parsedError := fmt.Sprintf("Selected Subflow in Action %s doesn't exist", trigger.Label)
						if !ArrayContains(workflow.Errors, parsedError) {
							workflow.Errors = append(workflow.Errors, parsedError)
						}

						log.Printf("[ERROR] Couldn't find subflow '%s' for workflow %s (%s). NOT setting to self as failover for now, and trusting authentication system instead.", param.Value, workflow.Name, workflow.ID)
						//trigger.Parameters[paramIndex].Value = workflow.ID
					}
				}

				//if len(param.Value) == 0 && param.Name != "argument" {
				// FIXME: No longer necessary to use the org's users' actual APIkey
				// Instead, this is replaced during runtime to use the executions' key
				/*
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
									resp.WriteHeader(400)
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
				*/
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
					if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
						baseUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
					}

					if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
						baseUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
					}

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

			_ = subflow

			if len(triggerType) == 0 {
				log.Printf("[DEBUG] No type specified for user input node")
				if workflow.PreviouslySaved {
					//resp.WriteHeader(401)
					//resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "No contact option specified in user input"}`)))
					//return
				}
			}

			// FIXME: This is not the right time to send them, BUT it's well served for testing. Save -> send email / sms
			_ = triggerInformation
			if strings.Contains(triggerType, "email") {
				if email == "test@test.com" {
					log.Printf("Email isn't specified during save.")
					if workflow.PreviouslySaved {
						workflow.Errors = append(workflow.Errors, "Email field in user input can't be empty")
						continue
					}
				}

				//log.Printf("[DEBUG] Should send email to %s during execution.", email)
			}

			if strings.Contains(triggerType, "sms") {
				if sms == "0000000" {
					log.Printf("Email isn't specified during save.")
					if workflow.PreviouslySaved {
						workflow.Errors = append(workflow.Errors, "SMS field in user input can't be empty")
						continue
					}
				}

				log.Printf("[DEBUG] Should send SMS to %s during execution.", sms)
			}
		}

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

		comment.Position.X = float64(comment.Position.X)
		comment.Position.Y = float64(comment.Position.Y)

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
		}
	}

	if len(workflow.ExecutionVariables) > 0 {
		log.Printf("[INFO] Found %d runtime variable(s) for workflow %s", len(workflow.ExecutionVariables), workflow.ID)
	}

	if len(workflow.WorkflowVariables) > 0 {
		log.Printf("[INFO] Found %d workflow variable(s) for workflow %s", len(workflow.WorkflowVariables), workflow.ID)
	}

	// Nodechecks
	foundNodes := []string{}
	for _, node := range allNodes {
		for _, branch := range workflow.Branches {
			if node == branch.DestinationID || node == branch.SourceID {
				foundNodes = append(foundNodes, node)
				break
			}

			// Check if source parent
		}
	}

	// Making sure to check if infinite loops exist
	// This is now done during execution. Should be done on frontend & backend too
	/*
		for _, action := range workflow.Actions {
			//log.Printf("[INFO] Checking childnodes for action %s (%s)", action.Label, action.ID)
			childNodes := FindChildNodes(WorkflowExecution{Workflow: workflow}, action.ID, []string{}, []string{})
			log.Printf("[INFO] Found %d childnodes for action %s (%s)", len(childNodes), action.Label, action.ID)
		}
	*/

	// FIXME - append all nodes (actions, triggers etc) to one single array here
	//log.Printf("PRE VARIABLES")
	if len(foundNodes) != len(allNodes) || len(workflow.Actions) <= 0 {
		// This shit takes a few seconds lol
		if !workflow.IsValid {
			oldworkflow, err := GetWorkflow(ctx, fileId)
			if err != nil {
				log.Printf("[WARNING] Workflow %s doesn't exist - oldworkflow.", fileId)
				if workflow.PreviouslySaved {
					resp.WriteHeader(400)
					resp.Write([]byte(`{"success": false, "reason": "Item already exists."}`))
					return
				}
			}

			oldworkflow.IsValid = false
			err = SetWorkflow(ctx, *oldworkflow, fileId)
			if err != nil {
				log.Printf("[WARNING] Failed saving workflow to database: %s", err)
				if workflow.PreviouslySaved {
					resp.WriteHeader(500)
					resp.Write([]byte(`{"success": false}`))
					return
				}
			}
		}
	}

	// Check every app action and param to see whether they exist
	allAuths, autherr := GetAllWorkflowAppAuth(ctx, user.ActiveOrg.Id)
	authGroups := []AppAuthenticationGroup{}
	newActions = []Action{}
	for _, action := range workflow.Actions {
		reservedApps := []string{
			"0ca8887e-b4af-4e3e-887c-87e9d3bc3d3e",
		}

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
		if action.AuthenticationId == "authgroups" {
			log.Printf("[DEBUG] Action %s (%s) in workflow %s (%s) uses authgroups", action.Label, action.ID, workflow.Name, workflow.ID)

			// Check if the authgroups exists
			if len(workflow.AuthGroups) > 0 && len(authGroups) == 0 {
				authGroups, err = GetAuthGroups(ctx, user.ActiveOrg.Id)
				if err != nil {
					log.Printf("[WARNING] Failed getting authgroups for org %s: %s", user.ActiveOrg.Id, err)
				} else {
					log.Printf("[INFO] Found %d authgroups for org %s", len(authGroups), user.ActiveOrg.Id)

					// Validate the workflow groups to see if they exist. Remove if not.
					newGroups := []string{}
					for _, group := range workflow.AuthGroups {
						found := false

						for _, authGroup := range authGroups {
							if group == authGroup.Id {
								found = true
								break
							}
						}

						if !found {
							log.Printf("[WARNING] Authgroup %s doesn't exist. Removing from workflow", group)
						} else {
							newGroups = append(newGroups, group)
						}
					}

					workflow.AuthGroups = newGroups
				}
			}

		} else if len(action.AuthenticationId) > 0 {
			authFound := false
			for _, auth := range allAuths {
				if auth.Id == action.AuthenticationId {
					authFound = true

					if strings.ToLower(auth.Type) == "oauth2" {
						handleOauth = true
					}

					// Updates the auth item itself IF necessary
					UpdateAppAuth(ctx, auth, workflow.ID, action.ID, true)
					break
				}
			}

			if !authFound {
				log.Printf("[WARNING] App auth %s doesn't exist. Setting error", action.AuthenticationId)

				errorMsg := fmt.Sprintf("Selected app Authentication for app %s doesn't exist!", strings.ToLower(strings.ReplaceAll(action.AppName, "_", " ")))
				if !ArrayContains(workflow.Errors, errorMsg) {
					workflow.Errors = append(workflow.Errors, errorMsg)
				}

				workflow.IsValid = false
				action.Errors = append(action.Errors, "App authentication doesn't exist")
				action.IsValid = false
				action.AuthenticationId = ""
			}
		}

		if builtin {
			newActions = append(newActions, action)
		} else {
			curapp := WorkflowApp{}

			// ID first, then name + version
			// If it can't find param, it will swap it over farther down
			for _, app := range workflowapps {
				if app.ID == action.AppID {
					curapp = app
					break
				}
			}

			if curapp.ID == "" && action.AppID != "integration" {
				log.Printf("[WARNING] Didn't find the App ID for %s", action.AppID)
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
			} else {
				//log.Printf("[DEBUG] Found correct App ID for %s", action.AppID)
			}

			if curapp.ID != action.AppID && curapp.Name != action.AppName {
				if action.AppID == "integration" {
					for _, param := range action.Parameters {
						if param.Name == "action" {
							if len(param.Value) > 0 {
								continue
							}

							errorMsg := fmt.Sprintf("Parameter %s in Action %s is empty", param.Name, action.Label)
							if !ArrayContains(workflow.Errors, errorMsg) {
								workflow.Errors = append(workflow.Errors, errorMsg)
							}
						}
					}
				} else {
					errorMsg := fmt.Sprintf("App %s version %s doesn't exist", action.AppName, action.AppVersion)

					action.Errors = append(action.Errors, "This app doesn't exist.")

					if !ArrayContains(workflow.Errors, errorMsg) {
						workflow.Errors = append(workflow.Errors, errorMsg)
						log.Printf("[WARNING] App %s:%s doesn't exist. Adding as error.", action.AppName, action.AppVersion)
					}

					action.IsValid = false
					workflow.IsValid = false

				}

				newActions = append(newActions, action)
			} else {
				// Check to see if the appaction is valid
				curappaction := WorkflowAppAction{}
				for _, curAction := range curapp.Actions {
					if action.Name == curAction.Name {
						curappaction = curAction
						break
					}
				}

				if curappaction.Name != action.Name {
					for _, app := range workflowapps {
						if app.ID == curapp.ID {
							continue
						}

						// Has to NOT be generated
						if app.Name == action.AppName && app.AppVersion == action.AppVersion {
							for _, curAction := range app.Actions {
								if action.Name == curAction.Name {
									log.Printf("[DEBUG] Found app %s (NOT %s) with the param: %s", app.ID, curapp.ID, curAction.Name)
									curappaction = curAction
									action.AppID = app.ID
									curapp = app
									break
								}
							}
						}

						if curappaction.Name == action.Name {
							break
						}
					}
				}

				// Check to see if the action is valid
				if curappaction.Name != action.Name {
					log.Printf("[ERROR] Action '%s' in app %s doesn't exist. Workflow: %s (%s)", action.Name, curapp.Name, workflow.Name, workflow.ID)
					// Reserved names
					if action.Name != "router" {
						thisError := fmt.Sprintf("%s: Action %s in app %s doesn't exist", action.Label, action.Name, action.AppName)
						workflow.Errors = append(workflow.Errors, thisError)
						workflow.IsValid = false

						if !ArrayContains(action.Errors, thisError) {
							action.Errors = append(action.Errors, thisError)
						}

						action.IsValid = false
					}
				}

				selectedAuth := AppAuthenticationStorage{}
				if len(action.AuthenticationId) > 0 && autherr == nil {
					for _, auth := range allAuths {
						if auth.Id == action.AuthenticationId {
							selectedAuth = auth
							break
						}
					}
				}

				// Check if it uses oauth2 and if it's authenticated or not
				if selectedAuth.Id == "" && len(action.AuthenticationId) == 0 {
					authRequired := false
					fieldsFilled := 0
					for _, param := range curappaction.Parameters {
						if param.Configuration {
							if len(param.Value) > 0 {
								fieldsFilled += 1
							}

							authRequired = true
							break
						}
					}

					if authRequired && fieldsFilled > 1 {
						foundErr := fmt.Sprintf("Action %s (%s) requires authentication (1)", action.Label, strings.ToLower(strings.Replace(action.AppName, "_", " ", -1)))

						if !ArrayContains(workflow.Errors, foundErr) {
							log.Printf("\n\n[DEBUG] Adding auth error 1: %s\n\n", foundErr)
							workflow.Errors = append(workflow.Errors, foundErr)
							//continue
						}
					} else if authRequired && fieldsFilled == 1 {
						foundErr := fmt.Sprintf("Action %s (%s) requires authentication (2)", action.Label, strings.ToLower(strings.Replace(action.AppName, "_", " ", -1)))

						if !ArrayContains(workflow.Errors, foundErr) {
							log.Printf("[DEBUG] Workflow save - adding auth error 2: %s", foundErr)
							workflow.Errors = append(workflow.Errors, foundErr)
							//continue
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

								// Some internal reserves
								if ((strings.ToLower(action.AppName) == "http" && param.Name == "body") || (strings.ToLower(action.Name) == "send_sms_shuffle" || strings.ToLower(action.Name) == "send_email_shuffle") && param.Name == "apikey") || (action.Name == "repeat_back_to_me") || (action.Name == "filter_list" && param.Name == "field") {
									// Do nothing
								} else {
									thisError := fmt.Sprintf("Action %s is missing required parameter %s", action.Label, param.Name)
									if actionParam.Configuration && len(action.AuthenticationId) == 0 {
										thisError = fmt.Sprintf("Action %s (%s) requires authentication (3)", action.Label, strings.ToLower(strings.Replace(action.AppName, "_", " ", -1)))
									}

									action.Errors = append(action.Errors, thisError)

									errorFound := false
									for errIndex, oldErr := range workflow.Errors {
										if oldErr == thisError {
											errorFound = true
											break
										}

										if strings.Contains(oldErr, action.Label) && strings.Contains(oldErr, "missing required parameter") {
											workflow.Errors[errIndex] += ", " + param.Name
											errorFound = true
											break
										}
									}

									if !errorFound {
										workflow.Errors = append(workflow.Errors, thisError)
									}

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
							//workflow.Errors = append(workflow.Errors, fmt.Sprintf("Debug: Handling one Oauth2 app (%s). May cause issues during initial configuration (2)", action.Name))
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

	for _, trigger := range workflow.Triggers {
		if trigger.Status != "running" && trigger.TriggerType != "SUBFLOW" && trigger.TriggerType != "USERINPUT" {
			errorInfo := fmt.Sprintf("Trigger %s needs to be started", trigger.Name)
			if !ArrayContains(workflow.Errors, errorInfo) {
				workflow.Errors = append(workflow.Errors, errorInfo)
			}
		}
	}

	if !workflow.PreviouslySaved {
		log.Printf("[DEBUG] WORKFLOW INIT: NOT PREVIOUSLY SAVED - SET ACTION AUTH!")
		timeNow := int64(time.Now().Unix())

		//workflow.ID = uuid.NewV4().String()

		// Get the workflow and check if we own it
		workflow, err := GetWorkflow(ctx, workflow.ID)
		if err != nil || len(workflow.Actions) != 1 {
			log.Printf("[ERROR] FAILED GETTING WORKFLOW: %s - CREATING NEW ID!", err)
			workflow.ID = uuid.NewV4().String()
		}

		workflow.Public = false
		workflow.Owner = user.Id
		workflow.ExecutingOrg = user.ActiveOrg
		workflow.OrgId = user.ActiveOrg.Id
		workflow.Created = timeNow
		workflow.Edited = timeNow
		workflow.Org = []OrgMini{
			user.ActiveOrg,
		}

		for i, trigger := range workflow.Triggers {
			if trigger.Status == "running" {
				workflow.Triggers[i].Status = "uninitialized"
			}
		}

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

							_ = found

							/*
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
							*/

							log.Printf("[DEBUG] NOT adding authentication for workflow %s (%s) in org %s (%s) automatically as this should be done from within the workflow/during setup.", workflow.Name, workflow.ID, user.ActiveOrg.Name, user.ActiveOrg.Id)

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

	auth, authOk := request.URL.Query()["set_auth"]
	if authOk && len(auth) > 0 && auth[0] == "true" {
		for actionIndex, action := range workflow.Actions {
			if action.AuthenticationId != "" {
				continue
			}

			// Check if auth is required
			outerapp := WorkflowApp{}
			for _, app := range workflowapps {
				if app.Name != action.AppName {
					continue
				}

				outerapp = app
				break
			}

			if len(outerapp.ID) > 0 && outerapp.Authentication.Required {
				for _, auth := range allAuths {
					if auth.App.ID == outerapp.ID || auth.App.Name == outerapp.Name {
						log.Printf("[DEBUG] Automatically setting authentication for action %s (%s) in workflow %s (%s)", action.Name, action.ID, workflow.Name, workflow.ID)

						workflow.Actions[actionIndex].AuthenticationId = auth.Id
					}
				}
			}
		}
	}

	workflow.Actions = newActions
	workflow.IsValid = true

	// TBD: Is this too drastic? May lead to issues in the future.
	if workflow.OrgId != user.ActiveOrg.Id {
		log.Printf("[WARNING] NOT Editing workflow to be owned by org %s. Instead just editing. Original org: %s", user.ActiveOrg.Id, workflow.OrgId)

		/*
			workflow.OrgId = user.ActiveOrg.Id
			workflow.ExecutingOrg = user.ActiveOrg
			workflow.Org = append(workflow.Org, user.ActiveOrg)
		*/
		//resp.WriteHeader(500)
		//resp.Write([]byte(`{"success": false, "error": "Workflow does not belong to this org"}`))
		//return
	}

	// Only happens if the workflow is public and being edited
	if correctUser {
		workflow.Public = true

		// Should save it in Algolia too?
		_, err = handleAlgoliaWorkflowUpdate(ctx, workflow)
		if err != nil {
			log.Printf("[ERROR] Failed finding publicly changed workflow %s for user %s (%s): %s", workflow.ID, user.Username, user.Id, err)
		} else {
			log.Printf("[DEBUG] User %s (%s) updated their public workflow %s (%s)", user.Username, user.Id, workflow.Name, workflow.ID)
		}
	}

	if len(workflow.SuborgDistribution) > 0 {
		//log.Printf("[DEBUG] Diffing based on parent workflow %s", workflow.ID)
		for actionIndex, _ := range workflow.Actions {
			workflow.Actions[actionIndex].ParentControlled = true
		}

		for triggerIndex, _ := range workflow.Triggers {
			workflow.Triggers[triggerIndex].ParentControlled = true
		}

		for branchIndex, _ := range workflow.Branches {
			workflow.Branches[branchIndex].ParentControlled = true
		}

		workflow = diffWorkflowWrapper(workflow)
	}

	workflow.UpdatedBy = user.Username
	if workflow.Public {
		workflow.SuborgDistribution = []string{}
	}

	err = SetWorkflow(ctx, workflow, workflow.ID)
	if err != nil {
		log.Printf("[ERROR] Failed saving workflow to database: %s", err)
		if workflow.PreviouslySaved {
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	if org.Id == "" {
		org, err = GetOrg(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("[WARNING] Failed getting org during wf save of %s (org: %s): %s", workflow.ID, user.ActiveOrg.Id, err)
		}
	}

	// This may cause some issues with random slow loads with cross & suborgs, but that's fine (for now)
	// FIX: Should only happen for users with this org as the active one
	// Org-based workflows may also work
	if org.Id != "" {
		//for _, loopUser := range org.Users {
		//	DeleteCache(ctx, fmt.Sprintf("%s_workflows", loopUser.Id))
		//	DeleteCache(ctx, fmt.Sprintf("%s_workflows", org.Id))
		//}
	}

	if orgUpdated {
		err = SetOrg(ctx, *org, org.Id)
		if err != nil {
			log.Printf("[WARNING] Failed setting org when autoadding apps and updating framework on save workflow save (%s): %s", workflow.ID, err)
		} else {
			log.Printf("[DEBUG] Successfully updated org %s during save of %s for user %s (%s", user.ActiveOrg.Id, workflow.ID, user.Username, user.Id)
		}
	}

	// Save a backup version of the workflow
	// This is to be used for loading in workflows in the future
	// It automatically changes the ID to be unique
	workflow.OrgId = user.ActiveOrg.Id
	workflow.ExecutingOrg = OrgMini{
		Id:   user.ActiveOrg.Id,
		Name: user.ActiveOrg.Name,
	}

	SetWorkflowRevision(ctx, workflow)
	err = SetGitWorkflow(ctx, workflow, org)
	if err != nil {

		// Make a notification for this
		err = CreateOrgNotification(
			ctx,
			fmt.Sprintf("Failed setting git workflow for %s (%s): %s", workflow.Name, workflow.ID, err),
			fmt.Sprintf("User %s (%s) tried to upload %s (%s) but failed: %s. Make sure there is already a file in the repository, like README.md", user.Username, user.Id, workflow.Name, workflow.ID, err),
			fmt.Sprintf("/workflows/%s", workflow.ID),
			user.ActiveOrg.Id,
			true,
		)

		if err != nil {
			log.Printf("[WARNING] Failed creating notification for failed git workflow for %s (%s): %s", workflow.Name, workflow.ID, err)
		} else {
			log.Printf("[WARNING] Failed setting git workflow for %s (%s). Notification created. %s", workflow.Name, workflow.ID, err)
		}

	}

	type returnData struct {
		Success bool     `json:"success"`
		Errors  []string `json:"errors"`
	}

	returndata := returnData{
		Success: true,
		Errors:  workflow.Errors,
	}

	// Really don't know why this was happening
	log.Printf("[INFO] Saved new version of workflow %s (%s) for org %s. User: %s (%s). Actions: %d, Triggers: %d", workflow.Name, fileId, workflow.OrgId, user.Username, user.Id, len(workflow.Actions), len(workflow.Triggers))
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

	if project.Environment == "cloud" {
		// Checking if it's a special region. All user-specific requests should
		// go through shuffler.io and not subdomains
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting API GEN request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
	}

	userInfo, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in apigen: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	//log.Printf("IN APIKEY GENERATION")
	ctx := GetContext(request)
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
			log.Printf("Failed reading body")
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

	if project.Environment == "cloud" {
		// Checking if it's a special region. All user-specific requests should
		// go through shuffler.io and not subdomains
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting Handle Settings request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
	}

	userInfo, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in settings: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	newObject := SettingsReturn{
		Success:  true,
		Username: userInfo.Username,
		Verified: userInfo.Verified,
		Apikey:   userInfo.ApiKey,
		Image:    userInfo.PublicProfile.GithubAvatar,
	}

	newjson, err := json.Marshal(newObject)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshal in get settings: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed handling your user"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func HandleGetUsers(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	if project.Environment == "cloud" {
		// Checking if it's a special region. All user-specific requests should
		// go through shuffler.io and not subdomains
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting Get Users request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
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

		// Get the actual user
		foundUser, err := GetUser(ctx, item.Id)
		if err != nil {
			log.Printf("[WARNING] Failed getting user in get users: %s", err)
		} else {
			item = *foundUser
		}

		//&& (len(item.Orgs) > 1 || item.Role == "admin") {
		if item.Id != user.Id {
			item.ApiKey = ""
		}

		item.Password = ""
		item.Session = ""
		item.VerificationToken = ""
		item.Orgs = []string{}
		item.EthInfo = EthInfo{}

		item.Authentication = []UserAuth{}
		item.Executions = ExecutionInfo{}
		item.Limits = UserLimits{}
		item.PrivateApps = []WorkflowApp{}
		item.MFA = MFAInfo{
			Active: item.MFA.Active,
		}

		if !user.SupportAccess {
			item.LoginInfo = []LoginInfo{}
		}

		// Will get from cache 2nd time so this is fine.
		if user.Id == item.Id {
			item.Orgs = user.Orgs
			item.Active = user.Active
			//item.MFA = user.MFA
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

				//item.MFA = foundUser.MFA
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

	deduplicatedUsers := []User{}
	for _, item := range newUsers {
		found := false
		for _, tmpUser := range deduplicatedUsers {
			if tmpUser.Username == item.Username {
				found = true
				break
			}
		}

		if !found {
			//log.Printf("[DEBUG] Adding user %s (%s) to list", item.Username, item.Id)
			deduplicatedUsers = append(deduplicatedUsers, item)
		}
	}

	newjson, err := json.Marshal(deduplicatedUsers)
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
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
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
		log.Printf("[WARNING] Failed reading body")
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false}`)))
		return
	}

	// Get the current user - check if they're admin or the "username" user.
	var t PasswordChange
	err = json.Unmarshal(body, &t)
	if err != nil {
		log.Printf("Failed unmarshaling")
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
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't change users outside your org (2)."}`)))
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

	ctx := GetContext(request)
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

	ctx := GetContext(request)
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

func DuplicateWorkflow(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Removed check here as it may be a public workflow
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in duplicate workflow: %s. Continuing because it may be public IF cloud.", err)
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

	if strings.Contains(fileId, "?") {
		fileId = strings.Split(fileId, "?")[0]
	}

	if len(fileId) != 36 {
		log.Printf("\n\n[WARNING] Workflow ID when duplicating workflow is not valid: %s. URL: %s", fileId, request.URL.String())
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID when getting workflow is not valid"}`))
		return
	}

	ctx := GetContext(request)
	workflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Workflow %s doesn't exist.", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed finding workflow"}`))
		return
	}

	// Check workflow.Sharing == private / public / org  too
	isOwner := false
	if user.Id != workflow.Owner || len(user.Id) == 0 {
		// Added org-reader as the user should be able to read everything in an org
		//if workflow.OrgId == user.ActiveOrg.Id && (user.Role == "admin" || user.Role == "org-reader") {
		if workflow.OrgId == user.ActiveOrg.Id {
			log.Printf("[AUDIT] User %s is accessing workflow %s as the org is same (duplicate workflow)", user.Username, workflow.ID)

			isOwner = true
		} else if workflow.Public {
			log.Printf("[AUDIT] Letting user %s access workflow %s because it's public (duplicate workflow)", user.Username, workflow.ID)

			// Only for Read-Only. No executions or impersonations.
		} else if project.Environment == "cloud" && user.Verified == true && user.Active == true && user.SupportAccess == true && strings.HasSuffix(user.Username, "@shuffler.io") {
			log.Printf("[AUDIT] Letting verified support admin %s access workflow %s (duplicate workflow)", user.Username, workflow.ID)

			isOwner = true
		} else {
			log.Printf("[AUDIT] Wrong user %s (%s) for workflow '%s' (duplicate workflow). Verified: %t, Active: %t, SupportAccess: %t, Username: %s", user.Username, user.Id, workflow.ID, user.Verified, user.Active, user.SupportAccess, user.Username)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	if len(workflow.ParentWorkflowId) > 0 {
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Can't duplicate a workflow distributed from a parent org"}`))
		return
	}

	newId := uuid.NewV4().String()
	log.Printf("[DEBUG] Duplicated workflow %s for user %s with new ID %s", workflow.ID, user.Username, newId)

	type WorkflowDupe struct {
		Name string `json:"name"`
	}

	var t WorkflowDupe
	err = json.NewDecoder(request.Body).Decode(&t)
	if err != nil {
		log.Printf("[WARNING] Failed decoding workflow dupe: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(t.Name) == 0 {
		t.Name = workflow.Name + " (copy)"
	}

	workflow.Name = t.Name
	workflow.Owner = user.Id
	workflow.ID = newId
	workflow.OrgId = user.ActiveOrg.Id
	workflow.Org = []OrgMini{user.ActiveOrg}
	workflow.ExecutingOrg = user.ActiveOrg
	workflow.Created = 0
	workflow.Edited = 0

	err = SetWorkflow(ctx, *workflow, newId)
	if err != nil {
		log.Printf("[WARNING] Failed setting workflow %s: %s", workflow.ID, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	_ = isOwner

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "id": "%s"}`, workflow.ID)))
	return
}

func GenerateWorkflowFromParent(ctx context.Context, workflow Workflow, parentOrgId, subOrgId string) (*Workflow, error) {

	DeleteCache(ctx, fmt.Sprintf("%s_workflows", workflow.OrgId))
	DeleteCache(ctx, fmt.Sprintf("%s_workflows", subOrgId))
	DeleteCache(ctx, fmt.Sprintf("workflow_%s_childworkflows", workflow.ID))
	var err error
	parentWorkflowId := workflow.ID

	// Make a copy of the workflow, and set parent/child relationships
	// Seed random based on the existing workflow + suborg to make sure we only make one
	seedString := fmt.Sprintf("%s_%s", workflow.ID, subOrgId)
	hash := sha1.New()
	hash.Write([]byte(seedString))
	hashBytes := hash.Sum(nil)

	uuidBytes := make([]byte, 16)
	copy(uuidBytes, hashBytes)
	newId := uuid.Must(uuid.FromBytes(uuidBytes)).String()
	DeleteCache(ctx, fmt.Sprintf("workflow_%s_childworkflows", newId))

	foundWorkflow, err := GetWorkflow(ctx, newId)
	if err == nil && foundWorkflow.ID == newId && foundWorkflow.ParentWorkflowId == parentWorkflowId {
		return foundWorkflow, nil
	}

	if !ArrayContains(workflow.ChildWorkflowIds, newId) {
		workflow.ChildWorkflowIds = append(workflow.ChildWorkflowIds, newId)

		DeleteCache(ctx, fmt.Sprintf("%s_workflows", workflow.OrgId))
		err = SetWorkflow(ctx, workflow, workflow.ID)
		if err != nil {
			log.Printf("[ERROR] Failed adding new child workflow %s: %s", newId, err)
		} else {
			log.Printf("[AUDIT] Added new child workflow of %s in suborg %s", workflow.ID, subOrgId)
		}
	}

	newWf := workflow
	newWf.ID = newId

	newWf.SuborgDistribution = []string{}
	newWf.ChildWorkflowIds = []string{}
	newWf.ParentWorkflowId = parentWorkflowId

	newWf.Org = []OrgMini{
		OrgMini{
			Id: subOrgId,
		},
	}

	newWf.OrgId = subOrgId
	newWf.ExecutingOrg = OrgMini{
		Id: subOrgId,
	}

	newWf.Created = 0
	newWf.Edited = 0

	defaultEnvironment := "cloud"
	envs, err := GetEnvironments(ctx, subOrgId)
	for _, env := range envs {
		if env.Default {
			defaultEnvironment = env.Name
			break
		}
	}

	for actionIndex, _ := range workflow.Actions {
		workflow.Actions[actionIndex].ParentControlled = true
		workflow.Actions[actionIndex].AuthenticationId = ""
		workflow.Actions[actionIndex].Environment = defaultEnvironment
	}

	for triggerIndex, _ := range workflow.Triggers {
		workflow.Triggers[triggerIndex].ParentControlled = true
		workflow.Triggers[triggerIndex].Environment = defaultEnvironment

		// FIXME: How do we manage secondary IDs?
		// E.g. for webhooks, how do we have a URL correctly, and start/stop properly?

		workflow.Triggers[triggerIndex].Status = "uninitialized"
		if workflow.Triggers[triggerIndex].TriggerType == "WEBHOOK" {
			for paramIndex, param := range workflow.Triggers[triggerIndex].Parameters {
				if param.Name == "url" {
					workflow.Triggers[triggerIndex].Parameters[paramIndex].Value = ""
				}

				if param.Name == "tmp" {
					workflow.Triggers[triggerIndex].Parameters[paramIndex].Value = ""
				}
			}
		}

	}

	err = SetWorkflow(ctx, newWf, newWf.ID)
	if err != nil {
		log.Printf("[DEBUG] Failed setting new child workflow of ID %s (%s): %s", workflow.ID, newWf.ID, err)
	}

	return &newWf, err
}

func GetSpecificWorkflow(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Removed check here as it may be a public workflow
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in getting specific workflow: %s. Continuing because it may be public IF cloud.", err)

		if project.Environment != "cloud" {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
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
		log.Printf("\n\n[WARNING] Workflow ID when getting workflow is not valid: %s. URL: %s", fileId, request.URL.String())
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID when getting workflow is not valid"}`))
		return
	}

	ctx := GetContext(request)
	workflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Workflow %s doesn't exist.", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed finding workflow"}`))
		return
	}

	// Special case to handle suborg distribution workflow loading
	if len(workflow.SuborgDistribution) > 0 {
		for _, orgId := range workflow.SuborgDistribution {
			if orgId != user.ActiveOrg.Id {
				continue
			}

			log.Printf("[AUDIT] User %s is accessing workflow %s from a suborg that has access (get workflow)", user.Username, workflow.ID)

			// Check local workflows to see if a local version of the workflow exists. Should NOT be able to see the parents' workflow directly (?)
			workflows, err := GetAllWorkflowsByQuery(ctx, user)
			if err != nil {
				log.Printf("[WARNING] Failed getting workflows in get workflow with suborg distrib. Auth should fail.: %s", err)
			} else {
				found := false
				for _, childWorkflow := range workflows {
					if childWorkflow.ParentWorkflowId != workflow.ID {
						continue
					}

					found = true
					fileId = childWorkflow.ID
					workflow = &childWorkflow
					break
				}

				if !found {

					log.Printf("[AUDIT] Failed to find existing workflow for user %s in suborg %s. Making replica.", user.Username, orgId)
					parentWorkflowOrgId := workflow.OrgId
					childOrgId := orgId

					newWf, err := GenerateWorkflowFromParent(ctx, *workflow, parentWorkflowOrgId, childOrgId)
					if err != nil {
						log.Printf("[ERROR] Failed setting new child workflow %s: %s", newWf.ID, err)
					} else {
						log.Printf("[AUDIT] Created new child workflow of %s for user %s in suborg %s", workflow.ID, user.Username, orgId)
						workflow = newWf

					}

					DeleteCache(ctx, fmt.Sprintf("%s_workflows", user.ActiveOrg.Id))
				} else {
					log.Printf("[AUDIT] Found existing workflow for user %s in suborg %s. Loading.", user.Username, orgId)
				}
			}

			break
		}
	}

	// Check workflow.Sharing == private / public / org  too
	isOwner := false
	if user.Id != workflow.Owner || len(user.Id) == 0 {
		// Added org-reader as the user should be able to read everything in an org
		//if workflow.OrgId == user.ActiveOrg.Id && (user.Role == "admin" || user.Role == "org-reader") {
		if workflow.OrgId == user.ActiveOrg.Id {
			log.Printf("[AUDIT] User %s is accessing workflow %s as the org is same (get workflow)", user.Username, workflow.ID)

			isOwner = true
		} else if workflow.Public {
			log.Printf("[AUDIT] Letting user %s access workflow %s because it's public", user.Username, workflow.ID)

			// Only for Read-Only. No executions or impersonations.
		} else if project.Environment == "cloud" && user.Verified == true && user.Active == true && user.SupportAccess == true && strings.HasSuffix(user.Username, "@shuffler.io") {
			log.Printf("[AUDIT] Letting verified support admin %s access workflow %s", user.Username, workflow.ID)

			isOwner = true
		} else {
			log.Printf("[AUDIT] Wrong user %s (%s) for workflow '%s' (get workflow). Verified: %t, Active: %t, SupportAccess: %t, Username: %s", user.Username, user.Id, workflow.ID, user.Verified, user.Active, user.SupportAccess, user.Username)
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

	for key, _ := range workflow.Actions {
		// RefUrl not necessary anymore, as we migrated to getting apps during exec
		workflow.Actions[key].ReferenceUrl = ""

		// Never helpful when this is red
		if workflow.Actions[key].AppName == "Shuffle Tools" {
			workflow.Actions[key].IsValid = true
		}

		if !workflow.Actions[key].IsValid {
			//log.Printf("[AUDIT] Invalid action in workflow '%s' (%s): '%s' (%s)", workflow.Name, workflow.ID, workflow.Actions[key].Label, workflow.Actions[key].ID)

			// Check if all fields are set
			// Check if auth is set (autofilled)
			isValid := true
			for _, param := range workflow.Actions[key].Parameters {
				if param.Required && len(param.Value) == 0 {
					isValid = false
					break
				}
			}

			if isValid {
				workflow.Actions[key].IsValid = true
			}
		}
	}

	// Getting in here during schemaless is normal
	if len(workflow.Name) == 0 && len(workflow.ID) == 0 {
		//log.Printf("[ERROR] Workflow has no name or ID, hence may not exist. Reference ID (maybe from Algolia?: %s)", fileId)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "No workflow found"}`))
		return
	}

	// Never load without a node
	if len(workflow.Actions) == 0 {
		// Append
		nodeId := uuid.NewV4().String()
		workflow.Start = nodeId

		envName := "cloud"
		if project.Environment != "cloud" {
			envName = "Shuffle"
		}

		workflowapps, err := GetPrioritizedApps(ctx, user)
		if err == nil {
			for _, item := range workflowapps {
				//log.Printf("NAME: %s", item.Name)
				if (item.Name == "Shuffle Tools" || item.Name == "Shuffle-Tools") && item.AppVersion == "1.2.0" {
					newAction := Action{
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
						Priority:    0,
						Errors:      []string{},
						ID:          nodeId,
						IsValid:     true,
						IsStartNode: true,
						Sharing:     true,
						PrivateID:   "",
						SmallImage:  "",
						AppName:     "Shuffle Tools",
						AppVersion:  "1.2.0",
						AppID:       item.ID,
						LargeImage:  item.LargeImage,
					}
					newAction.Position = Position{
						X: 449.5,
						Y: 446,
					}

					workflow.Actions = append(workflow.Actions, newAction)
					break
				}
			}
		}
	}

	workflowapps, err := GetPrioritizedApps(ctx, user)
	if err != nil {
		log.Printf("[WARNING] Error: Failed getting workflowapps: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Handle app versions & upgrades
	for _, action := range workflow.Actions {
		actionApp := strings.ToLower(strings.Replace(action.AppName, " ", "", -1))

		for _, app := range workflowapps {
			if strings.ToLower(strings.Replace(app.Name, " ", "", -1)) != actionApp {
				continue
			}

			if len(app.Versions) <= 1 {
				continue
			}

			v2, err := semver.NewVersion(action.AppVersion)
			if err != nil {
				log.Printf("[ERROR] Failed parsing original app version %s: %s", app.AppVersion, err)
				continue
			}

			newVersion := ""
			for _, loopedApp := range app.Versions {
				if action.AppVersion == loopedApp.Version {
					continue
				}

				appConstraint := fmt.Sprintf("< %s", loopedApp.Version)
				c, err := semver.NewConstraint(appConstraint)
				if err != nil {
					log.Printf("[ERROR] Failed preparing constraint %s: %s", appConstraint, err)
					continue
				}

				if c.Check(v2) {
					newVersion = loopedApp.Version
					action.AppVersion = loopedApp.Version
				}
			}

			if len(newVersion) > 0 {
				newError := fmt.Sprintf("App %s has version %s available.", app.Name, newVersion)
				if !ArrayContains(workflow.Errors, newError) {
					workflow.Errors = append(workflow.Errors, newError)
				}
			}
		}
	}

	if workflow.Public {
		workflow.ExecutingOrg = OrgMini{}
		workflow.Org = []OrgMini{}
		workflow.OrgId = ""

		if !isOwner {
			workflow.PreviouslySaved = false
			workflow.ID = ""
		}
	}

	log.Printf("[INFO] Got new version of workflow %s (%s) for org %s and user %s (%s). Actions: %d, Triggers: %d", workflow.Name, workflow.ID, user.ActiveOrg.Id, user.Username, user.Id, len(workflow.Actions), len(workflow.Triggers))

	body, err := json.Marshal(workflow)
	if err != nil {
		log.Printf("[WARNING] Failed workflow GET marshalling: %s", err)
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

	if project.Environment == "cloud" {
		// Checking if it's a special region. All user-specific requests should
		// go through shuffler.io and not subdomains
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting User request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
	}

	userInfo, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("[WARNING] Api authentication failed in delete user: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if userInfo.Role != "admin" {
		log.Printf("[DEBUG] Wrong user (%s) when deleting - must be admin", userInfo.Username)
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

	// Overwrite incase the user is in the same org
	// This could be a way to jump into someone elses organisation if the user already has the correct org name without correct name.
	if foundUser.ActiveOrg.Id == "" && foundUser.ActiveOrg.Name == userInfo.ActiveOrg.Name && len(foundUser.Orgs) == 0 {
		foundUser.ActiveOrg.Id = string(userInfo.ActiveOrg.Id)
	}

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

	// FIXME: Add a way to check if the user is a part of the
	if !orgFound && !userInfo.SupportAccess {
		log.Printf("[AUDIT] User %s (%s) is admin, but can't delete users outside their own org.", userInfo.Username, userInfo.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't change users outside your org (1)."}`)))
		return
	}

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
		foundUser.ActiveOrg.Id = ""
		foundUser.ActiveOrg.Name = ""
	}

	foundUser.Orgs = neworgs
	if len(foundUser.Orgs) == 0 {
		log.Printf("[INFO] User %s (%s) doesn't have an org anymore after being deleted. This will be generated when they log in next time", foundUser.Username, foundUser.Id)
	}

	if len(foundUser.ActiveOrg.Id) > 0 {
		foundUserOrg, err := GetOrg(ctx, foundUser.ActiveOrg.Id)
		if err != nil {
			log.Printf("[ERROR] Failed getting org '%s' in delete user: %s", foundUser.ActiveOrg.Id, err)
		} else {
			if foundUserOrg.SSOConfig.SSORequired && !ArrayContains(foundUser.ValidatedSessionOrgs, foundUserOrg.Id) {
				log.Printf("[AUDIT] User %s (%s) does not have an active session in org with forced SSO %s, so forcing a re-login (aka logout).", foundUser.ActiveOrg.Id)
				foundUser.Session = ""
				foundUser.ValidatedSessionOrgs = []string{}
			}
		}
	}

	err = SetUser(ctx, foundUser, false)
	if err != nil {
		log.Printf("[WARNING] Failed removing user %s (%s) from org %s: %s", foundUser.Username, foundUser.Id, userInfo.ActiveOrg.Id, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false}`)))
		return
	}

	// log.Printf("user active organization is %v: ", userInfo)

	org, err := GetOrg(ctx, userInfo.ActiveOrg.Id)
	if err != nil {
		log.Printf("[ERROR] Failed getting org '%s' in delete user: %s", userInfo.ActiveOrg.Id, err)
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

	log.Printf("[AUDIT] User %s (%s) successfully removed %s from org %s", userInfo.Username, userInfo.Id, foundUser.Username, userInfo.ActiveOrg.Id)

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleDeleteUsersAccount(resp http.ResponseWriter, request *http.Request) {

	cors := HandleCors(resp, request)
	if cors {
		return
	}

	if project.Environment == "cloud" {
		// Checking if it's a special region. All user-specific requests should
		// go through shuffler.io and not subdomains
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting User request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
	}

	userInfo, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("[WARNING] Api authentication failed in delete user: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "API authentication fail"}`))
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

	foundUser, err := GetUser(ctx, userId)
	if err != nil {
		log.Printf("[WARNING] Can't find user %s (delete user): %s", userId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't find user with uername: %v"}`, userInfo.Username)))
		return
	}

	if !userInfo.SupportAccess && userInfo.Id != foundUser.Id {
		log.Printf("Unauthorized user (%s) attempted to delete an account. Must be a user or have support access.", userInfo.Username)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Unauthorize User. Must be a regular user or have support access"}`))
		return
	}

	if !userInfo.SupportAccess {
		var requestBody struct {
			Password string `json:"password"`
		}

		if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed decoding request body"}`))
			return
		}

		password := requestBody.Password

		err = bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(password))
		if err != nil {
			// Passwords don't match
			log.Printf("[WARNING] Password is incorrect for user while deleting account %s (%s): %s", userInfo.Username, userInfo.Id, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Password is incorrect"}`))
			return
		}
	}

	// Overwrite incase the user is in the same org
	// This could be a way to jump into someone elses organisation if the user already has the correct org name without correct name.
	if foundUser.ActiveOrg.Id == "" && foundUser.ActiveOrg.Name == userInfo.ActiveOrg.Name && len(foundUser.Orgs) == 0 {
		foundUser.ActiveOrg.Id = string(userInfo.ActiveOrg.Id)
	}

	if foundUser.SupportAccess {
		log.Printf("[AUDIT] Can't delete support user %s (%s)", userInfo.Username, userInfo.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't delete support user"}`))
		return
	}

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

	// FIXME: Add a way to check if the user is a part of the
	if !orgFound && !userInfo.SupportAccess {
		log.Printf("[AUDIT] User %s (%s) is admin, but can't delete users outside their own org.", userInfo.Username, userInfo.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't change users outside your org (1)."}`)))
		return
	}

	if len(foundUser.Orgs) == 0 {
		log.Printf("[INFO] User %s (%s) doesn't have an org anymore after being deleted. This will be generated when they log in next time", foundUser.Username, foundUser.Id)
	}

	err = SetUser(ctx, foundUser, false)
	if err != nil {
		log.Printf("[WARNING] Failed removing user %s (%s) from org %s: %s", foundUser.Username, foundUser.Id, userInfo.ActiveOrg.Id, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false}`)))
		return
	}

	// log.Printf("user active organization is %v: ", userInfo)

	org, err := GetOrg(ctx, userInfo.ActiveOrg.Id)
	if err != nil {
		log.Printf("[ERROR] Failed getting org '%s' in delete user: %s", userInfo.ActiveOrg.Id, err)
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
	if len(org.Users) > 1 {
		err = SetOrg(ctx, *org, org.Id)
		if err != nil {
			log.Printf("[WARNING] Failed updating org (delete user %s) %s: %s", foundUser.Username, org.Id, err)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Removed their access but failed updating own user list"}`)))
			return
		}
	}

	err = DeleteUsersAccount(ctx, foundUser)
	if err != nil {
		log.Printf("[Error] Can't Delete User with User name: %v and Id: %v", foundUser.Username, foundUser.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason":"Can't Delete User with Username: %v}`, userInfo.Username)))
		return
	}

	log.Printf("[AUDIT] User %s (%s) successfully deleted %s (%s)", userInfo.Username, userInfo.Id, foundUser.Username, foundUser.Id)

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))

}

// Only used for onprem :/
func UpdateWorkflowAppConfig(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	if project.Environment == "cloud" {
		// Checking if it's a special region. All user-specific requests should
		// go through shuffler.io and not subdomains
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting LOGIN request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
	}

	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("[AUDIT] Api authentication failed in get all apps: %s", userErr)
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

	ctx := GetContext(request)
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
		log.Printf("[INFO] Changing app sharing for %s to %s", app.ID, tmpfields.Sharing)
		app.Sharing = tmpfields.Sharing

		if project.Environment != "cloud" {
			log.Printf("[INFO] Set app %s (%s) to share everywhere (PUBLIC=true/false), because running onprem", app.Name, app.ID)
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
	DeleteCache(ctx, fmt.Sprintf("apps_%s", user.ActiveOrg.Id))

	log.Printf("[INFO] Changed App configuration for %s (%s)", app.Name, app.ID)
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true}`)))
}

func deactivateApp(ctx context.Context, user User, app *WorkflowApp) error {
	//log.Printf("Should deactivate app %s\n for user %s", app, user)
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

	ctx := GetContext(request)
	app, err := GetApp(ctx, fileId, user, false)
	if err != nil {
		log.Printf("[WARNING] Error getting app %s: %s", app.Name, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if project.Environment != "cloud" && len(app.ReferenceOrg) == 0 {
		app.ReferenceOrg = user.ActiveOrg.Id
	}

	if user.Id != app.Owner && app.ReferenceOrg != user.ActiveOrg.Id {
		if user.Role == "admin" && app.Owner == "" {
			log.Printf("[INFO] Anyone can edit %s (%s), since it doesn't have an owner (DELETE).", app.Name, app.ID)
		} else {
			if user.Role == "admin" {
				err = deactivateApp(ctx, user, app)
				if err == nil {
					log.Printf("[INFO] App %s was deactivated for org %s", app.ID, user.ActiveOrg.Id)
					DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
					DeleteCache(ctx, fmt.Sprintf("apps_%s", user.ActiveOrg.Id))
					DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-100"))
					DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-500"))
					DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-1000"))
					DeleteCache(ctx, "all_apps")
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
		log.Printf("[WARNING] App %s being deleted is public. Shouldn't be allowed. Public: %s, Sharing: %s", app.Name, app.Public, app.Sharing)

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
	DeleteCache(ctx, fmt.Sprintf("apps_%s", user.ActiveOrg.Id))
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
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	var tmpData ReturnData
	err = json.Unmarshal(body, &tmpData)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshalling test: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if tmpData.OrgId != fileId {
		log.Printf("[INFO] OrgId %s and %s don't match", tmpData.OrgId, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "Organization ID's don't match"}`))
		return
	}

	ctx := GetContext(request)

	org, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("[INFO] Organization %s doesn't exist: %s", tmpData.OrgId, err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	workflowExecution, err := GetWorkflowExecution(ctx, tmpData.ExecutionRef)
	if err != nil {
		log.Printf("[INFO] Couldn't find workflow execution: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "No permission to get execution"}`))
		return
	}

	if workflowExecution.Authorization != tmpData.Authorization {
		log.Printf("[INFO] Execution auth %s and %s don't match", workflowExecution.Authorization, tmpData.Authorization)
		resp.WriteHeader(403)
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
				log.Printf("[WARNING] Failed getting key %s: %s (1)", dbKey, err)
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
				log.Printf("[WARNING] Failed getting key %s: %s (2)", dbKey, err)
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
				log.Printf("[ERROR] Error adding %s to appvalue: %s", notFoundValue, err)
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

	// Just getting here for later
	ctx := GetContext(request)
	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("[AUDIT] Api authentication failed in change org (local): %s", userErr)
	}

	if project.Environment == "cloud" {
		// Checking if it's a special region. All user-specific requests should
		// Clean up the users' cache for different parts
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {

			DeleteCache(ctx, fmt.Sprintf("%s_workflows", user.Id))
			DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
			DeleteCache(ctx, fmt.Sprintf("user_%s", user.Username))
			DeleteCache(ctx, fmt.Sprintf("user_%s", user.Id))
			DeleteCache(ctx, fmt.Sprintf(user.ApiKey))
			DeleteCache(ctx, fmt.Sprintf("session_%s", user.Session))

			log.Printf("[DEBUG] Redirecting ORGCHANGE request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)

			DeleteCache(ctx, fmt.Sprintf("%s_workflows", user.Id))
			DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
			DeleteCache(ctx, fmt.Sprintf("user_%s", user.Username))
			DeleteCache(ctx, fmt.Sprintf("user_%s", user.Id))
			DeleteCache(ctx, fmt.Sprintf(user.ApiKey))
			DeleteCache(ctx, fmt.Sprintf("session_%s", user.Session))

			return
		}
	}

	if userErr != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	type ReturnData struct {
		OrgId     string `json:"org_id" datastore:"org_id"`
		RegionUrl string `json:"region_url" datastore:"region_url"`
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

	foundOrg := false
	for _, org := range user.Orgs {
		if org == tmpData.OrgId {
			foundOrg = true
			break
		}
	}

	if user.ActiveOrg.Id == fileId {
		log.Printf("[WARNING] User swap to the org \"%s\" - already in the org", tmpData.OrgId)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "You are already in that organisation"}`))
		return
	}

	// Add instantswap of backend
	// This could in theory be built out open source as well
	regionUrl := ""
	if project.Environment == "cloud" && user.SupportAccess {
		regionUrl = "https://shuffler.io"
		foundOrg = true
	}

	if !foundOrg || tmpData.OrgId != fileId {
		log.Printf("[WARNING] User swap to the org \"%s\" - access denied", tmpData.OrgId)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "No permission to change to this org. Please contact support@shuffler.io if this is unexpected."}`))
		return
	}

	org, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("[WARNING] Organization %s doesn't exist: %s", tmpData.OrgId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	//if org.SSOConfig.SSORequired == true && !ArrayContains(user.ValidatedSessionOrgs, tmpData.OrgId) && user.SupportAccess == false {
	if org.SSOConfig.SSORequired == true && !ArrayContains(user.ValidatedSessionOrgs, tmpData.OrgId) {

		baseSSOUrl := org.SSOConfig.SSOEntrypoint
		redirectKey := "SSO_REDIRECT"
		if len(org.SSOConfig.OpenIdAuthorization) > 0 {
			log.Printf("[INFO] OpenID login for %s", org.Id)
			redirectKey = "SSO_REDIRECT"

			baseSSOUrl = GetOpenIdUrl(request, *org)
		}

		if !strings.HasPrefix(baseSSOUrl, "http") {
			log.Printf("[ERROR] SSO URL for %s (%s) is invalid: %s", org.Name, org.Id, baseSSOUrl)
			//resp.WriteHeader(401)
			//resp.Write([]byte(`{"success": false, "reason": "SSO URL is invalid"}`))
			//return
		} else {
			// Check if the user has other orgs that can be swapped to - if so SWAP
			log.Printf("[DEBUG] Change org: Should redirect user %s in org %s (%s) to SSO login at %s", user.Username, user.ActiveOrg.Name, user.ActiveOrg.Id, baseSSOUrl)
			ssoResponse := SSOResponse{
				Success: true,
				Reason:  redirectKey,
				URL:     baseSSOUrl,
			}

			b, err := json.Marshal(ssoResponse)
			if err != nil {
				log.Printf("[ERROR] Failed marshalling SSO response: %s", err)
				resp.Write([]byte(`{"success": false}`))
				return
			}

			resp.WriteHeader(200)
			resp.Write(b)
			return
		}
	}

	if project.Environment == "cloud" && len(org.RegionUrl) > 0 && !strings.Contains(org.RegionUrl, "\"") {
		regionUrl = org.RegionUrl
	}

	userFound := false
	usr := User{}
	for _, orgUsr := range org.Users {
		if user.Id == orgUsr.Id {
			usr = orgUsr
			userFound = true
			break
		}
	}

	if !userFound && !user.SupportAccess {
		log.Printf("[WARNING] User %s (%s) can't change to org %s (%s) (2)", user.Username, user.Id, org.Name, org.Id)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "No permission to change to this org (2). Please contact support@shuffler.io if this is unexpected."}`))
		return
	}

	if user.SupportAccess {
		usr.Role = "admin"
		user.Role = "admin"
	}

	user.ActiveOrg = OrgMini{
		Name: org.Name,
		Id:   org.Id,
		Role: usr.Role,
	}

	user.Role = usr.Role

	err = SetUser(ctx, &user, false)
	if err != nil {
		log.Printf("[ERROR] Failed updating user when changing org: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	expiration := time.Now().Add(3600 * time.Second)

	newCookie := &http.Cookie{
		Name:    "session_token",
		Value:   user.Session,
		Expires: expiration,
		Path:    "/",
	}

	if project.Environment == "cloud" {
		newCookie.Domain = ".shuffler.io"
		newCookie.Secure = true
		newCookie.HttpOnly = true
	}

	http.SetCookie(resp, newCookie)

	newCookie.Name = "__session"
	http.SetCookie(resp, newCookie)

	// Cleanup cache for the user
	DeleteCache(ctx, fmt.Sprintf("%s_workflows", user.Id))
	DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
	DeleteCache(ctx, fmt.Sprintf("apps_%s", user.ActiveOrg.Id))
	DeleteCache(ctx, fmt.Sprintf("user_%s", user.Username))
	DeleteCache(ctx, fmt.Sprintf("user_%s", user.Id))
	DeleteCache(ctx, fmt.Sprintf(user.ApiKey))
	DeleteCache(ctx, user.Session)

	DeleteCache(ctx, fmt.Sprintf("session_%s", user.Session))

	log.Printf("[INFO] User %s (%s) successfully changed org to '%s' (%s)", user.Username, user.Id, org.Name, org.Id)
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Changed Organization", "region_url": "%s"}`, regionUrl)))

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
		log.Printf("[WARNING] Can't make suborg without being admin: %s (%s).", user.Username, user.Id)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Not admin"}`))
		return
	}

	ctx := GetContext(request)
	parentOrg, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[ERROR] Organization %s doesn't exist or failed to load: %s", user.ActiveOrg.Id, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Just for cache reseting across regions
	for _, inneruser := range parentOrg.Users {
		DeleteCache(ctx, inneruser.ApiKey)
		DeleteCache(ctx, inneruser.Session)
		DeleteCache(ctx, fmt.Sprintf("session_%s", inneruser.Session))
		DeleteCache(ctx, fmt.Sprintf("user_%s", inneruser.Id))
		DeleteCache(ctx, fmt.Sprintf("%s_workflows", inneruser.Id))
		DeleteCache(ctx, fmt.Sprintf("apps_%s", inneruser.Id))
		DeleteCache(ctx, fmt.Sprintf("apps_%s", inneruser.ActiveOrg.Id))
		DeleteCache(ctx, fmt.Sprintf("user_%s", inneruser.Username))
		DeleteCache(ctx, fmt.Sprintf("user_%s", inneruser.Id))

		DeleteCache(ctx, fmt.Sprintf("%s_childorgs", inneruser.ActiveOrg.Id))
	}

	// Checking if it's a special region. All user-specific requests should
	// go through shuffler.io and not subdomains
	if project.Environment == "cloud" {
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting Create Suborg request to main site handler (shuffler.io)")

			RedirectUserRequest(resp, request)
			return
		}
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Failed reading body in create suborg: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	type ReturnData struct {
		OrgId   string `json:"org_id" datastore:"org_id"`
		OrgName string `json:"org_name" datastore:"org_name"`
		Name    string `json:"name" datastore:"name"`
	}

	var tmpData ReturnData
	err = json.Unmarshal(body, &tmpData)
	if err != nil {
		log.Printf("[INFO] Failed unmarshalling test: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "The data is badly formatted"}`))
		return
	}

	if len(tmpData.OrgName) > 0 && len(tmpData.Name) == 0 {
		tmpData.Name = tmpData.OrgName
	}

	if len(tmpData.Name) < 3 {
		log.Printf("[WARNING] Suborgname too short (min 3) %s", tmpData.Name)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Name must at least be 3 characters. Required fields: org_id, name"}`))
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
		resp.Write([]byte(`{"success": false, "reason": "No permission to edit this org (1). Org Id has to match in the body and the request."}`))
		return
	}

	if len(parentOrg.ManagerOrgs) > 0 {
		log.Printf("[WARNING] Organization %s can't have suborgs, as it's as suborg", tmpData.OrgId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Can't make suborg of suborg. Switch to a parent org to make another."}`))
		return
	}

	if project.Environment == "cloud" {
		if !parentOrg.SyncFeatures.MultiTenant.Active && !parentOrg.LeadInfo.Customer && !parentOrg.LeadInfo.POV && !parentOrg.LeadInfo.Internal {
			log.Printf("[WARNING] Org %s is not allowed to make a sub-organization: %s", tmpData.OrgId, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Sub-organizations require an active subscription or to be in the POV stage with access to multi-tenancy. Contact support@shuffler.io to try it out."}`))
			return
		}

		/*
			if parentOrg.SyncUsage.MultiTenant.Counter >= parentOrg.SyncFeatures.MultiTenant.Limit || len(parentOrg.ChildOrgs) > int(parentOrg.SyncFeatures.MultiTenant.Limit) {
				log.Printf("[WARNING] Org %s is not allowed to make ANOTHER sub-organization. Limit reached!: %s", tmpData.OrgId, err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "Your limit of sub-organizations has been reached. Contact support to increase."}`))
				return
			}
		*/

		parentOrg.SyncUsage.MultiTenant.Counter += 1
		log.Printf("[DEBUG] Allowing suborg for %s because they have %d vs %d limit", parentOrg.Id, len(parentOrg.ChildOrgs), parentOrg.SyncFeatures.MultiTenant.Limit)
	}

	orgId := uuid.NewV4().String()
	newApps := parentOrg.ActiveApps
	if len(newApps) > 11 {
		// Do the last 10 apps, not 10 first
		newApps = newApps[len(newApps)-10:]
	}

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
		CloudSyncActive: parentOrg.CloudSyncActive,
		CreatorOrg:      tmpData.OrgId,
		Region:          parentOrg.Region,
		RegionUrl:       parentOrg.RegionUrl,

		Defaults: parentOrg.Defaults,

		// FIXME: Should this be here? Makes things slow~
		// Should only append apps owned by the parentorg itself
		ActiveApps: newApps,
	}

	// FIXME: This may be good to auto distribute no matter what
	// Then maybe the kms problem won't happen

	parentOrg.ChildOrgs = append(parentOrg.ChildOrgs, OrgMini{
		Name: tmpData.Name,
		Id:   orgId,
	})

	DeleteCache(ctx, fmt.Sprintf("%s_childorgs", parentOrg.Id))
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

		//if loopUser.Id == user.Id {
		//	continue
		//}

		foundUser, err := GetUser(ctx, loopUser.Id)
		if err != nil {
			log.Printf("[ERROR] User with Identifier %s doesn't exist: %s (update admins - create)", loopUser.Id, err)
			continue
		}

		// Random between 50-200ms
		mathrand.Seed(time.Now().UnixNano())
		randInt := mathrand.Intn(150)
		time.Sleep(time.Duration(randInt+50) * time.Millisecond)

		// Add org to user
		foundUser.Orgs = append(foundUser.Orgs, newOrg.Id)
		err = SetUser(ctx, foundUser, false)
		if err != nil {
			log.Printf("[ERROR] Failed updating user when setting creating suborg (update admins - update): %s ", err)
			continue
		}

		// Add user to org
		newOrg.Users = append(newOrg.Users, loopUser)
	}

	DeleteCache(ctx, fmt.Sprintf("%s_childorgs", newOrg.Id))
	err = SetOrg(ctx, newOrg, newOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Failed setting new org %s: %s", newOrg.Id, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	user.Orgs = append(user.Orgs, newOrg.Id)
	//log.Printf("[INFO] Usr orgs: %s (%d)", user.Orgs, len(user.Orgs))
	err = SetUser(ctx, &user, false)
	if err != nil {
		log.Printf("[WARNING] Failed updating user when setting creating suborg: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	log.Printf("[INFO] User %s SUCCESSFULLY ADDED child org %s (%s) for parent %s (%s)", user.Username, newOrg.Name, newOrg.Id, parentOrg.Name, parentOrg.Id)
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Successfully created new sub-org"}`)))

}

func getSignatureSample(org Org) PaymentSubscription {
	if len(org.Subscriptions) > 0 {
		for _, sub := range org.Subscriptions {
			if !sub.EulaSigned {
				return sub
			}
		}
	}

	//log.Printf("[DEBUG] No signature sample found for org %s", org.Id)

	parsedEula := GetOnpremPaidEula()
	if (org.LeadInfo.Customer || org.LeadInfo.POV || len(org.ManagerOrgs) > 0) && !org.LeadInfo.OpenSource {
		return PaymentSubscription{}

		name := "App execution units - default"
		if len(org.ManagerOrgs) > 0 {
			name = "Suborg access - default"
		}

		return PaymentSubscription{
			Active:           true,
			Startdate:        int64(time.Now().Unix()),
			CancellationDate: 0,
			Enddate:          0,
			Name:             name,
			Recurrence:       string("monthly"),
			Amount:           string(rune(100000)),
			Currency:         string("USD"),
			Level:            "1",
			Reference:        "TBD",
			Limit:            100000,
			Features: []string{
				"Custom Contract features",
				"Multi-Tenant & Multi-Region",
			},

			EulaSigned: true,
			Eula:       parsedEula,
		}
	} else if (org.LeadInfo.Customer || org.LeadInfo.POV) && org.LeadInfo.OpenSource {
		name := "Open Source Scale Units"
		licensedWorkerUrl := os.Getenv("LICENSED_WORKER_URL")
		nightlyWorkerUrl := os.Getenv("NIGHTLY_WORKER_URL")

		if !org.EulaSigned {
			licensedWorkerUrl = "Sign EULA first"
			nightlyWorkerUrl = "Sign EULA first"
		}

		features := []string{
			"Priority Support",
			fmt.Sprintf("App and Workflow development support"),
			"Documentation: https://shuffler.io/docs/configuration#scaling_shuffle_with_swarm",
			fmt.Sprintf("Stable Worker License:  %s", licensedWorkerUrl),
			fmt.Sprintf("Nightly Worker License: %s", nightlyWorkerUrl),
		}

		return PaymentSubscription{
			Name:             name,
			Active:           true,
			CancellationDate: 0,
			Enddate:          0,
			Startdate:        int64(time.Now().Unix()),
			Recurrence:       string("monthly"),
			Amount:           string(rune(600)),
			Currency:         string("USD"),
			Level:            "1",
			Reference:        "TBD",
			Limit:            1,
			Features:         features,

			EulaSigned: org.EulaSigned,
			Eula:       parsedEula,
		}
	}

	return PaymentSubscription{}
}

func HandleEditOrg(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Checking if it's a special region. All user-specific requests should
	// go through shuffler.io and not subdomains
	if project.Environment == "cloud" {
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting Edit Org request to main site handler (shuffler.io)")

			RedirectUserRequest(resp, request)
			return
		}
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
		resp.WriteHeader(403)
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
		Tutorial    string    `json:"tutorial" datastore:"tutorial"`
		Name        string    `json:"name" datastore:"name"`
		Image       string    `json:"image" datastore:"image"`
		CompanyType string    `json:"company_type" datastore:"company_type"`
		Description string    `json:"description" datastore:"description"`
		OrgId       string    `json:"org_id" datastore:"org_id"`
		Priority    string    `json:"priority" datastore:"priority"`
		Defaults    Defaults  `json:"defaults" datastore:"defaults"`
		SSOConfig   SSOConfig `json:"sso_config" datastore:"sso_config"`
		LeadInfo    []string  `json:"lead_info" datastore:"lead_info"`
		MFARequired bool      `json:"mfa_required" datastore:"mfa_required"`

		CreatorConfig string              `json:"creator_config" datastore:"creator_config"`
		Subscription  PaymentSubscription `json:"subscription" datastore:"subscription"`

		SyncFeatures SyncFeatures `json:"sync_features" datastore:"sync_features"`
		Billing      Billing      `json:"billing" datastore:"billing"`
	}

	var tmpData ReturnData
	err = json.Unmarshal(body, &tmpData)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshalling test: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}
	//log.Printf("SSO: %s", tmpData.SSOConfig)

	var fileId string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("Path too short: %d", len(location))
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	admin := false
	if tmpData.OrgId != user.ActiveOrg.Id || fileId != user.ActiveOrg.Id {
		log.Printf("[WARNING] User can't edit org %s (active: %s)", fileId, user.ActiveOrg.Id)
		if !user.SupportAccess {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "No permission to edit this org (2)"}`))
			return
		}

		log.Printf("[AUDIT] User %s (%s) is editing org %s (%s) with support access", user.Username, user.Id, fileId, user.ActiveOrg.Id)
		admin = true
	}

	ctx := GetContext(request)
	org, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("[WARNING] Organization doesn't exist: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

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

	if user.SupportAccess {
		log.Printf("[AUDIT] User %s (%s) is editing org %s (%s) with support access", user.Username, user.Id, fileId, user.ActiveOrg.Id)
		userFound = true
		admin = true
	}

	if !userFound && !user.SupportAccess {
		log.Printf("[WARNING] User %s doesn't exist in organization for edit %s", user.Id, org.Id)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if !admin {
		log.Printf("[WARNING] User %s doesn't have edit rights to %s", user.Id, org.Id)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	sendOrgUpdaterHook := false
	if len(tmpData.Image) > 0 {
		org.Image = tmpData.Image
	}

	if len(tmpData.Name) > 0 {
		org.Name = tmpData.Name
	}

	if len(tmpData.Description) > 0 {
		org.Description = tmpData.Description
	}

	if len(tmpData.Defaults.AppDownloadRepo) > 0 || len(tmpData.Defaults.AppDownloadBranch) > 0 || len(tmpData.Defaults.WorkflowDownloadRepo) > 0 || len(tmpData.Defaults.WorkflowDownloadBranch) > 0 || len(tmpData.Defaults.NotificationWorkflow) > 0 {
		org.Defaults = tmpData.Defaults
	}

	if len(tmpData.CompanyType) > 0 {
		org.CompanyType = tmpData.CompanyType

		if len(org.CompanyType) == 0 {
			sendOrgUpdaterHook = true
		}
	}

	if len(tmpData.Tutorial) > 0 {
		if tmpData.Tutorial == "welcome" {
			sendOrgUpdaterHook = true
		}
	}

	/*
		// Old code that had frontend buttons.
		// Now we discover this instead
			if len(tmpData.Priority) > 0 {
				if len(org.MainPriority) == 0 {
					org.MainPriority = tmpData.Priority
					sendOrgUpdaterHook = true
				}

				found := false
				for _, prio := range org.Priorities {
					if prio.Name == tmpData.Priority {
						found = true
					}
				}

				if !found {
					org.Priorities = append(org.Priorities, Priority{
						Name:        tmpData.Priority,
						Description: fmt.Sprintf("Priority %s decided by user.", tmpData.Priority),
						Type:        "usecases",
						Active:      true,
						URL:         fmt.Sprintf("/usecases"),
					})
				}
			}
	*/

	// Update Billing email alert threshold
	tmpDataAlert := tmpData.Billing.AlertThreshold
	orgAlertThreshold := org.Billing.AlertThreshold

	if len(tmpDataAlert) > 0 {
		if len(tmpDataAlert) != len(orgAlertThreshold) {
			org.Billing.AlertThreshold = tmpData.Billing.AlertThreshold
		} else {
			for i := 0; i < len(tmpDataAlert); i++ {
				if tmpDataAlert[i].Percentage != orgAlertThreshold[i].Percentage || tmpDataAlert[i].Count != orgAlertThreshold[i].Count {
					org.Billing.AlertThreshold = tmpData.Billing.AlertThreshold
					break
				}
			}
		}
	}

	//Update mfa required value
	if tmpData.MFARequired != org.MFARequired {
		org.MFARequired = tmpData.MFARequired
	}

	//if len(tmpData.SSOConfig) > 0 {
	if len(tmpData.SSOConfig.SSOEntrypoint) > 0 || len(tmpData.SSOConfig.OpenIdClientId) > 0 || len(tmpData.SSOConfig.OpenIdClientSecret) > 0 || len(tmpData.SSOConfig.OpenIdAuthorization) > 0 || len(tmpData.SSOConfig.OpenIdToken) > 0 {
		org.SSOConfig = tmpData.SSOConfig
	}
	// Check if there are new values for SSO entry point or certificate or SSORequired
	if (tmpData.SSOConfig.SSOEntrypoint != org.SSOConfig.SSOEntrypoint) ||
		(tmpData.SSOConfig.SSOCertificate != org.SSOConfig.SSOCertificate) ||
		(tmpData.SSOConfig.SSORequired != org.SSOConfig.SSORequired) {
		org.SSOConfig = tmpData.SSOConfig
	}

	if (tmpData.SSOConfig.OpenIdClientId != org.SSOConfig.OpenIdClientId) || (tmpData.SSOConfig.OpenIdAuthorization != org.SSOConfig.OpenIdAuthorization) {
		org.SSOConfig = tmpData.SSOConfig
	}

	if len(tmpData.SSOConfig.SSOCertificate) > 0 {
		savedCert := fixCertificate(tmpData.SSOConfig.SSOCertificate)

		log.Printf("[INFO] Stripped down cert from %d to %d", len(tmpData.SSOConfig.SSOCertificate), len(savedCert))

		org.SSOConfig.SSOCertificate = savedCert
	}

	if len(org.Defaults.NotificationWorkflow) > 0 && len(org.Defaults.NotificationWorkflow) != 36 {
		log.Printf("[WARNING] Notification Workflow ID %s is not valid.", org.Defaults.NotificationWorkflow)
	}

	if len(tmpData.LeadInfo) > 0 && user.SupportAccess {
		log.Printf("[INFO] Updating lead info for %s to %s", org.Id, tmpData.LeadInfo)

		// Make a new one, as to start with all from false
		newLeadinfo := LeadInfo{}

		for _, lead := range tmpData.LeadInfo {
			if lead == "contacted" {
				newLeadinfo.Contacted = true
			}

			if lead == "student" {
				newLeadinfo.Student = true
			}

			if lead == "lead" {
				newLeadinfo.Lead = true
			}

			if lead == "pov" {
				newLeadinfo.POV = true
			}

			if lead == "demo started" {
				newLeadinfo.DemoDone = true
			}

			if lead == "customer" {
				newLeadinfo.Customer = true
			}

			if lead == "old lead" {
				newLeadinfo.OldLead = true
			}

			if lead == "old customer" {
				newLeadinfo.OldCustomer = true
			}

			if lead == "opensource" || lead == "open source" {
				newLeadinfo.OpenSource = true
			}

			if lead == "internal" {
				newLeadinfo.Internal = true
			}

			if lead == "creator" {
				newLeadinfo.Creator = true
			}

			if lead == "tech partner" {
				newLeadinfo.TechPartner = true
			}
		}

		org.LeadInfo = newLeadinfo
	}

	if len(tmpData.CreatorConfig) > 0 {
		// Check if they're a creator already
		if tmpData.CreatorConfig == "join" {

			if org.CreatorId != "" {
				log.Printf("[WARNING] Org %s is already a creator", org.Id)
				resp.WriteHeader(400)
				resp.Write([]byte(`{"success": false}`))
				return
			}

			// Make md5 from current ID (to make it replicable)
			hasher := md5.New()
			hasher.Write([]byte(org.Id))
			creatorId := hex.EncodeToString(hasher.Sum(nil))

			log.Printf("[INFO] Org %s (%s) is joining creators with ID %s", org.Name, org.Id, creatorId)

			org.CreatorId = creatorId
			parsedCreatorUser := User{
				Id:       creatorId,
				Username: org.Name,
			}

			parsedCreatorUser.PublicProfile.GithubAvatar = org.Image
			parsedCreatorUser.PublicProfile.GithubUsername = org.Name

			HandleAlgoliaCreatorUpload(ctx, parsedCreatorUser, false, true)

			// Should create a new user with the same ID as the org creatorId
			// This is to save public information about the org, which is used for verifying access in all other APIs
			// In short: It's a way to NOT have to make all old Creator API's also support orgs. A hack, but it works

			// Try to get the user
			foundUser, err := GetUser(ctx, creatorId)
			if err != nil {
				log.Printf("[WARNING] Failed to get creator user %s: %s", creatorId, err)

				// Create the user
				creatorUser := parsedCreatorUser

				creatorUser.PublicProfile.Public = true
				creatorUser.PublicProfile.GithubUserid = org.CreatorId
				creatorUser.PublicProfile.GithubUsername = org.Name
				creatorUser.PublicProfile.GithubAvatar = org.Image

				SetUser(ctx, &creatorUser, false)

			} else {
				log.Printf("[INFO] Creator user %s already exists. Should set back to public.", creatorId)

				foundUser.PublicProfile.Public = true
				foundUser.PublicProfile.GithubUsername = org.Name
				SetUser(ctx, foundUser, false)

			}

			org.LeadInfo.Creator = true

		} else if tmpData.CreatorConfig == "leave" {
			log.Printf("[INFO] Org %s is leaving creators", org.Id)
			if org.CreatorId != "" {
				// Remove item with the ID from Algolia

				foundUser, err := GetUser(ctx, org.CreatorId)
				if err == nil {
					foundUser.PublicProfile.Public = false

					SetUser(ctx, foundUser, false)
				}

				err = HandleAlgoliaCreatorDeletion(ctx, org.CreatorId)
				if err != nil {
					log.Printf("[WARNING] Failed to remove creator %s (%s) from Algolia: %s", org.Name, org.CreatorId, err)
				} else {
					org.CreatorId = ""
				}
			}

			org.LeadInfo.Creator = false
		}
	}

	if tmpData.Subscription.EulaSigned == true {
		log.Printf("[DEBUG] EULA signed for %s", org.Id)

		// Compare cloud vs onprem
		sigSample := getSignatureSample(*org)
		if len(sigSample.Eula) > 0 && sigSample.Eula == tmpData.Subscription.Eula && sigSample.Name == tmpData.Subscription.Name && sigSample.Active {
			for subIndex, sub := range org.Subscriptions {
				if len(sub.EulaSignedBy) == 0 {
					org.Subscriptions[subIndex].EulaSignedBy = user.Username
				}
			}

			org.Subscriptions = append(org.Subscriptions, tmpData.Subscription)

			org.EulaSignedBy = user.Username
			org.EulaSigned = true
		}
	}

	if project.Environment == "cloud" && user.SupportAccess && tmpData.SyncFeatures.Editing {
		log.Printf("[DEBUG] Updating features for org %s (%s)", org.Name, org.Id)

		org.SyncFeatures = tmpData.SyncFeatures
		org.SyncFeatures.Editing = false
	}

	// Built a system around this now, which checks for the actual org.
	// if requestdata.Environment == "cloud" && project.Environment != "cloud" {
	//if project.Environment != "cloud" && len(org.SSOConfig.SSOEntrypoint) > 0 && len(org.ManagerOrgs) == 0 {
	//	//log.Printf("[INFO] Should set SSO entrypoint to %s", org.SSOConfig.SSOEntrypoint)
	//	SSOUrl = org.SSOConfig.SSOEntrypoint
	//}

	//log.Printf("Org: %s", org)
	err = SetOrg(ctx, *org, org.Id)
	if err != nil {
		log.Printf("[WARNING] Failed to edit org %s: %s", org.Id, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Sends tracker for this on cloud
	if sendOrgUpdaterHook && project.Environment == "cloud" {
		signupWebhook := os.Getenv("WEBSITE_ORG_WEBHOOK")
		if strings.HasPrefix(signupWebhook, "http") {
			curIndex := -1
			for orgIndex, orguser := range org.Users {
				if orguser.Id == user.Id {
					curIndex = orgIndex
				}
			}

			if curIndex >= 0 {
				user.Password = ""
				user.Session = ""
				user.ApiKey = ""
				user.LoginInfo = []LoginInfo{}
				user.PrivateApps = []WorkflowApp{}

				org.Users[curIndex] = user
			}

			mappedData, err := json.Marshal(org)
			if err != nil {
				log.Printf("[WARNING] Marshal error for org sending: %s", err)
			} else {
				req, err := http.NewRequest(
					"POST",
					signupWebhook,
					bytes.NewBuffer(mappedData),
				)

				client := &http.Client{
					Timeout: 3 * time.Second,
				}

				req.Header.Add("Content-Type", "application/json")
				res, err := client.Do(req)
				if err != nil {
					log.Printf("[ERROR] Failed request to signup webhook FOR ORG (2): %s", err)
				} else {
					log.Printf("[INFO] Successfully ran org priority webhook")
				}

				defer res.Body.Close()
			}
		}
	}

	GetTutorials(ctx, *org, true)

	log.Printf("[INFO] Successfully updated org %s (%s) with %d priorities", org.Name, org.Id, len(org.Priorities))
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Successfully updated org"}`)))

}

func sendMailSendgrid(toEmail []string, subject, body string, emailApp bool) error {
	log.Printf("[DEBUG] In mail sending with subject %s and body length %s. TO: %s", subject, body, toEmail)
	srequest := sendgrid.GetRequest(os.Getenv("SENDGRID_API_KEY"), "/v3/mail/send", "https://api.sendgrid.com")
	srequest.Method = "POST"

	type SendgridContent struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}

	type SendgridEmail struct {
		Email string `json:"email"`
	}

	type SendgridPersonalization struct {
		To      []SendgridEmail `json:"to"`
		Subject string          `json:"subject"`
	}

	type sendgridMailBody struct {
		Personalizations []SendgridPersonalization `json:"personalizations"`
		From             SendgridEmail             `json:"from"`
		Content          []SendgridContent         `json:"content"`
	}

	body = strings.Replace(body, "\n", "<br/>", -1)

	newBody := sendgridMailBody{
		Personalizations: []SendgridPersonalization{
			SendgridPersonalization{
				To:      []SendgridEmail{},
				Subject: subject,
			},
		},
		From: SendgridEmail{
			Email: "Shuffle Support <shuffle-support@shuffler.io>",
		},
		Content: []SendgridContent{
			SendgridContent{
				Type:  "text/html",
				Value: body,
			},
		},
	}

	if emailApp {
		newBody.From.Email = "Shuffle Email App <email-app@shuffler.io>"
	}

	for _, email := range toEmail {
		newBody.Personalizations[0].To = append(newBody.Personalizations[0].To,
			SendgridEmail{
				Email: strings.TrimSpace(email),
			})
	}

	parsedBody, err := json.Marshal(newBody)
	if err != nil {
		log.Printf("[ERROR] Failed to parse JSON in sendmail: %s", err)
		return err
	}

	srequest.Body = parsedBody

	log.Printf("[DEBUG] Email: %s\n\n", srequest.Body)

	response, err := sendgrid.API(srequest)
	if err != nil {
		log.Println(err)
	} else {
		if response.StatusCode >= 300 {
			log.Printf("[DEBUG] Failed sending mail! Statuscode: %d. Body: %s", response.StatusCode, response.Body)
		} else {
			log.Printf("[DEBUG] Successfully sent email! Statuscode: %d. Body: %s", response.StatusCode, response.Body)
		}
		return nil
		//log.Printf(response.Headers)
	}

	return err
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

	ctx := GetContext(request)
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
	//log.Printf("Abort info: %s vs %s", workflowExecution.Authorization, parsedKey)
	if workflowExecution.Authorization != parsedKey {
		user, err := HandleApiAuthentication(resp, request)
		if err != nil {
			log.Printf("[AUDIT] Api authentication failed in abort workflow: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

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

		if len(result.Result) > 0 && result.Status == "SUCCESS" {
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

	parsedReason := "An error occurred during execution of this node. This may be due to the Workflow being Aborted, or an error in the node itself."
	reason, reasonok := request.URL.Query()["reason"]
	if reasonok {
		parsedReason = reason[0]

		// Custom reason handler for weird inputs
		if strings.Contains(parsedReason, "manifest for registry") {
			foundImageSplit := strings.Split(parsedReason, " ")
			foundImage := ""
			if len(foundImageSplit) > 7 {
				foundImage = foundImageSplit[6]

				foundImageSplit = strings.Split(foundImageSplit[6], ":")
				if len(foundImageSplit) > 1 {
					foundImage = foundImageSplit[1]
				}
			}

			parsedReason = fmt.Sprintf("Couldn't find the Docker image %s. Did you activate the app?", foundImage)
		}
	}

	returnData := SubflowData{
		Success: false,
		Result:  parsedReason,
	}

	reasonData, err := json.Marshal(returnData)
	if err != nil {
		reasonData = []byte(parsedReason)
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
			Result:        string(reasonData),
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
					Result:        string(reasonData),
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

	// This is the same as aborted
	IncrementCache(ctx, workflowExecution.ExecutionOrg, "workflow_executions_failed")
	err = SetWorkflowExecution(ctx, *workflowExecution, true)
	if err != nil {
		log.Printf("[WARNING] Error saving workflow execution for updates when aborting (2) %s: %s", topic, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed setting workflowexecution status to abort"}`)))
		return
	} else {
		log.Printf("[INFO][%s] Set workflowexecution to aborted.", workflowExecution.ExecutionId)
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
		Type           string `json:"type"`
		Description    string `json:"description"`
		Id             string `json:"id"`
		Name           string `json:"name"`
		Workflow       string `json:"workflow"`
		Start          string `json:"start"`
		Environment    string `json:"environment"`
		Auth           string `json:"auth"`
		CustomResponse string `json:"custom_response"`
		Version        string `json:"version" datastore:"version"`
		VersionTimeout int    `json:"version_timeout" datastore:"version_timeout"`
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Body data error in webhook set: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := GetContext(request)
	var requestdata requestData
	err = json.Unmarshal([]byte(body), &requestdata)
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
		log.Printf("[WARNING] Type %s is not valid. Try any of these: %s", requestdata.Type, strings.Join(validTypes, ", "))
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Let remote endpoint handle access checks (shuffler.io)
	baseUrl := "https://shuffler.io"
	if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
		baseUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
	}

	if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
		baseUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
	}

	currentUrl := fmt.Sprintf("%s/api/v1/hooks/webhook_%s", baseUrl, newId)
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
			Url:         fmt.Sprintf("%s/api/v1/hooks/webhook_%s", baseUrl, newId),
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
		Running:        false,
		OrgId:          user.ActiveOrg.Id,
		Environment:    requestdata.Environment,
		Auth:           requestdata.Auth,
		CustomResponse: requestdata.CustomResponse,
		Version:        requestdata.Version,
		VersionTimeout: requestdata.VersionTimeout,
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

	// Check if fileId has the prefix "webhook_"
	if strings.HasPrefix(fileId, "webhook_") {
		fileId = strings.TrimPrefix(fileId, "webhook_")
	}

	if len(fileId) != 36 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID when deleting hook is not valid"}`))
		return
	}

	ctx := GetContext(request)
	hook, err := GetHook(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Failed getting hook %s (delete): %s", fileId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	//if user.Id != hook.Owner && user.ActiveOrg.Id != hook.OrgId {
	//	log.Printf("[WARNING] Wrong user (%s) for workflow %s", user.Username, hook.Id)
	//	resp.WriteHeader(401)
	//	resp.Write([]byte(`{"success": false}`))
	//	return
	//}

	if user.Id != hook.Owner || len(user.Id) == 0 {
		if hook.OrgId == user.ActiveOrg.Id && user.Role == "admin" {
			log.Printf("[AUDIT] User %s is stopping hook for workflow %s as admin. Owner: %s", user.Username, hook.Workflows[0], hook.Owner)
		} else {
			log.Printf("[AUDIT] Wrong user (%s) for hook %s (stop hook)", user.Username, hook.Workflows[0])
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
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
	log.Printf("Versions: %s", versions)

	//versions = sort.Sort(semver.Collection(versions))
	return versions
}

func GetWorkflowAppConfig(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	if project.Environment == "cloud" {
		// Checking if it's a special region. All user-specific requests should
		// go through shuffler.io and not subdomains
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting App request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
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

	//log.Printf("[INFO] Running GetWorkflowAppConfig for '%s'", fileId)

	ctx := GetContext(request)
	app, err := GetApp(ctx, fileId, User{}, false)
	if err != nil {
		log.Printf("[WARNING] Error getting app %s (app config): %s", fileId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "App doesn't exist"}`))
		return
	}

	log.Printf("[INFO] Successfully got app %s", fileId)

	app.ReferenceUrl = ""
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

	openapi, openapiok := request.URL.Query()["openapi"]
	//if app.Sharing || app.Public || (project.Environment == "cloud" && user.Id == "what") {
	//log.Printf("SHARING: %s. PUBLIC: %s", app.Sharing, app.Public)
	if app.Sharing || app.Public {
		if openapiok && len(openapi) > 0 && strings.ToLower(openapi[0]) == "false" {
			log.Printf("[DEBUG] Returning app '%s' without OpenAPI", fileId)
		} else {
			//log.Printf("CAN SHARE APP!")
			parsedApi, err := GetOpenApiDatastore(ctx, fileId)
			if err != nil {
				log.Printf("[WARNING] OpenApi doesn't exist for (0): %s - err: %s. Returning basic app", fileId, err)
				resp.WriteHeader(200)
				resp.Write(appdata)
				return
			}

			if len(parsedApi.Body) > 0 {
				if len(parsedApi.ID) > 0 {
					parsedApi.Success = true
				} else {
					parsedApi.Success = false
				}

				//log.Printf("PARSEDAPI: %s", parsedApi)
				openapidata, err := json.Marshal(parsedApi)
				if err != nil {
					log.Printf("[WARNING] Error parsing api json: %s", err)
					resp.WriteHeader(422)
					resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed marshalling new parsed swagger: %s"}`, err)))
					return
				}

				appReturn.OpenAPI = openapidata
			}
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

	// Modified to make it so users admins in same org can modify an app
	//log.Printf("User: %s, role: %s, org: %s vs %s", user.Username, user.Role, user.ActiveOrg.Id, app.ReferenceOrg)
	if project.Environment != "cloud" && len(app.ReferenceOrg) == 0 {
		app.ReferenceOrg = user.ActiveOrg.Id
	}

	if user.Id == app.Owner || user.ActiveOrg.Id == app.ReferenceOrg || ArrayContains(app.Contributors, user.Id) {

		log.Printf("[DEBUG] Got app %s with user %s (%s) in org %s", app.ID, user.Username, user.Id, user.ActiveOrg.Id)

	} else {
		if project.Environment == "cloud" && user.Verified == true && user.Active == true && user.SupportAccess == true && strings.HasSuffix(user.Username, "@shuffler.io") {
			log.Printf("[AUDIT] Support & Admin user %s (%s) got access to app %s (cloud only)", user.Username, user.Id, app.ID)
		} else if user.Role == "admin" && app.Owner == "" {
			log.Printf("[AUDIT] Any admin can GET %s (%s), since it doesn't have an owner (GET).", app.Name, app.ID)
		} else {
			exit := true

			log.Printf("[INFO] Check published app reference ID: %#v", app.PublishedId)
			if len(app.PublishedId) > 0 {

				// FIXME: is this privacy / vulnerability?
				// Allows parent owner to see child usage.
				// Intended to allow vision of changes, and have parent app suggestions be possible
				parentapp, err := GetApp(ctx, app.PublishedId, user, false)
				if err == nil {
					if parentapp.Owner == user.Id {
						log.Printf("[AUDIT] Parent app owner %s got access to child app %s (%s)", user.Username, user.Id, app.Name, app.ID)
						exit = false
						//app, err := GetApp(ctx, fileId, User{}, false)
					}
				}
			}

			if exit {
				log.Printf("[AUDIT] Wrong user (%s) for app %s (%s) - get app config", user.Username, app.Name, app.ID)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false}`))
				return
			}
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

func verifier() (*CodeVerifier, error) {
	r := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 32, 32)
	for i := 0; i < 32; i++ {
		b[i] = byte(r.Intn(255))
	}
	return CreateCodeVerifierFromBytes(b)
}

func GetOpenIdUrl(request *http.Request, org Org) string {
	baseSSOUrl := org.SSOConfig.OpenIdAuthorization

	codeChallenge := uuid.NewV4().String()
	//h.Write([]byte(v.Value))
	verifier, verifiererr := verifier()
	if verifiererr == nil {
		codeChallenge = verifier.Value
	}

	//log.Printf("[DEBUG] Got challenge value %s (pre state)", codeChallenge)

	// https://192.168.55.222:3443/api/v1/login_openid
	//location := strings.Split(request.URL.String(), "/")
	//redirectUrl := url.QueryEscape("http://localhost:5001/api/v1/login_openid")
	redirectUrl := url.QueryEscape(fmt.Sprintf("http://%s/api/v1/login_openid", request.Host))
	if project.Environment == "cloud" {
		redirectUrl = url.QueryEscape(fmt.Sprintf("https://shuffler.io/api/v1/login_openid"))
	}

	if project.Environment != "cloud" && strings.Contains(request.Host, "shuffle-backend") && !strings.Contains(os.Getenv("BASE_URL"), "shuffle-backend") {
		redirectUrl = url.QueryEscape(fmt.Sprintf("%s/api/v1/login_openid", os.Getenv("BASE_URL")))
	}

	if project.Environment != "cloud" && len(os.Getenv("SSO_REDIRECT_URL")) > 0 {
		redirectUrl = url.QueryEscape(fmt.Sprintf("%s/api/v1/login_openid", os.Getenv("SSO_REDIRECT_URL")))
	}

	state := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("org=%s&challenge=%s&redirect=%s", org.Id, codeChallenge, redirectUrl)))

	// has to happen after initial value is stored
	if verifiererr == nil {
		codeChallenge = verifier.CodeChallengeS256()
	}

	//log.Printf("[DEBUG] Got challenge value %s (POST state)", codeChallenge)

	if len(org.SSOConfig.OpenIdClientSecret) > 0 {

		//baseSSOUrl += fmt.Sprintf("?client_id=%s&response_type=code&scope=openid&redirect_uri=%s&state=%s&client_secret=%s", org.SSOConfig.OpenIdClientId, redirectUrl, state, org.SSOConfig.OpenIdClientSecret)
		state := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("org=%s&redirect=%s&challenge=%s", org.Id, redirectUrl, org.SSOConfig.OpenIdClientSecret)))
		//log.Printf("[INFO] URL: %s", redirectUrl)

		baseSSOUrl += fmt.Sprintf("?client_id=%s&response_type=id_token&scope=openid&redirect_uri=%s&state=%s&response_mode=form_post&nonce=%s", org.SSOConfig.OpenIdClientId, redirectUrl, state, state)
		//baseSSOUrl += fmt.Sprintf("&client_secret=%s", org.SSOConfig.OpenIdClientSecret)
		//log.Printf("[DEBUG] Found OpenID url (client secret). Extra redirect check: %s - %s", request.URL.String(), baseSSOUrl)
	} else {
		//log.Printf("[DEBUG] Found OpenID url (PKCE!!). Extra redirect check: %s", request.URL.String())
		baseSSOUrl += fmt.Sprintf("?client_id=%s&response_type=code&scope=openid&redirect_uri=%s&state=%s&code_challenge_method=S256&code_challenge=%s", org.SSOConfig.OpenIdClientId, redirectUrl, state, codeChallenge)
	}

	return baseSSOUrl
}

func GetRequestIp(r *http.Request) string {
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		// The X-Forwarded-For header can contain a comma-separated list of IP addresses.
		// The client's IP is usually the first one.
		stringSplit := strings.Split(forwardedFor, ",")
		if len(stringSplit) > 1 {
			log.Printf("[DEBUG] Found multiple IPs in X-Forwarded-For header: %s", forwardedFor)
			return stringSplit[0]
		} else {
			return forwardedFor
		}
	}

	// Check for the X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		if strings.Count(realIP, ":") == 1 {
			return strings.Split(realIP, ":")[0]
		}

		return realIP
	}

	realIP = r.Header.Get("CF-Connecting-IP")
	if realIP != "" {
		if strings.Count(realIP, ":") == 1 {
			return strings.Split(realIP, ":")[0]
		}

		return realIP
	}

	realIP = r.Header.Get("X-Appengine-User-Ip")
	if realIP != "" {
		if strings.Count(realIP, ":") == 1 {
			return strings.Split(realIP, ":")[0]
		}

		return realIP
	}

	// Loop through and find headers with "IP" in them
	for k, v := range r.Header {
		if strings.Contains(strings.ToLower(k), "ip") {
			log.Printf("[ERROR] Found useful unhandled IP header %s: %s", k, v)
		}
	}

	// If neither header is present, fall back to using the RemoteAddr field.
	// Check for IPv6 and split accordingly.

	re := regexp.MustCompile(`\[[^\]]+\]`)
	remoteAddr := re.ReplaceAllString(r.RemoteAddr, "")
	if remoteAddr != "" {
		return remoteAddr
	}

	remoteAddrSplit := strings.Split(r.RemoteAddr, ":")
	return remoteAddrSplit[0]

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
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting LOGIN request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
	}

	err := ValidateRequestOverload(resp, request)
	if err != nil {
		log.Printf("[INFO] Request overload for IP %s in login", GetRequestIp(request))
		resp.WriteHeader(429)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Too many requests"}`)))
		return
	}

	// Gets a struct of Username, password
	data, err := ParseLoginParameters(resp, request)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
		return
	}

	log.Printf("[AUDIT] Handling SSO login of %s", data.Username)

	data.Username = strings.ToLower(strings.TrimSpace(data.Username))
	err = checkUsername(data.Username)
	if err != nil {
		log.Printf("[INFO] Username is too short or bad for %s: %s", data.Username, err)
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
				log.Printf(`[AUDIT] Username %s (%s) isn't valid (2). Amount of users checked: %d (1)`, user.Username, user.Id, len(users))
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

	// Starting caching of the username
	// This is to make it faster later :)
	go GetAllWorkflowsByQuery(context.Background(), userdata)
	go GetPrioritizedApps(context.Background(), userdata)

	/*
			// FIXME: Reenable activation?
		if project.Environment == "cloud" && !userdata.Active {
			log.Printf("[DEBUG] %s is not active, but tried to login. Error: %v", data.Username, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "This user is deactivated"}`))
			return
		}
	*/

	updateUser := false
	if project.Environment == "cloud" {
		if strings.HasSuffix(strings.ToLower(userdata.Username), "@shuffler.io") {
			if !userdata.Active {
				log.Printf("[INFO] User %s with @shuffler suffix is not active.", userdata.Username)
				resp.WriteHeader(401)
				resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "error: You need to activate your account before logging in"}`)))
				return
			}
		}
	}

	org, err := GetOrg(ctx, userdata.ActiveOrg.Id)
	if err == nil {
		//log.Printf("Got org during signin: %s - checking SAML SSO", baseOrg.Id)
		ssoRequired := org.SSOConfig.SSORequired
		if ssoRequired {
			orgFound := false
			for _, orgString := range userdata.Orgs {
				innerorg, err := GetOrg(ctx, orgString)
				if err != nil {
					log.Printf("[ERROR] Failed getting org %s: %s", orgString, err)
					continue
				}

				if innerorg.SSOConfig.SSORequired {
					continue
				}

				log.Printf("[INFO] Found Non-SSO org %s (%s) for user %s (%s)", innerorg.Name, innerorg.Id, userdata.Username, userdata.Id)
				org = innerorg
				userdata.ActiveOrg.Id = innerorg.Id
				userdata.ActiveOrg.Name = innerorg.Name
				orgFound = true
				break
			}

			if !orgFound {

				log.Printf("[INFO] Inside SSO / OpenID check: %s", org.Id)
				// has to contain http(s)
				baseSSOUrl := org.SSOConfig.SSOEntrypoint
				redirectKey := "SSO_REDIRECT"
				if len(org.SSOConfig.OpenIdAuthorization) > 0 {
					log.Printf("[INFO] OpenID login for %s", org.Id)
					redirectKey = "SSO_REDIRECT"

					baseSSOUrl = GetOpenIdUrl(request, *org)
				}

				log.Printf("[DEBUG] Login: Should redirect user %s in org %s(%s) to SSO login at %s", userdata.Username, userdata.ActiveOrg.Name, userdata.ActiveOrg.Id, baseSSOUrl)

				// Check if the user has other orgs that can be swapped to - if so SWAP
				if !strings.HasPrefix(baseSSOUrl, "http") {
					log.Printf("[ERROR] SSO URL for %s (%s) is invalid: %s", org.Name, org.Id, baseSSOUrl)
					//resp.WriteHeader(401)
					//resp.Write([]byte(`{"success": false, "reason": "SSO URL is invalid"}`))
					//return
				} else {
					// Check if the user has other orgs that can be swapped to - if so SWAP
					log.Printf("[DEBUG] Change org: Should redirect user %s in org %s (%s) to SSO login at %s", userdata.Username, userdata.ActiveOrg.Name, userdata.ActiveOrg.Id, baseSSOUrl)
					ssoResponse := SSOResponse{
						Success: true,
						Reason:  redirectKey,
						URL:     baseSSOUrl,
					}

					b, err := json.Marshal(ssoResponse)
					if err != nil {
						log.Printf("[ERROR] Failed marshalling SSO response: %s", err)
						resp.Write([]byte(`{"success": false}`))
						return
					}

					resp.WriteHeader(200)
					resp.Write(b)
					return
				}

			}
		}
	}

	if len(users) == 1 && len(data.Password) > 0 {
		err = bcrypt.CompareHashAndPassword([]byte(userdata.Password), []byte(data.Password))
		if err != nil {
			userdata = User{}
			log.Printf("[WARNING] Bad password: %s", err)
		} else {
			log.Printf("[DEBUG] Correct password with single user!")
		}
	}

	if userdata.Id == "" && userdata.Username == "" {
		log.Printf(`[AUDIT] Login for Username %s isn't valid with that password. Amount of users checked: %d (2)`, data.Username, len(users))
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

	if len(data.MFACode) == 0 {
		for _, orgID := range userdata.Orgs {
			org, err := GetOrg(ctx, orgID)
			if err != nil {
				log.Printf("[ERROR] Failed getting org %s during login: %s", orgID, err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "Failed getting org"}`))
				return
			}
			if org.MFARequired {
				if org.MFARequired && !userdata.MFA.Active {
					log.Printf("MFA is required for org %s and user has not set up MFA.", orgID)

					// Generate a unique code
					MFACode := uuid.NewV4().String()

					cacheKey := fmt.Sprintf("user_id_%s", MFACode)

					err := SetCache(ctx, cacheKey, []byte(userdata.Id), 30)
					if err != nil {
						log.Printf("[ERROR] Failed setting cache for user %s: %s", userdata.Username, err)
						resp.WriteHeader(500)
						resp.Write([]byte(`{"success": false, "reason": "Failed setting cache"}`))
						return
					}

					cacheKey = fmt.Sprintf("mfa_code_%s", MFACode)
					err = SetCache(ctx, cacheKey, []byte(MFACode), 30)
					if err != nil {
						log.Printf("[ERROR] Failed setting cache for user %s: %s", userdata.Username, err)
						resp.WriteHeader(500)
						resp.Write([]byte(`{"success": false, "reason": "Failed setting cache"}`))
						return
					}

					response := fmt.Sprintf(`{"success": true, "reason": "MFA_SETUP", "url": "%s"}`, MFACode)
					resp.WriteHeader(200)
					resp.Write([]byte(response))
					return
				}
				log.Printf("MFA is required for org %s. Redirecting.", orgID)
				resp.WriteHeader(409)
				resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "MFA_REDIRECT"}`)))
				return
			}
		}
	}

	if userdata.MFA.Active && len(data.MFACode) == 0 {
		log.Printf(`[DEBUG] Username %s (%s) has MFA activated. Redirecting.`, userdata.Username, userdata.Id)
		resp.WriteHeader(409)
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

	// This is a hack to get the real IP address
	// https://stackoverflow.com/questions/27234861/golang-http-request-returns-127-0-0-1
	userdata.LoginInfo = append(userdata.LoginInfo, LoginInfo{
		IP:        GetRequestIp(request),
		Timestamp: time.Now().Unix(),
	})

	tutorialsFinished := []Tutorial{}
	for _, tutorial := range userdata.PersonalInfo.Tutorials {
		tutorialsFinished = append(tutorialsFinished, Tutorial{
			Name: tutorial,
		})
	}

	if len(org.Id) == 0 {
		newOrg, err := GetOrg(ctx, userdata.ActiveOrg.Id)
		if err == nil {
			org = newOrg
		}
	}

	if len(org.SecurityFramework.SIEM.Name) > 0 || len(org.SecurityFramework.Network.Name) > 0 || len(org.SecurityFramework.EDR.Name) > 0 || len(org.SecurityFramework.Cases.Name) > 0 || len(org.SecurityFramework.IAM.Name) > 0 || len(org.SecurityFramework.Assets.Name) > 0 || len(org.SecurityFramework.Intel.Name) > 0 || len(org.SecurityFramework.Communication.Name) > 0 {
		tutorialsFinished = append(tutorialsFinished, Tutorial{
			Name: "find_integrations",
		})
	}

	for _, tutorial := range org.Tutorials {
		tutorialsFinished = append(tutorialsFinished, tutorial)
	}

	//log.Printf("[INFO] Tutorials finished: %v", tutorialsFinished)

	returnValue := HandleInfo{
		Success:   true,
		Tutorials: tutorialsFinished,
	}

	loginData := `{"success": true}`
	newData, err := json.Marshal(returnValue)
	if err == nil {
		loginData = string(newData)
	}

	// On cloud, we just generate a new org for them on the fly
	// Onprem, the user shouldn't exist anymore, which means you would need to re-register. You should only get to this point if the user exists
	if project.Environment != "cloud" {

		// Check activeorg if they have access to it (the user)
		found := false
		foundOrg, err := GetOrg(ctx, userdata.ActiveOrg.Id)
		if err == nil {
			log.Printf("[DEBUG] Found org %s for user %s (%s).", userdata.ActiveOrg.Id, userdata.Username, userdata.Id)
			for _, foundUser := range foundOrg.Users {
				if foundUser.Id == userdata.Id {
					found = true
					break
				}
			}

			if !found {
				log.Printf("[DEBUG] Failed to find user %s (%s) in org %s", userdata.Username, userdata.Id, userdata.ActiveOrg.Id)
			}

			if !found && len(foundOrg.Users) == 0 {
				// Forcefully add the user back in there (org)
				err = fixOrgUsers(ctx, *foundOrg)
				if err != nil {
					log.Printf("[ERROR] Failed fixing org %s while re-adding a user: %s", foundOrg.Id, err)
				}
			}
		} else {
			log.Printf("[ERROR] Failed finding org %s during login: %s", userdata.ActiveOrg.Id, err)
		}

		// Check if we need to move them over (move the activeOrg to other user org)
		if !found {
			log.Printf("[DEBUG] Current active org (%s) for user %s (%s) not found. Checking other orgs. Found %d orgs.", userdata.ActiveOrg.Id, userdata.Username, userdata.Id, len(userdata.Orgs))
			userdata.Role = "admin"
			userdata.Roles = []string{"admin"}
			for _, org := range userdata.Orgs {
				// Verify if the user is in the org and if it points to an org but
				// that does not exist we create re-create that org.
				foundOrg, err := GetOrg(ctx, org)
				if err != nil {
					log.Printf("[WARNING] Failed finding org %s: %s. Trying to recreate the org", org, err)

					rOrg := Org{
						Name:      "default",
						Id:        org,
						Org:       "default",
						Users:     []User{userdata},
						Roles:     userdata.Roles,
						CloudSync: false,
					}

					err := SetOrg(ctx, rOrg, org)
					found = true

					if err != nil {
						log.Printf("[ERROR] Failed to re-create the org")
						found = false
					}

					log.Printf("[DEBUG] Re-created the org %s", org)
				}

				for _, foundUser := range foundOrg.Users {
					if foundUser.Id == userdata.Id {
						found = true
						break
					}
				}

				if found {
					break
				}
			}
		}

		// User has no orgs after all checks, create a default
		if !found {

			// Check all the workflows has orgs and user
			workflows, err := GetAllWorkflows(ctx)
			log.Printf("[DEBUG] Checking all the worflows and finding user a org.")
			userdata.Role = "admin"
			userdata.Roles = []string{"admin"}
			for _, workflow := range workflows {
				for _, vOrg := range workflow.Org {

					wOrg, err := GetOrg(ctx, vOrg.Id)

					if err != nil {
						log.Printf("[WARNING] Faild getting a org %s for a workflow %s", vOrg.Id, workflow.ID)
						log.Printf("[DEBUG] Recreating the org %s", vOrg.Id)

						WorkflowOrg := Org{
							Name:      vOrg.Name,
							Id:        vOrg.Id,
							Org:       vOrg.Name,
							Users:     []User{},
							Roles:     []string{vOrg.Role},
							CloudSync: false,
						}

						err := SetOrg(ctx, WorkflowOrg, vOrg.Id)

						if err != nil {
							log.Printf("[ERROR] Failed setting a org")
						}
					}

					err = fixOrgUsers(ctx, *wOrg)
					if err != nil {
						log.Printf("[ERROR] %s", err)
					}
				}
			}
			log.Printf("[WARNING] User %s (%s) has no orgs. ID: %s, Name: %s. Creating a default one.", userdata.Username, userdata.Id, userdata.ActiveOrg.Id, userdata.ActiveOrg.Name)

			orgSetupName := "default"
			orgId := uuid.NewV4().String()
			newOrg := Org{
				Name:      orgSetupName,
				Id:        orgId,
				Org:       orgSetupName,
				Users:     []User{userdata},
				Roles:     userdata.Roles,
				CloudSync: false,
			}

			err = SetOrg(ctx, newOrg, newOrg.Id)

			if err != nil {
				log.Printf("[ERROR] Failed setting default org for the user: %s", userdata.Username)
			} else {
				log.Printf("[DEBUG] Successfully created the default org!")

				defaultEnv := os.Getenv("ORG_ID")
				if len(defaultEnv) == 0 {
					defaultEnv = "Shuffle"
					log.Printf("[DEBUG] Setting default environment for org to %s", defaultEnv)
				}

				item := Environment{
					Name:    defaultEnv,
					Type:    "onperm",
					OrgId:   orgId,
					Default: true,
					Id:      uuid.NewV4().String(),
				}

				err := SetEnvironment(ctx, &item)
				if err != nil {
					log.Printf("[ERROR] Failed setting up new environment for new org: %s", err)
				}

				userdata.Orgs = append(userdata.Orgs, newOrg.Id)
			}
			userdata.ActiveOrg.Id = userdata.Orgs[0]
		}
	}

	if len(userdata.Session) != 0 {
		log.Printf("[INFO] User session exists - resetting session")
		expiration := time.Now().Add(3600 * time.Second)

		newCookie := &http.Cookie{
			Name:    "session_token",
			Value:   userdata.Session,
			Expires: expiration,
			Path:    "/",
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
		log.Printf("[INFO] User session for %s (%s) is empty - create one!", userdata.Username, userdata.Id)

		sessionToken := uuid.NewV4().String()
		expiration := time.Now().Add(3600 * time.Second)
		newCookie := &http.Cookie{
			Name:    "session_token",
			Value:   sessionToken,
			Expires: expiration,
			Path:    "/",
		}

		if project.Environment == "cloud" {
			newCookie.Domain = ".shuffler.io"
			newCookie.Secure = true
			newCookie.HttpOnly = true
		}

		// Does it not set both?
		http.SetCookie(resp, newCookie)

		newCookie.Name = "__session"
		http.SetCookie(resp, newCookie)

		// ADD TO DATABASE
		err = SetSession(ctx, userdata, sessionToken)
		if err != nil {
			log.Printf("[DEBUG] Error adding session to database: %s", err)
		}

		userdata.Session = sessionToken

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

		err = SetUser(ctx, &userdata, true)
		if err != nil {
			log.Printf("[ERROR] Failed updating user when setting session: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false}`))
			return
		}

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

// FIXME: Do NOT use this yet (May 24th, 2024). It is not ready for production due to being a potential cross-tenant attack vector.
func HandleSSOLogin(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	if project.Environment == "cloud" {
		// Checking if it's a special region. All user-specific requests should
		// go through shuffler.io and not subdomains
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting LOGIN request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
	}

	err := ValidateRequestOverload(resp, request)
	if err != nil {
		log.Printf("[INFO] Request overload for IP %s in login", GetRequestIp(request))
		resp.WriteHeader(429)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Too many requests"}`)))
		return
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
		log.Printf("[INFO] Username is too short or bad for %s: %s", data.Username, err)
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
				log.Printf(`[AUDIT] Username %s (%s) isn't valid (2). Amount of users checked: %d (1)`, user.Username, user.Id, len(users))
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

	// Starting caching of the username
	// This is to make it faster later :)

	if project.Environment == "cloud" {
		if strings.HasSuffix(strings.ToLower(userdata.Username), "@shuffler.io") {
			if !userdata.Active {
				log.Printf("[INFO] User %s with @shuffler suffix is not active.", userdata.Username)
				resp.WriteHeader(401)
				resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "error: You need to activate your account before logging in"}`)))
				return
			}
		}
	}

	//log.Printf("[DEBUG] Are they using SSO?")
	// If it fails, allow login if password correct?
	// Check if suborg -> Get parent & check SSO
	//log.Printf("Got org during signin: %s - checking SAML SSO", baseOrg.Id)

	for _, orgString := range userdata.Orgs {
		org, err := GetOrg(ctx, orgString)
		if err != nil {
			log.Printf("[ERROR] Failed getting org %s during SSO login: %s", userdata.ActiveOrg.Id, err)
			continue
		}

		if len(org.SSOConfig.SSOEntrypoint) == 0 || len(org.SSOConfig.OpenIdAuthorization) == 0 || len(org.SSOConfig.OpenIdClientId) == 0 {
			continue
		}

		ssoRequired := false
		if org.SSOConfig.SSORequired {
			ssoRequired = true
		} else if len(data.Password) > 0 {
			ssoRequired = false
		} else if len(org.SSOConfig.SSOEntrypoint) > 4 || len(org.SSOConfig.OpenIdAuthorization) > 4 {
			ssoRequired = true
		} else if !org.SSOConfig.SSORequired && (len(org.SSOConfig.SSOEntrypoint) == 0 || len(org.SSOConfig.OpenIdAuthorization) == 0) {
			ssoRequired = false
		} else {
			ssoRequired = false
		}

		log.Printf("[INFO] Inside SSO / OpenID check for user %s (%s) with org %s (%s)", userdata.Username, userdata.Id, org.Name, org.Id)
		// has to contain http(s)
		if !ssoRequired {
			continue
		}

		baseSSOUrl := org.SSOConfig.SSOEntrypoint
		redirectKey := "SSO_REDIRECT"
		if len(org.SSOConfig.OpenIdAuthorization) > 0 {
			redirectKey = "SSO_REDIRECT"

			baseSSOUrl = GetOpenIdUrl(request, *org)
		}

		log.Printf("[DEBUG] SSO Redirecting user %s (%s) in org %s (%s) to SSO login at %s", userdata.Username, userdata.Id, userdata.ActiveOrg.Name, userdata.ActiveOrg.Id, baseSSOUrl)

		// Check if the user has other orgs that can be swapped to - if so SWAP
		ssoResponse := SSOResponse{
			Success: true,
			Reason:  redirectKey,
			URL:     baseSSOUrl,
		}

		marshalled, err := json.Marshal(ssoResponse)
		if err != nil {
			log.Printf("[ERROR] Failed to marshal SSO response: %v", err)
			continue
		}

		resp.Header().Set("Content-Type", "application/json")
		resp.Write(marshalled)
		resp.WriteHeader(200)
		return
	}

	loginData := `{"success": false, "reason": "No SSO or OpenID login found. Please use the normal Shuffle login."}`
	log.Printf("[AUDIT] Failed to find a sso login for %s (%s)", data.Username, userdata.Id)

	resp.WriteHeader(401)
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

// Handles workflow executions across systems (open source, worker, cloud)
// getWorkflow
// GetWorkflow
// executeWorkflow

// This should happen locally.. Meaning, polling may be stupid.
// Let's do it anyway, since it seems like the best way to scale
// without remoting problems and the like.
func updateExecutionParent(ctx context.Context, executionParent, returnValue, parentAuth, parentNode, subflowExecutionId string) error {

	// Was an error here. Now defined to run with http://shuffle-backend:5001 by default
	backendUrl := os.Getenv("BASE_URL")
	if project.Environment == "cloud" {
		backendUrl = "https://shuffler.io"

		if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
			backendUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
		}

		if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
			backendUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
		}

	}

	// FIXME: This MAY fail at scale due to not being able to get the right worker
	// Maybe we need to pass the worker's real id, and not its VIP?
	if os.Getenv("SHUFFLE_SWARM_CONFIG") == "run" && (project.Environment == "" || project.Environment == "worker") {
		backendUrl = "http://shuffle-workers:33333"

		hostenv := os.Getenv("WORKER_HOSTNAME")
		if len(hostenv) > 0 {
			backendUrl = fmt.Sprintf("http://%s:33333", hostenv)
		}

		// From worker:
		//parsedRequest.BaseUrl = fmt.Sprintf("http://%s:%d", hostname, baseport)

		log.Printf("[DEBUG][%s] Sending request for shuffle-subflow result to %s. Should this be a specific worker? Specific worker is better if cache is NOT memcached", subflowExecutionId, backendUrl)
	}

	// Waiting due to speed problems in certain circumstances
	time.Sleep(350 * time.Millisecond)

	// Callback to itself
	if len(backendUrl) == 0 {
		backendUrl = "http://localhost:5001"
	}

	resultUrl := fmt.Sprintf("%s/api/v1/streams/results", backendUrl)

	topClient := GetExternalClient(backendUrl)
	newExecution := WorkflowExecution{}
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

	defer newresp.Body.Close()
	body, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading parent body: %s", err)
		return err
	}
	//log.Printf("\n\nBODY FROM STREAM OF PARENT FROM %s (%d): %s", resultUrl, newresp.StatusCode, string(body))

	if newresp.StatusCode != 200 {
		log.Printf("[ERROR] Bad statuscode setting subresult (1) with URL %s: %d, %s. Input data: %s", resultUrl, newresp.StatusCode, string(body), string(data))
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

	isLooping := false
	selectedTrigger := Trigger{}

	// Validating parent node
	checkResult := false
	// Subflows and the like may not be in here anymore. Maybe they are in actions
	for _, trigger := range newExecution.Workflow.Triggers {
		if trigger.ID != parentNode {
			continue
		}

		selectedTrigger = trigger
		for _, param := range trigger.Parameters {
			if param.Name == "argument" && strings.Contains(param.Value, "$") && strings.Contains(param.Value, ".#") {
				isLooping = true
			}

			// Check for if wait for results is set
			if param.Name == "check_result" {
				if param.Value == "true" {
					checkResult = true
				} else {
					checkResult = false
				}
			}
		}

		break
	}

	// Because we changed out how we handle mid-flow triggers
	if len(selectedTrigger.ID) == 0 {
		for _, action := range newExecution.Workflow.Actions {
			if action.ID != parentNode {
				continue
			}

			selectedTrigger = Trigger{
				ID:    action.ID,
				Label: action.Label,
			}

			foundResult.Action = action

			for _, param := range action.Parameters {
				if param.Name == "argument" && strings.Contains(param.Value, "$") && strings.Contains(param.Value, ".#") {
					isLooping = true
				}

				// Check for if wait for results is set
				if param.Name == "check_result" {
					if param.Value == "true" {
						checkResult = true
					} else {
						checkResult = false
					}
				}
			}

			break
		}
	}

	// Checks if the variable is set properly
	if !checkResult {
		//log.Printf("[DEBUG][%s] No check_result param found for subflow. Not mapping subflow result back to parent workflow. Trigger: %#v", subflowExecutionId, selectedTrigger.ID)

		return nil
	}

	// IF the workflow is looping, the result is added in the backend to not
	// cause consistency issues. This means the result will be sent back, and instead
	// Added to the workflow result by the backend itself.
	// When all the "WAITING" executions are done, the backend will set the execution itself
	// back to executing, allowing the parent to continue
	sendRequest := false
	resultData := []byte{}
	if isLooping {
		//log.Printf("[DEBUG][%s] SUBFLOW LOOPING - SHOULD ADD TO A LIST!", subflowExecutionId)

		// Saved for each subflow ID -> parentNode
		subflowResultCacheId := fmt.Sprintf("%s_%s_subflowresult", subflowExecutionId, parentNode)

		if len(returnValue) > 0 {
			err = SetCache(ctx, subflowResultCacheId, []byte(returnValue), 61)
			if err != nil {
				log.Printf("[ERROR] Failed setting subflow loop cache result for action in parsed exec results %s: %s", subflowResultCacheId, err)
				return err
			}
		}

		// Every time we get here, we need to both SET the value in cache AND look for other values in cache to make sure the list is good.
		parentNodeFound := false
		var parentSubflowResult []SubflowData
		for _, result := range newExecution.Results {
			if result.Action.ID != parentNode {
				continue
			}

			//log.Printf("[DEBUG] FOUND RES: %s", foundResult.Result)

			parentNodeFound = true
			err = json.Unmarshal([]byte(foundResult.Result), &parentSubflowResult)
			if err != nil {
				log.Printf("[ERROR] Failed to unmarshal result to parentsubflow res: %s", err)
				continue
			}

			break
		}

		// If found, loop through and make sure to check the result for ALL of them. If they're not in there, add them as values.
		if parentNodeFound {
			log.Printf("[DEBUG] Found result for subflow (parentNodeFound). Got %d parentSubflowResults", len(parentSubflowResult))

			ranUpdate := false

			newResults := []SubflowData{}
			finishedSubflows := 0
			for _, res := range parentSubflowResult {
				// If value length = 0 for any, then check cache and add the result
				//log.Printf("[DEBUG] EXEC: %s", res)
				if res.ExecutionId == subflowExecutionId {
					//foundResult.Result
					res.Result = string(returnValue)
					res.ResultSet = true

					ranUpdate = true

					//log.Printf("[DEBUG] Set the result for the node! Run update with %s", res)
					finishedSubflows += 1
				} else {
					res.ResultSet = true

					// Overutilization of cache :>
					if !res.ResultSet || len(res.Result) == 0 {
						subflowResultCacheId = fmt.Sprintf("%s_%s_subflowresult", res.ExecutionId, parentNode)

						cache, err := GetCache(ctx, subflowResultCacheId)
						if err == nil {
							cacheData := []byte(cache.([]uint8))
							res.Result = string(cacheData)
							res.ResultSet = true
							ranUpdate = true

							finishedSubflows += 1
						} else {
							//log.Printf("[DEBUG] No cache data set for subflow cache %s", subflowResultCacheId)
						}
					} else {
						finishedSubflows += 1
					}
				}

				newResults = append(newResults, res)
			}

			if finishedSubflows == len(newResults) {
				log.Printf("[DEBUG][%s] Finished workflow because status of all should be set to finished now", subflowExecutionId)

				// Status is used to determine if the current subflow is finished

				/*
					foundResult.Status = "SUCCESS"

					if result.CompletedAt == 0 {
						result.CompletedAt = time.Now().Unix()*1000
					}
				*/
			}

			if ranUpdate {

				sendRequest = true
				baseResultData, err := json.Marshal(newResults)
				if err != nil {
					log.Printf("[ERROR][%s] Failed marshalling subflow loop request data (1): %s", subflowExecutionId, err)
					return err
				}

				foundResult.Result = string(baseResultData)
				foundResult.ExecutionId = executionParent
				foundResult.Authorization = parentAuth
				resultData, err = json.Marshal(foundResult)
				if err != nil {
					log.Printf("[ERROR][%s] Failed marshalling FULL subflow loop request data (2): %s", subflowExecutionId, err)
					return err
				}
			}
		} else {
			//log.Printf("[ERROR][%s] Did NOT enter parentNodeFound in subflow loop. This means we can't update the parent", subflowExecutionId)

		}

		// Check if the item alreayd exists or not in results
		//return nil
	} else {
		//log.Printf("\n\n[DEBUG] ITS NOT LOOP for parent node '%s'. Found data: %s\n\n", parentNode, returnValue)

		if len(selectedTrigger.ID) > 0 {
			foundResult.Action.ID = selectedTrigger.ID
		}

		// 1. Get result of parentnode's subflow (foundResult.Result)
		// 2. Try to marshal parent into a loop.
		// 3. If possible, loop through and find the one matching SubflowData.ExecutionId with "executionParent"
		// 4. If it's matching, update ONLY that one.

		var subflowDataLoop []SubflowData
		err = json.Unmarshal([]byte(foundResult.Result), &subflowDataLoop)
		if err == nil {
			for subflowIndex, subflowData := range subflowDataLoop {
				if subflowData.ExecutionId == executionParent {
					log.Printf("[DEBUG][%s] Updating execution Id %s with subflow info", subflowExecutionId, subflowData.ExecutionId)
					subflowDataLoop[subflowIndex].Result = returnValue
				}
			}

			//foundResult.ExecutionId = executionParent
			//foundResult.Authorization = parentAuth
			resultData, err = json.Marshal(subflowDataLoop)
			if err != nil {
				log.Printf("[WARNING] Failed updating resultData (4): %s", err)
				return err
			}

			sendRequest = true
		} else {
			// In here maning no-loop?
			actionValue := SubflowData{
				Success:       true,
				ExecutionId:   executionParent,
				Authorization: parentAuth,
				Result:        returnValue,
			}

			parsedActionValue, err := json.Marshal(actionValue)
			if err != nil {
				log.Printf("[ERROR] Failed updating resultData (1): %s", err)
				return err
			}

			// This is probably bad for loops
			timeNow := time.Now().Unix()
			if len(foundResult.Action.ID) == 0 {
				log.Printf("\n\n[INFO] Couldn't find the result? Data: %s\n\n", string(resultData))
				parsedAction := Action{
					Label:          selectedTrigger.Label,
					ID:             parentNode,
					Name:           "run_subflow",
					AppName:        "shuffle-subflow",
					AppVersion:     "1.1.0",
					Environment:    selectedTrigger.Environment,
					ExecutionDelay: selectedTrigger.ExecutionDelay,
				}

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
					log.Printf("[ERROR] Failed updating resultData (2): %s", err)
					return err
				}

				sendRequest = true
			} else {
				log.Printf("[DEBUG][%s] Found subflow result. Sending result with input data", foundResult.ExecutionId)

				foundResult.StartedAt = timeNow
				foundResult.CompletedAt = timeNow
				foundResult.Authorization = parentAuth
				foundResult.ExecutionId = executionParent
				foundResult.Result = string(parsedActionValue)

				if foundResult.Status == "" {
					foundResult.Status = "SUCCESS"
				}

				resultData, err = json.Marshal(foundResult)
				if err != nil {
					log.Printf("[ERROR][%s] Failed updating resultData (3): %s", subflowExecutionId, err)
					return err
				}

				sendRequest = true
			}
		}
	}

	// This is to ensure cache is in time. Timing issues between parent & child nodes are awful :)
	if isLooping {
		cacheId := fmt.Sprintf("%s_%s_result", foundResult.ExecutionId, foundResult.Action.ID)
		err = SetCache(ctx, cacheId, resultData, 35)
		if err != nil {
			log.Printf("[WARNING][%s] Couldn't set cache for subflow action result %s (4): %s", subflowExecutionId, cacheId, err)
		}

		log.Printf("[DEBUG][%s] Set cache for subflow action result loop %s (4) with 250 ms delay before request", subflowExecutionId, cacheId)
		//time.Sleep(250 * time.Millisecond)
	}

	if sendRequest && len(resultData) > 0 {
		//log.Printf("[INFO][%s] Should send subflow request to backendURL %s. Data: %s!", executionParent, backendUrl, string(resultData))

		streamUrl := fmt.Sprintf("%s/api/v1/streams", backendUrl)
		req, err := http.NewRequest(
			"POST",
			streamUrl,
			bytes.NewBuffer([]byte(resultData)),
		)

		if err != nil {
			log.Printf("[ERROR] Error building subflow request: %s", subflowExecutionId, err)
			return err
		}

		newresp, err := topClient.Do(req)
		if err != nil {
			log.Printf("[ERROR] Error running subflow request: %s", subflowExecutionId, err)
			return err
		}

		defer newresp.Body.Close()
		if newresp.StatusCode != 200 {
			body, err := ioutil.ReadAll(newresp.Body)
			if err != nil {
				log.Printf("[INFO][%s] Failed reading body after subflow request: %s", subflowExecutionId, err)
				return err
			} else {
				log.Printf("[ERROR][%s] Failed forwarding subflow request of length %d\n: %s", subflowExecutionId, len(resultData), string(body))
			}
		}
	} else {
		log.Printf("[INFO][%s] NOT sending request to parent %s because data len is %d and sendRequest is %t", subflowExecutionId, executionParent, len(resultData), sendRequest)

	}

	return nil
}

func ResendActionResult(actionData []byte, retries int64) {
	if project.Environment == "cloud" && retries == 0 {
		retries = 4
		//return

		//var res ActionResult
		//err := json.Unmarshal(actionData, &res)
		//if err == nil {
		//	log.Printf("[WARNING] Cloud - skipping rerun with %d retries for %s (%s)", retries, res.Action.Label, res.Action.ID)
		//}

		//return
	}

	if retries >= 5 {
		return
	}

	backendUrl := os.Getenv("BASE_URL")
	if project.Environment == "cloud" {
		backendUrl = "https://shuffler.io"

		if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
			backendUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
		}

	}

	if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
		backendUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
	}

	if os.Getenv("SHUFFLE_SWARM_CONFIG") == "run" && (project.Environment == "" || project.Environment == "worker") {
		backendUrl = "http://shuffle-workers:33333"

		// Should connect to self, not shuffle-workers
		hostenv := os.Getenv("WORKER_HOSTNAME")
		if len(hostenv) > 0 {
			backendUrl = fmt.Sprintf("http://%s:33333", hostenv)
		}
		//parsedRequest.BaseUrl = fmt.Sprintf("http://%s:%d", hostname, baseport)

		// From worker:
		//parsedRequest.BaseUrl = fmt.Sprintf("http://%s:%d", hostname, baseport)

		log.Printf("\n\n[DEBUG] REsending request to rerun action result to %s\n\n", backendUrl)

		// Here to prevent infinite loops
		var res ActionResult
		err := json.Unmarshal(actionData, &res)
		if err == nil {
			ctx := context.Background()
			parsedValue, err := GetBackendexecution(ctx, res.ExecutionId, res.Authorization)
			if err != nil {
				log.Printf("[WARNING] Failed getting execution from backend to verify (3): %s", err)
			} else {
				log.Printf("[INFO][%s] Found execution result (3) %s for subflow %s in backend with %d results and result %s", res.ExecutionId, parsedValue.Status, res.ExecutionId, len(parsedValue.Results), parsedValue.Result)
				if parsedValue.Status != "EXECUTING" {
					return
				}
			}
		}
	}

	if len(backendUrl) == 0 {
		backendUrl = "http://localhost:5001"
	}

	//log.Printf("[INFO] Resending action result to backend %s", backendUrl)
	log.Printf("[DEBUG][] Action: Resend, Label: '', Action: '', Status: '', Run status: '', Extra=url:%s", backendUrl)

	streamUrl := fmt.Sprintf("%s/api/v1/streams?rerun=true&retries=%d", backendUrl, retries+1)
	req, err := http.NewRequest(
		"POST",
		streamUrl,
		bytes.NewBuffer(actionData),
	)

	if err != nil {
		log.Printf("[ERROR] Error building resend action request - retries: %d, err: %s", retries, err)

		if project.Environment != "cloud" && retries < 5 {
			if strings.Contains(fmt.Sprintf("%s", err), "cannot assign requested address") {
				time.Sleep(5 * time.Second)
				retries = retries + 1

				ResendActionResult(actionData, retries)
			}
		}

		return
	}

	//Timeout: 3 * time.Second,
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}

	newresp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error running resend action request - retries: %d, err: %s", retries, err)

		if !strings.Contains(fmt.Sprintf("%s", err), "context deadline") && !strings.Contains(fmt.Sprintf("%s", err), "Client.Timeout exceeded") {
			// How to self repair? Quit and restart the worker?
			// This means worker is buggy when talking to itself
			if project.Environment != "cloud" && retries < 5 {
				if strings.Contains(fmt.Sprintf("%s", err), "cannot assign requested address") {
					time.Sleep(5 * time.Second)
					retries = retries + 1

					ResendActionResult(actionData, retries)
				}
			} else if project.Environment != "cloud" && retries >= 5 {
				//panic("No more sockets available. Restarting worker to self-repair.")
				log.Printf("[WARNING] Should we quit out on worker and start a new? How can we remove socket boundry?")
			}
		}

		return
	}

	defer newresp.Body.Close()

	//body, err := ioutil.ReadAll(newresp.Body)
	//if err != nil {
	//	log.Printf("[WARNING] Error getting body from rerun: %s", err)
	//	return
	//}

	//log.Printf("[DEBUG] Status %d and Body from rerun: %s", newresp.StatusCode, string(body))
}

// Function for translating action results into whatever.
// Came about because of general issues with Oauth2
func FixActionResultOutput(actionResult ActionResult) ActionResult {
	if strings.Contains(actionResult.Result, "TypeError") && strings.Contains(actionResult.Result, "missing 1 required positional argument: 'access_token'") {
		//log.Printf("\n\nTypeError  in actionresult!")
		actionResult.Result = `{"success": false, "reason": "This App requires authentication with Oauth2. Make sure to authenticate it first.", "extra": "If the app is authenticated, are you sure the Token & Refresh URL in the App is correct? Authentication refresh may have failed."}`
	}

	// Check length of result timestamp
	if len(strconv.FormatInt(actionResult.StartedAt, 10)) == 10 {
		actionResult.StartedAt = actionResult.StartedAt * 1000
	}

	if len(strconv.FormatInt(actionResult.CompletedAt, 10)) == 10 {
		actionResult.CompletedAt = actionResult.CompletedAt * 1000
	}

	if len(strconv.FormatInt(actionResult.StartedAt, 10)) == 19 {
		actionResult.StartedAt = actionResult.StartedAt / 1000000
	}

	if len(strconv.FormatInt(actionResult.CompletedAt, 10)) == 19 {
		actionResult.CompletedAt = actionResult.CompletedAt / 1000000
	}

	//log.Printf("[DEBUG] Fixed LEN: %d, %d", len(strconv.FormatInt(actionResult.StartedAt, 10)), len(strconv.FormatInt(actionResult.CompletedAt, 10)))

	return actionResult
}

func runTranslation(ctx context.Context, standard string, inputBody string) {
	// Send HTTP request to localhost:3001

	httpClient := &http.Client{}
	url := fmt.Sprintf("http://localhost:5003/api/v1/translate_to/%s", standard)
	req, err := http.NewRequest(
		"POST",
		url,
		bytes.NewBuffer([]byte(inputBody)),
	)

	if err != nil {
		log.Printf("[WARNING] Error building translation request to %s: %s", standard, err)
		return
	}

	newresp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("[WARNING] Error running translation to %s: %s", standard, err)
		return
	}

	defer newresp.Body.Close()
	body, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		log.Printf("[WARNING] Error getting body from translation for %s: %s", standard, err)
		return
	}

	log.Printf("[DEBUG] Status: %d", newresp.StatusCode)
	log.Printf("\n\n\nOUTPUT: %s\n\n\n", string(body))
}

func RunExecutionTranslation(ctx context.Context, actionResult ActionResult) {
	//log.Printf("\n\n[DEBUG] Running execution translation for app '%s' with action '%s' towards standardized data\n\n", actionResult.Action.AppName, actionResult.Action.Name)
	return

	// Try to unmarshal the data to see if it has a status and if its less than 300
	var parsedValue map[string]interface{}
	err := json.Unmarshal([]byte(actionResult.Result), &parsedValue)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshalling action result for translation: %s", err)
		return
	}

	// For now only handling proper returns with standard HTTP messaging
	if status, ok := parsedValue["status"]; ok {
		if status == nil {
			log.Printf("[DEBUG] Found BAD status in action result: %s", status)
			return
		}

		parsedStatus := status.(float64)
		if parsedStatus >= 300 {
			log.Printf("[DEBUG] Found status in action result: %d", parsedStatus)
			return
		}
	} else {
		log.Printf("[DEBUG] Did NOT find status in action result: %s", actionResult.Result)
		return
	}

	log.Printf("\n\n[DEBUG] Running execution translation for app '%s' with action '%s' towards standardized data\n\n", actionResult.Action.AppName, actionResult.Action.Name)

	parsedBody := ""
	if body, ok := parsedValue["body"]; ok {
		if body == nil {
			return
		}

		// Check if body is a dictionary
		if reflect.TypeOf(body).Kind() == reflect.Map {

			bodyDict := body.(map[string]interface{})
			bodyDictBytes, err := json.Marshal(bodyDict)
			if err != nil {
				log.Printf("[WARNING] Failed marshalling body dict: %s", err)
				return
			}

			parsedBody = string(bodyDictBytes)

			// Look for a list of items in here?
			// How does it know to look for a list?

			runTranslation(ctx, "email", parsedBody)

		} else if reflect.TypeOf(body).Kind() == reflect.Slice {
			// Check if body is a list and marshal it

			bodyList := body.([]interface{})
			bodyListBytes, err := json.Marshal(bodyList)
			if err != nil {
				log.Printf("[WARNING] Failed marshalling body list: %s", err)
				return
			}

			// Should loop the items?
			//parsedBody = string(bodyListBytes)
			log.Printf("[WARNING] Found body list in action result of length: %d. Warning: No handler of lists yet", len(bodyListBytes))
		}
	}

	//log.Printf("\n\n[DEBUG] Found body in action result of length: %d", len(parsedBody))
}

// Updateparam is a check to see if the execution should be continuously validated
func ParsedExecutionResult(ctx context.Context, workflowExecution WorkflowExecution, actionResult ActionResult, updateParam bool, retries int64) (*WorkflowExecution, bool, error) {
	var err error
	if actionResult.Action.ID == "" && actionResult.Action.Name == "" {
		// Can we find it based on label?

		log.Printf("\n\n[ERROR][%s] Failed handling EMPTY action %#v (ParsedExecutionResult). Usually ONLY happens during worker run that sets everything?\n\n", workflowExecution.ExecutionId, actionResult)

		return &workflowExecution, true, nil
	}

	// 1. CHECK cache if it happened in another?
	// 2. Set cache
	// 3. Find executed without a result
	// 4. Ensure the result is NOT set when running an action

	actionResult = FixActionResultOutput(actionResult)
	actionCacheId := fmt.Sprintf("%s_%s_result", actionResult.ExecutionId, actionResult.Action.ID)
	// Done elsewhere

	// Don't set cache for triggers?
	//log.Printf("\n\nACTIONRES: %s\n\nRES: %s\n", actionResult, actionResult.Result)

	setCache := true
	if actionResult.Action.AppName == "shuffle-subflow" {

		// Verifying if the userinput should be sent properly or not
		if actionResult.Action.Name == "run_userinput" && actionResult.Status != "SKIPPED" {
			//log.Printf("\n\n[INFO] Inside userinput default return! Return data: %s", actionResult.Result)
			actionResult.Status = "WAITING"
			actionResult.CompletedAt = time.Now().Unix() * 1000

			if strings.Contains(actionResult.Result, "\"success\":") {
				//log.Printf("Found success in result. Now verifying if the workflow should just continue or not")

				type SubflowMapping struct {
					Success bool `json:"success"`
				}

				var subflowData SubflowMapping
				err := json.Unmarshal([]byte(actionResult.Result), &subflowData)
				if err == nil && subflowData.Success == false {
					log.Printf("[INFO][%s] Userinput subflow failed. Should abort workflow or continue execution by default?", actionResult.ExecutionId)

				} else {
					log.Printf("\n\n[INFO][%s] Userinput subflow succeeded. Should continue execution by default? Value: %s\n\n", actionResult.ExecutionId, actionResult.Result)

					// FIXME:
					// 1. What should happen on cloud?
					// 2. What should happen if on backend with NON cloud env?
					// 3. What should happen if inside Worker?
					// 4. What if Swarm?

					setWorkflow := false
					if strings.ToLower(actionResult.Action.Environment) != "cloud" {
						if project.Environment == "worker" {

							if os.Getenv("SHUFFLE_SWARM_CONFIG") == "run" || os.Getenv("SHUFFLE_SWARM_CONFIG") == "swarm" {
								//log.Printf("\n\n\n[DEBUG] MODIFYING workflow based on User Input as we are in swarm\n\n\n")
								workflowExecution.Status = "WAITING"
								workflowExecution.Results = append(workflowExecution.Results, actionResult)
								setWorkflow = true
							} else {
								log.Printf("\n\n\n[DEBUG] NOT modifying workflow based on User Input as we are in worker\n\n\n")
							}

						} else {
							// Find the waiting node and change it to this result
							workflowExecution.Status = "WAITING"
							workflowExecution.Results = append(workflowExecution.Results, actionResult)

							setWorkflow = true
						}
					}

					if setWorkflow {
						// Set with database saving
						err = SetWorkflowExecution(ctx, workflowExecution, true)
						if err != nil {
							log.Printf("[ERROR][%s] Failed setting workflow execution during user input return onprem~: %s", workflowExecution.ExecutionId, err)
						}
					}

					if strings.Contains(actionResult.Result, "\"execution_id\":") && strings.Contains(actionResult.Result, "\"authorization\":") {
						log.Printf("\n\n[DEBUG][%s] Found execution_id and authorization in result. Now verifying if the workflow should just continue or not\n\n", actionResult.ExecutionId)
						return &workflowExecution, false, errors.New("User Input")
					}
				}
			}

			// Finding the waiting node and changing it to this result
			foundWaiting := false
			for resultIndex, result := range workflowExecution.Results {
				if result.Action.ID != actionResult.Action.ID {
					continue
				}

				workflowExecution.Results[resultIndex].Result = actionResult.Result

				// Updating cache for the result to always use the latest
				//actionResultBody, err := json.Marshal(workflowExecution.Results[resultIndex].Result)
				actionResultBody, err := json.Marshal(actionResult)
				if err == nil {
					cacheId := fmt.Sprintf("%s_%s_result", workflowExecution.ExecutionId, actionResult.Action.ID)
					err = SetCache(ctx, cacheId, actionResultBody, 35)
					if err != nil {
						log.Printf("[WARNING] Couldn't find in fix exec %s (2): %s", cacheId, err)
						continue
					}
				}

				foundWaiting = true
				break
			}

			if !foundWaiting {
				workflowExecution.Results = append(workflowExecution.Results, actionResult)

				actionResultBody, err := json.Marshal(actionResult)
				if err == nil {
					cacheId := fmt.Sprintf("%s_%s_result", workflowExecution.ExecutionId, actionResult.Action.ID)
					err = SetCache(ctx, cacheId, actionResultBody, 35)
					if err != nil {
						log.Printf("[ERROR][%s] Failed to update cache for %s", workflowExecution.ExecutionId, cacheId)
					}
				}
			}

			err = SetWorkflowExecution(ctx, workflowExecution, true)
			if err != nil {
				log.Printf("[ERROR][%s] Failed setting workflow execution during user input return: %s", workflowExecution.ExecutionId, err)
			}

			return &workflowExecution, true, nil
		} else {
			// Should NOT run with all this if the action is SKIPPED
			// Cache when SKIPPED - this is to handle the case where the subflow is skipped (condition) and the result is not set

			if actionResult.Status == "SKIPPED" {
				setCache = true
			} else {
				for _, param := range actionResult.Action.Parameters {
					if param.Name == "check_result" {
						if param.Value == "true" {
							setCache = false
						}

						break
					}
				}
			}

			if !setCache {
				var subflowData SubflowData
				jsonerr := json.Unmarshal([]byte(actionResult.Result), &subflowData)
				if jsonerr == nil && len(subflowData.Result) == 0 && !strings.Contains(actionResult.Result, "\"result\"") {
					setCache = false
				} else {
					setCache = true
				}
			}
		}

		//log.Printf("[DEBUG] Skipping setcache for subflow? SetCache: %t", setCache)
	}

	if setCache {
		go RunExecutionTranslation(ctx, actionResult)

		actionResultBody, err := json.Marshal(actionResult)
		if err == nil {
			err = SetCache(ctx, actionCacheId, actionResultBody, 35)
			if err != nil {
				//log.Printf("\n\n\n[ERROR] Failed setting cache for action in parsed exec results %s: %s\n\n", actionCacheId, err)
			}
		} else {
			log.Printf("[ERROR] Failed marshalling result and put it in cache.")
		}
	} else {
		//log.Printf("[WARNING] Skipping cache for %s", actionResult.Action.Name)
	}

	skipExecutionCount := false
	if workflowExecution.Status == "FINISHED" {
		skipExecutionCount = true
	}

	dbSave := false
	startAction, extra, children, parents, visited, executed, nextActions, environments := GetExecutionVariables(ctx, workflowExecution.ExecutionId)

	// Shitty workaround as it may be missing it at times
	for _, action := range workflowExecution.Workflow.Actions {
		if action.ID == actionResult.Action.ID {
			//log.Printf("HAS EXEC VARIABLE: %s", action.ExecutionVariable)
			actionResult.Action.ExecutionVariable = action.ExecutionVariable
			break
		}
	}

	newResult := FixBadJsonBody([]byte(actionResult.Result))
	actionResult.Result = string(newResult)

	if len(actionResult.Action.ExecutionVariable.Name) > 0 && (actionResult.Status == "SUCCESS" || actionResult.Status == "FINISHED") {
		setExecVar := true

		// Should just check the first bytes for this, as it should be at the start if it's a failure with the individual action itself
		// This is finicky, but it's the easiest fix for this
		checkLength := 1000
		firstFifty := actionResult.Result
		if len(actionResult.Result) > checkLength {
			firstFifty = actionResult.Result[0:checkLength]
		}

		if strings.Contains(firstFifty, "\"success\":") && !(strings.HasPrefix(actionResult.Result, "[{") && strings.HasSuffix(actionResult.Result, "}]")) {
			type SubflowMapping struct {
				Success bool `json:"success"`
			}

			var subflowData SubflowMapping
			err := json.Unmarshal([]byte(actionResult.Result), &subflowData)
			if err != nil {
				log.Printf("[ERROR] Failed to map in set execvar name with success: %s", err)
				setExecVar = false
			} else {
				if subflowData.Success == false {
					setExecVar = false
				}
			}
		}

		if len(actionResult.Result) == 0 {
			setExecVar = false
		}

		if setExecVar {
			log.Printf("[DEBUG][%s] Updating exec variable %s with new value of length %d (2)", workflowExecution.ExecutionId, actionResult.Action.ExecutionVariable.Name, len(actionResult.Result))

			if len(workflowExecution.Results) > 0 {
				// Should this be used?
				// lastResult := workflowExecution.Results[len(workflowExecution.Results)-1].Result
			}

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
		} else {
			log.Printf("[DEBUG] NOT updating exec variable %s with new value of length %d. Check previous errors, or if action was successful (success: true)", actionResult.Action.ExecutionVariable.Name, len(actionResult.Result))
		}
	}

	if workflowExecution.Workflow.Configuration.SkipNotifications == false && actionResult.Status == "SUCCESS" && strings.Contains(actionResult.Result, "\"success\":") && strings.Contains(actionResult.Result, "\"status\":") {
		type resultMapping struct {
			Success bool `json:"success"`
			Status  int  `json:"status"`
		}

		var mapping resultMapping
		err := json.Unmarshal([]byte(actionResult.Result), &mapping)
		if err == nil && mapping.Success == true && mapping.Status >= 300 {
			//log.Printf("\n\n[DEBUG] Setting status to failure as it's a success with status code %d\n\n", mapping.Status)

			parsedDescription := fmt.Sprintf("Bad status code in action %s: %d. This shows up if status is >= 300", actionResult.Action.Name, mapping.Status)
			if mapping.Status == 404 {
				parsedDescription = fmt.Sprintf("404 not found for action %s. Check if the URL is correct, and that the data it is trying to retrieve exists.", actionResult.Action.Name)
			}

			if mapping.Status == 401 {
				parsedDescription = fmt.Sprintf("401 unauthorized for action %s. Make sure your credentials are correct.", actionResult.Action.Name)
			}

			if mapping.Status == 403 {
				parsedDescription = fmt.Sprintf("403 forbidden for action %s. Make sure the account you are using has access to the resource.", actionResult.Action.Name)
			}

			// Send notification for it
			err := CreateOrgNotification(
				ctx,
				fmt.Sprintf("Bad Status code in Workflow %s: %d", workflowExecution.Workflow.Name, mapping.Status),
				parsedDescription,
				fmt.Sprintf("/workflows/%s?execution_id=%s&view=executions&node=%s", workflowExecution.Workflow.ID, workflowExecution.ExecutionId, actionResult.Action.ID),
				workflowExecution.ExecutionOrg,
				true,
			)

			if err != nil {
				log.Printf("[WARNING] Failed making org notification: %s", err)
			} else {
				workflowExecution.NotificationsCreated++
			}
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
	notificationSent := false
	for paramIndex, param := range actionResult.Action.Parameters {
		if param.Configuration {
			//log.Printf("[INFO] Deleting param %s (auth)", param.Name)
			actionResult.Action.Parameters[paramIndex].Value = ""
		}

		if param.Name == "liquid_syntax_error" && !notificationSent {
			// Send notification for it
			err := CreateOrgNotification(
				ctx,
				fmt.Sprintf("Liquid Syntax Error in Workflow %s", workflowExecution.Workflow.Name),
				fmt.Sprintf("Node %s in Workflow %s was found to have a Liquid Syntax Error. Click to investigate", actionResult.Action.Label, workflowExecution.Workflow.Name),
				fmt.Sprintf("/workflows/%s?execution_id=%s&view=executions&node=%s", workflowExecution.Workflow.ID, workflowExecution.ExecutionId, actionResult.Action.ID),
				workflowExecution.ExecutionOrg,
				true,
			)

			if err == nil {
				notificationSent = true
				workflowExecution.NotificationsCreated++
			} else {
				log.Printf("[WARNING] Failed making org notification: %s", err)
			}
		}
	}

	// Used for testing subflow shit
	//if strings.Contains(actionResult.Action.Label, "Shuffle Workflow_30") {
	//	log.Printf("RESULT FOR %s: %s", actionResult.Action.Label, actionResult.Result)
	//	if !strings.Contains(actionResult.Result, "\"result\"") {
	//		log.Printf("NO RESULT - RETURNING!")
	//		return &workflowExecution, false, nil
	//	}
	//}

	// Fills in data from subflows, whether they're loops or not
	// Update: handling this farther down the function
	//log.Printf("[DEBUG] STATUS OF %s: %s", actionResult.Action.AppName, actionResult.Status)
	if actionResult.Status == "SUCCESS" && actionResult.Action.AppName == "shuffle-subflow" {
		dbSave = true
	}

	if actionResult.Status == "ABORTED" || actionResult.Status == "FAILURE" {
		IncrementCache(ctx, workflowExecution.ExecutionOrg, "app_executions_failed")

		if workflowExecution.Workflow.Configuration.SkipNotifications == false {
			// Add an else for HTTP request errors with success "false"
			// These could be "silent" issues
			if actionResult.Status == "FAILURE" && workflowExecution.Workflow.Hidden == false {
				log.Printf("[DEBUG] Result is %s for %s (%s). Making notification.", actionResult.Status, actionResult.Action.Label, actionResult.Action.ID)
				err := CreateOrgNotification(
					ctx,
					fmt.Sprintf("Error in Workflow %s", workflowExecution.Workflow.Name),
					fmt.Sprintf("Node %s in Workflow %s was found to have an error. Click to investigate", actionResult.Action.Label, workflowExecution.Workflow.Name),
					fmt.Sprintf("/workflows/%s?execution_id=%s&view=executions&node=%s", workflowExecution.Workflow.ID, workflowExecution.ExecutionId, actionResult.Action.ID),
					workflowExecution.ExecutionOrg,
					true,
				)

				if err != nil {
					log.Printf("[WARNING] Failed making org notification: %s", err)
				} else {
					workflowExecution.NotificationsCreated++
				}
			}
		}

		newResults := []ActionResult{}
		childNodes := []string{}
		if workflowExecution.Workflow.Configuration.ExitOnError {
			// Find underlying nodes and add them
			log.Printf("[WARNING] Actionresult is %s for node %s (%s) in execution %s. Should set workflowExecution and exit all running functions", actionResult.Status, actionResult.Action.Label, actionResult.Action.ID, workflowExecution.ExecutionId)
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
			childNodes = FindChildNodes(workflowExecution, actionResult.Action.ID, []string{}, []string{})
			//log.Printf("[DEBUG][%s] FOUND %d CHILDNODES\n\n", workflowExecution.ExecutionId, len(childNodes))
			for _, nodeId := range childNodes {
				log.Printf("[DEBUG][%s] Checking if node %s is already in results", workflowExecution.ExecutionId, nodeId)
				if nodeId == actionResult.Action.ID {
					log.Printf("[DEBUG][%s] Skipping marking node %s (%s) as anything", workflowExecution.ExecutionId, nodeId, actionResult.Action.Label)
					continue
				}

				// 1. Find the action itself
				// 2. Create an actionresult
				curAction := Action{ID: ""}
				for _, action := range workflowExecution.Workflow.Actions {
					if action.ID == nodeId {
						curAction = action
						log.Printf("[DEBUG][%s] Found action %s (%s) for node %s", workflowExecution.ExecutionId, action.Label, action.ID, nodeId)
						break
					}
				}
				log.Printf("[DEBUG][%s] Found action with ID: %s", workflowExecution.ExecutionId, curAction.ID)

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
						//log.Printf("Couldn't find subnode %s", nodeId)
						log.Printf("[WARNING][%s] Couldn't find subnode %s. Forgetting about it", workflowExecution.ExecutionId, nodeId)
						continue
					}
				}

				resultExists := false
				for _, result := range workflowExecution.Results {
					log.Printf("[DEBUG][%s] Checking if result %s (%s) exists in results", workflowExecution.ExecutionId, result.Action.Label, result.Action.ID)
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
										log.Printf("[DEBUG][%s] Parent %s (%s) is a trigger. Continuing..", workflowExecution.ExecutionId, branch.SourceID, curAction.Label)
										parentTrigger = true
									}
								}
							}

							if parentTrigger {
								log.Printf("[DEBUG][%s] Parent %s (of child %s) is a trigger. Continuing..", workflowExecution.ExecutionId, branch.SourceID, nodeId)
								continue
							}

							log.Printf("[DEBUG][%s] Parent %s (of child %s) is NOT a trigger. Continuing..", workflowExecution.ExecutionId, branch.SourceID, nodeId)

							sourceNodeFound := false
							for _, item := range childNodes {
								if item == branch.SourceID {
									log.Printf("[DEBUG][%s] Found source node %s (%s) for node %s", workflowExecution.ExecutionId, branch.SourceID, curAction.Label, nodeId)
									sourceNodeFound = true
									break
								}
							}

							log.Printf("[DEBUG][%s] sourceNodeFound: %t for node %s", workflowExecution.ExecutionId, sourceNodeFound, nodeId)

							if !sourceNodeFound {
								// FIXME: Shouldn't add skip for child nodes of these nodes. Check if this node is parent of upcoming nodes.
								//log.Printf("\n\n NOT setting node %s to SKIPPED", nodeId)
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
							Result:        `{"success": false, "reason": "Skipped because of previous node - 2"}`,
							StartedAt:     0,
							CompletedAt:   0,
							Status:        "SKIPPED",
						}

						newResults = append(newResults, newResult)

						visited = append(visited, curAction.ID)
						executed = append(executed, curAction.ID)

						UpdateExecutionVariables(ctx, workflowExecution.ExecutionId, startAction, children, parents, visited, executed, nextActions, environments, extra)
					} else {
						// log.Printf("\n\nNOT adding %s as skipaction - should add to execute?", nodeId)
						//var visited []string
						//var executed []string
						//var nextActions []string
						log.Printf("[DEBUG][%s] Not adding %s - %s as a skipaction.", workflowExecution.ExecutionId, curAction.ID, nodeId)
					}
				}
			}
		}

		// Cleans up aborted, and always gives a result
		lastResult := ""
		// type ActionResult struct {
		for _, result := range workflowExecution.Results {
			log.Printf("[DEBUG][%s] Checking result %s (%s) with status %s", workflowExecution.ExecutionId, result.Action.Label, result.Action.ID, result.Status)
			if actionResult.Action.ID == result.Action.ID {
				continue
			}

			if result.Status == "EXECUTING" {
				result.Status = actionResult.Status
				result.Result = "Aborted because of error in another node (2)"
			}

			if len(result.Result) > 0 && result.Status == "SUCCESS" {
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
		//childNodes := FindChildNodes(workflowExecution, actionResult.Action.ID)

		// See if it can even find it in here for skipped?
		//log.Printf("childnodes of %s (%s): %d: %s", actionResult.Action.Label, actionResult.Action.Id, len(childNodes), childNodes)

		//FIXME: Should this run and fix all nodes,
		// or should it send them in as new SKIPs? Should we only handle DIRECT
		// children? I wonder.

		//log.Printf("\n\n\n[DEBUG] FROM %s - FOUND childnode %s %s (%s). exists: %s\n\n\n", actionResult.Action.Label, curAction.ID, curAction.Name, curAction.Label, resultExists)
		// FIXME: Add triggers
		for _, branch := range workflowExecution.Workflow.Branches {
			if branch.SourceID != actionResult.Action.ID {
				continue
			}

			// Find the target & check if it has more branches. If it does, and they're not finished - continue
			foundAction := Action{}
			for _, action := range workflowExecution.Workflow.Actions {
				if action.ID == branch.DestinationID {
					foundAction = action
					break
				}
			}

			if len(foundAction.ID) == 0 {
				for _, trigger := range workflowExecution.Workflow.Triggers {
					//if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
					if trigger.ID == branch.DestinationID {
						foundAction = Action{
							ID:      trigger.ID,
							AppName: trigger.AppName,
							Name:    trigger.AppName,
							Label:   trigger.Label,
						}

						if trigger.AppName == "Shuffle Workflow" {
							foundAction.AppName = "shuffle-subflow"
						}

						break
					}
				}

				if len(foundAction.ID) == 0 {
					continue
				}
			}

			log.Printf("[DEBUG][%s] Found that %s (%s) should be skipped? Should check if it has more parents. If not, send in a skip", workflowExecution.ExecutionId, foundAction.Label, foundAction.AppName)

			foundCount := 0
			skippedBranches := []string{}
			for _, checkBranch := range workflowExecution.Workflow.Branches {
				if checkBranch.DestinationID == foundAction.ID {
					foundCount += 1

					// Check if they're all skipped or not
					if checkBranch.SourceID == actionResult.Action.ID {
						skippedBranches = append(skippedBranches, checkBranch.SourceID)
						continue
					}

					// Not found = not counted yet
					for _, res := range workflowExecution.Results {
						if res.Action.ID == checkBranch.SourceID && res.Status != "SUCCESS" && res.Status != "FINISHED" {
							skippedBranches = append(skippedBranches, checkBranch.SourceID)
							break
						}
					}
				}
			}

			skippedCount := len(skippedBranches)

			//log.Printf("[DEBUG][%s] Found %d branch(es) for %s. %d skipped. If equal, make the node skipped. SKIPPED: %s", workflowExecution.ExecutionId, foundCount, foundAction.Label, skippedCount, skippedBranches)
			if foundCount == skippedCount {
				found := false
				for _, res := range workflowExecution.Results {
					if res.Action.ID == foundAction.ID {
						found = true
					}
				}

				// Send only IF it's not the startnode
				//if !found {
				if !found && foundAction.ID != workflowExecution.Start {
					newResult := ActionResult{
						Action:        foundAction,
						ExecutionId:   actionResult.ExecutionId,
						Authorization: actionResult.Authorization,
						Result:        fmt.Sprintf(`{"success": false, "reason": "Skipped because of previous node (%s) - 1"}`, actionResult.Action.Label),
						StartedAt:     0,
						CompletedAt:   0,
						Status:        "SKIPPED",
					}

					resultData, err := json.Marshal(newResult)
					if err != nil {
						log.Printf("[ERROR] Failed skipping action")
						continue
					}

					streamUrl := fmt.Sprintf("http://localhost:5001/api/v1/streams")
					if project.Environment == "cloud" {
						streamUrl = fmt.Sprintf("https://shuffler.io/api/v1/streams")

						if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
							streamUrl = fmt.Sprintf("https://%s.%s.r.appspot.com/api/v1/streams", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
						}

						if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
							streamUrl = fmt.Sprintf("%s/api/v1/streams", os.Getenv("SHUFFLE_CLOUDRUN_URL"))
						}
					} else {
						if len(os.Getenv("WORKER_HOSTNAME")) > 0 {
							streamUrl = fmt.Sprintf("http://%s:33333/api/v1/streams", os.Getenv("WORKER_HOSTNAME"))
						}

						log.Printf("[DEBUG] OPTIMIZED: %s, PORT: %s", os.Getenv("SHUFFLE_OPTIMIZED"), os.Getenv("WORKER_PORT"))
						if os.Getenv("SHUFFLE_OPTIMIZED") == "true" && len(os.Getenv("WORKER_PORT")) > 0 {
							streamUrl = fmt.Sprintf("http://localhost:%s/api/v1/streams", os.Getenv("WORKER_PORT"))
						} else if os.Getenv("SHUFFLE_SWARM_CONFIG") == "run" && (project.Environment == "" || project.Environment == "worker") {
							streamUrl = fmt.Sprintf("http://localhost:33333/api/v1/streams")

						} else {
							// Does this fuck it up? This should only run
							// if the worker is NON OPTIMIZED. Problem:
							// The worker needs to talk back to itself.
							if len(os.Getenv("BASE_URL")) > 0 {
								streamUrl = fmt.Sprintf("%s/api/v1/streams", os.Getenv("BASE_URL"))
							}
						}
					}

					//log.Printf("[DEBUG] Sending skip for action %s (%s) to URL %s", foundAction.Label, foundAction.AppName, streamUrl)

					req, err := http.NewRequest(
						"POST",
						streamUrl,
						bytes.NewBuffer([]byte(resultData)),
					)

					if err != nil {
						log.Printf("[ERROR] Error building SKIPPED request (%s): %s", foundAction.Label, err)
						continue
					}

					client := &http.Client{}
					newresp, err := client.Do(req)
					if err != nil {
						log.Printf("[ERROR] Error running SKIPPED request (%s): %s", foundAction.Label, err)
						continue
					}

					defer newresp.Body.Close()
					body, err := ioutil.ReadAll(newresp.Body)
					if err != nil {
						log.Printf("[ERROR] Failed reading body when running SKIPPED request (%s): %s", foundAction.Label, err)
						continue
					}

					//log.Printf("[DEBUG] Skipped body return from %s (%d): %s", streamUrl, newresp.StatusCode, string(body))
					if strings.Contains(string(body), "already finished") {
						log.Printf("[WARNING] Data couldn't be re-inputted for %s.", foundAction.Label)
						// DONT CHANGE THE ERROR OUTPUT HERE
						return &workflowExecution, true, errors.New(fmt.Sprintf("Workflow has already been ran with label %s. Raw: %s", foundAction.Label, string(body)))
					}
				}
			}
		}
	}

	// Related to notifications
	if actionResult.Status == "SUCCESS" && workflowExecution.Workflow.Configuration.SkipNotifications == false {
		// Marshal default failures
		resultCheck := ResultChecker{}
		err = json.Unmarshal([]byte(actionResult.Result), &resultCheck)
		if err == nil {
			//log.Printf("\n\n[WARNING] Unmarshal success in workflow %s! Trying to check for success. Success: %#v\n\n", workflowExecution.Workflow.Name, resultCheck.Success)

			if strings.Contains(strings.Replace(actionResult.Result, " ", "", -1), `"success":false`) && resultCheck.Success == false && workflowExecution.Workflow.Hidden == false {

				description := fmt.Sprintf("Node '%s' in Workflow '%s' failed silently. Failure Reason: %s", actionResult.Action.Label, workflowExecution.Workflow.Name, resultCheck.Reason)

				if len(resultCheck.Reason) == 0 {
					description = fmt.Sprintf("Node '%s' in Workflow '%s' failed silently. Check the workflow run for more details.", actionResult.Action.Label, workflowExecution.Workflow.Name)
				}

				err = CreateOrgNotification(
					ctx,
					fmt.Sprintf("Potential error in Workflow '%s'", workflowExecution.Workflow.Name),
					description,
					fmt.Sprintf("/workflows/%s?execution_id=%s&view=executions&node=%s", workflowExecution.Workflow.ID, workflowExecution.ExecutionId, actionResult.Action.ID),
					workflowExecution.ExecutionOrg,
					true,
				)

				if err != nil {
					log.Printf("[WARNING] Failed making org notification for %s: %s", workflowExecution.ExecutionOrg, err)
				} else {
					workflowExecution.NotificationsCreated++
				}
			}
		} else {
			//log.Printf("[ERROR] Failed unmarshaling result into resultChecker (%s): %s", err, actionResult)
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
				//log.Printf("EXECUTION VARIABLE LOCAL: %s", actionVarName)
				for index, execvar := range workflowExecution.ExecutionVariables {
					if execvar.Name == actionVarName {
						// Sets the value for the variable

						if len(actionResult.Result) > 0 {
							log.Printf("\n\n[DEBUG] SET EXEC VAR\n\n", execvar.Name)
							workflowExecution.ExecutionVariables[index].Value = actionResult.Result
						} else {
							log.Printf("\n\n[DEBUG] SKIPPING EXEC VAR\n\n")
						}

						break
					}
				}
			}

			log.Printf("[INFO][%s] Updating %s (%s) in workflow from %s to %s", workflowExecution.ExecutionId, actionResult.Action.Name, actionResult.Action.ID, workflowExecution.Results[outerindex].Status, actionResult.Status)

			if workflowExecution.Results[outerindex].Status != actionResult.Status {
				dbSave = true
			}

			actionResultBody, err := json.Marshal(actionResult)
			if err == nil {

				// Set cache for it too?
				cacheId := fmt.Sprintf("%s_%s_result", workflowExecution.ExecutionId, actionResult.Action.ID)
				err = SetCache(ctx, cacheId, actionResultBody, 35)
				if err != nil {
					log.Printf("[ERROR] Failed setting cache for User Input to %s: %s", actionResult.Status, err)
				} else {
					//log.Printf("[DEBUG] Set cache for SUBFLOW action result %s", cacheId)
				}
			} else {
				log.Printf("[ERROR] Failed marshaling action result for %s: %s", actionResult.Action.ID, err)
			}

			workflowExecution.Results[outerindex] = actionResult
		} else {
			workflowExecution.Results = append(workflowExecution.Results, actionResult)
		}
	} else {
		log.Printf("[INFO][%s] Setting value of %s (INIT - %s) to %s (%d)", workflowExecution.ExecutionId, actionResult.Action.Label, actionResult.Action.ID, actionResult.Status, len(workflowExecution.Results))
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
	// Auto fixing and ensuring the same isn't ran multiple times?

	extraInputs := 0
	for _, trigger := range workflowExecution.Workflow.Triggers {
		if trigger.Name == "User Input" && trigger.AppName == "User Input" {
			extraInputs += 1
		} else if trigger.Name == "Shuffle Workflow" && trigger.AppName == "Shuffle Workflow" {
			extraInputs += 1
		}
	}

	updateParentRan := false
	if len(workflowExecution.Results) == len(workflowExecution.Workflow.Actions)+extraInputs {
		//log.Printf("\nIN HERE WITH RESULTS %d vs %d\n", len(workflowExecution.Results), len(workflowExecution.Workflow.Actions)+extraInputs)
		finished := true
		lastResult := ""

		// Doesn't have to be SUCCESS and FINISHED everywhere anymore.
		//skippedNodes := false
		for _, result := range workflowExecution.Results {
			if result.Status == "EXECUTING" || result.Status == "WAITING" {
				finished = false
				break
			}

			if result.Status == "SUCCESS" {
				lastResult = result.Result
			}
		}

		if finished {
			dbSave = true
			if len(workflowExecution.ExecutionParent) == 0 {
				//log.Printf("[INFO][%s] Execution in workflow %s finished (not subflow).", workflowExecution.ExecutionId, workflowExecution.Workflow.ID)
			} else {
				log.Printf("[INFO][%s] SubExecution of parentExecution %s in workflow %s finished (subflow).", workflowExecution.ExecutionId, workflowExecution.ExecutionParent, workflowExecution.Workflow.ID)

			}

			for actionIndex, action := range workflowExecution.Workflow.Actions {
				for parameterIndex, param := range action.Parameters {
					if param.Configuration {
						//log.Printf("Cleaning up %s in %s", param.Name, action.Name)
						workflowExecution.Workflow.Actions[actionIndex].Parameters[parameterIndex].Value = ""
					}
				}
			}

			workflowExecution.Result = lastResult
			workflowExecution.Status = "FINISHED"
			workflowExecution.CompletedAt = int64(time.Now().Unix())
			if workflowExecution.LastNode == "" {
				workflowExecution.LastNode = actionResult.Action.ID
			}

			// 1. Check if the LAST node is FAILURE or ABORTED or SKIPPED
			// 2. If it's either of those, set the executionResult default value to DefaultReturnValue
			//log.Printf("\n\n===========\nSETTING VALUE TO %s\n============\nPARENT: %s\n\n", lastResult, workflowExecution.ExecutionParent)
			//log.Printf("\n\n===========\nSETTING VALUE TO %s\n============\nPARENT: %s\n\n", lastResult, workflowExecution.ExecutionParent)
			//log.Printf("%s", workflowExecution)

			valueToReturn := ""
			if len(workflowExecution.Workflow.DefaultReturnValue) > 0 {
				valueToReturn = workflowExecution.Workflow.DefaultReturnValue
				//log.Printf("\n\nCHECKING RESULT FOR LAST NODE %s with value \"%s\". Executionparent: %s\n\n", workflowExecution.ExecutionSourceNode, workflowExecution.Workflow.DefaultReturnValue, workflowExecution.ExecutionParent)
				for _, result := range workflowExecution.Results {
					if result.Action.ID == workflowExecution.LastNode {
						if result.Status == "ABORTED" || result.Status == "FAILURE" || result.Status == "SKIPPED" {
							workflowExecution.Result = workflowExecution.Workflow.DefaultReturnValue
							if len(workflowExecution.ExecutionParent) > 0 {
								// 1. Find the parent workflow
								// 2. Find the parent's existing value

								log.Printf("[DEBUG] FOUND SUBFLOW WITH EXECUTIONPARENT %s!", workflowExecution.ExecutionParent)
							}
						} else {
							valueToReturn = workflowExecution.Result
						}

						break
					}
				}
			} else {
				valueToReturn = workflowExecution.Result
			}

			// First: handle it in backend for loops
			// 2nd: Handle it in worker for normal executions
			/*
				if len(workflowExecution.ExecutionParent) > 0 && (project.Environment == "onprem") {
					//log.Printf("[DEBUG][%s] Got the result %s for subflow of %s. Check if this should be added to loop.", workflowExecution.ExecutionId, workflowExecution.Result, workflowExecution.ExecutionParent)

					parentExecution, err := GetWorkflowExecution(ctx, workflowExecution.ExecutionParent)
					if err == nil {
						isLooping := false
						for _, trigger := range parentExecution.Workflow.Triggers {
							if trigger.ID == workflowExecution.ExecutionSourceNode {
								for _, param := range trigger.Parameters {
									if param.Name == "argument" && strings.Contains(param.Value, "$") && strings.Contains(param.Value, ".#") {
										isLooping = true
										break
									}
								}

								break
							}
						}

						if isLooping {
							log.Printf("[DEBUG] Parentexecutions' subflow IS looping.")
						}
					}

				} else
			*/
			if len(workflowExecution.ExecutionParent) > 0 && len(workflowExecution.ExecutionSourceAuth) > 0 && len(workflowExecution.ExecutionSourceNode) > 0 {

				// Check if source node has "Wait for Results" set to true

				log.Printf("[DEBUG][%s] Found execution parent %s for workflow '%s' (%s)", workflowExecution.ExecutionId, workflowExecution.ExecutionParent, workflowExecution.Workflow.Name, workflowExecution.Workflow.ID)

				err = updateExecutionParent(ctx, workflowExecution.ExecutionParent, valueToReturn, workflowExecution.ExecutionSourceAuth, workflowExecution.ExecutionSourceNode, workflowExecution.ExecutionId)
				if err != nil {
					log.Printf("[ERROR][%s] Failed running update execution parent: %s", workflowExecution.ExecutionId, err)
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
				if param.Value == "true" {
					runCheck = true
				}

				break
			}
		}

		if runCheck {
			var subflowData SubflowData
			jsonerr := json.Unmarshal([]byte(actionResult.Result), &subflowData)

			// Big blob to check cache & backend for more results
			if jsonerr == nil && len(subflowData.Result) == 0 && !strings.Contains(actionResult.Result, "\"result\"") {
				if project.Environment != "cloud" {

					//Check cache for whether the execution actually finished or not
					cacheKey := fmt.Sprintf("workflowexecution_%s", subflowData.ExecutionId)
					value, err := GetCache(ctx, cacheKey)
					if err == nil {
						parsedValue := WorkflowExecution{}
						cacheData := []byte(value.([]uint8))
						err = json.Unmarshal(cacheData, &parsedValue)
						if err == nil {
							log.Printf("[INFO][%s] Found subflow result (1) %s for subflow %s in recheck from cache with %d results and result %s", workflowExecution.ExecutionId, parsedValue.Status, subflowData.ExecutionId, len(parsedValue.Results), parsedValue.Result)

							if len(parsedValue.Result) > 0 {
								subflowData.Result = parsedValue.Result
							} else if parsedValue.Status == "FINISHED" {
								subflowData.Result = "Subflow finished (PS: This is from worker autofill - happens if no actual result in subflow exec)"
							}
						}

						// Check backend
						//log.Printf("[INFO][%s] Found subflow result %s for subflow %s in recheck from cache with %d results and result %s", workflowExecution.ExecutionId, parsedValue.Status, subflowData.ExecutionId, len(parsedValue.Results), parsedValue.Result)
						if len(subflowData.Result) == 0 && !strings.Contains(actionResult.Result, "\"result\"") {
							log.Printf("[INFO][%s] No subflow result found in cache for subflow %s. Checking backend next", workflowExecution.ExecutionId, subflowData.ExecutionId)
							if len(subflowData.ExecutionId) > 0 {
								parsedValue, err := GetBackendexecution(ctx, subflowData.ExecutionId, subflowData.Authorization)
								if err != nil {
									log.Printf("[WARNING] Failed getting subflow execution from backend to verify: %s", err)
								} else {
									log.Printf("[INFO][%s] Found subflow result (2) %s for subflow %s in backend with %d results and result %s", workflowExecution.ExecutionId, parsedValue.Status, subflowData.ExecutionId, len(parsedValue.Results), parsedValue.Result)
									if len(parsedValue.Result) > 0 {
										subflowData.Result = parsedValue.Result
									} else if parsedValue.Status == "FINISHED" {
										subflowData.Result = "Subflow finished (PS: This is from worker autofill - happens if no actual result in subflow exec)"
									}
								}
							}
						}
					}
				}
			}

			log.Printf("[WARNING][%s] Sinkholing request of %s IF the subflow-result DOESNT have result.", workflowExecution.ExecutionId, actionResult.Action.Label)

			if jsonerr == nil && len(subflowData.Result) == 0 && !strings.Contains(actionResult.Result, "\"result\"") {
				log.Printf("[INFO][%s] NO RESULT FOR SUBFLOW RESULT - SETTING TO EXECUTING. Results: %d. Trying to find subexec in cache onprem", workflowExecution.ExecutionId, len(workflowExecution.Results))

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

				// Returning as we are waiting for the subflow to finish
				return &workflowExecution, dbSave, nil

			} else {
				var subflowDataList []SubflowData
				err = json.Unmarshal([]byte(actionResult.Result), &subflowDataList)

				// This is in case the list is not an actual list
				if err != nil || len(subflowDataList) == 0 {
					log.Printf("NOT sinkholed from subflow result: %s", err)
					for resultIndex, result := range workflowExecution.Results {
						if result.Action.ID == actionResult.Action.ID {
							workflowExecution.Results[resultIndex] = actionResult
							break
						}
					}

				} else {
					log.Printf("[WARNING] LIST sinkholed (len: %d) for action %s (%s) - Should apply list setup for same as subflow without result! Set the execution back to EXECUTING and the action to WAITING, as it's already running. Waiting for each individual result to add to the list.", len(subflowDataList), actionResult.Action.Label, actionResult.Action.ID)

					//log.Printf("\n\n\nRESULT: %#v\n\n\n", actionResult.Result)

					// Set to executing, as the point is for the subflows themselves to update this part. This does NOT happen in the subflow, but in the parent workflow, which is waiting for results to be ingested, hence it's set to EXECUTING

					// Setting to waiting, as it should be updated by child executions' fill-ins from their result when they finish
					workflowExecution.Status = "EXECUTING"

					amountFinished := 0
					for _, subflowData := range subflowDataList {
						if subflowData.ResultSet || len(subflowData.Result) > 0 {
							amountFinished++
						}
					}

					log.Printf("[DEBUG] %d / %d subflows finished with a result. If equal, status = SUCCESS", amountFinished, len(subflowDataList))
					actionResultCache := fmt.Sprintf("%s_%s_result", workflowExecution.ExecutionId, actionResult.Action.ID)
					if amountFinished >= len(subflowDataList) {
						actionResult.Status = "SUCCESS"

						// Force updating cache
						parsedAction, err := json.Marshal(actionResult)
						if err == nil {
							SetCache(ctx, actionResultCache, parsedAction, 35)
						}

						dbSave = true
					} else {
						actionResult.Status = "WAITING"

						DeleteCache(ctx, actionResultCache)
					}

					foundSubflow := false
					for resultIndex, result := range workflowExecution.Results {
						if result.Action.ID != actionResult.Action.ID {
							continue
						}

						foundSubflow = true
						workflowExecution.Results[resultIndex] = actionResult
						actionResultBody, err := json.Marshal(actionResult)
						if err == nil && actionResult.Status != "WAITING" {
							cacheId := fmt.Sprintf("%s_%s_result", workflowExecution.ExecutionId, actionResult.Action.ID)
							err = SetCache(ctx, cacheId, actionResultBody, 35)
							if err != nil {
								log.Printf("[ERROR] Failed setting cache for SUBFLOW to WAITING: %s", err)
							} else {
								//log.Printf("[DEBUG] Set cache for SUBFLOW action result %s", cacheId)
							}
						} else {
							//log.Printf("[ERROR] Failed marshalling action result for SUBFLOW to WAITING: %s", err)
						}

						break
					}

					if !foundSubflow {
						log.Printf("[ERROR] Failed finding subflow in results for %s (%s). Setting it in cache so that it can be loaded.", actionResult.Action.Label, actionResult.Action.ID)
					}
				}

				dbSave = true
			}
		}
	}

	workflowExecution, newDbSave := compressExecution(ctx, workflowExecution, "mid-cleanup")
	if !dbSave {
		dbSave = newDbSave
	}

	// Does it work to cache it here?
	err = SetWorkflowExecution(ctx, workflowExecution, dbSave)
	if err != nil {
		log.Printf("[ERROR][%s] Failed saving execution to DB: %s", workflowExecution.ExecutionId, err)
	}

	// Should only apply a few seconds after execution, otherwise it's bascially spam.
	if !skipExecutionCount && workflowExecution.Status == "FINISHED" {
		//IncrementCache(ctx, workflowExecution.ExecutionOrg, "workflow_executions_finished")
	}

	// Should this be able to return errors?
	//return &workflowExecution, dbSave, err
	return &workflowExecution, dbSave, nil
}

// Finds execution results and parameters that are too large to manage and reduces them / saves data partly
func compressExecution(ctx context.Context, workflowExecution WorkflowExecution, saveLocationInfo string) (WorkflowExecution, bool) {

	//GetApp(ctx context.Context, id string, user User) (*WorkflowApp, error) {
	//return workflowExecution, false
	dbSave := false
	tmpJson, err := json.Marshal(workflowExecution)
	if err == nil {
		if project.DbType != "opensearch" {
			//log.Printf("[DEBUG] Result length is %d for execution Id %s, %s", len(tmpJson), workflowExecution.ExecutionId, saveLocationInfo)
			if len(tmpJson) >= 1000000 {
				// Clean up results' actions

				//log.Printf("[DEBUG][%s](%s) ExecutionVariables size: %d, Result size: %d, executionArgument size: %d, Results size: %d", workflowExecution.ExecutionId, saveLocationInfo, len(workflowExecution.ExecutionVariables), len(workflowExecution.Result), len(workflowExecution.ExecutionArgument), len(workflowExecution.Results))

				dbSave = true
				//log.Printf("[WARNING][%s] Result length is too long (%d) when running %s! Need to reduce result size. Attempting auto-compression by saving data to disk.", workflowExecution.ExecutionId, len(tmpJson), saveLocationInfo)
				actionId := "execution_argument"

				//gs://shuffler.appspot.com/extra_specs/0373ed696a3a2cba0a2b6838068f2b80
				//log.Printf("[WARNING] Couldn't find  for %s. Should check filepath gs://%s/%s (size too big)", innerApp.ID, internalBucket, fullParsedPath)

				// Result        string `json:"result" datastore:"result,noindex"`
				// Arbitrary reduction size
				maxSize := 50000
				bucketName := fmt.Sprintf("%s.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"))

				//log.Printf("[DEBUG] Execution Argument length is %d for execution Id %s (%s)", len(workflowExecution.ExecutionArgument), workflowExecution.ExecutionId, saveLocationInfo)

				if len(workflowExecution.ExecutionArgument) > maxSize {
					itemSize := len(workflowExecution.ExecutionArgument)
					baseResult := fmt.Sprintf(`{
								"success": false,
								"reason": "Result too large to handle (https://github.com/frikky/shuffle/issues/171).",
								"size": %d,
								"extra": "",
								"id": "%s_%s"
							}`, itemSize, workflowExecution.ExecutionId, actionId)

					log.Printf("[DEBUG] len(executionArgument) is %d for execution Id %s", len(workflowExecution.ExecutionArgument), workflowExecution.ExecutionId)

					fullParsedPath := fmt.Sprintf("large_executions/%s/%s_%s", workflowExecution.ExecutionOrg, workflowExecution.ExecutionId, actionId)
					//log.Printf("[DEBUG] Saving value of %s to storage path %s", actionId, fullParsedPath)
					bucket := project.StorageClient.Bucket(bucketName)
					obj := bucket.Object(fullParsedPath)
					w := obj.NewWriter(ctx)
					if _, err := fmt.Fprint(w, workflowExecution.ExecutionArgument); err != nil {
						log.Printf("[WARNING] Failed writing new exec file: %s", err)
						workflowExecution.ExecutionArgument = baseResult
						//continue
					} else {
						// Close, just like writing a file.
						if err := w.Close(); err != nil {
							log.Printf("[WARNING] Failed closing new exec file (2): %s", err)
							workflowExecution.ExecutionArgument = baseResult
						} else {
							log.Printf("[DEBUG] Saved execution argument to %s", fullParsedPath)
							workflowExecution.ExecutionArgument = fmt.Sprintf(`{
								"success": false,
								"reason": "Result too large to handle (https://github.com/frikky/shuffle/issues/171).",
								"size": %d,
								"extra": "replace",
								"id": "%s_%s"
							}`, itemSize, workflowExecution.ExecutionId, actionId)
						}
					}
				}

				newResults := []ActionResult{}
				//shuffle-large-executions
				for _, item := range workflowExecution.Results {
					//log.Printf("[DEBUG] Result length is %d for execution Id %s (%s)", len(item.Result), workflowExecution.ExecutionId, saveLocationInfo)
					if len(item.Result) > maxSize {
						//log.Printf("[WARNING][%s](%s) result length is larger than maxSize for %s (%d)", workflowExecution.ExecutionId, saveLocationInfo, item.Action.Label, len(item.Result))

						itemSize := len(item.Result)
						baseResult := fmt.Sprintf(`{
								"success": false,
								"reason": "Result too large to handle (https://github.com/frikky/shuffle/issues/171).",
								"size": %d,
								"extra": "",
								"id": "%s_%s"
							}`, itemSize, workflowExecution.ExecutionId, item.Action.ID)

						// 1. Get the value and set it instead if it exists
						// 2. If it doesn't exist, add it
						_, err := getExecutionFileValue(ctx, workflowExecution, item)
						if err == nil {
							//log.Printf("[DEBUG][%s] Found execution file locally for '%s'. Not saving another.", workflowExecution.ExecutionId, item.Action.Label)
						} else {
							fullParsedPath := fmt.Sprintf("large_executions/%s/%s_%s", workflowExecution.ExecutionOrg, workflowExecution.ExecutionId, item.Action.ID)
							//log.Printf("[DEBUG] (1) Saving value of %s to storage path %s", item.Action.ID, fullParsedPath)
							bucket := project.StorageClient.Bucket(bucketName)
							obj := bucket.Object(fullParsedPath)
							w := obj.NewWriter(ctx)
							//log.Printf("RES: ", item.Result)
							if _, err := fmt.Fprint(w, item.Result); err != nil {
								log.Printf("[WARNING][%s] Failed writing new exec file: %s", err, workflowExecution.ExecutionId)
								item.Result = baseResult
								newResults = append(newResults, item)
								continue
							}

							// Close, just like writing a file.
							if err := w.Close(); err != nil {
								log.Printf("[WARNING][%s] Failed closing new exec file (1): %s", err, workflowExecution.ExecutionId)
								item.Result = baseResult
								newResults = append(newResults, item)
								continue
							}
						}

						item.Result = fmt.Sprintf(`{
								"success": false,
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
					//log.Printf("[DEBUG][%s] newResults: %d and item labelled %s length is: %d", workflowExecution.ExecutionId, len(newResults), item.Action.Label, len(item.Result))
				}

				//log.Printf("[DEBUG][%s](%s) Overwriting executions results now! newResults length: %d", workflowExecution.ExecutionId, saveLocationInfo, len(newResults))
				workflowExecution.Results = newResults
			}

			jsonString, err := json.Marshal(workflowExecution)
			if err == nil {
				//log.Printf("[DEBUG] Execution size: %d for %s", len(jsonString), workflowExecution.ExecutionId)
				if len(jsonString) > 1000000 {
					//log.Printf("[WARNING][%s] Execution size is still too large (%d) when running %s!", workflowExecution.ExecutionId, len(jsonString), saveLocationInfo)
					//for _, action := range workflowExecution.Workflow.Actions {
					//	actionData, err := json.Marshal(action)
					//	if err == nil {
					//		//log.Printf("[DEBUG] Action Size for %s (%s - %s): %d", action.Label, action.Name, action.ID, len(actionData))
					//	}
					//}

					for resultIndex, result := range workflowExecution.Results {
						//resultData, err := json.Marshal(result)
						//_ = resultData
						actionData, err := json.Marshal(result.Action)
						if err == nil {
							// log.Printf("[DEBUG] Result Size (%s - action: %d): %d. Value size: %d", result.Action.Label, len(resultData), len(actionData), len(result.Result))
						}

						if len(actionData) > 10000 {
							for paramIndex, param := range result.Action.Parameters {
								if len(param.Value) > 10000 {
									workflowExecution.Results[resultIndex].Action.Parameters[paramIndex].Value = "Size too large. Removed."
								}
							}
						}
					}
				}
			}
		}
	}

	return workflowExecution, dbSave
}

// Finds the child nodes of a node in execution and returns them
// Used if e.g. a node in a branch is exited, and all children have to be stopped
func FindChildNodes(workflowExecution WorkflowExecution, nodeId string, parents, handledBranches []string) []string {
	allChildren := []string{nodeId}

	// 1. Find children of this specific node
	// 2. Find the children of those nodes etc.
	// 3. Sort it in the right order to handle merges properly
	for _, branch := range workflowExecution.Workflow.Branches {
		if branch.SourceID == nodeId {
			if ArrayContains(parents, branch.DestinationID) {
				continue
			}

			parents = append(parents, branch.SourceID)
			if ArrayContains(handledBranches, branch.ID) {
				continue
			}

			//log.Printf("NODE: %s, SRC: %s, CHILD: %s\n", nodeId, branch.SourceID, branch.DestinationID)
			allChildren = append(allChildren, branch.DestinationID)

			handledBranches = append(handledBranches, branch.ID)
			childNodes := FindChildNodes(workflowExecution, branch.DestinationID, parents, handledBranches)
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
		if tmpnode == nodeId {
			continue
		}

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

// Also deactivates. It's a toggle for off and on.
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
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	ctx := GetContext(request)
	location := strings.Split(request.URL.String(), "/")
	var fileId string
	activate := true
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
		if strings.ToLower(location[5]) == "deactivate" {
			activate = false
		}
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
			if project.Environment == "cloud" && gceProject != "shuffler" {
				app, err := HandleAlgoliaAppSearch(ctx, fileId)
				if err == nil {
					// this means that the app exists. so, let's
					// ask our propagator to proagate it further.
					log.Printf("[INFO] Found apps %s - %s in algolia", app.Name, app.ObjectID)

					if app.ObjectID != fileId {
						log.Printf("[WARNING] App %s doesn't exist in algolia", fileId)
						resp.WriteHeader(401)
						resp.Write([]byte(`{"success": false, "reason": "App doesn't exist"}`))
						return
					}
					// i can in theory, run this without using goroutines
					// and then recursively call the same function. but that
					// would make this request way too long.
					go func() {
						err = propagateApp(fileId, false)
						if err != nil {
							log.Printf("[WARNING] Error propagating app %s - %s: %s", app.Name, app.ObjectID, err)
						} else {
							log.Printf("[INFO] Propagated app %s - %s. Sending request again!", app.Name, app.ObjectID)
						}
					}()

					resp.WriteHeader(202)
					resp.Write([]byte(`{"success": false, "reason": "Taking care of some magic. Please try activation again in a few seconds!"}`))
					return
				} else {
					log.Printf("[WARNING] Error getting app %s (algolia): %s", appName, err)
				}
			}
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "App doesn't exist"}`))
			return
		}
	}

	org := &Org{}
	added := false
	if app.Sharing || app.Public || !activate {
		org, err = GetOrg(ctx, user.ActiveOrg.Id)
		if err == nil {
			if len(org.ActiveApps) > 150 {
				// No reason for it to be this big. Arbitrarily reducing.
				same := []string{}
				samecnt := 0
				for _, activeApp := range org.ActiveApps {
					if ArrayContains(same, activeApp) {
						samecnt += 1
						continue
					}

					same = append(same, activeApp)
				}

				added = true
				//log.Printf("Same: %d, total uniq: %d", samecnt, len(same))
				org.ActiveApps = org.ActiveApps[len(org.ActiveApps)-100 : len(org.ActiveApps)-1]
			}

			if activate {
				if !ArrayContains(org.ActiveApps, app.ID) {
					org.ActiveApps = append(org.ActiveApps, app.ID)
					added = true
				}
			} else {
				// Remove from the array
				newActiveApps := []string{}
				for _, activeApp := range org.ActiveApps {
					if activeApp == app.ID {
						continue
					}

					newActiveApps = append(newActiveApps, activeApp)
				}

				org.ActiveApps = newActiveApps
				added = true
			}

			if added {
				err = SetOrg(ctx, *org, org.Id)
				if err != nil {
					log.Printf("[WARNING] Failed setting org when autoadding apps on save: %s", err)
				} else {
					addRemove := "Added"
					if !activate {
						addRemove = "Removed"
					}

					log.Printf("[INFO] %s public app %s (%s) to/from org %s (%s). Activated apps: %d", addRemove, app.Name, app.ID, user.ActiveOrg.Name, user.ActiveOrg.Id, len(org.ActiveApps))
					DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
					DeleteCache(ctx, fmt.Sprintf("apps_%s", user.ActiveOrg.Id))

					if project.Environment == "cloud" && gceProject != "shuffler" {
						// propagate org.ActiveApps to the main region
						go func() {
							// wait for a second before propagating again
							log.Printf("[INFO] Propagating org %s after sleeping for a second!", user.ActiveOrg.Id)
							time.Sleep(1 * time.Second)
							err = propagateOrg(*org, true)
							if err != nil {
								log.Printf("[WARNING] Error propagating org %s: %s", user.ActiveOrg.Id, err)
							}
						}()
					}

				}
			}
		}
	} else {
		log.Printf("[WARNING] User is trying to activate %s which is NOT a public app", app.Name)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if activate {
		log.Printf("[DEBUG] App %s (%s) activated for org %s by user %s (%s). Active apps: %d. Already existed: %t", app.Name, app.ID, user.ActiveOrg.Id, user.Username, user.Id, len(org.ActiveApps), !added)
	} else {
		log.Printf("[DEBUG] App %s (%s) deactivated for org %s by user %s (%s). Active apps: %d. Already existed: %t", app.Name, app.ID, user.ActiveOrg.Id, user.Username, user.Id, len(org.ActiveApps), !added)
	}

	DeleteCache(ctx, fmt.Sprintf("apps_%s", user.ActiveOrg.Id))
	DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
	DeleteCache(ctx, "all_apps")
	DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-100"))
	DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-500"))
	DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-1000"))

	// If onprem, it should autobuild the container(s) from here

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func GetExecutionbody(body []byte) string {
	parsedBody := string(body)

	// Specific weird newline issues
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

	// Replaces dots in string when it's key specifically has a dot
	// FIXME: Do this with key recursion and key replacements only
	pattern := regexp.MustCompile(`\"(\w+)\.(\w+)\":`)
	found := pattern.FindAllString(parsedBody, -1)
	for _, item := range found {
		newItem := strings.Replace(item, ".", "_", -1)
		parsedBody = strings.Replace(parsedBody, item, newItem, -1)
	}

	if !strings.HasPrefix(parsedBody, "{") && !strings.HasPrefix(parsedBody, "[") && strings.Contains(parsedBody, "=") {
		//log.Printf("[DEBUG] Trying to make string %s to json (skipping if XML, doing queries & k:v)", parsedBody)

		// Dumb XML handler
		if strings.HasPrefix(strings.TrimSpace(parsedBody), "<") && strings.HasSuffix(strings.TrimSpace(parsedBody), ">") {
			log.Printf("[DEBUG] XML detected. Not parsing anyything.")
			return parsedBody
		}

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
			log.Printf("[ERROR] Failed marshaling queries: %s: %s", newbody, err)
		} else {
			parsedBody = string(jsonString)
		}
		//fmt.Printf(err)
		//log.Printf("BODY: %s", newbody)
	}

	// Check bad characters in keys
	// FIXME: Re-enable this when it's safe.
	//log.Printf("Input: %s", parsedBody)
	parsedBody = string(FixBadJsonBody([]byte(parsedBody)))
	//log.Printf("Output: %s", parsedBody)

	return parsedBody
}

// Can't just regex out stuff due to unicode problems with other languages
func handleKeyRemoval(key string) string {
	abolish := []string{"!", "@", "#", "$", "%", "~", "|", "^", "&", "*", "(", ")", "[", "]", "{", "}", "<", ">", "+", "=", "?", ".", ",", "/", "\\", "'"}

	for _, remove := range abolish {
		key = strings.Replace(key, remove, "", -1)
	}

	return key
}

// https://www.codemio.com/2021/02/advanced-golang-tutorials-dynamic-json-parsing.html
func handleJSONObject(object interface{}, key, totalObject string) string {
	currentObject := ""
	key = handleKeyRemoval(key)

	switch t := object.(type) {
	case int:
		currentObject += fmt.Sprintf(`"%s": %d, `, key, t)
		if len(key) == 0 {
			currentObject += fmt.Sprintf(`%d, `, t)
		}
	case int64:
		currentObject += fmt.Sprintf(`"%s": %d, `, key, t)
		if len(key) == 0 {
			currentObject += fmt.Sprintf(`%d, `, t)
		}
	case float64:
		tmpObject := fmt.Sprintf(`"%s": %f, `, key, t)
		if len(key) == 0 {
			tmpObject = fmt.Sprintf(`%f, `, t)
		}

		if strings.HasSuffix(tmpObject, "000000, ") {
			tmpObject = tmpObject[0 : len(tmpObject)-9]
			tmpObject += ", "
		}

		currentObject += tmpObject
	case bool:
		if len(key) == 0 {
			currentObject += fmt.Sprintf(`%v, `, t)
		} else {
			currentObject += fmt.Sprintf(`"%s": %v, `, key, t)
		}
	case string:
		if len(key) == 0 {
			currentObject += fmt.Sprintf(`"%s", `, t)
		} else {
			currentObject += fmt.Sprintf(`"%s": "%s", `, key, t)
		}
	case map[string]interface{}:
		if len(key) == 0 {
			currentObject += fmt.Sprintf(`{`)
		} else {
			currentObject += fmt.Sprintf(`"%s": {`, key)
		}

		for k, v := range t {
			currentObject = handleJSONObject(v, k, currentObject)
		}

		if len(currentObject) > 3 {
			currentObject = currentObject[0 : len(currentObject)-2]
		}

		currentObject += "}, "
	case []interface{}:
		if len(key) == 0 {
			currentObject += fmt.Sprintf(`[`)
		} else {
			currentObject += fmt.Sprintf(`"%s": [`, key)
		}

		for _, v := range t {
			currentObject = handleJSONObject(v, "", currentObject)
		}

		if len(currentObject) > 3 {
			currentObject = currentObject[0 : len(currentObject)-2]
		}

		currentObject += "], "
	default:
		log.Printf("[ERROR] Missing handler for type %s in app framework - key: %s", t, key)
	}

	totalObject += currentObject
	return totalObject
}

func FixBadJsonBody(parsedBody []byte) []byte {
	if os.Getenv("SHUFFLE_JSON_PARSER") != "parse" {
		return parsedBody
	}
	// NOT handling data that starts as a loop for now: [] instead of {} as outer wrapper.
	// Lists and all other types do work inside the JSON, and are rebuilt with a new key (if applicable).

	if !strings.HasPrefix(string(parsedBody), "{") {
		return parsedBody
	}

	var results map[string]interface{}
	err := json.Unmarshal([]byte(parsedBody), &results)
	if err != nil {
		log.Printf("[WARNING] Failed parsing data: %s", err)
		return parsedBody
	}

	totalObject := "{"
	for key, value := range results {
		_ = value
		totalObject = handleJSONObject(value, key, totalObject)
	}

	if len(totalObject) > 3 {
		totalObject = totalObject[0 : len(totalObject)-2]
	}

	totalObject += "}"

	//log.Printf("Auto sanitized keys.: %s", totalObject)
	//for _, result := range results {
	//	// But if you don't know the field types, you can use type switching to determine (safe):
	//	// Keep in mind that, since this is a map, the order is not guaranteed.
	//	fmt.Printf("\nType Switching: ")
	//	for k := range result {
	//	}

	//	fmt.Printf("------------------------------")
	//}

	return []byte(totalObject)
}

func ValidateSwagger(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just here to verify that the user is logged in
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in validate swagger: %s", err)
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
	//log.Printf(string(body))
	//tmpbody, err := yaml.YAMLToJSON(body)
	//log.Printf(err)
	//log.Printf(string(tmpbody))

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
		log.Printf("[WARNING] Json upload err: %s", err)

		body = []byte(strings.Replace(string(body), "\\/", "/", -1))
		err = yaml.Unmarshal(body, &version)
		if err != nil {
			log.Printf("[WARNING] Yaml error (3): %s", err)
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

	log.Printf("[INFO] Version: %s", version)
	log.Printf("[INFO] OpenAPI: %s", version.OpenAPI)
	if strings.HasPrefix(version.Swagger, "3.") || strings.HasPrefix(version.OpenAPI, "3.") {
		log.Printf("[INFO] Handling v3 API")
		swaggerLoader := openapi3.NewSwaggerLoader()
		swaggerLoader.IsExternalRefsAllowed = true
		//swagger, err := swaggerLoader.LoadSwaggerFromData(body)

		swagger := &openapi3.Swagger{}
		swagger, err = swaggerLoader.LoadSwaggerFromData(body)
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
			log.Printf("[WARNING] Failed unmarshaling v3 data: %s", err)
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed marshalling swaggerv3 data: %s"}`, err)))
			return
		}
		parsed := ParsedOpenApi{
			ID:   idstring,
			Body: string(swaggerdata),
		}

		ctx := GetContext(request)
		err = SetOpenApiDatastore(ctx, idstring, parsed)
		if err != nil {
			log.Printf("[WARNING] Failed uploading openapi to datastore: %s", err)
			resp.WriteHeader(422)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed reading openapi2: %s"}`, err)))
			return
		}

		log.Printf("[INFO] Successfully set OpenAPI with name %s and ID %s", swagger.Info.Title, idstring)
		resp.WriteHeader(200)
		resp.Write([]byte(fmt.Sprintf(`{"success": true, "id": "%s"}`, idstring)))
		return
	} else { //strings.HasPrefix(version.Swagger, "2.") || strings.HasPrefix(version.OpenAPI, "2.") {
		// Convert
		log.Printf("[WARNING] Handling v2 API")
		swagger := openapi2.Swagger{}
		//log.Printf(string(body))
		err = json.Unmarshal(body, &swagger)
		if err != nil {
			log.Printf("[WARNING] Json error for v2 - trying yaml next: %s", err)
			err = yaml.Unmarshal([]byte(body), &swagger)
			if err != nil {
				log.Printf("[WARNING] Yaml error (4): %s", err)

				resp.WriteHeader(422)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed reading openapi2: %s"}`, err)))
				return
			} else {
				log.Printf("Found valid yaml!")
			}

		}

		swaggerv3, err := openapi2conv.ToV3Swagger(&swagger)
		if err != nil {
			log.Printf("[WARNING] Failed converting from openapi2 to 3: %s", err)
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

		ctx := GetContext(request)
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
	//log.Printf("FIND CHILDNODES OF STARTNODE %s", workflowAction)
	workflowExecution := WorkflowExecution{
		Workflow: *workflow,
	}

	childNodes := FindChildNodes(workflowExecution, workflowAction, []string{}, []string{})
	//log.Printf("Found %d childnodes of %s", len(childNodes), workflowAction)
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

		if changed {
			return newActions, branches, lastNode
		}
	}

	return []Action{}, []Branch{}, ""
}

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

func handleKeyEncryption(data []byte, passphrase string) ([]byte, error) {
	key, err := create32Hash(passphrase)
	if err != nil {
		log.Printf("[WARNING] Failed hashing in encrypt: %s", err)
		return []byte{}, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("[WARNING] Error generating ciphertext: %s", err)
		return []byte{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("[WARNING] Error creating new GCM from block: %s", err)
		return []byte{}, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Printf("[WARNING] Error reading GCM nonce: %s", err)
		return []byte{}, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// base64 encoding to ensure we can store it as a string
	parsedValue := base64.StdEncoding.EncodeToString(ciphertext)
	return []byte(parsedValue), nil
}

func HandleKeyDecryption(data []byte, passphrase string) ([]byte, error) {
	//log.Printf("[DEBUG] Passphrase: %s", passphrase)
	//log.Printf("Decrypting key: %s", data)
	key, err := create32Hash(passphrase)
	if err != nil {
		log.Printf("[ERROR] Failed hashing in decrypt: %s", err)
		return []byte{}, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("[ERROR] Error creating cipher from key in decryption: %s", err)
		return []byte{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("[ERROR] Error creating new GCM block in decryption: %s", err)
		return []byte{}, err
	}

	parsedData, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		//log.Printf("[WARNING] Failed base64 decode for auth key '%s': '%s'. Data: '%s'. Returning as if this is valid.", data, err, string(data))
		//return []byte{}, err
		return data, nil
	}

	nonceSize := gcm.NonceSize()
	if nonceSize > len(parsedData) {
		log.Printf("[ERROR] Nonce size is larger than parsed data. Returning as if this is valid.")
		return data, nil
	}

	nonce, ciphertext := parsedData[:nonceSize], parsedData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		//log.Printf("[ERROR] Error reading decryptionkey: %s - nonce: %s, ciphertext: %s", err, nonce, ciphertext)
		//log.Printf("[ERROR] Error reading decryptionkey: %s - nonce: %s", err, nonce)
		return []byte{}, err
	}

	return plaintext, nil
}

func HandleListCacheKeys(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[DEBUG] Api authentication failed in list cache keys: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
		return
	}

	if user.Role != "admin" && !user.SupportAccess {
		log.Printf("[AUDIT] User %s (%s) tried to list cache keys without admin role", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Admin required"}`))
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

	if fileId == "undefined" {
		fileId = user.ActiveOrg.Id
	}

	ctx := GetContext(request)
	org, err := GetOrg(ctx, fileId)
	if err != nil {
		log.Printf("[INFO] Organization doesn't exist: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	maxAmount := 30
	top, topOk := request.URL.Query()["top"]
	if topOk && len(top) > 0 {
		val, err := strconv.Atoi(top[0])
		if err == nil {
			maxAmount = val
		}
	}

	cursor := ""
	cursorList, cursorOk := request.URL.Query()["cursor"]
	if cursorOk && len(cursorList) > 0 {
		cursor = cursorList[0]
	}

	keys, newCursor, err := GetAllCacheKeys(ctx, org.Id, maxAmount, cursor)
	isSuccess := true
	if err != nil {
		isSuccess = false
	}

	newReturn := CacheReturn{
		Success: isSuccess,
		Keys:    keys,
		Cursor:  newCursor,
	}

	b, err := json.Marshal(newReturn)
	if err != nil {
		log.Printf("[WARNING] Failed to marshal cache keys for org %s: %s", org.Id, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Something went wrong in cache key json management. Please refresh."}`))
		return
	}

	if err != nil {
		log.Printf("[INFO] Failed getting cache key list for org %s: %s", org.Id, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(b)
}

func HandleDeleteCacheKey(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[DEBUG] Api authentication failed in delete cache key: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
		return
	}

	//for key, value := range data.Apps {
	var orgId string
	var cacheKey string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("Path too short: %d", len(location))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		orgId = location[4]
		cacheKey = location[6]
	}

	if len(cacheKey) == 0 || len(orgId) == 0 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Missing org id or cache key"}`))
		return
	}

	ctx := GetContext(request)
	if orgId != user.ActiveOrg.Id {
		log.Printf("[INFO] OrgId %s and %s don't match", orgId, user.ActiveOrg.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Organization ID's don't match"}`))
		return
	}

	cacheKey, err = url.QueryUnescape(strings.Trim(cacheKey, " "))
	if err != nil {
		log.Printf("[WARNING] Failed to unescape cache key %s: %s", err)
		cacheKey = strings.Trim(cacheKey, " ")
	}

	//cacheKey = strings.Replace(cacheKey, "%20", " ", -1)
	cacheKey = strings.Trim(cacheKey, " ")
	cacheId := fmt.Sprintf("%s_%s", orgId, cacheKey)

	cacheData, err := GetCacheKey(ctx, cacheId)
	if err != nil || cacheData.Key == "" {
		log.Printf("[WARNING] Failed to GET cache key '%s' for org %s (delete)", cacheId, orgId)
		resp.WriteHeader(400)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to get key. Does it exist?", "extra": "%s"}`, cacheData.Key)))
		return
	}

	if cacheData.OrgId != user.ActiveOrg.Id {
		log.Printf("[INFO] OrgId '%s' and '%s' don't match", cacheData.OrgId, user.ActiveOrg.Id)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Organization ID's don't match"}`))
		return
	}

	entity := "org_cache"

	DeleteKey(ctx, entity, cacheId)
	if len(cacheData.WorkflowId) > 0 {
		escapedKey := url.QueryEscape(cacheKey)

		DeleteKey(ctx, entity, fmt.Sprintf("%s_%s_%s", orgId, cacheData.WorkflowId, cacheData.Key))
		DeleteKey(ctx, entity, fmt.Sprintf("%s_%s_%s", orgId, cacheData.WorkflowId, escapedKey))

		DeleteKey(ctx, entity, fmt.Sprintf("%s_%s", cacheData.WorkflowId, cacheData.Key))

		DeleteKey(ctx, entity, fmt.Sprintf("%s_%s", cacheData.WorkflowId, escapedKey))
	}

	DeleteCache(ctx, cacheKey)
	DeleteCache(ctx, fmt.Sprintf("%s_%s", entity, cacheKey))
	DeleteCache(ctx, fmt.Sprintf("%s_%s", entity, orgId))

	log.Printf("[INFO] Successfully Deleted key '%s' for org %s", cacheKey, orgId)
	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleDeleteCacheKeyPost(resp http.ResponseWriter, request *http.Request) {
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
		log.Printf("[WARNING] Failed unmarshalling in DELETE cache value: %s", err)
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

	ctx := GetContext(request)
	org, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("[INFO] Organization doesn't exist: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	selectedOrg := tmpData.OrgId
	if len(tmpData.ExecutionId) > 0 {
		workflowExecution, err := GetWorkflowExecution(ctx, tmpData.ExecutionId)
		if err != nil {
			log.Printf("[INFO] Failed getting the execution: %s", err)
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
	} else {
		// Fail over to user if exec isn't there

		user, err := HandleApiAuthentication(resp, request)
		if err != nil {
			log.Printf("[INFO] Missing auth when deleting key %s for org %s", tmpData.Key, tmpData.OrgId)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
			return
		}

		if user.ActiveOrg.Id != org.Id {
			org, err = GetOrg(ctx, user.ActiveOrg.Id)
			if err != nil {
				log.Printf("[INFO] Organization doesn't exist in cache delete: %s", err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false}`))
				return
			}
		}

		selectedOrg = user.ActiveOrg.Id
	}

	tmpData.Key = strings.Trim(tmpData.Key, " ")
	cacheId := fmt.Sprintf("%s_%s", selectedOrg, tmpData.Key)
	cacheData, err := GetCacheKey(ctx, cacheId)

	log.Printf("[DEBUG] Attempting to delete cache key '%s' for org %s", tmpData.Key, tmpData.OrgId)

	if err != nil {
		log.Printf("[WARNING] Failed to DELETE cache key %s for org %s (delete). Does it exist?", tmpData.Key, tmpData.OrgId)
		resp.WriteHeader(400)

		result := ResultChecker{
			Success: false,
			Reason:  "Failed to get key. Does it exist?",
			Extra:   fmt.Sprintf("Attempted to delete key '%s'", tmpData.Key),
		}

		marshalled, err := json.Marshal(result)
		if err != nil {
			resp.Write([]byte(`{"success": false, "reason": "Failed to get key. Does it exist?"}`))
			return
		}

		resp.Write(marshalled)
		return
	}

	entity := "org_cache"
	DeleteKey(ctx, entity, url.QueryEscape(cacheId))
	err = DeleteKey(ctx, entity, cacheId)
	if err != nil {
		log.Printf("[WARNING] Failed to DELETE cache key %s for org %s (delete)", tmpData.Key, tmpData.OrgId)
	}

	if len(cacheData.WorkflowId) > 0 {
		escapedKey := url.QueryEscape(tmpData.Key)

		DeleteKey(ctx, entity, fmt.Sprintf("%s_%s_%s", org.Id, cacheData.WorkflowId, cacheData.Key))
		DeleteKey(ctx, entity, fmt.Sprintf("%s_%s_%s", org.Id, cacheData.WorkflowId, escapedKey))

		DeleteKey(ctx, entity, fmt.Sprintf("%s_%s", cacheData.WorkflowId, cacheData.Key))
		DeleteKey(ctx, entity, fmt.Sprintf("%s_%s", cacheData.WorkflowId, escapedKey))
	}

	DeleteCache(ctx, tmpData.Key)
	DeleteCache(ctx, fmt.Sprintf("%s_%s", entity, tmpData.Key))
	DeleteCache(ctx, fmt.Sprintf("%s_%s", entity, org.Id))
	DeleteCache(ctx, fmt.Sprintf("%s_%s", entity, cacheId))
	DeleteCache(ctx, fmt.Sprintf("%s_%s", entity, url.QueryEscape(cacheId)))

	result := ResultChecker{
		Success: true,
		Reason:  fmt.Sprintf("Key '%s' deleted", tmpData.Key),
	}

	// Marshal
	resp.WriteHeader(200)
	jsonResult, err := json.Marshal(result)
	if err != nil {
		log.Printf("[WARNING] Failed to marshal result: %s", err)
		resp.Write([]byte(`{"success": true}`))
		return
	}

	resp.Write([]byte(jsonResult))
}

func HandleGetCacheKey(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
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

	if strings.Contains(fileId, "?") {
		fileId = strings.Split(fileId, "?")[0]
	}

	// Check if request method is POST
	// 3 different auth mechanisms due to public exposing of this endpoint, and for use in workflows
	query := request.URL.Query()
	requireCacheAuth := false
	skipExecutionAuth := false

	var tmpData CacheKeyData
	if request.Method == "POST" {
		body, err := ioutil.ReadAll(request.Body)
		if err != nil {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
			return
		}

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
	} else {
		if len(location) <= 6 {
			log.Printf("[ERROR] Cache Path too short: %d", len(location))
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		if strings.Contains(location[6], "?") {
			location[6] = strings.Split(location[6], "?")[0]
		}

		// urlescape
		parsedCacheKey, err := url.QueryUnescape(location[6])
		if err != nil {
			log.Printf("[ERROR] Failed to unescape cache key: %s", err)
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		tmpData = CacheKeyData{
			OrgId: fileId,
			Key:   parsedCacheKey,
		}

		// Use normal user auth

		user, err := HandleApiAuthentication(resp, request)
		if err != nil {
			// Check if authorization query exists
			if len(query.Get("authorization")) == 0 {
				log.Printf("[INFO] Failed to authenticate user in GET cache key: %s", err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "No authorization provided"}`))
				return
			}

			requireCacheAuth = true
			user.ActiveOrg.Id = fileId
		}

		if user.ActiveOrg.Id != fileId {
			log.Printf("[INFO] OrgId %s and %s don't match in get cache key list. Checking cache auth", user.ActiveOrg.Id, fileId)

			requireCacheAuth = true
			user.ActiveOrg.Id = fileId

			/*
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "Organization ID's don't match"}`))
				return
			*/
		}

		skipExecutionAuth = true
	}

	ctx := GetContext(request)

	org, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("[INFO] Organization '%s' doesn't exist in get cache: %s", tmpData.OrgId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	executionId := ""
	if !skipExecutionAuth {
		workflowExecution, err := GetWorkflowExecution(ctx, tmpData.ExecutionId)
		if err != nil {
			log.Printf("[INFO] Failed getting the execution: %s", err)
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

		executionId = workflowExecution.ExecutionId
	}

	tmpData.Key = strings.Trim(tmpData.Key, " ")
	cacheId := fmt.Sprintf("%s_%s", tmpData.OrgId, tmpData.Key)
	cacheData, err := GetCacheKey(ctx, cacheId)
	if err != nil {

		// Doing a last resort search, e.g. to handle spaces and the like
		allkeys, _, err := GetAllCacheKeys(ctx, org.Id, 30, "")
		if err == nil {
			cacheData = &CacheKeyData{}
			searchkey := strings.ReplaceAll(strings.Trim(strings.ToLower(tmpData.Key), " "), " ", "_")

			for _, key := range allkeys {
				tmpkey := strings.ReplaceAll(strings.Trim(strings.ToLower(key.Key), " "), " ", "_")

				log.Printf("%s vs %s", tmpkey, searchkey)
				if tmpkey == searchkey {
					log.Printf("\n\n[INFO] Found key %s for org %s\n\n", key.Key, org.Id)
					cacheData = &key
					break
				}
			}

			if cacheData.Key == "" {
				log.Printf("[WARNING] Failed to GET cache key %s for org %s (get)", tmpData.Key, tmpData.OrgId)
				resp.WriteHeader(400)
				resp.Write([]byte(`{"success": false, "reason": "Failed authentication or key doesn't exist"}`))
				return
			}

		} else {
			log.Printf("[WARNING][%s] Failed to GET cache key %s for org %s (get)", executionId, tmpData.Key, tmpData.OrgId)
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "Failed authentication or key doesn't exist"}`))
			return
		}
	}

	if requireCacheAuth {
		authQuery := query.Get("authorization")

		log.Printf("[INFO] Cache auth required for '%s'. Input auth: %s. Required auth: %#v", tmpData.Key, authQuery, cacheData.PublicAuthorization)
		if cacheData.PublicAuthorization == "" || authQuery != cacheData.PublicAuthorization {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed authentication or key doesn't exist"}`))
			return
		}
	}

	cacheData.Success = true
	cacheData.ExecutionId = ""
	cacheData.Authorization = ""
	cacheData.OrgId = ""

	// Look for query param "type"
	typeQuery := query.Get("type")

	// Check for header accept
	if typeQuery == "text" || typeQuery == "raw" || request.Header.Get("Accept") == "text/plain" {
		if typeQuery == "text" {
			// Check if the value is valid JSON or not

			var newstring = ""
			var jsonCheck []interface{}
			// If it's valid JSON list, add all items to a string with newlines

			err := json.Unmarshal([]byte(cacheData.Value), &jsonCheck)
			if err == nil {
				for _, item := range jsonCheck {
					newstring += fmt.Sprintf("%v\n", item)
				}
			}

			if newstring != "" {
				cacheData.Value = newstring
			}
		}

		resp.Header().Set("Content-Type", "text/plain")
		resp.WriteHeader(200)
		resp.Write([]byte(cacheData.Value))

		return
	} else if typeQuery == "json" {
		resp.Header().Set("Content-Type", "application/json")

		//validate if it's json or not
		isValidJson := false
		cacheData.Value = strings.Trim(cacheData.Value, " ")
		if strings.HasPrefix(cacheData.Value, "{") && strings.HasSuffix(cacheData.Value, "}") || strings.HasPrefix(cacheData.Value, "[") && strings.HasSuffix(cacheData.Value, "]") {
			// Check if it's a list of JSON
			listMarshalled := []interface{}{}
			err := json.Unmarshal([]byte(cacheData.Value), &listMarshalled)
			if err == nil {
				isValidJson = true

				outputBody, err := json.MarshalIndent(listMarshalled, "", "  ")
				if err == nil {
					cacheData.Value = string(outputBody)
				}
			} else {
				objectMarshalled := map[string]interface{}{}
				err := json.Unmarshal([]byte(cacheData.Value), &objectMarshalled)
				if err == nil {
					isValidJson = true

					outputBody, err := json.MarshalIndent(objectMarshalled, "", "  ")
					if err == nil {
						cacheData.Value = string(outputBody)
					}
				} else {
					//log.Printf("[INFO] Cache key %s for org %s isn't valid JSON: '%s'", tmpData.Key, tmpData.OrgId, cacheData.Value)
					isValidJson = false
				}
			}
		}

		if !isValidJson {
			jsonlist := []string{}
			if strings.Contains(cacheData.Value, "\n") {
				if strings.Count(cacheData.Value, "\n") == 1 {
					if strings.Contains(cacheData.Value, ",") {
						jsonlist = strings.Split(cacheData.Value, ",")
					} else {
						jsonlist = strings.Split(cacheData.Value, "\n")
					}
				} else {
					jsonlist = strings.Split(cacheData.Value, "\n")
				}
			}

			parsedJsonlist, err := json.MarshalIndent(jsonlist, "", "  ")
			if err != nil {
				log.Printf("[WARNING] Failed to parse JSON list for key %s for org %s", tmpData.Key, tmpData.OrgId)
				resp.WriteHeader(500)
				resp.Write([]byte(`{"success": false, "reason": "Failed to parse JSON list"}`))
				return
			}

			cacheData.Value = string(parsedJsonlist)
		}

		resp.WriteHeader(200)
		resp.Write([]byte(cacheData.Value))
		return
	}

	b, err := json.Marshal(cacheData)
	if err != nil {
		log.Printf("[WARNING] Failed to marshal cache data %s for org %s", tmpData.Key, tmpData.OrgId)
		resp.WriteHeader(500)
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

	user, usererr := HandleApiAuthentication(resp, request)

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Failed reading body in set cache: %s", err)
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

	ctx := GetContext(request)

	if len(tmpData.OrgId) == 0 {
		//log.Printf("[INFO] No org id specified. User org: %#v", user.ActiveOrg)
		tmpData.OrgId = user.ActiveOrg.Id
	}

	org, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("[WARNING] Organization doesn't exist: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	workflowExecution, err := GetWorkflowExecution(ctx, tmpData.ExecutionId)
	if err != nil {
		if len(tmpData.ExecutionId) > 0 {
			log.Printf("[WARNING] Failed getting exec: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "No permission to get execution"}`))
			return
		}

		workflowExecution.Authorization = uuid.NewV4().String()
	}

	if workflowExecution.Authorization != tmpData.Authorization || len(tmpData.Authorization) == 0 || len(workflowExecution.Authorization) == 0 {

		// Get the user?
		if usererr != nil {
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

			tmpData.OrgId = user.ActiveOrg.Id
		}
	} else {
		if workflowExecution.Status != "EXECUTING" {
			log.Printf("[INFO] Workflow '%s' isn't executing and shouldn't be searching", workflowExecution.ExecutionId)
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "Workflow isn't executing"}`))
			return
		}

		if workflowExecution.ExecutionOrg != org.Id {
			log.Printf("[INFO] Org '%s' wasn't used to execute %s", org.Id, workflowExecution.ExecutionId)
			resp.WriteHeader(403)
			resp.Write([]byte(`{"success": false, "reason": "Bad organization specified"}`))
			return
		}
	}

	if tmpData.OrgId != fileId {
		log.Printf("[INFO] OrgId '%s' and '%s' don't match (set cache)", tmpData.OrgId, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Organization ID's don't match"}`))
		return
	}

	if len(tmpData.Value) == 0 {
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Value can't be empty"}`))
		return
	}

	tmpData.Key = strings.Trim(tmpData.Key, " ")
	err = SetCacheKey(ctx, tmpData)
	if err != nil {
		log.Printf("[ERROR] Failed to set cache key '%s' for org %s", tmpData.Key, tmpData.OrgId)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed to set data. Please try again, or contact support@shuffler.io"}`))
		return
	}

	log.Printf("[INFO] Successfully set key '%s' for org '%s' (%s)", tmpData.Key, org.Name, tmpData.OrgId)
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
			lineSplit = strings.Split(line, ":")
		}

		if len(lineSplit) >= 2 {
			validationHeader := strings.ToLower(strings.TrimSpace(lineSplit[0]))
			found := false

			joinedItemValue := strings.Join(lineSplit[1:], "=")
			log.Printf("[INFO] Checking %s = %s", validationHeader, joinedItemValue)
			for key, value := range request.Header {
				if strings.ToLower(key) == validationHeader && len(value) > 0 {
					//log.Printf("FOUND KEY %s. Value: %s", validationHeader, value)
					if value[0] == strings.TrimSpace(joinedItemValue) {
						found = true
						break
					}
				}
			}

			if !found {
				return errors.New(fmt.Sprintf("Missing or bad header: %s", validationHeader))
			}

			//log.Printf("Find header %s", validationHeader)
			//itemHeader := request.Header[validationHeader]
			//log.Printf("LINE: %s. Header: %s", line, itemHeader)
		} else {
			log.Printf("[WARNING] Bad auth line: %s. NOT checking auth.", line)
		}
	}

	//return errors.New("Bad auth!")
	return nil
}

// Body = The action body received from the user to test.
func PrepareSingleAction(ctx context.Context, user User, fileId string, body []byte) (WorkflowExecution, error) {
	workflowExecution := WorkflowExecution{}

	var action Action
	err := json.Unmarshal(body, &action)
	if err != nil {
		log.Printf("[WARNING] Failed action single execution unmarshaling: %s", err)
		return workflowExecution, err
	}

	if fileId != action.AppID {
		log.Printf("[WARNING] Bad appid in single execution of App %s", fileId)
		return workflowExecution, err
	}

	if len(action.ID) == 0 {
		action.ID = uuid.NewV4().String()
	}

	app, err := GetApp(ctx, fileId, user, false)
	if err != nil {
		log.Printf("[WARNING] Error getting app (execute SINGLE app action): %s", fileId)
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
	/*
		for _, param := range action.Parameters {
			if param.Configuration && len(param.Value) == 0 {
				continue
			}

			newParams = append(newParams, param)
		}
	*/

	// Auth is handled in PrepareWorkflowExec, so this may not be needed
	for _, param := range action.Parameters {
		newName := GetValidParameters([]string{param.Name})
		if len(newName) > 0 {
			param.Name = newName[0]
		}

		//if param.Configuration && len(param.Value) == 0 {
		//	continue
		//}

		/*
			if param.Required && len(param.Value) == 0 {
				if param.Name == "username_basic" {
					param.Name = "username"
				} else if param.Name == "password_basic" {
					param.Name = "password"
				}

				param.Name = strings.Replace(param.Name, "_", " ", -1)
				param.Name = strings.Title(param.Name)

				value := fmt.Sprintf("Param %s can't be empty. Please fill all required parameters (orange outline). If you don't know the value, input space in the field.", param.Name)
				log.Printf("[WARNING] During single exec: %s", value)
				//return workflowExecution, errors.New(value)
			}
		*/

		newParams = append(newParams, param)
	}

	action.Parameters = newParams

	action.Sharing = app.Sharing
	action.Public = app.Public
	action.Generated = app.Generated

	if len(action.Environment) == 0 {
		if project.Environment == "cloud" {
			action.Environment = "cloud"
		} else {
			environments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
			if err != nil {
				log.Printf("[ERROR] Failed getting environments for org in single action %s: %s", user.ActiveOrg.Id, err)
			}

			for _, env := range environments {
				if env.Default {
					//log.Printf("[INFO] Setting default environment for single action: %s", env.Name)
					action.Environment = env.Name
					break
				}
			}
		}
	}

	workflow := Workflow{
		Actions: []Action{
			action,
		},
		Start:     action.ID,
		ID:        uuid.NewV4().String(),
		Generated: true,
		Hidden:    true,
	}

	//log.Printf("Sharing: %s, Public: %s, Generated: %s. Start: %s", action.Sharing, action.Public, action.Generated, workflow.Start)

	/*
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
	*/

	// Make a fake request object as it's not necessary
	badRequest := &http.Request{}

	if user.ActiveOrg.Id != "" {
		workflow.Owner = user.Id
		workflow.OrgId = user.ActiveOrg.Id
		workflow.ExecutingOrg = user.ActiveOrg
		workflowExecution.ExecutionOrg = user.ActiveOrg.Id
		workflowExecution.OrgId = user.ActiveOrg.Id
	}

	// Add fake queries to it
	badRequest.URL, _ = url.Parse(fmt.Sprintf("http://localhost:3000/api/v1/workflows/%s/execute", workflow.ID))
	badRequest.URL.RawQuery = fmt.Sprintf("")
	badRequest.Method = "GET"

	workflowExecution, _, errString, err := PrepareWorkflowExecution(ctx, workflow, badRequest, 10)
	if err != nil || len(errString) > 0 {
		log.Printf("[ERROR] Failed preparing single execution (%s): %s", workflowExecution.ExecutionId, err)
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

func HandleRetValidation(ctx context.Context, workflowExecution WorkflowExecution, resultAmount int) SingleResult {
	cnt := 0

	returnBody := SingleResult{
		Success:       true,
		Id:            workflowExecution.ExecutionId,
		Authorization: workflowExecution.Authorization,
		Result:        "",
		Errors:        []string{},
	}

	// VERY short sleeptime here on purpose
	maxSeconds := 15
	if project.Environment != "cloud" {
		maxSeconds = 60
	}

	sleeptime := 100
	for {
		time.Sleep(100 * time.Millisecond)

		newExecution, err := GetWorkflowExecution(ctx, workflowExecution.ExecutionId)
		if err != nil {
			log.Printf("[WARNING] Failed getting single execution data: %s", err)
			break
		}

		//log.Printf("[INFO] Checking single execution %s. Status: %s. Len: %d, resultAmount: %d", workflowExecution.ExecutionId, newExecution.Status, len(newExecution.Results), resultAmount-1)

		if len(newExecution.Results) > resultAmount-1 {
			relevantIndex := len(newExecution.Results) - 1

			if len(newExecution.Results[relevantIndex].Result) > 0 || newExecution.Results[relevantIndex].Status == "SUCCESS" {
				returnBody.Result = newExecution.Results[relevantIndex].Result

				// Check for single action errors in liquid and similar
				// to be used in the frontend
				//log.Printf("[INFO] Checking for errors in single execution %s", workflowExecution.ExecutionId)

				for _, param := range newExecution.Results[relevantIndex].Action.Parameters {
					//log.Printf("Name: %s", param.Name)
					if strings.Contains(param.Name, "liquid") && !ArrayContains(returnBody.Errors, param.Value) {
						returnBody.Errors = append(returnBody.Errors, param.Value)
					}
				}
				break
			}
		}

		cnt += 1
		//log.Printf("Cnt: %d", cnt)
		if cnt == (maxSeconds * (maxSeconds * 100 / sleeptime)) {

			returnBody.Success = true

			returnBody.Errors = []string{fmt.Sprintf("Polling timed out after %d seconds. Use the /api/v1/streams API with body `{\"execution_id\": \"%s\", \"authorization\": \"%s\"}` to get the latest results", maxSeconds, workflowExecution.ExecutionId, workflowExecution.Authorization)}

			break
		}
	}

	if len(returnBody.Result) == 0 && len(returnBody.Errors) == 0 {
		returnBody.Success = false
	}

	return returnBody

}

func GetDocs(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	location := strings.Split(request.URL.String(), "/")
	if len(location) < 5 {
		resp.WriteHeader(404)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Bad path. Use e.g. /api/v1/docs/workflows.md"`)))
		return
	}

	if strings.Contains(location[4], "?") {
		location[4] = strings.Split(location[4], "?")[0]
	}

	ctx := GetContext(request)
	downloadLocation, downloadOk := request.URL.Query()["location"]
	version, versionOk := request.URL.Query()["version"]
	cacheKey := fmt.Sprintf("docs_%s", location[4])
	if downloadOk {
		cacheKey = fmt.Sprintf("%s_%s", cacheKey, downloadLocation[0])
	}

	if versionOk {
		cacheKey = fmt.Sprintf("%s_%s", cacheKey, version[0])
	}

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

	// FIXME: User controlled and dangerous (possibly). Uses Markdown on the frontend to render it
	realPath := ""

	newname := location[4]
	if downloadOk {
		if downloadLocation[0] == "openapi" {
			newname = strings.ReplaceAll(strings.ToLower(location[4]), `%20`, "_")
			docPath = fmt.Sprintf("https://raw.githubusercontent.com/Shuffle/openapi-apps/master/docs/%s.md", newname)
			realPath = fmt.Sprintf("https://github.com/Shuffle/openapi-apps/blob/master/docs/%s.md", newname)

		} else if downloadLocation[0] == "python" && versionOk {
			// Apparently this uses dashes for no good reason?
			// Should maybe move everything over to underscores later?
			newname = strings.ReplaceAll(newname, `%20`, "-")
			newname = strings.ReplaceAll(newname, ` `, "-")
			newname = strings.ReplaceAll(newname, `_`, "-")
			newname = strings.ToLower(newname)

			if version[0] == "1.0.0" {
				docPath = fmt.Sprintf("https://raw.githubusercontent.com/Shuffle/python-apps/master/%s/1.0.0/README.md", newname)
				realPath = fmt.Sprintf("https://github.com/Shuffle/python-apps/blob/master/%s/1.0.0/README.md", newname)

				log.Printf("[INFO] Should download python app for version %s: %s", version[0], docPath)

			} else {
				realPath = fmt.Sprintf("https://github.com/Shuffle/python-apps/blob/master/%s/README.md", newname)
				docPath = fmt.Sprintf("https://raw.githubusercontent.com/Shuffle/python-apps/master/%s/README.md", newname)
			}

		}
	}

	//log.Printf("Docpath: %s", docPath)

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

	defer newresp.Body.Close()
	body, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't parse data"}`)))
		return
	}

	commitOptions := &github.CommitsListOptions{
		Path: fmt.Sprintf("%s/%s.md", path, location[4]),
	}

	parsedLink := fmt.Sprintf("https://github.com/%s/%s/blob/master/%s/%s.md", owner, repo, path, location[4])
	if len(realPath) > 0 {
		parsedLink = realPath
	}

	client := github.NewClient(nil)
	githubResp := GithubResp{
		Name:         location[4],
		Contributors: []GithubAuthor{},
		Edited:       "",
		ReadTime:     len(body) / 10 / 250,
		Link:         parsedLink,
	}

	if githubResp.ReadTime == 0 {
		githubResp.ReadTime = 1
	}

	info, _, err := client.Repositories.ListCommits(ctx, owner, repo, commitOptions)
	if err != nil {
		log.Printf("[WARNING] Failed getting commit info: %s", err)
	} else {
		//log.Printf("Info: %s", info)
		for _, commit := range info {
			//log.Printf("Commit: %s", commit.Author)
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

	result.Reason = string(body)
	b, err := json.Marshal(result)
	if err != nil {
		http.Error(resp, err.Error(), 500)
		return
	}

	err = SetCache(ctx, cacheKey, b, 180)
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

	ctx := GetContext(request)
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
		log.Printf("[WARNING] Failed getting docs list: %s", err)
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

		// FIXME: Scuffed readtime calc
		// Average word length = 5. Space = 1. 5+1 = 6 avg.
		// Words = *item.Size/6/250
		//250 = average read time / minute
		// Doubling this for bloat removal in Markdown~
		githubResp := GithubResp{
			Name:         (*item.Name)[0 : len(*item.Name)-3],
			Contributors: []GithubAuthor{},
			Edited:       "",
			ReadTime:     *item.Size / 6 / 250,
			Link:         fmt.Sprintf("https://github.com/%s/%s/blob/master/%s/%s", owner, repo, path, *item.Name),
		}

		names = append(names, githubResp)
	}

	//log.Printf(names)
	result.Success = true
	result.Reason = "Success"
	result.List = names
	b, err := json.Marshal(result)
	if err != nil {
		http.Error(resp, err.Error(), 500)
		return
	}

	err = SetCache(ctx, cacheKey, b, 300)
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
func ValidateNewWorkerExecution(ctx context.Context, body []byte) error {
	var execution WorkflowExecution
	err := json.Unmarshal(body, &execution)
	if err != nil {
		log.Printf("[WARNING] Failed execution unmarshaling: %s", err)
		if strings.Contains(fmt.Sprintf("%s", err), "array into") {
			log.Printf("Array unmarshal error: %s", string(body))
		}

		return err
	}

	if len(execution.ExecutionId) == 0 {
		log.Printf("[ERROR] No execution id provided to validate new worker")
		return errors.New("No execution id provided to validate new worker")
	}

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
	for _, result := range execution.Results {
		//log.Printf("%s = %s", result.Action.AppName, result.Status)
		if result.Action.AppName == "shuffle-subflow" {
			if result.Status == "SKIPPED" {
				continue
			}

			for _, trigger := range baseExecution.Workflow.Triggers {
				if trigger.ID != result.Action.ID {
					continue
				}

				for _, param := range trigger.Parameters {
					if param.Name == "check_result" && param.Value == "true" {
						//log.Printf("Found check as true!")

						var subflowData SubflowData
						err = json.Unmarshal([]byte(result.Result), &subflowData)
						if err != nil {
							log.Printf("Failed unmarshal in subflow check for %s: %s", result.Result, err)
						} else if len(subflowData.Result) == 0 {
							log.Printf("There is no result yet. Don't save?")
						} else {
							//log.Printf("There is a result: %s", result.Result)
						}

						break
					}
				}

				break
			}
		}
	}

	// Check status is finished, and set timestamp for finished if it's 0
	if execution.Status == "FINISHED" || execution.Status == "ABORTED" || execution.Status == "FAILURE" {
		if baseExecution.CompletedAt == 0 {
			baseExecution.CompletedAt = time.Now().Unix()
		}
	}

	// FIXME: Add extra here
	//executionLength := len(baseExecution.Workflow.Actions)
	//if executionLength != len(execution.Results) {
	//	return errors.New(fmt.Sprintf("Bad length of actions vs results: want: %d have: %d", executionLength, len(execution.Results)))
	//}

	err = SetWorkflowExecution(ctx, execution, true)
	executionSet := true
	if err == nil {
		log.Printf("[INFO][%s] Set workflowexecution based on new worker (>0.8.53) for workflow %s. Actions: %d, Triggers: %d, Results: %d, Status: %s", execution.ExecutionId, execution.WorkflowId, len(execution.Workflow.Actions), len(execution.Workflow.Triggers), len(execution.Results), execution.Status)
		executionSet = true

		if execution.Status == "FINISHED" || execution.Status == "ABORTED" {
			//log.Printf("[INFO][%s] Execution is finished or aborted. Incrementing cache statistics", execution.ExecutionId)

			HandleExecutionCacheIncrement(ctx, execution)
		}

	} else {
		log.Printf("[WARNING] Failed setting the execution for new worker (>0.8.53) - retrying once: %s. ExecutionId: %s, Actions: %d, Triggers: %d, Results: %d, Status: %s", err, execution.ExecutionId, len(execution.Workflow.Actions), len(execution.Workflow.Triggers), len(execution.Results), execution.Status)
		// Retrying
		time.Sleep(5 * time.Second)
		err = SetWorkflowExecution(ctx, execution, true)
		if err != nil {
			log.Printf("[ERROR] Failed setting the execution for new worker (>0.8.53) - 2nd attempt: %s. ExecutionId: %s, Actions: %d, Triggers: %d, Results: %d, Status: %s", err, execution.ExecutionId, len(execution.Workflow.Actions), len(execution.Workflow.Triggers), len(execution.Results), execution.Status)
		} else {
			executionSet = true
		}
	}

	// Long convoluted way of validating and setting the value of a subflow that is also a loop
	// timing issues / non-queues
	_ = executionSet
	//if executionSet {
	//	RunFixParentWorkflowResult(ctx, execution)
	//}

	DeleteCache(ctx, fmt.Sprintf("workflowexecution_%s", execution.WorkflowId))
	DeleteCache(ctx, fmt.Sprintf("workflowexecution_%s_50", execution.WorkflowId))
	DeleteCache(ctx, fmt.Sprintf("workflowexecution_%s_100", execution.WorkflowId))

	return nil
}

// Only returning error as the point is for the current workflow to update the parent workflow
func RunFixParentWorkflowResult(ctx context.Context, execution WorkflowExecution) error {
	//log.Printf("IS IT SUBFLOW?")
	if len(execution.ExecutionParent) > 0 && execution.Status != "EXECUTING" && (project.Environment == "onprem" || project.Environment == "cloud") {

		parentExecution, err := GetWorkflowExecution(ctx, execution.ExecutionParent)
		if err == nil {
			//log.Printf("[DEBUG] Got parent execution: %s", parentExecution.ExecutionId)

			isLooping := false
			setExecution := true
			shouldSetValue := false

			for _, action := range parentExecution.Workflow.Actions {
				if action.AppName == "User Input" || action.AppName == "Shuffle Workflow" || action.AppName == "shuffle-subflow" {
					parentExecution.Workflow.Triggers = append(parentExecution.Workflow.Triggers, Trigger{
						AppName:    action.AppName,
						Parameters: action.Parameters,
						ID:         action.ID,
					})
				}
			}

			for _, trigger := range parentExecution.Workflow.Triggers {
				if trigger.ID != execution.ExecutionSourceNode {
					continue
				}

				for _, param := range trigger.Parameters {
					if param.Name == "workflow" && param.Value != execution.Workflow.ID {
						setExecution = false
					}

					if param.Name == "argument" && strings.Contains(param.Value, "$") && strings.Contains(param.Value, ".#") {
						isLooping = true
					}

					if param.Name == "check_result" && param.Value == "true" {
						shouldSetValue = true
					}
				}

				break
			}

			if !isLooping && setExecution && shouldSetValue && parentExecution.Status == "EXECUTING" {
				log.Printf("[DEBUG] Its NOT looping. Should we override the value?")
				return nil
			} else if isLooping && setExecution && shouldSetValue && parentExecution.Status == "EXECUTING" {
				log.Printf("[DEBUG] Parentexecutions' subflow IS looping and is correct workflow. Should find correct answer in the node's result. Length of results: %d", len(parentExecution.Results))
				// 1. Find the action's existing result
				// 2. ONLY update it if the action status is WAITING and workflow status is EXECUTING
				// 3. IF all parts of the subflow execution are finished, set it to FINISHED
				// 4. If result length == length of actions + extra, set it to FINISHED
				// 5. Before setting parent execution, make sure to grab the latest version of the workflow again, in case processing time is slow
				resultIndex := -1
				updateIndex := -1
				for parentResultIndex, result := range parentExecution.Results {
					if result.Action.ID != execution.ExecutionSourceNode {
						continue
					}

					//log.Printf("[DEBUG] Found action %s' results: %s", result.Action.ID, result.Result)
					if result.Status != "WAITING" {
						break
					}

					//result.Result
					var subflowDataLoop []SubflowData
					err = json.Unmarshal([]byte(result.Result), &subflowDataLoop)
					if err != nil {
						log.Printf("[DEBUG] Failed unmarshaling in set parent data: %s", err)
						break
					}

					for subflowIndex, subflowResult := range subflowDataLoop {
						if subflowResult.ExecutionId != execution.ExecutionId {
							// Should look for the subflowresult for this one too

							continue
						}

						//log.Printf("[DEBUG] Found right execution on index %d. Result: %s", subflowIndex, subflowResult.Result)
						if len(subflowResult.Result) == 0 {
							updateIndex = subflowIndex
						}

						resultIndex = parentResultIndex
						break
					}
				}

				// FIXME: MAY cause transaction issues.
				if updateIndex >= 0 && resultIndex >= 0 {
					//log.Printf("\n\n\n[DEBUG] Should update index %d in resultIndex %d with new result %s\n\n\n", updateIndex, resultIndex, execution.Result)

					// Again, get the result, just in case, and update that exact value instantly
					newParentExecution, err := GetWorkflowExecution(ctx, execution.ExecutionParent)
					if err == nil {

						var subflowDataLoop []SubflowData
						err = json.Unmarshal([]byte(newParentExecution.Results[resultIndex].Result), &subflowDataLoop)
						if err == nil {
							subflowDataLoop[updateIndex].Result = execution.Result
							subflowDataLoop[updateIndex].ResultSet = true

							marshalledSubflow, err := json.Marshal(subflowDataLoop)
							if err == nil {
								newParentExecution.Results[resultIndex].Result = string(marshalledSubflow)
								err = SetWorkflowExecution(ctx, *newParentExecution, true)
								if err != nil {
									log.Printf("[WARNING] Error saving parent execution in subflow setting: %s", err)
								} else {
									log.Printf("[DEBUG] Updated index %d in subflow result %d with value of length %d. IDS HAVE TO MATCH: %s vs %s", updateIndex, resultIndex, len(execution.Result), subflowDataLoop[updateIndex].ExecutionId, execution.ExecutionId)
								}
							}

							// Validating if all are done and setting back to executing
							allFinished := true
							for _, parentResult := range newParentExecution.Results {
								if parentResult.Action.ID != execution.ExecutionSourceNode {

									continue
								}

								var subflowDataLoop []SubflowData
								err = json.Unmarshal([]byte(parentResult.Result), &subflowDataLoop)
								if err == nil {
									for _, subflowResult := range subflowDataLoop {
										if subflowResult.ResultSet != true {
											allFinished = false
											break
										}
									}

									break
								} else {
									allFinished = false
									break
								}
							}

							// FIXME: This will break if subflow with loop is last node in two workflows in a row (main workflow -> []subflow -> []subflow)
							// Should it send the whole thing back as a result to itself to be handled manually? :thinking:
							if allFinished {
								//newParentExecution.Results[resultIndex].Status = "SUCCESS"

								extra := 0
								for _, trigger := range newParentExecution.Workflow.Triggers {
									//log.Printf("Appname trigger (0): %s", trigger.AppName)
									if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
										extra += 1
									}
								}

								if len(newParentExecution.Workflow.Actions)+extra == len(newParentExecution.Results) {
									newParentExecution.Status = "FINISHED"
								}

								err = SetWorkflowExecution(ctx, *newParentExecution, true)
								if err != nil {
									log.Printf("[ERROR] Failed updating setExecution to FINISHED and SUCCESS: %s", err)
								}
							}
						} else {
							log.Printf("[WARNING] Failed to unmarshal result in set parent subflow: %s", err)
						}

						//= newValue
					} else {
						log.Printf("[WARNING] Failed to update parent, because execution %s couldn't be found: %s", execution.ExecutionParent, err)
					}
				}
			}
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
	//log.Printf("%s", parsedX509Key)
	return parsedX509Key
}

// Example implementation of SSO, including a redirect for the user etc
// Should make this stuff only possible after login
func HandleOpenId(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	//https://dev-18062475.okta.com/oauth2/default/v1/authorize?client_id=oa3romteykJ2aMgx5d7&response_type=code&scope=openid&redirect_uri=http%3A%2F%2Flocalhost%3A5002%2Fapi%2Fv1%2Flogin_openid&state=state-296bc9a0-a2a2-4a57-be1a-d0e2fd9bb601&code_challenge_method=S256&code_challenge=codechallenge
	// http://localhost:5001/api/v1/login_openid#id_token=asdasd&session_state=asde9d78d8-6535-45fe-848d-0efa9f119595

	//code -> Token
	ctx := GetContext(request)

	skipValidation := false
	openidUser := OpenidUserinfo{}
	org := &Org{}
	code := request.URL.Query().Get("code")
	if len(code) == 0 {
		// Check id_token grant info
		if request.Method == "POST" {
			body, err := ioutil.ReadAll(request.Body)
			if err != nil {
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "No code or id_token specified - body read error in POST"}`)))
				resp.WriteHeader(401)
				return
			}

			stateSplit := strings.Split(string(body), "&")
			for _, innerstate := range stateSplit {
				itemsplit := strings.Split(innerstate, "=")

				if len(itemsplit) <= 1 {
					log.Printf("[WARNING] No key:value: %s", innerstate)
					continue
				}

				if itemsplit[0] == "id_token" {
					token, err := VerifyIdToken(ctx, itemsplit[1])
					if err != nil {
						log.Printf("[ERROR] Bad ID token provided: %s", err)
						resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Bad ID token provided"}`)))
						resp.WriteHeader(401)
						return
					}

					openidUser.Sub = token.Sub
					org = &token.Org
					skipValidation = true

					break
				}
			}
		}

		if !skipValidation {
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "No code specified"}`)))
			resp.WriteHeader(401)
			return
		}
	}

	if !skipValidation {
		state := request.URL.Query().Get("state")
		if len(state) == 0 {
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "No state specified"}`)))
			return
		}

		stateBase, err := base64.StdEncoding.DecodeString(state)
		if err != nil {
			log.Printf("[ERROR] Failed base64 decode OpenID state: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed base64 decoding of state"}`)))
			return
		}

		log.Printf("State: %s", stateBase)
		foundOrg := ""
		foundRedir := ""
		foundChallenge := ""
		stateSplit := strings.Split(string(stateBase), "&")
		for _, innerstate := range stateSplit {
			itemsplit := strings.Split(innerstate, "=")
			//log.Printf("Itemsplit: %s", itemsplit)
			if len(itemsplit) <= 1 {
				log.Printf("[WARNING] No key:value: %s", innerstate)
				continue
			}

			if itemsplit[0] == "org" {
				foundOrg = strings.TrimSpace(itemsplit[1])
			}

			if itemsplit[0] == "redirect" {
				foundRedir = strings.TrimSpace(itemsplit[1])
			}

			if itemsplit[0] == "challenge" {
				foundChallenge = strings.TrimSpace(itemsplit[1])
			}
		}

		//log.Printf("Challenge len2: %d", len(foundChallenge))

		if len(foundOrg) == 0 {
			log.Printf("[ERROR] No org specified in state")
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "No org specified in state"}`)))
			return
		}

		org, err = GetOrg(ctx, foundOrg)
		if err != nil {
			log.Printf("[WARNING] Error getting org in OpenID: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Couldn't find the org for sign-in in Shuffle"}`))
			return
		}

		clientId := org.SSOConfig.OpenIdClientId
		tokenUrl := org.SSOConfig.OpenIdToken
		if len(tokenUrl) == 0 {
			log.Printf("[ERROR] No token URL specified for OpenID")
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "No token URL specified. Please make sure to specify a token URL in the /admin panel in Shuffle for OpenID Connect"}`)))
			return
		}

		//log.Printf("Challenge: %s", foundChallenge)
		body, err := RunOpenidLogin(ctx, clientId, tokenUrl, foundRedir, code, foundChallenge, org.SSOConfig.OpenIdClientSecret)
		if err != nil {
			log.Printf("[WARNING] Error with body read of OpenID Connect: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		openid := OpenidResp{}
		err = json.Unmarshal(body, &openid)
		if err != nil {
			log.Printf("[WARNING] Error in Openid marshal: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		// Automated replacement
		userInfoUrlSplit := strings.Split(org.SSOConfig.OpenIdAuthorization, "/")
		userinfoEndpoint := strings.Join(userInfoUrlSplit[0:len(userInfoUrlSplit)-1], "/") + "/userinfo"
		//userinfoEndpoint := strings.Replace(org.SSOConfig.OpenIdAuthorization, "/authorize", "/userinfo", -1)
		log.Printf("Userinfo endpoint: %s", userinfoEndpoint)
		client := &http.Client{}
		req, err := http.NewRequest(
			"GET",
			userinfoEndpoint,
			nil,
		)

		//req.Header.Add("accept", "application/json")
		//req.Header.Add("cache-control", "no-cache")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", openid.AccessToken))
		res, err := client.Do(req)
		if err != nil {
			log.Printf("[WARNING] OpenID client DO (2): %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed userinfo request"}`))
			return
		}

		defer res.Body.Close()
		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			log.Printf("[WARNING] OpenID client Body (2): %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed userinfo body parsing"}`))
			return
		}

		err = json.Unmarshal(body, &openidUser)
		if err != nil {
			log.Printf("[WARNING] Error in Openid marshal (2): %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	//log.Printf("Got user body: %s", string(body))

	/*

		BELOW HERE ITS ALL COPY PASTE OF USER INFO THINGS!

	*/

	if len(openidUser.Sub) == 0 {
		log.Printf("[WARNING] No user found in openid login (2)")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if project.Environment == "cloud" {
		log.Printf("[WARNING] Openid SSO is not implemented for cloud yet. User %s", openidUser.Sub)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Cloud Openid is not available yet"}`)))
		return
	}

	userName := strings.ToLower(strings.TrimSpace(openidUser.Sub))
	if !strings.Contains(userName, "@") {
		log.Printf("[ERROR] Bad username, but allowing due to OpenID: %s. Full Subject: %#v", userName, openidUser)
	}
	redirectUrl := "https://shuffler.io/workflows"

	users, err := FindGeneratedUser(ctx, strings.ToLower(strings.TrimSpace(userName)))
	if err == nil && len(users) > 0 {
		for _, user := range users {
			log.Printf("%s - %s", user.GeneratedUsername, userName)
			if user.GeneratedUsername == userName {
				log.Printf("[AUDIT] Found user %s (%s) which matches SSO info for %s. Redirecting to login!", user.Username, user.Id, userName)

				//log.Printf("SESSION: %s", user.Session)
				user.ActiveOrg = OrgMini{
					Name: org.Name,
					Id:   org.Id,
					Role: user.Role,
				}

				expiration := time.Now().Add(3600 * time.Second)
				//if len(user.Session) == 0 {
				log.Printf("[INFO] User does NOT have session - creating")
				sessionToken := uuid.NewV4().String()

				newCookie := http.Cookie{
					Name:    "session_token",
					Value:   sessionToken,
					Expires: expiration,
					Path:    "/",
				}

				if project.Environment == "cloud" {
					newCookie.Domain = ".shuffler.io"
					newCookie.Secure = true
					newCookie.HttpOnly = true
				}

				http.SetCookie(resp, &newCookie)

				newCookie.Name = "__session"
				http.SetCookie(resp, &newCookie)

				err = SetSession(ctx, user, sessionToken)
				if err != nil {
					log.Printf("[WARNING] Error creating session for user: %s", err)
					resp.WriteHeader(401)
					resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed setting session"}`)))
					return
				}

				user.Session = sessionToken
				user.LoginInfo = append(user.LoginInfo, LoginInfo{
					IP:        GetRequestIp(request),
					Timestamp: time.Now().Unix(),
				})
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
				log.Printf("[AUDIT] Found user %s (%s) which matches SSO info for %s. Redirecting to login %s!", user.Username, user.Id, userName, redirectUrl)

				//log.Printf("SESSION: %s", user.Session)
				user.ActiveOrg = OrgMini{
					Name: org.Name,
					Id:   org.Id,
					Role: user.Role,
				}

				expiration := time.Now().Add(3600 * time.Second)
				//if len(user.Session) == 0 {
				log.Printf("[INFO] User does NOT have session - creating")
				sessionToken := uuid.NewV4().String()
				newCookie := &http.Cookie{
					Name:    "session_token",
					Value:   sessionToken,
					Expires: expiration,
					Path:    "/",
				}

				if project.Environment == "cloud" {
					newCookie.Domain = ".shuffler.io"
					newCookie.Secure = true
					newCookie.HttpOnly = true
				}

				http.SetCookie(resp, newCookie)

				newCookie.Name = "__session"
				http.SetCookie(resp, newCookie)

				err = SetSession(ctx, user, sessionToken)
				if err != nil {
					log.Printf("[WARNING] Error creating session for user: %s", err)
					resp.WriteHeader(401)
					resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed setting session"}`)))
					return
				}

				user.Session = sessionToken
				user.LoginInfo = append(user.LoginInfo, LoginInfo{
					IP:        GetRequestIp(request),
					Timestamp: time.Now().Unix(),
				})
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

	if len(org.Id) == 0 {
		log.Printf("[WARNING] Failed finding a valid org (default) without suborgs during SSO setup")
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed finding valid SSO auto org"}`)))
		return
	}

	log.Printf("[AUDIT] Adding user %s to org %s (%s) through single sign-on", userName, org.Name, org.Id)
	newUser := new(User)
	// Random password to ensure its not empty
	newUser.Password = uuid.NewV4().String()
	newUser.Username = userName
	newUser.GeneratedUsername = userName
	newUser.Verified = true
	newUser.Active = true
	newUser.CreationTime = time.Now().Unix()
	newUser.Orgs = []string{org.Id}
	newUser.LoginType = "OpenID"
	newUser.Role = "user"
	newUser.Session = uuid.NewV4().String()
	newUser.ActiveOrg = OrgMini{
		Name: org.Name,
		Id:   org.Id,
		Role: "user",
	}

	verifyToken := uuid.NewV4()
	ID := uuid.NewV4()
	newUser.Id = ID.String()
	newUser.VerificationToken = verifyToken.String()

	expiration := time.Now().Add(3600 * time.Second)
	//if len(user.Session) == 0 {
	log.Printf("[INFO] User does NOT have session - creating")
	sessionToken := uuid.NewV4().String()

	newCookie := &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: expiration,
		Path:    "/",
	}

	if project.Environment == "cloud" {
		newCookie.Domain = ".shuffler.io"
		newCookie.Secure = true
		newCookie.HttpOnly = true
	}

	http.SetCookie(resp, newCookie)

	newCookie.Name = "__session"
	http.SetCookie(resp, newCookie)

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

// Example implementation of SSO, including a redirect for the user etc
// Should make this stuff only possible after login
func HandleSSO(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	//log.Printf("SSO LOGIN: %s", request)
	// Deserialize
	// Serialize

	// SAML
	//entryPoint := "https://dev-23367303.okta.com/app/dev-23367303_shuffletest_1/exk1vg1j7bYUYEG0k5d7/sso/saml"
	redirectUrl := "http://localhost:3001/workflows"
	backendUrl := os.Getenv("SSO_REDIRECT_URL")

	if len(backendUrl) == 0 && project.Environment == "onprem" {
		backendUrl = "http://localhost:3000"
	}

	if len(backendUrl) == 0 && len(os.Getenv("BASE_URL")) > 0 {
		backendUrl = os.Getenv("BASE_URL")
	}

	if len(backendUrl) > 0 {
		redirectUrl = fmt.Sprintf("%s/workflows", backendUrl)
	}

	if project.Environment == "cloud" {
		redirectUrl = "https://shuffler.io/workflows"

		if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
			backendUrl = fmt.Sprintf("https://%s.%s.r.appspot.com/workflows", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
		}

		if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
			backendUrl = fmt.Sprintf("%s/workflows", os.Getenv("SHUFFLE_CLOUDRUN_URL"))
		}
	}

	log.Printf("[DEBUG] Using %s as redirectUrl in SSO", backendUrl)

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Error with body read of SSO: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Parsing out without using Field
	// This is a mess, but all made to handle base64 and equal signs
	parsedSAML := ""
	for _, item := range strings.Split(string(body), "&") {
		//log.Printf("Got body with info: %s", item)
		if strings.Contains(item, "SAMLRequest") || strings.Contains(item, "SAMLResponse") {
			equalsplit := strings.Split(item, "=")
			addedEquals := len(equalsplit)
			if len(equalsplit) >= 2 {
				//bareEquals := strings.Join(equalsplit[1:len(equalsplit)-1], "=")
				bareEquals := equalsplit[1]
				//log.Printf("Equal: %s", bareEquals)
				_ = addedEquals
				//if len(strings.Split(bareEquals, "=")) < addedEquals {
				//	bareEquals += "="
				//}

				decodedValue, err := url.QueryUnescape(bareEquals)
				if err != nil {
					log.Printf("[WARNING] Failed url query escape: %s", err)
					resp.WriteHeader(401)
					resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed decoding saml value"}`)))
					return
				}

				if strings.Contains(decodedValue, " ") {
					decodedValue = strings.Replace(decodedValue, " ", "+", -1)
				}

				parsedSAML = decodedValue
				break
			}
		}
	}

	if len(parsedSAML) == 0 {
		log.Printf("[WARNING] No SAML to be parsed from request.")
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "No data to parse. Is the request missing the SAMLResponse query?"}`)))
		return
	}

	bytesXML, err := base64.StdEncoding.DecodeString(parsedSAML)
	if err != nil {
		log.Printf("[WARNING] Failed base64 decode of SAML: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed base64 decoding in SAML"}`)))
		return
	}

	//log.Printf("Parsed: %s", bytesXML)

	// Sample request in keycloak lab env
	// PS: Should it ever come this way..?
	//<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" AssertionConsumerServiceURL="http://192.168.55.2:8080/auth/realms/ShuffleSSOSaml/broker/shaffuru/endpoint" Destination="http://192.168.55.2:3001/api/v1/login_sso" ForceAuthn="false" ID="" IssueInstant="2022-01-31T20:24:37.238Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer>http://192.168.55.2:8080/auth/realms/ShuffleSSOSaml</saml:Issuer><samlp:NameIDPolicy AllowCreate="false" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/></samlp:AuthnRequest>

	var samlResp SAMLResponse
	err = xml.Unmarshal(bytesXML, &samlResp)
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "AuthnRequest") {
			var newSamlResp SamlRequest
			err = xml.Unmarshal(bytesXML, &newSamlResp)
			if err != nil {
				log.Printf("[WARNING] Failed XML unmarshal (2): %s", err)
				resp.WriteHeader(401)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed XML unpacking in SAML (2)"}`)))
				return
			}

			// Being here means we need to redirect
			log.Printf("[DEBUG] Handling authnrequest redirect back to %s? That's not how any of this works.", newSamlResp.AssertionConsumerServiceURL)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed XML unpacking in SAML (2)"}`)))
			return

			// User tries to access a protected resource on the SP. SP checks if the user has a local (and authenticated session). If not it generates a SAML <AuthRequest> which includes a random id. The SP then redirects the user to the IDP with this AuthnRequest.

			return
		} else {
			log.Printf("[WARNING] Failed XML unmarshal: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed XML unpacking in SAML (1)"}`)))
			return
		}
	}

	baseCertificate := samlResp.Signature.KeyInfo.X509Data.X509Certificate
	if len(baseCertificate) == 0 {
		//log.Printf("%s", samlResp.Signature.KeyInfo.X509Data)
		baseCertificate = samlResp.Assertion.Signature.KeyInfo.X509Data.X509Certificate
	}

	parsedX509Key := fixCertificate(baseCertificate)

	ctx := GetContext(request)
	matchingOrgs, err := GetOrgByField(ctx, "sso_config.sso_certificate", parsedX509Key)
	if err != nil && len(matchingOrgs) == 0 {
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
	userName := strings.ToLower(strings.TrimSpace(samlResp.Assertion.Subject.NameID.Text))
	if !strings.Contains(userName, "@") {
		log.Printf("[ERROR] Bad username, but allowing due to SSO: %s. Full Subject: %#v", userName, samlResp.Assertion.Subject)
	}

	if len(userName) == 0 {
		log.Printf("[WARNING] Failed finding user - No name: %s", samlResp.Assertion.Subject)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed finding a user to authenticate"}`)))
		return
	}

	// Start actually fixing the user
	// 1. Check if the user exists - if it does - give it a valid cookie
	// 2. If it doesn't, find the correct org to connect them with, then register them

	/*
		if project.Environment == "cloud" {
			log.Printf("[WARNING] SAML SSO is not implemented for cloud yet")
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Cloud SSO is not available for you"}`)))
			return
		}
	*/

	users, err := FindGeneratedUser(ctx, strings.ToLower(strings.TrimSpace(userName)))
	if err == nil && len(users) > 0 {
		for _, user := range users {
			log.Printf("%s - %s", user.GeneratedUsername, userName)
			if user.GeneratedUsername == userName {
				log.Printf("[AUDIT] Found user %s (%s) which matches SSO info for %s. Redirecting to login!", user.Username, user.Id, userName)

				if project.Environment == "cloud" {
					// user.ActiveOrg.Id = matchingOrgs[0].Id

					DeleteCache(ctx, fmt.Sprintf("%s_workflows", user.Id))
					DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
					DeleteCache(ctx, fmt.Sprintf("apps_%s", user.ActiveOrg.Id))
					DeleteCache(ctx, fmt.Sprintf("user_%s", user.Username))
					DeleteCache(ctx, fmt.Sprintf("user_%s", user.Id))
				}

				user.ActiveOrg = OrgMini{
					Name: matchingOrgs[0].Name,
					Id:   matchingOrgs[0].Id,
					Role: user.Role,
				}
				//log.Printf("SESSION: %s", user.Session)

				expiration := time.Now().Add(3600 * time.Second)
				// if len(user.Session) == 0 {
					log.Printf("[INFO] User does NOT have session - creating")
					sessionToken := uuid.NewV4().String()
					newCookie := &http.Cookie{
						Name:    "session_token",
						Value:   sessionToken,
						Expires: expiration,
						Path:    "/",
					}

					if project.Environment == "cloud" {
						newCookie.Domain = ".shuffler.io"
						newCookie.Secure = true
						newCookie.HttpOnly = true
					}

					http.SetCookie(resp, newCookie)

					newCookie.Name = "__session"
					http.SetCookie(resp, newCookie)

					err = SetSession(ctx, user, sessionToken)
					if err != nil {
						log.Printf("[WARNING] Error creating session for user: %s", err)
						resp.WriteHeader(401)
						resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed setting session"}`)))
						return
					}

					user.LoginInfo = append(user.LoginInfo, LoginInfo{
						IP:        GetRequestIp(request),
						Timestamp: time.Now().Unix(),
					})

					user.Session = sessionToken
					user.LoginInfo = append(user.LoginInfo, LoginInfo{
						IP:        GetRequestIp(request),
						Timestamp: time.Now().Unix(),
					})
				// }
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
				log.Printf("[AUDIT] Found user %s (%s) which matches SSO info for %s. Redirecting to login %s!", user.Username, user.Id, userName, redirectUrl)

				//log.Printf("SESSION: %s", user.Session)
				// if project.Environment == "cloud" {
				// 	user.ActiveOrg.Id = matchingOrgs[0].Id
				// }

				user.ActiveOrg = OrgMini{
					Name: matchingOrgs[0].Name,
					Id:   matchingOrgs[0].Id,
					Role: user.Role,
				}

				expiration := time.Now().Add(3600 * time.Second)
				// if len(user.Session) == 0 {
					log.Printf("[INFO] User does NOT have session - creating")
					sessionToken := uuid.NewV4().String()
					newCookie := &http.Cookie{
						Name:    "session_token",
						Value:   sessionToken,
						Expires: expiration,
						Path:    "/",
					}

					if project.Environment == "cloud" {
						newCookie.Domain = ".shuffler.io"
						newCookie.Secure = true
						newCookie.HttpOnly = true
					}

					http.SetCookie(resp, newCookie)

					newCookie.Name = "__session"
					http.SetCookie(resp, newCookie)

					err = SetSession(ctx, user, sessionToken)
					if err != nil {
						log.Printf("[WARNING] Error creating session for user: %s", err)
						resp.WriteHeader(401)
						resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed setting session"}`)))
						return
					}

					user.Session = sessionToken
					user.LoginInfo = append(user.LoginInfo, LoginInfo{
						IP:        GetRequestIp(request),
						Timestamp: time.Now().Unix(),
					})
				// }
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

	// newUser.ActiveOrg.Id = matchingOrgs[0].Id

	newUser.ActiveOrg = OrgMini{
		Name: matchingOrgs[0].Name,
		Id:   matchingOrgs[0].Id,
		Role: "user",
	}

	verifyToken := uuid.NewV4()
	ID := uuid.NewV4()
	newUser.Id = ID.String()
	newUser.VerificationToken = verifyToken.String()

	expiration := time.Now().Add(3600 * time.Second)
	//if len(user.Session) == 0 {
	log.Printf("[INFO] User does NOT have session - creating")
	sessionToken := uuid.NewV4().String()
	newCookie := &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: expiration,
		Path:    "/",
	}

	if project.Environment == "cloud" {
		newCookie.Domain = ".shuffler.io"
		newCookie.Secure = true
		newCookie.HttpOnly = true
	}

	http.SetCookie(resp, newCookie)

	newCookie.Name = "__session"
	http.SetCookie(resp, newCookie)

	err = SetSession(ctx, *newUser, sessionToken)
	if err != nil {
		log.Printf("[WARNING] Error creating session for user: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed setting session"}`)))
		return
	}

	newUser.Session = sessionToken

	newUser.LoginInfo = append(newUser.LoginInfo, LoginInfo{
		IP:        GetRequestIp(request),
		Timestamp: time.Now().Unix(),
	})

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
		SetCache(ctx, cacheKey, []byte{}, 30)
		return []byte{}, err
	}

	newresp, err := httpClient.Do(req)
	if err != nil {
		return []byte{}, err
	}

	//log.Printf("URL %s, RESP: %d", url, newresp.StatusCode)
	if newresp.StatusCode != 200 {
		SetCache(ctx, cacheKey, []byte{}, 30)

		return []byte{}, errors.New(fmt.Sprintf("No body to handle for %s. Status: %d", url, newresp.StatusCode))
	}

	defer newresp.Body.Close()
	body, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		SetCache(ctx, cacheKey, []byte{}, 30)
		return []byte{}, err
	}

	//log.Printf("Documentation: %s", string(body))
	if len(body) > 0 {
		err = SetCache(ctx, cacheKey, body, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for workflow/app doc %s: %s", url, err)
		}
		return body, nil
	}

	SetCache(ctx, cacheKey, []byte{}, 30)
	return []byte{}, errors.New(fmt.Sprintf("No body to handle for %s", url))
}

// New execution with firestore
func PrepareWorkflowExecution(ctx context.Context, workflow Workflow, request *http.Request, maxExecutionDepth int64) (WorkflowExecution, ExecInfo, string, error) {
	workflowBytes, err := json.Marshal(workflow)
	if err != nil {
		log.Printf("[WARNING] Failed workflow unmarshal in execution: %s", err)
		return WorkflowExecution{}, ExecInfo{}, "", err
	}

	//log.Printf(workflow)
	var workflowExecution WorkflowExecution
	err = json.Unmarshal(workflowBytes, &workflowExecution.Workflow)
	if err != nil {
		log.Printf("[WARNING] Failed prepare execution unmarshaling: %s", err)
		return WorkflowExecution{}, ExecInfo{}, "Failed unmarshal during execution", err
	}

	if len(workflow.OrgId) > 0 {
		workflowExecution.ExecutionOrg = workflow.OrgId
		workflowExecution.OrgId = workflow.OrgId
	}

	makeNew := true
	parentExecution := &WorkflowExecution{}
	start, startok := request.URL.Query()["start"]
	if request.Method == "POST" {
		body, err := ioutil.ReadAll(request.Body)
		if err != nil {
			log.Printf("[ERROR] Failed request POST read: %s", err)
			return WorkflowExecution{}, ExecInfo{}, "Failed getting body", err
		}

		// This one doesn't really matter.
		//log.Printf("[INFO][%s] Running POST execution with body of length %d for workflow %s", workflowExecution.ExecutionId, len(string(body)), workflowExecution.Workflow.ID)

		if len(body) >= 4 {
			if body[0] == 34 && body[len(body)-1] == 34 {
				body = body[1 : len(body)-1]
			}
			if body[0] == 34 && body[len(body)-1] == 34 {
				body = body[1 : len(body)-1]
			}
		}

		authgroupName, authgroupNameOk := request.URL.Query()["authgroup"]
		if authgroupNameOk {
			//log.Printf("\n\nAuthgroup: %s\n\n", authgroupName[0])
			workflowExecution.Authgroup = authgroupName[0]
		}

		sourceAuth, sourceAuthOk := request.URL.Query()["source_auth"]
		if sourceAuthOk {
			workflowExecution.ExecutionSourceAuth = sourceAuth[0]
		} else {
			//log.Printf("[DEBUG] Did NOT get source workflow auth")
		}

		sourceNode, sourceNodeOk := request.URL.Query()["source_node"]
		if sourceNodeOk {
			workflowExecution.ExecutionSourceNode = sourceNode[0]
		} else {
			//log.Printf("[DEBUG] Did NOT get source workflow node")
		}

		//workflowExecution.ExecutionSource = "default"
		sourceWorkflow, sourceWorkflowOk := request.URL.Query()["source_workflow"]
		if sourceWorkflowOk {
			//log.Printf("Got source workflow %s", sourceWorkflow)
			workflowExecution.ExecutionSource = sourceWorkflow[0]
		} else {
			//log.Printf("[DEBUG] Did NOT get source workflow (real). Not critical, as it can be overwritten with reference execution matching.")
		}

		sourceExecution, sourceExecutionOk := request.URL.Query()["source_execution"]

		referenceExecution, referenceExecutionOk := request.URL.Query()["reference_execution"]
		if referenceExecutionOk {
			sourceExecutionOk = true
			sourceExecution = referenceExecution
		}

		if sourceExecutionOk {
			//log.Printf("[INFO] Got source execution%s", sourceExecution)
			workflowExecution.ExecutionParent = sourceExecution[0]

			// FIXME: Get the execution and check count
			//workflowExecution.SubExecutionCount += 1

			parentExecution, err = GetWorkflowExecution(ctx, workflowExecution.ExecutionParent)
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

		// Checks whether the subflow has been ran before based on parent execution ID + parent execution node ID (always unique)
		// Used to deduplicate runs
		if len(workflowExecution.ExecutionParent) > 0 && len(workflowExecution.ExecutionSourceNode) > 0 {
			// Check if it should be looping:
			// 1. Get workflowExecution.ExecutionParent's workflow
			// 2. Find the ExecutionSourceNode
			// 3. Check if the value of it is looping
			var parentErr error
			if len(parentExecution.ExecutionId) == 0 {
				parentExecution, parentErr = GetWorkflowExecution(ctx, workflowExecution.ExecutionParent)
			}

			allowContinuation := false
			if parentErr == nil {
				found := false
				for _, trigger := range parentExecution.Workflow.Triggers {
					if trigger.ID != workflowExecution.ExecutionSourceNode {
						continue
					}

					found = true

					//$Get_Offenses.# -> Allow to run more
					for _, param := range trigger.Parameters {
						if param.Name == "argument" {
							if strings.Contains(param.Value, "$") && strings.Contains(param.Value, ".#") {
								allowContinuation = true
								break
							}
						}
					}

					if allowContinuation {
						break
					}
				}

				if !found {
					// Added from subflow trigger -> action translation
					for _, action := range parentExecution.Workflow.Actions {
						if action.ID != workflowExecution.ExecutionSourceNode {
							continue
						}

						found = true

						//$Get_Offenses.# -> Allow to run more
						for _, param := range action.Parameters {
							if param.Name == "argument" {
								if strings.Contains(param.Value, "$") && strings.Contains(param.Value, ".#") {
									allowContinuation = true
									break
								}
							}
						}

						if allowContinuation {
							break
						}
					}
				}
			}

			if allowContinuation == false {
				newExecId := fmt.Sprintf("%s_%s_%s", workflowExecution.ExecutionParent, workflowExecution.ExecutionId, workflowExecution.ExecutionSourceNode)
				cache, err := GetCache(ctx, newExecId)
				if err == nil {
					cacheData := []byte(cache.([]uint8))

					newexec := WorkflowExecution{}
					log.Printf("[WARNING] Subflow exec %s already found - returning", newExecId)

					// Returning to be used in worker
					err = json.Unmarshal(cacheData, &newexec)
					if err == nil {
						return newexec, ExecInfo{}, fmt.Sprintf("Subflow for %s has already been executed", newExecId), errors.New(fmt.Sprintf("Subflow for %s has already been executed", newExecId))
					}

					return workflowExecution, ExecInfo{}, fmt.Sprintf("Subflow for %s has already been executed", newExecId), errors.New(fmt.Sprintf("Subflow for %s has already been executed", newExecId))
				}

				cacheData := []byte("1")
				err = SetCache(ctx, newExecId, cacheData, 2)
				if err != nil {
					log.Printf("[WARNING] Failed setting cache for action %s: %s", newExecId, err)
				} else {
				}
			}
		}

		if len(string(body)) < 75 && len(string(body)) > 1 {
			log.Printf("[DEBUG][%s] Body: %s", workflowExecution.ExecutionId, string(body))
		} else {
			// Here for debug purposes
			//log.Printf("[DEBUG][%s] Body len: %d", workflowExecution.ExecutionId, len(string(body)))
		}

		var execution ExecutionRequest
		err = json.Unmarshal(body, &execution)
		if err != nil {
			if len(string(body)) < 100 {
				log.Printf("[WARNING] Failed execution POST unmarshaling - continuing anyway: '%s'. Err: %s", string(body), err)
			} else {
				log.Printf("[WARNING] Failed execution POST unmarshaling - continuing anyway: %s", err)
			}
		}

		// Ensuring it works even if startpoint isn't defined
		if execution.Start == "" && len(body) > 0 && len(execution.ExecutionSource) == 0 && len(execution.ExecutionArgument) == 0 {
			// Check if "execution_argument" in body
			execution.ExecutionArgument = string(body)
		}

		// FIXME - this should have "execution_argument" from executeWorkflow frontend
		//log.Printf("EXEC: %s", execution)
		if len(execution.ExecutionArgument) > 0 {
			workflowExecution.ExecutionArgument = execution.ExecutionArgument
		}

		if len(execution.ExecutionSource) > 0 {
			workflowExecution.ExecutionSource = execution.ExecutionSource

			if workflowExecution.Priority == 0 {
				workflowExecution.Priority = 5
			}
		}

		//log.Printf("Execution data: %s", execution)
		if len(execution.Start) == 36 && len(workflow.Actions) > 0 {
			//log.Printf("[INFO][%s] Should start execution on node %s", execution.ExecutionId, execution.Start)
			workflowExecution.Start = execution.Start

			found := false
			newStartnode := ""
			for _, action := range workflow.Actions {
				if action.ID == execution.Start {
					found = true
					break
				}

				if action.IsStartNode {
					newStartnode = action.ID
				}
			}

			if !found {
				if len(newStartnode) > 0 {
					execution.Start = newStartnode
				} else {
					log.Printf("[ERROR] Action %s was NOT found, and no other startnode found! Exiting execution.", execution.Start)
					return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Startnode %s was not found in actions", workflow.Start), errors.New(fmt.Sprintf("Startnode %s was not found in actions", workflow.Start))
				}
			}
		} else if len(execution.Start) > 0 {
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
		authorization, authorizationok := request.URL.Query()["authorization"]
		if answerok && referenceok && authorizationok {
			// If answer is false, reference execution with result
			log.Printf("[INFO] Should update reference execution and return, no need for further execution! exec ref: %s. Auth: %s", referenceId[0], authorization[0])

			// Get the reference execution
			oldExecution, err := GetWorkflowExecution(ctx, referenceId[0])
			if err != nil {
				log.Printf("[INFO] Failed getting execution (execution) %s: %s", referenceId[0], err)
				return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Failed getting execution ID %s because it doesn't exist.", referenceId[0]), err
			}

			if oldExecution.Workflow.ID != workflow.ID {
				log.Printf("[INFO] Wrong workflowid!")
				return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Bad workflow ID in get %s", referenceId), errors.New("Bad workflow ID")
			}

			if authorization[0] != oldExecution.Authorization {
				log.Printf("[AUDIT][%s] Wrong authorization for execution during userinput! %s vs %s", referenceId[0], authorization[0], oldExecution.Authorization)
				return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Bad authorization in get %s", referenceId), errors.New("Bad authorization key")
			}

			if len(start) == 0 {
				// Just guessing~
				for _, trigger := range workflow.Triggers {
					if trigger.AppName == "User Input" {
						start = []string{trigger.ID}
						break
					}
				}
			}

			if len(start) == 0 {
				log.Printf("[ERROR] No start node found for workflow %s during workflow continuation", workflow.ID)
				return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("No start node found for workflow continuation %s", workflow.ID), errors.New("No start node found for workflow continuation")
			}

			//log.Printf("Result len: %d", len(oldExecution.Results))
			newResults := []ActionResult{}
			foundresult := ActionResult{}
			for _, result := range oldExecution.Results {
				//log.Printf("Action: %s - %s", result.Action.ID, start[0])

				if result.Action.ID == start[0] {
					if result.Status == "ABORTED" {
						log.Printf("[INFO] Found aborted result: %s (%s)", result.Action.Label, result.Action.ID)
						if oldExecution.Status != "ABORTED" {
							log.Printf("[INFO] Aborting execution %s as it should have already been aborted in the past", oldExecution.ExecutionId)
							oldExecution.Status = "ABORTED"
							oldExecution.CompletedAt = time.Now().Unix()
							SetWorkflowExecution(ctx, *oldExecution, true)

							return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Execution %s was already aborted", oldExecution.ExecutionId), errors.New("Execution already aborted")
						}
					}
				}

				if result.Status == "WAITING" {
					log.Printf("[INFO][%s] Found result: %s (%s)", result.ExecutionId, result.Action.Label, result.Action.ID)

					var userinputResp UserInputResponse
					err = json.Unmarshal([]byte(result.Result), &userinputResp)
					// Error here should just be warnings
					if err != nil {
						log.Printf("[ERROR][%s] Failed unmarshalling userinput (not critical): %s", result.ExecutionId, err)
					}

					//if err == nil {
					userinputResp.ClickInfo.Clicked = true
					userinputResp.ClickInfo.Time = time.Now().Unix()
					userinputResp.ClickInfo.IP = GetRequestIp(request)
					userinputResp.ClickInfo.Note = ""

					user, err := HandleApiAuthentication(nil, request)
					if err == nil && user.Username != "" {
						userinputResp.ClickInfo.User = user.Username
					}

					b, err := json.Marshal(userinputResp)
					if err != nil {
						log.Printf("[ERROR] Failed marshalling userinput: %s", err)
					} else {
						result.Result = string(b)
					}

					result.CompletedAt = int64(time.Now().Unix()) * 1000
					log.Printf("[INFO][%s] Setting result to %s", oldExecution.ExecutionId, result.Action.Label)

					sendSelfRequest := false
					if answer[0] == "false" {
						result.Status = "SKIPPED"
						sendSelfRequest = true
					} else {
						result.Status = "SUCCESS"
					}

					// Should send result to self?
					fullMarshal, err := json.Marshal(result)
					if err == nil {
						actionCacheId := fmt.Sprintf("%s_%s_result", result.ExecutionId, result.Action.ID)
						err = SetCache(ctx, actionCacheId, fullMarshal, 35)
						if err != nil {
							log.Printf("[ERROR] Failed setting cache for action result %s: %s", actionCacheId, err)
						}

						// FIXME: Should send result to self?
						// Maybe that is ONLY if on cloud?
						if strings.ToLower(result.Action.Environment) != "cloud" {
							log.Printf("[DEBUG][%s] SETTING user input result, and re-adding it to queue IF not in worker. Environment: %s", result.ExecutionId, result.Action.Environment)
							if project.Environment == "worker" {
								log.Printf("\n\n[DEBUG][%s] Worker user input restart. What do? Should we ever reach this point?\n\n")
							} else {

								updateMade := true

								log.Printf("[DEBUG][%s] Re-adding user input execution to db & queue after re-setting result back", result.ExecutionId)
								oldExecution.Status = "EXECUTING"

								for newresIndex, newres := range oldExecution.Results {
									if newres.Action.ID == result.Action.ID {
										oldExecution.Results[newresIndex] = result
										break
									}
								}

								err = SetWorkflowExecution(ctx, *oldExecution, true)
								if err != nil {
									updateMade = false
									log.Printf("[ERROR] Failed setting workflow execution actionresult in execution: %s", err)
								}

								// Should re-add to queue
								executionRequest := ExecutionRequest{
									ExecutionId:   oldExecution.ExecutionId,
									WorkflowId:    oldExecution.Workflow.ID,
									Authorization: oldExecution.Authorization,
									Environments:  []string{result.Action.Environment},
								}

								// Increase priority on User Input catch-ups
								executionRequest.Priority = 11
								parsedEnv := fmt.Sprintf("%s_%s", strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(result.Action.Environment, " ", "-"), "_", "-")), oldExecution.ExecutionOrg)

								if project.Environment != "cloud" {
									parsedEnv = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(result.Action.Environment, " ", "-"), "_", "-"))
								}

								err = SetWorkflowQueue(ctx, executionRequest, parsedEnv)
								if err != nil {
									updateMade = false
									log.Printf("[ERROR] Failed re-adding User Input execution to db: %s", err)
								}

								if updateMade {
									return *oldExecution, ExecInfo{}, "", errors.New("User Input: Execution action skipped!")
								}
							}
						}

						if sendSelfRequest || strings.ToLower(result.Action.Environment) == "cloud" {
							log.Printf("[DEBUG][%s] Sending User Input result to self because we are on cloud env/action is skipped", result.ExecutionId)

							backendUrl := os.Getenv("BASE_URL")
							if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
								backendUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
							}

							if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
								backendUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
							}

							topClient := &http.Client{
								Transport: &http.Transport{
									Proxy: nil,
								},
							}
							streamUrl := fmt.Sprintf("%s/api/v1/streams", backendUrl)
							req, err := http.NewRequest(
								"POST",
								streamUrl,
								bytes.NewBuffer([]byte(fullMarshal)),
							)

							if err != nil {
								log.Printf("[ERROR] Failed creating request for stream during SKIPPED user input: %s", err)
								return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Execution action failed to skip. Contact support if this persists.", oldExecution.ExecutionId), errors.New("Execution action failed to skip. Contact support if this persists.")
							}

							newresp, err := topClient.Do(req)
							if err != nil {
								log.Printf("[ERROR] Failed sending request for stream during SKIPPED user input: %s", err)
								return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Execution action failed to skip during send. Contact support if this persists.", oldExecution.ExecutionId), errors.New("Execution action failed to skip during send. Contact support if this persists.")
							}

							defer newresp.Body.Close()
						}

						return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Execution action skipped", oldExecution.ExecutionId), errors.New("User Input: Execution action skipped!")
					}

					foundresult = result
					newResults = append(newResults, result)
				} else {
					newResults = append(newResults, result)
				}
			}

			if foundresult.Action.AppName != "" {
				// Should resend the result to redeploy the job?
				log.Printf("[INFO][%s] Rerunning node for user input with WAITING", oldExecution.ExecutionId)
				b, err := json.Marshal(foundresult)
				if err != nil {
					log.Printf("[WARNING][%s] Failed to run node for user input with WAITING", oldExecution.ExecutionId)
				} else {
					ResendActionResult(b, 4)
				}
			} else {
				log.Printf("[WARNING][%s] No job to rerun for user input as a WAITING node was not found", oldExecution.ExecutionId)

				return WorkflowExecution{}, ExecInfo{}, "", errors.New("Already Clicked")
			}

			//if err != nil {
			/*
				oldExecution.Results = newResults
				err = SetWorkflowExecution(ctx, *oldExecution, true)
				if err != nil {
					log.Printf("[WARNING] Error saving workflow execution actionresult setting: %s", err)
					return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Failed setting workflowexecution actionresult in execution: %s", err), err
				}

				if foundresult.Action.AppName != "" {
					b, err := json.Marshal(foundresult)
					if err != nil {
						log.Printf("[ERROR] Error marshalling actionresult: %s", err)
					} else {
						log.Printf("[INFO] Sending user input result: %s", string(b))
						ResendActionResult(b, 4)
					}
				} else {
					log.Printf("[INFO] No WAITING node found")
					return *oldExecution, ExecInfo{}, "", errors.New("User Input: Already finished")
				}
			*/

			// Add new execution to queue?
			//if os.Getenv("SHUFFLE_SWARM_CONFIG") == "run" && (project.Environment == "" || project.Environment == "worker") {

			return *oldExecution, ExecInfo{}, "", errors.New("User Input")
		}

		if referenceok {
			log.Printf("[DEBUG] Handling an old execution continuation! Start: %s", start)

			// Will use the old name, but still continue with NEW ID
			oldExecution, err := GetWorkflowExecution(ctx, referenceId[0])
			if err != nil {
				log.Printf("[ERROR] Failed getting execution (execution) %s: %s", referenceId[0], err)
				return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Failed getting execution ID %s because it doesn't exist.", referenceId[0]), err
			}

			if oldExecution.Status != "WAITING" {
				return WorkflowExecution{}, ExecInfo{}, "", errors.New("Workflow is no longer with status waiting. Can't continue.")
			}

			if startok {
				for _, result := range oldExecution.Results {
					if result.Action.ID == start[0] {
						if result.Status == "SUCCESS" || result.Status == "FINISHED" {
							// Disabling this to allow multiple continuations
							//return WorkflowExecution{}, ExecInfo{}, "", errors.New("This workflow has already been continued")
						}
						//log.Printf("Start: %s", result.Status)
					}
				}
			}

			workflowExecution = *oldExecution

			// A previously stopped workflow. Same priority as subflow.
			workflowExecution.Priority = 9
		}

		if len(workflowExecution.ExecutionId) == 0 {
			sessionToken := uuid.NewV4()
			workflowExecution.ExecutionId = sessionToken.String()
		} else {
			log.Printf("[DEBUG] Using the same executionId as before: %s", workflowExecution.ExecutionId)
			makeNew = false
		}

		// Don't override workflow defaults
	}

	if workflowExecution.SubExecutionCount == 0 {
		workflowExecution.SubExecutionCount = 1
	}

	if workflowExecution.SubExecutionCount >= maxExecutionDepth {
		return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Max subflow of %d reached", maxExecutionDepth), err
	}

	if workflowExecution.Priority == 0 {
		workflowExecution.Priority = 10
	}

	if startok {
		//workflowExecution.Workflow.Start = start[0]
		workflowExecution.Start = start[0]
	} else {

		if workflowExecution.ExecutionSource == "schedule" {
			// This is kind of silly as it doesn't really check which trigger
			// it instead just picks one (meaning we can max have one..?)
			for _, trigger := range workflowExecution.Workflow.Triggers {
				if trigger.TriggerType != "SCHEDULE" {
					continue
				}

				startChanged := false
				for _, branch := range workflowExecution.Workflow.Branches {
					if branch.SourceID != trigger.ID {
						continue
					}

					if workflowExecution.Start != branch.DestinationID {
						workflowExecution.Start = branch.DestinationID
						startChanged = true
						break
					}
				}

				if startChanged {
					break
				}
			}
		}
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
		//log.Printf("[INFO] No execution source (trigger) specified. Setting to default")
		workflowExecution.ExecutionSource = "default"
	}

	// Look for header 'appauth' with upper/lowercase check
	authHeader := ""
	chosenEnvironment := ""
	for key, value := range request.Header {
		if strings.ToLower(key) == "appauth" {
			authHeader = value[0]
		}

		if strings.ToLower(key) == "environment" {
			chosenEnvironment = value[0]
		}
	}

	// curl 'http://localhost:5002/api/v1/workflows/{workflow_id}/run' -H 'app_auth: appname=auth_id;appname2=auth_id2'
	authGroups := []AppAuthenticationGroup{}
	allAuths := []AppAuthenticationStorage{}
	if len(authHeader) > 0 {
		//log.Printf("\n\n\n\n[DEBUG] Found appauth header in request. Attempting to find matching auth with name/ID '%s'\n\n\n\n", authHeader)
		if len(allAuths) == 0 {
			allAuths, err = GetAllWorkflowAppAuth(ctx, workflow.ExecutingOrg.Id)
			if err != nil {
				log.Printf("[ERROR] Failed getting all app authentications: %s", err)
			}
		}

		appAuthSplit := strings.Split(authHeader, ";")
		for _, authitem := range appAuthSplit {
			authitemSplit := strings.Split(authitem, "=")
			if len(authitemSplit) != 2 {
				continue
			}

			// Find the app in the workflow and replace the ID
			appname := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(authitemSplit[0])), " ", "_")
			authId := strings.ReplaceAll(strings.TrimSpace(authitemSplit[1]), " ", "_")

			authFound := false
			for _, auth := range allAuths {
				if auth.Id == authId || strings.ReplaceAll(auth.Label, " ", "_") == authId {
					authFound = true
					authId = auth.Id
				}
			}

			if !authFound {
				return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("App auth not found: %s", authId), errors.New(fmt.Sprintf("App auth '%s' not found for app '%s'", authId, appname))
			}

			found := false
			for actionIndex, action := range workflowExecution.Workflow.Actions {
				if strings.ReplaceAll(strings.ToLower(action.AppName), " ", "_") == appname || strings.ReplaceAll(strings.ToLower(action.ID), " ", "_") == appname || strings.ReplaceAll(strings.ToLower(action.AppID), " ", "_") == appname {
					workflowExecution.Workflow.Actions[actionIndex].AuthenticationId = authId
					found = true
				}
			}

			if !found {
				log.Printf("[DEBUG][%s] Didn't find custom app/auth: %s", workflowExecution.ExecutionId, appname)
			}
		}
	}

	workflowExecution.ExecutionVariables = workflow.ExecutionVariables
	if len(workflowExecution.Start) == 0 && len(workflowExecution.Workflow.Start) > 0 {
		workflowExecution.Start = workflowExecution.Workflow.Start
	}

	startnodeFound := false
	newStartnode := ""
	for actionIndex, item := range workflowExecution.Workflow.Actions {
		if item.ID == workflowExecution.Start {
			startnodeFound = true
		}

		// Backup fallback in case we can't find the one assigned
		if item.IsStartNode {
			newStartnode = item.ID
		}

		// Fix names of parameters
		for paramIndex, param := range item.Parameters {

			// Added after problem with api-secret -> apisecret
			if strings.Contains(param.Description, "header") {
				if strings.Contains(param.Value, "=undefined") {
					newheaders := []string{}
					for _, line := range strings.Split(param.Value, "\n") {
						if !strings.Contains(line, "=undefined") {
							newheaders = append(newheaders, line)
							continue
						}
					}

					item.Parameters[paramIndex].Value = strings.Join(newheaders, "\n")
				}
				continue
			}

			if strings.Contains(param.Description, "query") {
				continue
			}

			newName := GetValidParameters([]string{param.Name})
			if len(newName) > 0 {
				workflowExecution.Workflow.Actions[actionIndex].Parameters[paramIndex].Name = newName[0]
			}
		}
	}

	if !startnodeFound {
		log.Printf("[WARNING] Couldn't find startnode %s among %d actions. Remapping to %s", workflowExecution.Start, len(workflowExecution.Workflow.Actions), newStartnode)

		if len(newStartnode) > 0 {
			workflowExecution.Start = newStartnode
		} else {
			return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Startnode couldn't be found"), errors.New("Startnode isn't defined in this workflow..")
		}
	}

	childNodes := FindChildNodes(workflowExecution, workflowExecution.Start, []string{}, []string{})

	//topic := "workflows"
	startFound := false
	// FIXME - remove this?
	newActions := []Action{}
	defaultResults := []ActionResult{}

	if project.Environment == "cloud" {
		//apps, err := GetPrioritizedApps(ctx, user)
		//if err != nil {
		//	log.Printf("[WARNING] Error: Failed getting apps during setup: %s", err)
		//}
	}

	// Overwrites environment before validation below
	if len(chosenEnvironment) > 0 {
		for actionIndex, _ := range workflowExecution.Workflow.Actions {
			workflowExecution.Workflow.Actions[actionIndex].Environment = chosenEnvironment
		}
	}

	isAuthgroup := false
	if request != nil {
		// Check if "authgroups" param exists
		if authGroups, authGroupsOk := request.URL.Query()["authgroups"]; authGroupsOk {
			if len(authGroups) > 0 && authGroups[0] == "true" {
				isAuthgroup = true

				workflowExecution.ExecutionSource = "authgroups"
			}
		}
	}

	org := &Org{}
	previousEnvironment := ""
	orgEnvironments := []Environment{}

	subExecutionsDone := false
	for workflowExecutionIndex, action := range workflowExecution.Workflow.Actions {
		//action.LargeImage = ""
		if action.ID == workflowExecution.Start {
			startFound = true
		}

		// Fill in apikey?
		if project.Environment == "cloud" {

			if (action.AppName == "Shuffle Tools" || action.AppName == "email") && action.Name == "send_email_shuffle" || action.Name == "send_sms_shuffle" {
				for paramKey, param := range action.Parameters {
					if param.Name == "apikey" && action.Name == "send_sms_shuffle" {
						// This will be in cache after running once or twice AKA fast
						org, err := GetOrg(ctx, workflow.OrgId)
						if err != nil {
							log.Printf("[ERROR] Error getting org in APIkey replacement: %s", err)
							continue
						}

						// Make sure to find one that's belonging to the org
						// Picking random last user if

						backupApikey := ""
						for _, user := range org.Users {
							if len(user.ApiKey) == 0 {
								continue
							}

							if user.Role != "org-reader" {
								backupApikey = user.ApiKey
							}

							if len(user.Orgs) == 1 || user.ActiveOrg.Id == workflowExecution.Workflow.OrgId {
								//log.Printf("Choice: %s, %s - %s", user.Username, user.Id, user.ApiKey)
								workflowExecution.Workflow.Actions[workflowExecutionIndex].Parameters[paramKey].Value = user.ApiKey
								break
							}
						}

						if len(action.Parameters[paramKey].Value) == 0 {
							log.Printf("[WARNING] No apikey user found. Picking first random user")
							action.Parameters[paramKey].Value = backupApikey
							workflowExecution.Workflow.Actions[workflowExecutionIndex].Parameters[paramKey].Value = backupApikey
						}

						log.Printf("[DEBUG] Replaced apikey for %s with %s", param.Name, action.Parameters[paramKey].Value)

						break
					}

					// Autoreplace in general, even if there is a key. Overwrite previous configs to ensure this becomes the norm. Frontend also matches.
					if param.Name != "apikey" {
						//log.Printf("Autoreplacing apikey")

						// This will be in cache after running once or twice AKA fast
						org, err = GetOrg(ctx, workflowExecution.Workflow.OrgId)
						if err != nil {
							log.Printf("[ERROR] Error getting org in APIkey replacement: %s", err)
							continue
						}

						// Make sure to find one that's belonging to the org
						// Picking random last user if

						backupApikey := ""
						for _, user := range org.Users {
							if len(user.ApiKey) == 0 {
								continue
							}

							if user.Role != "org-reader" {
								backupApikey = user.ApiKey
							}

							if (len(user.Orgs) == 1 || user.ActiveOrg.Id == workflowExecution.Workflow.OrgId) && action.Name != "send_email_shuffle" {
								//log.Printf("Choice: %s, %s - %s", user.Username, user.Id, user.ApiKey)
								action.Parameters[paramKey].Value = user.ApiKey
								break
							}
						}

						if len(action.Parameters[paramKey].Value) == 0 {
							log.Printf("[WARNING] No apikey user found. Picking first random user")
							action.Parameters[paramKey].Value = backupApikey
						}

						break
					}
				}
			}
		}

		if action.Environment == "" {
			// Fallback automatically to the project environment
			if len(previousEnvironment) > 0 {
				action.Environment = previousEnvironment
			} else if project.Environment == "cloud" {
				action.Environment = "cloud"
			}

			if len(action.Environment) == 0 {
				log.Printf("[ERROR] Environment is not defined for action %s in workflow %s (%s)", action.Name, workflowExecution.Workflow.Name, workflowExecution.Workflow.ID)
				action.Environment = "shuffle"
			}

			if len(action.Environment) > 0 {
				previousEnvironment = action.Environment
			}
		} else {
			previousEnvironment = action.Environment
		}

		if action.AuthenticationId == "authgroups" && !subExecutionsDone && workflowExecution.ExecutionSource != "authgroup" && !isAuthgroup {
			discoveredApikey := ""
			if len(org.Users) == 0 {
				org, err = GetOrg(ctx, workflowExecution.Workflow.OrgId)
				if err != nil {
					log.Printf("[ERROR] Failed getting org for action %s: %s", action.Label, err)
				}
			}

			if len(org.Users) != 0 {
				log.Printf("[DEBUG][%s] Found %d users in org %s", workflowExecution.ExecutionId, len(org.Users), org.Id)

				for _, user := range org.Users {
					if user.Role != "admin" {
						continue
					}

					foundUser, err := GetUser(ctx, user.Id)
					if err != nil {
						log.Printf("[ERROR] Failed getting user %s: %s", user.Id, err)
					}

					if len(foundUser.ApiKey) == 0 {
						continue
					}

					log.Printf("[DEBUG][%s] Found apikey for user %s to be used for subexecutions", workflowExecution.ExecutionId, foundUser.Username)
					discoveredApikey = foundUser.ApiKey
					break
				}
			}

			log.Printf("[DEBUG][%s] Found authgroups in action %s (%s)", workflowExecution.ExecutionId, action.Label, action.ID)
			if len(authGroups) == 0 {
				authGroups, err = GetAuthGroups(ctx, workflow.OrgId)
				if err != nil {
					log.Printf("[ERROR] Failed getting authgroups for org %s: %s", workflow.OrgId, err)
					return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Failed getting authgroups for org %s: %s", workflow.OrgId, err), err
				}

				if len(authGroups) == 0 {
					log.Printf("[ERROR] No authgroups found for org %s", workflow.OrgId)
					return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("No authgroups found for org %s", workflow.OrgId), errors.New("No authgroups exist")
				}
			}

			relevantAuthgroups := []AppAuthenticationGroup{}
			for _, authGroup := range workflow.AuthGroups {
				found := false
				for _, group := range authGroups {
					if group.Id == authGroup {
						relevantAuthgroups = append(relevantAuthgroups, group)
						found = true
						break
					}
				}

				if !found {
					log.Printf("[WARNING] Authgroup %s not found in org %s", authGroup, workflow.OrgId)
				}
			}

			if len(relevantAuthgroups) == 0 {
				log.Printf("[ERROR] No relevant authgroups found for org %s. Do they still exist?", workflow.OrgId)
				return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("No relevant authgroups found for org %s. Do they still exist?", workflow.OrgId), errors.New("No relevant authgroups found for workflow. Do they still exist?")
			}

			log.Printf("[DEBUG][%s] Found %d relevant auth groups for action %s", workflowExecution.ExecutionId, len(relevantAuthgroups), action.Label)

			// FIXME: Start doing replication here.
			// First request (this one) should use the first authgroup
			// Second and all after should run as new requests that are overwritten with the right auth.

			firstGroup := relevantAuthgroups[0]

			for authgroupindex, authgroup := range relevantAuthgroups {

				if len(orgEnvironments) == 0 {
					orgEnvironments, err = GetEnvironments(ctx, workflowExecution.Workflow.OrgId)
					if err != nil {
						log.Printf("[ERROR] Failed getting environments for org %s: %s", workflow.OrgId, err)
						return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Failed getting environments for org %s: %s", workflow.OrgId, err), err
					}
				}

				environmentFound := false
				if authgroup.Environment == "" {
					// Fallback automatically to the project environment
					for _, env := range orgEnvironments {
						if env.Default {
							authgroup.Environment = env.Name
						}
					}
				}

				for _, env := range orgEnvironments {
					if strings.ToLower(env.Name) == strings.ToLower(authgroup.Environment) || env.Id == authgroup.Environment {
						environmentFound = true
						break
					}
				}

				if !environmentFound {
					log.Printf("[ERROR] Environment %s not found for authgroup %s", authgroup.Environment, authgroup.Id)
					return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Environment %s not found for authgroup %s", authgroup.Environment, authgroup.Id), errors.New(fmt.Sprintf("Environment %s not found for authgroup %s", authgroup.Environment, authgroup.Id))
				}

				for findActionIndex, findAction := range workflowExecution.Workflow.Actions {
					workflowExecution.Workflow.Actions[findActionIndex].Environment = authgroup.Environment

					if findAction.AuthenticationId != "authgroups" {
						continue
					}

					log.Printf("[DEBUG][%s] Found authgroups in action %s (%s)", workflowExecution.ExecutionId, findAction.Label, findAction.ID)

					// Find the app in the group
					authFound := false
					for _, auth := range firstGroup.AppAuths {
						if strings.ToLower(auth.App.Name) == strings.ToLower(findAction.AppName) || auth.App.ID == findAction.AppID {
							workflowExecution.Workflow.Actions[findActionIndex].AuthenticationId = auth.Id

							if workflowExecution.Workflow.Actions[findActionIndex].ID == action.ID {
								action = workflowExecution.Workflow.Actions[findActionIndex]
							}

							authFound = true
							break
						}
					}

					log.Printf("[DEBUG][%s] New auth ID for %s: %s", workflowExecution.ExecutionId, findAction.AppName, workflowExecution.Workflow.Actions[findActionIndex].AuthenticationId)

					if !authFound {
						log.Printf("[ERROR][%s] App %s not found in authgroup %s", workflowExecution.ExecutionId, findAction.AppName, firstGroup.Id)
						return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("App %s not found in authgroup %s", findAction.AppName, firstGroup.Id), errors.New(fmt.Sprintf("App %s not found in authgroup %s", findAction.AppName, firstGroup.Id))
					}

					//action = workflowExecution.Workflow.Actions[workflowExecutionIndex]
					log.Printf("[DEBUG][%s] Updated action with ID %s to use authgroup %s", workflowExecution.ExecutionId, action.ID, firstGroup.Id)

				}

				if authgroupindex == 0 {
					// First one is the current execution.
					// No need to run as subflow
					workflowExecution.Authgroup = authgroup.Label
					continue
				}

				// Replication starts here
				log.Printf("[DEBUG][%s] SHOULD REPLICATE AUTHGROUP ACTION MAPPING into %d groups", workflowExecution.ExecutionId, len(relevantAuthgroups))
				subExecutionsDone = true
				// Send a self-request to execute THIS workflow as a subflow

				go executeAuthgroupSubflow(workflowExecution, authgroup, discoveredApikey)
				/*
					err = executeAuthgroupSubflow(workflowExecution, authgroup, discoveredApikey)
					if err != nil {
						log.Printf("[ERROR] Failed executing authgroup subflow: %s", err)
					}
				*/
			}

			//log.Printf("[DEBUG][%s] RETURNING BEFORE ORIGINAL SUBFLOW CAN RUN", workflowExecution.ExecutionId)
			//return  WorkflowExecution{}, ExecInfo{}, "", errors.New("authgroup")
		}

		if len(action.AuthenticationId) > 0 {
			if len(allAuths) == 0 {
				allAuths, err = GetAllWorkflowAppAuth(ctx, workflow.ExecutingOrg.Id)
				if err != nil {
					log.Printf("[ERROR] Api authentication failed in get all app auth for ID %s: %s", workflow.ExecutingOrg.Id, err)
					return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Api authentication failed in get all app auth for %s: %s", workflow.ExecutingOrg.Id, err), err
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
				//continue
				return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("App Auth ID %s doesn't exist for app '%s'. Please re-authenticate the app.", action.AuthenticationId, action.AppName), errors.New(fmt.Sprintf("App Auth ID %s doesn't exist for app '%s'. Please re-authenticate the app.", action.AuthenticationId, action.AppName))
			}

			if curAuth.Encrypted {
				setField := true
				newFields := []AuthenticationStore{}
				fieldLength := 0
				for _, field := range curAuth.Fields {
					parsedKey := fmt.Sprintf("%s_%d_%s_%s", curAuth.OrgId, curAuth.Created, curAuth.Label, field.Key)
					newValue, err := HandleKeyDecryption([]byte(field.Value), parsedKey)
					if err != nil {
						log.Printf("[ERROR] Failed decryption (3) in auth org %s for %s: %s. Auth label: %s", curAuth.OrgId, field.Key, err, curAuth.Label)
						setField = false
						//fieldLength = 0
						break
					}

					// Remove / at end of urls
					// TYPICALLY shouldn't use them.
					if field.Key == "url" {
						//log.Printf("Value2 (%s): %s", field.Key, string(newValue))
						if strings.HasSuffix(string(newValue), "/") {
							newValue = []byte(string(newValue)[0 : len(newValue)-1])
						}

						//log.Printf("Value2 (%s): %s", field.Key, string(newValue))
					}

					fieldLength += len(newValue)
					field.Value = string(newValue)
					newFields = append(newFields, field)
				}

				// There is some Very weird bug that has caused encryption to sometimes be skipped.
				// This is a way to discover when this happens properly.
				// The problem happens about every 10.000~ decryption, which is still way too much.
				// By adding the full total, there should be no problem with this, seeing as lengths are added together
				fieldNames := ""
				for _, field := range curAuth.Fields {
					fieldNames += field.Key + ", "
				}

				if setField {
					curAuth.Fields = newFields

					//log.Printf("[DEBUG] Outer decryption (1) debugging for %s. Auth: %s, Fields: %s. Length: %d", curAuth.OrgId, curAuth.Label, fieldNames, fieldLength)
				} else {
					//log.Printf("[ERROR] Outer decryption (2) debugging for org %s. Auth: '%s'. Fields: %s. Length: %d", curAuth.OrgId, curAuth.Label, fieldNames, fieldLength)

				}
			} else {
				//log.Printf("[INFO] AUTH IS NOT ENCRYPTED - attempting auto-encrypting if key is set!")
				err = SetWorkflowAppAuthDatastore(ctx, curAuth, curAuth.Id)
				if err != nil {
					log.Printf("[WARNING] Failed running encryption during execution: %s", err)
				}
			}

			newParams := []WorkflowAppActionParameter{}
			if strings.ToLower(curAuth.Type) == "oauth2-app" {
				// Check if they need to be decrypted

				// Check if it already has a new token in cache from same auth current execution

				setAuth := false
				executionAuthKey := fmt.Sprintf("oauth2_%s", curAuth.Id)

				log.Printf("[DEBUG] Looking for cached authkey '%s'", executionAuthKey)
				execAuthData, err := GetCache(ctx, executionAuthKey)
				if err == nil {
					log.Printf("[DEBUG] Successfully retrieved auth wrapper from cache for %s", executionAuthKey)
					cacheData := []byte(execAuthData.([]uint8))

					appAuthWrapper := AppAuthenticationStorage{}
					err = json.Unmarshal(cacheData, &appAuthWrapper)
					if err == nil {
						log.Printf("[DEBUG] Successfully unmarshalled auth wrapper from cache for %s", executionAuthKey)

						newParams = action.Parameters
						for _, param := range appAuthWrapper.Fields {
							if param.Key != "access_token" {
								continue
							}

							newParams = append(newParams, WorkflowAppActionParameter{
								Name:  param.Key,
								Value: param.Value,
							})
						}

						setAuth = true
					} else {
						log.Printf("[ERROR] Failed unmarshalling auth wrapper from cache for %s: %s", executionAuthKey, err)
					}
				}

				if !setAuth {
					for fieldIndex, field := range curAuth.Fields {

						parsedKey := fmt.Sprintf("%s_%d_%s_%s", curAuth.OrgId, curAuth.Created, curAuth.Label, field.Key)
						decrypted, err := HandleKeyDecryption([]byte(field.Value), parsedKey)
						if err != nil {
							log.Printf("[ERROR] Failed decryption (1) in org %s for %s: %s", curAuth.OrgId, field.Key, err)
							if field.Key != "access_key" && field.Key != "access_token" {
								//log.Printf("[ERROR] Failed decryption (1) in org %s for %s: %s", curAuth.OrgId, field.Key, err)
							}
							continue
						}

						curAuth.Fields[fieldIndex].Value = string(decrypted)
						//field.Value = decrypted
					}

					user := User{
						Username: "refresh",
						ActiveOrg: OrgMini{
							Id: curAuth.OrgId,
						},
					}

					newAuth, err := GetOauth2ApplicationPermissionToken(ctx, user, curAuth)
					if err != nil {
						log.Printf("[ERROR] Failed running oauth request to refresh oauth2 tokens: %s. Stopping Oauth2 continuation and sending abort for app. This is NOT critical, but means refreshing access_token failed, and it will stop working in the future.", err)
						//workflowExecution.Status = "ABORTED"
						//workflowExecution.Result = "Oauth2 failed during start of execution. Please re-authenticate the app."

						workflowExecution.NotificationsCreated += 1
						workflowExecution.Results = append(workflowExecution.Results, ActionResult{
							Action:        action,
							ExecutionId:   workflowExecution.ExecutionId,
							Authorization: workflowExecution.Authorization,
							Result:        fmt.Sprintf(`{"success": false, "reason": "Failed running oauth2 request to refresh tokens. Are your credentials and URL correct? Contact support@shuffler.io if this persists.", "details": "%s"}`, strings.ReplaceAll(fmt.Sprintf("%s", err), `"`, `\"`)),
							StartedAt:     workflowExecution.StartedAt,
							CompletedAt:   workflowExecution.StartedAt,
							Status:        "SKIPPED",
						})

						CreateOrgNotification(
							ctx,
							fmt.Sprintf("Failed to refresh Oauth2 tokens for auth '%s'. Did the credentials change?", curAuth.Label),
							fmt.Sprintf("Failed running oauth2 request to refresh oauth2 tokens for app '%s'. Are your credentials and URL correct? Please check backend logs for more details or contact support@shiffler.io for additional help. Details: %#v", curAuth.App.Name, err.Error()),
							fmt.Sprintf("/workflows/%s?execution_id=%s", workflowExecution.Workflow.ID, workflowExecution.ExecutionId),
							workflowExecution.ExecutionOrg,
							true,
						)

						// Abort the workflow due to auth being bad
						//return workflowExecution, ExecInfo{}, fmt.Sprintf("Oauth2 failed to initialize"), nil

					} else {
						// Resets the params and overwrites with the relevant fields
						curAuth = newAuth
						newParams = action.Parameters
						for _, param := range newAuth.Fields {
							if param.Key != "access_token" {
								continue
							}

							newParams = append(newParams, WorkflowAppActionParameter{
								Name:  param.Key,
								Value: param.Value,
							})
						}

						marshalledAuth, err := json.Marshal(newAuth)
						if err == nil {
							err = SetCache(ctx, executionAuthKey, marshalledAuth, 1)
							if err != nil {
								log.Printf("[ERROR] Failed setting cache for %s: %s", executionAuthKey, err)
							}
						} else {
							log.Printf("[ERROR] Failed marshalling auth wrapper for %s: %s", executionAuthKey, err)
						}
					}
				}
			} else if strings.ToLower(curAuth.Type) == "oauth2" {
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

				runRefresh = true
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
						//log.Printf("[INFO] Running Oauth2 request with URL %s", refreshUrl)

						newAuth, err := RunOauth2Request(ctx, user, curAuth, true)
						if err != nil {
							log.Printf("[ERROR] Failed running oauth request to refresh oauth2 tokens: '%s'. Stopping Oauth2 continuation and sending abort for app. This is NOT critical, but means refreshing access_token failed, and it will stop working in the future.", err)

							CreateOrgNotification(
								ctx,
								fmt.Sprintf("Failed to refresh Oauth2 tokens for app '%s'", curAuth.Label),
								fmt.Sprintf("Failed running oauth2 request to refresh oauth2 tokens for app '%s'. Are your credentials and URL correct? Please check backend logs for more details or contact support@shiffler.io for additional help. Details: %#v", curAuth.App.Name, err.Error()),
								fmt.Sprintf("/workflows/%s?execution_id=%s", workflowExecution.Workflow.ID, workflowExecution.ExecutionId),
								workflowExecution.ExecutionOrg,
								true,
							)

							// Adding so it can be used to fail the auth naturally with Outlook

							authfieldFound := false
							for _, field := range curAuth.Fields {
								if field.Key == "access_token" {
									authfieldFound = true
									break
								}
							}

							if !authfieldFound {
								newAuth.Fields = append(newAuth.Fields, AuthenticationStore{
									Key:   "access_token",
									Value: "FAILURE_REFRESH",
								})
							}

							// Commented out as we don't want to stop the app, but just continue with the old tokens
							/*
								actionRes := ActionResult{
									Action:        action,
									ExecutionId:   workflowExecution.ExecutionId,
									Authorization: workflowExecution.Authorization,
									Result:        fmt.Sprintf(`{"success": false, "reason": "Failed running oauth2 request to refresh oauth2 tokens for this app."}`),
									StartedAt:     workflowExecution.StartedAt,
									CompletedAt:   workflowExecution.StartedAt,
									Status:        "FAILURE",
								}

								workflowExecution.Results = append(workflowExecution.Results, actionRes)
								cacheData := []byte("1")

								newExecId := fmt.Sprintf("%s_%s", workflowExecution.ExecutionId, action.ID)
								err = SetCache(ctx, newExecId, cacheData, 2)
								if err != nil {
									log.Printf("[WARNING] Failed setting base cache for failed Oauth2 action %s: %s", newExecId, err)
								}

								b, err := json.Marshal(actionRes)
								if err == nil {
									err = SetCache(ctx, fmt.Sprintf("%s_result", newExecId), b, 2)
									if err != nil {
										log.Printf("[WARNING] Failed setting result cache for failed Oauth2 action %s: %s", newExecId, err)
									}
								}
							*/
						}

						allAuths[authIndex] = newAuth

						// Does the oauth2 replacement
						newParams = []WorkflowAppActionParameter{}
						for _, param := range newAuth.Fields {
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

				for _, param := range action.Parameters {
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
			extra := 0
			for _, trigger := range workflowExecution.Workflow.Triggers {
				//log.Printf("Appname trigger (0): %s", trigger.AppName)
				if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
					extra += 1
				}
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
					Result:        `{"success": false, "reason": "Skipped because it's not under the startnode (1)"}`,
					StartedAt:     0,
					CompletedAt:   0,
					Status:        "SKIPPED",
				})
			}
		}
	}

	// Added fixes for e.g. URL's ending in /
	fixes := []string{"url"}
	for actionIndex, action := range workflowExecution.Workflow.Actions {
		if strings.ToLower(action.AppName) == "http" {
			continue
		}

		for paramIndex, param := range action.Parameters {
			if !param.Configuration {
				continue
			}

			if ArrayContains(fixes, strings.ToLower(param.Name)) {
				if strings.HasSuffix(param.Value, "/") {
					workflowExecution.Workflow.Actions[actionIndex].Parameters[paramIndex].Value = param.Value[0 : len(param.Value)-1]
				}
			}
		}
	}

	// Not necessary with comments at all
	workflowExecution.Workflow.Comments = []Comment{}
	for _, trigger := range workflowExecution.Workflow.Triggers {
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

				found := false
				for _, res := range defaultResults {
					if res.Action.ID == trigger.ID {
						found = true
						break
					}
				}

				if !found {
					defaultResults = append(defaultResults, ActionResult{
						Action:        curaction,
						ExecutionId:   workflowExecution.ExecutionId,
						Authorization: workflowExecution.Authorization,
						Result:        `{"success": false, "reason": "Skipped because it's not under the startnode (2)"}`,
						StartedAt:     0,
						CompletedAt:   0,
						Status:        "SKIPPED",
					})
				}
			} else {
				// Replaces trigger with the subflow

			}
		}
	}

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
				//log.Printf("[DEBUG] Couldn't find environment %s in cloud for some reason.", action.Environment)
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

	if len(workflowExecution.Workflow.ExecutingOrg.Id) == 0 || workflowExecution.ExecutionOrg != workflowExecution.Workflow.ExecutingOrg.Id {
		workflowExecution.Workflow.ExecutingOrg = OrgMini{
			Id: workflowExecution.ExecutionOrg,
		}
	}

	workflowExecution.Workflow.OrgId = workflowExecution.Workflow.ExecutingOrg.Id

	/*
		workflowExecution.Workflow.ExecutingOrg = OrgMini{
			Id: workflowExecution.Workflow.ExecutingOrg.Id,
		}
		workflowExecution.Workflow.Org = []OrgMini{
			workflowExecution.Workflow.ExecutingOrg,
		}
	*/

	// Means executing a subflow is happening
	if len(workflowExecution.ExecutionParent) > 0 {
		IncrementCache(ctx, workflowExecution.ExecutionOrg, "subflow_executions")
	}

	// NEW check for subflow
	// This is also handling triggers -> action translation now for subflow
	extra := 0
	newTriggers := []Trigger{}
	for _, trigger := range workflowExecution.Workflow.Triggers {
		if trigger.TriggerType != "SUBFLOW" && trigger.TriggerType != "USERINPUT" {
			newTriggers = append(newTriggers, trigger)
			continue
		}

		if trigger.TriggerType == "SUBFLOW" {
			//log.Printf("[INFO] Subflow trigger found during execution! envs: %#v", environments)

			// Find branch that has the subflow as destinationID
			foundenv := ""
			for _, branch := range workflowExecution.Workflow.Branches {
				if branch.DestinationID == trigger.ID {

					// FIX: May not work for subflow -> subflow if they are added in opposite order or something weird
					for _, action := range workflowExecution.Workflow.Actions {
						if action.ID == branch.SourceID {
							foundenv = action.Environment
							break
						}
					}

					if len(foundenv) > 0 {
						break
					}
				}
			}

			// Backup env :>
			if len(foundenv) == 0 && len(environments) > 0 {
				//log.Printf("[ERROR] Fallback to environment %s for subflow (default). Does it still run?", environments[0])
				foundenv = environments[0]
			}

			// Setting to default?
			// environments := []string{}
			action := GetAction(workflowExecution, trigger.ID, foundenv)

			action.Label = trigger.Label
			action.ID = trigger.ID
			action.Name = "run_subflow"
			action.AppName = "shuffle-subflow"
			action.AppVersion = "1.1.0"

			action.Parameters = []WorkflowAppActionParameter{}
			for _, parameter := range trigger.Parameters {
				parameter.Variant = "STATIC_VALUE"
				if parameter.Name == "user_apikey" {
					continue
				}

				action.Parameters = append(action.Parameters, parameter)
				//log.Printf("[INFO] Adding parameter %s to subflow", parameter.Name)
			}

			action.Parameters = append(action.Parameters, WorkflowAppActionParameter{
				Name:  "source_workflow",
				Value: workflowExecution.Workflow.ID,
			})

			action.Parameters = append(action.Parameters, WorkflowAppActionParameter{
				Name:  "source_execution",
				Value: workflowExecution.ExecutionId,
			})

			action.Parameters = append(action.Parameters, WorkflowAppActionParameter{
				Name:  "source_auth",
				Value: workflowExecution.Authorization,
			})

			action.Parameters = append(action.Parameters, WorkflowAppActionParameter{
				Name:  "user_apikey",
				Value: workflowExecution.Authorization,
			})

			action.Parameters = append(action.Parameters, WorkflowAppActionParameter{
				Name:  "source_node",
				Value: action.ID,
			})

			backendUrl := os.Getenv("BASE_URL")
			if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
				backendUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
			}

			if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 && strings.Contains(os.Getenv("SHUFFLE_CLOUDRUN_URL"), "http") {
				backendUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
			}

			if len(backendUrl) > 0 {
				action.Parameters = append(action.Parameters, WorkflowAppActionParameter{
					Name:  "backend_url",
					Value: backendUrl,
				})
			} else {
				log.Printf("[ERROR] No Backend URL found for subflow. May fail to connect properly.")
			}

			workflowExecution.Workflow.Actions = append(workflowExecution.Workflow.Actions, action)
		} else {
			newTriggers = append(newTriggers, trigger)
			extra += 1
		}
	}

	workflowExecution.Workflow.Triggers = newTriggers

	// Checking authentication fields as they should now be filled in no matter where

	if len(workflowExecution.ExecutionOrg) == 0 {
		log.Printf("\n\n[ERROR] No org found for execution. This should not happen.\n\n")
	}

	if len(org.Id) == 0 {
		org, err = GetOrg(ctx, workflowExecution.ExecutionOrg)
		if err != nil {
			log.Printf("[ERROR] Failed to get org: %s", err)
		}
	}

	// Clear out example & description fields
	for actionIndex, action := range workflowExecution.Workflow.Actions {
		for paramIndex, _ := range action.Parameters {
			workflowExecution.Workflow.Actions[actionIndex].Parameters[paramIndex].Example = ""
			workflowExecution.Workflow.Actions[actionIndex].Parameters[paramIndex].Description = ""
		}
	}

	// A way to set default config for kmsid if it's not set
	if len(org.Defaults.KmsId) == 0 {
		if len(allAuths) == 0 {
			allAuths, err = GetAllWorkflowAppAuth(ctx, workflow.ExecutingOrg.Id)
			if err != nil {
				log.Printf("[ERROR] Failed to get auths during kms prep: %s", err)
			}
		}

		for _, auth := range allAuths {
			if strings.ReplaceAll(strings.TrimSpace(strings.ToLower(auth.Label)), "_", " ") == "kms shuffle storage" {
				org.Defaults.KmsId = auth.Id
				break
			}
		}
	}

	if len(org.Defaults.KmsId) > 0 {
		if len(allAuths) == 0 {
			allAuths, err = GetAllWorkflowAppAuth(ctx, workflow.ExecutingOrg.Id)
			if err != nil {
				log.Printf("[ERROR] Failed to get auths during kms prep: %s", err)
			}
		}

		foundAuth := AppAuthenticationStorage{}
		for _, auth := range allAuths {
			if auth.Id != org.Defaults.KmsId {
				continue
			}

			foundAuth = auth
			break
		}

		// Use the auth to decrypt
		if foundAuth.Id == org.Defaults.KmsId {
			foundAuth.App.LargeImage = ""
			foundAuth.App.SmallImage = ""

			findKeys := []string{}
			for actionIndex, action := range workflowExecution.Workflow.Actions {
				for paramIndex, param := range action.Parameters {
					// FIXME: Should we allow KMS for ANYthing?

					if !param.Configuration && !kmsDebug {
						continue
					}

					if strings.HasPrefix(param.Value, "/") {
						param.Value = strings.TrimPrefix(param.Value, "/")
					}

					// Allow for both kms/ kms. and kms: as prefix
					if !strings.HasPrefix(strings.ToLower(param.Value), "kms.") && !strings.HasPrefix(strings.ToLower(param.Value), "kms/") && !strings.HasPrefix(strings.ToLower(param.Value), "kms:") {
						continue
					}

					splitValue := "/"
					if strings.Contains(strings.ToLower(param.Value), "kms:") {
						splitValue = ":"
					}

					if strings.HasSuffix(param.Value, splitValue) {
						param.Value = param.Value[0 : len(param.Value)-1]
					}

					if param.Configuration {
						param.Value = fmt.Sprintf("%s%s${%s}", param.Value, splitValue, param.Name)
					}

					if !ArrayContains(findKeys, param.Value) {
						findKeys = append(findKeys, param.Value)
					}

					workflowExecution.Workflow.Actions[actionIndex].Parameters[paramIndex].Value = param.Value
				}
			}

			// Should run all keys goroutines, then go find them again when all are done and replace
			// Wtf is this garbage
			if len(findKeys) > 0 {
				//log.Printf("\n\n\n\n[INFO] Found %d auth key(s) to decrypt from KMS\n\n\n\n", len(findKeys))

				// Have to set the workflow exec in cache while running this so that access rights exist
				foundValues := map[string]string{}
				marshalledExec, err := json.Marshal(workflowExecution)
				if err == nil {
					cacheKey := fmt.Sprintf("workflowexecution_%s", workflowExecution.ExecutionId)
					err = SetCache(ctx, cacheKey, marshalledExec, 1)
					if err == nil {

						// FIXME: Optimize this to run in parallel
						// across multiple goroutines
						for _, k := range findKeys {
							decrypted, err := DecryptKMS(ctx, foundAuth, k, workflowExecution.Authorization, workflowExecution.ExecutionId)
							if err == nil {
								foundValues[k] = decrypted
							} else {
								CreateOrgNotification(
									ctx,
									fmt.Sprintf("Failed to decrypt KMS key '%s'", k),
									fmt.Sprintf("Failed to decrypt KMS key '%s'. Error: %s", k, err),
									fmt.Sprintf("/workflows/%s?execution_id=%s", workflowExecution.Workflow.ID, workflowExecution.ExecutionId),
									workflowExecution.ExecutionOrg,
									true,
								)
							}
						}
					} else {
						log.Printf("[ERROR] Failed to set workflow execution in cache: %s", err)
					}
				} else {
					log.Printf("[ERROR] Failed to marshal workflow execution for cache: %s", err)
				}

				// Continue here
				if len(foundValues) > 0 {
					for actionIndex, action := range workflowExecution.Workflow.Actions {
						for paramIndex, param := range action.Parameters {
							if !param.Configuration && !kmsDebug {
								continue
							}

							if !strings.HasPrefix(strings.ToLower(param.Value), "kms.") && !strings.HasPrefix(strings.ToLower(param.Value), "kms/") && !strings.HasPrefix(strings.ToLower(param.Value), "kms:") {
								continue
							}

							if val, ok := foundValues[param.Value]; ok {
								//log.Printf("[INFO] Replacing value for %s with %s", param.Value, val)
								workflowExecution.Workflow.Actions[actionIndex].Parameters[paramIndex].Value = val
							} else {
								// Remove the last /${%s} part if it exists in a key
								for mapKey, mapValue := range foundValues {
									if strings.HasPrefix(mapKey, param.Value) {
										workflowExecution.Workflow.Actions[actionIndex].Parameters[paramIndex].Value = mapValue
										break
									}
								}
							}
						}
					}

				}
			}
		} else {
			//log.Printf("[ERROR] Default KMS ID not found in organization. Will not be able to decrypt secrets.")
		}
	}

	// Handles org setting for subflows
	if len(workflowExecution.Workflow.ExecutingOrg.Name) == 0 {
		// Maybe should be set from the parentorg?

		if parentExecution.Workflow.ExecutingOrg.Id != "" {
			workflowExecution.Workflow.ExecutingOrg = parentExecution.Workflow.ExecutingOrg
		} else {
			//log.Printf("[ERROR] Execution org name is empty, but should be filled in. This is a bug. Execution org: %+v", workflowExecution.ExecutionOrg)

			workflowExecution.Workflow.ExecutingOrg.Name = org.Name
			workflowExecution.Workflow.ExecutingOrg.Name = org.Id
		}
	}

	finished := ValidateFinished(ctx, extra, workflowExecution)
	if finished {
		log.Printf("[INFO][%s] Workflow already finished during startup. Is this correct?", workflowExecution.ExecutionId)
	}

	DeleteCache(ctx, fmt.Sprintf("workflowexecution_%s", workflowExecution.WorkflowId))
	DeleteCache(ctx, fmt.Sprintf("workflowexecution_%s_50", workflowExecution.WorkflowId))
	DeleteCache(ctx, fmt.Sprintf("workflowexecution_%s_100", workflowExecution.WorkflowId))

	workflowExecution.WorkflowId = workflowExecution.Workflow.ID

	return workflowExecution, ExecInfo{OnpremExecution: onpremExecution, Environments: environments, CloudExec: cloudExec, ImageNames: imageNames}, "", nil
}

func executeAuthgroupSubflow(workflowExecution WorkflowExecution, authgroup AppAuthenticationGroup, apikey string) error {
	if len(apikey) == 0 {
		log.Printf("[ERROR] No admin API key found to handle subflow execution")
		return errors.New("No API key found for subflow execution")
	}

	log.Printf("[DEBUG] Starting authgroup subflow execution for %s with authgroup %s", workflowExecution.ExecutionId, authgroup.Label)

	parsedEnvironment := authgroup.Environment
	parsedAuthIds := ""

	relevantAuth := map[string]string{}
	for _, auth := range authgroup.AppAuths {
		if len(auth.App.ID) == 0 {
			continue
		}

		relevantAuth[auth.App.ID] = auth.Id
	}

	for key, value := range relevantAuth {
		parsedAuthIds += fmt.Sprintf("%s=%s;", key, value)
	}

	parsedAuthIds = strings.TrimRight(parsedAuthIds, ";")

	backendUrl := os.Getenv("BASE_URL")
	if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
		backendUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
	}

	resultUrl := fmt.Sprintf("%s/api/v1/workflows/%s/execute", backendUrl, workflowExecution.Workflow.ID)

	// FIXME: Missing source node (?)
	//queries := fmt.Sprintf("authgroups=true&source_workflow=authgroups&startnode=%s&source_execution=%s", workflowExecution.Start, workflowExecution.ExecutionId)

	urlEncodedLabel := url.QueryEscape(authgroup.Label)

	queries := fmt.Sprintf("authgroups=true&authgroup=%s&source_workflow=%s&startnode=%s&source_execution=%s", urlEncodedLabel, workflowExecution.Workflow.Start, workflowExecution.Start, workflowExecution.ExecutionId)

	//if action.AuthenticationId == "authgroups" && !subExecutionsDone && workflowExecution.ExecutionSource != "authgroup" {
	//sourceWorkflow, sourceWorkflowOk := request.URL.Query()["source_workflow"]

	resultUrl += "?" + queries

	log.Printf("\n\n\n[DEBUG][%s] Running subflow execution for workflow %s (%s) with URL %s\n\n", workflowExecution.ExecutionId, workflowExecution.Workflow.Name, workflowExecution.Workflow.ID, resultUrl)

	preparedRuntime := ExecutionRequest{
		Priority:          10,
		ExecutionSource:   "authgroups",
		Start:             workflowExecution.Start,
		WorkflowId:        workflowExecution.Workflow.ID,
		Environments:      []string{parsedEnvironment},
		ExecutionArgument: workflowExecution.ExecutionArgument,

		Authgroup: authgroup.Label,
	}

	topClient := GetExternalClient(backendUrl)

	data, err := json.Marshal(preparedRuntime)
	if err != nil {
		log.Printf("[WARNING] Failed parent init marshal: %s", err)
		return err
	}

	req, err := http.NewRequest(
		"POST",
		resultUrl,
		bytes.NewBuffer([]byte(data)),
	)

	if len(apikey) == 0 {
		return errors.New("No API key found for subflow execution")
	}

	if strings.HasPrefix(apikey, "Bearer ") && len(apikey) > 7 {
		apikey = apikey[7:]
	}

	req.Header.Set("Org-Identifier", workflowExecution.ExecutionOrg)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apikey))
	req.Header.Set("appauth", parsedAuthIds)
	req.Header.Set("environment", parsedEnvironment)

	newresp, err := topClient.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed making authgroup subflow request (1): %s. Is URL valid: %s", err, resultUrl)
		return err
	}

	defer newresp.Body.Close()
	body, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading body response from authgroup exec: %s", err)
		return err
	}

	log.Printf("AUTHGROUP RUN BODY (%d): %s", newresp.StatusCode, string(body))

	if newresp.StatusCode != 200 {
		log.Printf("[ERROR] Bad statuscode running authgroup execution (2) with URL %s: %d, %s", resultUrl, newresp.StatusCode, string(body))
		return errors.New(fmt.Sprintf("Bad statuscode: %d", newresp.StatusCode))
	}

	return nil
}

func HealthCheckHandler(resp http.ResponseWriter, request *http.Request) {
	ret, err := project.Es.Info()
	if err != nil {
		log.Printf("[ERROR] Failed connecting to ES: %s", err)
		resp.WriteHeader(ret.StatusCode)
		resp.Write([]byte("Bad response from ES (1). Check logs for more details."))
		return
	}

	if ret.StatusCode >= 300 {
		resp.WriteHeader(ret.StatusCode)
		resp.Write([]byte(fmt.Sprintf("Bad response from ES - Status code %d", ret.StatusCode)))
		return
	}

	fmt.Fprint(resp, "OK")
}

// Extra validation sample to be used for workflow executions based on parent workflow instead of users' auth

// Check if the execution data has correct info in it! Happens based on subflows.
// 1. Parent workflow contains this workflow ID in the source trigger?
// 2. Parent workflow's owner is same org?
// 3. Parent execution auth is correct
func RunExecuteAccessValidation(request *http.Request, workflow *Workflow) (bool, string) {
	log.Printf("[DEBUG] Inside execute validation for workflow %s (%s)! Request method: %s", workflow.Name, workflow.ID, request.Method)

	//if request.Method == "POST" {
	ctx := GetContext(request)
	workflowExecution := &WorkflowExecution{}
	sourceExecution, sourceExecutionOk := request.URL.Query()["source_execution"]
	if !sourceExecutionOk {
		sourceExecution, sourceExecutionOk = request.URL.Query()["reference_execution"]
		if !sourceExecutionOk {
			log.Printf("[AUDIT] No source_execution or reference_execution in access validation")
			return false, ""
		}
	}

	if sourceExecutionOk && len(sourceExecution) > 0 {
		//log.Printf("[DEBUG] Got source exec %s", sourceExecution)
		newExec, err := GetWorkflowExecution(ctx, sourceExecution[0])
		if err != nil {
			//log.Printf("[INFO] Failed getting source_execution in test validation based on '%s'", sourceExecution[0])
			return false, ""
		} else {
			workflowExecution = newExec
		}
	}

	if workflowExecution.ExecutionId == "" {
		log.Printf("[WARNING] No execution ID found. Bad auth.")
		return false, ""
	}

	sourceAuth, sourceAuthOk := request.URL.Query()["source_auth"]
	if !sourceAuthOk {
		sourceAuth, sourceAuthOk = request.URL.Query()["authorization"]
		if !sourceAuthOk {
			log.Printf("[AUDIT] No source auth found. Bad auth.")
			return false, ""
		}
	}

	if sourceAuthOk {
		//log.Printf("[DEBUG] Got source auth %s", sourceAuth)
		// Must origin from a parent workflow")

		if sourceAuth[0] != workflowExecution.Authorization {
			log.Printf("[AUDIT] Bad authorization for workflowexecution defined.")
			return false, ""
		}

		// Check if workflow is in waiting stage
		// If it is, accept from this point already, as it's a user input action
		if workflowExecution.Status == "WAITING" {
			return true, ""
		}

	}

	// When reaching here, authentication is done, but not authorization.
	// Need to verify the workflow, and whether it SHOULD have access to execute it.
	sourceWorkflow, sourceWorkflowOk := request.URL.Query()["source_workflow"]
	if sourceWorkflowOk {
		//log.Printf("[DEBUG] Got source workflow %s", sourceWorkflow)
		_ = sourceWorkflow

		// Source workflow = parent
		// This workflow = child

		//if sourceWorkflow[0] != workflow.ID {
		//	log.Printf("[DEBUG] Bad workflow in execution.")
		//	return false, ""
		//}

	} else {
		if len(workflowExecution.Workflow.ID) > 0 {
			log.Printf("[AUDIT][%s] Got source workflow in subflow execution. Continuing.", workflowExecution.ExecutionId)
		} else {
			log.Printf("[AUDIT] Did NOT get source workflow in subflow execution. Failing out.")
			return false, ""
		}
	}

	//if workflow.OrgId != workflowExecution.Workflow.OrgId || workflow.ExecutingOrg.Id != workflowExecution.Workflow.ExecutingOrg.Id || workflow.OrgId == "" {
	if workflow.OrgId == "" || workflow.OrgId != workflowExecution.Workflow.OrgId {
		log.Printf("[ERROR][%s] Bad org ID in workflowexecution subflow run. Required: %s vs %s", workflowExecution.ExecutionId, workflow.OrgId, workflowExecution.Workflow.OrgId)
		return false, ""
	}

	// 1. Parent workflow contains this workflow ID in the source trigger?
	// 2. Parent workflow's owner is same org?
	// 3. Parent execution auth is correct

	sourceNode, sourceNodeOk := request.URL.Query()["source_node"]
	if !sourceNodeOk {
		// Use default startnode instead

		/*
			// This is finding the startnode of the parent workflow, not the actual startnode of the execution
			sourceNode = []string{workflowExecution.Workflow.Start}
			startFound := false
			for _, action := range workflowExecution.Workflow.Actions {
				if action.Id == workflowExecution.Workflow.Start {
					startFound = true
					break
				}
			}

			if !startFound {
		*/

		log.Printf("[AUDIT] Couldn't find source node that started the execution")
		return false, ""
	}

	// SHOULD be executed by a trigger in the parent.
	for _, trigger := range workflowExecution.Workflow.Triggers {
		if sourceNode[0] == trigger.ID {
			return true, workflowExecution.ExecutionOrg
		}
	}

	for _, action := range workflowExecution.Workflow.Actions {
		if sourceNode[0] == action.ID {
			return true, workflowExecution.ExecutionOrg
		}
	}
	//}

	log.Printf("[AUDIT] Bad auth for workflowexecution (bottom).")

	return false, ""
}

// Significantly slowed down everything. Just returning for now.
func findReferenceAppDocs(ctx context.Context, allApps []WorkflowApp) []WorkflowApp {
	newApps := []WorkflowApp{}

	// Skipping this for now as it makes things slow
	return allApps

	for _, app := range allApps {
		if len(app.ReferenceInfo.DocumentationUrl) > 0 && strings.HasPrefix(app.ReferenceInfo.DocumentationUrl, "https://raw.githubusercontent.com/Shuffle") && strings.Contains(app.ReferenceInfo.DocumentationUrl, ".md") {
			// Should find documentation from the github (only if github?) and add it to app.Documentation before caching
			//log.Printf("DOCS: %s", app.ReferenceInfo.DocumentationUrl)
			documentationData, err := DownloadFromUrl(ctx, app.ReferenceInfo.DocumentationUrl)
			if err != nil {
				log.Printf("[ERROR] Failed getting data: %s", err)
			} else {
				app.Documentation = string(documentationData)
			}
		}

		//if app.Documentation == "" && strings.ToLower(app.Name) == "discord" {
		if app.Documentation == "" {
			referenceUrl := ""

			if app.Generated {
				//log.Printf("[DEBUG] Should look in the OpenAPI folder")
				baseUrl := "https://raw.githubusercontent.com/Shuffle/openapi-apps/master/docs"

				newName := strings.ToLower(strings.Replace(strings.Replace(app.Name, " ", "_", -1), "-", "_", -1))
				referenceUrl = fmt.Sprintf("%s/%s.md", baseUrl, newName)
			} else {
				//log.Printf("[DEBUG] Should look in the Python-apps folder")
			}

			if len(referenceUrl) > 0 {
				//log.Printf("REF: %s", referenceUrl)

				documentationData, err := DownloadFromUrl(ctx, referenceUrl)
				if err != nil {
					log.Printf("[ERROR] Failed getting documentation data for app %s: %s", app.Name, err)
				} else {
					//log.Printf("[INFO] Added documentation from github for %s", app.Name)
					app.Documentation = string(documentationData)
				}
			}
		}

		newApps = append(newApps, app)
	}

	return newApps
}

func EchoOpenapiData(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just here to verify that the user is logged in
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[DEBUG] Api authentication failed in download Yaml echo: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to echo OpenAPI data: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Bodyreader err: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	newbody := string(body)
	newbody = strings.TrimSpace(newbody)
	if strings.HasPrefix(newbody, "\"") {
		newbody = newbody[1:len(newbody)]
	}

	if strings.HasSuffix(newbody, "\"") {
		newbody = newbody[0 : len(newbody)-1]
	}

	// Rewrite to download proper one from Github even without raw path
	if strings.Contains(newbody, "https://github.com/") {
		// https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml
		// https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/openapi/openapi.yaml
		// https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/openapi/openapi.yaml

		urlsplit := strings.Split(newbody, "/")
		if len(urlsplit) > 6 {
			log.Printf("[DEBUG] Rewriting github URL %s.", newbody)
			ghuser := urlsplit[3]
			repo := urlsplit[4]
			branch := urlsplit[6]
			path := strings.Join(urlsplit[7:len(urlsplit)], "/")
			newbody = fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", ghuser, repo, branch, path)
		}
	}

	log.Printf("[DEBUG] Downloading content from %s", newbody)

	req, err := http.NewRequest("GET", newbody, nil)
	if err != nil {
		log.Printf("[ERROR] Requestbuilder err: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed building request"}`))
		return
	}

	httpClient := &http.Client{}
	newresp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("[ERROR] Grabbing error: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed making remote request to get the data"}`)))
		return
	}

	defer newresp.Body.Close()
	urlbody, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		log.Printf("[ERROR] URLbody error: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Can't get data from selected uri"}`)))
		return
	}

	if newresp.StatusCode >= 400 {
		resp.WriteHeader(200)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, urlbody)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(urlbody)
}

func GetFrameworkConfiguration(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just here to verify that the user is logged in
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[DEBUG] Api authentication failed in get detection framework: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
		return
	}

	ctx := GetContext(request)
	org, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Error getting org: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	newjson, err := json.Marshal(org.SecurityFramework)
	if err != nil {
		log.Printf("[ERROR] Failed marshal in get security framework: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking framework. Contact us to get it fixed."}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func SetFrameworkConfiguration(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just here to verify that the user is logged in
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[DEBUG] Api authentication failed in set detection framework: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to set detection framework: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Error with body read: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	type parsedValue struct {
		Type        string `json:"type"`
		Name        string `json:"name"`
		ID          string `json:"id"`
		LargeImage  string `json:"large_image"`
		Description string `json:"description"`
	}

	var value parsedValue
	err = json.Unmarshal(body, &value)
	if err != nil {
		log.Printf("[WARNING] Error with unmarshal tmpBody in frameworkconfig: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := GetContext(request)
	org, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Error getting org in set framework: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	app := &WorkflowApp{
		Name:        "",
		Description: "",
		ID:          "",
		LargeImage:  "",
	}

	// System for replacing an app if it's not defined
	if value.ID != "remove" {
		app, err = GetApp(ctx, value.ID, user, false)
		if err != nil {

			if project.Environment == "cloud" {
				log.Printf("[ERROR] Error getting app '%s' in set framework: %s", value.ID, err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false}`))
				return
			} else {
				// Forwarded from Algolia in the frontend
				app.Name = value.Name
				app.ID = value.Name
				app.Description = value.Description
				app.LargeImage = value.LargeImage
			}
		}

		if project.Environment == "cloud" && !app.Sharing && app.Public {
			log.Printf("[WARNING] Error setting app %s for org %s as it's not public.", value.ID, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	// Trim and lower
	value.Type = strings.ToLower(strings.TrimSpace(value.Type))
	if value.Type == "email" || value.Type == "comms" {
		value.Type = "communication"
	}

	if value.Type == "eradication" {
		value.Type = "edr"
	}

	if value.Type == "edr & av" {
		value.Type = "edr"
	}

	appPriority := Priority{}
	prioIndex := -1
	for i, priority := range org.Priorities {
		if priority.Type == "apps" && strings.Contains(strings.ToLower(priority.Name), value.Type) && strings.Contains(priority.Name, "/8)") {
			appPriority = priority
			prioIndex = i
			break
		}
	}

	log.Printf("[INFO] Found app priority (%s) with name '%s'", value.Type, appPriority.Name)
	if prioIndex >= 0 && strings.Contains(strings.ToLower(appPriority.Name), value.Type) {
		if value.ID == "remove" {
			org.Priorities[prioIndex].Active = true
		} else {
			org.Priorities[prioIndex].Active = false
		}
	}

	// 1. Check if the app exists and the user has access to it. If public/sharing ->

	if value.Type == "siem" {
		org.SecurityFramework.SIEM.Name = app.Name
		org.SecurityFramework.SIEM.Description = app.Description
		org.SecurityFramework.SIEM.ID = app.ID
		org.SecurityFramework.SIEM.LargeImage = app.LargeImage
	} else if value.Type == "network" {
		org.SecurityFramework.Network.Name = app.Name
		org.SecurityFramework.Network.Description = app.Description
		org.SecurityFramework.Network.ID = app.ID
		org.SecurityFramework.Network.LargeImage = app.LargeImage
	} else if value.Type == "edr" {
		org.SecurityFramework.EDR.Name = app.Name
		org.SecurityFramework.EDR.Description = app.Description
		org.SecurityFramework.EDR.ID = app.ID
		org.SecurityFramework.EDR.LargeImage = app.LargeImage
	} else if value.Type == "cases" {
		org.SecurityFramework.Cases.Name = app.Name
		org.SecurityFramework.Cases.Description = app.Description
		org.SecurityFramework.Cases.ID = app.ID
		org.SecurityFramework.Cases.LargeImage = app.LargeImage
	} else if value.Type == "iam" {
		org.SecurityFramework.IAM.Name = app.Name
		org.SecurityFramework.IAM.Description = app.Description
		org.SecurityFramework.IAM.ID = app.ID
		org.SecurityFramework.IAM.LargeImage = app.LargeImage
	} else if value.Type == "assets" {
		org.SecurityFramework.Assets.Name = app.Name
		org.SecurityFramework.Assets.Description = app.Description
		org.SecurityFramework.Assets.ID = app.ID
		org.SecurityFramework.Assets.LargeImage = app.LargeImage
	} else if value.Type == "intel" {
		org.SecurityFramework.Intel.Name = app.Name
		org.SecurityFramework.Intel.Description = app.Description
		org.SecurityFramework.Intel.ID = app.ID
		org.SecurityFramework.Intel.LargeImage = app.LargeImage
	} else if value.Type == "communication" {
		org.SecurityFramework.Communication.Name = app.Name
		org.SecurityFramework.Communication.Description = app.Description
		org.SecurityFramework.Communication.ID = app.ID
		org.SecurityFramework.Communication.LargeImage = app.LargeImage
	} else {
		log.Printf("[WARNING] No handler for type %s in app framework during update of app %s", value.Type, app.Name)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Counting up for the getting started piece
	cnt := 0
	if len(org.SecurityFramework.SIEM.Name) > 0 {
		cnt += 1
	}

	if len(org.SecurityFramework.Intel.Name) > 0 {
		cnt += 1
	}

	if len(org.SecurityFramework.Communication.Name) > 0 {
		cnt += 1
	}

	if len(org.SecurityFramework.Assets.Name) > 0 {
		cnt += 1
	}

	if len(org.SecurityFramework.IAM.Name) > 0 {
		cnt += 1
	}

	if len(org.SecurityFramework.Cases.Name) > 0 {
		cnt += 1
	}

	if len(org.SecurityFramework.EDR.Name) > 0 {
		cnt += 1
	}

	if len(org.SecurityFramework.Network.Name) > 0 {
		cnt += 1
	}

	// Add app as active for org too
	if len(app.ID) > 0 && !ArrayContains(org.ActiveApps, app.ID) {
		org.ActiveApps = append(org.ActiveApps, app.ID)
	}

	for tutorialIndex, tutorial := range org.Tutorials {
		if tutorial.Name == "Find relevant apps" {
			org.Tutorials[tutorialIndex].Description = fmt.Sprintf("%d out of %d apps configured. Find more relevant apps in the search bar.", cnt, 8)

			if cnt > 0 {
				org.Tutorials[tutorialIndex].Done = true
			}
		}
	}

	// Reset priorities as framework has changed
	newPrios := []Priority{}
	for _, priority := range org.Priorities {
		if priority.Type == "usecase" {
			continue
		}

		newPrios = append(newPrios, priority)
	}

	org.Priorities = newPrios
	foundPrios, err := GetPriorities(ctx, user, org)
	if err != nil {
		log.Printf("[WARNING] Failed getting priorities for org %s: %s", org.Name, err)
	} else {
		org.Priorities = foundPrios
	}

	err = SetOrg(ctx, *org, org.Id)
	if err != nil {
		log.Printf("[WARNING] Failed setting app framework for org %s: %s", org.Name, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed updating organization info. Please contact us if this persists."}`))
		return
	} else {
		DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
		DeleteCache(ctx, fmt.Sprintf("apps_%s", user.ActiveOrg.Id))
		DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-100"))
		DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-500"))
		DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-1000"))
		DeleteCache(ctx, "all_apps")
		DeleteCache(ctx, fmt.Sprintf("user_%s", user.Username))
		DeleteCache(ctx, fmt.Sprintf("user_%s", user.Id))
	}

	if value.ID != "remove" {
		log.Printf("[DEBUG] Successfully updated app framework type %s to app %s (%s) for org %s (%s)!", value.Type, app.Name, app.ID, org.Name, org.Id)
	} else {
		log.Printf("[DEBUG] Successfully REMOVED app framework type %s for org %s (%s)!", value.Type, org.Name, org.Id)
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

type flushWriter struct {
	f http.Flusher
	w io.Writer
}

func (fw *flushWriter) Write(p []byte) (n int, err error) {
	n, err = fw.w.Write(p)
	if fw.f != nil {
		fw.f.Flush()
	}
	return
}

func UpdateUsecases(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get usecases. Continuing anyway: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Needs to be an active shuffler.io account to update
	if project.Environment == "cloud" && !strings.HasSuffix(user.Username, "@shuffler.io") {
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Can't change framework info"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Error with body read for usecase update: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	var usecase Usecase
	err = json.Unmarshal(body, &usecase)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling usecase: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	usecase.Success = true
	usecase.Name = strings.Replace(usecase.Name, " ", "_", -1)
	usecase.Name = url.QueryEscape(usecase.Name)
	log.Printf("[DEBUG] Updated usecase %s as user %s (%s)", usecase.Name, user.Username, user.Id)
	usecase.EditedBy = user.Id
	ctx := GetContext(request)
	err = SetUsecase(ctx, usecase)
	if err != nil {
		log.Printf("[ERROR] Failed updating usecase: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleGetUsecase(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	_, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get usecase (1). Continuing anyway: %s", err)
		//resp.WriteHeader(401)
		//resp.Write([]byte(`{"success": false}`))
		//return
	}

	var name string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 5 {
			log.Printf("[ERROR] Path too short: %d", len(location))
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		name = location[5]
	}

	ctx := GetContext(request)
	usecase, err := GetUsecase(ctx, name)
	if err != nil {
		log.Printf("[ERROR] Failed getting usecase %s: %s", name, err)

		usecase.Success = false
		usecase.Name = name
		//resp.WriteHeader(400)
		//resp.Write([]byte(`{"success": false}`))
		//return
	} else {
		usecase.Success = true
	}

	// Hardcoding until we have something good for open source + cloud
	replacedName := strings.Replace(strings.ToLower(usecase.Name), " ", "_", -1)
	if replacedName == "email_management" {
		usecase.ExtraButtons = []ExtraButton{
			ExtraButton{
				Name:  "IMAP",
				App:   "Email",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/email_ec25da1fdbf18934ca468788b73bec32.png",
				Link:  "https://shuffler.io/workflows/b65d180c-4d27-4cb6-8128-3687a08aadb3",
				Type:  "communication",
			},
			ExtraButton{
				Name:  "Gmail",
				App:   "Gmail",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Gmail_794e51c3c1a8b24b89ccc573a3defc47.png",
				Link:  "https://shuffler.io/workflows/e506060f-0c58-4f95-a0b8-f671103d78e5",
				Type:  "communication",
			},
			ExtraButton{
				Name:  "Outlook",
				App:   "Outlook Graph",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Outlook_graph_d71641a57deeee8149df99080adebeb7.png",
				Link:  "https://shuffler.io/workflows/3862ed8f-7801-4393-8524-05de8f8a401d",
				Type:  "communication",
			},
		}
	} else if replacedName == "edr_to_ticket" {
		usecase.ExtraButtons = []ExtraButton{
			ExtraButton{
				Name:  "Velociraptor",
				App:   "Velociraptor",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/velociraptor_63de9fc91bcb4813d9c58cc6efd49b33.png",
				Link:  "https://shuffler.io/apps/63de9fc91bcb4813d9c58cc6efd49b33",
				Type:  "edr",
			},
			ExtraButton{
				Name:  "Carbon Black",
				App:   "Carbon Black",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Carbon_Black_Response_e9fa2602ea6baafffa4b5eec722095d3.png",
				Link:  "https://shuffler.io/apps/e9fa2602ea6baafffa4b5eec722095d3",
				Type:  "edr",
			},
			ExtraButton{
				Name:  "Crowdstrike",
				App:   "Crowdstrike",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Crowdstrike_Falcon_7a66ce3c26e0d724f31f1ebc9a7a41b4.png",
				Link:  "https://shuffler.io/apps/7a66ce3c26e0d724f31f1ebc9a7a41b4",
				Type:  "edr",
			},
		}
	} else if replacedName == "siem_to_ticket" {
		usecase.ExtraButtons = []ExtraButton{
			ExtraButton{
				Name:  "Wazuh",
				App:   "Wazuh",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Wazuh_fb715a176a192687e95e9d162186c97f.png",
				Link:  "https://shuffler.io/workflows/bb45124c-d39e-4acc-a5d9-f8aa526042b5",
				Type:  "siem",
			},
			ExtraButton{
				Name:  "Splunk",
				App:   "Splunk",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Splunk_Splunk_e352462c6d2f0a692281600d96002a45.png",
				Link:  "https://shuffler.io/apps/441a2d85f6c1e8408dd1ee1e804cd241",
				Type:  "siem",
			},
			ExtraButton{
				Name:  "QRadar",
				App:   "QRadar",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/QRadar_4fe358bd204f672d37c55b4f1d48ccdb.png",
				Link:  "https://shuffler.io/apps/96a3d95a2a73cfdb51ea4a394287ed33",
				Type:  "siem",
			},
		}
	} else if replacedName == "chatops" {
		usecase.ExtraButtons = []ExtraButton{
			ExtraButton{
				Name:  "Webex",
				App:   "Webex",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Webex_1f6f2fc4fd399597e98ff34f78f56c45.png",
				Link:  "https://shuffler.io/workflows/88e16093-37b7-41cf-b02b-d1ca0e737993",
				Type:  "communication",
			},
			ExtraButton{
				Name:  "Teams",
				App:   "Microsoft Teams",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Microsoft_Teams_User_Access_4826c529f8082205a4b926ac9f1dfcfb.png",
				Link:  "https://shuffler.io/apps/4826c529f8082205a4b926ac9f1dfcfb",
				Type:  "communication",
			},
			ExtraButton{
				Name:  "Slack",
				App:   "Slack",
				Image: "https://storage.googleapis.com/shuffle_public/app_images/Slack_Web_API_f63a65ddf0ee369845b6918575d47fc1.png",
				Link:  "https://shuffler.io/workflows/0a7eeca9-e056-40e5-9a70-f078937c6055",
				Type:  "communication",
			},
		}
	}

	newjson, err := json.Marshal(usecase)
	if err != nil {
		log.Printf("[ERROR] Failed marshal in get usecase: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking data"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func GetBackendexecution(ctx context.Context, executionId, authorization string) (WorkflowExecution, error) {
	exec := WorkflowExecution{}

	// Is polling the backend actually correct?
	// Or should worker/backend talk to itself?
	backendUrl := os.Getenv("BASE_URL")
	if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
		backendUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
	}

	if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
		backendUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
	}

	// Should this be without worker? :thinking:
	resultUrl := fmt.Sprintf("%s/api/v1/streams/results", backendUrl)

	topClient := GetExternalClient(backendUrl)
	requestData := ActionResult{
		ExecutionId:   executionId,
		Authorization: authorization,
	}

	data, err := json.Marshal(requestData)
	if err != nil {
		log.Printf("[WARNING] Failed parent init marshal: %s", err)
		return exec, err
	}

	req, err := http.NewRequest(
		"POST",
		resultUrl,
		bytes.NewBuffer([]byte(data)),
	)

	newresp, err := topClient.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed making subflow request (1): %s. Is URL valid: %s", err, resultUrl)
		return exec, err
	}

	defer newresp.Body.Close()
	body, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading parent body: %s", err)
		return exec, err
	}
	//log.Printf("BODY (%d): %s", newresp.StatusCode, string(body))

	if newresp.StatusCode != 200 {
		log.Printf("[ERROR] Bad statuscode getting execution (2) with URL %s: %d, %s", resultUrl, newresp.StatusCode, string(body))
		return exec, errors.New(fmt.Sprintf("Bad statuscode: %d", newresp.StatusCode))
	}

	err = json.Unmarshal(body, &exec)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshalling execution: %s", err)
		return exec, err
	}

	if exec.Status == "FINISHED" || exec.Status == "FAILURE" {
		cacheKey := fmt.Sprintf("workflowexecution_%s", executionId)
		err = SetCache(ctx, cacheKey, body, 31)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for workflowexec key %s: %s", cacheKey, err)
		}
	}

	return exec, nil
}

func AddPriority(org Org, priority Priority, updated bool) (*Org, bool) {
	found := false

	usecasesFound := 0
	for _, p := range org.Priorities {
		if p.Type == "usecase" && p.Active {
			usecasesFound += 1
		}
	}

	for _, p := range org.Priorities {
		if p.Name == priority.Name || (p.Type == priority.Type && p.Active) && p.Type != "usecase" {
			found = true
			break
		}

		if p.Type == priority.Type && p.Type == "usecase" && p.Active && usecasesFound >= 3 {
			found = true
			break
		}
	}

	if !found {
		priority.Active = true
		org.Priorities = append(org.Priorities, priority)
		updated = true
	}

	return &org, updated
}

// Watch academy - Shuffle 101 if you're new
// Check notifications
// Check if all apps have been discovered
// Check if notification workflow is made
// Check workflows vs usecases
// Check based on org configuration (name, environments, apps...)
// Workflows not finished / without a parent workflow/trigger
// Workflows not in production

// Should just be based on cache, not queries - keep it fast!
func GetPriorities(ctx context.Context, user User, org *Org) ([]Priority, error) {
	// Get usecases -> Check which aren't done based on priorities
	// 1. Check what apps are selected. Are email, edr and siem in there?
	// If not - autocorrect based on workflows' apps?
	//log.Printf("[DEBUG] SecurityFramework: %s", org.SecurityFramework)

	// First prio: Find these & attach usecases?
	// Only set these if cache is set for the user
	orgUpdated := false
	updated := false
	if project.CacheDb == false {
		// Not checking as cache is used for all checks
		return org.Priorities, nil
	}

	if len(org.Defaults.NotificationWorkflow) == 0 {
		org, updated = AddPriority(*org, Priority{
			Name:        fmt.Sprintf("You haven't defined a notification workflow yet."),
			Description: "Notification workflows are used to automate your notification handling. These can be used to alert yourself in other systems when issues are found in your current- or sub-organizations",
			Type:        "notifications",
			Active:      true,
			URL:         fmt.Sprintf("/admin?admin_tab=organization"),
			Severity:    2,
		}, updated)

		if updated {
			orgUpdated = true
		}
	}

	// Notify about hybrid
	if project.Environment == "cloud" {
		org, updated = AddPriority(*org, Priority{
			Name:        fmt.Sprintf("Try Hybrid Shuffle by connecting environments"),
			Description: "Hybrid Shuffle allows you to connect Shuffle to your local datacenter(s) internal resources, and get the results in the cloud.",
			Type:        "hybrid",
			Active:      true,
			URL:         fmt.Sprintf("/admin?tab=environments"),
			Severity:    3,
		}, updated)
	} else {
		org, updated = AddPriority(*org, Priority{
			Name:        fmt.Sprintf("Get more functionality by connecting to the cloud"),
			Description: "Get access to webhooks, schedules and other functions by connecting to the cloud. Try it out for free, or contact our team if you want to learn more!",
			Type:        "hybrid",
			Active:      true,
			URL:         fmt.Sprintf("/admin?admin_tab=cloud_sync"),
			Severity:    2,
		}, updated)
	}

	var notifications []Notification
	cache, err := GetCache(ctx, fmt.Sprintf("notifications_%s", org.Id))
	if err == nil {
		cacheData := []byte(cache.([]uint8))
		err = json.Unmarshal(cacheData, &notifications)
		if err == nil && len(notifications) > 0 {
			org, updated = AddPriority(*org, Priority{
				Name:        fmt.Sprintf("You have %d unhandled notifications.", len(notifications)),
				Description: "Notifications help make your workflow infrastructure stable. Click the notification icon in the top right to see all open ones.",
				Type:        "notifications",
				Active:      true,
				URL:         fmt.Sprintf("/admin?tab=priorities"),
				Severity:    1,
			}, updated)

			if updated {
				orgUpdated = true
			}
		}
	} else {
	}

	if len(org.MainPriority) == 0 {
		// Just choosing something for them, e.g. basic usecase building

		org.MainPriority = "1. Collect"
		orgUpdated = true
	}

	org, orgUpdated = GetWorkflowSuggestions(ctx, user, org, orgUpdated, 1)
	if orgUpdated {
		log.Printf("[DEBUG] Should update org with %d priorities", len(org.Priorities))
		SetOrg(ctx, *org, org.Id)
	}

	return org.Priorities, nil
}

// Sorts an org list in order to make ChildOrgs appear under their parent org
func SortOrgList(orgs []OrgMini) []OrgMini {
	// Sort based on the name of the org first
	sort.Slice(orgs, func(i, j int) bool {
		return strings.ToLower(orgs[i].Name) < strings.ToLower(orgs[j].Name)
	})

	// Creates parentorg map
	parentOrgs := map[string][]OrgMini{}
	for _, org := range orgs {
		if len(org.CreatorOrg) == 0 && len(org.ChildOrgs) > 0 {
			parentOrgs[org.Id] = []OrgMini{}
		} else if len(org.CreatorOrg) == 0 {
			// No childorgs, but isn't a parentorg either
			parentOrgs[org.Id] = []OrgMini{}
		} else {
			// Child orgs go here
		}
	}

	noParentOrg := []OrgMini{}
	for _, org := range orgs {
		// Check if parent in parentOrgs map
		if len(org.CreatorOrg) == 0 {
			continue
		}

		if val, ok := parentOrgs[org.CreatorOrg]; ok {
			parentOrgs[org.CreatorOrg] = append(val, org)
		} else {
			noParentOrg = append(noParentOrg, org)
		}
	}

	newOrgs := []OrgMini{}
	for key, value := range parentOrgs {
		// Find key in orgs
		found := false
		for _, org := range orgs {
			if org.Id == key {
				found = true
				newOrgs = append(newOrgs, org)
				break
			}
		}

		if found {
			for _, childorg := range value {
				newOrgs = append(newOrgs, childorg)
			}
		}
	}

	// Adding orgs where parentorg is unavailable
	// They should probably be under some "inactive" parentorg..
	newOrgs = append(newOrgs, noParentOrg...)

	return newOrgs
}

func findMissingChildren(ctx context.Context, workflowExecution *WorkflowExecution, children map[string][]string, inputNode string, checkedNodes []string) []string {
	nextActions := []string{}

	if ArrayContains(checkedNodes, inputNode) {
		return nextActions
	}

	checkedNodes = append(checkedNodes, inputNode)
	parentRan := false
	for _, result := range workflowExecution.Results {
		if result.Action.ID == inputNode && result.Status != "WAITING" {
			parentRan = true
		}
	}

	if !parentRan {
		//log.Printf("Should run parent first.")
		return []string{inputNode}
	} else {
		// Starting from the startnode, go through the workflow one level at a time
		foundCnt := 0
		for _, child := range children[inputNode] {
			// Check if the parent and its childs have a result
			found := false
			for _, result := range workflowExecution.Results {
				if result.Action.ID == child {
					foundCnt += 1
					found = true
					break
				}
			}

			if !found {
				// Due to being too fast cleared
				//cacheId := fmt.Sprintf("%s_%s", workflowExecution.ExecutionId, child)
				//_, err := GetCache(ctx, cacheId)
				//if err != nil {
				//	//log.Printf("[INFO] Missing execution (2): %s", child)
				//	nextActions = append(nextActions, child)
				//	continue
				//}

				cacheId := fmt.Sprintf("%s_%s_result", workflowExecution.ExecutionId, child)
				_, err := GetCache(ctx, cacheId)
				if err != nil {
					//log.Printf("[INFO] Missing execution (2): %s", child)
					nextActions = append(nextActions, child)
				}
			}
		}

		if foundCnt == len(children[inputNode]) {
			//log.Printf("All nodes done. Check their child results. Child nodes: %d, found: %d", len(children[inputNode]), foundCnt)
			// Run child nodes of this!
			nextActions = []string{}

			// Randomize order as to keep digging
			//for _, child := range rand.Perm(children[inputNode]) {
			for _, child := range children[inputNode] {
				next := findMissingChildren(ctx, workflowExecution, children, child, checkedNodes)

				// Only doing one are at a time as to SLOWLY dig down into it
				if len(next) > 0 {
					nextActions = append(nextActions, next...)
					break
				}
			}

			return nextActions
		} else {
			//log.Printf("Missing nodes. Found: %d, Expected: %d", foundCnt, len(children[inputNode]))
		}
	}

	return nextActions
}

// Finds next actions that aren't already executed and don't have results
func CheckNextActions(ctx context.Context, workflowExecution *WorkflowExecution) []string {
	extra := 0
	parents := map[string][]string{}
	children := map[string][]string{}
	nextActions := []string{}

	inputNode := workflowExecution.Start
	if len(workflowExecution.Results) == 0 {
		return []string{inputNode}
	}

	if ValidateFinished(ctx, extra, *workflowExecution) {
		return []string{}
	}

	for _, trigger := range workflowExecution.Workflow.Triggers {
		if trigger.TriggerType != "SUBFLOW" && trigger.TriggerType != "USERINPUT" {
			continue
		}

		extra += 1
	}

	for _, branch := range workflowExecution.Workflow.Branches {
		// Check what the parent is first. If it's trigger - skip
		sourceFound := false
		destinationFound := false
		for _, action := range workflowExecution.Workflow.Actions {
			if action.ID == branch.SourceID {
				sourceFound = true
			}

			if action.ID == branch.DestinationID {
				destinationFound = true
			}
		}

		if !sourceFound || !destinationFound {
			for _, trigger := range workflowExecution.Workflow.Triggers {
				if trigger.ID == branch.SourceID {
					sourceFound = true
				}

				if trigger.ID == branch.DestinationID {
					destinationFound = true
				}
			}
		}

		foundCnt := 0
		if sourceFound {
			parents[branch.DestinationID] = append(parents[branch.DestinationID], branch.SourceID)
			foundCnt += 1
		}

		if destinationFound {
			children[branch.SourceID] = append(children[branch.SourceID], branch.DestinationID)
			foundCnt += 1
		}

		if foundCnt != 2 {
			//log.Printf("[INFO] Missing branch fullfillment for src + dst!")
		}
	}

	nextActions = findMissingChildren(ctx, workflowExecution, children, inputNode, []string{})

	//log.Printf("[DEBUG][%s] Checking what are next actions in workflow %s. Results: %d/%d. NextActions: %s", workflowExecution.ExecutionId, workflowExecution.ExecutionId, len(workflowExecution.Results), len(workflowExecution.Workflow.Actions)+extra, nextActions)

	return nextActions
}

// Decideds what should happen next. Used both for cloud & onprem environments
// Added early 2023 as yet another way to standardize decisionmaking of app executions
func DecideExecution(ctx context.Context, workflowExecution WorkflowExecution, environment string) (WorkflowExecution, []Action) {
	// ensuring always latest
	newexec, err := GetWorkflowExecution(ctx, workflowExecution.ExecutionId)
	if err != nil {
		log.Printf("[ERROR] Failed to get workflow execution in Decide: %s", err)
	} else {
		workflowExecution = *newexec
	}

	startAction, extra, children, parents, visited, executed, nextActions, environments := GetExecutionVariables(ctx, workflowExecution.ExecutionId)
	if len(startAction) == 0 {
		startAction = workflowExecution.Start
		if len(startAction) == 0 {
			log.Printf("[WARNING] Didn't find execution start action. Setting it to workflow start action.")
			startAction = workflowExecution.Workflow.Start
		}
	}

	// Dedup results just in case
	newResults := []ActionResult{}
	handled := []string{}
	for _, result := range workflowExecution.Results {
		if ArrayContains(handled, result.Action.ID) {
			continue
		}

		handled = append(handled, result.Action.ID)
		newResults = append(newResults, result)
	}

	workflowExecution.Results = newResults
	relevantActions := []Action{}

	log.Printf("[INFO][%s] Inside Decide execution with %d / %d results (extra: %d). Status: %s", workflowExecution.ExecutionId, len(workflowExecution.Results), len(workflowExecution.Workflow.Actions)+extra, extra, workflowExecution.Status)

	if len(startAction) == 0 {
		startAction = workflowExecution.Start

		if len(startAction) == 0 {
			log.Printf("[WARNING] Didn't find execution start action. Setting it to workflow start action (%s)", workflowExecution.Workflow.Start)
			startAction = workflowExecution.Workflow.Start
			workflowExecution.Start = workflowExecution.Workflow.Start
		}
	}

	queueNodes := []string{}
	if len(workflowExecution.Results) == 0 {
		nextActions = []string{startAction}
	} else {
		// This is to re-check the nodes that exist and whether they should continue
		appendActions := []string{}
		for _, item := range workflowExecution.Results {

			// FIXME: Check whether the item should be visited or not
			// Do the same check as in walkoff.go - are the parents done?
			// If skipped and both parents are skipped: keep as skipped, otherwise queue
			if item.Status == "SKIPPED" {
				isSkipped := true

				for _, branch := range workflowExecution.Workflow.Branches {
					// 1. Finds branches where the destination is our node
					// 2. Finds results of those branches, and sees the status
					// 3. If the status isn't skipped or failure, then it will still run this node
					if branch.DestinationID == item.Action.ID {
						for _, subresult := range workflowExecution.Results {
							if subresult.Action.ID == branch.SourceID {
								if subresult.Status != "SKIPPED" && subresult.Status != "FAILURE" {
									isSkipped = false

									break
								}
							}
						}
					}
				}

				if isSkipped {
					//log.Printf("Skipping %s as all parents are done", item.Action.Label)
					if !ArrayContains(visited, item.Action.ID) {
						//log.Printf("[INFO] Adding visited (1): %s", item.Action.Label)
						visited = append(visited, item.Action.ID)
					}
				} else {
					//log.Printf("[INFO] Continuing %s as all parents are NOT done", item.Action.Label)
					// FIXME: Remove this  visited?
					//visited = append(visited, item.Action.ID)

					appendActions = append(appendActions, item.Action.ID)
				}
			} else {
				if item.Status == "FINISHED" {
					//log.Printf("[INFO] Adding visited (2): %s", item.Action.Label)
					visited = append(visited, item.Action.ID)
				}
			}

			//if len(nextActions) == 0 {
			//nextActions = append(nextActions, children[item.Action.ID]...)
			for _, child := range children[item.Action.ID] {
				if !ArrayContains(nextActions, child) && !ArrayContains(visited, child) && !ArrayContains(visited, child) {
					nextActions = append(nextActions, child)
				}
			}

			if len(appendActions) > 0 {
				//log.Printf("APPENDED NODES: %s", appendActions)
				nextActions = append(nextActions, appendActions...)
			}
		}
	}

	//log.Printf("Nextactions: %s", nextActions)
	// This is a backup in case something goes wrong in this complex hellhole.
	// Max default execution time is 5 minutes for now anyway, which should take
	// care if it gets stuck in a loop.
	// FIXME: Force killing a worker should result in a notification somewhere
	if len(nextActions) == 0 {
		log.Printf("[DEBUG] No next action. Finished? Result vs Actions: %d - %d", len(workflowExecution.Results), len(workflowExecution.Workflow.Actions))
		extra = 0

		for _, trigger := range workflowExecution.Workflow.Triggers {
			if (trigger.Name == "User Input" && trigger.AppName == "User Input") || (trigger.Name == "Shuffle Workflow" && trigger.AppName == "Shuffle Workflow") {
				extra += 1
			}
		}

		exit := true
		for _, item := range workflowExecution.Results {
			if item.Status == "EXECUTING" {
				exit = false
				break
			}
		}

		if len(environments) == 1 {
			log.Printf("[INFO] Should send results to the backend because environments are %s", environments)
			ValidateFinished(ctx, extra, workflowExecution)
		}

		if exit && len(workflowExecution.Results) == len(workflowExecution.Workflow.Actions) {
			ValidateFinished(ctx, extra, workflowExecution)
			//handleAbortExecution(ctx, workflowExecution)
			return workflowExecution, relevantActions
		}

		// Look for the NEXT missing action
		notFound := []string{}
		for _, action := range workflowExecution.Workflow.Actions {
			found := false
			for _, result := range workflowExecution.Results {
				if action.ID == result.Action.ID {
					found = true
					break
				}
			}

			if !found {
				notFound = append(notFound, action.ID)
			}
		}

		//log.Printf("SOMETHING IS MISSING!: %s", notFound)
		for _, item := range notFound {
			if ArrayContains(executed, item) {
				log.Printf("%s has already executed but no result!", item)
			}

			// Visited means it's been touched in any way.
			outerIndex := -1
			for index, visit := range visited {
				if visit == item {
					outerIndex = index
					break
				}
			}

			if outerIndex >= 0 {
				log.Printf("Removing index %s from visited", item)
				visited = append(visited[:outerIndex], visited[outerIndex+1:]...)
			}

			fixed := 0
			for _, parent := range parents[item] {
				parentResult := ActionResult{}
				workflowExecution, parentResult = GetActionResult(ctx, workflowExecution, parent)
				if parentResult.Status == "FINISHED" || parentResult.Status == "SUCCESS" || parentResult.Status == "SKIPPED" || parentResult.Status == "FAILURE" {
					fixed += 1
				}
			}

			if fixed == len(parents[item]) {
				nextActions = append(nextActions, item)
			}

			// If it's not executed and not in nextActions
		}
	}

	//log.Printf("Checking nextactions: %s", nextActions)
	for _, node := range nextActions {
		nodeChildren := children[node]
		for _, child := range nodeChildren {
			if !ArrayContains(queueNodes, child) {
				queueNodes = append(queueNodes, child)
			}
		}
	}

	// IF NOT VISITED && IN toExecuteOnPrem
	// SKIP if it's not onprem
	for _, nextAction := range nextActions {
		//log.Printf("[DEBUG] Handling nextAction %s", nextAction)
		action := GetAction(workflowExecution, nextAction, environment)

		// Using cache to ensure the same app isn't ran twice
		// May arise due to one app being nanoseconds before another

		// Not really sure how this edgecase happens.

		// FIXME
		// Execute, as we don't really care if env is not set? IDK
		if action.Environment != environment { //&& action.Environment != "" {
			if strings.ToLower(action.Environment) == strings.ToLower(environment) {
				// Fixing names
				action.Environment = environment
			} else {
				//log.Printf("envs: %s", environments)
				//log.Printf("[WARNING] Bad environment for node: %s. Want %s", action.Environment, environment)
				action.Environment = "cloud"
				//DeleteCache(ctx, newExecId)
				//continue
			}
		}

		// check whether the parent is finished executing

		fixed := 0
		fixedNames := []string{}
		continueOuter := true
		if action.IsStartNode {
			continueOuter = false
		} else if len(parents[nextAction]) > 0 {
			// Wait for parents to finish executing
			skippedCnt := 0
			childNodes := FindChildNodes(workflowExecution, nextAction, []string{}, []string{})
			for _, parent := range parents[nextAction] {
				// Check if the parent is also a child. This can ensure continueation no matter what
				if ArrayContains(childNodes, parent) {
					log.Printf("[ERROR][%s] Parent %s is also a child of %s. Skipping parent check", workflowExecution.ExecutionId, parent, nextAction)
					fixed += 1
					continue
				}

				// Not including ABORTED/FAILURE
				_, parentResult := GetActionResult(ctx, workflowExecution, parent)
				if parentResult.Status == "FINISHED" || parentResult.Status == "SUCCESS" || parentResult.Status == "SKIPPED" {
					if parentResult.Status == "SKIPPED" {
						skippedCnt += 1
					}
					fixed += 1

					// Debug names
					fixedNames = append(fixedNames, fmt.Sprintf("%s:%s", parent, parentResult.Status))
				} else {
					// Should check if it's actually RAN at all?
					// This is not necessary anymore as the cache is used previously, and this won't be any different

					//Look for ABORT/FAILURE?
					//parentId := fmt.Sprintf("%s_%s", workflowExecution.ExecutionId, parent)
					//_, err := GetCache(ctx, parentId)
					//if err != nil {
					//	//log.Printf("[INFO] No cache for parent ID %#v", parentId)
					//} else {
					//	//log.Printf("Parent ID already ran. How long ago?")
					//}
				}
			}

			// Check if there are as many successful results as there are parents
			// Else, continueOuter = true by default, and it will be skipped
			if fixed == len(parents[nextAction]) {
				continueOuter = false

				if fixed > 0 && skippedCnt == len(parents[nextAction]) {
					//log.Printf("[WARNING][%s] All parents of %s (%s) are skipped. (%d/%d): %s. Should set to skipped.", workflowExecution.ExecutionId, action.Label, nextAction, fixed, len(parents[nextAction]), strings.Join(parents[nextAction], ", "))
					continueOuter = true
				}
			}
		} else {
			//log.Printf("[INFO] No parents for %s", action.Label)
			continueOuter = false
		}

		if continueOuter {
			//log.Printf("[DEBUG][%s] Parents of %s (%s) aren't finished yet (%d/%d). Parents: %s", workflowExecution.ExecutionId, action.Label, nextAction, fixed, len(parents[nextAction]), strings.Join(parents[nextAction], ", "))

			continue
		} else {
			// Was a bug related to bad parent
			if len(parents[nextAction]) > 0 {
				//log.Printf("[DEBUG][%s] ALL Parents of %s (%s) are finished. (%d/%d): %s. But are they succeeded?", workflowExecution.ExecutionId, action.Label, nextAction, fixed, len(parents[nextAction]), strings.Join(parents[nextAction], ", "))
			}

		}

		// get action status
		workflowExecution, actionResult := GetActionResult(ctx, workflowExecution, nextAction)
		if actionResult.Action.ID == action.ID {
			//log.Printf("\n\n[INFO] %s (%s) already has status %s\n\n", action.Label, action.ID, actionResult.Status)
			//DeleteCache(ctx, newExecId)
			continue
		} else {
			//log.Printf("[INFO] %s:%s has no status result yet. Should execute.", action.Name, action.ID)
		}

		// Checked multiple times due to the cache
		newExecId := fmt.Sprintf("%s_%s", workflowExecution.ExecutionId, nextAction)
		_, err := GetCache(ctx, newExecId)
		if err == nil {
			//log.Printf("\n\n[DEBUG] Already found %s - returning\n\n", newExecId)
			continue
		}

		parentlen := 0
		// Check if nextAction in parents map, not len of it
		if _, ok := parents[nextAction]; ok {
			parentlen = len(parents[nextAction])
		}

		//log.Printf("[DEBUG][%s] Running %s (%s) with %d parent(s). Names: %#v", workflowExecution.ExecutionId, action.Label, nextAction, parentlen, fixedNames)

		if project.Environment != "cloud" {
			branchesFound := 0
			parentFinished := 0

			for _, item := range workflowExecution.Workflow.Branches {
				if item.DestinationID != action.ID {
					continue
				}

				branchesFound += 1

				found := false
				for _, result := range workflowExecution.Results {
					if result.Action.ID != item.SourceID {
						continue
					}

					found = true

					// Check for fails etc
					if result.Status == "SUCCESS" || result.Status == "SKIPPED" {
						parentFinished += 1
					} else {
						log.Printf("[WARNING] Parent %s has status %s", result.Action.Label, result.Status)
					}

					break
				}

				if !found {
					// Ensuring triggers are handled as they should
					for _, trigger := range workflowExecution.Workflow.Triggers {
						if trigger.AppName == "Shuffle Workflow" || trigger.AppName == "User Input" || trigger.AppName == "shuffle-subworkflow" {
							continue
						}

						if trigger.ID == item.SourceID {
							found = true
							parentFinished += 1
						}
					}
				}
			}

			if branchesFound != parentFinished {
				log.Printf("[WARNING][%s] Skipping execution of %s (%s) due to unfinished parents (%d/%d). Orig parentlen: %d", workflowExecution.ExecutionId, action.Label, nextAction, parentFinished, branchesFound, parentlen)
				continue
			}
		}

		if action.AppName == "Shuffle Workflow" {
			branchesFound := 0
			parentFinished := 0

			for _, item := range workflowExecution.Workflow.Branches {
				if item.DestinationID == action.ID {
					branchesFound += 1

					for _, result := range workflowExecution.Results {
						if result.Action.ID == item.SourceID {
							// Check for fails etc
							if result.Status == "SUCCESS" || result.Status == "SKIPPED" {
								parentFinished += 1
							} else {
								log.Printf("Parent %s has status %s", result.Action.Label, result.Status)
							}

							break
						}
					}
				}
			}

			if branchesFound == parentFinished {
				action.Environment = environment
				action.AppName = "shuffle-subflow"
				action.Name = "run_subflow"
				action.AppVersion = "1.1.0"

				//appname := action.AppName
				//appversion := action.AppVersion
				//appname = strings.Replace(appname, ".", "-", -1)
				//appversion = strings.Replace(appversion, ".", "-", -1)

				//visited = append(visited, action.ID)
				//executed = append(executed, action.ID)

				trigger := Trigger{}
				for _, innertrigger := range workflowExecution.Workflow.Triggers {
					if innertrigger.ID == action.ID {
						trigger = innertrigger
						break
					}
				}

				// FIXME: Add startnode from frontend
				action.ExecutionDelay = trigger.ExecutionDelay
				action.Parameters = []WorkflowAppActionParameter{}
				for _, parameter := range trigger.Parameters {
					parameter.Variant = "STATIC_VALUE"
					action.Parameters = append(action.Parameters, parameter)
				}

				action.Parameters = append(action.Parameters, WorkflowAppActionParameter{
					Name:  "source_workflow",
					Value: workflowExecution.Workflow.ID,
				})

				action.Parameters = append(action.Parameters, WorkflowAppActionParameter{
					Name:  "source_execution",
					Value: workflowExecution.ExecutionId,
				})

				action.Parameters = append(action.Parameters, WorkflowAppActionParameter{
					Name:  "source_auth",
					Value: workflowExecution.Authorization,
				})

				action.Parameters = append(action.Parameters, WorkflowAppActionParameter{
					Name:  "source_node",
					Value: action.ID,
				})

				backendUrl := os.Getenv("BASE_URL")
				if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
					backendUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
				}

				if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
					backendUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
				}

				if len(backendUrl) > 0 {
					action.Parameters = append(action.Parameters, WorkflowAppActionParameter{
						Name:  "backend_url",
						Value: backendUrl,
					})
				}

			}
		} else if action.AppName == "User Input" {
			branchesFound := 0
			parentFinished := 0

			for _, item := range workflowExecution.Workflow.Branches {
				if item.DestinationID == action.ID {
					branchesFound += 1

					for _, result := range workflowExecution.Results {
						if result.Action.ID == item.SourceID {
							// Check for fails etc
							if result.Status == "SUCCESS" || result.Status == "SKIPPED" {
								parentFinished += 1
							} else {
								log.Printf("Parent %s has status %s", result.Action.Label, result.Status)
							}

							break
						}
					}
				}
			}

			//log.Printf("[DEBUG] Should execute parent %s (?). Branches: %d. Parents done: %d", action.AppName, branchesFound, parentFinished)
			if branchesFound == parentFinished {

				if action.ID == workflowExecution.Start {
					log.Printf("Skipping because it's the startnode")
					visited = append(visited, action.ID)
					executed = append(executed, action.ID)
					continue
				} else {
					log.Printf("[DEBUG][%s] Should stop after this iteration because it's user-input based.", workflowExecution.ExecutionId)

					trigger := Trigger{}
					for _, innertrigger := range workflowExecution.Workflow.Triggers {
						if innertrigger.ID == action.ID {
							trigger = innertrigger
							break
						}
					}

					trigger.LargeImage = ""
					triggerData, err := json.Marshal(trigger)
					if err != nil {
						log.Printf("[WARNING] Failed unmarshalling action: %s", err)
						triggerData = []byte("Failed unmarshalling. Cancel execution!")
					}

					_ = triggerData

					timeNow := int64(time.Now().Unix())
					result := ActionResult{
						Action:        action,
						ExecutionId:   workflowExecution.ExecutionId,
						Authorization: workflowExecution.Authorization,
						Result:        "{\"success\": true, \"reason\": \"WAITING FOR USER INPUT\"}",
						StartedAt:     (timeNow + 3) * 1000,
						CompletedAt:   (timeNow + 3) * 1000,
						Status:        "WAITING",
					}

					// old: 1710863749000
					// new: 1710863808000

					workflowExecution.Results = append(workflowExecution.Results, result)
					workflowExecution.Status = "WAITING"
					err = SetWorkflowExecution(ctx, workflowExecution, true)
					if err != nil {
						log.Printf("[ERROR] Error saving workflow execution actionresult setting: %s", err)
						break
					}

					action.Environment = environment
					action.AppName = "shuffle-subflow"
					action.Name = "run_userinput"
					action.AppVersion = "1.1.0"
					action.ExecutionDelay = trigger.ExecutionDelay

					for _, innertrigger := range workflowExecution.Workflow.Triggers {
						if innertrigger.ID == action.ID {
							trigger = innertrigger
							break
						}
					}

					smsEnabled := false
					emailEnabled := false
					subflowEnabled := false
					for _, trigger := range trigger.Parameters {
						if trigger.Name == "type" {
							if strings.Contains(trigger.Value, "sms") {
								smsEnabled = true
							}

							if strings.Contains(trigger.Value, "email") {
								emailEnabled = true
							}

							if strings.Contains(trigger.Value, "subflow") {
								subflowEnabled = true
							}
						}
					}

					//log.Printf("\n\nSHOULD RUN USER INPUT! SMS: %#v, email: %#v, subflow: %#v \n\n", smsEnabled, emailEnabled, subflowEnabled)

					// FIXME: Add startnode from frontend
					action.ExecutionDelay = trigger.ExecutionDelay
					action.Parameters = []WorkflowAppActionParameter{}
					for _, parameter := range trigger.Parameters {
						parameter.Variant = "STATIC_VALUE"
						if parameter.Name == "alertinfo" {
							parameter.Name = "information"
						}

						if parameter.Name == "sms" && smsEnabled == false {
							continue
						}

						if parameter.Name == "email" && emailEnabled == false {
							continue
						}

						if parameter.Name == "subflow" && subflowEnabled == false {
							continue
						}

						action.Parameters = append(action.Parameters, parameter)
					}

					action.Parameters = append(action.Parameters, WorkflowAppActionParameter{
						Name:  "startnode",
						Value: workflowExecution.Start,
					})

					backendUrl := os.Getenv("BASE_URL")
					if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
						backendUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
					}

					if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
						backendUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
					}

					// Fallback
					if len(backendUrl) == 0 {
						backendUrl = "https://shuffler.io"
					}

					if len(backendUrl) > 0 {
						action.Parameters = append(action.Parameters, WorkflowAppActionParameter{
							Name:  "backend_url",
							Value: backendUrl,
						})
					}

					log.Printf("[DEBUG][%s] Starting with user input sourcenode '%s'", workflowExecution.ExecutionId, trigger.ID)
					action.Parameters = append(action.Parameters, WorkflowAppActionParameter{
						Name:  "source_node",
						Value: trigger.ID,
					})

					// If sms/email, it should be setting the apikey based on the org
					syncApikey := workflowExecution.Authorization
					if project.Environment != "cloud" && project.Environment != "worker" {
						org, err := GetOrg(ctx, workflowExecution.ExecutionOrg)
						if err == nil {
							log.Printf("[DEBUG] Got syncconfig key: %s", org.SyncConfig.Apikey)
							syncApikey = org.SyncConfig.Apikey
						} else {
							log.Printf("[ERROR] Failed to get org %s: %s", workflowExecution.ExecutionOrg, err)
						}
					}

					action.Parameters = append(action.Parameters, WorkflowAppActionParameter{
						Name:  "user_apikey",
						Value: syncApikey,
					})
				}
			}
		} else {
			//log.Printf("Handling action %s", action)
		}

		// Here it's still in a loop..?
		_, _, _, _, _, executed, _, _ = GetExecutionVariables(ctx, workflowExecution.ExecutionId)
		if ArrayContains(visited, action.ID) || ArrayContains(executed, action.ID) {
			log.Printf("[WARNING][%s] SKIP EXECUTION %s:%s with label %s", workflowExecution.ExecutionId, action.AppName, action.AppVersion, action.Label)
			continue
		} else {
			// FIXME? This was a test to check if a result was finished or not after a certain time. Not viable for production (obv)

			//time.Sleep(1 * time.Second)
			//validateExecution, err := shuffle.GetWorkflowExecution(ctx, workflowExecution.ExecutionId)
			//if err == nil {
			//	skipAction := false
			//	for _, result := range validateExecution.Results {
			//		if result.Action.ID == action.ID {
			//			skipAction = true
			//			break
			//		}
			//	}

			//	if skipAction {
			//		log.Printf("[DEBUG] Skipping action %s afterall.", action.Label)
			//		continue
			//	}
			//}
		}

		// Verify if parents are done
		//log.Printf("[INFO][%s] Should execute %s:%s (%s) with label %s", workflowExecution.ExecutionId, action.AppName, action.AppVersion, action.ID, action.Label)

		relevantActions = append(relevantActions, action)
	}

	return workflowExecution, relevantActions
}

func GetExternalClient(baseUrl string) *http.Client {
	httpProxy := os.Getenv("HTTP_PROXY")
	httpsProxy := os.Getenv("HTTPS_PROXY")

	// Look for internal proxy instead
	// in case apps need a different one: https://jamboard.google.com/d/1KNr4JJXmTcH44r5j_5goQYinIe52lWzW-12Ii_joi-w/viewer?mtt=9r8nrqpnbz6z&f=0

	overrideHttpProxy := os.Getenv("SHUFFLE_INTERNAL_HTTP_PROXY")
	overrideHttpsProxy := os.Getenv("SHUFFLE_INTERNAL_HTTPS_PROXY")
	if len(overrideHttpProxy) > 0 && strings.ToLower(overrideHttpProxy) != "noproxy" {
		httpProxy = overrideHttpProxy
	}

	if len(overrideHttpsProxy) > 0 && strings.ToLower(overrideHttpProxy) != "noproxy" {
		httpsProxy = overrideHttpsProxy
	}

	transport := http.DefaultTransport.(*http.Transport)
	transport.MaxIdleConnsPerHost = 100
	transport.ResponseHeaderTimeout = time.Second * 60
	transport.IdleConnTimeout = time.Second * 60
	transport.Proxy = nil

	skipSSLVerify := false
	if strings.ToLower(os.Getenv("SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY")) == "true" || strings.ToLower(os.Getenv("SHUFFLE_SKIPSSL_VERIFY")) == "true" {
		//log.Printf("[DEBUG] SKIPPING SSL verification with Opensearch")
		skipSSLVerify = true

		os.Setenv("SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY", "true")
		os.Setenv("SHUFFLE_SKIPSSL_VERIFY", "true")
	}

	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS11,
		InsecureSkipVerify: skipSSLVerify,
	}

	if (len(httpProxy) > 0 || len(httpsProxy) > 0) && baseUrl != "http://shuffle-backend:5001" {
		//client = &http.Client{}
	} else {
		if len(httpProxy) > 0 {
			log.Printf("[INFO] Running with HTTP proxy %s (env: HTTP_PROXY)", httpProxy)

			url_i := url.URL{}
			url_proxy, err := url_i.Parse(httpProxy)
			if err == nil {
				transport.Proxy = http.ProxyURL(url_proxy)
			}
		}
		if len(httpsProxy) > 0 {
			log.Printf("[INFO] Running with HTTPS proxy %s (env: HTTPS_PROXY)", httpsProxy)

			url_i := url.URL{}
			url_proxy, err := url_i.Parse(httpsProxy)
			if err == nil {
				transport.Proxy = http.ProxyURL(url_proxy)
			}
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * 60,
	}

	return client
}

func GetAllAppCategories() []AppCategory {
	categories := []AppCategory{
		AppCategory{
			Name:         "Cases",
			Color:        "",
			Icon:         "cases",
			ActionLabels: []string{"Create ticket", "List tickets", "Get ticket", "Create ticket", "Close ticket", "Add comment", "Update ticket"},
			RequiredFields: map[string][]string{
				"Create ticket": []string{"title"},
				"Add comment":   []string{"comment"},
				"Lis tickets":   []string{"time_range"},
			},
			OptionalFields: map[string][]string{
				"Create ticket": []string{"description"},
			},
		},
		AppCategory{
			Name:           "Communication",
			Color:          "",
			Icon:           "communication",
			ActionLabels:   []string{"List Messages", "Send Message", "Get Message", "Search messages"},
			RequiredFields: map[string][]string{},
			OptionalFields: map[string][]string{},
		},
		AppCategory{
			Name:           "SIEM",
			Color:          "",
			Icon:           "siem",
			ActionLabels:   []string{"Search", "List Alerts", "Close Alert", "Create detection", "Add to lookup list"},
			RequiredFields: map[string][]string{},
			OptionalFields: map[string][]string{},
		},
		AppCategory{
			Name:           "Eradication",
			Color:          "",
			Icon:           "eradication",
			ActionLabels:   []string{"List Alerts", "Close Alert", "Create detection", "Block hash", "Search Hosts", "Isolate host", "Unisolate host"},
			RequiredFields: map[string][]string{},
			OptionalFields: map[string][]string{},
		},
		AppCategory{
			Name:           "Assets",
			Color:          "",
			Icon:           "assets",
			ActionLabels:   []string{"List Assets", "Get Asset", "Search Assets", "Search Users", "Search endpoints", "Search vulnerabilities"},
			RequiredFields: map[string][]string{},
			OptionalFields: map[string][]string{},
		},
		AppCategory{
			Name:           "Intel",
			Color:          "",
			Icon:           "intel",
			ActionLabels:   []string{"Get IOC", "Search IOC", "Create IOC", "Update IOC", "Delete IOC"},
			RequiredFields: map[string][]string{},
			OptionalFields: map[string][]string{},
		},
		AppCategory{
			Name:           "IAM",
			Color:          "",
			Icon:           "iam",
			ActionLabels:   []string{"Reset Password", "Enable user", "Disable user", "Get Identity", "Get Asset", "Search Identity"},
			RequiredFields: map[string][]string{},
			OptionalFields: map[string][]string{},
		},
		AppCategory{
			Name:           "Network",
			Color:          "",
			Icon:           "network",
			ActionLabels:   []string{"Get Rules", "Allow IP", "Block IP"},
			RequiredFields: map[string][]string{},
			OptionalFields: map[string][]string{},
		},
		AppCategory{
			Name:           "Other",
			Color:          "",
			Icon:           "other",
			ActionLabels:   []string{"Update Info", "Get Info", "Get Status", "Get Version", "Get Health", "Get Config", "Get Configs", "Get Configs by type", "Get Configs by name", "Run script"},
			RequiredFields: map[string][]string{},
			OptionalFields: map[string][]string{},
		},
	}

	return categories
}

// Function with the name RemoveFromArray to remove a string from a string array
func RemoveFromArray(array []string, element string) []string {
	for i, v := range array {
		if v == element {
			return append(array[:i], array[i+1:]...)
		}
	}

	return array
}

func FindRelevantApps(appname string, apps []WorkflowApp) []WorkflowApp {
	return []WorkflowApp{}
}

func FindMatchingCategoryApps(category string, apps []WorkflowApp, org *Org) []WorkflowApp {
	if len(category) == 0 {
		return []WorkflowApp{}
	}

	category = strings.ToLower(category)
	parsedCategories := map[string]Category{
		"siem":          org.SecurityFramework.SIEM,
		"email":         org.SecurityFramework.Communication,
		"communication": org.SecurityFramework.Communication,
		"assets":        org.SecurityFramework.Assets,
		"cases":         org.SecurityFramework.Cases,
		"network":       org.SecurityFramework.Network,
		"intel":         org.SecurityFramework.Intel,
		"eradication":   org.SecurityFramework.EDR,
		"edr":           org.SecurityFramework.EDR,
		"iam":           org.SecurityFramework.IAM,
	}

	var matchingApps []WorkflowApp
	foundCategory, ok := parsedCategories[category]
	if ok && len(foundCategory.Name) > 0 {
		parsedCategoryNames := strings.Split(foundCategory.Name, ",")
		for _, catApp := range parsedCategoryNames {
			catApp = strings.ToLower(strings.TrimSpace(catApp))

			found := false
			for _, app := range apps {
				if strings.ToLower(app.Name) == catApp {
					matchingApps = append(matchingApps, app)
					found = true
					break
				}
			}

			if !found {
				log.Printf("[INFO] Could not find app %s in category %s", catApp, category)
			}
		}
	}

	log.Printf("[INFO] Found %d apps in category '%s'", len(matchingApps), category)
	if category == "email" {
		category = "communication"
	}

	for _, app := range apps {
		if len(app.Categories) == 0 {
			continue
		}

		if strings.ToLower(app.Categories[0]) != category {
			continue
		}

		matchingApps = append(matchingApps, app)
	}

	return matchingApps
}

// Apps to test:
// Communication: Slack & Teams -> Send message
// Ticketing: TheHive & Jira 		-> Create ticket

// 1. Check the category, if it has the label in it
// 2. Get the app (openapi & app config)
// 3. Check if the label exists for the app in any action
// 4. Do the translation~ (workflow or direct)
// 5. Run app action/workflow
// 6. Return result from the app
func RunCategoryAction(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just here to verify that the user is logged in
	if resp != nil {
		resp.Header().Add("x-execution-url", "")
		resp.Header().Add("x-apprun-url", "")
	}

	ctx := GetContext(request)
	err := ValidateRequestOverload(resp, request)
	if err != nil {
		log.Printf("[ERROR] Request overload for Run Category Action with IP %s", GetRequestIp(request))
		resp.WriteHeader(429)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Too many requests. This is an experimental AI feature and can't handle burst traffic yet."}`)))
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		// Look for "authorization" and "execution_id" queries
		authorization := request.URL.Query().Get("authorization")
		executionId := request.URL.Query().Get("execution_id")
		if len(authorization) == 0 || len(executionId) == 0 {
			log.Printf("[AUDIT] Api authentication failed in run category action: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
			return
		}

		//log.Printf("[INFO] Running category action request with authorization and execution_id: %s, %s", authorization, executionId)
		// 1. Get the executionId and check if it's valid
		// 2. Check if authorization is valid
		// 3. Check if the execution is FINISHED or not
		exec, err := GetWorkflowExecution(ctx, executionId)
		if err != nil {
			log.Printf("[WARNING] Error with getting execution in run category action: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed to get execution"}`))
			return
		}

		if exec.Status != "EXECUTING" {
			log.Printf("[WARNING] Execution is not executing in run category action: %s", exec.Status)
			resp.WriteHeader(403)
			resp.Write([]byte(`{"success": false, "reason": "Execution is not executing. Can't modify."}`))
			return
		}

		// 4. Check if the user is the owner of the execution
		if exec.Authorization != authorization {
			log.Printf("[WARNING] Authorization doesn't match in run category action: %s != %s", exec.Authorization, authorization)
			resp.WriteHeader(403)
			resp.Write([]byte(`{"success": false, "reason": "Authorization doesn't match"}`))
			return
		}

		user.Role = "admin"
		user.ActiveOrg.Id = exec.ExecutionOrg
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to run category action: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	request.Header.Add("Org-Id", user.ActiveOrg.Id)
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Error with body read for category action: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body of the request"}`))
		return
	}

	var value CategoryAction
	err = json.Unmarshal(body, &value)
	if err != nil {
		log.Printf("[WARNING] Error with unmarshal tmpBody in category action: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed unmarshaling body of the request"}`))
		return
	}

	log.Printf("[INFO] Running category-action '%s' in category '%s' for org %s (%s)", value.Label, value.Category, user.ActiveOrg.Name, user.ActiveOrg.Id)

	if len(value.Query) > 0 {
		// Check if app authentication. If so, check if intent is to actually authenticate, or find the actual intent
		if value.Label == "authenticate_app" && !strings.Contains(strings.ToLower(value.Query), "auth") {
			log.Printf("[INFO] Got authenticate app request. Does the intent %#v match auth?", value.Query)
		}
	}

	if value.Label == "use_app" {
		for _, field := range value.Fields {
			if field.Key == "action" {
				log.Printf("[INFO] NOT IMPLEMENTED: Changing to action label '%s' from use_app", field.Value)
				//value.Label = field.Value
				break
			}
		}
	}

	threadId := value.WorkflowId
	if len(value.WorkflowId) > 0 {
		// Should maybe cache this based on the thread? Then reuse and connect?
		if strings.HasPrefix(value.WorkflowId, "thread") {
			threadCache, err := GetCache(ctx, value.WorkflowId)
			if err != nil {
				//log.Printf("[WARNING] Error with getting thread cache in category action: %s", err)
			} else {
				// Make threadcache into a string and map it to value.WorkflowId
				// Then use that to get the thread cache
				value.WorkflowId = string([]byte(threadCache.([]uint8)))
			}
		}
	}

	categories := GetAllAppCategories()

	value.Category = strings.ToLower(value.Category)
	value.Label = strings.ReplaceAll(strings.ToLower(value.Label), " ", "_")
	value.AppName = strings.ReplaceAll(strings.ToLower(value.AppName), " ", "_")

	if value.AppName == "email" {
		value.Category = "email"
		value.AppName = ""
	}

	foundIndex := -1
	labelIndex := -1
	if len(value.Category) > 0 {

		for categoryIndex, category := range categories {
			if strings.ToLower(category.Name) != value.Category {
				continue
			}

			foundIndex = categoryIndex
			break
		}

		if foundIndex >= 0 {
			for _, label := range categories[foundIndex].ActionLabels {
				if strings.ReplaceAll(strings.ToLower(label), " ", "_") == value.Label {
					labelIndex = foundIndex
				}
			}
		}
	} else {
		//log.Printf("[DEBUG] No category set in category action")
	}

	_ = labelIndex

	log.Printf("[INFO] Found label '%s' in category '%s'. Indexes for category: %d, and label: %d", value.Label, value.Category, foundIndex, labelIndex)

	newapps, err := GetPrioritizedApps(ctx, user)
	if err != nil {
		log.Printf("[WARNING] Failed getting apps in category action: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed loading apps. Contact support@shuffler.io"}`))
		return
	}

	org, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[ERROR] Failed getting org %s (%s) in category action: %s", user.ActiveOrg.Name, user.ActiveOrg.Id, err)
	}

	if value.Category == "email" {
		value.Category = "communication"
	}

	// Check the app framework
	foundAppType := value.Category
	foundCategory := Category{}
	if foundAppType == "cases" {
		foundCategory = org.SecurityFramework.Cases
	} else if foundAppType == "communication" {
		foundCategory = org.SecurityFramework.Communication
	} else if foundAppType == "assets" {
		foundCategory = org.SecurityFramework.Assets
	} else if foundAppType == "network" {
		foundCategory = org.SecurityFramework.Network
	} else if foundAppType == "intel" {
		foundCategory = org.SecurityFramework.Intel
	} else if foundAppType == "edr" {
		foundCategory = org.SecurityFramework.EDR
	} else if foundAppType == "iam" {
		foundCategory = org.SecurityFramework.IAM
	} else if foundAppType == "siem" {
		foundCategory = org.SecurityFramework.SIEM
	} else {
		if len(foundAppType) > 0 {
			log.Printf("[ERROR] Unknown app type in category action: %#v", foundAppType)
		}
	}

	if foundCategory.Name == "" && value.AppName == "" {
		log.Printf("[DEBUG] No category found AND no app name set in category action for user %s (%s). Returning", user.Username, user.Id)

		structuredFeedback := StructuredCategoryAction{
			Success:  false,
			Action:   "select_category",
			Category: foundAppType,
			Reason:   fmt.Sprintf("Help us set up an app in the '%s' category for you first", foundAppType),
		}

		jsonBytes, err := json.Marshal(structuredFeedback)
		if err != nil {
			log.Printf("[ERROR] Failed marshaling structured feedback in category action: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed marshaling structured feedback. Contact"}`))
			return
		}

		resp.WriteHeader(400)
		resp.Write(jsonBytes)
		return
	} else {
		if len(foundCategory.Name) > 0 {
			log.Printf("[DEBUG] Found app for category %s: %s (%s)", foundAppType, foundCategory.Name, foundCategory.ID)
		}
	}

	selectedApp := WorkflowApp{}
	selectedCategory := AppCategory{}
	selectedAction := WorkflowAppAction{}

	availableLabels := []string{}
	for _, app := range newapps {
		if app.Name == "" || len(app.Categories) == 0 {
			continue
		}

		// If we HAVE an app as a category already
		if len(value.AppName) == 0 {
			availableLabels = []string{}
			if len(app.Categories) == 0 {
				continue
			}

			if strings.ToLower(app.Categories[0]) != value.Category {
				continue
			}

			// Check if the label is in the action
			for _, action := range app.Actions {
				if len(action.CategoryLabel) == 0 {
					continue
				}

				availableLabels = append(availableLabels, action.CategoryLabel[0])

				if len(value.ActionName) > 0 && action.Name != value.ActionName {
					continue
				}

				if strings.ReplaceAll(strings.ToLower(action.CategoryLabel[0]), " ", "_") == value.Label {
					selectedAction = action

					log.Printf("[INFO] Found label %s in app %s. ActionName: %s", value.Label, app.Name, action.Name)
					break
				}
			}

			//log.Printf("[DEBUG] Found app with category %s", value.Category)
			selectedApp = app
			if len(selectedAction.Name) > 0 {
				log.Printf("[DEBUG] Selected app %s (%s) with action %s", selectedApp.Name, selectedApp.ID, selectedAction.Name)

				// FIXME: Don't break on the first one?
				//break
				availableLabels = []string{}
			}

			if foundCategory.ID == app.ID {
				break
			}

		} else {
			// If we DONT have a category app already
			if app.ID == value.AppName || strings.ReplaceAll(strings.ToLower(app.Name), " ", "_") == value.AppName {
				//log.Printf("[DEBUG] Found app: %s vs %s (%s)", app.Name, value.AppName, app.ID)
				availableLabels = []string{}
				selectedApp = app

				for _, action := range app.Actions {
					if len(action.CategoryLabel) == 0 {
						continue
					} else {
						//log.Printf("[DEBUG] Found label %s", action.CategoryLabel)

						availableLabels = append(availableLabels, action.CategoryLabel[0])
					}

					if len(value.ActionName) > 0 && action.Name != value.ActionName {
						continue
					}

					// For now just finding the first one
					if strings.ReplaceAll(strings.ToLower(action.CategoryLabel[0]), " ", "_") == strings.ReplaceAll(strings.ToLower(value.Label), " ", "_") {
						selectedAction = action

						for _, category := range categories {
							if strings.ToLower(category.Name) == strings.ToLower(app.Categories[0]) {
								selectedCategory = category
								break
							}
						}

						//log.Printf("[INFO] Found label %s in app %s. ActionName: %s", value.Label, app.Name, action.Name)
						break
					}
				}

				break
			} else if selectedApp.ID == "" && len(value.AppName) > 0 && (strings.Contains(strings.ToLower(app.Name), strings.ToLower(value.AppName)) || strings.Contains(strings.ToLower(value.AppName), strings.ToLower(app.Name))) {
				selectedApp = app
				log.Printf("[WARNING] Set selected app to partial match %s (%s) for input %s", selectedApp.Name, selectedApp.ID, value.AppName)

				availableLabels = []string{}

				lowercaseLabel := strings.ReplaceAll(strings.ToLower(value.Label), " ", "_")
				for _, action := range app.Actions {
					if len(action.CategoryLabel) == 0 {
						continue
					}

					log.Printf("[DEBUG] Found category label %#v", action.CategoryLabel)
					availableLabels = append(availableLabels, action.CategoryLabel[0])

					actionCategory := strings.ReplaceAll(strings.ToLower(action.CategoryLabel[0]), " ", "_")
					if actionCategory == lowercaseLabel || strings.HasPrefix(actionCategory, lowercaseLabel) {
						selectedAction = action

						for _, category := range categories {
							if strings.ToLower(category.Name) == strings.ToLower(app.Categories[0]) {
								selectedCategory = category
								break
							}
						}

						//log.Printf("[INFO] Found label %s in app %s. ActionName: %s", value.Label, app.Name, action.Name)
						break
					}
				}
			}
		}
	}

	if len(selectedApp.ID) == 0 {
		log.Printf("[WARNING] Couldn't find app with ID or name '%s' active in org %s (%s)", value.AppName, user.ActiveOrg.Name, user.ActiveOrg.Id)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed finding an app with the name or ID '%s'. Please make sure the app is already activated for your organization."}`, value.AppName)))
		return
	}

	fieldHash := ""
	fieldFileFound := false
	fieldFileContentMap := map[string]interface{}{}
	if len(value.Fields) > 0 {
		sortedKeys := []string{}
		for _, field := range value.Fields {
			sortedKeys = append(sortedKeys, field.Key)
		}

		sort.Strings(sortedKeys)
		newFields := []Valuereplace{}
		for _, key := range sortedKeys {
			for _, field := range value.Fields {
				if field.Key == key {
					newFields = append(newFields, field)
					break
				}
			}
		}

		value.Fields = newFields

		// Md5 based on sortedKeys. Could subhash key search work?
		mappedString := fmt.Sprintf("%s-%s", selectedApp.ID, value.Label, strings.Join(sortedKeys, ""))
		fieldHash = fmt.Sprintf("%x", md5.Sum([]byte(mappedString)))
		file, err := GetFile(ctx, fmt.Sprintf("file_%s", fieldHash))

		if err != nil {
			log.Printf("[DEBUG] Error with getting file in category action: %s", err)
		} else {
			log.Printf("\n\n\n[DEBUG] Found file in category action: %#v. Status: %s. Category: %s\n\n\n", file, file.Status, file.Namespace)

			if file.Status == "active" {
				fieldFileFound = true
				fileContent, err := GetFileContent(ctx, file, nil)
				if err != nil {
					log.Printf("[ERROR] Failed getting file content in category action: %s", err)
					fieldFileFound = false
				}

				//log.Printf("Output content: %#v", string(fileContent))
				err = json.Unmarshal(fileContent, &fieldFileContentMap)
				if err != nil {
					log.Printf("[ERROR] Failed unmarshaling file content in category action: %s", err)
				}
			}
		}
	}

	if strings.Contains(strings.ToLower(strings.Join(selectedApp.ReferenceInfo.Triggers, ",")), "webhook") {
		availableLabels = append(availableLabels, "Webhook")

		if len(selectedAction.Name) == 0 {
			//log.Printf("\n\n[DEBUG] Due to webhook in app %s (%s), we don't need an action. Should not return\n\n", selectedApp.Name, selectedApp.ID)
		}
	}

	if len(selectedAction.Name) == 0 {
		log.Printf("[WARNING] Couldn't find the label '%s' in app '%s'. If authentication/use_app, ignore this.", value.Label, selectedApp.Name)

		if value.Label != "app_authentication" && value.Label != "authenticate_app" && value.Label != "use_app" {
			resp.WriteHeader(500)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed finding action '%s' labeled in app '%s'. If this is wrong, please contact support@shuffler.io"}`, value.Label, strings.ReplaceAll(selectedApp.Name, "_", " "))))
			return
		} else {
			//log.Printf("[DEBUG] NOT sending back due to label %s", value.Label)
		}
	}

	discoveredCategory := foundAppType
	if len(selectedApp.Categories) > 0 {
		discoveredCategory = selectedApp.Categories[0]
	}

	if len(selectedCategory.Name) > 0 {
		if len(selectedCategory.RequiredFields) == 0 {
			for _, param := range selectedAction.Parameters {
				if !param.Required {
					continue
				}

				if param.Name == "url" {
					continue
				}

				selectedCategory.RequiredFields[param.Name] = []string{param.Name}
			}
		}
	}

	// Need translation here, now that we have the action
	// Should just do an app injection into the workflow?
	foundFields := 0
	missingFields := []string{}
	baseFields := []string{}

	_ = foundFields
	for innerLabel, labelValue := range selectedCategory.RequiredFields {
		if strings.ReplaceAll(strings.ToLower(innerLabel), " ", "_") != value.Label {
			continue
		}

		baseFields = labelValue
		missingFields = labelValue
		for _, field := range value.Fields {
			if ArrayContains(labelValue, field.Key) {
				// Remove from missingFields
				missingFields = RemoveFromArray(missingFields, field.Key)

				foundFields += 1
			}
		}

		break
	}

	if len(missingFields) > 0 {
		for _, missingField := range missingFields {
			if missingField != "body" {
				continue
			}

			fixedBody, err := UpdateActionBody(selectedAction)
			if err != nil {
				log.Printf("[ERROR] Failed getting correct action body for %s: %s", selectedAction.Name, err)
				continue
			}

			log.Printf("[DEBUG] GOT BODY: %#v", fixedBody)
		}
	}

	// FIXME: Check if ALL fields for the target app can be fullfiled
	// E.g. for Jira: Org_id is required.

	/*
		if foundFields != len(baseFields) {
			log.Printf("[WARNING] Not all required fields were found in category action. Want: %#v, have: %#v", baseFields, value.Fields)

			resp.WriteHeader(400)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Not all required fields are set. This can be autocompleted from fields you fille in", "label": "%s", "missing_fields": "%s"}`, value.Label, strings.Join(missingFields, ","))))
			return

		}
	*/
	_ = baseFields

	/*











	 */

	// Uses the thread to continue generating in the same workflow
	foundWorkflow := &Workflow{}
	newWorkflowId := uuid.NewV4().String()
	if len(value.WorkflowId) > 0 && !strings.HasPrefix(value.WorkflowId, "thread") {
		newWorkflowId = value.WorkflowId

		// Get the workflow
		foundWorkflow, err = GetWorkflow(ctx, newWorkflowId)
		if err != nil {
			log.Printf("[WARNING] Failed getting workflow %s: %s", newWorkflowId, err)
		}
	}

	if len(threadId) > 0 && strings.HasPrefix(threadId, "thread") {
		// Set the thread ID in cache
		err = SetCache(ctx, threadId, []byte(newWorkflowId), 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for thread ID %s: %s", threadId, err)
		}
	}

	startId := uuid.NewV4().String()
	workflowName := fmt.Sprintf("Category action: %s", selectedAction.Name)
	if len(value.Query) > 0 {
		workflowName = value.Query
	}

	newWorkflow := Workflow{
		ID:          newWorkflowId,
		Name:        workflowName,
		Description: fmt.Sprintf("Category action: %s. This is a workflow generated and ran by ShuffleGPT. More here: https://shuffler.io/chat", selectedAction.Name),
		Generated:   true,
		Hidden:      true,
		Start:       startId,
		OrgId:       user.ActiveOrg.Id,
	}

	if len(foundWorkflow.ID) > 0 {
		newWorkflow = *foundWorkflow
		newWorkflow.Start = startId

		// Remove is startnode from previous nodes
		newActions := []Action{}
		for actionIndex, action := range newWorkflow.Actions {
			if len(selectedAction.Name) > 0 && action.Name == selectedAction.Name {
				//log.Printf("[DEBUG] Found action %s, setting as start node", action.Name)
				continue
			}

			if action.IsStartNode {
				newWorkflow.Actions[actionIndex].IsStartNode = false
			}

			newActions = append(newActions, action)
		}

		// Remove any node with the same name
		newWorkflow.Actions = newActions
	}

	environment := "Cloud"
	// FIXME: Make it dynamic based on the default env
	if project.Environment != "cloud" {
		environment = "Shuffle"
	}

	// Get the environments for the user and choose the default
	environments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
	if err == nil {
		defaultEnv := ""

		foundEnv := strings.TrimSpace(strings.ToLower(value.Environment))
		for _, env := range environments {
			if env.Archived {
				continue
			}

			if env.Default {
				defaultEnv = env.Name
			}

			envName := strings.TrimSpace(strings.ToLower(env.Name))
			if len(value.Environment) > 0 && envName == foundEnv {
				environment = env.Name
			}
		}

		if len(environment) == 0 && len(defaultEnv) > 0 {
			environment = defaultEnv
		}
	}

	foundAuthenticationId := value.AuthenticationId
	if len(foundAuthenticationId) == 0 {
		// 1. Get auth
		// 2. Append the auth
		// 3. Run!

		auth, err := GetAllWorkflowAppAuth(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("[WARNING] Failed getting auths for org %s: %s", user.ActiveOrg.Id, err)
		} else {
			latestEdit := int64(0)
			for _, auth := range auth {
				if auth.Edited < latestEdit {
					continue
				}

				// Check if the app name or ID is correct
				if auth.App.Name != selectedApp.Name && auth.App.ID != selectedApp.ID {
					continue
				}

				foundAuthenticationId = auth.Id
				latestEdit = auth.Edited
			}
		}
	}

	if len(foundAuthenticationId) == 0 {
		log.Printf("\n\n[WARNING] Couldn't find auth for app %s\n\n", selectedApp.Name)

		requiresAuth := false
		for _, action := range selectedApp.Actions {
			for _, param := range action.Parameters {
				if param.Configuration {
					requiresAuth = true
					break
				}
			}

			if requiresAuth {
				break
			}
		}

		if !requiresAuth {
			log.Printf("\n\n[ERROR] App %s doesn't require auth, but we are still sending back with auth requires\n\n", selectedApp.Name)
		}

		// Reducing size drastically as it isn't really necessary
		selectedApp.Actions = []WorkflowAppAction{}
		//selectedApp.Authentication = Authentication{}
		selectedApp.ChildIds = []string{}
		selectedApp.SmallImage = ""
		structuredFeedback := StructuredCategoryAction{
			Success:  false,
			Action:   "app_authentication",
			Category: discoveredCategory,
			Reason:   fmt.Sprintf("Help us set up app '%s' for you first. If you want to skip this, fill in empty fields and submit it.", selectedApp.Name),
			Apps: []WorkflowApp{
				selectedApp,
			},

			AvailableLabels: availableLabels,
		}

		jsonFormatted, err := json.Marshal(structuredFeedback)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling structured feedback: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed formatting your data"}`))
			return
		}

		resp.WriteHeader(400)
		resp.Write(jsonFormatted)
		return
	}

	// Send back with SUCCESS as we already have an authentication
	// Use the labels to show what Jira can do
	if value.Label == "app_authentication" || value.Label == "authenticate_app" || value.Label == "use_app" {
		ifSuccess := true
		reason := fmt.Sprintf("Please authenticate with %s", selectedApp.Name)

		// Find out if it should re-authenticate or not
		for _, field := range value.Fields {
			if (field.Key == "re-authenticate" || field.Key == "reauthenticate") && field.Value == "true" {
				ifSuccess = false
				reason = fmt.Sprintf("Please re-authenticate with %s by clicking the button below!", selectedApp.Name)
			}
		}

		selectedApp.Actions = []WorkflowAppAction{}
		//selectedApp.Authentication = Authentication{}
		selectedApp.ChildIds = []string{}
		selectedApp.SmallImage = ""
		structuredFeedback := StructuredCategoryAction{
			Success:  ifSuccess,
			Action:   "app_authentication",
			Category: discoveredCategory,
			Reason:   reason,
			Apps: []WorkflowApp{
				selectedApp,
			},
			AvailableLabels: availableLabels,
		}

		// marshalled
		jsonFormatted, err := json.Marshal(structuredFeedback)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling structured feedback: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed formatting your data"}`))
			return
		}

		resp.WriteHeader(400)
		resp.Write(jsonFormatted)
		return
	}

	if !value.SkipWorkflow {
		log.Printf("\n\n[INFO] Adding workflow %s\n\n", newWorkflow.ID)
	}

	/*
		refUrl := ""
		if project.Environment == "cloud" {
			location := "europe-west2"
			if len(os.Getenv("SHUFFLE_GCEPROJECT_REGION")) > 0 {
				location = os.Getenv("SHUFFLE_GCEPROJECT_REGION")
			}

			gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
			functionName := fmt.Sprintf("%s-%s", selectedApp.Name, selectedApp.ID)
			functionName = strings.ToLower(strings.Replace(strings.Replace(strings.Replace(strings.Replace(strings.Replace(functionName, "_", "-", -1), ":", "-", -1), "-", "-", -1), " ", "-", -1), ".", "-", -1))

			refUrl = fmt.Sprintf("https://%s-%s.cloudfunctions.net/%s", location, gceProject, functionName)
		}
	*/

	// Now start connecting it to the correct app (Jira?)

	label := selectedAction.Name
	if strings.HasPrefix(label, "get_list") {
		// Remove get_ at the start
		label = strings.Replace(label, "get_list", "list", 1)
	}

	step := int64(0)
	if value.Step >= 1 {
		step = value.Step
	} else {
		step = int64(len(newWorkflow.Actions) + 1)
	}

	secondAction := Action{
		Name:        selectedAction.Name,
		Label:       selectedAction.Name,
		AppName:     selectedApp.Name,
		AppVersion:  selectedApp.AppVersion,
		AppID:       selectedApp.ID,
		Environment: environment,
		IsStartNode: true,
		ID:          uuid.NewV4().String(),
		Parameters:  []WorkflowAppActionParameter{},
		Position: Position{
			X: 0.0 + float64(step*300.0),
			Y: 100.0,
		},
		AuthenticationId: foundAuthenticationId,
		IsValid:          true,
		//ReferenceUrl:     refUrl,
	}

	// Ensuring it gets overwritten
	startNode := Action{
		Position: Position{
			X: 100000,
		},
	}

	if step > 0 {
		// Should find nearest neighor to the left, and then add a branch from it to this one
		// If it's a GENERATED app, add a condition to the branch checking if the output status is < 300

		nearestXNeighbor := Action{}
		for _, action := range newWorkflow.Actions {
			if action.Position.X > nearestXNeighbor.Position.X {
				nearestXNeighbor = action
			}

			// Find farthest to the left
			if action.Position.X < startNode.Position.X {
				startNode = action
			}
		}

		if nearestXNeighbor.ID != "" {

			//Conditions    []Condition `json:"conditions" datastore: "conditions"`
			newWorkflow.Branches = append(newWorkflow.Branches, Branch{
				Label: "Validating",

				SourceID:      nearestXNeighbor.ID,
				DestinationID: secondAction.ID,
				ID:            uuid.NewV4().String(),

				Conditions: []Condition{
					Condition{
						Source: WorkflowAppActionParameter{
							Name:    "source",
							Value:   fmt.Sprintf("$%s.status", strings.ReplaceAll(nearestXNeighbor.Label, " ", "_")),
							Variant: "STATIC_VALUE",
						},
						Condition: WorkflowAppActionParameter{
							Name:    "condition",
							Value:   "less than",
							Variant: "STATIC_VALUE",
						},
						Destination: WorkflowAppActionParameter{
							Name:    "destination",
							Value:   "300",
							Variant: "STATIC_VALUE",
						},
					},
				},
			})
		}
	}

	if len(selectedAction.RequiredBodyFields) == 0 && len(selectedCategory.RequiredFields) > 0 {
		// Check if the required fields are present
		//selectedAction.RequiredBodyFields = selectedCategory.RequiredFields
		for labelName, requiredFields := range selectedCategory.RequiredFields {
			newName := strings.ReplaceAll(strings.ToLower(labelName), " ", "_")
			if newName != value.Label {
				continue
			}

			for _, requiredField := range requiredFields {
				selectedAction.RequiredBodyFields = append(selectedAction.RequiredBodyFields, requiredField)
			}
		}
	}

	// Check if the organisation has a specific set of parameters for this action, mapped to the following fields:
	selectedAction.AppID = selectedApp.ID
	selectedAction.AppName = selectedApp.Name
	selectedAction = GetOrgspecificParameters(ctx, *org, selectedAction)

	//log.Printf("[DEBUG] Required bodyfields: %#v", selectedAction.RequiredBodyFields)
	handledRequiredFields := []string{}
	missingFields = []string{}
	for _, param := range selectedAction.Parameters {

		// Optional > Required
		fieldChanged := false
		for _, field := range value.OptionalFields {
			if strings.ReplaceAll(strings.ToLower(field.Key), " ", "_") == strings.ReplaceAll(strings.ToLower(param.Name), " ", "_") {
				param.Value = field.Value
				fieldChanged = true

				//handledFields = append(handledFields, field.Key)
			}
		}

		// Parse input params into the field
		for _, field := range value.Fields {
			//log.Printf("%s & %s", strings.ReplaceAll(strings.ToLower(field.Key), " ", "_"), strings.ReplaceAll(strings.ToLower(param.Name), " ", "_"))
			if strings.ReplaceAll(strings.ToLower(field.Key), " ", "_") == strings.ReplaceAll(strings.ToLower(param.Name), " ", "_") {
				param.Value = field.Value
				fieldChanged = true

				handledRequiredFields = append(handledRequiredFields, field.Key)
			}
		}

		if param.Name == "body" {

			// FIXME: Look for key:values and inject values into them
			// This SHOULD be just a dumb injection of existing value.Fields & value.OptionalFields for now with synonyms, but later on it should be a more advanced (use schemaless & cross org referencing)
			// FIXME: Should PRELOAD all of this?

			if len(param.Example) > 0 {
				param.Value = param.Example
			} else {
				//param.Value = ""
				log.Printf("[DEBUG] Found body param. Validating: %#v", param)
				if !fieldChanged {
					log.Printf("\n\nBody not filled yet. Should fill it in (somehow) based on the existing input fields.\n\n")
				}

				param.Required = true
			}
		}

		if param.Required && len(param.Value) == 0 && !param.Configuration {
			missingFields = append(missingFields, param.Name)
		}

		secondAction.Parameters = append(secondAction.Parameters, param)
	}

	if len(handledRequiredFields) < len(value.Fields) {
		// Compare which ones are not handled from value.Fields
		for _, field := range value.Fields {
			if !ArrayContains(handledRequiredFields, field.Key) {
				missingFields = append(missingFields, field.Key)
			}
		}

		log.Printf("[WARNING] Not all required fields were handled. Missing: %#v. Should force use of all fields?", missingFields)
	}

	// Send request to /api/v1/conversation with this data
	baseUrl := fmt.Sprintf("https://shuffler.io")
	if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
		baseUrl = fmt.Sprintf("%s", os.Getenv("SHUFFLE_CLOUDRUN_URL"))
	}

	client := GetExternalClient(baseUrl)

	selectedAction.AppName = selectedApp.Name
	selectedAction.AppID = selectedApp.ID
	selectedAction.AppVersion = selectedApp.AppVersion

	for _, missing := range missingFields {
		if missing != "body" {
			continue
		}

		fixedBody, err := UpdateActionBody(selectedAction)
		if err != nil {
			log.Printf("[ERROR] Failed getting correct action body for %s: %s", selectedAction.Name, err)
			continue
		}

		// Remove newlines
		fixedBody = strings.ReplaceAll(fixedBody, "\n", "")

		log.Printf("[DEBUG] GOT BODY: %#v", fixedBody)
		if len(fixedBody) > 0 {
			bodyFound := false
			for paramIndex, param := range selectedAction.Parameters {
				if param.Name != "body" {
					continue
				}

				bodyFound = true
				//selectedAction.Parameters[paramIndex].Example = fixedBody
				selectedAction.Parameters[paramIndex].Value = fixedBody
				selectedAction.Parameters[paramIndex].Tags = append(selectedAction.Parameters[paramIndex].Tags, "generated")
			}

			if !bodyFound {
				selectedAction.Parameters = append(selectedAction.Parameters, WorkflowAppActionParameter{
					Name:  "body",
					Value: fixedBody,
					//Example: fixedBody,
					Tags: []string{"generated"},
				})
			}

			missingFields = RemoveFromArray(missingFields, "body")
		}

		break
	}

	// Finds WHERE in the destination to put the input data
	// Loops through input fields, then takes the data from them 
	if len(fieldFileContentMap) > 0 {
		log.Printf("\n\n[DEBUG] Found file content map (Reverse Schemaless): %#v\n\n", fieldFileContentMap)

		for key, mapValue := range fieldFileContentMap {
			if _, ok := mapValue.(string); !ok {
				log.Printf("[WARNING] Value for key %s is not a string: %#v", key, mapValue)
				continue
			}

			mappedFieldSplit := strings.Split(mapValue.(string), ".")
			if len(mappedFieldSplit) == 0 {
				log.Printf("[WARNING] Failed splitting value for key %s: %#v", key, mapValue)
				continue
			}

			// Finds the location
			for _, field := range value.Fields {
				if field.Key != key {
					continue
				}

				mapValue = field.Value
				break
			}

			// Check if the key exists in the parameters
			for paramIndex, param := range selectedAction.Parameters {
				if param.Name != mappedFieldSplit[0] {
					continue
				}

				foundIndex = paramIndex
				if param.Name == "queries" {
					if len(param.Value) == 0 {
						selectedAction.Parameters[paramIndex].Value = fmt.Sprintf("%s=%s", key, mapValue.(string))
					} else {
						selectedAction.Parameters[paramIndex].Value = fmt.Sprintf("%s&%s=%s", param.Value, key, mapValue.(string))
					}

					missingFields = RemoveFromArray(missingFields, key)
				} else if param.Name == "body" {

					log.Printf("\n\n\n[DEBUG] Found body field for file content: %s. Location: %#v, Value: %#v\n\n\n", key, strings.Join(mappedFieldSplit, "."), mapValue)

					newBody := param.Value

					mapToSearch := map[string]interface{}{}
					err := json.Unmarshal([]byte(newBody), &mapToSearch)
					if err != nil {
						log.Printf("[WARNING] Failed unmarshalling body for file content: %s. Body: %s", err, string(newBody))
						continue
					}

					// Finds where in the body the value should be placed
					location := strings.Join(mappedFieldSplit[1:], ".")
					outputMap := schemaless.MapValueToLocation(mapToSearch, location, mapValue.(string))

					// Marshal back to JSON
					marshalledMap, err := json.Marshal(outputMap)
					if err != nil {
						log.Printf("[WARNING] Failed marshalling body for file content: %s", err)
					} else {
						selectedAction.Parameters[paramIndex].Value = string(marshalledMap)
						missingFields = RemoveFromArray(missingFields, key)
					}
				} else {
					log.Printf("\n\n\n[DEBUG] Found map with actionParameter %s with value %s\n\n\n", param.Name, mapValue)
				}

				break
			}
		}
	}

	// AI fallback mechanism to handle missing fields
	// This is in case some fields are not sent in properly
	orgId := ""
	authorization := ""
	optionalExecutionId := ""
	if len(missingFields) > 0 {
		//log.Printf("\n\n\n[DEBUG] Missing fields for action: %#v\n\n\n", missingFields)

		formattedQueryFields := []string{}
		for _, missing := range missingFields {

			for _, field := range value.Fields {

				if field.Key != missing {
					continue
				}

				formattedQueryFields = append(formattedQueryFields, fmt.Sprintf("%s=%s", field.Key, field.Value))
				break
			}
		}

		//formattedQuery := fmt.Sprintf("Use any of the fields '%s' with app %s to '%s'.", strings.Join(formattedQueryFields, "&"), strings.ReplaceAll(selectedApp.Name, "_", " "), strings.ReplaceAll(value.Label, "_", " "))
		formattedQuery := fmt.Sprintf("Use the fields '%s' with app %s to '%s'.", strings.Join(formattedQueryFields, "&"), strings.ReplaceAll(selectedApp.Name, "_", " "), strings.ReplaceAll(value.Label, "_", " "))

		newQueryInput := QueryInput{
			Query:        formattedQuery,
			OutputFormat: "action", // To run the action (?)
			//OutputFormat: "action_parameters", 	// To get the action parameters back so we can run it manually

			//Label: value.Label,
			Category: value.Category,

			AppId:      selectedApp.ID,
			AppName:    selectedApp.Name,
			ActionName: selectedAction.Name,
			Parameters: selectedAction.Parameters,
		}

		// JSON marshal and send it back in to /api/conversation with type "action"
		marshalledBody, err := json.Marshal(newQueryInput)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling action: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Failed marshalling action"}`))
			return
		}

		//streamUrl = "http://localhost:5002"
		conversationUrl := fmt.Sprintf("%s/api/v1/conversation", baseUrl)

		// Check if "execution_id" & "authorization" queries exist
		if len(request.Header.Get("Authorization")) == 0 && len(request.URL.Query().Get("execution_id")) > 0 && len(request.URL.Query().Get("authorization")) > 0 {
			conversationUrl = fmt.Sprintf("%s?execution_id=%s&authorization=%s", conversationUrl, request.URL.Query().Get("execution_id"), request.URL.Query().Get("authorization"))
		}

		req, err := http.NewRequest(
			"POST",
			conversationUrl,
			bytes.NewBuffer(marshalledBody),
		)

		if err != nil {
			log.Printf("[WARNING] Error in new request for execute generated workflow: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed preparing new request. Contact support."}`)))
			return
		}

		log.Printf("[DEBUG] MISSINGFIELDS: %#v", missingFields)
		log.Printf("[DEBUG] LOCAL AI REQUEST SENT TO %s", conversationUrl)

		req.Header.Add("Authorization", request.Header.Get("Authorization"))
		req.Header.Add("Org-Id", request.Header.Get("Org-Id"))

		authorization = request.Header.Get("Authorization")
		orgId = request.Header.Get("Org-Id")

		newresp, err := client.Do(req)
		if err != nil {
			log.Printf("[WARNING] Error running body for execute generated workflow: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed running app %s (%s). Contact support."}`, selectedAction.Name, selectedAction.AppID)))
			return
		}

		defer newresp.Body.Close()
		responseBody, err := ioutil.ReadAll(newresp.Body)
		if err != nil {
			log.Printf("[WARNING] Failed reading body for execute generated workflow: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unmarshalling app response. Contact support."}`)))
			return
		}

		//log.Printf("\n\n[DEBUG] TRANSLATED REQUEST RETURNED: %s\n\n", string(responseBody))
		if strings.Contains(string(responseBody), `"success": false`) {
			log.Printf("[WARNING] Failed running app %s (%s). Contact support.", selectedAction.Name, selectedAction.AppID)
			resp.WriteHeader(500)
			resp.Write(responseBody)
			return
		}

		// Unmarshal responseBody back to
		newSecondAction := Action{}
		err = json.Unmarshal(responseBody, &newSecondAction)
		if err != nil {
			log.Printf("[WARNING] Failed unmarshalling body for execute generated workflow: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed parsing app response. Contact support if this persists."}`)))
			return
		}

		log.Printf("[DEBUG] Taking params and image from second action and adding to workflow")

		// FIXME: Image?
		//secondAction.Parameters = newSecondAction.Parameters
		//secondAction.LargeImage = newSecondAction.LargeImage
		secondAction.LargeImage = ""

		missingFields = []string{}
		for _, param := range newSecondAction.Parameters {
			if param.Configuration {
				continue
			}

			for paramIndex, originalParam := range secondAction.Parameters {
				if originalParam.Name != param.Name {
					continue
				}

				if len(param.Value) > 0 && param.Value != originalParam.Value {
					secondAction.Parameters[paramIndex].Value = param.Value
					secondAction.Parameters[paramIndex].Tags = param.Tags
				}

				//log.Printf("[INFO] Required - Key: %s, Value: %#v", param.Name, param.Value)
				if originalParam.Required && len(secondAction.Parameters[paramIndex].Value) == 0 {
					missingFields = append(missingFields, param.Name)
				}

				break
			}
		}
	}

	if value.SkipWorkflow {
		//log.Printf("[DEBUG] Skipping workflow generation, and instead attempting to directly run the action. This is only applicable IF the action is atomic (skip_workflow=true).")

		if len(missingFields) > 0 {
			log.Printf("[WARNING] Not all required fields were found in category action. Want: %#v", missingFields)
			resp.WriteHeader(400)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Not all required fields are set", "label": "%s", "missing_fields": "%s"}`, value.Label, strings.Join(missingFields, ","))))
			return
		}

		// FIXME: Make a check for IF we have filled in all fields or not
		for paramIndex, _ := range secondAction.Parameters {
			//if param.Configuration {
			//	continue
			//}
			//log.Printf("[DEBUG] Param: %s, Value: %s", param.Name, param.Value)
			secondAction.Parameters[paramIndex].Example = ""
		}

		//log.Printf("[DEBUG] App authentication: %#v", secondAction.AuthenticationId)
		preparedAction, err := json.Marshal(secondAction)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling action in category run for app %s: %s", secondAction.AppID, err)
			resp.WriteHeader(500)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed marshalling action"}`)))
			return
		}

		// FIXME: Delete disabled for now (April 2nd 2024)
		// This is due to needing debug capabilities
		if len(request.Header.Get("Authorization")) > 0 {
			tmpAuth := request.Header.Get("Authorization")

			if strings.HasPrefix(tmpAuth, "Bearer") {
				tmpAuth = strings.Replace(tmpAuth, "Bearer ", "", 1)
			}

			authorization = tmpAuth
		}

		// The app run url to use. Default delete is false
		shouldDelete := "false"
		apprunUrl := fmt.Sprintf("%s/api/v1/apps/%s/run?delete=%s", baseUrl, secondAction.AppID, shouldDelete)
		if len(request.Header.Get("Authorization")) == 0 && len(request.URL.Query().Get("execution_id")) > 0 && len(request.URL.Query().Get("authorization")) > 0 {
			apprunUrl = fmt.Sprintf("%s&execution_id=%s&authorization=%s", apprunUrl, request.URL.Query().Get("execution_id"), request.URL.Query().Get("authorization"))

			authorization = request.URL.Query().Get("authorization")
			optionalExecutionId = request.URL.Query().Get("execution_id")
		}

		if len(value.OrgId) > 0 {
			apprunUrl = fmt.Sprintf("%s&org_id=%s", apprunUrl, value.OrgId)
		}

		additionalInfo := ""
		inputQuery := ""
		originalAppname := selectedApp.Name

		// Add "execution-url" header with a full link
		//resp.Header().Add("execution-url", fmt.Sprintf("/workflows/%s?execution_id=%s", newWorkflow.ID, optionalExecutionId))
		resp.Header().Add("x-apprun-url", apprunUrl)

		// Runs attempts up to X times
		maxAttempts := 7
		for i := 0; i < maxAttempts; i++ {

			// Sends back how many translations happened
			// -url is just for the app to parse it :(
			attemptString := "x-translation-attempt-url"
			if _, ok := resp.Header()[attemptString]; ok {
				resp.Header().Set(attemptString, fmt.Sprintf("%d", i+1))
			} else {
				resp.Header().Add(attemptString, fmt.Sprintf("%d", i+1))
			}

			// The request that goes to the CORRECT app
			req, err := http.NewRequest(
				"POST",
				apprunUrl,
				bytes.NewBuffer(preparedAction),
			)

			if err != nil {
				log.Printf("[WARNING] Error in new request for execute generated app run: %s", err)
				resp.WriteHeader(500)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed preparing new request. Contact support."}`)))
				return
			}

			for key, value := range request.Header {
				if len(value) == 0 {
					continue
				}

				req.Header.Add(key, value[0])
			}

			newresp, err := client.Do(req)
			if err != nil {
				log.Printf("[WARNING] Error running body for execute generated app run: %s", err)
				resp.WriteHeader(500)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed running generated app. Contact support."}`)))
				return
			}

			// Ensures frontend has something to debug if things go wrong
			for key, value := range newresp.Header {
				if strings.HasSuffix(strings.ToLower(key), "-url") {

					// Remove old ones with the same key
					if _, ok := resp.Header()[key]; ok {
						resp.Header().Set(key, value[0])
					} else {
						resp.Header().Add(key, value[0])
					}
				}
			}

			defer newresp.Body.Close()
			apprunBody, err := ioutil.ReadAll(newresp.Body)
			if err != nil {
				log.Printf("[WARNING] Failed reading body for execute generated app run: %s", err)
				resp.WriteHeader(500)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unmarshalling app response. Contact support."}`)))
				return
			}

			// Input value to get raw output instead of translated
			if value.SkipOutputTranslation {
				resp.WriteHeader(202)
				resp.Write(apprunBody)
				return
			}

			httpOutput, marshalledBody, httpParseErr := FindHttpBody(apprunBody)
			parsedTranslation := SchemalessOutput{
				Success: false,
				Action:  value.Label,

				Status: httpOutput.Status,
				URL:    httpOutput.Url,
			}

			for _, param := range secondAction.Parameters {
				if param.Name == "body" && len(param.Value) > 0 {
					translatedBodyString := "x-translated-body-url"
					if _, ok := resp.Header()[translatedBodyString]; ok {
						resp.Header().Set(translatedBodyString, param.Value)
					} else {
						resp.Header().Add(translatedBodyString, param.Value)
					}
				}

				if param.Name == "queries" && len(param.Value) > 0 {
					translatedQueryString := "x-translated-query-url"
					if _, ok := resp.Header()[translatedQueryString]; ok {
						resp.Header().Set(translatedQueryString, param.Value)
					} else {
						resp.Header().Add(translatedQueryString, param.Value)
					}
				}
			}


			marshalledHttpOutput, marshalErr := json.Marshal(httpOutput)

			responseBodyString := "x-raw-response-url"
			if _, ok := resp.Header()[responseBodyString]; ok {
				resp.Header().Set(responseBodyString, string(marshalledHttpOutput))
			} else {
				resp.Header().Add(responseBodyString, string(marshalledHttpOutput))
			}

			if marshalErr == nil {

				if strings.HasPrefix(string(marshalledHttpOutput), "[") {
					outputArray := []interface{}{}
					err = json.Unmarshal(marshalledHttpOutput, &outputArray)
					if err != nil {
						log.Printf("[WARNING] Failed unmarshalling RAW list schemaless (3) output for label %s: %s", value.Label, err)

						parsedTranslation.RawResponse = string(marshalledHttpOutput)
					} else {
						parsedTranslation.RawResponse = outputArray
					}
				} else if strings.HasPrefix(string(marshalledHttpOutput), "{") {
					outputmap := map[string]interface{}{}
					err = json.Unmarshal(marshalledHttpOutput, &outputmap)
					if err != nil {
						log.Printf("[WARNING] Failed unmarshalling RAW {} schemaless (2) output for label %s: %s", value.Label, err)
					}

					parsedTranslation.RawResponse = outputmap
				} else {
					parsedTranslation.RawResponse = string(marshalledHttpOutput)
				}
			}

			if httpParseErr == nil && httpOutput.Status < 300 {
				log.Printf("[DEBUG] Found status from schemaless: %d. Should save the current fields as new base", httpOutput.Status)

				parsedParameterMap := map[string]interface{}{}
				for _, param := range secondAction.Parameters {
					if strings.Contains(param.Value, "&") && strings.Contains(param.Value, "=") {
						// Split by & and then by =
						parsedParameterMap[param.Name] = map[string]interface{}{}
						paramSplit := strings.Split(param.Value, "&")
						for _, paramValue := range paramSplit {
							paramValueSplit := strings.Split(paramValue, "=")
							if len(paramValueSplit) != 2 {
								continue
							}

							parsedParameterMap[param.Name].(map[string]interface{})[paramValueSplit[0]] = paramValueSplit[1]
						}
					} else {
						parsedParameterMap[param.Name] = param.Value
					}

					// FIXME: Skipping anything but body for now
					if param.Name != "body" {
						continue
					}

					err = uploadParameterBase(ctx, user.ActiveOrg.Id, selectedApp.ID, secondAction.Name, param.Name, param.Value)
					if err != nil {
						log.Printf("[WARNING] Failed uploading parameter base for %s: %s", param.Name, err)
					}
				}

				if len(fieldHash) > 0 && fieldFileFound == false {
					inputFieldMap := map[string]interface{}{}
					for _, field := range value.Fields {
						inputFieldMap[field.Key] = field.Value
					}

					// Finds location of some data in another part of the data. This is to have a predefined location in subsequent requests
					//log.Printf("\n\n\nREVERSE TRANSLATING FROM: %s\n\nTO: %s\n\n\n", parsedParameterMap, inputFieldMap)
					reversed, err := schemaless.ReverseTranslate(parsedParameterMap, inputFieldMap)
					//reversed, err := schemaless.ReverseTranslate(inputFieldMap, parsedParameterMap)
					if err != nil {
						log.Printf("[ERROR] Problem with reversing: %s", err)
					} else {
						log.Printf("[DEBUG] Raw reverse: %s", reversed)

						finishedFields := 0
						mappedFields := map[string]interface{}{}
						err = json.Unmarshal([]byte(reversed), &mappedFields)
						if err == nil {
							for _, value := range mappedFields {
								if _, ok := value.(string); ok && len(value.(string)) > 0 {
									finishedFields++
								} else {
									log.Printf("[DEBUG] Found non-string value: %#v", value)
								}
							}
						}

						log.Printf("Reversed fields (%d): %s", finishedFields, reversed)
						if finishedFields == 0 {
						} else {

							timeNow := time.Now().Unix()

							fileId := fmt.Sprintf("file_%s", fieldHash)
							encryptionKey := fmt.Sprintf("%s_%s", user.ActiveOrg.Id, fileId)
							folderPath := fmt.Sprintf("%s/%s/%s", basepath, user.ActiveOrg.Id, "global")
							downloadPath := fmt.Sprintf("%s/%s", folderPath, fileId)
							file := &File{
								Id:           fileId,
								CreatedAt:    timeNow,
								UpdatedAt:    timeNow,
								Description:  "",
								Status:       "active",
								Filename:     fmt.Sprintf("%s.json", fieldHash),
								OrgId:        user.ActiveOrg.Id,
								WorkflowId:   "global",
								DownloadPath: downloadPath,
								Subflows:     []string{},
								StorageArea:  "local",
								Namespace:    "translation_output",
								Tags: []string{
									"autocomplete",
								},
							}

							returnedId, err := uploadFile(ctx, file, encryptionKey, []byte(reversed))
							if err != nil {
								log.Printf("[ERROR] Problem uploading file: %s", err)
							} else {
								log.Printf("[DEBUG] Uploaded file with ID: %s", returnedId)
							}
						}
					}
				}
			} else {
				// Parses out data from the output
				// Reruns the app with the new parameters
				log.Printf("HTTP PARSE ERR: %#v", httpParseErr)
				if strings.Contains(strings.ToLower(fmt.Sprintf("%s", httpParseErr)), "status: ") {
					log.Printf("\n\n\n[DEBUG] Found status code in error: %s\n\n\n", err)

					outputString, outputAction, err, additionalInfo := FindNextApiStep(secondAction, apprunBody, additionalInfo, inputQuery, originalAppname)
					log.Printf("[DEBUG]\n==== AUTOCORRECT ====\nOUTPUTSTRING: %s\nADDITIONALINFO: %s", outputString, additionalInfo)

					// Rewriting before continuing
					// This makes the NEXT loop iterator run with the
					// output params from this one
					if err == nil && len(outputAction.Parameters) > 0 {
						log.Printf("[DEBUG] Found output action: %s", outputAction.Name)
						secondAction.Name = outputAction.Name
						secondAction.Label = outputAction.Label
						secondAction.Parameters = outputAction.Parameters
						secondAction.InvalidParameters = outputAction.InvalidParameters
						preparedAction, err = json.Marshal(outputAction)
						if err != nil {
							resp.WriteHeader(202)
							resp.Write(apprunBody)
							return
						}

						log.Printf("\n\nRUNNING WITH NEW PARAMS. Index: %d\n\n", i)
						continue

					} else {
						log.Printf("[ERROR] Problem in autocorrect (%d):\n%#v\nParams: %d", i, err, len(outputAction.Parameters))
						if i < maxAttempts-1 {
							continue
						}
					}
				}

				marshalledOutput, err := json.Marshal(parsedTranslation)
				if err != nil {
					log.Printf("[WARNING] Failed marshalling schemaless output for label %s: %s", value.Label, err)
					resp.WriteHeader(400)
					resp.Write(apprunBody)
					return
				}

				resp.WriteHeader(400)
				resp.Write(marshalledOutput)
				return
			}

			// Unmarshal responseBody back to secondAction
			// FIXME: add auth config to save translation files properly

			//streamUrl = fmt.Sprintf("%s&execution_id=%s&authorization=%s", streamUrl, request.URL.Query().Get("execution_id"), request.URL.Query().Get("authorization"))

			baseurlSplit := strings.Split(baseUrl, "/")
			if len(baseurlSplit) > 2 {
				// Only grab from https -> start of path
				baseUrl = strings.Join(baseurlSplit[0:3], "/")
			}

			authConfig := fmt.Sprintf("%s,%s,%s,%s", baseUrl, authorization, orgId, optionalExecutionId)

			//log.Printf("\n\n[DEBUG] BASEURL FOR SCHEMALESS: %s\nAUTHCONFIG: %s\n\n", streamUrl, authConfig)

			outputmap := make(map[string]interface{})
			schemalessOutput, err := schemaless.Translate(ctx, value.Label, marshalledBody, authConfig)
			if err != nil {
				log.Printf("[ERROR] Failed translating schemaless output for label '%s': %s", value.Label, err)

				/*
					err = json.Unmarshal(marshalledBody, &outputmap)
					if err != nil {
						log.Printf("[WARNING] Failed unmarshalling in schemaless (1) output for label %s: %s", value.Label, err)

					} else {
						parsedTranslation.Output = outputmap
					}
				*/
			} else {
				parsedTranslation.Success = true
				//parsedTranslation.RawOutput = string(schemalessOutput)

				err = json.Unmarshal(schemalessOutput, &outputmap)
				if err != nil {

					// If it's an array and not a map, we should try to unmarshal it as an array
					if strings.HasPrefix(string(schemalessOutput), "[") {
						outputArray := []interface{}{}
						err = json.Unmarshal(schemalessOutput, &outputArray)
						if err != nil {
							log.Printf("[WARNING] Failed unmarshalling schemaless (3) output for label %s: %s", value.Label, err)
						}

						parsedTranslation.Output = outputArray
						parsedTranslation.RawResponse = nil
					} else {
						log.Printf("[WARNING] Failed unmarshalling schemaless (2) output for label %s: %s", value.Label, err)
					}
				} else {
					parsedTranslation.Output = outputmap
					parsedTranslation.RawResponse = nil
				}
			}

			// Check if length of output exists. If it does, remove raw output
			//if len(parsedTranslation.Output) > 0 {
			//	parsedTranslation.RawOutput = ""
			//}

			marshalledOutput, err := json.Marshal(parsedTranslation)
			if err != nil {
				log.Printf("[WARNING] Failed marshalling schemaless output for label %s: %s", value.Label, err)
				resp.WriteHeader(202)
				resp.Write(schemalessOutput)
				return
			}

			resp.WriteHeader(200)
			resp.Write(marshalledOutput)

			return

		}

		log.Printf("\n\n\n[DEBUG] Done in autocorrect loop\n\n\n")
	}

	newWorkflow.Start = secondAction.ID
	newWorkflow.Actions = append(newWorkflow.Actions, secondAction)

	// Used to be where we stopped
	//resp.Write(responseBody)
	//resp.WriteHeader(200)
	//return
	/*
	*
	* Below is all the old stuff before we started doing atomic functions
	* the goal is now to make this a lot more dynamic and not have to
	* know everything beforehand
	*
	 */

	// Add params and such of course

	// Set workflow in cache only?
	// That way it can be loaded during execution

	if startNode.ID != "" {
		// Check if the workflow contains a trigger
		// If it doesn't, add one. Schedule or Webhook.
		// Default: schedule. Webhook is an option added

		triggersFound := 0
		for _, trigger := range newWorkflow.Triggers {
			if trigger.Name != "Shuffle Workflow" && trigger.Name != "User Input" {
				triggersFound++
			}
		}

		if triggersFound == 0 {

			decidedTrigger := Trigger{
				Name:        "Schedule",
				Status:      "uninitialized",
				TriggerType: "SCHEDULE",
				IsValid:     true,
				Label:       "Scheduler",
			}

			if strings.Contains(strings.ToLower(strings.Join(selectedApp.ReferenceInfo.Triggers, ",")), "webhook") {
				// Add a schedule trigger
				decidedTrigger = Trigger{
					Name:        "Webhook",
					Status:      "uninitialized",
					TriggerType: "WEBHOOK",
					IsValid:     true,
					Label:       "Webhook",
				}
			} else {
				// Check if it's CRUD (Read)
				// If it's List + schedule, we should add some kind of filter after 1st node

				// Check if startnode has "list" or "search" in it
				if strings.Contains(strings.ToLower(startNode.Name), "list") || strings.Contains(strings.ToLower(startNode.Name), "search") {
					log.Printf("[DEBUG] Found list/search in startnode name, adding filter after trigger? Can this be automatic?")
				}

			}

			decidedTrigger.ID = uuid.NewV4().String()
			decidedTrigger.Position = Position{
				X: startNode.Position.X - 200,
				Y: startNode.Position.Y,
			}
			decidedTrigger.AppAssociation = WorkflowApp{
				Name:       selectedApp.Name,
				AppVersion: selectedApp.AppVersion,
				ID:         selectedApp.ID,
				LargeImage: selectedApp.LargeImage,
			}

			newWorkflow.Triggers = append(newWorkflow.Triggers, decidedTrigger)
			// Add a branch from trigger to startnode
			newWorkflow.Branches = append(newWorkflow.Branches, Branch{
				SourceID:      decidedTrigger.ID,
				DestinationID: startNode.ID,
				ID:            uuid.NewV4().String(),
			})

			log.Printf("[DEBUG] Added trigger to the generated workflow")
		}
	}

	err = SetWorkflow(ctx, newWorkflow, newWorkflow.ID)
	if err != nil {
		log.Printf("[WARNING] Failed setting workflow during category run: %s", err)
	}

	/*
		workflowBytes, err := json.Marshal(newWorkflow)
		if err != nil {
			log.Printf("[WARNING] Failed marshal of workflow during cache setting: %s", err)
			resp.WriteHeader(400)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed packing workflow. Please try again and contact support if this persists."}`)))
			return
		}

		// Force it to ONLY be in cache? Means it times out.
		err = SetCache(ctx, fmt.Sprintf("workflow_%s", newWorkflow.ID), workflowBytes, 10)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for workflow during category run: %s", err)

			SetWorkflow(ctx, newWorkflow, newWorkflow.ID)
		}
	*/

	log.Printf("[DEBUG] Done preparing workflow '%s' (%s) to be ran for category action %s", newWorkflow.Name, newWorkflow.ID, selectedAction.Name)

	/*














	 */

	if value.DryRun {
		log.Printf("\n\n[DEBUG] Returning before execution because dry run is set\n\n")
		if len(startNode.ID) > 0 {
			log.Printf("[DEBUG] GOT STARTNODE: %s (%s)", startNode.Name, startNode.ID)
			// Find the action and set it as the new startnode
			// This works as the execution is already done
			for actionIndex, action := range newWorkflow.Actions {
				if action.ID == startNode.ID {
					newWorkflow.Start = startNode.ID
					newWorkflow.Actions[actionIndex].IsStartNode = true
				} else {
					newWorkflow.Actions[actionIndex].IsStartNode = false
				}
			}

			// Save the workflow
			err = SetWorkflow(ctx, newWorkflow, newWorkflow.ID)
			if err != nil {
				log.Printf("[WARNING] Failed saving workflow in run category action: %s", err)
			}
		}

		resp.Write([]byte(fmt.Sprintf(`{"success": true, "dry_run": true, "workflow_id": "%s", "reason": "Steps built, but workflow not executed"}`, newWorkflow.ID)))
		resp.WriteHeader(200)

		return
	}

	// FIXME: Make dynamic? AKA input itself is what controls the workflow?
	// E.g. for the "body", instead of having to know it's "body" we just have to know it's "input" and dynamically fill in based on execution args
	executionArgument := ""
	execData := ExecutionStruct{
		Start:             startId,
		ExecutionSource:   "ShuffleGPT",
		ExecutionArgument: executionArgument,
	}

	newExecBody, _ := json.Marshal(execData)

	// Starting execution
	/*
		baseUrl := fmt.Sprintf("https://shuffler.io")
		if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
			baseUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
		}

		if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
			baseUrl = fmt.Sprintf("%s", os.Getenv("SHUFFLE_CLOUDRUN_URL"))
		}
	*/

	workflowRunUrl := fmt.Sprintf("%s/api/v1/workflows/%s/execute", baseUrl, newWorkflow.ID)
	req, err := http.NewRequest(
		"POST",
		workflowRunUrl,
		bytes.NewBuffer(newExecBody),
	)
	if err != nil {
		log.Printf("[WARNING] Error in new request for execute generated workflow: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed preparing new request. Contact support."}`)))
		return
	}

	req.Header.Add("Authorization", request.Header.Get("Authorization"))
	newresp, err := client.Do(req)
	if err != nil {
		log.Printf("[WARNING] Error running body for execute generated workflow: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed running generated app. Contact support."}`)))
		return
	}

	defer newresp.Body.Close()
	executionBody, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		log.Printf("[WARNING] Failed reading body for execute generated workflow: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unmarshalling app response. Contact support."}`)))
		return
	}

	workflowExecution := WorkflowExecution{}
	err = json.Unmarshal(executionBody, &workflowExecution)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshalling body for execute generated workflow: %s", err)
	}

	if len(workflowExecution.ExecutionId) == 0 {
		log.Printf("[ERROR] Failed running the app. Raw: %s", string(executionBody))
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed running the app. Contact support@shuffler.io if this persists."}`)))
		return
	}

	returnBody := HandleRetValidation(ctx, workflowExecution, len(newWorkflow.Actions))
	selectedApp.LargeImage = ""
	selectedApp.Actions = []WorkflowAppAction{}
	structuredFeedback := StructuredCategoryAction{
		Success:     true,
		WorkflowId:  newWorkflow.ID,
		ExecutionId: workflowExecution.ExecutionId,
		Action:      "done",
		Category:    discoveredCategory,
		Reason:      "Analyze Result for details",

		Result: returnBody.Result,
	}

	jsonParsed, err := json.Marshal(structuredFeedback)
	if err != nil {
		log.Printf("[ERROR] Failed marshalling structured feedback: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed marshalling structured feedback (END)"}`))
		return
	}

	if len(startNode.ID) > 0 {
		log.Printf("[DEBUG] GOT STARTNODE: %s (%s)", startNode.Name, startNode.ID)
		// Find the action and set it as the new startnode
		// This works as the execution is already done
		for actionIndex, action := range newWorkflow.Actions {
			if action.ID == startNode.ID {
				newWorkflow.Start = startNode.ID
				newWorkflow.Actions[actionIndex].IsStartNode = true
			} else {
				newWorkflow.Actions[actionIndex].IsStartNode = false
			}
		}

		// Save the workflow
		err = SetWorkflow(ctx, newWorkflow, newWorkflow.ID)
		if err != nil {
			log.Printf("[WARNING] Failed saving workflow in run category action: %s", err)
		}
	}

	resp.WriteHeader(200)
	resp.Write(jsonParsed)
}

func GetActiveCategories(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just here to verify that the user is logged in
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in run category action: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
		return
	}

	ctx := GetContext(request)

	newapps, err := GetPrioritizedApps(ctx, user)
	if err != nil {
		log.Printf("[WARNING] Failed getting apps in category action: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed loading apps. Contact support@shuffler.io"}`))
		return
	}

	categories := GetAllAppCategories()
	//AppCategory{
	//	Name:         "Cases",
	//	Color:        "",
	//	Icon:         "cases",
	//	ActionLabels: []string{"Create ticket"},
	//	LabelApps: []AppCategoryLabel{
	//		AppCategoryLabel{
	//			Name: "Create ticket",
	//			Apps: []WorkflowApp{
	//			},
	//		}
	//	}
	//},

	// This is not fast, but ok with just a few hundred thousand iterations :>
	log.Printf("[INFO] Starting mapping of labels from all %d apps", len(newapps))
	for categoryIndex, _ := range categories {
		categories[categoryIndex].AppLabels = []AppLabel{}
	}
	/*
			for labelIndex, label := range category.ActionLabels {
				//categories[categoryIndex].LabelApps = append(categories[categoryIndex].LabelApps, AppCategoryLabel{
				//	Label:          label,
				//	FormattedLabel: strings.ReplaceAll(strings.ToLower(label), " ", "_"),
				//	Apps:           []WorkflowApp{},
				//})
			}
		}
	*/

	for _, app := range newapps {
		if len(app.Name) == 0 {
			continue
		}

		if len(app.Categories) == 0 {
			//log.Printf("[INFO] No categories: %#v (%s)", app.Name, app.ID)
			continue
		}

		appLabels := []string{}
		for _, action := range app.Actions {
			// Compare with formatted label
			if len(action.CategoryLabel) > 0 {
				//&& strings.ReplaceAll(strings.ToLower(action.CategoryLabel[0]), " ", "_") == categories[categoryIndex].LabelApps[labelIndex].FormattedLabel {
				appLabels = append(appLabels, action.CategoryLabel[0])

				//AppLabels    []AppCategoryLabel `json:"app_labels"`

			}
		}

		if len(appLabels) > 0 {
			log.Printf("[DEBUG] '%s' Got labels (%s): %#v", app.Name, app.Categories[0], appLabels)
			for categoryIndex, category := range categories {
				if strings.ToLower(category.Name) == strings.ToLower(app.Categories[0]) {
					newApp := AppLabel{
						AppName:    app.Name,
						LargeImage: app.LargeImage,
						ID:         app.ID,
					}

					// FIXME: May need to set the label to be the correct name according to the category's label
					for _, appLabel := range appLabels {
						newApp.Labels = append(newApp.Labels, LabelStruct{
							Category: category.Name,
							Label:    appLabel,
						})
					}

					categories[categoryIndex].AppLabels = append(categories[categoryIndex].AppLabels, newApp)
				}
			}
		}
	}

	newjson, err := json.Marshal(categories)
	if err != nil {
		log.Printf("[WARNING] Failed marshal in get categories: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking categories. Please try again."}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)

}

func HandleRecommendationAction(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in modify recommendation: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		http.Error(resp, "Error reading request body", http.StatusInternalServerError)
		return
	}

	var recommendation RecommendationAction
	err = json.Unmarshal(body, &recommendation)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshalling recommendation: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	availableActions := []string{"dismiss"}
	if !ArrayContains(availableActions, recommendation.Action) {
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Invalid action"}`))
		return
	}

	ctx := GetContext(request)
	org, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Failed getting org '%s': %s", user.ActiveOrg.Id, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting your org details"}`))
		return
	}

	changed := false
	for prioIndex, prio := range org.Priorities {
		if !prio.Active {
			continue
		}

		if prio.Name != recommendation.Name {
			//log.Printf("[DEBUG] '%s' is not '%s'", prio.Name, recommendation.Name)
			continue
		}

		// dismiss first, other later :)
		if recommendation.Action == "dismiss" {
			org.Priorities[prioIndex].Active = false
			changed = true
			break
		}
	}

	if changed {
		err = SetOrg(ctx, *org, org.Id)
		if err != nil {
			log.Printf("[WARNING] Failed updating org during priority updates: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": true}`))
			return
		}
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

// Hard-coded to test out how we can generate next steps in workflows
// This could actually work when mapped back to usecases & with LLMs

// Mainly tested with Outlook Office365 for now
// Should be made based on:
// - Usecases and their structure
// - Active Apps (framework~)
// - LLMs
func HandleActionRecommendation(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Disabled until it gets improved enough to work onprem
	// Should be automatically built into the dockerfile of the backend onprem
	// Point with cloud download it to have it regularly updated
	if project.Environment != "cloud" {
		resp.WriteHeader(200)
		resp.Write([]byte(`{"success": true, "reason": "Not yet enabled. Contact support@shuffler.io to learn more about progress on this API."}`))
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in get action recommendations: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Get the users' org
	ctx := GetContext(request)
	org, err := GetOrg(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Failed getting org '%s': %s", user.ActiveOrg.Id, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting your org details"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		http.Error(resp, "Error reading request body", http.StatusInternalServerError)
		return
	}

	var workflow Workflow
	workflowerr := json.Unmarshal(body, &workflow)
	if workflowerr != nil {
		log.Printf("[WARNING] Failed unmarshalling workflow: %s", workflowerr)
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Need apps to check against
	// These are also the only ones we're able to recommend from
	// Using the app framework + these we can generate recommendations :)
	apps, err := GetPrioritizedApps(ctx, user)
	if err != nil {
		log.Printf("[WARNING] Failed getting apps during node suggestion validation: %s", err)
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(`{"success": false, "reason": "Failed to fetch recommendation data"}`))
		return
	}

	// Load in node relations
	nodeRelations, err := GetNodeRelations(ctx)
	if err != nil {
		log.Printf("[WARNING] Failed getting node relations: %s", err)
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(`{"success": false, "reason": "Failed to fetch recommendation data"}`))
		return
	}

	var recommendAction ActionRecommendations
	if len(workflow.Actions) == 0 {
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte(`{"success": false, "reason": "No actions in workflow"}`))
		return
	}

	// Because this usually means "formatting"
	skippable := []string{"repeat_back_to_me"}

	// More testing based on node relation output
	// Goal with this is to test singular node connections
	// Next step: Use multi-step checks to improve further
	for key, inputAction := range workflow.Actions {
		var recommendations []Recommendations
		var action RecommendAction

		app := workflow.Actions[key].AppName + "_" + workflow.Actions[key].AppVersion
		_ = app

		// Check if there is any label for the current action we're using
		//log.Printf("App: %s", app)

		foundApp := WorkflowApp{}
		if len(inputAction.CategoryLabel) == 0 {
			for _, app := range apps {
				if app.Name != inputAction.AppName && app.ID != inputAction.AppID {
					continue
				}

				foundApp = app

				if foundApp.Name == "Shuffle Tools" {
					inputAction.CategoryLabel = []string{inputAction.Name}
					break
				}

				// Look for the correct action
				//log.Printf("Found app %s", app.Name)
				for _, action := range app.Actions {
					if action.Name == inputAction.Name {
						//log.Printf("Found action %s", action.Name)

						if len(action.CategoryLabel) > 0 {
							inputAction.CategoryLabel = action.CategoryLabel
							break
						}
					}
				}

				break
			}
		}

		if len(inputAction.CategoryLabel) == 0 {
			//log.Printf("No labels for action %s in app %s", inputAction.Name, inputAction.AppName)
			continue
		}

		//log.Printf("Action %s (%s) has %d labels: %#v", inputAction.Name,foundApp.Name,  len(inputAction.CategoryLabel), inputAction.CategoryLabel)
		parsedCategory := strings.ToLower(strings.Replace(inputAction.CategoryLabel[0], " ", "_", -1))
		// Check synonyms
		for key, node := range nodeRelations {
			if len(node.Synonyms) == 0 {
				continue
			}

			for _, synonym := range node.Synonyms {
				if synonym == parsedCategory {
					log.Printf("[DEBUG] Found new synonym '%s' for '%s'", synonym, parsedCategory)
					parsedCategory = key
					break
				}
			}

			if parsedCategory == key {
				break
			}
		}

		// Specific parsing
		if parsedCategory == "repeat_back_to_me" {
			continue
		}

		//log.Printf("Looking for category: %s", parsedCategory)
		for category, categoryValue := range nodeRelations {
			//log.Printf("Checking category %s vs %s", category, parsedCategory)
			if category != parsedCategory {
				continue
			}

			// Choose first 2 outgoing nodes
			for cnt, outgoing := range categoryValue.Outgoing {
				//log.Printf("Found outgoing %s:%d", outgoing.Name, outgoing.Count)
				categoryname := outgoing.Name
				if ArrayContains(skippable, categoryname) {
					continue
				}

				// Check if categoryname in nodeRelations map
				foundAppType := ""
				if foundWrapper, ok := nodeRelations[categoryname]; ok {
					foundAppType = foundWrapper.AppCategory
				} else {
					log.Printf("No node relations for %s", categoryname)
					continue
				}

				recommendation := Recommendations{}
				if foundAppType == "tools" {
					recommendation = Recommendations{
						AppName:    "Shuffle Tools",
						AppAction:  outgoing.Name,
						AppVersion: "1.2.0",
						AppId:      "bc78f35c6c6351b07a09b7aed5d29652",
					}
				} else if categoryname == "subflow" {
					recommendation = Recommendations{
						AppName:    "Shuffle Subflow",
						AppVersion: "1.1.0",
						AppAction:  "subflow",
						AppId:      "a891257fcf905c2d256ce5674282864c",
					}
				} else {
					log.Printf("[DEBUG] Found app category %s for category %s", foundAppType, categoryname)
					foundCategory := Category{}

					if foundAppType == "cases" {
						foundCategory = org.SecurityFramework.Cases
					} else if foundAppType == "communication" {
						foundCategory = org.SecurityFramework.Communication
					} else if foundAppType == "assets" {
						foundCategory = org.SecurityFramework.Assets
					} else if foundAppType == "network" {
						foundCategory = org.SecurityFramework.Network
					} else if foundAppType == "intel" {
						foundCategory = org.SecurityFramework.Intel
					} else if foundAppType == "edr" {
						foundCategory = org.SecurityFramework.EDR
					} else if foundAppType == "iam" {
						foundCategory = org.SecurityFramework.IAM
					} else if foundAppType == "siem" {
						foundCategory = org.SecurityFramework.SIEM
					} else {
						//foundCategory = org.SecurityFramework.Other
					}

					if foundCategory.Name == "" {
						log.Printf("[ERROR] No app found for category %s", categoryname)
						continue
					}

					// TODO: Find the name of the action in the app that has the category label
					foundAction := WorkflowAppAction{}
					for _, action := range foundApp.Actions {
						if len(action.CategoryLabel) == 0 {
							continue
						}

						// make all labels lowercase and with underscore
						newLabels := []string{}
						for _, label := range action.CategoryLabel {
							newLabels = append(newLabels, strings.ToLower(strings.Replace(label, " ", "_", -1)))
						}

						if ArrayContains(newLabels, categoryname) {
							foundAction = action
							break
						}
					}

					if foundAction.Name == "" {
						log.Printf("[ERROR] No action explainer found for category '%s'", categoryname)
					} else {
						log.Printf("Found action %s for category %s", foundAction.Name, categoryname)
					}

					recommendation = Recommendations{
						AppName:   foundCategory.Name,
						AppId:     foundCategory.ID,
						AppAction: foundAction.Name,
					}
				}

				if recommendation.AppName != "" {
					recommendations = append(recommendations, recommendation)
				}

				if cnt == 1 {
					break
				}
			}

			break
		}

		//log.Printf("[DEBUG] Found %d recommendations for action %s", len(recommendations), inputAction.Name)
		action.ActionId = inputAction.ID
		action.AppName = inputAction.AppName
		action.Recommendations = recommendations
		recommendAction.Actions = append(recommendAction.Actions, action)
	}

	recommendAction.Success = true
	newjson, err := json.Marshal(recommendAction)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal recommendedAction: %s", err)
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)

}

func HandleGetenvStats(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get env stats executions: %s", err)
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

	ctx := GetContext(request)
	environmentName := fileId
	if len(fileId) != 36 {
		log.Printf("[DEBUG] Environment length %d for %s is not good for env Stats. Attempting to find the actual ID for it", len(fileId), fileId)

		environments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("[WARNING] Failed getting environments to validate: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed to validate environment"}`))
			return
		}

		for _, environment := range environments {
			if environment.Name == fileId && len(environment.Id) > 0 {
				environmentName = fileId
				fileId = environment.Id
				break
			}
		}

		if len(fileId) != 36 {
			log.Printf("[WARNING] Failed getting environments to validate. New FileId: %s", fileId)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed getting environment for ID %s"}`, fileId)))
			return
		}
	}

	// Should get stats for this
	_ = environmentName

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true}`)))
}

func GetWorkflowSuggestions(ctx context.Context, user User, org *Org, orgUpdated bool, amount int) (*Org, bool) {
	// Loop workflows

	//if amount > 3 {
	//	log.Printf("[WARNING] Amount of suggestions is too high: %d", amount)
	//	return org, orgUpdated
	//}

	// 1. Suggest based on usecases
	// 2. Suggest public workflows (cloud)
	// 3. Use workflow template (local)
	var updated bool
	workflows, err := GetAllWorkflowsByQuery(ctx, user)
	if err != nil {
		log.Printf("[WARNING] No workflows found for user %s (2)", user.Id)
		return org, orgUpdated
	}

	//log.Printf("[INFO] Finding workflow suggestions for %s (%s) based on %d workflows", org.Name, org.Id, len(workflows))
	for _, workflow := range workflows {
		for _, action := range workflow.Actions {
			if len(action.Category) == 0 {
				continue
			}

			//log.Printf("%s:%s = %s", action.AppName, action.AppVersion, action.Category)
			if org.SecurityFramework.Communication.Name == "" && (action.Category == "Communication" || action.Category == "email") {
				orgUpdated = true
				org.SecurityFramework.Communication = Category{
					Name:        action.AppName,
					Count:       1,
					Description: "",
					LargeImage:  action.LargeImage,
					ID:          action.AppID,
				}
			}

			if org.SecurityFramework.Intel.Name == "" && action.Category == "Intel" {
				orgUpdated = true
				org.SecurityFramework.Intel = Category{
					Name:        action.AppName,
					Count:       1,
					Description: "",
					LargeImage:  action.LargeImage,
					ID:          action.AppID,
				}
			}

			if org.SecurityFramework.Network.Name == "" && action.Category == "Network" {
				orgUpdated = true
				org.SecurityFramework.Network = Category{
					Name:        action.AppName,
					Count:       1,
					Description: "",
					LargeImage:  action.LargeImage,
					ID:          action.AppID,
				}
			}

			if org.SecurityFramework.Assets.Name == "" && action.Category == "Assets" {
				orgUpdated = true
				org.SecurityFramework.Assets = Category{
					Name:        action.AppName,
					Count:       1,
					Description: "",
					LargeImage:  action.LargeImage,
					ID:          action.AppID,
				}
			}

			if org.SecurityFramework.Cases.Name == "" && action.Category == "Cases" {
				orgUpdated = true
				org.SecurityFramework.Cases = Category{
					Name:        action.AppName,
					Count:       1,
					Description: "",
					LargeImage:  action.LargeImage,
					ID:          action.AppID,
				}
			}

			if org.SecurityFramework.SIEM.Name == "" && action.Category == "SIEM" {
				orgUpdated = true
				org.SecurityFramework.SIEM = Category{
					Name:        action.AppName,
					Count:       1,
					Description: "",
					LargeImage:  action.LargeImage,
					ID:          action.AppID,
				}
			}

			if org.SecurityFramework.EDR.Name == "" && action.Category == "EDR" {
				orgUpdated = true
				org.SecurityFramework.EDR = Category{
					Name:        action.AppName,
					Count:       1,
					Description: "",
					LargeImage:  action.LargeImage,
					ID:          action.AppID,
				}
			}

			if org.SecurityFramework.IAM.Name == "" && action.Category == "IAM" {
				orgUpdated = true
				org.SecurityFramework.IAM = Category{
					Name:        action.AppName,
					Count:       1,
					Description: "",
					LargeImage:  action.LargeImage,
					ID:          action.AppID,
				}
			}
		}
	}

	// Checking again to see if specifying either should be a priority
	missingType := ""
	amountDone := 0
	if missingType == "" && org.SecurityFramework.SIEM.Name == "" {
		missingType = "SIEM"
		amountDone = 1
	} else if missingType == "" && org.SecurityFramework.Communication.Name == "" {
		missingType = "Email"
		amountDone = 2
	} else if missingType == "" && org.SecurityFramework.EDR.Name == "" {
		missingType = "EDR"
		amountDone = 3
	} else if missingType == "" && org.SecurityFramework.Cases.Name == "" {
		missingType = "Cases"
		amountDone = 4
	} else if missingType == "" && org.SecurityFramework.Intel.Name == "" {
		missingType = "Intel"
		amountDone = 5
	} else if missingType == "" && org.SecurityFramework.Network.Name == "" {
		missingType = "Network"
		amountDone = 6
	} else if missingType == "" && org.SecurityFramework.Assets.Name == "" {
		missingType = "Assets"
		amountDone = 7
	} else if missingType == "" && org.SecurityFramework.IAM.Name == "" {
		missingType = "IAM"
		amountDone = 8
	}

	if len(missingType) > 0 {
		org, updated = AddPriority(*org, Priority{
			Name:        fmt.Sprintf("Your Organizations' %s App hasn't been specified (%d/8)", missingType, amountDone),
			Description: fmt.Sprintf("Your %s system should be specified to enable us to suggest relevant usecases to you", missingType),
			Type:        "apps",
			Active:      true,
			URL:         fmt.Sprintf("/welcome?tab=2&target=%s", missingType),
			Severity:    3,
		}, updated)

		if updated {
			orgUpdated = true
		}
	}
	//org.SecurityFramework.EDR.Name == "" || org.SecurityFramework.Communication.Name == "" {

	// Checking which workflows SHOULD have a usecase attached to them
	for _, workflow := range workflows {
		if len(workflow.UsecaseIds) != 0 {
			continue
		}

		//log.Printf("[INFO] No usecase for workflow %s", workflow.Name)

		// Sample: If email (get/trigger) & cases (create ticket) in same workflow -> email usecase = done
		// If excel/sheets is used, reporting
		// Add keywords to usecases? Check if anything matching in:
		// - name
		// - action name
		// - action label(s)
		// - action description
	}

	// Matching org priority with usecases & previously built workflows
	usecasesAdded := 0
	for _, orgPriority := range org.Priorities {
		if orgPriority.Type != "usecase" || !orgPriority.Active {
			continue
		}

		usecasesAdded += 1
	}

	var usecases UsecaseLinks
	err = json.Unmarshal([]byte(GetUsecaseData()), &usecases)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal usecase data (priorities): %s", err)
	} else {
		//log.Printf("[DEBUG] Got parsed usecases for %s - should check priority vs mainpriority (%s)", org.Name, org.MainPriority)

		selectedAppName := ""
		selectedAppImage := ""
		innerUpdate := false
		for usecaseIndex, usecase := range usecases {
			//if usecase.Name != org.MainPriority {
			//	continue
			//}

			// match them with usecases here
			for _, workflow := range workflows {
				if len(workflow.UsecaseIds) == 0 {
					continue
				}

				// Fidning matching usecase for workflow
				for _, workflowUsecase := range workflow.UsecaseIds {
					newUsecasename := strings.ToLower(workflowUsecase)

					for subusecaseIndex, subusecase := range usecase.List {
						if newUsecasename == strings.ToLower(subusecase.Name) {
							usecases[usecaseIndex].List[subusecaseIndex].Matches = append(usecases[usecaseIndex].List[subusecaseIndex].Matches, workflow)
							break
						}
					}
				}
			}

			// Sort sub-usecases by priority
			slice.Sort(usecase.List[:], func(i, j int) bool {
				return usecase.List[i].Priority > usecase.List[j].Priority
			})

			//log.Printf("[DEBUG] Priorities for %s", usecase.Name)
			cntAdded := 0
			for _, subusecase := range usecase.List {
				// Matches = matching usecases that have workflows attached to them
				// This means if it exists, don't add it as priority
				if len(subusecase.Matches) > 0 {
					continue
				}

				if strings.ToLower(subusecase.Type) == "iam" {
					if org.SecurityFramework.IAM.Name == "" {
						continue
					}

					selectedAppName = org.SecurityFramework.IAM.Name
					selectedAppImage = org.SecurityFramework.IAM.LargeImage
				}

				if strings.ToLower(subusecase.Type) == "siem" {
					if org.SecurityFramework.SIEM.Name == "" {
						continue
					}

					selectedAppName = org.SecurityFramework.SIEM.Name
					selectedAppImage = org.SecurityFramework.SIEM.LargeImage
				}

				if strings.ToLower(subusecase.Type) == "edr" {
					if org.SecurityFramework.EDR.Name == "" {
						continue
					}

					selectedAppName = org.SecurityFramework.EDR.Name
					selectedAppImage = org.SecurityFramework.EDR.LargeImage
				}

				if strings.ToLower(subusecase.Type) == "communication" {
					if org.SecurityFramework.Communication.Name == "" {
						continue
					}

					selectedAppName = org.SecurityFramework.Communication.Name
					selectedAppImage = org.SecurityFramework.Communication.LargeImage
				}

				if strings.ToLower(subusecase.Type) == "assets" {
					if org.SecurityFramework.Assets.Name == "" {
						continue
					}

					selectedAppName = org.SecurityFramework.Assets.Name
					selectedAppImage = org.SecurityFramework.Assets.LargeImage
				}

				if strings.ToLower(subusecase.Type) == "cases" {
					if org.SecurityFramework.Cases.Name == "" {
						continue
					}

					selectedAppName = org.SecurityFramework.Cases.Name
					selectedAppImage = org.SecurityFramework.Cases.LargeImage
				}

				if strings.ToLower(subusecase.Type) == "network" {
					if org.SecurityFramework.Network.Name == "" {
						continue
					}

					selectedAppName = org.SecurityFramework.Network.Name
					selectedAppImage = org.SecurityFramework.Network.LargeImage
				}

				if strings.ToLower(subusecase.Type) == "intel" {
					if org.SecurityFramework.Intel.Name == "" {
						continue
					}

					selectedAppName = org.SecurityFramework.Intel.Name
					selectedAppImage = org.SecurityFramework.Intel.LargeImage
				}

				usecaseDescription := "A priority usecase for your organization has been found. Click explore to learn more."
				if len(selectedAppName) > 0 && len(selectedAppImage) > 0 && subusecase.Type != subusecase.Last {
					usecaseDescription = fmt.Sprintf("%s&%s", strings.Replace(selectedAppName, "_", " ", -1), selectedAppImage)

					// Adding "last" node as well
					if strings.ToLower(subusecase.Last) == "iam" && org.SecurityFramework.IAM.Name != "" && org.SecurityFramework.IAM.LargeImage != "" {
						usecaseDescription = fmt.Sprintf("%s&%s&%s", usecaseDescription, strings.Replace(org.SecurityFramework.IAM.Name, "_", " ", -1), org.SecurityFramework.IAM.LargeImage)
					} else if strings.ToLower(subusecase.Last) == "siem" && org.SecurityFramework.SIEM.Name != "" && org.SecurityFramework.SIEM.LargeImage != "" {
						usecaseDescription = fmt.Sprintf("%s&%s&%s", usecaseDescription, strings.Replace(org.SecurityFramework.SIEM.Name, "_", " ", -1), org.SecurityFramework.SIEM.LargeImage)
					} else if strings.ToLower(subusecase.Last) == "edr" && org.SecurityFramework.EDR.Name != "" && org.SecurityFramework.EDR.LargeImage != "" {
						usecaseDescription = fmt.Sprintf("%s&%s&%s", usecaseDescription, strings.Replace(org.SecurityFramework.EDR.Name, "_", " ", -1), org.SecurityFramework.EDR.LargeImage)
					} else if strings.ToLower(subusecase.Last) == "communication" && org.SecurityFramework.Communication.Name != "" && org.SecurityFramework.Communication.LargeImage != "" {
						usecaseDescription = fmt.Sprintf("%s&%s&%s", usecaseDescription, strings.Replace(org.SecurityFramework.Communication.Name, "_", " ", -1), org.SecurityFramework.Communication.LargeImage)
					} else if strings.ToLower(subusecase.Last) == "assets" && org.SecurityFramework.Assets.Name != "" && org.SecurityFramework.Assets.LargeImage != "" {
						usecaseDescription = fmt.Sprintf("%s&%s&%s", usecaseDescription, strings.Replace(org.SecurityFramework.Assets.Name, "_", " ", -1), org.SecurityFramework.Assets.LargeImage)
					} else if strings.ToLower(subusecase.Last) == "cases" && org.SecurityFramework.Cases.Name != "" && org.SecurityFramework.Cases.LargeImage != "" {
						usecaseDescription = fmt.Sprintf("%s&%s&%s", usecaseDescription, strings.Replace(org.SecurityFramework.Cases.Name, "_", " ", -1), org.SecurityFramework.Cases.LargeImage)
					} else if strings.ToLower(subusecase.Last) == "network" && org.SecurityFramework.Network.Name != "" && org.SecurityFramework.Network.LargeImage != "" {
						usecaseDescription = fmt.Sprintf("%s&%s&%s", usecaseDescription, strings.Replace(org.SecurityFramework.Network.Name, "_", " ", -1), org.SecurityFramework.Network.LargeImage)
					} else if strings.ToLower(subusecase.Last) == "intel" && org.SecurityFramework.Intel.Name != "" && org.SecurityFramework.Intel.LargeImage != "" {
						usecaseDescription = fmt.Sprintf("%s&%s&%s", usecaseDescription, strings.Replace(org.SecurityFramework.Intel.Name, "_", " ", -1), org.SecurityFramework.Intel.LargeImage)
					}
				} else if len(subusecase.Last) > 0 && subusecase.Type == subusecase.Last {
					usecaseDescription = fmt.Sprintf("%s&%s&%s:default&", strings.Replace(selectedAppName, "_", " ", -1), selectedAppImage, subusecase.Last)
				}

				usecaseDescription += "&" + subusecase.Description

				// Should find info about the usecase
				// No description as this has custom rendering
				org, innerUpdate = AddPriority(*org, Priority{
					Name:        fmt.Sprintf("Suggested Usecase: %s", subusecase.Name),
					Description: usecaseDescription,
					Type:        "usecase",
					Active:      true,
					URL:         fmt.Sprintf("/usecases?selected_object=%s", subusecase.Name),
					Severity:    3,
				}, updated)

				if innerUpdate {
					//log.Printf("[DEBUG] Org %s (%s) got the priority for Usecase '%s' added. Added: %d", org.Name, org.Id, subusecase.Name, usecasesAdded)

					cntAdded += 1
					orgUpdated = true

					usecasesAdded += 1
					if usecasesAdded >= 3 {
						break
					}
				}
			}

			if innerUpdate && usecasesAdded >= 3 {
				break
			}
		}
	}

	if usecasesAdded < 3 {
		//log.Printf("[DEBUG] Should check if workflows still are the same amount or not to change priorities")

		// Check all existing priorities if they should still be closed, or reopened
		for prioIndex, priority := range org.Priorities {
			if priority.Type != "usecase" || priority.Active == true {
				continue
			}

			// Check if the usecase is still in the workflow list
			usecaseName := strings.ReplaceAll(priority.Name, "Suggested Usecase: ", "")

			found := false
			for _, workflow := range workflows {
				for _, usecase := range workflow.UsecaseIds {
					if usecase == usecaseName {
						found = true
						break
					}
				}

				if found {
					break
				}
			}

			if !found {
				if usecasesAdded < 3 {
					usecasesAdded += 1
					orgUpdated = true
					org.Priorities[prioIndex].Active = true
				} else {
					break
				}
			}
		}
	}

	//if usecasesAdded <= 3 {
	//	return GetWorkflowSuggestions(ctx, user, org, orgUpdated, amount+1)
	//}

	if usecasesAdded < 3 {
		//log.Printf("\n\n[DEBUG] Should generate priorities for org %s (%s) based on purely numbers\n\n", org.Name, org.Id)

		newPrios := []Priority{
			Priority{
				Name:        "Suggested Usecase: SIEM to ticket",
				Description: "siem:default&&cases:default&&SIEM to ticket is a usecase that is very common in most organizations. It is a usecase that is very important to get right, as it is the most common way for attackers to get into your organization.",
				Type:        "usecase",
				Active:      true,
				URL:         "/usecases?selected_object=SIEM to ticket",
				Severity:    3,
			}, Priority{
				Name:        "Suggested Usecase: Email management",
				Description: "edr:default&&cases:default&&Email management is a usecase that is very common in most organizations. It is a usecase that is very important to get right, as it is the most common way for attackers to get into your organization.",
				Type:        "usecase",
				Active:      true,
				URL:         "/usecases?selected_object=Email management",
				Severity:    3,
			}, Priority{
				Name:        "Suggested Usecase: EDR to ticket",
				Description: "communication:default&&cases:default&&EDR to ticket is a usecase that is very common in most organizations. It is a usecase that is very important to get right, as it is the most common way for attackers to get into your organization.",
				Type:        "usecase",
				Active:      true,
				URL:         "/usecases?selected_object=EDR to ticket",
				Severity:    3,
			},
		}

		for _, prio := range newPrios {
			prioName := strings.ToLower(strings.ReplaceAll(prio.Name, "Suggested Usecase: ", ""))
			found := false
			for _, existingPrio := range org.Priorities {
				if strings.Contains(strings.ToLower(strings.ReplaceAll(existingPrio.Name, "Suggested Usecase: ", "")), prioName) {
					//log.Printf("[DEBUG] Org %s (%s) already has the priority for Usecase '%s' added. Added: %d", org.Name, org.Id, prio.Name, usecasesAdded)
					found = true
					break
				}
			}

			if !found {
				org.Priorities = append(org.Priorities, prio)

				usecasesAdded += 1

				// Force not org update due to this being temporary
				orgUpdated = false
				if usecasesAdded >= 3 {
					break
				}
			}
		}
	} else {
		//log.Printf("[DEBUG] Org %s (%s) already has the priorities added. Added: %d", org.Name, org.Id, usecasesAdded)
	}

	return org, orgUpdated
}

func GetWorkflowRevisions(resp http.ResponseWriter, request *http.Request) {
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

	ctx := GetContext(request)
	workflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Workflow %s doesn't exist.", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed finding workflow"}`))
		return
	}

	// Check workflow.Sharing == private / public / org  too
	if user.Id != workflow.Owner || len(user.Id) == 0 {
		// Added org-reader as the user should be able to read everything in an org
		//if workflow.OrgId == user.ActiveOrg.Id && (user.Role == "admin" || user.Role == "org-reader") {
		if workflow.OrgId == user.ActiveOrg.Id {
			log.Printf("[AUDIT] User %s is accessing workflow %s as admin (get workflow revisions)", user.Username, workflow.ID)

			// Only for Read-Only. No executions or impersonations.
		} else if project.Environment == "cloud" && user.Verified == true && user.Active == true && user.SupportAccess == true && strings.HasSuffix(user.Username, "@shuffler.io") {
			log.Printf("[AUDIT] Letting verified support admin %s access workflow revisions for %s", user.Username, workflow.ID)

		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (get workflow revisions). Verified: %t, Active: %t, SupportAccess: %t, Username: %s", user.Username, workflow.ID, user.Verified, user.Active, user.SupportAccess, user.Username)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	// Access is granted -> get revisions
	revisions, err := ListWorkflowRevisions(ctx, workflow.ID)
	if err != nil {
		log.Printf("[WARNING] Failed getting revisions for workflow %s: %s", workflow.ID, err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	body, err := json.Marshal(revisions)
	if err != nil {
		log.Printf("[WARNING] Failed workflow GET marshalling: %s", err)
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(body)
}

func HandleDeleteOrg(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Checking if it's a special region. All user-specific requests should
	// go through shuffler.io and not subdomains
	if project.Environment == "cloud" {
		gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
		if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
			log.Printf("[DEBUG] Redirecting GET ORG request to main site handler (shuffler.io)")
			RedirectUserRequest(resp, request)
			return
		}
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

	if strings.Contains(fileId, "?") {
		fileId = strings.Split(fileId, "?")[0]
	}

	ctx := GetContext(request)
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in DELETING specific org: %s. Continuing because it may be public.", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role != "admin" {
		log.Printf("[WARNING] Not admin: %s (%s).", user.Username, user.Id)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Not admin"}`))
		return
	}

	org, err := GetOrg(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Failed getting org '%s': %s", fileId, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting org details"}`))
		return
	}

	foundAdmin := false
	for _, orgUser := range org.Users {
		if user.Username == orgUser.Username && orgUser.Role == "admin" {
			foundAdmin = true
			break
		}
	}

	if !foundAdmin {
		log.Printf("[WARNING] User %s is not an admin of org %s", user.Username, org.Name)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Not admin of org"}`))
		return
	}

	// Check if it's a suborg
	if len(org.ManagerOrgs) == 0 || len(org.ChildOrgs) > 0 {
		log.Printf("[WARNING] Org '%s' is NOT a suborg. Not deleting.", fileId)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Org is not a suborg"}`))
		return
	}

	// Get workflows
	user.ActiveOrg.Id = org.Id
	user.ActiveOrg.Name = org.Name
	workflows, err := GetAllWorkflowsByQuery(ctx, user)
	if err != nil {
		log.Printf("[WARNING] Failed getting workflows for user %s (0): %s", user.Username, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting workflows"}`))
		return
	}

	// Return if workflows, as they should be deleted beforehand
	if len(workflows) > 0 {
		log.Printf("[WARNING] Org '%s' has %d workflow(s). Not deleting.", fileId, len(workflows))
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Org still has workflows. Delete them first by listing the /api/v1/workflows API."}`))
		return
	}

	// Delete the org
	err = DeleteKey(ctx, "Organizations", fileId)
	if err != nil {
		log.Printf("[WARNING] Failed deleting org '%s': %s", fileId, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed deleting org"}`))
		return
	}

	newOrgString := []string{}
	for _, orgId := range user.Orgs {
		if orgId != fileId {
			newOrgString = append(newOrgString, orgId)
		}
	}

	user.Orgs = newOrgString
	newOrg := ""
	if len(org.ManagerOrgs) > 0 {
		if ArrayContains(user.Orgs, org.ManagerOrgs[0].Id) {
			newOrg = org.ManagerOrgs[0].Id
		} else {
			if len(user.Orgs) > 0 {
				newOrg = user.Orgs[0]
			} else {
				log.Printf("[WARNING] User %s has no orgs left. Setting default to empty.", user.Username)
				newOrg = ""
			}
		}
	}

	if len(newOrg) > 0 {
		// Get the org and fill in
		newOrgDetails, err := GetOrg(ctx, newOrg)
		if err == nil {
			user.ActiveOrg.Id = newOrgDetails.Id
			user.ActiveOrg.Name = newOrgDetails.Name
		} else {
			user.ActiveOrg.Id = ""
			user.ActiveOrg.Name = ""
		}
	} else {
		// Will cause the user to generate a new org as it doesn't have any?
		user.ActiveOrg.Id = ""
		user.ActiveOrg.Name = ""
	}

	//for _, orgUser := range org.Users {
	//	// Get the user
	//	orgUserDetails, err := GetUser(ctx, orgUser.Username)
	//	if err != nil {
	//		continue
	//	}

	//	if orgUserDetails.ActiveOrg.Id == fileId {
	//		orgUserDetails.ActiveOrg.Id = newOrg
	//	}
	//}

	err = SetUser(ctx, &user, true)
	if err != nil {
		log.Printf("[WARNING] Failed setting user '%s': %s", user.Username, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed setting user"}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func AssignAuthEverywhere(ctx context.Context, auth *AppAuthenticationStorage, user User) error {
	log.Printf("[INFO] Should set authentication config")
	baseWorkflows, err := GetAllWorkflowsByQuery(ctx, user)
	if err != nil && len(baseWorkflows) == 0 {
		log.Printf("Getall error in auth update: %s", err)
		return err
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

			//cacheKey := fmt.Sprintf("%s_workflows", user.Id)

			//DeleteCache(ctx, cacheKey)

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
			return err
		} else {
			// FIXME: Remove ALL workflows from other auths using the same
		}
	}

	return nil
}

func HandleWorkflowRunSearch(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("[WARNING] Api authentication failed in search workflow runs: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Failed workflow body read (workflow search): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	search := WorkflowSearch{}
	err = json.Unmarshal([]byte(body), &search)
	if err != nil {
		//log.Printf(string(body))
		log.Printf("[ERROR] Failed workflow unmarshaling (workflow search): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
		return
	}

	//log.Printf("[DEBUG] Got Run search: %+v", search)

	// Here to check access rights
	ctx := GetContext(request)
	if len(search.WorkflowId) > 0 {
		workflow, err := GetWorkflow(ctx, search.WorkflowId)
		if err != nil {
			log.Printf("[WARNING] Failed getting the workflow %s locally (search workflow runs): %s", search.WorkflowId, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		// Check workflow.Sharing == private / public / org  too
		if user.Id != workflow.Owner || len(user.Id) == 0 {
			// Added org-reader as the user should be able to read everything in an org
			if workflow.OrgId == user.ActiveOrg.Id {
				log.Printf("[AUDIT] User %s is accessing workflow %s as admin (workflow run search)", user.Username, workflow.ID)
			} else if workflow.Public {
				log.Printf("[AUDIT] Letting user %s access workflow %s because it's public", user.Username, workflow.ID)

				// Only for Read-Only. No executions or impersonations.
			} else if project.Environment == "cloud" && user.Verified == true && user.Active == true && user.SupportAccess == true && strings.HasSuffix(user.Username, "@shuffler.io") {
				log.Printf("[AUDIT] Letting verified support admin %s access workflow run debug search for %s", user.Username, workflow.ID)
			} else {
				log.Printf("[AUDIT] Wrong user (%s) for workflow %s (workflow run search). Verified: %t, Active: %t, SupportAccess: %t, Username: %s", user.Username, workflow.ID, user.Verified, user.Active, user.SupportAccess, user.Username)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false}`))
				return
			}
		}
	}

	chosenOrg := user.ActiveOrg.Id
	if search.IgnoreOrg == true && user.SupportAccess {
		chosenOrg = ""
	}

	runs, cursor, err := GetWorkflowRunsBySearch(ctx, chosenOrg, search)
	if err != nil {
		log.Printf("[WARNING] Failed getting workflow runs by search: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	parsedRuns := []WorkflowExecution{}
	for _, run := range runs {
		if run.ExecutionOrg != user.ActiveOrg.Id {
			if !user.SupportAccess {
				continue
			}
		}

		parsedRuns = append(parsedRuns, run)
	}

	runs = parsedRuns
	workflowSearchResult := WorkflowSearchResult{
		Success: true,
		Runs:    runs,
		Cursor:  cursor,
	}

	respBody, err := json.Marshal(workflowSearchResult)
	if err != nil {
		log.Printf("[WARNING] Failed marshaling workflow runs: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.Write(respBody)
}

// func HandleSavePipelineInfo(resp http.ResponseWriter, request *http.Request) {
//     cors := HandleCors(resp, request)
//     if cors {
//         return
//     }

//     // How do I make sure that Orborus is the one that made this request?

//     var requestBody Pipeline
//     err := json.NewDecoder(request.Body).Decode(&requestBody)
// 	if err != nil {
//         log.Printf("[WARNING] Failed to decode request body: %s", err)
//         resp.WriteHeader(401)
//         resp.Write([]byte(`{"success": false}`))
//         return
//     }
// 	if len(requestBody.TriggerId) == 0 || len(requestBody.PipelineId) == 0 || len(requestBody.Status) == 0 {
// 		log.Printf("[WARNING] Missing fields in the request body")
//         resp.WriteHeader(400)
//         resp.Write([]byte(`{"success": false, "reason": "Missing fields in the request body"}`))
//         return
// 	}

//     ctx := GetContext(request)
//     pipeline, err := GetPipeline(ctx, requestBody.TriggerId)
//     if err != nil {
// 		if strings.Contains(fmt.Sprintf("%s", err),"pipeline doesn't exist"){
// 			log.Printf("[DEBUG] no matching document found for Pipeline: %s", requestBody.PipelineId)
// 			resp.WriteHeader(404)
// 			resp.Write([]byte(`{"success": false, "reason": "pipeline not found"}`))
// 			return
// 		} else {
//         log.Printf("[WARNING] Failed getting pipeline: %s due to %s", requestBody.PipelineId, err)
//         resp.WriteHeader(500)
//         resp.Write([]byte(`{"success": false}`))
//         return
// 		}
//     }

//     pipeline.PipelineId = requestBody.PipelineId
//     pipeline.Status = requestBody.Status

//     err = savePipelineData(ctx, *pipeline)
//     if err != nil {
//         log.Printf("[WARNING] Failed updating pipeline with ID: %s due to %s", pipeline.PipelineId, err)
//         resp.WriteHeader(500)
//         resp.Write([]byte(`{"success": false}`))
//         return
//     }
// 	log.Printf("[INFO] Sucessfully saved pipeline: %s", pipeline.PipelineId)
//     resp.WriteHeader(200)
//     resp.Write([]byte(`{"success": true}`))
// }

func LoadUsecases(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get usecases. Continuing anyway: %s", err)
		//resp.WriteHeader(401)
		//resp.Write([]byte(`{"success": false}`))
		//return
	}

	// FIXME: Load for the specific org and have structs for it all
	_ = user

	//ctx := GetContext(request)

	resp.WriteHeader(200)
	resp.Write([]byte(GetUsecaseData()))
}

func parseSubflowResults(ctx context.Context, result ActionResult) (ActionResult, bool) {
	var parentSubflowResult []SubflowData
	err := json.Unmarshal([]byte(result.Result), &parentSubflowResult)
	if err != nil {
		//log.Printf("[WARNING] Failed unmarshaling subflow result. This could be due to it not being a list: %s", err)
		return result, false
	}

	for _, param := range result.Action.Parameters {
		if param.Name == "check_result" {
			if param.Value == "false" {
				return result, false
			}
		}
	}

	newResults := []SubflowData{}
	finishedSubflows := 0

	failedCount := 0
	for _, res := range parentSubflowResult {
		// If value length = 0 for any, then check cache and add the result
		if res.ResultSet && len(res.Result) > 0 {
			//log.Printf("[DEBUG][%s] Got result set for subflow. Result: %#v", res.ExecutionId, res.Result)

			newResults = append(newResults, res)
			finishedSubflows += 1
			continue
		}

		if !res.Success {
			//log.Printf("[DEBUG][%s] Subflow failed", res.ExecutionId)

			newResults = append(newResults, res)

			failedCount += 1
			finishedSubflows += 1
			continue
		}

		subflowResultCacheId := fmt.Sprintf("%s_%s_subflowresult", res.ExecutionId, result.Action.ID)
		cache, err := GetCache(ctx, subflowResultCacheId)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("[DEBUG] Cachedata for other subflow: '%s'", string(cacheData))
			if len(cacheData) > 0 {
				res.Result = string(cacheData)
				res.ResultSet = true
				finishedSubflows += 1
			} else {
				DeleteCache(ctx, subflowResultCacheId)
			}

		} else {
			// Get the workflow execution for the subflow

			// Can't do this, as it causes an infinite loop?
			// This function is used in GetWorkflowExecution
			subflowExecution, err := GetWorkflowExecution(ctx, res.ExecutionId)
			//log.Printf("[DEBUG][%s] Got subflow execution: %s", res.ExecutionId, subflowExecution.Status)

			if err != nil {
				log.Printf("[ERROR] Failed getting subflow execution: %s", subflowExecution.Status)
			} else {
				if subflowExecution.Status == "EXECUTING" {
					//DeleteCache(ctx, fmt.Sprintf("workflowexecution_%s", res.ExecutionId))
				} else if subflowExecution.Status != "EXECUTING" {
					// Ensure it gets the last result based on CompletedAt
					//log.Printf("[DEBUG] NOT EXECUTING!!")
					foundResult := ActionResult{}
					for _, result := range subflowExecution.Results {
						if result.Status == "SUCCESS" && result.CompletedAt >= foundResult.CompletedAt {
							foundResult = result
						}
					}

					if len(foundResult.Result) > 0 {
						res.Result = foundResult.Result
					}

					if len(res.Result) == 0 || subflowExecution.Status == "ABORTED" {
						// Find the last result and use that
						res.Result = subflowExecution.Workflow.DefaultReturnValue
					}

					if len(subflowExecution.Result) > 0 {
						res.Result = subflowExecution.Result
					}

					res.ResultSet = true
					finishedSubflows += 1

					if len(res.Result) > 0 {
						SetCache(ctx, subflowResultCacheId, []byte(subflowExecution.Result), 60)
					}
				}
			}

		}

		newResults = append(newResults, res)
	}

	baseResultData, err := json.Marshal(newResults)
	if err != nil {
		log.Printf("[ERROR] Failed marshalling subflow loop request data (1): %s", err)
		return result, false
	}

	result.Result = string(baseResultData)
	if finishedSubflows == len(newResults) {
		//log.Printf("[DEBUG] Finished sub result from caching?")

		// Status is used to determine if the current subflow is finished
		if failedCount == finishedSubflows {
			result.Status = "FAILURE"
		} else {
			result.Status = "SUCCESS"
		}

		if result.CompletedAt == 0 {
			result.CompletedAt = time.Now().Unix() * 1000
		}

	} else {
		//log.Printf("[DEBUG] Not finished sub result from caching yet")
	}

	return result, true
}

func ValidateRequestOverload(resp http.ResponseWriter, request *http.Request) error {
	// 1. Get current amount of requests for the user
	// 2. Check if the user is allowed to make more requests
	// 3. If not, return error
	// 4. If yes, continue and add the request to the list
	// Use the GetCache() and SetCache() functions to store the request count

	// Max amount per minute
	maxAmount := 4
	foundIP := GetRequestIp(request)
	if foundIP == "" || foundIP == "127.0.0.1" || foundIP == "::1" {
		log.Printf("[DEBUG] Skipping request overload check for IP: %s", foundIP)
		return nil
	}

	// Check if the foundIP includes ONE colon for the port
	if strings.Count(foundIP, ":") == 1 {
		foundIP = strings.Split(foundIP, ":")[0]
	}

	timenow := time.Now().Unix()
	userRequest := UserRequest{
		IP:        foundIP,
		Method:    request.Method,
		Path:      request.URL.Path,
		Timestamp: timenow,
	}

	requestList := []UserRequest{}

	// Maybe do per path? Idk
	ctx := GetContext(request)
	cacheKey := fmt.Sprintf("userrequest_%s", userRequest.IP)
	cache, err := GetCache(ctx, cacheKey)
	if err != nil {
		//log.Printf("[ERROR] Failed getting cache for key %s: %s", cacheKey, err)
		requestList = append(requestList, userRequest)

		b, err := json.Marshal(requestList)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling requestlist: %s", err)
			return nil
		}

		// Set cache for 1 minute
		err = SetCache(ctx, cacheKey, b, 1)
		if err != nil {
			log.Printf("[ERROR] Failed setting cache for key %s: %s", cacheKey, err)
			return nil
		}

		return nil
	}

	// Parse out the data in the cache
	cacheData := []byte(cache.([]uint8))
	err = json.Unmarshal(cacheData, &requestList)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshalling requestlist: %s", err)
		return nil
	}

	// Remove any item more than 60 seconds back to make a sliding window
	newList := []UserRequest{}
	for _, req := range requestList {
		if req.Timestamp < (timenow - 60) {
			continue
		}

		newList = append(newList, req)
	}

	if len(newList) > maxAmount {
		// FIXME: Should we add to the list even if we return an error?

		return errors.New("Too many requests")
	}

	log.Printf("[DEBUG] Adding request to list")
	newList = append(newList, userRequest)
	b, err := json.Marshal(newList)
	if err != nil {
		log.Printf("[ERROR] Failed marshalling requestlist: %s", err)
		return nil
	}

	// Set cache for 1 minute
	err = SetCache(ctx, cacheKey, b, 1)
	if err != nil {
		log.Printf("[ERROR] Failed setting cache for key %s: %s", cacheKey, err)
	}

	return nil
}

func DistributeAppToEnvironments(ctx context.Context, org Org, appnames []string) error {
	envs, err := GetEnvironments(ctx, org.Id)
	if err != nil {
		log.Printf("[ERROR] Failed getting environments for org: %s", err)
		return err
	}

	if len(envs) > 10 {
		envs = envs[:10]
	}

	// Should add to queues in the current org
	for _, env := range envs {
		if env.Archived {
			continue
		}

		if strings.ToLower(env.Name) == "cloud" {
			continue
		}

		log.Printf("[DEBUG] Distributing app image %s to environment: %s", strings.Join(appnames, ", "), env.Name)

		// Add to the queue
		request := ExecutionRequest{
			Type:              "DOCKER_IMAGE_DOWNLOAD",
			ExecutionId:       uuid.NewV4().String(),
			ExecutionArgument: strings.Join(appnames, ","),
			Priority:          11,
		}

		parsedId := fmt.Sprintf("%s_%s", strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(env.Name, " ", "-"), "_", "-")), org.Id)
		err = SetWorkflowQueue(ctx, request, parsedId)
		if err != nil {
			log.Printf("[ERROR] Failed setting workflow queue for env: %s", err)
			continue
		}
	}

	return nil
}

func fixOrgUsers(ctx context.Context, foundOrg Org) error {
	if project.Environment == "cloud" {
		log.Printf("[DEBUG] Skipping fixOrgUsers for cloud")
		return errors.New("Not updating cloud")
	}

	if len(foundOrg.Users) != 0 {
		return errors.New("Org already has users")
	}

	users, countErr := GetAllUsers(ctx)
	if countErr != nil {
		log.Printf("[ERROR] Failed getting all users in auto fix org users: %s", countErr)
		return countErr
	}

	log.Printf("[DEBUG] Found %d users to potentially add to org %s", len(users), foundOrg.Id)
	for _, user := range users {
		if !ArrayContains(user.Orgs, foundOrg.Id) {
			continue
		}

		log.Printf("[DEBUG] Re-adding user %s (%s) to org %s (%s)", user.Username, user.Id, foundOrg.Name, foundOrg.Id)
		user.Role = "admin"
		foundOrg.Users = append(foundOrg.Users, user)
	}

	// Save the org
	err := SetOrg(ctx, foundOrg, foundOrg.Id)
	if err != nil {
		log.Printf("[ERROR] Failed saving org %s while readding a user: %s", foundOrg.Id, err)
		return err
	}

	return nil
}

func IsLicensed(ctx context.Context, org Org) bool {
	if project.Environment == "cloud" && len(org.ManagerOrgs) > 0 {
		return true
	}

	if len(org.SubscriptionUserId) == 0 {
		return false
	}

	//if len(org.Subscriptions) > 0 {
	//	return true
	//}

	environments, err := GetEnvironments(ctx, org.Id)
	if err != nil {
		log.Printf("[ERROR] Failed getting environments for org %s: %s", org.Id, err)
		return false
	}

	for _, env := range environments {
		if env.Archived {
			continue
		}

		if env.Licensed {
			return true
		}
	}

	return false
}

// Generates a standard destination workflow that uses:
// 1. A Startnode mapping $exec
// 2. An enrichment subflow that maps the data from $exec
// - A data merger of 1 & 2
// - Integration framework with dest app
func GetStandardDestWorkflow(app *WorkflowApp, action string, enrich bool) *Workflow {
	appname := app.Name
	appCategory := ""
	if len(app.Categories) > 0 {
		appCategory = app.Categories[0]
	}

	workflowId := uuid.NewV4().String()
	startnodeId := uuid.NewV4().String()

	workflow := Workflow{
		ID:    workflowId,
		Start: startnodeId,
	}

	workflow.Actions = append(workflow.Actions, Action{
		AppName:    "Shuffle Tools",
		AppVersion: "1.2.0",
		Label:      "create_startnode",
		ID:         startnodeId,
		Name:       "repeat_back_to_me",
		Parameters: []WorkflowAppActionParameter{
			WorkflowAppActionParameter{
				Name:      "call",
				Value:     "$exec",
				Multiline: true,
			},
		},
		Position: Position{
			X: 0,
			Y: 0,
		},
	})

	previousnodeId := startnodeId
	previousnodeRef := fmt.Sprintf("$%s", workflow.Actions[0].Label)
	if enrich {
		enrichNodeId := uuid.NewV4().String()
		workflow.Triggers = append(workflow.Triggers, Trigger{
			AppName:    "Shuffle Workflow",
			AppVersion: "1.0.0",
			Name:       "Shuffle Workflow",

			ID:          enrichNodeId,
			Label:       "Enrich",
			Tags:        []string{"Enrich"},
			TriggerType: "SUBFLOW",

			Position: Position{
				X: 150,
				Y: 150,
			},

			Parameters: []WorkflowAppActionParameter{
				WorkflowAppActionParameter{
					Name:  "workflow",
					Value: "",
				},
				WorkflowAppActionParameter{
					Name:  "argument",
					Value: "$exec",
				},
				WorkflowAppActionParameter{
					Name:  "user_apikey",
					Value: "",
				},
				WorkflowAppActionParameter{
					Name:  "startnode",
					Value: "",
				},
				WorkflowAppActionParameter{
					Name:  "check_result",
					Value: "true",
				},
			},
		})

		// Start -> subflow node
		workflow.Branches = append(workflow.Branches, Branch{
			ID:            uuid.NewV4().String(),
			SourceID:      startnodeId,
			DestinationID: enrichNodeId,
		})

		// Add merge node
		mergeNodeId := uuid.NewV4().String()
		workflow.Actions = append(workflow.Actions, Action{
			AppName:    "Shuffle Tools",
			AppVersion: "1.2.0",
			Label:      "merge enrichment",
			ID:         mergeNodeId,
			Name:       "merge_incoming_branches",
			Parameters: []WorkflowAppActionParameter{
				WorkflowAppActionParameter{
					Name:     "input_type",
					Value:    "dict",
					Options:  []string{"list", "dict"},
					Required: true,
				},
			},
			Position: Position{
				X: 0,
				Y: 300,
			},
		})

		// Start -> subflow node
		workflow.Branches = append(workflow.Branches, Branch{
			ID:            uuid.NewV4().String(),
			SourceID:      startnodeId,
			DestinationID: mergeNodeId,
		})

		workflow.Branches = append(workflow.Branches, Branch{
			ID:            uuid.NewV4().String(),
			SourceID:      enrichNodeId,
			DestinationID: mergeNodeId,
		})

		previousnodeId = mergeNodeId
		previousnodeRef = fmt.Sprintf("$%s", strings.ReplaceAll(workflow.Actions[1].Label, " ", "_"))
	}

	integrationFrameworkId := uuid.NewV4().String()
	workflow.Actions = append(workflow.Actions, Action{
		AppName:    "Integration Framework",
		AppVersion: "1.0.0",
		AppID:      "integration",
		Label:      strings.ReplaceAll(action, " ", "_"),
		ID:         integrationFrameworkId,
		Name:       appCategory,
		LargeImage: app.LargeImage,
		Parameters: []WorkflowAppActionParameter{
			WorkflowAppActionParameter{
				Name:     "action",
				Value:    action,
				Options:  []string{action},
				Required: true,
			},
			WorkflowAppActionParameter{
				Name:      "fields",
				Value:     previousnodeRef,
				Multiline: true,
			},
			WorkflowAppActionParameter{
				Name:  "app_name",
				Value: appname,
			},
		},
		Position: Position{
			X: 0,
			Y: 450,
		},
	})

	workflow.Branches = append(workflow.Branches, Branch{
		ID:            uuid.NewV4().String(),
		SourceID:      previousnodeId,
		DestinationID: integrationFrameworkId,
	})

	return &workflow
}

func CheckSessionOrgs(ctx context.Context, user User) {
	if !ArrayContains(user.ValidatedSessionOrgs, user.ActiveOrg.Id) {
		user.ValidatedSessionOrgs = append(user.ValidatedSessionOrgs, user.ActiveOrg.Id)

		err := SetUser(ctx, &user, false)
		if err != nil {
			log.Printf("[ERROR] Failed setting validated session orgs for user %s: %s", user.Username, err)
		}
	}
}

// Handles statistics incrementation for workflow executions
func HandleExecutionCacheIncrement(ctx context.Context, execution WorkflowExecution) {
	if execution.Status != "FINISHED" && execution.Status != "ABORTED" && execution.Status != "FAILURE" {
		//log.Printf("[DEBUG] Execution %s is not finished (%s). Not incrementing cache", execution.ExecutionId, execution.Status)
		return
	}

	cacheIncrementKey := fmt.Sprintf("%s_cacheset", execution.ExecutionId)
	_, err := GetCache(ctx, cacheIncrementKey)
	if err == nil {
		//log.Printf("[DEBUG] Cache already incremented for execution %s", execution.ExecutionId)
		return
	}

	SetCache(ctx, cacheIncrementKey, []byte{1}, 60)

	env := ""
	appruns := 0
	appfailure := 0
	subflows := 0

	for _, result := range execution.Results {
		// Shoud all be the same :)
		if len(result.Action.Environment) > 0 {
			env = result.Action.Environment
		}

		if result.Status == "SUCCESS" {
			appruns += 1
		} else if result.Status == "FAILURE" || result.Status == "ABORTED" {
			appruns += 1
			appfailure += 1

		}

		if result.Action.AppName == "Shuffle Workflow" && result.Status == "SUCCESS" {
			subflows += 1
		}
	}

	actionLabelSuccess := map[string]int{}
	actionLabelFails := map[string]int{}
	for _, action := range execution.Workflow.Actions {
		if len(action.Environment) > 0 {
			env = action.Environment
		}

		if len(action.CategoryLabel) == 0 {
			continue
		}

		categoryLabel := strings.ToLower(strings.ReplaceAll(action.CategoryLabel[0], " ", "_"))
		for _, result := range execution.Results {
			if result.Action.ID != action.ID {
				continue
			}

			if result.Status == "SUCCESS" {
				// Check the result if result.Result.status < 300  or something similar
				updateValue := true
				outputValue := HTTPOutput{}
				err := json.Unmarshal([]byte(result.Result), &outputValue)
				if err == nil {
					if !outputValue.Success || outputValue.Status >= 300 {
						result.Status = "ABORTED"
						updateValue = false
					}
				}

				if updateValue {
					if _, ok := actionLabelSuccess[categoryLabel]; ok {
						actionLabelSuccess[categoryLabel] += 1
					} else {
						actionLabelSuccess[categoryLabel] = 1
					}
				}
			}

			if result.Status == "FAILURE" || result.Status == "ABORTED" {
				if _, ok := actionLabelFails[categoryLabel]; ok {
					actionLabelFails[categoryLabel] += 1
				} else {
					actionLabelFails[categoryLabel] = 1
				}
			} else {
				// Skipped or something. Not relevant.
			}
		}
	}

	if appruns > 0 {
		apprunName := fmt.Sprintf("app_executions_%s", env)
		if len(env) == 0 {
			apprunName = fmt.Sprintf("app_executions")
		}

		IncrementCache(ctx, execution.ExecutionOrg, apprunName, appruns)
	}

	if appfailure > 0 {
		IncrementCache(ctx, execution.ExecutionOrg, "app_executions_failed", appfailure)
	}

	if subflows > 0 {
		IncrementCache(ctx, execution.ExecutionOrg, "subflow_executions", subflows)
	}

	if execution.Status == "ABORTED" {
		IncrementCache(ctx, execution.ExecutionOrg, "workflow_executions_failed")
	} else if execution.Status == "FINISHED" {
		IncrementCache(ctx, execution.ExecutionOrg, "workflow_executions_finished")
	} else {
		IncrementCache(ctx, execution.ExecutionOrg, "workflow_executions_executing")
	}

	for key, value := range actionLabelSuccess {
		IncrementCache(ctx, execution.ExecutionOrg, fmt.Sprintf("categorylabel_success_%s", key), value)
	}

	for key, value := range actionLabelFails {
		IncrementCache(ctx, execution.ExecutionOrg, fmt.Sprintf("categorylabel_fail_%s", key), value)
	}
}

func GetChildWorkflows(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Removed check here as it may be a public workflow
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in getting child workflows: %s", err)
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

	if strings.Contains(fileId, "?") {
		fileId = strings.Split(fileId, "?")[0]
	}

	if len(fileId) != 36 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID when getting workflow is not valid"}`))
		return
	}

	ctx := GetContext(request)
	workflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Workflow %s doesn't exist.", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed finding workflow"}`))
		return
	}

	// Check workflow.Sharing == private / public / org  too
	if user.Id != workflow.Owner || len(user.Id) == 0 {
		// Added org-reader as the user should be able to read everything in an org
		//if workflow.OrgId == user.ActiveOrg.Id && (user.Role == "admin" || user.Role == "org-reader") {
		if workflow.OrgId == user.ActiveOrg.Id {
			log.Printf("[AUDIT] User %s is accessing workflow %s as admin (get child workflows)", user.Username, workflow.ID)

			// Only for Read-Only. No executions or impersonations.
		} else if project.Environment == "cloud" && user.Verified == true && user.Active == true && user.SupportAccess == true && strings.HasSuffix(user.Username, "@shuffler.io") {
			log.Printf("[AUDIT] Letting verified support admin %s access childs workflows for %s", user.Username, workflow.ID)

		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (get child workflow). Verified: %t, Active: %t, SupportAccess: %t, Username: %s", user.Username, workflow.ID, user.Verified, user.Active, user.SupportAccess, user.Username)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	// Access is granted -> get revisions
	childWorkflows, err := ListChildWorkflows(ctx, workflow.ID)
	if err != nil {
		log.Printf("[WARNING] Failed getting child workflows of %s: %s", workflow.ID, err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	newWfs := []Workflow{}
	for _, wf := range childWorkflows {
		if wf.ParentWorkflowId != workflow.ID {
			continue
		}

		newWfs = append(newWfs, wf)
	}

	body, err := json.Marshal(newWfs)
	if err != nil {
		log.Printf("[WARNING] Failed child workflow GET marshalling: %s", err)
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(body)
}
