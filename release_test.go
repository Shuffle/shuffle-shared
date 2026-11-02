package shuffle

import (
	"bytes"
	"cloud.google.com/go/datastore"
	pb "cloud.google.com/go/datastore/apiv1/datastorepb"
	"cloud.google.com/go/storage"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	cache "github.com/patrickmn/go-cache"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- Consolidated from app_auth_test.go ----

const appAuthTestID = "00000000-0000-4000-8000-000000000111"
const appAuthPath = "/api/v1/apps/authentication"

func newAppAuthAPIFixture(t *testing.T) (*datastoreAPIFixture, AppAuthenticationStorage) {
	t.Helper()
	fixture := newDatastoreAPIFixture(t)
	project.Environment = "cloud"
	project.GceProject = "release-tests"
	t.Setenv("SHUFFLE_ENCRYPTION_MODIFIER", "release-tests-only")
	t.Setenv("SHUFFLE_ENCRYPTION_MODIFIER_ROLLOVER", "")
	app := WorkflowApp{ID: "0123456789abcdef0123456789abcdef", Name: "Release Auth App", AppVersion: "1.0.0",
		Actions: []WorkflowAppAction{{Name: "check"}}}
	for _, orgID := range []string{datastoreTestOrg, isolationOtherOrg} {
		org := Org{Id: orgID, ActiveApps: []string{app.ID}}
		if _, err := project.Dbclient.Put(context.Background(), datastore.NameKey("Organizations", orgID, nil), &org); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := project.Dbclient.Put(context.Background(), datastore.NameKey("workflowapp", app.ID, nil), &app); err != nil {
		t.Fatal(err)
	}
	cacheAppAuthUser(t, "admin")
	owner, err := json.Marshal(User{Id: "foreign-owner", Username: "owner@example.invalid", Role: "admin", ActiveOrg: OrgMini{Id: isolationOtherOrg}})
	if err != nil {
		t.Fatal(err)
	}
	if err := SetCache(context.Background(), workflowOwnerAPIKey+isolationOtherOrg, owner, 60); err != nil {
		t.Fatal(err)
	}
	return fixture, AppAuthenticationStorage{Id: appAuthTestID, Label: "release auth", App: app, Active: true, Type: "apikey",
		Fields: []AuthenticationStore{{Key: "api_key", Value: "synthetic-private-key"}, {Key: "url", Value: "https://api.example.invalid"}}}
}

func saveAppAuthAPI(t *testing.T, auth AppAuthenticationStorage) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(auth)
	if err != nil {
		t.Fatal(err)
	}
	return requestWorkflowAPI(AddAppAuthentication, http.MethodPut, appAuthPath, string(body))
}

func cacheAppAuthUser(t *testing.T, role string) {
	t.Helper()
	user := User{Id: "release-test-user", Username: "scheduler@shuffler.io", Role: role,
		ActiveOrg: OrgMini{Id: datastoreTestOrg}, Orgs: []string{datastoreTestOrg}, ApiKey: datastoreTestAPIKey}
	for key, value := range map[string]interface{}{datastoreTestAPIKey + datastoreTestOrg: user, "Users_" + datastoreTestAPIKey: []User{user}} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := SetCache(context.Background(), key, encoded, 60); err != nil {
			t.Fatal(err)
		}
	}
}

func listAppAuthAPI(t *testing.T, org string) []AppAuthenticationStorage {
	t.Helper()
	key := datastoreTestAPIKey
	if org == isolationOtherOrg {
		key = workflowOwnerAPIKey
	}
	request := httptest.NewRequest(http.MethodGet, appAuthPath, nil)
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("Org-Id", org)
	response := httptest.NewRecorder()
	GetAppAuthentication(response, request)
	var body struct {
		Success bool                       `json:"success"`
		Data    []AppAuthenticationStorage `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || !body.Success {
		t.Fatalf("authentication list failed: HTTP %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "synthetic-private-key") {
		t.Fatal("authentication list exposed the synthetic secret")
	}
	return body.Data
}

func appAuthActionFields(t *testing.T, id string) map[string]string {
	t.Helper()
	stored, err := GetAllWorkflowAppAuth(context.Background(), datastoreTestOrg)
	if err != nil {
		t.Fatal(err)
	}
	action, _ := GetAuthentication(context.Background(), WorkflowExecution{}, Action{AuthenticationId: id}, stored)
	fields := map[string]string{}
	for _, parameter := range action.Parameters {
		fields[parameter.Name] = parameter.Value
	}
	return fields
}

func TestAppAuthAPICreateMaskedListEditAndDelete(t *testing.T) {
	_, auth := newAppAuthAPIFixture(t)
	auth.OrgId = isolationOtherOrg
	created := saveAppAuthAPI(t, auth)
	if created.Code != http.StatusOK {
		t.Fatalf("authentication creation failed: HTTP %d, %s", created.Code, created.Body.String())
	}
	items := listAppAuthAPI(t, datastoreTestOrg)
	if len(items) != 1 || items[0].Id != auth.Id || items[0].OrgId != datastoreTestOrg || items[0].Label != auth.Label {
		t.Fatal("created authentication did not belong to the authenticated organization")
	}
	for _, field := range items[0].Fields {
		if field.Key == "url" && field.Value != "https://api.example.invalid" {
			t.Fatal("listing lost the allowed URL field")
		}
		if field.Key == "api_key" && field.Value != "Secret. Replaced during app execution!" {
			t.Fatal("listing did not mask the API key")
		}
	}
	edit := items[0]
	edit.Label = "renamed release auth"
	for i := range edit.Fields {
		if edit.Fields[i].Key == "url" {
			edit.Fields[i].Value = "https://updated.example.invalid"
		}
	}
	if response := saveAppAuthAPI(t, edit); response.Code != http.StatusOK {
		t.Fatalf("masked authentication edit failed: HTTP %d", response.Code)
	}
	items = listAppAuthAPI(t, datastoreTestOrg)
	if len(items) != 1 || items[0].Id != auth.Id || items[0].Label != edit.Label {
		t.Fatal("editing the authentication changed its identity or lost the label")
	}
	// Observe the same public auth-resolution boundary used to prepare an action.
	fields := appAuthActionFields(t, auth.Id)
	if fields["api_key"] != "synthetic-private-key" || fields["url"] != "https://updated.example.invalid" {
		t.Fatal("masked edit/rename changed the secret or lost the edited URL during action preparation")
	}
	deleted := requestWorkflowAPI(DeleteAppAuthentication, http.MethodDelete, appAuthPath+"/"+auth.Id, "")
	if deleted.Code != http.StatusOK || len(listAppAuthAPI(t, datastoreTestOrg)) != 0 {
		t.Fatalf("authentication remained listed after deletion: HTTP %d", deleted.Code)
	}
}

func TestAppAuthAPILabelOnlyEditPreservesCredentials(t *testing.T) {
	_, auth := newAppAuthAPIFixture(t)
	if response := saveAppAuthAPI(t, auth); response.Code != http.StatusOK {
		t.Fatalf("initial creation failed: HTTP %d", response.Code)
	}
	edit := listAppAuthAPI(t, datastoreTestOrg)[0]
	edit.Label = "label-only update"
	edit.Fields = nil
	if response := saveAppAuthAPI(t, edit); response.Code != http.StatusOK {
		t.Fatalf("label-only edit failed: HTTP %d", response.Code)
	}
	fields := appAuthActionFields(t, auth.Id)
	if fields["api_key"] != "synthetic-private-key" || fields["url"] != "https://api.example.invalid" {
		t.Fatal("label-only edit lost the existing credentials during action preparation")
	}
}

func TestAppAuthAPIForeignOrganizationCannotReadEditOrDelete(t *testing.T) {
	_, auth := newAppAuthAPIFixture(t)
	auth.OrgId = isolationOtherOrg
	if _, err := project.Dbclient.Put(context.Background(), datastore.NameKey("workflowappauth", auth.Id, nil), &auth); err != nil {
		t.Fatal(err)
	}
	if len(listAppAuthAPI(t, isolationOtherOrg)) != 1 || len(listAppAuthAPI(t, datastoreTestOrg)) != 0 {
		t.Fatal("authentication list was not isolated before mutation attempts")
	}
	auth.OrgId = datastoreTestOrg
	auth.Label = "forged foreign edit"
	edited := saveAppAuthAPI(t, auth)
	deleted := requestWorkflowAPI(DeleteAppAuthentication, http.MethodDelete, appAuthPath+"/"+auth.Id, "")
	for _, response := range []*httptest.ResponseRecorder{edited, deleted} {
		var body map[string]interface{}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if response.Code < 400 || response.Code >= 500 || body["success"] != false {
			t.Errorf("foreign authentication mutation was not rejected: HTTP %d", response.Code)
		}
	}
	items := listAppAuthAPI(t, isolationOtherOrg)
	if len(items) != 1 || items[0].Label != "release auth" || items[0].OrgId != isolationOtherOrg {
		t.Fatal("foreign-owner read-back changed after rejected mutation")
	}
}

func TestAppAuthAPIStorageLookupFailureCannotTransferForeignOwnership(t *testing.T) {
	fixture, auth := newAppAuthAPIFixture(t)
	auth.OrgId = isolationOtherOrg
	if _, err := project.Dbclient.Put(context.Background(), datastore.NameKey("workflowappauth", auth.Id, nil), &auth); err != nil {
		t.Fatal(err)
	}
	if len(listAppAuthAPI(t, isolationOtherOrg)) != 1 || len(listAppAuthAPI(t, datastoreTestOrg)) != 0 {
		t.Fatal("foreign authentication control failed before storage fault")
	}
	fixture.lookupErrKind = "workflowappauth"
	fixture.lookupErr = status.Error(codes.PermissionDenied, "synthetic authentication lookup rejected")
	auth.OrgId = datastoreTestOrg
	auth.Label = "attempted ownership transfer"
	response := saveAppAuthAPI(t, auth)
	if response.Code < 400 {
		t.Errorf("authentication lookup failure was treated as a new record: HTTP %d", response.Code)
	}
	fixture.lookupErr = nil
	// Refresh both lists after storage recovers, as the owner may have a cached list.
	DeleteCache(context.Background(), "workflowappauth_"+isolationOtherOrg)
	DeleteCache(context.Background(), "workflowappauth_"+datastoreTestOrg)
	ownerItems := listAppAuthAPI(t, isolationOtherOrg)
	callerItems := listAppAuthAPI(t, datastoreTestOrg)
	if len(ownerItems) != 1 || ownerItems[0].Id != auth.Id || ownerItems[0].Label != "release auth" || len(callerItems) != 0 {
		t.Fatal("storage lookup failure let the caller take the foreign authentication from its owner")
	}
}

func TestAppAuthAPIMissingAndInvalidCredentialsCannotReadOrMutate(t *testing.T) {
	_, auth := newAppAuthAPIFixture(t)
	if response := saveAppAuthAPI(t, auth); response.Code != http.StatusOK {
		t.Fatalf("initial creation failed: HTTP %d", response.Code)
	}
	auth.Label = "unauthorized edit"
	payload, err := json.Marshal(auth)
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{"", "Bearer 00000000-0000-4000-8000-000000000112", "Basic invalid"} {
		for _, operation := range []struct {
			method, path string
			handler      http.HandlerFunc
		}{
			{http.MethodGet, appAuthPath, GetAppAuthentication},
			{http.MethodPut, appAuthPath, AddAppAuthentication},
			{http.MethodDelete, appAuthPath + "/" + auth.Id, DeleteAppAuthentication},
		} {
			t.Run(credential+"/"+operation.method, func(t *testing.T) {
				request := httptest.NewRequest(operation.method, operation.path, strings.NewReader(string(payload)))
				request.Header.Set("Authorization", credential)
				request.Header.Set("Org-Id", datastoreTestOrg)
				response := httptest.NewRecorder()
				operation.handler(response, request)
				var body map[string]interface{}
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || body["success"] != false {
					t.Errorf("unauthenticated %s was not denied: HTTP %d", operation.method, response.Code)
				}
				if strings.Contains(response.Body.String(), "synthetic-private-key") || strings.Contains(response.Body.String(), "api.example.invalid") {
					t.Error("unauthenticated response exposed credential fields")
				}
				items := listAppAuthAPI(t, datastoreTestOrg)
				if len(items) != 1 || items[0].Label != "release auth" {
					t.Fatal("unauthenticated request changed owner-visible authentication")
				}
			})
		}
	}
}

func TestAppAuthAPIReadOnlyUserCanReadButCannotCreateEditOrDelete(t *testing.T) {
	_, auth := newAppAuthAPIFixture(t)
	if response := saveAppAuthAPI(t, auth); response.Code != http.StatusOK {
		t.Fatalf("initial creation failed: HTTP %d", response.Code)
	}
	cacheAppAuthUser(t, "org-reader")
	if len(listAppAuthAPI(t, datastoreTestOrg)) != 1 {
		t.Fatal("read-only user lost authentication list access")
	}
	edit := auth
	edit.Label = "read-only edit"
	create := auth
	create.Id = "00000000-0000-4000-8000-000000000113"
	create.Label = "read-only create"
	for _, response := range []*httptest.ResponseRecorder{
		saveAppAuthAPI(t, edit), saveAppAuthAPI(t, create),
		requestWorkflowAPI(DeleteAppAuthentication, http.MethodDelete, appAuthPath+"/"+auth.Id, ""),
	} {
		var body map[string]interface{}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || body["success"] != false {
			t.Errorf("read-only mutation was not denied: HTTP %d", response.Code)
		}
	}
	cacheAppAuthUser(t, "admin")
	items := listAppAuthAPI(t, datastoreTestOrg)
	if len(items) != 1 || items[0].Label != auth.Label || items[0].Id != auth.Id {
		t.Fatal("read-only request changed owner-visible authentication")
	}
}

func TestAppAuthAPIForgedOrgHeaderCannotExposeForeignAuth(t *testing.T) {
	_, auth := newAppAuthAPIFixture(t)
	auth.OrgId = isolationOtherOrg
	if _, err := project.Dbclient.Put(context.Background(), datastore.NameKey("workflowappauth", auth.Id, nil), &auth); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, appAuthPath, nil)
	request.Header.Set("Authorization", "Bearer "+datastoreTestAPIKey)
	request.Header.Set("Org-Id", isolationOtherOrg)
	response := httptest.NewRecorder()
	GetAppAuthentication(response, request)
	var body map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || body["success"] != false {
		t.Errorf("forged organization header granted authentication access: HTTP %d", response.Code)
	}
	if strings.Contains(response.Body.String(), auth.Label) || strings.Contains(response.Body.String(), "api.example.invalid") {
		t.Fatal("forged organization header exposed foreign authentication fields")
	}
}

func TestAppAuthAPIFailedCreationCanBeRetried(t *testing.T) {
	fixture, auth := newAppAuthAPIFixture(t)
	fixture.rejectWritesToKind = "workflowappauth"
	response := saveAppAuthAPI(t, auth)
	var body map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code < 400 || body["success"] != false || len(listAppAuthAPI(t, datastoreTestOrg)) != 0 {
		t.Fatal("failed authentication creation was acknowledged or became visible")
	}
	fixture.rejectWritesToKind = ""
	if response := saveAppAuthAPI(t, auth); response.Code != http.StatusOK {
		t.Fatalf("creation retry failed after storage recovery: HTTP %d", response.Code)
	}
	if len(listAppAuthAPI(t, datastoreTestOrg)) != 1 || appAuthActionFields(t, auth.Id)["api_key"] != "synthetic-private-key" {
		t.Fatal("successful retry lost the authentication or its secret")
	}
}

func TestAppAuthAPIFailedEditPreservesCredentialsAndCanBeRetried(t *testing.T) {
	fixture, auth := newAppAuthAPIFixture(t)
	if response := saveAppAuthAPI(t, auth); response.Code != http.StatusOK {
		t.Fatalf("initial creation failed: HTTP %d", response.Code)
	}
	edit := listAppAuthAPI(t, datastoreTestOrg)[0]
	edit.Label = "retried edit"
	fixture.rejectWritesToKind = "workflowappauth"
	response := saveAppAuthAPI(t, edit)
	if response.Code < 400 {
		t.Errorf("rejected edit was acknowledged: HTTP %d", response.Code)
	}
	fixture.rejectWritesToKind = ""
	items := listAppAuthAPI(t, datastoreTestOrg)
	if len(items) != 1 || items[0].Label != auth.Label || appAuthActionFields(t, auth.Id)["api_key"] != "synthetic-private-key" {
		t.Fatal("failed edit changed the existing authentication")
	}
	if response := saveAppAuthAPI(t, edit); response.Code != http.StatusOK {
		t.Fatalf("edit retry failed after storage recovery: HTTP %d", response.Code)
	}
	items = listAppAuthAPI(t, datastoreTestOrg)
	if len(items) != 1 || items[0].Label != edit.Label || appAuthActionFields(t, auth.Id)["api_key"] != "synthetic-private-key" {
		t.Fatal("successful edit retry lost the label or existing secret")
	}
}

func TestAppAuthAPIFailedDeletionPreservesAuthAndCanBeRetried(t *testing.T) {
	for _, cacheEnabled := range []bool{false, true} {
		name := "without cache"
		if cacheEnabled {
			name = "with cache"
		}
		t.Run(name, func(t *testing.T) {
			fixture, auth := newAppAuthAPIFixture(t)
			project.CacheDb = cacheEnabled
			if response := saveAppAuthAPI(t, auth); response.Code != http.StatusOK {
				t.Fatalf("initial creation failed: HTTP %d", response.Code)
			}
			fixture.rejectDeletesToKind = "workflowappauth"
			response := requestWorkflowAPI(DeleteAppAuthentication, http.MethodDelete, appAuthPath+"/"+auth.Id, "")
			var body map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code < 400 || body["success"] != false {
				t.Errorf("rejected storage deletion was acknowledged: HTTP %d, success=%v", response.Code, body["success"])
			}
			if items := listAppAuthAPI(t, datastoreTestOrg); len(items) != 1 || items[0].Id != auth.Id {
				t.Fatal("failed deletion removed the authentication")
			}
			fixture.rejectDeletesToKind = ""
			response = requestWorkflowAPI(DeleteAppAuthentication, http.MethodDelete, appAuthPath+"/"+auth.Id, "")
			if response.Code != http.StatusOK || len(listAppAuthAPI(t, datastoreTestOrg)) != 0 {
				t.Fatal("deletion retry failed after storage recovery")
			}
		})
	}
}

func TestAppAuthAPIAuthorizedSuborgHeaderCanCreateEditReadAndDelete(t *testing.T) {
	_, auth := newAppAuthAPIFixture(t)
	user := User{Id: "release-test-user", Username: "scheduler@shuffler.io", Role: "admin", ApiKey: datastoreTestAPIKey,
		ActiveOrg: OrgMini{Id: datastoreTestOrg}, Orgs: []string{datastoreTestOrg, isolationOtherOrg}}
	encoded, err := json.Marshal([]User{user})
	if err != nil {
		t.Fatal(err)
	}
	if err := SetCache(context.Background(), "Users_"+datastoreTestAPIKey, encoded, 60); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"create", "read", "edit", "read", "delete"} {
		method, path, handler := http.MethodGet, appAuthPath, GetAppAuthentication
		if operation == "create" || operation == "edit" {
			method, handler = http.MethodPut, AddAppAuthentication
			if operation == "edit" {
				auth.Label = "suborg edited auth"
			}
		} else if operation == "delete" {
			method, path, handler = http.MethodDelete, appAuthPath+"/"+auth.Id, DeleteAppAuthentication
		}
		payload, err := json.Marshal(auth)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(method, path, strings.NewReader(string(payload)))
		request.Header.Set("Authorization", "Bearer "+datastoreTestAPIKey)
		request.Header.Set("Org-Id", isolationOtherOrg)
		response := httptest.NewRecorder()
		handler(response, request)
		var body map[string]interface{}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if response.Code != http.StatusOK || body["success"] != true {
			t.Fatalf("authorized suborg %s failed: HTTP %d", operation, response.Code)
		}
		items := listAppAuthAPI(t, isolationOtherOrg)
		if operation == "delete" {
			if len(items) != 0 {
				t.Fatal("suborg deletion did not persist")
			}
			break
		}
		if len(items) != 1 || items[0].Id != auth.Id || items[0].Label != auth.Label || items[0].OrgId != isolationOtherOrg {
			t.Fatalf("suborg %s did not persist in the header-selected organization", operation)
		}
		if len(listAppAuthAPI(t, datastoreTestOrg)) != 0 {
			t.Fatal("suborg authentication leaked into the parent list")
		}
	}
}

func TestAppAuthAPIMaskedEditPreservesSecretAcrossEncryptionRotation(t *testing.T) {
	_, auth := newAppAuthAPIFixture(t)
	if response := saveAppAuthAPI(t, auth); response.Code != http.StatusOK {
		t.Fatalf("initial creation failed: HTTP %d", response.Code)
	}
	edit := listAppAuthAPI(t, datastoreTestOrg)[0]
	t.Setenv("SHUFFLE_ENCRYPTION_MODIFIER_ROLLOVER", "release-tests-new-key")
	edit.Label = "rotated and renamed auth"
	if response := saveAppAuthAPI(t, edit); response.Code != http.StatusOK {
		t.Fatalf("masked edit during rotation failed: HTTP %d", response.Code)
	}
	if appAuthActionFields(t, auth.Id)["api_key"] != "synthetic-private-key" {
		t.Fatal("encryption rotation lost the existing authentication secret")
	}
}

func TestAppAuthAPIMalformedSavesReturnJSONAndPreserveExistingAuth(t *testing.T) {
	_, auth := newAppAuthAPIFixture(t)
	if response := saveAppAuthAPI(t, auth); response.Code != http.StatusOK {
		t.Fatalf("initial creation failed: HTTP %d", response.Code)
	}
	for _, input := range []string{"", "null", "{} {}", `{"label":`, `{"fields":"invalid"}`, `{"app":[]}`} {
		t.Run(input, func(t *testing.T) {
			response := requestWorkflowAPI(AddAppAuthentication, http.MethodPut, appAuthPath, input)
			var body map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code < 400 || response.Code >= 500 || body["success"] != false {
				t.Errorf("malformed authentication save was not rejected: HTTP %d", response.Code)
			}
			items := listAppAuthAPI(t, datastoreTestOrg)
			if len(items) != 1 || items[0].Id != auth.Id || items[0].Label != auth.Label {
				t.Fatal("malformed request changed the existing authentication")
			}
		})
	}
}

// ---- Consolidated from datastore_test.go ----

const datastoreTestOrg = "00000000-0000-4000-8000-000000000001"
const datastoreTestAPIKey = "00000000-0000-4000-8000-000000000002"

// Only the external Datastore service is substituted; requests use the real API handler.
type datastoreAPIFixture struct {
	pb.UnimplementedDatastoreServer
	mu                  sync.Mutex
	entities            []*pb.Entity
	lookupErr           error
	lookupErrKind       string
	queryErr            error
	queryErrKind        string
	rejectWritesToKind  string
	rejectDeletesToKind string
}

func (f *datastoreAPIFixture) Lookup(_ context.Context, req *pb.LookupRequest) (*pb.LookupResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	response := &pb.LookupResponse{}
	for _, key := range req.Keys {
		if key.Path[0].Kind == f.lookupErrKind && f.lookupErr != nil {
			return nil, f.lookupErr
		}
		var found *pb.Entity
		for _, entity := range f.entities {
			if entity.Key.Path[0].Kind == key.Path[0].Kind && entity.Key.Path[0].GetName() == key.Path[0].GetName() {
				found = entity
				break
			}
		}
		if found == nil {
			response.Missing = append(response.Missing, &pb.EntityResult{Entity: &pb.Entity{Key: key}})
		} else {
			response.Found = append(response.Found, &pb.EntityResult{Entity: found})
		}
	}
	return response, nil
}

func (f *datastoreAPIFixture) RunQuery(_ context.Context, req *pb.RunQueryRequest) (*pb.RunQueryResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	query := req.GetQuery()
	if f.queryErr != nil && len(query.Kind) > 0 && query.Kind[0].Name == f.queryErrKind {
		return nil, f.queryErr
	}
	batch := &pb.QueryResultBatch{MoreResults: pb.QueryResultBatch_NO_MORE_RESULTS}
	for _, entity := range f.entities {
		if entity.Key.Path[0].Kind == query.Kind[0].Name && datastoreFilterMatches(entity, query.Filter) {
			batch.EntityResults = append(batch.EntityResults, &pb.EntityResult{Entity: entity})
		}
	}
	return &pb.RunQueryResponse{Batch: batch}, nil
}

func (f *datastoreAPIFixture) Commit(_ context.Context, req *pb.CommitRequest) (*pb.CommitResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	response := &pb.CommitResponse{}
	for _, mutation := range req.Mutations {
		if key := mutation.GetDelete(); key != nil {
			if key.Path[0].Kind == f.rejectDeletesToKind {
				return nil, status.Error(codes.PermissionDenied, "fixture datastore delete rejected")
			}
			for i, existing := range f.entities {
				if existing.Key.Path[0].Kind == key.Path[0].Kind && existing.Key.Path[0].GetName() == key.Path[0].GetName() {
					f.entities = append(f.entities[:i], f.entities[i+1:]...)
					break
				}
			}
			response.MutationResults = append(response.MutationResults, &pb.MutationResult{})
			continue
		}
		entity := mutation.GetUpsert()
		if entity == nil {
			return nil, status.Error(codes.Unimplemented, "fixture only supports upserts")
		}
		if f.rejectWritesToKind != "" && entity.Key.Path[0].Kind == f.rejectWritesToKind {
			return nil, status.Error(codes.PermissionDenied, "fixture datastore write rejected")
		}
		replaced := false
		for i, existing := range f.entities {
			if existing.Key.Path[0].Kind == entity.Key.Path[0].Kind && existing.Key.Path[0].GetName() == entity.Key.Path[0].GetName() {
				f.entities[i] = entity
				replaced = true
				break
			}
		}
		if !replaced {
			f.entities = append(f.entities, entity)
		}
		response.MutationResults = append(response.MutationResults, &pb.MutationResult{Key: entity.Key, Version: 1})
	}
	return response, nil
}

func datastoreFilterMatches(entity *pb.Entity, filter *pb.Filter) bool {
	if property := filter.GetPropertyFilter(); property != nil {
		return entity.Properties[property.Property.Name].GetStringValue() == property.Value.GetStringValue()
	}
	for _, child := range filter.GetCompositeFilter().GetFilters() {
		if !datastoreFilterMatches(entity, child) {
			return false
		}
	}
	return true
}

func datastoreEntity(kind, name string, fields map[string]string) *pb.Entity {
	entity := &pb.Entity{
		Key: &pb.Key{PartitionId: &pb.PartitionId{ProjectId: "release-tests"}, Path: []*pb.Key_PathElement{
			{Kind: kind, IdType: &pb.Key_PathElement_Name{Name: name}},
		}},
		Properties: map[string]*pb.Value{},
	}
	for field, value := range fields {
		entity.Properties[field] = &pb.Value{ValueType: &pb.Value_StringValue{StringValue: value}}
	}
	return entity
}

func newDatastoreAPIFixture(t *testing.T) *datastoreAPIFixture {
	t.Helper()
	t.Setenv("SHUFFLE_SWARM_CONFIG", "")
	t.Setenv("DATASTORE_EMULATOR_HOST", "")
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	fixture := &datastoreAPIFixture{lookupErrKind: "org_cache", entities: []*pb.Entity{
		datastoreEntity("Organizations", datastoreTestOrg, map[string]string{"id": datastoreTestOrg}),
	}}
	pb.RegisterDatastoreServer(server, fixture)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	t.Cleanup(func() { listener.Close() })
	conn, err := grpc.NewClient("passthrough:///release-tests", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	client, err := datastore.NewClient(context.Background(), "release-tests", option.WithGRPCConn(conn))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	previousProject, previousCache, previousMemcached := project, requestCache, memcached
	t.Cleanup(func() { project, requestCache, memcached = previousProject, previousCache, previousMemcached })
	project = ShuffleStorage{Dbclient: *client, CacheDb: true}
	requestCache = cache.New(time.Minute, 0)
	memcached = ""
	user := User{Id: "release-test-user", Username: "scheduler@shuffler.io", ActiveOrg: OrgMini{Id: datastoreTestOrg}, Role: "admin"}
	data, err := json.Marshal(user)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetCache(context.Background(), datastoreTestAPIKey+datastoreTestOrg, data, 60); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func requestDatastoreKey(t *testing.T, key, category string) (int, map[string]interface{}) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"org_id": datastoreTestOrg, "key": key, "category": category})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/orgs/"+datastoreTestOrg+"/get_cache", strings.NewReader(string(body))).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer "+datastoreTestAPIKey)
	request.Header.Set("Org-Id", datastoreTestOrg)
	response := httptest.NewRecorder()
	HandleGetCacheKey(response, request)
	var result map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return response.Code, result
}

func TestDatastoreAPIMissingCategoryKey(t *testing.T) {
	newDatastoreAPIFixture(t)
	for attempt := 0; attempt < 2; attempt++ {
		status, result := requestDatastoreKey(t, "missing", "release_tests")
		if status != http.StatusBadRequest || result["success"] != false {
			t.Fatalf("missing key returned HTTP %d, body %#v", status, result)
		}
	}
}

func TestDatastoreAPIRejectsOldEmptyCacheRecord(t *testing.T) {
	newDatastoreAPIFixture(t)
	if err := SetCache(context.Background(), "org_cache_"+datastoreTestOrg+"_missing_release_tests", []byte(`{"key":"","value":""}`), 60); err != nil {
		t.Fatal(err)
	}
	status, result := requestDatastoreKey(t, "missing", "release_tests")
	if status != http.StatusBadRequest || result["success"] != false {
		t.Fatalf("empty cached record returned HTTP %d, body %#v", status, result)
	}
}

func TestDatastoreAPIMissingCategoryCannotReadDefaultCategory(t *testing.T) {
	fixture := newDatastoreAPIFixture(t)
	fixture.entities = append(fixture.entities, datastoreEntity("org_cache", datastoreTestOrg+"_shared", map[string]string{
		"OrgId": datastoreTestOrg, "Key": "shared", "category": "", "Value": "default-category-secret", "PublicAuthorization": "fixture-public",
	}))
	status, result := requestDatastoreKey(t, "shared", "release_tests")
	if status != http.StatusBadRequest || result["success"] != false || result["value"] != nil {
		t.Fatalf("missing category lookup did not fail cleanly: HTTP %d, body %#v", status, result)
	}
}

func TestDatastoreAPIDefaultCannotReadNamedCategory(t *testing.T) {
	fixture := newDatastoreAPIFixture(t)
	fixture.entities = append(fixture.entities, datastoreEntity("org_cache", datastoreTestOrg+"_shared_release_tests", map[string]string{
		"OrgId": datastoreTestOrg, "Key": "shared", "category": "release_tests", "Value": "named-category-secret", "PublicAuthorization": "fixture-public",
	}))
	status, result := requestDatastoreKey(t, "shared", "default")
	if status != http.StatusBadRequest || result["success"] != false || result["value"] != nil {
		t.Fatalf("default category returned another category's key: HTTP %d, body %#v", status, result)
	}
}

func TestDatastoreAPIRejectsOldCacheFromAnotherCategory(t *testing.T) {
	newDatastoreAPIFixture(t)
	if err := SetCache(context.Background(), "org_cache_"+datastoreTestOrg+"_shared", []byte(`{"key":"shared","category":"release_tests","value":"named-category-secret"}`), 60); err != nil {
		t.Fatal(err)
	}
	status, result := requestDatastoreKey(t, "shared", "default")
	if status != http.StatusBadRequest || result["success"] != false || result["value"] != nil {
		t.Fatalf("cached category mismatch returned HTTP %d, body %#v", status, result)
	}
}

func TestDatastoreAPICannotReturnRecordWithoutKey(t *testing.T) {
	fixture := newDatastoreAPIFixture(t)
	fixture.entities = append(fixture.entities, datastoreEntity("org_cache", datastoreTestOrg+"_broken_release_tests", map[string]string{
		"OrgId": datastoreTestOrg, "category": "release_tests", "Value": "orphan-value", "PublicAuthorization": "fixture-public",
	}))
	status, result := requestDatastoreKey(t, "broken", "release_tests")
	if status != http.StatusBadRequest || result["success"] != false || result["value"] != nil {
		t.Fatalf("record without key returned HTTP %d, body %#v", status, result)
	}
}

func TestDatastoreAPIRecoversEmptyValueFromOldEmptyCache(t *testing.T) {
	fixture := newDatastoreAPIFixture(t)
	fixture.entities = append(fixture.entities, datastoreEntity("org_cache", datastoreTestOrg+"_empty_release_tests", map[string]string{
		"OrgId": datastoreTestOrg, "Key": "empty", "category": "release_tests", "Value": "", "PublicAuthorization": "fixture-public",
	}))
	if err := SetCache(context.Background(), "org_cache_"+datastoreTestOrg+"_empty_release_tests", []byte(`{"key":"","value":"stale"}`), 60); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		status, result := requestDatastoreKey(t, "empty", "release_tests")
		if status != http.StatusOK || result["success"] != true || result["key"] != "empty" || result["category"] != "release_tests" || result["value"] != "" {
			t.Fatalf("valid empty value returned HTTP %d, body %#v", status, result)
		}
	}
}

func TestDatastoreAPIPreservesLegacyCategoryLookups(t *testing.T) {
	for _, test := range []struct{ category, storedCategory, key, requestedKey string }{
		{"", "", "Shared Key", "shared_key"},
		{"default", "default", "shared", "shared"},
		{"Release Tests", "release_tests", "Shared Key", "shared_key"},
		{"shuffle-security_vulns", "shuffle-security_vulnerabilities", "shared", "shared"},
	} {
		t.Run(test.category, func(t *testing.T) {
			fixture := newDatastoreAPIFixture(t)
			name := "legacy-noncanonical-id"
			if test.storedCategory == "shuffle-security_vulnerabilities" {
				name = datastoreTestOrg + "_shared_shuffle-security_vulnerabilities"
			}
			fixture.entities = append(fixture.entities, datastoreEntity("org_cache", name, map[string]string{
				"OrgId": datastoreTestOrg, "Key": test.key, "category": test.storedCategory, "Value": "legacy-value", "PublicAuthorization": "fixture-public",
			}))
			status, result := requestDatastoreKey(t, test.requestedKey, test.category)
			if status != http.StatusOK || result["success"] != true || result["key"] != test.key || result["category"] != test.storedCategory || result["value"] != "legacy-value" {
				t.Fatalf("legacy key returned HTTP %d, body %#v", status, result)
			}
		})
	}
}

func TestDatastoreAPIStorageErrorDoesNotBecomeSuccess(t *testing.T) {
	fixture := newDatastoreAPIFixture(t)
	fixture.lookupErr = status.Error(codes.PermissionDenied, "fixture storage denied")
	for attempt := 0; attempt < 2; attempt++ {
		status, result := requestDatastoreKey(t, "missing", "release_tests")
		if status != http.StatusBadRequest || result["success"] != false || result["value"] != nil {
			t.Fatalf("storage error returned HTTP %d, body %#v", status, result)
		}
	}
}

// ---- Consolidated from encryption_test.go ----

func TestHandleKeyDecryptionRotationLegacyPlaintextAndTamperedCiphertext(t *testing.T) {
	const (
		passphrase = "org_created_label_field"
		primary    = "old-modifier"
		rollover   = "new-modifier"
	)

	t.Setenv("SHUFFLE_ENCRYPTION_MODIFIER", primary)
	t.Setenv("SHUFFLE_ENCRYPTION_MODIFIER_ROLLOVER", "")
	oldCiphertext, err := HandleKeyEncryption([]byte("old value"), passphrase)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("SHUFFLE_ENCRYPTION_MODIFIER_ROLLOVER", rollover)
	newCiphertext, err := HandleKeyEncryption([]byte("new value"), passphrase)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		ciphertext []byte
		want       []byte
	}{
		{oldCiphertext, []byte("old value")},
		{newCiphertext, []byte("new value")},
	} {
		got, err := HandleKeyDecryption(test.ciphertext, passphrase)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, test.want) {
			t.Fatalf("got %q, want %q", got, test.want)
		}
	}

	// The helper intentionally preserves legacy non-encrypted values.
	for _, legacy := range []string{"plaintext", "short", "dGV4dA=="} {
		got, err := HandleKeyDecryption([]byte(legacy), passphrase)
		if err != nil || string(got) != legacy {
			t.Fatalf("legacy value compatibility changed: error=%v, got=%q", err, got)
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(string(newCiphertext))
	if err != nil {
		t.Fatal(err)
	}
	decoded[len(decoded)-1] ^= 1
	if _, err := HandleKeyDecryption([]byte(base64.StdEncoding.EncodeToString(decoded)), passphrase); err == nil {
		t.Fatal("tampered authenticated ciphertext was accepted")
	}
	if _, err := HandleKeyDecryption(newCiphertext, "wrong-passphrase"); err == nil {
		t.Fatal("encrypted value was accepted with the wrong passphrase")
	}
}

// ---- Consolidated from environments_test.go ----

const environmentAPIPath = "/api/v1/environments"

func newEnvironmentAPIFixture(t *testing.T) (*datastoreAPIFixture, []Environment) {
	t.Helper()
	fixture := newDatastoreAPIFixture(t)
	project.Environment = "cloud"
	project.GceProject = "release-tests"
	for _, id := range []string{datastoreTestOrg, isolationOtherOrg} {
		org := Org{Id: id}
		org.SyncFeatures.MultiEnv.Limit = 20
		if _, err := project.Dbclient.Put(context.Background(), datastore.NameKey("Organizations", id, nil), &org); err != nil {
			t.Fatal(err)
		}
	}
	items := []Environment{
		{Id: "00000000-0000-4000-8000-000000000121", Name: "Cloud", Type: "cloud", OrgId: datastoreTestOrg, Default: true, Auth: "synthetic-cloud-auth"},
		{Id: "00000000-0000-4000-8000-000000000122", Name: "Release Relay", Type: "onprem", OrgId: datastoreTestOrg, Auth: "synthetic-relay-auth"},
		{Id: "00000000-0000-4000-8000-000000000123", Name: "Cloud", Type: "cloud", OrgId: isolationOtherOrg, Default: true, Auth: "synthetic-foreign-auth"},
	}
	for _, item := range items {
		if _, err := project.Dbclient.Put(context.Background(), datastore.NameKey("Environments", item.Id, nil), &item); err != nil {
			t.Fatal(err)
		}
	}
	owner, err := json.Marshal(User{Id: "environment-owner", Username: "scheduler@shuffler.io", Role: "admin", ActiveOrg: OrgMini{Id: isolationOtherOrg}})
	if err != nil {
		t.Fatal(err)
	}
	if err := SetCache(context.Background(), workflowOwnerAPIKey+isolationOtherOrg, owner, 60); err != nil {
		t.Fatal(err)
	}
	return fixture, items[:2]
}

func listEnvironmentAPI(t *testing.T, org string) map[string]Environment {
	t.Helper()
	key := datastoreTestAPIKey
	if org == isolationOtherOrg {
		key = workflowOwnerAPIKey
	}
	request := httptest.NewRequest(http.MethodGet, environmentAPIPath, nil)
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("Org-Id", org)
	response := httptest.NewRecorder()
	HandleGetEnvironments(response, request)
	var items []Environment
	if err := json.Unmarshal(response.Body.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK {
		t.Fatalf("environment list failed: HTTP %d", response.Code)
	}
	result := map[string]Environment{}
	for _, item := range items {
		if item.Id == "" || item.OrgId != org {
			t.Fatal("environment list returned a missing identity or a foreign record")
		}
		if _, duplicate := result[item.Id]; duplicate {
			t.Fatal("environment list returned duplicate IDs")
		}
		result[item.Id] = item
	}
	return result
}

func saveEnvironmentAPI(t *testing.T, items []Environment) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	return requestWorkflowAPI(HandleSetEnvironments, http.MethodPut, environmentAPIPath, string(body))
}

func TestEnvironmentAPIReadRenameAndArchivePreserveIdentityAndAuth(t *testing.T) {
	_, items := newEnvironmentAPIFixture(t)
	if saved := listEnvironmentAPI(t, datastoreTestOrg); len(saved) != 2 || saved[items[1].Id].Name != "Release Relay" {
		t.Fatal("initial environment configuration was not readable")
	}
	items[1].Name = "Renamed Relay"
	items[1].Auth = "untrusted replacement token"
	response := saveEnvironmentAPI(t, items)
	if response.Code != http.StatusOK {
		t.Fatalf("environment rename failed: HTTP %d, %s", response.Code, response.Body.String())
	}
	saved := listEnvironmentAPI(t, datastoreTestOrg)
	if len(saved) != 2 || saved[items[1].Id].Name != "Renamed Relay" || saved[items[1].Id].Auth != "synthetic-relay-auth" {
		t.Fatal("rename changed the environment identity or execution authentication")
	}
	items[1].Archived = true
	response = saveEnvironmentAPI(t, items)
	saved = listEnvironmentAPI(t, datastoreTestOrg)
	if response.Code != http.StatusOK || !saved[items[1].Id].Archived || saved[items[0].Id].Archived || !saved[items[0].Id].Default {
		t.Fatal("archiving the relay changed the active default Cloud environment")
	}
}

func TestEnvironmentAPIFailedSavePreservesExistingConfiguration(t *testing.T) {
	fixture, items := newEnvironmentAPIFixture(t)
	if len(listEnvironmentAPI(t, datastoreTestOrg)) != 2 {
		t.Fatal("initial environment list control failed")
	}
	updated := append([]Environment(nil), items...)
	updated[1].Name = "relay after recovery"
	fixture.rejectWritesToKind = "Environments"
	response := saveEnvironmentAPI(t, updated)
	var body map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code < 400 || body["success"] != false {
		t.Errorf("failed storage write was acknowledged: HTTP %d", response.Code)
	}
	fixture.rejectWritesToKind = ""
	// Model a subsequent request on a replica without this process's cached list.
	DeleteCache(context.Background(), "Environments_"+datastoreTestOrg)
	saved := listEnvironmentAPI(t, datastoreTestOrg)
	if len(saved) != 2 || saved[items[0].Id].Auth != items[0].Auth || saved[items[1].Id].Name != items[1].Name || saved[items[1].Id].Auth != items[1].Auth {
		t.Error("rejected save destroyed the previously saved environments or their execution authentication")
	}
	response = saveEnvironmentAPI(t, updated)
	saved = listEnvironmentAPI(t, datastoreTestOrg)
	if response.Code != http.StatusOK || len(saved) != 2 || saved[items[1].Id].Name != updated[1].Name {
		t.Fatal("environment save could not be retried after storage recovery")
	}
	if saved[items[0].Id].Auth != items[0].Auth || saved[items[1].Id].Auth != items[1].Auth {
		t.Error("recovery changed the execution authentication of existing environments")
	}
}

func TestEnvironmentAPIForeignIDCannotTransferOwnershipOrOverwriteConfiguration(t *testing.T) {
	for _, forgedDistribution := range []bool{false, true} {
		name := "foreign ID"
		if forgedDistribution {
			name = "foreign ID with forged distribution"
		}
		t.Run(name, func(t *testing.T) {
			_, items := newEnvironmentAPIFixture(t)
			foreign := listEnvironmentAPI(t, isolationOtherOrg)
			if len(foreign) != 1 || len(listEnvironmentAPI(t, datastoreTestOrg)) != 2 {
				t.Fatal("initial organization-isolation control failed")
			}
			const foreignID = "00000000-0000-4000-8000-000000000123"
			injected := foreign[foreignID]
			injected.Name = "unauthorized environment change"
			injected.Auth = "untrusted execution authentication"
			if forgedDistribution {
				injected.SuborgDistribution = []string{datastoreTestOrg}
			}
			response := saveEnvironmentAPI(t, append(items, injected))
			var body map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code < 400 || body["success"] != false {
				t.Errorf("foreign environment ID was accepted for mutation: HTTP %d", response.Code)
			}
			DeleteCache(context.Background(), "Environments_"+isolationOtherOrg)
			DeleteCache(context.Background(), "Environments_"+datastoreTestOrg)
			ownerView := listEnvironmentAPI(t, isolationOtherOrg)
			if ownerView[foreignID].Name != "Cloud" || ownerView[foreignID].Auth != "synthetic-foreign-auth" || ownerView[foreignID].OrgId != isolationOtherOrg {
				t.Error("caller changed the foreign owner's environment identity, configuration, or execution auth")
			}
			if len(listEnvironmentAPI(t, datastoreTestOrg)) != 2 {
				t.Error("foreign environment appeared in the caller's own configuration")
			}
		})
	}
}

func TestEnvironmentAPIGetByIDOrNameStaysOrganizationScoped(t *testing.T) {
	_, items := newEnvironmentAPIFixture(t)
	for _, identity := range []string{items[1].Id, "release_relay"} {
		response := requestWorkflowAPI(HandleGetEnvironments, http.MethodGet, environmentAPIPath+"/"+identity, "")
		var env Environment
		if err := json.Unmarshal(response.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		if response.Code != http.StatusOK || env.Id != items[1].Id || env.OrgId != datastoreTestOrg || env.Auth != "synthetic-relay-auth" {
			t.Fatalf("authorized environment lookup failed: HTTP %d", response.Code)
		}
	}
	for _, identity := range []string{"00000000-0000-4000-8000-000000000123", "missing-relay"} {
		response := requestWorkflowAPI(HandleGetEnvironments, http.MethodGet, environmentAPIPath+"/"+identity, "")
		var body map[string]interface{}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if response.Code < 400 || response.Code >= 500 || body["success"] != false || strings.Contains(response.Body.String(), "synthetic-foreign-auth") {
			t.Fatalf("foreign/missing environment lookup was not safely rejected: HTTP %d", response.Code)
		}
	}
}

func TestEnvironmentAPINonAdminCanReadButCannotSave(t *testing.T) {
	for _, role := range []string{"org-reader", "user"} {
		t.Run(role, func(t *testing.T) {
			_, items := newEnvironmentAPIFixture(t)
			user, err := json.Marshal(User{Id: "release-test-user", Username: "scheduler@shuffler.io", Role: role, ActiveOrg: OrgMini{Id: datastoreTestOrg}})
			if err != nil {
				t.Fatal(err)
			}
			if err := SetCache(context.Background(), datastoreTestAPIKey+datastoreTestOrg, user, 60); err != nil {
				t.Fatal(err)
			}
			if len(listEnvironmentAPI(t, datastoreTestOrg)) != 2 {
				t.Fatal("non-admin user lost environment read access")
			}
			items[1].Name = "non-admin mutation"
			response := saveEnvironmentAPI(t, items)
			var body map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || body["success"] != false {
				t.Errorf("non-admin environment save was not denied: HTTP %d", response.Code)
			}
			if listEnvironmentAPI(t, datastoreTestOrg)[items[1].Id].Name != "Release Relay" {
				t.Fatal("denied save changed the existing environment")
			}
		})
	}
}

func TestEnvironmentAPIMissingAndInvalidCredentialsCannotReadOrSave(t *testing.T) {
	_, items := newEnvironmentAPIFixture(t)
	items[1].Name = "unauthorized mutation"
	payload, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{"", "Bearer 00000000-0000-4000-8000-000000000129", "Basic invalid"} {
		for _, method := range []string{http.MethodGet, http.MethodPut} {
			t.Run(credential+"/"+method, func(t *testing.T) {
				request := httptest.NewRequest(method, environmentAPIPath, strings.NewReader(string(payload)))
				request.Header.Set("Authorization", credential)
				request.Header.Set("Org-Id", datastoreTestOrg)
				response := httptest.NewRecorder()
				if method == http.MethodGet {
					HandleGetEnvironments(response, request)
				} else {
					HandleSetEnvironments(response, request)
				}
				var body map[string]interface{}
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || body["success"] != false {
					t.Errorf("unauthenticated environment request was not denied: HTTP %d", response.Code)
				}
				if strings.Contains(response.Body.String(), "synthetic-") {
					t.Error("unauthenticated environment request exposed execution authentication")
				}
				if listEnvironmentAPI(t, datastoreTestOrg)[items[1].Id].Name != "Release Relay" {
					t.Fatal("unauthenticated save changed the environment")
				}
			})
		}
	}
}

func TestEnvironmentAPIMalformedSavePreservesConfiguration(t *testing.T) {
	_, items := newEnvironmentAPIFixture(t)
	for _, input := range []string{"", "null", "[]", "{}", "[", `[{"archived":"invalid"}]`, `[{"default":true}] {}`} {
		t.Run(input, func(t *testing.T) {
			response := requestWorkflowAPI(HandleSetEnvironments, http.MethodPut, environmentAPIPath, input)
			var body map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code < 400 || response.Code >= 500 || body["success"] != false {
				t.Errorf("malformed environment save was not rejected: HTTP %d", response.Code)
			}
			saved := listEnvironmentAPI(t, datastoreTestOrg)
			if len(saved) != 2 || saved[items[0].Id].Auth != items[0].Auth || saved[items[1].Id].Name != "Release Relay" {
				t.Fatal("malformed save changed existing configuration")
			}
		})
	}
}

func TestEnvironmentAPIUnsafeArchiveRequestsLeaveConfigurationUnchanged(t *testing.T) {
	for _, kind := range []string{"cloud", "default relay", "all archived"} {
		t.Run(kind, func(t *testing.T) {
			_, items := newEnvironmentAPIFixture(t)
			if kind == "cloud" {
				items[0].Archived = true
			} else if kind == "default relay" {
				items[0].Default = false
				items[1].Default, items[1].Archived = true, true
			} else {
				for i := range items {
					items[i].Type, items[i].Default, items[i].Archived = "onprem", false, true
				}
			}
			response := saveEnvironmentAPI(t, items)
			var body map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code < 400 || response.Code >= 500 || body["success"] != false {
				t.Errorf("unsafe archive request was not rejected: HTTP %d", response.Code)
			}
			saved := listEnvironmentAPI(t, datastoreTestOrg)
			if len(saved) != 2 || saved[items[0].Id].Archived || !saved[items[0].Id].Default || saved[items[1].Id].Archived {
				t.Fatal("rejected archive request changed active/default configuration")
			}
		})
	}
}

func TestEnvironmentAPICloudArchiveProtectionUsesStoredType(t *testing.T) {
	_, items := newEnvironmentAPIFixture(t)
	items[0].Type, items[0].Default, items[0].Archived = "onprem", false, true
	items[1].Default = true
	response := saveEnvironmentAPI(t, items)
	var body map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code < 400 || body["success"] != false {
		t.Errorf("changing submitted type bypassed cloud archive protection: HTTP %d", response.Code)
	}
	saved := listEnvironmentAPI(t, datastoreTestOrg)
	if saved[items[0].Id].Archived || !saved[items[0].Id].Default || saved[items[1].Id].Default {
		t.Fatal("forged type changed the protected Cloud environment's active/default state")
	}
}

func TestEnvironmentAPIOrgHeaderRequiresMembershipAndAllowsAuthorizedSuborgSave(t *testing.T) {
	for _, authorized := range []bool{false, true} {
		name := "forged header"
		if authorized {
			name = "authorized suborg header"
		}
		t.Run(name, func(t *testing.T) {
			_, own := newEnvironmentAPIFixture(t)
			orgs := []string{datastoreTestOrg}
			if authorized {
				orgs = append(orgs, isolationOtherOrg)
			}
			user := User{Id: "release-test-user", Username: "scheduler@shuffler.io", Role: "admin", ApiKey: datastoreTestAPIKey,
				ActiveOrg: OrgMini{Id: datastoreTestOrg}, Orgs: orgs}
			encoded, err := json.Marshal([]User{user})
			if err != nil {
				t.Fatal(err)
			}
			if err := SetCache(context.Background(), "Users_"+datastoreTestAPIKey, encoded, 60); err != nil {
				t.Fatal(err)
			}
			foreign := listEnvironmentAPI(t, isolationOtherOrg)
			items := []Environment{foreign["00000000-0000-4000-8000-000000000123"],
				{Id: "00000000-0000-4000-8000-000000000124", Name: "Suborg Relay", Type: "onprem", OrgId: datastoreTestOrg}}
			payload, err := json.Marshal(items)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPut, environmentAPIPath, strings.NewReader(string(payload)))
			request.Header.Set("Authorization", "Bearer "+datastoreTestAPIKey)
			request.Header.Set("Org-Id", isolationOtherOrg)
			response := httptest.NewRecorder()
			HandleSetEnvironments(response, request)
			var body map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			saved := listEnvironmentAPI(t, isolationOtherOrg)
			if authorized {
				if response.Code != http.StatusOK || body["success"] != true || len(saved) != 2 || saved[items[1].Id].OrgId != isolationOtherOrg || saved[items[1].Id].Name != "Suborg Relay" {
					t.Fatal("authorized suborg header did not scope the save to the selected organization")
				}
			} else if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || body["success"] != false || len(saved) != 1 {
				t.Fatal("forged suborg header changed another organization's configuration")
			}
			if savedOwn := listEnvironmentAPI(t, datastoreTestOrg); len(savedOwn) != 2 || savedOwn[own[1].Id].Name != own[1].Name {
				t.Fatal("suborg request changed the caller's original organization")
			}
		})
	}
}

// ---- Consolidated from executions_test.go ----

const executionTestID = "00000000-0000-4000-8000-000000000091"
const executionTestToken = "00000000-0000-4000-8000-000000000092"

func newExecutionAPIFixture(t *testing.T) (*datastoreAPIFixture, WorkflowExecution) {
	t.Helper()
	fixture := newDatastoreAPIFixture(t)
	fixture.entities = append(fixture.entities, datastoreEntity("Organizations", isolationOtherOrg, map[string]string{"id": isolationOtherOrg}))
	project.GceProject = "release-tests"
	project.Environment = "onprem"
	previous := standalone
	standalone = false
	t.Setenv("STANDALONE", "false")
	t.Cleanup(func() { standalone = previous })
	first := Action{ID: "00000000-0000-4000-8000-000000000093", Name: "repeat_back_to_me", AppName: "Shuffle Tools", Label: "completed"}
	second := Action{ID: "00000000-0000-4000-8000-000000000094", Name: "repeat_back_to_me", AppName: "Shuffle Tools", Label: "running"}
	execution := WorkflowExecution{
		ExecutionId: executionTestID, Authorization: executionTestToken, WorkflowId: workflowTestID,
		ExecutionOrg: datastoreTestOrg, OrgId: datastoreTestOrg, Status: "EXECUTING", Start: first.ID, StartedAt: time.Now().Unix(),
		Workflow: Workflow{ID: workflowTestID, Owner: "release-test-user", OrgId: datastoreTestOrg, Actions: []Action{first, second}},
		Results: []ActionResult{
			{Action: first, ExecutionId: executionTestID, Status: "SUCCESS", Result: "completed output", StartedAt: 1000, CompletedAt: 2000},
			{Action: second, ExecutionId: executionTestID, Status: "EXECUTING", Result: "in progress", StartedAt: 2000},
		},
	}
	return fixture, execution
}

func seedExecutionAPI(t *testing.T, execution WorkflowExecution) {
	t.Helper()
	ctx := context.Background()
	for _, item := range []struct {
		kind, id string
		value    interface{}
	}{
		{"workflow", execution.Workflow.ID, &execution.Workflow},
		{"workflowexecution", execution.ExecutionId, &execution},
	} {
		if _, err := project.Dbclient.Put(ctx, datastore.NameKey(item.kind, item.id, nil), item.value); err != nil {
			t.Fatal(err)
		}
	}
	// A completed validation snapshot keeps unrelated background validation outside this fixture.
	for key, value := range map[string]interface{}{
		"workflowexecution_" + execution.ExecutionId: execution,
		"validation_" + execution.ExecutionId:        TypeValidation{ExecutionId: execution.ExecutionId, ValidationRan: true},
	} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := SetCache(ctx, key, data, 60); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExecutionAPIAbortStopsWaitingActions(t *testing.T) {
	_, execution := newExecutionAPIFixture(t)
	execution.Results[1].Status = "WAITING"
	seedExecutionAPI(t, execution)
	response := requestWorkflowAPI(AbortExecution, http.MethodPost, "/api/v1/workflows/"+workflowTestID+"/executions/"+executionTestID+"/abort", "")
	items := executionHistory(t)
	if response.Code != http.StatusOK || len(items) != 1 || items[0].Status != "ABORTED" {
		t.Fatalf("waiting execution was not aborted: HTTP %d, %+v", response.Code, items)
	}
	for _, result := range items[0].Results {
		if result.Status == "WAITING" || result.Status == "EXECUTING" {
			t.Fatalf("terminal execution still contains active work: %+v", result)
		}
	}
}

func TestExecutionAPIAbortCanRetryAfterPersistenceFailure(t *testing.T) {
	fixture, execution := newExecutionAPIFixture(t)
	seedExecutionAPI(t, execution)
	fixture.rejectWritesToKind = "workflowexecution"
	path := "/api/v1/workflows/" + workflowTestID + "/executions/" + executionTestID + "/abort"
	rejected := requestWorkflowAPI(AbortExecution, http.MethodPost, path, "")
	var result map[string]interface{}
	if err := json.Unmarshal(rejected.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if rejected.Code == http.StatusOK || result["success"] != false {
		t.Fatalf("rejected abort write was acknowledged: HTTP %d, %s", rejected.Code, rejected.Body.String())
	}
	items := executionHistory(t)
	if len(items) != 1 || items[0].Status != "EXECUTING" {
		t.Fatalf("failed write changed persisted execution: %+v", items)
	}
	fixture.rejectWritesToKind = ""
	retried := requestWorkflowAPI(AbortExecution, http.MethodPost, path, "")
	items = executionHistory(t)
	if retried.Code != http.StatusOK {
		t.Errorf("abort retry was rejected after recovery: HTTP %d, %s", retried.Code, retried.Body.String())
	}
	if len(items) != 1 {
		t.Fatalf("abort retry lost execution history: %d records", len(items))
	}
	if items[0].Status != "ABORTED" {
		t.Fatalf("abort retry did not persist after recovery: status %q", items[0].Status)
	}
}

func TestExecutionAPIReadOnlyOwnerCannotAbort(t *testing.T) {
	_, execution := newExecutionAPIFixture(t)
	seedExecutionAPI(t, execution)
	user, err := json.Marshal(User{Id: "release-test-user", Username: "scheduler@shuffler.io", Role: "org-reader", ActiveOrg: OrgMini{Id: datastoreTestOrg}})
	if err != nil {
		t.Fatal(err)
	}
	if err := SetCache(context.Background(), datastoreTestAPIKey+datastoreTestOrg, user, 60); err != nil {
		t.Fatal(err)
	}
	response := requestWorkflowAPI(AbortExecution, http.MethodPost, "/api/v1/workflows/"+workflowTestID+"/executions/"+executionTestID+"/abort", "")
	if response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden {
		t.Errorf("read-only owner was allowed to abort: HTTP %d", response.Code)
	}
	items := executionHistory(t)
	if len(items) != 1 || items[0].Status != "EXECUTING" {
		t.Fatal("read-only abort changed persisted execution state")
	}
}

func TestExecutionAPIUntrustedAbortCannotChangeStateOrRevealResults(t *testing.T) {
	for _, credential := range []string{"", "Bearer 00000000-0000-4000-8000-000000000095", "Basic " + executionTestToken} {
		t.Run(credential, func(t *testing.T) {
			_, execution := newExecutionAPIFixture(t)
			seedExecutionAPI(t, execution)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflowTestID+"/executions/"+executionTestID+"/abort", nil)
			request.Header.Set("Authorization", credential)
			request.Header.Set("Org-Id", datastoreTestOrg)
			response := httptest.NewRecorder()
			AbortExecution(response, request)
			var result map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || result["success"] != false {
				t.Fatalf("unauthorized abort was not denied: HTTP %d, %s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "completed output") || strings.Contains(response.Body.String(), executionTestToken) {
				t.Fatal("denied abort exposed private execution data")
			}
			items := executionHistory(t)
			if len(items) != 1 || items[0].Status != "EXECUTING" || items[0].Results[0].Result != "completed output" {
				t.Fatal("unauthorized abort changed persisted work")
			}
		})
	}
}

func TestExecutionAPIExecutionTokenCanAbortWithoutAUserSession(t *testing.T) {
	_, execution := newExecutionAPIFixture(t)
	seedExecutionAPI(t, execution)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflowTestID+"/executions/"+executionTestID+"/abort", nil)
	request.Header.Set("Authorization", "Bearer "+executionTestToken)
	request.Header.Set("Org-Id", datastoreTestOrg)
	response := httptest.NewRecorder()
	AbortExecution(response, request)
	items := executionHistory(t)
	if response.Code != http.StatusOK || len(items) != 1 || items[0].Status != "ABORTED" {
		t.Fatalf("valid execution token did not abort: HTTP %d", response.Code)
	}
}

func TestExecutionAPIAbortDoesNotChangeAlreadyTerminalRuns(t *testing.T) {
	for _, status := range []string{"FINISHED", "ABORTED", "FAILURE"} {
		t.Run(status, func(t *testing.T) {
			_, execution := newExecutionAPIFixture(t)
			execution.Status = status
			execution.CompletedAt = execution.StartedAt + 1
			execution.Results[1].Status = "SUCCESS"
			execution.Results[1].Result = "final output"
			seedExecutionAPI(t, execution)
			response := requestWorkflowAPI(AbortExecution, http.MethodPost, "/api/v1/workflows/"+workflowTestID+"/executions/"+executionTestID+"/abort", "")
			var result map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if response.Code == http.StatusOK || result["success"] != false {
				t.Fatalf("terminal abort was acknowledged as a new mutation: HTTP %d", response.Code)
			}
			items := executionHistory(t)
			if len(items) != 1 || items[0].Status != status || items[0].CompletedAt != execution.CompletedAt || len(items[0].Results) != 2 || items[0].Results[1].Result != "final output" {
				t.Fatal("abort changed an already terminal run")
			}
		})
	}
}

func TestExecutionAPIAbortBeforeFirstResultRecordsTheTimeoutReason(t *testing.T) {
	_, execution := newExecutionAPIFixture(t)
	execution.Results = nil
	seedExecutionAPI(t, execution)
	reason := "release timeout: \"waiting for first action\"\nretry required"
	response := requestWorkflowAPI(AbortExecution, http.MethodPost, "/api/v1/workflows/"+workflowTestID+"/executions/"+executionTestID+"/abort?reason="+url.QueryEscape(reason), "")
	items := executionHistory(t)
	if response.Code != http.StatusOK || len(items) != 1 || items[0].Status != "ABORTED" || len(items[0].Results) != 1 {
		t.Fatalf("abort did not record initial failure: HTTP %d", response.Code)
	}
	result := items[0].Results[0]
	var failure SubflowData
	if err := json.Unmarshal([]byte(result.Result), &failure); err != nil {
		t.Fatal(err)
	}
	if result.Action.ID != execution.Start || result.Status != "FAILURE" || failure.Success || failure.Result != reason {
		t.Fatalf("timeout reason was lost or malformed: status=%q, reason=%q", result.Status, failure.Result)
	}
}

func TestExecutionAPIHistoryAndAbortRemainOrganizationScoped(t *testing.T) {
	for _, operation := range []struct {
		name, method, path string
		handler            http.HandlerFunc
	}{
		{"history", http.MethodGet, "/api/v1/workflows/" + workflowTestID + "/executions", GetWorkflowExecutions},
		{"abort", http.MethodPost, "/api/v1/workflows/" + workflowTestID + "/executions/" + executionTestID + "/abort", AbortExecution},
	} {
		t.Run(operation.name, func(t *testing.T) {
			_, execution := newExecutionAPIFixture(t)
			execution.Workflow.Owner = "another-user"
			execution.Workflow.OrgId = isolationOtherOrg
			execution.OrgId = isolationOtherOrg
			execution.ExecutionOrg = isolationOtherOrg
			seedExecutionAPI(t, execution)
			response := requestWorkflowAPI(operation.handler, operation.method, operation.path, "")
			var result map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || result["success"] != false || strings.Contains(response.Body.String(), "completed output") {
				t.Fatalf("foreign execution access was not denied: HTTP %d, %s", response.Code, response.Body.String())
			}
			user, err := json.Marshal(User{Id: "another-user", Username: "scheduler@shuffler.io", Role: "admin", ActiveOrg: OrgMini{Id: isolationOtherOrg}, Orgs: []string{isolationOtherOrg}})
			if err != nil {
				t.Fatal(err)
			}
			if err := SetCache(context.Background(), datastoreTestAPIKey+isolationOtherOrg, user, 60); err != nil {
				t.Fatal(err)
			}
			ownerView := notificationRequest(GetWorkflowExecutions, http.MethodGet, "/api/v1/workflows/"+workflowTestID+"/executions", "", isolationOtherOrg)
			var items []WorkflowExecution
			if err := json.Unmarshal(ownerView.Body.Bytes(), &items); err != nil {
				t.Fatal(err)
			}
			if ownerView.Code != http.StatusOK || len(items) != 1 || items[0].Status != "EXECUTING" || items[0].Results[0].Result != "completed output" {
				t.Fatal("foreign owner's execution was changed or inaccessible after denied access")
			}
		})
	}
}

func TestExecutionAPIAuthorizedSuborgHeaderCanAbortAndReadHistory(t *testing.T) {
	_, execution := newExecutionAPIFixture(t)
	execution.Workflow.Owner = "another-user"
	execution.Workflow.OrgId = isolationOtherOrg
	execution.OrgId = isolationOtherOrg
	execution.ExecutionOrg = isolationOtherOrg
	seedExecutionAPI(t, execution)
	user, err := json.Marshal(User{Id: "release-test-user", Username: "scheduler@shuffler.io", Role: "admin", ActiveOrg: OrgMini{Id: isolationOtherOrg}, Orgs: []string{datastoreTestOrg, isolationOtherOrg}})
	if err != nil {
		t.Fatal(err)
	}
	if err := SetCache(context.Background(), datastoreTestAPIKey+isolationOtherOrg, user, 60); err != nil {
		t.Fatal(err)
	}
	abort := notificationRequest(AbortExecution, http.MethodPost, "/api/v1/workflows/"+workflowTestID+"/executions/"+executionTestID+"/abort", "", isolationOtherOrg)
	history := notificationRequest(GetWorkflowExecutions, http.MethodGet, "/api/v1/workflows/"+workflowTestID+"/executions", "", isolationOtherOrg)
	var items []WorkflowExecution
	if err := json.Unmarshal(history.Body.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	if abort.Code != http.StatusOK || history.Code != http.StatusOK || len(items) != 1 || items[0].ExecutionOrg != isolationOtherOrg || items[0].Status != "ABORTED" {
		t.Fatalf("authorized suborg lifecycle failed: abort HTTP %d, history HTTP %d", abort.Code, history.Code)
	}
}

type executionBackendTransport func(*http.Request) (*http.Response, error)

func (transport executionBackendTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestExecutionAPIBulkRerunCountsOnlyBackendAcknowledgedRuns(t *testing.T) {
	for _, backend := range []struct {
		name   string
		status int
		body   string
		ok     bool
	}{
		{"accepted", http.StatusOK, `{"success":true}`, true},
		{"unavailable", http.StatusServiceUnavailable, `{"success":false}`, false},
		{"rejected", http.StatusOK, `{"success":false}`, false},
		{"malformed", http.StatusOK, `not JSON`, false},
	} {
		t.Run(backend.name, func(t *testing.T) {
			_, execution := newExecutionAPIFixture(t)
			project.Environment = "cloud"
			t.Setenv("SHUFFLE_CLOUDRUN_URL", "https://execution-backend.test")
			t.Setenv("SHUFFLE_DISABLE_RERUN_AND_ABORT", "false")
			execution.StartedAt = time.Now().Add(-10 * time.Minute).Unix()
			for i := range execution.Workflow.Actions {
				execution.Workflow.Actions[i].Environment = "cloud"
			}
			seedExecutionAPI(t, execution)
			environment := Environment{Id: "00000000-0000-4000-8000-000000000096", Name: "cloud", OrgId: datastoreTestOrg, Type: "cloud"}
			if _, err := project.Dbclient.Put(context.Background(), datastore.NameKey("Environments", environment.Id, nil), &environment); err != nil {
				t.Fatal(err)
			}
			workflows, err := json.Marshal([]Workflow{execution.Workflow})
			if err != nil {
				t.Fatal(err)
			}
			if err := SetCache(context.Background(), datastoreTestOrg+"_workflows", workflows, 60); err != nil {
				t.Fatal(err)
			}
			previous := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = previous })
			calls := 0
			http.DefaultTransport = executionBackendTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.Host != "execution-backend.test" || request.Method != http.MethodPost || request.URL.Path != "/api/v1/workflows/"+workflowTestID+"/executions/"+executionTestID+"/rerun" || request.Header.Get("Authorization") != "Bearer "+executionTestToken {
					t.Errorf("unexpected rerun request: %s %s", request.Method, request.URL.Redacted())
				}
				return &http.Response{StatusCode: backend.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(backend.body)), Request: request}, nil
			})
			response := requestWorkflowAPI(HandleRerunExecutions, http.MethodPost, "/api/v1/environments/cloud/rerun", "")
			if calls != 1 {
				t.Fatalf("expected one resume request, got %d", calls)
			}
			var result map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if backend.ok {
				if response.Code != http.StatusOK || result["success"] != true || result["reason"] != "Successfully RERAN 1 executions" {
					t.Fatalf("accepted rerun was not counted: HTTP %d, %s", response.Code, response.Body.String())
				}
			} else if response.Code == http.StatusOK && result["success"] == true && result["reason"] != "Successfully RERAN 0 executions" {
				t.Fatalf("unacknowledged rerun was counted as successful: HTTP %d, %s", response.Code, response.Body.String())
			}
		})
	}
}

func executionHistory(t *testing.T) []WorkflowExecution {
	t.Helper()
	response := requestWorkflowAPI(GetWorkflowExecutions, http.MethodGet, "/api/v1/workflows/"+workflowTestID+"/executions", "")
	var executions []WorkflowExecution
	if err := json.Unmarshal(response.Body.Bytes(), &executions); err != nil {
		t.Fatalf("invalid execution history: HTTP %d, %s", response.Code, response.Body.String())
	}
	if response.Code != http.StatusOK {
		t.Fatalf("execution history failed: HTTP %d", response.Code)
	}
	return executions
}

func TestExecutionAPIAbortPersistsTerminalStateAndPreservesCompletedResults(t *testing.T) {
	_, execution := newExecutionAPIFixture(t)
	seedExecutionAPI(t, execution)
	path := "/api/v1/workflows/" + workflowTestID + "/executions/" + executionTestID + "/abort"
	response := requestWorkflowAPI(AbortExecution, http.MethodPost, path, "")
	if response.Code != http.StatusOK {
		t.Fatalf("abort failed: HTTP %d, %s", response.Code, response.Body.String())
	}
	items := executionHistory(t)
	if len(items) != 1 || items[0].ExecutionId != executionTestID || items[0].Status != "ABORTED" || items[0].CompletedAt < execution.StartedAt || len(items[0].Results) != 2 {
		t.Fatalf("abort did not persist a terminal execution: %+v", items)
	}
	for _, result := range items[0].Results {
		if result.Action.ID == execution.Results[0].Action.ID && (result.Status != "SUCCESS" || result.Result != "completed output") {
			t.Errorf("abort overwrote completed work: %+v", result)
		}
		if result.Action.ID == execution.Results[1].Action.ID && result.Status != "ABORTED" {
			t.Errorf("running action remained active after abort: %+v", result)
		}
	}
	completedAt := items[0].CompletedAt
	requestWorkflowAPI(AbortExecution, http.MethodPost, path, "")
	items = executionHistory(t)
	if len(items) != 1 || items[0].Status != "ABORTED" || items[0].CompletedAt != completedAt || len(items[0].Results) != 2 {
		t.Fatalf("repeated abort changed the terminal execution: %+v", items)
	}
}

// ---- Consolidated from files_test.go ----

func newFileAPIFixture(t *testing.T) *datastoreAPIFixture {
	t.Helper()
	fixture := newDatastoreAPIFixture(t)
	previous := basepath
	basepath = t.TempDir()
	t.Cleanup(func() { basepath = previous })
	t.Setenv("SHUFFLE_ENCRYPTION_MODIFIER", "release-file-test-key")
	t.Setenv("SHUFFLE_ENCRYPTION_MODIFIER_ROLLOVER", "")
	return fixture
}

func createFileThroughAPI(t *testing.T, filename string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{"filename": filename, "org_id": datastoreTestOrg, "workflow_id": "global", "namespace": "release_tests"})
	if err != nil {
		t.Fatal(err)
	}
	response := requestWorkflowAPI(HandleCreateFile, http.MethodPost, "/api/v1/files/create", string(body))
	var result struct {
		Success bool   `json:"success"`
		ID      string `json:"id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || !result.Success || !strings.HasPrefix(result.ID, "file_") {
		t.Fatalf("file creation failed: HTTP %d, %s", response.Code, response.Body.String())
	}
	return result.ID
}

func fileUploadRequest(t *testing.T, id, filename string, contents []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("shuffle_file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(contents); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/files/"+id+"/upload", &body)
	request.Header.Set("Authorization", "Bearer "+datastoreTestAPIKey)
	request.Header.Set("Org-Id", datastoreTestOrg)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	return request
}

func uploadFileThroughAPI(t *testing.T, id, filename string, contents []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := fileUploadRequest(t, id, filename, contents)
	response := httptest.NewRecorder()
	HandleUploadFile(response, request)
	return response
}

func TestFileAPIRoundTripsBytesAndMakesDeletedFileUnavailable(t *testing.T) {
	binary := make([]byte, 256)
	for i := range binary {
		binary[i] = byte(i)
	}
	for name, contents := range map[string][]byte{"empty.bin": {}, "binary.bin": binary, "Unicode-雪.txt": []byte("  spaced\tUnicode ✓ 世界\r\nlast line\n")} {
		t.Run(name, func(t *testing.T) {
			newFileAPIFixture(t)
			id := createFileThroughAPI(t, name)
			upload := uploadFileThroughAPI(t, id, name, contents)
			if upload.Code != http.StatusOK {
				t.Fatalf("upload failed: HTTP %d, %s", upload.Code, upload.Body.String())
			}
			metaResponse := requestWorkflowAPI(HandleGetFileMeta, http.MethodGet, "/api/v1/files/"+id, "")
			var metadata File
			if err := json.Unmarshal(metaResponse.Body.Bytes(), &metadata); err != nil {
				t.Fatal(err)
			}
			if metaResponse.Code != http.StatusOK || metadata.OrgId != datastoreTestOrg || metadata.Filename != name || metadata.Status != "active" || metadata.Sha256sum != fmt.Sprintf("%x", sha256.Sum256(contents)) {
				t.Fatalf("uploaded file metadata is incorrect: HTTP %d, %+v", metaResponse.Code, metadata)
			}
			download := requestWorkflowAPI(HandleGetFileContent, http.MethodGet, "/api/v1/files/"+id+"/content", "")
			if download.Code != http.StatusOK || !bytes.Equal(download.Body.Bytes(), contents) {
				t.Fatalf("download changed bytes: HTTP %d, got %q, want %q", download.Code, download.Body.Bytes(), contents)
			}
			deleted := requestWorkflowAPI(HandleDeleteFile, http.MethodDelete, "/api/v1/files/"+id, "")
			var result map[string]interface{}
			if err := json.Unmarshal(deleted.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if deleted.Code != http.StatusOK || result["success"] != true {
				t.Fatalf("delete failed: HTTP %d, %#v", deleted.Code, result)
			}
			download = requestWorkflowAPI(HandleGetFileContent, http.MethodGet, "/api/v1/files/"+id+"/content", "")
			if download.Code == http.StatusOK {
				t.Fatal("deleted file is still downloadable")
			}
		})
	}
}

type fileStorageTransport func(*http.Request) (*http.Response, error)

func (transport fileStorageTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

type cloudFileFailures struct{ rejectDelete, rejectRead, corruptRead bool }

func newCloudFileAPIFixture(t *testing.T, rejectUpload *bool) *cloudFileFailures {
	t.Helper()
	newFileAPIFixture(t)
	objects := map[string][]byte{}
	failures := &cloudFileFailures{}
	transport := fileStorageTransport(func(request *http.Request) (*http.Response, error) {
		response := httptest.NewRecorder()
		path := strings.SplitN(request.URL.Path, "/o/", 2)
		if request.Method == http.MethodPost {
			if *rejectUpload {
				response.WriteHeader(400)
				response.WriteString(`{"error":{"code":400,"message":"fixture object write rejected"}}`)
			} else {
				_, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
				if err != nil {
					return nil, err
				}
				reader := multipart.NewReader(request.Body, parameters["boundary"])
				metadataPart, err := reader.NextPart()
				if err != nil {
					return nil, err
				}
				var metadata struct {
					Name string `json:"name"`
				}
				if err := json.NewDecoder(metadataPart).Decode(&metadata); err != nil {
					return nil, err
				}
				part, err := reader.NextPart()
				if err != nil {
					return nil, err
				}
				contents, err := io.ReadAll(part)
				if err != nil {
					return nil, err
				}
				objects[metadata.Name] = contents
				json.NewEncoder(response).Encode(map[string]string{"name": metadata.Name, "bucket": orgFileBucket, "size": fmt.Sprint(len(contents))})
			}
		} else if request.Method == http.MethodDelete && failures.rejectDelete {
			response.WriteHeader(400)
			response.WriteString(`{"error":{"code":400,"message":"fixture object delete rejected"}}`)
		} else if request.Method == http.MethodGet && failures.rejectRead {
			response.WriteHeader(403)
			response.WriteString(`{"error":{"code":403,"message":"fixture object read denied"}}`)
		} else if len(path) == 2 {
			contents, exists := objects[path[1]]
			if !exists {
				response.WriteHeader(404)
				response.WriteString(`{"error":{"code":404,"message":"fixture object missing"}}`)
			} else if request.Method == http.MethodGet {
				if failures.corruptRead && len(contents) > 0 {
					contents = append([]byte(nil), contents...)
					if contents[0] == 'A' {
						contents[0] = 'B'
					} else {
						contents[0] = 'A'
					}
				}
				response.Header().Set("Content-Length", fmt.Sprint(len(contents)))
				response.Write(contents)
			} else if request.Method == http.MethodDelete {
				delete(objects, path[1])
				response.WriteHeader(204)
			} else {
				return nil, fmt.Errorf("unexpected fixture storage method %s", request.Method)
			}
		} else {
			return nil, fmt.Errorf("unexpected fixture storage path %s", request.URL.Path)
		}
		result := response.Result()
		result.Request = request
		return result, nil
	})
	client, err := storage.NewClient(context.Background(), option.WithEndpoint("http://storage.test"),
		option.WithHTTPClient(&http.Client{Transport: transport}), option.WithoutAuthentication(), storage.WithJSONReads())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	project.StorageClient = *client
	project.Environment = "cloud"
	return failures
}

func TestFileAPICloudWriteFailureIsReported(t *testing.T) {
	rejectUpload := true
	newCloudFileAPIFixture(t, &rejectUpload)
	id := createFileThroughAPI(t, "cloud-retry.bin")
	response := uploadFileThroughAPI(t, id, "cloud-retry.bin", []byte("retry these bytes"))
	var result map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusInternalServerError || result["success"] != false {
		t.Fatalf("object write rejection was reported as success: HTTP %d, %#v", response.Code, result)
	}
}

func TestFileAPICloudWriteFailureLeavesSameFileRetryable(t *testing.T) {
	rejectUpload := true
	newCloudFileAPIFixture(t, &rejectUpload)
	id := createFileThroughAPI(t, "cloud-retry.bin")
	uploadFileThroughAPI(t, id, "cloud-retry.bin", []byte("retry these bytes"))
	rejectUpload = false
	response := uploadFileThroughAPI(t, id, "cloud-retry.bin", []byte("retry these bytes"))
	if response.Code != http.StatusOK {
		t.Fatalf("file could not be retried: HTTP %d, %s", response.Code, response.Body.String())
	}
	download := requestWorkflowAPI(HandleGetFileContent, http.MethodGet, "/api/v1/files/"+id+"/content", "")
	if download.Code != http.StatusOK || download.Body.String() != "retry these bytes" {
		t.Fatalf("retried cloud upload changed bytes: HTTP %d, %q", download.Code, download.Body.String())
	}
}

func TestFileAPICloudRoundTripsExactBytes(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for name, contents := range map[string][]byte{
			"empty.bin": {}, "binary.bin": {0, 255, 128, '\r', '\n', 0, 1},
			"Unicode-雪.txt": []byte("  leading\t✓ 世界\r\nlast line\n"),
		} {
			t.Run(fmt.Sprintf("%s/encrypted=%t", name, encrypted), func(t *testing.T) {
				rejectUpload := false
				newCloudFileAPIFixture(t, &rejectUpload)
				if !encrypted {
					t.Setenv("SHUFFLE_ENCRYPTION_MODIFIER", "")
				}
				id := createFileThroughAPI(t, name)
				upload := uploadFileThroughAPI(t, id, name, contents)
				if upload.Code != http.StatusOK {
					t.Fatalf("cloud upload failed: HTTP %d, %s", upload.Code, upload.Body.String())
				}
				download := requestWorkflowAPI(HandleGetFileContent, http.MethodGet, "/api/v1/files/"+id+"/content", "")
				if download.Code != http.StatusOK || !bytes.Equal(download.Body.Bytes(), contents) {
					t.Fatalf("cloud download changed bytes: HTTP %d, got %q, want %q", download.Code, download.Body.Bytes(), contents)
				}
			})
		}
	}
}

func TestFileAPIOversizedUploadDoesNotPreventValidRetry(t *testing.T) {
	rejectUpload := false
	newCloudFileAPIFixture(t, &rejectUpload)
	previous := maxFileSize
	maxFileSize = 8
	t.Cleanup(func() { maxFileSize = previous })
	id := createFileThroughAPI(t, "size-limit.bin")
	rejected := uploadFileThroughAPI(t, id, "size-limit.bin", []byte("ninebytes"))
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("oversized file was not rejected: HTTP %d", rejected.Code)
	}
	retry := uploadFileThroughAPI(t, id, "size-limit.bin", []byte("valid"))
	// A fresh-ID control distinguishes rejected-ID retry policy from a broken upload service.
	fresh := createFileThroughAPI(t, "fresh-size-limit.bin")
	accepted := uploadFileThroughAPI(t, fresh, "fresh-size-limit.bin", []byte("valid"))
	download := requestWorkflowAPI(HandleGetFileContent, http.MethodGet, "/api/v1/files/"+fresh+"/content", "")
	if accepted.Code != http.StatusOK || download.Code != http.StatusOK || download.Body.String() != "valid" {
		t.Fatal("fresh file identity could not upload and read valid content after size rejection")
	}
	if retry.Code != http.StatusOK {
		t.Fatalf("same-ID retry is rejected while a fresh-ID retry works: HTTP %d, %s", retry.Code, retry.Body.String())
	}
}

func TestFileAPIDuplicateCanBeDownloadedWithItsOwnIdentity(t *testing.T) {
	newFileAPIFixture(t)
	for _, name := range []string{"first.bin", "duplicate.bin"} {
		id := createFileThroughAPI(t, name)
		upload := uploadFileThroughAPI(t, id, name, []byte("identical payload"))
		if upload.Code != http.StatusOK {
			t.Fatalf("upload failed: HTTP %d", upload.Code)
		}
		download := requestWorkflowAPI(HandleGetFileContent, http.MethodGet, "/api/v1/files/"+id+"/content", "")
		if download.Code != http.StatusOK || download.Body.String() != "identical payload" {
			t.Fatalf("duplicate identity cannot read its bytes: HTTP %d, %q", download.Code, download.Body.String())
		}
	}
}

func TestFileAPIDeletingOneDuplicatePreservesTheOther(t *testing.T) {
	for _, storage := range []string{"local", "cloud"} {
		t.Run(storage, func(t *testing.T) {
			if storage == "cloud" {
				rejectUpload := false
				newCloudFileAPIFixture(t, &rejectUpload)
			} else {
				newFileAPIFixture(t)
			}
			first := createFileThroughAPI(t, "first.bin")
			second := createFileThroughAPI(t, "second.bin")
			for _, id := range []string{first, second} {
				upload := uploadFileThroughAPI(t, id, "same.bin", []byte("identical payload"))
				if upload.Code != http.StatusOK {
					t.Fatalf("upload failed: HTTP %d", upload.Code)
				}
			}
			for _, id := range []string{first, second} {
				before := requestWorkflowAPI(HandleGetFileContent, http.MethodGet, "/api/v1/files/"+id+"/content", "")
				if before.Code != http.StatusOK || before.Body.String() != "identical payload" {
					t.Fatalf("duplicate control failed before deletion: HTTP %d", before.Code)
				}
			}
			deleted := requestWorkflowAPI(HandleDeleteFile, http.MethodDelete, "/api/v1/files/"+first, "")
			if deleted.Code != http.StatusOK {
				t.Fatalf("delete failed: HTTP %d", deleted.Code)
			}
			download := requestWorkflowAPI(HandleGetFileContent, http.MethodGet, "/api/v1/files/"+second+"/content", "")
			if download.Code != http.StatusOK || download.Body.String() != "identical payload" {
				t.Fatalf("deleting one file damaged another: HTTP %d, %q", download.Code, download.Body.String())
			}
		})
	}
}

func TestFileAPIRepeatedEditsReplaceRatherThanAppendBytes(t *testing.T) {
	newFileAPIFixture(t)
	t.Chdir(t.TempDir())
	basepath = "files"
	id := createFileThroughAPI(t, "edited.bin")
	if response := uploadFileThroughAPI(t, id, "edited.bin", []byte("original")); response.Code != http.StatusOK {
		t.Fatalf("upload failed: HTTP %d", response.Code)
	}
	for _, contents := range []string{"first edit", "second edit\x00with Unicode 雪"} {
		response := requestWorkflowAPI(HandleEditFile, http.MethodPut, "/api/v1/files/"+id+"/edit", contents)
		if response.Code != http.StatusOK {
			t.Fatalf("edit failed: HTTP %d, %s", response.Code, response.Body.String())
		}
		download := requestWorkflowAPI(HandleGetFileContent, http.MethodGet, "/api/v1/files/"+id+"/content", "")
		if download.Code != http.StatusOK || download.Body.String() != contents {
			t.Fatalf("edit did not replace the bytes: HTTP %d, got %q, want %q", download.Code, download.Body.String(), contents)
		}
	}
}

func TestFileAPIEditHonorsConfiguredStorageDirectory(t *testing.T) {
	newFileAPIFixture(t)
	t.Chdir(t.TempDir())
	id := createFileThroughAPI(t, "configured-directory.bin")
	if response := uploadFileThroughAPI(t, id, "configured-directory.bin", []byte("original")); response.Code != http.StatusOK {
		t.Fatalf("upload failed: HTTP %d", response.Code)
	}
	response := requestWorkflowAPI(HandleEditFile, http.MethodPut, "/api/v1/files/"+id+"/edit", "replacement bytes")
	if response.Code != http.StatusOK {
		t.Fatalf("edit ignored configured storage root: HTTP %d, %s", response.Code, response.Body.String())
	}
}

func TestFileAPIReaderCanReadButCannotMutate(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{"create": HandleCreateFile, "upload": HandleUploadFile, "edit": HandleEditFile, "delete": HandleDeleteFile} {
		t.Run(name, func(t *testing.T) {
			newFileAPIFixture(t)
			id := createFileThroughAPI(t, "reader.bin")
			if name != "upload" {
				if response := uploadFileThroughAPI(t, id, "reader.bin", []byte("readable bytes")); response.Code != http.StatusOK {
					t.Fatalf("upload failed: HTTP %d", response.Code)
				}
			}
			data, err := json.Marshal(User{Id: "release-test-user", Username: "scheduler@shuffler.io", Role: "org-reader", ActiveOrg: OrgMini{Id: datastoreTestOrg}})
			if err != nil {
				t.Fatal(err)
			}
			if err := SetCache(context.Background(), datastoreTestAPIKey+datastoreTestOrg, data, 60); err != nil {
				t.Fatal(err)
			}
			var response *httptest.ResponseRecorder
			switch name {
			case "create":
				response = requestWorkflowAPI(handler, http.MethodPost, "/api/v1/files/create", `{"filename":"denied.bin","workflow_id":"global"}`)
			case "upload":
				response = uploadFileThroughAPI(t, id, "reader.bin", []byte("denied upload"))
			case "edit":
				response = requestWorkflowAPI(handler, http.MethodPut, "/api/v1/files/"+id+"/edit", "denied edit")
			case "delete":
				response = requestWorkflowAPI(handler, http.MethodDelete, "/api/v1/files/"+id, "")
			}
			if response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden {
				t.Fatalf("reader was allowed %s: HTTP %d", name, response.Code)
			}
			meta := requestWorkflowAPI(HandleGetFileMeta, http.MethodGet, "/api/v1/files/"+id, "")
			if meta.Code != http.StatusOK {
				t.Fatalf("reader lost read access: HTTP %d", meta.Code)
			}
			if name != "upload" {
				download := requestWorkflowAPI(HandleGetFileContent, http.MethodGet, "/api/v1/files/"+id+"/content", "")
				if download.Code != http.StatusOK || download.Body.String() != "readable bytes" {
					t.Fatalf("denied mutation changed file: HTTP %d, %q", download.Code, download.Body.String())
				}
			}
		})
	}
}

func TestFileAPIExecutionTokenUsesSavedWorkflowOrganizationFallback(t *testing.T) {
	for _, executionOrg := range []string{datastoreTestOrg, ""} {
		t.Run("execution_org="+executionOrg, func(t *testing.T) {
			fixture := newFileAPIFixture(t)
			const id = "file_00000000-0000-4000-8000-000000000094"
			const executionID = "00000000-0000-4000-8000-000000000095"
			const token = "00000000-0000-4000-8000-000000000096"
			fixture.entities = append(fixture.entities, datastoreEntity("Files", id, map[string]string{"id": id, "org_id": datastoreTestOrg, "filename": "execution-file.bin", "status": "active"}))
			data, err := json.Marshal(WorkflowExecution{ExecutionId: executionID, ExecutionOrg: executionOrg, Authorization: token, Status: "FINISHED", Workflow: Workflow{OrgId: datastoreTestOrg, ExecutingOrg: OrgMini{Id: datastoreTestOrg}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := SetCache(context.Background(), "workflowexecution_"+executionID, data, 60); err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/api/v1/files/"+id+"?execution_id="+executionID, nil)
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			HandleGetFileMeta(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("valid execution fallback org was ignored: HTTP %d, %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestFileAPIMissingAndInvalidCredentialsCannotReadOrMutate(t *testing.T) {
	for _, token := range []string{"", "00000000-0000-4000-8000-000000000090"} {
		for name, handler := range map[string]http.HandlerFunc{"metadata": HandleGetFileMeta, "content": HandleGetFileContent, "create": HandleCreateFile, "upload": HandleUploadFile, "edit": HandleEditFile, "delete": HandleDeleteFile} {
			t.Run(name+"/"+token, func(t *testing.T) {
				fixture := newFileAPIFixture(t)
				const id = "file_00000000-0000-4000-8000-000000000093"
				path := filepath.Join(t.TempDir(), "owned-file")
				if err := os.WriteFile(path, []byte("private bytes"), 0600); err != nil {
					t.Fatal(err)
				}
				status := "active"
				if name == "upload" {
					status = "created"
				}
				fixture.entities = append(fixture.entities, datastoreEntity("Files", id, map[string]string{"id": id, "org_id": datastoreTestOrg, "filename": "owned.bin", "status": status, "download_path": path, "storage_area": "local"}))
				method, endpoint, body := http.MethodGet, "/api/v1/files/"+id, ""
				switch name {
				case "content":
					endpoint += "/content"
				case "create":
					method, endpoint, body = http.MethodPost, "/api/v1/files/create", `{"filename":"denied.bin","workflow_id":"global"}`
				case "edit":
					method, endpoint, body = http.MethodPut, endpoint+"/edit", "denied edit"
				case "delete":
					method = http.MethodDelete
				}
				request := httptest.NewRequest(method, endpoint, strings.NewReader(body))
				if name == "upload" {
					request = fileUploadRequest(t, id, "owned.bin", []byte("denied upload"))
				}
				request.Header.Del("Authorization")
				if token != "" {
					request.Header.Set("Authorization", "Bearer "+token)
				}
				request.Header.Set("Org-Id", datastoreTestOrg)
				response := httptest.NewRecorder()
				handler(response, request)
				var result map[string]interface{}
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || result["success"] != false || strings.Contains(response.Body.String(), "private bytes") {
					t.Fatalf("invalid credentials accessed file %s: HTTP %d, %#v", name, response.Code, result)
				}
			})
		}
	}
}

func TestFileAPICloudDeleteFailureIsNotReportedAsSuccess(t *testing.T) {
	rejectUpload := false
	failures := newCloudFileAPIFixture(t, &rejectUpload)
	id := createFileThroughAPI(t, "delete-failure.bin")
	if response := uploadFileThroughAPI(t, id, "delete-failure.bin", []byte("must not silently remain stored")); response.Code != http.StatusOK {
		t.Fatalf("upload failed: HTTP %d", response.Code)
	}
	failures.rejectDelete = true
	response := requestWorkflowAPI(HandleDeleteFile, http.MethodDelete, "/api/v1/files/"+id, "")
	var result map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusInternalServerError || result["success"] != false {
		t.Fatalf("rejected object deletion was reported as success: HTTP %d, %#v", response.Code, result)
	}
}

func TestFileAPICloudReadPermissionFailureDoesNotMarkFileDeleted(t *testing.T) {
	rejectUpload := false
	failures := newCloudFileAPIFixture(t, &rejectUpload)
	id := createFileThroughAPI(t, "read-failure.bin")
	if response := uploadFileThroughAPI(t, id, "read-failure.bin", []byte("still stored")); response.Code != http.StatusOK {
		t.Fatalf("upload failed: HTTP %d", response.Code)
	}
	failures.rejectRead = true
	response := requestWorkflowAPI(HandleGetFileContent, http.MethodGet, "/api/v1/files/"+id+"/content", "")
	meta := requestWorkflowAPI(HandleGetFileMeta, http.MethodGet, "/api/v1/files/"+id, "")
	var file File
	if err := json.Unmarshal(meta.Body.Bytes(), &file); err != nil {
		t.Fatal(err)
	}
	if meta.Code != http.StatusOK || file.Status != "active" || response.Code == http.StatusOK {
		t.Fatalf("storage permission error changed file identity/state: download HTTP %d, metadata HTTP %d, status %q", response.Code, meta.Code, file.Status)
	}
}

func TestFileAPICorruptedEncryptedCloudObjectIsNotReturnedAsSuccessfulDownload(t *testing.T) {
	rejectUpload := false
	failures := newCloudFileAPIFixture(t, &rejectUpload)
	id := createFileThroughAPI(t, "corruption.bin")
	if response := uploadFileThroughAPI(t, id, "corruption.bin", []byte("authenticated file contents")); response.Code != http.StatusOK {
		t.Fatalf("upload failed: HTTP %d", response.Code)
	}
	control := requestWorkflowAPI(HandleGetFileContent, http.MethodGet, "/api/v1/files/"+id+"/content", "")
	if control.Code != http.StatusOK || control.Body.String() != "authenticated file contents" {
		t.Fatalf("healthy cloud object failed: HTTP %d, %q", control.Code, control.Body.String())
	}
	failures.corruptRead = true
	response := requestWorkflowAPI(HandleGetFileContent, http.MethodGet, "/api/v1/files/"+id+"/content", "")
	if response.Code == http.StatusOK {
		t.Fatal("corrupt encrypted object was returned as a successful file download")
	}
}

// ---- Consolidated from hooks_test.go ----

const hookTestID = "00000000-0000-4000-8000-000000000131"

func newHookAPIFixture(t *testing.T) (*datastoreAPIFixture, map[string]interface{}) {
	t.Helper()
	fixture := newDatastoreAPIFixture(t)
	project.Environment = "cloud"
	project.GceProject = "release-tests"
	t.Setenv("SHUFFLE_CLOUDRUN_URL", "https://release.example.invalid")
	t.Setenv("SHUFFLE_GCEPROJECT", "")
	t.Setenv("SHUFFLE_GCEPROJECT_LOCATION", "")
	workflow := Workflow{ID: workflowTestID, Name: "release hook workflow", OrgId: datastoreTestOrg, Owner: "release-test-user",
		Start:    "00000000-0000-4000-8000-000000000132",
		Actions:  []Action{{ID: "00000000-0000-4000-8000-000000000132", Name: "repeat_back_to_me", AppName: "Shuffle Tools"}},
		Triggers: []Trigger{{ID: hookTestID, Name: "Webhook", TriggerType: "WEBHOOK", Status: "stopped", Environment: "cloud"}}}
	if _, err := project.Dbclient.Put(context.Background(), datastore.NameKey("workflow", workflow.ID, nil), &workflow); err != nil {
		t.Fatal(err)
	}
	return fixture, map[string]interface{}{"id": hookTestID, "type": "webhook", "name": "release webhook",
		"workflow": workflow.ID, "start": workflow.Start, "environment": "cloud", "auth": "synthetic-hook-auth",
		"custom_response": "accepted \"release\"\n", "version": "v1", "version_timeout": 20}
}

func createHookAPI(t *testing.T, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return requestWorkflowAPI(HandleNewHook, http.MethodPost, "/api/v1/hooks", string(encoded))
}

func hookRegistry(t *testing.T) []Hook {
	t.Helper()
	// The callback GET executes a webhook; metadata is read via the public library API.
	hooks, err := GetHooks(context.Background(), datastoreTestOrg)
	if err != nil {
		t.Fatal(err)
	}
	return hooks
}

func hookWorkflow(t *testing.T) Workflow {
	t.Helper()
	response := requestWorkflowAPI(GetSpecificWorkflow, http.MethodGet, "/api/v1/workflows/"+workflowTestID, "")
	var workflow Workflow
	if err := json.Unmarshal(response.Body.Bytes(), &workflow); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || workflow.ID != workflowTestID {
		t.Fatalf("workflow read-back failed: HTTP %d", response.Code)
	}
	return workflow
}

func TestHookAPICreateAndDeletePreserveConfigurationAndIsolation(t *testing.T) {
	_, body := newHookAPIFixture(t)
	if len(hookRegistry(t)) != 0 {
		t.Fatal("unexpected hook before creation")
	}
	created := createHookAPI(t, body)
	hooks := hookRegistry(t)
	if created.Code != http.StatusOK || len(hooks) != 1 {
		t.Fatalf("hook creation failed: HTTP %d", created.Code)
	}
	hook := hooks[0]
	if hook.Id != hookTestID || hook.OrgId != datastoreTestOrg || hook.Auth != "synthetic-hook-auth" ||
		hook.CustomResponse != "accepted \"release\"\n" || hook.Start != body["start"] || !hook.Running || hook.Status != "running" ||
		len(hook.Workflows) != 1 || hook.Workflows[0] != workflowTestID || hook.VersionTimeout != 20 {
		t.Fatal("created hook lost its identity, scope, execution configuration, or running state")
	}
	if hookWorkflow(t).Triggers[0].Status != "running" {
		t.Fatal("successful creation did not update the workflow trigger")
	}
	deleted := requestWorkflowAPI(HandleDeleteHook, http.MethodDelete, "/api/v1/hooks/"+hookTestID, "")
	if deleted.Code != http.StatusOK || len(hookRegistry(t)) != 0 {
		t.Fatalf("hook remained active after deletion: HTTP %d", deleted.Code)
	}
}

func TestHookAPIDeletionIsReflectedInWorkflowTriggerView(t *testing.T) {
	_, body := newHookAPIFixture(t)
	if response := createHookAPI(t, body); response.Code != http.StatusOK || hookWorkflow(t).Triggers[0].Status != "running" {
		t.Fatal("hook was not running before deletion")
	}
	response := requestWorkflowAPI(HandleDeleteHook, http.MethodDelete, "/api/v1/hooks/"+hookTestID, "")
	if response.Code != http.StatusOK || len(hookRegistry(t)) != 0 {
		t.Fatal("hook deletion failed before workflow consistency check")
	}
	DeleteCache(context.Background(), "workflow_"+workflowTestID)
	if hookWorkflow(t).Triggers[0].Status != "stopped" {
		t.Fatal("deleted webhook still appears running in the saved workflow definition")
	}
}

func seedForeignHook(t *testing.T) Hook {
	t.Helper()
	workflow := Workflow{ID: "00000000-0000-4000-8000-000000000133", OrgId: isolationOtherOrg, Owner: "foreign-hook-owner",
		Name: "foreign hook workflow", Start: "00000000-0000-4000-8000-000000000136",
		Actions:  []Action{{ID: "00000000-0000-4000-8000-000000000136", Name: "repeat_back_to_me", AppName: "Shuffle Tools"}},
		Triggers: []Trigger{{ID: "00000000-0000-4000-8000-000000000134", Name: "Webhook", TriggerType: "WEBHOOK", Status: "running", Environment: "cloud"}}}
	hook := Hook{Id: "00000000-0000-4000-8000-000000000134", OrgId: isolationOtherOrg, Owner: "foreign-hook-owner",
		Workflows: []string{workflow.ID}, Running: true, Status: "running", Auth: "synthetic-foreign-hook-auth", Environment: "cloud"}
	for _, item := range []struct {
		kind, id string
		value    interface{}
	}{{"workflow", workflow.ID, &workflow}, {"hooks", hook.Id, &hook}, {"Organizations", isolationOtherOrg, &Org{Id: isolationOtherOrg}}} {
		if _, err := project.Dbclient.Put(context.Background(), datastore.NameKey(item.kind, item.id, nil), item.value); err != nil {
			t.Fatal(err)
		}
	}
	return hook
}

func TestHookAPIFailedLookupCannotOverwriteForeignRegistration(t *testing.T) {
	fixture, body := newHookAPIFixture(t)
	foreign := seedForeignHook(t)
	control, err := GetHooks(context.Background(), isolationOtherOrg)
	if err != nil || len(control) != 1 {
		t.Fatal("foreign registration read control failed")
	}
	fixture.lookupErrKind = "hooks"
	fixture.lookupErr = status.Error(codes.PermissionDenied, "synthetic hook lookup rejected")
	body["id"] = foreign.Id
	response := createHookAPI(t, body)
	if response.Code < 400 {
		t.Errorf("failed hook lookup was treated as a free ID: HTTP %d", response.Code)
	}
	fixture.lookupErr = nil
	ownerView, err := GetHooks(context.Background(), isolationOtherOrg)
	if err != nil || len(ownerView) != 1 || ownerView[0].Auth != foreign.Auth || len(hookRegistry(t)) != 0 {
		t.Fatal("lookup failure let the caller take another organization's registered hook")
	}
}

func TestHookAPIForeignWorkflowAndHookMutationsAreDenied(t *testing.T) {
	for _, target := range []string{"workflow", "hook", "delete"} {
		t.Run(target, func(t *testing.T) {
			_, body := newHookAPIFixture(t)
			foreign := seedForeignHook(t)
			var response *httptest.ResponseRecorder
			if target == "delete" {
				response = requestWorkflowAPI(HandleDeleteHook, http.MethodDelete, "/api/v1/hooks/"+foreign.Id, "")
			} else {
				if target == "workflow" {
					body["workflow"] = foreign.Workflows[0]
				} else {
					body["id"] = foreign.Id
				}
				response = createHookAPI(t, body)
			}
			var result map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if response.Code < 400 || response.Code >= 500 || result["success"] != false || strings.Contains(response.Body.String(), foreign.Auth) {
				t.Errorf("foreign hook operation was not safely denied: HTTP %d", response.Code)
			}
			ownerView, err := GetHooks(context.Background(), isolationOtherOrg)
			if err != nil || len(ownerView) != 1 || ownerView[0].Auth != foreign.Auth || ownerView[0].Status != "running" || len(hookRegistry(t)) != 0 {
				t.Fatal("denied operation changed either organization's registration")
			}
		})
	}
}

func TestHookAPIFailedRegistrationWriteCanBeRetried(t *testing.T) {
	fixture, body := newHookAPIFixture(t)
	fixture.rejectWritesToKind = "hooks"
	response := createHookAPI(t, body)
	if response.Code < 400 || len(hookRegistry(t)) != 0 || hookWorkflow(t).Triggers[0].Status != "stopped" {
		t.Fatal("rejected hook write changed registration or workflow state")
	}
	fixture.rejectWritesToKind = ""
	response = createHookAPI(t, body)
	if response.Code != http.StatusOK || len(hookRegistry(t)) != 1 || hookWorkflow(t).Triggers[0].Status != "running" {
		t.Fatal("hook creation retry failed after storage recovery")
	}
}

func TestHookAPIFailedWorkflowWriteDoesNotLeaveRunningRegistration(t *testing.T) {
	fixture, body := newHookAPIFixture(t)
	fixture.rejectWritesToKind = "workflow"
	response := createHookAPI(t, body)
	if response.Code < 400 {
		t.Errorf("rejected workflow write was acknowledged: HTTP %d", response.Code)
	}
	fixture.rejectWritesToKind = ""
	DeleteCache(context.Background(), "workflow_"+workflowTestID)
	if hookWorkflow(t).Triggers[0].Status != "stopped" {
		t.Fatal("rejected workflow write changed the saved trigger")
	}
	for _, hook := range hookRegistry(t) {
		if hook.Running || hook.Status == "running" {
			t.Error("failed creation left a running webhook while its workflow trigger is stopped")
		}
	}
	if response := createHookAPI(t, body); response.Code != http.StatusOK || hookWorkflow(t).Triggers[0].Status != "running" {
		t.Fatal("retry did not recover a consistent running webhook")
	}
}

func TestHookAPIFailedDeletionIsReportedAndRetryable(t *testing.T) {
	fixture, body := newHookAPIFixture(t)
	if response := createHookAPI(t, body); response.Code != http.StatusOK {
		t.Fatal("initial hook creation failed")
	}
	fixture.rejectDeletesToKind = "hooks"
	response := requestWorkflowAPI(HandleDeleteHook, http.MethodDelete, "/api/v1/hooks/"+hookTestID, "")
	var result map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code < 400 || result["success"] != false {
		t.Errorf("rejected hook deletion was acknowledged: HTTP %d", response.Code)
	}
	if len(hookRegistry(t)) != 1 {
		t.Fatal("storage-rejected deletion lost the registration")
	}
	fixture.rejectDeletesToKind = ""
	response = requestWorkflowAPI(HandleDeleteHook, http.MethodDelete, "/api/v1/hooks/"+hookTestID, "")
	if response.Code != http.StatusOK || len(hookRegistry(t)) != 0 {
		t.Fatal("hook deletion retry did not recover")
	}
}

func TestHookAPIInvalidRequestsDoNotRegisterAnything(t *testing.T) {
	_, valid := newHookAPIFixture(t)
	for _, mutation := range []map[string]interface{}{{"id": "invalid"}, {"name": ""}, {"type": "schedule"}, {"workflow": "missing-workflow"}} {
		body := map[string]interface{}{}
		for key, value := range valid {
			body[key] = value
		}
		for key, value := range mutation {
			body[key] = value
		}
		response := createHookAPI(t, body)
		var result map[string]interface{}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if response.Code < 400 || response.Code >= 500 || result["success"] != false || len(hookRegistry(t)) != 0 {
			t.Fatalf("invalid hook input was not rejected without side effects: HTTP %d", response.Code)
		}
	}
	for _, body := range []string{"", "null", "{} {}", `{"id":`, `{"name":[]}`} {
		response := requestWorkflowAPI(HandleNewHook, http.MethodPost, "/api/v1/hooks", body)
		var result map[string]interface{}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if response.Code < 400 || response.Code >= 500 || result["success"] != false || len(hookRegistry(t)) != 0 {
			t.Fatalf("malformed hook input was not rejected without side effects: HTTP %d", response.Code)
		}
	}
}

func TestHookAPIMissingInvalidAndReadOnlyCredentialsCannotMutate(t *testing.T) {
	for _, mode := range []string{"missing", "invalid", "read-only"} {
		t.Run(mode, func(t *testing.T) {
			_, body := newHookAPIFixture(t)
			if response := createHookAPI(t, body); response.Code != http.StatusOK {
				t.Fatal("initial hook creation failed")
			}
			credential := ""
			if mode == "invalid" {
				credential = "Bearer 00000000-0000-4000-8000-000000000135"
			} else if mode == "read-only" {
				credential = "Bearer " + datastoreTestAPIKey
				user, err := json.Marshal(User{Id: "release-test-user", Username: "scheduler@shuffler.io", Role: "org-reader", ActiveOrg: OrgMini{Id: datastoreTestOrg}})
				if err != nil {
					t.Fatal(err)
				}
				if err := SetCache(context.Background(), datastoreTestAPIKey+datastoreTestOrg, user, 60); err != nil {
					t.Fatal(err)
				}
			}
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			for _, method := range []string{http.MethodPost, http.MethodDelete} {
				path, handler := "/api/v1/hooks", HandleNewHook
				if method == http.MethodDelete {
					path, handler = path+"/"+hookTestID, HandleDeleteHook
				}
				request := httptest.NewRequest(method, path, strings.NewReader(string(encoded)))
				request.Header.Set("Authorization", credential)
				request.Header.Set("Org-Id", datastoreTestOrg)
				response := httptest.NewRecorder()
				handler(response, request)
				var result map[string]interface{}
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || result["success"] != false {
					t.Errorf("untrusted hook mutation was not denied: HTTP %d", response.Code)
				}
				hooks := hookRegistry(t)
				if len(hooks) != 1 || hooks[0].Status != "running" || hooks[0].Auth != "synthetic-hook-auth" {
					t.Fatal("untrusted request changed the registered hook")
				}
			}
		})
	}
}

func TestHookAPIAuthorizedSuborgHeaderCanUpdateAndDeleteRegistration(t *testing.T) {
	_, body := newHookAPIFixture(t)
	foreign := seedForeignHook(t)
	user := User{Id: "release-test-user", Username: "scheduler@shuffler.io", Role: "admin", ApiKey: datastoreTestAPIKey,
		ActiveOrg: OrgMini{Id: datastoreTestOrg}, Orgs: []string{datastoreTestOrg, isolationOtherOrg}}
	encoded, err := json.Marshal([]User{user})
	if err != nil {
		t.Fatal(err)
	}
	if err := SetCache(context.Background(), "Users_"+datastoreTestAPIKey, encoded, 60); err != nil {
		t.Fatal(err)
	}
	body["id"], body["workflow"], body["start"] = foreign.Id, foreign.Workflows[0], "00000000-0000-4000-8000-000000000136"
	body["auth"] = "synthetic-updated-suborg-auth"
	encoded, err = json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		path, handler := "/api/v1/hooks/new", HandleNewHook
		if method == http.MethodDelete {
			path, handler = "/api/v1/hooks/"+foreign.Id, HandleDeleteHook
		}
		request := httptest.NewRequest(method, path, strings.NewReader(string(encoded)))
		request.Header.Set("Authorization", "Bearer "+datastoreTestAPIKey)
		request.Header.Set("Org-Id", isolationOtherOrg)
		response := httptest.NewRecorder()
		handler(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("authorized suborg %s failed: HTTP %d", method, response.Code)
		}
		items, err := GetHooks(context.Background(), isolationOtherOrg)
		if err != nil {
			t.Fatal(err)
		}
		if method == http.MethodPost && (len(items) != 1 || items[0].Auth != "synthetic-updated-suborg-auth" || items[0].OrgId != isolationOtherOrg) {
			t.Fatal("suborg update changed the wrong registration")
		}
		if method == http.MethodDelete && len(items) != 0 {
			t.Fatal("suborg registration was not deleted")
		}
		if len(hookRegistry(t)) != 0 {
			t.Fatal("suborg request changed the caller's original organization")
		}
	}
}

func TestHookAPIDeleteAcceptsWebhookPrefixAndLegacySuffix(t *testing.T) {
	for _, path := range []string{"/api/v1/hooks/webhook_" + hookTestID, "/api/v1/hooks/" + hookTestID + "/delete"} {
		t.Run(path, func(t *testing.T) {
			_, body := newHookAPIFixture(t)
			if response := createHookAPI(t, body); response.Code != http.StatusOK {
				t.Fatal("initial hook creation failed")
			}
			response := requestWorkflowAPI(HandleDeleteHook, http.MethodDelete, path, "")
			if response.Code != http.StatusOK || len(hookRegistry(t)) != 0 {
				t.Fatalf("supported hook deletion path failed: HTTP %d", response.Code)
			}
		})
	}
}

// ---- Consolidated from isolation_test.go ----

const isolationOtherOrg = "00000000-0000-4000-8000-000000000099"

func isolationDatastoreFixture(t *testing.T) *datastoreAPIFixture {
	t.Helper()
	fixture := newDatastoreAPIFixture(t)
	fixture.entities = append(fixture.entities,
		datastoreEntity("Organizations", isolationOtherOrg, map[string]string{"id": isolationOtherOrg}),
		datastoreEntity("org_cache", isolationOtherOrg+"_private_release_tests", map[string]string{
			"OrgId": isolationOtherOrg, "Key": "private", "category": "release_tests", "Value": "other-organization-private-value", "PublicAuthorization": "fixture-public",
		}),
	)
	return fixture
}

func TestDatastoreAPICannotReadAnotherOrganizationWithBodyAndPath(t *testing.T) {
	isolationDatastoreFixture(t)
	response := requestWorkflowAPI(HandleGetCacheKey, http.MethodPost, "/api/v1/orgs/"+isolationOtherOrg+"/get_cache",
		`{"org_id":"`+isolationOtherOrg+`","key":"private","category":"release_tests"}`)
	var result map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || result["success"] != false || strings.Contains(response.Body.String(), "other-organization-private-value") {
		t.Fatalf("foreign organization read was not denied: HTTP %d, %#v", response.Code, result)
	}
}

func TestDatastoreAPIForgedOrgHeaderStillRequiresMembership(t *testing.T) {
	isolationDatastoreFixture(t)
	user := User{Id: "release-test-user", Username: "scheduler@shuffler.io", Role: "admin",
		ActiveOrg: OrgMini{Id: datastoreTestOrg}, Orgs: []string{datastoreTestOrg}, ApiKey: datastoreTestAPIKey}
	data, err := json.Marshal([]User{user})
	if err != nil {
		t.Fatal(err)
	}
	if err := SetCache(context.Background(), "Users_"+datastoreTestAPIKey, data, 60); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/orgs/"+isolationOtherOrg+"/get_cache",
		strings.NewReader(`{"org_id":"`+isolationOtherOrg+`","key":"private","category":"release_tests"}`))
	request.Header.Set("Authorization", "Bearer "+datastoreTestAPIKey)
	request.Header.Set("Org-Id", isolationOtherOrg)
	response := httptest.NewRecorder()
	HandleGetCacheKey(response, request)
	var result map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || result["success"] != false || strings.Contains(response.Body.String(), "other-organization-private-value") {
		t.Fatalf("a forged Org-Id header granted foreign access: HTTP %d, %#v", response.Code, result)
	}
}

func TestDatastoreAPIAuthorizedSuborgHeaderCanReadAndUpdate(t *testing.T) {
	isolationDatastoreFixture(t)
	user := User{Id: "release-test-user", Username: "scheduler@shuffler.io", Role: "admin",
		ActiveOrg: OrgMini{Id: isolationOtherOrg}, Orgs: []string{datastoreTestOrg, isolationOtherOrg}}
	data, err := json.Marshal(user)
	if err != nil {
		t.Fatal(err)
	}
	// The normal auth cache contains the identity after its Org-Id access check.
	if err := SetCache(context.Background(), datastoreTestAPIKey+isolationOtherOrg, data, 60); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []struct {
		handler     http.HandlerFunc
		path, value string
	}{{HandleGetCacheKey, "get_cache", ""}, {HandleSetCacheKey, "set_cache", "authorized-suborg-update"}, {HandleGetCacheKey, "get_cache", "authorized-suborg-update"}} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/orgs/"+isolationOtherOrg+"/"+operation.path,
			strings.NewReader(`{"org_id":"`+isolationOtherOrg+`","key":"private","category":"release_tests","value":"`+operation.value+`"}`))
		request.Header.Set("Authorization", "Bearer "+datastoreTestAPIKey)
		request.Header.Set("Org-Id", isolationOtherOrg)
		response := httptest.NewRecorder()
		operation.handler(response, request)
		var result map[string]interface{}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if response.Code != http.StatusOK || result["success"] != true || (operation.path == "get_cache" && operation.value != "" && result["value"] != operation.value) {
			t.Fatalf("authorized suborg header failed for %s: HTTP %d, %#v", operation.path, response.Code, result)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/orgs/"+isolationOtherOrg+"/delete_cache",
		strings.NewReader(`{"org_id":"`+isolationOtherOrg+`","key":"private","category":"release_tests"}`))
	request.Header.Set("Authorization", "Bearer "+datastoreTestAPIKey)
	request.Header.Set("Org-Id", isolationOtherOrg)
	deleted := httptest.NewRecorder()
	HandleDeleteCacheKeyPost(deleted, request)
	var result map[string]interface{}
	if err := json.Unmarshal(deleted.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if deleted.Code != http.StatusOK || result["success"] != true {
		t.Fatalf("authorized suborg deletion failed: HTTP %d, %#v", deleted.Code, result)
	}
}

func TestDatastoreAPIPublicKeyAndExecutionAuthorizationRemainSupported(t *testing.T) {
	t.Run("public key", func(t *testing.T) {
		fixture := isolationDatastoreFixture(t)
		fixture.entities = append(fixture.entities, datastoreEntity("org_cache", isolationOtherOrg+"_public", map[string]string{
			"OrgId": isolationOtherOrg, "Key": "public", "category": "", "Value": "explicitly shared value", "PublicAuthorization": "public-test-authorization",
		}))
		for token, expected := range map[string]int{"public-test-authorization": http.StatusOK, "invalid-public-token": http.StatusUnauthorized} {
			response := requestWorkflowAPI(HandleGetCacheKey, http.MethodGet, "/api/v1/orgs/"+isolationOtherOrg+"/cache/public?authorization="+token, "")
			if response.Code != expected {
				t.Fatalf("public-key request returned HTTP %d, want %d", response.Code, expected)
			}
		}
	})
	t.Run("execution token", func(t *testing.T) {
		isolationDatastoreFixture(t)
		const executionID = "00000000-0000-4000-8000-000000000097"
		data, err := json.Marshal(WorkflowExecution{ExecutionId: executionID, ExecutionOrg: isolationOtherOrg, Authorization: "execution-test-authorization", Status: "EXECUTING"})
		if err != nil {
			t.Fatal(err)
		}
		if err := SetCache(context.Background(), "workflowexecution_"+executionID, data, 60); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/orgs/"+isolationOtherOrg+"/get_cache",
			strings.NewReader(`{"org_id":"`+isolationOtherOrg+`","key":"private","category":"release_tests","execution_id":"`+executionID+`","authorization":"execution-test-authorization"}`))
		response := httptest.NewRecorder()
		HandleGetCacheKey(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "other-organization-private-value") {
			t.Fatalf("valid execution authorization was rejected: HTTP %d, %s", response.Code, response.Body.String())
		}
	})
}

func TestDatastoreAPICannotMutateAnotherOrganizationThroughBodyAndPath(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{"set_cache": HandleSetCacheKey, "delete_cache": HandleDeleteCacheKeyPost} {
		t.Run(name, func(t *testing.T) {
			isolationDatastoreFixture(t)
			owner, err := json.Marshal(User{Id: "other-user", Username: "scheduler@shuffler.io", Role: "admin", ActiveOrg: OrgMini{Id: isolationOtherOrg}, Orgs: []string{isolationOtherOrg}})
			if err != nil {
				t.Fatal(err)
			}
			const ownerKey = "00000000-0000-4000-8000-000000000087"
			if err := SetCache(context.Background(), ownerKey+isolationOtherOrg, owner, 60); err != nil {
				t.Fatal(err)
			}
			response := requestWorkflowAPI(handler, http.MethodPost, "/api/v1/orgs/"+isolationOtherOrg+"/"+name,
				`{"org_id":"`+isolationOtherOrg+`","key":"private","category":"release_tests","value":"unauthorized update"}`)
			var result map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if response.Code < 400 || response.Code >= 500 || result["success"] != false {
				t.Fatalf("foreign organization mutation was acknowledged: HTTP %d, %#v", response.Code, result)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/orgs/"+isolationOtherOrg+"/get_cache", strings.NewReader(`{"org_id":"`+isolationOtherOrg+`","key":"private","category":"release_tests"}`))
			request.Header.Set("Authorization", "Bearer "+ownerKey)
			request.Header.Set("Org-Id", isolationOtherOrg)
			read := httptest.NewRecorder()
			HandleGetCacheKey(read, request)
			if err := json.Unmarshal(read.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if read.Code != http.StatusOK || result["value"] != "other-organization-private-value" {
				t.Fatalf("foreign owner's value changed after rejected mutation: HTTP %d, %#v", read.Code, result)
			}
		})
	}
}

func TestDatastoreAPIForeignDeleteCannotDeleteSameNamedOwnKey(t *testing.T) {
	fixture := isolationDatastoreFixture(t)
	fixture.entities = append(fixture.entities, datastoreEntity("org_cache", datastoreTestOrg+"_private_release_tests", map[string]string{
		"OrgId": datastoreTestOrg, "Key": "private", "category": "release_tests", "Value": "own key must survive", "PublicAuthorization": "fixture-public",
	}))
	response := requestWorkflowAPI(HandleDeleteCacheKeyPost, http.MethodPost, "/api/v1/orgs/"+isolationOtherOrg+"/delete_cache",
		`{"org_id":"`+isolationOtherOrg+`","key":"private","category":"release_tests"}`)
	status, result := requestDatastoreKey(t, "private", "release_tests")
	if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || status != http.StatusOK || result["value"] != "own key must survive" {
		t.Fatalf("foreign delete was redirected to own key: delete HTTP %d, own read HTTP %d, %#v", response.Code, status, result)
	}
}

func TestFileAPICannotAccessOrMutateAnotherOrganization(t *testing.T) {
	const id = "file_00000000-0000-4000-8000-000000000098"
	for _, operation := range []struct {
		name, method, suffix, status string
		handler                      http.HandlerFunc
	}{{"metadata", http.MethodGet, "", "active", HandleGetFileMeta},
		{"download", http.MethodGet, "/content", "active", HandleGetFileContent},
		{"edit", http.MethodPut, "/edit", "active", HandleEditFile},
		{"delete", http.MethodDelete, "", "active", HandleDeleteFile},
		{"upload", http.MethodPost, "/upload", "created", HandleUploadFile}} {
		t.Run(operation.name, func(t *testing.T) {
			fixture := newFileAPIFixture(t)
			path := filepath.Join(t.TempDir(), "foreign-file")
			if err := os.WriteFile(path, []byte("other-org private file bytes"), 0600); err != nil {
				t.Fatal(err)
			}
			fixture.entities = append(fixture.entities, datastoreEntity("Files", id, map[string]string{
				"id": id, "org_id": isolationOtherOrg, "filename": "private.bin", "status": operation.status, "storage_area": "local", "download_path": path,
			}))
			var response *httptest.ResponseRecorder
			if operation.name == "upload" {
				response = uploadFileThroughAPI(t, id, "private.bin", []byte("unauthorized upload"))
			} else {
				response = requestWorkflowAPI(operation.handler, operation.method, "/api/v1/files/"+id+operation.suffix, "unauthorized edit")
			}
			var result map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || result["success"] != false || strings.Contains(response.Body.String(), "other-org private file bytes") {
				t.Fatalf("foreign file access was not denied: HTTP %d, %#v", response.Code, result)
			}
		})
	}
}

func TestWorkflowAPIPrivateReadsAndRevisionsRemainOrganizationScoped(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{"definition": GetSpecificWorkflow, "revisions": GetWorkflowRevisions} {
		t.Run(name, func(t *testing.T) {
			fixture := newDatastoreAPIFixture(t)
			fixture.entities = append(fixture.entities, datastoreEntity("workflow", workflowTestID, map[string]string{
				"id": workflowTestID, "name": "private foreign workflow", "org_id": isolationOtherOrg, "owner": "another-user",
			}))
			path := "/api/v1/workflows/" + workflowTestID
			if name == "revisions" {
				path += "/revisions"
			}
			response := requestWorkflowAPI(handler, http.MethodGet, path, "")
			var result map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || result["success"] != false || strings.Contains(response.Body.String(), "private foreign workflow") {
				t.Fatalf("private workflow %s was not isolated: HTTP %d, %#v", name, response.Code, result)
			}
		})
	}
}

func TestFileAPIAuthorizedSuborgHeaderCanCreateUploadReadAndDelete(t *testing.T) {
	fixture := newFileAPIFixture(t)
	fixture.entities = append(fixture.entities, datastoreEntity("Organizations", isolationOtherOrg, map[string]string{"id": isolationOtherOrg}))
	user := User{Id: "release-test-user", Username: "scheduler@shuffler.io", Role: "admin",
		ActiveOrg: OrgMini{Id: isolationOtherOrg}, Orgs: []string{datastoreTestOrg, isolationOtherOrg}}
	data, err := json.Marshal(user)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetCache(context.Background(), datastoreTestAPIKey+isolationOtherOrg, data, 60); err != nil {
		t.Fatal(err)
	}
	requestAsSuborg := func(handler http.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+datastoreTestAPIKey)
		request.Header.Set("Org-Id", isolationOtherOrg)
		response := httptest.NewRecorder()
		handler(response, request)
		return response
	}
	created := requestAsSuborg(HandleCreateFile, http.MethodPost, "/api/v1/files/create", `{"org_id":"`+isolationOtherOrg+`","filename":"suborg.bin","workflow_id":"global","namespace":"release_tests"}`)
	var result map[string]interface{}
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	id, _ := result["id"].(string)
	if created.Code != http.StatusOK || result["success"] != true || !strings.HasPrefix(id, "file_") {
		t.Fatalf("suborg create failed: HTTP %d, %#v", created.Code, result)
	}
	request := fileUploadRequest(t, id, "suborg.bin", []byte("authorized suborg bytes"))
	request.Header.Set("Org-Id", isolationOtherOrg)
	upload := httptest.NewRecorder()
	HandleUploadFile(upload, request)
	if upload.Code != http.StatusOK {
		t.Fatalf("suborg upload failed: HTTP %d, %s", upload.Code, upload.Body.String())
	}
	content := requestAsSuborg(HandleGetFileContent, http.MethodGet, "/api/v1/files/"+id+"/content", "")
	if content.Code != http.StatusOK || content.Body.String() != "authorized suborg bytes" {
		t.Fatalf("suborg download failed: HTTP %d, %q", content.Code, content.Body.String())
	}
	meta := requestAsSuborg(HandleGetFileMeta, http.MethodGet, "/api/v1/files/"+id, "")
	var metadata File
	if err := json.Unmarshal(meta.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if meta.Code != http.StatusOK || metadata.OrgId != isolationOtherOrg {
		t.Fatalf("suborg file ended up in wrong organization: HTTP %d, %q", meta.Code, metadata.OrgId)
	}
	deleted := requestAsSuborg(HandleDeleteFile, http.MethodDelete, "/api/v1/files/"+id, "")
	if err := json.Unmarshal(deleted.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if deleted.Code != http.StatusOK || result["success"] != true {
		t.Fatalf("suborg delete failed: HTTP %d, %#v", deleted.Code, result)
	}
}

func TestFileAPILegacyDatastoreFieldCannotMakeDeduplicationCrossOrganizations(t *testing.T) {
	fixture := newFileAPIFixture(t)
	const foreignID = "file_00000000-0000-4000-8000-000000000088"
	const foreignAPIKey = "00000000-0000-4000-8000-000000000089"
	payload := []byte("identical payload across organizations")
	path := filepath.Join(t.TempDir(), "foreign-blob")
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	file := File{Id: foreignID, OrgId: isolationOtherOrg, Filename: "foreign.bin", Status: "active", StorageArea: "local", DownloadPath: path, Md5sum: fmt.Sprintf("%x", md5.Sum(payload)), FileSize: int64(len(payload))}
	fixture.entities = append(fixture.entities,
		datastoreEntity("Organizations", isolationOtherOrg, map[string]string{"id": isolationOtherOrg}),
		datastoreEntity("Files", foreignID, map[string]string{"id": foreignID, "org_id": isolationOtherOrg, "filename": file.Filename, "status": "active", "storage_area": "local", "download_path": path, "md5_sum": file.Md5sum, "removed_legacy_field": "old schema value"}),
	)
	// Normalized cached metadata is readable while queries encounter an older schema.
	for key, value := range map[string]interface{}{
		"Files_" + foreignID:              file,
		foreignAPIKey + isolationOtherOrg: User{Id: "other-user", Username: "scheduler@shuffler.io", Role: "admin", ActiveOrg: OrgMini{Id: isolationOtherOrg}},
	} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := SetCache(context.Background(), key, data, 60); err != nil {
			t.Fatal(err)
		}
	}
	readForeign := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/files/"+foreignID+"/content", nil)
		request.Header.Set("Authorization", "Bearer "+foreignAPIKey)
		request.Header.Set("Org-Id", isolationOtherOrg)
		response := httptest.NewRecorder()
		HandleGetFileContent(response, request)
		return response
	}
	before := readForeign()
	if before.Code != http.StatusOK || before.Body.String() != string(payload) {
		t.Fatalf("foreign owner control failed: HTTP %d, %q", before.Code, before.Body.String())
	}
	ownID := createFileThroughAPI(t, "own.bin")
	upload := uploadFileThroughAPI(t, ownID, "own.bin", payload)
	if upload.Code != http.StatusOK {
		t.Fatalf("own upload failed: HTTP %d", upload.Code)
	}
	deleted := requestWorkflowAPI(HandleDeleteFile, http.MethodDelete, "/api/v1/files/"+ownID, "")
	if deleted.Code != http.StatusOK {
		t.Fatalf("own delete failed: HTTP %d", deleted.Code)
	}
	after := readForeign()
	if after.Code != http.StatusOK || after.Body.String() != string(payload) {
		t.Fatalf("own file lifecycle damaged another organization: foreign read HTTP %d, %q", after.Code, after.Body.String())
	}
}

// ---- Consolidated from notifications_test.go ----

func newNotificationAPIFixture(t *testing.T) *datastoreAPIFixture {
	t.Helper()
	fixture := newDatastoreAPIFixture(t)
	project.Environment = "cloud"
	previous := standalone
	standalone = false
	t.Cleanup(func() { standalone = previous })
	return fixture
}

func notificationRequest(handler http.HandlerFunc, method, path, body, org string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+datastoreTestAPIKey)
	request.Header.Set("Org-Id", org)
	response := httptest.NewRecorder()
	handler(response, request)
	return response
}

func notificationList(t *testing.T, org, query string) []Notification {
	t.Helper()
	response := notificationRequest(HandleGetNotifications, http.MethodGet, "/api/v1/notifications"+query, "", org)
	var body NotificationResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || !body.Success {
		t.Fatalf("notification list failed: HTTP %d, %s", response.Code, response.Body.String())
	}
	return body.Notifications
}

func TestNotificationAPICreateReadMarkAndUnreadFilter(t *testing.T) {
	newNotificationAPIFixture(t)
	created := requestWorkflowAPI(HandleCreateNotification, http.MethodPost, "/api/v1/notifications",
		`{"title":"release test alert","description":"controlled failure","reference_url":"/release-tests/notice","severity":"high","origin":"release-tests"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create failed: HTTP %d, %s", created.Code, created.Body.String())
	}
	items := notificationList(t, datastoreTestOrg, "")
	if len(items) != 1 || items[0].Title != "release test alert" || items[0].Description != "controlled failure" || items[0].OrgId != datastoreTestOrg || items[0].ReferenceUrl != "/release-tests/notice" || items[0].Severity != "high" || items[0].Origin != "release-tests" || items[0].Read {
		t.Fatalf("created notification was not visible with exact content: %+v", items)
	}
	read := requestWorkflowAPI(HandleMarkAsRead, http.MethodGet, "/api/v1/notifications/"+items[0].Id+"/markasread", "")
	if read.Code != http.StatusOK {
		t.Fatalf("mark-as-read failed: HTTP %d", read.Code)
	}
	if unread := notificationList(t, datastoreTestOrg, "?status=unread"); len(unread) != 0 {
		t.Fatalf("read notification remained unread: %+v", unread)
	}
	items = notificationList(t, datastoreTestOrg, "")
	if len(items) != 1 || !items[0].Read {
		t.Fatalf("read state was not persisted: %+v", items)
	}
}

func TestNotificationAPIDeduplicatesOnlyWithinTheTargetOrganization(t *testing.T) {
	fixture := newNotificationAPIFixture(t)
	fixture.entities = append(fixture.entities, datastoreEntity("Organizations", isolationOtherOrg, map[string]string{"id": isolationOtherOrg}))
	user, err := json.Marshal(User{Id: "release-test-user", Username: "scheduler@shuffler.io", Role: "admin", ActiveOrg: OrgMini{Id: isolationOtherOrg}, Orgs: []string{datastoreTestOrg, isolationOtherOrg}})
	if err != nil {
		t.Fatal(err)
	}
	if err := SetCache(context.Background(), datastoreTestAPIKey+isolationOtherOrg, user, 60); err != nil {
		t.Fatal(err)
	}
	body := `{"title":"shared alert shape","description":"same failure type","reference_url":"/apps/authentication","severity":"high","origin":"oauth"}`
	for _, org := range []string{datastoreTestOrg, isolationOtherOrg} {
		for attempt := 0; attempt < 2; attempt++ {
			response := notificationRequest(HandleCreateNotification, http.MethodPost, "/api/v1/notifications", body, org)
			if response.Code != http.StatusOK {
				t.Fatalf("create failed for %s: HTTP %d", org, response.Code)
			}
		}
		items := notificationList(t, org, "")
		if len(items) != 1 || items[0].OrgId != org || items[0].ReferenceUrl != "/apps/authentication" {
			t.Fatalf("notification was lost or duplicated in org %s: %+v", org, items)
		}
	}
}

func TestNotificationAPIForeignOrganizationCannotBeTargetedByBodyOrMarkRead(t *testing.T) {
	fixture := newNotificationAPIFixture(t)
	const id = "00000000-0000-4000-8000-000000000081"
	fixture.entities = append(fixture.entities,
		datastoreEntity("Organizations", isolationOtherOrg, map[string]string{"id": isolationOtherOrg}),
		datastoreEntity("notifications", id, map[string]string{"id": id, "org_id": isolationOtherOrg, "title": "foreign private alert", "description": "foreign private detail"}),
	)
	created := requestWorkflowAPI(HandleCreateNotification, http.MethodPost, "/api/v1/notifications", `{"title":"foreign edit","org_id":"`+isolationOtherOrg+`"}`)
	marked := requestWorkflowAPI(HandleMarkAsRead, http.MethodGet, "/api/v1/notifications/"+id+"/markasread", "")
	for _, response := range []*httptest.ResponseRecorder{created, marked} {
		var result map[string]interface{}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || result["success"] != false || strings.Contains(response.Body.String(), "foreign private detail") {
			t.Fatalf("foreign notification access was not denied: HTTP %d, %#v", response.Code, result)
		}
	}
	if items := notificationList(t, datastoreTestOrg, ""); len(items) != 0 {
		t.Fatalf("foreign notification leaked into own list: %+v", items)
	}
}

func TestNotificationAPIFailedWriteCanBeRetriedWithoutLosingTheAlert(t *testing.T) {
	fixture := newNotificationAPIFixture(t)
	body := `{"title":"retry alert","description":"controlled write failure","reference_url":"/release-tests/notification-retry","severity":"high","origin":"release-tests"}`
	fixture.rejectWritesToKind = "notifications"
	rejected := requestWorkflowAPI(HandleCreateNotification, http.MethodPost, "/api/v1/notifications", body)
	if rejected.Code != http.StatusInternalServerError {
		t.Fatalf("failed write was not reported: HTTP %d", rejected.Code)
	}
	fixture.rejectWritesToKind = ""
	retried := requestWorkflowAPI(HandleCreateNotification, http.MethodPost, "/api/v1/notifications", body)
	if retried.Code != http.StatusOK {
		t.Fatalf("retry failed: HTTP %d", retried.Code)
	}
	items := notificationList(t, datastoreTestOrg, "")
	if len(items) != 1 || items[0].Title != "retry alert" {
		t.Fatalf("successful retry silently lost alert: %+v", items)
	}
}

func TestNotificationAPIExecutionFailureContextIsBoundToTheReferencedExecution(t *testing.T) {
	for _, org := range []string{datastoreTestOrg, isolationOtherOrg} {
		t.Run("execution_org="+org, func(t *testing.T) {
			newNotificationAPIFixture(t)
			const executionID = "00000000-0000-4000-8000-000000000082"
			const nodeID = "00000000-0000-4000-8000-000000000083"
			action := Action{ID: nodeID, Label: "private refresh label", Name: "refresh_token", AppName: "Private OAuth app"}
			execution := WorkflowExecution{ExecutionId: executionID, WorkflowId: workflowTestID, ExecutionOrg: org, OrgId: org, Status: "FAILURE",
				Workflow: Workflow{ID: workflowTestID, OrgId: org, Actions: []Action{action}}, Results: []ActionResult{{Action: action, Status: "FAILURE", Result: `{"success":false,"reason":"private OAuth failure detail"}`}}}
			data, err := json.Marshal(execution)
			if err != nil {
				t.Fatal(err)
			}
			if err := SetCache(context.Background(), "workflowexecution_"+executionID, data, 60); err != nil {
				t.Fatal(err)
			}
			created := requestWorkflowAPI(HandleCreateNotification, http.MethodPost, "/api/v1/notifications",
				`{"title":"execution failure","description":"safe caller text","reference_url":"/workflows/`+workflowTestID+`?execution_id=`+executionID+`&node=`+nodeID+`","severity":"high","origin":"workflow"}`)
			items := notificationList(t, datastoreTestOrg, "")
			if org != datastoreTestOrg {
				for _, item := range items {
					if item.FailureReason == "private OAuth failure detail" || item.NodeLabel == "private refresh label" || item.AppName == "Private OAuth app" {
						t.Fatalf("notification resolved another organization's private execution: %+v", item)
					}
				}
				return
			}
			if created.Code != http.StatusOK || len(items) != 1 || items[0].ExecutionId != executionID || items[0].WorkflowId != workflowTestID || items[0].NodeId != nodeID || items[0].NodeStatus != "FAILURE" || items[0].FailureReason != "private OAuth failure detail" {
				t.Fatalf("failure context was not tied to its execution: HTTP %d, %+v", created.Code, items)
			}
		})
	}
}

func TestNotificationAPISeverityFilterCanFindTheSeverityThatWasSubmitted(t *testing.T) {
	newNotificationAPIFixture(t)
	created := requestWorkflowAPI(HandleCreateNotification, http.MethodPost, "/api/v1/notifications", `{"title":"critical case","description":"case-sensitive severity","severity":"CRITICAL","origin":"release-tests"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create failed: HTTP %d", created.Code)
	}
	items := notificationList(t, datastoreTestOrg, "?severity=CRITICAL")
	if len(items) != 1 || items[0].Title != "critical case" {
		t.Fatalf("severity filter hid the submitted alert: %+v", items)
	}
}

func TestNotificationAPIMissingAndInvalidCredentialsCannotReadOrMutate(t *testing.T) {
	newNotificationAPIFixture(t)
	created := requestWorkflowAPI(HandleCreateNotification, http.MethodPost, "/api/v1/notifications", `{"title":"private alert","description":"private failure detail"}`)
	items := notificationList(t, datastoreTestOrg, "")
	if created.Code != http.StatusOK || len(items) != 1 {
		t.Fatalf("failed to prepare alert: HTTP %d, %+v", created.Code, items)
	}
	for _, credential := range []string{"", "Bearer invalid-release-test-key"} {
		for _, endpoint := range []struct {
			name, method, path, body string
			handler                  http.HandlerFunc
		}{
			{"list", http.MethodGet, "/api/v1/notifications", "", HandleGetNotifications},
			{"create", http.MethodPost, "/api/v1/notifications", `{"title":"unauthorized alert"}`, HandleCreateNotification},
			{"mark", http.MethodGet, "/api/v1/notifications/" + items[0].Id + "/markasread", "", HandleMarkAsRead},
			{"clear", http.MethodGet, "/api/v1/notifications/clear", "", HandleClearNotifications},
		} {
			t.Run(endpoint.name+"/"+credential, func(t *testing.T) {
				request := httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(endpoint.body))
				request.Header.Set("Authorization", credential)
				request.Header.Set("Org-Id", datastoreTestOrg)
				response := httptest.NewRecorder()
				endpoint.handler(response, request)
				var result map[string]interface{}
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || result["success"] != false || strings.Contains(response.Body.String(), "private failure detail") {
					t.Fatalf("unauthorized request was not denied: HTTP %d, %s", response.Code, response.Body.String())
				}
			})
		}
	}
	remaining := notificationList(t, datastoreTestOrg, "?status=unread")
	if len(remaining) != 1 || remaining[0].Id != items[0].Id {
		t.Fatalf("denied mutations changed unread alerts: %+v", remaining)
	}
}

func TestNotificationAPIFailedReadStateWriteIsReportedAndRetryable(t *testing.T) {
	for _, operation := range []struct {
		name, path string
		handler    http.HandlerFunc
	}{
		{"mark", "/api/v1/notifications/%s/markasread", HandleMarkAsRead},
		{"clear", "/api/v1/notifications/clear", HandleClearNotifications},
	} {
		t.Run(operation.name, func(t *testing.T) {
			fixture := newNotificationAPIFixture(t)
			created := requestWorkflowAPI(HandleCreateNotification, http.MethodPost, "/api/v1/notifications", `{"title":"unread retry alert"}`)
			items := notificationList(t, datastoreTestOrg, "?status=unread")
			if created.Code != http.StatusOK || len(items) != 1 {
				t.Fatalf("failed to prepare unread alert: HTTP %d, %+v", created.Code, items)
			}
			path := strings.ReplaceAll(operation.path, "%s", items[0].Id)
			fixture.rejectWritesToKind = "notifications"
			rejected := requestWorkflowAPI(operation.handler, http.MethodGet, path, "")
			var result map[string]interface{}
			if err := json.Unmarshal(rejected.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if rejected.Code < 500 || result["success"] != false {
				t.Errorf("failed read-state write was acknowledged: HTTP %d, %s", rejected.Code, rejected.Body.String())
			}
			remaining := notificationList(t, datastoreTestOrg, "?status=unread")
			if len(remaining) != 1 || remaining[0].Id != items[0].Id {
				t.Fatalf("failed write changed unread state: %+v", remaining)
			}
			fixture.rejectWritesToKind = ""
			retried := requestWorkflowAPI(operation.handler, http.MethodGet, path, "")
			if retried.Code != http.StatusOK || len(notificationList(t, datastoreTestOrg, "?status=unread")) != 0 {
				t.Fatalf("read-state retry did not persist: HTTP %d", retried.Code)
			}
		})
	}
}

// ---- Consolidated from rls_test.go ----

// Helper to compare JSON semantically (ignores key order)
func jsonEqual(a, b string) bool {
	var ma, mb any
	if err := json.Unmarshal([]byte(a), &ma); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(b), &mb); err != nil {
		return false
	}
	return deepEqual(ma, mb)
}

func deepEqual(a, b any) bool {
	switch aa := a.(type) {
	case map[string]any:
		bb, ok := b.(map[string]any)
		if !ok || len(aa) != len(bb) {
			return false
		}
		for k, v := range aa {
			if !deepEqual(v, bb[k]) {
				return false
			}
		}
		return true
	case []any:
		bb, ok := b.([]any)
		if !ok || len(aa) != len(bb) {
			return false
		}
		for i := range aa {
			if !deepEqual(aa[i], bb[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}

func TestEvalPolicyJSON_Comprehensive(t *testing.T) {
	tests := []struct {
		name       string
		policy     string
		oldJSON    string
		newJSON    string
		wantJSON   string
		wantOk     bool
		wantReason string
	}{
		// ---------------------- 1. Basic Merging ----------------------
		{
			name:       "merge_top-level_allowed_field",
			policy:     `merge if allowed_fields["hello","foo"]`,
			oldJSON:    `{"foo":"bar","hello":"world"}`,
			newJSON:    `{"hello":"you"}`,
			wantJSON:   `{"foo":"bar","hello":"you"}`,
			wantOk:     true,
			wantReason: "",
		},
		{
			name:       "merge_allowed_field_partial_update",
			policy:     `merge if allowed_fields["nested","missing"]`,
			oldJSON:    `{"nested":{"a":1}}`,
			newJSON:    `{"nested":{"a":2}}`,
			wantJSON:   `{"nested":{"a":2}}`,
			wantOk:     true,
			wantReason: "",
		},

		// ---------------------- 2. Overwrite / Shape Checks ----------------------
		{
			name:       "overwrite_same_shape_success",
			policy:     `overwrite if same_shape`,
			oldJSON:    `{"a":1,"b":2}`,
			newJSON:    `{"a":10,"b":20}`,
			wantJSON:   `{"a":10,"b":20}`,
			wantOk:     true,
			wantReason: "",
		},
		{
			name:       "overwrite_shape_mismatch_fails",
			policy:     `overwrite if same_shape`,
			oldJSON:    `{"a":1}`,
			newJSON:    `{"a":1,"b":2}`,
			wantJSON:   `{"a":1}`,
			wantOk:     false,
			wantReason: "no matching allow rule",
		},

		// ---------------------- 3. Deny / Deletion Logic ----------------------
		{
			name:     "deny_deleted_field_simple",
			policy:   `deny if has_deleted_field`,
			oldJSON:  `{"a":1,"b":2}`,
			newJSON:  `{"a":1}`,
			wantJSON: `{"a":1,"b":2}`,
			wantOk:   false,
			// UPDATED: Now expects specific path
			wantReason: "deny: field deletion detected at 'b'",
		},
		{
			name:     "deny_deleted_field_nested",
			policy:   `deny if has_deleted_field`,
			oldJSON:  `{"nested":{"x":1,"y":2}}`,
			newJSON:  `{"nested":{"x":1}}`,
			wantJSON: `{"nested":{"x":1,"y":2}}`,
			wantOk:   false,
			// UPDATED: Now expects nested path
			wantReason: "deny: field deletion detected at 'nested.y'",
		},
		{
			// Implicit Merge + Injection (Should be allowed if only deny rules exist)
			name:       "deny_only_allows_injection",
			policy:     `deny if has_deleted_field`,
			oldJSON:    `{"a":1}`,
			newJSON:    `{"a":1, "b":2}`,
			wantJSON:   `{"a":1, "b":2}`,
			wantOk:     true,
			wantReason: "",
		},

		// ---------------------- 4. Interaction: Merge + Deny ----------------------
		{
			name:       "merge_allowed_and_deny_deleted",
			policy:     `merge if allowed_fields["nested"]; deny if has_deleted_field`,
			oldJSON:    `{"nested":{"a":1,"b":2},"keep":42}`,
			newJSON:    `{"nested":{"b":20},"keep":42}`,
			wantJSON:   `{"nested":{"a":1,"b":20},"keep":42}`,
			wantOk:     true,
			wantReason: "",
		},
		{
			name:       "merge_safely_ignores_missing_unallowed_fields",
			policy:     `merge if allowed_fields["nested"]; deny if has_deleted_field`,
			oldJSON:    `{"nested":{"a":1,"b":2},"keep":42}`,
			newJSON:    `{"nested":{"b":20}}`,                 // 'keep' is missing here
			wantJSON:   `{"nested":{"a":1,"b":20},"keep":42}`, // 'keep' is preserved by merge logic
			wantOk:     true,
			wantReason: "",
		},

		// ---------------------- 5. Complex Nested / Edge Cases ----------------------
		{
			name:       "nested_overwrite_same_shape",
			policy:     `overwrite if same_shape`,
			oldJSON:    `{"nested":{"x":1,"y":2}}`,
			newJSON:    `{"nested":{"x":10,"y":20}}`,
			wantJSON:   `{"nested":{"x":10,"y":20}}`,
			wantOk:     true,
			wantReason: "",
		},
		{
			name:       "allow_type_change_string_to_map",
			policy:     `deny if has_deleted_field`,
			oldJSON:    `{"a": "value"}`,
			newJSON:    `{"a": {"sub": 1}}`,
			wantJSON:   `{"a": {"sub": 1}}`,
			wantOk:     true,
			wantReason: "",
		},
		{
			name:     "deny_type_change_map_to_string",
			policy:   `deny if has_deleted_field`,
			oldJSON:  `{"a": {"sub": 1}}`,
			newJSON:  `{"a": "value"}`,
			wantJSON: `{"a": {"sub": 1}}`,
			wantOk:   false,
			// UPDATED: "a" is the key where the map structure disappeared
			wantReason: "deny: field deletion detected at 'a'",
		},

		// ---------------------- 6. Array Deletion Logic ----------------------
		{
			// FAIL: Explicitly removing a field from an ID-ed item
			name:     "deny_deleted_nested_in_array",
			policy:   `deny if has_deleted_field`,
			oldJSON:  `{"list": [ {"id": 1, "secret": "keep_me"}, {"id": 2} ]}`,
			newJSON:  `{"list": [ {"id": 1}, {"id": 2} ]}`,
			wantJSON: `{"list": [ {"id": 1, "secret": "keep_me"}, {"id": 2} ]}`,
			wantOk:   false,
			// UPDATED PATH: Uses [id=1]
			wantReason: "deny: field deletion detected at 'list[id=1].secret'",
		},

		// ---------------------- 7. Smart Merge Logic (Delta Updates) ----------------------
		{
			// SUCCESS: User sends ONLY the new item.
			// Smart Merge sees ID 2 is new, so it APPENDS it. ID 1 is preserved.
			// Old Logic would have failed/overwritten. New Logic allows this.
			name:    "nested_array_smart_append",
			policy:  "merge if always; deny if has_deleted_field",
			oldJSON: `{"metadata":{"tasks":[{"id":1,"title":"Keep Me"}]}}`,
			newJSON: `{"metadata":{"tasks":[{"id":2}]}}`,
			// Result: Combined List
			wantJSON:   `{"metadata":{"tasks":[{"id":1,"title":"Keep Me"},{"id":2}]}}`,
			wantOk:     true,
			wantReason: "",
		},
		{
			// SUCCESS: User sends Full List (No Duplication).
			// Smart Merge sees ID 1 exists (merges it), ID 2 is new (appends it).
			name:    "nested_array_smart_merge_no_dupes",
			policy:  "merge if always; deny if has_deleted_field",
			oldJSON: `{"metadata":{"tasks":[{"id":1,"title":"Keep Me"}]}}`,
			newJSON: `{"metadata":{"tasks":[{"id":1,"title":"Keep Me"},{"id":2,"title":"New Task"}]}}`,
			// Result: Exact match (No "Keep Me" duplication)
			wantJSON:   `{"metadata":{"tasks":[{"id":1,"title":"Keep Me"},{"id":2,"title":"New Task"}]}}`,
			wantOk:     true,
			wantReason: "",
		},
		{
			// SUCCESS: Patch Existing Item via Merge
			// User sends partial data for ID 1. Smart Merge updates it.
			name:    "nested_array_smart_patch",
			policy:  "merge; deny if has_deleted_field",
			oldJSON: `{"tasks": [{"id":1, "title":"Old", "status":"open"}]}`,
			newJSON: `{"tasks": [{"id":1, "status":"closed"}]}`,
			// Result: Title preserved (from Old), Status updated (from New)
			wantJSON:   `{"tasks": [{"id":1, "status":"closed","title":"Old"}]}`,
			wantOk:     true,
			wantReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotJSON, gotOk, gotReason := EvalPolicyJSON(tt.policy, tt.oldJSON, tt.newJSON)

			if gotOk != tt.wantOk {
				t.Errorf("\nCheck: %s\nWanted OK: %v\nGot OK:    %v\nReason:    %q", tt.name, tt.wantOk, gotOk, gotReason)
			}

			// Only check reason if we expected a failure
			if !tt.wantOk && gotReason != tt.wantReason {
				t.Errorf("\nCheck: %s\nWanted Reason: %q\nGot Reason:    %q", tt.name, tt.wantReason, gotReason)
			}

			if !jsonEqual(gotJSON, tt.wantJSON) {
				t.Errorf("\nCheck: %s\nWanted JSON: %s\nGot JSON:    %s", tt.name, tt.wantJSON, gotJSON)
			}
		})
	}
}

// ---- Consolidated from schedules_test.go ----

const scheduleAPIPath = "/api/v1/workflows/schedules"

func seedScheduleAPI(t *testing.T) ScheduleOld {
	t.Helper()
	item := ScheduleOld{Id: "00000000-0000-4000-8000-000000000141", Name: "release schedule", Org: datastoreTestOrg,
		WorkflowId: workflowTestID, Seconds: 300, Frequency: "*/5 * * * *", Environment: "cloud", Status: "running",
		Argument: `{"marker":"owned schedule input"}`}
	foreign := item
	foreign.Id, foreign.Org, foreign.Argument = "00000000-0000-4000-8000-000000000142", isolationOtherOrg, "foreign-private-schedule-input"
	for _, schedule := range []ScheduleOld{item, foreign} {
		if _, err := project.Dbclient.Put(context.Background(), datastore.NameKey("schedules", schedule.Id, nil), &schedule); err != nil {
			t.Fatal(err)
		}
	}
	return item
}

func TestScheduleAPIEmptyOrganizationReturnsAJSONList(t *testing.T) {
	newDatastoreAPIFixture(t)
	project.Environment = "cloud"
	response := requestWorkflowAPI(HandleGetSchedules, http.MethodGet, scheduleAPIPath, "")
	var body interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	items, ok := body.([]interface{})
	if response.Code != http.StatusOK || !ok || len(items) != 0 {
		t.Fatalf("empty schedule list is not a JSON array: HTTP %d, %s", response.Code, response.Body.String())
	}
}

func TestScheduleAPIListPreservesOwnedConfigurationAndExcludesForeignOrg(t *testing.T) {
	newDatastoreAPIFixture(t)
	project.Environment = "cloud"
	want := seedScheduleAPI(t)
	response := requestWorkflowAPI(HandleGetSchedules, http.MethodGet, scheduleAPIPath, "")
	var items []ScheduleOld
	if err := json.Unmarshal(response.Body.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || len(items) != 1 {
		t.Fatalf("owned schedule list failed: HTTP %d, items=%d", response.Code, len(items))
	}
	got := items[0]
	if got.Id != want.Id || got.Org != want.Org || got.WorkflowId != want.WorkflowId || got.Frequency != want.Frequency || got.Seconds != want.Seconds || got.Argument != want.Argument || got.Status != want.Status {
		t.Fatal("schedule list lost identity or execution configuration")
	}
	if strings.Contains(response.Body.String(), "foreign-private-schedule-input") {
		t.Fatal("schedule list exposed the other organization's input")
	}
}

func TestScheduleAPIMissingInvalidAndNonAdminCredentialsAreDenied(t *testing.T) {
	for _, mode := range []string{"missing", "invalid", "org-reader", "user"} {
		t.Run(mode, func(t *testing.T) {
			newDatastoreAPIFixture(t)
			project.Environment = "cloud"
			seedScheduleAPI(t)
			credential := ""
			if mode == "invalid" {
				credential = "Bearer 00000000-0000-4000-8000-000000000143"
			} else if mode != "missing" {
				credential = "Bearer " + datastoreTestAPIKey
				user, err := json.Marshal(User{Id: "release-test-user", Username: "scheduler@shuffler.io", Role: mode, ActiveOrg: OrgMini{Id: datastoreTestOrg}})
				if err != nil {
					t.Fatal(err)
				}
				if err := SetCache(context.Background(), datastoreTestAPIKey+datastoreTestOrg, user, 60); err != nil {
					t.Fatal(err)
				}
			}
			request := httptest.NewRequest(http.MethodGet, scheduleAPIPath, nil)
			request.Header.Set("Authorization", credential)
			request.Header.Set("Org-Id", datastoreTestOrg)
			response := httptest.NewRecorder()
			HandleGetSchedules(response, request)
			var body map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || body["success"] != false || strings.Contains(response.Body.String(), "schedule-input") {
				t.Fatalf("untrusted schedule read was not safely denied: HTTP %d", response.Code)
			}
		})
	}
}

func TestScheduleAPIOrgHeaderRequiresMembership(t *testing.T) {
	for _, authorized := range []bool{false, true} {
		name := "forged header"
		if authorized {
			name = "authorized suborg"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newDatastoreAPIFixture(t)
			project.Environment = "cloud"
			seedScheduleAPI(t)
			fixture.entities = append(fixture.entities, datastoreEntity("Organizations", isolationOtherOrg, map[string]string{"id": isolationOtherOrg}))
			user := User{Id: "release-test-user", Username: "scheduler@shuffler.io", Role: "admin", ApiKey: datastoreTestAPIKey,
				ActiveOrg: OrgMini{Id: datastoreTestOrg}, Orgs: []string{datastoreTestOrg}}
			if authorized {
				user.Orgs = append(user.Orgs, isolationOtherOrg)
			}
			encoded, err := json.Marshal([]User{user})
			if err != nil {
				t.Fatal(err)
			}
			if err := SetCache(context.Background(), "Users_"+datastoreTestAPIKey, encoded, 60); err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, scheduleAPIPath, nil)
			request.Header.Set("Authorization", "Bearer "+datastoreTestAPIKey)
			request.Header.Set("Org-Id", isolationOtherOrg)
			response := httptest.NewRecorder()
			HandleGetSchedules(response, request)
			if authorized {
				var items []ScheduleOld
				if err := json.Unmarshal(response.Body.Bytes(), &items); err != nil {
					t.Fatal(err)
				}
				if response.Code != http.StatusOK || len(items) != 1 || items[0].Org != isolationOtherOrg || items[0].Id != "00000000-0000-4000-8000-000000000142" {
					t.Fatal("authorized organization switch did not select its own schedules")
				}
			} else {
				var body map[string]interface{}
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || body["success"] != false || strings.Contains(response.Body.String(), "foreign-private-schedule-input") {
					t.Fatal("forged org header exposed schedules")
				}
			}
		})
	}
}

func TestScheduleAPIFailedReadIsReportedAndRecovers(t *testing.T) {
	fixture := newDatastoreAPIFixture(t)
	project.Environment = "cloud"
	want := seedScheduleAPI(t)
	fixture.queryErrKind = "schedules"
	fixture.queryErr = status.Error(codes.PermissionDenied, "synthetic schedule read rejected")
	response := requestWorkflowAPI(HandleGetSchedules, http.MethodGet, scheduleAPIPath, "")
	var body map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code < 400 || body["success"] != false {
		t.Errorf("failed schedule read was reported as a successful empty list: HTTP %d", response.Code)
	}
	fixture.queryErr = nil
	response = requestWorkflowAPI(HandleGetSchedules, http.MethodGet, scheduleAPIPath, "")
	var items []ScheduleOld
	if err := json.Unmarshal(response.Body.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || len(items) != 1 || items[0].Id != want.Id {
		t.Fatal("schedule read did not recover after the storage fault")
	}
}

// ---- Consolidated from workflow_test.go ----

const workflowTestID = "00000000-0000-4000-8000-000000000003"
const workflowOwnerAPIKey = "00000000-0000-4000-8000-000000000005"

func requestWorkflowAPI(handler http.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+datastoreTestAPIKey)
	request.Header.Set("Org-Id", datastoreTestOrg)
	response := httptest.NewRecorder()
	handler(response, request)
	return response
}

func TestWorkflowSaveMalformedJSONReturnsJSONError(t *testing.T) {
	fixture := newDatastoreAPIFixture(t)
	fixture.entities = append(fixture.entities, datastoreEntity("workflow", workflowTestID, map[string]string{
		"id": workflowTestID, "name": "existing workflow", "owner": "release-test-user", "org_id": datastoreTestOrg,
	}))
	for name, input := range map[string]string{
		"missing comma":   `{"name":"example" "description":"invalid separator"}`,
		"wrong name type": `{"name":123}`, "wrong action type": `{"actions":"invalid"}`,
		"invalid escape": `{"name":"bad\q"}`, "trailing data": `{} {}`, "empty body": "",
	} {
		t.Run(name, func(t *testing.T) {
			response := requestWorkflowAPI(SaveWorkflow, http.MethodPut, "/api/v1/workflows/"+workflowTestID, input)
			var body map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("malformed request produced invalid JSON: HTTP %d, %s", response.Code, response.Body.String())
			}
			if response.Code != http.StatusBadRequest || body["success"] != false {
				t.Fatalf("malformed request returned HTTP %d, %#v", response.Code, body)
			}
		})
	}
}

func TestWorkflowCreateCannotMakeItselfPublic(t *testing.T) {
	newDatastoreAPIFixture(t)
	response := requestWorkflowAPI(SetNewWorkflow, http.MethodPost, "/api/v1/workflows", `{"name":"release workflow","public":true,"sharing":"public","actions":[{"id":"00000000-0000-4000-8000-000000000004","name":"repeat_back_to_me","environment":"Cloud"}]}`)
	var workflow Workflow
	if err := json.Unmarshal(response.Body.Bytes(), &workflow); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || len(workflow.ID) != 36 {
		t.Fatalf("workflow creation failed before privacy could be checked: HTTP %d", response.Code)
	}
	if workflow.Public || workflow.Sharing != "private" || workflow.OrgId != datastoreTestOrg || workflow.Owner != "release-test-user" {
		t.Errorf("workflow creation did not enforce private ownership: HTTP %d, public=%t, sharing=%q, org=%q, owner=%q", response.Code, workflow.Public, workflow.Sharing, workflow.OrgId, workflow.Owner)
	}
	loaded := requestWorkflowAPI(GetSpecificWorkflow, http.MethodGet, "/api/v1/workflows/"+workflow.ID, "")
	var saved Workflow
	if err := json.Unmarshal(loaded.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if loaded.Code != http.StatusOK || saved.ID != workflow.ID || saved.Name != "release workflow" || saved.Public || saved.OrgId != datastoreTestOrg {
		t.Errorf("created workflow was not privately retrievable: HTTP %d, public=%t, org=%q", loaded.Code, saved.Public, saved.OrgId)
	}
	anonymous := httptest.NewRecorder()
	GetSpecificWorkflow(anonymous, httptest.NewRequest(http.MethodGet, "/api/v1/workflows/"+workflow.ID, nil))
	if anonymous.Code != http.StatusUnauthorized && anonymous.Code != http.StatusForbidden {
		t.Fatalf("newly created private workflow was accessible anonymously: HTTP %d", anonymous.Code)
	}
}

func TestWorkflowSaveCannotForgePrivateWorkflowOwnership(t *testing.T) {
	workflow := publicWorkflowAPIFixture(t)
	workflow.Public = false
	workflow.Sharing = "private"
	if _, err := project.Dbclient.Put(context.Background(), datastore.NameKey("workflow", workflow.ID, nil), &workflow); err != nil {
		t.Fatal(err)
	}
	workflow.Owner = "release-test-user"
	workflow.OrgId = datastoreTestOrg
	workflow.Public = true
	workflow.Description = "forged private update"
	payload, err := json.Marshal(workflow)
	if err != nil {
		t.Fatal(err)
	}
	response := requestWorkflowAPI(SaveWorkflow, http.MethodPut, "/api/v1/workflows/"+workflowTestID, string(payload))
	var body map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || body["success"] != false {
		t.Errorf("forged ownership was not rejected: HTTP %d, %s", response.Code, response.Body.String())
	}
	source := readWorkflowAsOriginalOwner(t)
	if source.Owner != "another-user" || source.Public || source.Description != "" || len(source.Actions) != 1 {
		t.Fatalf("forged save changed private source: owner=%q, public=%t, description=%q", source.Owner, source.Public, source.Description)
	}
}

func publicWorkflowAPIFixture(t *testing.T) Workflow {
	t.Helper()
	newDatastoreAPIFixture(t)
	project.Environment = "cloud"
	t.Setenv("ALGOLIA_CLIENT", "")
	t.Setenv("ALGOLIA_SECRET", "")
	t.Setenv("GITHUB_USER_ALLOWLIST", "")
	workflow := Workflow{ID: workflowTestID, Name: "public source", Owner: "another-user", OrgId: isolationOtherOrg,
		Public: true, Sharing: "public", PreviouslySaved: true, IsValid: true,
		Start: "00000000-0000-4000-8000-000000000004",
		Actions: []Action{{ID: "00000000-0000-4000-8000-000000000004", Name: "repeat_back_to_me",
			Label: "echo", AppName: "Shuffle Tools", AppVersion: "1.0.0", AppID: "0123456789abcdef0123456789abcdef", Environment: "cloud", IsValid: true}}}
	for _, org := range []Org{
		{Id: datastoreTestOrg, ActiveApps: []string{workflow.Actions[0].AppID}, Users: []User{{Id: "release-test-user", Role: "admin"}}},
		{Id: isolationOtherOrg, ActiveApps: []string{workflow.Actions[0].AppID}, Users: []User{{Id: "another-user", Role: "admin"}}},
	} {
		owner := org.Users[0]
		owner.ActiveOrg = OrgMini{Id: org.Id}
		owner.Orgs = []string{org.Id}
		if _, err := project.Dbclient.Put(context.Background(), datastore.NameKey("Users", owner.Id, nil), &owner); err != nil {
			t.Fatal(err)
		}
		if _, err := project.Dbclient.Put(context.Background(), datastore.NameKey("Organizations", org.Id, nil), &org); err != nil {
			t.Fatal(err)
		}
	}
	app := WorkflowApp{ID: workflow.Actions[0].AppID, Name: "Shuffle Tools", AppVersion: "1.0.0",
		Actions: []WorkflowAppAction{{Name: "repeat_back_to_me"}}}
	for key, value := range map[string]interface{}{
		"apps_" + datastoreTestOrg: []WorkflowApp{app}, "apps_" + isolationOtherOrg: []WorkflowApp{app},
		"algolia_creator_":                      AlgoliaSearchCreator{ObjectID: "another-user"},
		workflowOwnerAPIKey + isolationOtherOrg: User{Id: "another-user", Username: "scheduler@shuffler.io", Role: "admin", ActiveOrg: OrgMini{Id: isolationOtherOrg}, Orgs: []string{isolationOtherOrg}},
	} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := SetCache(context.Background(), key, data, 60); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := project.Dbclient.Put(context.Background(), datastore.NameKey("workflow", workflow.ID, nil), &workflow); err != nil {
		t.Fatal(err)
	}
	return workflow
}

func readWorkflowAsOriginalOwner(t *testing.T) Workflow {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workflows/"+workflowTestID, nil)
	request.Header.Set("Authorization", "Bearer "+workflowOwnerAPIKey)
	request.Header.Set("Org-Id", isolationOtherOrg)
	response := httptest.NewRecorder()
	GetSpecificWorkflow(response, request)
	var workflow Workflow
	if err := json.Unmarshal(response.Body.Bytes(), &workflow); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK {
		t.Fatalf("public workflow owner read failed: HTTP %d", response.Code)
	}
	return workflow
}

func TestWorkflowSaveCopiesPublicWorkflowForNonOwner(t *testing.T) {
	workflow := publicWorkflowAPIFixture(t)
	payload, err := json.Marshal(workflow)
	if err != nil {
		t.Fatal(err)
	}
	response := requestWorkflowAPI(SaveWorkflow, http.MethodPut, "/api/v1/workflows/"+workflowTestID, string(payload))
	var body map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	newID, _ := body["new_id"].(string)
	if response.Code != http.StatusOK || body["success"] != true || len(newID) != 36 || newID == workflowTestID {
		t.Fatalf("public source was not copied to a new workflow: HTTP %d, %#v", response.Code, body)
	}
	loaded := requestWorkflowAPI(GetSpecificWorkflow, http.MethodGet, "/api/v1/workflows/"+newID, "")
	var copy Workflow
	if err := json.Unmarshal(loaded.Body.Bytes(), &copy); err != nil {
		t.Fatal(err)
	}
	if loaded.Code != http.StatusOK || copy.ID != newID || copy.Public || copy.Owner != "release-test-user" || copy.OrgId != datastoreTestOrg || copy.Name != "public source" {
		t.Fatalf("public source did not produce an owned private copy: HTTP %d, %+v", loaded.Code, copy)
	}
	if len(copy.Actions) != 1 || copy.Actions[0].Name != "repeat_back_to_me" {
		t.Fatal("copied workflow lost the source action")
	}
	source := readWorkflowAsOriginalOwner(t)
	if source.Owner != "another-user" || !source.Public || source.Description != "" || len(source.Actions) != 1 {
		t.Fatal("normal public copy modified the original workflow")
	}
}

func TestWorkflowSaveCannotOverwritePublicSourceByForgingOwner(t *testing.T) {
	workflow := publicWorkflowAPIFixture(t)
	workflow.Owner = "release-test-user"
	workflow.OrgId = datastoreTestOrg
	workflow.Description = "forged update"
	payload, err := json.Marshal(workflow)
	if err != nil {
		t.Fatal(err)
	}
	response := requestWorkflowAPI(SaveWorkflow, http.MethodPut, "/api/v1/workflows/"+workflowTestID, string(payload))
	var body map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code == http.StatusOK && body["success"] == true {
		if id, _ := body["new_id"].(string); len(id) != 36 || id == workflowTestID {
			t.Errorf("forged owner save acknowledged without a separate copy: HTTP %d, %s", response.Code, response.Body.String())
		}
	} else if response.Code != http.StatusBadRequest && response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden {
		t.Errorf("unexpected save failure: HTTP %d, %s", response.Code, response.Body.String())
	}
	source := readWorkflowAsOriginalOwner(t)
	if source.Owner != "another-user" || !source.Public || source.Description != "" || len(source.Actions) != 1 {
		t.Fatalf("forged save changed the public source: id=%q, owner=%q, public=%t, description=%q", source.ID, source.Owner, source.Public, source.Description)
	}
}

func TestWorkflowReaderCannotCreateOrSave(t *testing.T) {
	newDatastoreAPIFixture(t)
	data, err := json.Marshal(User{Id: "release-test-user", Username: "scheduler@shuffler.io", Role: "org-reader", ActiveOrg: OrgMini{Id: datastoreTestOrg}})
	if err != nil {
		t.Fatal(err)
	}
	if err := SetCache(context.Background(), datastoreTestAPIKey+datastoreTestOrg, data, 60); err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct {
		handler      http.HandlerFunc
		method, path string
	}{{SetNewWorkflow, http.MethodPost, "/api/v1/workflows"}, {SaveWorkflow, http.MethodPut, "/api/v1/workflows/" + workflowTestID}} {
		response := requestWorkflowAPI(request.handler, request.method, request.path, `{"name":"denied edit"}`)
		var body map[string]interface{}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if (response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden) || body["success"] != false {
			t.Fatalf("read-only user was allowed to mutate a workflow: HTTP %d, %#v", response.Code, body)
		}
	}
}
