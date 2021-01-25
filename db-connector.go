package shuffle

import (
	"cloud.google.com/go/datastore"
	"context"
	"log"
)

func GetDatastoreClient(ctx context.Context, projectID string) (datastore.Client, error) {
	// FIXME - this doesn't work
	//client, err := datastore.NewClient(ctx, projectID, option.WithCredentialsFile(test"))
	client, err := datastore.NewClient(ctx, projectID)
	//client, err := datastore.NewClient(ctx, projectID, option.WithCredentialsFile("test"))
	if err != nil {
		return datastore.Client{}, err
	}

	return *client, nil
}

func SetWorkflowAppDatastore(ctx context.Context, gceProject string, workflowapp WorkflowApp, id string) error {
	dbclient, err := getDatastoreClient(ctx, gceProject)
	if err != nil {
		log.Printf("Error setting datastore: %s", err)
		return err
	}

	key := datastore.NameKey("workflowapp", id, nil)

	// New struct, to not add body, author etc
	if _, err := dbclient.Put(ctx, key, &workflowapp); err != nil {
		log.Printf("Error adding workflow app: %s", err)
		return err
	}

	return nil
}

func SetWorkflowExecution(ctx context.Context, workflowExecution WorkflowExecution) error {
	if len(workflowExecution.ExecutionId) == 0 {
		log.Printf("Workflowexeciton executionId can't be empty.")
		return errors.New("ExecutionId can't be empty.")
	}

	dbclient, err := getDatastoreClient(ctx, gceProject)
	if err != nil {
		log.Printf("Error setting datastore: %s", err)
		return err
	}

	key := datastore.NameKey("workflowexecution", workflowExecution.ExecutionId, nil)

	// New struct, to not add body, author etc
	if _, err := dbclient.Put(ctx, key, &workflowExecution); err != nil {
		log.Printf("Error adding workflow_execution: %s", err)
		return err
	}

	return nil
}

func GetWorkflowExecution(ctx context.Context, id string) (*WorkflowExecution, error) {
	dbclient, err := getDatastoreClient(ctx, gceProject)
	if err != nil {
		log.Println(err)
		return &WorkflowExecution{}, err
	}

	key := datastore.NameKey("workflowexecution", strings.ToLower(id), nil)
	workflowExecution := &WorkflowExecution{}
	if err := dbclient.Get(ctx, key, workflowExecution); err != nil {
		return &WorkflowExecution{}, err
	}

	return workflowExecution, nil
}

func GetApp(ctx context.Context, id string) (*WorkflowApp, error) {
	dbclient, err := getDatastoreClient(ctx, gceProject)
	if err != nil {
		log.Println(err)
		return &WorkflowApp{}, err
	}

	key := datastore.NameKey("workflowapp", strings.ToLower(id), nil)
	workflowApp := &WorkflowApp{}
	if err := dbclient.Get(ctx, key, workflowApp); err != nil {
		return &WorkflowApp{}, err
	}

	return workflowApp, nil
}

func GetWorkflow(ctx context.Context, id string) (*Workflow, error) {
	dbclient, err := getDatastoreClient(ctx, gceProject)
	if err != nil {
		log.Println(err)
		return &Workflow{}, err
	}

	key := datastore.NameKey("workflow", strings.ToLower(id), nil)
	workflow := &Workflow{}
	if err := dbclient.Get(ctx, key, workflow); err != nil {
		return &Workflow{}, err
	}

	return workflow, nil
}

func GetAllWorkflows(ctx context.Context) ([]Workflow, error) {
	dbclient, err := getDatastoreClient(ctx, gceProject)
	if err != nil {
		return []Workflow{}, err
	}

	q := datastore.NewQuery("workflow")
	var allworkflows []Workflow

	_, err = dbclient.GetAll(ctx, q, &allworkflows)
	if err != nil {
		return []Workflow{}, err
	}

	return allworkflows, nil
}

// Hmm, so I guess this should use uuid :(
// Consistency PLX
func GetWorkflow(ctx context.Context, workflow Workflow, id string) error {
	dbclient, err := getDatastoreClient(ctx, gceProject)
	if err != nil {
		log.Printf("Error setting datastore: %s", err)
		return err
	}

	key := datastore.NameKey("workflow", id, nil)

	// New struct, to not add body, author etc
	if _, err := dbclient.Put(ctx, key, &workflow); err != nil {
		log.Printf("Error adding workflow: %s", err)
		return err
	}

	return nil
}

// ListBooks returns a list of books, ordered by title.
func GetOrg(ctx context.Context, id string) (*Org, error) {
	dbclient, err := getDatastoreClient(ctx, gceProject)
	if err != nil {
		log.Println(err)
		return &Org{}, err
	}

	key := datastore.NameKey("Organizations", id, nil)
	curOrg := &Org{}
	if err := dbclient.Get(ctx, key, curOrg); err != nil {
		return &Org{}, err
	}

	return curOrg, nil
}

func SetOrg(ctx context.Context, data Org, id string) error {
	dbclient, err := getDatastoreClient(ctx, gceProject)
	if err != nil {
		log.Println(err)
		return err
	}

	// clear session_token and API_token for user
	k := datastore.NameKey("Organizations", id, nil)
	if _, err := dbclient.Put(ctx, k, &data); err != nil {
		log.Println(err)
		return err
	}

	return nil
}

//https://cloud.google.com/go/getting-started/using-cloud-datastore
func GetDatastoreClient(ctx context.Context, projectID string) (datastore.Client, error) {
	// FIXME - this doesn't work
	//client, err := datastore.NewClient(ctx, projectID, option.WithCredentialsFile(test"))
	client, err := datastore.NewClient(ctx, projectID)
	//client, err := datastore.NewClient(ctx, projectID, option.WithCredentialsFile("test"))
	if err != nil {
		return datastore.Client{}, err
	}

	return *client, nil
}

func GetSession(ctx context.Context, thissession string) (*session, error) {
	dbclient, err := getDatastoreClient(ctx, gceProject)
	if err != nil {
		log.Println(err)
		return &session{}, err
	}

	key := datastore.NameKey("sessions", thissession, nil)
	curUser := &session{}
	if err := dbclient.Get(ctx, key, curUser); err != nil {
		return &session{}, err
	}

	return curUser, nil
}

// ListBooks returns a list of books, ordered by title.
func GetUser(ctx context.Context, Username string) (*shuffle.User, error) {
	dbclient, err := getDatastoreClient(ctx, gceProject)
	if err != nil {
		log.Println(err)
		return &User{}, err
	}

	key := datastore.NameKey("Users", strings.ToLower(Username), nil)
	curUser := &User{}
	if err := dbclient.Get(ctx, key, curUser); err != nil {
		return &User{}, err
	}

	return curUser, nil
}

// Index = Username
func DeleteKey(ctx context.Context, entity string, value string) error {
	dbclient, err := getDatastoreClient(ctx, gceProject)
	if err != nil {
		log.Println(err)
		return err
	}

	// Non indexed User data
	key1 := datastore.NameKey(entity, value, nil)

	err = dbclient.Delete(ctx, key1)
	if err != nil {
		log.Printf("Error deleting %s from %s: %s", value, entity, err)
		return err
	}

	return nil
}

// Index = Username
func SetApikey(ctx context.Context, Userdata User) error {
	dbclient, err := getDatastoreClient(ctx, gceProject)
	if err != nil {
		log.Println(err)
		return err
	}

	// Non indexed User data
	newapiUser := new(Userapi)
	newapiUser.ApiKey = Userdata.ApiKey
	newapiUser.Username = Userdata.Username
	key1 := datastore.NameKey("apikey", newapiUser.ApiKey, nil)

	// New struct, to not add body, author etc
	if _, err := dbclient.Put(ctx, key1, newapiUser); err != nil {
		log.Printf("Error adding apikey: %s", err)
		return err
	}

	return nil
}

// Index = Username
func SetSession(ctx context.Context, Userdata shuffle.User, value string) error {
	dbclient, err := getDatastoreClient(ctx, gceProject)
	if err != nil {
		log.Println(err)
		return err
	}

	// Non indexed User data
	Userdata.Session = value
	key1 := datastore.NameKey("Users", strings.ToLower(Userdata.Username), nil)

	// New struct, to not add body, author etc
	if _, err := dbclient.Put(ctx, key1, &Userdata); err != nil {
		log.Printf("rror adding Usersession: %s", err)
		return err
	}

	if len(Userdata.Session) > 0 {
		// Indexed session data
		sessiondata := new(session)
		sessiondata.Username = Userdata.Username
		sessiondata.Session = Userdata.Session
		key2 := datastore.NameKey("sessions", sessiondata.Session, nil)

		if _, err := dbclient.Put(ctx, key2, sessiondata); err != nil {
			log.Printf("Error adding session: %s", err)
			return err
		}
	}

	return nil
}

func SetOpenApiDatastore(ctx context.Context, id string, data ParsedOpenApi) error {
	dbclient, err := getDatastoreClient(ctx, gceProject)
	if err != nil {
		log.Println(err)
		return err
	}

	k := datastore.NameKey("openapi3", id, nil)
	if _, err := dbclient.Put(ctx, k, &data); err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func GetOpenApiDatastore(ctx context.Context, id string) (ParsedOpenApi, error) {
	dbclient, err := getDatastoreClient(ctx, gceProject)
	if err != nil {
		log.Println(err)
		return ParsedOpenApi{}, err
	}

	key := datastore.NameKey("openapi3", id, nil)
	api := &ParsedOpenApi{}
	if err := dbclient.Get(ctx, key, api); err != nil {
		return ParsedOpenApi{}, err
	}

	return *api, nil
}

func SetUser(ctx context.Context, data *User) error {
	dbclient, err := getDatastoreClient(ctx, gceProject)
	if err != nil {
		log.Println(err)
		return err
	}

	log.Printf("[INFO] Role: %s", data.Role)
	data = fixUserOrg(ctx, data)

	// clear session_token and API_token for user
	k := datastore.NameKey("Users", strings.ToLower(data.Username), nil)
	if _, err := dbclient.Put(ctx, k, data); err != nil {
		log.Println(err)
		return err
	}

	return nil
}
