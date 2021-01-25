package shuffle

import (
	"cloud.google.com/go/datastore"
	"context"
	"log"
)

func getDatastoreClient(ctx context.Context, projectID string) (datastore.Client, error) {
	// FIXME - this doesn't work
	//client, err := datastore.NewClient(ctx, projectID, option.WithCredentialsFile(test"))
	client, err := datastore.NewClient(ctx, projectID)
	//client, err := datastore.NewClient(ctx, projectID, option.WithCredentialsFile("test"))
	if err != nil {
		return datastore.Client{}, err
	}

	return *client, nil
}

func setWorkflowAppDatastore(ctx context.Context, gceProject string, workflowapp WorkflowApp, id string) error {
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
