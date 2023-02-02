package shuffle

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	//"strconv"
	//"encoding/binary"
	"sort"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/Masterminds/semver"
	"github.com/bradfitz/slice"
	"github.com/frikky/go-elasticsearch/v8/esapi"
	uuid "github.com/satori/go.uuid"

	//"github.com/frikky/kin-openapi/openapi3"
	"github.com/patrickmn/go-cache"
	"google.golang.org/api/iterator"

	"cloud.google.com/go/storage"
	gomemcache "github.com/bradfitz/gomemcache/memcache"
	"google.golang.org/appengine/memcache"

	elasticsearch "github.com/frikky/go-elasticsearch/v8"
)

var requestCache *cache.Cache
var memcached = os.Getenv("SHUFFLE_MEMCACHED")
var mc = gomemcache.New(memcached)

var maxCacheSize = 1020000

//var maxCacheSize = 2000000

// Create ElasticSearch/OpenSearch index prefix
// It is used where a single cluster of ElasticSearch/OpenSearch utilized by several
// Shuffle instance
// E.g. Instance1_Workflowapp
func GetESIndexPrefix(index string) string {
	prefix := os.Getenv("SHUFFLE_OPENSEARCH_INDEX_PREFIX")
	if len(prefix) > 0 {
		return fmt.Sprintf("%s_%s", prefix, index)
	}
	return index
}

// Dumps data from cache to DB for every 25 action
var dumpInterval = 0x19

func IncrementCacheDump(ctx context.Context, orgId, dataType string) {

	nameKey := "org_statistics"
	orgStatistics := &ExecutionInfo{}

	if project.Environment != "cloud" {
		log.Printf("[DEBUG] Not cloud. Not dumping cache stats for datatype %s.", dataType)
	} else {
		tx, err := project.Dbclient.NewTransaction(ctx)
		if err != nil {
			log.Printf("[WARNING] Error in cache dump: %s", err)
			return
		}

		key := datastore.NameKey(nameKey, strings.ToLower(orgId), nil)
		if err := tx.Get(key, orgStatistics); err != nil {

			if strings.Contains(fmt.Sprintf("%s", err), "no such entity") {
				log.Printf("[DEBUG] Continuing by creating entity for org %s", orgId)
			} else {
				log.Printf("[ERROR] Failed getting stats in increment: %s", err)
				tx.Rollback()
				return
			}
		}

		// FIXME: Sometimes run this update even when the name is set
		// e.g. 1% of the time to ensure we have the right one
		if orgStatistics.OrgName == "" {
			org, err := GetOrg(ctx, orgId)
			if err == nil {
				orgStatistics.OrgName = org.Name
			}

			orgStatistics.OrgId = orgId
		}

		if dataType == "workflow_executions" {
			orgStatistics.TotalWorkflowExecutions += int64(dumpInterval)
			orgStatistics.MonthlyWorkflowExecutions += int64(dumpInterval)
			orgStatistics.WeeklyWorkflowExecutions += int64(dumpInterval)
			orgStatistics.DailyWorkflowExecutions += int64(dumpInterval)
			orgStatistics.HourlyWorkflowExecutions += int64(dumpInterval)

		} else if dataType == "workflow_executions_finished" {
			orgStatistics.TotalWorkflowExecutionsFinished += int64(dumpInterval)
			orgStatistics.MonthlyWorkflowExecutionsFinished += int64(dumpInterval)
			orgStatistics.WeeklyWorkflowExecutionsFinished += int64(dumpInterval)
			orgStatistics.DailyWorkflowExecutionsFinished += int64(dumpInterval)
			orgStatistics.HourlyWorkflowExecutionsFinished += int64(dumpInterval)

		} else if dataType == "workflow_executions_failed" {
			orgStatistics.TotalWorkflowExecutionsFailed += int64(dumpInterval)
			orgStatistics.MonthlyWorkflowExecutionsFailed += int64(dumpInterval)
			orgStatistics.WeeklyWorkflowExecutionsFailed += int64(dumpInterval)
			orgStatistics.DailyWorkflowExecutionsFailed += int64(dumpInterval)
			orgStatistics.HourlyWorkflowExecutionsFailed += int64(dumpInterval)

		} else if dataType == "app_executions" {
			orgStatistics.TotalAppExecutions += int64(dumpInterval)
			orgStatistics.MonthlyAppExecutions += int64(dumpInterval)
			orgStatistics.WeeklyAppExecutions += int64(dumpInterval)
			orgStatistics.DailyAppExecutions += int64(dumpInterval)
			orgStatistics.HourlyAppExecutions += int64(dumpInterval)

		} else if dataType == "app_executions_failed" {
			orgStatistics.TotalAppExecutionsFailed += int64(dumpInterval)
			orgStatistics.MonthlyAppExecutionsFailed += int64(dumpInterval)
			orgStatistics.WeeklyAppExecutionsFailed += int64(dumpInterval)
			orgStatistics.DailyAppExecutionsFailed += int64(dumpInterval)
			orgStatistics.HourlyAppExecutionsFailed += int64(dumpInterval)

		} else if dataType == "subflow_executions" {
			orgStatistics.TotalSubflowExecutions += int64(dumpInterval)
			orgStatistics.MonthlySubflowExecutions += int64(dumpInterval)
			orgStatistics.WeeklySubflowExecutions += int64(dumpInterval)
			orgStatistics.DailySubflowExecutions += int64(dumpInterval)
			orgStatistics.HourlySubflowExecutions += int64(dumpInterval)

		} else if dataType == "org_sync_actions" {
			orgStatistics.TotalOrgSyncActions += int64(dumpInterval)
			orgStatistics.MonthlyOrgSyncActions += int64(dumpInterval)
			orgStatistics.WeeklyOrgSyncActions += int64(dumpInterval)
			orgStatistics.DailyOrgSyncActions += int64(dumpInterval)
			orgStatistics.HourlyOrgSyncActions += int64(dumpInterval)

		} else if dataType == "workflow_executions_cloud" {
			orgStatistics.TotalCloudExecutions += int64(dumpInterval)
			orgStatistics.MonthlyCloudExecutions += int64(dumpInterval)
			orgStatistics.WeeklyCloudExecutions += int64(dumpInterval)
			orgStatistics.DailyCloudExecutions += int64(dumpInterval)
			orgStatistics.HourlyCloudExecutions += int64(dumpInterval)

		} else if dataType == "workflow_executions_onprem" {
			orgStatistics.TotalOnpremExecutions += int64(dumpInterval)
			orgStatistics.MonthlyOnpremExecutions += int64(dumpInterval)
			orgStatistics.WeeklyOnpremExecutions += int64(dumpInterval)
			orgStatistics.DailyOnpremExecutions += int64(dumpInterval)
			orgStatistics.HourlyOnpremExecutions += int64(dumpInterval)
		}

		if _, err := tx.Put(key, orgStatistics); err != nil {
			log.Printf("[WARNING] Failed setting stats: %s", err)
			tx.Rollback()
			return
		}

		if _, err = tx.Commit(); err != nil {
			log.Printf("[WARNING] Failed commiting stats: %s", err)
		}
	}
}

// Rudementary caching system. WILL go wrong at times without sharding.
// It's only good for the user in cloud, hence wont bother for a while
func IncrementCache(ctx context.Context, orgId, dataType string) {

	// Dump to disk every 0x19
	// 1. Get the existing value
	// 2. Update it
	dbDumpInterval := uint8(dumpInterval)
	key := fmt.Sprintf("cache_%s_%s", orgId, dataType)
	if len(memcached) > 0 {
		item, err := mc.Get(key)
		if err == gomemcache.ErrCacheMiss {
			log.Printf("[DEBUG] Increment memcache miss for %s: %s", key, err)

			item := &gomemcache.Item{
				Key:        key,
				Value:      []byte(string(1)),
				Expiration: 18000,
			}

			if err := mc.Set(item); err != nil {
				log.Printf("[ERROR] Failed setting increment cache for key %s: %s", orgId, err)
			}

		} else if err != nil {
			log.Printf("[ERROR] Failed increment memcache err: %s", err)
		} else {
			if item == nil || item.Value == nil {
				item = &gomemcache.Item{
					Key:        key,
					Value:      []byte(string(1)),
					Expiration: 18000,
				}

				log.Printf("[ERROR] Value in DB is nil for cache %s.", dataType)
			}

			if len(item.Value) == 1 {
				num := item.Value[0]
				//log.Printf("Item: %s", num)

				num += 1
				//log.Printf("Item2: %s", num)
				if num >= dbDumpInterval {
					// Memcache dump first to keep the counter going for other executions
					num = 0

					item := &gomemcache.Item{
						Key:        key,
						Value:      []byte(string(num)),
						Expiration: 18000,
					}
					if err := mc.Set(item); err != nil {
						log.Printf("[ERROR] Failed setting inner memcache for key %s: %s", orgId, err)
					}

					IncrementCacheDump(ctx, orgId, dataType)
				} else {
					//log.Printf("NOT Dumping!")

					item := &gomemcache.Item{
						Key:        key,
						Value:      []byte(string(num)),
						Expiration: 18000,
					}

					if err := mc.Set(item); err != nil {
						log.Printf("[ERROR] Failed setting inner memcache for key %s: %s", orgId, err)
					}
				}
			} else {
				log.Printf("[ERROR] Length of value is longer than 1")
			}
		}

	} else {
		if project.Environment != "cloud" {
			return
		}

		//if item, err := memcache.Get(ctx, key); err == memcache.ErrCacheMiss {
		if item, err := memcache.Get(ctx, key); err == memcache.ErrCacheMiss {
			item := &memcache.Item{
				Key:        key,
				Value:      []byte(string(1)),
				Expiration: time.Minute * 300,
			}

			if err := memcache.Set(ctx, item); err != nil {
				log.Printf("[ERROR] Failed setting cache for key %s: %s", orgId, err)
			}
		} else {
			if item == nil || item.Value == nil {
				item = &memcache.Item{
					Key:        key,
					Value:      []byte(string(1)),
					Expiration: time.Minute * 300,
				}

				log.Printf("[ERROR] Value in DB is nil for cache %s.", dataType)
			}

			if len(item.Value) == 1 {
				num := item.Value[0]
				//log.Printf("Item: %s", num)

				num += 1
				//log.Printf("Item2: %s", num)
				if num >= dbDumpInterval {
					// Memcache dump first to keep the counter going for other executions
					num = 0

					item := &memcache.Item{
						Key:        key,
						Value:      []byte(string(num)),
						Expiration: time.Minute * 300,
					}
					if err := memcache.Set(ctx, item); err != nil {
						log.Printf("[ERROR] Failed setting inner cache for key %s: %s", orgId, err)
					}

					IncrementCacheDump(ctx, orgId, dataType)
				} else {
					//log.Printf("NOT Dumping!")

					item := &memcache.Item{
						Key:        key,
						Value:      []byte(string(num)),
						Expiration: time.Minute * 300,
					}
					if err := memcache.Set(ctx, item); err != nil {
						log.Printf("[ERROR] Failed setting inner cache for key %s: %s", orgId, err)
					}
				}

			} else {
				log.Printf("[ERROR] Length of cache value is more than 1: %s", item.Value)
			}
		}
	}

	/*
		cache, err := GetCache(ctx, key)
		if err != nil {
			SetCache(ctx, key, []byte(string(1)))
		} else {
			//cacheData := string([]byte(cache.([]uint8)))
			cacheData := cache.(int)
			log.Printf("\n\nGot cache value %s\n\n", cacheData)

			//number, err := strconv.Atoi(cacheData)
			//if err != nil {
			//	log.Printf("[ERROR] error in cache setting: %s", err)
			//	return
			//}

			//log.Printf("NUM: %d", number)
			//cacheData += 1

			//if cacheData == dbDumpInterVal {
			//	log.
			//}
		}

		//cache, err := GetCache(ctx, cacheKey)
		//if err == nil {
	*/
}

// Cache handlers
func DeleteCache(ctx context.Context, name string) error {
	if len(memcached) > 0 {
		return mc.Delete(name)
	}

	if project.Environment == "cloud" {
		return memcache.Delete(ctx, name)

	} else if project.Environment == "onprem" {
		requestCache.Delete(name)
		return nil
	} else {
		requestCache.Delete(name)
		return nil
		return errors.New(fmt.Sprintf("No cache handler for environment %s yet WHILE DELETING", project.Environment))
	}

	return errors.New(fmt.Sprintf("No cache found for %s when DELETING cache", name))
}

// Cache handlers
func GetCache(ctx context.Context, name string) (interface{}, error) {
	if len(memcached) > 0 {

		item, err := mc.Get(name)
		if err == gomemcache.ErrCacheMiss {
			//log.Printf("[DEBUG] Cache miss for %s: %s", name, err)
		} else if err != nil {
			log.Printf("[WARNING] Failed cache err: %s", err)
		} else {
			//log.Printf("[INFO] Got new cache: %s", item)

			if len(item.Value) == maxCacheSize {
				totalData := item.Value
				keyCount := 1
				keyname := fmt.Sprintf("%s_%d", name, keyCount)
				for {
					if item, err := mc.Get(keyname); err == gomemcache.ErrCacheMiss {
						break
					} else {
						totalData = append(totalData, item.Value...)

						//log.Printf("%d - %d = ", len(item.Value), maxCacheSize)
						if len(item.Value) != maxCacheSize {
							break
						}
					}

					keyCount += 1
					keyname = fmt.Sprintf("%s_%d", name, keyCount)
				}

				// Random~ high number
				if len(totalData) > 10062147 {
					log.Printf("[WARNING] CACHE: TOTAL SIZE FOR %s: %d", name, len(totalData))
				}
				return totalData, nil
			} else {
				return item.Value, nil
			}
		}

		return "", errors.New(fmt.Sprintf("No cache found in SHUFFLE_MEMCACHED for %s", name))
	}

	if project.Environment == "cloud" {

		if item, err := memcache.Get(ctx, name); err == memcache.ErrCacheMiss {
		} else if err != nil {
			return "", errors.New(fmt.Sprintf("Failed getting CLOUD cache for %s: %s", name, err))
		} else {
			// Loops if cachesize is more than max allowed in memcache (multikey)
			if len(item.Value) == maxCacheSize {
				totalData := item.Value
				keyCount := 1
				keyname := fmt.Sprintf("%s_%d", name, keyCount)
				for {
					if item, err := memcache.Get(ctx, keyname); err == memcache.ErrCacheMiss {
						break
					} else {
						totalData = append(totalData, item.Value...)

						//log.Printf("%d - %d = ", len(item.Value), maxCacheSize)
						if len(item.Value) != maxCacheSize {
							break
						}
					}

					keyCount += 1
					keyname = fmt.Sprintf("%s_%d", name, keyCount)
				}

				// Random~ high number
				if len(totalData) > 10062147 {
					log.Printf("[WARNING] CACHE: TOTAL SIZE FOR %s: %d", name, len(totalData))
				}
				return totalData, nil
			} else {
				return item.Value, nil
			}
		}
	} else if project.Environment == "onprem" {
		//log.Printf("[INFO] GETTING CACHE FOR %s ONPREM", name)
		if value, found := requestCache.Get(name); found {
			return value, nil
		} else {
			return "", errors.New(fmt.Sprintf("Failed getting ONPREM cache for %s", name))
		}
	} else {
		if value, found := requestCache.Get(name); found {
			return value, nil
		} else {
			return "", errors.New(fmt.Sprintf("Failed getting ONPREM cache for %s", name))
		}
		//return "", errors.New(fmt.Sprintf("No cache handler for environment %s yet", project.Environment))
	}

	return "", errors.New(fmt.Sprintf("No cache found for %s", name))
}

// FIXME: Add the option to set cache that expires at longer intervals
func SetCache(ctx context.Context, name string, data []byte) error {
	//log.Printf("DATA SIZE: %d", len(data))
	// Maxsize ish~

	// Splitting into multiple cache items
	//if len(memcached) > 0 {
	if project.Environment == "cloud" || len(memcached) > 0 {
		comparisonNumber := 50
		if len(data) > maxCacheSize*comparisonNumber {
			return errors.New(fmt.Sprintf("Couldn't set cache for %s - too large: %d > %d", name, len(data), maxCacheSize*comparisonNumber))
		}

		loop := false
		if len(data) > maxCacheSize {
			loop = true
			//log.Printf("Should make multiple cache items for %s", name)
		}

		// Custom for larger sizes. Max is maxSize*10 when being set
		if loop {
			currentChunk := 0
			keyAmount := 0
			totalAdded := 0
			chunkSize := maxCacheSize
			nextStep := chunkSize
			keyname := name

			for {
				if len(data) < nextStep {
					nextStep = len(data)
				}

				//log.Printf("%d - %d = ", currentChunk, nextStep)
				parsedData := data[currentChunk:nextStep]
				item := &memcache.Item{
					Key:        keyname,
					Value:      parsedData,
					Expiration: time.Minute * 30,
				}

				var err error
				if len(memcached) > 0 {
					newitem := &gomemcache.Item{
						Key:        keyname,
						Value:      parsedData,
						Expiration: 1800,
					}

					err = mc.Set(newitem)
				} else {
					err = memcache.Set(ctx, item)
				}

				if err != nil {
					if !strings.Contains(fmt.Sprintf("%s", err), "App Engine context") {
						log.Printf("[WARNING] Failed setting cache for %s (1): %s", keyname, err)
					}
					break
				} else {
					totalAdded += chunkSize
					currentChunk = nextStep
					nextStep += chunkSize

					keyAmount += 1
					//log.Printf("%s: %d: %d", keyname, totalAdded, len(data))

					keyname = fmt.Sprintf("%s_%d", name, keyAmount)
					if totalAdded > len(data) {
						break
					}
				}
			}

			//log.Printf("[INFO] Set app cache with length %d and %d keys", len(data), keyAmount)
		} else {
			item := &memcache.Item{
				Key:        name,
				Value:      data,
				Expiration: time.Minute * 30,
			}

			var err error
			if len(memcached) > 0 {
				newitem := &gomemcache.Item{
					Key:        name,
					Value:      data,
					Expiration: 1800,
				}

				err = mc.Set(newitem)
			} else {
				err = memcache.Set(ctx, item)
			}

			if err != nil {
				if !strings.Contains(fmt.Sprintf("%s", err), "App Engine context") {
					log.Printf("[WARNING] Failed setting cache for %s (2): %s", name, err)
				} else {
					log.Printf("[WARNING] Something bad with App Engine context for memcache: %s", err)
				}
			}
		}

		return nil
	} else if project.Environment == "onprem" {
		//log.Printf("SETTING CACHE FOR %s ONPREM", name)
		requestCache.Set(name, data, cache.DefaultExpiration)
	} else {
		//log.Printf("SETTING CACHE FOR %s ONPREM", name)
		requestCache.Set(name, data, cache.DefaultExpiration)
		//return errors.New(fmt.Sprintf("No cache handler for environment %s yet", project.Environment))
	}

	return nil
}

func GetDatastoreClient(ctx context.Context, projectID string) (datastore.Client, error) {
	//client, err := datastore.NewClient(ctx, projectID, option.WithCredentialsFile(test"))
	client, err := datastore.NewClient(ctx, projectID)
	//client, err := datastore.NewClient(ctx, projectID, option.WithCredentialsFile("test"))
	if err != nil {
		return datastore.Client{}, err
	}

	return *client, nil
}

func SetWorkflowAppDatastore(ctx context.Context, workflowapp WorkflowApp, id string) error {
	nameKey := "workflowapp"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	timeNow := int64(time.Now().Unix())
	workflowapp.Edited = timeNow

	if workflowapp.Created == 0 {
		workflowapp.Created = timeNow
	}

	// New struct, to not add body, author etc
	data, err := json.Marshal(workflowapp)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in setapp: %s", err)
		return nil
	}

	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, workflowapp.ID, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if _, err := project.Dbclient.Put(ctx, key, &workflowapp); err != nil {
			if strings.Contains(fmt.Sprintf("%s", err), "entity is too big") || strings.Contains(fmt.Sprintf("%s", err), "is longer than") {
				workflowapp, err = UploadAppSpecFiles(ctx, &project.StorageClient, workflowapp, ParsedOpenApi{})
				if err != nil {
					log.Printf("[WARNING] Failed uploading app spec file in set workflow app: %s", err)
				} else {
					if _, err = project.Dbclient.Put(ctx, key, &workflowapp); err != nil {
						log.Printf("[ERROR] Failed second upload of app %s (%s): %s", workflowapp.Name, workflowapp.ID, err)
					} else {
						log.Printf("[DEBUG] Successfully updated app %s (%s)!", workflowapp.Name, workflowapp.ID)
					}
				}
			} else {
				log.Printf("[WARNING] Error adding workflow app: %s", err)
			}

			if err != nil {
				return err
			}
		}
	}

	if project.CacheDb {
		// Don't want to overwrite this part.
		//data, err := json.Marshal(workflowapp)
		//if err != nil {
		//	log.Printf("[WARNING] Failed marshalling in setapp: %s", err)
		//	return nil
		//}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for setapp: %s", err)
		}

		DeleteCache(ctx, fmt.Sprintf("openapi3_%s", id))
	}

	return nil
}

func SetWorkflowExecution(ctx context.Context, workflowExecution WorkflowExecution, dbSave bool) error {
	//log.Printf("\n\n\nRESULT: %s\n\n\n", workflowExecution.Status)
	nameKey := "workflowexecution"
	if len(workflowExecution.ExecutionId) == 0 {
		log.Printf("[WARNING] Workflowexeciton executionId can't be empty.")
		return errors.New("ExecutionId can't be empty.")
	}

	newexec, err := GetWorkflowExecution(ctx, workflowExecution.ExecutionId)
	if err == nil && (newexec.Status == "FINISHED" || newexec.Status == "ABORTED") {
		log.Printf("[INFO] Already finished! Stopping the rest of the request for execution %s.", workflowExecution.ExecutionId)
		return nil
	}

	// Fixes missing pieces
	workflowExecution = Fixexecution(ctx, workflowExecution)

	cacheKey := fmt.Sprintf("%s_%s", nameKey, workflowExecution.ExecutionId)
	executionData, err := json.Marshal(workflowExecution)
	if err == nil {

		err = SetCache(ctx, cacheKey, executionData)
		if err != nil {
			log.Printf("[WARNING] Failed updating execution cache. Setting DB! %s", err)
			dbSave = true
		} else {
			//log.Printf("\n\n\n[INFO] Set cache for %s with length %d", cacheKey, len(executionData))

		}
	} else {
		log.Printf("[WARNING] Failed marshalling execution for cache: %s", err)
		//log.Printf("[INFO] Set execution cache for workflowexecution %s", cacheKey)
	}

	//requestCache.Set(cacheKey, &workflowExecution, cache.DefaultExpiration)
	if !dbSave && workflowExecution.Status == "EXECUTING" && len(workflowExecution.Results) > 1 {
		//log.Printf("[WARNING] SHOULD skip DB saving for execution")
		return nil
	} else {
		// Deleting cache so that listing can work well
		//DeleteCache(ctx, fmt.Sprintf("%s_%s", nameKey, workflowExecution.WorkflowId))
		DeleteCache(ctx, fmt.Sprintf("%s_%s_50", nameKey, workflowExecution.WorkflowId))
		DeleteCache(ctx, fmt.Sprintf("%s_%s_100", nameKey, workflowExecution.WorkflowId))
	}

	// New struct, to not add body, author etc
	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, workflowExecution.ExecutionId, executionData)
		if err != nil {
			log.Printf("[ERROR] Failed saving new execution %s: %s", workflowExecution.ExecutionId, err)
			return err
		}
	} else {
		workflowExecution, _ := compressExecution(ctx, workflowExecution, "db-connector save")

		log.Printf("[INFO] Saving execution %s with status %s and %d/%d results (not including subflows)", workflowExecution.ExecutionId, workflowExecution.Status, len(workflowExecution.Results), len(workflowExecution.Workflow.Actions))

		key := datastore.NameKey(nameKey, workflowExecution.ExecutionId, nil)
		if _, err := project.Dbclient.Put(ctx, key, &workflowExecution); err != nil {
			log.Printf("[WARNING] Error adding workflow_execution to datastore: %s", err)

			// Has to do with certain data coming back in parameters where it shouldn't, causing saving to be impossible
			if strings.Contains(fmt.Sprintf("%s", err), "contains an invalid nested") {
				//log.Printf("[DEBUG] RETRYING WITHOUT WORKFLOW AND PARAMS?")
				//workflowExecution.Workflow = Workflow{}
				//newParams = []WorkflowAppActionParameters{}
				newResults := []ActionResult{}
				for _, result := range workflowExecution.Results {
					result.Action.Parameters = []WorkflowAppActionParameter{}
					newResults = append(newResults, result)
				}

				workflowExecution.Results = newResults

				key := datastore.NameKey(nameKey, workflowExecution.ExecutionId, nil)
				if _, err := project.Dbclient.Put(ctx, key, &workflowExecution); err != nil {
					log.Printf("[ERROR] Workflow execution Error number 2: %s", err)
				} else {
					return nil
				}
			}
			return err
		}
	}

	return nil
}

// Initializes an execution's extra variables
func SetInitExecutionVariables(ctx context.Context, workflowExecution WorkflowExecution) {
	environments := []string{}
	nextActions := []string{}
	startAction := ""
	extra := 0
	parents := map[string][]string{}
	children := map[string][]string{}

	// Hmm
	triggersHandled := []string{}

	for _, action := range workflowExecution.Workflow.Actions {
		if !ArrayContains(environments, action.Environment) {
			environments = append(environments, action.Environment)
		}

		if action.ID == workflowExecution.Start {
			/*
				functionName = fmt.Sprintf("%s-%s", action.AppName, action.AppVersion)

				if !action.Sharing {
					functionName = fmt.Sprintf("%s-%s", action.AppName, action.PrivateID)
				}
			*/

			startAction = action.ID
		}
	}

	nextActions = append(nextActions, startAction)
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

		continueCount := true
		if extra > 0 {
			continueCount = false
		}

		for _, trigger := range workflowExecution.Workflow.Triggers {
			//log.Printf("Appname trigger (0): %s", trigger.AppName)
			if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
				//log.Printf("%s is a special trigger. Checking where.", trigger.AppName)

				found := false
				for _, check := range triggersHandled {
					if check == trigger.ID {
						found = true
						break
					}
				}

				if !found {
					if continueCount {
						extra += 1
					}
				} else {
					triggersHandled = append(triggersHandled, trigger.ID)
				}

				if trigger.ID == branch.SourceID {
					//log.Printf("[INFO] Trigger %s is the source!", trigger.AppName)
					sourceFound = true
				} else if trigger.ID == branch.DestinationID {
					//log.Printf("[INFO] Trigger %s is the destination!", trigger.AppName)
					destinationFound = true
				}
			}
		}

		if sourceFound {
			parents[branch.DestinationID] = append(parents[branch.DestinationID], branch.SourceID)
		} else {
			//log.Printf("[WARNING] Action ID %s was not found in actions! Skipping parent. (TRIGGER?)", branch.SourceID)
		}

		if destinationFound {
			children[branch.SourceID] = append(children[branch.SourceID], branch.DestinationID)
		} else {
			//log.Printf("[WARNING] Action ID %s was not found in actions! Skipping child. (TRIGGER?)", branch.SourceID)
		}
	}

	/*
		log.Printf("\n\nEnvironments: %s", environments)
		log.Printf("Startnode: %s", startAction)
		log.Printf("Parents: %s", parents)
		log.Printf("NextActions: %s", nextActions)
		log.Printf("Extra: %d", extra)
		log.Printf("Children: %s", children)
	*/

	UpdateExecutionVariables(ctx, workflowExecution.ExecutionId, startAction, children, parents, []string{startAction}, []string{startAction}, nextActions, environments, extra)

}

func UpdateExecutionVariables(ctx context.Context, executionId, startnode string, children, parents map[string][]string, visited, executed, nextActions, environments []string, extra int) error {
	cacheKey := fmt.Sprintf("%s-actions", executionId)
	//log.Printf("\n\nSHOULD UPDATE VARIABLES FOR %s. Next: %s\n\n", executionId, nextActions)

	newVariableWrapper := ExecutionVariableWrapper{
		StartNode:    startnode,
		Children:     children,
		Parents:      parents,
		NextActions:  nextActions,
		Environments: environments,
		Extra:        extra,
		Visited:      visited,
		Executed:     visited,
	}

	variableWrapperData, err := json.Marshal(newVariableWrapper)
	if err != nil {
		log.Printf("[ERROR] Failed marshalling execution: %s", err)
		return err
	}

	err = SetCache(ctx, cacheKey, variableWrapperData)
	if err != nil {
		log.Printf("[ERROR] Failed updating execution variables: %s", err)
		return err
	}

	//log.Printf("[INFO] Successfully set cache for execution variables %s. Extra: %d\n\n", cacheKey, extra)
	return nil
}

func GetExecutionVariables(ctx context.Context, executionId string) (string, int, map[string][]string, map[string][]string, []string, []string, []string, []string) {

	cacheKey := fmt.Sprintf("%s-actions", executionId)
	wrapper := &ExecutionVariableWrapper{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &wrapper)
			if err == nil {
				return wrapper.StartNode, wrapper.Extra, wrapper.Children, wrapper.Parents, wrapper.Visited, wrapper.Executed, wrapper.NextActions, wrapper.Environments
			}
		} else {
			//log.Printf("[ERROR][%s] Failed getting cache for execution variables data %s: %s", executionId, executionId, err)
		}
	} else {
		log.Printf("[ERROR][%s] CacheDB is being skipped - can we handle execution?", executionId)
	}

	return "", 0, map[string][]string{}, map[string][]string{}, []string{}, []string{}, []string{}, []string{}
}

func getExecutionFileValue(ctx context.Context, workflowExecution WorkflowExecution, action ActionResult) (string, error) {
	fullParsedPath := fmt.Sprintf("large_executions/%s/%s_%s", workflowExecution.ExecutionOrg, workflowExecution.ExecutionId, action.Action.ID)

	cacheKey := fmt.Sprintf("%s_%s_action_replace", workflowExecution.ExecutionId, action.Action.ID)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := string(cache.([]uint8))
			return cacheData, nil
		}
	}

	bucket := project.StorageClient.Bucket("shuffler.appspot.com")
	obj := bucket.Object(fullParsedPath)
	fileReader, err := obj.NewReader(ctx)
	if err != nil {
		return "", err
	}

	data, err := ioutil.ReadAll(fileReader)
	if err != nil {
		return "", err
	}

	if project.CacheDb {
		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating execution file value: %s", err)
		}
	}

	return string(data), nil
}

func Fixexecution(ctx context.Context, workflowExecution WorkflowExecution) WorkflowExecution {

	// Make sure to not having missing items in the execution
	for _, action := range workflowExecution.Workflow.Actions {
		found := false

		for _, result := range workflowExecution.Results {
			if result.Action.ID == action.ID {
				found = true
				break
			}
		}

		if found {
			continue
		}

		cacheId := fmt.Sprintf("%s_%s_result", workflowExecution.ExecutionId, action.ID)
		cache, err := GetCache(ctx, cacheId)
		if err != nil {
			//log.Printf("[WARNING] Couldn't find in fix exec %s (2): %s", cacheId, err)
			continue
		}

		actionResult := ActionResult{}
		cacheData := []byte(cache.([]uint8))

		// Just ensuring the data is good
		err = json.Unmarshal(cacheData, &actionResult)
		if err == nil {
			workflowExecution.Results = append(workflowExecution.Results, actionResult)
		} else {
			log.Printf("[ERROR] Failed unmarshalling in fix exec for ID %s (1): %s", cacheId, err)
		}
	}

	// Don't forget any!!
	extra := 0
	for _, trigger := range workflowExecution.Workflow.Triggers {
		if trigger.TriggerType != "SUBFLOW" && trigger.TriggerType != "USERINPUT" {
			continue
		}

		extra += 1

		found := false
		for _, result := range workflowExecution.Results {
			if result.Action.ID == trigger.ID {
				found = true
				break
			}
		}

		if found {
			continue
		}

		cacheId := fmt.Sprintf("%s_%s_result", workflowExecution.ExecutionId, trigger.ID)
		cache, err := GetCache(ctx, cacheId)
		if err != nil {
			//log.Printf("[WARNING] Couldn't find in fix exec %s (2): %s", cacheId, err)
			continue
		}

		actionResult := ActionResult{}
		cacheData := []byte(cache.([]uint8))

		// Just ensuring the data is good
		err = json.Unmarshal(cacheData, &actionResult)
		if err == nil {
			workflowExecution.Results = append(workflowExecution.Results, actionResult)
		} else {
			log.Printf("[ERROR] Failed unmarshalling in fix exec for ID %s (1): %s", cacheId, err)
		}
	}

	// Clean up the results
	handled := []string{}
	newResults := []ActionResult{}
	for _, result := range workflowExecution.Results {
		if ArrayContains(handled, result.Action.ID) {
			continue
		}

		handled = append(handled, result.Action.ID)
		newResults = append(newResults, result)
	}

	workflowExecution.Results = newResults
	if workflowExecution.Status == "FINISHED" || workflowExecution.Status == "ABORTED" {
		return workflowExecution
	}

	if len(workflowExecution.Results) >= len(workflowExecution.Workflow.Actions)+extra {

		log.Printf("\n\n[INFO] Execution %s is complete!\n\n", workflowExecution.ExecutionId)

		workflowExecution.Status = "FINISHED"

		lastResult := ActionResult{}
		highest_finishTime := int64(0)
		for actionIndex, action := range workflowExecution.Workflow.Actions {
			for parameterIndex, param := range action.Parameters {
				if param.Configuration {
					workflowExecution.Workflow.Actions[actionIndex].Parameters[parameterIndex].Value = ""
				}
			}

			// Only show result of last success..?
			if workflowExecution.Results[actionIndex].CompletedAt > highest_finishTime && workflowExecution.Results[actionIndex].Status == "SUCCESS" {
				lastResult = workflowExecution.Results[actionIndex]
			}
		}

		workflowExecution.Result = lastResult.Result
		workflowExecution.CompletedAt = int64(time.Now().Unix())

		nameKey := "workflowexecution"

		// Inject into these?
		DeleteCache(ctx, fmt.Sprintf("%s_%s_50", nameKey, workflowExecution.WorkflowId))
		DeleteCache(ctx, fmt.Sprintf("%s_%s_100", nameKey, workflowExecution.WorkflowId))
	}

	return workflowExecution
}

func GetWorkflowExecution(ctx context.Context, id string) (*WorkflowExecution, error) {
	nameKey := "workflowexecution"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)

	workflowExecution := &WorkflowExecution{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &workflowExecution)
			if err == nil {
				//log.Printf("[DEBUG] Checking individual execution cache with %d results", len(workflowExecution.Results))
				if strings.Contains(workflowExecution.ExecutionArgument, "Result too large to handle") {
					baseArgument := &ActionResult{
						Result: workflowExecution.ExecutionArgument,
						Action: Action{ID: "execution_argument"},
					}

					newValue, err := getExecutionFileValue(ctx, *workflowExecution, *baseArgument)
					if err != nil {
						log.Printf("[DEBUG] Failed to parse in execution file value for exec argument: %s (3)", err)
					} else {
						log.Printf("[DEBUG] Found a new value to parse with exec argument")
						workflowExecution.ExecutionArgument = newValue
					}
				}

				for valueIndex, value := range workflowExecution.Results {
					if strings.Contains(value.Result, "Result too large to handle") {
						//log.Printf("[DEBUG] Found prefix %s to be replaced (1)", value.Result)
						newValue, err := getExecutionFileValue(ctx, *workflowExecution, value)
						if err != nil {
							log.Printf("[DEBUG] Failed to parse in execution file value %s (1)", err)
							continue
						}

						workflowExecution.Results[valueIndex].Result = newValue
					}
				}

				// Fixes missing pieces
				newexec := Fixexecution(ctx, *workflowExecution)
				workflowExecution = &newexec

				//log.Printf("[DEBUG] Returned execution %s", id)
				return workflowExecution, nil
			} else {
				//log.Printf("[WARNING] Failed getting workflowexecution: %s", err)
			}
		} else {
		}
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return workflowExecution, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return workflowExecution, errors.New("User doesn't exist")
		}

		defer res.Body.Close()
		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return workflowExecution, err
		}

		wrapped := ExecWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return workflowExecution, err
		}

		workflowExecution = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		if err := project.Dbclient.Get(ctx, key, workflowExecution); err != nil {
			return &WorkflowExecution{}, err
		}

		// A workaround for large bits of information for execution argument
		if strings.Contains(workflowExecution.ExecutionArgument, "Result too large to handle") {
			log.Printf("[DEBUG] Found prefix %s to be replaced for exec argument (3)", workflowExecution.ExecutionArgument)
			baseArgument := &ActionResult{
				Result: workflowExecution.ExecutionArgument,
				Action: Action{ID: "execution_argument"},
			}
			newValue, err := getExecutionFileValue(ctx, *workflowExecution, *baseArgument)
			if err != nil {
				log.Printf("[DEBUG] Failed to parse in execution file value for exec argument: %s (3)", err)
			} else {
				log.Printf("[DEBUG] Found a new value to parse with exec argument")
				workflowExecution.ExecutionArgument = newValue
			}

		}

		// Parsing as file.
		log.Printf("[DEBUG] Getting execution %s. Results: %d", id, len(workflowExecution.Results))
		for valueIndex, value := range workflowExecution.Results {
			if strings.Contains(value.Result, "Result too large to handle") {
				//log.Printf("[DEBUG] Found prefix %s to be replaced (2)", value.Result)
				newValue, err := getExecutionFileValue(ctx, *workflowExecution, value)
				if err != nil {
					log.Printf("[DEBUG] Failed to parse in execution file value %s (2)", err)
					continue
				}

				workflowExecution.Results[valueIndex].Result = newValue
			}
		}
	}

	// Fixes missing pieces
	newexec := Fixexecution(ctx, *workflowExecution)
	workflowExecution = &newexec

	if project.CacheDb {
		newexecution, err := json.Marshal(workflowExecution)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling execution: %s", err)
			return workflowExecution, nil
		}

		err = SetCache(ctx, id, newexecution)
		if err != nil {
			log.Printf("[WARNING] Failed updating execution: %s", err)
		}
	}

	return workflowExecution, nil
}

func getCloudFileApp(ctx context.Context, workflowApp WorkflowApp, id string) (WorkflowApp, error) {
	//project.BucketName := "shuffler.appspot.com"
	fullParsedPath := fmt.Sprintf("extra_specs/%s/appspec.json", id)
	log.Printf("[DEBUG] Couldn't find working app for app with ID %s. Checking filepath gs://%s/%s (size too big)", id, project.BucketName, fullParsedPath)
	//gs://shuffler.appspot.com/extra_specs/0373ed696a3a2cba0a2b6838068f2b80

	cacheKey := fmt.Sprintf("cloud_file_app_%s", id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &workflowApp)
			if err == nil {
				return workflowApp, nil
			}
		}
	}

	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Printf("[WARNING] Failed to create client (storage - algolia img): %s", err)
		return workflowApp, err
	}

	bucket := client.Bucket(project.BucketName)
	obj := bucket.Object(fullParsedPath)
	fileReader, err := obj.NewReader(ctx)
	if err != nil {
		log.Printf("[ERROR] Failed making App reader for %s: %s", fullParsedPath, err)
		return workflowApp, err
	}

	data, err := ioutil.ReadAll(fileReader)
	if err != nil {
		log.Printf("[WARNING] Failed reading from filereader: %s", err)
		return workflowApp, err
	}

	err = json.Unmarshal(data, &workflowApp)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling from remote store: %s", err)
		return workflowApp, err
	}

	log.Printf("[DEBUG] Got new file data for app with ID %s from filepath gs://%s/%s with %d actions", id, project.BucketName, fullParsedPath, len(workflowApp.Actions))
	if project.CacheDb {
		data, err := json.Marshal(workflowApp)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in get cloud app cache: %s", err)
			return workflowApp, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for get cloud app cache: %s", err)
		}
	}

	defer fileReader.Close()
	return workflowApp, nil
}

func GetApp(ctx context.Context, id string, user User, skipCache bool) (*WorkflowApp, error) {
	nameKey := "workflowapp"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)

	workflowApp := &WorkflowApp{}
	if !skipCache {
		if project.CacheDb {
			cache, err := GetCache(ctx, cacheKey)
			if err == nil {
				cacheData := []byte(cache.([]uint8))
				//log.Printf("CACHEDATA: %s", cacheData)
				err = json.Unmarshal(cacheData, &workflowApp)
				if err == nil {
					if (len(workflowApp.ID) == 0 || len(workflowApp.Actions) == 0) && project.Environment == "cloud" {
						tmpApp, err := getCloudFileApp(ctx, *workflowApp, id)

						if err == nil {
							log.Printf("[DEBUG] Got app %s (%s) with %d actions from file (cache)", workflowApp.Name, workflowApp.ID, len(tmpApp.Actions))
							workflowApp = &tmpApp
							return workflowApp, nil
						} else {
							log.Printf("[DEBUG] Failed remote loading app %s (%s) from file (cache): %s", workflowApp.Name, workflowApp.ID, err)
						}
					}

				}
			} else {
				//log.Printf("[DEBUG] Failed getting cache for org: %s", err)
			}
		}
	} else {
		log.Printf("[DEBUG] Skipping cache check in get app for ID %s", id)
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return workflowApp, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return workflowApp, errors.New("App doesn't exist")
		}

		defer res.Body.Close()
		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return workflowApp, err
		}

		wrapped := AppWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return workflowApp, err
		}

		workflowApp = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		err := project.Dbclient.Get(ctx, key, workflowApp)
		log.Printf("[DEBUG] Actions in %s (%s): %d. Err: %s", workflowApp.Name, strings.ToLower(id), len(workflowApp.Actions), err)
		if err != nil || len(workflowApp.Actions) == 0 {
			log.Printf("[WARNING] Failed getting app in GetApp with name %s and ID %s. Actions: %d. Getting if EITHER is bad or 0. Err: %s", workflowApp.Name, id, len(workflowApp.Actions), err)
			for _, app := range user.PrivateApps {
				if app.ID == id {
					workflowApp = &app
					break
				}
			}

			// Exists in case of "too large" issues.
			if (len(workflowApp.ID) == 0 || len(workflowApp.Actions) == 0) && project.Environment == "cloud" {
				tmpApp, err := getCloudFileApp(ctx, *workflowApp, id)

				if err == nil {
					log.Printf("[DEBUG] Got app %s (%s) with %d actions from file", workflowApp.Name, workflowApp.ID, len(tmpApp.Actions))
					workflowApp = &tmpApp
				} else {
					log.Printf("[DEBUG] Failed remote loading app  %s (%s) from file: %s", workflowApp.Name, workflowApp.ID, err)
				}

			} else {
				log.Printf("[DEBUG] Returning %s (%s) normally", workflowApp.Name, id)
			}
		}
	}

	if workflowApp.ID == "" {
		return &WorkflowApp{}, errors.New(fmt.Sprintf("Couldn't find app %s", id))
	}

	if project.CacheDb {
		data, err := json.Marshal(workflowApp)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getapp: %s", err)
			return workflowApp, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getapp: %s", err)
		}
	}

	return workflowApp, nil
}

func SetSubscriptionRecipient(ctx context.Context, sub SubscriptionRecipient, id string) error {
	nameKey := "gmail_subscription"
	sub.Edited = int(time.Now().Unix())

	// New struct, to not add body, author etc
	data, err := json.Marshal(sub)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in setGmailSub: %s", err)
		return nil
	}
	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, id, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if _, err := project.Dbclient.Put(ctx, key, &sub); err != nil {
			log.Printf("\n\n[WARNING] Error adding gmail sub: %s\n\n", err)
			return err
		}
	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for setworkflow: %s", err)
		}
	}

	return nil
}

func GetSubscriptionRecipient(ctx context.Context, id string) (*SubscriptionRecipient, error) {
	sub := &SubscriptionRecipient{}
	nameKey := "gmail_subscription"

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &sub)
			if err == nil {
				return sub, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for sub: %s", err)
		}
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return sub, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return sub, errors.New("HistoryId doesn't exist")
		}

		defer res.Body.Close()
		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return sub, err
		}

		wrapped := SubWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return sub, err
		}

		sub = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		if err := project.Dbclient.Get(ctx, key, sub); err != nil {
			return &SubscriptionRecipient{}, err
			//if strings.Contains(err.Error(), `cannot load field`) {
			//	log.Printf("[INFO] Error in sub loading. Migrating sub to new sub handler.")
			//	err = nil
			//} else {
			//	return &SubscriptionRecipient{}, err
			//}
		}
	}

	if project.CacheDb {
		//log.Printf("[DEBUG] Setting cache for sub %s", cacheKey)
		data, err := json.Marshal(sub)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getsub: %s", err)
			return sub, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getsub: %s", err)
		}
	}

	return sub, nil
}

func GetEnvironment(ctx context.Context, id, orgId string) (*Environment, error) {
	//log.Printf("\n\n[DEBUG] Getting query %s for orgId %s\n\n", id, orgId)
	env := &Environment{}
	nameKey := "Environments"

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &env)
			if err == nil {
				return env, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for env: %s", err)
		}
	}

	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer

		// FIXME: Don't do name = here, but ID
		// Or search?
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"should": []map[string]interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"Name": id,
							},
						},
						map[string]interface{}{
							"match": map[string]interface{}{
								"id": id,
							},
						},
					},
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return env, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get environment): %s", err)
			return env, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return env, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return env, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return env, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return env, err
		}

		wrapped := EnvironmentSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return env, err
		}

		if len(wrapped.Hits.Hits) == 1 && len(orgId) == 0 {
			env = &wrapped.Hits.Hits[0].Source
		} else {
			//environments = []Environment{}
			for _, hit := range wrapped.Hits.Hits {
				//log.Printf("[DEBUG] Hit: %s", hit)
				//if hit.ID == id {
				//	env = &hit.Source
				//	break
				//}
				if hit.Source.OrgId == orgId {
					env = &hit.Source
					break
				}

				//environments = append(environments, hit.Source)
			}

			//if len(environments) != 1 {
			//	return env, errors.New(fmt.Sprintf("Found %d environments. Want 1 only.", len(environments)))
			//}
		}
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		if err := project.Dbclient.Get(ctx, key, env); err != nil {
			if strings.Contains(err.Error(), `cannot load field`) {
				log.Printf("[INFO] Error in environment loading of %s", id)
				err = nil
			} else {
				return env, err
			}
		}
	}

	//log.Printf("[DEBUG] Got hit: %s", env)

	if project.CacheDb {
		//log.Printf("[DEBUG] Setting cache for workflow %s", cacheKey)
		data, err := json.Marshal(env)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getenv: %s", err)
			return env, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getenv: %s", err)
		}
	}

	return env, nil
}

func GetWorkflow(ctx context.Context, id string) (*Workflow, error) {
	workflow := &Workflow{}
	nameKey := "workflow"

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &workflow)
			if err == nil {
				return workflow, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for workflow: %s", err)
		}
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return workflow, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return workflow, errors.New("Workflow doesn't exist")
		}

		defer res.Body.Close()
		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return workflow, err
		}

		wrapped := WorkflowWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return workflow, err
		}

		workflow = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		if err := project.Dbclient.Get(ctx, key, workflow); err != nil {
			if strings.Contains(err.Error(), `cannot load field`) {
				log.Printf("[ERROR] Error in workflow loading. Migrating workflow to new workflow handler (1): %s", err)
				err = nil
			} else {
				return &Workflow{}, err
			}
		}
	}

	if project.CacheDb {
		//log.Printf("[DEBUG] Setting cache for workflow %s", cacheKey)
		data, err := json.Marshal(workflow)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getworkflow: %s", err)
			return workflow, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getworkflow: %s", err)
		}
	}

	return workflow, nil
}

func GetOrgStatistics(ctx context.Context, orgId string) (*ExecutionInfo, error) {
	nameKey := "org_statistics"

	workflow := &ExecutionInfo{}
	cacheKey := fmt.Sprintf("%s_%s", nameKey, orgId)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &workflow)
			if err == nil {
				return workflow, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for workflow: %s", err)
		}
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		//res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), orgId)
		//if err != nil {
		//	log.Printf("[WARNING] Error: %s", err)
		//	return workflow, err
		//}

		//defer res.Body.Close()
		//if res.StatusCode == 404 {
		//	return workflow, errors.New("Workflow doesn't exist")
		//}

		//defer res.Body.Close()
		//respBody, err := ioutil.ReadAll(res.Body)
		//if err != nil {
		//	return workflow, err
		//}

		//wrapped := WorkflowWrapper{}
		//err = json.Unmarshal(respBody, &wrapped)
		//if err != nil {
		//	return workflow, err
		//}

		//workflow = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(orgId), nil)
		if err := project.Dbclient.Get(ctx, key, workflow); err != nil {
			if strings.Contains(err.Error(), `cannot load field`) {
				log.Printf("[INFO] Error in org loading. Migrating org to new org and user handler (3): %s", err)
				err = nil
			} else {
				return workflow, err
			}
		}
	}

	if project.CacheDb {
		//log.Printf("[DEBUG] Setting cache for workflow %s", cacheKey)
		data, err := json.Marshal(workflow)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getworkflow: %s", err)
			return workflow, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getworkflow: %s", err)
		}
	}

	return workflow, nil
}

func GetAllWorkflowsByQuery(ctx context.Context, user User) ([]Workflow, error) {
	var workflows []Workflow
	limit := 30

	if user.Role == "org-reader" {
		log.Printf("[DEBUG] Giving org-reader %s (%s) access to all workflows in their active org.", user.Username, user.Id)
		user.Role = "admin"
	}

	if user.Role == "user" {
		log.Printf("[DEBUG] Giving org-user %s (%s) access to all workflows in their active org.", user.Username, user.Id)
		user.Role = "admin"
	}

	// Appending the users' workflows
	var err error
	nameKey := "workflow"
	log.Printf("[AUDIT] Getting workflows for user %s (%s - %s)", user.Username, user.Role, user.Id)
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"should": []map[string]interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"owner": user.Id,
							},
						},
						map[string]interface{}{
							"match": map[string]interface{}{
								"owner": "",
							},
						},
					},
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return workflows, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get workflows): %s", err)
			return workflows, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return workflows, nil
		}

		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return workflows, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return workflows, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return workflows, err
		}

		wrapped := WorkflowSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return workflows, err
		}

		//log.Printf("Found workflows: %d", len(wrapped.Hits.Hits))
		for _, hit := range wrapped.Hits.Hits {
			if hit.Source.Owner == user.Id {
				workflows = append(workflows, hit.Source)
			} else {
				//log.Printf("bad workflow owner: %s", hit.Source.Owner)
			}
		}

		if user.Role == "admin" {
			var buf bytes.Buffer
			query = map[string]interface{}{
				"size": 1000,
				"query": map[string]interface{}{
					"match": map[string]interface{}{
						"org_id": user.ActiveOrg.Id,
					},
				},
			}
			if err := json.NewEncoder(&buf).Encode(query); err != nil {
				log.Printf("[WARNING] Error encoding find user query: %s", err)
				return workflows, err
			}

			res, err := project.Es.Search(
				project.Es.Search.WithContext(context.Background()),
				project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
				project.Es.Search.WithBody(&buf),
				project.Es.Search.WithTrackTotalHits(true),
			)
			if err != nil {
				log.Printf("[ERROR] Error getting response from Opensearch (Get workflows 2): %s", err)
				return workflows, err
			}

			defer res.Body.Close()
			if res.StatusCode == 404 {
				return workflows, nil
			}

			defer res.Body.Close()
			if res.IsError() {
				var e map[string]interface{}
				if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
					log.Printf("[WARNING] Error parsing the response body: %s", err)
					return workflows, err
				} else {
					// Print the response status and error information.
					log.Printf("[%s] %s: %s",
						res.Status(),
						e["error"].(map[string]interface{})["type"],
						e["error"].(map[string]interface{})["reason"],
					)
				}
			}

			if res.StatusCode != 200 && res.StatusCode != 201 {
				return workflows, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
			}

			respBody, err := ioutil.ReadAll(res.Body)
			if err != nil {
				return workflows, err
			}

			wrapped := WorkflowSearchWrapper{}
			err = json.Unmarshal(respBody, &wrapped)
			if err != nil {
				return workflows, err
			}

			userWorkflowLen := len(workflows)
			for _, hit := range wrapped.Hits.Hits {
				found := false
				for _, workflow := range workflows {
					if workflow.ID == hit.ID {
						found = true
						break
					}
				}

				if !found {
					workflows = append(workflows, hit.Source)
				}
			}

			log.Printf("[INFO] Appending workflows (ADMIN) for organization %s. Already have %d workflows for the user. Found %d (%d new) for org. New unique amount: %d (1)", user.ActiveOrg.Id, userWorkflowLen, len(wrapped.Hits.Hits), len(workflows)-userWorkflowLen, len(workflows))
		}

	} else {
		query := datastore.NewQuery(nameKey).Filter("owner =", user.Id).Limit(limit)
		cursorStr := ""
		for {
			it := project.Dbclient.Run(ctx, query)

			for {
				innerWorkflow := Workflow{}
				_, err := it.Next(&innerWorkflow)
				if err != nil {
					if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
						log.Printf("[INFO] Fixing workflow %s to have proper org (0.8.74)", innerWorkflow.ID)
						innerWorkflow.Org = []OrgMini{user.ActiveOrg}
						err = SetWorkflow(ctx, innerWorkflow, innerWorkflow.ID)
						if err != nil {
							log.Printf("[WARNING] Failed automatic update of workflow %s", innerWorkflow.ID)
						}
					} else {
						//log.Printf("[WARNING] Workflow iterator issue: %s", err)
						break
					}
				}

				workflows = append(workflows, innerWorkflow)
			}

			if err != iterator.Done {
				//log.Printf("[INFO] Failed fetching results: %v", err)
				//break
			}

			// Get the cursor for the next page of results.
			nextCursor, err := it.Cursor()
			if err != nil {
				log.Printf("Cursorerror: %s", err)
				break
			} else {
				//log.Printf("NEXTCURSOR: %s", nextCursor)
				nextStr := fmt.Sprintf("%s", nextCursor)
				if cursorStr == nextStr {
					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)
				//cursorStr = nextCursor
				//break
			}
		}

		// q *datastore.Query

		if user.Role == "admin" {
			log.Printf("[INFO] Appending workflows (ADMIN) for organization %s (2)", user.ActiveOrg.Id)
			query = datastore.NewQuery(nameKey).Filter("org_id =", user.ActiveOrg.Id).Limit(limit)
			//if project.Environment != "cloud" {
			//	query = query.Order("-edited")
			//}

			cursorStr := ""
			for {
				it := project.Dbclient.Run(ctx, query)

				for {
					innerWorkflow := Workflow{}
					_, err := it.Next(&innerWorkflow)
					if err != nil {
						if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
							log.Printf("[INFO] Fixing workflow %s to have proper org (0.8.74)", innerWorkflow.ID)
							innerWorkflow.Org = []OrgMini{user.ActiveOrg}
							err = SetWorkflow(ctx, innerWorkflow, innerWorkflow.ID)
							if err != nil {
								log.Printf("[WARNING] Failed automatic update of workflow %s", innerWorkflow.ID)
							}
						} else {
							//log.Printf("[WARNING] Workflow iterator issue: %s", err)
							break
						}
					}

					found := false
					for _, loopedWorkflow := range workflows {
						if loopedWorkflow.ID == innerWorkflow.ID {
							found = true
							break
						}
					}

					if !found {
						workflows = append(workflows, innerWorkflow)
					}
				}

				if err != iterator.Done {
					//log.Printf("[INFO] Failed fetching results: %v", err)
					//break
				}

				// Get the cursor for the next page of results.
				nextCursor, err := it.Cursor()
				if err != nil {
					log.Printf("Cursorerror: %s", err)
					break
				} else {
					//log.Printf("NEXTCURSOR: %s", nextCursor)
					nextStr := fmt.Sprintf("%s", nextCursor)
					if cursorStr == nextStr {
						break
					}

					cursorStr = nextStr
					query = query.Start(nextCursor)
					//cursorStr = nextCursor
					//break
				}
			}
		}
	}

	fixedWorkflows := []Workflow{}
	for _, workflow := range workflows {
		if len(workflow.Name) == 0 && len(workflow.Actions) <= 1 {
			continue
		}

		fixedWorkflows = append(fixedWorkflows, workflow)
	}

	slice.Sort(fixedWorkflows[:], func(i, j int) bool {
		return fixedWorkflows[i].Edited > fixedWorkflows[j].Edited
	})

	//log.Printf("Returning %d workflows", len(fixedWorkflows))

	return fixedWorkflows, nil
}

func GetAllHooks(ctx context.Context) ([]Hook, error) {
	var apis []Hook
	q := datastore.NewQuery("hooks")

	_, err := project.Dbclient.GetAll(ctx, q, &apis)
	if err != nil && len(apis) == 0 {
		return []Hook{}, err
	}

	return apis, nil
}

func GetAllOpenApi(ctx context.Context) ([]ParsedOpenApi, error) {
	var apis []ParsedOpenApi
	q := datastore.NewQuery("openapi3")

	_, err := project.Dbclient.GetAll(ctx, q, &apis)
	if err != nil && len(apis) == 0 {
		return []ParsedOpenApi{}, err
	}

	return apis, nil
}

func GetAllWorkflows(ctx context.Context, orgId string) ([]Workflow, error) {
	var allworkflows []Workflow
	q := datastore.NewQuery("workflow").Filter("org_id = ", orgId).Limit(100)
	if orgId == "ALL" {
		q = datastore.NewQuery("workflow")
	}

	_, err := project.Dbclient.GetAll(ctx, q, &allworkflows)
	if err != nil && len(allworkflows) == 0 {
		return []Workflow{}, err
	}

	return allworkflows, nil
}

// ListBooks returns a list of books, ordered by title.
// Handles org grabbing and user / org migrations
func GetOrg(ctx context.Context, id string) (*Org, error) {
	nameKey := "Organizations"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)

	curOrg := &Org{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &curOrg)
			if err == nil {
				return curOrg, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for org: %s", err)
		}
	}

	setOrg := false
	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error in org get: %s", err)
			return &Org{}, err
		}

		defer res.Body.Close()
		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Printf("[WARNING] Failed getting org body: %s", err)
			return &Org{}, err
		}

		if res.StatusCode == 404 {
			log.Printf("[WARNING] Failed getting org - status: %d - %s", 404, string(respBody))
			return &Org{}, errors.New("Org doesn't exist")
		}

		wrapped := OrgWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			log.Printf("[WARNING] Failed unmarshaling org: %s", err)
			return &Org{}, err
		}

		curOrg = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if err := project.Dbclient.Get(ctx, key, curOrg); err != nil {
			log.Printf("[ERROR] Error in org loading for %s: %s", key, err)
			//log.Printf("Users: %s", curOrg.Users)
			if strings.Contains(err.Error(), `cannot load field`) && strings.Contains(err.Error(), `users`) {
				//Self correcting Org handler for user migration. This may come in handy if we change the structure of private apps later too.
				log.Printf("[INFO] Error in org loading. Migrating org to new org and user handler (2): %s", err)
				err = nil

				users := []User{}
				q := datastore.NewQuery("Users").Filter("orgs =", id)
				_, usererr := project.Dbclient.GetAll(ctx, q, &users)

				if usererr != nil {
					log.Printf("[WARNING] Failed finding users for org too: %s", err)
				}
				//	log.Printf("[WARNING] Failed handling users in org fixer: %s", usererr)
				//	for index, user := range users {
				//		users[index].ActiveOrg = OrgMini{
				//			Name: curOrg.Name,
				//			Id:   curOrg.Id,
				//			Role: user.Role,
				//		}

				//		//log.Printf("Should update user %s because there's an error with it", users[index].Id)
				//		SetUser(ctx, &users[index], false)
				//	}
				//}

				if len(users) > 0 {
					curOrg.Users = users
					setOrg = true
				}
			} else if strings.Contains(err.Error(), `cannot load field`) {
				log.Printf("[WARNING] Error in org loading, but returning without warning: %s", err)
				err = nil
			} else {
				return &Org{}, err
			}
		}

		if len(curOrg.Id) == 0 {
			return &Org{}, errors.New(fmt.Sprintf("Couldn't find org with ID %s", curOrg.Id))
		}
	}

	newUsers := []User{}
	for _, user := range curOrg.Users {
		user.Password = ""
		user.Session = ""
		user.ResetReference = ""
		user.PrivateApps = []WorkflowApp{}
		user.VerificationToken = ""
		//user.ApiKey = ""
		user.Executions = ExecutionInfo{}
		newUsers = append(newUsers, user)
	}

	curOrg.Users = newUsers
	if len(curOrg.Tutorials) == 0 {
		curOrg = GetTutorials(*curOrg, true)
	}

	if project.CacheDb {
		neworg, err := json.Marshal(curOrg)
		if err != nil {
			log.Printf("[ERROR] Failed marshalling org for cache: %s", err)
			return curOrg, nil
		}

		err = SetCache(ctx, cacheKey, neworg)
		if err != nil {
			log.Printf("[ERROR] Failed updating org cache: %s", err)
		}

		if setOrg {
			log.Printf("[INFO] UPDATING ORG %s!!", curOrg.Id)
			SetOrg(ctx, *curOrg, curOrg.Id)
		}
	}

	return curOrg, nil
}

func indexEs(ctx context.Context, nameKey, id string, bytes []byte) error {
	req := esapi.IndexRequest{
		Index:      strings.ToLower(GetESIndexPrefix(nameKey)),
		DocumentID: id,
		Body:       strings.NewReader(string(bytes)),
		Refresh:    "true",
		Pretty:     true,
	}

	res, err := req.Do(ctx, &project.Es)
	if err != nil {
		log.Printf("[ERROR] Error getting response from Opensearch (index ES): %s", err)
		return err
	}

	defer res.Body.Close()
	respBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		respBody = []byte("Failed to parse body")
	}

	if res.StatusCode != 200 && res.StatusCode != 201 {
		return errors.New(fmt.Sprintf("Bad statuscode from database: %d. Reason: %s", res.StatusCode, string(respBody)))
	}

	var r map[string]interface{}
	err = json.Unmarshal(respBody, &r)
	if err != nil {
		log.Printf("[WARNING] Error parsing the response body from Opensearch: %s. Raw: %s", err, respBody)
		//return err
	}
	return nil
}

func GetTutorials(org Org, updateOrg bool) *Org {
	log.Printf("[DEBUG] Getting init tutorials for org %s (%s)", org.Name, org.Id)

	allSteps := []Tutorial{
		Tutorial{
			Name:        "Find relevant apps",
			Description: "0 out of 8 apps configured",
			Done:        false,
			Link:        "/welcome?tab=2",
			Active:      true,
		},
		Tutorial{
			Name:        "Discover Usecases",
			Description: "0 workflows created. Create from Workflow Templates! Additional usecases: /usecases",
			Done:        false,
			Link:        "/welcome?tab=3",
			Active:      true,
		},
		Tutorial{
			Name:        "Invite teammates",
			Description: "Configure org name, image, and invite teammates",
			Done:        false,
			Link:        "/admin?tab=users",
			Active:      true,
		},
		Tutorial{
			Name:        "Security & Stability",
			Description: "Configure MFA or SAML/SSO, new Environments & a Notification workflow",
			Done:        false,
			Link:        "/admin?tab=organization",
			Active:      true,
		},
	}

	have := []string{}
	missing := []string{}
	if len(org.SecurityFramework.SIEM.Name) > 0 {
		have = append(have, "SIEM")
	} else {
		missing = append(missing, "SIEM")
	}
	if len(org.SecurityFramework.Communication.Name) > 0 {
		have = append(have, "Communication")
	} else {
		missing = append(missing, "Communication")
	}
	if len(org.SecurityFramework.Assets.Name) > 0 {
		have = append(have, "Assets")
	} else {
		missing = append(missing, "Assets")
	}
	if len(org.SecurityFramework.Cases.Name) > 0 {
		have = append(have, "Cases")
	} else {
		missing = append(missing, "Cases")
	}
	if len(org.SecurityFramework.Network.Name) > 0 {
		have = append(have, "Network")
	} else {
		missing = append(missing, "Network")
	}
	if len(org.SecurityFramework.Intel.Name) > 0 {
		have = append(have, "Intel")
	} else {
		missing = append(missing, "Intel")
	}
	if len(org.SecurityFramework.EDR.Name) > 0 {
		have = append(have, "EDR")
	} else {
		missing = append(missing, "EDR")
	}
	if len(org.SecurityFramework.IAM.Name) > 0 {
		have = append(have, "IAM")
	} else {
		missing = append(missing, "IAM")
	}

	if len(have) > 1 {
		allSteps[0].Done = true
		allSteps[0].Description = fmt.Sprintf("%d out of %d apps configured", len(have), len(have)+len(missing))
	}

	selectedUser := User{}
	ctx := context.Background()
	for _, inputUser := range org.Users {
		user, err := GetUser(ctx, inputUser.Id)
		if user.Role == "admin" && user.ActiveOrg.Id == org.Id {
			if err == nil {
				selectedUser = *user
				break
			}
		}
	}

	if len(org.Users) > 1 {
		allSteps[2].Description = fmt.Sprintf("%d users invited and org name changed.", len(org.Users))
		if strings.ToLower(org.Org) == strings.ToLower(org.Name) {
			allSteps[2].Description = "Edit your org name and invite teammates"
			allSteps[2].Link = "/admin?tab=organization"
		} else {
			allSteps[2].Done = true
		}
	}

	if len(selectedUser.Id) > 0 {
		workflows, _ := GetAllWorkflowsByQuery(ctx, selectedUser)
		if len(workflows) > 1 {
			allSteps[1].Done = true
			allSteps[1].Description = fmt.Sprintf("%d workflows created. Find more workflows in /search", len(workflows))
			allSteps[1].Link = "/search?tab=workflows"
		}
	}

	if org.SSOConfig.SSOEntrypoint != "" && org.Defaults.NotificationWorkflow != "" {
		allSteps[3].Done = true
	} else {
		allSteps[3].Link = "/admin?tab=organization&subtab=configure"
	}

	org.Tutorials = allSteps

	if updateOrg {
		SetOrg(ctx, org, org.Id)
	}
	return &org
}

func SetOrg(ctx context.Context, data Org, id string) error {
	nameKey := "Organizations"
	timeNow := int64(time.Now().Unix())
	if data.Created == 0 {
		data.Created = timeNow
	}

	data.Edited = timeNow
	newUsers := []User{}
	for _, user := range data.Users {
		user.Password = ""
		user.Session = ""
		user.PrivateApps = []WorkflowApp{}
		user.MFA = MFAInfo{}
		user.Authentication = []UserAuth{}

		user.EthInfo = EthInfo{}
		user.PublicProfile = PublicProfile{}
		user.LoginInfo = []LoginInfo{}
		user.PersonalInfo = PersonalInfo{}

		newUsers = append(newUsers, user)
	}

	data.Users = newUsers
	if len(data.Tutorials) == 0 {
		data = *GetTutorials(data, false)
	}

	// clear session_token and API_token for user
	if project.DbType == "elasticsearch" {
		b, err := json.Marshal(data)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling %s - %s: %s", id, nameKey, err)
			return err
		}

		err = indexEs(ctx, nameKey, id, b)
		if err != nil {
			return err
		}
	} else {
		k := datastore.NameKey(nameKey, id, nil)
		if _, err := project.Dbclient.Put(ctx, k, &data); err != nil {
			log.Println(err)
			return err
		}
	}

	if project.CacheDb {
		newUsers := []User{}
		for _, user := range data.Users {
			user.Password = ""
			user.Session = ""
			user.ResetReference = ""
			user.PrivateApps = []WorkflowApp{}
			user.VerificationToken = ""
			user.Executions = ExecutionInfo{}
			newUsers = append(newUsers, user)
		}

		data.Users = newUsers

		neworg, err := json.Marshal(data)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in setorg: %s", err)
			return nil
		}

		cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
		err = SetCache(ctx, cacheKey, neworg)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for org: %s", err)
		}
	}

	return nil
}

func GetSession(ctx context.Context, thissession string) (*Session, error) {
	session := &Session{}
	cache, err := GetCache(ctx, thissession)
	if err == nil {
		cacheData := []byte(cache.([]uint8))
		//log.Printf("CACHEDATA: %s", cacheData)
		err = json.Unmarshal(cacheData, &session)
		if err == nil {
			return session, nil
		}
	} else {
		//log.Printf("[WARNING] Error getting session cache for %s: %v", thissession, err)
	}

	nameKey := "sessions"
	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), thissession)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return session, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return session, errors.New("Session doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return session, err
		}

		wrapped := SessionWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return session, err
		}

		session = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, thissession, nil)
		if err := project.Dbclient.Get(ctx, key, session); err != nil {
			return &Session{}, err
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(thissession)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling session: %s", err)
			return session, nil
		}

		err = SetCache(ctx, thissession, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating session cache: %s", err)
		}
	}

	return session, nil
}

// Index = Username
func DeleteKey(ctx context.Context, entity string, value string) error {
	// Non indexed User data
	DeleteCache(ctx, fmt.Sprintf("%s_%s", entity, value))
	if len(value) == 0 {
		log.Printf("[WARNING] Couldn't delete %s because value (id) must be longer than 0", entity)
		return errors.New("Value to delete must be larger than 0")
	}

	if project.DbType == "elasticsearch" {
		res, err := project.Es.Delete(strings.ToLower(GetESIndexPrefix(entity)), value)

		if err != nil {
			log.Printf("[WARNING] Error in DELETE: %s", err)
			return err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			log.Printf("[WARNING] Couldn't delete %s:%s. Status: %d", entity, value, res.StatusCode)
			return nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body (DELETE): %s", err)
				return err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		//log.Printf("[DEBUG] Deleted %s (%s)", strings.ToLower(entity), value)
	} else {
		key1 := datastore.NameKey(entity, value, nil)
		err := project.Dbclient.Delete(ctx, key1)
		if err != nil {
			log.Printf("[WARNING] Error deleting %s from %s: %s", value, entity, err)
			return err
		}
	}

	return nil
}

// Index = Username
func SetApikey(ctx context.Context, Userdata User) error {

	// Non indexed User data
	newapiUser := new(Userapi)
	newapiUser.ApiKey = Userdata.ApiKey
	newapiUser.Username = strings.ToLower(Userdata.Username)
	nameKey := "apikey"

	// New struct, to not add body, author etc
	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(Userdata)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling user in set apikey: %s", err)
			return err
		}

		err = indexEs(ctx, nameKey, newapiUser.ApiKey, data)
		if err != nil {
			return err
		}
	} else {
		key1 := datastore.NameKey(nameKey, newapiUser.ApiKey, nil)
		if _, err := project.Dbclient.Put(ctx, key1, newapiUser); err != nil {
			log.Printf("Error adding apikey: %s", err)
			return err
		}
	}

	return nil
}

func SetOpenApiDatastore(ctx context.Context, id string, openapi ParsedOpenApi) error {
	nameKey := "openapi3"
	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(openapi)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling user: %s", err)
			return err
		}
		err = indexEs(ctx, nameKey, id, data)
		if err != nil {
			return err
		}
	} else {
		k := datastore.NameKey(nameKey, id, nil)
		if _, err := project.Dbclient.Put(ctx, k, &openapi); err != nil {

			if strings.Contains(fmt.Sprintf("%s", err), "entity is too big") || strings.Contains(fmt.Sprintf("%s", err), "is longer than") {
				_, err = UploadAppSpecFiles(ctx, &project.StorageClient, WorkflowApp{}, openapi)
				if err != nil {
					log.Printf("[WARNING] Failed uploading app spec file in set openapi app: %s", err)
				} else {
					oldBody := openapi.Body
					openapi.Body = ""
					if _, err = project.Dbclient.Put(ctx, k, &openapi); err != nil {
						log.Printf("[ERROR] Failed second upload of openapi app %s: %s", openapi.ID, err)
					} else {
						log.Printf("[DEBUG] Successfully updated openapi app with no body!")

						// Ensuring cache is in order
						openapi.Body = oldBody
					}
				}
			} else {
				//log.Printf("[WARNING] Error adding workflow app: %s", err)
				log.Printf("[WARNING] Failed setting openapi for ID %s in datastore: %s", id, err)
			}
			return err
		}

	}

	if project.CacheDb {
		data, err := json.Marshal(openapi)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling openapi3 in set: %s", err)
			return nil
		}

		cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating openapi cache in set: %s", err)
		}
	}

	return nil
}

func GetOpenApiDatastore(ctx context.Context, id string) (ParsedOpenApi, error) {
	nameKey := "openapi3"
	api := &ParsedOpenApi{}

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &api)
			if err == nil {
				return *api, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for user: %s", err)
		}
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return *api, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return *api, errors.New("OpenAPI spec doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return *api, err
		}

		wrapped := ParsedApiWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return *api, err
		}

		api = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		err := project.Dbclient.Get(ctx, key, api)
		//if (err != nil || len(api.Body) == 0) && !strings.Contains(fmt.Sprintf("%s", err), "no such") {
		if err != nil || len(api.Body) == 0 {
			//project.BucketName := "shuffler.appspot.com"
			fullParsedPath := fmt.Sprintf("extra_specs/%s/openapi.json", id)
			//gs://shuffler.appspot.com/extra_specs/0373ed696a3a2cba0a2b6838068f2b80
			log.Printf("[DEBUG] Couldn't find openapi for %s. Checking filepath gs://%s/%s (size too big). Error: %s", id, project.BucketName, fullParsedPath, err)

			client, err := storage.NewClient(ctx)
			if err != nil {
				log.Printf("[WARNING] Failed to create client (storage - algolia img): %s", err)
				return *api, err
			}

			bucket := client.Bucket(project.BucketName)
			obj := bucket.Object(fullParsedPath)
			fileReader, err := obj.NewReader(ctx)
			if err != nil {
				log.Printf("[ERROR] Failed making OpenAPI reader for %s: %s", fullParsedPath, err)
				return *api, err
			}

			data, err := ioutil.ReadAll(fileReader)
			if err != nil {
				log.Printf("[WARNING] Failed reading from filereader: %s", err)
				return *api, err
			}

			err = json.Unmarshal(data, &api)
			if err != nil {
				log.Printf("[WARNING] Failed unmarshaling from remote store: %s", err)
				return *api, err
			}

			defer fileReader.Close()
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(api)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling openapi: %s", err)
			return *api, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating openapi cache: %s", err)
		}
	}

	return *api, nil
}

// Index = Username
func SetSession(ctx context.Context, user User, value string) error {
	//parsedKey := strings.ToLower(user.Username)
	//if project.Environment != "cloud" {
	//}
	// Non indexed User data
	parsedKey := user.Id
	user.Session = value

	nameKey := "Users"
	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(user)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling user: %s", err)
			return err
		}

		//log.Printf("SESSION RES: %s", res)
		err = indexEs(ctx, nameKey, parsedKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating user with session: %s", err)
			return err
		}
	} else {
		key1 := datastore.NameKey(nameKey, parsedKey, nil)
		if _, err := project.Dbclient.Put(ctx, key1, &user); err != nil {
			log.Printf("[WARNING] Error adding Usersession: %s", err)
			return err
		}
	}

	if len(user.Session) > 0 {
		// Indexed session data
		sessiondata := new(Session)
		sessiondata.UserId = strings.ToLower(user.Id)
		sessiondata.Username = strings.ToLower(user.Username)
		sessiondata.Session = user.Session
		sessiondata.Id = user.Id
		nameKey = "sessions"

		if project.DbType == "elasticsearch" {
			data, err := json.Marshal(sessiondata)
			if err != nil {
				log.Printf("[WARNING] Failed marshalling session %s", err)
				return err
			}

			err = indexEs(ctx, nameKey, sessiondata.Session, data)
			if err != nil {
				return err
			}
		} else {
			key2 := datastore.NameKey(nameKey, sessiondata.Session, nil)
			if _, err := project.Dbclient.Put(ctx, key2, sessiondata); err != nil {
				log.Printf("Error adding session: %s", err)
				return err
			}
		}
	}

	return nil
}

func FindWorkflowAppByName(ctx context.Context, appName string) ([]WorkflowApp, error) {
	var apps []WorkflowApp

	nameKey := "workflowapp"
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"name": appName,
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find app query: %s", err)
			return apps, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (find app by name): %s", err)
			return apps, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return apps, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return apps, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return apps, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return apps, err
		}

		wrapped := AppSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return apps, err
		}

		apps = []WorkflowApp{}
		for _, hit := range wrapped.Hits.Hits {
			apps = append(apps, hit.Source)
		}
	} else {
		log.Printf("Looking for name %s in %s", appName, nameKey)
		q := datastore.NewQuery(nameKey).Filter("name =", appName)
		_, err := project.Dbclient.GetAll(ctx, q, &apps)
		if err != nil && len(apps) == 0 {
			log.Printf("[WARNING] Failed getting apps for name: %s", appName)
			return apps, err
		}
	}

	log.Printf("[INFO] Found %d apps for name %s in db-connector", len(apps), appName)
	return apps, nil
}

func FindGeneratedUser(ctx context.Context, username string) ([]User, error) {
	var users []User

	nameKey := "Users"
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"generated_username": username,
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return []User{}, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (find user): %s", err)
			return []User{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return []User{}, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return []User{}, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return []User{}, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return []User{}, err
		}

		wrapped := UserSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return []User{}, err
		}

		users = []User{}
		for _, hit := range wrapped.Hits.Hits {
			users = append(users, hit.Source)
		}
	} else {
		q := datastore.NewQuery(nameKey).Filter("Username =", username)
		_, err := project.Dbclient.GetAll(ctx, q, &users)
		if err != nil && len(users) == 0 {
			log.Printf("[WARNING] Failed getting users for username: %s", username)
			return users, err
		}
	}

	newUsers := []User{}
	parsedUsername := strings.ToLower(strings.TrimSpace(username))
	for _, user := range users {
		if strings.ToLower(strings.TrimSpace(user.GeneratedUsername)) != parsedUsername {
			continue
		}

		newUsers = append(newUsers, user)
	}

	log.Printf("[INFO] Found %d (%d) user(s) for username %s in db-connector", len(newUsers), len(users), username)
	return newUsers, nil
}

func FindUser(ctx context.Context, username string) ([]User, error) {
	var users []User

	nameKey := "Users"
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"username": username,
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return []User{}, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (find user): %s", err)
			return []User{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return []User{}, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return []User{}, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return []User{}, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return []User{}, err
		}

		wrapped := UserSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return []User{}, err
		}

		users = []User{}
		for _, hit := range wrapped.Hits.Hits {
			users = append(users, hit.Source)
		}
	} else {
		q := datastore.NewQuery(nameKey).Filter("Username =", username)
		_, err := project.Dbclient.GetAll(ctx, q, &users)
		if err != nil && len(users) == 0 {
			log.Printf("[WARNING] Failed getting users for username: %s", username)
			return users, err
		}
	}

	newUsers := []User{}
	parsedUsername := strings.ToLower(strings.TrimSpace(username))
	for _, user := range users {
		if strings.ToLower(strings.TrimSpace(user.Username)) != parsedUsername {
			continue
		}

		newUsers = append(newUsers, user)
	}

	log.Printf("[INFO] Found %d (%d) user(s) for username %s in db-connector", len(newUsers), len(users), username)
	return newUsers, nil
}

// ListBooks returns a list of books, ordered by title.
func GetUser(ctx context.Context, username string) (*User, error) {
	curUser := &User{}

	parsedKey := strings.ToLower(username)
	cacheKey := fmt.Sprintf("user_%s", parsedKey)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &curUser)
			if err == nil {
				return curUser, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for user: %s", err)
		}
	}

	nameKey := "Users"
	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), parsedKey)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return curUser, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return curUser, errors.New("User doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return curUser, err
		}

		wrapped := UserWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return curUser, err
		}

		curUser = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, parsedKey, nil)
		if err := project.Dbclient.Get(ctx, key, curUser); err != nil {
			// Handles migration of the user
			if strings.Contains(err.Error(), `cannot load field`) {
				log.Printf("[DEBUG] Failed loading user %s (this is ok): %s", username, err)
			} else {
				log.Printf("[WARNING] Failed loading user %s - does it have to change? %s", username, err)
				return &User{}, err
			}
			//	curUser.ActiveOrg = OrgMini{
			//		Name: curUser.ActiveOrg.Name,
			//		Id:   curUser.ActiveOrg.Id,
			//		Role: "user",
			//	}

			//	// Updating the user and their org
			//	SetUser(ctx, curUser, false)
			//} else {
			//	log.Printf("[WARNING] Error in Get User: %s", err)
			//	return &User{}, err
			//}
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(curUser)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling user: %s", err)
			return curUser, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating cache: %s", err)
		}
	}

	return curUser, nil
}

func SetUser(ctx context.Context, user *User, updateOrg bool) error {
	log.Printf("[INFO] Updating a user (%s) that has the role %s with %d apps and %d orgs. Org updater: %s", user.Username, user.Role, len(user.PrivateApps), len(user.Orgs), updateOrg)
	parsedKey := user.Id
	if updateOrg {
		user = fixUserOrg(ctx, user)
	}

	nameKey := "Users"
	data, err := json.Marshal(user)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling user: %s", err)
		return nil
	}

	log.Printf("[INFO] Updating user %s (%s) with data length %d", user.Username, user.Id, len(data))
	if len(data) > 1000000 {
		user.PrivateApps = []WorkflowApp{}

		data, err = json.Marshal(user)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling user (2): %s", err)
			return nil
		}
	}

	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, parsedKey, data)
		if err != nil {
			return err
		}
	} else {
		k := datastore.NameKey(nameKey, parsedKey, nil)
		if _, err := project.Dbclient.Put(ctx, k, user); err != nil {
			log.Printf("[WARNING] Error updating user: %s", err)
			return err
		}
	}

	DeleteCache(ctx, user.ApiKey)
	DeleteCache(ctx, user.Session)
	DeleteCache(ctx, fmt.Sprintf("session_%s", user.Session))

	if project.CacheDb {
		cacheKey := fmt.Sprintf("user_%s", parsedKey)

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating user cache (ID): %s", err)
		}

		cacheKey = fmt.Sprintf("user_%s", strings.ToLower(user.Username))
		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating user cache (username): %s", err)
		}
	}

	return nil
}

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

func fixUserOrg(ctx context.Context, user *User) *User {
	found := false
	for _, id := range user.Orgs {
		if user.ActiveOrg.Id == id {
			found = true
			break
		}
	}

	if !found {
		user.Orgs = append(user.Orgs, user.ActiveOrg.Id)
	}

	innerUser := *user
	innerUser.PrivateApps = []WorkflowApp{}
	innerUser.Executions = ExecutionInfo{}
	innerUser.Limits = UserLimits{}
	innerUser.Authentication = []UserAuth{}
	innerUser.Password = ""
	innerUser.Session = ""

	// Might be vulnerable to timing attacks.
	for _, orgId := range user.Orgs {
		if len(orgId) == 0 {
			continue
		}

		org, err := GetOrg(ctx, orgId)
		if err != nil {
			log.Printf("[WARNING] Error getting org %s in fixUserOrg: %s", orgId, err)
			continue
		}

		orgIndex := 0
		userFound := false
		for index, orgUser := range org.Users {
			if orgUser.Id == user.Id {
				orgIndex = index
				userFound = true
				break
			}
		}

		if userFound {
			org.Users[orgIndex] = innerUser
		} else {
			org.Users = append(org.Users, innerUser)
		}

		err = SetOrg(ctx, *org, orgId)
		if err != nil {
			log.Printf("[WARNING] Failed setting org %s (2)", orgId)
		}
	}

	return user
}

func GetAllWorkflowAppAuth(ctx context.Context, orgId string) ([]AppAuthenticationStorage, error) {
	var allworkflowappAuths []AppAuthenticationStorage
	nameKey := "workflowappauth"

	cacheKey := fmt.Sprintf("%s_%s", nameKey, orgId)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &allworkflowappAuths)
			if err == nil {
				return allworkflowappAuths, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for app auth: %s", err)
		}
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"org_id": orgId,
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return allworkflowappAuths, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get app auth): %s", err)
			return allworkflowappAuths, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return allworkflowappAuths, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return allworkflowappAuths, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return allworkflowappAuths, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return allworkflowappAuths, err
		}

		wrapped := AppAuthSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return allworkflowappAuths, err
		}

		allworkflowappAuths = []AppAuthenticationStorage{}
		for _, hit := range wrapped.Hits.Hits {
			allworkflowappAuths = append(allworkflowappAuths, hit.Source)
		}
	} else {
		q := datastore.NewQuery(nameKey).Filter("org_id = ", orgId)
		if orgId == "ALL" && project.Environment != "cloud" {
			q = datastore.NewQuery(nameKey)
		}

		_, err := project.Dbclient.GetAll(ctx, q, &allworkflowappAuths)
		if err != nil && len(allworkflowappAuths) == 0 {
			return allworkflowappAuths, err
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(allworkflowappAuths)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling get app auth: %s", err)
			return allworkflowappAuths, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating get app auth cache: %s", err)
		}

		log.Printf("[DEBUG] Set cache for app auth %s with length %d", cacheKey, len(allworkflowappAuths))
	}

	//for _, env := range allworkflowappAuths {
	//	for _, param := range env.Fields {
	//		log.Printf("ENV: %s", param)
	//	}
	//}

	return allworkflowappAuths, nil
}

func GetEnvironments(ctx context.Context, orgId string) ([]Environment, error) {
	//log.Printf("[DEBUG] Getting environments for orgId %s", orgId)
	nameKey := "Environments"

	cacheKey := fmt.Sprintf("%s_%s", nameKey, orgId)
	environments := []Environment{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &environments)
			if err == nil {
				return environments, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache in GET environments: %s", err)
		}
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"org_id": orgId,
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return environments, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get environments): %s", err)
			return environments, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			item := Environment{
				Name:    "Shuffle",
				Type:    "onprem",
				OrgId:   orgId,
				Default: true,
				Id:      uuid.NewV4().String(),
			}

			err = SetEnvironment(ctx, &item)
			if err != nil {
				log.Printf("[WARNING] Failed setting up new environment")
			} else {
				environments = append(environments, item)
			}

			return environments, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return environments, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return environments, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return environments, err
		}

		wrapped := EnvironmentSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return environments, err
		}

		environments = []Environment{}
		for _, hit := range wrapped.Hits.Hits {
			environments = append(environments, hit.Source)
		}
	} else {
		//log.Printf("\n\nQuerying ALL for org %s\n\n", orgId)
		q := datastore.NewQuery(nameKey).Filter("org_id =", orgId).Limit(10)
		//q := datastore.NewQuery(nameKey).Filter("org_id =", orgId).Filter("archived =", false).Limit(10)
		_, err := project.Dbclient.GetAll(ctx, q, &environments)
		if err != nil && len(environments) == 0 {
			return []Environment{}, err
		}

		//log.Printf("Got %d environments for org: %s", len(environments), environments)
	}

	if len(environments) == 0 {
		item := Environment{
			Name:    "Shuffle",
			Type:    "onprem",
			OrgId:   orgId,
			Default: true,
			Id:      uuid.NewV4().String(),
		}

		if project.Environment == "cloud" {
			item.Name = "Cloud"
			item.Type = "cloud"
		}

		err := SetEnvironment(ctx, &item)
		if err != nil {
			log.Printf("[WARNING] Failed setting up new environment")
		} else {
			environments = append(environments, item)
		}
	}

	// Fixing environment return search problems
	for envIndex, env := range environments {
		if env.Name == "Cloud" {
			environments[envIndex].Type = "cloud"
		} else if env.Name == "Shuffle" {
			environments[envIndex].Type = "onprem"
		}
	}

	//log.Printf("\n\n[DEBUG2] Getting environments2 for orgId %s\n\n", orgId)

	if project.CacheDb {
		data, err := json.Marshal(environments)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling environment cache: %s", err)
			return environments, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating environment cache: %s", err)
		}

		log.Printf("[DEBUG] Set cache for environment %s", cacheKey)
	}

	return environments, nil
}

// Gets apps based on a new schema instead of looping everything
// Primarily made for cloud. Load in this order:
// 1. Get ORGs' private apps
// 2. Get USERs' private apps
// 3. Get PUBLIC apps
func GetPrioritizedApps(ctx context.Context, user User) ([]WorkflowApp, error) {
	if project.Environment != "cloud" {
		return GetAllWorkflowApps(ctx, 1000, 0)
	}

	log.Printf("[AUDIT] Getting apps for user %s with active org %s", user.Username, user.ActiveOrg.Id)
	allApps := []WorkflowApp{}
	//log.Printf("[INFO] LOOPING REAL APPS: %d. Private: %d", len(user.PrivateApps))

	// 1. Caching apps locally
	cacheKey := fmt.Sprintf("apps_%s", user.Id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &allApps)
			if err == nil {
				return allApps, nil
			} else {
				log.Println(string(cacheData))
				log.Printf("[ERROR] Failed unmarshaling apps: %s", err)
				//log.Printf("[ERROR] DATALEN: %d", len(cacheData))
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for apps with KEY %s: %s", cacheKey, err)
		}
	}

	maxLen := 200
	queryLimit := 50
	cursorStr := ""

	allApps = user.PrivateApps
	org, orgErr := GetOrg(ctx, user.ActiveOrg.Id)
	if len(user.PrivateApps) > 0 && orgErr == nil {
		//log.Printf("[INFO] Migrating %d apps for user %s to org %s if they don't exist", len(user.PrivateApps), user.Username, user.ActiveOrg.Id)
		orgChanged := false
		for _, app := range user.PrivateApps {
			if !ArrayContains(org.ActiveApps, app.ID) {
				orgChanged = true
				org.ActiveApps = append(org.ActiveApps, app.ID)
			}
		}

		if orgChanged {
			err := SetOrg(ctx, *org, org.Id)
			if err != nil {
				log.Printf("[WARNING] Failed setting org %s with %d apps: %s", org.Id, len(org.ActiveApps), err)

				if len(org.Users) > 10 {
					newUsers := []User{}
					for _, user := range org.Users {
						if len(user.Id) == 0 {
							continue
						}

						newUsers = append(newUsers, user)
					}

					if len(newUsers) > 0 {
						org.Users = newUsers

						err := SetOrg(ctx, *org, org.Id)
						if err != nil {
							log.Printf("[WARNING] (2) Failed setting org %s with %d apps after cleanup: %s", org.Id, len(org.ActiveApps), err)
						}
					}
				}
			}
		}
	}

	nameKey := "workflowapp"

	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Printf("[WARNING] Failed to create client (storage - prioritizedapps): %s", err)
	}

	query := datastore.NewQuery(nameKey).Filter("reference_org =", user.ActiveOrg.Id).Limit(queryLimit)
	for {
		it := project.Dbclient.Run(ctx, query)

		for {
			innerApp := WorkflowApp{}
			_, err := it.Next(&innerApp)
			if err != nil {
				if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
					//log.Printf("[WARNING] Error in reference_org load: %s.", err)
					continue
				}

				//log.Printf("[WARNING] No more apps for %s in org app load? Breaking: %s.", user.Username, err)
				break
			}

			if orgErr == nil && !ArrayContains(org.ActiveApps, innerApp.ID) {
				continue
			}

			if len(innerApp.Actions) == 0 {
				//log.Printf("[INFO] App %s (%s) doesn't have actions - check filepath", innerApp.Name, innerApp.ID)

				//project.BucketName := "shuffler.appspot.com"
				fullParsedPath := fmt.Sprintf("extra_specs/%s/appspec.json", innerApp.ID)
				//gs://shuffler.appspot.com/extra_specs/0373ed696a3a2cba0a2b6838068f2b80
				//log.Printf("[WARNING] Couldn't find  for %s. Should check filepath gs://%s/%s (size too big)", innerApp.ID, project.BucketName, fullParsedPath)

				bucket := client.Bucket(project.BucketName)
				obj := bucket.Object(fullParsedPath)
				fileReader, err := obj.NewReader(ctx)
				if err == nil {

					data, err := ioutil.ReadAll(fileReader)
					if err == nil {
						err = json.Unmarshal(data, &innerApp)
						if err != nil {
							log.Printf("[WARNING] Failed unmarshaling from remote store: %s", err)
							continue
						}
					}
				}

				//log.Printf("%s\n%s - %s\n%d\n", string(data), innerApp.Name, innerApp.ID, len(innerApp.Actions))
			}

			allApps, innerApp = fixAppAppend(allApps, innerApp)
		}

		if err != iterator.Done {
			//log.Printf("[INFO] Failed fetching results: %v", err)
			//break
		}

		// Get the cursor for the next page of results.
		nextCursor, err := it.Cursor()
		if err != nil {
			log.Printf("Cursorerror: %s", err)
			break
		} else {
			//log.Printf("NEXTCURSOR: %s", nextCursor)
			nextStr := fmt.Sprintf("%s", nextCursor)
			if cursorStr == nextStr {
				break
			}

			cursorStr = nextStr
			query = query.Start(nextCursor)
			//cursorStr = nextCursor
			//break
		}

		if len(allApps) > maxLen {
			break
		}
	}

	// Find public apps
	publicApps := []WorkflowApp{}
	publicAppsKey := fmt.Sprintf("public_apps")
	if project.CacheDb {
		cache, err := GetCache(ctx, publicAppsKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &publicApps)
			if err != nil {
				log.Printf("[WARNING] Failed unmarshaling PUBLIC apps: %s", err)
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for PUBLIC apps: %s", err)
		}
	}

	if len(publicApps) == 0 {
		query = datastore.NewQuery(nameKey).Filter("public =", true).Limit(queryLimit)
		for {
			it := project.Dbclient.Run(ctx, query)

			for {
				innerApp := WorkflowApp{}
				_, err := it.Next(&innerApp)
				if err != nil {
					if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
						//log.Printf("[WARNING] Error in public app load: %s", err)
						//continue
					} else {

						//log.Printf("[WARNING] No more apps (public) - Breaking: %s.", err)
						break
					}
				}

				if len(innerApp.Actions) == 0 {
					log.Printf("App %s (%s) doesn't have actions - check filepath", innerApp.Name, innerApp.ID)

					//project.BucketName := "shuffler.appspot.com"
					fullParsedPath := fmt.Sprintf("extra_specs/%s/appspec.json", innerApp.ID)
					//gs://shuffler.appspot.com/extra_specs/0373ed696a3a2cba0a2b6838068f2b80
					//log.Printf("[WARNING] Couldn't find  for %s. Should check filepath gs://%s/%s (size too big)", innerApp.ID, project.BucketName, fullParsedPath)

					bucket := client.Bucket(project.BucketName)
					obj := bucket.Object(fullParsedPath)
					fileReader, err := obj.NewReader(ctx)
					if err == nil {

						data, err := ioutil.ReadAll(fileReader)
						if err == nil {
							err = json.Unmarshal(data, &innerApp)
							if err != nil {
								log.Printf("[WARNING] Failed unmarshaling from remote store: %s", err)
								continue
							}
						}
					}

					//log.Printf("%s\n%s - %s\n%d\n", string(data), innerApp.Name, innerApp.ID, len(innerApp.Actions))
				}

				allApps, innerApp = fixAppAppend(allApps, innerApp)

			}

			if err != iterator.Done {
				//log.Printf("[INFO] Failed fetching results: %v", err)
				//break
			}

			// Get the cursor for the next page of results.
			nextCursor, err := it.Cursor()
			if err != nil {
				log.Printf("Cursorerror: %s", err)
				break
			} else {
				//log.Printf("NEXTCURSOR: %s", nextCursor)
				nextStr := fmt.Sprintf("%s", nextCursor)
				if cursorStr == nextStr {
					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)
				//cursorStr = nextCursor
				//break
			}

			if len(allApps) > maxLen {
				break
			}
		}

		newbody, err := json.Marshal(publicApps)
		if err != nil {
			return allApps, nil
		}

		err = SetCache(ctx, publicAppsKey, newbody)
		if err != nil {
			log.Printf("[INFO] Error setting app cache item for %s: %v", publicAppsKey, err)
		} else {
			log.Printf("[INFO] Set app cache for %s", publicAppsKey)
		}
	}

	//allApps = append(allApps, publicApps...)
	//log.Printf("Active apps: %d", len(org.ActiveApps))
	appsAdded := []string{}
	if orgErr == nil {
		for _, publicApp := range publicApps {
			if ArrayContains(org.ActiveApps, publicApp.ID) {
				appsAdded = append(appsAdded, publicApp.ID)
				allApps = append(allApps, publicApp)
			}
		}
	}

	// PS: If you think there's an error here, it's probably in the Algolia upload of CloudSpecific
	// Instead loading in all public apps which is shared between all orgs
	// This should make the request fast for everyone except that one
	// person who loads it first (or keeps it in cache?)
	if orgErr == nil && len(org.ActiveApps) > 0 {
		//log.Printf("[INFO] Should append ORG APPS: %s", org.ActiveApps)

		allKeys := []*datastore.Key{}
		for _, appId := range org.ActiveApps {
			if ArrayContains(appsAdded, appId) {
				continue
			}

			found := false
			for _, app := range allApps {
				if app.ID == appId {
					found = true
					break
				}
			}

			if !found && len(appId) > 0 {
				allKeys = append(allKeys, datastore.NameKey(nameKey, appId, nil))
			}
		}

		var newApps = make([]WorkflowApp, len(allKeys))
		err = project.Dbclient.GetMulti(ctx, allKeys, newApps)
		if err != nil {
			log.Printf("[ERROR] Failed getting org apps: %s. Apps: %d. NOT FATAL", err, len(newApps))
		}

		log.Printf("[DEBUG] Got %d apps from dbclient multi", len(newApps))

		// IF the app doesn't have actions, check OpenAPI
		// 1. Get the app directly
		// 2. Parse OpenAPI for it to get the actions
		for appIndex, app := range newApps {
			if len(app.Actions) == 0 && len(app.Name) > 0 {
				log.Printf("[WARNING] %s has %d actions (%s). Getting directly.", app.Name, len(app.Actions), app.ID)

				newApp, err := GetApp(ctx, app.ID, user, true)
				if err != nil {
					log.Printf("[WARNING] Failed to find app while parsing app %s: %s", app.Name, err)
					continue
				} else {
					log.Printf("[DEBUG] Found action %s (%s) directly with %d actions", app.Name, app.ID, len(newApp.Actions))
					newApps[appIndex] = *newApp
				}

			}
		}

		allApps = append(allApps, newApps...)
	}

	if len(allApps) > 0 {
		// Finds references
		allApps = findReferenceAppDocs(ctx, allApps)

		newbody, err := json.Marshal(allApps)
		if err != nil {
			return allApps, nil
		}

		err = SetCache(ctx, cacheKey, newbody)
		if err != nil {
			log.Printf("[INFO] Error setting app cache item for %s: %v", cacheKey, err)
		} else {
			log.Printf("[INFO] Set app cache for %s", cacheKey)
		}
	}

	return allApps, nil
}

func fixAppAppend(allApps []WorkflowApp, innerApp WorkflowApp) ([]WorkflowApp, WorkflowApp) {
	newIndex := -1
	newApp := WorkflowApp{}
	found := false

	for appIndex, loopedApp := range allApps {
		if strings.ToLower(loopedApp.Name) == "shuffle tools" {
			//log.Printf("%s vs %s - %s vs %s", loopedApp.Name, innerApp.Name, loopedApp.AppVersion, innerApp.AppVersion)
		}
		if loopedApp.Name == innerApp.Name {

			if ArrayContains(loopedApp.LoopVersions, innerApp.AppVersion) || loopedApp.AppVersion == innerApp.AppVersion {

				// If the new is active, and the old one is NOT - replace it.
				// FIXME: May be a problem here with semantic versioning
				// As of 0.8 this is not a concern, hence is ignored.
				if innerApp.Activated && !loopedApp.Activated {
					newIndex = appIndex
					newApp = innerApp

					//newApp.Versions = append(newApp.Versions, AppVersion{
					//	Version: innerApp.AppVersion,
					//	ID:      innerApp.ID,
					//})
					//newApp.LoopVersions = append(newApp.LoopVersions, innerApp.AppVersion)

					//newApp.Versions = loopedApp.Versions
					//newApp.LoopVersions = loopedApp.Versions
					found = false
				} else {
					found = true
				}
			} else {
				//log.Printf("\n\nFound NEW version %s of app %s on index %d\n\n", innerApp.AppVersion, innerApp.Name, appIndex)

				v2, err := semver.NewVersion(innerApp.AppVersion)
				if err != nil {
					log.Printf("[ERROR] Failed parsing original app version %s: %s", innerApp.AppVersion, err)
					continue
				}

				appConstraint := fmt.Sprintf("> %s", loopedApp.AppVersion)
				c, err := semver.NewConstraint(appConstraint)
				if err != nil {
					log.Printf("[ERROR] Failed preparing constraint %s: %s", appConstraint, err)
					continue
				}

				if c.Check(v2) {
					newApp = innerApp
					newApp.Versions = loopedApp.Versions
					newApp.LoopVersions = loopedApp.LoopVersions

					//log.Printf("[DEBUG] New IS larger - changing app on index %d from %s to %s. Versions: %s", appIndex, loopedApp.AppVersion, innerApp.AppVersion, newApp.LoopVersions)
				} else {
					//log.Printf("[DEBUG] New is NOT larger: %s_%s (new) vs %s_%s - just appending", innerApp.Name, innerApp.AppVersion, loopedApp.Name, loopedApp.AppVersion)
					newApp = loopedApp
				}

				newApp.Versions = append(newApp.Versions, AppVersion{
					Version: innerApp.AppVersion,
					ID:      innerApp.ID,
				})
				newApp.LoopVersions = append(newApp.LoopVersions, innerApp.AppVersion)
				newIndex = appIndex
				//log.Printf("Versions for %s_%s: %s", newApp.Name, newApp.AppVersion, newApp.LoopVersions)
			}

			break
		}
	}

	if newIndex >= 0 && newApp.ID != "" {
		//log.Printf("Should update app on index %d", newIndex)
		allApps[newIndex] = newApp
	} else {
		if !found {
			innerApp.Versions = append(innerApp.Versions, AppVersion{
				Version: innerApp.AppVersion,
				ID:      innerApp.ID,
			})
			innerApp.LoopVersions = append(innerApp.LoopVersions, innerApp.AppVersion)

			allApps = append(allApps, innerApp)
		}
	}

	return allApps, innerApp
}

func GetAllWorkflowApps(ctx context.Context, maxLen int, depth int) ([]WorkflowApp, error) {
	var allApps []WorkflowApp
	var err error

	// Used for recursion and autocleanup
	if depth > 5 {
		return []WorkflowApp{}, errors.New(fmt.Sprintf("Too deep: max recursion at %d", depth))
	}

	wrapper := []WorkflowApp{}
	cacheKey := fmt.Sprintf("workflowapps-sorted-%d", maxLen)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &wrapper)
			if err == nil {
				return wrapper, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for apps with KEY %s: %s", cacheKey, err)
		}
	}

	nameKey := "workflowapp"
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer

		// FIXME: Overwrite necessary?
		query := map[string]interface{}{
			"size": 1000,
			"sort": map[string]interface{}{
				"edited": map[string]interface{}{
					"order": "desc",
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find workflowapp query: %s", err)
			return []WorkflowApp{}, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get apps): %s", err)
			return []WorkflowApp{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return []WorkflowApp{}, err
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return []WorkflowApp{}, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return []WorkflowApp{}, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return []WorkflowApp{}, err
		}

		wrapped := AppSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return []WorkflowApp{}, err
		}

		allApps = []WorkflowApp{}
		duplicates := map[string][]string{}
		for _, hit := range wrapped.Hits.Hits {
			innerApp := hit.Source
			//if strings.Contains(strings.ToLower(innerApp.Name), "shuffle") {
			//	log.Printf("APP: %s", innerApp.Name)
			//}

			_, found := duplicates[innerApp.Name]
			if found {
				duplicates[innerApp.Name] = append(duplicates[innerApp.Name], innerApp.ID)
			} else {
				duplicates[innerApp.Name] = []string{innerApp.ID}
				//duplicates[innerApp.Name] = append(duplicates[innerApp.Name], innerApp.ID)
			}

			if innerApp.Name == "Shuffle Subflow" {
				continue
			}

			// This is used to validate with ALL apps
			if maxLen == 0 {
				allApps = append(allApps, innerApp)
				continue
			}

			if !innerApp.IsValid {
				continue
			}

			allApps, innerApp = fixAppAppend(allApps, innerApp)
		}

		deletions := false
		for key, value := range duplicates {
			if len(value) <= 10 {
				continue
			}

			log.Printf("[WARNING] Should delete loads of %s (%d). Cleanup process starting (max 5 recursions)", key, len(value))
			err = DeleteKeys(ctx, "workflowapp", value[0:len(value)-10])
			if err == nil {
				deletions = true
			} else {
				log.Printf("[WARNING] App cleanup failed: %s", err)
			}
		}

		if deletions {
			newAllApps, err := GetAllWorkflowApps(ctx, maxLen, depth+1)
			if err != nil {
				log.Printf("[WARNING] Failed to get subapps after cleanup")
				allApps = newAllApps
			} else {
				allApps = newAllApps
			}
		}

	} else {
		cursorStr := ""
		query := datastore.NewQuery(nameKey).Order("-edited").Limit(10)
		for {
			it := project.Dbclient.Run(ctx, query)
			//innerApp := WorkflowApp{}
			//data, err := it.Next(&innerApp)
			//log.Printf("DATA: %s, err: %s", data, err)

			for {
				innerApp := WorkflowApp{}
				_, err := it.Next(&innerApp)
				if err != nil {
					//log.Printf("No more apps? Breaking: %s.", err)
					break
				}

				if innerApp.Name == "Shuffle Subflow" {
					continue
				}

				if !innerApp.IsValid {
					continue
				}

				allApps, innerApp = fixAppAppend(allApps, innerApp)
			}

			if err != iterator.Done {
				//log.Printf("[INFO] Failed fetching results: %v", err)
				//break
			}

			// Get the cursor for the next page of results.
			nextCursor, err := it.Cursor()
			if err != nil {
				log.Printf("Cursorerror: %s", err)
				break
			} else {
				//log.Printf("NEXTCURSOR: %s", nextCursor)
				nextStr := fmt.Sprintf("%s", nextCursor)
				if cursorStr == nextStr {
					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)
				//cursorStr = nextCursor
				//break
			}

			if len(allApps) > maxLen && maxLen != 0 {
				break
			}
		}
	}

	if project.CacheDb {
		//log.Printf("[INFO] Setting %d apps in cache for 10 minutes for %s", len(allApps), cacheKey)

		//requestCache.Set(cacheKey, &apps, cache.DefaultExpiration)
		data, err := json.Marshal(allApps)
		if err == nil {
			err = SetCache(ctx, cacheKey, data)
			if err != nil {
				log.Printf("[WARNING] Failed updating cache for execution: %s", err)
			}
		} else {
			log.Printf("[WARNING] Failed marshalling execution: %s", err)
		}
	}

	return allApps, nil
}

func SetWorkflowQueue(ctx context.Context, executionRequest ExecutionRequest, env string) error {
	env = strings.ReplaceAll(env, " ", "-")
	nameKey := fmt.Sprintf("workflowqueue-%s", env)

	// New struct, to not add body, author etc
	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(executionRequest)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in setworkflow: %s", err)
			return nil
		}

		nameKey = strings.ToLower(nameKey)
		err = indexEs(ctx, nameKey, executionRequest.ExecutionId, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, executionRequest.ExecutionId, nil)
		if _, err := project.Dbclient.Put(ctx, key, &executionRequest); err != nil {
			log.Printf("[WARNING] Error adding workflow queue: %s", err)
			return err
		}
	}

	return nil
}

func GetWorkflowQueue(ctx context.Context, id string, limit int) (ExecutionRequestWrapper, error) {
	id = strings.ReplaceAll(id, " ", "-")
	nameKey := fmt.Sprintf("workflowqueue-%s", id)
	executions := []ExecutionRequest{}

	amount := limit
	q := datastore.NewQuery(nameKey).Limit(amount)
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"from": 0,
			"size": amount,
			"sort": map[string]interface{}{
				"priority": map[string]interface{}{
					"order": "desc",
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return ExecutionRequestWrapper{}, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get workflow queue): %s", err)
			return ExecutionRequestWrapper{}, err
		}
		defer res.Body.Close()

		// Here in case of older executions. Should work itself out long-term with
		// priority sorting
		if res.StatusCode == 400 {
			query = map[string]interface{}{
				"from": 0,
				"size": amount,
			}

			if err := json.NewEncoder(&buf).Encode(query); err != nil {
				log.Printf("[WARNING] Error encoding find user query: %s", err)
				return ExecutionRequestWrapper{}, err
			}

			res, err = project.Es.Search(
				project.Es.Search.WithContext(context.Background()),
				project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
				project.Es.Search.WithBody(&buf),
				project.Es.Search.WithTrackTotalHits(true),
			)
			if err != nil {
				log.Printf("[ERROR] Error getting response from Opensearch (get workflow queue): %s", err)
				return ExecutionRequestWrapper{}, err
			}
			defer res.Body.Close()
		}

		if res.StatusCode == 404 {
			return ExecutionRequestWrapper{}, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return ExecutionRequestWrapper{}, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return ExecutionRequestWrapper{}, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))

		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return ExecutionRequestWrapper{}, err
		}

		wrapped := ExecRequestSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return ExecutionRequestWrapper{}, err
		}

		executions = []ExecutionRequest{}
		for _, hit := range wrapped.Hits.Hits {
			//log.Printf("[DEBUG] Priority: %d", hit.Source.Priority)

			executions = append(executions, hit.Source)
		}
	} else {
		_, err := project.Dbclient.GetAll(ctx, q, &executions)
		if err != nil {
			return ExecutionRequestWrapper{}, err
		}
	}

	//log.Printf("[DEBUG] Returning %d executions", len(executions))
	return ExecutionRequestWrapper{
		Data: executions,
	}, nil
}

func SetNewValue(ctx context.Context, newvalue NewValue) error {
	nameKey := fmt.Sprintf("app_execution_values")

	if newvalue.Created == 0 {
		newvalue.Created = int64(time.Now().Unix())
	}

	if newvalue.Id == "" {
		newvalue.Id = uuid.NewV4().String()
	}

	// New struct, to not add body, author etc
	data, err := json.Marshal(newvalue)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in newValue: %s", err)
		return nil
	}
	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, newvalue.Id, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, newvalue.Id, nil)
		if _, err := project.Dbclient.Put(ctx, key, &newvalue); err != nil {
			log.Printf("Error adding newvalue: %s", err)
			return err
		}

	}

	return nil
}

func GetOpenseaAsset(ctx context.Context, id string) (*OpenseaAsset, error) {
	nameKey := "openseacollection"

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	workflowExecution := &OpenseaAsset{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &workflowExecution)
			if err == nil {
				return workflowExecution, nil
			} else {
				log.Printf("[WARNING] Failed getting opensea collection: %s", err)
			}
		} else {
		}
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return workflowExecution, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return workflowExecution, errors.New("Collection doesn't exist")
		}

		defer res.Body.Close()
		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return workflowExecution, err
		}

		wrapped := OpenseaAssetWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return workflowExecution, err
		}

		workflowExecution = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		if err := project.Dbclient.Get(ctx, key, workflowExecution); err != nil {
			return workflowExecution, err
		}
	}

	if project.CacheDb {
		newexecution, err := json.Marshal(workflowExecution)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling collection: %s", err)
			return workflowExecution, nil
		}

		err = SetCache(ctx, id, newexecution)
		if err != nil {
			log.Printf("[WARNING] Failed updating collection: %s", err)
		}
	}

	return workflowExecution, nil
}

func GetOpenseaAssets(ctx context.Context, collectionName string) ([]OpenseaAsset, error) {
	index := "openseacollection"

	var executions []OpenseaAsset
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		newCollection := strings.Replace(collectionName, "-", " ", -1)
		query := map[string]interface{}{
			"from": 0,
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"collection.name": newCollection,
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("Error encoding query: %s", err)
			return executions, err
		}

		// Perform the search request.
		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(index))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get workflow assets): %s", err)
			return executions, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return executions, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return executions, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return executions, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return executions, err
		}

		wrapped := OpenseaAssetSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return executions, err
		}

		executions = []OpenseaAsset{}
		for _, hit := range wrapped.Hits.Hits {
			if len(hit.Source.ID) == 0 || len(hit.Source.Name) == 0 {
				continue
			}

			newName := strings.ToLower(strings.Replace(strings.Replace(hit.Source.Collection, "#", "", -1), " ", "-", -1))

			if newName == strings.ToLower(collectionName) {
				executions = append(executions, hit.Source)
			} else {
				log.Printf("[DEBUG] Skipping %s vs. %s", newName, collectionName)
			}
		}

		return executions, nil
	} else {
		// FIXME: Sorting doesn't seem to work...
		//StartedAt          int64          `json:"started_at" datastore:"started_at"`
		//log.Printf("[WARNING] Getting executions from datastore")
		q := datastore.NewQuery(index).Limit(24)
		_, err := project.Dbclient.GetAll(ctx, q, &executions)
		if err != nil {
			log.Printf("[WARNING] Error getting opensea items: %s", err)
			return executions, err
		}
	}

	slice.Sort(executions[:], func(i, j int) bool {
		return executions[i].Created < executions[j].Created
	})

	return executions, nil
}

func SetOpenseaAsset(ctx context.Context, collection OpenseaAsset, id string, optionalEditedSecondsOffset ...int) error {
	nameKey := "openseacollection"
	timeNow := int64(time.Now().Unix())
	collection.Edited = timeNow
	if collection.Created == 0 {
		collection.Created = timeNow
	}

	if len(optionalEditedSecondsOffset) > 0 {
		collection.Edited += int64(optionalEditedSecondsOffset[0])
	}

	// New struct, to not add body, author etc
	data, err := json.Marshal(collection)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in set collection: %s", err)
		return nil
	}
	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, id, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if _, err := project.Dbclient.Put(ctx, key, &collection); err != nil {
			log.Printf("[WARNING] Error adding opensea asset: %s", err)
			return err
		}
	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getworkflow: %s", err)
		}
	}

	return nil
}

func SetWorkflow(ctx context.Context, workflow Workflow, id string, optionalEditedSecondsOffset ...int) error {
	nameKey := "workflow"
	timeNow := int64(time.Now().Unix())
	workflow.Edited = timeNow
	if workflow.Created == 0 {
		workflow.Created = timeNow
	}

	if len(optionalEditedSecondsOffset) > 0 {
		workflow.Edited += int64(optionalEditedSecondsOffset[0])
	}

	// New struct, to not add body, author etc
	data, err := json.Marshal(workflow)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in getworkflow: %s", err)
		return nil
	}
	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, id, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if _, err := project.Dbclient.Put(ctx, key, &workflow); err != nil {
			log.Printf("[WARNING] Error adding workflow: %s", err)
			return err
		}
	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getworkflow: %s", err)
		}
	}

	return nil
}

func SetWorkflowAppAuthDatastore(ctx context.Context, workflowappauth AppAuthenticationStorage, id string) error {
	nameKey := "workflowappauth"
	timeNow := int64(time.Now().Unix())
	if workflowappauth.Created == 0 {
		workflowappauth.Created = timeNow
	}

	workflowappauth.Edited = timeNow
	workflowappauth.App.Actions = []WorkflowAppAction{}

	// Will ALWAYS encrypt the values when it's not done already
	// This makes it so just re-saving the auth will encrypt them (next run)

	// Uses OrgId (Database) + Backend (ENV) modifier for the keys.
	// Using created timestamp to ensure it's always unique, even if it's the same key of same app in same org.
	if !workflowappauth.Encrypted {
		//log.Printf("[INFO] Encrypting authentication values")
		setEncrypted := true
		newFields := []AuthenticationStore{}
		for _, field := range workflowappauth.Fields {
			parsedKey := fmt.Sprintf("%s_%d_%s_%s", workflowappauth.OrgId, workflowappauth.Created, workflowappauth.Label, field.Key)
			newKey, err := handleKeyEncryption([]byte(field.Value), parsedKey)
			if err != nil {
				setEncrypted = false
				break
			}

			field.Value = string(newKey)
			newFields = append(newFields, field)
		}

		if setEncrypted {
			workflowappauth.Fields = newFields
			workflowappauth.Encrypted = true
		}
	}

	// New struct, to not add body, author etc
	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(workflowappauth)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in set app auth: %s", err)
			return err
		}

		err = indexEs(ctx, nameKey, id, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if _, err := project.Dbclient.Put(ctx, key, &workflowappauth); err != nil {
			log.Printf("[ERROR] Error adding workflow app AUTH %s (%s) with %d fields: %s", workflowappauth.Label, workflowappauth.Id, len(workflowappauth.Fields), err)
			for _, field := range workflowappauth.Fields {
				log.Printf("FIELD: %s: %d", field.Key, len(field.Value))
			}

			return err
		}
	}

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	DeleteCache(ctx, cacheKey)
	cacheKey = fmt.Sprintf("%s_%s", nameKey, workflowappauth.OrgId)
	DeleteCache(ctx, cacheKey)

	return nil
}

func SetEnvironment(ctx context.Context, env *Environment) error {
	// clear session_token and API_token for user
	nameKey := "Environments"

	if env.Id == "" {
		env.Id = uuid.NewV4().String()
	}

	timeNow := time.Now().Unix()
	if env.Created == 0 {
		env.Created = timeNow
	}

	env.Edited = timeNow

	// New struct, to not add body, author etc
	//log.Printf("[INFO] SETTING ENVIRONMENT %s", env.Id)
	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(env)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in set env: %s", err)
			return err
		}

		err = indexEs(ctx, nameKey, env.Id, data)
		if err != nil {
			return err
		}
	} else {
		k := datastore.NameKey(nameKey, env.Id, nil)
		if _, err := project.Dbclient.Put(ctx, k, env); err != nil {
			log.Println(err)
			return err
		}
	}

	cacheKey := fmt.Sprintf("%s_%s", nameKey, env.OrgId)
	DeleteCache(ctx, cacheKey)

	return nil
}

func GetSchedule(ctx context.Context, schedulename string) (*ScheduleOld, error) {
	nameKey := "schedules"
	curUser := &ScheduleOld{}
	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), strings.ToLower(schedulename))
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return &ScheduleOld{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return &ScheduleOld{}, errors.New("Schedule doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return &ScheduleOld{}, err
		}

		wrapped := ScheduleWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return &ScheduleOld{}, err
		}

		curUser = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(schedulename), nil)
		if err := project.Dbclient.Get(ctx, key, curUser); err != nil {
			return &ScheduleOld{}, err
		}

	}

	return curUser, nil
}

func GetSessionNew(ctx context.Context, sessionId string) (User, error) {
	cacheKey := fmt.Sprintf("session_%s", sessionId)
	user := &User{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &user)
			if err == nil && len(user.Id) > 0 {
				//log.Printf("Found user in cache for session %s", sessionId)
				return *user, nil
			} else {
				return *user, errors.New(fmt.Sprintf("Bad cache for %s", sessionId))
			}
		} else {
		}
	}

	// Query for the specific API-key in users
	nameKey := "Users"
	var users []User
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"from": 0,
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"session": sessionId,
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return User{}, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get api keys): %s", err)
			return User{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return User{}, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return User{}, nil
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return User{}, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))

		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return User{}, err
		}

		wrapped := UserSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return User{}, err
		}

		users = []User{}
		for _, hit := range wrapped.Hits.Hits {
			if hit.Source.Session != sessionId {
				continue
			}

			users = append(users, hit.Source)
		}

	} else {
		//log.Printf("[DEBUG] Searching for session %s", sessionId)
		q := datastore.NewQuery(nameKey).Filter("session =", sessionId).Limit(1)
		_, err := project.Dbclient.GetAll(ctx, q, &users)
		if err != nil && len(users) == 0 {
			log.Printf("[WARNING] Error getting session: %s", err)
			return User{}, err
		}
	}

	if len(users) == 0 {
		//log.Printf("[WARNING] No users found for session %s", sessionId)
		return User{}, errors.New("No users found for this apikey")
	}

	if project.CacheDb {
		data, err := json.Marshal(users[0])
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getSession: %s", err)
			return User{}, err
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting session cache for user %s: %s", sessionId, err)
		}
	}

	return users[0], nil
}

func GetApikey(ctx context.Context, apikey string) (User, error) {
	// Query for the specific API-key in users
	nameKey := "Users"
	var users []User
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"from": 0,
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"apikey": apikey,
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return User{}, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get api keys): %s", err)
			return User{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return User{}, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return User{}, nil
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return User{}, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))

		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return User{}, err
		}

		wrapped := UserSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return User{}, err
		}

		users = []User{}
		for _, hit := range wrapped.Hits.Hits {
			if hit.Source.ApiKey != apikey {
				continue
			}

			users = append(users, hit.Source)
		}

	} else {
		q := datastore.NewQuery(nameKey).Filter("apikey =", apikey).Limit(1)
		_, err := project.Dbclient.GetAll(ctx, q, &users)
		if err != nil && len(users) == 0 {
			log.Printf("[WARNING] Error getting apikey: %s", err)
			return User{}, err
		}
	}

	if len(users) == 0 {
		log.Printf("[WARNING] No users found for apikey %s", apikey)
		return User{}, errors.New("No users found for this apikey")
	}

	return users[0], nil
}

func GetHook(ctx context.Context, hookId string) (*Hook, error) {
	nameKey := "hooks"
	hookId = strings.ToLower(hookId)
	cacheKey := fmt.Sprintf("%s_%s", nameKey, hookId)

	hook := &Hook{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &hook)
			if err == nil && len(hook.Id) > 0 {
				return hook, nil
			} else {
				return hook, errors.New(fmt.Sprintf("Bad cache for %s", hookId))
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for hook: %s", err)
		}
	}
	//log.Printf("DBTYPE: %s", project.DbType)

	var err error
	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), hookId)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return &Hook{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return &Hook{}, errors.New("Hook doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return &Hook{}, err
		}

		wrapped := HookWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return &Hook{}, err
		}

		hook = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, hookId, nil)
		err = project.Dbclient.Get(ctx, key, hook)
		if err != nil {
			return &Hook{}, err
		}
	}

	if project.CacheDb {
		hookData, err := json.Marshal(hook)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in gethook: %s", err)
			return hook, err
		}

		err = SetCache(ctx, cacheKey, hookData)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for gethook: %s", err)
		}
	}

	return hook, err
}

func SetHook(ctx context.Context, hook Hook) error {
	nameKey := "hooks"

	// New struct, to not add body, author etc
	hookData, err := json.Marshal(hook)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in setHook: %s", err)
		return nil
	}
	hookId := strings.ToLower(hook.Id)

	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, hookId, hookData)
		if err != nil {
			return err
		}
	} else {
		key1 := datastore.NameKey(nameKey, hookId, nil)
		if _, err := project.Dbclient.Put(ctx, key1, &hook); err != nil {
			log.Printf("Error adding hook: %s", err)
			return err
		}
	}

	if project.CacheDb {

		cacheKey := fmt.Sprintf("%s_%s", nameKey, hookId)
		err = SetCache(ctx, cacheKey, hookData)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for hook: %s", err)
		}
	}

	return nil
}

func GetNotification(ctx context.Context, id string) (*Notification, error) {
	nameKey := "notifications"
	curFile := &Notification{}
	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return &Notification{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return &Notification{}, errors.New("Notification with that ID doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return &Notification{}, err
		}

		wrapped := NotificationWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return &Notification{}, err
		}

		curFile = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if err := project.Dbclient.Get(ctx, key, curFile); err != nil {
			return &Notification{}, err
		}

	}

	return curFile, nil
}

func GetFile(ctx context.Context, id string) (*File, error) {
	nameKey := "Files"
	curFile := &File{}
	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return &File{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return &File{}, errors.New("File doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return &File{}, err
		}

		wrapped := FileWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return &File{}, err
		}

		curFile = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if err := project.Dbclient.Get(ctx, key, curFile); err != nil {
			return &File{}, err
		}

	}

	return curFile, nil
}

func SetNotification(ctx context.Context, notification Notification) error {
	// clear session_token and API_token for user
	timeNow := time.Now().Unix()
	if notification.CreatedAt == 0 {
		notification.CreatedAt = timeNow
	}

	notification.UpdatedAt = timeNow
	nameKey := "notifications"
	//log.Printf("SETTING NOTIFICATION: %s", notification)

	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(notification)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling set notification: %s", err)
			return err
		}

		err = indexEs(ctx, nameKey, notification.Id, data)
		if err != nil {
			return err
		}
	} else {
		k := datastore.NameKey(nameKey, notification.Id, nil)
		if _, err := project.Dbclient.Put(ctx, k, &notification); err != nil {
			log.Println(err)
			return err
		}
	}

	cacheKey := fmt.Sprintf("%s_%s", nameKey, notification.OrgId)
	DeleteCache(ctx, cacheKey)

	return nil
}

func SetFile(ctx context.Context, file File) error {
	// clear session_token and API_token for user
	timeNow := time.Now().Unix()
	file.UpdatedAt = timeNow
	nameKey := "Files"

	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(file)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling set file: %s", err)
			return err
		}

		err = indexEs(ctx, nameKey, file.Id, data)
		if err != nil {
			return err
		}
	} else {
		k := datastore.NameKey(nameKey, file.Id, nil)
		if _, err := project.Dbclient.Put(ctx, k, &file); err != nil {
			log.Println(err)
			return err
		}
	}

	return nil
}

func GetOrgNotifications(ctx context.Context, orgId string) ([]Notification, error) {
	nameKey := "notifications"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, orgId)

	var notifications []Notification
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &notifications)
			if err == nil {
				return notifications, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for org: %s", err)
		}
	}

	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"from": 0,
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"org_id": orgId,
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return notifications, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get notifications): %s", err)
			return notifications, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return notifications, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return notifications, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return notifications, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))

		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return notifications, err
		}

		wrapped := NotificationSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return notifications, err
		}

		notifications = []Notification{}
		for _, hit := range wrapped.Hits.Hits {
			if hit.Source.OrgId == orgId {
				notifications = append(notifications, hit.Source)
			}
		}

	} else {
		q := datastore.NewQuery(nameKey).Filter("org_id =", orgId).Limit(100)
		_, err := project.Dbclient.GetAll(ctx, q, &notifications)

		if err != nil && len(notifications) == 0 {
			if strings.Contains(fmt.Sprintf("%s", err), "ResourceExhausted") {
				q = q.Limit(50)
				_, err := project.Dbclient.GetAll(ctx, q, &notifications)
				if err != nil && len(notifications) == 0 {
					return notifications, err
				}
			} else if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
				log.Printf("[INFO] Failed loading SOME notifications - skipping: %s", err)
			} else {
				return notifications, err
			}
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(notifications)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling notification cache: %s", err)
			return notifications, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating notification cache: %s", err)
		}
	}

	return notifications, nil
}

func GetUserNotifications(ctx context.Context, userId string) ([]Notification, error) {
	var notifications []Notification

	nameKey := "notifications"
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"from": 0,
			"size": 1000,
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": []map[string]interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"user_id": userId,
							},
						},
						map[string]interface{}{
							"match": map[string]interface{}{
								"read": false,
							},
						},
					},
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return notifications, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get user notifications): %s", err)
			return notifications, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return notifications, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return notifications, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return notifications, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))

		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return notifications, err
		}

		wrapped := NotificationSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return notifications, err
		}

		//log.Printf("[DEBUG] Have %d notifications for user %s", len(wrapped.Hits.Hits), userId)

		notifications = []Notification{}
		for _, hit := range wrapped.Hits.Hits {
			if hit.Source.UserId == userId {
				notifications = append(notifications, hit.Source)
			}
		}

	} else {
		q := datastore.NewQuery(nameKey).Filter("user_id =", userId).Limit(25)

		_, err := project.Dbclient.GetAll(ctx, q, &notifications)
		if err != nil && len(notifications) == 0 {
			if strings.Contains(fmt.Sprintf("%s", err), "ResourceExhausted") {
				q = q.Limit(10)
				_, err := project.Dbclient.GetAll(ctx, q, &notifications)
				if err != nil && len(notifications) == 0 {
					return notifications, err
				}
			} else if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
				log.Printf("[INFO] Failed loading SOME notifications - skipping: %s", err)
			} else {
				return notifications, err
			}
		}
	}

	return notifications, nil
}

func GetAllFiles(ctx context.Context, orgId, namespace string) ([]File, error) {
	var files []File

	nameKey := "Files"
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"from": 0,
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"org_id": orgId,
				},
			},
		}

		if len(namespace) > 0 {
			query = map[string]interface{}{
				"from": 0,
				"size": 1000,
				"query": map[string]interface{}{
					"bool": map[string]interface{}{
						"must": []map[string]interface{}{
							map[string]interface{}{
								"match": map[string]interface{}{
									"org_id": orgId,
								},
							},
							map[string]interface{}{
								"match": map[string]interface{}{
									"namespace": namespace,
								},
							},
						},
					},
				},
			}
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return files, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get files): %s", err)
			return files, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return files, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return files, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return files, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))

		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return files, err
		}

		wrapped := FileSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return files, err
		}

		files = []File{}
		for _, hit := range wrapped.Hits.Hits {
			files = append(files, hit.Source)
		}

	} else {
		q := datastore.NewQuery(nameKey).Filter("org_id =", orgId).Order("-created_at").Limit(100)

		_, err := project.Dbclient.GetAll(ctx, q, &files)
		if err != nil && len(files) == 0 {
			if strings.Contains(fmt.Sprintf("%s", err), "ResourceExhausted") {
				q = q.Limit(50)
				_, err := project.Dbclient.GetAll(ctx, q, &files)
				if err != nil && len(files) == 0 {
					return []File{}, err
				}
			} else if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
				log.Printf("[INFO] Failed loading SOME files - skipping: %s", err)
			} else {
				return []File{}, err
			}
		}
	}

	return files, nil
}

func GetWorkflowAppAuthDatastore(ctx context.Context, id string) (*AppAuthenticationStorage, error) {
	nameKey := "workflowappauth"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)

	appAuth := &AppAuthenticationStorage{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &appAuth)
			if err == nil {
				return appAuth, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for org: %s", err)
		}
	}

	// New struct, to not add body, author etc
	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return appAuth, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return appAuth, errors.New("App auth doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return appAuth, nil
		}

		wrapped := AppAuthWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return appAuth, nil
		}

		appAuth = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if err := project.Dbclient.Get(ctx, key, appAuth); err != nil {
			return &AppAuthenticationStorage{}, err
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(appAuth)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling app auth cache: %s", err)
			return appAuth, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed updating app auth cache: %s", err)
		}
	}

	return appAuth, nil
}

func GetAllSchedules(ctx context.Context, orgId string) ([]ScheduleOld, error) {
	var schedules []ScheduleOld

	nameKey := "schedules"
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"from": 0,
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"org": orgId,
				},
			},
		}

		if orgId == "ALL" && project.Environment != "cloud" {
			query = map[string]interface{}{}
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("Error encoding query: %s", err)
			return schedules, err
		}

		// Perform the search request.
		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get schedules): %s", err)
			return schedules, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return schedules, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return schedules, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return schedules, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return schedules, err
		}

		wrapped := ScheduleSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return schedules, err
		}

		schedules = []ScheduleOld{}
		for _, hit := range wrapped.Hits.Hits {
			schedules = append(schedules, hit.Source)
		}

		return schedules, err
	} else {
		q := datastore.NewQuery(nameKey).Filter("org = ", orgId).Limit(50)

		_, err := project.Dbclient.GetAll(ctx, q, &schedules)
		if err != nil && len(schedules) == 0 {
			return schedules, err
		}
	}

	return schedules, nil
}

func GetTriggerAuth(ctx context.Context, id string) (*TriggerAuth, error) {
	nameKey := "trigger_auth"
	triggerauth := &TriggerAuth{}
	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), strings.ToLower(id))
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return &TriggerAuth{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return &TriggerAuth{}, errors.New("Trigger auth doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return &TriggerAuth{}, err
		}

		wrapped := TriggerAuthWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return &TriggerAuth{}, err
		}

		triggerauth = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		if err := project.Dbclient.Get(ctx, key, triggerauth); err != nil {
			return &TriggerAuth{}, err
		}
	}

	return triggerauth, nil
}

func SetTriggerAuth(ctx context.Context, trigger TriggerAuth) error {
	nameKey := "trigger_auth"

	// New struct, to not add body, author etc
	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(trigger)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in set trigger auth: %s", err)
			return err
		}

		err = indexEs(ctx, nameKey, strings.ToLower(trigger.Id), data)
		if err != nil {
			return err
		}
	} else {
		key1 := datastore.NameKey(nameKey, strings.ToLower(trigger.Id), nil)
		if _, err := project.Dbclient.Put(ctx, key1, &trigger); err != nil {
			log.Printf("[ERROR] Error adding trigger auth: %s", err)
			return err
		}
	}

	return nil
}

// Index = Username
func DeleteKeys(ctx context.Context, entity string, value []string) error {
	// Non indexed User data
	if project.DbType == "elasticsearch" {
		for _, item := range value {
			DeleteKey(ctx, entity, item)
		}
	} else {
		keys := []*datastore.Key{}
		for _, item := range value {
			keys = append(keys, datastore.NameKey(entity, item, nil))
		}

		err := project.Dbclient.DeleteMulti(ctx, keys)
		if err != nil {
			log.Printf("[WARNING] Error deleting %s from %s: %s", value, entity, err)
			return err
		}
	}

	return nil
}

func GetEnvironmentCount() (int, error) {
	ctx := context.Background()
	q := datastore.NewQuery("Environments").Limit(1)
	count, err := project.Dbclient.Count(ctx, q)
	if err != nil {
		return 0, err
	}

	return count, nil
}

func GetAllUsers(ctx context.Context) ([]User, error) {
	index := "Users"

	users := []User{}
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"from": 0,
			"size": 1000,
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find workflowapp query: %s", err)
			return []User{}, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(index))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get all users): %s", err)
			return []User{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return []User{}, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return []User{}, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return []User{}, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return []User{}, err
		}

		wrapped := UserSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return []User{}, err
		}

		users = []User{}
		for _, hit := range wrapped.Hits.Hits {
			users = append(users, hit.Source)
		}

		return users, nil
	} else {
		q := datastore.NewQuery(index).Limit(50)

		_, err := project.Dbclient.GetAll(ctx, q, &users)
		if err != nil {
			return []User{}, err
		}
	}

	return users, nil
}

func GetUnfinishedExecutions(ctx context.Context, workflowId string) ([]WorkflowExecution, error) {
	index := "workflowexecution"
	var executions []WorkflowExecution
	var err error
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"sort": map[string]interface{}{
				"started_at": map[string]interface{}{
					"order": "desc",
				},
			},
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": []map[string]interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"workflow_id": workflowId,
							},
						},
						map[string]interface{}{
							"match": map[string]interface{}{
								"status": "EXECUTING",
							},
						},
					},
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("Error encoding query: %s", err)
			return executions, err
		}

		// Perform the search request.
		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(index))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get workflow executions): %s", err)
			return executions, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return executions, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return executions, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return executions, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return executions, err
		}

		wrapped := ExecutionSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return executions, err
		}

		executions = []WorkflowExecution{}
		for _, hit := range wrapped.Hits.Hits {
			executions = append(executions, hit.Source)
		}

		return executions, nil
	} else {
		// FIXME: Sorting doesn't seem to work...
		//StartedAt          int64          `json:"started_at" datastore:"started_at"`
		//log.Printf("[WARNING] Getting executions from datastore")
		query := datastore.NewQuery(index).Filter("workflow_id =", workflowId).Order("-started_at").Limit(5)
		//query := datastore.NewQuery(index).Filter("workflow_id =", workflowId).Limit(10)
		max := 50
		cursorStr := ""
		for {
			it := project.Dbclient.Run(ctx, query)

			for {
				innerWorkflow := WorkflowExecution{}
				_, err := it.Next(&innerWorkflow)
				if err != nil {
					//log.Printf("[WARNING] Error: %s", err)
					break
					//if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
					//} else {
					//	//log.Printf("[WARNING] Workflow iterator issue: %s", err)
					//	break
					//}
				}

				executions = append(executions, innerWorkflow)
			}

			if err != iterator.Done {
				//log.Printf("[INFO] Failed fetching results: %v", err)
				//break
			}

			if len(executions) >= max {
				break
			}

			// Get the cursor for the next page of results.
			nextCursor, err := it.Cursor()
			if err != nil {
				log.Printf("[WARNING] Cursorerror: %s", err)
				break
			} else {
				//log.Printf("NEXTCURSOR: %s", nextCursor)
				nextStr := fmt.Sprintf("%s", nextCursor)
				if cursorStr == nextStr {
					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)
				//cursorStr = nextCursor
				//break
			}
		}

		slice.Sort(executions[:], func(i, j int) bool {
			return executions[i].StartedAt > executions[j].StartedAt
		})
	}

	return executions, nil
}

func GetAllWorkflowExecutions(ctx context.Context, workflowId string, amount int) ([]WorkflowExecution, error) {
	index := "workflowexecution"

	cacheKey := fmt.Sprintf("%s_%s_%d", index, workflowId, amount)
	var err error
	var executions []WorkflowExecution
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &executions)
			if err == nil {
				//log.Printf("[DEBUG] Returned %d executions for workflow %s", len(executions), workflowId)
				return executions, nil
			} else {
				log.Printf("[WARNING] Failed getting workflowexecutions for %s: %s", workflowId, err)
			}
		} else {
			//log.Printf("[WARNING] Failed getting execution cache for workflow %s", workflowId)
		}
	}

	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": amount,
			"sort": map[string]interface{}{
				"started_at": map[string]interface{}{
					"order": "desc",
				},
			},
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"workflow_id": workflowId,
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding executions query: %s", err)
			return executions, err
		}

		// Perform the search request.
		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(index))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get workflow executions): %s", err)
			return executions, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return executions, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return executions, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return executions, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return executions, err
		}

		wrapped := ExecutionSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return executions, err
		}

		executions = []WorkflowExecution{}
		for _, hit := range wrapped.Hits.Hits {
			executions = append(executions, hit.Source)
		}

		//return executions, nil
	} else {
		// FIXME: Sorting doesn't seem to work...
		//StartedAt          int64          `json:"started_at" datastore:"started_at"`
		//log.Printf("[WARNING] Getting executions from datastore")
		//query := datastore.NewQuery(index).Filter("workflow_id =", workflowId).Limit(10)
		//totalMaxSize := 33554432
		//totalMaxSize := 22369621 // Total of App Engine max /3*2
		//totalMaxSize := 11184810
		totalMaxSize := 11184810
		query := datastore.NewQuery(index).Filter("workflow_id =", workflowId).Order("-started_at").Limit(5)
		cursorStr := ""
		for {
			it := project.Dbclient.Run(ctx, query)

			for {
				innerWorkflow := WorkflowExecution{}
				_, err := it.Next(&innerWorkflow)
				if err != nil {
					break
				}

				executions = append(executions, innerWorkflow)
			}

			if err != iterator.Done {
				//log.Printf("Breaking due to no more iterator")
				//log.Printf("[INFO] Failed fetching results: %v", err)
				//break
			}

			// This is a way to load as much data as we want, and the frontend will load the actual result for us
			executionmarshal, err := json.Marshal(executions)
			if err == nil {
				if len(executionmarshal) > totalMaxSize {
					// Reducing size

					for execIndex, execution := range executions {
						// Making sure the first 5 are "always" proper
						if execIndex < 5 {
							continue
						}

						newResults := []ActionResult{}

						newActions := []Action{}
						for _, action := range execution.Workflow.Actions {
							newAction := Action{
								Name:    action.Name,
								ID:      action.ID,
								AppName: action.AppName,
								AppID:   action.AppID,
							}

							newActions = append(newActions, newAction)
						}

						executions[execIndex].Workflow = Workflow{
							Name:     execution.Workflow.Name,
							ID:       execution.Workflow.ID,
							Triggers: execution.Workflow.Triggers,
							Actions:  newActions,
						}

						for _, result := range execution.Results {
							result.Result = "Result was too large to load. Full Execution needs to be loaded individually for this execution. Click \"Explore execution\" in the UI to see it in detail."
							result.Action = Action{
								Name:       result.Action.Name,
								ID:         result.Action.ID,
								AppName:    result.Action.AppName,
								AppID:      result.Action.AppID,
								LargeImage: result.Action.LargeImage,
							}

							newResults = append(newResults, result)
						}

						executions[execIndex].ExecutionArgument = "too large"
						executions[execIndex].Results = newResults
					}

					executionmarshal, err = json.Marshal(executions)
					if err == nil && len(executionmarshal) > totalMaxSize {
						log.Printf("Length breaking (2): %d", len(executionmarshal))
						break
					}
				}
			}

			// expected to get here
			if len(executions) >= amount {
				//log.Printf("[INFO] Breaking due to executions larger than amount (%d/%d)", len(executions), amount)
				break
			}

			// Get the cursor for the next page of results.
			nextCursor, err := it.Cursor()
			if err != nil {
				log.Printf("[WARNING] Cursorerror: %s", err)
				break
			} else {
				//log.Printf("NEXTCURSOR: %s", nextCursor)
				nextStr := fmt.Sprintf("%s", nextCursor)
				if cursorStr == nextStr {
					//log.Printf("Breaking due to no new cursor")
					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)
				//cursorStr = nextCursor
				//break
			}
		}

		slice.Sort(executions[:], func(i, j int) bool {
			return executions[i].StartedAt > executions[j].StartedAt
		})
	}

	if project.CacheDb {
		data, err := json.Marshal(executions)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling update execution cache: %s", err)
			return executions, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache executions (%s): %s", workflowId, err)
			return executions, nil
		}
	}

	return executions, nil
}

func GetOrgByField(ctx context.Context, fieldName, value string) ([]Org, error) {
	nameKey := "Organizations"

	var orgs []Org
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1,
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": []map[string]interface{}{
						{
							"match": map[string]interface{}{
								fieldName: value,
							},
						},
					},
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return orgs, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(nameKey)),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get app exec values): %s", err)
			return orgs, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return orgs, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return orgs, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return orgs, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return orgs, err
		}

		wrapped := OrgSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return orgs, err
		}

		orgs = []Org{}
		for _, hit := range wrapped.Hits.Hits {
			orgs = append(orgs, hit.Source)
		}
	} else {
		query := datastore.NewQuery(nameKey).Filter(fmt.Sprintf("%s =", fieldName), value).Limit(10)
		_, err := project.Dbclient.GetAll(ctx, query, &orgs)
		if err != nil {
			log.Printf("[WARNING] Failed getting orgs for field %s: %s", fieldName, err)
			return orgs, err
		}
	}

	return orgs, nil
}

func GetAllOrgs(ctx context.Context) ([]Org, error) {
	index := "Organizations"

	var orgs []Org
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find workflowapp query: %s", err)
			return []Org{}, err
		}

		// Perform the search request.
		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(index))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get org): %s", err)
			return []Org{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return []Org{}, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return []Org{}, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return []Org{}, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return []Org{}, err
		}

		wrapped := OrgSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return []Org{}, err
		}

		orgs = []Org{}
		for _, hit := range wrapped.Hits.Hits {
			orgs = append(orgs, hit.Source)
		}

		return orgs, nil
	} else {
		q := datastore.NewQuery(index).Limit(100)

		_, err := project.Dbclient.GetAll(ctx, q, &orgs)
		if err != nil {
			return []Org{}, err
		}
	}

	return orgs, nil
}

// Index = Username
func SetSchedule(ctx context.Context, schedule ScheduleOld) error {
	nameKey := "schedules"

	// New struct, to not add body, author etc
	if project.DbType == "elasticsearch" {
		data, err := json.Marshal(schedule)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in setschedule: %s", err)
			return nil
		}

		err = indexEs(ctx, nameKey, strings.ToLower(schedule.Id), data)
		if err != nil {
			return err
		}
	} else {
		key1 := datastore.NameKey(nameKey, strings.ToLower(schedule.Id), nil)
		if _, err := project.Dbclient.Put(ctx, key1, &schedule); err != nil {
			log.Printf("Error adding schedule: %s", err)
			return err
		}
	}

	return nil
}

func GetAppExecutionValues(ctx context.Context, parameterNames, orgId, workflowId, value string) ([]NewValue, error) {
	nameKey := fmt.Sprintf("app_execution_values")
	var workflows []NewValue
	var err error

	// Appending the users' workflows
	if project.DbType == "elasticsearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": []map[string]interface{}{
						{
							"match": map[string]interface{}{
								"org_id": orgId,
							},
						},
					},
				},
			},
		}

		//"workflow_id":    executionId,
		//"parameter_name": parameterNames,
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return workflows, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get app exec values): %s", err)
			return workflows, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return workflows, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return workflows, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return workflows, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return workflows, err
		}

		wrapped := NewValueSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return workflows, err
		}

		log.Printf("\n\nFOUND: %d", len(wrapped.Hits.Hits))
		workflows = []NewValue{}
		for _, hit := range wrapped.Hits.Hits {
			if hit.Source.Value == value && hit.Source.OrgId == orgId {
				workflows = append(workflows, hit.Source)
			}
		}
	} else {
		query := datastore.NewQuery(nameKey).Filter("org_id =", orgId).Filter("workflow_id =", workflowId).Filter("parameter_name =", parameterNames).Filter("value =", value)
		//foundCount, err := project.Dbclient.Count(ctx, q)
		cursorStr := ""
		for {
			it := project.Dbclient.Run(ctx, query)

			for {
				innerWorkflow := NewValue{}
				_, err := it.Next(&innerWorkflow)
				if err != nil {
					if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
					} else {
						log.Printf("[WARNING] CreateValue iterator issue: %s", err)
						break
					}
				}

				workflows = append(workflows, innerWorkflow)
			}

			if err != iterator.Done {
				//log.Printf("[INFO] Failed fetching results: %v", err)
				//break
			}

			// Get the cursor for the next page of results.
			nextCursor, err := it.Cursor()
			if err != nil {
				log.Printf("Cursorerror: %s", err)
				break
			} else {
				//log.Printf("NEXTCURSOR: %s", nextCursor)
				nextStr := fmt.Sprintf("%s", nextCursor)
				if cursorStr == nextStr {
					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)
				//cursorStr = nextCursor
				//break

			}
		}
	}

	return workflows, nil
}

// Used for cache for individual organizations
func SetCacheKey(ctx context.Context, cacheData CacheKeyData) error {
	nameKey := "org_cache"
	timeNow := int64(time.Now().Unix())
	cacheData.Edited = timeNow

	//cacheId := fmt.Sprintf("%s_%s_%s", cacheData.OrgId, cacheData.WorkflowId, cacheData.Key)
	cacheId := fmt.Sprintf("%s_%s", cacheData.OrgId, cacheData.Key)
	if len(cacheId) > 128 {
		cacheId = cacheId[0:127]
	}

	cacheId = url.QueryEscape(cacheId)
	cacheData.Authorization = ""

	// New struct, to not add body, author etc
	data, err := json.Marshal(cacheData)
	if err != nil {
		log.Printf("[ERROR] Failed marshalling in set cache key: %s", err)
		return nil
	}
	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, cacheId, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, cacheId, nil)
		if _, err := project.Dbclient.Put(ctx, key, &cacheData); err != nil {
			log.Printf("[ERROR] Error setting org cache: %s", err)
			return err
		}
	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, cacheId)
		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[ERROR] Failed setting cache for set cache key: %s", err)
		}
	}

	return nil
}

// Used for cache for individual organizations
func GetCacheKey(ctx context.Context, id string) (*CacheKeyData, error) {
	cacheData := &CacheKeyData{}
	nameKey := "org_cache"

	if len(id) > 128 {
		id = id[0:127]
	}

	id = url.QueryEscape(id)
	//fmt.Println("http://example.com/say?message="+url.QueryEscape(s))

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			parsedCache := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(parsedCache, &cacheData)
			if err == nil {
				return cacheData, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for cache key %s: %s", id, err)
		}
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return cacheData, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return cacheData, errors.New("Key doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return cacheData, err
		}

		wrapped := CacheKeyWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return cacheData, err
		}

		cacheData = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		if err := project.Dbclient.Get(ctx, key, cacheData); err != nil {
			if strings.Contains(err.Error(), `cannot load field`) {
				log.Printf("[ERROR] Error in workflow loading. Migrating workflow to new workflow handler (2): %s", err)
				err = nil
			} else {
				return cacheData, err
			}
		}
	}

	if project.CacheDb {
		//log.Printf("[DEBUG] Setting cache for workflow %s", cacheKey)
		data, err := json.Marshal(cacheData)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getcachekey: %s", err)
			return cacheData, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for get cache key: %s", err)
		}
	}

	return cacheData, nil
}

func RunInit(dbclient datastore.Client, storageClient storage.Client, gceProject, environment string, cacheDb bool, dbType string) (ShuffleStorage, error) {
	project = ShuffleStorage{
		Dbclient:      dbclient,
		StorageClient: storageClient,
		GceProject:    gceProject,
		Environment:   environment,
		CacheDb:       cacheDb,
		DbType:        dbType,
		CloudUrl:      "https://shuffler.io",
		BucketName:    "shuffler.appspot.com",
	}

	bucketName := os.Getenv("SHUFFLE_ORG_BUCKET")
	if len(bucketName) > 0 {
		log.Printf("[DEBUG] Using custom project bucketname: %s", bucketName)
		project.BucketName = bucketName
	}

	// docker run -p 11211:11211 --name memcache -d memcached -m 100
	log.Printf("[DEBUG] Starting with memcached address %s (SHUFFLE_MEMCACHED). If this is empty, fallback to appengine", memcached)

	requestCache = cache.New(35*time.Minute, 35*time.Minute)
	if strings.ToLower(dbType) == "elasticsearch" || strings.ToLower(dbType) == "opensearch" {
		project.Es = *GetEsConfig()

		ret, err := project.Es.Info()
		if err != nil {
			log.Printf("[ERROR] Failed setting up Opensearch: %s", err)
			return project, err
		}

		if ret.StatusCode >= 300 {
			respBody, err := ioutil.ReadAll(ret.Body)
			if err != nil {
				log.Printf("[ERROR] Failed handling ES setup: %s", ret)
				return project, errors.New(fmt.Sprintf("Bad status code from ES: %d", ret.StatusCode))
			}

			log.Printf("[ERROR] Bad Status from ES: %d", ret.StatusCode)
			log.Printf("[ERROR] Bad Body from ES: %s", string(respBody))

			return project, errors.New(fmt.Sprintf("Bad status code from ES: %d", ret.StatusCode))
		} else {
			//log.Printf("\n\n[INFO] Should check for SSO during setup - finding main org\n\n")
			ctx := context.Background()
			orgs, err := GetAllOrgs(ctx)
			if err == nil {
				for _, org := range orgs {
					if len(org.ManagerOrgs) == 0 && len(org.SSOConfig.SSOEntrypoint) > 0 {
						log.Printf("[INFO] Set initial SSO url for logins to %s", org.SSOConfig.SSOEntrypoint)
						SSOUrl = org.SSOConfig.SSOEntrypoint
						break
					}
				}
			} else {
				log.Printf("[WARNING] Error loading orgs: %s", err)
			}
		}
	}

	return project, nil
}

func GetEsConfig() *elasticsearch.Client {
	esUrl := os.Getenv("SHUFFLE_OPENSEARCH_URL")
	if len(esUrl) == 0 {
		esUrl = "http://shuffle-opensearch:9200"
	}

	// https://github.com/elastic/go-elasticsearch/blob/f741c073f324c15d3d401d945ee05b0c410bd06d/elasticsearch.go#L98
	config := elasticsearch.Config{
		Addresses:     strings.Split(esUrl, ","),
		Username:      os.Getenv("SHUFFLE_OPENSEARCH_USERNAME"),
		Password:      os.Getenv("SHUFFLE_OPENSEARCH_PASSWORD"),
		APIKey:        os.Getenv("SHUFFLE_OPENSEARCH_APIKEY"),
		CloudID:       os.Getenv("SHUFFLE_OPENSEARCH_CLOUDID"),
		MaxRetries:    5,
		RetryOnStatus: []int{500, 502, 503, 504, 429, 403},
	}

	//config.Transport.TLSClientConfig
	//transport := http.DefaultTransport.(*http.Transport).Clone()
	transport := http.DefaultTransport.(*http.Transport)
	transport.MaxIdleConnsPerHost = 100
	transport.ResponseHeaderTimeout = time.Second * 10
	transport.Proxy = nil

	if len(os.Getenv("SHUFFLE_OPENSEARCH_PROXY")) > 0 {
		httpProxy := os.Getenv("SHUFFLE_OPENSEARCH_PROXY")

		url_i := url.URL{}
		url_proxy, err := url_i.Parse(httpProxy)
		if err == nil {
			log.Printf("[DEBUG] Setting Opensearch proxy to %s", httpProxy)
			transport.Proxy = http.ProxyURL(url_proxy)
		} else {
			log.Printf("[ERROR] Failed setting proxy for %s", httpProxy)
		}
	}

	skipSSLVerify := false
	if strings.ToLower(os.Getenv("SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY")) == "true" {
		log.Printf("[DEBUG] SKIPPING SSL verification with Opensearch")
		skipSSLVerify = true
	}

	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS11,
		InsecureSkipVerify: skipSSLVerify,
	}

	//https://github.com/elastic/go-elasticsearch/blob/master/_examples/security/elasticsearch-cluster.yml
	certificateLocation := os.Getenv("SHUFFLE_OPENSEARCH_CERTIFICATE_FILE")
	if len(certificateLocation) > 0 {
		cert, err := ioutil.ReadFile(certificateLocation)
		if err != nil {
			log.Fatalf("[WARNING] Failed configuring certificates: %s not found", err)
		} else {
			config.CACert = cert

			//if transport.TLSClientConfig.RootCAs, err = x509.SystemCertPool(); err != nil {
			//	log.Fatalf("[ERROR] Problem adding system CA: %s", err)
			//}

			//// --> Add the custom certificate authority
			//if ok := transport.TLSClientConfig.RootCAs.AppendCertsFromPEM(cert); !ok {
			//	log.Fatalf("[ERROR] Problem adding CA from file %q", *cert)
			//}
		}

		log.Printf("[INFO] Added certificate %s elastic client.", certificateLocation)
	}
	config.Transport = transport

	es, err := elasticsearch.NewClient(config)
	if err != nil {
		log.Fatalf("[DEBUG] Database client for ELASTICSEARCH error during init (fatal): %s", err)
	}

	return es
}

func SetJoinPrizedraw2021(ctx context.Context, inputItem PrizedrawSubmitter) error {
	nameKey := "prizedraw_season1"
	timeNow := int64(time.Now().Unix())
	inputItem.Edited = timeNow
	if inputItem.Created == 0 {
		inputItem.Created = timeNow
	}

	if project.DbType == "elasticsearch" {
		return errors.New("No elasticsearch handler for this API ")
	} else {
		key := datastore.NameKey(nameKey, inputItem.ID, nil)
		if _, err := project.Dbclient.Put(ctx, key, &inputItem); err != nil {
			log.Printf("[WARNING] Error adding prizedraw: %s", err)
			return err
		}
	}

	return nil
}

func UploadAppSpecFiles(ctx context.Context, client *storage.Client, api WorkflowApp, parsed ParsedOpenApi) (WorkflowApp, error) {
	extraPath := fmt.Sprintf("extra_specs/%s/appspec.json", api.ID)
	openApiPath := fmt.Sprintf("extra_specs/%s/openapi.json", parsed.ID)
	//log.Printf("[WARNING] Should save actions as other part: %s", extraPath)

	appBytes, err := json.Marshal(api)
	if err != nil {
		log.Printf("[WARNING] Failed marshaling app during failure fix: %s", err)
		return api, err
	}

	openapiBytes, err := json.Marshal(parsed)
	if err != nil {
		log.Printf("[WARNING] Failed marshaling app's OpenAPI during failure fix: %s", err)
		return api, err
	}

	// Api.yaml
	bucket := client.Bucket(project.BucketName)

	if len(api.ID) > 0 {
		obj := bucket.Object(extraPath)
		w := obj.NewWriter(ctx)
		if _, err := fmt.Fprint(w, string(appBytes)); err != nil {
			log.Printf("[WARNING] Failed writing app file: %s", err)
			return api, err
		}

		// Close, just like writing a file.
		if err := w.Close(); err != nil {
			log.Printf("[WARNING] Failed closing app file: %s", err)
			return api, err
		}
	}

	// OpenAPI
	if len(parsed.ID) > 0 {
		obj := bucket.Object(openApiPath)
		w := obj.NewWriter(ctx)
		if _, err := fmt.Fprint(w, string(openapiBytes)); err != nil {
			log.Printf("[WARNING] Failed writing openapi file: %s", err)
			return api, err
		}

		// Close, just like writing a file.
		if err := w.Close(); err != nil {
			log.Printf("[WARNING] Failed closing openapi file: %s", err)
			return api, err
		}

		log.Printf("[DEBUG] Uploaded OpenAPI for %s to path: %s", api.ID, openApiPath)
	}

	fullParsedPath := fmt.Sprintf("gs://%s/extra_specs/%s", project.BucketName, api.ID)
	log.Printf("[DEBUG] Successfully uploaded app action data to path: %s. App ID: %s, OpenAPI ID: %s", fullParsedPath, api.ID, parsed.ID)
	api.Actions = []WorkflowAppAction{}
	api.ActionFilePath = fullParsedPath
	err = SetWorkflowAppDatastore(ctx, api, api.ID)
	if err != nil {
		log.Printf("[ERROR] Failed adding app to db: %s", err)
		return api, err
	}

	return api, nil
}

func SetUsecase(ctx context.Context, usecase Usecase, optionalEditedSecondsOffset ...int) error {
	var err error
	nameKey := "usecases"
	name := strings.ToLower(strings.Replace(usecase.Name, " ", "_", -1))

	timeNow := int64(time.Now().Unix())
	usecase.Edited = timeNow

	// New struct, to not add body, author etc
	data, err := json.Marshal(usecase)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in setapp: %s", err)
		return nil
	}

	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, name, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, name, nil)
		if _, err := project.Dbclient.Put(ctx, key, &usecase); err != nil {
			log.Printf("[WARNING] Error adding usecase: %s", err)
			return err
		}
	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, name)
		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for setusecase: %s", err)
		}
	}

	return nil
}

func GetUsecase(ctx context.Context, name string) (*Usecase, error) {
	usecase := &Usecase{}
	nameKey := "usecases"
	id := strings.ToLower(strings.Replace(name, " ", "_", -1))

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &usecase)
			if err == nil {
				return usecase, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for usecase: %s", err)
		}
	}

	if project.DbType == "elasticsearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error: %s", err)
			return usecase, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return usecase, errors.New("Usecase doesn't exist")
		}

		defer res.Body.Close()
		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return usecase, err
		}

		wrapped := UsecaseWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return usecase, err
		}

		usecase = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		if err := project.Dbclient.Get(ctx, key, usecase); err != nil {
			if strings.Contains(err.Error(), `cannot load field`) {
				log.Printf("[INFO] Error in usecase loading. Migrating usecase to new workflow handler.")
				err = nil
			} else {
				return usecase, err
			}
		}
	}

	if project.CacheDb {
		//log.Printf("[DEBUG] Setting cache for usecase %s", cacheKey)
		data, err := json.Marshal(usecase)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getusecase: %s", err)
			return usecase, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getusecase: %s", err)
		}
	}

	return usecase, nil

}

func SetNewDeal(ctx context.Context, deal ResellerDeal) error {
	nameKey := "reseller_deal"

	timeNow := int64(time.Now().Unix())
	deal.Edited = timeNow
	if deal.Created == 0 {
		deal.Created = timeNow
	}

	if len(deal.ID) == 0 {
		deal.ID = uuid.NewV4().String()
	}

	// New struct, to not add body, author etc
	data, err := json.Marshal(deal)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in set deal: %s", err)
		return err
	}

	// FIXMe: Shouldn't really be possible, but may be useful for hybrid (?)
	if project.DbType == "elasticsearch" {
		err = indexEs(ctx, nameKey, deal.ID, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, deal.ID, nil)
		if _, err := project.Dbclient.Put(ctx, key, &deal); err != nil {
			log.Printf("[WARNING] Error adding deal: %s", err)
			return err
		}
	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, deal.ID)
		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for deal: %s", err)
		}
	}

	return nil
}

func GetAllDeals(ctx context.Context, orgId string) ([]ResellerDeal, error) {
	nameKey := "reseller_deal"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, orgId)

	deals := []ResellerDeal{}
	if project.DbType == "elasticsearch" {
		log.Printf("GETTING deals for org %s in item %s", orgId, nameKey)
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"sort": map[string]interface{}{
				"edited": map[string]interface{}{
					"order": "desc",
				},
			},
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": []map[string]interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"reseller_org": orgId,
							},
						},
					},
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("Error encoding deal query: %s", err)
			return deals, err
		}

		// Perform the search request.
		res, err := project.Es.Search(
			project.Es.Search.WithContext(context.Background()),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)

		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get deals): %s", err)
			return deals, err
		}

		defer res.Body.Close()
		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return deals, err
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			log.Printf("[WARNING] Body of deals is bad: %s", string(respBody))
			return deals, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		wrapped := DealSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return deals, err
		}

		newDeals := []ResellerDeal{}
		for _, hit := range wrapped.Hits.Hits {
			if hit.Source.ResellerOrg != orgId {
				continue
			}

			newDeals = append(newDeals, hit.Source)
		}

		log.Printf("[INFO] Got %d deals for org %s", len(newDeals), orgId)
		deals = newDeals
	} else {

		query := datastore.NewQuery(nameKey).Filter("reseller_org =", orgId).Limit(50)
		_, err := project.Dbclient.GetAll(ctx, query, &deals)
		if err != nil {
			log.Printf("[WARNING] Failed getting deals for org: %s", orgId)
			return deals, err
		}

		log.Printf("[INFO] Got %d deals for org %s", len(deals), orgId)
	}

	if project.CacheDb {
		newdeal, err := json.Marshal(deals)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling deals: %s", err)
			return deals, nil
		}

		err = SetCache(ctx, cacheKey, newdeal)
		if err != nil {
			log.Printf("[WARNING] Failed updating deal cache: %s", err)
		}
	}

	return deals, nil
}

func GetAppStats(ctx context.Context, id string) (*Conversionevents, error) {
	stats := &Conversionevents{}

	nameKey := "app_stats"

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &stats)
			if err == nil {
				return stats, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for appstats: %s", err)
		}
	}

	if project.DbType == "elasticsearch" {
		return &Conversionevents{}, errors.New("es api not supported yet")
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if err := project.Dbclient.Get(ctx, key, stats); err != nil {
			log.Printf("[WARNING] Error in appstats loading of %s: %s", id, err)
		}
	}

	if project.CacheDb {
		//log.Printf("[DEBUG] Setting cache for workflow %s", cacheKey)
		data, err := json.Marshal(stats)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getappstats: %s", err)
			return stats, nil
		}

		err = SetCache(ctx, cacheKey, data)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getappstats: %s", err)
		}
	}

	return stats, nil
}

// Finds custom oauth2 secret etc. based on
func GetHostedOAuth(ctx context.Context, id string) (*DataToSend, error) {
	stats := &DataToSend{}

	nameKey := "oauth2_storage"
	if project.DbType == "elasticsearch" {
		return &DataToSend{}, errors.New("es api not supported for custom oauth")
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if err := project.Dbclient.Get(ctx, key, stats); err != nil {
			log.Printf("[WARNING] Error in oauth2 key loading of ID %s: %s", id, err)
		}
	}

	return stats, nil
}

func GetCreatorStats(ctx context.Context, creatorName string, startDate string, endDate string) ([]CreatorStats, error) {
	stats := []CreatorStats{}
	nameKey := "creator_stats"

	log.Printf("[INFO] Looking for name %s", creatorName)

	q := datastore.NewQuery(nameKey).Filter("creator =", creatorName).Limit(1)
	_, err := project.Dbclient.GetAll(ctx, q, &stats)
	if err != nil {
		if strings.Contains(err.Error(), `cannot load field`) {
			log.Printf("[INFO] error %s", err)
			err = nil
		} else {
			log.Printf("[INFO] error loading data for %s", creatorName)
		}
	}

	if len(stats) == 0 { // used to handle error when creator name is not valid
		return stats, nil
	}

	var parsedStartDate time.Time
	var parsedEndDate time.Time

	startPresent := false
	endPresent := false
	bothPresent := false

	if len(startDate) > 0 && len(endDate) > 0 {
		parsedStartDate, err = time.Parse("2006-01-02", startDate)
		if err != nil {
			log.Printf("[ERROR] Incorrect date format %s: %s", startDate, err)
			return stats, err
		}
		parsedEndDate, err = time.Parse("2006-01-02", endDate)
		if err != nil {
			log.Printf("[ERROR] Incorrect date format %s: %s", endDate, err)
			return stats, err
		}
		bothPresent = true
	} else if len(startDate) > 0 {
		parsedStartDate, err = time.Parse("2006-01-02", startDate)
		if err != nil {
			log.Printf("[ERROR] Incorrect date format %s: %s", startDate, err)
			return stats, err
		}
		startPresent = true
	} else if len(endDate) > 0 {
		parsedEndDate, err = time.Parse("2006-01-02", endDate)
		if err != nil {
			log.Printf("[ERROR] Incorrect date format %s: %s", endDate, err)
			return stats, err
		}
		endPresent = true
	}

	if startPresent == false && endPresent == false && bothPresent == false { // if no query parameter is provided
		if len(stats[0].AppStats) > 0 {
			// calculating most conversed app and sorts in order highest first
			sort.Slice(stats[0].AppStats, func(i, j int) bool {
				return len(stats[0].AppStats[i].Events[0].Data) > len(stats[0].AppStats[j].Events[0].Data)
			})
			stats[0].MostConversedApp = stats[0].AppStats[0].AppName

			// calculating most clicked app and sorts in order highest first
			sort.Slice(stats[0].AppStats, func(i, j int) bool {
				return len(stats[0].AppStats[i].Events[1].Data) > len(stats[0].AppStats[j].Events[1].Data)
			})
			stats[0].MostClickedApp = stats[0].AppStats[0].AppName
		}
		return stats, err
	}

	var updatedStats []AppStats

	for index, i := range stats[0].AppStats { // This is for filtering data by dates.
		var appData []WidgetPoint
		var totalConversions int64
		var totalClicks int64

		for eventIndex, j := range i.Events {
			var appEvents []WidgetPointData
			if len(j.Data) > 0 {
				for _, k := range j.Data {
					if len(k.Key) > 0 {
						parsedData, err := time.Parse("2006-01-02", k.Key)
						if err != nil {
							log.Printf("[ERROR] error parsing data %s: %s", k.Key, err)
							return stats, err
						}
						if bothPresent == true {
							if parsedData.After(parsedStartDate) && parsedData.Before(parsedEndDate) {
								appEvents = append(appEvents, k)
								if eventIndex == 0 {
									totalConversions += k.Data
								}
								if eventIndex == 1 {
									totalClicks += k.Data
								}
							}
						}
						if startPresent == true {
							if parsedData.After(parsedStartDate) {
								appEvents = append(appEvents, k)
								if eventIndex == 0 {
									totalConversions += k.Data
								}
								if eventIndex == 1 {
									totalClicks += k.Data
								}
							}
						}
						if endPresent == true {
							if parsedData.Before(parsedEndDate) {
								appEvents = append(appEvents, k)
								if eventIndex == 0 {
									totalConversions += k.Data
								}
								if eventIndex == 1 {
									totalClicks += k.Data
								}
							}
						}

					} else {
						// stats[0].AppStats[index] = AppStats{} // for discarding apps with no events
					}

				}
				if eventIndex == 0 {
					appData = append(appData, WidgetPoint{"conversion", appEvents})
					// appData[0].Key = "conversion"
					// appData[0].Data = appEvents
				}

				if eventIndex == 1 {
					appData = append(appData, WidgetPoint{"click", appEvents})
					// appData[1].Key = "click"
					// appData[1].Data = appEvents
				}
				//
			}

		}
		updatedStats = append(updatedStats, i) //fill in updatedStats with old data
		updatedStats[index].TotalConversions = int(totalConversions)
		updatedStats[index].TotalClicks = int(totalClicks)
		updatedStats[index].Events = appData // update events with filtered events
	}
	stats[0].AppStats = updatedStats // updating stats with updated values

	if len(stats[0].AppStats) > 1 {
		// calculating most conversed app and sorts in order highest first

		sort.Slice(stats[0].AppStats, func(i, j int) bool {
			if len(stats[0].AppStats[i].Events) > 1 {
				return len(stats[0].AppStats[i].Events[0].Data) > len(stats[0].AppStats[j].Events[0].Data)
			} else {
				return false
			}
		})
		stats[0].MostConversedApp = stats[0].AppStats[0].AppName

		// // calculating most clicked app and sorts in order highest first
		sort.Slice(stats[0].AppStats, func(i, j int) bool {
			if len(stats[0].AppStats[i].Events) > 1 {
				return len(stats[0].AppStats[i].Events[0].Data) > len(stats[0].AppStats[j].Events[0].Data)
			} else {
				return false
			}
		})
		stats[0].MostClickedApp = stats[0].AppStats[1].AppName
	}

	return stats, err
}
