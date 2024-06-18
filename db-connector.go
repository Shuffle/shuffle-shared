package shuffle

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"

	//"strconv"
	//"encoding/binary"
	"math"
	"math/rand"
	"sort"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/Masterminds/semver"
	"github.com/bradfitz/slice"
	uuid "github.com/satori/go.uuid"

	//"github.com/frikky/kin-openapi/openapi3"
	"github.com/patrickmn/go-cache"
	"google.golang.org/api/iterator"

	"cloud.google.com/go/storage"
	gomemcache "github.com/bradfitz/gomemcache/memcache"
	"google.golang.org/appengine/memcache"

	//opensearch "github.com/shuffle/opensearch-go"
	opensearch "github.com/opensearch-project/opensearch-go"
	"github.com/opensearch-project/opensearch-go/v2/opensearchapi"
)

var requestCache = cache.New(60*time.Minute, 60*time.Minute)
var memcached = os.Getenv("SHUFFLE_MEMCACHED")
var mc = gomemcache.New(memcached)
var gceProject = os.Getenv("SHUFFLE_GCEPROJECT")
var propagateUrl = os.Getenv("SHUFFLE_PROPAGATE_URL")
var propagateToken = os.Getenv("SHUFFLE_PROPAGATE_TOKEN")

var maxCacheSize = 1020000

// var dbInterval = 0x19
// var dbInterval = 0x1
var dbInterval = 0xA
// Dumps data from cache to DB for every {dbInterval} action (tried 5, 10, 25)

type ShuffleStorage struct {
	GceProject    string
	Dbclient      datastore.Client
	StorageClient storage.Client
	Environment   string
	CacheDb       bool
	Es            opensearch.Client
	DbType        string
	CloudUrl      string
	BucketName    string
}

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

// 1. Check list if there is a record for yesterday
// 2. If there isn't, set it and clear out the daily records
// Also: can we dump a list of apps that run? Maybe a list of them?
func handleDailyCacheUpdate(executionInfo *ExecutionInfo) *ExecutionInfo {
	timeYesterday := time.Now().AddDate(0, 0, -1)
	timeYesterdayFormatted := timeYesterday.Format("2006-12-02")

	for _, day := range executionInfo.DailyStatistics {

		// Check if the day.Date is the same as yesterday and return if it is
		if day.Date.Format("2006-12-02") == timeYesterdayFormatted {
			//log.Printf("[DEBUG] Daily stats already updated for %s. Data: %#v", day.Date, day)
			return executionInfo
		}
	}

	log.Printf("[DEBUG] Daily stats not updated for %s in org %s today. Only have %d stats so far - running update.", timeYesterday, executionInfo.OrgId, len(executionInfo.DailyStatistics))
	// If we get here, we need to update the daily stats
	newDay := DailyStatistics{
		Date:                       timeYesterday,
		AppExecutions:              executionInfo.DailyAppExecutions,
		AppExecutionsFailed:        executionInfo.DailyAppExecutionsFailed,
		SubflowExecutions:          executionInfo.DailySubflowExecutions,
		WorkflowExecutions:         executionInfo.DailyWorkflowExecutions,
		WorkflowExecutionsFinished: executionInfo.DailyWorkflowExecutionsFinished,
		WorkflowExecutionsFailed:   executionInfo.DailyWorkflowExecutionsFailed,
		OrgSyncActions:             executionInfo.DailyOrgSyncActions,
		CloudExecutions:            executionInfo.DailyCloudExecutions,
		OnpremExecutions:           executionInfo.DailyOnpremExecutions,
		AIUsage:                    executionInfo.DailyAIUsage,

		ApiUsage: executionInfo.DailyApiUsage,

		Additions: executionInfo.Additions,
	}

	executionInfo.DailyStatistics = append(executionInfo.DailyStatistics, newDay)

	// Reset daily
	executionInfo.DailyAppExecutions = 0
	executionInfo.DailyAppExecutionsFailed = 0
	executionInfo.DailySubflowExecutions = 0
	executionInfo.DailyWorkflowExecutions = 0
	executionInfo.DailyWorkflowExecutionsFinished = 0
	executionInfo.DailyWorkflowExecutionsFailed = 0
	executionInfo.DailyOrgSyncActions = 0
	executionInfo.DailyCloudExecutions = 0
	executionInfo.DailyOnpremExecutions = 0
	executionInfo.DailyApiUsage = 0
	executionInfo.DailyAIUsage = 0

	// Cleaning up old stuff we don't use for now
	executionInfo.HourlyAppExecutions = 0
	executionInfo.HourlyAppExecutionsFailed = 0
	executionInfo.HourlySubflowExecutions = 0
	executionInfo.HourlyWorkflowExecutions = 0
	executionInfo.HourlyWorkflowExecutionsFinished = 0
	executionInfo.HourlyWorkflowExecutionsFailed = 0
	executionInfo.HourlyOrgSyncActions = 0
	executionInfo.HourlyCloudExecutions = 0
	executionInfo.HourlyOnpremExecutions = 0

	// Weekly
	executionInfo.WeeklyAppExecutions = 0
	executionInfo.WeeklyAppExecutionsFailed = 0
	executionInfo.WeeklySubflowExecutions = 0
	executionInfo.WeeklyWorkflowExecutions = 0
	executionInfo.WeeklyWorkflowExecutionsFinished = 0
	executionInfo.WeeklyWorkflowExecutionsFailed = 0
	executionInfo.WeeklyOrgSyncActions = 0
	executionInfo.WeeklyCloudExecutions = 0
	executionInfo.WeeklyOnpremExecutions = 0

	for additionIndex, _ := range executionInfo.Additions {
		executionInfo.Additions[additionIndex].DailyValue = 0
	}

	return executionInfo
}

func HandleIncrement(dataType string, orgStatistics *ExecutionInfo, increment uint8) *ExecutionInfo {

	appendCustom := false 
	if dataType == "app_executions" || strings.HasPrefix(dataType, "app_executions") {
		orgStatistics.TotalAppExecutions += int64(increment)
		orgStatistics.MonthlyAppExecutions += int64(increment)
		orgStatistics.WeeklyAppExecutions += int64(increment)
		orgStatistics.DailyAppExecutions += int64(increment)
		orgStatistics.HourlyAppExecutions += int64(increment)

		if dataType != "app_executions" { 
			appendCustom = true
		}

	} else if dataType == "workflow_executions" {
		orgStatistics.TotalWorkflowExecutions += int64(increment)
		orgStatistics.MonthlyWorkflowExecutions += int64(increment)
		orgStatistics.WeeklyWorkflowExecutions += int64(increment)
		orgStatistics.DailyWorkflowExecutions += int64(increment)
		orgStatistics.HourlyWorkflowExecutions += int64(increment)

	} else if dataType == "workflow_executions_finished" {
		orgStatistics.TotalWorkflowExecutionsFinished += int64(increment)
		orgStatistics.MonthlyWorkflowExecutionsFinished += int64(increment)
		orgStatistics.WeeklyWorkflowExecutionsFinished += int64(increment)
		orgStatistics.DailyWorkflowExecutionsFinished += int64(increment)
		orgStatistics.HourlyWorkflowExecutionsFinished += int64(increment)

	} else if dataType == "workflow_executions_failed" {
		orgStatistics.TotalWorkflowExecutionsFailed += int64(increment)
		orgStatistics.MonthlyWorkflowExecutionsFailed += int64(increment)
		orgStatistics.WeeklyWorkflowExecutionsFailed += int64(increment)
		orgStatistics.DailyWorkflowExecutionsFailed += int64(increment)
		orgStatistics.HourlyWorkflowExecutionsFailed += int64(increment)


	} else if dataType == "app_executions_failed" {
		orgStatistics.TotalAppExecutionsFailed += int64(increment)
		orgStatistics.MonthlyAppExecutionsFailed += int64(increment)
		orgStatistics.WeeklyAppExecutionsFailed += int64(increment)
		orgStatistics.DailyAppExecutionsFailed += int64(increment)
		orgStatistics.HourlyAppExecutionsFailed += int64(increment)

	} else if dataType == "subflow_executions" {
		orgStatistics.TotalSubflowExecutions += int64(increment)
		orgStatistics.MonthlySubflowExecutions += int64(increment)
		orgStatistics.WeeklySubflowExecutions += int64(increment)
		orgStatistics.DailySubflowExecutions += int64(increment)
		orgStatistics.HourlySubflowExecutions += int64(increment)

	} else if dataType == "org_sync_actions" {
		orgStatistics.TotalOrgSyncActions += int64(increment)
		orgStatistics.MonthlyOrgSyncActions += int64(increment)
		orgStatistics.WeeklyOrgSyncActions += int64(increment)
		orgStatistics.DailyOrgSyncActions += int64(increment)
		orgStatistics.HourlyOrgSyncActions += int64(increment)

	} else if dataType == "workflow_executions_cloud" {
		orgStatistics.TotalCloudExecutions += int64(increment)
		orgStatistics.MonthlyCloudExecutions += int64(increment)
		orgStatistics.WeeklyCloudExecutions += int64(increment)
		orgStatistics.DailyCloudExecutions += int64(increment)
		orgStatistics.HourlyCloudExecutions += int64(increment)

	} else if dataType == "workflow_executions_onprem" {
		orgStatistics.TotalOnpremExecutions += int64(increment)
		orgStatistics.MonthlyOnpremExecutions += int64(increment)
		orgStatistics.WeeklyOnpremExecutions += int64(increment)
		orgStatistics.DailyOnpremExecutions += int64(increment)
		orgStatistics.HourlyOnpremExecutions += int64(increment)
	} else if dataType == "api_usage" {
		orgStatistics.TotalApiUsage += int64(increment)
		orgStatistics.MonthlyApiUsage += int64(increment)
		orgStatistics.DailyApiUsage += int64(increment)
	} else if dataType == "ai_executions" {
		orgStatistics.TotalAIUsage += int64(increment)
		orgStatistics.MonthlyAIUsage += int64(increment)
		orgStatistics.DailyAIUsage += int64(increment)
	} else {
		//log.Printf("\n\n[ERROR] Unknown data type in stats increment for org %s: %s. Appending to custom list.\n\n", orgStatistics.OrgId, dataType)
		appendCustom = true
	}

	if appendCustom {
		//log.Printf("[DEBUG] Appending custom data type %s for org %s", dataType, orgStatistics.OrgId)

		found := false
		for additionIndex, addition := range orgStatistics.Additions {
			if addition.Key != dataType {
				continue
			}

			found = true 
			amount := int64(increment)

			orgStatistics.Additions[additionIndex].Value += amount
			orgStatistics.Additions[additionIndex].DailyValue += amount

			break
		}

		if !found {
			orgStatistics.Additions = append(orgStatistics.Additions, AdditionalUseConfig {
				Key:        dataType,
				Value:      int64(increment),
				DailyValue: int64(increment),
			})
		}
	}

	//send mail if the app runs more than the set threshold limit
	ctx := context.Background()
	orgId := orgStatistics.OrgId

	//Unmarshal the org details
	cacheKey := fmt.Sprintf("OrgDetails_%s", orgId)
	orgData, err := GetCache(ctx, cacheKey)
	if err != nil {
		log.Printf("[ERROR] Failed getting org in increment: %s", err)
		return orgStatistics
	}

	var org *Org
	orgBytes, ok := orgData.([]byte)
	if !ok {
		log.Printf("[ERROR] Unexpected data type in cache for org details")
		return orgStatistics
	}

	org = new(Org)
	err = json.Unmarshal(orgBytes, org)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshalling org in increment: %s", err)
		return orgStatistics
	}

	if len(org.Id) > 0 {
		for index, AlertThreshold := range org.Billing.AlertThreshold {
			if int64(AlertThreshold.Count) < orgStatistics.MonthlyAppExecutions && AlertThreshold.Email_send == false {
				mailbody := Mailcheck{
					Targets: []string{org.Org},
					Subject: "You have reached the threshold limit of app executions.",
					Body:    fmt.Sprintf("You have reached the threshold limit of %v percent Or %v app executions run. Please login to shuffle and check it.", AlertThreshold.Percentage, AlertThreshold.Count),
				}
				err = sendMailSendgrid(mailbody.Targets, mailbody.Subject, mailbody.Body, false)
				if err != nil {
					log.Printf("[ERROR] Failed sending alert mail in increment: %s", err)
				}
				if err == nil {
					org.Billing.AlertThreshold[index].Email_send = true
					err = SetOrg(ctx, *org, orgId)
					if err != nil {
						log.Printf("[ERROR] Failed setting org in increment: %s", err)
						return orgStatistics
					}
				}
				log.Printf("[DEBUG] Successfully sent alert mail for org %s", orgId)
			}
		}
	}
	return orgStatistics
}

func SetOrgStatistics(ctx context.Context, stats ExecutionInfo, id string) error {
	nameKey := "org_statistics"

	// dedup based on date
	allDates := []string{}

	newDaily := []DailyStatistics{}
	for _, stat := range stats.OnpremStats {
		statdate := stat.Date.Format("2006-12-30")
		if !ArrayContains(allDates, statdate) {
			newDaily = append(newDaily, stat)
			allDates = append(allDates, statdate)
		}
	}

	if len(newDaily) < len(stats.OnpremStats) {
		log.Printf("[INFO] Deduped %d stats for org %s", len(stats.OnpremStats)-len(newDaily), id)
	}

	stats.OnpremStats = newDaily

	data, err := json.Marshal(stats)
	if err != nil {
		log.Printf("[ERROR] Failed marshalling in set stats: %s", err)
		return nil
	}

	if project.DbType == "opensearch" {
		err := indexEs(ctx, nameKey, id, data)
		if err != nil {
			log.Printf("[ERROR] Failed indexing in set stats: %s", err)
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if _, err := project.Dbclient.Put(ctx, key, &stats); err != nil {
			log.Printf("[ERROR] Failed adding stats with ID %s: %s", id, err)
			return err
		}

	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
		data, err := json.Marshal(data)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in set org stats: %s", err)
			return nil
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for org stats '%s': %s", cacheKey, err)
		}
	}

	return nil
}

func IncrementCacheDump(ctx context.Context, orgId, dataType string, amount ...int) {

	nameKey := "org_statistics"
	orgStatistics := &ExecutionInfo{}

	dbDumpInterval := uint8(dbInterval)
	if len(amount) > 0 {
		if amount[0] > 0 {
			dbDumpInterval = uint8(amount[0])
		}
	}

	// Get the org
	tmpOrgDetail, err := GetOrg(ctx, orgId)
	if err != nil {
		log.Printf("[ERROR] Failed getting org in increment: %s", err)
		return
	}

	cacheKey := fmt.Sprintf("OrgDetails_%s", orgId)

	if tmpOrgDetail.Id != "" {
		data, err := json.Marshal(tmpOrgDetail)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in set org stats: %s", err)
			return
		}
		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for org stats '%s': %s", cacheKey, err)
		}
	}

	if project.DbType == "opensearch" {
		// Get it from opensearch (may be prone to more issues at scale (thousands/second) due to no transactional locking)

		id := strings.ToLower(orgId)
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error in org STATS get: %s", err)
			return
		}

		defer res.Body.Close()
		respBody, bodyErr := ioutil.ReadAll(res.Body)
		if err != nil || bodyErr != nil || res.StatusCode >= 300 {
			log.Printf("[WARNING] Failed getting org STATS body: %s. Resp: %d. Body err: %s", err, res.StatusCode, bodyErr)

			// Init the org stats if it doesn't exist
			if res.StatusCode == 404 {
				orgStatistics.OrgId = orgId
				orgStatistics = HandleIncrement(dataType, orgStatistics, dbDumpInterval)
				orgStatistics = handleDailyCacheUpdate(orgStatistics)

				marshalledData, err := json.Marshal(orgStatistics)
				if err != nil {
					log.Printf("[ERROR] Failed marshalling org STATS body: %s", err)
				} else {
					err := indexEs(ctx, nameKey, id, marshalledData)
					if err != nil {
						log.Printf("[ERROR] Failed indexing org STATS body: %s", err)
					} else {
						log.Printf("[DEBUG] Indexed org STATS body for %s", orgId)
					}
				}
			}

			return
		}

		orgStatsWrapper := &ExecutionInfoWrapper{}
		err = json.Unmarshal(respBody, &orgStatsWrapper)
		if err != nil {
			log.Printf("[ERROR] Failed unmarshalling org STATS body: %s", err)
			return
		}

		orgStatistics = &orgStatsWrapper.Source
		if orgStatistics.OrgName == "" || orgStatistics.OrgName == orgStatistics.OrgId {
			org, err := GetOrg(ctx, orgId)
			if err == nil {
				orgStatistics.OrgName = org.Name
			}

			orgStatistics.OrgId = orgId
		}

		orgStatistics = HandleIncrement(dataType, orgStatistics, dbDumpInterval)
		orgStatistics = handleDailyCacheUpdate(orgStatistics)

		// Set the data back in the database
		marshalledData, err := json.Marshal(orgStatistics)
		if err != nil {
			log.Printf("[ERROR] Failed marshalling org STATS body (2): %s", err)
			return
		}

		err = indexEs(ctx, nameKey, id, marshalledData)
		if err != nil {
			log.Printf("[ERROR] Failed indexing org STATS body (2): %s", err)
		}

		//log.Printf("[DEBUG] Incremented org stats for %s", orgId)
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

		if orgStatistics.OrgName == "" || orgStatistics.OrgName == orgStatistics.OrgId {
			org, err := GetOrg(ctx, orgId)
			if err == nil {
				orgStatistics.OrgName = org.Name
			}

			orgStatistics.OrgId = orgId
		}

		orgStatistics = HandleIncrement(dataType, orgStatistics, dbDumpInterval)
		orgStatistics = handleDailyCacheUpdate(orgStatistics)

		if _, err := tx.Put(key, orgStatistics); err != nil {
			log.Printf("[WARNING] Failed setting stats: %s", err)
			tx.Rollback()
			return
		}

		if _, err = tx.Commit(); err != nil {
			log.Printf("[ERROR] Failed commiting stats: %s", err)
		}
	}

	// Could use cache for everything, really
	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, orgId)
		data, err := json.Marshal(orgStatistics)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in set org stats: %s", err)
			return
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for org stats '%s': %s", cacheKey, err)
		}
	}
}

// Rudementary caching system. WILL go wrong at times without sharding.
// It's only good for the user in cloud, hence wont bother for a while
// Optional input is the amount to increment
func IncrementCache(ctx context.Context, orgId, dataType string, amount...int) {
	// Check if environment is worker and skip
	if project.Environment == "worker" {
		//log.Printf("[DEBUG] Skipping cache increment for worker with datatype %s", dataType)
		return
	}

	//log.Printf("[DEBUG] Incrementing cache '%s' for org '%s'", dataType, orgId)

	incrementAmount := 1
	if len(amount) > 0 {
		if amount[0] > 0 {
			incrementAmount = amount[0]
		}
	}

	// Dump to disk every 0x19
	// 1. Get the existing value
	// 2. Update it
	dbDumpInterval := uint8(dbInterval)
	key := fmt.Sprintf("cache_%s_%s", orgId, dataType)
	if len(memcached) > 0 {
		item, err := mc.Get(key)
		if err == gomemcache.ErrCacheMiss {
			//log.Printf("[DEBUG] Increment memcache miss for %s: %s", key, err)

			item := &gomemcache.Item{
				Key:        key,
				Value:      []byte(string(incrementAmount)),
				Expiration: 86400,
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
					Value:      []byte(string(incrementAmount)),
					Expiration: 86400,
				}

				log.Printf("[ERROR] Value in DB is nil for cache %s.", dataType)
			}

			// Just the byte length. 
			if len(item.Value) == 1 {
				num := item.Value[0]
				num += byte(incrementAmount)
				//num += []byte{2}

				log.Printf("NEW NUM: %d", num)

				if num >= dbDumpInterval {
					// Memcache dump first to keep the counter going for other executions
					num = 0

					item := &gomemcache.Item{
						Key:        key,
						Value:      []byte(string(num)),
						Expiration: 86400,
					}
					if err := mc.Set(item); err != nil {
						log.Printf("[ERROR] Failed setting inner memcache for key %s: %s", orgId, err)
					}

					IncrementCacheDump(ctx, orgId, dataType, int(num))
				} else {
					//log.Printf("NOT Dumping!")

					item := &gomemcache.Item{
						Key:        key,
						Value:      []byte(string(num)),
						Expiration: 86400,
					}

					if err := mc.Set(item); err != nil {
						log.Printf("[ERROR] Failed setting inner memcache for key %s: %s", orgId, err)
					}
				}
			} else {
				log.Printf("[ERROR] Length of value in cache key %s is longer than 1: %d", key, len(item.Value))
			}
		}

	} else {
		// Get the cache, but use requestCache instead of memcache
		//log.Printf("[DEBUG] Incrementing cache for %s with amount %d", key, incrementAmount)
		foundItem := 1
		item, err := GetCache(ctx, key)
		if err != nil {
			if incrementAmount > int(dbDumpInterval) {
				foundItem = incrementAmount

				err = SetCache(ctx, key, []byte(fmt.Sprintf("0")), 86400)
			} else {
				err = SetCache(ctx, key, []byte(fmt.Sprintf("%d", incrementAmount)), 86400)
				if err != nil {
					log.Printf("[ERROR] Failed setting increment cache for key %s: %s", orgId, err)
				}
			}

			//log.Printf("[DEBUG] Increment cache miss for %s", key)
		} else {
			// make item into a number

			if item == nil {
				log.Printf("[ERROR] Value in DB is nil for cache %s. Setting to 1", dataType)
			} else {
				// Parse out int from []uint8 with marshal
				foundData := []byte(item.([]uint8))
				foundItem, err = strconv.Atoi(string(foundData))
				if err != nil {
					log.Printf("[ERROR] Failed converting item to int: %s", err)
					foundItem = incrementAmount
				} else {
					foundItem += incrementAmount
				}
			}
		}

		if foundItem >= int(dbDumpInterval) {
			// Memcache dump first to keep the counter going for other executions
			go SetCache(ctx, key, []byte("0"), 86400)
			IncrementCacheDump(ctx, orgId, dataType, foundItem)

			//log.Printf("[DEBUG] Dumping cache for %s with amount %d", key, foundItem)
		} else {
			// Set cacheo
			err = SetCache(ctx, key, []byte(strconv.Itoa(foundItem)), 86400)
			if err != nil {
				log.Printf("[ERROR] Failed setting increment cache for key %s: %s", orgId, err)
			}
		}

		return
	}
}

// Cache handlers
func DeleteCache(ctx context.Context, name string) error {
	if len(memcached) > 0 {
		return mc.Delete(name)
	}

	//if project.Environment == "cloud" {
	if false {
		return memcache.Delete(ctx, name)

	} else if project.Environment == "onprem" {
		requestCache.Delete(name)
		return nil
	} else {
		requestCache.Delete(name)
		return nil
	}

	return errors.New(fmt.Sprintf("No cache found for %s when DELETING cache", name))
}

// Cache handlers
func GetCache(ctx context.Context, name string) (interface{}, error) {
	if len(name) == 0 {
		log.Printf("[ERROR] No name provided for cache")
		return "", nil
	}

	name = strings.Replace(name, " ", "_", -1)

	if len(memcached) > 0 {
		item, err := mc.Get(name)
		if err == gomemcache.ErrCacheMiss {
			//log.Printf("[DEBUG] Cache miss for %s: %s", name, err)
		} else if err != nil {
			//log.Printf("[DEBUG] Failed to find cache for key %s: %s", name, err)
		} else {
			//log.Printf("[INFO] Got new cache: %s", item)

			if len(item.Value) == maxCacheSize {
				totalData := item.Value
				keyCount := 1
				keyname := fmt.Sprintf("%s_%d", name, keyCount)
				for {
					if item, err := mc.Get(keyname); err != nil {
						break
					} else {
						if totalData != nil && item != nil && item.Value != nil {
							totalData = append(totalData, item.Value...)
						}

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
					//log.Printf("[WARNING] CACHE: TOTAL SIZE FOR %s: %d", name, len(totalData))
				}
				return totalData, nil
			} else {
				return item.Value, nil
			}
		}

		return "", errors.New(fmt.Sprintf("No cache found in SHUFFLE_MEMCACHED for %s", name))
	}

	if false {

		if item, err := memcache.Get(ctx, name); err != nil {

		} else if err != nil {
			return "", errors.New(fmt.Sprintf("Failed getting CLOUD cache for %s: %s", name, err))
		} else {
			// Loops if cachesize is more than max allowed in memcache (multikey)
			if len(item.Value) == maxCacheSize {
				totalData := item.Value
				keyCount := 1
				keyname := fmt.Sprintf("%s_%d", name, keyCount)
				for {
					if item, err := memcache.Get(ctx, keyname); err != nil {
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
					//log.Printf("[WARNING] CACHE: TOTAL SIZE FOR %s: %d", name, len(totalData))
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

// Sets a key in cache. Expiration is in minutes.
func SetCache(ctx context.Context, name string, data []byte, expiration int32) error {
	// Set cache verbose
	//if strings.Contains(name, "execution") || strings.Contains(name, "action") && len(data) > 1 {
	//}

	if len(name) == 0 {
		log.Printf("[WARNING] Key '%s' is empty with value length %d and expiration %d. Skipping cache.", name, len(data), expiration)
		return nil
	}

	// Maxsize ish~
	name = strings.Replace(name, " ", "_", -1)

	// Splitting into multiple cache items
	//if project.Environment == "cloud" || len(memcached) > 0 {
	if len(memcached) > 0 {
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

				parsedData := data[currentChunk:nextStep]
				item := &memcache.Item{
					Key:        keyname,
					Value:      parsedData,
					Expiration: time.Minute * time.Duration(expiration),
				}

				var err error
				if len(memcached) > 0 {
					newitem := &gomemcache.Item{
						Key:        keyname,
						Value:      parsedData,
						Expiration: expiration * 60,
					}

					err = mc.Set(newitem)
				} else {
					err = memcache.Set(ctx, item)
				}

				if err != nil {
					if !strings.Contains(fmt.Sprintf("%s", err), "App Engine context") {
						log.Printf("[ERROR] Failed setting cache for '%s' (1): %s", keyname, err)
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
				Expiration: time.Minute * time.Duration(expiration),
			}

			var err error
			if len(memcached) > 0 {
				newitem := &gomemcache.Item{
					Key:        name,
					Value:      data,
					Expiration: expiration * 60,
				}

				err = mc.Set(newitem)
			} else {
				err = memcache.Set(ctx, item)
			}

			if err != nil {
				if !strings.Contains(fmt.Sprintf("%s", err), "App Engine context") {
					log.Printf("[WARNING] Failed setting cache for key '%s' with data size %d (2): %s", name, len(data), err)
				} else {
					log.Printf("[ERROR] Something bad with App Engine context for memcache (key: %s): %s", name, err)
				}
			}
		}

		return nil
	} else if project.Environment == "onprem" {
		requestCache.Set(name, data, time.Minute*time.Duration(expiration))
	} else {
		requestCache.Set(name, data, time.Minute*time.Duration(expiration))
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

	if project.DbType == "opensearch" {
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

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[ERROR] Failed setting cache for 'setapp' key %s: %s", cacheKey, err)

		}

		DeleteCache(ctx, fmt.Sprintf("openapi3_%s", id))
	}

	return nil
}

func SetWorkflowExecution(ctx context.Context, workflowExecution WorkflowExecution, dbSave bool) error {

	nameKey := "workflowexecution"
	if len(workflowExecution.ExecutionId) == 0 {
		log.Printf("[ERROR] Workflowexecution executionId can't be empty.")

		// Generate it on the fly?
		//workflowExecution.ExecutionId = uuid.NewV4().String()
		return errors.New("ExecutionId can't be empty.")
	}

	if len(workflowExecution.WorkflowId) == 0 {
		log.Printf("[WARNING][%s] Workflowexecution workflowId can't be empty.", workflowExecution.ExecutionId)
		workflowExecution.WorkflowId = workflowExecution.Workflow.ID
	}

	if len(workflowExecution.Authorization) == 0 {
		log.Printf("[WARNING][%s] Workflowexecution authorization can't be empty.", workflowExecution.ExecutionId)
		//workflowExecution.Authorization = uuid.NewV4().String()
		return errors.New("Authorization can't be empty.")
	}

	// Fixes missing pieces
	workflowExecution, newDbSave := Fixexecution(ctx, workflowExecution)
	if newDbSave {
		dbSave = true
	}


	cacheKey := fmt.Sprintf("%s_%s", nameKey, workflowExecution.ExecutionId)
	executionData, err := json.Marshal(workflowExecution)
	if err == nil {
		err = SetCache(ctx, cacheKey, executionData, 31)
		if err != nil {
			//log.Printf("[WARNING] Failed updating execution cache. Setting DB! %s", err)
			dbSave = true
		} else {

		}
	} else {
		//log.Printf("[ERROR] Failed marshalling execution for cache: %s", err)
		//log.Printf("[INFO] Set execution cache for workflowexecution %s", cacheKey)
	}

	// Weird workaround that only applies during local development
	hostname, err := os.Hostname()
	if err != nil || hostname == "debian" {
		hostname = "shuffle-backend"
	}

	// FIXME: This right here has caused more problems during dev than anything
	if (os.Getenv("SHUFFLE_SWARM_CONFIG") == "run" || project.Environment == "worker") && !strings.Contains(strings.ToLower(hostname), "backend") {
		//log.Printf("[INFO] Not saving execution to DB (just cache), since we are running in swarm mode.")
		return nil
	}


	// This may get data from cache, hence we need to continuously set things in the database. Mainly as a precaution.
	newexec, err := GetWorkflowExecution(ctx, workflowExecution.ExecutionId)
	HandleExecutionCacheIncrement(ctx, *newexec) 
	if !dbSave && err == nil && (newexec.Status == "FINISHED" || newexec.Status == "ABORTED") {
		log.Printf("[INFO][%s] Already finished (set workflow) with status %s! Stopping the rest of the request for execution.", workflowExecution.ExecutionId, newexec.Status)
		return nil
	}

	// Deleting cache so that listing can work well
	DeleteCache(ctx, fmt.Sprintf("%s_%s", nameKey, workflowExecution.WorkflowId))
	DeleteCache(ctx, fmt.Sprintf("%s_%s_50", nameKey, workflowExecution.WorkflowId))
	DeleteCache(ctx, fmt.Sprintf("%s_%s_100", nameKey, workflowExecution.WorkflowId))
	if !dbSave && workflowExecution.Status == "EXECUTING" && len(workflowExecution.Results) > 1 {
		//log.Printf("[WARNING][%s] SHOULD skip DB saving for execution. Status: %s", workflowExecution.ExecutionId, workflowExecution.Status)

		if project.Environment != "cloud" {
			return nil
		}

		// Randomly saving once every 5 times
		// Just making sure results are saved
		if rand.Intn(5) != 1 {
			return nil
		}
	}

	// New struct, to not add body, author etc
	//log.Printf("[DEBUG][%s] Adding execution to database, not just cache. Workflow: %s (%s)", workflowExecution.ExecutionId, workflowExecution.Workflow.Name, workflowExecution.Workflow.ID)
	if project.DbType == "opensearch" {
		// Need to fix an indexing problem?
		// "mapper [workflow.actions.position.x] cannot be changed from type [float] to [long]"

		// Position doesn't matter in execution. Maybe just set all to 0?
		for actionIndex, _ := range workflowExecution.Workflow.Actions {
			workflowExecution.Workflow.Actions[actionIndex].Position.X = float64(0)
			workflowExecution.Workflow.Actions[actionIndex].Position.Y = float64(0)
		}

		for actionIndex, _ := range workflowExecution.Workflow.Triggers {
			workflowExecution.Workflow.Triggers[actionIndex].Position.X = float64(0)
			workflowExecution.Workflow.Triggers[actionIndex].Position.Y = float64(0)
		}

		for actionIndex, _ := range workflowExecution.Workflow.Comments {
			workflowExecution.Workflow.Comments[actionIndex].Position.X = float64(0)
			workflowExecution.Workflow.Comments[actionIndex].Position.Y = float64(0)
		}

		err = indexEs(ctx, nameKey, workflowExecution.ExecutionId, executionData)
		if err != nil {
			log.Printf("[ERROR] Failed saving new execution %s: %s", workflowExecution.ExecutionId, err)
			return err
		}

		//log.Printf("[INFO] Successfully saved new execution %s. Timestamp: %d!", workflowExecution.ExecutionId, workflowExecution.StartedAt)
	} else {

		// Compresses and removes unecessary things
		workflowExecution, _ := compressExecution(ctx, workflowExecution, "db-connector save")

		// Setting to nothing as this is realtime calculated anyway
		workflowExecution.Result = ""

		// Print 1 out of X times as a debug mode
		if rand.Intn(20) == 1 {
			log.Printf("[INFO][%s] Saving execution with status %s and %d/%d results (not including subflows) - 2", workflowExecution.ExecutionId, workflowExecution.Status, len(workflowExecution.Results), len(workflowExecution.Workflow.Actions))
		}

		key := datastore.NameKey(nameKey, strings.ToLower(workflowExecution.ExecutionId), nil)
		if _, err := project.Dbclient.Put(ctx, key, &workflowExecution); err != nil {
			if strings.Contains(fmt.Sprintf("%s", err), "context deadline exceeded") {
				log.Printf("[ERROR][%s] Context deadline exceeded. Retrying...", workflowExecution.ExecutionId)
				ctx := context.Background()
				if _, err := project.Dbclient.Put(ctx, key, &workflowExecution); err != nil {
					log.Printf("[ERROR] Workflow execution Error number 1: %s", err)
				}
			} else if strings.Contains(fmt.Sprintf("%s", err), "context canceled") {
				log.Printf("[ERROR][%s] Context canceled, most likely with manual timeout: %s", workflowExecution.ExecutionId, err)
			} else {
				log.Printf("[ERROR][%s] Problem adding workflow_execution to datastore: %s", workflowExecution.ExecutionId, err)
			}

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

	UpdateExecutionVariables(ctx, workflowExecution.ExecutionId, startAction, children, parents, []string{startAction}, []string{startAction}, nextActions, environments, extra)
}

func UpdateExecutionVariables(ctx context.Context, executionId, startnode string, children, parents map[string][]string, visited, executed, nextActions, environments []string, extra int) error {
	cacheKey := fmt.Sprintf("%s-actions", executionId)

	// Get first and check if too many changes
	_, _, oldchildren, oldparents, _, _, _, _ := GetExecutionVariables(ctx, executionId)

	// Don't allow certain parts to update
	if len(oldchildren) > 0 {
		children = oldchildren
	}

	if len(oldparents) > 0 {
		parents = oldparents
	}

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

	err = SetCache(ctx, cacheKey, variableWrapperData, 30)
	if err != nil {
		log.Printf("[ERROR] Failed updating execution variables: %s", err)
		return err
	}

	return nil
}

func GetExecutionVariables(ctx context.Context, executionId string) (string, int, map[string][]string, map[string][]string, []string, []string, []string, []string) {

	cacheKey := fmt.Sprintf("%s-actions", executionId)
	wrapper := &ExecutionVariableWrapper{}
	cache, err := GetCache(ctx, cacheKey)
	if err == nil {
		cacheData := []byte(cache.([]uint8))
		err = json.Unmarshal(cacheData, &wrapper)
		if err == nil {
			return wrapper.StartNode, wrapper.Extra, wrapper.Children, wrapper.Parents, wrapper.Visited, wrapper.Executed, wrapper.NextActions, wrapper.Environments
		}
	} else {
		//log.Printf("[WARNING][%s] Failed getting cache for execution variables data %s: %s", executionId, executionId, err)
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

	bucket := project.StorageClient.Bucket(project.BucketName)
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
		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed updating execution file value: %s", err)
		}
	}

	return string(data), nil
}

func SanitizeExecution(workflowExecution WorkflowExecution) WorkflowExecution {
	sanitizeLiquid := os.Getenv("LIQUID_SANITIZE_INPUT")

	if sanitizeLiquid == "" {
		sanitizeLiquid = "true" // Set default value to "true" if not set
	}

	if project.Environment == "cloud" || sanitizeLiquid != "true" {
		if sanitizeLiquid != "true" {
			log.Printf("[WARNING] Liquid sanitization is disabled. Skipping sanitization.")
		}
		return workflowExecution
	}

	//log.Printf("[INFO] Sanitizing execution %s from liquid syntax", workflowExecution.ExecutionId)

	workflowExecution.ExecutionArgument = sanitizeString(workflowExecution.ExecutionArgument)
	for i := range workflowExecution.Results {
		workflowExecution.Results[i].Result = sanitizeString(workflowExecution.Results[i].Result)
	}

	// Sanitize ExecutionVariables
	for i := range workflowExecution.ExecutionVariables {
		workflowExecution.ExecutionVariables[i].Value = sanitizeString(workflowExecution.ExecutionVariables[i].Value)
	}

	return workflowExecution
}

func sanitizeString(input string) string {

	// Sanitize instances of {{...}}
	for strings.Contains(input, "{{") && strings.Contains(input, "}}") {
		startIndex := strings.Index(input, "{{")
		endIndex := strings.Index(input, "}}") + 2

		if startIndex >= 0 && endIndex > startIndex {
			input = input[:startIndex] + input[endIndex:]
		} else {
			break // Exit the loop if opening and closing tags don't exist for each other
		}
	}

	// Sanitize instances of {%...%}
	for strings.Contains(input, "{%") && strings.Contains(input, "%}") {
		startIndex := strings.Index(input, "{%")
		endIndex := strings.Index(input, "%}") + 2

		if startIndex >= 0 && endIndex > startIndex {
			input = input[:startIndex] + input[endIndex:]
		} else {
			break // Same here
		}
	}

	return input
}

func Fixexecution(ctx context.Context, workflowExecution WorkflowExecution) (WorkflowExecution, bool) {
	dbsave := false
	workflowExecution.Workflow.Image = ""

	// Make sure to not having missing items in the execution
	lastexecVar := map[string]ActionResult{}
	for actionIndex, action := range workflowExecution.Workflow.Actions {
		found := false
		result := ActionResult{}

		workflowExecution.Workflow.Actions[actionIndex].LargeImage = ""
		workflowExecution.Workflow.Actions[actionIndex].SmallImage = ""

		for _, innerresult := range workflowExecution.Results {
			if innerresult.Action.ID == action.ID && innerresult.Status != "WAITING" {
				found = true
				result = innerresult
				break
			}
		}

		if found {
			// Handles execution vars
			if len(action.ExecutionVariable.Name) > 0 {

				// Check if key in lastexecVar
				if _, ok := lastexecVar[action.ExecutionVariable.Name]; ok {

					if lastexecVar[action.ExecutionVariable.Name].CompletedAt > result.CompletedAt {
						lastexecVar[action.ExecutionVariable.Name] = result
					}
				} else {
					lastexecVar[action.ExecutionVariable.Name] = result
				}
			}

			continue
		}

		cacheId := fmt.Sprintf("%s_%s_result", workflowExecution.ExecutionId, action.ID)
		cache, err := GetCache(ctx, cacheId)
		if err != nil {
			//log.Printf("[WARNING] Couldn't find in fix exec %s (2): %s", cacheId, err)
			continue
		}

		cacheData := []byte(cache.([]uint8))

		// Just ensuring the data is good
		err = json.Unmarshal(cacheData, &result)
		if err == nil {
			workflowExecution.Results = append(workflowExecution.Results, result)

			if len(action.ExecutionVariable.Name) > 0 {

				// Check if key in lastexecVar
				if _, ok := lastexecVar[action.ExecutionVariable.Name]; ok {

					if lastexecVar[action.ExecutionVariable.Name].CompletedAt > result.CompletedAt {
						lastexecVar[action.ExecutionVariable.Name] = result
					}
				} else {
					lastexecVar[action.ExecutionVariable.Name] = result
				}
			}

		} else {
			log.Printf("[ERROR] Failed unmarshalling in fix exec for ID %s (1): %s", cacheId, err)
		}
	}

	// Don't forget any!!
	extra := 0
	for triggerIndex, trigger := range workflowExecution.Workflow.Triggers {
		if trigger.TriggerType != "SUBFLOW" && trigger.TriggerType != "USERINPUT" {
			continue
		}

		workflowExecution.Workflow.Triggers[triggerIndex].LargeImage = ""
		workflowExecution.Workflow.Triggers[triggerIndex].SmallImage = ""

		workflowExecution.Workflow.Triggers[triggerIndex] = trigger

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
			log.Printf("[ERROR] Failed unmarshalling in fix exec for ID %s (2): %s", cacheId, err)
		}
	}

	// Deduplicat the results
	handled := []string{}
	newResults := []ActionResult{}
	for _, result := range workflowExecution.Results {
		if result.Action.ID == "" && result.Action.Name == "" && result.Result == "" {
			log.Printf("[DEBUG][%s] Removing empty result started at %d and finished at %d", workflowExecution.ExecutionId, result.StartedAt, result.CompletedAt)
			continue
		}

		if ArrayContains(handled, result.Action.ID) {
			continue
		}

		// Checking if results are correct or not
		if project.Environment != "worker" {
			if result.Status != "WAITING" && result.Status != "SKIPPED" && (result.Action.AppName == "User Input" || result.Action.AppName == "Shuffle Workflow" || result.Action.AppName == "shuffle-subflow") {
				tmpResult, _ := parseSubflowResults(ctx, result)

				if result.Status == "SUCCESS" {
					result.Result = tmpResult.Result
				}
			}

			// Checks for subflows in waiting status
			// May also work for user input in the future
			if result.Status == "WAITING" {
				tmpResult, changed := parseSubflowResults(ctx, result)
				//log.Printf("HANDLE HERE: %s", tmpResult.Status)

				if changed && (tmpResult.Status == "SUCCESS" || tmpResult.Status == "FAILURE") {
					// Making sure we don't infinite loop :)
					// Keeping for 1 minute, as that's the rerun period
					cacheKey := fmt.Sprintf("%s_%s_sent", workflowExecution.ExecutionId, tmpResult.Action.ID)
					cache, err := GetCache(ctx, cacheKey)
					if err == nil && cache != nil {
						//SetCache(ctx, cacheKey, []byte("1"), 1)

						result = tmpResult
					} else {
						SetCache(ctx, cacheKey, []byte("1"), 1)

						log.Printf("[DEBUG][%s] Found waiting result for %s, now with status %s. Sending request to self for the full response of it", workflowExecution.ExecutionId, result.Action.ID, tmpResult.Status)

						// Forcing a resend to handle transaction normally
						actionData, err := json.Marshal(tmpResult)
						if err == nil {
							ResendActionResult(actionData, 4)
						} else {
							//result = tmpResult
						}
					}

				} else {
					//result = tmpResult
				}
			}
		}

		handled = append(handled, result.Action.ID)
		newResults = append(newResults, result)

	}

	workflowExecution.Results = newResults

	// Sort results based on CompletedAt
	sort.Slice(workflowExecution.Results, func(i, j int) bool {
		return workflowExecution.Results[i].CompletedAt < workflowExecution.Results[j].CompletedAt
	})

	for varKey, variable := range workflowExecution.Workflow.ExecutionVariables {
		for key, value := range lastexecVar {
			if key == variable.Name {
				workflowExecution.Workflow.ExecutionVariables[varKey].Value = value.Result
				break
			}
		}
	}

	// Check for failures before setting to finished
	// Update execution parent
	if workflowExecution.Status == "EXECUTING" {

		for _, result := range workflowExecution.Results {
			if result.Status == "FAILURE" || result.Status == "ABORTED" {
				log.Printf("[DEBUG][%s] Setting execution to aborted because of result %s (%s) with status '%s'. Should update execution parent if it exists (not implemented).", workflowExecution.ExecutionId, result.Action.Name, result.Action.ID, result.Status)

				workflowExecution.Status = "ABORTED"
				dbsave = true
				if workflowExecution.CompletedAt == 0 {
					workflowExecution.CompletedAt = time.Now().Unix()
				}

				break
			}
		}
	}

	// Check if finished too?
	finalWorkflowExecution := SanitizeExecution(workflowExecution)
	if workflowExecution.Status == "EXECUTING" && len(workflowExecution.Results) == len(workflowExecution.Workflow.Actions)+extra {

		skipFinished := false
		for _, result := range workflowExecution.Results {
			if result.Status == "WAITING" {
				skipFinished = true
				break
			}
		}

		if !skipFinished {
			log.Printf("[DEBUG][%s] Setting execution to finished because all results are in and it was still in EXECUTING mode. Should set subflow parent result as well (not implemented).", workflowExecution.ExecutionId)

			finalWorkflowExecution.Status = "FINISHED"
			dbsave = true
			if finalWorkflowExecution.CompletedAt == 0 {
				finalWorkflowExecution.CompletedAt = time.Now().Unix()
			}
		}
	}

	// Cleaning up values as they shouldn't exist anymore in actions
	// after a result has been found for it.
	for resIndex, result := range finalWorkflowExecution.Results {
		if result.Status != "FINISHED" && result.Status != "SUCCESS" && result.Status != "ABORTED" {
			continue
		}

		cleaned := false
		for paramIndex, param := range result.Action.Parameters {
			if param.Configuration {
				finalWorkflowExecution.Results[resIndex].Action.Parameters[paramIndex].Value = ""
			}

			finalWorkflowExecution.Results[resIndex].Action.Parameters[paramIndex].Example = ""
			finalWorkflowExecution.Results[resIndex].Action.Parameters[paramIndex].Description = ""
		}

		if cleaned {
			for actionIndex, action := range finalWorkflowExecution.Workflow.Actions {
				if action.ID != result.Action.ID {
					continue
				}

				for paramIndex, param := range action.Parameters {
					if param.Configuration {
						finalWorkflowExecution.Workflow.Actions[actionIndex].Parameters[paramIndex].Value = ""
					}

					finalWorkflowExecution.Workflow.Actions[actionIndex].Parameters[paramIndex].Example = ""
					finalWorkflowExecution.Workflow.Actions[actionIndex].Parameters[paramIndex].Description = ""
				}
			}
		}
	}

	// Update WorkflowExecution.Result to be correct, as to return correct for:
	// - Subflows with wait for response
	// - Webhooks v2 with for response
	if finalWorkflowExecution.Status == "ABORTED" {
		finalWorkflowExecution.Result = finalWorkflowExecution.Workflow.DefaultReturnValue
	} else if (len(finalWorkflowExecution.Result) == 0 || finalWorkflowExecution.Result == finalWorkflowExecution.Workflow.DefaultReturnValue) && finalWorkflowExecution.Status == "FINISHED" {
		//log.Printf("\n\n[DEBUG] Finding new response value\n\n")
		lastResult := ""
		lastCompleted := int64(-1)
		for _, result := range finalWorkflowExecution.Results {
			if result.Status == "SUCCESS" && result.CompletedAt > lastCompleted {
				lastResult = result.Result
				lastCompleted = result.CompletedAt
			}
		}

		if len(lastResult) > 0 {
			finalWorkflowExecution.Result = lastResult
		} else {
			if len(finalWorkflowExecution.Result) == 0 && len(finalWorkflowExecution.Workflow.DefaultReturnValue) > 0 {
				finalWorkflowExecution.Result = finalWorkflowExecution.Workflow.DefaultReturnValue
			}
		}
	}

	return finalWorkflowExecution, dbsave
}

func GetWorkflowExecutionByAuth(ctx context.Context, authId string) (*WorkflowExecution, error) {
	nameKey := "workflowexecution"
	cacheKey := fmt.Sprintf("%s_auth_%s", nameKey, authId)

	workflowExecution := &WorkflowExecution{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &workflowExecution)
			if err == nil {
				return workflowExecution, nil
			}
		}
	}

	if project.DbType == "opensearch" {
		return workflowExecution, errors.New("Not implemented")
	} else {
		// Google datastore search based on "authorization ="
		allExecutions := []*WorkflowExecution{}
		q := datastore.NewQuery(nameKey).Filter("authorization =", authId).Limit(1)
		_, err := project.Dbclient.GetAll(ctx, q, &allExecutions)
		if err != nil {
			log.Printf("[WARNING] Failed getting workflow execution by auth: %s", err)
			return nil, err
		} else {
			if len(allExecutions) > 0 {
				workflowExecution = allExecutions[0]
			}
		}
	}

	if project.CacheDb {
		//log.Printf("[DEBUG] Caching workflow execution %s", cacheKey)
		workflowExecutionJson, err := json.Marshal(workflowExecution)
		if err == nil {
			err := SetCache(ctx, cacheKey, workflowExecutionJson, 10)
			if err != nil {
				log.Printf("[WARNING] Failed caching workflow execution %s: %s", cacheKey, err)
			}
		}
	}

	return workflowExecution, nil
}

func GetWorkflowExecution(ctx context.Context, id string) (*WorkflowExecution, error) {
	nameKey := "workflowexecution"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)

	workflowExecution := &WorkflowExecution{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
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
						log.Printf("[DEBUG][%s] Failed to parse in execution file value for exec argument: %s (3)", workflowExecution.ExecutionId, err)
					} else {
						//log.Printf("[DEBUG][%s] Found a new value to parse with exec argument", workflowExecution.ExecutionId)
						workflowExecution.ExecutionArgument = newValue
					}
				}

				for valueIndex, value := range workflowExecution.Results {
					if strings.Contains(value.Result, "Result too large to handle") {
						newValue, err := getExecutionFileValue(ctx, *workflowExecution, value)
						if err != nil {
							continue
						}

						workflowExecution.Results[valueIndex].Result = newValue
					}
				}

				// Fixes missing pieces
				newexec, _ := Fixexecution(ctx, *workflowExecution)
				workflowExecution = &newexec

				return workflowExecution, nil
			} else {
				//log.Printf("[WARNING] Failed getting workflowexecution: %s", err)
			}
		} else {
		}
	}

	if (os.Getenv("SHUFFLE_SWARM_CONFIG") == "run" || project.Environment == "worker") && project.Environment != "cloud" {
		return workflowExecution, errors.New("ExecutionId doesn't exist in cache")
	}

	if project.DbType == "opensearch" {
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING][%s] Error for %s: %s", workflowExecution.ExecutionId, cacheKey, err)
			return workflowExecution, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return workflowExecution, errors.New("execution doesn't exist")
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
			return workflowExecution, err
		}

		// A workaround for large bits of information for execution argument
		if strings.Contains(workflowExecution.ExecutionArgument, "Result too large to handle") {
			//log.Printf("[DEBUG] Found prefix %s to be replaced for exec argument (3)", workflowExecution.ExecutionArgument)
			baseArgument := &ActionResult{
				Result: workflowExecution.ExecutionArgument,
				Action: Action{ID: "execution_argument"},
			}
			newValue, err := getExecutionFileValue(ctx, *workflowExecution, *baseArgument)
			if err != nil {
				log.Printf("[DEBUG] Failed to parse in execution file value for exec argument: %s (4)", err)
			} else {
				//log.Printf("[DEBUG] Found a new value to parse with exec argument")
				workflowExecution.ExecutionArgument = newValue
			}
		}

		// Parsing as file.
		//log.Printf("[DEBUG] Got execution %s. Results: ~%d/%d", id, len(workflowExecution.Results), len(workflowExecution.Workflow.Actions))
		for valueIndex, value := range workflowExecution.Results {
			if strings.Contains(value.Result, "Result too large to handle") {
				//log.Printf("[DEBUG] Found prefix %s to be replaced (2)", value.Result)
				newValue, err := getExecutionFileValue(ctx, *workflowExecution, value)
				if err != nil {
					log.Printf("[DEBUG] Failed to parse in execution file value %s (5)", err)
					continue
				}

				workflowExecution.Results[valueIndex].Result = newValue
			}
		}
	}

	//log.Printf("[DEBUG] Returned execution %s with %d results (1)", id, len(workflowExecution.Results))

	// Fixes missing pieces
	newexec, _ := Fixexecution(ctx, *workflowExecution)
	workflowExecution = &newexec

	//log.Printf("[DEBUG] Returned execution %s with %d results (2)", id, len(workflowExecution.Results))

	if project.CacheDb && workflowExecution.Authorization != "" {
		newexecution, err := json.Marshal(workflowExecution)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling execution: %s", err)
			return workflowExecution, nil
		}

		err = SetCache(ctx, id, newexecution, 30)
		if err != nil {
			log.Printf("[WARNING] Failed updating execution: %s", err)
		}
	}

	return workflowExecution, nil
}

func getCloudFileApp(ctx context.Context, workflowApp WorkflowApp, id string) (WorkflowApp, error) {
	if len(workflowApp.Name) == 0 {
		return workflowApp, nil
	}
	//project.BucketName := project.BucketName

	if strings.HasSuffix(id, ".") {
		id = id[:len(id)-1]
	}

	fullParsedPath := fmt.Sprintf("extra_specs/%s/appspec.json", id)
	//log.Printf("[DEBUG] Couldn't find working app for app with ID %s. Checking filepath gs://%s/%s (size too big)", id, project.BucketName, fullParsedPath)
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
		// Set cache anyway
		if project.CacheDb {
			data, err := json.Marshal(workflowApp)
			if err != nil {
				log.Printf("[WARNING] Failed marshalling app: %s", err)
				return workflowApp, nil
			}

			err = SetCache(ctx, cacheKey, data, 30)
			if err != nil {
				log.Printf("[WARNING] Failed updating app: %s", err)
			}
		}

		//log.Printf("[ERROR] Failed making App reader for %s: %s", fullParsedPath, err)
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

	//log.Printf("[DEBUG] Got new file data for app with ID %s from filepath gs://%s/%s with %d actions", id, project.BucketName, fullParsedPath, len(workflowApp.Actions))
	if project.CacheDb {
		data, err := json.Marshal(workflowApp)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in get cloud app cache: %s", err)
			return workflowApp, nil
		}

		err = SetCache(ctx, cacheKey, data, 1440)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for get cloud app cache key '%s': %s", cacheKey, err)
		}
	}

	defer fileReader.Close()
	return workflowApp, nil
}

func GetApp(ctx context.Context, id string, user User, skipCache bool) (*WorkflowApp, error) {
	workflowApp := &WorkflowApp{}
	if len(id) == 0 {
		return workflowApp, errors.New("No ID provided to get an app")
	}

	if id == "integration" {
		return workflowApp, errors.New("App ID 'integration' is for the integration framework. Uses the Shuffle-ai app.")
	}

	nameKey := "workflowapp"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)

	if !skipCache && project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)

		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &workflowApp)
			if err == nil {

				// Grabbing extra files necessary
				if (len(workflowApp.ID) == 0 || len(workflowApp.Actions) == 0) && project.Environment == "cloud" {
					tmpApp, err := getCloudFileApp(ctx, *workflowApp, id)

					if err == nil {
						log.Printf("[DEBUG] Got app '%s' (%s) with %d actions from file (cache)", workflowApp.Name, workflowApp.ID, len(tmpApp.Actions))
						workflowApp = &tmpApp
						return workflowApp, nil
					} else {
						//log.Printf("[DEBUG] Failed remote loading app '%s' (%s) from file (cache): %s", workflowApp.Name, workflowApp.ID, err)
					}
				} else {
					return workflowApp, nil
				}
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for org: %s", err)
		}
	} else {
		//log.Printf("[DEBUG] Skipping cache check in get app for ID %s", id)
	}

	if project.DbType == "opensearch" {
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
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
		//log.Printf("[DEBUG] Getting app from datastore for ID %s", id)

		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		err := project.Dbclient.Get(ctx, key, workflowApp)

		//log.Printf("\n\n[DEBUG] Actions in %s (%s): %d. Err: %s", workflowApp.Name, strings.ToLower(id), len(workflowApp.Actions), err)

		if err != nil || len(workflowApp.Actions) == 0 {
			if strings.Contains(fmt.Sprintf("%s", err), "no such entity") {
				return workflowApp, errors.New("App doesn't exist")
			}

			//log.Printf("[WARNING] Failed getting app in GetApp with name %s and ID %s. Actions: %d. Getting if EITHER is bad or 0. Err: %s", workflowApp.Name, id, len(workflowApp.Actions), err)
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
					//log.Printf("[DEBUG] Got app %s (%s) with %d actions from file", workflowApp.Name, workflowApp.ID, len(tmpApp.Actions))
					workflowApp = &tmpApp
				} else {
					//log.Printf("[DEBUG] Failed remote loading app  %s (%s) from file: %s", workflowApp.Name, workflowApp.ID, err)
				}

			} else {
				log.Printf("[DEBUG] Returning %s (%s) normally", workflowApp.Name, id)
			}
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(workflowApp)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getapp: %s", err)
			return workflowApp, nil
		}

		err = SetCache(ctx, cacheKey, data, 1440)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getapp key '%s': %s", cacheKey, err)
		}
	}

	if workflowApp.ID == "" {
		return workflowApp, errors.New(fmt.Sprintf("Couldn't find app %s", id))
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
	if project.DbType == "opensearch" {
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
		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for setworkflow key '%s': %s", cacheKey, err)
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
			err = json.Unmarshal(cacheData, &sub)
			if err == nil {
				return sub, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for sub: %s", err)
		}
	}

	if project.DbType == "opensearch" {
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
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

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getsub key '%s': %s", cacheKey, err)
		}
	}

	return sub, nil
}

// No deduplication for popular files
func FindSimilarFilename(ctx context.Context, filename, orgId string) ([]File, error) {
	//log.Printf("\n\n[DEBUG] Getting query %s for orgId %s\n\n", id, orgId)
	files := []File{}
	nameKey := "Files"

	cacheKey := fmt.Sprintf("%s_%s_%s", nameKey, orgId, filename)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &files)
			if err == nil {
				return files, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for file: %s", err)
		}
	}

	if project.DbType == "opensearch" {
		var buf bytes.Buffer

		// Or search?
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": []map[string]interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"filename": filename,
							},
						},
						map[string]interface{}{
							"match": map[string]interface{}{
								"org_id": orgId,
							},
						},
					},
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return files, nil
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (find file filename): %s", err)
			return files, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return files, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
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

		if len(wrapped.Hits.Hits) == 1 && len(orgId) == 0 && wrapped.Hits.Hits[0].Source.Status == "active" && wrapped.Hits.Hits[0].Source.Md5sum == filename {
			files = append(files, wrapped.Hits.Hits[0].Source)
		} else {
			//file = []Environment{}
			for _, hit := range wrapped.Hits.Hits {
				if hit.Source.Md5sum != filename {
					continue
				}

				if hit.Source.OrgId == orgId && hit.Source.Status == "active" {
					files = append(files, hit.Source)
				}

			}
		}
	} else {
		query := datastore.NewQuery(nameKey).Filter("filename =", filename).Limit(25)
		_, err := project.Dbclient.GetAll(ctx, query, &files)
		if err != nil {
			log.Printf("[WARNING] Failed getting deals for org: %s", orgId)
			return files, err
		} else {
			//log.Printf("[INFO] Got %d files for filename: %s", len(files), filename)
			parsedFiles := []File{}
			for _, newfile := range files {
				if newfile.OrgId == orgId && newfile.Status == "active" {
					parsedFiles = append(parsedFiles, newfile)
				}
			}

			//log.Printf("[INFO] Got %d PARSD files for filename: %s", len(parsedFiles), md5)

			if len(parsedFiles) == 0 {
				return parsedFiles, errors.New(fmt.Sprintf("No file found for filename: %s", filename))
				//log.Printf("[INFO] Couldn't find file with md5 %s for org %s", md5, orgId)
			}

			files = parsedFiles
		}
	}

	//log.Printf("[DEBUG] Got hit: %s", file)

	if project.CacheDb {
		//log.Printf("[DEBUG] Setting cache for workflow %s", cacheKey)
		data, err := json.Marshal(files)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in find file md5 : %s", err)
			return files, nil
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for find file md5 %s: %s", cacheKey, err)
		}
	}

	return files, nil
}

// Check OrgId later
// No deduplication for popular files
func FindSimilarFile(ctx context.Context, md5, orgId string) ([]File, error) {
	//log.Printf("\n\n[DEBUG] Getting query %s for orgId %s\n\n", id, orgId)
	files := []File{}
	nameKey := "Files"

	cacheKey := fmt.Sprintf("%s_%s_%s", nameKey, orgId, md5)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &files)
			if err == nil {
				return files, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for file: %s", err)
		}
	}

	if project.DbType == "opensearch" {
		var buf bytes.Buffer

		// Or search?
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": []map[string]interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"md5_sum": md5,
							},
						},
						map[string]interface{}{
							"match": map[string]interface{}{
								"org_id": orgId,
							},
						},
					},
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return files, nil
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (find file md5): %s", err)
			return files, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return files, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
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

		if len(wrapped.Hits.Hits) == 1 && len(orgId) == 0 && wrapped.Hits.Hits[0].Source.Status == "active" && wrapped.Hits.Hits[0].Source.Md5sum == md5 {
			files = append(files, wrapped.Hits.Hits[0].Source)
		} else {
			//file = []Environment{}
			for _, hit := range wrapped.Hits.Hits {
				if hit.Source.Md5sum != md5 {
					continue
				}

				if hit.Source.OrgId == orgId && hit.Source.Status == "active" {
					files = append(files, hit.Source)
				}

			}
		}
	} else {
		query := datastore.NewQuery(nameKey).Filter("md5_sum =", md5).Limit(250)
		_, err := project.Dbclient.GetAll(ctx, query, &files)
		if err != nil {
			log.Printf("[WARNING] Failed getting deals for org: %s", orgId)
			return files, err
		} else {
			//log.Printf("[INFO] Got %d files for md5: %s", len(files), md5)
			parsedFiles := []File{}
			for _, newfile := range files {
				if newfile.OrgId == orgId && newfile.Status == "active" {
					parsedFiles = append(parsedFiles, newfile)
				}
			}

			//log.Printf("[INFO] Got %d PARSD files for md5: %s", len(parsedFiles), md5)

			if len(parsedFiles) == 0 {
				return parsedFiles, errors.New(fmt.Sprintf("No file found for md5: %s", md5))
				//log.Printf("[INFO] Couldn't find file with md5 %s for org %s", md5, orgId)
			}

			files = parsedFiles
		}
	}

	//log.Printf("[DEBUG] Got hit: %s", file)

	if project.CacheDb {
		//log.Printf("[DEBUG] Setting cache for workflow %s", cacheKey)
		data, err := json.Marshal(files)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in find file md5 : %s", err)
			return files, nil
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for find file md5 %s: %s", cacheKey, err)
		}
	}

	return files, nil
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
			err = json.Unmarshal(cacheData, &env)
			if err == nil {
				return env, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for env: %s", err)
		}
	}

	if project.DbType == "opensearch" {
		var buf bytes.Buffer

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
			"sort": map[string]interface{}{
				"created": map[string]interface{}{
					"order": "desc",
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return env, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
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

		log.Printf("[DEBUG] Got %d environments for id: %s", len(wrapped.Hits.Hits), id)

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

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getenv '%s: %s", cacheKey, err)
		}
	}

	return env, nil
}

func GetWorkflowRunCount(ctx context.Context, id string, start int64, end int64) (int, error) {
	var err error
	nameKey := "workflowexecution"
	cacheKey := fmt.Sprintf("%s_count_%s_%s_%s", nameKey, id, strconv.FormatInt(start, 10), strconv.FormatInt(end, 10))

	count := 0

	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			count, err = strconv.Atoi(string(cacheData))
			if err == nil {
				//log.Printf("[DEBUG] Got count %d from cache for workflow id %s", count, id)
				return count, nil
			}
		}
		//log.Printf("[DEBUG] Failed getting count cache for workflow id %s: %s", id, err)
	}

	if project.DbType == "opensearch" {
		// count WorkflowExecution where workflowId = id
		query := map[string]interface{}{
			"size": 0,
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": []map[string]interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"workflow_id": id,
							},
						},
						map[string]interface{}{
							"range": map[string]interface{}{
								"started_at": map[string]interface{}{
									"gte": start,
									"lte": end,
								},
							},
						},
					},
				},
			},
		}

		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding get workflow run count query: %s", err)
			return 0, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)

		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get workflow run count): %s", err)
			return 0, err
		}

		defer res.Body.Close()

		if res.StatusCode == 404 {
			return 0, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return 0, err
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
			return 0, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return 0, err
		}

		wrapped := ExecutionSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return 0, err
		}

		count = wrapped.Hits.Total.Value
	} else {
		// count WorkflowExecution where workflowId = id
		//query := datastore.NewQuery(nameKey).Filter("workflow_id =", strings.ToLower(id))

		query := datastore.NewQuery(nameKey).Filter("workflow_id =", strings.ToLower(id)).Filter("started_at >=", start).Filter("started_at <=", end)
		count, err = project.Dbclient.Count(ctx, query)
		if err != nil {
			log.Printf("[WARNING] Failed getting count for workflow %s : %s", id, err)
			return 0, err
		}
	}

	// count int to []byte
	countStr := strconv.Itoa(count)
	countBytes := []byte(countStr)
	if project.CacheDb {
		//log.Printf("[DEBUG] Setting cache count for workflow id %s count: %s", id, countStr)

		err := SetCache(ctx, cacheKey, countBytes, 1440)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for workflow id %s count: %s", id, err)
		}
	}

	return count, nil
}

func GetAllChildOrgs(ctx context.Context, orgId string) ([]Org, error) {
	orgs := []Org{}
	nameKey := "Organizations"

	cacheKey := fmt.Sprintf("%s_childorgs", orgId)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &orgs)
			if err == nil && len(orgs) > 0 {
				return orgs, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for workflow: %s", err)
		}
	}

	if project.DbType == "opensearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"creator_org": orgId,
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return orgs, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (Get workflows 2): %s", err)
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

		for _, hit := range wrapped.Hits.Hits {
			if hit.Source.CreatorOrg != orgId {
				continue
			}

			orgs = append(orgs, hit.Source)
		}
	} else {
		// Cloud database
		query := datastore.NewQuery(nameKey).Filter("creator_org =", orgId).Limit(1000)

		_, err := project.Dbclient.GetAll(ctx, query, &orgs)
		if err != nil {
			return orgs, err
		}
	}

	if project.CacheDb && len(orgs) > 0 {
		//log.Printf("[DEBUG] Setting cache for workflow %s", cacheKey)
		data, err := json.Marshal(orgs)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getchildorgs: %s", err)
			return orgs, nil
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getworkflow '%s': %s", cacheKey, err)
		}
	}

	return orgs, nil
}

func GetWorkflow(ctx context.Context, id string) (*Workflow, error) {
	workflow := &Workflow{}
	nameKey := "workflow"

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &workflow)
			if err == nil && workflow.ID != "" {
				return workflow, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for workflow: %s", err)
		}
	}

	if project.DbType == "opensearch" {
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
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
			if strings.Contains(err.Error(), `no such entity`) {
				query := datastore.NewQuery(nameKey).Filter("id =", strings.ToLower(id)).Limit(1)
				var workflows []Workflow
				if _, err := project.Dbclient.GetAll(ctx, query, &workflows); err != nil {
					return &Workflow{}, err
				}

				if len(workflows) == 1 {
					workflow = &workflows[0]
				}
			} else if strings.Contains(err.Error(), `cannot load field`) {
				log.Printf("[ERROR] Error in workflow loading. Migrating workflow to new workflow handler (1): %s", err)
				err = nil
			} else {
				return &Workflow{}, err
			}
		}
	}

	newWorkflow := FixWorkflowPosition(ctx, *workflow)
	workflow = &newWorkflow

	if project.CacheDb && workflow.ID != "" {
		//log.Printf("[DEBUG] Setting cache for workflow %s", cacheKey)
		data, err := json.Marshal(workflow)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getworkflow: %s", err)
			return workflow, nil
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getworkflow '%s': %s", cacheKey, err)
		}
	}

	return workflow, nil
}

func GetOrgStatistics(ctx context.Context, orgId string) (*ExecutionInfo, error) {
	nameKey := "org_statistics"
	stats := &ExecutionInfo{}
	cacheKey := fmt.Sprintf("%s_%s", nameKey, orgId)

	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &stats)
			if err == nil {
				return stats, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for stats: %s", err)
		}
	}

	if project.DbType == "opensearch" {
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), orgId)
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
			return stats, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return stats, errors.New(fmt.Sprintf("Org stats for %s doesn't exist", orgId))
		}

		defer res.Body.Close()
		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return stats, err
		}

		wrapped := ExecutionInfoWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return stats, err
		}

		stats = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(orgId), nil)
		if err := project.Dbclient.Get(ctx, key, stats); err != nil {
			if strings.Contains(err.Error(), `cannot load field`) {
				log.Printf("[INFO] Error in org loading (1). Migrating org to new org and user handler (3): %s", err)
				err = nil
			} else {
				return stats, err
			}
		}
	}

	if project.CacheDb {
		//log.Printf("[DEBUG] Setting cache for stats %s", cacheKey)
		data, err := json.Marshal(stats)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in get stats: %s", err)
			return stats, nil
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for get stats'%s': %s", cacheKey, err)
		}
	}

	return stats, nil
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

	// Cache

	var err error
	cacheKey := fmt.Sprintf("%s_workflows", user.ActiveOrg.Id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &workflows)
			if err == nil {
				return workflows, nil
			}
		}
	}

	// Appending the users' workflows
	nameKey := "workflow"
	log.Printf("[AUDIT] Getting workflows for user %s (%s - %s)", user.Username, user.Role, user.Id)
	if project.DbType == "opensearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": []map[string]interface{}{
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
			project.Es.Search.WithContext(ctx),
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
			if hit.Source.ID == "" {
				continue
			}

			if hit.Source.Owner == user.Id || hit.Source.OrgId == user.ActiveOrg.Id {
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
				project.Es.Search.WithContext(ctx),
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
				if hit.Source.ID == "" {
					continue
				}

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

			log.Printf("[INFO] Appending workflows (ADMIN + suborg distribution) for organization %s. Already have %d workflows for the user. Found %d (%d new) for org. New unique amount: %d (1)", user.ActiveOrg.Id, userWorkflowLen, len(wrapped.Hits.Hits), len(workflows)-userWorkflowLen, len(workflows))
		}

	} else {
		log.Printf("[INFO] Appending workflows (ADMIN) for organization %s (2)", user.ActiveOrg.Id)
		if len(user.ActiveOrg.Id) > 0 {
			query := datastore.NewQuery(nameKey).Filter("org_id =", user.ActiveOrg.Id).Limit(limit)

			cursorStr := ""
			for {
				it := project.Dbclient.Run(ctx, query)

				for {
					innerWorkflow := Workflow{}
					_, err = it.Next(&innerWorkflow)
					if err != nil {
						if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
							log.Printf("[ERROR] Fixing workflow %s to have proper org (0.8.74)", innerWorkflow.ID)
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
					log.Printf("[INFO] Failed fetching workflow results: %v", err)
					break
				}

				// Get the cursor for the next page of results.
				nextCursor, err := it.Cursor()
				if err != nil {
					log.Printf("Cursorerror: %s", err)
					break
				} else {
					nextStr := fmt.Sprintf("%s", nextCursor)
					if cursorStr == nextStr {
						break
					}

					cursorStr = nextStr
					query = query.Start(nextCursor)
				}
			}

			log.Printf("[INFO] Appending suborg distribution workflows for organization %s (%s)", user.ActiveOrg.Name, user.ActiveOrg.Id)
			cursorStr = ""
			query = datastore.NewQuery(nameKey).Filter("suborg_distribution =", user.ActiveOrg.Id)
			for {
				it := project.Dbclient.Run(ctx, query)

				for {
					innerWorkflow := Workflow{}
					_, err = it.Next(&innerWorkflow)
					//log.Printf("[DEBUG] SUBFLOW: %#v", innerWorkflow.ID)

					if err != nil {
						if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
							log.Printf("[ERROR] Error in workflow loading. Migrating workflow to new workflow handler (1): %s", err)
						} else if strings.Contains(fmt.Sprintf("%s", err), "no more items in iterator") {
							break
						} else {
							log.Printf("[ERROR] Error in suborg workflow iterator: %s", err)
							break
						}
					}

					log.Printf("[DEBUG] Got suborg workflow %s (%s)", innerWorkflow.Name, innerWorkflow.ID)

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

				// FIXME: Handle nil?
				if err != iterator.Done {
					//log.Printf("[INFO] Failed fetching suborg workflows: %v", err)
					break
				}

				// Get the cursor for the next page of results.
				nextCursor, err := it.Cursor()
				if err != nil {
					log.Printf("Cursorerror: %s", err)
					break
				} else {
					nextStr := fmt.Sprintf("%s", nextCursor)
					if cursorStr == nextStr {
						break
					}

					cursorStr = nextStr
					query = query.Start(nextCursor)
				}
			}
		}
	}

	fixedWorkflows := []Workflow{}
	for _, workflow := range workflows {
		if workflow.Hidden {
			continue
		}

		if len(workflow.Name) == 0 && len(workflow.Actions) <= 1 {
			continue
		}

		if len(workflow.OrgId) == 0 && len(workflow.Owner) == 0 {
			log.Printf("[ERROR] Workflow %s has no org or owner", workflow.ID)
			continue
		}

		fixedWorkflows = append(fixedWorkflows, workflow)
	}

	slice.Sort(fixedWorkflows[:], func(i, j int) bool {
		return fixedWorkflows[i].Edited > fixedWorkflows[j].Edited
	})

	if project.CacheDb {
		newjson, err := json.Marshal(fixedWorkflows)
		if err != nil {
			return fixedWorkflows, nil
		}

		err = SetCache(ctx, cacheKey, newjson, 60)
		if err != nil {
			log.Printf("[WARNING] Failed updating workflow cache: %s", err)
		}
	}

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


func GetOrgByCreatorId(ctx context.Context, id string) (*Org, error) {
	nameKey := "Organizations"
	cacheKey := fmt.Sprintf("creator_%s_%s", nameKey, id)

	curOrg := &Org{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &curOrg)
			if err == nil {
				return curOrg, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for org: %s", err)
		}
	}

	setOrg := false
	if project.DbType == "opensearch" {
	} else {
		query := datastore.NewQuery(nameKey).Filter("creator_id =", id).Limit(1)

		allOrgs := []Org{}
		_, err := project.Dbclient.GetAll(ctx, query, &allOrgs)
		if err != nil {
			return curOrg, err
		}

		if len(allOrgs) > 0 {
			curOrg = &allOrgs[0]
		}
	}

	// How does this happen?
	if len(curOrg.Id) == 0 {
		curOrg.Id = id
		return curOrg, errors.New(fmt.Sprintf("Couldn't find creator org with ID %s", curOrg.Id))
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
		curOrg = GetTutorials(ctx, *curOrg, true)
	}

	// Making sure to skip old irrelevant priorities
	newPriorities := []Priority{}
	for _, priority := range curOrg.Priorities {
		if priority.Type == "usecases" {
			continue
		}

		newPriorities = append(newPriorities, priority)
	}

	curOrg.Priorities = newPriorities
	if project.CacheDb {
		neworg, err := json.Marshal(curOrg)
		if err != nil {
			log.Printf("[ERROR] Failed marshalling org for cache: %s", err)
			return curOrg, nil
		}

		err = SetCache(ctx, cacheKey, neworg, 1440)
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
			err = json.Unmarshal(cacheData, &curOrg)
			if err == nil {
				return curOrg, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for org: %s", err)
		}
	}

	setOrg := false
	if project.DbType == "opensearch" {
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
			log.Printf("[WARNING] Failed getting org '%s' - status: 404 - %s", id, string(respBody))
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
			log.Printf("[ERROR] Error in org loading (2) for %s: %s", key, err)
			//log.Printf("Users: %s", curOrg.Users)
			if strings.Contains(err.Error(), `cannot load field`) && strings.Contains(err.Error(), `users`) {
				//Self correcting Org handler for user migration. This may come in handy if we change the structure of private apps later too.
				log.Printf("[INFO] Error in org loading (3). Migrating org to new org and user handler (2): %s", err)
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
				log.Printf("[WARNING] Error in org loading (4), but returning without warning: %s", err)
				err = nil
			} else {
				return &Org{}, err
			}
		}
	}

	// How does this happen?
	if len(curOrg.Id) == 0 {
		curOrg.Id = id
		return curOrg, errors.New(fmt.Sprintf("Couldn't find org with ID '%s'", curOrg.Id))
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
		curOrg = GetTutorials(ctx, *curOrg, true)
	}

	// Making sure to skip old irrelevant priorities
	newPriorities := []Priority{}
	for _, priority := range curOrg.Priorities {
		if priority.Type == "usecases" {
			continue
		}

		newPriorities = append(newPriorities, priority)
	}

	// Check if Subscription is from BEFORE November 4th 2023

	eulaSigned := false
	if len(curOrg.Subscriptions) > 1 {
		replicas := map[string]int64{}
		for orgIndex, sub := range curOrg.Subscriptions {
			if sub.EulaSigned {
				eulaSigned = true
			}

			if sub.Startdate == 0 || sub.Startdate < 1699053459 {
				curOrg.Subscriptions[orgIndex].EulaSigned = true
			}

			if _, ok := replicas[sub.Name]; ok {
				if replicas[sub.Name] > sub.Startdate {
					log.Printf("[DEBUG] Removing subscription %s from org %s", sub.Name, curOrg.Id)

					replicas[sub.Name] = sub.Startdate
				}
			} else {
				replicas[sub.Name] = sub.Startdate
			}
		}

		newsubs := []PaymentSubscription{}
		for key, value := range replicas {
			foundsub := PaymentSubscription{}
			for _, sub := range curOrg.Subscriptions {
				if sub.Name == key && sub.Startdate == value {
					foundsub = sub
					break
				}
			}

			if foundsub.Name != "" {
				foundsub.EulaSigned = eulaSigned
				newsubs = append(newsubs, foundsub)
			}
		}

		if len(newsubs) > 0 {
			curOrg.Subscriptions = newsubs
			//log.Printf("[DEBUG] New subscriptions for org %s: %d", curOrg.Id, len(newsubs))
		}
	}

	curOrg.Priorities = newPriorities
	if project.CacheDb {
		neworg, err := json.Marshal(curOrg)
		if err != nil {
			log.Printf("[ERROR] Failed marshalling org for cache: %s", err)
			return curOrg, nil
		}

		err = SetCache(ctx, cacheKey, neworg, 1440)
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

func GetFirstOrg(ctx context.Context) (*Org, error) {
	nameKey := "Organizations"

	curOrg := &Org{}
	if project.DbType == "opensearch" {
		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get first org): %s", err)
			return curOrg, err
		}

		defer res.Body.Close()
		if res.StatusCode != 200 && res.StatusCode != 201 {
			return curOrg, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return curOrg, err
		}

		wrapped := OrgSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return curOrg, err
		}

		if len(wrapped.Hits.Hits) > 0 {
			for _, hit := range wrapped.Hits.Hits {
				if len(hit.Source.Id) > 0 && len(hit.Source.Users) > 0 {
					curOrg = &hit.Source
					break
				}
			}

			if curOrg.Id == "" {
				log.Printf("[ERROR] No orgs found with users & an ID, returning first org")
				curOrg = &wrapped.Hits.Hits[0].Source
			}
		} else {
			return curOrg, errors.New("No orgs found")
		}

	} else {
		query := datastore.NewQuery(nameKey).Limit(1)
		allOrgs := []Org{}
		_, err := project.Dbclient.GetAll(ctx, query, &allOrgs)
		if err != nil {
			return curOrg, err
		}

		if len(allOrgs) > 0 {
			curOrg = &allOrgs[0]
		} else {
			return curOrg, errors.New("No orgs found")
		}
	}

	return curOrg, nil
}

func indexEs(ctx context.Context, nameKey, id string, bytes []byte) error {
	//req := esapi.IndexRequest{
	req := opensearchapi.IndexRequest{
		Index:      strings.ToLower(GetESIndexPrefix(nameKey)),
		DocumentID: id,
		Body:       strings.NewReader(string(bytes)),
		Refresh:    "true",
		Pretty:     true,
	}

	res, err := req.Do(ctx, &project.Es)
	if err != nil {
		// Usually due to goroutines
		if strings.Contains(err.Error(), "context deadline exceeded") {
			res, err = req.Do(context.Background(), &project.Es)
			if err != nil {
				log.Printf("[ERROR] Error getting response from Opensearch (index ES) - 2: %s", err)
			}
		} else {
			log.Printf("[ERROR] Error getting response from Opensearch (index ES) - 1: %s", err)
		}

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

func GetTutorials(ctx context.Context, org Org, updateOrg bool) *Org {
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
			allSteps[2].Description = "Edit your org name and image, and invite your teammates to build together"
			allSteps[2].Link = "/admin?tab=users"
		} else {
			allSteps[2].Done = true
		}
	}

	if len(selectedUser.Id) > 0 {
		workflows, _ := GetAllWorkflowsByQuery(ctx, selectedUser)
		if len(workflows) > 1 {
			allSteps[1].Done = true
			allSteps[1].Description = fmt.Sprintf("%d workflows created. Find more workflows in the searchbar or on /usecases", len(workflows))
			allSteps[1].Link = "/usecases"
		}
	}

	if org.SSOConfig.SSOEntrypoint != "" && org.Defaults.NotificationWorkflow != "" {
		allSteps[3].Done = true
	} else {
		allSteps[3].Link = "/admin?admin_tab=organization"
	}

	org.Tutorials = allSteps

	if updateOrg {
		SetOrg(ctx, org, org.Id)
	}
	return &org
}

func propagateOrg(org Org, reverse bool) error {
	// the philosophy here is that, usually, we propagate only
	// from the main region to the other regions. However, "reverse"
	// makes propagation go from the other regions to the main region.

	if len(org.Id) == 0 {
		return errors.New("no ID provided for org")
	}

	if len(propagateUrl) == 0 || len(propagateToken) == 0 {
		return errors.New("no SHUFFLE_PROPAGATE_URL or SHUFFLE_PROPAGATE_TOKEN provided")
	}

	log.Printf("[INFO] Asking %s to propagate org %s", propagateUrl, org.Id)

	data := map[string]string{"mode": "org", "orgId": org.Id}

	if reverse {
		data["region"] = os.Getenv("SHUFFLE_GCEPROJECT_REGION")
	}

	reqBody, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", propagateUrl, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", propagateToken)

	// Send the request via a client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode != 200 {
		log.Printf("[WARNING] Error in propagation: %s for org %s", resp.Status, org.Id)
		return errors.New(fmt.Sprintf("bad statuscode: %d", resp.StatusCode))
	}

	return nil
}

func propagateApp(appId string, delete bool) error {
	if len(appId) == 0 {
		return errors.New("no ID provided for app")
	}

	if delete {
		log.Printf("[INFO] Deletion propagation is disabled right now.")
		return nil
	}

	if len(propagateUrl) == 0 || len(propagateToken) == 0 {
		return errors.New("no SHUFFLE_PROPAGATE_URL or SHUFFLE_PROPAGATE_TOKEN provided")
	}
	// SHUFFLE_GCE_LOCATION
	gceRegion := os.Getenv("SHUFFLE_GCEPROJECT_REGION")

	log.Printf("[INFO] Asking %s to propagate app %s", propagateUrl, appId)
	data := map[string]string{"mode": "app", "appId": appId, "region": gceRegion}

	reqBody, err := json.Marshal(data)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling propagation data %s: %s", appId, err)
		return err
	}

	req, err := http.NewRequest("POST", propagateUrl, bytes.NewBuffer(reqBody))
	if err != nil {
		log.Printf("[WARNING] Failed creating request for app %s: %s", appId, err)
		return err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", propagateToken)

	// Send the request via a client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[WARNING] Failed sending request for app %s: %s", appId, err)
		return err
	}

	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode != 200 {
		log.Printf("[WARNING] Error in propagation: %s for app %s", resp.Status, appId)
		return errors.New(fmt.Sprintf("bad statuscode: %d", resp.StatusCode))
	}

	log.Printf("[INFO] Propagation successful for app %s", appId)

	return nil
}

func propagateUser(user User, delete bool) error {
	if len(user.Id) == 0 {
		return errors.New("no ID provided for user")
	}

	if len(propagateUrl) == 0 || len(propagateToken) == 0 {
		return errors.New("no SHUFFLE_PROPAGATE_URL or SHUFFLE_PROPAGATE_TOKEN provided")
	}

	log.Printf("[INFO] Asking %s to propagate user %s", propagateUrl, user.Id)

	data := map[string]string{"mode": "user", "userId": user.Id}
	if delete {
		log.Printf("[INFO] Deletion propagation is disabled right now.")
		// data["delete"] = "true"
	}

	reqBody, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", propagateUrl, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", propagateToken)

	// Send the request via a client
	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode != 200 {
		log.Printf("[WARNING] Error in propagation: %s for user %s", resp.Status, user.Id)
		return errors.New(fmt.Sprintf("bad statuscode: %d", resp.StatusCode))
	}

	return nil
}

func SetOrg(ctx context.Context, data Org, id string) error {
	if len(id) == 0 {
		return errors.New(fmt.Sprintf("No ID provided for org %s", data.Name))
	}

	if id != data.Id && len(data.Id) > 0 {
		log.Printf("[ERROR] Org ID mismatch: %s != %s. Resetting ID", id, data.Id)
		id = data.Id
	}

	data.Id = id
	if len(data.Name) == 0 {
		data.Name = "tmp"

		if len(data.Org) > 0 {
			data.Name = data.Org
		} else {
			data.Org = data.Name
		}
	}

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
		data = *GetTutorials(ctx, data, false)
	}

	if len(data.Users) == 0 {
		return errors.New("Not allowed to update an org without any users in the organization. Add at least one user to update")
	}

	// clear session_token and API_token for user
	if project.DbType == "opensearch" {
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

		if data.Region != "" && data.Region != "europe-west2" && gceProject == "shuffler" {
			go func() {
				err := propagateOrg(data, false)
				if err != nil {
					if !strings.Contains(fmt.Sprintf("%s", err), "no SHUFFLE_PROPAGATE_URL") {
						log.Printf("[ERROR] Failed propagating org %s for region %#v: %s", data.Id, data.Region, err)
					}
				} else {
					log.Printf("[INFO] Successfully propagated org %s to region %#v", data.Id, data.Region)
				}
			}()
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
		err = SetCache(ctx, cacheKey, neworg, 1440)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for org '%s': %s", cacheKey, err)
		}
	}

	return nil
}

func GetSession(ctx context.Context, thissession string) (*Session, error) {
	session := &Session{}

	cacheKey := thissession
	cache, err := GetCache(ctx, cacheKey)
	if err == nil {
		cacheData := []byte(cache.([]uint8))
		err = json.Unmarshal(cacheData, &session)
		if err == nil {
			return session, nil
		}
	} else {
		//log.Printf("[WARNING] Error getting session cache for %s: %v", thissession, err)
	}

	nameKey := "sessions"
	if project.DbType == "opensearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), thissession)
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
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

		err = SetCache(ctx, thissession, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed updating session cache: %s", err)
		}
	}

	return session, nil
}

// Index = Username
func DeleteKey(ctx context.Context, entity string, value string) error {
	// Non indexed User data
	if entity == "workflowexecution" {
		log.Printf("[WARNING] Deleting workflowexecution: %s", value)
	}

	DeleteCache(ctx, fmt.Sprintf("%s_%s", entity, value))
	if len(value) == 0 {
		log.Printf("[WARNING] Couldn't delete %s because value (id) must be longer than 0", entity)
		return errors.New("Value to delete must be larger than 0")
	}

	if project.DbType == "opensearch" {
		log.Printf("[DEBUG] Deleting from index '%s' with item '%s' from opensearch", entity, value)

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
	if project.DbType == "opensearch" {
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
	if project.DbType == "opensearch" {
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
		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed updating openapi cache in set: %s", err)
		}
	}

	return nil
}

func GetOpenApiDatastore(ctx context.Context, id string) (ParsedOpenApi, error) {
	nameKey := "openapi3"
	api := &ParsedOpenApi{}

	if strings.HasSuffix(id, ".") {
		id = id[:len(id)-1]
	}

	if len(id) > 32 {
		log.Printf("[ERROR] ID %s is too long for datastore. Reducing to 32", id)
		id = id[:32]
	}

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

	if project.DbType == "opensearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
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
			log.Printf("Some API issue: %s", err)

			if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
				return *api, nil
			}

			//project.BucketName := project.BucketName
			fullParsedPath := fmt.Sprintf("extra_specs/%s/openapi.json", id)
			//gs://shuffler.appspot.com/extra_specs/0373ed696a3a2cba0a2b6838068f2b80
			//log.Printf("[DEBUG] Couldn't find openapi for %s. Checking filepath gs://%s/%s (size too big). Error: %s", id, project.BucketName, fullParsedPath, err)

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

		err = SetCache(ctx, cacheKey, data, 1440)
		if err != nil {
			log.Printf("[WARNING] Failed updating openapi cache: %s", err)
		}
	}

	return *api, nil
}

// Index = Username
func SetSession(ctx context.Context, user User, value string) error {
	//parsedKey := strings.ToLower(user.Username)
	// Non indexed User data
	parsedKey := user.Id
	user.Session = value

	nameKey := "Users"
	if project.DbType == "opensearch" {
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

		if project.DbType == "opensearch" {
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

func FindWorkflowByName(ctx context.Context, name string) ([]Workflow, error) {
	var workflows []Workflow

	if project.DbType == "opensearch" {
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"name": name,
				},
			},
		}

		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return workflows, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix("workflow"))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)

		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get workflows named): %s", err)
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

		for _, hit := range wrapped.Hits.Hits {
			workflows = append(workflows, hit.Source)
		}
	} else {
		q := datastore.NewQuery("workflow").Filter("name =", name).Limit(100)

		_, err := project.Dbclient.GetAll(ctx, q, &workflows)
		if err != nil && len(workflows) == 0 {
			return []Workflow{}, err
		}
	}

	return workflows, nil
}

func FindWorkflowAppByName(ctx context.Context, appName string) ([]WorkflowApp, error) {
	var apps []WorkflowApp

	nameKey := "workflowapp"
	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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
		//log.Printf("Looking for name %s in %s", appName, nameKey)
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
	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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
	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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
	if project.DbType == "opensearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), parsedKey)
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
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

		err = SetCache(ctx, cacheKey, data, 1440)
		if err != nil {
			log.Printf("[WARNING] Failed updating cache: %s", err)
		}
	}

	return curUser, nil
}

func SetUser(ctx context.Context, user *User, updateOrg bool) error {
	log.Printf("[INFO] Updating user %s (%s) that has the role %s with %d apps and %d orgs. Org updater: %t", user.Username, user.Id, user.Role, len(user.PrivateApps), len(user.Orgs), updateOrg)
	parsedKey := user.Id

	DeleteCache(ctx, user.ApiKey)
	DeleteCache(ctx, user.Session)
	DeleteCache(ctx, fmt.Sprintf("session_%s", user.Session))
	if updateOrg {
		user = fixUserOrg(ctx, user)
	}

	nameKey := "Users"
	data, err := json.Marshal(user)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling user: %s", err)
		return nil
	}

	//log.Printf("[INFO] Updating user %s (%s) with data length %d", user.Username, user.Id, len(data))

	// This may cause issues huh
	if len(data) > 1000000 {
		user.PrivateApps = []WorkflowApp{}

		data, err = json.Marshal(user)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling user (2): %s", err)
			return nil
		}
	}

	if project.DbType == "opensearch" {
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

		if len(user.Regions) > 1 {
			go func() {
				log.Printf("[INFO] Updating user %s in org %s (%s) with region %#v", user.Username, user.ActiveOrg.Name, user.ActiveOrg.Id, user.Regions)
				err = propagateUser(*user, false)
				if err != nil {
					log.Printf("[WARNING] Failed propagating user %s (%s) with region %#v: %s", user.Username, user.Id, user.Regions, err)
				}
			}()
		}
	}

	DeleteCache(ctx, user.ApiKey)
	DeleteCache(ctx, user.Session)
	DeleteCache(ctx, fmt.Sprintf("session_%s", user.Session))
	if project.CacheDb {
		cacheKey := fmt.Sprintf("user_%s", parsedKey)

		err = SetCache(ctx, cacheKey, data, 1440)
		if err != nil {
			log.Printf("[WARNING] Failed updating user cache (ID): %s", err)
		}

		cacheKey = fmt.Sprintf("user_%s", strings.ToLower(user.Username))
		err = SetCache(ctx, cacheKey, data, 1440)
		if err != nil {
			log.Printf("[WARNING] Failed updating user cache (username): %s", err)
		}
	}

	return nil
}

func DeleteUsersAccount(ctx context.Context, user *User) error {
	cacheKey := fmt.Sprintf("user_%s", user.Id)

	for _, orgId := range user.Orgs {
		org, err := GetOrg(ctx, orgId)
		if err != nil {
			log.Printf("[WARNING] Error getting org %s in delete user: %s", orgId, err)
			continue
		}

		newUsers := []User{}
		for _, orgUser := range org.Users {
			if orgUser.Id == user.Id {
				continue
			}

			newUsers = append(newUsers, orgUser)
		}
		org.Users = newUsers
		err = SetOrg(ctx, *org, org.Id)
		if err != nil {
			log.Printf("[WARNING] Failed setting org %s (1)", orgId)
		}
	}

	nameKey := "Users"
	if project.DbType == "opensearch" {
		res, err := project.Es.Delete(strings.ToLower(GetESIndexPrefix(nameKey)), user.Id)
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
			return err
		}
		defer res.Body.Close()

		log.Printf("Response from OpenSearch deletion: StatusCode=%d", res.StatusCode)

		if res.StatusCode == 404 {
			return errors.New("User doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}

		wrapped := UserWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, user.Id, nil)
		err := project.Dbclient.Delete(ctx, key)
		if err != nil {
			log.Printf("[Error] deleting from %s from %s: %s", nameKey, user.Id, err)
		}
		// if (len(user.Regions)) > 1 {
		// 	go func() {
		// 		log.Printf("[INFO] Updating user %s in org %s (%s) with region %#v", user.Username, user.ActiveOrg.Name, user.ActiveOrg.Id, user.Regions)
		// 		err = propagateUser(*user, true)
		// 		if err != nil {
		// 			log.Printf("[WARNING] Failed propagating user %s (%s) with region %#v: %s", user.Username, user.Id, user.Regions, err)
		// 		}
		// 	}()
		// }

	}

	DeleteCache(ctx, user.ApiKey)
	DeleteCache(ctx, user.Session)
	DeleteCache(ctx, fmt.Sprintf("session_%s", user.Session))

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

		err = SetOrg(ctx, *org, org.Id)
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
			err = json.Unmarshal(cacheData, &allworkflowappAuths)
			if err == nil {
				return allworkflowappAuths, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for app auth: %s", err)
		}
	}

	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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

	// Should check if it's a child org and get parent orgs app auths that are shared
	foundOrg, err := GetOrg(ctx, orgId)
	if err == nil && len(foundOrg.ChildOrgs) == 0 && len(foundOrg.CreatorOrg) > 0 && foundOrg.CreatorOrg != orgId {

		parentOrg, err := GetOrg(ctx, foundOrg.CreatorOrg)
		if err == nil {

			// No recursion as parents can't have parents
			parentAuths, err := GetAllWorkflowAppAuth(ctx, parentOrg.Id)
			if err == nil {
				for _, parentAuth := range parentAuths {
					if !parentAuth.SuborgDistributed {
						continue
					}

					allworkflowappAuths = append(allworkflowappAuths, parentAuth)
				}
			}
		}
	}

	// Deduplicate keys
	for _, auth := range allworkflowappAuths {
		allFields := []string{}
		newFields := []AuthenticationStore{}
		for _, field := range auth.Fields {
			if ArrayContains(allFields, field.Key) {
				continue
			}

			allFields = append(allFields, field.Key)
			newFields = append(newFields, field)
		}

		auth.Fields = newFields
	}

	if project.CacheDb {
		data, err := json.Marshal(allworkflowappAuths)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling get app auth: %s", err)
			return allworkflowappAuths, nil
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed updating get app auth cache: %s", err)
		}
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
			err = json.Unmarshal(cacheData, &environments)
			if err == nil {
				return environments, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache in GET environments: %s", err)
		}
	}

	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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
	timenow := time.Now().Unix()
	for envIndex, env := range environments {
		if env.Name == "Cloud" {
			environments[envIndex].Type = "cloud"
			environments[envIndex].RunType = "cloud"

		} else if env.Name == "Shuffle" {
			environments[envIndex].Type = "onprem"

			if env.RunType == "" {
				environments[envIndex].RunType = "docker"
			}
		} else {
			if environments[envIndex].Type == "" {
				environments[envIndex].Type = "onprem"
			}

			if env.RunType == "" {
				environments[envIndex].RunType = "docker"
			}
		}

		if environments[envIndex].Type == "onprem" {
			if env.Checkin > 0 && timenow-env.Checkin > 90 {
				environments[envIndex].RunningIp = ""
				environments[envIndex].Licensed = false
			}
		}
	}

	//log.Printf("\n\n[DEBUG2] Getting environments2 for orgId %s\n\n", orgId)

	if project.CacheDb {
		data, err := json.Marshal(environments)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling environment cache: %s", err)
			return environments, nil
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed updating environment cache: %s", err)
		}
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
		// Make "body" field a required field if it exists
		allApps, err := GetAllWorkflowApps(ctx, 1000, 0)
		if err != nil {
			return allApps, err
		}

		for appIndex, app := range allApps {
			for actionIndex, action := range app.Actions {
				for paramIndex, param := range action.Parameters {
					if param.Name == "body" {
						allApps[appIndex].Actions[actionIndex].Parameters[paramIndex].Required = true

					}
				}
			}

			if app.Authentication.Type == "oauth2-app" && len(app.Authentication.RedirectUri) > 0 {
				allApps[appIndex].Authentication.Type = "oauth2"
			}
		}

		return allApps, nil
	}

	log.Printf("[AUDIT] Getting apps for user '%s' with active org %s", user.Username, user.ActiveOrg.Id)
	allApps := []WorkflowApp{}

	// 1. Caching apps locally
	// Make it based on org and not user :)
	cacheKey := fmt.Sprintf("apps_%s", user.ActiveOrg.Id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &allApps)
			if err == nil {
				return allApps, nil
			} else {
				//log.Println(string(cacheData))
				log.Printf("[ERROR] Failed unmarshaling apps (in cache). Is it stored or mapped together correctly?: %s", err)
				DeleteCache(ctx, cacheKey)
				//log.Printf("[ERROR] DATALEN: %d", len(cacheData))
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for apps with KEY %s: %s", cacheKey, err)
		}
	}

	maxLen := 200
	queryLimit := 25
	cursorStr := ""

	allApps = user.PrivateApps
	org, orgErr := GetOrg(ctx, user.ActiveOrg.Id)
	if orgErr == nil && len(org.ActiveApps) > 150 {
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

		org.ActiveApps = org.ActiveApps[len(org.ActiveApps)-100 : len(org.ActiveApps)-1]
		go SetOrg(ctx, *org, org.Id)
	}

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
	var err error
	if user.ActiveOrg.Id != "" {
		query := datastore.NewQuery(nameKey).Filter("reference_org =", user.ActiveOrg.Id).Limit(queryLimit)
		//log.Printf("[INFO] Before ref org search. Org: %s\n\n", user.ActiveOrg.Id)
		for {
			it := project.Dbclient.Run(ctx, query)

			for {
				innerApp := WorkflowApp{}
				_, err := it.Next(&innerApp)
				if err != nil {
					if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
						//log.Printf("[ERROR] Error in reference_org app load of %s (%s): %s.", innerApp.Name, innerApp.ID, err)
					} else {
						//log.Printf("[WARNING] No more apps for %s in org app load? Breaking: %s.", user.Username, err)

						break
					}
				}

				if innerApp.Name == "Shuffle Subflow" {
					continue
				}

				//if orgErr == nil && !ArrayContains(org.ActiveApps, innerApp.ID) {
				//	continue
				//}

				if len(innerApp.Actions) == 0 {
					//log.Printf("[INFO] App %s (%s) doesn't have actions (1) - check filepath", innerApp.Name, innerApp.ID)

					foundApp, err := getCloudFileApp(ctx, innerApp, innerApp.ID)
					if err == nil {
						innerApp = foundApp
					}
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
				nextStr := fmt.Sprintf("%s", nextCursor)
				if cursorStr == nextStr {
					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)
			}

			if len(allApps) > maxLen {
				break
			}
		}
	}

	// Find public apps

	appsAdded := []string{}

	// Search for apps with these names, not all public ones
	importantApps := []string{"Shuffle Tools", "http"}

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

	// May be better to just list all, then set to true?
	// Is this the slow one?
	if len(publicApps) == 0 {
		for _, name := range importantApps {
			query := datastore.NewQuery(nameKey).Filter("Name =", name).Limit(queryLimit)
			//query := datastore.NewQuery(nameKey).Filter("public =", true).Limit(queryLimit)
			for {
				it := project.Dbclient.Run(ctx, query)

				for {
					innerApp := WorkflowApp{}
					_, err := it.Next(&innerApp)
					if err != nil {
						//log.Printf("[WARNING] No more apps (public). Amount found: %d", len(publicApps))

						if strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
							//log.Printf("[WARNING] Error in public app load: %s", err)
							//continue
						} else {

							//log.Printf("[WARNING] No more apps (public) - Breaking: %s.", err)
							break
						}
					}

					if innerApp.Name == "Shuffle Subflow" {
						continue
					}

					// Special fix for other regions for these reserved apps
					if innerApp.Public == false && innerApp.Sharing == false && gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
						if ArrayContains(importantApps, innerApp.Name) {
							innerApp.Public = true
							innerApp.Sharing = true
						} else {
							log.Printf("[INFO] App %s is not public", innerApp.Name)
							continue
						}
					}

					if len(innerApp.Actions) == 0 {
						foundApp, err := getCloudFileApp(ctx, innerApp, innerApp.ID)
						if err == nil {
							innerApp = foundApp
						}
					}

					//log.Printf("[DEBUG] Got app %s:%s (%s)", innerApp.Name, innerApp.AppVersion, innerApp.ID)
					//publicApps = append(publicApps, innerApp)
					//publicApps, innerApp = fixAppAppend(allApps, innerApp)
					allApps, innerApp = fixAppAppend(allApps, innerApp)

				}

				if err != iterator.Done {
				}

				// Get the cursor for the next page of results.
				nextCursor, err := it.Cursor()
				if err != nil {
					log.Printf("Cursorerror: %s", err)
					break
				} else {
					nextStr := fmt.Sprintf("%s", nextCursor)
					if cursorStr == nextStr {
						break
					}

					cursorStr = nextStr
					query = query.Start(nextCursor)
				}

				if len(allApps) > maxLen {
					break
				}
			}
		}

		newbody, err := json.Marshal(publicApps)
		if err != nil {
			return allApps, nil
		}

		err = SetCache(ctx, publicAppsKey, newbody, 1440)
		if err != nil {
			log.Printf("[INFO] Error setting app cache item for %s: %v", publicAppsKey, err)
		} else {
			//log.Printf("[INFO] Set app cache for %s. Next are private apps.", publicAppsKey)
		}
	}

	//log.Printf("All apps: %d", len(allApps))
	//allApps = append(allApps, publicApps...)
	//log.Printf("All apps: %d", len(allApps))

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
			//log.Printf("[ERROR] Failed getting org apps: %s. Apps: %d. NOT FATAL", err, len(newApps))
		}

		//log.Printf("[DEBUG] Got %d apps from dbclient multi", len(newApps))

		// IF the app doesn't have actions, check OpenAPI
		// 1. Get the app directly
		// 2. Parse OpenAPI for it to get the actions
		for appIndex, app := range newApps {
			if len(app.Actions) == 0 && len(app.Name) > 0 {
				//log.Printf("[WARNING] %s has %d actions (%s). Getting directly.", app.Name, len(app.Actions), app.ID)

				newApp, err := GetApp(ctx, app.ID, user, true)
				if err != nil {
					log.Printf("[WARNING] Failed to find app while parsing app %s: %s", app.Name, err)
					continue
				} else {
					// Check if they should have access?
					newApps[appIndex] = *newApp
				}

			}
		}

		// Authentication system to ensure the user actually has access to all the apps it says it wants

		// FIXME: Enable this and fix suborg <-> parentorg access
		// Problem: If you're in a suborg, you can't access parentorg apps and vice versa
		// This stage doesn't have org information either, so it needs to be grabbed first.

		parentOrg := &Org{}
		if len(org.ManagerOrgs) > 0 {
			parentOrg, err = GetOrg(ctx, org.ManagerOrgs[0].Id)
			if err != nil {
				log.Printf("[ERROR] Failed getting parent org %s during app load verification: %s", org.ManagerOrgs[0], err)
			}
		}

		if len(parentOrg.Id) == 0 && len(org.ChildOrgs) > 0 {
			parentOrg = org
		}

		notAppendedApps := []string{}
		parsedNewapps := []WorkflowApp{}
		for _, newApp := range newApps {
			if len(newApp.ID) == 0 || len(newApp.Name) == 0 {
				continue
			}

			//if user.SupportAccess {
			//	parsedNewapps = append(parsedNewapps, newApp)
			if newApp.Sharing || newApp.Public || newApp.SharingConfig == "everyone" || newApp.SharingConfig == "public" {
				parsedNewapps = append(parsedNewapps, newApp)
			} else if newApp.Owner == user.ActiveOrg.Id || newApp.Owner == user.Id {
				parsedNewapps = append(parsedNewapps, newApp)
			} else if newApp.ReferenceOrg == user.ActiveOrg.Id {
				parsedNewapps = append(parsedNewapps, newApp)

			} else {
				// FIXME: Parentorg <-> suborg access
				if len(newApp.ReferenceOrg) > 0 {
					orgFound := false
					for _, childOrg := range parentOrg.ChildOrgs {
						if childOrg.Id != newApp.ReferenceOrg {
							continue
						}

						orgFound = true
						log.Printf("[DEBUG] Found matching org %s in parent org %s", newApp.ReferenceOrg, parentOrg.Id)
						break
					}

					if orgFound {
						parsedNewapps = append(parsedNewapps, newApp)
						continue
					}
				}

				notAppendedApps = append(notAppendedApps, fmt.Sprintf("%s - %s", newApp.Name, newApp.ID))
			}
		}

		if len(notAppendedApps) > 0 {
			//log.Printf("[INFO] Not appended apps (%d) for org %s (%s): %s", len(notAppendedApps), user.ActiveOrg.Name, user.ActiveOrg.Id, strings.Join(notAppendedApps, ", "))
			//log.Printf("[WARNING] %d non-allowed, but activated apps for org %s (%s). Removed.", len(notAppendedApps), user.ActiveOrg.Name, user.ActiveOrg.Id)
		}

		allApps = append(allApps, newApps...)
	}

	// Deduplicate (e.g. multiple gmail)
	dedupedApps := []WorkflowApp{}
	for _, app := range allApps {
		found := false
		replaceIndex := -1
		for dedupIndex, dedupApp := range dedupedApps {
			if len(strings.TrimSpace(dedupApp.Name)) == 0 {
				continue
			}

			// Name, owner, ID, parent ID
			if strings.ToLower(dedupApp.Name) == strings.ToLower(app.Name) {
				//log.Printf("[DEBUG] Found duplicate app: %s (%s). Dedup index: %d", app.Name, app.ID, dedupIndex)
				found = true
				replaceIndex = dedupIndex
			}
		}

		if !found {
			dedupedApps = append(dedupedApps, app)
			continue
		}

		//log.Printf("[INFO] Found duplicate app: %s (%s). Dedup index: %d", app.Name, app.ID, replaceIndex)
		// If owner of dedup, don't change
		/*
			if dedupedApps[replaceIndex].Owner == user.Id {
				log.Printf("[INFO] Owner of deduped app is user. Not replacing.")
				continue
			}
		*/

		// Check if one is referenceOrg not
		if dedupedApps[replaceIndex].ReferenceOrg == user.ActiveOrg.Id {
			continue
		}

		if app.ReferenceOrg == user.ActiveOrg.Id {
			dedupedApps[replaceIndex] = app
			continue
		}

		if app.Edited > dedupedApps[replaceIndex].Edited {
			//log.Printf("[INFO] Replacing deduped app with newer app in get apps: %s", app.Name)
			dedupedApps[replaceIndex] = app
			continue
		}

		// Check if image, and other doesn't have
		if len(dedupedApps[replaceIndex].LargeImage) == 0 && len(app.LargeImage) > 0 {
			log.Printf("[INFO] Replacing deduped app with image in get apps (2): %s", app.Name)
			dedupedApps[replaceIndex] = app
		}
	}

	allApps = dedupedApps

	for appIndex, app := range allApps {
		for actionIndex, action := range app.Actions {
			lastRequiredIndex := -1
			bodyIndex := -1
			for paramIndex, param := range action.Parameters {
				if param.Required {
					lastRequiredIndex = paramIndex
				}

				if param.Name == "body" {
					allApps[appIndex].Actions[actionIndex].Parameters[paramIndex].Required = true
					bodyIndex = paramIndex
				}

				if param.Name == "headers" {
					// Make a newline between all headers based on knownHeaders
					// or just rewrite because lol
					if strings.Count(strings.ToLower(param.Value), "content-type") > 1 {
						allApps[appIndex].Actions[actionIndex].Parameters[paramIndex].Value = "Content-Type=application/json\nAccept=application/json"
					}

					if strings.Contains(strings.ToLower(param.Value), "accept") && strings.Contains(strings.ToLower(param.Value), "application/json") && !strings.Contains(strings.ToLower(param.Value), "content-type") {
						allApps[appIndex].Actions[actionIndex].Parameters[paramIndex].Value = fmt.Sprintf("%s\nContent-Type=application/json", param.Value)
					}
				}
			}

			_ = lastRequiredIndex

			// Add bodyIndex parameter in the next index after lastRequiredIndex, but retain all fields
			if bodyIndex > -1 {
				//log.Printf("[INFO] Moving body parameter to index %d after %d", lastRequiredIndex+1, bodyIndex)
			}
		}
	}

	// Also prioritize most used ones from app-framework on top?
	slice.Sort(allApps[:], func(i, j int) bool {
		return allApps[i].Edited > allApps[j].Edited
	})

	// Fix Oauth2 issues
	for appIndex, app := range allApps {
		if app.Authentication.Type != "oauth2-app" {
			continue
		}

		if len(app.Authentication.RedirectUri) > 0 {
			allApps[appIndex].Authentication.Type = "oauth2"
		}
	}

	if len(allApps) > 0 {
		// Finds references
		allApps = findReferenceAppDocs(ctx, allApps)

		newbody, err := json.Marshal(allApps)
		if err != nil {
			return allApps, nil
		}

		err = SetCache(ctx, cacheKey, newbody, 1440)
		if err != nil {
			log.Printf("[INFO] Error setting app cache item for %s: %v", cacheKey, err)
		} else {
			//log.Printf("[INFO] Set app cache for %s", cacheKey)
		}
	}



	return allApps, nil
}

func fixAppAppend(allApps []WorkflowApp, innerApp WorkflowApp) ([]WorkflowApp, WorkflowApp) {
	newIndex := -1
	newApp := WorkflowApp{}
	found := false

	for appIndex, loopedApp := range allApps {
		// Check if shuffle subflow and skip

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

func GetUserApps(ctx context.Context, userId string) ([]WorkflowApp, error) {
	wrapper := []WorkflowApp{}
	//var err error

	cacheKey := fmt.Sprintf("userapps-%s", userId)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &wrapper)
			if err == nil {
				return wrapper, nil
			}
		}
	}

	userApps := []WorkflowApp{}
	indexName := "workflowapp"
	if project.DbType == "opensearch" {
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
					"should": []map[string]interface{}{
						{
							"match": map[string]interface{}{
								"owner": userId,
							},
						},
						{
							"match": map[string]interface{}{
								"contributors": userId,
							},
						},
					},
				},
				"minimum_should_match": 1,
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find workflowapp query: %s", err)
			return []WorkflowApp{}, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(indexName))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(false),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get apps): %s", err)
			return []WorkflowApp{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return []WorkflowApp{}, err
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

		for _, hit := range wrapped.Hits.Hits {
			innerApp := hit.Source
			userApps = append(userApps, innerApp)
		}
	} else {

		cursorStr := ""

		log.Printf("[DEBUG] Getting user apps for %s", userId)
		var err error

		queries := []datastore.Query{}
		q := datastore.NewQuery(indexName).Filter("contributors =", userId)

		queries = append(queries, *q)

		q = datastore.NewQuery(indexName).Filter("owner =", userId)
		queries = append(queries, *q)

		cnt := 0
		maxAmount := 100 
		for _, tmpQuery := range queries {
			query := &tmpQuery

			if cnt > maxAmount {
				break
			}

			for {
				it := project.Dbclient.Run(ctx, query)
				if cnt > maxAmount {
					break
				}

				for {
					innerApp := WorkflowApp{}
					_, err = it.Next(&innerApp)
					//log.Printf("Got app: %s (%s)", innerApp.Name, innerApp.ID)
					cnt += 1
					if cnt > maxAmount {
						break
					}

					if err != nil {

						if !strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
							log.Printf("[ERROR] Failed fetching user apps (1): %v", err)

							if strings.Contains("no matching index found", fmt.Sprintf("%s", err)) {
								log.Printf("[ERROR] No more apps for %s in user app load? Breaking: %s.", userId, err)
							} else {
								log.Printf("[WARNING] No more apps for %s in user app load? Breaking: %s.", userId, err)
							}

							break
						}
					}

					if !ArrayContains(innerApp.Contributors, userId) && innerApp.Owner != userId {
						continue
					}

					userApps = append(userApps, innerApp)


				}

				if err != nil {
					if !strings.Contains(fmt.Sprintf("%s", err), "no more items") {
						log.Printf("[ERROR] Failed fetching user apps (3): %v", err)
					}

					break
				}

				if err != iterator.Done {
					log.Printf("[ERROR] Failed fetching user apps (2): %v", err)
				}

				// Get the cursor for the next page of results.
				nextCursor, err := it.Cursor()
				if err != nil {
					log.Printf("Cursor error: %s", err)
					break

				} else {
					nextStr := fmt.Sprintf("%s", nextCursor)
					if cursorStr == nextStr {
						// Break the loop if the cursor is the same as the previous one
						break
					}

					cursorStr = nextStr
					query = query.Start(nextCursor)
				}
			}
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(userApps)
		if err == nil {
			err = SetCache(ctx, cacheKey, data, 30)
			if err != nil {
				log.Printf("[WARNING] Failed updating cache for execution: %s", err)
			}
		} else {
			log.Printf("[WARNING] Failed marshalling execution: %s", err)
		}
	}

	return userApps, nil
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
	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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
				nextStr := fmt.Sprintf("%s", nextCursor)
				if cursorStr == nextStr {
					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)
			}

			if len(allApps) > maxLen && maxLen != 0 {
				break
			}
		}
	}

	slice.Sort(allApps[:], func(i, j int) bool {
		return allApps[i].Edited > allApps[j].Edited
	})

	if project.CacheDb {
		data, err := json.Marshal(allApps)
		if err == nil {
			err = SetCache(ctx, cacheKey, data, 30)
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
	if project.DbType == "opensearch" {
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

	// workflowqueue-new-service-test_7e9b9007-5df2-4b47-bca5-c4d267ef2943

	if project.DbType == "opensearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"from": 0,
			"size": limit,
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
			project.Es.Search.WithContext(ctx),
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
				"size": limit,
			}

			if err := json.NewEncoder(&buf).Encode(query); err != nil {
				log.Printf("[WARNING] Error encoding find user query: %s", err)
				return ExecutionRequestWrapper{}, err
			}

			res, err = project.Es.Search(
				project.Es.Search.WithContext(ctx),
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

			executions = append(executions, hit.Source)
		}
	} else {
		q := datastore.NewQuery(nameKey).Limit(limit)
		_, err := project.Dbclient.GetAll(ctx, q, &executions)
		if err != nil {
			log.Printf("[WARNING] Error getting workflow queue: %s", err)
			return ExecutionRequestWrapper{
				Data: executions,
			}, err
		}
	}

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
	if project.DbType == "opensearch" {
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

func GetPlatformHealth(ctx context.Context, beforeTimestamp int, afterTimestamp int, limit int) ([]HealthCheckDB, error) {
	nameKey := "platform_health"
	// sort by "updated", and get the first one

	health := []HealthCheckDB{}
	cacheKey := fmt.Sprintf("%s-%d-%d-%d", nameKey, beforeTimestamp, afterTimestamp, limit)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &health)
			if err == nil {
				return health, nil
			} else {
				//log.Printf("[WARNING] Failed collection: %s", err)
			}
		} else {
		}
	}

	if project.DbType == "opensearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"sort": map[string]interface{}{
				"updated": map[string]interface{}{
					"order": "desc",
				},
			},
		}

		if limit != 0 {
			query["size"] = limit
		}

		if beforeTimestamp > 0 || afterTimestamp > 0 {
			query["query"] = map[string]interface{}{
				"bool": map[string]interface{}{
					"must": []map[string]interface{}{},
				},
			}
		}

		if beforeTimestamp > 0 {
			query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"] = append(
				query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"].([]map[string]interface{}),
				map[string]interface{}{
					"range": map[string]interface{}{
						"updated": map[string]interface{}{
							"gt": beforeTimestamp,
						},
					},
				},
			)
		}

		if afterTimestamp > 0 {
			query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"] = append(
				query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"].([]map[string]interface{}),
				map[string]interface{}{
					"range": map[string]interface{}{
						"updated": map[string]interface{}{
							"lt": afterTimestamp,
						},
					},
				},
			)
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return health, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get latest platform health): %s", err)
			return health, err
		}
		defer res.Body.Close()

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return health, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return health, err
			} else {
				// Print the response status and error information.
				log.Printf("[%s] %s: %s",
					res.Status(),
					e["error"].(map[string]interface{})["type"],
					e["error"].(map[string]interface{})["reason"],
				)
			}
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return health, err
		}

		wrapped := HealthCheckSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return health, err
		}

		for _, hit := range wrapped.Hits.Hits {
			health = append(health, hit.Source)
		}

	} else {
		q := datastore.NewQuery(nameKey)

		// Modify the query to filter for "before" timestamp.
		if beforeTimestamp != 0 {
			q = q.Filter("Updated >", beforeTimestamp)
		}

		// Modify the query to filter for "after" timestamp.
		if afterTimestamp != 0 {
			q = q.Filter("Updated <", afterTimestamp)
		}

		if limit != 0 {
			//log.Printf("[ERROR] Limiting platform health to %d", limit)
			q = q.Limit(limit)
		}

		q = q.Order("-Updated")

		_, err := project.Dbclient.GetAll(ctx, q, &health)
		if err != nil {
			log.Printf("[WARNING] Error getting latest platform health: %s", err)
			return health, err
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(health)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling health: %s", err)
			return health, nil
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed updating health cache: %s", err)
		}
	}

	return health, nil
}

func SetPlatformHealth(ctx context.Context, health HealthCheckDB) error {
	nameKey := "platform_health"

	// generate random ID
	health.ID = uuid.NewV4().String()

	data, err := json.Marshal(health)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in set platform health: %s", err)
		return nil
	}

	if project.DbType == "opensearch" {
		err = indexEs(ctx, nameKey, health.ID, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, health.ID, nil)
		if _, err := project.Dbclient.Put(ctx, key, &health); err != nil {
			log.Printf("[WARNING] Error adding platform health: %s", err)
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
			err = json.Unmarshal(cacheData, &workflowExecution)
			if err == nil {
				return workflowExecution, nil
			} else {
				log.Printf("[WARNING] Failed getting opensea collection: %s", err)
			}
		} else {
		}
	}

	if project.DbType == "opensearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
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

		err = SetCache(ctx, id, newexecution, 30)
		if err != nil {
			log.Printf("[WARNING] Failed updating collection: %s", err)
		}
	}

	return workflowExecution, nil
}

func GetOpenseaAssets(ctx context.Context, collectionName string) ([]OpenseaAsset, error) {
	index := "openseacollection"

	var executions []OpenseaAsset
	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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
	if project.DbType == "opensearch" {
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
		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getworkflow '%s': %s", cacheKey, err)
		}
	}

	return nil
}

func ListChildWorkflows(ctx context.Context, originalId string) ([]Workflow, error) {
	var workflows []Workflow
	var err error

	nameKey := "workflow"
	cacheKey := fmt.Sprintf("%s_%s_childworkflows", nameKey, originalId)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &workflows)
			if err == nil {

				sort.Slice(workflows, func(i, j int) bool {
					return workflows[i].Edited > workflows[j].Edited
				})

				return workflows, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for workflow: %s", err)
		}
	}

	log.Printf("[AUDIT] Getting workflow children for workflow %s.", originalId)
	if project.DbType == "opensearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"parentorg_workflow": originalId,
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return workflows, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
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

		for _, hit := range wrapped.Hits.Hits {
			if hit.Source.ID != originalId {
				continue
			}

			workflows = append(workflows, hit.Source)
		}
	} else {
		query := datastore.NewQuery(nameKey).Filter("parentorg_workflow =", originalId).Limit(50)
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
					//log.Printf("[WARNING] Workflow iterator issue: %s", err)
					break
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
				nextStr := fmt.Sprintf("%s", nextCursor)
				if cursorStr == nextStr {
					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)
			}
		}
	}

	// Sort by edited
	sort.Slice(workflows, func(i, j int) bool {
		return workflows[i].Edited > workflows[j].Edited
	})

	// Deduplicate based on edited time
	filtered := []Workflow{}
	handled := []string{}
	for _, workflow := range workflows {
		if ArrayContains(handled, string(workflow.Edited)) {
			continue
		}

		handled = append(handled, string(workflow.Edited))
		filtered = append(filtered, workflow)
	}

	// Set cache
	if project.CacheDb {
		cacheData, err := json.Marshal(workflows)
		if err != nil {
			return workflows, nil
		}

		err = SetCache(ctx, cacheKey, cacheData, 60)
		if err != nil {
			log.Printf("[ERROR] Failed setting cache for workflow revisions: %s (not critical)", err)
		}
	}

	return workflows, nil
}

func ListWorkflowRevisions(ctx context.Context, originalId string) ([]Workflow, error) {
	var workflows []Workflow
	var err error

	nameKey := "workflow_revisions"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, originalId)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &workflows)
			if err == nil {

				sort.Slice(workflows, func(i, j int) bool {
					return workflows[i].Edited > workflows[j].Edited
				})

				return workflows, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for workflow: %s", err)
		}
	}

	log.Printf("[AUDIT] Getting workflow revisions for workflow %s.", originalId)
	if project.DbType == "opensearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"id": originalId,
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return workflows, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
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

		for _, hit := range wrapped.Hits.Hits {
			if hit.Source.ID != originalId {
				continue
			}

			workflows = append(workflows, hit.Source)
		}
	} else {
		query := datastore.NewQuery(nameKey).Filter("id =", originalId).Limit(50)
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
					//log.Printf("[WARNING] Workflow iterator issue: %s", err)
					break
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
				nextStr := fmt.Sprintf("%s", nextCursor)
				if cursorStr == nextStr {
					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)
			}
		}
	}

	// Sort by edited
	sort.Slice(workflows, func(i, j int) bool {
		return workflows[i].Edited > workflows[j].Edited
	})

	// Deduplicate based on edited time
	filtered := []Workflow{}
	handled := []string{}
	for _, workflow := range workflows {
		if ArrayContains(handled, string(workflow.Edited)) {
			continue
		}

		handled = append(handled, string(workflow.Edited))
		filtered = append(filtered, workflow)
	}

	// Set cache
	if project.CacheDb {
		cacheData, err := json.Marshal(workflows)
		if err != nil {
			return workflows, nil
		}

		err = SetCache(ctx, cacheKey, cacheData, 60)
		if err != nil {
			log.Printf("[ERROR] Failed setting cache for workflow revisions: %s (not critical)", err)
		}
	}

	return workflows, nil
}

func SetAppRevision(ctx context.Context, app WorkflowApp) error {
	nameKey := "app_revisions"
	timeNow := int64(time.Now().Unix())
	app.Edited = timeNow
	if app.Created == 0 {
		app.Created = timeNow
	}

	actionNames := ""
	for _, action := range app.Actions {
		actionNames += fmt.Sprintf("%s-", action.Name)
	}

	appHashString := fmt.Sprintf("%s_%s_%s", app.Name, app.ID, actionNames)
	hasher := md5.New()
	hasher.Write([]byte(appHashString))
	appHash := hex.EncodeToString(hasher.Sum(nil))
	app.RevisionId = appHash

	// New struct, to not add body, author etc
	data, err := json.Marshal(app)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in set app revision: %s", err)
		return nil
	}
	if project.DbType == "opensearch" {
		err = indexEs(ctx, nameKey, app.RevisionId, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, app.RevisionId, nil)
		if _, err := project.Dbclient.Put(ctx, key, &app); err != nil {
			log.Printf("[ERROR] Error adding app revision: %s", err)
			return err
		}
	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, app.RevisionId)
		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for set app revision '%s': %s", cacheKey, err)
		}

		DeleteCache(ctx, fmt.Sprintf("%s_%s", nameKey, app.ID))
	}

	return nil
}

func SetWorkflowRevision(ctx context.Context, workflow Workflow) error {
	nameKey := "workflow_revisions"
	timeNow := int64(time.Now().Unix())
	workflow.Edited = timeNow
	if workflow.Created == 0 {
		workflow.Created = timeNow
	}

	// Tet ID to be an md5 for name+ID+action+triggers+variables
	// this makes sure overwrites don't happen, and duplicates aren't kept
	// json marshal actions
	actionData, actionerr := json.Marshal(workflow.Actions)
	triggerData, triggererr := json.Marshal(workflow.Triggers)
	variableData, variableerr := json.Marshal(workflow.WorkflowVariables)

	if actionerr != nil || triggererr != nil || variableerr != nil {
		log.Printf("[WARNING] Failed marshalling in set workflow revision: %s", actionerr)
		return nil
	}

	workflowHashString := fmt.Sprintf("%s_%s_%s_%s_%s", workflow.Name, workflow.ID, string(actionData), string(triggerData), string(variableData))
	// md5 of workflowHashString
	hasher := md5.New()
	hasher.Write([]byte(workflowHashString))
	workflowHash := hex.EncodeToString(hasher.Sum(nil))
	workflow.RevisionId = workflowHash

	// New struct, to not add body, author etc
	data, err := json.Marshal(workflow)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in set workflow revision: %s", err)
		return nil
	}
	if project.DbType == "opensearch" {
		err = indexEs(ctx, nameKey, workflow.RevisionId, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, workflow.RevisionId, nil)
		if _, err := project.Dbclient.Put(ctx, key, &workflow); err != nil {
			log.Printf("[WARNING] Error adding workflow revision: %s", err)
			return err
		}
	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, workflow.RevisionId)
		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for set workflow revision '%s': %s", cacheKey, err)
		}

		DeleteCache(ctx, fmt.Sprintf("%s_%s", nameKey, workflow.ID))
	}

	return nil
}

func fixPosition(position float64) float64 {
	intValue := int(math.Round(position)) // Convert the float to the nearest integer

	difference := position - float64(intValue)
	difference = math.Abs(difference)

	if difference == 0 {
		//log.Printf("[DEBUG] Position fixed from %s to %s", position, position + 0.001)
		return position + 0.001
	}

	return position
}

func FixWorkflowPosition(ctx context.Context, workflow Workflow) Workflow {
	for index, action := range workflow.Actions {
		workflow.Actions[index].Position.X = fixPosition(float64(action.Position.X))
		workflow.Actions[index].Position.Y = fixPosition(float64(action.Position.Y))

		// Check if no ID
		if action.ID == "" {
			workflow.Actions[index].ID = uuid.NewV4().String()
		}
	}

	for index, comments := range workflow.Comments {
		workflow.Comments[index].Position.X = fixPosition(float64(comments.Position.X))
		workflow.Comments[index].Position.Y = fixPosition(float64(comments.Position.Y))

		if comments.ID == "" {
			workflow.Comments[index].ID = uuid.NewV4().String()
		}
	}

	// Fix branches & triggers
	for index, trigger := range workflow.Triggers {
		if trigger.ID == "" {
			workflow.Triggers[index].ID = uuid.NewV4().String()
		}
	}

	for index, branch := range workflow.Branches {
		if branch.ID == "" {
			workflow.Branches[index].ID = uuid.NewV4().String()
		}
	}

	return workflow
}

func SetWorkflow(ctx context.Context, workflow Workflow, id string, optionalEditedSecondsOffset ...int) error {
	// Overwriting to be sure these are matching
	// No real point in having id + workflow.ID anymore
	id = workflow.ID

	nameKey := "workflow"
	timeNow := int64(time.Now().Unix())
	workflow.Edited = timeNow
	if workflow.Created == 0 {
		workflow.Created = timeNow
	}

	if len(optionalEditedSecondsOffset) > 0 {
		workflow.Edited += int64(optionalEditedSecondsOffset[0])
	}

	workflow = FixWorkflowPosition(ctx, workflow)

	// New struct, to not add body, author etc
	data, err := json.Marshal(workflow)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in set workflow: %s", err)
		return nil
	}

	if project.DbType == "opensearch" {
		err = indexEs(ctx, nameKey, id, data)
		if err != nil {
			return err
		}
	} else {
		//log.Printf("\n\n[INFO] Adding workflow with ID %s\n\n", id)
		key := datastore.NameKey(nameKey, id, nil)
		if _, err := project.Dbclient.Put(ctx, key, &workflow); err != nil {
			log.Printf("[ERROR] Failed adding workflow with ID %s: %s", id, err)
			return err
		}
	}

	// Handles parent/child workflow relationships
	if len(workflow.ParentWorkflowId) > 0 {
		DeleteCache(ctx, fmt.Sprintf("workflow_%s_childworkflows", workflow.ID))
	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getworkflow '%s': %s", cacheKey, err)
		}

		// Find the key for "workflows_<workflow.org_id>" and update the cache for this one. If it doesn't exist, add it

		// Get the cache for the workflows
		cacheKey = fmt.Sprintf("%s_workflows", workflow.OrgId)
		cache, err := GetCache(ctx, cacheKey)
		if err != nil {
			//log.Printf("[WARNING] Failed getting cache for getworkflow '%s': %s", cacheKey, err)
		} else {
			var workflows []Workflow

			cacheData := []byte(cache.([]uint8))
			//log.Printf("[INFO] Got cache for getworkflow '%s': %s", cacheKey, cacheData)
			err = json.Unmarshal(cacheData, &workflows)
			if err != nil {
				log.Printf("[WARNING] Failed unmarshalling cache for getworkflow '%s': %s", cacheKey, err)
			} else {
				slice.Sort(workflows[:], func(i, j int) bool {
					return workflows[i].Edited > workflows[j].Edited
				})

				// Find the workflow in the cache
				found := false
				for i, w := range workflows {
					if w.ID == id {
						// Update the cache
						workflows[i] = workflow
						found = true
						break
					}
				}

				if !found {
					// Add it to the cache
					workflows = append(workflows, workflow)
				}

				// Marshal
				workflowsData, err := json.Marshal(workflows)
				if err != nil {
					log.Printf("[WARNING] Failed marshalling cache for getworkflow '%s': %s", cacheKey, err)
				} else {
					err = SetCache(ctx, cacheKey, workflowsData, 30)
					if err != nil {
						log.Printf("[WARNING] Failed setting cache for getworkflow '%s': %s", cacheKey, err)
					}
				}
			}
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

	if len(workflowappauth.Fields) > 500 {
		//log.Printf("[WARNING][%s] Too many fields for app auth: %d", id, len(workflowappauth.Fields))
		newfields := []AuthenticationStore{}

		// Rebuilds all fields
		addedFields := []string{}

		// Run loop backwards due to ordering, as to take last version of all parts
		for i := len(workflowappauth.Fields) - 1; i >= 0; i-- {
			field := workflowappauth.Fields[i]
			if ArrayContains(addedFields, field.Key) {
				continue
			}

			addedFields = append(addedFields, field.Key)
			newfields = append(newfields, field)
		}

		workflowappauth.Fields = newfields

		log.Printf("[INFO][%s] Reduced auth fields for app auth to %d", id, len(workflowappauth.Fields))
	}

	// Will ALWAYS encrypt the values when it's not done already
	// This makes it so just re-saving the auth will encrypt them (next run)

	// Uses OrgId (Database) + Backend (ENV) modifier for the keys.
	// Using created timestamp to ensure it's always unique, even if it's the same key of same app in same org.
	if !workflowappauth.Encrypted {
		setEncrypted := true
		newFields := []AuthenticationStore{}
		for _, field := range workflowappauth.Fields {
			// Custom skip for this
			//if field.Key == "url" {
			//	newFields = append(newFields, field)
			//	continue
			//}

			parsedKey := fmt.Sprintf("%s_%d_%s_%s", workflowappauth.OrgId, workflowappauth.Created, workflowappauth.Label, field.Key)
			newKey, err := handleKeyEncryption([]byte(field.Value), parsedKey)
			if err != nil {
				//log.Printf("[WARNING] Failed encrypting key '%s': %s", field.Key, err)
				setEncrypted = false
				break
			}

			field.Value = string(newKey)
			newFields = append(newFields, field)
		}

		if setEncrypted {
			//log.Printf("[INFO] Encrypted authentication values as they weren't already encrypted")
			workflowappauth.Fields = newFields
			workflowappauth.Encrypted = true
		}
	}

	// New struct, to not add body, author etc
	if project.DbType == "opensearch" {
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

			return err
		}
	}

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	DeleteCache(ctx, cacheKey)
	cacheKey = fmt.Sprintf("%s_%s", nameKey, workflowappauth.OrgId)
	DeleteCache(ctx, cacheKey)

	return nil
}

func GetAppAuthGroup(ctx context.Context, id string) (*AppAuthenticationGroup, error) {
	authGroup := &AppAuthenticationGroup{}
	nameKey := "workflowappauthgroup"

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &authGroup)
			if err == nil && authGroup.Id != "" {
				return authGroup, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for authGroup: %s", err)
		}
	}

	if project.DbType == "opensearch" {
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
			return authGroup, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return authGroup, errors.New("Workflow doesn't exist")
		}

		defer res.Body.Close()
		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return authGroup, err
		}

		wrapped := AuthGroupWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return authGroup, err
		}

		authGroup = &wrapped.Source
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		if err := project.Dbclient.Get(ctx, key, authGroup); err != nil {
			log.Printf("[WARNING] Error getting workflow app auth group %s: %s", id, err)
			return authGroup, err
		}
	}

	if project.CacheDb && authGroup.Id != "" {
		data, err := json.Marshal(authGroup)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in get auth group: %s", err)
			return authGroup, nil
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for authGroup '%s': %s", cacheKey, err)
		}
	}

	return authGroup, nil
}

func SetAuthGroupDatastore(ctx context.Context, workflowappauthgroup AppAuthenticationGroup, id string) error {
	nameKey := "workflowappauthgroup"
	timeNow := int64(time.Now().Unix())
	if workflowappauthgroup.Created == 0 {
		workflowappauthgroup.Created = timeNow
	}

	data, err := json.Marshal(workflowappauthgroup)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in set app auth group: %s", err)
		return err
	}

	workflowappauthgroup.Edited = timeNow

	// Check for uniqueness and organization membership
	newAuth := []AppAuthenticationStorage{}
	removeIds := []string{}
	uniqueIds := make(map[string]bool)
	for _, auth := range workflowappauthgroup.AppAuths {
		// Check uniqueness
		if _, exists := uniqueIds[auth.Id]; exists {
			log.Printf("[WARNING] App auth group %s has duplicate app auth id %s", id, auth.Id)
			//return errors.New("Duplicate app auth id")
			removeIds = append(removeIds, auth.Id)
			continue
		}


		// Fetch real data
		uniqueIds[auth.Id] = true
		realAuth, err := GetWorkflowAppAuthDatastore(ctx, auth.Id)
		if err != nil {
			log.Printf("[WARNING] Failed getting app auth %s for app auth group %s: %s", auth.Id, id, err)
			removeIds = append(removeIds, auth.Id)

			// Remove the app auth from the slice
			//workflowappauthgroup.AppAuths = append(workflowappauthgroup.AppAuths[:index], workflowappauthgroup.AppAuths[index+1:]...)
			continue
		}

		// Update the slice with real data
		//workflowappauthgroup.AppAuths[index] = *realAuth
		auth = *realAuth

		// Check organization membership
		if realAuth.OrgId != workflowappauthgroup.OrgId {
			log.Printf("[WARNING] App auth group %s has app auth id %s that doesn't belong to the same org", id, auth.Id)
			removeIds = append(removeIds, auth.Id)
			continue
		}

		auth.App.SmallImage = ""
		auth.App.LargeImage = ""
		auth.App.Documentation = ""

		for authFieldIndex, _ := range auth.Fields {
			auth.Fields[authFieldIndex].Value = ""
		}

		newAuth = append(newAuth, auth)
	}

	workflowappauthgroup.AppAuths = newAuth

	// Remove the invalid app auths
	for _, removeId := range removeIds {
		for index, auth := range workflowappauthgroup.AppAuths {
			if auth.Id == removeId {
				log.Printf("[WARNING] Removed invalid app auth %s from app auth group %s", removeId, id)
				workflowappauthgroup.AppAuths = append(workflowappauthgroup.AppAuths[:index], workflowappauthgroup.AppAuths[index+1:]...)
				break
			}
		}
	}


	// New struct, to not add body, author etc
	if project.DbType == "opensearch" {
		err = indexEs(ctx, nameKey, id, data)
		if err != nil {
			log.Printf("[ERROR] Error adding workflow app AUTH group %s (%s) with %d apps: %s", workflowappauthgroup.Label, workflowappauthgroup.Id, len(workflowappauthgroup.AppAuths), err)
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, id, nil)
		if _, err := project.Dbclient.Put(ctx, key, &workflowappauthgroup); err != nil {
			log.Printf("[ERROR] Error adding workflow app AUTH group %s (%s) with %d apps: %s", workflowappauthgroup.Label, workflowappauthgroup.Id, len(workflowappauthgroup.AppAuths), err)
			return err
		}
	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
		err := SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for setusecase: %s", err)
		}

		cacheKey = fmt.Sprintf("%s_%s", nameKey, workflowappauthgroup.OrgId)
		DeleteCache(ctx, cacheKey)
	}

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
	if project.DbType == "opensearch" {
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
			log.Printf("[ERROR] Failed to update environment %s: %s", env.Id, err)
			return err
		}
	}

	cacheKey := fmt.Sprintf("%s_%s", nameKey, env.OrgId)
	DeleteCache(ctx, cacheKey)

	return nil
}

func GetScheduleByWorkflowId(ctx context.Context, workflowId string) (*ScheduleOld, error) {
	nameKey := "schedules"
	curSchedule := &ScheduleOld{}
	if project.DbType == "opensearch" {
		return curSchedule, errors.New("Not implemented")
	} else {
		q := datastore.NewQuery(nameKey).Filter("workflow_id =", workflowId).Limit(1)
		tmpSchedules := []ScheduleOld{}
		_, err := project.Dbclient.GetAll(ctx, q, &tmpSchedules)
		if err != nil && len(tmpSchedules) == 0 {
			log.Printf("[WARNING] Error getting schedules for workflow Id: %s", err)
			return curSchedule, err
		}

		if len(tmpSchedules) > 0 {
			curSchedule = &tmpSchedules[0]
		}
	}

	return curSchedule, nil
}

func GetSchedule(ctx context.Context, schedulename string) (*ScheduleOld, error) {
	nameKey := "schedules"

	cacheKey := fmt.Sprintf("%s_%s", nameKey, schedulename)
	curUser := &ScheduleOld{}
	if project.DbType == "opensearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), strings.ToLower(schedulename))
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
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

func GetHooks(ctx context.Context, OrgId string) ([]Hook, error) {
	hooks := []Hook{}
	nameKey := "hooks"
	OrgId = strings.ToLower(OrgId)

	//FIXME: Implement caching

	if project.DbType == "opensearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"from": 0,
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"org_id": OrgId,
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return []Hook{}, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get hooks): %s", err)
			return []Hook{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return []Hook{}, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return []Hook{}, nil
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
			return []Hook{}, fmt.Errorf("Bad statuscode: %d", res.StatusCode)
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return []Hook{}, err
		}
		wrapper := AllHooksWrapper{}
		err = json.Unmarshal(respBody, &wrapper)
	
		if err != nil {
			return []Hook{}, err
		}

		for _, hit := range wrapper.Hits.Hits {
			hook := hit.Source 
			hooks = append(hooks, hook) 
		}
		return hooks, err
		
	} else {
		q := datastore.NewQuery(nameKey).Filter("org_id = ", OrgId).Limit(1000)

		_, err := project.Dbclient.GetAll(ctx, q, &hooks)
		if err != nil && len(hooks) == 0 {
			return hooks, err
		}
	}

	return hooks, nil
}

func GetPipelines(ctx context.Context, OrgId string) ([]Pipeline, error) {
	pipelines := []Pipeline{}
	nameKey := "pipelines"
	OrgId = strings.ToLower(OrgId)

	//FIXME: Implement caching

	if project.DbType == "opensearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"from": 0,
			"size": 1000,
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"org_id": OrgId,
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding find user query: %s", err)
			return []Pipeline{}, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get pipelines): %s", err)
			return []Pipeline{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return []Pipeline{}, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return []Pipeline{}, nil
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
			return []Pipeline{}, fmt.Errorf("bad statuscode: %d", res.StatusCode)
			
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return []Pipeline{}, err
		}
		wrapper := AllPipelinesWrapper{}
		err = json.Unmarshal(respBody, &wrapper)
	
		if err != nil {
			return []Pipeline{}, err
		}

		for _, hit := range wrapper.Hits.Hits {
			pipeline := hit.Source 
			pipelines = append(pipelines, pipeline) 
		}
		return pipelines, err
		
	} else {
		q := datastore.NewQuery(nameKey).Filter("org_id = ", OrgId).Limit(1000)

		_, err := project.Dbclient.GetAll(ctx, q, &pipelines)
		if err != nil && len(pipelines) == 0 {
			return pipelines, err
		}
	}

	return pipelines, nil
}

func GetSessionNew(ctx context.Context, sessionId string) (User, error) {
	cacheKey := fmt.Sprintf("session_%s", sessionId)
	user := &User{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &user)
			if err == nil && len(user.Id) > 0 {

				return *user, nil
			} else {
				log.Printf("[WARNING] Bad cache for %s: %s", sessionId, err)
				//return *user, errors.New(fmt.Sprintf("Bad cache for %s", sessionId))
			}
		} else {
		}
	}

	// Query for the specific API-key in users
	nameKey := "Users"
	var users []User
	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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
		return User{}, errors.New("No users found for this apikey (1)")
	}

	if project.CacheDb {
		data, err := json.Marshal(users[0])
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getSession: %s", err)
			return User{}, err
		}

		err = SetCache(ctx, cacheKey, data, 30)
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
	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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
		return User{}, errors.New("No users found for this apikey (2)")
	}

	return users[0], nil
}

func savePipelineData(ctx context.Context, pipeline Pipeline) error {
	// assuming IndexRequest can be used as an upsert operation
	nameKey := "pipelines"

	pipelineData, err := json.Marshal(pipeline)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in savePipelineData: %s", err)
		return err
	}
	triggerId := strings.ToLower(pipeline.TriggerId)
	if project.DbType == "opensearch" {
		err = indexEs(ctx, nameKey, triggerId, pipelineData)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, triggerId, nil)
		if _, err := project.Dbclient.Put(ctx, key, &pipeline); err != nil {
			log.Printf("[ERROR] failed to add pipeline: %s", err)
			return err
	}
	}

	return nil
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
			err = json.Unmarshal(cacheData, &hook)
			if err == nil && len(hook.Id) > 0 {
				return hook, nil
			} else {
				log.Printf("[ERROR] Failed unmarshalling cache for hook: %s", err)
				//return hook, errors.New(fmt.Sprintf("Bad cache for %s", hookId))
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for hook: %s", err)
		}
	}
	//log.Printf("DBTYPE: %s", project.DbType)

	var err error
	if project.DbType == "opensearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), hookId)
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
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

		err = SetCache(ctx, cacheKey, hookData, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for gethook '%s': %s", cacheKey, err)
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
	if project.DbType == "opensearch" {
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
		err = SetCache(ctx, cacheKey, hookData, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for hook key '%s': %s", cacheKey, err)
		}
	}

	return nil
}

func GetPipeline(ctx context.Context, triggerId string) (*Pipeline, error) {
	pipeline := &Pipeline{}
	nameKey := "pipelines"
	
	triggerId = strings.ToLower(triggerId)

	if project.DbType == "opensearch" {

		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), triggerId)
		if err != nil {
			return &Pipeline{}, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return &Pipeline{}, errors.New("pipeline doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return &Pipeline{}, err
		}

		wrapped := PipelineWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return &Pipeline{}, err
		}

		pipeline = &wrapped.Source
	}  else {
		// key := datastore.NameKey(nameKey, triggerId, nil)
		// err := project.Dbclient.Get(ctx, key, pipeline)
		// if err != nil {
		// 	return &Pipeline{}, err
		// }
	}
	return pipeline, nil
}

func GetNotification(ctx context.Context, id string) (*Notification, error) {
	nameKey := "notifications"

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	curFile := &Notification{}
	if project.DbType == "opensearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
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

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			curFile := &File{}
			err = json.Unmarshal(cacheData, &curFile)
			if err == nil {
				return curFile, nil
			}
		}
	}

	curFile := &File{}
	if project.DbType == "opensearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
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

	if project.CacheDb {
		fileData, err := json.Marshal(curFile)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getfile: %s", err)
			return curFile, nil 
		}

		err = SetCache(ctx, cacheKey, fileData, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for file key '%s': %s", cacheKey, err)
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

	if project.DbType == "opensearch" {
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
	cacheKey = fmt.Sprintf("%s_%s", nameKey, notification.UserId)
	DeleteCache(ctx, cacheKey)

	return nil
}

func SetFile(ctx context.Context, file File) error {
	// clear session_token and API_token for user
	timeNow := time.Now().Unix()
	file.UpdatedAt = timeNow
	nameKey := "Files"

	if file.CreatedAt == 0 {
		file.CreatedAt = timeNow
	}

	/*
	if !strings.HasPrefix(file.Id, "file_") {
		return errors.New("Invalid file ID. Must start with file_")
	}
	*/

	cacheKey := fmt.Sprintf("%s_%s", nameKey, file.Id)

	if project.DbType == "opensearch" {
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

	if project.CacheDb {
		data, err := json.Marshal(file)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in setfile: %s", err)

		} else {
			err = SetCache(ctx, cacheKey, data, 30)
			if err != nil {
				log.Printf("[WARNING] Failed setting cache for set file '%s': %s", cacheKey, err)
			}
		}
	}

	DeleteCache(ctx, fmt.Sprintf("files_%s_%s", file.OrgId, file.Namespace))
	DeleteCache(ctx, fmt.Sprintf("files_%s_", file.OrgId))


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
			err = json.Unmarshal(cacheData, &notifications)
			if err == nil {
				return notifications, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for org: %s", err)
		}
	}

	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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
			if hit.Source.Personal {
				continue
			}

			if hit.Source.OrgId == orgId {
				notifications = append(notifications, hit.Source)
			}
		}

	} else {
		q := datastore.NewQuery(nameKey).Filter("org_id =", orgId).Order("-updated_at").Limit(200)
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
			} else if strings.Contains(fmt.Sprintf("%s", err), "no matching index found") || strings.Contains(fmt.Sprintf("%s", err), "not ready to serve") {
				log.Printf("[ERROR] Failed loading notifications based on index: %s", err)

				q := datastore.NewQuery(nameKey).Filter("org_id =", orgId).Limit(200)
				_, err := project.Dbclient.GetAll(ctx, q, &notifications)
				if err != nil && len(notifications) == 0 {
					return notifications, err
				}

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

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed updating notification cache: %s", err)
		}
	}

	return notifications, nil
}

func GetUserNotifications(ctx context.Context, userId string) ([]Notification, error) {
	var notifications []Notification

	nameKey := "notifications"
	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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

	cacheKey := fmt.Sprintf("files_%s_%s", orgId, namespace)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &files)
			if err == nil {
				return files, nil
			}
		}
	}

	nameKey := "Files"
	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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
		q := datastore.NewQuery(nameKey).Filter("org_id =", orgId).Order("-created_at").Limit(200)
		if len(namespace) > 0 {
			q = datastore.NewQuery(nameKey).Filter("namespace =", namespace).Filter("org_id =", orgId).Order("-created_at").Limit(200)
		}

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
				log.Printf("[ERROR] Failed loading files: %s", err)
				return []File{}, err
			}
		}

		// Finds extra namespaces in the db if none are specified
		if len(namespace) == 0 {
			foundNamespaces := []string{}
			for _, f := range files {
				if f.OrgId != orgId {
					continue
				}

				if !ArrayContains(foundNamespaces, f.Namespace) {
					foundNamespaces = append(foundNamespaces, f.Namespace)
				}
			}

			var namespaceFiles []File
			namespaceQuery := datastore.NewQuery(nameKey).Filter("org_id =", orgId).Filter("namespace !=", "").Limit(1000)
			_, err = project.Dbclient.GetAll(ctx, namespaceQuery, &namespaceFiles)
			if err != nil {
				log.Printf("[ERROR] Failed loading namespace files: %s", err)
				return files, nil
			}

			for _, f := range namespaceFiles {
				if f.OrgId != orgId {
					continue
				}

				if !ArrayContains(foundNamespaces, f.Namespace) {
					foundNamespaces = append(foundNamespaces, f.Namespace)

					files = append(files, f)
				}
			}
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(files)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling file cache: %s", err)
			return files, nil
		}

		err = SetCache(ctx, cacheKey, data, 2)
		if err != nil {
			log.Printf("[WARNING] Failed updating file cache: %s", err)
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
			err = json.Unmarshal(cacheData, &appAuth)
			if err == nil {
				return appAuth, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for org: %s", err)
		}
	}

	// New struct, to not add body, author etc
	if project.DbType == "opensearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
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
			if !strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
				log.Printf("[ERROR] Failed loading app auth: %s", err)
				return &AppAuthenticationStorage{}, err
			}

			log.Printf("[ERROR] Failed loading app auth fields for auth %s (continue anyway): %s", appAuth.Id, err)
		}
	}

	allFields := []string{}
	newFields := []AuthenticationStore{}
	for _, field := range appAuth.Fields {
		if ArrayContains(allFields, field.Key) {
			continue
		}

		allFields = append(allFields, field.Key)
		newFields = append(newFields, field)
	}

	appAuth.Fields = newFields

	if project.CacheDb {
		data, err := json.Marshal(appAuth)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling app auth cache: %s", err)
			return appAuth, nil
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed updating app auth cache: %s", err)
		}
	}

	return appAuth, nil
}

func GetAuthGroups(ctx context.Context, orgId string) ([]AppAuthenticationGroup, error) {
	nameKey := "workflowappauthgroup"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, orgId)

	appAuths := []AppAuthenticationGroup{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &appAuths)
			if err == nil {
				return appAuths, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for org: %s", err)
		}
	}

	if project.DbType == "opensearch" {
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
			return appAuths, err
		}
		
		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get app auths): %s", err)
			return appAuths, err
		}

		defer res.Body.Close()

		if res.StatusCode == 404 {
			return appAuths, nil
		}

	} else {
		q := datastore.NewQuery(nameKey).Filter("org_id =", orgId).Limit(50)
		_, err := project.Dbclient.GetAll(ctx, q, &appAuths)
		if err != nil && len(appAuths) == 0 {
			return appAuths, err
		}
	}
	
	if project.CacheDb {
		data, err := json.Marshal(appAuths)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling app auth cache: %s", err)
			return appAuths, nil
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed updating app auth cache: %s", err)
		}
	}

	return appAuths, nil
}

func GetAllSchedules(ctx context.Context, orgId string) ([]ScheduleOld, error) {
	var schedules []ScheduleOld

	nameKey := "schedules"
	if project.DbType == "opensearch" {
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
			query = map[string]interface{}{
				"from": 0,
				"size": 1000,
			}
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("Error encoding query: %s", err)
			return schedules, err
		}

		// Perform the search request.
		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
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

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	triggerauth := &TriggerAuth{}
	if project.DbType == "opensearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), strings.ToLower(id))
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
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
	if project.DbType == "opensearch" {
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
	if project.DbType == "opensearch" {
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

func GetAllWorkflows(ctx context.Context) ([]Workflow, error) {
	index := "workflow"

	workflows := []Workflow{}
	if project.DbType == "opensearch" {
		var buf bytes.Buffer
		query := map[string]interface{} {
			"from": 0,
			"size": 1000,
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding  %s", err)
			return workflows, err
		}

		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(index))),
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
			workflows = append(workflows, hit.Source)
		}
		return workflows, nil
	} else {
		// implementation for different db
		q := datastore.NewQuery(index).Limit(50)

		_, err := project.Dbclient.GetAll(ctx, q, &workflows)
		if err != nil {
			return []Workflow{}, err
		}
	}
		return workflows, nil
}

func GetAllUsers(ctx context.Context) ([]User, error) {
	index := "Users"

	users := []User{}
	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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
	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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
		query := datastore.NewQuery(index).Filter("workflow_id =", workflowId).Order("-started_at").Limit(5)
		//query := datastore.NewQuery(index).Filter("workflow_id =", workflowId).Limit(10)
		max := 100
		cursorStr := ""
		for {
			it := project.Dbclient.Run(ctx, query)

			for {
				innerWorkflow := WorkflowExecution{}
				_, err := it.Next(&innerWorkflow)
				if err != nil {
					// log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
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

	// Gets the correct one from cache to make it appear to be correct everywhere
	for execIndex, execution := range executions {
		if execution.Status == "EXECUTING" {
			// Get the right one from cache
			newexec, err := GetWorkflowExecution(ctx, execution.ExecutionId)
			if err == nil {
				// Set the execution as well in the database
				if newexec.Status != execution.Status {

					if project.Environment == "cloud" {
						go SetWorkflowExecution(ctx, *newexec, true)
					} else {
						SetWorkflowExecution(ctx, *newexec, false)
					}
				}

				executions[execIndex] = *newexec
			}
		}
	}

	return executions, nil
}

func GetAllWorkflowExecutionsV2(ctx context.Context, workflowId string, amount int, inputcursor string) ([]WorkflowExecution, string, error) {
	index := "workflowexecution"

	//cacheKey := fmt.Sprintf("%s_%s_%s", index, inputcursor, workflowId)
	var executions []WorkflowExecution
	var err error
	totalMaxSize := 11184810

	cursor := ""
	if project.DbType == "opensearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": amount,
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": []map[string]interface{}{
						{
							"match": map[string]interface{}{
								"workflow_id": workflowId,
							},
						},
					},
				},
			},
			"sort": map[string]interface{}{
				"started_at": map[string]interface{}{
					"order": "desc",
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding executions query: %s", err)
			return executions, cursor, err
		}

		// Perform the search request.
		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(index))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)
		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get workflow executions): %s", err)
			return executions, cursor, err
		}

		defer res.Body.Close()
		if res.StatusCode == 404 {
			return executions, cursor, nil
		}

		defer res.Body.Close()
		if res.IsError() {
			var e map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
				log.Printf("[WARNING] Error parsing the response body: %s", err)
				return executions, cursor, err
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
			return executions, cursor, errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return executions, cursor, err
		}

		wrapped := ExecutionSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return executions, cursor, err
		}

		executions = []WorkflowExecution{}
		for _, hit := range wrapped.Hits.Hits {
			if hit.Source.WorkflowId == workflowId || hit.Source.Workflow.ID == workflowId {
				executions = append(executions, hit.Source)
			}
		}

	} else {
		query := datastore.NewQuery(index).Filter("workflow_id =", workflowId).Order("-started_at").Limit(5)
		if inputcursor != "" {
			outputcursor, err := datastore.DecodeCursor(inputcursor)
			if err != nil {
				log.Printf("[WARNING] Error decoding cursor: %s", err)
				return executions, "", err
			}

			query = query.Start(outputcursor)
		}

		// Create a timeout to prevent the query from taking more than 5 seconds total

		cursorStr := ""
		for {
			it := project.Dbclient.Run(ctx, query)

			breakOuter := false
			for {
				innerWorkflow := WorkflowExecution{}
				_, err := it.Next(&innerWorkflow)
				if err != nil {
					if strings.Contains(err.Error(), "context deadline exceeded") {
						log.Printf("[WARNING] Error getting workflow executions: %s", err)
						breakOuter = true
					}

					break
				}

				executions = append(executions, innerWorkflow)
			}

			if breakOuter {
				break
			}

			if err != iterator.Done {
				//log.Printf("[DEBUG] Breaking due to no more iterator")
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
						//log.Printf("Length breaking (2): %d", len(executionmarshal))
						break
					}
				}
			}

			// expected to get here
			if len(executions) >= amount {
				//log.Printf("[INFO] Breaking due to executions larger than amount (%d/%d)", len(executions), amount)
				// Get next cursor
				nextCursor, err := it.Cursor()
				if err != nil {
					log.Printf("[ERROR] Cursorerror: %s", err)
				} else {
					cursor = fmt.Sprintf("%s", nextCursor)
				}

				break
			}

			// Get the cursor for the next page of results.
			nextCursor, err := it.Cursor()
			if err != nil {
				log.Printf("[WARNING] Cursorerror: %s", err)
				break
			} else {
				nextStr := fmt.Sprintf("%s", nextCursor)
				cursor = nextStr
				if cursorStr == nextStr {
					//log.Printf("Breaking due to no new cursor")

					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)
			}
		}
	}

	// Find difference between what's in the list and what is in cache
	//log.Printf("\n\n[DEBUG] Checking local cache for executions. Got %d executions\n\n", len(executions))
	for execIndex, execution := range executions {
		if execution.Status == "EXECUTING" {
			//log.Printf("\n\n[DEBUG] Execution %s is executing, skipping cache\n\n", execution.ExecutionId)

			// Get the right one from cache
			newexec, err := GetWorkflowExecution(ctx, execution.ExecutionId)
			if err == nil {
				//log.Printf("[DEBUG] Got with status %s", newexec.Status)
				// Set the execution as well in the database
				if newexec.Status != execution.Status || len(newexec.Results) > len(execution.Results) {

					if project.Environment == "cloud" {
						go SetWorkflowExecution(ctx, *newexec, true)
					} else {
						SetWorkflowExecution(ctx, *newexec, true)
					}
				}

				executions[execIndex] = *newexec
			}
		} else {
			// Delete cache to clear up memory
			if project.Environment != "cloud" && (execution.Status == "ABORTED" || execution.Status == "FAILURE" || execution.Status == "FINISHED") {
				// Delete cache for it
				RunCacheCleanup(ctx, execution)
			}
		}
	}

	slice.Sort(executions[:], func(i, j int) bool {
		return executions[i].StartedAt > executions[j].StartedAt
	})

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
		}
	}

	/*
		if project.CacheDb {
			data, err := json.Marshal(executions)
			if err != nil {
				log.Printf("[WARNING] Failed marshalling update execution cache: %s", err)
				return executions, cursor, nil
			}

			err = SetCache(ctx, cacheKey, data, 10)
			if err != nil {
				log.Printf("[WARNING] Failed setting cache executions (%s): %s", workflowId, err)
				return executions, cursor, nil
			}
		}
	*/

	return executions, cursor, nil
}

func GetAllWorkflowExecutions(ctx context.Context, workflowId string, amount int) ([]WorkflowExecution, error) {
	index := "workflowexecution"

	cacheKey := fmt.Sprintf("%s_%s", index, workflowId)
	var executions []WorkflowExecution
	var err error
	totalMaxSize := 11184810
	/*
		if project.CacheDb {
			cache, err := GetCache(ctx, cacheKey)
			if err == nil {
				cacheData := []byte(cache.([]uint8))
				err = json.Unmarshal(cacheData, &executions)
				if err == nil {
					if len(executions) > amount {
						executions = executions[:amount]
					}

					log.Printf("[DEBUG] Returned %d executions for workflow %s", len(executions), workflowId)

					return executions, nil
				} else {
					log.Printf("[WARNING] Failed getting workflowexecutions for %s: %s", workflowId, err)
				}
			} else {
				//log.Printf("[WARNING] Failed getting execution cache for workflow %s", workflowId)
			}
		}
	*/

	if project.DbType == "opensearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": amount,
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": []map[string]interface{}{
						{
							"match": map[string]interface{}{
								"workflow_id": workflowId,
							},
						},
					},
				},
			},
			"sort": map[string]interface{}{
				"started_at": map[string]interface{}{
					"order": "desc",
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding executions query: %s", err)
			return executions, err
		}

		// Perform the search request.
		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
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
			if hit.Source.WorkflowId == workflowId || hit.Source.Workflow.ID == workflowId {
				executions = append(executions, hit.Source)
			}
		}

		//return executions, nil
	} else {
		// FIXME: Sorting doesn't seem to work...
		//StartedAt          int64          `json:"started_at" datastore:"started_at"`
		//query := datastore.NewQuery(index).Filter("workflow_id =", workflowId).Limit(10)
		//totalMaxSize := 33554432
		//totalMaxSize := 22369621 // Total of App Engine max /3*2
		//totalMaxSize := 11184810
		query := datastore.NewQuery(index).Filter("workflow_id =", workflowId).Order("-started_at").Limit(5)
		cursorStr := ""
		for {
			it := project.Dbclient.Run(ctx, query)

			for {
				innerWorkflow := WorkflowExecution{}
				_, err := it.Next(&innerWorkflow)
				if err != nil {
					//log.Printf("[WARNING] Error getting workflow executions: %s", err)
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
						//log.Printf("Length breaking (2): %d", len(executionmarshal))
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
	}

	slice.Sort(executions[:], func(i, j int) bool {
		return executions[i].StartedAt > executions[j].StartedAt
	})

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
		}
	}

	if project.CacheDb {
		data, err := json.Marshal(executions)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling update execution cache: %s", err)
			return executions, nil
		}

		err = SetCache(ctx, cacheKey, data, 10)
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
	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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
	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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
	if project.DbType == "opensearch" {
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
	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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
				nextStr := fmt.Sprintf("%s", nextCursor)
				if cursorStr == nextStr {
					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)
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

	if cacheData.Created == 0 {
		cacheData.Created = timeNow
	}

	//cacheId := fmt.Sprintf("%s_%s_%s", cacheData.OrgId, cacheData.WorkflowId, cacheData.Key)
	cacheId := fmt.Sprintf("%s_%s", cacheData.OrgId, cacheData.Key)
	if len(cacheId) > 128 {
		cacheId = cacheId[0:127]
	}

	// URL encode
	cacheId = url.QueryEscape(cacheId)
	cacheData.Authorization = ""

	if len(cacheData.PublicAuthorization) == 0 {
		cacheData.PublicAuthorization = uuid.NewV4().String()
	}

	// New struct, to not add body, author etc
	data, err := json.Marshal(cacheData)
	if err != nil {
		log.Printf("[ERROR] Failed marshalling in set cache key: %s", err)
		return nil
	}
	if project.DbType == "opensearch" {
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
		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[ERROR] Failed setting cache for set cache key '%s': %s", cacheKey, err)
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

	//log.Printf("[WARNING] ID in get cache: %s", id)
	id = url.QueryEscape(id)

	// 2e7b6a08-b63b-4fc2-bd70-718091509db1
	// b0ef85ff-353c-4dbf-9e47-b9d0474dc14e
	// 4.6.11.191

	// 2e7b6a08-b63b-4fc2-bd70-718091509db1_b0ef85ff-353c-4dbf-9e47-b9d0474dc14e_4.6.11.191
	// 2e7b6a08-b63b-4fc2-bd70-718091509db1_4.6.11.191

	//fmt.Println("http://example.com/say?message="+url.QueryEscape(s))

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			parsedCache := []byte(cache.([]uint8))
			err = json.Unmarshal(parsedCache, &cacheData)
			if err == nil {
				return cacheData, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for cache key %s: %s", id, err)
		}
	}

	if project.DbType == "opensearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
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
		key := datastore.NameKey(nameKey, id, nil)
		if err := project.Dbclient.Get(ctx, key, cacheData); err != nil {

			if strings.Contains(err.Error(), `cannot load field`) {
				log.Printf("[ERROR] Error in workflow loading. Migrating workflow to new workflow handler (2): %s", err)
				err = nil
			} else {
				log.Printf("[WARNING] Error in cache key loading for %s: %s", id, err)

				// Search for key by removing first uuid part
				newId := id
				orgId := ""
				newIdSplit := strings.Split(id, "_")
				if len(newIdSplit) > 1 {
					orgId = newIdSplit[0]
					newId = strings.Join(newIdSplit[1:], "_")
				} else {
					log.Printf("[ERROR] Failed splitting cache id %s", id)
					return cacheData, err
				}

				// 2e7b6a08-b63b-4fc2-bd70-718091509db1
				// b0ef85ff-353c-4dbf-9e47-b9d0474dc14e
				// Skipped+because+of+previous+node+-+1

				newId, err = url.QueryUnescape(newId)
				if err != nil {
					log.Printf("[ERROR] Failed unescaping cache id %s", newId)
				}

				// Search for it in datastore with key =
				cacheKeys := []CacheKeyData{}
				cacheData.FormattedKey = newId
				query := datastore.NewQuery(nameKey).Filter("Key =", newId).Limit(5)
				_, err := project.Dbclient.GetAll(ctx, query, &cacheKeys)
				if err != nil {
					log.Printf("[WARNING] Failed getting cacheKey %s: %s (1)", newId, err)
					return cacheData, err
				}

				if len(cacheKeys) > 0 {
					for _, cacheKey := range cacheKeys {
						if cacheKey.OrgId == orgId {
							cacheData = &cacheKey
							break
						}
					}

					if cacheData.Key == "" {
						return cacheData, errors.New("Key doesn't exist")
					}
				} else {
					log.Printf("[WARNING] Failed getting cacheKey %s: %s (2)", newId, err)

					return cacheData, errors.New("Key doesn't exist")
				}
			}
		} else {
			cacheData.FormattedKey = id
		}
	}

	if project.CacheDb {
		//log.Printf("[DEBUG] Setting cache for workflow %s", cacheKey)
		data, err := json.Marshal(cacheData)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getcachekey: %s", err)
			return cacheData, nil
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for get cache key: %s", err)
		}
	}

	return cacheData, nil
}

var retryCount int

func RunInit(dbclient datastore.Client, storageClient storage.Client, gceProject, environment string, cacheDb bool, dbType string, defaultCreds bool, count int) (ShuffleStorage, error) {
	if dbType == "elasticsearch" {
		dbType = "opensearch"
	}

	cloudRunUrl := os.Getenv("SHUFFLE_CLOUDRUN_URL")
	if cloudRunUrl == "" {
		cloudRunUrl = "https://shuffler.io"
	}

	project = ShuffleStorage{
		Dbclient:      dbclient,
		StorageClient: storageClient,
		GceProject:    gceProject,
		Environment:   environment,
		CacheDb:       cacheDb,
		DbType:        dbType,
		CloudUrl:      cloudRunUrl,
		BucketName:    "shuffler.appspot.com",
	}

	bucketName := os.Getenv("SHUFFLE_ORG_BUCKET")
	if len(bucketName) > 0 {
		log.Printf("[DEBUG] Using custom project bucketname: %s", bucketName)
		project.BucketName = bucketName
	}

	kmsDebugEnabled := os.Getenv("SHUFFLE_KMS_DEBUG")
	if strings.ToLower(kmsDebugEnabled) == "true" {
		kmsDebug = true
	}

	// docker run -p 11211:11211 --name memcache -d memcached -m 100
	log.Printf("[DEBUG] Starting with memcached address '%s' (SHUFFLE_MEMCACHED). If this is empty, fallback to default (appengine / local). Name: '%s'", memcached, environment)

	// In case of downtime / large requests
	if len(memcached) > 0 {
		mc.Timeout = 10 * time.Second
	}

	requestCache = cache.New(35*time.Minute, 35*time.Minute)
	if strings.ToLower(environment) != "worker" && (strings.ToLower(dbType) == "opensearch" || strings.ToLower(dbType) == "opensearch") {

		project.Es = *GetEsConfig(defaultCreds)

		ret, err := project.Es.Info()
		if err != nil {
			if strings.Contains(fmt.Sprintf("%s", err), "the client noticed that the server is not a supported distribution") {
				log.Printf("[ERROR] Version is not supported - most likely Elasticsearch >= 8.0.0.")
			}
		}

		if err != nil {
			if fmt.Sprintf("%s", err) == "EOF" {
				log.Printf("[ERROR] Database should be available soon. Retrying in 5 seconds: %s", err)
			} else {
				log.Printf("[WARNING] Failed setting up Opensearch: %s. Typically means the backend can't connect, or that there's a HTTPS vs HTTP problem. Is the SHUFFLE_OPENSEARCH_URL correct?", err)
			}

			if strings.Contains(fmt.Sprintf("%s", err), "x509: certificate signed by unknown authority") || strings.Contains(fmt.Sprintf("%s", err), "EOF") {
				if retryCount == 0 {
					esUrl := os.Getenv("SHUFFLE_OPENSEARCH_URL")
					if strings.Contains(esUrl, "http://") {
						esUrl = strings.Replace(esUrl, "http://", "https://", 1)
					}

					os.Setenv("SHUFFLE_OPENSEARCH_URL", esUrl)

					log.Printf("[ERROR] Automatically skipping SSL verification for Opensearch connection and swapping http/https.")
					os.Setenv("SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY", "true")

					retryCount += 1
					return RunInit(dbclient, storageClient, gceProject, environment, cacheDb, dbType, false, 0)
				}
			}

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

			if count == 0 {
				count += 1
				log.Printf("[ERROR] Trying default creds for ES once before failing")
				return RunInit(dbclient, storageClient, gceProject, environment, cacheDb, dbType, true, count)
			}

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
	} else {
		// Fix potential cloud init problems here
	}

	return project, nil
}

func GetEsConfig(defaultCreds bool) *opensearch.Client {
	esUrl := os.Getenv("SHUFFLE_OPENSEARCH_URL")
	if len(esUrl) == 0 {
		esUrl = "https://shuffle-opensearch:9200"
	}

	username := os.Getenv("SHUFFLE_OPENSEARCH_USERNAME")
	if len(username) == 0 {
		username = "admin"
	}

	password := os.Getenv("SHUFFLE_OPENSEARCH_PASSWORD")
	if len(password) == 0 {
		// New password that is set by default.
		// Security Audit points to changing this during onboarding.
		password = "StrongShufflePassword321!"
	}

	if defaultCreds {
		log.Printf("[DEBUG] Using default credentials for Opensearch (previous versions)")

		username = "admin"
		password = "admin"
	}

	log.Printf("[DEBUG] Using custom opensearch url '%s'", esUrl)

	// https://github.com/elastic/go-opensearch/blob/f741c073f324c15d3d401d945ee05b0c410bd06d/opensearch.go#L98
	config := opensearch.Config{
		Addresses:     strings.Split(esUrl, ","),
		Username:      username,
		Password:      password,
		MaxRetries:    5,
		RetryOnStatus: []int{500, 502, 503, 504, 429, 403},

		// User Agent to work with Elasticsearch 8
	}
	//APIKey:        os.Getenv("SHUFFLE_OPENSEARCH_APIKEY"),
	//CloudID:       os.Getenv("SHUFFLE_OPENSEARCH_CLOUDID"),

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
		//log.Printf("[DEBUG] SKIPPING SSL verification with Opensearch")
		skipSSLVerify = true
	}

	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS11,
		InsecureSkipVerify: skipSSLVerify,
	}

	//https://github.com/elastic/go-opensearch/blob/master/_examples/security/opensearch-cluster.yml
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

	es, err := opensearch.NewClient(config)
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

	if project.DbType == "opensearch" {
		return errors.New("No opensearch handler for this API ")
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

		log.Printf("[DEBUG] Uploaded OpenAPI for api with ID '%s' to path: %s", api.ID, openApiPath)
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

	if project.DbType == "opensearch" {
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
		err = SetCache(ctx, cacheKey, data, 30)
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
			err = json.Unmarshal(cacheData, &usecase)
			if err == nil {
				return usecase, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for usecase: %s", err)
		}
	}

	if project.DbType == "opensearch" {
		//log.Printf("GETTING ES USER %s",
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error for %s: %s", cacheKey, err)
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

		err = SetCache(ctx, cacheKey, data, 30)
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
	if project.DbType == "opensearch" {
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
		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for deal: %s", err)
		}
	}

	return nil
}

func GetAllCacheKeys(ctx context.Context, orgId string, max int, inputcursor string) ([]CacheKeyData, string, error) {
	nameKey := "org_cache"
	cacheKey := fmt.Sprintf("%s_%s_%s", nameKey, inputcursor, orgId)

	cursor := ""
	cacheKeys := []CacheKeyData{}
	if project.DbType == "opensearch" {
		log.Printf("[DEBUG] GETTING cachekeys for org %s in item %s", orgId, nameKey)
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": max,
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
								"org_id": orgId,
							},
						},
					},
				},
			},
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("Error encoding deal query: %s", err)
			return cacheKeys, "", err
		}

		// Perform the search request.
		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(nameKey))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)

		if err != nil {
			log.Printf("[ERROR] Error getting response from Opensearch (get cachekeys): %s", err)
			return cacheKeys, "", err
		}

		defer res.Body.Close()
		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return cacheKeys, "", err
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			log.Printf("[WARNING] Body of cachekeys is bad. Status: %d. This is fixed by adding an item.", res.StatusCode)

			if res.StatusCode == 404 {
				return cacheKeys, "", nil
			}
			return cacheKeys, "", errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		wrapped := CacheKeySearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return cacheKeys, "", err
		}

		newCacheKeys := []CacheKeyData{}
		for _, hit := range wrapped.Hits.Hits {
			if hit.Source.OrgId != orgId {
				continue
			}

			newCacheKeys = append(newCacheKeys, hit.Source)
		}

		//log.Printf("[INFO] Got %d cachekeys for org %s (es)", len(newCacheKeys), orgId)
		cacheKeys = newCacheKeys
	} else {

		// Query datastore with pages

		query := datastore.NewQuery(nameKey).Filter("OrgId =", orgId).Order("-Edited").Limit(max)
		if inputcursor != "" {
			outputcursor, err := datastore.DecodeCursor(inputcursor)
			if err != nil {
				log.Printf("[WARNING] Error decoding cursor: %s", err)
				return cacheKeys, "", err
			}

			query = query.Start(outputcursor)
		}

		// Skip page in query
		errcnt := 0
		cursorStr := inputcursor
		var err error
		for {
			it := project.Dbclient.Run(ctx, query)

			for {
				innerWorkflow := CacheKeyData{}
				_, err := it.Next(&innerWorkflow)
				if err != nil {
					//log.Printf("[WARNING] Workflow iterator issue: %s", err)
					break
				}

				cacheKeys = append(cacheKeys, innerWorkflow)
			}

			if err != iterator.Done {
				//log.Printf("[ERROR] Failed fetching results for cache: %v", err)
				//break
			}

			if len(cacheKeys) >= max {
				// Get next cursor and set it as the new cursor

				nextCursor, err := it.Cursor()
				if err != nil {
					log.Printf("[WARNING] Cursorerror for cache: %s", err)
				} else {
					cursor = fmt.Sprintf("%s", nextCursor)
				}

				break
			}

			// Get the cursor for the next page of results.
			nextCursor, err := it.Cursor()
			if err != nil {
				if errcnt == 0 && (strings.Contains(err.Error(), "no matching index") || strings.Contains(err.Error(), "not ready to serve")) {
					log.Printf("[WARNING] No matching index for cache. Running without edit index.")
					query = datastore.NewQuery(nameKey).Filter("OrgId =", orgId).Limit(max)
					errcnt += 1
					continue
				}

				log.Printf("Cursorerror: %s", err)
				break
			} else {
				nextStr := fmt.Sprintf("%s", nextCursor)
				if cursorStr == nextStr {
					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)

				cursor = cursorStr
				//cursorStr = nextCursor
				//break
			}

		}

		//log.Printf("[INFO] Got %d cacheKeys for org %s (datastore)", len(cacheKeys), orgId)
	}

	// Sort by edited field
	slice.Sort(cacheKeys[:], func(i, j int) bool {
		return cacheKeys[i].Edited > cacheKeys[j].Edited
	})

	if project.CacheDb {
		newcache, err := json.Marshal(cacheKeys)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling cacheKeys: %s", err)
			return cacheKeys, cursor, nil
		}

		err = SetCache(ctx, cacheKey, newcache, 30)
		if err != nil {
			log.Printf("[WARNING] Failed updating cache keys cache: %s", err)
		}
	}

	return cacheKeys, cursor, nil
}

func GetAllDeals(ctx context.Context, orgId string) ([]ResellerDeal, error) {
	nameKey := "reseller_deal"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, orgId)

	deals := []ResellerDeal{}
	if project.DbType == "opensearch" {
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
			project.Es.Search.WithContext(ctx),
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

		err = SetCache(ctx, cacheKey, newdeal, 30)
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

	if project.DbType == "opensearch" {
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

		err = SetCache(ctx, cacheKey, data, 30)
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
	if project.DbType == "opensearch" {
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

	log.Printf("[AUDIT] Looking for creator stats for name %s", creatorName)

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

// Stopped clearing them out as the result from it is used in subsequent workflows as well (subflows). This means the 31 min timeout is default.
func RunCacheCleanup(ctx context.Context, workflowExecution WorkflowExecution) {
	// Keeping cache for 30-60 min due to rerun management
	if project.Environment == "cloud" {
		return
	}

	// As worker will be killed off anyway otherwise
	if os.Getenv("SHUFFLE_SWARM_CONFIG") != "run" {
		return
	}

	//log.Printf("[INFO][%s] Cleaning up cache for all %d results.", workflowExecution.ExecutionId, len(workflowExecution.Results))
	//for _, result := range workflowExecution.Results {
	//	cacheId := fmt.Sprintf("%s_%s_result", workflowExecution.ExecutionId, result.Action.ID)
	//	DeleteCache(ctx, cacheId)
	//}
	//DeleteCache(ctx, fmt.Sprintf("workflowexecution_%s", workflowExecution.ExecutionId))
}

func ValidateFinished(ctx context.Context, extra int, workflowExecution WorkflowExecution) bool {
	// Print 1/5 times to
	// Should find it if it doesn't exist
	//if extra == -1 {
	extra = 0
	for _, trigger := range workflowExecution.Workflow.Triggers {
		if trigger.Name == "User Input" || trigger.AppName == "User Input" || trigger.Name == "Shuffle Workflow" || trigger.AppName == "Shuffle Workflow" {

			extra += 1
		}
	}

	for _, action := range workflowExecution.Workflow.Actions {
		if action.AppName == "User Input" || action.AppName == "Shuffle Workflow" {
			extra += 1
		}
	}

	workflowExecution, _ = Fixexecution(ctx, workflowExecution)
	//if rand.Intn(5) == 1 || len(workflowExecution.Results) >= len(workflowExecution.Workflow.Actions) {
	log.Printf("[INFO][%s] Validation. Status: %s, Actions: %d, Extra: %d, Results: %d\n", workflowExecution.ExecutionId, workflowExecution.Status, len(workflowExecution.Workflow.Actions), extra, len(workflowExecution.Results))


	if len(workflowExecution.Results) >= len(workflowExecution.Workflow.Actions)+extra && len(workflowExecution.Workflow.Actions) > 0 {
		validResults := 0
		invalidResults := 0
		subflows := 0

		lastResult := ActionResult{}
		for _, result := range workflowExecution.Results {
			if result.Status == "EXECUTING" || result.Status == "WAITING" {
				log.Printf("[WARNING][%s] Waiting for action %s to finish", workflowExecution.ExecutionId, result.Action.ID)
				return false
			}

			if result.Status == "SUCCESS" && result.CompletedAt >= lastResult.CompletedAt {
				lastResult = result
			}

			if result.Status == "SUCCESS" {
				validResults += 1
			}

			if result.Status == "ABORTED" || result.Status == "FAILURE" {
				invalidResults += 1
			}

			if result.Action.AppName == "User Input" || result.Action.AppName == "Shuffle Workflow" {
				subflows += 1
			}
		}

		// Check if status is already set first from cache
		newexec, err := GetWorkflowExecution(ctx, workflowExecution.ExecutionId)
		if err == nil && (newexec.Status == "FINISHED" || newexec.Status == "ABORTED") {
			log.Printf("[INFO][%s] Already finished (validate)! Stopping the rest of the request for execution.", workflowExecution.ExecutionId)
			return true
		}


		// Updating stats for the workflow
		/*
		if project.Environment != "cloud" {
			for i := 0; i < validResults; i++ {
				IncrementCache(ctx, workflowExecution.OrgId, "app_executions")
			}

			for i := 0; i < invalidResults; i++ {
				IncrementCache(ctx, workflowExecution.OrgId, "app_executions_failed")
			}

			for i := 0; i < subflows; i++ {
				IncrementCache(ctx, workflowExecution.OrgId, "subflow_executions")
			}
		}
		*/

		if len(workflowExecution.Result) == 0 && len(lastResult.Result) > 0 {
			workflowExecution.Result = lastResult.Result
		}

		workflowExecution.CompletedAt = int64(time.Now().Unix())
		workflowExecution.Status = "FINISHED"

		HandleExecutionCacheIncrement(ctx, workflowExecution) 

		err = SetWorkflowExecution(ctx, workflowExecution, true)
		if err != nil {
			log.Printf("[ERROR] Failed to set execution during finalization %s: %s", workflowExecution.ExecutionId, err)
		} else {
			log.Printf("[INFO] Finalized execution %s for workflow %s with %d results and status %s", workflowExecution.ExecutionId, workflowExecution.Workflow.ID, len(workflowExecution.Results), workflowExecution.Status)

			// Validate text vs previous executions
			//RunTextClassifier(ctx, workflowExecution)

			// Enrich IPs and the like by finding stuff with regex
			RunCacheCleanup(ctx, workflowExecution)
			RunIOCFinder(ctx, workflowExecution)

			comparisonTime := workflowExecution.CompletedAt - workflowExecution.StartedAt

			userInput := false
			for _, result := range workflowExecution.Results {
				if result.Action.AppName == "User Input" {
					userInput = true
				}
			}

			if comparisonTime > 600 && !userInput {
				// FIXME: Check if there are any actions with delays?

				err := CreateOrgNotification(
					ctx,
					fmt.Sprintf("Workflow %s took too long to run. Time taken: %d seconds", workflowExecution.Workflow.Name, comparisonTime),
					fmt.Sprintf("This notification is made when the execution takes more than 10 minutes.", workflowExecution.Workflow.Name, comparisonTime),
					fmt.Sprintf("/workflows/%s?execution_id=%s&view=executions", workflowExecution.Workflow.ID, workflowExecution.ExecutionId),
					workflowExecution.ExecutionOrg,
					true,
				)

				if err != nil {
					log.Printf("[ERROR] Failed to create notification for workflow %s: %s", workflowExecution.Workflow.ID, err)
				}
			}

			return true
		}
	}

	HandleExecutionCacheIncrement(ctx, workflowExecution) 
	return false
}

func SetSuggestion(ctx context.Context, suggestion Suggestion) error {
	nameKey := "Suggestions"
	timeNow := int64(time.Now().Unix())
	suggestion.Edited = timeNow
	if suggestion.Created == 0 {
		suggestion.Created = timeNow
	}

	// New struct, to not add body, author etc
	data, err := json.Marshal(suggestion)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in set suggestion: %s", err)
		return nil
	}
	if project.DbType == "opensearch" {
		err = indexEs(ctx, nameKey, suggestion.SuggestionID, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, suggestion.SuggestionID, nil)
		if _, err := project.Dbclient.Put(ctx, key, &suggestion); err != nil {
			log.Printf("[WARNING] Error adding suggestion: %s", err)
			return err
		}
	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, suggestion.SuggestionID)
		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for set suggestion '%s': %s", cacheKey, err)
		}
	}

	return nil
}

func GetSuggestions(ctx context.Context, creatorname string) ([]Suggestion, error) {
	var suggestions []Suggestion

	nameKey := "Suggestions"
	if project.DbType == "opensearch" {
		// Not implemented
		return []Suggestion{}, nil
	} else {
		//log.Printf("Looking for name %s in %s", appName, nameKey)
		q := datastore.NewQuery(nameKey).Filter("creator =", creatorname).Filter("status =", "")
		_, err := project.Dbclient.GetAll(ctx, q, &suggestions)
		if err != nil && len(suggestions) == 0 {
			log.Printf("[WARNING] Failed getting suggestion for: %s. Err: %s", creatorname, err)
			return suggestions, err
		}
	}

	log.Printf("[INFO] Found %d suggestions for name %s in db-connector", len(suggestions), creatorname)

	slice.Sort(suggestions[:], func(i, j int) bool {
		return suggestions[i].Edited > suggestions[j].Edited
	})

	return suggestions, nil
}

func GetSuggestion(ctx context.Context, id string) (*Suggestion, error) {
	suggestion := &Suggestion{}
	nameKey := "Suggestions"

	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, &suggestion)
			if err == nil {
				return suggestion, nil
			}
		} else {
			//log.Printf("[DEBUG] Failed getting cache for workflow: %s", err)
		}
	}

	if project.DbType == "opensearch" {
		return suggestion, nil
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		if err := project.Dbclient.Get(ctx, key, suggestion); err != nil {
			if strings.Contains(err.Error(), `cannot load field`) {
				log.Printf("[ERROR] Error in workflow loading. Migrating workflow to new workflow handler (1): %s", err)
				err = nil
			} else {
				return suggestion, err
			}
		}
	}

	if project.CacheDb {
		//log.Printf("[DEBUG] Setting cache for suggestion %s", cacheKey)
		data, err := json.Marshal(suggestion)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in getsuggestion: %s", err)
			return suggestion, nil
		}

		err = SetCache(ctx, cacheKey, data, 60)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for getsuggestion'%s': %s", cacheKey, err)
		}
	}

	return suggestion, nil
}

func SetConversation(ctx context.Context, input QueryInput) error {
	nameKey := "conversations"

	if len(input.Id) == 0 {
		input.Id = uuid.NewV4().String()
	}

	// New struct, to not add body, author etc
	data, err := json.Marshal(input)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in conversation: %s", err)
		return nil
	}

	if project.DbType == "opensearch" {
		err = indexEs(ctx, nameKey, input.Id, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, input.Id, nil)
		if _, err := project.Dbclient.Put(ctx, key, &input); err != nil {
			log.Printf("[WARNING] Error adding conversation: %s", err)
			return err
		}
	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, input.Id)
		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for conversation '%s': %s", cacheKey, err)
		}
	}

	return nil
}

func SetenvStats(ctx context.Context, input OrborusStats) error {
	nameKey := "environment_stats"

	if len(input.Id) == 0 {
		input.Id = uuid.NewV4().String()
	}

	if input.Timestamp == 0 {
		input.Timestamp = time.Now().Unix()
	}

	// New struct, to not add body, author etc
	data, err := json.Marshal(input)
	if err != nil {
		log.Printf("[WARNING] Failed marshalling in conversation: %s", err)
		return nil
	}

	if project.DbType == "opensearch" {
		err = indexEs(ctx, nameKey, input.Id, data)
		if err != nil {
			return err
		}
	} else {
		key := datastore.NameKey(nameKey, input.Id, nil)
		if _, err := project.Dbclient.Put(ctx, key, &input); err != nil {
			log.Printf("[WARNING] Error adding stats: %s", err)
			return err
		}
	}

	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, input.Id)
		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for conversation '%s': %s", cacheKey, err)
		}
	}

	return nil
}

func GetNodeRelations(ctx context.Context) (map[string]NodeRelation, error) {
	// Check if we already have it in cache
	cacheKey := "workflow_node_relations"

	// Download a file
	allNodesRelations := make(map[string]NodeRelation)

	url := "https://storage.googleapis.com/shuffle_public/machine_learning/node_recs_2.json"
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("\n\n[WARNING] Failed getting node relations: %s\n\n", err)
		return allNodesRelations, err
	}

	defer resp.Body.Close()
	// Unmarshal
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[WARNING] Failed reading body: %s", err)
		return allNodesRelations, err
	}

	var nodeRelations map[string]NodeRelation
	err = json.Unmarshal(body, &nodeRelations)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshalling body: %s", err)
		return allNodesRelations, err
	}

	// Set cache for it
	if project.CacheDb {
		err = SetCache(ctx, cacheKey, body, 60*60*24*30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for node relations '%s': %s", cacheKey, err)
		}
	}

	return nodeRelations, nil
}

func GetDatastore() *datastore.Client {
	return &project.Dbclient
}

func GetStorage() *storage.Client {
	return &project.StorageClient
}

func GetWorkflowRunsBySearch(ctx context.Context, orgId string, search WorkflowSearch) ([]WorkflowExecution, string, error) {
	index := "workflowexecution"

	var executions []WorkflowExecution
	totalMaxSize := 11184810

	inputcursor := search.Cursor
	maxLimit := 20
	if search.Limit > 0 {
		maxLimit = search.Limit
	}

	cursor := ""
	if project.DbType == "opensearch" {
		var buf bytes.Buffer
		query := map[string]interface{}{
			"size": maxLimit,
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": []map[string]interface{}{
						{
							"match": map[string]interface{}{
								"execution_org": orgId,
							},
						},
					},
				},
			},
			"sort": map[string]interface{}{
				"started_at": map[string]interface{}{
					"order": "desc",
				},
			},
		}

		if len(search.WorkflowId) > 0 {
			// Change out the "must" part entirely to contain the workflow id as well
			query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"] = []map[string]interface{}{
				{
					"match": map[string]interface{}{
						"execution_org": orgId,
					},
				},
				{
					"match": map[string]interface{}{
						"workflow_id": search.WorkflowId,
					},
				},
			}
		}

		if len(search.Status) > 0 {

			// Change out the "must" part entirely to contain the workflow id as well
			// Append map[string]interface{} to the "must" part
			query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"] = append(query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"].([]map[string]interface{}), map[string]interface{}{
				"match": map[string]interface{}{
					"status": search.Status,
				},
			})
		}

		// String to timestamp for search.SearchFrom (string)
		startTimestamp, err := time.Parse(time.RFC3339, search.SearchFrom)
		if err != nil {
			//log.Printf("[WARNING] Failed parsing start time: %s", err)
		} else {
			// Make sure to add map[string]interface{} to the "must" part
			query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"] = append(query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"].([]map[string]interface{}), map[string]interface{}{
				"range": map[string]interface{}{
					"started_at": map[string]interface{}{
						"gte": startTimestamp.Unix(),
					},
				},
			})
		}

		// String to timestamp for search.SearchTo (string)
		endTimestamp, err := time.Parse(time.RFC3339, search.SearchUntil)
		if err != nil {
			//log.Printf("[WARNING] Failed parsing end time: %s", err)
		} else {
			query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"] = append(query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"].([]map[string]interface{}), map[string]interface{}{
				"range": map[string]interface{}{
					"started_at": map[string]interface{}{
						"lte": endTimestamp.Unix(),
					},
				},
			})
		}

		if len(inputcursor) > 0 {
			log.Printf("[DEBUG] Using cursor: %s", inputcursor)
			query["search_after"] = []interface{}{inputcursor}
		}

		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Printf("[WARNING] Error encoding executions query: %s", err)
			return executions, cursor, err
		}

		// Perform the search request.
		res, err := project.Es.Search(
			project.Es.Search.WithContext(ctx),
			project.Es.Search.WithIndex(strings.ToLower(GetESIndexPrefix(index))),
			project.Es.Search.WithBody(&buf),
			project.Es.Search.WithTrackTotalHits(true),
		)

		if err != nil {
			log.Printf("[WARNING] Failed executing query: %s", err)
			return executions, "", err
		}

		defer res.Body.Close()
		if res.IsError() {
			log.Printf("[WARNING] Failed executing query: %s", res.String())
			return executions, "", errors.New(res.String())
		}

		if res.StatusCode != 200 && res.StatusCode != 201 {
			return executions, "", errors.New(fmt.Sprintf("Bad statuscode: %d", res.StatusCode))
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return executions, "", err
		}

		wrapped := ExecutionSearchWrapper{}
		err = json.Unmarshal(respBody, &wrapped)
		if err != nil {
			return executions, "", err
		}

		executions = []WorkflowExecution{}
		for _, hit := range wrapped.Hits.Hits {
			executions = append(executions, hit.Source)
		}

		//return executions, "", errors.New("Not implemented yet")
	} else {
		query := datastore.NewQuery(index).Filter("execution_org=", orgId).Order("-started_at").Limit(5)

		// This is a trick for SupportAccess users
		if len(orgId) == 0 {
			query = datastore.NewQuery(index).Order("-started_at").Limit(5)
		}

		if len(search.WorkflowId) > 0 {
			query = query.Filter("workflow_id =", search.WorkflowId)
		}

		if len(search.Status) > 0 {
			query = query.Filter("status =", search.Status)
		}

		// String to timestamp for search.SearchFrom (string)
		startTimestamp, err := time.Parse(time.RFC3339, search.SearchFrom)
		endTimestamp, enderr := time.Parse(time.RFC3339, search.SearchUntil)
		if err != nil {
			if len(search.SearchFrom) > 0 {
				//log.Printf("[WARNING] Failed parsing start time: %s", err)

				// If there is no endTimestamp
				if enderr != nil {
					// FIXME: Set 3 months back in time
				}
			}
		} else {
			// Make it into a number instead of a string
			query = query.Filter("started_at >=", startTimestamp.Unix())
		}

		// String to timestamp for search.SearchUntil (string)
		if enderr != nil {
			if len(search.SearchFrom) > 0 {
				//log.Printf("[WARNING] Failed parsing end time: %s", err)
			}
		} else {
			// Make it into a number instead of a string
			query = query.Filter("started_at <=", endTimestamp.Unix())
		}

		if inputcursor != "" {
			outputcursor, err := datastore.DecodeCursor(inputcursor)
			if err != nil {
				log.Printf("[WARNING] Error decoding cursor: %s", err)
				return executions, "", err
			}

			query = query.Start(outputcursor)
		}

		cursorStr := ""
		for {
			it := project.Dbclient.Run(ctx, query)

			for {
				innerWorkflow := WorkflowExecution{}
				_, err := it.Next(&innerWorkflow)
				if err != nil {
					//log.Printf("[WARNING] Error getting workflow executions: %s", err)
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
						//log.Printf("Length breaking (2): %d", len(executionmarshal))
						break
					}
				}
			}

			// expected to get here
			if len(executions) >= maxLimit {
				//log.Printf("[INFO] Breaking due to executions larger than amount (%d/%d)", len(executions), maxLimit)
				// Get next cursor
				nextCursor, err := it.Cursor()
				if err != nil {
					log.Printf("[WARNING] Cursorerror: %s", err)
				} else {
					cursor = fmt.Sprintf("%s", nextCursor)
				}

				break
			}

			// Get the cursor for the next page of results.
			nextCursor, err := it.Cursor()
			if err != nil {
				log.Printf("[WARNING] Cursorerror: %s", err)
				break
			} else {
				nextStr := fmt.Sprintf("%s", nextCursor)
				cursor = nextStr
				if cursorStr == nextStr {
					//log.Printf("Breaking due to no new cursor")

					break
				}

				cursorStr = nextStr
				query = query.Start(nextCursor)
			}
		}
	}

	// Find difference between what's in the list and what is in cache

	removeIndexes := []int{}
	for execIndex, execution := range executions {
		if execution.ExecutionOrg != orgId && len(orgId) > 0 {
			removeIndexes = append(removeIndexes, execIndex)
			continue
		}

		if execution.Status == "EXECUTING" {
			// Get the right one from cache
			newexec, err := GetWorkflowExecution(ctx, execution.ExecutionId)
			if err == nil {
				//log.Printf("[DEBUG] Got with status %s", newexec.Status)
				// Set the execution as well in the database
				if newexec.Status != execution.Status || len(newexec.Results) > len(execution.Results) {

					if project.Environment == "cloud" {
						go SetWorkflowExecution(ctx, *newexec, true)
					} else {
						SetWorkflowExecution(ctx, *newexec, true)
					}
				}

				executions[execIndex] = *newexec
			}
		} else {
			// Delete cache to clear up memory
			if project.Environment != "cloud" && (execution.Status == "ABORTED" || execution.Status == "FAILURE" || execution.Status == "FINISHED") {
				// Delete cache for it
				RunCacheCleanup(ctx, execution)
			}
		}

		parsedActions := []Action{}

		for _, action := range execution.Workflow.Actions {
			parsedActions = append(parsedActions, Action{
				Name:    action.Name,
				ID:      action.ID,
				AppName: action.AppName,
				AppID:   action.AppID,
			})
		}

		executions[execIndex].Workflow = Workflow{
			ID:       execution.Workflow.ID,
			Name:     execution.Workflow.Name,
			Triggers: execution.Workflow.Triggers,
			Actions:  parsedActions,
		}

		//execution.Result = ""
		if len(execution.Results) > 1000 {
			execution.Results = execution.Results[:1000]
		}

		/*
			for resIndex, _ := range execution.Results {
				if execIndex > len(executions) {
					continue
				}

				if resIndex > len(executions[execIndex].Results) {
					continue
				}

				executions[execIndex].Results[resIndex].Action = Action{}
				executions[execIndex].Results[resIndex].Result = ""
			}
		*/

		// Set action in all execution results to empty

	}

	// Loop through removeIndexes backwards and remove them
	for i := len(removeIndexes) - 1; i >= 0; i-- {
		executions = append(executions[:removeIndexes[i]], executions[removeIndexes[i]+1:]...)
	}

	slice.Sort(executions[:], func(i, j int) bool {
		return executions[i].StartedAt > executions[j].StartedAt
	})

	/*
		var err error
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
			}
		}
	*/

	/*
		if project.CacheDb {
			data, err := json.Marshal(executions)
			if err != nil {
				log.Printf("[WARNING] Failed marshalling update execution cache: %s", err)
				return executions, cursor, nil
			}

			err = SetCache(ctx, cacheKey, data, 10)
			if err != nil {
				log.Printf("[WARNING] Failed setting cache executions (%s): %s", workflowId, err)
				return executions, cursor, nil
			}
		}
	*/

	return executions, cursor, nil

}

func DeleteDbIndex(ctx context.Context, index string) error {
	if !strings.HasPrefix(index, "workflowqueue-") {
		return errors.New("Not allowed to delete that index")
	}

	if project.Environment != "cloud" {
		return errors.New("Can only delete indexes from cloud")
	}

	log.Printf("[WARNING] Deleting index %s entirely. This is normal behavior for workflowqueues", index)

	// Create a query to retrieve all items in the index
	var err error
	query := datastore.NewQuery(index).KeysOnly()
	it := project.Dbclient.Run(ctx, query)

	var keys []*datastore.Key
	for {
		var key *datastore.Key
		key, err = it.Next(nil)
		if err == iterator.Done {
			break
		}

		if err != nil {
			log.Printf("[ERROR] Error fetching next key: %v\n", err)
			break
		}

		keys = append(keys, key)
		if len(keys) == 500 {
			// Delete entities in batch
			err := project.Dbclient.DeleteMulti(ctx, keys)
			if err != nil {
				log.Printf("[WARNING] Failed deleting keys: %s", err)
				break
			}
			keys = nil
		}
	}

	// Delete remaining entities
	if len(keys) > 0 {
		err := project.Dbclient.DeleteMulti(ctx, keys)
		if err != nil {
			log.Printf("[WARNING] Failed deleting keys: %s", err)
		}
	}

	return nil
}

func SetTraining(ctx context.Context, training Training) error {
	if project.DbType == "opensearch" {
		return errors.New("Not implemented")
	}

	if training.ID == "" {
		training.ID = uuid.NewV4().String()
	}

	if training.SignupTime == 0 {
		training.SignupTime = time.Now().Unix()
	}

	// Overwriting to be sure these are matching
	// No real point in having id + workflow.ID anymore
	nameKey := "training"

	log.Printf("[INFO] Setting training with %d attendants", training.NumberOfAttendees)
	key := datastore.NameKey(nameKey, training.ID, nil)
	if _, err := project.Dbclient.Put(ctx, key, &training); err != nil {
		log.Printf("[ERROR] Failed adding training with ID %s: %s", training.ID, err)
		return err
	}

	return nil
}

func GetOrgAuth(ctx context.Context, session string) (User, error) {
	// Search the "org" index for the session in org.org_auth.token
	log.Printf("[DEBUG] Searching for session %#v", session)
	nameKey := "Organizations"

	if project.DbType == "opensearch" {
		return User{}, errors.New("Not implemented")
	} else {
		q := datastore.NewQuery(nameKey).Filter("org_auth.token =", session)
		var orgs []Org
		_, err := project.Dbclient.GetAll(ctx, q, &orgs)
		if err != nil {
			log.Printf("[WARNING] Failed getting org for session %#v: %s", session, err)
			return User{}, err
		}

		if len(orgs) == 0 {
			return User{}, errors.New("No org found")
		}

		// Get the user from the org
		org := orgs[0]
		// Check if the token is expired. If it is, override and returns error
		if org.OrgAuth.Expires.Before(time.Now()) {
			org.OrgAuth.Token = uuid.NewV4().String()
			org.OrgAuth.Expires = time.Now().AddDate(0, 0, 1)

			SetOrg(ctx, org, org.Id)
			return User{}, errors.New("Token expired")
		}

		for _, user := range org.Users {
			if user.Role == "admin" {
				log.Printf("[DEBUG] Letting org auth token %#v impersonate admin user %s (%s) in org %s (%s)", session, user.Username, user.Id, org.Name, org.Id)
				return user, nil
			}
		}
	}

	// If found, return a sample admin user 
	return User{}, nil
}
