package shuffle

// Basic classifier that tries to look for similarities without requiring a lot of resources.
// FIXME: Not doing loops at all yet.

import (
	//"bytes"

	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	//"github.com/rcrowley/go-metrics"
	"reflect"
)

func findSimilarity(blob1, blob2 string, onlyItems []string) (int64, []string) {
	var blob1Map map[string]interface{}
	var blob2Map map[string]interface{}

	err := json.Unmarshal([]byte(blob1), &blob1Map)
	if err != nil {
		//log.Printf("[WARNING] Something went wrong for blob1: %s", err)
		blob1Map = map[string]interface{}{
			"default": blob1,
		}

		blob2Map = map[string]interface{}{
			"default": blob2,
		}

	} else {
		err = json.Unmarshal([]byte(blob2), &blob2Map)
		if err != nil {
			//log.Printf("[WARNING] Something went wrong for blob2: %s", err)
			blob2Map = map[string]interface{}{
				"default": blob2,
			}
		}
	}

	allValues, skippedValues := findSimilarityInterface("", blob1Map, blob2Map, onlyItems)
	log.Printf("Allvalues: %#v", allValues)
	log.Printf("SkippedValues: %#v", skippedValues)

	if len(allValues) == 0 {
		return 0, skippedValues
	}

	avg := int64(0)
	for _, value := range allValues {
		avg = avg + value
	}

	return avg / int64(len(allValues)), skippedValues
}

func cleanupText(input string) string {
	typesToRemove := []string{",", ".", "\n"}
	for _, val := range typesToRemove {
		input = strings.Replace(input, val, "", -1)
	}

	input = strings.ToLower(input)
	input = strings.TrimSpace(input)
	return input
}

func findSimilarityInterface(rootNode string, blob1Map, blob2Map map[string]interface{}, onlyItems []string) ([]int64, []string) {
	// clean up data first: stopwords, dots - halvor :)
	log.Printf("[DEBUG] Root: %s", rootNode)
	// "reflect"
	badKeys := []string{"id"}
	avgValues := []int64{}
	skippedValues := []string{}
	for key, value := range blob1Map {
		if fmt.Sprintf("%s", reflect.TypeOf(value)) == "string" {
			if len(onlyItems) > 0 && !ArrayContains(onlyItems, strings.ToLower(key)) {
				skippedValues = append(skippedValues, key)
				continue
			}

			if ArrayContains(badKeys, key) {
				skippedValues = append(skippedValues, key)
				continue
			}

			newValue1 := cleanupText(fmt.Sprintf("%#v", blob1Map[key]))
			newValue2 := cleanupText(fmt.Sprintf("%#v", blob2Map[key]))

			//log.Printf("Val1: %#v, Val2: %#v", newValue1, newValue2)
			//fmt.Printf("%.2f\n", similarity) // Output: 0.43
			similarity := strutil.Similarity(newValue1, newValue2, metrics.NewLevenshtein())

			avgValues = append(avgValues, int64(similarity*100))

		} else if fmt.Sprintf("%s", reflect.TypeOf(value)) == "map[string]interface {}" {
			var mappedValue2 map[string]interface{}
			if val, ok := blob2Map[key]; ok {
				mappedValue2 = val.(map[string]interface{})
			} else {
				continue
			}

			mappedValue1 := value.(map[string]interface{})

			newRootnode := fmt.Sprintf("%s/%s", rootNode, key)
			parentValue, parentSkipped := findSimilarityInterface(newRootnode, mappedValue1, mappedValue2, onlyItems)
			avgValues = append(avgValues, parentValue...)
			skippedValues = append(skippedValues, parentSkipped...)

		} else {
			log.Printf("%s: %s", key, reflect.TypeOf(value))
		}
	}

	return avgValues, skippedValues
}

// Checks same workflow's executions if it has had something similar happening in the last 10 workflows
func RunTextClassifier(ctx context.Context, workflowExecution WorkflowExecution) {
	// Onlyitems is here in case we JUST want to look for specific keys. Could be per action, app or workflow
	onlyItems := []string{}
	maxCheck := 10
	workflowExecutions, err := GetAllWorkflowExecutions(ctx, workflowExecution.Workflow.ID, 50)
	if err != nil {
		log.Printf("[WARNING] Failed getting executions for %s in text classifier: %s", workflowExecution.Workflow.ID, err)
		return
	}

	// Compare with at most 10 previous
	if len(workflowExecutions) > maxCheck {
		workflowExecutions = workflowExecutions[0 : maxCheck-1]
	}

	updatedExecutions := []string{}
	for mainResultKey, mainResult := range workflowExecution.Results {
		if len(mainResult.Result) == 0 {
			continue
		}

		for executionKey, execution := range workflowExecutions {
			if execution.ExecutionId == mainResult.ExecutionId {
				continue
			}

			// Need to be same length
			if len(execution.Results) != len(workflowExecution.Results) {
				continue
			}

			executionAdded := false
			for subResultKey, result := range execution.Results {
				if mainResult.Action.ID != result.Action.ID {
					continue
				}

				// FIXME: 100% match for this action
				//log.Printf("[DEBUG] Checking action %s (%s)", mainResult.Action.Name, mainResult.Action.ID)
				similarity := int64(0)
				if mainResult.Result == result.Result {
					//log.Printf("[DEBUG] They are exactly equal\n")
					// Skip exactly equal for now
					//similarity = 100
				} else {
					similarity, skippedItems := findSimilarity(mainResult.Result, result.Result, onlyItems)
					log.Printf("[DEBUG] Similarity: %d, Skipped: %#v\n", similarity, skippedItems)
				}

				if similarity > 0 {
					workflowExecution.Results[mainResultKey].SimilarActions = append(workflowExecution.Results[mainResultKey].SimilarActions, SimilarAction{
						ExecutionId: execution.ExecutionId,
						Similarity:  similarity,
					})

					workflowExecutions[executionKey].Results[subResultKey].SimilarActions = append(workflowExecutions[executionKey].Results[subResultKey].SimilarActions, SimilarAction{
						ExecutionId: workflowExecution.ExecutionId,
						Similarity:  similarity,
					})

					if !executionAdded {
						executionAdded = true
						updatedExecutions = append(updatedExecutions, execution.ExecutionId)
					}
				}
			}
		}
	}

	for _, execution := range workflowExecutions {
		if execution.ExecutionId == workflowExecution.ExecutionId {
			continue
		}

		if !ArrayContains(updatedExecutions, execution.ExecutionId) {
			continue
		}

		//log.Printf("Should update %s", execution.ExecutionId)
		err := SetWorkflowExecution(ctx, execution, true)
		if err != nil {
			log.Printf("[WARNING] Failed to update execution %s", execution.ExecutionId)
		}
	}

	// Means main one is also updated
	if len(updatedExecutions) > 0 {
		//log.Printf("Should current: %s", execution.ExecutionId)
		err := SetWorkflowExecution(ctx, workflowExecution, true)
		if err != nil {
			log.Printf("[WARNING] Failed to update main execution %s", workflowExecution.ExecutionId)
		}
	}
}

func runDedup(inputArr []string) []string {
	newarr := []string{}
	for _, value := range inputArr {
		if !ArrayContains(newarr, value) {
			newarr = append(newarr, value)
		}
	}

	return newarr
}

// Finds IPs, domains and hashes
// Point is to test out how we can create a structured database of these, correlate with, and store them
func RunIOCFinder(ctx context.Context, workflowExecution WorkflowExecution) {

	numBlock := "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
	regexPattern := numBlock + "\\." + numBlock + "\\." + numBlock + "\\." + numBlock
	ips := regexp.MustCompile(regexPattern)

	domains := regexp.MustCompile(`^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$`)

	//urls := regexp.MustCompile(`(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})`)
	//urls := regexp.MustCompile(`(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})`)

	md5s := regexp.MustCompile(`[a-f0-9]{32}`)
	sha256s := regexp.MustCompile(`[A-Fa-f0-9]{64}`)

	foundIps := []string{}
	foundDomains := []string{}
	foundMd5s := []string{}
	foundSha256s := []string{}
	for _, result := range workflowExecution.Results {
		// Too big?
		//if len(result.Result) > 1000000 {
		//	continue
		//}

		foundIps = append(foundIps, ips.FindAllString(result.Result, -1)...)
		foundDomains = append(foundDomains, domains.FindAllString(result.Result, -1)...)
		foundMd5s = append(foundMd5s, md5s.FindAllString(result.Result, -1)...)
		foundSha256s = append(foundSha256s, sha256s.FindAllString(result.Result, -1)...)
	}

	foundIps = runDedup(foundIps)
	foundDomains = runDedup(foundDomains)
	foundMd5s = runDedup(foundMd5s)
	foundSha256s = runDedup(foundSha256s)

	fmt.Printf("[DEBUG][%s] IPS: %#v, Domains: %#v, Md5s: %#v, Sha256s: %#v", workflowExecution.ExecutionId, foundIps, foundDomains, foundMd5s, foundSha256s)
}
