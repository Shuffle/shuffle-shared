package shuffle

// Basic classifier that tries to look for similarities without requiring a lot of resources.
// FIXME: Not doing loops at all yet.

import (
	//"bytes"

	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	//"github.com/rcrowley/go-metrics"
	"reflect"
)

/*
func main() {
	//blob1 := `{"agentDetectionInfo":{"accountId":"723148011584467478","accountName":"Secure Tokens - 993292b3-c0d3-4b70-aac7-7745f9700c21","agentDetectionState":null,"agentDomain":"LOCAL","agentIpV4":"10.10.50.47","agentIpV6":"fe80::1807:a54d:bcb4:e60b","agentLastLoggedInUserName":"rgarcia","agentMitigationMode":"detect","agentOsName":"Windows 10 Pro","agentOsRevision":"19042","agentRegisteredAt":"2021-05-05T13:04:16.845921Z","agentUuid":"d80755056dd04bdeb0b2052e11353528","agentVersion":"4.6.11.191","externalIp":"74.8.228.210","groupId":"1083408428243037105","groupName":"Default Group","siteId":"1083408428226259888","siteName":"Local810"},"agentRealtimeInfo":{"accountId":"723148011584467478","accountName":"Secure Tokens - 993292b3-c0d3-4b70-aac7-7745f9700c21","activeThreats":12,"agentComputerName":"LOCAL-LAPTOP08","agentDecommissionedAt":null,"agentDomain":"LOCAL","agentId":"1149164275445453016","agentInfected":true,"agentIsActive":true,"agentIsDecommissioned":false,"agentMachineType":"laptop","agentMitigationMode":"protect","agentNetworkStatus":"connected","agentOsName":"Windows 10 Pro","agentOsRevision":"19042","agentOsType":"windows","agentUuid":"d80755056dd04bdeb0b2052e11353528","agentVersion":"4.6.11.191","groupId":"1083408428243037105","groupName":"Default Group","networkInterfaces":[{"id":"1149164275453841625","inet":["10.10.50.47"],"inet6":["fe80::1807:a54d:bcb4:e60b"],"name":"Wi-Fi","physical":"50:eb:71:41:92:5e"}],"operationalState":"na","rebootRequired":false,"scanAbortedAt":null,"scanFinishedAt":"2021-05-05T13:37:54.639340Z","scanStartedAt":"2021-05-05T13:05:49.572424Z","scanStatus":"finished","siteId":"1083408428226259888","siteName":"Local810","storageName":null,"storageType":null,"userActionsNeeded":[]},"containerInfo":{"id":null,"image":null,"labels":null,"name":null},"id":"1329910606362668927","indicators":[{"category":"Evasion","description":"Internal process resource was manipulated in memory.","ids":[68],"tactics":[{"name":"Defense Evasion","source":"MITRE","techniques":[]}]},{"category":"Evasion","description":"Attempt to evade monitoring using the Process hollowing technique.","ids":[88],"tactics":[{"name":"Privilege Escalation","source":"MITRE","techniques":[{"link":"https://attack.mitre.org/techniques/T1055/012","name":"T1055.012"}]},{"name":"Defense Evasion","source":"MITRE","techniques":[{"link":"https://attack.mitre.org/techniques/T1055/012","name":"T1055.012"}]}]},{"category":"Exploitation","description":"Shellcode execution from Powershell was detected.","ids":[123],"tactics":[{"name":"Execution","source":"MITRE","techniques":[{"link":"https://attack.mitre.org/techniques/T1059/001","name":"T1059.001"},{"link":"https://attack.mitre.org/techniques/T1106/","name":"T1106"}]}]}],"kubernetesInfo":{"cluster":null,"controllerKind":null,"controllerLabels":null,"controllerName":null,"namespace":null,"namespaceLabels":null,"node":null,"pod":null,"podLabels":null},"mitigationStatus":[{"action":"kill","actionsCounters":{"failed":0,"notFound":0,"pendingReboot":0,"success":1,"total":1},"agentSupportsReport":true,"groupNotFound":false,"lastUpdate":"2022-01-09T22:14:58.871326Z","latestReport":"/threats/mitigation-report/1329910609055412117","mitigationEndedAt":"2022-01-09T22:14:58.324000Z","mitigationStartedAt":"2022-01-09T22:14:58.324000Z","status":"success"}],"threatInfo":{"analystVerdict":"undefined","analystVerdictDescription":"Undefined","automaticallyResolved":false,"browserType":null,"certificateId":"","classification":"Malware","classificationSource":"Static","cloudFilesHashVerdict":"provider_unknown","collectionId":"1326764489556282273","confidenceLevel":"malicious","createdAt":"2022-01-09T22:14:58.549750Z","detectionEngines":[{"key":"exploits","title":"Anti Exploitation / Fileless"}],"detectionType":"dynamic","engines":["Anti Exploitation / Fileless"],"externalTicketExists":false,"externalTicketId":null,"failedActions":false,"fileExtension":"","fileExtensionType":"Unknown","filePath":"\\Device\\HarddiskVolume3\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe (CLI fa08)","fileSize":0,"fileVerificationType":"NotSigned","identifiedAt":"2022-01-09T22:14:58.243000Z","incidentStatus":"unresolved","incidentStatusDescription":"Unresolved","initiatedBy":"agent_policy","initiatedByDescription":"Agent Policy","initiatingUserId":null,"initiatingUsername":null,"isFileless":false,"isValidCertificate":false,"maliciousProcessArguments":"-Command \"([WMI] '').ConvertToDateTime((Get-WmiObject win32_operatingsystem | select -expandproperty LastBootUpTime)).ToUniversalTime().ToString('o')\"","md5":null,"mitigatedPreemptively":false,"mitigationStatus":"not_mitigated","mitigationStatusDescription":"Not mitigated","originatorProcess":null,"pendingActions":false,"processUser":"NT AUTHORITY\\SYSTEM","publisherName":"","reachedEventsLimit":false,"rebootRequired":false,"sha1":"fa08dde7f06cb34b3d6824a634c9ed2c4de8da71","sha256":null,"storyline":"CC9DC7CE84085158","threatId":"1329910606362668927","threatName":"powershell.exe (CLI fa08)","updatedAt":"2022-01-09T22:14:58.868897Z"},"whiteningOptions":["hash"]}`
	//blob2 := `{"agentDetectionInfoo":{"accountId":"723148011584467478","accountName":"Secure Tokens - 993292b3-c0d3-4b70-aac7-7745f9700c21","agentDetectionState":null,"agentDomain":"LOCAL","agentIpV4":"10.10.50.47","agentIpV6":"fe80::1807:a54d:bcb4:e60b","agentLastLoggedInUserName":"rgarcia","agentMitigationMode":"protect","agentOsName":"Windows 10 Pro","agentOsRevision":"19042","agentRegisteredAt":"2021-05-05T13:04:16.845921Z","agentUuid":"d80755056dd04bdeb0b2052e11353528","agentVersion":"4.6.11.191","externalIp":"23.246.127.150","groupId":"1083408428243037105","groupName":"Default Group","siteId":"1083408428226259888","siteName":"Local810"},"agentRealtimeInfo":{"accountId":"723148011584467478","accountName":"Secure Tokens - 993292b3-c0d3-4b70-aac7-7745f9700c21","activeThreats":12,"agentComputerName":"LOCAL-LAPTOP08","agentDecommissionedAt":null,"agentDomain":"LOCAL","agentId":"1149164275445453016","agentInfected":true,"agentIsActive":true,"agentIsDecommissioned":false,"agentMachineType":"laptop","agentMitigationMode":"protect","agentNetworkStatus":"connected","agentOsName":"Windows 10 Pro","agentOsRevision":"19042","agentOsType":"windows","agentUuid":"d80755056dd04bdeb0b2052e11353528","agentVersion":"4.6.11.191","groupId":"1083408428243037105","groupName":"Default Group","networkInterfaces":[{"id":"1149164275453841625","inet":["10.10.50.47"],"inet6":["fe80::1807:a54d:bcb4:e60b"],"name":"Wi-Fi","physical":"50:eb:71:41:92:5e"}],"operationalState":"na","rebootRequired":false,"scanAbortedAt":null,"scanFinishedAt":"2021-05-05T13:37:54.639340Z","scanStartedAt":"2021-05-05T13:05:49.572424Z","scanStatus":"finished","siteId":"1083408428226259888","siteName":"Local810","storageName":null,"storageType":null,"userActionsNeeded":[]},"containerInfo":{"id":null,"image":null,"labels":null,"name":null},"id":"1329729701415842799","indicators":[{"category":"Evasion","description":"Internal process resource was manipulated in memory.","ids":[68],"tactics":[{"name":"Defense Evasion","source":"MITRE","techniques":[]}]},{"category":"Exploitation","description":"Shellcode execution from Powershell was detected.","ids":[123],"tactics":[{"name":"Execution","source":"MITRE","techniques":[{"link":"https://attack.mitre.org/techniques/T1059/001","name":"T1059.001"},{"link":"https://attack.mitre.org/techniques/T1106/","name":"T1106"}]}]}],"kubernetesInfo":{"cluster":null,"controllerKind":null,"controllerLabels":null,"controllerName":null,"namespace":null,"namespaceLabels":null,"node":null,"pod":null,"podLabels":null},"mitigationStatus":[{"action":"kill","actionsCounters":{"failed":0,"notFound":0,"pendingReboot":0,"success":2,"total":2},"agentSupportsReport":true,"groupNotFound":false,"lastUpdate":"2022-01-09T16:15:33.109931Z","latestReport":"/threats/mitigation-report/1329729702330201090","mitigationEndedAt":"2022-01-09T16:15:32.660000Z","mitigationStartedAt":"2022-01-09T16:15:32.660000Z","status":"success"}],"threatInfo":{"analystVerdict":"undefined","analystVerdictDescription":"Undefined","automaticallyResolved":false,"browserType":null,"certificateId":"","classification":"Malware","classificationSource":"Static","cloudFilesHashVerdict":"provider_unknown","collectionId":"1329662995053499119","confidenceLevel":"malicious","createdAt":"2022-01-09T16:15:32.999785Z","detectionEngines":[{"key":"exploits","title":"Anti Exploitation / Fileless"}],"detectionType":"dynamic","engines":["Anti Exploitation / Fileless"],"externalTicketExists":false,"externalTicketId":null,"failedActions":false,"fileExtension":"","fileExtensionType":"Unknown","filePath":"\\Device\\HarddiskVolume3\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe (CLI b989)","fileSize":0,"fileVerificationType":"NotSigned","identifiedAt":"2022-01-09T16:15:32.640000Z","incidentStatus":"unresolved","incidentStatusDescription":"Unresolved","initiatedBy":"agent_policy","initiatedByDescription":"Agent Policy","initiatingUserId":null,"initiatingUsername":null,"isFileless":false,"isValidCertificate":false,"maliciousProcessArguments":"","md5":null,"mitigatedPreemptively":false,"mitigationStatus":"not_mitigated","mitigationStatusDescription":"Not mitigated","originatorProcess":null,"pendingActions":false,"processUser":"NT AUTHORITY\\SYSTEM","publisherName":"","reachedEventsLimit":false,"rebootRequired":false,"sha1":"b989edafc6285a41647d27658d6e71a5a1e45b6e","sha256":null,"storyline":"30BFE426ED042C60","threatId":"1329729701415842799","threatName":"powershell.exe (CLI b989)","updatedAt":"2022-01-09T16:15:33.107759Z"},"whiteningOptions":["hash"]}`

	fmt.Println("vim-go")
	blob1 := `halvor halvor halvor halvor halvor halvor halvor halvor`
	blob2 := `HALVR HALVR HALVR HALVR HALVR HALVR HALVR HALVR`

	//var a = make(map[string]string)
	findSimilarity(blob1, blob2)
}
*/

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
	workflowExecutions, err := GetAllWorkflowExecutions(ctx, workflowExecution.Workflow.ID)
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
