package shuffle

import (
	//"github.com/goccy/go-json"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
)

// A file built single-handedly for optimising executions. Functions:
// - Fixexecution
// - Setexecution
// - Getexecution

func Fixexecution(ctx context.Context, workflowExecution WorkflowExecution) (WorkflowExecution, bool) {
	dbsave := false
	workflowExecution.Workflow.Image = ""

	workflowExecution = cleanupProtectedKeys(workflowExecution)
	validation, err := GetExecutionValidation(ctx, workflowExecution.ExecutionId)
	if err == nil {
		if workflowExecution.NotificationsCreated > 0 {
			validation.NotificationsCreated = workflowExecution.NotificationsCreated
		}

		workflowExecution.Workflow.Validation = validation
	}

	// Make sure to not having missing items in the execution
	lastexecVar := map[string]ActionResult{}
	for actionIndex, action := range workflowExecution.Workflow.Actions {
		found := false
		result := ActionResult{}

		workflowExecution.Workflow.Actions[actionIndex].LargeImage = ""
		workflowExecution.Workflow.Actions[actionIndex].SmallImage = ""
		for resultIndex, innerresult := range workflowExecution.Results {

			// Very weird edgecase handling for agent cleanup
			// This is for auto-correctiveness of executions
			if len(workflowExecution.Workflow.Actions) == 1 && action.Name == "agent" && innerresult.Action.Name == "agent" && innerresult.Action.ID == "" {
				innerresult.Action.ID = action.ID
				innerresult.Action.AppName = "AI Agent"
			}

			if innerresult.Action.ID != action.ID {
				continue
			}

			// There was some WAITING issue here. This is a hotfix from agent issues.
			if innerresult.Status == "WAITING" && innerresult.Action.AppName == "Shuffle Tools" && innerresult.CompletedAt > 0 {
				workflowExecution.Results[resultIndex].Status = "SUCCESS"
			}

			// Forcing it to become agent
			if innerresult.Action.AppName == "AI Agent" || innerresult.Action.AppName == "Shuffle Agent" {
				workflowExecution.Type = "AGENT"
			}

			if innerresult.Status != "WAITING" && innerresult.Status != "SUCCESS" {
				found = true
				result = innerresult
			}

			// Special cleanup for agents
			if innerresult.Action.AppName == "AI Agent" || innerresult.Action.AppName == "Shuffle Agent" {
				if workflowExecution.Status == "FINISHED" || workflowExecution.Status == "ABORTED" {
					if workflowExecution.Status == "FINISHED" {
						log.Printf("[DEBUG][%s] Fixexecution: Agent execution is finished, skipping agent result %s", workflowExecution.ExecutionId, innerresult.Action.ID)
					}

					break
				}

				actionCacheId := fmt.Sprintf("%s_%s_result", workflowExecution.ExecutionId, innerresult.Action.ID)
				if cachedData, cacheErr := GetCache(ctx, actionCacheId); cacheErr == nil {
					cachedBytes := []byte(cachedData.([]uint8))
					var cachedOutput AgentOutput
					if err := json.Unmarshal(cachedBytes, &cachedOutput); err == nil && len(cachedOutput.Decisions) > 0 {
						var currentOutput AgentOutput
						_ = json.Unmarshal([]byte(innerresult.Result), &currentOutput)
						if len(cachedOutput.Decisions) >= len(currentOutput.Decisions) {
							//if debug {
							//	log.Printf("[DEBUG][%s] Fixexecution: upgrading agent result index %d from cache (%d decisions vs %d)", workflowExecution.ExecutionId, resultIndex, len(cachedOutput.Decisions), len(currentOutput.Decisions))
							//}

							innerresult.Result = string(cachedBytes)
							workflowExecution.Results[resultIndex].Result = string(cachedBytes)
						}
					}
				}

				// Starting autocorrections
				mappedOutput := AgentOutput{}
				decisionsUpdated := false
				err = json.Unmarshal([]byte(innerresult.Result), &mappedOutput)
				if err != nil {
					log.Printf("[WARNING] Agent mapping: Failed in mapped output mapping: %s", err)
				} else {
					// Handles "stuck" cases
					if innerresult.Status == "WAITING" {
						decisionFailedCheck := ResultChecker{}
						err = json.Unmarshal([]byte(mappedOutput.DecisionString), &decisionFailedCheck)
						if err == nil && len(decisionFailedCheck.Reason) > 0 && decisionFailedCheck.Success == false {
							//if strings.Contains(decisionFailedCheck.Reason
							//mappedOutput.Status = "SKIPPED"
							mappedOutput.Status = "FINISHED"

							innerresult.Status = "SKIPPED"
							workflowExecution.Results[resultIndex].Status = "SKIPPED"
							decisionsUpdated = true
						}
					}
				}

				// Overwrites missing statuses
				setFinished := mappedOutput.Status == "FINISHED" && mappedOutput.CompletedAt > 0
				finishFound := false
				for decisionIndex, decision := range mappedOutput.Decisions {
					if setFinished && decision.RunDetails.Status == "" {
						mappedOutput.Decisions[decisionIndex].RunDetails.Status = "IGNORED"
						mappedOutput.Decisions[decisionIndex].RunDetails.CompletedAt = time.Now().UnixMilli()
						decisionsUpdated = true
					}

					if decision.Action == "finish" || decision.Category == "finish" {

						if decision.RunDetails.Status != "FINISHED" {
							if mappedOutput.Decisions[decisionIndex].RunDetails.StartedAt == 0 {
								mappedOutput.Decisions[decisionIndex].RunDetails.StartedAt = time.Now().UnixMilli()
							}

							mappedOutput.Decisions[decisionIndex].RunDetails.CompletedAt = time.Now().UnixMilli()
							mappedOutput.Decisions[decisionIndex].RunDetails.Status = "FINISHED"
							decisionsUpdated = true
						}

						finishFound = true
					}
				}

				if finishFound {
					mappedOutput.Status = "FINISHED"

					result.Status = "SUCCESS"
					innerresult.Status = "SUCCESS"
					workflowExecution.Results[resultIndex].Status = "SUCCESS"
					go sendAgentActionSelfRequest("SUCCESS", workflowExecution, workflowExecution.Results[resultIndex])
					break
				}

				if !finishFound && (innerresult.Status == "WAITING" || innerresult.Status == "SUCCESS") || decisionsUpdated {
					if workflowExecution.Results[resultIndex].StartedAt == 0 {
						workflowExecution.Results[resultIndex].StartedAt = time.Now().UnixMilli()
					}

					// Somehow possible to get Nano()
					if workflowExecution.Results[resultIndex].StartedAt > 17769710273568 {
						workflowExecution.Results[resultIndex].StartedAt = time.Now().UnixMilli()
					}

					// Auto fixing decision data based on cache for better decisionmaking
					// Map the result into AgentOutput to check decisions

					// Any Unix timestamp under 10 billion is in seconds (valid through year 2286). Milliseconds are > 1 trillion.
					const maxSecondsTimestamp int64 = 10_000_000_000

					finishedDecisions := []string{}
					failedFound := false
					finishDecisionFound := false
					for decisionIndex, decision := range mappedOutput.Decisions {
						if decision.Action == "finish" {
							finishDecisionFound = true

							if decision.RunDetails.Status == "" {
								decision.RunDetails.Status = "FINISHED"
								mappedOutput.Decisions[decisionIndex].RunDetails.Status = "FINISHED"
							}
						}

						parsedDelay, err := strconv.Atoi(decision.Delay)
						if err != nil {
							parsedDelay = 0
						}

						decisionId := fmt.Sprintf("agent-%s-%s", workflowExecution.ExecutionId, decision.RunDetails.Id)
						if decision.RunDetails.Status == "FINISHED" || decision.RunDetails.Status == "IGNORED" {
							finishedDecisions = append(finishedDecisions, decision.RunDetails.Id)
							continue
						} else if decision.RunDetails.Status == "FAILURE" {
							finishedDecisions = append(finishedDecisions, decision.RunDetails.Id)
							failedFound = true
							continue
						} else if decision.RunDetails.Status == "RUNNING" && decision.Action != "ask" && parsedDelay <= 0 {

							// Max runtime of a decision at 5 minutes
							startedTs := decision.RunDetails.StartedAt
							if startedTs > 0 && startedTs < maxSecondsTimestamp {
								startedTs *= 1000
							}

							if startedTs > 0 && time.Now().UnixMilli()-startedTs > 300000 {
								timeoutFlagKey := fmt.Sprintf("agent-%s-%s-timeout-handled", workflowExecution.ExecutionId, decision.RunDetails.Id)
								if _, err := GetCache(ctx, timeoutFlagKey); err == nil {
									// Already handled this timeout in a previous check so just count it as finished.
									finishedDecisions = append(finishedDecisions, decision.RunDetails.Id)
									failedFound = true
								} else {
									log.Printf("[WARNING][%s] AI_AGENT_DECISION_TIMEOUT: org=%s tool=%s action=%s duration=%ds — marking FAILURE and triggering recovery", workflowExecution.ExecutionId, workflowExecution.Workflow.OrgId, decision.Tool, decision.Action, (time.Now().UnixMilli()-startedTs)/1000)
									SetCache(ctx, timeoutFlagKey, []byte("1"), 60) // 60 min TTL — long enough to outlive any recovery cycle

									decisionsUpdated = true
									mappedOutput.Decisions[decisionIndex].RunDetails.Status = "FAILURE"
									mappedOutput.Decisions[decisionIndex].RunDetails.CompletedAt = time.Now().UnixMilli()
									mappedOutput.Decisions[decisionIndex].RunDetails.RawResponse += "\n[ERROR] Decision marked as FAILURE due to 5 minute timeout."

									// Write FAILURE back to the per-decision cache so the still-alive goroutine
									// in RunAgentDecisionAction sees it and discards its late result instead of
									// messing the recovery state.
									timedOutDecision := mappedOutput.Decisions[decisionIndex]
									if marshalledTimedOut, err := json.Marshal(timedOutDecision); err == nil {
										go SetCache(ctx, decisionId, marshalledTimedOut, 300)
									}

									// Count as finished so the all-decisions-done check fires in this same check.
									finishedDecisions = append(finishedDecisions, decision.RunDetails.Id)
									failedFound = true
								}
							}
						} else {
							if decision.RunDetails.CompletedAt > 0 && decision.RunDetails.Status != "WAITING" {
								if debug {
									log.Printf("[DEBUG] Rewriting decision %s to FINISHED based on completed at timestamp.", decision.RunDetails.Id)
								}

								mappedOutput.Decisions[decisionIndex].RunDetails.Status = "FINISHED"
								finishedDecisions = append(finishedDecisions, decision.RunDetails.Id)
								decisionsUpdated = true

								marshalledDecision, err := json.Marshal(mappedOutput.Decisions[decisionIndex])
								if err == nil {
									err = SetCache(ctx, decisionId, marshalledDecision, 60)
								}

								continue
							} else {
								if decision.Action == "finish" && decision.RunDetails.Status == "" {
									mappedOutput.Decisions[decisionIndex].RunDetails.Status = "FINISHED"
									if mappedOutput.Decisions[decisionIndex].RunDetails.StartedAt == 0 {
										mappedOutput.Decisions[decisionIndex].RunDetails.StartedAt = time.Now().UnixMilli()
									}

									finishedDecisions = append(finishedDecisions, decision.RunDetails.Id)
									mappedOutput.Decisions[decisionIndex].RunDetails.CompletedAt = time.Now().UnixMilli()
									decisionsUpdated = true

									marshalledDecision, err := json.Marshal(mappedOutput.Decisions[decisionIndex])
									if err == nil {
										err = SetCache(ctx, decisionId, marshalledDecision, 60)
									}
								}

								//if debug {
								//	log.Printf("[DEBUG][%s] Decision %s (action=%s, status='%s') has no CompletedAt yet. Checking cache for updates.", workflowExecution.ExecutionId, decision.RunDetails.Id, action.ID, decision.RunDetails.Status)
								//}
							}
						}

						cache, err := GetCache(ctx, decisionId)
						if err == nil {
							foundDecision := AgentDecision{}
							cacheData := []byte(cache.([]uint8))
							err = json.Unmarshal(cacheData, &foundDecision)
							if err != nil {
								log.Printf("[ERROR][%s] Faled mapping foundDecision: %s", workflowExecution.ExecutionId, foundDecision.RunDetails.Id)
							} else {
								if foundDecision.RunDetails.Status != "" {
									decisionsUpdated = true
									mappedOutput.Decisions[decisionIndex] = foundDecision
								}
							}
						}
					}

					// FIXME: Is failure hadnling here necessary?
					// Changed it to do failure handling better in the agent itself
					// due to having a 'finish' action that should handle it properly
					if failedFound {
						decisionsUpdated = true
						//if debug {
						//	log.Printf("[DEBUG][%s] Failure found for agent %s. Should we exit?", workflowExecution.ExecutionId, action.ID)
						//}

						/*
							mappedOutput.Status = "FAILURE"
							mappedOutput.CompletedAt = time.Now().UnixMilli()
							workflowExecution.Results[resultIndex].Status = "ABORTED"

							go sendAgentActionSelfRequest("FAILURE", workflowExecution, workflowExecution.Results[resultIndex])
						*/

					}

					if len(finishedDecisions) == len(mappedOutput.Decisions) && mappedOutput.Status != "FINISHED" && mappedOutput.Status != "FAILURE" && mappedOutput.Status != "ABORTED" {

						// Check if requests was recently sent or not
						cacheId := fmt.Sprintf("agent-%s-%s-fixexec-finished-check", workflowExecution.ExecutionId, action.ID)
						if _, err := GetCache(ctx, cacheId); err == nil {
							continue
						}

						// Set cache to prevent multiple sends — if cache is down, skip to prevent retry storm
						if cacheErr := SetCache(ctx, cacheId, []byte("handled"), 60); cacheErr != nil {
							log.Printf("[WARNING][%s] Memcache down — skipping fixexec agent self-request for action %s to prevent retry storm", workflowExecution.ExecutionId, action.ID)
							continue
						}

						decisionsUpdated = true
						if finishDecisionFound {
							//log.Printf("[INFO][%s] All decisions finished for agent action %s - marking as FINISHED.", workflowExecution.ExecutionId, action.ID)

							mappedOutput.Status = "FINISHED"
							mappedOutput.CompletedAt = time.Now().UnixMilli()

							workflowExecution.Results[resultIndex].Status = "SUCCESS"

							go func() {
								time.Sleep(1 * time.Second)
								go sendAgentActionSelfRequest("SUCCESS", workflowExecution, workflowExecution.Results[resultIndex])
							}()
						} else {
							mostRecentCompletion := int64(0)
							for _, dec := range mappedOutput.Decisions {
								ts := dec.RunDetails.CompletedAt
								if ts > 0 && ts < maxSecondsTimestamp {
									ts *= 1000
								}
								if ts > mostRecentCompletion {
									mostRecentCompletion = ts
								}
							}
							timeSinceCompletionMs := time.Now().UnixMilli() - mostRecentCompletion
							if timeSinceCompletionMs < 60000 {
								if debug {
									log.Printf("[DEBUG][%s] Skipping fixexecution_timeout_recovery: last decision completed %d ms ago (waiting for LLM response from primary stream handler).", workflowExecution.ExecutionId, timeSinceCompletionMs)
								}
								continue
							}

							log.Printf("[INFO][%s] All decisions finished for agent action %s - but no finish action found, marking as WAITING.", workflowExecution.ExecutionId, action.ID)
							//log.Printf("[INFO][%s] All decisions finished for agent action %s - but no finish action found. Re-invoking agent to finalize (failedFound: %t).", workflowExecution.ExecutionId, action.ID, failedFound)

							mappedOutput.Status = "RUNNING"
							mappedOutput.CompletedAt = 0
							workflowExecution.Results[resultIndex].Status = "WAITING"

							if workflowExecution.Status == "FINISHED" {
								workflowExecution.Status = "EXECUTING"
							}

							// Marshal updated state now so the goroutine snapshot is consistent
							if marshalledResult, err := json.Marshal(mappedOutput); err == nil {
								workflowExecution.Results[resultIndex].Result = string(marshalledResult)
							}

							// Re-invoke the agent so the LLM can see the failure and produce a proper "finish" decision.
							capturedExec := workflowExecution
							capturedAction := action
							go func() {
								time.Sleep(1 * time.Second)
								sendAgentActionSelfRequest("WAITING", capturedExec, capturedExec.Results[resultIndex])
								time.Sleep(2 * time.Second)
								_, err := HandleAiAgentExecutionStart(capturedExec, capturedAction, true, "fixexecution_timeout_recovery")
								if err != nil {
									log.Printf("[ERROR][%s] Failed re-invoking agent after decisions completed for action %s: %s", capturedExec.ExecutionId, capturedAction.ID, err)
								}
							}()
						}
					} else if (result.Status == "" || result.Status == "WAITING") && mappedOutput.Status == "FINISHED" {
						if debug {
							log.Printf("[INFO][%s] Agent action %s marked as FINISHED, updating result status to SUCCESS.", workflowExecution.ExecutionId, action.ID)
						}

						workflowExecution.Results[resultIndex].Status = "SUCCESS"
						go sendAgentActionSelfRequest("SUCCESS", workflowExecution, workflowExecution.Results[resultIndex])
					}
				}

				if decisionsUpdated {
					marshalledResult, err := json.Marshal(mappedOutput)
					if err == nil {
						workflowExecution.Results[resultIndex].Result = string(marshalledResult)
					} else {
						log.Printf("[DEBUG] Failed unmarshalling agent decision: %s", err)
					}
				}
			}
		}

		if found {
			// Handles execution vars
			result.Action = action
			if setExecutionVariable(result) {

				// Check if key in lastexecVar
				if _, ok := lastexecVar[result.Action.ExecutionVariable.Name]; ok {

					if lastexecVar[result.Action.ExecutionVariable.Name].CompletedAt > result.CompletedAt {
						lastexecVar[result.Action.ExecutionVariable.Name] = result
					}
				} else {
					lastexecVar[result.Action.ExecutionVariable.Name] = result
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
			result.Action = action
			if setExecutionVariable(result) {

				// Check if key in lastexecVar
				if _, ok := lastexecVar[result.Action.ExecutionVariable.Name]; ok {

					if lastexecVar[result.Action.ExecutionVariable.Name].CompletedAt < result.CompletedAt {
						lastexecVar[result.Action.ExecutionVariable.Name] = result
					}
				} else {
					lastexecVar[result.Action.ExecutionVariable.Name] = result
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
			//log.Printf("[WARNING][%s] Removing empty result started at '%d' and finished at '%d'. ID: %#v, Name: %#v.", workflowExecution.ExecutionId, result.StartedAt, result.CompletedAt, result.Action.ID, result.Action.Name)
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
			if key != variable.Name {
				continue
			}

			if workflowExecution.Workflow.ExecutionVariables[varKey].Value != value.Result {
				//log.Printf("\n\n\n[DEBUG][%s] Updating execution variable '%s' from len %d to %d (%s)\n\n", workflowExecution.ExecutionId, variable.Name, len(workflowExecution.Workflow.ExecutionVariables[varKey].Value), len(value.Result), value.Action.Label)
			}

			workflowExecution.Workflow.ExecutionVariables[varKey].Value = value.Result
			break
		}
	}

	workflowExecution.ExecutionVariables = workflowExecution.Workflow.ExecutionVariables

	// Check for failures before setting to finished
	// Update execution parent
	if workflowExecution.Status == "EXECUTING" {

		for _, result := range workflowExecution.Results {
			if result.Status == "FAILURE" || result.Status == "ABORTED" {
				// Only log once per execution to avoid spam
				cacheKey := fmt.Sprintf("abort_log_%s", workflowExecution.ExecutionId)
				if _, err := GetCache(ctx, cacheKey); err != nil {
					log.Printf("[DEBUG][%s] Setting execution to aborted because of result %s (%s) with status '%s'. Should update execution parent if it exists (not implemented).", workflowExecution.ExecutionId, result.Action.Name, result.Action.ID, result.Status)
					SetCache(ctx, cacheKey, []byte("logged"), 5) // 5 minute TTL
				}

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
	if (workflowExecution.Status == "WAITING" || workflowExecution.Status == "EXECUTING") && len(workflowExecution.Results) == len(workflowExecution.Workflow.Actions)+extra {
		skipFinished := false
		for _, result := range workflowExecution.Results {
			if result.Status == "WAITING" {
				skipFinished = true
				break
			}
		}

		// Has to do with rerun systems from April 2025
		for _, action := range workflowExecution.Workflow.Actions {
			if action.Category == "rerun" {
				skipFinished = true
				break
			}
		}

		if !skipFinished {
			// FIXME: Is this subflow result (not implemented) valid? I think it should have been added? Hmm.
			//log.Printf("[DEBUG][%s] Setting execution to finished because all results are in and it was still in EXECUTING mode. Should set subflow parent result as well (not implemented) - just returning for now for parent function to handle.", workflowExecution.ExecutionId)
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

func SetWorkflowExecution(ctx context.Context, workflowExecution WorkflowExecution, dbSave bool) error {
	nameKey := "workflowexecution"
	if len(workflowExecution.ExecutionId) == 0 {
		log.Printf("[ERROR] Workflowexecution executionId can't be empty.")

		// Generate it on the fly?
		//workflowExecution.ExecutionId = uuid.NewV4().String()
		return errors.New("ExecutionId can't be empty.")
	}

	if len(workflowExecution.WorkflowId) == 0 {
		log.Printf("[ERROR][%s] Workflowexecution workflowId can't be empty.", workflowExecution.ExecutionId)
		workflowExecution.WorkflowId = workflowExecution.Workflow.ID
	}

	if len(workflowExecution.Authorization) == 0 {
		log.Printf("[ERROR][%s] Workflowexecution authorization can't be empty.", workflowExecution.ExecutionId)
		//workflowExecution.Authorization = uuid.NewV4().String()
		return errors.New("Authorization can't be empty.")
	}

	// Fixes missing pieces
	workflowExecution, newDbSave := Fixexecution(ctx, workflowExecution)
	workflowExecution = cleanupExecutionNodes(ctx, workflowExecution)
	if newDbSave {
		dbSave = true
	}

	cacheKey := fmt.Sprintf("%s_%s", nameKey, workflowExecution.ExecutionId)

	// Weird workaround that only applies during local development
	hostname, err := os.Hostname()
	if err != nil || hostname == "debian" {
		hostname = "shuffle-backend"
	}

	executionData, err := json.Marshal(workflowExecution)
	if err == nil {
		err = SetCache(ctx, cacheKey, executionData, 600)
		if err != nil {
			//log.Printf("[WARNING] Failed updating execution cache. Setting DB! %s", err)
			dbSave = true
		} else {

		}
	} else {
		//log.Printf("[ERROR] Failed marshalling execution for cache: %s", err)
		//log.Printf("[INFO] Set execution cache for workflowexecution %s", cacheKey)
	}

	// FIXME: This right here has caused more problems during dev than anything
	if (os.Getenv("SHUFFLE_SWARM_CONFIG") == "run" || project.Environment == "worker") && !strings.Contains(strings.ToLower(hostname), "backend") {
		if debug {
			log.Printf("[DEBUG] Not saving execution to DB (just cache), since we are running in swarm mode (SHUFFLE_SWARM_CONFIG=run).")
		}

		return nil
	}

	// This may get data from cache, hence we need to continuously set things in the database. Mainly as a precaution.
	newexec, err := GetWorkflowExecution(ctx, workflowExecution.ExecutionId)
	if err != nil {
		return fmt.Errorf("[ERROR] Failed to get new execution(%s): %s", workflowExecution.ExecutionId, err)
	}

	HandleExecutionCacheIncrement(ctx, *newexec)
	if !dbSave && err == nil && (newexec.Status == "FINISHED" || newexec.Status == "ABORTED") {
		log.Printf("[INFO][%s] Already finished (set workflow) with status %s! Stopping the rest of the request for execution.", workflowExecution.ExecutionId, newexec.Status)
		return nil
	}

	// Deleting cache so that listing can work well
	DeleteCache(ctx, fmt.Sprintf("%s_%s", nameKey, workflowExecution.WorkflowId))
	DeleteCache(ctx, fmt.Sprintf("%s_%s_50", nameKey, workflowExecution.WorkflowId))
	DeleteCache(ctx, fmt.Sprintf("%s_%s_100", nameKey, workflowExecution.WorkflowId))
	DeleteCache(ctx, fmt.Sprintf("%s__%s", nameKey, workflowExecution.WorkflowId))
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

	if newexec.Status == "FINISHED" || newexec.Status == "ABORTED" {
		// Handles stat updates. Upgrading status to prevent timeouts for first iter of this
		ctx = context.Background()
		newexec = checkExecutionStatus(ctx, newexec)
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

		// Compresses and removes unecessary things
		workflowExecution, _ := compressExecution(ctx, workflowExecution, "db-connector save")

		executionData, err = json.Marshal(workflowExecution)
		if err != nil {
			log.Printf("[ERROR] Failed marshalling execution for ES: %s", err)
			return err
		}

		if debug {
			log.Printf("[DEBUG] Final string size of execution is: %d", len(executionData))
		}

		err = writeExecutionDocument(ctx, workflowExecution.ExecutionId, workflowExecution.Status, executionData)
		if err == ErrExecutionArchived {
			log.Printf("[INFO][%s] Rejected write to archived execution", workflowExecution.ExecutionId)
			return ErrExecutionArchived
		}
		if err != nil {
			if strings.Contains(err.Error(), "immense term") {
				retried := false

				if len(workflowExecution.ExecutionArgument) > 32500 {
					workflowExecution.ExecutionArgument = "Size too large. Removed."
					retried = true
				}

				if len(workflowExecution.Result) > 32500 {
					workflowExecution.Result = "Size too large. Removed."
					retried = true
				}

				for resultIndex, result := range workflowExecution.Results {
					if len(result.Result) > 32500 {
						workflowExecution.Results[resultIndex].Result = "Size too large. Removed."
						retried = true
					}

					for paramIndex, param := range result.Action.Parameters {
						if len(param.Value) > 32500 {
							workflowExecution.Results[resultIndex].Action.Parameters[paramIndex].Value = "Size too large. Removed."
							retried = true
						}
					}

					for paramIndex, param := range result.Action.InvalidParameters {
						if len(param.Value) > 32500 {
							workflowExecution.Results[resultIndex].Action.InvalidParameters[paramIndex].Value = "Size too large. Removed."
							retried = true
						}
					}
				}

				for actionIndex, action := range workflowExecution.Workflow.Actions {
					for paramIndex, param := range action.Parameters {
						if len(param.Value) > 32500 {
							workflowExecution.Workflow.Actions[actionIndex].Parameters[paramIndex].Value = "Size too large. Removed."
							retried = true
						}
					}

					for paramIndex, param := range action.InvalidParameters {
						if len(param.Value) > 32500 {
							workflowExecution.Workflow.Actions[actionIndex].InvalidParameters[paramIndex].Value = "Size too large. Removed."
							retried = true
						}
					}
				}

				for triggerIndex, trigger := range workflowExecution.Workflow.Triggers {
					for paramIndex, param := range trigger.Parameters {
						if len(param.Value) > 32500 {
							workflowExecution.Workflow.Triggers[triggerIndex].Parameters[paramIndex].Value = "Size too large. Removed."
							retried = true
						}
					}
				}

				if retried {
					executionData, err = json.Marshal(workflowExecution)
					if err != nil {
						log.Printf("[ERROR] Failed marshalling execution for ES retry: %s", err)
						return err
					}

					log.Printf("[DEBUG][%s] Retrying OpenSearch save after trimming remaining oversized values", workflowExecution.ExecutionId)
					err = writeExecutionDocument(ctx, workflowExecution.ExecutionId, workflowExecution.Status, executionData)
				}
			}

			if err != nil {
				log.Printf("[ERROR] Failed saving new execution %s: %s", workflowExecution.ExecutionId, err)
				return err
			}
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

func GetWorkflowExecution(ctx context.Context, id string) (*WorkflowExecution, error) {
	nameKey := "workflowexecution"
	cacheKey := fmt.Sprintf("%s_%s", nameKey, id)

	// Loads of cache management to ensure we have the latest version of the execution no matter what
	workflowExecution := &WorkflowExecution{}
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			err = json.Unmarshal(cacheData, workflowExecution)

			if (err == nil && workflowExecution != nil) && len(workflowExecution.ExecutionId) > 0 {
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

				if strings.Contains(workflowExecution.Result, "Result too large to handle") {
					baseResult := &ActionResult{
						Result: workflowExecution.Result,
						Action: Action{ID: "execution_result"},
					}

					newValue, err := getExecutionFileValue(ctx, *workflowExecution, *baseResult)
					if err != nil {
						log.Printf("[DEBUG][%s] Failed to parse in execution file value for Result: %s", workflowExecution.ExecutionId, err)
					} else {
						log.Printf("[DEBUG][%s] Found a new value to parse with Result field", workflowExecution.ExecutionId)
						workflowExecution.Result = newValue
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

					for paramIndex, param := range value.Action.Parameters {
						if strings.Contains(param.Value, "Result too large to handle") {
							newValue, err := getExecutionFileValue(ctx, *workflowExecution, ActionResult{
								Result: param.Value,
							})
							if err == nil {
								workflowExecution.Results[valueIndex].Action.Parameters[paramIndex].Value = newValue
							}
						}
					}

					for paramIndex, param := range value.Action.InvalidParameters {
						if strings.Contains(param.Value, "Result too large to handle") {
							newValue, err := getExecutionFileValue(ctx, *workflowExecution, ActionResult{
								Result: param.Value,
							})
							if err == nil {
								workflowExecution.Results[valueIndex].Action.InvalidParameters[paramIndex].Value = newValue
							}
						}
					}
				}

				for actionIndex, action := range workflowExecution.Workflow.Actions {
					for paramIndex, param := range action.Parameters {
						if strings.Contains(param.Value, "Result too large to handle") {
							newValue, err := getExecutionFileValue(ctx, *workflowExecution, ActionResult{
								Result: param.Value,
							})
							if err == nil {
								workflowExecution.Workflow.Actions[actionIndex].Parameters[paramIndex].Value = newValue
							}
						}
					}

					for paramIndex, param := range action.InvalidParameters {
						if strings.Contains(param.Value, "Result too large to handle") {
							newValue, err := getExecutionFileValue(ctx, *workflowExecution, ActionResult{
								Result: param.Value,
							})
							if err == nil {
								workflowExecution.Workflow.Actions[actionIndex].InvalidParameters[paramIndex].Value = newValue
							}
						}
					}
				}

				for triggerIndex, trigger := range workflowExecution.Workflow.Triggers {
					for paramIndex, param := range trigger.Parameters {
						if strings.Contains(param.Value, "Result too large to handle") {
							newValue, err := getExecutionFileValue(ctx, *workflowExecution, ActionResult{
								Result: param.Value,
							})
							if err == nil {
								workflowExecution.Workflow.Triggers[triggerIndex].Parameters[paramIndex].Value = newValue
							}
						}
					}
				}

				for execVarIndex, execVar := range workflowExecution.Workflow.ExecutionVariables {
					if strings.Contains(execVar.Value, "Result too large to handle") {
						newValue, err := getExecutionFileValue(ctx, *workflowExecution, ActionResult{
							Result: execVar.Value,
						})
						if err == nil {
							workflowExecution.Workflow.ExecutionVariables[execVarIndex].Value = newValue
						}
					}
				}

				for execVarIndex, execVar := range workflowExecution.ExecutionVariables {
					if strings.Contains(execVar.Value, "Result too large to handle") {
						newValue, err := getExecutionFileValue(ctx, *workflowExecution, ActionResult{
							Result: execVar.Value,
						})
						if err == nil {
							workflowExecution.ExecutionVariables[execVarIndex].Value = newValue
						}
					}
				}

				// Fixes missing pieces
				newexec, _ := Fixexecution(ctx, *workflowExecution)
				workflowExecution = &newexec

				return workflowExecution, nil
			} else {
				if debug {
					log.Printf("[DEBUG] Failed mapping workflowexecution cache for '%s': %s", id, err)
				}
			}
		} else {
		}
	}

	if (os.Getenv("SHUFFLE_SWARM_CONFIG") == "run" || project.Environment == "worker") && project.Environment != "cloud" {
		return workflowExecution, errors.New("ExecutionId doesn't exist in cache")
	}

	var getErr error = nil
	if project.DbType == "opensearch" {
		fetched, fetchErr := getExecutionDocument(ctx, id)
		if fetchErr != nil {
			return workflowExecution, fetchErr
		}

		workflowExecution = fetched
	} else {
		key := datastore.NameKey(nameKey, strings.ToLower(id), nil)
		if getErr = project.Dbclient.Get(ctx, key, workflowExecution); getErr != nil {
			if strings.Contains(getErr.Error(), `cannot load field`) {
				getErr = nil
			} else {
				//return workflowExecution, err
			}
		}
	}
	if len(workflowExecution.ExecutionId) > 0 {
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

		if strings.Contains(workflowExecution.Result, "Result too large to handle") {
			baseResult := &ActionResult{
				Result: workflowExecution.Result,
				Action: Action{ID: "execution_result"},
			}

			newValue, err := getExecutionFileValue(ctx, *workflowExecution, *baseResult)
			if err != nil {
				log.Printf("[DEBUG][%s] Failed to parse in execution file value for Result: %s", workflowExecution.ExecutionId, err)
			} else {
				workflowExecution.Result = newValue
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

			for paramIndex, param := range value.Action.Parameters {
				if strings.Contains(param.Value, "Result too large to handle") {
					newValue, err := getExecutionFileValue(ctx, *workflowExecution, ActionResult{
						Result: param.Value,
					})
					if err == nil {
						workflowExecution.Results[valueIndex].Action.Parameters[paramIndex].Value = newValue
					}
				}
			}

			for paramIndex, param := range value.Action.InvalidParameters {
				if strings.Contains(param.Value, "Result too large to handle") {
					newValue, err := getExecutionFileValue(ctx, *workflowExecution, ActionResult{
						Result: param.Value,
					})
					if err == nil {
						workflowExecution.Results[valueIndex].Action.InvalidParameters[paramIndex].Value = newValue
					}
				}
			}
		}

		for actionIndex, action := range workflowExecution.Workflow.Actions {
			for paramIndex, param := range action.Parameters {
				if strings.Contains(param.Value, "Result too large to handle") {
					newValue, err := getExecutionFileValue(ctx, *workflowExecution, ActionResult{
						Result: param.Value,
					})
					if err == nil {
						workflowExecution.Workflow.Actions[actionIndex].Parameters[paramIndex].Value = newValue
					}
				}
			}

			for paramIndex, param := range action.InvalidParameters {
				if strings.Contains(param.Value, "Result too large to handle") {
					newValue, err := getExecutionFileValue(ctx, *workflowExecution, ActionResult{
						Result: param.Value,
					})
					if err == nil {
						workflowExecution.Workflow.Actions[actionIndex].InvalidParameters[paramIndex].Value = newValue
					}
				}
			}
		}

		for triggerIndex, trigger := range workflowExecution.Workflow.Triggers {
			for paramIndex, param := range trigger.Parameters {
				if strings.Contains(param.Value, "Result too large to handle") {
					newValue, err := getExecutionFileValue(ctx, *workflowExecution, ActionResult{
						Result: param.Value,
					})
					if err == nil {
						workflowExecution.Workflow.Triggers[triggerIndex].Parameters[paramIndex].Value = newValue
					}
				}
			}
		}

		for execVarIndex, execVar := range workflowExecution.Workflow.ExecutionVariables {
			if strings.Contains(execVar.Value, "Result too large to handle") {
				newValue, err := getExecutionFileValue(ctx, *workflowExecution, ActionResult{
					Result: execVar.Value,
				})
				if err == nil {
					workflowExecution.Workflow.ExecutionVariables[execVarIndex].Value = newValue
				}
			}
		}

		for execVarIndex, execVar := range workflowExecution.ExecutionVariables {
			if strings.Contains(execVar.Value, "Result too large to handle") {
				newValue, err := getExecutionFileValue(ctx, *workflowExecution, ActionResult{
					Result: execVar.Value,
				})
				if err == nil {
					workflowExecution.ExecutionVariables[execVarIndex].Value = newValue
				}
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
			return workflowExecution, getErr
		}

		err = SetCache(ctx, id, newexecution, 600)
		if err != nil {
			log.Printf("[WARNING] Failed updating execution: %s", err)
		}
	}

	return workflowExecution, getErr
}
