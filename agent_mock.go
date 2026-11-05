package shuffle

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	openai "github.com/sashabaranov/go-openai"
	uuid "github.com/satori/go.uuid"
)

// AgentTestRequest represents the JSON request body accepted by POST /api/v1/agent_tests.
type AgentTestRequest struct {
	TestCase        string `json:"test_case"`
	Prompt          string `json:"prompt"`
	Input           string `json:"input"`
	Tools           string `json:"tools"`
	Action          string `json:"action"`
	EnableQuestions string `json:"enable_questions"`
	WorkflowId      string `json:"workflow_id"`
}

// HandleAgentTests handles POST /api/v1/agent_tests.
// Authenticates the caller, verifies SupportAccess, sets `test_case` in the AI Agent
// start node parameters, saves the WorkflowExecution, and calls HandleAiAgentExecutionStart directly.
func HandleAgentTests(resp http.ResponseWriter, request *http.Request) {
	if HandleCors(resp, request) {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Authentication failed on /api/v1/agent_tests: %s", err)
		resp.WriteHeader(http.StatusUnauthorized)
		resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
		return
	}

	if !user.SupportAccess && !(project.Environment != "cloud" && user.Role == "admin") {
		log.Printf("[WARNING] User %s (%s) attempted to call /api/v1/agent_tests without SupportAccess", user.Username, user.Id)
		resp.WriteHeader(http.StatusForbidden)
		resp.Write([]byte(`{"success": false, "reason": "Support access required to run agent tests"}`))
		return
	}

	body, err := io.ReadAll(request.Body)
	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading request body"}`))
		return
	}
	defer request.Body.Close()

	var req AgentTestRequest
	if err := json.Unmarshal(body, &req); err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Invalid JSON body: %s"}`, err.Error())))
		return
	}

	req.TestCase = strings.TrimSpace(req.TestCase)
	if req.TestCase == "" {
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte(`{"success": false, "reason": "test_case is required"}`))
		return
	}

	if _, stepErr := getMockAgentResponse(req.TestCase, 1); stepErr != nil && strings.HasPrefix(stepErr.Error(), "unknown test_case:") {
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, stepErr.Error())))
		return
	}

	prompt := req.Prompt
	if prompt == "" {
		prompt = req.Input
	}
	tools := req.Tools
	if tools == "" {
		tools = req.Action
	}
	if tools == "" {
		tools = "shuffle_tools,http"
	}
	enableQuestions := req.EnableQuestions
	if enableQuestions == "" {
		enableQuestions = "true"
	}

	nodeId := uuid.NewV4().String()
	action := Action{
		ID:          nodeId,
		Name:        "agent",
		AppName:     "AI Agent",
		AppID:       "shuffle_agent",
		AppVersion:  "1.0.0",
		Label:       "agent",
		Environment: "Cloud",
		IsStartNode: true,
		Sharing:     true,
		Parameters: []WorkflowAppActionParameter{
			{Name: "input", Value: prompt},
			{Name: "action", Value: tools},
			{Name: "enable_questions", Value: enableQuestions},
			{Name: "test_case", Value: req.TestCase},
		},
	}

	executionId := uuid.NewV4().String()
	workflowId := req.WorkflowId
	if workflowId == "" {
		workflowId = executionId
	}

	ctx := GetContext(request)
	exec := WorkflowExecution{
		Type:                "agent",
		Status:              "EXECUTING",
		StartedAt:           time.Now().Unix(),
		LastNode:            action.ID,
		Start:               action.ID,
		ExecutionSourceNode: action.ID,
		ExecutionId:         executionId,
		Authorization:       uuid.NewV4().String(),
		WorkflowId:          workflowId,
		ExecutionSource:     "agent_test",
		ExecutionOrg:        user.ActiveOrg.Id,
		Workflow: Workflow{
			ID:        workflowId,
			Name:      fmt.Sprintf("Agent Test (%s)", req.TestCase),
			OrgId:     user.ActiveOrg.Id,
			Start:     action.ID,
			Actions:   []Action{action},
			UpdatedBy: user.Username,
		},
	}

	if err := SetWorkflowExecution(ctx, exec, true); err != nil {
		log.Printf("[ERROR][%s] Failed saving initial agent test execution: %s", exec.ExecutionId, err)
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(`{"success": false, "reason": "Failed saving initial workflow execution"}`))
		return
	}

	_, _ = HandleAiAgentExecutionStart(exec, action, false, "HandleAgentTests")

	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(http.StatusOK)
	respBytes, _ := json.Marshal(map[string]interface{}{
		"success":       true,
		"execution_id":  exec.ExecutionId,
		"authorization": exec.Authorization,
		"workflow_id":   exec.WorkflowId,
		"test_case":     req.TestCase,
	})
	resp.Write(respBytes)
}

// RunAiQueryMock is called by HandleAiAgentExecutionStart when `isTestMode` is true.
// It fetches the mock JSON string for `(testCase, step)` (1-based: step 1, step 2, step 3...),
// records the OpenAI response on `info.Resp`, and returns the output string.
func RunAiQueryMock(testCase string, step int, completionRequest openai.ChatCompletionRequest, info AiCallInfo) (string, error) {
	output, err := getMockAgentResponse(testCase, step)
	if err != nil {
		return "", err
	}

	modelName := completionRequest.Model
	if modelName == "" {
		modelName = "gpt-5.4-mock"
	}

	fullResp := openai.ChatCompletionResponse{
		ID:      fmt.Sprintf("chatcmpl-mock-%s-step-%d-%d", testCase, step, time.Now().UnixNano()),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   modelName,
		Choices: []openai.ChatCompletionChoice{
			{
				Index: 0,
				Message: openai.ChatCompletionMessage{
					Role:    openai.ChatMessageRoleAssistant,
					Content: output,
				},
				FinishReason: openai.FinishReasonStop,
			},
		},
		Usage: openai.Usage{
			PromptTokens:     500,
			CompletionTokens: 100,
			TotalTokens:      600,
		},
	}

	if info.Resp != nil {
		if respBytes, marshalErr := json.Marshal(fullResp); marshalErr == nil {
			info.Resp.WriteHeader(http.StatusOK)
			_, _ = info.Resp.Write(respBytes)
		}
	}

	return output, nil
}

// getMockAgentResponse dispatches `(testCase, step)` (where step is 1, 2, 3...) to the test's function.
func getMockAgentResponse(testCase string, step int) (string, error) {
	if strings.HasPrefix(testCase, "test_20_worker_") {
		var workerIdx int
		if _, err := fmt.Sscanf(testCase, "test_20_worker_%d", &workerIdx); err == nil {
			return test20_ConcurrentWorker(workerIdx, step)
		}
	}

	switch testCase {
	case "test_01":
		return test01_DirectFinish(step)
	case "test_02":
		return test02_PythonSmoke(step)
	case "test_03":
		return test03_HistoryPropagation(step)
	case "test_04":
		return test04_ChainedTools(step)
	case "test_05":
		return test05_ParallelTools(step)
	case "test_06":
		return test06_LookaheadPlan(step)
	case "test_07":
		return test07_AskAndResume(step)
	case "test_08":
		return test08_StandaloneAnswer(step)
	case "test_09":
		return test09_ContinuationAfterFinish(step)
	case "test_10":
		return test10_DelayEnforcement(step)
	case "test_11":
		return test11_CodeFenceStripping(step)
	case "test_12":
		return test12_CategoryNormalization(step)
	case "test_13":
		return test13_StaleIndexAutocorrect(step)
	case "test_14":
		return test14_StripFakeRawResponse(step)
	case "test_15":
		return test15_DataFilterList(step)
	case "test_16":
		return test16_ToolFailureRecovery(step)
	case "test_17":
		return test17_FourFailuresHardAbort(step)
	case "test_18":
		return test18_RateLimit429Abort(step)
	case "test_19":
		return test19_MalformedNonJSON(step)
	case "test_21":
		return test21_JSONWrapperVariants(step)
	case "test_22":
		return test22_FinishReasonFallback(step)
	case "test_23":
		return test23_AskFieldAutorepair(step)
	case "test_24":
		return test24_ApprovalRequiredPause(step)
	case "test_25":
		return test25_EmptyActionAbort(step)
	case "test_26":
		return test26_MinimalDecisionFields(step)
	case "test_27":
		return test27_FinishCategoryInference(step)
	case "test_28":
		return test28_NegativeIndexReindex(step)
	case "test_29":
		return test29_NonStringFieldValues(step)
	case "test_30":
		return test30_MissingToolRecovery(step)
	case "test_31":
		return test31_ClampBizarreDelays(step)
	case "test_32":
		return test32_UnknownStandaloneRecovery(step)
	case "test_33":
		return test33_TruncatedJSONBalance(step)
	case "test_34":
		return test34_StringConcatRepair(step)
	case "test_35":
		return test35_ProseAndEscapedQuotes(step)
	case "test_36":
		return test36_JSONLDecisions(step)
	case "test_37":
		return test37_EmptyObjectFailure(step)
	case "test_38":
		return test38_EightStepEndurance(step)
	case "test_39_case_0":
		return test39_SwarmCase0(step)
	case "test_39_case_1":
		return test39_SwarmCase1(step)
	case "test_39_case_2":
		return test39_SwarmCase2(step)
	case "test_39_case_3":
		return test39_SwarmCase3(step)
	case "test_39_case_4":
		return test39_SwarmCase4(step)
	case "test_40":
		return test40_Large8KBOutput(step)
	case "test_41":
		return test41_MultiRoundAskAndTool(step)
	case "test_42":
		return test42_AskEmptyFieldsFallback(step)
	case "test_43":
		return test43_FinishBodyFieldKey(step)
	case "test_44":
		return test44_MaxLoopsHardAbort(step)
	case "test_45":
		return test45_Upstream502Abort(step)
	case "test_46":
		return test46_DisallowedToolBlocked(step)
	case "test_47":
		return test47_ConditionFailedMessage(step)
	case "test_48":
		return test48_UniqueDecisionIds(step)
	case "test_49":
		return test49_UnassignedRealToolBlocked(step)
	case "test_50":
		return test50_ToolAndActionNormalization(step)
	case "test_51":
		return test51_CaseInsensitiveFields(step)
	case "test_52":
		return test52_HallucinatedActionRecovery(step)
	case "test_53":
		return test53_PromptConstructionContract(step)
	case "test_54":
		return test54_PrefixStabilityAcrossSteps(step)
	case "test_55":
		return test55_DataFilterPartialMatch(step)
	case "test_56":
		return test56_DataFilterFallbacks(step)
	default:
		return "", fmt.Errorf("unknown test_case: %s", testCase)
	}
}

// ============================================================================
// Test 01: Direct finish in 1 step (no tools)
// ============================================================================
func test01_DirectFinish(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Paris is the capital of France."}]}]`, nil
	default:
		return "", fmt.Errorf("test_01: unexpected step %d", step)
	}
}

// ============================================================================
// Test 02: Shuffle Tools execute_python smoke test (2 steps)
// ============================================================================
func test02_PythonSmoke(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(68)"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "A random number between 1 and 100 was generated using Python in Shuffle Tools: **Result:** ` + "`68`" + `"}]}]`, nil
	default:
		return "", fmt.Errorf("test_02: unexpected step %d", step)
	}
}

// ============================================================================
// Test 03: Closed-loop HISTORY propagation (print(1337 * 3) -> 4011)
// ============================================================================
func test03_HistoryPropagation(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(1337 * 3)"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Computed result from HISTORY is 4011"}]}]`, nil
	default:
		return "", fmt.Errorf("test_03: unexpected step %d", step)
	}
}

// ============================================================================
// Test 04: Chained tools across 3 steps (Ipinfoio -> Shuffle Tools -> Finish)
// ============================================================================
func test04_ChainedTools(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "get_ip_geo_info", "tool": "Ipinfoio", "category": "singul", "fields": [{"key": "ip", "value": "34.34.65.23"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(68)"}]}]`, nil
	case 3:
		return `[{"i": 2, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "A random number between 1 and 100 was generated using Python in Shuffle Tools: **Result:** ` + "`68`" + `"}]}]`, nil
	default:
		return "", fmt.Errorf("test_04: unexpected step %d", step)
	}
}

// ============================================================================
// Test 05: Parallel tool calls sharing the same index (i=0, i=0)
// ============================================================================
func test05_ParallelTools(step int) (string, error) {
	switch step {
	case 1:
		return `[
			{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(111)"}]},
			{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(222)"}]}
		]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Both parallel Python tasks completed (111 and 222)."}]}]`, nil
	default:
		return "", fmt.Errorf("test_05: unexpected step %d", step)
	}
}

// ============================================================================
// Test 06: Multi-step lookahead plan returned in a single turn ([i=0, i=1])
// ============================================================================
func test06_LookaheadPlan(step int) (string, error) {
	switch step {
	case 1:
		return `[
			{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(10)"}]},
			{"i": 1, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(20)"}]}
		]`, nil
	case 2:
		return `[{"i": 2, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Multi-step lookahead plan completed."}]}]`, nil
	default:
		return "", fmt.Errorf("test_06: unexpected step %d", step)
	}
}

// ============================================================================
// Test 07: Ask question -> WAITING -> User answers "42" -> Python -> Finish
// ============================================================================
func test07_AskAndResume(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "ask", "tool": "core", "category": "standalone", "fields": [{"key": "question", "value": "What is your secret number?"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(42 * 2)"}]}]`, nil
	case 3:
		return `[{"i": 2, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "42 multiplied by 2 is 84."}]}]`, nil
	default:
		return "", fmt.Errorf("test_07: unexpected step %d", step)
	}
}

// ============================================================================
// Test 08: Standalone `answer` decision followed by `finish` in 1 step
// ============================================================================
func test08_StandaloneAnswer(step int) (string, error) {
	switch step {
	case 1:
		return `[
			{"i": 0, "action": "answer", "tool": "core", "category": "standalone", "fields": [{"key": "answer", "value": "Intermediate standalone answer"}]},
			{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Completed after standalone answer."}]}
		]`, nil
	default:
		return "", fmt.Errorf("test_08: unexpected step %d", step)
	}
}

// ============================================================================
// Test 09: Continuation after finish (Steps 1-2 initial run, Steps 3-4 continuation)
// ============================================================================
func test09_ContinuationAfterFinish(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(10)"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Generated 10."}]}]`, nil
	case 3:
		return `[{"i": 2, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(68)"}]}]`, nil
	case 4:
		return `[{"i": 3, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "A random number between 1 and 100 was generated using Python in Shuffle Tools: **Result:** ` + "`68`" + `"}]}]`, nil
	default:
		return "", fmt.Errorf("test_09: unexpected step %d", step)
	}
}

// ============================================================================
// Test 10: Delay enforcement (`delay: "4"` seconds on Step 1)
// ============================================================================
func test10_DelayEnforcement(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "delay": "4", "fields": [{"key": "code", "value": "print(68)"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Delayed Python execution complete."}]}]`, nil
	default:
		return "", fmt.Errorf("test_10: unexpected step %d", step)
	}
}

// ============================================================================
// Test 11: Markdown ```json ... ``` code fence stripping
// ============================================================================
func test11_CodeFenceStripping(step int) (string, error) {
	switch step {
	case 1:
		return "```json\n[{\"i\": 0, \"action\": \"execute_python\", \"tool\": \"Shuffle Tools\", \"category\": \"singul\", \"fields\": [{\"key\": \"code\", \"value\": \"print(68)\"}]}]\n```", nil
	case 2:
		return "```json\n[{\"i\": 1, \"action\": \"finish\", \"tool\": \"core\", \"category\": \"finish\", \"fields\": [{\"key\": \"output\", \"value\": \"Parsed fenced JSON properly.\"}]}]\n```", nil
	default:
		return "", fmt.Errorf("test_11: unexpected step %d", step)
	}
}

// ============================================================================
// Test 12: Category auto-normalization (wrong category fixed by harness)
// ============================================================================
func test12_CategoryNormalization(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "standalone", "fields": [{"key": "code", "value": "print(68)"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "singul", "fields": [{"key": "output", "value": "Normalized categories properly."}]}]`, nil
	default:
		return "", fmt.Errorf("test_12: unexpected step %d", step)
	}
}

// ============================================================================
// Test 13: Stale index auto-correction (LLM outputs i=0 on all 3 steps)
// ============================================================================
func test13_StaleIndexAutocorrect(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(1)"}]}]`, nil
	case 2:
		return `[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(2)"}]}]`, nil
	case 3:
		return `[{"i": 0, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Completed despite stale i=0 indices."}]}]`, nil
	default:
		return "", fmt.Errorf("test_13: unexpected step %d", step)
	}
}

// ============================================================================
// Test 14: Hallucinated `run_details.raw_response` stripped & replaced by real tool output
// ============================================================================
func test14_StripFakeRawResponse(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(999)"}], "run_details": {"raw_response": "{\"success\": true, \"message\": \"FAKE_HALLUCINATED_BY_LLM\"}"}}]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Verified real tool output 999 replaced hallucinated raw_response."}]}]`, nil
	default:
		return "", fmt.Errorf("test_14: unexpected step %d", step)
	}
}

// ============================================================================
// Test 15: Data filter (`data_filter: "list"`, `fields_needed: ["ip", "country"]`)
// ============================================================================
func test15_DataFilterList(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "get_ip_geo_info", "tool": "Ipinfoio", "category": "singul", "data_filter": "list", "fields_needed": ["ip", "country"], "fields": [{"key": "ip", "value": "34.34.65.23"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Filtered IP lookup done."}]}]`, nil
	default:
		return "", fmt.Errorf("test_15: unexpected step %d", step)
	}
}

// ============================================================================
// Test 16: Single tool failure on Step 1 -> self-correction on Step 2 -> Finish
// ============================================================================
func test16_ToolFailureRecovery(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "non_existent_broken_action", "tool": "UnassignedFakeTool", "category": "singul", "fields": [{"key": "foo", "value": "bar"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(777)"}]}]`, nil
	case 3:
		return `[{"i": 2, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Recovered from tool failure and generated 777."}]}]`, nil
	default:
		return "", fmt.Errorf("test_16: unexpected step %d", step)
	}
}

// ============================================================================
// Test 17: Same tool fails 4 times -> 3x warning on Step 4 -> 4x hard abort
// ============================================================================
func test17_FourFailuresHardAbort(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "non_existent_broken_action", "tool": "UnassignedFakeTool", "category": "singul", "fields": [{"key": "foo", "value": "bar"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "non_existent_broken_action", "tool": "UnassignedFakeTool", "category": "singul", "fields": [{"key": "foo", "value": "bar"}]}]`, nil
	case 3:
		return `[{"i": 2, "action": "non_existent_broken_action", "tool": "UnassignedFakeTool", "category": "singul", "fields": [{"key": "foo", "value": "bar"}]}]`, nil
	case 4:
		return `[{"i": 3, "action": "non_existent_broken_action", "tool": "UnassignedFakeTool", "category": "singul", "fields": [{"key": "foo", "value": "bar"}]}]`, nil
	case 5:
		return `[{"i": 4, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Should NEVER be reached"}]}]`, nil
	default:
		return "", fmt.Errorf("test_17: unexpected step %d", step)
	}
}

// ============================================================================
// Test 18: Upstream LLM 429 rate-limit error -> immediate abort
// ============================================================================
func test18_RateLimit429Abort(step int) (string, error) {
	switch step {
	case 1:
		return "", errors.New("429 Too Many Requests: rate limit exceeded")
	default:
		return "", fmt.Errorf("test_18: unexpected step %d", step)
	}
}

// ============================================================================
// Test 19: Malformed non-JSON LLM output -> fails cleanly
// ============================================================================
func test19_MalformedNonJSON(step int) (string, error) {
	switch step {
	case 1:
		return "I am sorry, I cannot return valid JSON right now.", nil
	default:
		return "", fmt.Errorf("test_19: unexpected step %d", step)
	}
}

// ============================================================================
// Test 20: Concurrent stress worker (`test_20_worker_0` .. `test_20_worker_9`)
// ============================================================================
func test20_ConcurrentWorker(workerIdx int, step int) (string, error) {
	switch step {
	case 1:
		return fmt.Sprintf(`[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(1000 + %d)"}]}]`, workerIdx), nil
	case 2:
		return fmt.Sprintf(`[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Completed concurrent run #%d with Python result %d"}]}]`, workerIdx, 1000+workerIdx), nil
	default:
		return "", fmt.Errorf("test_20_worker_%d: unexpected step %d", workerIdx, step)
	}
}

// ============================================================================
// Test 21: JSON wrapper variants (`{"decisions": [...]}` & bare single object)
// ============================================================================
func test21_JSONWrapperVariants(step int) (string, error) {
	switch step {
	case 1:
		return `{"decisions": [{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(314)"}]}]}`, nil
	case 2:
		return `{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Unwrapped both object wrapper and single decision object."}]}`, nil
	default:
		return "", fmt.Errorf("test_21: unexpected step %d", step)
	}
}

// ============================================================================
// Test 22: Finish with empty `fields: []` falls back to `decision.reason`
// ============================================================================
func test22_FinishReasonFallback(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "finish", "tool": "Standalone", "category": "finish", "fields": [], "reason": "Fallback output populated from decision.reason when fields are empty."}]`, nil
	default:
		return "", fmt.Errorf("test_22: unexpected step %d", step)
	}
}

// ============================================================================
// Test 23: Malformed `ask` field (`{"question": "..."}` without key/value) auto-repaired
// ============================================================================
func test23_AskFieldAutorepair(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "ask", "tool": "Standalone", "category": "ask", "fields": [{"question": "Which environment should I run the Python script in?"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Completed in production environment."}]}]`, nil
	default:
		return "", fmt.Errorf("test_23: unexpected step %d", step)
	}
}

// ============================================================================
// Test 24: `approval_required: true` pauses decision in WAITING state
// ============================================================================
func test24_ApprovalRequiredPause(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "approval_required": true, "fields": [{"key": "code", "value": "print('sensitive_action')"}]}]`, nil
	default:
		return "", fmt.Errorf("test_24: unexpected step %d", step)
	}
}

// ============================================================================
// Test 25: Empty `action: ""` triggers `no_decision_action_ran` abort
// ============================================================================
func test25_EmptyActionAbort(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "", "tool": "Shuffle Tools", "category": "singul", "fields": []}]`, nil
	default:
		return "", fmt.Errorf("test_25: unexpected step %d", step)
	}
}

// ============================================================================
// Test 26: Minimal decision objects with optional fields omitted
// ============================================================================
func test26_MinimalDecisionFields(step int) (string, error) {
	switch step {
	case 1:
		return `[{"action": "execute_python", "tool": "Shuffle Tools", "fields": [{"key": "code", "value": "print(505)"}]}]`, nil
	case 2:
		return `[{"action": "finish", "fields": [{"key": "output", "value": "Minimal decision succeeded with 505"}]}]`, nil
	default:
		return "", fmt.Errorf("test_26: unexpected step %d", step)
	}
}

// ============================================================================
// Test 27: Missing `action` field inferred when `category == "finish"`
// ============================================================================
func test27_FinishCategoryInference(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "category": "finish", "fields": [{"key": "output", "value": "Inferred finish action from category=finish despite missing action field."}]}]`, nil
	default:
		return "", fmt.Errorf("test_27: unexpected step %d", step)
	}
}

// ============================================================================
// Test 28: Negative and missing `i` values (`-5`, omitted, `-99`) auto-reindexed
// ============================================================================
func test28_NegativeIndexReindex(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": -5, "action": "execute_python", "tool": "Shuffle Tools", "fields": [{"key": "code", "value": "print(11)"}]}]`, nil
	case 2:
		return `[{"action": "execute_python", "tool": "Shuffle Tools", "fields": [{"key": "code", "value": "print(22)"}]}]`, nil
	case 3:
		return `[{"i": -99, "action": "finish", "fields": [{"key": "output", "value": "Reindexed -5, missing, and -99 to 0, 1, 2."}]}]`, nil
	default:
		return "", fmt.Errorf("test_28: unexpected step %d", step)
	}
}

// ============================================================================
// Test 29: Non-string `fields[].value` (int, bool, array, nested object) normalized
// ============================================================================
func test29_NonStringFieldValues(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "fields": [{"key": "code", "value": "print(808)"}, {"key": "int_param", "value": 42}, {"key": "bool_param", "value": true}, {"key": "list_param", "value": [1, 2, 3]}, {"key": "obj_param", "value": {"nested_key": "nested_val"}}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "fields": [{"key": "output", "value": "Normalized non-string field values cleanly."}]}]`, nil
	default:
		return "", fmt.Errorf("test_29: unexpected step %d", step)
	}
}

// ============================================================================
// Test 30: Missing `tool` field rejected on Step 1 -> recovered on Step 2
// ============================================================================
func test30_MissingToolRecovery(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "execute_python", "category": "singul", "fields": [{"key": "code", "value": "print(303)"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(303)"}]}]`, nil
	case 3:
		return `[{"i": 2, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Recovered after missing tool field on Turn 1."}]}]`, nil
	default:
		return "", fmt.Errorf("test_30: unexpected step %d", step)
	}
}

// ============================================================================
// Test 31: Bizarre `delay` values (`"-50"`, `"999999999"`, `"not_a_number"`) clamped to 0
// ============================================================================
func test31_ClampBizarreDelays(step int) (string, error) {
	switch step {
	case 1:
		return `[
			{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "delay": "-50", "fields": [{"key": "code", "value": "print(1)"}]},
			{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "delay": "999999999", "fields": [{"key": "code", "value": "print(2)"}]},
			{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "delay": "not_a_number", "fields": [{"key": "code", "value": "print(3)"}]}
		]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "All bizarre delays clamped to 0 without hanging."}]}]`, nil
	default:
		return "", fmt.Errorf("test_31: unexpected step %d", step)
	}
}

// ============================================================================
// Test 32: Unknown standalone action rejected on Step 1 -> recovered on Step 2
// ============================================================================
func test32_UnknownStandaloneRecovery(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "invented_magic_action", "tool": "Standalone", "category": "standalone", "fields": []}]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Recovered from invented action."}]}]`, nil
	default:
		return "", fmt.Errorf("test_32: unexpected step %d", step)
	}
}

// ============================================================================
// Test 33: Truncated unbalanced JSON auto-healed by `balanceJSONLikeString`
// ============================================================================
func test33_TruncatedJSONBalance(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "finish", "category": "finish", "fields": [{"key": "output", "value": "Auto-healed truncated JSON output`, nil
	default:
		return "", fmt.Errorf("test_33: unexpected step %d", step)
	}
}

// ============================================================================
// Test 34: LLM string concatenation glue (`"part1 " + "part2"`) auto-repaired
// ============================================================================
func test34_StringConcatRepair(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "finish", "category": "finish", "fields": [{"key": "output", "value": "Concatenated " + "string " + "repaired!"}]}]`, nil
	default:
		return "", fmt.Errorf("test_34: unexpected step %d", step)
	}
}

// ============================================================================
// Test 35: Conversational prose wrapper on Step 1 & escaped quotes `\"` on Step 2
// ============================================================================
func test35_ProseAndEscapedQuotes(step int) (string, error) {
	switch step {
	case 1:
		return "Sure! I will run the Python calculation for you right now:\n\n" +
			`[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(616)"}]}]` +
			"\n\nLet me know once the tool finishes!", nil
	case 2:
		return `[{\"i\": 1, \"action\": \"finish\", \"tool\": \"core\", \"category\": \"finish\", \"fields\": [{\"key\": \"output\", \"value\": \"Completed after prose wrapper and escaped quotes.\"}]}]`, nil
	default:
		return "", fmt.Errorf("test_35: unexpected step %d", step)
	}
}

// ============================================================================
// Test 36: Newline-delimited JSONL decisions without outer `[` and `]` brackets
// ============================================================================
func test36_JSONLDecisions(step int) (string, error) {
	switch step {
	case 1:
		return `{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(111)"}]}` + "\n" +
			`{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(222)"}]}`, nil
	case 2:
		return `{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "JSONL decisions parsed and executed."}]}`, nil
	default:
		return "", fmt.Errorf("test_36: unexpected step %d", step)
	}
}

// ============================================================================
// Test 37: Empty JSON object `[{}]` fails gracefully without panic
// ============================================================================
func test37_EmptyObjectFailure(step int) (string, error) {
	switch step {
	case 1:
		return `[{}]`, nil
	default:
		return "", fmt.Errorf("test_37: unexpected step %d", step)
	}
}

// ============================================================================
// Test 38: Deep 8-step endurance loop (Steps 1..7 Python, Step 8 Finish)
// ============================================================================
func test38_EightStepEndurance(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(100)"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(200)"}]}]`, nil
	case 3:
		return `[{"i": 2, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(300)"}]}]`, nil
	case 4:
		return `[{"i": 3, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(400)"}]}]`, nil
	case 5:
		return `[{"i": 4, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(500)"}]}]`, nil
	case 6:
		return `[{"i": 5, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(600)"}]}]`, nil
	case 7:
		return `[{"i": 6, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(700)"}]}]`, nil
	case 8:
		return `[{"i": 7, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Completed 8-turn endurance loop."}]}]`, nil
	default:
		return "", fmt.Errorf("test_38: unexpected step %d", step)
	}
}

// ============================================================================
// Test 39: Mixed-chaos concurrent swarm (5 cases running in parallel)
// ============================================================================
func test39_SwarmCase0(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(9001)"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Swarm 0 finished: 9001"}]}]`, nil
	default:
		return "", fmt.Errorf("test_39_case_0: unexpected step %d", step)
	}
}

func test39_SwarmCase1(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "finish", "category": "finish", "fields": [{"key": "output", "value": "Swarm " + "1 " + "healed`, nil
	default:
		return "", fmt.Errorf("test_39_case_1: unexpected step %d", step)
	}
}

func test39_SwarmCase2(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "bad_action", "tool": "BadTool", "category": "singul", "fields": []}]`, nil
	case 2:
		return `[{"i": 1, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(9002)"}]}]`, nil
	case 3:
		return `[{"i": 2, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Swarm 2 recovered: 9002"}]}]`, nil
	default:
		return "", fmt.Errorf("test_39_case_2: unexpected step %d", step)
	}
}

func test39_SwarmCase3(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": -10, "action": "execute_python", "tool": "Shuffle Tools", "fields": [{"key": "code", "value": "print(9003)"}, {"key": "extra_int", "value": 99}]}]`, nil
	case 2:
		return `[{"action": "finish", "fields": [{"key": "output", "value": "Swarm 3 finished: 9003"}]}]`, nil
	default:
		return "", fmt.Errorf("test_39_case_3: unexpected step %d", step)
	}
}

func test39_SwarmCase4(step int) (string, error) {
	switch step {
	case 1:
		return `[
			{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(401)"}]},
			{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(402)"}]}
		]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Swarm 4 finished: 401 & 402"}]}]`, nil
	default:
		return "", fmt.Errorf("test_39_case_4: unexpected step %d", step)
	}
}

// ============================================================================
// Test 40: Large 8KB tool output payload handling across steps
// ============================================================================
func test40_Large8KBOutput(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print('PAYLOAD_' + ('X' * 8000) + '_END')"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Processed 8KB tool output cleanly."}]}]`, nil
	default:
		return "", fmt.Errorf("test_40: unexpected step %d", step)
	}
}

// ============================================================================
// Test 41: Multi-round `ask` (Step 1) -> Tool (Step 2) -> `question` (Step 3) -> Finish (Step 4)
// ============================================================================
func test41_MultiRoundAskAndTool(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "ask", "tool": "core", "category": "standalone", "fields": [{"key": "question", "value": "What base number should I multiply by 5?"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(10 * 5)"}]}]`, nil
	case 3:
		return `[{"i": 2, "action": "question", "tool": "Standalone", "category": "standalone", "fields": [{"key": "question", "value": "Result is 50. Should I finalize?"}]}]`, nil
	case 4:
		return `[{"i": 3, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Finalized result 50 after two user questions."}]}]`, nil
	default:
		return "", fmt.Errorf("test_41: unexpected step %d", step)
	}
}

// ============================================================================
// Test 42: `ask` with empty `fields: []` falls back to `decision.reason`
// ============================================================================
func test42_AskEmptyFieldsFallback(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "ask", "tool": "Standalone", "category": "standalone", "fields": [], "reason": "Which region should I deploy to?"}]`, nil
	default:
		return "", fmt.Errorf("test_42: unexpected step %d", step)
	}
}

// ============================================================================
// Test 43: `finish` decision using `key: "body"` instead of `key: "output"`
// ============================================================================
func test43_FinishBodyFieldKey(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "finish", "category": "finish", "fields": [{"key": "body", "value": "Final answer provided via key='body' instead of key='output'."}], "reason": "Fallback reason that should be overridden by body field"}]`, nil
	default:
		return "", fmt.Errorf("test_43: unexpected step %d", step)
	}
}

// ============================================================================
// Test 44: Max agent loops hard cap (59 decisions on Step 1 -> hits 60 cap before Step 2)
// ============================================================================
func test44_MaxLoopsHardAbort(step int) (string, error) {
	switch step {
	case 1:
		var b strings.Builder
		b.WriteString(`[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(1)"}]}`)
		for idx := 1; idx < 59; idx++ {
			b.WriteString(fmt.Sprintf(`,{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(0)"}], "run_details": {"id": "ign_%03d", "status": "IGNORED"}}`, idx))
		}
		b.WriteString(`]`)
		return b.String(), nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Should never reach Turn 2 LLM call due to max_agent_loops_reached"}]}]`, nil
	default:
		return "", fmt.Errorf("test_44: unexpected step %d", step)
	}
}

// ============================================================================
// Test 45: Generic upstream 502 LLM error -> `run_ai_query_failed` abort
// ============================================================================
func test45_Upstream502Abort(step int) (string, error) {
	switch step {
	case 1:
		return "", errors.New("Failed to run AI query: 502 Bad Gateway: upstream LLM provider connection reset by peer")
	default:
		return "", fmt.Errorf("test_45: unexpected step %d", step)
	}
}

// ============================================================================
// Test 46: Disallowed tool (`Unauthorized_Vault_App`) blocked by `isAgentToolAllowed`
// ============================================================================
func test46_DisallowedToolBlocked(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "dump_all_secrets", "tool": "Unauthorized_Vault_App", "category": "singul", "fields": []}]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Blocked unauthorized tool as expected and finished safely."}]}]`, nil
	default:
		return "", fmt.Errorf("test_46: unexpected step %d", step)
	}
}

// ============================================================================
// Test 47: Condition failed (`"conditions must be correct"`) message handling
// ============================================================================
func test47_ConditionFailedMessage(step int) (string, error) {
	switch step {
	case 1:
		return "Skipping execution: conditions must be correct before running this workflow branch.", nil
	default:
		return "", fmt.Errorf("test_47: unexpected step %d", step)
	}
}

// ============================================================================
// Test 48: Unique `run_details.id` generation across parallel decisions
// ============================================================================
func test48_UniqueDecisionIds(step int) (string, error) {
	switch step {
	case 1:
		return `[
			{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(701)"}]},
			{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(702)"}]}
		]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Both parallel decisions assigned distinct run_details.id values."}]}]`, nil
	default:
		return "", fmt.Errorf("test_48: unexpected step %d", step)
	}
}

// ============================================================================
// Test 49: Real installed tool (`Ipinfoio`) blocked when not in `allowed_actions`
// ============================================================================
func test49_UnassignedRealToolBlocked(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "get_ip_geo_info", "tool": "Ipinfoio", "category": "singul", "fields": [{"key": "ip", "value": "8.8.8.8"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(4949)"}]}]`, nil
	case 3:
		return `[{"i": 2, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Blocked unassigned real tool Ipinfoio and recovered with 4949."}]}]`, nil
	default:
		return "", fmt.Errorf("test_49: unexpected step %d", step)
	}
}

// ============================================================================
// Test 50: Tool & action name normalization variants (`shuffle_tools`, `Execute Python`, etc.)
// ============================================================================
func test50_ToolAndActionNormalization(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "Execute Python", "tool": "shuffle_tools", "category": "singul", "fields": [{"key": "code", "value": "print(5001)"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "EXECUTE_PYTHON", "tool": "app:3e2bdf9d5069fe3f4746c29d68785a6a:shuffle_tools", "category": "singul", "fields": [{"key": "code", "value": "print(5002)"}]}]`, nil
	case 3:
		return `[{"i": 2, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Normalized both tool and action variants: 5001 and 5002."}]}]`, nil
	default:
		return "", fmt.Errorf("test_50: unexpected step %d", step)
	}
}

// ============================================================================
// Test 51: Case-insensitive field keys (`"CODE"`) and extra unmatched fields
// ============================================================================
func test51_CaseInsensitiveFields(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "CODE", "value": "print(5101)"}, {"key": "extra_unmatched_arg", "value": "harmless_extra_value"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Case-insensitive CODE field and extra parameter succeeded: 5101."}]}]`, nil
	default:
		return "", fmt.Errorf("test_51: unexpected step %d", step)
	}
}

// ============================================================================
// Test 52: Hallucinated action on allowed tool (`Shuffle Tools`) -> recovery on Step 2
// ============================================================================
func test52_HallucinatedActionRecovery(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "non_existent_magic_action", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(5201)"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(5201)"}]}]`, nil
	case 3:
		return `[{"i": 2, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Recovered after hallucinated action on allowed tool: 5201."}]}]`, nil
	default:
		return "", fmt.Errorf("test_52: unexpected step %d", step)
	}
}

// ============================================================================
// Test 53: Strict LLM prompt construction contract (1 step)
// ============================================================================
func test53_PromptConstructionContract(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Prompt construction contract verified."}]}]`, nil
	default:
		return "", fmt.Errorf("test_53: unexpected step %d", step)
	}
}

// ============================================================================
// Test 54: Multi-step prompt prefix stability & HISTORY ordering across 3 steps
// ============================================================================
func test54_PrefixStabilityAcrossSteps(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(5401)"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "fields": [{"key": "code", "value": "print(5402)"}]}]`, nil
	case 3:
		return `[{"i": 2, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Verified 3-turn prefix invariance and HISTORY ordering."}]}]`, nil
	default:
		return "", fmt.Errorf("test_54: unexpected step %d", step)
	}
}

// ============================================================================
// Test 55: `ReduceAgentResponseData` partial match warning & stored decision immutability
// ============================================================================
func test55_DataFilterPartialMatch(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "data_filter": "list", "fields_needed": ["id", "severity", "missing_ghost_field"], "fields": [{"key": "code", "value": "import json; print(json.dumps({'totalCount': 42, 'items': [{'id': 'inc_1', 'severity': 'critical', 'extra_noise': 'prune_me_in_prompt'}]}))"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Verified partial field reduction and stored decision immutability."}]}]`, nil
	default:
		return "", fmt.Errorf("test_55: unexpected step %d", step)
	}
}

// ============================================================================
// Test 56: `ReduceAgentResponseData` complete-miss fallback & `data_filter: "full"` bypass
// ============================================================================
func test56_DataFilterFallbacks(step int) (string, error) {
	switch step {
	case 1:
		return `[{"i": 0, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "data_filter": "list", "fields_needed": ["completely_nonexistent_xyz"], "fields": [{"key": "code", "value": "import json; print(json.dumps({'alpha_key': 'alpha_val_5601', 'beta_key': 'beta_val_5601'}))"}]}]`, nil
	case 2:
		return `[{"i": 1, "action": "execute_python", "tool": "Shuffle Tools", "category": "singul", "data_filter": "full", "fields_needed": ["keep_only_this"], "fields": [{"key": "code", "value": "import json; print(json.dumps({'keep_only_this': 'val_1', 'unfiltered_extra': 'preserved_in_full_mode'}))"}]}]`, nil
	case 3:
		return `[{"i": 2, "action": "finish", "tool": "core", "category": "finish", "fields": [{"key": "output", "value": "Verified complete-miss fallback and full-mode bypass."}]}]`, nil
	default:
		return "", fmt.Errorf("test_56: unexpected step %d", step)
	}
}

// RunAgentDecisionMockHandler is retained as a minimal stub so cloudSync.go compiles without changes.
func RunAgentDecisionMockHandler(execution WorkflowExecution, decision AgentDecision) ([]byte, string, string, error) {
	return nil, "", decision.Tool, fmt.Errorf("legacy AGENT_TEST_MODE file mock is deprecated; use /api/v1/agent_tests")
}
