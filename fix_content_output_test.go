package shuffle

// FixContentOutput regression tests: the pre-fix copy (fixContentOutputBeforeFix) vs FixContentOutput in ai.go.
//   - Run: go test -vet=off -run TestFixContentOutputCases -v .   (-vet=off: existing vet error in cloudSync.go)
//   - Cases: testdata/fixcontent_cases.json (synthetic samples s01-s20 plus edge_* cases)
//   - Results: summary printed with -v; full results in $TMPDIR/fixcontent_results.json (or $FIXCONTENT_RESULTS)
//   - Fails on a panic, a worse verdict or shorter agent answer than before, or a missed expected fix

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func fixContentOutputBeforeFix(contentOutput string) string {
	// Safely extract content from ```json or ``` blocks
	if start := strings.Index(contentOutput, "```json"); start != -1 {
		start += 7 // skip ```json
		if end := strings.Index(contentOutput[start:], "```"); end != -1 {
			contentOutput = contentOutput[start : start+end]
		} else {
			contentOutput = contentOutput[start:] // Unmatched, take the rest
		}
	} else if start := strings.Index(contentOutput, "```"); start != -1 {
		start += 3 // skip ```
		if end := strings.Index(contentOutput[start:], "```"); end != -1 {
			contentOutput = contentOutput[start : start+end]
		} else {
			contentOutput = contentOutput[start:] // Unmatched, take the rest
		}
	}

	contentOutput = strings.Trim(contentOutput, " ")
	contentOutput = strings.Trim(contentOutput, "\n")
	contentOutput = strings.Trim(contentOutput, "\t")

	// Fix issues with newlines in keys. Replace with raw newlines
	//contentOutput = strings.ReplaceAll(contentOutput, "\\n", "\n")

	// Attempts to balance it automatically
	contentOutput = FixJSONNewlines(contentOutput)
	contentOutput = balanceJSONLikeString(contentOutput)

	// Indent it with marshalling
	tmpMap := map[string]interface{}{}
	err := json.Unmarshal([]byte(contentOutput), &tmpMap)
	if err == nil {
		// Check if "method" exists and remove "body" if it's GET
		// Too many edgecases have occurred here.
		if methodFound, ok := tmpMap["method"]; ok {
			if methodString, ok := methodFound.(string); ok {
				if ok && methodString == "GET" {
					if _, ok := tmpMap["body"]; ok {
						delete(tmpMap, "body")
					}
				}
			}
		}

		marshalled, err := json.MarshalIndent(tmpMap, "", "  ")
		if err == nil {
			contentOutput = string(marshalled)
		} else {
			log.Printf("[WARNING] Failed to marshal indent tmpMap in FixContentOutput (1): %s", err)
		}
	} else {
		arrayMap := []interface{}{}
		newErr := json.Unmarshal([]byte(contentOutput), &arrayMap)
		if newErr != nil {
			log.Printf("[WARNING] Failed to unmarshal tmpMap in FixContentOutput (2) - both map & interface list: %s => %s => %s", string(contentOutput), err, newErr)
		} else {
			marshalled, err := json.MarshalIndent(arrayMap, "", "  ")
			if err == nil {
				contentOutput = string(marshalled)
			}
		}
	}

	return contentOutput
}

type fixContentCase struct {
	ID                 string   `json:"id"`
	Group              string   `json:"group"`
	Caller             string   `json:"caller"`
	Description        string   `json:"description"`
	Input              string   `json:"input"`
	InputB64           string   `json:"input_b64"`
	ExpectSuccessAfter []string `json:"expect_success_after"`
	ExpectMinAnswer    int      `json:"expect_min_answer_length"`
}

type fixContentVerdict struct {
	Verdict      string `json:"verdict"`
	Detail       string `json:"detail"`
	AnswerLength int    `json:"answer_length,omitempty"`
}

type fixContentRun struct {
	Panic    string                       `json:"panic,omitempty"`
	Cleaned  string                       `json:"cleaned_output"`
	Verdicts map[string]fixContentVerdict `json:"verdicts"`
}

var fixContentCallers = []string{"AutofixAppLabels", "HandleAiAgentExecutionStart", "RunSelfCorrectingRequest"}

var fixContentRank = map[string]int{"CRASH": 0, "NO_RESULT": 1, "SUCCESS": 2}

func parseAgentDecisionsBeforeFix(rawOutput string) ([]AgentDecision, error) {
	cleanedText := fixContentOutputBeforeFix(rawOutput)
	if decisions, err := extractDecisionArray(cleanedText); err == nil {
		return decisions, nil
	}
	if decisions, err := extractDecisionJSONL(cleanedText); err == nil {
		return decisions, nil
	}
	if decisions, err := extractDecisionArray(strings.ReplaceAll(cleanedText, `\"`, `"`)); err == nil {
		return decisions, nil
	}
	return nil, fmt.Errorf("failed to parse agent decisions from LLM output")
}

func autofixVerdict(cleaned string) fixContentVerdict {
	parsed := struct {
		Category string `json:"category"`
	}{}
	if err := json.Unmarshal([]byte(cleaned), &parsed); err != nil {
		return fixContentVerdict{Verdict: "NO_RESULT", Detail: err.Error()}
	}
	if parsed.Category == "" {
		return fixContentVerdict{Verdict: "NO_RESULT", Detail: "no category"}
	}
	return fixContentVerdict{Verdict: "SUCCESS", Detail: "category=" + parsed.Category}
}

func selfCorrectVerdict(cleaned string) fixContentVerdict {
	var outputJSON map[string]interface{}
	if err := json.Unmarshal([]byte(cleaned), &outputJSON); err != nil {
		return fixContentVerdict{Verdict: "NO_RESULT", Detail: err.Error()}
	}
	return fixContentVerdict{Verdict: "SUCCESS", Detail: fmt.Sprintf("object with %d field(s)", len(outputJSON))}
}

func agentVerdict(decisions []AgentDecision) fixContentVerdict {
	if len(decisions) == 0 {
		return fixContentVerdict{Verdict: "NO_RESULT", Detail: "0 decisions"}
	}
	answerLength := 0
	for _, field := range decisions[0].Fields {
		answerLength += len(field.Value)
	}
	return fixContentVerdict{Verdict: "SUCCESS", Detail: fmt.Sprintf("%d decision(s), first action=%q, answer length=%d", len(decisions), decisions[0].Action, answerLength), AnswerLength: answerLength}
}

func runFixContent(input string, fix func(string) string, parse func(string) ([]AgentDecision, error)) (run fixContentRun) {
	defer func() {
		if recovered := recover(); recovered != nil {
			run.Panic = fmt.Sprint(recovered)
			run.Verdicts = map[string]fixContentVerdict{}
			for _, caller := range fixContentCallers {
				run.Verdicts[caller] = fixContentVerdict{Verdict: "CRASH", Detail: run.Panic}
			}
		}
	}()

	cleaned := fix(input)
	decisions, _ := parse(input)
	run.Cleaned = cleaned
	run.Verdicts = map[string]fixContentVerdict{
		"AutofixAppLabels":            autofixVerdict(cleaned),
		"HandleAiAgentExecutionStart": agentVerdict(decisions),
		"RunSelfCorrectingRequest":    selfCorrectVerdict(cleaned),
	}
	return run
}

func TestFixContentOutputCases(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	raw, err := os.ReadFile(filepath.Join("testdata", "fixcontent_cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []fixContentCase{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}

	type caseResult struct {
		fixContentCase
		Before fixContentRun `json:"before"`
		After  fixContentRun `json:"after"`
	}
	results := []caseResult{}
	counts := map[string]map[string]map[string]int{}
	changed := []string{}

	for _, c := range cases {
		input := c.Input
		if c.InputB64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(c.InputB64)
			if err != nil {
				t.Fatalf("%s: %s", c.ID, err)
			}
			input = string(decoded)
		}

		before := runFixContent(input, fixContentOutputBeforeFix, parseAgentDecisionsBeforeFix)
		after := runFixContent(input, FixContentOutput, parseAgentDecisions)
		results = append(results, caseResult{c, before, after})

		if after.Panic != "" {
			t.Errorf("%s (%s): new code panicked: %s", c.ID, c.Description, after.Panic)
		}

		callers := fixContentCallers
		if c.Caller != "all" {
			callers = []string{c.Caller}
		}
		for _, caller := range callers {
			b, a := before.Verdicts[caller], after.Verdicts[caller]
			for label, verdict := range map[string]fixContentVerdict{"before": b, "after": a} {
				if counts[caller] == nil {
					counts[caller] = map[string]map[string]int{}
				}
				if counts[caller][label] == nil {
					counts[caller][label] = map[string]int{}
				}
				counts[caller][label][verdict.Verdict]++
			}

			if fixContentRank[a.Verdict] < fixContentRank[b.Verdict] {
				t.Errorf("%s (%s) %s: regressed from %s to %s (%s)", c.ID, c.Description, caller, b.Verdict, a.Verdict, a.Detail)
			}
			if a.Verdict == "SUCCESS" && b.Verdict == "SUCCESS" && a.AnswerLength < b.AnswerLength {
				t.Errorf("%s (%s) %s: answer got shorter (%d -> %d characters)", c.ID, c.Description, caller, b.AnswerLength, a.AnswerLength)
			}
			if b != a {
				changed = append(changed, fmt.Sprintf("%-9s %-28s %s: %s  ->  %s: %s", c.ID, caller, b.Verdict, b.Detail, a.Verdict, a.Detail))
			}
		}

		if agentAnswer := after.Verdicts["HandleAiAgentExecutionStart"].AnswerLength; agentAnswer < c.ExpectMinAnswer {
			t.Errorf("%s (%s): agent answer is %d characters, expected at least %d (answer cut short)", c.ID, c.Description, agentAnswer, c.ExpectMinAnswer)
		}

		for _, caller := range c.ExpectSuccessAfter {
			if after.Verdicts[caller].Verdict != "SUCCESS" {
				t.Errorf("%s (%s) %s: expected SUCCESS with the new code, got %s (%s)", c.ID, c.Description, caller, after.Verdicts[caller].Verdict, after.Verdicts[caller].Detail)
			}
		}
	}

	t.Logf("%d cases", len(cases))
	t.Logf("%-28s %-6s %8s %10s %6s", "caller", "code", "SUCCESS", "NO_RESULT", "CRASH")
	for _, caller := range fixContentCallers {
		for _, label := range []string{"before", "after"} {
			row := counts[caller][label]
			t.Logf("%-28s %-6s %8d %10d %6d", caller, label, row["SUCCESS"], row["NO_RESULT"], row["CRASH"])
		}
	}
	sort.Strings(changed)
	t.Logf("%d changed verdicts:", len(changed))
	for _, line := range changed {
		t.Log("  " + line)
	}

	resultsPath := os.Getenv("FIXCONTENT_RESULTS")
	if resultsPath == "" {
		resultsPath = filepath.Join(os.TempDir(), "fixcontent_results.json")
	}
	out, _ := json.MarshalIndent(results, "", "  ")
	if err := os.WriteFile(resultsPath, out, 0644); err != nil {
		t.Errorf("writing results: %s", err)
	} else {
		t.Logf("full per-case results: %s", resultsPath)
	}
}
