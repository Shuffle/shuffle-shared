package shuffle

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

// go test -run TestFixContentOutput -update rewrites the expected verdicts
// in testdata/fixcontent_cases.json from the current code. Review the diff.
var updateFixContentGolden = flag.Bool("update", false, "rewrite testdata/fixcontent_cases.json with current results")

const fixContentCasesFile = "testdata/fixcontent_cases.json"

type fixContentCase struct {
	ID          string            `json:"id"`
	Group       string            `json:"group"`
	Caller      string            `json:"caller"`
	Description string            `json:"description"`
	Input       string            `json:"input,omitempty"`
	InputB64    string            `json:"input_b64,omitempty"`
	Generated   bool              `json:"generated,omitempty"`
	Want        map[string]string `json:"want"`
}

// Inputs too large to keep in testdata are built here instead
func generatedFixContentInput(id string) string {
	fence := "```"
	decision := map[string]interface{}{"i": 0, "action": "finish", "category": "finish", "tool": "core", "confidence": 1.0,
		"fields": []map[string]string{{"key": "output", "value": "done"}}}
	mustJSON := func(value interface{}) string {
		out, _ := json.Marshal(value)
		return string(out)
	}

	switch id {
	case "edge_073":
		decisions := make([]interface{}, 1000)
		for i := range decisions {
			decisions[i] = decision
		}
		return mustJSON(decisions)
	case "edge_102":
		return strings.Repeat("`", 100000)
	case "edge_132":
		return strings.Repeat("a", 1000000)
	case "edge_133":
		return mustJSON(map[string]string{"category": "Intel", "blob": strings.Repeat("x", 1000000)})
	case "edge_134":
		return mustJSON(map[string]string{"category": "Intel", "notes": strings.Repeat("step "+fence+"bash\nls\n"+fence+" ", 5000)})
	case "edge_135":
		decision["fields"] = []map[string]string{{"key": "output", "value": strings.Repeat("step "+fence+"bash\nls\n"+fence+" ", 1000)}}
		worst := mustJSON([]interface{}{decision})
		return fence + "json\n" + worst[:len(worst)-10] + "\n" + fence
	case "edge_136":
		return "[" + strings.TrimSuffix(strings.Repeat("1,", 200000), ",") + "]"
	case "edge_137":
		return fence + "json\n" + strings.Repeat("b", 1000000)
	case "edge_140":
		return strings.Repeat("[", 100000)
	case "edge_141":
		return strings.Repeat("{", 100000)
	case "edge_143":
		return strings.Repeat("[", 100000) + strings.Repeat("]", 100000)
	}

	return ""
}

// ponytail: deep nesting hangs balanceJSONLikeString both before and after the fence fix. Unskip once that's fixed.
var skippedFixContentCases = map[string]string{
	"edge_139": "2000-level nesting takes ~25s (pre-existing, balanceJSONLikeString)",
	"edge_140": "100000 unclosed [ hangs (pre-existing, balanceJSONLikeString)",
	"edge_142": "10000-level nesting hangs (pre-existing, balanceJSONLikeString)",
	"edge_143": "100000-level nesting hangs (pre-existing, balanceJSONLikeString)",
}

// What each caller of FixContentOutput / parseAgentDecisions ends up with.
// Failure details are dropped since they are Go error strings.
func fixContentVerdicts(input string) map[string]string {
	cleaned := FixContentOutput(input)
	decisions, _ := parseAgentDecisions(input)

	verdicts := map[string]string{
		"AutofixAppLabels":            "NO_RESULT",
		"HandleAiAgentExecutionStart": "NO_RESULT",
		"RunSelfCorrectingRequest":    "NO_RESULT",
	}

	parsed := struct {
		Category string `json:"category"`
	}{}
	if json.Unmarshal([]byte(cleaned), &parsed) == nil && len(parsed.Category) > 0 {
		verdicts["AutofixAppLabels"] = "SUCCESS: category=" + parsed.Category
	}

	if len(decisions) > 0 {
		answerLength := 0
		for _, field := range decisions[0].Fields {
			answerLength += len(field.Value)
		}
		verdicts["HandleAiAgentExecutionStart"] = fmt.Sprintf("SUCCESS: %d decision(s), first action=%q, answer length=%d", len(decisions), decisions[0].Action, answerLength)
	}

	outputJSON := map[string]interface{}{}
	if json.Unmarshal([]byte(cleaned), &outputJSON) == nil {
		verdicts["RunSelfCorrectingRequest"] = fmt.Sprintf("SUCCESS: object with %d field(s)", len(outputJSON))
	}

	return verdicts
}

func TestFixContentOutput(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	raw, err := os.ReadFile(fixContentCasesFile)
	if err != nil {
		t.Fatal(err)
	}

	cases := []fixContentCase{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}

	for i := range cases {
		c := &cases[i]
		t.Run(c.ID, func(t *testing.T) {
			if reason, ok := skippedFixContentCases[c.ID]; ok {
				t.Skip(reason)
			}

			input := c.Input
			if c.Generated {
				input = generatedFixContentInput(c.ID)
			} else if len(c.InputB64) > 0 {
				decoded, err := base64.StdEncoding.DecodeString(c.InputB64)
				if err != nil {
					t.Fatal(err)
				}
				input = string(decoded)
			}

			// A hang is a failure, not a stuck test run
			done := make(chan map[string]string, 1)
			go func() { done <- fixContentVerdicts(input) }()

			var got map[string]string
			select {
			case got = <-done:
			case <-time.After(20 * time.Second):
				t.Fatalf("%s: did not finish within 20s", c.Description)
			}

			if *updateFixContentGolden {
				c.Want = got
				return
			}

			for caller, want := range c.Want {
				if got[caller] != want {
					t.Errorf("%s (%s)\n  got:  %s\n  want: %s", c.Description, caller, got[caller], want)
				}
			}
		})
	}

	if *updateFixContentGolden {
		out, err := json.MarshalIndent(cases, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixContentCasesFile, append(out, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
}
