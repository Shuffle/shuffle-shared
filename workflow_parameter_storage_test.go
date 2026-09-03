package shuffle

import (
	"strings"
	"testing"
)

func TestWorkflowParameterFileRoundTrip(t *testing.T) {
	t.Setenv("SHUFFLE_FILE_LOCATION", t.TempDir())
	largeValue := strings.Repeat("import json\n", 4000)
	workflow := Workflow{
		OrgId: "org-id",
		Actions: []Action{{
			Parameters:        []WorkflowAppActionParameter{{Value: largeValue}},
			InvalidParameters: []WorkflowAppActionParameter{{Value: largeValue}},
		}},
		Triggers: []Trigger{{
			Parameters: []WorkflowAppActionParameter{{Value: largeValue}},
		}},
	}

	if err := offloadWorkflowParameters(&workflow); err != nil {
		t.Fatal(err)
	}
	for _, value := range workflowParameterValues(&workflow) {
		if *value == largeValue {
			t.Fatal("large workflow parameter was not offloaded")
		}
	}

	if err := restoreWorkflowParameters(&workflow); err != nil {
		t.Fatal(err)
	}
	for _, value := range workflowParameterValues(&workflow) {
		if *value != largeValue {
			t.Fatal("large workflow parameter was not restored")
		}
	}
}
