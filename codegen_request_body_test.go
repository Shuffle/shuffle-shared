package shuffle

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/frikky/kin-openapi/openapi3"
)

func jsonBodyFixture(t *testing.T) *openapi3.Swagger {
	t.Helper()
	loader := openapi3.NewSwaggerLoader()
	loader.IsExternalRefsAllowed = false
	spec, err := loader.LoadSwaggerFromData([]byte(`{
      "openapi":"3.0.3", "info":{"title":"JSON body regression", "version":"1.0.0"},
      "servers":[{"url":"https://example.invalid/api"}],
      "security":[{"BearerAuth":[]}],
      "components":{"securitySchemes":{"BearerAuth":{"type":"http","scheme":"bearer"}}},
      "paths":{"/screen":{"post":{"summary":"Screen subject", "description":"Requires screenings:write.",
        "parameters":[{"in":"header","name":"Idempotency-Key","required":true,"schema":{"type":"string","minLength":8}}],
        "requestBody":{"required":true,"description":"Explicit subject and coverage JSON", "content":{"application/json":{"schema":{
          "type":"object","additionalProperties":false,"required":["subject"],
          "properties":{"subject":{"type":"object","required":["name"],"properties":{"name":{"type":"string","minLength":1}}},"all_sources":{"type":"boolean","enum":[true]},"sources":{"type":"array","minItems":1,"items":{"type":"string"}}},
          "oneOf":[{"required":["all_sources"],"not":{"required":["sources"]}},{"required":["sources"],"not":{"required":["all_sources"]}}]
        }}}},"responses":{"201":{"description":"Retained result"}}}}}
    }`))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func generatedPost(t *testing.T, spec *openapi3.Swagger) (WorkflowApp, WorkflowAppAction, []string) {
	t.Helper()
	_, app, code, err := GenerateYaml(spec, "offline-regression")
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range app.Actions {
		if action.Name == "post_screen_subject" {
			return app, action, code
		}
	}
	t.Fatal("generated POST action missing")
	return WorkflowApp{}, WorkflowAppAction{}, nil
}

func bodyParameters(action WorkflowAppAction) []WorkflowAppActionParameter {
	var bodies []WorkflowAppActionParameter
	for _, parameter := range action.Parameters {
		if parameter.Name == "body" {
			bodies = append(bodies, parameter)
		}
	}
	return bodies
}

func TestPostJSONRequestBodyMetadata(t *testing.T) {
	for _, required := range []bool{true, false} {
		t.Run(map[bool]string{true: "required", false: "optional"}[required], func(t *testing.T) {
			spec := jsonBodyFixture(t)
			spec.Paths["/screen"].Post.RequestBody.Value.Required = required
			_, action, code := generatedPost(t, spec)
			bodies := bodyParameters(action)
			if len(bodies) != 1 {
				t.Fatalf("expected one JSON body parameter, got %d: %#v", len(bodies), action.Parameters)
			}
			body := bodies[0]
			if body.Required != required || !body.Multiline || body.Schema.Type != "string" || body.Description != "Explicit subject and coverage JSON" {
				t.Fatalf("body metadata does not match requestBody: %#v", body)
			}
			if body.Value != "" || body.Example != "" {
				t.Fatal("must not manufacture a default screening request")
			}
			if !strings.Contains(strings.Join(code, "\n"), `body=""`) {
				t.Fatal("generated Python body argument missing")
			}
		})
	}
}

func TestPostJSONBodyPreservesSchemaAuthAndRequiredFields(t *testing.T) {
	spec := jsonBodyFixture(t)
	operation := spec.Paths["/screen"].Post
	operation.ExtensionProps.Extensions = map[string]interface{}{"x-required-fields": json.RawMessage(`["subject"]`)}
	beforeBody, err := json.Marshal(operation.RequestBody)
	if err != nil {
		t.Fatal(err)
	}
	beforeSecurity, _ := json.Marshal(spec.Security)
	beforeSchemes, _ := json.Marshal(spec.Components.SecuritySchemes)
	app, action, _ := generatedPost(t, spec)
	afterBody, _ := json.Marshal(operation.RequestBody)
	afterSecurity, _ := json.Marshal(spec.Security)
	afterSchemes, _ := json.Marshal(spec.Components.SecuritySchemes)
	if string(beforeBody) != string(afterBody) {
		t.Fatal("generator changed the request body or its complete schema")
	}
	if string(beforeSecurity) != string(afterSecurity) || string(beforeSchemes) != string(afterSchemes) {
		t.Fatal("security contract changed")
	}
	if !reflect.DeepEqual(action.RequiredBodyFields, []string{"subject"}) {
		t.Fatalf("existing x-required-fields changed: %#v", action.RequiredBodyFields)
	}
	if !app.Authentication.Required {
		t.Fatal("bearer authentication no longer required")
	}
	foundKey := false
	for _, parameter := range action.Parameters {
		if parameter.Name == "apikey" && parameter.Configuration && parameter.Required {
			foundKey = true
		}
	}
	if !foundKey {
		t.Fatal("bearer API-key configuration missing")
	}
	if len(bodyParameters(action)) != 1 {
		t.Fatal("body parameter missing")
	}
}

func TestPostResolvedJSONRequestBodyReference(t *testing.T) {
	spec := jsonBodyFixture(t)
	requestBody := spec.Paths["/screen"].Post.RequestBody
	spec.Components.RequestBodies = map[string]*openapi3.RequestBodyRef{"Subject": requestBody}
	spec.Paths["/screen"].Post.RequestBody = &openapi3.RequestBodyRef{Ref: "#/components/requestBodies/Subject"}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	loader := openapi3.NewSwaggerLoader()
	loader.IsExternalRefsAllowed = false
	resolved, err := loader.LoadSwaggerFromData(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, action, _ := generatedPost(t, resolved)
	if len(bodyParameters(action)) != 1 {
		t.Fatal("resolved referenced JSON requestBody omitted")
	}
}

func TestPostJSONBodyKeepsExistingLegacyParameter(t *testing.T) {
	spec := jsonBodyFixture(t)
	legacy := openapi3.NewStringSchema()
	// AppCreator currently emits this legacy parameter. It is compatibility input,
	// not a recommendation to add an invalid in:body parameter to an OAS3 file.
	spec.Paths["/screen"].Post.Parameters = append(spec.Paths["/screen"].Post.Parameters, &openapi3.ParameterRef{Value: &openapi3.Parameter{
		Name: "body", In: "body", Description: "Existing editor body", Required: false,
		Schema: &openapi3.SchemaRef{Value: legacy}, Example: `{"existing":true}`,
	}})
	_, action, _ := generatedPost(t, spec)
	bodies := bodyParameters(action)
	if len(bodies) != 1 {
		t.Fatalf("expected one existing body, got %d", len(bodies))
	}
	if bodies[0].Description != "Existing editor body" || bodies[0].Value != `{"existing":true}` || bodies[0].Required {
		t.Fatalf("legacy body changed: %#v", bodies[0])
	}
}

func TestPostNonJSONBodyUnchanged(t *testing.T) {
	for _, mediaType := range []string{"none", "text/plain", "multipart/form-data"} {
		t.Run(mediaType, func(t *testing.T) {
			spec := jsonBodyFixture(t)
			operation := spec.Paths["/screen"].Post
			if mediaType == "none" {
				operation.RequestBody = nil
			} else {
				media := operation.RequestBody.Value.Content["application/json"]
				operation.RequestBody.Value.Content = openapi3.Content{mediaType: media}
			}
			_, action, _ := generatedPost(t, spec)
			if len(bodyParameters(action)) != 0 {
				t.Fatal("JSON field added to non-JSON operation")
			}
		})
	}
}

func TestPostJSONBodyDoesNotReplaceMultipartFile(t *testing.T) {
	spec := jsonBodyFixture(t)
	field := openapi3.NewStringSchema()
	field.ExtensionProps.Extensions = map[string]interface{}{"value": json.RawMessage(`"upload"`)}
	spec.Paths["/screen"].Post.RequestBody.Value.Content["multipart/form-data"] = &openapi3.MediaType{Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
		Type: "object", Properties: map[string]*openapi3.SchemaRef{"fieldname": {Value: field}},
	}}}
	_, action, code := generatedPost(t, spec)
	if len(bodyParameters(action)) != 0 {
		t.Fatal("JSON field added to selected multipart upload action")
	}
	foundFile := false
	for _, parameter := range action.Parameters {
		if parameter.Name == "file_id" {
			foundFile = true
		}
	}
	if !foundFile || !strings.Contains(strings.Join(code, "\n"), "file_id") {
		t.Fatal("existing multipart file behavior changed")
	}
}
