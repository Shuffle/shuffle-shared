package shuffle

import (
	"encoding/xml"
	"time"
)

type AppContext struct {
	AppName         string `json:"app_name"`
	AppID           string `json:"app_id"`
	ActionName      string `json:"action_name"`
	Label           string `json:"label"`
	ExampleResponse string `json:"example_response,omitempty" datastore:"example_response,noindex"`
	Example         string `json:"example,omitempty" datastore:"example,noindex"`
}

type PipelineRequest struct {
	Name	   	string `json:"name"`
	Type 		string `json:"type"`
	Command		string `json:"command"`
	Environment string `json:"environment"`
	WorkflowId  string `json:"workflow_id"`
	StartNode   string `json:"start_node"`

	PipelineId 	string `json:"pipeline_id"`
	TriggerId	string `json:"trigger_id"`
}

type Pipeline struct {
	Name        string   `json:"name" datastore:"name"`
	Type        string   `json:"type" datastore:"type"`
	Command     string   `json:"command" datastore:"command"`
	Environment string   `json:"environment" datastore:"environment"`
	WorkflowId  string   `json:"workflow_id" datastore:"workflow_id"`
	StartNode   string   `json:"start_node" datastore:"start_node"`
	OrgId       string   `json:"org_id" datastore:"org_id"`
	Status      string   `json:"status" datastore:"status"`
	Errors      []string `json:"errors" datastore:"errors"`
	Url         string   `json:"url" datastore:"url"`
	Owner       string   `json:"owner" datastore:"owner"`

	PipelineId  string   `json:"pipeline_id" datastore:"pipeline_id"`
	TriggerId   string   `json:"trigger_id" datastore:"trigger_id"`
}

type PipelineWrapper struct {
	Index  string   `json:"_index"`
	Type   string   `json:"_type"`
	ID     string   `json:"_id"`
	Version int     `json:"_version"`
	Found   bool    `json:"found"`
	Source  Pipeline `json:"_source"`
}

type AllPipelinesWrapper struct {
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		Hits     []struct {
			Index  string  `json:"_index"`
			ID     string  `json:"_id"`
			Score  float64 `json:"_score"`
			Source Pipeline `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type QueryInput struct {
	// Required
	Query string `json:"query" datastore:"query,noindex"`

	// Output helpers
	Id           string `json:"id,omitempty"`
	OutputFormat string `json:"output_format,omitempty"`

	// App helpers
	WorkflowId string                       `json:"workflow_id"`
	AppName    string                       `json:"app_name,omitempty"`
	AppId      string                       `json:"app_id,omitempty"`
	Category   string                       `json:"category,omitempty"`
	ActionName string                       `json:"action_name,omitempty"`
	Parameters []WorkflowAppActionParameter `json:"parameters,omitempty"`

	// Optional Input Parameters for more context
	AppContext  []AppContext `json:"app_context,omitempty"`
	UserId      string       `json:"user_id,omitempty"`
	Username    string       `json:"username,omitempty"`
	OrgId       string       `json:"org_id,omitempty"`
	TimeStarted int64        `json:"time_started,omitempty"`
	TimeEnded   int64        `json:"time_ended,omitempty"`
	Formatting  string       `json:"formatting,omitempty"`

	// For OpenAI assistant with Shuffle labels
	ThreadId string `json:"thread_id,omitempty"`
	RunId    string `json:"run_id,omitempty"`
}

type AtomicOutput struct {
	Success bool   `json:"success"`
	Reason  string `json:"reason"`

	ThreadId   string `json:"thread_id"`              // Thread the assistant ran
	RunId      string `json:"run_id"`                 // Run ID for the thread
	ToolCallID string `json:"tool_call_id,omitempty"` // Result inside the run
}

type ExecutionRequestWrapper struct {
	Data []ExecutionRequest `json:"data"`
}

type ExecutionRequest struct {
	ExecutionId       string   `json:"execution_id"`
	ExecutionArgument string   `json:"execution_argument"`
	ExecutionSource   string   `json:"execution_source"`
	WorkflowId        string   `json:"workflow_id"`
	Environments      []string `json:"environments"`
	Authorization     string   `json:"authorization"`
	Status            string   `json:"status"`
	Start             string   `json:"start"`
	Type              string   `json:"type"`
	Priority          int64    `json:"priority" datastore:"priority" yaml:"priority"` // Mapped back to workflowexecutions' priority

	Authgroup string `json:"authgroup" datastore:"authgroup"`
}

type RetStruct struct {
	Success         bool         `json:"success"`
	SyncFeatures    SyncFeatures `json:"sync_features"`
	SessionKey      string       `json:"session_key"`
	IntervalSeconds int64        `json:"interval_seconds"`
}

type AppMini struct {
	Id                     string         `json:"id"`
	Name                   string         `json:"name"`
	Version                string         `json:"version"`
	LargeImage             string         `json:"large_image"`
	Authentication         Authentication `json:"authentication"`
	AuthenticationRequired bool           `json:"authentication_required"`

	ActionName string `json:"action_name,omitempty"`
	Category   string `json:"category,omitempty"`
}

type WorkflowApp struct {
	Name        string `json:"name" yaml:"name" required:true datastore:"name"`
	AppVersion  string `json:"app_version" yaml:"app_version" required:true datastore:"app_version"`
	ID          string `json:"id" yaml:"id,omitempty" required:false datastore:"id"`
	Link        string `json:"link" yaml:"link" required:false datastore:"link,noindex"`
	IsValid     bool   `json:"is_valid" yaml:"is_valid" required:true datastore:"is_valid"`
	Generated   bool   `json:"generated" yaml:"generated" required:false datastore:"generated"`
	Downloaded  bool   `json:"downloaded" yaml:"downloaded" required:false datastore:"downloaded"`
	Sharing     bool   `json:"sharing" yaml:"sharing" required:false datastore:"sharing"`
	Verified    bool   `json:"verified" yaml:"verified" required:false datastore:"verified"`
	Invalid     bool   `json:"invalid" yaml:"invalid" required:false datastore:"invalid"`
	Activated   bool   `json:"activated" yaml:"activated" required:false datastore:"activated"`
	Tested      bool   `json:"tested" yaml:"tested" required:false datastore:"tested"`
	Hash        string `json:"hash" datastore:"hash" yaml:"hash"` // api.yaml+dockerfile+src/app.py for apps
	PrivateID   string `json:"private_id" yaml:"private_id" required:false datastore:"private_id"`
	Environment string `json:"environment" datastore:"environment" required:true yaml:"environment"`
	SmallImage  string `json:"small_image" datastore:"small_image,noindex" required:false yaml:"small_image"`
	LargeImage  string `json:"large_image" datastore:"large_image,noindex" yaml:"large_image" required:false`
	ContactInfo struct {
		Name string `json:"name" datastore:"name" yaml:"name"`
		Url  string `json:"url" datastore:"url" yaml:"url"`
	} `json:"contact_info" datastore:"contact_info" yaml:"contact_info" required:false`
	FolderMount struct {
		FolderMount       bool   `json:"folder_mount" datastore:"folder_mount"`
		SourceFolder      string `json:"source_folder" datastore:"source_folder"`
		DestinationFolder string `json:"destination_folder" datastore:"destination_folder"`
	} `json:"folder_mount" datastore:"folder_mount"`
	Actions                  []WorkflowAppAction `json:"actions" yaml:"actions" required:true datastore:"actions,noindex"`
	Authentication           Authentication      `json:"authentication" yaml:"authentication" required:false datastore:"authentication"`
	Tags                     []string            `json:"tags" yaml:"tags" required:false datastore:"activated"`
	Categories               []string            `json:"categories" yaml:"categories" required:false datastore:"categories"`
	Created                  int64               `json:"created" datastore:"created"`
	Edited                   int64               `json:"edited" datastore:"edited"`
	LastRuntime              int64               `json:"last_runtime" datastore:"last_runtime"`
	Versions                 []AppVersion        `json:"versions" datastore:"versions"`
	LoopVersions             []string            `json:"loop_versions" datastore:"loop_versions"`
	Owner                    string              `json:"owner" datastore:"owner" yaml:"owner"`
	SharingConfig            string              `json:"sharing_config" yaml:"sharing_config" datastore:"sharing_config"`
	Public                   bool                `json:"public" datastore:"public"`
	PublishedId              string              `json:"published_id" datastore:"published_id"`
	ChildIds                 []string            `json:"child_ids" datastore:"child_ids"`
	ReferenceOrg             string              `json:"reference_org" datastore:"reference_org"`
	ReferenceUrl             string              `json:"reference_url" datastore:"reference_url"`
	ActionFilePath           string              `json:"action_file_path" datastore:"action_file_path"`
	Template                 bool                `json:"template" datastore:"template,noindex"`
	Documentation            string              `json:"documentation" datastore:"documentation,noindex"`
	Description              string              `json:"description" datastore:"description,noindex"`
	DocumentationDownloadUrl string              `json:"documentation_download_url" datastore:"documentation_download_url"`
	PrimaryUsecases          []string            `json:"primary_usecases" yaml:"primary_usecases"  datastore:"primary_usecases"`

	SkippedBuild bool `json:"skipped_build" yaml:"skipped_build" required:false datastore:"skipped_build"`
	//SelectedTemplate WorkflowApp         `json:"selected_template" datastore:"selected_template,noindex"`

	ReferenceInfo struct {
		IsPartner        bool     `json:"is_partner" datastore:"is_partner"`
		PartnerContacts  string   `json:"partner_contacts" datastore:"partner_contacts"`
		DocumentationUrl string   `json:"documentation_url" datastore:"documentation_url"`
		GithubUrl        string   `json:"github_url" datastore:"github_url"`
		Triggers         []string `json:"triggers" datastore:"triggers"`
	} `json:"reference_info" datastore:"reference_info"`
	Blogpost   string `json:"blogpost" yaml:"blogpost" datastore:"blogpost"`
	Video      string `json:"video" yaml:"video" datastore:"video"`
	CompanyURL string `json:"company_url" datastore:"company_url" required:false yaml:"company_url"`

	Contributors []string `json:"contributors" datastore:"contributors"`
	RevisionId   string   `json:"revision_id" datastore:"revision_id"`
}

type AppVersion struct {
	Version string `json:"version" datastore:"version"`
	ID      string `json:"id" datastore:"id"`
}

type WorkflowAppActionParameter struct {
	Description    string           `json:"description" datastore:"description,noindex" yaml:"description"`
	ID             string           `json:"id" datastore:"id" yaml:"id,omitempty"`
	Name           string           `json:"name" datastore:"name" yaml:"name"`
	Example        string           `json:"example" datastore:"example,noindex" yaml:"example"`
	Value          string           `json:"value" datastore:"value,noindex" yaml:"value,omitempty"`
	Multiline      bool             `json:"multiline" datastore:"multiline" yaml:"multiline"`
	Multiselect    bool             `json:"multiselect" datastore:"multiselect" yaml:"multiselect"`
	Options        []string         `json:"options" datastore:"options" yaml:"options"`
	ActionField    string           `json:"action_field" datastore:"action_field" yaml:"actionfield,omitempty"`
	Variant        string           `json:"variant" datastore:"variant" yaml:"variant,omitempty"`
	Required       bool             `json:"required" datastore:"required" yaml:"required"`
	Configuration  bool             `json:"configuration" datastore:"configuration" yaml:"configuration"`
	Tags           []string         `json:"tags" datastore:"tags" yaml:"tags"`
	Schema         SchemaDefinition `json:"schema" datastore:"schema" yaml:"schema"`
	SkipMulticheck bool             `json:"skip_multicheck" datastore:"skip_multicheck" yaml:"skip_multicheck"`
	ValueReplace   []Valuereplace   `json:"value_replace" datastore:"value_replace,noindex" yaml:"value_replace,omitempty"`
	UniqueToggled  bool             `json:"unique_toggled" datastore:"unique_toggled" yaml:"unique_toggled"`
}

type Valuereplace struct {
	Key   string `json:"key" datastore:"key" yaml:"key"`
	Value string `json:"value" datastore:"value,noindex" yaml:"value"`
}

type WorkflowAppAction struct {
	Description       string                       `json:"description" datastore:"description,noindex"`
	ID                string                       `json:"id" datastore:"id" yaml:"id,omitempty"`
	Name              string                       `json:"name" datastore:"name"`
	AppID             string                       `json:"app_id" datastore:"app_id"`
	AppName           string                       `json:"app_name,omitempty" datastore:"app_name"`
	AppVersion        string                       `json:"app_version,omitempty" datastore:"app_version"`
	Label             string                       `json:"label" datastore:"label"`
	NodeType          string                       `json:"node_type" datastore:"node_type"`
	Environment       string                       `json:"environment" datastore:"environment"`
	Sharing           bool                         `json:"sharing" datastore:"sharing"`
	PrivateID         string                       `json:"private_id" datastore:"private_id"`
	PublicID          string                       `json:"public_id" datastore:"public_id"`
	Tags              []string                     `json:"tags" datastore:"tags" yaml:"tags"`
	LargeImage        string                       `json:"large_image" datastore:"large_image"`
	Authentication    []AuthenticationStore        `json:"authentication" datastore:"authentication,noindex" yaml:"authentication,omitempty"`
	Tested            bool                         `json:"tested" datastore:"tested" yaml:"tested"`
	Parameters        []WorkflowAppActionParameter `json:"parameters" datastore: "parameters"`
	InvalidParameters []WorkflowAppActionParameter `json:"previous_parameters,omitempty" datastore: "previous_parameters,noindex"`
	ExecutionVariable Variable                     `json:"execution_variable" datastore:"execution_variables"`
	Returns           struct {
		Description string           `json:"description" datastore:"returns" yaml:"description,omitempty"`
		Example     string           `json:"example" datastore:"example,noindex" yaml:"example"`
		ID          string           `json:"id" datastore:"id" yaml:"id,omitempty"`
		Schema      SchemaDefinition `json:"schema" datastore:"schema" yaml:"schema"`
	} `json:"returns" datastore:"returns"`
	AuthenticationId   string   `json:"authentication_id" datastore:"authentication_id"`
	Example            string   `json:"example,noindex" datastore:"example" yaml:"example"`
	AuthNotRequired    bool     `json:"auth_not_required" datastore:"auth_not_required" yaml:"auth_not_required"`
	SourceWorkflow     string   `json:"source_workflow" yaml:"source_workflow" datastore:"source_workflow"`
	RunMagicOutput     bool     `json:"run_magic_output" datastore:"run_magic_output" yaml:"run_magic_output"`
	RunMagicInput      bool     `json:"run_magic_input" datastore:"run_magic_input" yaml:"run_magic_input"`
	ExecutionDelay     int64    `json:"execution_delay" datastore:"execution_delay"`
	RequiredBodyFields []string `json:"required_body_fields" datastore:"required_body_fields"`
	CategoryLabel      []string `json:"category_label" datastore:"category_label"`
	ExampleResponse    string   `json:"example_response" datastore:"example_response"`
}

type Authentication struct {
	Type         string                 `json:"type" datastore:"type" yaml:"type"`
	Required     bool                   `json:"required" datastore:"required" yaml:"required" `
	Parameters   []AuthenticationParams `json:"parameters" datastore:"parameters" yaml:"parameters"`
	RedirectUri  string                 `json:"redirect_uri" datastore:"redirect_uri" yaml:"redirect_uri"`
	TokenUri     string                 `json:"token_uri" datastore:"token_uri" yaml:"token_uri"`
	RefreshUri   string                 `json:"refresh_uri" datastore:"refresh_uri" yaml:"refresh_uri"`
	Scope        []string               `json:"scope" datastore:"scope" yaml:"scope"`
	ClientId     string                 `json:"client_id" datastore:"client_id"`
	ClientSecret string                 `json:"client_secret" datastore:"client_secret"`
	GrantType    string                 `json:"grant_type" datastore:"grant_type"`
}

type AuthenticationStore struct {
	Key   string `json:"key" datastore:"key"`
	Value string `json:"value" datastore:"value,noindex"`
}

type AuthenticationParams struct {
	Description string           `json:"description" datastore:"description,noindex" yaml:"description"`
	ID          string           `json:"id" datastore:"id" yaml:"id"`
	Name        string           `json:"name" datastore:"name" yaml:"name"`
	Example     string           `json:"example" datastore:"example,noindex" yaml:"example"`
	Value       string           `json:"value,omitempty" datastore:"value,noindex" yaml:"value"`
	Multiline   bool             `json:"multiline" datastore:"multiline" yaml:"multiline"`
	Required    bool             `json:"required" datastore:"required" yaml:"required"`
	In          string           `json:"in" datastore:"in" yaml:"in"`
	Schema      SchemaDefinition `json:"schema" datastore:"schema" yaml:"schema"`
	Scheme      string           `json:"scheme" datastore:"scheme" yaml:"scheme"` // Deprecated
}

type AppExecutionExample struct {
	AppName         string   `json:"app_name" datastore:"app_name"`
	AppVersion      string   `json:"app_version" datastore:"app_version"`
	AppAction       string   `json:"app_action" datastore:"app_action"`
	AppId           string   `json:"app_id" datastore:"app_id"`
	ExampleId       string   `json:"example_id" datastore:"example_id"`
	SuccessExamples []string `json:"success_examples" datastore:"success_examples,noindex"`
	FailureExamples []string `json:"failure_examples" datastore:"failure_examples,noindex"`
}

type SchemaDefinition struct {
	Type string `json:"type" datastore:"type"`
	Name string `json:"name,omitempty" datastore:"name"`
}

type Userapi struct {
	Username string `datastore:"Username"`
	ApiKey   string `datastore:"apikey"`
}

type AppUsage struct {
	AppName string `json:"app_name" datastore:"app_name"`
	AppId   string `json:"app_id" datastore:"app_id"`
	Usage   int64  `json:"usage" datastore:"usage"`
}

// Should be for a particular day
// Reset is handled during caching. If the date is not today, then the reset is handled
type DailyStatistics struct {
	Date time.Time `json:"date" datastore:"date"`

	AppExecutions              int64 `json:"app_executions" datastore:"app_executions"`
	AppExecutionsFailed        int64 `json:"app_executions_failed" datastore:"app_executions_failed"`
	SubflowExecutions          int64 `json:"subflow_executions" datastore:"subflow_executions"`
	WorkflowExecutions         int64 `json:"workflow_executions" datastore:"workflow_executions"`
	WorkflowExecutionsFinished int64 `json:"workflow_executions_finished" datastore:"workflow_executions_finished"`
	WorkflowExecutionsFailed   int64 `json:"workflow_executions_failed" datastore:"workflow_executions_failed"`
	OrgSyncActions             int64 `json:"org_sync_actions" datastore:"org_sync_actions"`
	CloudExecutions            int64 `json:"cloud_executions" datastore:"cloud_executions"`
	OnpremExecutions           int64 `json:"onprem_executions" datastore:"onprem_executions"`
	AIUsage                    int64 `json:"ai_executions" datastore:"ai_executions"`

	ApiUsage int64      `json:"api_usage" datastore:"api_usage"`
	AppUsage []AppUsage `json:"app_usage" datastore:"app_usage"`

	Additions []AdditionalUseConfig `json:"additions,omitempty" datastore:"additions"`
}

// Used to be related to users, now related to orgs.
// Not directly, but being updated by org actions
type ExecutionInfo struct {
	// These have been configured for cache updates in db-connector.go with 5 hour (300 minutes) timeouts before dumping
	OrgId       string `json:"org_id" datastore:"org_id"`
	OrgName     string `json:"org_name" datastore:"org_name"`
	LastCleared int64  `json:"last_cleared" datastore:"last_cleared"`

	DailyStatistics []DailyStatistics `json:"daily_statistics" datastore:"daily_statistics"`
	OnpremStats     []DailyStatistics `json:"onprem_stats,omitempty" datastore:"onprem_stats"`

	TotalAppExecutions              int64 `json:"total_app_executions" datastore:"total_app_executions"`
	TotalAppExecutionsFailed        int64 `json:"total_app_executions_failed" datastore:"total_app_executions_failed"`
	TotalSubflowExecutions          int64 `json:"total_subflow_executions" datastore:"total_subflow_executions"`
	TotalWorkflowExecutions         int64 `json:"total_workflow_executions" datastore:"total_workflow_executions"`
	TotalWorkflowExecutionsFinished int64 `json:"total_workflow_executions_finished" datastore:"total_workflow_executions_finished"`
	TotalWorkflowExecutionsFailed   int64 `json:"total_workflow_executions_failed" datastore:"total_workflow_executions_failed"`
	TotalOrgSyncActions             int64 `json:"total_org_sync_actions" datastore:"total_org_sync_actions"`
	TotalCloudExecutions            int64 `json:"total_cloud_executions" datastore:"total_cloud_executions"`
	TotalOnpremExecutions           int64 `json:"total_onprem_executions" datastore:"total_onprem_executions"`
	TotalAIUsage                    int64 `json:"total_ai_executions" datastore:"total_ai_executions"`

	MonthlyApiUsage                   int64 `json:"monthly_api_usage,omitempty" datastore:"monthly_api_usage"`
	MonthlyAppExecutions              int64 `json:"monthly_app_executions,omitempty" datastore:"monthly_app_executions"`
	MonthlyAppExecutionsFailed        int64 `json:"monthly_app_executions_failed,omitempty" datastore:"monthly_app_executions_failed"`
	MonthlySubflowExecutions          int64 `json:"monthly_subflow_executions,omitempty" datastore:"monthly_subflow_executions"`
	MonthlyWorkflowExecutions         int64 `json:"monthly_workflow_executions,omitempty" datastore:"monthly_workflow_executions"`
	MonthlyWorkflowExecutionsFinished int64 `json:"monthly_workflow_executions_finished,omitempty" datastore:"monthly_workflow_executions_finished"`
	MonthlyWorkflowExecutionsFailed   int64 `json:"monthly_workflow_executions_failed,omitempty" datastore:"monthly_workflow_executions_failed"`
	MonthlyOrgSyncActions             int64 `json:"monthly_org_sync_actions,omitempty" datastore:"monthly_org_sync_actions"`
	MonthlyCloudExecutions            int64 `json:"monthly_cloud_executions,omitempty" datastore:"monthly_cloud_executions"`
	MonthlyOnpremExecutions           int64 `json:"monthly_onprem_executions,omitempty" datastore:"monthly_onprem_executions"`
	MonthlyAIUsage                    int64 `json:"monthly_ai_executions,omitempty" datastore:"monthly_ai_executions"`

	WeeklyAppExecutions              int64 `json:"weekly_app_executions,omitempty" datastore:"weekly_app_executions"`
	WeeklyAppExecutionsFailed        int64 `json:"weekly_app_executions_failed,omitempty" datastore:"weekly_app_executions_failed"`
	WeeklySubflowExecutions          int64 `json:"weekly_subflow_executions,omitempty" datastore:"weekly_subflow_executions"`
	WeeklyWorkflowExecutions         int64 `json:"weekly_workflow_executions,omitempty" datastore:"weekly_workflow_executions"`
	WeeklyWorkflowExecutionsFinished int64 `json:"weekly_workflow_executions_finished,omitempty" datastore:"weekly_workflow_executions_finished"`
	WeeklyWorkflowExecutionsFailed   int64 `json:"weekly_workflow_executions_failed,omitempty" datastore:"weekly_workflow_executions_failed"`
	WeeklyOrgSyncActions             int64 `json:"weekly_org_sync_actions,omitempty" datastore:"weekly_org_sync_actions"`
	WeeklyCloudExecutions            int64 `json:"weekly_cloud_executions,omitempty" datastore:"weekly_cloud_executions"`
	WeeklyOnpremExecutions           int64 `json:"weekly_onprem_executions,omitempty" datastore:"weekly_onprem_executions"`
	WeeklyAIUsage                    int64 `json:"weekly_ai_executions,omitempty" datastore:"weekly_ai_executions"`

	DailyAppExecutions              int64 `json:"daily_app_executions" datastore:"daily_app_executions"`
	DailyAppExecutionsFailed        int64 `json:"daily_app_executions_failed" datastore:"daily_app_executions_failed"`
	DailySubflowExecutions          int64 `json:"daily_subflow_executions" datastore:"daily_subflow_executions"`
	DailyWorkflowExecutions         int64 `json:"daily_workflow_executions" datastore:"daily_workflow_executions"`
	DailyWorkflowExecutionsFinished int64 `json:"daily_workflow_executions_finished" datastore:"daily_workflow_executions_finished"`
	DailyWorkflowExecutionsFailed   int64 `json:"daily_workflow_executions_failed" datastore:"daily_workflow_executions_failed"`
	DailyOrgSyncActions             int64 `json:"daily_org_sync_actions" datastore:"daily_org_sync_actions"`
	DailyCloudExecutions            int64 `json:"daily_cloud_executions" datastore:"daily_cloud_executions"`
	DailyOnpremExecutions           int64 `json:"daily_onprem_executions" datastore:"daily_onprem_executions"`
	DailyAIUsage                    int64 `json:"daily_ai_executions" datastore:"daily_ai_executions"`

	HourlyAppExecutions              int64 `json:"hourly_app_executions,omitempty" datastore:"hourly_app_executions"`
	HourlyAppExecutionsFailed        int64 `json:"hourly_app_executions_failed,omitempty" datastore:"hourly_app_executions_failed"`
	HourlySubflowExecutions          int64 `json:"hourly_subflow_executions,omitempty" datastore:"hourly_subflow_executions"`
	HourlyWorkflowExecutions         int64 `json:"hourly_workflow_executions,omitempty" datastore:"hourly_workflow_executions"`
	HourlyWorkflowExecutionsFinished int64 `json:"hourly_workflow_executions_finished,omitempty" datastore:"hourly_workflow_executions_finished"`
	HourlyWorkflowExecutionsFailed   int64 `json:"hourly_workflow_executions_failed,omitempty" datastore:"hourly_workflow_executions_failed"`
	HourlyOrgSyncActions             int64 `json:"hourly_org_sync_actions,omitempty" datastore:"hourly_org_sync_actions"`
	HourlyCloudExecutions            int64 `json:"hourly_cloud_executions,omitempty" datastore:"hourly_cloud_executions"`
	HourlyOnpremExecutions           int64 `json:"hourly_onprem_executions,omitempty" datastore:"hourly_onprem_executions"`
	HourlyAIUsage                    int64 `json:"hourly_ai_executions,omitempty" datastore:"hourly_ai_executions"`

	// These are just here in case we get use of them
	TotalApiUsage int64 `json:"total_api_usage" datastore:"total_api_usage"`
	DailyApiUsage int64 `json:"daily_api_usage" datastore:"daily_api_usage"`

	Additions []AdditionalUseConfig `json:"additions,omitempty" datastore:"additions"`
}

type AdditionalUseConfig struct {
	Key   string `json:"key" datastore:"key"`
	Value int64 `json:"value" datastore:"value"`

	DailyValue int64 `json:"daily_value,omitempty" datastore:"daily_value"`
}

type ParsedOpenApi struct {
	Body    string `datastore:"body,noindex" json:"body"`
	ID      string `datastore:"id" json:"id,omitempty"`
	Success bool   `datastore:"success,omitempty" json:"success,omitempty"`
}

// Limits set for a user so that they can't do a shitload
type UserLimits struct {
	DailyApiUsage           int64 `json:"daily_api_usage" datastore:"daily_api_usage"`
	DailyWorkflowExecutions int64 `json:"daily_workflow_executions" datastore:"daily_workflow_executions"`
	DailyCloudExecutions    int64 `json:"daily_cloud_executions" datastore:"daily_cloud_executions"`
	DailyTriggers           int64 `json:"daily_triggers" datastore:"daily_triggers"`
	DailyMailUsage          int64 `json:"daily_mail_usage" datastore:"daily_mail_usage"`
	MaxTriggers             int64 `json:"max_triggers" datastore:"max_triggers"`
	MaxWorkflows            int64 `json:"max_workflows" datastore:"max_workflows"`
}

// FIXME: DONT FIX ME! If you add JSON object handling, it will break frontend.
type Environment struct {
	Name       string `datastore:"name"`
	Type       string `datastore:"type"`
	Registered bool   `datastore:"registered"`
	Default    bool   `datastore:"default" json:"default"`
	Archived   bool   `datastore:"archived" json:"archived"`
	Id         string `datastore:"id" json:"id"`
	OrgId      string `datastore:"org_id" json:"org_id"`
	Created    int64  `json:"created" datastore:"created"`
	Edited     int64  `json:"edited" datastore:"edited"`
	Checkin    int64  `json:"checkin" datastore:"checkin"`
	RunningIp  string `json:"running_ip" datastore:"running_ip"`
	Auth       string `json:"auth" datastore:"auth"`
	Queue      int    `json:"queue" datastore:"queue"`

	Licensed bool   `json:"licensed" datastore:"licensed"`
	RunType  string `json:"run_type" datastore:"run_type"`
}

// Saves some data, not sure what to have here lol
type UserAuth struct {
	Description string          `json:"description" datastore:"description" yaml:"description"`
	Name        string          `json:"name" datastore:"name" yaml:"name"`
	Workflows   []string        `json:"workflows" datastore:"workflows"`
	Username    string          `json:"username" datastore:"username"`
	Fields      []UserAuthField `json:"fields" datastore:"fields"`
}

type UserAuthField struct {
	Key   string `json:"key" datastore:"key"`
	Value string `json:"value" datastore:"value,noindex"`
}

// Used to contain users in miniOrg
type UserMini struct {
	Username string `datastore:"Username" json:"username"`
	Id       string `datastore:"id" json:"id"`
	Role     string `datastore:"role" json:"role"`
}

type MFAInfo struct {
	Active       bool   `datastore:"active" json:"active"`
	ActiveCode   string `datastore:"active_code" json:"active_code"`
	PreviousCode string `datastore:"previous_code" json:"previous_code"`
}

type PublicProfile struct {
	Public              bool                `datastore:"public" json:"public"`
	Self                bool                `datastore:"self" json:"self"`
	GithubUsername      string              `datastore:"github_username" json:"github_username"`
	GithubUserid        string              `datastore:"github_userid" json:"github_userid"`
	GithubAvatar        string              `datastore:"github_avatar,noindex" json:"github_avatar"`
	GithubLocation      string              `datastore:"github_location" json:"github_location"`
	GithubUrl           string              `datastore:"github_url" json:"github_url"`
	GithubBio           string              `datastore:"github_bio" json:"github_bio"`
	GithubTwitter       string              `datastore:"github_twitter" json:"github_twitter"`
	WorkStatus          string              `datastore:"work_status" json:"work_status"`
	Banner              string              `datastore:"banner" json:"banner"`
	GithubContributions GithubContributions `datastore:"github_contributions" json:"github_contributions"`
	ShuffleEarnings     string              `datastore:"shuffle_earnings" json:"shuffle_earnings"`
	ShuffleRanking      string              `datastore:"shuffle_ranking" json:"shuffle_ranking"`

	Skills          []string        `json:"skills"`
	Synonyms        []string        `json:"synonyms"`
	Workflows       int64           `json:"workflows"`
	Apps            int64           `json:"apps"`
	SpecializedApps []MinimizedApps `json:"specialized_apps"`
	Verified        bool            `json:"verified"`
	Social          []string        `json:"social"`
}

type ContributionCount struct {
	Count int64 `datastore:"contribution_count" json:"contribution_count"`
}

type GithubContributions struct {
	Core      ContributionCount `datastore:"core" json:"core"`
	Workflows ContributionCount `datastore:"workflows" json:"workflows"`
	Apps      ContributionCount `datastore:"apps" json:"apps"`
	Docs      ContributionCount `datastore:"docs" json:"docs"`
}

type LoginInfo struct {
	IP        string `json:"ip" datastore:"ip"`
	Timestamp int64  `json:"timestamp" datastore:"timestamp"`
}

type PersonalInfo struct {
	Firstname string   `datastore:"firstname" json:"firstname"`
	Lastname  string   `datastore:"lastname" json:"lastname"`
	Role      string   `datastore:"role" json:"role"`
	Tutorials []string `datastore:"tutorials" json:"tutorials"`
}

type User struct {
	Username          string        `datastore:"Username" json:"username"`
	Password          string        `datastore:"password,noindex" password:"password,omitempty"`
	Session           string        `datastore:"session" json:"session,omitempty"`
	Verified          bool          `datastore:"verified,noindex" json:"verified"`
	SupportAccess     bool          `datastore:"support_access" json:"support_access"`
	PrivateApps       []WorkflowApp `datastore:"privateapps" json:"privateapps":`
	Role              string        `datastore:"role" json:"role"`
	Roles             []string      `datastore:"roles" json:"roles"`
	VerificationToken string        `datastore:"verification_token" json:"verification_token"`
	ApiKey            string        `datastore:"apikey" json:"apikey"`
	ResetReference    string        `datastore:"reset_reference" json:"reset_reference"`
	Executions        ExecutionInfo `datastore:"executions" json:"executions"`
	Limits            UserLimits    `datastore:"limits" json:"limits,omitempty"`
	MFA               MFAInfo       `datastore:"mfa_info,noindex" json:"mfa_info"`
	Authentication    []UserAuth    `datastore:"authentication,noindex" json:"authentication"`
	ResetTimeout      int64         `datastore:"reset_timeout,noindex" json:"reset_timeout"`
	Id                string        `datastore:"id" json:"id"`
	Orgs              []string      `datastore:"orgs" json:"orgs"`
	CreationTime      int64         `datastore:"creation_time" json:"creation_time"`
	ActiveOrg         OrgMini       `json:"active_org" datastore:"active_org"`
	Active            bool          `datastore:"active" json:"active"`
	FirstSetup        bool          `datastore:"first_setup" json:"first_setup"`
	LoginType         string        `datastore:"login_type" json:"login_type"`
	GeneratedUsername string        `datastore:"generated_username" json:"generated_username"`
	SessionLogin      bool          `datastore:"session_login" json:"session_login"` // Whether it's a login with session or API (used to verify access)
	ValidatedSessionOrgs []string `datastore:"validated_session_orgs" json:"validated_session_orgs"` // Orgs that have been used in the current session for the user

	// Starting web3 integration
	EthInfo       EthInfo       `datastore:"eth_info" json:"eth_info"`
	PublicProfile PublicProfile `datastore:"public_profile" json:"public_profile"`

	// Tracking logins and such
	LoginInfo    []LoginInfo  `datastore:"login_info" json:"login_info"`
	PersonalInfo PersonalInfo `datastore:"personal_info" json:"personal_info"`
	Regions      []string     `datastore:"regions" json:"regions"`
}

type EthInfo struct {
	Account string `datastore:"account" json:"account"`
	Balance string `datastore:"balance" json:"balance"`
}

type Session struct {
	Username string `datastore:"Username,noindex"`
	Id       string `datastore:"Id,noindex"`
	UserId   string `datastore:"user_id,noindex"`
	Session  string `datastore:"session,noindex"`
}

type Contact struct {
	Firstname     string `json:"firstname"`
	Lastname      string `json:"lastname"`
	Title         string `json:"title"`
	Companyname   string `json:"companyname"`
	Phone         string `json:"phone"`
	Email         string `json:"email"`
	ValidateEmail string `json:"validate_email"`
	Message       string `json:"message"`
	DealType      string `json:"dealtype"`
	DealCountry   string `json:"dealcountry"`
}

type Translator struct {
	Src struct {
		Name        string `json:"name" datastore:"name"`
		Value       string `json:"value" datastore:"value,noindex"`
		Description string `json:"description" datastore:"description"`
		Required    string `json:"required" datastore:"required"`
		Type        string `json:"type" datastore:"type"`
		Schema      struct {
			Type string `json:"type" datastore:"type"`
		} `json:"schema" datastore:"schema"`
	} `json:"src" datastore:"src"`
	Dst struct {
		Name        string `json:"name" datastore:"name"`
		Value       string `json:"value" datastore:"value,noindex"`
		Type        string `json:"type" datastore:"type"`
		Description string `json:"description" datastore:"description"`
		Required    string `json:"required" datastore:"required"`
		Schema      struct {
			Type string `json:"type" datastore:"type"`
		} `json:"schema" datastore:"schema"`
	} `json:"dst" datastore:"dst"`
}

type Appconfig struct {
	Key   string `json:"key" datastore:"key"`
	Value string `json:"value" datastore:"value,noindex"`
}

type ScheduleApp struct {
	Foldername  string      `json:"foldername" datastore:"foldername,noindex"`
	Name        string      `json:"name" datastore:"name,noindex"`
	Id          string      `json:"id" datastore:"id,noindex"`
	Description string      `json:"description" datastore:"description,noindex"`
	Action      string      `json:"action" datastore:"action,noindex"`
	Config      []Appconfig `json:"config,omitempty" datastore:"config,noindex"`
}

type AppInfo struct {
	SourceApp      ScheduleApp `json:"sourceapp,omitempty" datastore:"sourceapp,noindex"`
	DestinationApp ScheduleApp `json:"destinationapp,omitempty" datastore:"destinationapp,noindex"`
}

type ScheduleOld struct {
	Name                 string       `json:"name" datastore:"name"`
	Id                   string       `json:"id" datastore:"id"`
	StartNode            string       `json:"start_node" datastore:"start_node"`
	Seconds              int          `json:"seconds" datastore:"seconds"`
	WorkflowId           string       `json:"workflow_id" datastore:"workflow_id", `
	Argument             string       `json:"argument" datastore:"argument"`
	WrappedArgument      string       `json:"wrapped_argument" datastore:"wrapped_argument"`
	AppInfo              AppInfo      `json:"appinfo" datastore:"appinfo,noindex"`
	Finished             bool         `json:"finished" finished:"id"`
	BaseAppLocation      string       `json:"base_app_location" datastore:"baseapplocation,noindex"`
	Translator           []Translator `json:"translator,omitempty" datastore:"translator"`
	Org                  string       `json:"org" datastore:"org"`
	CreatedBy            string       `json:"createdby" datastore:"createdby"`
	Availability         string       `json:"availability" datastore:"availability"`
	CreationTime         int64        `json:"creationtime" datastore:"creationtime,noindex"`
	LastModificationtime int64        `json:"lastmodificationtime" datastore:"lastmodificationtime,noindex"`
	LastRuntime          int64        `json:"lastruntime" datastore:"lastruntime,noindex"`
	Frequency            string       `json:"frequency" datastore:"frequency,noindex"`
	Environment          string       `json:"environment" datastore:"environment"`
	Status               string       `json:"status" datastore:"status"`
}

// Returned from /GET /schedules
type Schedules struct {
	Schedules []ScheduleOld `json:"schedules"`
	Success   bool          `json:"success"`
}

type ScheduleApps struct {
	Apps    []ApiYaml `json:"apps"`
	Success bool      `json:"success"`
}

// Hmm
type ApiYaml struct {
	Name        string `json:"name" yaml:"name" required:"true datastore:"name"`
	Foldername  string `json:"foldername" yaml:"foldername" required:"true datastore:"foldername"`
	Id          string `json:"id" yaml:"id",required:"true, datastore:"id"`
	Description string `json:"description" datastore:"description" yaml:"description"`
	AppVersion  string `json:"app_version" yaml:"app_version",datastore:"app_version"`
	ContactInfo struct {
		Name string `json:"name" datastore:"name" yaml:"name"`
		Url  string `json:"url" datastore:"url" yaml:"url"`
	} `json:"contact_info" datastore:"contact_info" yaml:"contact_info"`
	Types []string `json:"types" datastore:"types" yaml:"types"`
	Input []struct {
		Name            string `json:"name" datastore:"name" yaml:"name"`
		Description     string `json:"description" datastore:"description" yaml:"description"`
		InputParameters []struct {
			Name        string `json:"name" datastore:"name" yaml:"name"`
			Description string `json:"description" datastore:"description" yaml:"description"`
			Required    string `json:"required" datastore:"required" yaml:"required"`
			Schema      struct {
				Type string `json:"type" datastore:"type" yaml:"type"`
			} `json:"schema" datastore:"schema" yaml:"schema"`
		} `json:"inputparameters" datastore:"inputparameters" yaml:"inputparameters"`
		OutputParameters []struct {
			Name        string `json:"name" datastore:"name" yaml:"name"`
			Description string `json:"description" datastore:"description" yaml:"description"`
			Required    string `json:"required" datastore:"required" yaml:"required"`
			Schema      struct {
				Type string `json:"type" datastore:"type" yaml:"type"`
			} `json:"schema" datastore:"schema" yaml:"schema"`
		} `json:"outputparameters" datastore:"outputparameters" yaml:"outputparameters"`
		Config []struct {
			Name        string `json:"name" datastore:"name" yaml:"name"`
			Description string `json:"description" datastore:"description" yaml:"description"`
			Required    string `json:"required" datastore:"required" yaml:"required"`
			Schema      struct {
				Type string `json:"type" datastore:"type" yaml:"type"`
			} `json:"schema" datastore:"schema" yaml:"schema"`
		} `json:"config" datastore:"config" yaml:"config"`
	} `json:"input" datastore:"input" yaml:"input"`
	Output []struct {
		Name        string `json:"name" datastore:"name" yaml:"name"`
		Description string `json:"description" datastore:"description" yaml:"description"`
		Config      []struct {
			Name        string `json:"name" datastore:"name" yaml:"name"`
			Description string `json:"description" datastore:"description" yaml:"description"`
			Required    string `json:"required" datastore:"required" yaml:"required"`
			Schema      struct {
				Type string `json:"type" datastore:"type" yaml:"type"`
			} `json:"schema" datastore:"schema" yaml:"schema"`
		} `json:"config" datastore:"config" yaml:"config"`
		InputParameters []struct {
			Name        string `json:"name" datastore:"name" yaml:"name"`
			Description string `json:"description" datastore:"description" yaml:"description"`
			Required    string `json:"required" datastore:"required" yaml:"required"`
			Schema      struct {
				Type string `json:"type" datastore:"type" yaml:"type"`
			} `json:"schema" datastore:"schema" yaml:"schema"`
		} `json:"inputparameters" datastore:"inputparameters" yaml:"inputparameters"`
		OutputParameters []struct {
			Name        string `json:"name" datastore:"name" yaml:"name"`
			Description string `json:"description" datastore:"description" yaml:"description"`
			Required    string `json:"required" datastore:"required" yaml:"required"`
			Schema      struct {
				Type string `json:"type" datastore:"type" yaml:"type"`
			} `json:"schema" datastore:"schema" yaml:"schema"`
		} `json:"outputparameters" datastore:"outputparameters" yaml:"outputparameters"`
	} `json:"output" datastore:"output" yaml:"output"`
}

type Hooks struct {
	Hooks   []Hook `json:"hooks"`
	Success bool   `json:"-"`
}

type Info struct {
	Url         string `json:"url" datastore:"url"`
	Name        string `json:"name" datastore:"name"`
	Description string `json:"description" datastore:"description"`
}

// Actions to be done by webhooks etc
// Field is the actual field to use from json
type HookAction struct {
	Type  string `json:"type" datastore:"type"`
	Name  string `json:"name" datastore:"name"`
	Id    string `json:"id" datastore:"id"`
	Field string `json:"field" datastore:"field"`
}

type Hook struct {
	Id             string       `json:"id" datastore:"id"`
	Start          string       `json:"start" datastore:"start"`
	Info           Info         `json:"info" datastore:"info"`
	Actions        []HookAction `json:"actions" datastore:"actions,noindex"`
	Type           string       `json:"type" datastore:"type"`
	Owner          string       `json:"owner" datastore:"owner"`
	Status         string       `json:"status" datastore:"status"`
	Workflows      []string     `json:"workflows" datastore:"workflows"`
	Running        bool         `json:"running" datastore:"running"`
	OrgId          string       `json:"org_id" datastore:"org_id"`
	Environment    string       `json:"environment" datastore:"environment"`
	Auth           string       `json:"auth" datastore:"auth"`
	CustomResponse string       `json:"custom_response" datastore:"custom_response"`
	Version        string       `json:"version" datastore:"version"`
	VersionTimeout int          `json:"version_timeout" datastore:"version_timeout"`
}

type RegionBody struct {
	DstRegion string `json:"dst_region"`
	SrcRegion string `json:"src_region"`
	OrgId     string `json:"org_id"`
}

// Used within a user
type OrgMini struct {
	Name       string     `json:"name" datastore:"name"`
	Id         string     `json:"id" datastore:"id"`
	Users      []UserMini `json:"users" datastore:"users"`
	Role       string     `json:"role" datastore:"role"`
	CreatorOrg string     `json:"creator_org" datastore:"creator_org"`
	Image      string     `json:"image" datastore:"image,noindex"`
	ChildOrgs  []OrgMini  `json:"child_orgs" datastore:"child_orgs"`
	RegionUrl  string     `json:"region_url" datastore:"region_url"`
}

type Priority struct {
	Name        string `json:"name" datastore:"name"`
	Description string `json:"description" datastore:"description"`
	Type        string `json:"type" datastore:"type"`
	Active      bool   `json:"active" datastore:"active"`
	URL         string `json:"url" datastore:"url"`
	Severity    int    `json:"severity" datastore:"severity"` // 1 = high, 2 = mid, 3 = low
}

type LeadInfo struct {
	Contacted  bool `json:"contacted,omitempty" datastore:"contacted"`
	Student    bool `json:"student,omitempty" datastore:"student"`
	Lead       bool `json:"lead,omitempty" datastore:"lead"`
	POV        bool `json:"pov,omitempty" datastore:"pov"`
	DemoDone   bool `json:"demo_done,omitempty" datastore:"demo_done"`
	Customer   bool `json:"customer,omitempty" datastore:"customer"`
	OpenSource bool `json:"opensource,omitempty" datastore:"opensource"`
	Internal   bool `json:"internal,omitempty" datastore:"internal"`
	SubOrg     bool `json:"sub_org,omitempty" datastore:"sub_org"`

	OldCustomer bool `json:"old_customer,omitempty" datastore:"old_customer"`
	OldLead     bool `json:"old_lead,omitempty" datastore:"old_lead"`
	TechPartner bool `json:"tech_partner,omitempty" datastore:"tech_partner"`
	Creator     bool `json:"creator,omitempty" datastore:"creator"`
}

type Org struct {
	Name            string       `json:"name" datastore:"name"`
	Description     string       `json:"description" datastore:"description"`
	CompanyType     string       `json:"company_type" datastore:"company_type"`
	Image           string       `json:"image" datastore:"image,noindex"`
	Id              string       `json:"id" datastore:"id"`
	Org             string       `json:"org" datastore:"org"`
	Users           []User       `json:"users" datastore:"users"`
	Role            string       `json:"role" datastore:"role"`
	Roles           []string     `json:"roles" datastore:"roles"`
	ActiveApps      []string     `json:"active_apps" datastore:"active_apps"`
	CloudSync       bool         `json:"cloud_sync" datastore:"CloudSync"`
	CloudSyncActive bool         `json:"cloud_sync_active" datastore:"CloudSyncActive"`
	SyncConfig      SyncConfig   `json:"sync_config" datastore:"sync_config"`
	SyncFeatures    SyncFeatures `json:"sync_features,omitempty" datastore:"sync_features"`
	MFARequired     bool         `json:"mfa_required" datastore:"mfa_required"`

	SubscriptionUserId string                `json:"subscription_user_id" datastore:"subscription_user_id"`
	Subscriptions      []PaymentSubscription `json:"subscriptions" datastore:"subscriptions"`

	SyncUsage         SyncUsage   `json:"sync_usage" datastore:"sync_usage"`
	Created           int64       `json:"created" datastore:"created"`
	Edited            int64       `json:"edited" datastore:"edited"`
	Defaults          Defaults    `json:"defaults" datastore:"defaults"`
	Invites           []string    `json:"invites" datastore:"invites"`
	ChildOrgs         []OrgMini   `json:"child_orgs" datastore:"child_orgs"`
	ManagerOrgs       []OrgMini   `json:"manager_orgs" datastore:"manager_orgs"` // Multi in case more than one org should be able to control another
	CreatorOrg        string      `json:"creator_org" datastore:"creator_org"`
	PartnerInfo       PartnerInfo `json:"partner_info" datastore:"partner_info"`
	SSOConfig         SSOConfig   `json:"sso_config" datastore:"sso_config"`
	SecurityFramework Categories  `json:"security_framework" datastore:"security_framework,noindex"`
	Priorities        []Priority  `json:"priorities" datastore:"priorities,noindex"`
	MainPriority      string      `json:"main_priority" datastore:"main_priority"`
	Region            string      `json:"region" datastore:"region"`
	RegionUrl         string      `json:"region_url" datastore:"region_url"`
	Tutorials         []Tutorial  `json:"tutorials" datastore:"tutorials"`
	LeadInfo          LeadInfo    `json:"lead_info,omitempty" datastore:"lead_info"`
	OrgAuth OrgAuth `json:"org_auth" datastore:"org_auth"`


	CreatorId string `json:"creator_id" datastore:"creator_id"`
	Disabled  bool   `json:"disabled" datastore:"disabled"`

	EulaSigned   bool    `json:"eula_signed" datastore:"eula_signed"`
	EulaSignedBy string  `json:"eula_signed_by" datastore:"eula_signed_by"`
	Billing      Billing `json:"Billing" datastore:"Billing"`
}

type Billing struct {
	Email          string           `json:"Email" datastore:"Email"`
	AlertThreshold []AlertThreshold `json:"AlertThreshold" datastore:"AlertThreshold"`
}

type AlertThreshold struct {
	Percentage int  `json:"percentage" datastore:"percentage"`
	Count      int  `json:"count" datastore:"count"`
	Email_send bool `json:"Email_send" datastore:"Email_send"`
}

// Authentication overrides that times out
// Only works for certain features, such as public auth keys
// Timeout after 24 hours 
type OrgAuth struct {
	Token string `json:"token" datastore:"token"`
	Expires time.Time `json:"expires" datastore:"expires"`
}

type PartnerInfo struct {
	Reseller      bool   `json:"reseller" datastore:"reseller"`
	ResellerLevel string `json:"reseller_level" datastore:"reseller_level"`
}

type Defaults struct {
	AppDownloadRepo        string `json:"app_download_repo" datastore:"app_download_repo"`
	AppDownloadBranch      string `json:"app_download_branch" datastore:"app_download_branch"`
	WorkflowDownloadRepo   string `json:"workflow_download_repo" datastore:"workflow_download_repo"`
	WorkflowDownloadBranch string `json:"workflow_download_branch" datastore:"workflow_download_branch"`
	NotificationWorkflow   string `json:"notification_workflow" datastore:"notification_workflow"`
	DocumentationReference string `json:"documentation_reference" datastore:"documentation_reference"`

	WorkflowUploadRepo     string `json:"workflow_upload_repo" datastore:"workflow_upload_repo"`
	WorkflowUploadBranch   string `json:"workflow_upload_branch" datastore:"workflow_upload_branch"`
	WorkflowUploadUsername string `json:"workflow_upload_username" datastore:"workflow_upload_username"`
	WorkflowUploadToken    string `json:"workflow_upload_token" datastore:"workflow_upload_token"`

	NewsletterDisabled            bool `json:"newsletter" datastore:"newsletter_disabled"`
	WeeklyRecommendationsDisabled bool `json:"weekly_recommendations" datastore:"weekly_recommendations_disabled"`

	KmsId string `json:"kms_id" datastore:"kms_id"`
}

type CacheKeyData struct {
	Success       bool   `json:"success" datastore:"Success"`
	WorkflowId    string `json:"workflow_id," datastore:"WorkflowId"`
	ExecutionId   string `json:"execution_id,omityempty" datastore:"ExecutionId"`
	Authorization string `json:"authorization,omitempty" datastore:"Authorization"`
	OrgId         string `json:"org_id,omitempty" datastore:"OrgId"`
	Key           string `json:"key" datastore:"Key"`
	Value         string `json:"value" datastore:"Value,noindex"`

	Created 	  int64 `json:"created" datastore:"Created"`
	Edited        int64  `json:"edited" datastore:"Edited"`

	FormattedKey        string `json:"formatted_key,omitempty" datastore:"FormattedKey"`
	PublicAuthorization string `json:"public_authorization,omitempty" datastore:"PublicAuthorization"` // Used for public authorization
}

type SyncConfig struct {
	Interval int64  `json:"interval" datastore:"interval"`
	Apikey   string `json:"api_key" datastore:"api_key"`
	Source   string `json:"source" datastore:"source"`

	WorkflowBackup bool `json:"workflow_backup" datastore:"workflow_backup"`
	AppBackup      bool `json:"app_backup" datastore:"app_backup"`
}

type PaymentSubscription struct {
	Active           bool     `json:"active" datastore:"active"`
	Startdate        int64    `json:"startdate" datastore:"startdate"`
	CancellationDate int64    `json:"cancellationdate" datastore:"cancellationdate"`
	Enddate          int64    `json:"enddate" datastore:"enddate"`
	Name             string   `json:"name" datastore:"name"`
	Recurrence       string   `json:"recurrence" datastore:"recurrence"`
	Reference        string   `json:"reference" datastore:"reference"`
	Level            string   `json:"level" datastore:"level"`
	Amount           string   `json:"amount" datastore:"amount"`
	Currency         string   `json:"currency" datastore:"currency"`
	Limit            int64    `json:"limit" datastore:"limit"`
	Features         []string `json:"features" datastore:"features"`

	Eula         string `json:"eula" datastore:"eula,noindex"`
	EulaSigned   bool   `json:"eula_signed" datastore:"eula_signed"`
	EulaSignedBy string `json:"eula_signed_by" datastore:"eula_signed_by"`
}

type SyncUsage struct {
	WorkflowExecutions SyncDataUsage `json:"workflow_executions" datastore:"workflow_executions"`
	Webhook            SyncDataUsage `json:"webhook" datastore:"webhook"`
	Schedules          SyncDataUsage `json:"schedules" datastore:"schedules"`
	UserInput          SyncDataUsage `json:"user_input" datastore:"user_input"`
	SendMail           SyncDataUsage `json:"send_mail" datastore:"send_mail"`
	SendSms            SyncDataUsage `json:"send_sms" datastore:"send_sms"`
	EmailTrigger       SyncDataUsage `json:"email_trigger" datastore:"email_trigger"`
	Autocomplete       SyncDataUsage `json:"autocomplete" datastore:"autocomplete"`
	Authentication     SyncDataUsage `json:"authentication" datastore:"authentication"`
	Schedule           SyncDataUsage `json:"schedule" datastore:"schedule"`
	AppExecutions      SyncDataUsage `json:"app_executions" datastore:"app_executions"`
	Workflows          SyncDataUsage `json:"workflows" datastore:"workflows"`
	MultiTenant        SyncDataUsage `json:"multi_tenant" datastore:"multi_tenant"`
	MultiRegion        SyncDataUsage `json:"multi_region" datastore:"multi_region"`
	MultiEnv           SyncDataUsage `json:"multi_env" datastore:"multi_env"`
	Apps               SyncDataUsage `json:"apps" datastore:"apps"`
	ShuffleGPT         SyncDataUsage `json:"shuffle_gpt" datastore:"shuffle_gpt"`
}

type SyncDataUsage struct {
	StartDate int64  `json:"start_date" datastore:"start_date"`
	EndDate   int64  `json:"end_date" datastore:"end_date"`
	Reset     string `json:"reset" datastore:"reset"`
	Counter   int64  `json:"counter" datastore:"counter"`
}

type NewValue struct {
	OrgId               string `json:"org_id" datastore:"org_id"`
	WorkflowId          string `json:"workflow_id" datastore:"workflow_id"`
	WorkflowExecutionId string `json:"workflow_execution_id" datastore:"workflow_execution_id"`
	ParameterName       string `json:"parameter_name" datastore:"parameter_name"`
	Value               string `json:"value" datastore:"value,noindex"`
	Created             int64  `json:"created" datastore:"created"`
	Id                  string `json:"id" datastore:"id"`
}

type MailLevel struct {
	Type       string `json:"type"`
	Percentage int64  `json:"percentage"`
	LastSent   int64  `json:"last_sent"`
}

type SyncFeatures struct {
	Editing            bool        `json:"editing" datastore:"editing"`
	MailSent           []MailLevel `json:"mail_sent" datastore:"mail_sent"`
	AppExecutions      SyncData    `json:"app_executions" datastore:"app_executions"`
	MultiEnv           SyncData    `json:"multi_env" datastore:"multi_env"`
	MultiTenant        SyncData    `json:"multi_tenant" datastore:"multi_tenant"`
	MultiRegion        SyncData    `json:"multi_region" datastore:"multi_region"`
	Webhook            SyncData    `json:"webhook" datastore:"webhook"`
	Schedules          SyncData    `json:"schedules" datastore:"schedules"`
	UserInput          SyncData    `json:"user_input" datastore:"user_input"`
	SendMail           SyncData    `json:"send_mail" datastore:"send_mail"`
	SendSms            SyncData    `json:"send_sms" datastore:"send_sms"`
	Updates            SyncData    `json:"updates" datastore:"updates"`
	EmailTrigger       SyncData    `json:"email_trigger" datastore:"email_trigger"`
	Notifications      SyncData    `json:"notifications" datastore:"notifications"`
	Workflows          SyncData    `json:"workflows" datastore:"workflows"`
	Autocomplete       SyncData    `json:"autocomplete" datastore:"autocomplete"`
	WorkflowExecutions SyncData    `json:"workflow_executions" datastore:"workflow_executions"`
	Authentication     SyncData    `json:"authentication" datastore:"authentication"`
	Schedule           SyncData    `json:"schedule" datastore:"schedule"`
	Apps               SyncData    `json:"apps" datastore:"apps"`
	ShuffleGPT         SyncData    `json:"shuffle_gpt" datastore:"shuffle_gpt"`
}

type SyncData struct {
	Active         bool   `json:"active" datastore:"active"`
	Type           string `json:"type,omitempty" datastore:"type"`
	Name           string `json:"name,omitempty" datastore:"name"`
	Description    string `json:"description,omitempty" datastore:"description"`
	Usage          int64  `json:"usage" datastore:"usage"`
	Limit          int64  `json:"limit" datastore:"limit"`
	StartDate      int64  `json:"start_date,omitempty" datastore:"start_date"`
	EndDate        int64  `json:"end_date,omitempty" datastore:"end_date"`
	DataCollection int64  `json:"data_collection,omitempty" datastore:"data_collection"`
}

type Variable struct {
	Description string `json:"description" datastore:"description,noindex"`
	ID          string `json:"id" datastore:"id"`
	Name        string `json:"name" datastore:"name"`
	Value       string `json:"value" datastore:"value,noindex"`
}

type WorkflowExecution struct {
	Type                string         `json:"type" datastore:"type"`
	Status              string         `json:"status" datastore:"status"`
	Start               string         `json:"start" datastore:"start"`
	ExecutionArgument   string         `json:"execution_argument" datastore:"execution_argument,noindex"`
	ExecutionId         string         `json:"execution_id" datastore:"execution_id"`
	ExecutionOrg        string         `json:"execution_org" datastore:"execution_org"`
	StartedAt           int64          `json:"started_at" datastore:"started_at"`
	CompletedAt         int64          `json:"completed_at" datastore:"completed_at"`
	WorkflowId          string         `json:"workflow_id" datastore:"workflow_id"`
	LastNode            string         `json:"last_node" datastore:"last_node"`
	Authorization       string         `json:"authorization" datastore:"authorization"`
	Result              string         `json:"result" datastore:"result,noindex"`
	ProjectId           string         `json:"project_id" datastore:"project_id"`
	Locations           []string       `json:"locations,omitempty" datastore:"locations"`
	Workflow            Workflow       `json:"workflow,omitempty" datastore:"workflow,noindex"`
	Results             []ActionResult `json:"results" datastore:"results,noindex"`
	ExecutionVariables  []Variable     `json:"execution_variables,omitempty" datastore:"execution_variables,omitempty"`
	OrgId               string         `json:"org_id" datastore:"org_id"`
	ExecutionSource     string         `json:"execution_source" datastore:"execution_source"`
	ExecutionParent     string         `json:"execution_parent" datastore:"execution_parent"`
	ExecutionSourceNode string         `json:"execution_source_node" yaml:"execution_source_node"`
	ExecutionSourceAuth string         `json:"execution_source_auth" yaml:"execution_source_auth"`
	SubExecutionCount   int64          `json:"sub_execution_count" yaml:"sub_execution_count"` // Max depth to execute subflows in infinite loops (10 by default)
	Priority            int64          `json:"priority" datastore:"priority" yaml:"priority"`  // Priority of the execution. Usually manual should be 10, and all other UNDER that.

	NotificationsCreated int64 `json:"notifications_created" datastore:"notifications_created"`
	Authgroup 			 string `json:"authgroup" datastore:"authgroup"`
}

type Position struct {
	X float64 `json:"x" datastore:"x"`
	Y float64 `json:"y" datastore:"y"`
}

// This is for the nodes in a workflow, NOT the app action itself.
type Action struct {
	AppName           string                       `json:"app_name" datastore:"app_name"`
	AppVersion        string                       `json:"app_version" datastore:"app_version"`
	Description       string                       `json:"description" datastore:"description,noindex"`
	AppID             string                       `json:"app_id" datastore:"app_id"`
	Errors            []string                     `json:"errors" datastore:"errors"`
	ID                string                       `json:"id" datastore:"id"`
	IsValid           bool                         `json:"is_valid" datastore:"is_valid"`
	IsStartNode       bool                         `json:"isStartNode,omitempty" datastore:"isStartNode"`
	Sharing           bool                         `json:"sharing,omitempty" datastore:"sharing"`
	PrivateID         string                       `json:"private_id,omitempty" datastore:"private_id"`
	Label             string                       `json:"label,omitempty" datastore:"label"`
	SmallImage        string                       `json:"small_image,omitempty" datastore:"small_image,noindex" required:false yaml:"small_image"`
	Public            bool                         `json:"public" datastore:"public"`
	Generated         bool                         `json:"generated" yaml:"generated" required:false datastore:"generated"`
	LargeImage        string                       `json:"large_image,omitempty" datastore:"large_image,noindex" yaml:"large_image" required:false`
	Environment       string                       `json:"environment,omitempty" datastore:"environment"`
	Name              string                       `json:"name" datastore:"name"`
	Parameters        []WorkflowAppActionParameter `json:"parameters" datastore: "parameters,noindex"`
	InvalidParameters []WorkflowAppActionParameter `json:"previous_parameters,omitempty" datastore: "previous_parameters,noindex"`
	ExecutionVariable Variable                     `json:"execution_variable,omitempty" datastore:"execution_variable,omitempty"`
	Position          Position                     `json:"position,omitempty"`
	Priority          int                          `json:"priority,omitempty" datastore:"priority"`
	AuthenticationId  string                       `json:"authentication_id" datastore:"authentication_id"`
	Example           string                       `json:"example,omitempty" datastore:"example,noindex"`
	AuthNotRequired   bool                         `json:"auth_not_required,omitempty" datastore:"auth_not_required" yaml:"auth_not_required"`
	Category          string                       `json:"category" datastore:"category"`
	ReferenceUrl      string                       `json:"reference_url" datastore:"reference_url"`
	SubAction         bool                         `json:"sub_action" datastore:"sub_action"`
	SourceWorkflow    string                       `json:"source_workflow" yaml:"source_workflow" datastore:"source_workflow"`
	RunMagicOutput    bool                         `json:"run_magic_output" datastore:"run_magic_output" yaml:"run_magic_output"`
	RunMagicInput     bool                         `json:"run_magic_input" datastore:"run_magic_input" yaml:"run_magic_input"`
	ExecutionDelay    int64                        `json:"execution_delay" yaml:"execution_delay" datastore:"execution_delay"`
	CategoryLabel     []string                     `json:"category_label" datastore:"category_label"` // For categorization of the type of node in case it's available
	Suggestion        bool                         `json:"suggestion" datastore:"suggestion"`         // Whether it was a suggestion in the workflow or not

	ParentControlled bool `json:"parent_controlled" datastore:"parent_controlled"` // If the parent workflow node exists, and shouldn't be editable by child workflow
}

// Added environment for location to execute
type Trigger struct {
	AppName         string                       `json:"app_name" datastore:"app_name"`
	Description     string                       `json:"description" datastore:"description,noindex"`
	LongDescription string                       `json:"long_description" datastore:"long_description"`
	Status          string                       `json:"status" datastore:"status"`
	AppVersion      string                       `json:"app_version" datastore:"app_version"`
	Errors          []string                     `json:"errors" datastore:"errors"`
	ID              string                       `json:"id" datastore:"id"`
	IsValid         bool                         `json:"is_valid" datastore:"is_valid"`
	IsStartNode     bool                         `json:"isStartNode" datastore:"isStartNode"`
	Label           string                       `json:"label" datastore:"label"`
	SmallImage      string                       `json:"small_image" datastore:"small_image,noindex" required:false yaml:"small_image"`
	LargeImage      string                       `json:"large_image" datastore:"large_image,noindex" yaml:"large_image" required:false`
	Environment     string                       `json:"environment" datastore:"environment"`
	TriggerType     string                       `json:"trigger_type" datastore:"trigger_type"`
	Name            string                       `json:"name" datastore:"name"`
	Tags            []string                     `json:"tags" datastore:"tags" yaml:"tags"`
	Parameters      []WorkflowAppActionParameter `json:"parameters" datastore: "parameters,noindex"`
	Position        struct {
		X float64 `json:"x" datastore:"x"`
		Y float64 `json:"y" datastore:"y"`
	} `json:"position"`
	Priority       int         `json:"priority" datastore:"priority"`
	SourceWorkflow string      `json:"source_workflow" yaml:"source_workflow" datastore:"source_workflow"`
	ExecutionDelay int64       `json:"execution_delay" yaml:"execution_delay" datastore:"execution_delay"`
	AppAssociation WorkflowApp `json:"app_association" yaml:"app_association" datastore:"app_association"`

	ParentControlled bool `json:"parent_controlled" datastore:"parent_controlled"` // If the parent workflow node exists, and shouldn't be editable by child workflow
}

type Branch struct {
	DestinationID string      `json:"destination_id" datastore:"destination_id"`
	ID            string      `json:"id" datastore:"id"`
	SourceID      string      `json:"source_id" datastore:"source_id"`
	Label         string      `json:"label" datastore:"label"`
	HasError      bool        `json:"has_errors" datastore: "has_errors"`
	Conditions    []Condition `json:"conditions" datastore: "conditions"`
	Decorator     bool        `json:"decorator" datastore:"decorator"`

	ParentControlled bool `json:"parent_controlled" datastore:"parent_controlled"` // If the parent workflow node exists, and shouldn't be editable by child workflow
}

// Same format for a lot of stuff
type Condition struct {
	Source      WorkflowAppActionParameter `json:"source" datastore:"source"`
	Condition   WorkflowAppActionParameter `json:"condition" datastore:"condition"`
	Destination WorkflowAppActionParameter `json:"destination" datastore:"destination"`
}

type Schedule struct {
	Name              string `json:"name" datastore:"name"`
	Frequency         string `json:"frequency" datastore:"frequency"`
	ExecutionArgument string `json:"execution_argument" datastore:"execution_argument,noindex"`
	Id                string `json:"id" datastore:"id"`
	OrgId             string `json:"org_id" datastore:"org_id"`
	Environment       string `json:"environment" datastore:"environment"`
	Start             string `json:"start" datastore:"start"`
}

type Comment struct {
	ID              string `json:"id" datastore:"id"`
	Label           string `json:"label" datastore:"label"`
	Type            string `json:"type" datastore:"type"`
	IsValid         bool   `json:"is_valid" datastore:"is_valid"`
	Decorator       bool   `json:"decorator" datastore:"decorator"`
	Width           int64  `json:"width" datastore:"width"`
	Height          int64  `json:"height" datastore:"height"`
	Color           string `json:"color" datastore:"color"`
	BackgroundColor string `json:"backgroundcolor" datastore:"backgroundcolor"`
	Position        struct {
		X float64 `json:"x" datastore:"x"`
		Y float64 `json:"y" datastore:"y"`
	} `json:"position"`
}

type InputQuestion struct {
	Name     string `json:"name" datastore:"name,noindex"`
	Value    string `json:"value" datastore:"value,noindex"`
	Required bool   `json:"required" datastore:"required"`
	Deleted  bool   `json:"deleted" datastore:"deleted"`
}

type Workflow struct {
	Actions        []Action   `json:"actions" datastore:"actions,noindex"`
	Branches       []Branch   `json:"branches" datastore:"branches,noindex"`
	VisualBranches []Branch   `json:"visual_branches" datastore:"visual_branches,noindex"`
	Triggers       []Trigger  `json:"triggers" datastore:"triggers,noindex"`
	Schedules      []Schedule `json:"schedules" datastore:"schedules,noindex"`
	Comments       []Comment  `json:"comments" datastore:"comments,noindex"`
	Configuration  struct {
		ExitOnError       bool `json:"exit_on_error" datastore:"exit_on_error"`
		StartFromTop      bool `json:"start_from_top" datastore:"start_from_top"`
		SkipNotifications bool `json:"skip_notifications" datastore:"skip_notifications"`
	} `json:"configuration,omitempty" datastore:"configuration"`
	Created              int64      `json:"created" datastore:"created"`
	Edited               int64      `json:"edited" datastore:"edited"`
	LastRuntime          int64      `json:"last_runtime" datastore:"last_runtime"`
	DueDate              int64      `json:"due_date" datastore:"due_date"`
	Errors               []string   `json:"errors,omitempty" datastore:"errors"`
	Tags                 []string   `json:"tags,omitempty" datastore:"tags"`
	ID                   string     `json:"id" datastore:"id"`
	IsValid              bool       `json:"is_valid" datastore:"is_valid"`
	Name                 string     `json:"name" datastore:"name"`
	Description          string     `json:"description" datastore:"description,noindex"`
	Start                string     `json:"start" datastore:"start"`
	Owner                string     `json:"owner" datastore:"owner"`
	Sharing              string     `json:"sharing" datastore:"sharing"`
	Image                string     `json:"image,omitempty" datastore:"image,noindex"`
	Org                  []OrgMini  `json:"org,omitempty" datastore:"org"`
	ExecutingOrg         OrgMini    `json:"execution_org,omitempty" datastore:"execution_org"`
	OrgId                string     `json:"org_id,omitempty" datastore:"org_id"`
	WorkflowVariables    []Variable `json:"workflow_variables" datastore:"workflow_variables"`
	ExecutionVariables   []Variable `json:"execution_variables,omitempty" datastore:"execution_variables"`
	ExecutionEnvironment string     `json:"execution_environment" datastore:"execution_environment"`
	PreviouslySaved      bool       `json:"previously_saved" datastore:"first_save"`
	Categories           Categories `json:"categories" datastore:"categories"`
	ExampleArgument      string     `json:"example_argument" datastore:"example_argument,noindex"`
	Public               bool       `json:"public" datastore:"public"`
	DefaultReturnValue   string     `json:"default_return_value" datastore:"default_return_value,noindex"`
	ContactInfo          struct {
		Name string `json:"name" datastore:"name" yaml:"name"`
		Url  string `json:"url" datastore:"url" yaml:"url"`
	} `json:"contact_info" datastore:"contact_info" yaml:"contact_info" required:false`
	PublishedId    string          `json:"published_id" yaml:"published_id"`
	RevisionId     string          `json:"revision_id" yaml:"revision_id"`
	Subflows       []Workflow      `json:"subflows,omitempty" yaml:"subflows"`
	UsecaseIds     []string        `json:"usecase_ids" yaml:"usecase_ids" datastore:"usecase_ids"`
	InputQuestions []InputQuestion `json:"input_questions" datastore:"input_questions"`

	Blogpost     string `json:"blogpost" yaml:"blogpost"`
	Video        string `json:"video" yaml:"video"`
	Status       string `json:"status" datastore:"status"`
	WorkflowType string `json:"workflow_type" datastore:"workflow_type"`
	Generated    bool   `json:"generated" datastore:"generated"`
	Hidden       bool   `json:"hidden" datastore:"hidden"`
	UpdatedBy    string `json:"updated_by" datastore:"updated_by"`

	// Whether it's manually validated or not
	Validated  bool 	`json:"validated" datastore:"validated"` 


	// Distribution system for suborg/parentorg 
	ParentWorkflowId string `json:"parentorg_workflow" datastore:"parentorg_workflow"`
	ChildWorkflowIds []string `json:"childorg_workflow_ids" datastore:"childorg_workflow_ids"`
	SuborgDistribution []string `json:"suborg_distribution" datastore:"suborg_distribution"`

	// Config for backup configs
	// This overrides org settings for the workflow
	BackupConfig BackupConfig `json:"backup_config" datastore:"backup_config"`
	AuthGroups  []string     `json:"auth_groups" datastore:"auth_groups"`
}

type BackupConfig struct {
	UploadRepo     string `json:"upload_repo" datastore:"upload_repo"`
	UploadBranch   string `json:"upload_branch" datastore:"upload_branch"`
	UploadUsername string `json:"upload_username" datastore:"upload_username"`
	UploadToken    string `json:"upload_token" datastore:"upload_token"`
}

type Category struct {
	Name        string `json:"name" datastore:"name"`
	Count       int64  `json:"count" datastore:"count"`
	ID          string `json:"id" datastore:"id"`
	Description string `json:"description" datastore:"description,noindex"`
	LargeImage  string `json:"large_image" datastore:"large_image,noindex"`
}

type Categories struct {
	SIEM          Category `json:"siem" datastore:"siem"`
	Communication Category `json:"communication" datastore:"communication"`
	Assets        Category `json:"assets" datastore:"assets"`
	Cases         Category `json:"cases" datastore:"cases"`
	Network       Category `json:"network" datastore:"network"`
	Intel         Category `json:"intel" datastore:"intel"`
	EDR           Category `json:"edr" datastore:"edr"`
	IAM           Category `json:"iam" datastore:"IAM"`

	Email Category `json:"email" datastore:"email"`
	Other Category `json:"other" datastore:"other"`
}

type SimilarAction struct {
	WorkflowId  string `json:"workflow_id" datastore:"workflow_id"`
	ExecutionId string `json:"execution_id" datastore:"execution_id"`
	Similarity  int64  `json:"similarity" datastore:"similarity"`
}

type ActionResult struct {
	Action           Action          `json:"action" datastore:"action"`
	ExecutionId      string          `json:"execution_id" datastore:"execution_id"`
	Authorization    string          `json:"authorization" datastore:"authorization"`
	Result           string          `json:"result" datastore:"result,noindex"`
	StartedAt        int64           `json:"started_at" datastore:"started_at"`
	CompletedAt      int64           `json:"completed_at" datastore:"completed_at"`
	Status           string          `json:"status" datastore:"status"`
	AttackTechniques []string        `json:"attack_techniques" datastore:"attack_techniques"`
	AttackTactics    []string        `json:"attack_tactics" datastore:"attack_tactics"`
	SimilarActions   []SimilarAction `json:"similar_actions" datastore:"similar_actions"`
}

type AuthenticationUsage struct {
	WorkflowId string   `json:"workflow_id" datastore:"workflow_id"`
	Nodes      []string `json:"nodes" datastore:"nodes"`
}

type Notification struct {
	Image             string   `json:"image" datastore:"image"`
	CreatedAt         int64    `json:"created_at" datastore:"created_at"`
	UpdatedAt         int64    `json:"updated_at" datastore:"updated_at"`
	Title             string   `json:"title" datastore:"title"`
	Description       string   `json:"description" datastore:"description"`
	OrgId             string   `json:"org_id" datastore:"org_id"`
	OrgName           string   `json:"org_name" datastore:"org_name"`
	UserId            string   `json:"user_id" datastore:"user_id"`
	Tags              []string `json:"tags" datastore:"tags"`
	Amount            int      `json:"amount" datastore:"amount"`
	BucketDescription string   `json:"bucket_description" datastore:"bucket_description"`
	Id                string   `json:"id" datastore:"id"`
	ReferenceUrl      string   `json:"reference_url" datastore:"reference_url"`
	OrgNotificationId string   `json:"org_notification_id" datastore:"org_notification_id"`
	Dismissable       bool     `json:"dismissable" datastore:"dismissable"`
	Personal          bool     `json:"personal" datastore:"personal"`
	Read              bool     `json:"read" datastore:"read"`

	ModifiedBy  string `json:"modified_by" datastore:"modified_by"`
	Ignored     bool   `json:"ignored" datastore:"ignored"`
	ExecutionId string `json:"execution_id" datastore:"execution_id"`
}

type NotificationCached struct {
	NotificationId            string `json:"notification_id" datastore:"notification_id"`
	WorkflowId                string `json:"workflow_id" datastore:"workflow_id"`
	LastUpdated               int64  `json:"last_updated" datastore:"last_updated"`
	FirstUpdated              int64  `json:"first_updated" datastore:"first_updated"`
	LastNotificationAttempted string `json:"last_notification_attempted" datastore:"last_notification_attempted"`
	OriginalNotification      string `json:"original_notification" datastore:"original_notification"`
	Amount                    int64  `json:"amount" datastore:"amount"`
}

type File struct {
	Id              string   `json:"id" datastore:"id"`
	ReferenceFileId string   `json:"reference_file_id" datastore:"reference_file_id"`
	Type            string   `json:"type" datastore:"type"`
	CreatedAt       int64    `json:"created_at" datastore:"created_at"`
	UpdatedAt       int64    `json:"updated_at" datastore:"updated_at"`
	MetaAccessAt    int64    `json:"meta_access_at" datastore:"meta_access_at"`
	DownloadAt      int64    `json:"last_downloaded" datastore:"last_downloaded"`
	Description     string   `json:"description" datastore:"description"`
	ExpiresAt       string   `json:"expires_at" datastore:"expires_at"`
	Status          string   `json:"status" datastore:"status"`
	Filename        string   `json:"filename" datastore:"filename"`
	URL             string   `json:"url" datastore:"org"`
	OrgId           string   `json:"org_id" datastore:"org_id"`
	WorkflowId      string   `json:"workflow_id" datastore:"workflow_id"`
	Workflows       []string `json:"workflows" datastore:"workflows"`
	DownloadPath    string   `json:"download_path" datastore:"download_path"`
	Md5sum          string   `json:"md5_sum" datastore:"md5_sum"`
	Sha256sum       string   `json:"sha256_sum" datastore:"sha256_sum"`
	FileSize        int64    `json:"filesize" datastore:"filesize"`
	Duplicate       bool     `json:"duplicate" datastore:"duplicate"`
	Subflows        []string `json:"subflows" datastore:"subflows"`
	Tags            []string `json:"tags" datastore:"tags"`
	StorageArea     string   `json:"storage_area" datastore:"storage_area"`
	Etag            int      `json:"etag" datastore:"etag"`
	ContentType     string   `json:"content_type" datastore:"content_type"`
	UpdatedBy       string   `json:"updated_by" datastore:"updated_by"`
	CreatedBy       string   `json:"created_by" datastore:"created_by"`
	Namespace       string   `json:"namespace" datastore:"namespace"`
	Encrypted       bool     `json:"encrypted" datastore:"encrypted"`
	IsEdited        bool     `json:"isedited" datastore:"isedited"`
	LastEditor      string   `json:"lasteditor" datastore:"lasteditor"`
	OriginalMd5sum  string   `json:"Originalmd5_sum" datastore:"Originalmd5_sum"`
}

type AppAuthenticationGroup struct {
	Active			bool                  `json:"active" datastore:"active"`
	Label			string                `json:"label" datastore:"label"`
	Environment		string                `json:"environment" datastore:"environment"`
	Id				string                `json:"id" datastore:"id"`
	Description		string                `json:"description" datastore:"description"`
	OrgId			string                `json:"org_id" datastore:"org_id"`
	Created			int64                 `json:"created" datastore:"created"` 
	Edited			int64                 `json:"edited" datastore:"edited"`

	AppAuths		[]AppAuthenticationStorage `json:"app_auths" datastore:"app_auths,noindex"`
}

type AppAuthenticationStorage struct {
	Active            bool                  `json:"active" datastore:"active"`
	Label             string                `json:"label" datastore:"label"`
	Id                string                `json:"id" datastore:"id"`
	App               WorkflowApp           `json:"app" datastore:"app,noindex"`
	Fields            []AuthenticationStore `json:"fields" datastore:"fields"`
	Usage             []AuthenticationUsage `json:"usage" datastore:"usage"`
	WorkflowCount     int64                 `json:"workflow_count" datastore:"workflow_count"`
	NodeCount         int64                 `json:"node_count" datastore:"node_count"`
	OrgId             string                `json:"org_id" datastore:"org_id"`
	Created           int64                 `json:"created" datastore:"created"`
	Edited            int64                 `json:"edited" datastore:"edited"`
	Defined           bool                  `json:"defined" datastore:"defined"`
	Type              string                `json:"type" datastore:"type"`
	Encrypted         bool                  `json:"encrypted" datastore:"encrypted"`
	ReferenceWorkflow string                `json:"reference_workflow" datastore:"reference_workflow"`
	AutoDistribute    bool                  `json:"auto_distribute" datastore:"auto_distribute"`

	Environment string `json:"environment" datastore:"environment"` // In case an auth should ALWAYS be mapped to an environment. Can help out with Oauth2 refresh (e.g. running partially on cloud and partially onprem), as well as for KMS. For now ONLY KMS has a frontend.
	SuborgDistributed bool `json:"suborg_distributed" datastore:"suborg_distributed"` // Decides if it's distributed to suborgs or not
}

type PasswordChange struct {
	Username        string `json:"username"`
	Newpassword     string `json:"newpassword"`
	Newpassword2    string `json:"newpassword2"`
	Currentpassword string `json:"currentpassword"`
}

// Primary = usually an outer ID, e.g. workflow ID
// Secondary = something to specify what inside workflow to execute
// Third = Some data to add to it
type CloudSyncJob struct {
	Id            string `json:"id" datastore:"id"`
	Type          string `json:"type" datastore:"type"`
	Action        string `json:"action" datastore:"action"`
	OrgId         string `json:"org_id" datastore:"org_id"`
	PrimaryItemId string `json:"primary_item_id" datastore:"primary_item_id"`
	SecondaryItem string `json:"secondary_item" datastore:"secondary_item"`
	ThirdItem     string `json:"third_item" datastore:"third_item"`
	FourthItem    string `json:"fourth_item" datastore:"fourth_item"`
	FifthItem     string `json:"fifth_item" datastore:"fifth_item"`
	Created       string `json:"created" datastore:"created"`
}

type loginStruct struct {
	Username string `json:"username"`
	Password string `json:"password"`
	MFACode  string `json:"mfa_code"`
}

type ExecutionVariableWrapper struct {
	StartNode    string              `json:"startnode"`
	Children     map[string][]string `json:"children"`
	Parents      map[string][]string `json:"parents""`
	Visited      []string            `json:"visited"`
	Executed     []string            `json:"executed"`
	NextActions  []string            `json:"nextActions"`
	Environments []string            `json:"environments"`
	Extra        int                 `json:"extra"`
}

type MinimizedApps struct {
	Name     string `json:"name"`
	Image    string `json:"image"`
	Category string `json:"category"`
}

type AlgoliaSearchCreator struct {
	ObjectID        string          `json:"objectID"`
	TimeEdited      int64           `json:"time_edited"`
	Username        string          `json:"username"`
	Image           string          `json:"image"`
	Banner          string          `datastore:"banner" json:"banner"`
	Skills          []string        `json:"skills"`
	Synonyms        []string        `json:"synonyms"`
	Workflows       int64           `json:"workflows"`
	Apps            int64           `json:"apps"`
	SpecializedApps []MinimizedApps `json:"specialized_apps"`
	Verified        bool            `json:"verified"`
	Social          []string        `datastore:"social" json:"social"`
	WorkStatus      string          `datastore:"work_status" json:"work_status"`
	Url             string          `datastore:"url" json:"url"`
	IsOrg           bool            `datastore:"is_org" json:"is_org"`
}

type AlgoliaSearchWorkflow struct {
	Name             string            `json:"name"`
	ObjectID         string            `json:"objectID"`
	Description      string            `json:"description"`
	Variables        int               `json:"variables"`
	ActionAmount     int               `json:"action_amount"`
	TriggerAmount    int               `json:"trigger_amount"`
	Triggers         []string          `json:"triggers"`
	Actions          []string          `json:"actions"`
	Tags             []string          `json:"tags"`
	Categories       []string          `json:"categories"`
	AccessibleBy     []string          `json:"accessible_by,omitempty"`
	ImageUrl         string            `json:"image_url"`
	TimeEdited       int64             `json:"time_edited"`
	Invalid          bool              `json:"invalid"`
	Creator          string            `json:"creator,omitempty"`
	SourceIPLower    string            `json:"source_ip,omitempty"`
	SourceIP         string            `json:"SourceIP,omitempty"`
	Type             string            `json:"type"`
	UsecaseIds       []string          `json:"usecase_ids"`
	CreatorInfo      CreatorInfo       `json:"creator_info,omitempty"`
	ActionReferences []ActionReference `json:"action_references,omitempty"`
	Priority         int               `json:"priority"`
	Validated  		 bool 			   `json:"validated"`
}

type ActionReference struct {
	Name       string   `json:"name"`
	Id         string   `json:"id"`
	ImageUrl   string   `json:"image_url"`
	ActionName []string `json:"action_name"`
}

type CreatorInfo struct {
	Username string `json:"username"`
	Image    string `json:"image"`
}

type AlgoliaSearchApp struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	ObjectID     string   `json:"objectID"`
	Creator      string   `json:"creator"`
	AppVersion   string   `json:"app_version"`
	ImageUrl     string   `json:"image_url"`
	TimeEdited   int64    `json:"time_edited"`
	Generated    bool     `json:"generated"`
	Invalid      bool     `json:"invalid"`
	Priority     int      `json:"priority"`
	Actions      int      `json:"actions"`
	Tags         []string `json:"tags"`
	AccessibleBy []string `json:"accessible_by"`
	Categories   []string `json:"categories"`
	ActionLabels []string `json:"action_labels"`
	Triggers     []string `json:"triggers"`
	Verified     bool     `json:"verified"`
}

type ExecutionStruct struct {
	Start             string `json:"start"`
	ExecutionSource   string `json:"execution_source"`
	ExecutionArgument string `json:"execution_argument"`
}

type OauthToken struct {
	AccessToken  string    `json:"AccessToken" datastore:"AccessToken,noindex"`
	TokenType    string    `json:"TokenType" datastore:"TokenType,noindex"`
	RefreshToken string    `json:"RefreshToken" datastore:"RefreshToken,noindex"`
	Expiry       time.Time `json:"Expiry" datastore:"Expiry,noindex"`
}

type TriggerAuth struct {
	Id             string `json:"id" datastore:"id"`
	SubscriptionId string `json:"subscriptionId" datastore:"subscriptionId"`

	Username       string     `json:"username" datastore:"username,noindex"`
	Owner          string     `json:"owner" datastore:"owner"`
	OrgId          string     `json:"org_id" datastore:"org_id"`
	Type           string     `json:"type" datastore:"type"`
	Code           string     `json:"code,omitempty" datastore:"code,noindex"`
	WorkflowId     string     `json:"workflow_id" datastore:"workflow_id,noindex"`
	Start          string     `json:"start" datastore:"start"`
	OauthToken     OauthToken `json:"oauth_token,omitempty" datastore:"oauth_token"`
	AssociatedUser string     `json:"associated_user" yaml:"associated_user" datastore:"associated_user"`
	Folders        []string   `json:"folders" yaml:"folders" datastore:"folders"`
}

// This is what the structure should be when it's sent into a workflow
type ParsedShuffleMail struct {
	Body struct {
		URI           []string `json:"uri"`
		Email         []string `json:"email"`
		Domain        []string `json:"domain"`
		ContentHeader struct {
		} `json:"content_header"`
		Content     string `json:"content"`
		ContentType string `json:"content_type"`
		Hash        string `json:"hash"`
		RawBody     string `json:"raw_body"`
	} `json:"body"`
	Header struct {
		Subject  string   `json:"subject"`
		From     string   `json:"from"`
		To       []string `json:"to"`
		Date     string   `json:"date"`
		Received []struct {
			Src  string   `json:"src"`
			From []string `json:"from"`
			By   []string `json:"by"`
			With string   `json:"with"`
			Date string   `json:"date"`
		} `json:"received"`
		ReceivedDomain []string `json:"received_domain"`
		ReceivedIP     []string `json:"received_ip"`
		Header         struct {
		} `json:"header"`
	} `json:"header"`
	MessageID      string   `json:"message_id"`
	EmailFileid    string   `json:"email_fileid"`
	AttachmentUids []string `json:"attachment_uids"`
}

type FullEmail struct {
	OdataContext               string        `json:"@odata.context"`
	OdataEtag                  string        `json:"@odata.etag"`
	ID                         string        `json:"id"`
	Createddatetime            time.Time     `json:"createdDateTime"`
	Lastmodifieddatetime       time.Time     `json:"lastModifiedDateTime"`
	Changekey                  string        `json:"changeKey"`
	Categories                 []interface{} `json:"categories"`
	Receiveddatetime           time.Time     `json:"receivedDateTime"`
	Sentdatetime               time.Time     `json:"sentDateTime"`
	Hasattachments             bool          `json:"hasAttachments"`
	Internetmessageid          string        `json:"internetMessageId"`
	Subject                    string        `json:"subject"`
	Bodypreview                string        `json:"bodyPreview"`
	Importance                 string        `json:"importance"`
	Parentfolderid             string        `json:"parentFolderId"`
	Conversationid             string        `json:"conversationId"`
	Conversationindex          string        `json:"conversationIndex"`
	Isdeliveryreceiptrequested interface{}   `json:"isDeliveryReceiptRequested"`
	Isreadreceiptrequested     bool          `json:"isReadReceiptRequested"`
	Isread                     bool          `json:"isRead"`
	Isdraft                    bool          `json:"isDraft"`
	Weblink                    string        `json:"webLink"`
	Inferenceclassification    string        `json:"inferenceClassification"`
	Body                       struct {
		Contenttype string `json:"contentType"`
		Content     string `json:"content"`
	} `json:"body"`
	Sender struct {
		Emailaddress struct {
			Name    string `json:"name"`
			Address string `json:"address"`
		} `json:"emailAddress"`
	} `json:"sender"`
	From struct {
		Emailaddress struct {
			Name    string `json:"name"`
			Address string `json:"address"`
		} `json:"emailAddress"`
	} `json:"from"`
	Torecipients []struct {
		Emailaddress struct {
			Name    string `json:"name"`
			Address string `json:"address"`
		} `json:"emailAddress"`
	} `json:"toRecipients"`
	Ccrecipients  []interface{} `json:"ccRecipients"`
	Bccrecipients []interface{} `json:"bccRecipients"`
	Replyto       []interface{} `json:"replyTo"`
	Flag          struct {
		Flagstatus string `json:"flagStatus"`
	} `json:"flag"`
	Attachments []struct {
		OdataType             string      `json:"@odata.type"`
		OdataMediacontenttype string      `json:"@odata.mediaContentType"`
		ID                    string      `json:"id"`
		Lastmodifieddatetime  time.Time   `json:"lastModifiedDateTime"`
		Name                  string      `json:"name"`
		Contenttype           string      `json:"contentType"`
		Size                  int         `json:"size"`
		Isinline              bool        `json:"isInline"`
		Contentid             interface{} `json:"contentId"`
		Contentlocation       interface{} `json:"contentLocation"`
		Contentbytes          string      `json:"contentBytes"`
	} `json:"attachments"`
	FileIds []string `json:"file_ids"`
}

type OutlookAttachment struct {
	OdataContext          string      `json:"@odata.context"`
	OdataType             string      `json:"@odata.type"`
	OdataMediaContentType string      `json:"@odata.mediaContentType"`
	ID                    string      `json:"id"`
	LastModifiedDateTime  time.Time   `json:"lastModifiedDateTime"`
	Name                  string      `json:"name"`
	ContentType           string      `json:"contentType"`
	Size                  int         `json:"size"`
	IsInline              bool        `json:"isInline"`
	ContentID             interface{} `json:"contentId"`
	ContentLocation       interface{} `json:"contentLocation"`
	ContentBytes          string      `json:"contentBytes"`
}

type MailDataOutlookList struct {
	OdataContext string `json:"@odata.context"`
	Value        []struct {
		OdataType             string      `json:"@odata.type"`
		OdataMediaContentType string      `json:"@odata.mediaContentType"`
		ID                    string      `json:"id"`
		LastModifiedDateTime  time.Time   `json:"lastModifiedDateTime"`
		Name                  string      `json:"name"`
		ContentType           string      `json:"contentType"`
		Size                  int         `json:"size"`
		IsInline              bool        `json:"isInline"`
		ContentID             interface{} `json:"contentId"`
		ContentLocation       interface{} `json:"contentLocation"`
		ContentBytes          string      `json:"contentBytes"`
	} `json:"value"`
}

type MailDataOutlook struct {
	Value []struct {
		Subscriptionid                 string `json:"subscriptionId"`
		Subscriptionexpirationdatetime string `json:"subscriptionExpirationDateTime"`
		Changetype                     string `json:"changeType"`
		Resource                       string `json:"resource"`
		Resourcedata                   struct {
			OdataType string `json:"@odata.type"`
			OdataID   string `json:"@odata.id"`
			OdataEtag string `json:"@odata.etag"`
			ID        string `json:"id"`
		} `json:"resourceData"`
		Clientstate string `json:"clientState"`
		Tenantid    string `json:"tenantId"`
	} `json:"value"`
}

type OutlookProfile struct {
	OdataContext      string      `json:"@odata.context"`
	BusinessPhones    []string    `json:"businessPhones"`
	DisplayName       string      `json:"displayName"`
	GivenName         string      `json:"givenName"`
	JobTitle          interface{} `json:"jobTitle"`
	Mail              string      `json:"mail"`
	MobilePhone       interface{} `json:"mobilePhone"`
	OfficeLocation    interface{} `json:"officeLocation"`
	PreferredLanguage interface{} `json:"preferredLanguage"`
	Surname           string      `json:"surname"`
	UserPrincipalName string      `json:"userPrincipalName"`
	ID                string      `json:"id"`
}

type GmailLabels struct {
	Labels []GmailLabel `json:"labels"`
}

type GmailLabel struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	MessageListVisibility string `json:"messageListVisibility"`
	LabelListVisibility   string `json:"labelListVisibility"`
	Type                  string `json:"type"`
}

type OutlookFolder struct {
	ID               string `json:"id"`
	DisplayName      string `json:"displayName"`
	ParentFolderID   string `json:"parentFolderId"`
	ChildFolderCount int    `json:"childFolderCount"`
	UnreadItemCount  int    `json:"unreadItemCount"`
	TotalItemCount   int    `json:"totalItemCount"`
}

type OutlookFolders struct {
	OdataContext  string          `json:"@odata.context"`
	OdataNextLink string          `json:"@odata.nextLink"`
	Value         []OutlookFolder `json:"value"`
}

type StatisticsData struct {
	Timestamp int64  `json:"timestamp" datastore:"timestamp"`
	Id        string `json:"id" datastore:"id"`
	Amount    int64  `json:"amount" datastore:"amount"`
}

type StatisticsItem struct {
	Total     int64            `json:"total" datastore:"total"`
	Fieldname string           `json:"field_name" datastore:"field_name"`
	Data      []StatisticsData `json:"data" datastore:"data"`
	OrgId     string           `json:"org_id" datastore:"org_id"`
}

type HealthCheckSearchWrapper struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string        `json:"_index"`
			Type   string        `json:"_type"`
			ID     string        `json:"_id"`
			Score  float64       `json:"_score"`
			Source HealthCheckDB `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type NewValueSearchWrapper struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string   `json:"_index"`
			Type   string   `json:"_type"`
			ID     string   `json:"_id"`
			Score  float64  `json:"_score"`
			Source NewValue `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type ExecutionInfoWrapper struct {
	Index       string        `json:"_index"`
	Type        string        `json:"_type"`
	ID          string        `json:"_id"`
	Version     int           `json:"_version"`
	SeqNo       int           `json:"_seq_no"`
	PrimaryTerm int           `json:"_primary_term"`
	Found       bool          `json:"found"`
	Source      ExecutionInfo `json:"_source"`
}

type EnvironentSearchWrapper struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string      `json:"_index"`
			Type   string      `json:"_type"`
			ID     string      `json:"_id"`
			Score  float64     `json:"_score"`
			Source Environment `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type OpenseaAssetSearchWrapper struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string       `json:"_index"`
			Type   string       `json:"_type"`
			ID     string       `json:"_id"`
			Score  float64      `json:"_score"`
			Source OpenseaAsset `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type ExecutionSearchWrapper struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string            `json:"_index"`
			Type   string            `json:"_type"`
			ID     string            `json:"_id"`
			Score  float64           `json:"_score"`
			Source WorkflowExecution `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type OrgSearchWrapper struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string  `json:"_index"`
			Type   string  `json:"_type"`
			ID     string  `json:"_id"`
			Score  float64 `json:"_score"`
			Source Org     `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type AppSearchWrapper struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string      `json:"_index"`
			Type   string      `json:"_type"`
			ID     string      `json:"_id"`
			Score  float64     `json:"_score"`
			Source WorkflowApp `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type ScheduleSearchWrapper struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string      `json:"_index"`
			Type   string      `json:"_type"`
			ID     string      `json:"_id"`
			Score  float64     `json:"_score"`
			Source ScheduleOld `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type NotificationSearchWrapper struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string       `json:"_index"`
			Type   string       `json:"_type"`
			ID     string       `json:"_id"`
			Score  float64      `json:"_score"`
			Source Notification `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type FileSearchWrapper struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string  `json:"_index"`
			Type   string  `json:"_type"`
			ID     string  `json:"_id"`
			Score  float64 `json:"_score"`
			Source File    `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type WorkflowSearchWrapper struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string   `json:"_index"`
			Type   string   `json:"_type"`
			ID     string   `json:"_id"`
			Score  float64  `json:"_score"`
			Source Workflow `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type EnvironmentSearchWrapper struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string      `json:"_index"`
			Type   string      `json:"_type"`
			ID     string      `json:"_id"`
			Score  float64     `json:"_score"`
			Source Environment `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type ExecRequestSearchWrapper struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string           `json:"_index"`
			Type   string           `json:"_type"`
			ID     string           `json:"_id"`
			Score  float64          `json:"_score"`
			Source ExecutionRequest `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type AppAuthSearchWrapper struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string                   `json:"_index"`
			Type   string                   `json:"_type"`
			ID     string                   `json:"_id"`
			Score  float64                  `json:"_score"`
			Source AppAuthenticationStorage `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type UserSearchWrapper struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string  `json:"_index"`
			Type   string  `json:"_type"`
			ID     string  `json:"_id"`
			Score  float64 `json:"_score"`
			Source User    `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type SessionWrapper struct {
	Index       string  `json:"_index"`
	Type        string  `json:"_type"`
	ID          string  `json:"_id"`
	Version     int     `json:"_version"`
	SeqNo       int     `json:"_seq_no"`
	PrimaryTerm int     `json:"_primary_term"`
	Found       bool    `json:"found"`
	Source      Session `json:"_source"`
}

// Used for Gmail triggers using Pubsub
type SubscriptionRecipient struct {
	HistoryId    string `json:"history_id"`
	TriggerId    string `json:"trigger_id"`
	Edited       int    `json:"edited"`
	Expiration   string `json:"expiration"`
	LastSync     int    `json:"last_sync"`
	WorkflowId   string `json:"workflow_id`
	Startnode    string `json:"startnode`
	IsCloud      bool   `json:"is_cloud"`
	EmailAddress string `json:"email_address"`
}

type GmailProfile struct {
	EmailAddress  string `json:"emailAddress"`
	MessagesTotal int    `json:"messagesTotal"`
	ThreadsTotal  int    `json:"threadsTotal"`
	HistoryId     string `json:"historyId"`
}

type SubResponse struct {
	HistoryId  string `json:"historyId"`
	Expiration string `json:"expiration`
}

type AllTriggersWrapper struct {
	Pipelines []Pipeline `json:"pipelines"`
	WebHooks   []Hook `json:"webhooks"`
	Schedules []ScheduleOld `json:"schedules"`
}

type SubWrapper struct {
	Index       string                `json:"_index"`
	Type        string                `json:"_type"`
	ID          string                `json:"_id"`
	Version     int                   `json:"_version"`
	SeqNo       int                   `json:"_seq_no"`
	PrimaryTerm int                   `json:"_primary_term"`
	Found       bool                  `json:"found"`
	Source      SubscriptionRecipient `json:"_source"`
}

type EnvWrapper struct {
	Index       string      `json:"_index"`
	Type        string      `json:"_type"`
	ID          string      `json:"_id"`
	Version     int         `json:"_version"`
	SeqNo       int         `json:"_seq_no"`
	PrimaryTerm int         `json:"_primary_term"`
	Found       bool        `json:"found"`
	Source      Environment `json:"_source"`
}

type AuthGroupWrapper struct {
	Index       string   `json:"_index"`
	Type        string   `json:"_type"`
	ID          string   `json:"_id"`
	Version     int      `json:"_version"`
	SeqNo       int      `json:"_seq_no"`
	PrimaryTerm int      `json:"_primary_term"`
	Found       bool     `json:"found"`
	Source      AppAuthenticationGroup `json:"_source"`
}

type WorkflowWrapper struct {
	Index       string   `json:"_index"`
	Type        string   `json:"_type"`
	ID          string   `json:"_id"`
	Version     int      `json:"_version"`
	SeqNo       int      `json:"_seq_no"`
	PrimaryTerm int      `json:"_primary_term"`
	Found       bool     `json:"found"`
	Source      Workflow `json:"_source"`
}

type UsecaseWrapper struct {
	Index       string  `json:"_index"`
	Type        string  `json:"_type"`
	ID          string  `json:"_id"`
	Version     int     `json:"_version"`
	SeqNo       int     `json:"_seq_no"`
	PrimaryTerm int     `json:"_primary_term"`
	Found       bool    `json:"found"`
	Source      Usecase `json:"_source"`
}

type AppWrapper struct {
	Index       string      `json:"_index"`
	Type        string      `json:"_type"`
	ID          string      `json:"_id"`
	Version     int         `json:"_version"`
	SeqNo       int         `json:"_seq_no"`
	PrimaryTerm int         `json:"_primary_term"`
	Found       bool        `json:"found"`
	Source      WorkflowApp `json:"_source"`
}

type OpenseaAssetWrapper struct {
	Index       string       `json:"_index"`
	Type        string       `json:"_type"`
	ID          string       `json:"_id"`
	Version     int          `json:"_version"`
	SeqNo       int          `json:"_seq_no"`
	PrimaryTerm int          `json:"_primary_term"`
	Found       bool         `json:"found"`
	Source      OpenseaAsset `json:"_source"`
}

type ExecWrapper struct {
	Index       string            `json:"_index"`
	Type        string            `json:"_type"`
	ID          string            `json:"_id"`
	Version     int               `json:"_version"`
	SeqNo       int               `json:"_seq_no"`
	PrimaryTerm int               `json:"_primary_term"`
	Found       bool              `json:"found"`
	Source      WorkflowExecution `json:"_source"`
}

type OrgWrapper struct {
	Index       string `json:"_index"`
	Type        string `json:"_type"`
	ID          string `json:"_id"`
	Version     int    `json:"_version"`
	SeqNo       int    `json:"_seq_no"`
	PrimaryTerm int    `json:"_primary_term"`
	Found       bool   `json:"found"`
	Source      Org    `json:"_source"`
}

type TriggerAuthWrapper struct {
	Index       string      `json:"_index"`
	Type        string      `json:"_type"`
	ID          string      `json:"_id"`
	Version     int         `json:"_version"`
	SeqNo       int         `json:"_seq_no"`
	PrimaryTerm int         `json:"_primary_term"`
	Found       bool        `json:"found"`
	Source      TriggerAuth `json:"_source"`
}

type AppAuthWrapper struct {
	Index       string                   `json:"_index"`
	Type        string                   `json:"_type"`
	ID          string                   `json:"_id"`
	Version     int                      `json:"_version"`
	SeqNo       int                      `json:"_seq_no"`
	PrimaryTerm int                      `json:"_primary_term"`
	Found       bool                     `json:"found"`
	Source      AppAuthenticationStorage `json:"_source"`
}

type NotificationWrapper struct {
	Index       string       `json:"_index"`
	Type        string       `json:"_type"`
	ID          string       `json:"_id"`
	Version     int          `json:"_version"`
	SeqNo       int          `json:"_seq_no"`
	PrimaryTerm int          `json:"_primary_term"`
	Found       bool         `json:"found"`
	Source      Notification `json:"_source"`
}

type FileWrapper struct {
	Index       string `json:"_index"`
	Type        string `json:"_type"`
	ID          string `json:"_id"`
	Version     int    `json:"_version"`
	SeqNo       int    `json:"_seq_no"`
	PrimaryTerm int    `json:"_primary_term"`
	Found       bool   `json:"found"`
	Source      File   `json:"_source"`
}

type HookWrapper struct {
	Index       string `json:"_index"`
	Type        string `json:"_type"`
	ID          string `json:"_id"`
	Version     int    `json:"_version"`
	SeqNo       int    `json:"_seq_no"`
	PrimaryTerm int    `json:"_primary_term"`
	Found       bool   `json:"found"`
	Source      Hook   `json:"_source"`
}

type AllHooksWrapper struct {
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		Hits     []struct {
			Index  string  `json:"_index"`
			ID     string  `json:"_id"`
			Score  float64 `json:"_score"`
			Source Hook `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type ScheduleWrapper struct {
	Index       string      `json:"_index"`
	Type        string      `json:"_type"`
	ID          string      `json:"_id"`
	Version     int         `json:"_version"`
	SeqNo       int         `json:"_seq_no"`
	PrimaryTerm int         `json:"_primary_term"`
	Found       bool        `json:"found"`
	Source      ScheduleOld `json:"_source"`
}

type ParsedApiWrapper struct {
	Index       string        `json:"_index"`
	Type        string        `json:"_type"`
	ID          string        `json:"_id"`
	Version     int           `json:"_version"`
	SeqNo       int           `json:"_seq_no"`
	PrimaryTerm int           `json:"_primary_term"`
	Found       bool          `json:"found"`
	Source      ParsedOpenApi `json:"_source"`
}

type ExecRequestWrapper struct {
	Index       string           `json:"_index"`
	Type        string           `json:"_type"`
	ID          string           `json:"_id"`
	Version     int              `json:"_version"`
	SeqNo       int              `json:"_seq_no"`
	PrimaryTerm int              `json:"_primary_term"`
	Found       bool             `json:"found"`
	Source      ExecutionRequest `json:"_source"`
}

type UserWrapper struct {
	Index       string `json:"_index"`
	Type        string `json:"_type"`
	ID          string `json:"_id"`
	Version     int    `json:"_version"`
	SeqNo       int    `json:"_seq_no"`
	PrimaryTerm int    `json:"_primary_term"`
	Found       bool   `json:"found"`
	Source      User   `json:"_source"`
}

type CacheKeyWrapper struct {
	Index       string       `json:"_index"`
	Type        string       `json:"_type"`
	ID          string       `json:"_id"`
	Version     int          `json:"_version"`
	SeqNo       int          `json:"_seq_no"`
	PrimaryTerm int          `json:"_primary_term"`
	Found       bool         `json:"found"`
	Source      CacheKeyData `json:"_source"`
}

type GithubAuthor struct {
	Name     string `json:"name"`
	Url      string `json:"url"`
	ImageUrl string `json:"image"`
}

type GithubResp struct {
	Name         string         `json:"name"`
	Contributors []GithubAuthor `json:"contributors"`
	Edited       string         `json:"edited"`
	ReadTime     int            `json:"read_time"`
	Link         string         `json:"link"`
}

type FileList struct {
	Success bool         `json:"success"`
	Reason  string       `json:"reason"`
	List    []GithubResp `json:"list"`
}

type SessionCookie struct {
	Key        string `json:"key"`
	Value      string `json:"value"`
	Expiration int64  `json:"expiration"`
}

type Tutorial struct {
	Name        string `json:"name" datastore:"name"`
	Description string `json:"description" datastore:"description"`
	Link        string `json:"link" datastore:"link"`
	Done        bool   `json:"done" datastore:"done"`
	Active      bool   `json:"active" datastore:"active"`
}

type HandleInfo struct {
	Success            bool            `json:"success"`
	Admin              string          `json:"admin"`
	Username           string          `json:"username"`
	PublicUsername     string          `json:"public_username"`
	Name               string          `json:"name"`
	ActiveApps         []string        `json:"active_apps"`
	Id                 string          `json:"id"`
	Avatar             string          `json:"avatar"`
	Orgs               []OrgMini       `json:"orgs"`
	ActiveOrg          OrgMini         `json:"active_org"`
	EthInfo            EthInfo         `json:"eth_info,omitempty"`
	ChatDisabled       bool            `json:"chat_disabled"`
	Priorities         []Priority      `json:"priorities"`
	Cookies            []SessionCookie `json:"cookies"`
	AppExecutionsLimit int64           `json:"app_execution_limit"`
	AppExecutionsUsage int64           `json:"app_execution_usage"`
	RegionUrl          string          `json:"region_url"`
	Support            bool            `json:"support"`
	Tutorials          []Tutorial      `json:"tutorials"`
	OrgStatus          []string        `json:"org_status"`

	HasCardAvailable    bool `json:"has_card_available,omitempty"`
	ActivatedPayasyougo bool `json:"activated_pay_as_you_go,omitempty"`
	Licensed            bool `json:"licensed"`
}

//Cookies      []SessionCookie `json:"session_cookie"`

type BuildLaterStruct struct {
	Tags  []string
	Extra string
	Id    string
}

// Overwriting results fo a subflow trigger
type SubflowData struct {
	Success       bool   `json:"success"`
	ExecutionId   string `json:"execution_id,omitempty"`
	Authorization string `json:"authorization,omitempty"`
	Result        string `json:"result"`
	ResultSet     bool   `json:"result_set,omitempty"`
}

// AuthenticationStore with oauth2
type Oauth2Resp struct {
	AccessToken  string `json:"access_token" url:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token" url:"refresh_token,omitempty"`
	TokenType    string `json:"token_type" url:"token_type,omitempty"`
	Scope        string `json:"scope" url:"scope,omitempty"`
	ExpiresIn    int    `json:"expires_in" url:"expires_in,omitempty"`
	ExtExpiresIn int    `json:"ext_expires_in" url:"ext_expires_in,omitempty"`
}

type OpenidUserinfo struct {
	Sub string `json:"sub"`
}

type OpenidResp struct {
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	ExtExpiresIn int    `json:"ext_expires_in"`
}

type AuthorizationCode struct {
	AuthorizationUrl string   `json:"authorizationUrl"`
	RefreshUrl       string   `json:"refreshUrl"`
	Scopes           []string `json:"scopes"`
	TokenUrl         string   `json:"tokenUrl"`
}

type Oauth2Openapi struct {
	AuthorizationCode AuthorizationCode `json:"authorizationCode"`
}

// The data to be parsed
type DataToSend struct {
	Code         string `json:"code"  datastore:"code" url:"code,omitempty"`
	GrantType    string `json:"grant_type"  datastore:"grant_type" url:"grant_type,omitempty"`
	ClientSecret string `json:"client_secret"  datastore:"client_secret" url:"client_secret,omitempty"`
	ClientId     string `json:"client_id"  datastore:"client_id" url:"client_id,omitempty"`
	Scope        string `json:"scope"  datastore:"scope" url:"scope,omitempty"`
	RedirectUri  string `json:"redirect_uri" datastore:"id" url:"redirect_uri,omitempty"`
	Name         string `json:"name,omitempty"  datastore:"name" url:"name,omitempty"`
	Id           string `json:"id,omitempty" datastore:"id" url:"id,omitempty"`
	Resource     string `json:"resource,omitempty" datastore:"resource" url:"resource,omitempty"`
}

type BaseFile struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	Type      string `json:"type"`
	UpdatedAt int64  `json:"updated_at"`
	Md5Sum    string `json:"md5_sum"`
	Status    string `json:"status"`
	FileSize  int64  `json:"filesize"`
}

type FileResponse struct {
	Success    bool       `json:"success" datastore:"success"`
	Files      []File     `json:"files,omitempty" datastore:"files"`
	Namespaces []string   `json:"namespaces,omitempty" datastore:"namespaces"`
	List       []BaseFile `json:"list,omitempty" datastore:"list"`
}

type SSOConfig struct {
	SSOEntrypoint       string `json:"sso_entrypoint" datastore:"sso_entrypoint"`
	SSOCertificate      string `json:"sso_certificate" datastore:"sso_certificate"`
	OpenIdClientId      string `json:"client_id" datastore:"client_id"`
	OpenIdClientSecret  string `json:"client_secret" datastore:"client_secret"`
	OpenIdAuthorization string `json:"openid_authorization" datastore:"openid_authorization"`
	OpenIdToken         string `json:"openid_token" datastore:"openid_token"`
	SSORequired         bool   `json:"SSORequired" datastore:"SSORequired"`
}

type SamlRequest struct {
	XMLName                     xml.Name `xml:"AuthnRequest"`
	Text                        string   `xml:",chardata"`
	Samlp                       string   `xml:"samlp,attr"`
	Xmlns                       string   `xml:"xmlns,attr"`
	Saml                        string   `xml:"saml,attr"`
	AssertionConsumerServiceURL string   `xml:"AssertionConsumerServiceURL,attr"`
	Destination                 string   `xml:"Destination,attr"`
	ForceAuthn                  string   `xml:"ForceAuthn,attr"`
	ID                          string   `xml:"ID,attr"`
	IssueInstant                string   `xml:"IssueInstant,attr"`
	ProtocolBinding             string   `xml:"ProtocolBinding,attr"`
	Version                     string   `xml:"Version,attr"`
	Issuer                      string   `xml:"Issuer"`
	NameIDPolicy                struct {
		Text        string `xml:",chardata"`
		AllowCreate string `xml:"AllowCreate,attr"`
		Format      string `xml:"Format,attr"`
	} `xml:"NameIDPolicy"`
}

type SAMLResponse struct {
	XMLName      xml.Name `xml:"Response"`
	Text         string   `xml:",chardata"`
	Destination  string   `xml:"Destination,attr"`
	ID           string   `xml:"ID,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Version      string   `xml:"Version,attr"`
	Saml2p       string   `xml:"saml2p,attr"`
	Issuer       struct {
		Text   string `xml:",chardata"`
		Format string `xml:"Format,attr"`
		Saml2  string `xml:"saml2,attr"`
	} `xml:"Issuer"`
	Signature struct {
		Text       string `xml:",chardata"`
		Ds         string `xml:"ds,attr"`
		SignedInfo struct {
			Text                   string `xml:",chardata"`
			CanonicalizationMethod struct {
				Text      string `xml:",chardata"`
				Algorithm string `xml:"Algorithm,attr"`
			} `xml:"CanonicalizationMethod"`
			SignatureMethod struct {
				Text      string `xml:",chardata"`
				Algorithm string `xml:"Algorithm,attr"`
			} `xml:"SignatureMethod"`
			Reference struct {
				Text       string `xml:",chardata"`
				URI        string `xml:"URI,attr"`
				Transforms struct {
					Text      string `xml:",chardata"`
					Transform []struct {
						Text      string `xml:",chardata"`
						Algorithm string `xml:"Algorithm,attr"`
					} `xml:"Transform"`
				} `xml:"Transforms"`
				DigestMethod struct {
					Text      string `xml:",chardata"`
					Algorithm string `xml:"Algorithm,attr"`
				} `xml:"DigestMethod"`
				DigestValue string `xml:"DigestValue"`
			} `xml:"Reference"`
		} `xml:"SignedInfo"`
		SignatureValue string `xml:"SignatureValue"`
		KeyInfo        struct {
			Text     string `xml:",chardata"`
			X509Data struct {
				Text            string `xml:",chardata"`
				X509Certificate string `xml:"X509Certificate"`
			} `xml:"X509Data"`
		} `xml:"KeyInfo"`
	} `xml:"Signature"`
	Status struct {
		Text       string `xml:",chardata"`
		Saml2p     string `xml:"saml2p,attr"`
		StatusCode struct {
			Text  string `xml:",chardata"`
			Value string `xml:"Value,attr"`
		} `xml:"StatusCode"`
	} `xml:"Status"`
	Assertion struct {
		Text         string `xml:",chardata"`
		ID           string `xml:"ID,attr"`
		IssueInstant string `xml:"IssueInstant,attr"`
		Version      string `xml:"Version,attr"`
		Saml2        string `xml:"saml2,attr"`
		Issuer       struct {
			Text   string `xml:",chardata"`
			Format string `xml:"Format,attr"`
			Saml2  string `xml:"saml2,attr"`
		} `xml:"Issuer"`
		Signature struct {
			Text       string `xml:",chardata"`
			Ds         string `xml:"ds,attr"`
			SignedInfo struct {
				Text                   string `xml:",chardata"`
				CanonicalizationMethod struct {
					Text      string `xml:",chardata"`
					Algorithm string `xml:"Algorithm,attr"`
				} `xml:"CanonicalizationMethod"`
				SignatureMethod struct {
					Text      string `xml:",chardata"`
					Algorithm string `xml:"Algorithm,attr"`
				} `xml:"SignatureMethod"`
				Reference struct {
					Text       string `xml:",chardata"`
					URI        string `xml:"URI,attr"`
					Transforms struct {
						Text      string `xml:",chardata"`
						Transform []struct {
							Text      string `xml:",chardata"`
							Algorithm string `xml:"Algorithm,attr"`
						} `xml:"Transform"`
					} `xml:"Transforms"`
					DigestMethod struct {
						Text      string `xml:",chardata"`
						Algorithm string `xml:"Algorithm,attr"`
					} `xml:"DigestMethod"`
					DigestValue string `xml:"DigestValue"`
				} `xml:"Reference"`
			} `xml:"SignedInfo"`
			SignatureValue string `xml:"SignatureValue"`
			KeyInfo        struct {
				Text     string `xml:",chardata"`
				X509Data struct {
					Text            string `xml:",chardata"`
					X509Certificate string `xml:"X509Certificate"`
				} `xml:"X509Data"`
			} `xml:"KeyInfo"`
		} `xml:"Signature"`
		Subject struct {
			Text   string `xml:",chardata"`
			Saml2  string `xml:"saml2,attr"`
			NameID struct {
				Text   string `xml:",chardata"`
				Format string `xml:"Format,attr"`
			} `xml:"NameID"`
			SubjectConfirmation struct {
				Text                    string `xml:",chardata"`
				Method                  string `xml:"Method,attr"`
				SubjectConfirmationData struct {
					Text         string `xml:",chardata"`
					NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
					Recipient    string `xml:"Recipient,attr"`
				} `xml:"SubjectConfirmationData"`
			} `xml:"SubjectConfirmation"`
		} `xml:"Subject"`
		Conditions struct {
			Text                string `xml:",chardata"`
			NotBefore           string `xml:"NotBefore,attr"`
			NotOnOrAfter        string `xml:"NotOnOrAfter,attr"`
			Saml2               string `xml:"saml2,attr"`
			AudienceRestriction struct {
				Text     string `xml:",chardata"`
				Audience string `xml:"Audience"`
			} `xml:"AudienceRestriction"`
		} `xml:"Conditions"`
		AuthnStatement struct {
			Text         string `xml:",chardata"`
			AuthnInstant string `xml:"AuthnInstant,attr"`
			SessionIndex string `xml:"SessionIndex,attr"`
			Saml2        string `xml:"saml2,attr"`
			AuthnContext struct {
				Text                 string `xml:",chardata"`
				AuthnContextClassRef string `xml:"AuthnContextClassRef"`
			} `xml:"AuthnContext"`
		} `xml:"AuthnStatement"`
	} `xml:"Assertion"`
}

type WrappedData struct {
	Data        string `json:"data"`
	MessageId   string `json:"message_id"`
	PublishTime string `json:"publish_time"`
}

type Inputdata struct {
	Message      WrappedData `json:"message"`
	Subscription string      `json:"subscription"`
}

type ParsedMessage struct {
	EmailAddress string `json:"emailAddress"`
	HistoryId    int    `json:"historyId"`
	MessageId    string `json:"messageId"`
}

type NotificationResponse struct {
	Success       bool           `json:"success"`
	Notifications []Notification `json:"notifications"`
}

type GmailMessagesStruct struct {
	Messages []struct {
		ID       string `json:"id"`
		ThreadID string `json:"threadId"`
	} `json:"messages"`
	NextPageToken      string `json:"nextPageToken"`
	ResultSizeEstimate int    `json:"resultSizeEstimate"`
}

type MessageAddedMessage struct {
	ID       string   `json:"id"`
	ThreadID string   `json:"threadId"`
	LabelIds []string `json:"labelIds"`
}

type MessageAdded struct {
	Message MessageAddedMessage `json:"message"`
}

type GmailHistoryStruct struct {
	History []struct {
		ID       string `json:"id"`
		Messages []struct {
			ID       string `json:"id"`
			ThreadID string `json:"threadId"`
		} `json:"messages"`
		MessagesDeleted []struct {
			Message struct {
				ID       string   `json:"id"`
				ThreadID string   `json:"threadId"`
				LabelIds []string `json:"labelIds"`
			} `json:"message"`
		} `json:"messagesDeleted,omitempty"`
		MessagesAdded []MessageAdded `json:"messagesAdded,omitempty"`
	} `json:"history"`
	HistoryID string `json:"historyId"`
}

type GmailThreadStruct struct {
	ID        string               `json:"id"`
	HistoryID string               `json:"historyId"`
	Messages  []GmailMessageStruct `json:"messages"`
}

type GmailMessageStruct struct {
	ID       string   `json:"id"`
	ThreadID string   `json:"threadId"`
	LabelIds []string `json:"labelIds"`
	Snippet  string   `json:"snippet"`
	Payload  struct {
		PartID       string `json:"partId"`
		MessageID    string `json:"message_id"`
		MimeType     string `json:"mimeType"`
		Filename     string `json:"filename"`
		FileMimeType string `json:"file_mimetype"`
		Sender       string `json:"sender"`
		Subject      string `json:"subject"`
		Recipient    string `json:"recipient"`
		ParsedBody   string `json:"parsed_body"`
		Headers      []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"headers"`
		Body struct {
			Size int `json:"size"`
		} `json:"body"`
		Parts []struct {
			PartID   string `json:"partId"`
			MimeType string `json:"mimeType"`
			Filename string `json:"filename"`
			Headers  []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"headers"`
			Body struct {
				AttachmentID string `json:"attachmentId"`
				Size         int    `json:"size"`
				Data         string `json:"data"`
			} `json:"body"`
		} `json:"parts"`
	} `json:"payload"`
	SizeEstimate int      `json:"sizeEstimate"`
	HistoryID    string   `json:"historyId"`
	InternalDate string   `json:"internalDate"`
	FileIds      []string `json:"file_ids"`
	Type         string   `json:"type"`
}

type GmailAttachment struct {
	Size int    `json:"size"`
	Data string `json:"data"`
}

type MdmMeta struct {
	CanonicalId   string `json:"canonical_id"`
	CreatedAt     string `json:"created_at"`
	Id            string `json:"id"`
	SchemaVersion string `json:"schema_version"`
}

type MdmAttachment struct {
	ContentTransferEncoding string `json:"content_transfer_encoding"`
	ContentType             string `json:"content_type"`
	FileExtension           string `json:"file_extension"`
	FileName                string `json:"file_name"`
	Filetype                string `json:"file_type"`
	Raw                     string `json:"raw"`
	Size                    int    `json:"size"`
}

type MdmBody struct {
	Html  MdmHtml   `json:"html"`
	IPs   []MdmIP   `json:"ips"`
	Links []MdmLink `json:"links"`
	Plain MdmPlain  `json:"_errors"`
}

type MdmHtml struct {
	Charset                 string `json:"_errors"`
	ContentTransferEncoding string `json:"_errors"`
	Raw                     string `json:"_errors"`
}

type MdmPlain struct {
	Charset                 string `json:"_errors"`
	ContentTransferEncoding string `json:"_errors"`
	Raw                     string `json:"_errors"`
}

type MdmExternal struct {
}
type MdmHeaders struct {
}
type MdmMailbox struct {
}
type MdmRecipients struct {
}
type MdmSubject struct {
}
type MdmSender struct {
}
type MdmType struct {
}

type MdmDisplayUrl struct {
}

// TBD
type MdmIP struct {
	IP string `json:"ip"`
}

// TBD
type MdmLink struct {
	DisplayText string        `json:"ip"`
	DisplayUrl  MdmDisplayUrl `json:"ip"`
}

/*
type MessageDataModel struct {
	Errors      []string        `json:"_errors"`
	Meta        MdmMeta         `json:"attachments"`
	Attachments []MdmAttachment `json:"_meta"`
	Body        MdmBody         `json:"body"`
	External    MdmExternal     `json:"external"`
	Headers     MdmHeaders      `json:"headers"`
	Mailbox     MdmMailbox      `json:"mailbox"`
	Recipients  MdmRecipients   `json:"recipients"`
	Sender      MdmSender       `json:"sender"`
	Subject     MdmSubject      `json:"subject"`
	Type        MdmType         `json:"type"`
}
*/

type ExecInfo struct {
	OnpremExecution bool
	CloudExec       bool
	Environments    []string
	ImageNames      []string
}

type ResultChecker struct {
	Success bool   `json:"success"`
	Reason  string `json:"reason"`
	Extra   string `json:"extra,omitempty"`
}

type Metadata struct {
	ID            string    `description:"Message ID" json:"id" format:"uuid4" validate:"required,uuid4"`
	CanonicalID   string    `description:"An ID that can be used to group similar messages/campaigns together" json:"canonical_id" validate:"required"`
	CreatedAt     time.Time `description:"Creation time of the data model" json:"created_at" format:"date-time" validate:"required"`
	SchemaVersion string    `description:"Schema version number" json:"schema_version" validate:"required"`
}

type MessageDataModel struct {
	Attachments []Attachment        `description:"Attachments" json:"attachments,omitempty" validate:"omitempty"`
	Body        *Body               `description:"Body of the email" json:"body,omitempty" validate:"omitempty"`
	External    *External           `description:"Cloud API provider or other external source metadata" json:"external,omitempty" validate:"omitempty"`
	Headers     Headers             `description:"The message headers" json:"headers" validate:"required"`
	Type        MessageType         `description:"The types of the message from the perspective of the message source" json:"type" validate:"required"`
	Mailbox     *Mailbox            `description:"The mailbox we retrieved the message from" json:"mailbox,omitempty" validate:"omitempty"`
	Recipients  Recipients          `description:"Recipient objects" json:"recipients" validate:"required"`
	Sender      Mailbox             `description:"Sender object" json:"sender" validate:"required"`
	Subject     *Subject            `description:"Subject object" json:"subject,omitempty" validate:"omitempty"`
	Meta        Metadata            `description:"Metadata" json:"_meta" validate:"required"`
	Errors      []map[string]string `description:"Non-fatal errors while parsing MDM" json:"_errors,omitempty"`
}

type Attachment struct {
	ContentTransferEncoding string  `description:"Content-Transfer-Encoding extracted from the MIME payload" json:"content_transfer_encoding,omitempty" validate:"omitempty"`
	ContentType             string  `description:"Content-Type extracted from the MIME payload" json:"content_type,omitempty" validate:"omitempty"`
	FileExtension           string  `description:"File extension" json:"file_extension,omitempty" validate:"omitempty,isdefault"`
	FileName                string  `description:"File name" json:"file_name,omitempty" validate:"omitempty"`
	FileType                string  `description:"File type (determined by looking at the magic bytes in the file)" json:"file_type,omitempty" validate:"omitempty,isdefault"`
	Size                    *int64  `description:"Size of the attachment in bytes" json:"size,omitempty" validate:"omitempty,isdefault"`
	Raw                     *string `description:"Base64 encoded source of the attachment" json:"raw,omitempty" validate:"omitempty"`
}

type Body struct {
	HTML  *BodyText `description:"The body part containing content-type text/html" json:"html,omitempty" validate:"omitempty"`
	Plain *BodyText `description:"The body part containing content-type text/plain" json:"plain,omitempty" validate:"omitempty"`
	IPs   []IP      `description:"IP Addresses located in the body" json:"ips,omitempty" validate:"omitempty"`
	Links []Link    `description:"All links (including standalone URLs) found in the body of the message" json:"links,omitempty" validate:"omitempty"`
}

type BodyText struct {
	Raw                     *string `description:"Decoded raw content of a body text type (text/[subtype] section)" json:"raw,omitempty" validate:"omitempty"`
	Charset                 string  `description:"charset of the text/[subtype]" json:"charset,omitempty" validate:"omitempty"`
	ContentTransferEncoding string  `description:"Content-Transfer-Encoding of the text/[subtype]" json:"content_transfer_encoding,omitempty" validate:"omitempty"`
}

type Domain struct {
	Domain     string `description:"The fully qualified domain name (FQDN). This may not *always* be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar" json:"domain" validate:"required"`
	RootDomain string `description:"The root domain, including the TLD" json:"root_domain,omitempty" validate:"omitempty"`
	Sld        string `description:"Second-level domain, e.g. 'windows' for the domain 'windows.net'" json:"sld,omitempty" validate:"omitempty"`
	Subdomain  string `description:"Subdomain, e.g. 'drive' for the domain 'drive.google.com'" json:"subdomain,omitempty" validate:"omitempty"`
	Tld        string `description:"The domain's top-level domain. E.g. the TLD of google.com is 'com'" json:"tld,omitempty" validate:"omitempty"`
	Valid      bool   `description:"Whether the domain is valid" json:"valid,omitempty" validate:"omitempty"`
}

type EmailAddress struct {
	Email     string `description:"Full email address" json:"email" validate:"required"`
	LocalPart string `description:"Local-part, i.e. before the @" json:"local_part" validate:"required"`
	Domain    Domain `description:"Domain of the email address" json:"domain,omitempty" validate:"omitempty"`
}

type External struct {
	CreatedAt  *time.Time `description:"The created time of the message as provided by the cloud API (G Suite or Office 365) or other external source. This is typically the time the external source received the message" format:"date-time" json:"created_at,omitempty" validate:"omitempty"`
	MessageID  string     `description:"The message ID as provided by the cloud API (G Suite or Office 365) or other external source" json:"message_id,omitempty" validate:"omitempty"`
	RouteType  string     `description:"whether the message was sent or" json:"route_type,omitempty" validate:"omitempty" enum:"sent,received"`
	Spam       *bool      `description:"The upstream mail gateway determined the message to be spam. For cloud API providers, this will be the same as spam_folder. For other implementation methods like transport rules, this will be determined by message header values (e.g. X-SPAM) if supported" json:"spam,omitempty" validate:"omitempty"`
	SpamFolder *bool      `description:"The message arrived in the user's spam folder. This only applies to cloud APIs (G Suite or Office 365)" json:"spam_folder,omitempty" validate:"omitempty"`
	ThreadID   string     `description:"The thread/conversation's unique ID as provided by the cloud API (G Suite or Office 365)" json:"thread_id,omitempty" validate:"omitempty"`
}

type IP struct {
	IP string `description:"The raw IP" json:"ip" validate:"required"`
}

type Mailbox struct {
	DisplayName string       `description:"Display name" json:"display_name,omitempty" validate:"omitempty"`
	Email       EmailAddress `description:"Email address object" json:"email" validate:"required"`
}

type MessageType struct {
	Inbound  bool `description:"Message was sent from someone outside your organization, to *at least one* recipient inside your organization" json:"inbound,omitempty" validate:"omitempty"`
	Internal bool `description:"Message was sent between two or more participants inside your organization" json:"internal,omitempty" validate:"omitempty"`
	Outbound bool `description:"Message was sent from someone inside your organization, to *at least one* recipient outside your organization" json:"outbound,omitempty" validate:"omitempty"`
}

type Recipients struct {
	Bcc []Mailbox `description:"List of 'bcc' Mailbox objects" json:"bcc,omitempty" validate:"omitempty"`
	Cc  []Mailbox `description:"List of 'cc' Mailbox objects" json:"cc,omitempty" validate:"omitempty"`
	To  []Mailbox `description:"List of 'to' Mailbox objects" json:"to,omitempty" validate:"omitempty"`
}

type Subject struct {
	Subject string `description:"Subject of the email" json:"subject" validate:"required"`
}

type Link struct {
	DisplayText string `description:"The text of a hyperlink, if it's not a URL" json:"display_text,omitempty" validate:"omitempty"`
	DisplayURL  *URL   `description:"URL the user sees when viewing the message" json:"display_url,omitempty" validate:"omitempty"`
	HrefURL     *URL   `description:"Target URL in a hyperlink. This differs from the display_url when there is a mismatched URL" json:"href_url,omitempty" validate:"omitempty"`
	Mismatched  *bool  `description:"Whether the display URL and href URL root domains are mismatched" json:"mismatched,omitempty" validate:"omitempty"`
}

type URL struct {
	URL         string  `description:"Full URL" json:"url" validate:"required"`
	Domain      *Domain `description:"Target domain of URL" json:"domain,omitempty" validate:"omitempty"`
	Fragment    string  `description:"Fragment identifier; the text following the # in the href_url (also called the anchor tag)" json:"fragment,omitempty" validate:"omitempty"`
	Password    string  `description:"The password specified before the domain name" json:"password,omitempty" validate:"omitempty"`
	Path        string  `description:"Everything after the TLD and before the query parameters" json:"path,omitempty" validate:"omitempty"`
	Port        *int    `description:"The port used for the href_url. If no explicit port is set, the port will be inferred from the protocol" json:"port,omitempty" validate:"omitempty"`
	QueryParams string  `description:"The query parameters of the href_url" json:"query_params,omitempty" validate:"omitempty"`
	Scheme      string  `description:"Protocol for the href_url request, e.g. http" json:"scheme,omitempty" validate:"omitempty"`
	Username    string  `description:"The username specified before the domain name of the href_url" json:"username,omitempty" validate:"omitempty"`
}

type Headers struct {
	Date               *time.Time    `description:"Date the email was sent in UTC." json:"date,omitempty" validate:"omitempty"`
	DateOriginalOffset *string       `description:"UTC timezone offset of the sender" json:"date_original_offset,omitempty" validate:"omitempty"`
	Domains            []Domain      `description:"All domains found in the Received headers" json:"domains,omitempty" validate:"omitempty"`
	DeliveredTo        *EmailAddress `description:"Delivered-to header value" json:"delivered_to,omitempty" validate:"omitempty"`
	IPs                []IP          `description:"All IP addresses found in the Received headers" json:"ips,omitempty" validate:"omitempty"`
	Mailer             *string       `description:"X-Mailer or User-Agent extracted from headers" json:"mailer,omitempty" validate:"omitempty"`
	MessageID          *string       `description:"Message-ID extracted from the header" json:"message_id,omitempty" validate:"omitempty"`
	References         []string      `description:"The Message-IDs of the other messages within this chain" json:"references,omitempty" validate:"omitempty"`
	ReplyTo            []Mailbox     `description:"Where replies should be delivered to" json:"reply_to,omitempty" validate:"omitempty"`
	ReturnPath         *EmailAddress `description:"RFC 5321 envelope FROM (SMTP MAIL FROM). This is also where bounces are delivered" json:"return_path,omitempty" validate:"omitempty" `
	XOriginatingIP     *IP           `description:"X-Originating-IP header, which identifies the originating IP address of the sender client" json:"x_originating_ip,omitempty" validate:"omitempty"`
	Hops               []Hop         `description:"List of hops the message took from Sender to Recipient" json:"hops" validate:"required"`
}

type Hop struct {
	Index       int          `description:"Index indicates the order in which a hop occurred from sender to recipient" json:"index" validate:"required"`
	AuthResults *AuthResults `description:"Results of authentication. Supported fields include 'Authentication-Results', 'X-Original-Authentication-Results', 'X-MS-Exchange-Authentication-Results', 'X-Agari-Authentication-Results' and 'ARC-Authentication-Results'. Specification details can be found at https://tools.ietf.org/html/rfc8601" json:"authentication_results,omitempty" validate:"omitempty"`
	Signature   *Signature   `description:"Details of a message signature. Supported fields include 'DKIM-Signature', 'DomainKey-Signature', 'X-Google-DKIM-Signature' and 'ARC-Message-Signature'" json:"signature,omitempty" validate:"omitempty"`
	SPF         *SPF         `description:"Details of the Sender Policy Framework check. Supported fields include 'Received-SPF' and 'X-Received-SPF'" json:"received_spf,omitempty" validate:"omitempty"`
	Fields      []HopField   `description:"List of all raw header fields contained within this hop" json:"fields" validate:"required"`
}

type HopField struct {
	Name     string `description:"The name of the field" json:"name" validate:"required"`
	Value    string `description:"The value contained within the field" json:"value" validate:"required"`
	Position int    `description:"This field's position along the entire list of header fields" json:"position" validate:"required"`
}

type AuthResults struct {
	Type         string      `description:"The type of authentication result, derived from the field name" json:"type,omitempty" validate:"omitempty"`
	Instance     string      `description:"Instance number of this auth result (if ARC)" json:"instance,omitempty" validate:"omitempty"`
	CompAuth     *CompAuth   `description:"Composite Authentication result, used by Microsoft O365" json:"compauth,omitempty" validate:"omitempty"`
	DKIM         string      `description:"Verdict of the Domain Keys Identified Mail check" enum:"none,pass,fail,policy,neutral,temperror,permerror" json:"dkim,omitempty" validate:"omitempty"`
	DKIMDetails  []Signature `description:"List of details of the Domain Keys Identified Mail checks" json:"dkim_details,omitempty" validate:"omitempty"`
	DMARC        string      `description:"Verdict of the Domain-based Message Authentication, Reporting & Conformance check" json:"dmarc,omitempty" enum:"none,pass,fail,reject,bestguesspass,temperror,permerror" validate:"omitempty"`
	DMARCDetails *DMARC      `description:"Details of the Domain-based Message Authentication, Reporting & Conformance check" json:"dmarc_details,omitempty" validate:"omitempty"`
	SPF          string      `description:"Verdict of the Sender Policy Framework" enum:"none,pass,fail,softfail,policy,neutral,temperror,permerror" json:"spf,omitempty" validate:"omitempty"`
	SPFDetails   *SPF        `description:"Details of the Sender Policy Framework" json:"spf_details,omitempty" validate:"omitempty"`
	Server       *Domain     `description:"The domain of the verifying mail server" json:"server,omitempty" validate:"omitempty"`
}

type CompAuth struct {
	Verdict string `description:"Verdict of the compauth" json:"verdict" validate:"required"`
	Reason  string `description:"Reason for the verdict" json:"reason" validate:"required"`
}

type Signature struct {
	Type      string `description:"The type of signature, derived from the field name" json:"type,omitempty" validate:"omitempty"`
	Instance  string `description:"Instance number of this signature (if ARC)" json:"instance,omitempty" validate:"omitempty"`
	Version   string `description:"Version" json:"version,omitempty" validate:"omitempty"`
	Algorithm string `description:"Signing algorithm" json:"algorithm,omitempty" validate:"omitempty"`
	Selector  string `description:"Selector" json:"selector,omitempty" validate:"omitempty"`
	Signature string `description:"Signature of headers and body" json:"signature,omitempty" validate:"omitempty"`
	BodyHash  string `description:"Body Hash" json:"body_hash,omitempty" validate:"omitempty"`
	Domain    string `description:"Domain" json:"domain,omitempty" validate:"omitempty"`
	Headers   string `description:"Header fields signed by the algorithm" json:"headers,omitempty" validate:"omitempty"`
}

type DMARC struct {
	Version     *string `description:"DMARC version" json:"version" validate:"omitempty"`
	Verdict     *string `description:"Verdict of the DMARC" json:"verdict" validate:"omitempty"`
	Action      *string `description:"Action" json:"action" validate:"omitempty"`
	Policy      *string `description:"Policy for the organizational domain" json:"policy,omitempty" validate:"omitempty"`
	SubPolicy   *string `description:"Policy for the subdomain of the organizational domain" json:"sub_policy,omitempty" validate:"omitempty"`
	Disposition *string `description:"Gmail-applied policy" json:"disposition,omitempty" validate:"omitempty"`
	From        *Domain `description:"Domain of the server that checked the SPF" json:"from,omitempty" validate:"omitempty"`
}

type SPF struct {
	Verdict     *string `description:"Verdict of the SPF" json:"verdict" validate:"omitempty"`
	Server      *Domain `description:"Domain of the server that checked the SPF" json:"server,omitempty" validate:"omitempty"`
	ClientIP    *IP     `description:"IP of the client the email originated from" json:"client_ip,omitempty" validate:"omitempty"`
	Designator  *string `description:"Email or domain of the designating body" json:"designator,omitempty" validate:"omitempty"`
	Helo        *Domain `description:"Domain of the previous server this message hopped from" json:"helo,omitempty" validate:"omitempty"`
	Description *string `description:"Verbose description of the SPF verdict" json:"description,omitempty" validate:"omitempty"`
}

type GeneratedMitre struct {
	Success bool `json:"success"`
	Timing  struct {
		AnalysisTime float64 `json:"analysis_time"`
		TimeVariant  string  `json:"time_variant"`
	} `json:"timing"`
	InputLength       int `json:"input_length"`
	TacticsChecked    int `json:"tactics_checked"`
	TechniquesChecked int `json:"techniques_checked"`
	Tactics           []struct {
		Code              string  `json:"code"`
		Confidence        float64 `json:"confidence"`
		ConfidenceVariant string  `json:"confidence_variant"`
	} `json:"tactics"`
	Techniques []struct {
		Code              string  `json:"code"`
		Confidence        float64 `json:"confidence"`
		ConfidenceVariant string  `json:"confidence_variant"`
	} `json:"techniques"`
	AnalysisID string `json:"analysis_id"`
	Reason     string `json:"reason"`
}

// BaseUrl = Backend URL
// Url = Worker URL
type OrborusExecutionRequest struct {
	ExecutionId           string            `json:"execution_id"`
	Authorization         string            `json:"authorization"`
	HTTPProxy             string            `json:"http_proxy"`
	HTTPSProxy            string            `json:"https_proxy"`
	BaseUrl               string            `json:"base_url"`
	Url                   string            `json:"url"`
	EnvironmentName       string            `json:"environment_name"`
	Timezone              string            `json:"timezone"`
	Cleanup               string            `json:"cleanup"`
	ShufflePassProxyToApp string            `json:"shuffle_pass_proxy_to_app"`
	Action                Action            `json:"action"`
	FullExecution         WorkflowExecution `json:"workflow_execution"`
	WorkerServerUrl       string            `json:"worker_server_url"`
}

type OpenseaAsset struct {
	Name              string `json:"name" datastore:"name"`
	Collection        string `json:"collection" datastore:"collection"`
	CollectionURL     string `json:"collection_url" datastore:"collection_url"`
	Image             string `json:"image" datastore:"image"`
	Asset             string `json:"asset" datastore:"asset"`
	AssetLink         string `json:"asset_link" datastore:"asset_link"`
	Polygon           bool   `json:"polygon" datastore:"polygon"`
	WorkflowReference string `json:"workflow_reference" datastore:"workflow_reference"`
	Workflow          string `json:"workflow" datastore:"workflow"`
	Creator           string `json:"creator" datastore:"creator"`
	OwnerUsername     string `json:"owner_username" datastore:"owner_username"`
	Owner             string `json:"owner" datastore:"owner"`
	ID                string `json:"id" datastore:"id"`
	Created           int64  `json:"created" datastore:"created"`
	Edited            int64  `json:"edited" datastore:"edited"`
}

type PrizedrawSubmitter struct {
	IP             string   `json:"ip"`
	ID             string   `json:"id"`
	Username       string   `json:"username"`
	UserId         string   `json:"user_id""`
	Email          string   `json:"email"`
	Firstname      string   `json:"firstname"`
	Lastname       string   `json:"lastname"`
	Twitter        string   `json:"twitter"`
	Address        string   `json:"address"`
	WinningIds     []string `json:"winning_ids"`
	PreviousWinner bool     `json:"previous_winner"`
	Created        int64    `json:"created"`
	Edited         int64    `json:"edited"`
}

type GithubProfile struct {
	Login                   string    `json:"login"`
	ID                      int       `json:"id"`
	NodeID                  string    `json:"node_id"`
	AvatarURL               string    `json:"avatar_url"`
	GravatarID              string    `json:"gravatar_id"`
	URL                     string    `json:"url"`
	HTMLURL                 string    `json:"html_url"`
	FollowersURL            string    `json:"followers_url"`
	FollowingURL            string    `json:"following_url"`
	GistsURL                string    `json:"gists_url"`
	StarredURL              string    `json:"starred_url"`
	SubscriptionsURL        string    `json:"subscriptions_url"`
	OrganizationsURL        string    `json:"organizations_url"`
	ReposURL                string    `json:"repos_url"`
	EventsURL               string    `json:"events_url"`
	ReceivedEventsURL       string    `json:"received_events_url"`
	Type                    string    `json:"type"`
	SiteAdmin               bool      `json:"site_admin"`
	Name                    string    `json:"name"`
	Company                 string    `json:"company"`
	Blog                    string    `json:"blog"`
	Location                string    `json:"location"`
	Email                   string    `json:"email"`
	Hireable                bool      `json:"hireable"`
	Bio                     string    `json:"bio"`
	TwitterUsername         string    `json:"twitter_username"`
	PublicRepos             int       `json:"public_repos"`
	PublicGists             int       `json:"public_gists"`
	Followers               int       `json:"followers"`
	Following               int       `json:"following"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
	PrivateGists            int       `json:"private_gists"`
	TotalPrivateRepos       int       `json:"total_private_repos"`
	OwnedPrivateRepos       int       `json:"owned_private_repos"`
	DiskUsage               int       `json:"disk_usage"`
	Collaborators           int       `json:"collaborators"`
	TwoFactorAuthentication bool      `json:"two_factor_authentication"`
	Plan                    struct {
		Name          string `json:"name"`
		Space         int    `json:"space"`
		PrivateRepos  int    `json:"private_repos"`
		Collaborators int    `json:"collaborators"`
	} `json:"plan"`
	Contributions int64 `json:"contributions"`
}

type SettingsReturn struct {
	Success  bool   `json:"success"`
	Username string `json:"username"`
	Verified bool   `json:"verified"`
	Apikey   string `json:"apikey"`
	Image    string `json:"image"`
}

type ExtraButton struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	Link  string `json:"link"`
	App   string `json:"app"`
	Type  string `json:"type"`
}

type Usecase struct {
	Success     bool   `json:"success"`
	Name        string `json:"name"`
	Description string `json:"description"`
	LeftText    string `json:"left_text"`
	RightText   string `json:"right_text"`
	LeftImage   string `json:"left_image"`
	RightImage  string `json:"right_image"`
	Direction   string `json:"direction"`
	Process     []struct {
		Source      string `json:"source"`
		Target      string `json:"target"`
		Description string `json:"description"`
		Human       bool   `json:"human"`
	} `json:"process"`
	Edited          int64         `json:"edited"`
	EditedBy        string        `json:"edited_by"`
	Blogpost        string        `json:"blogpost"`
	Video           string        `json:"video"`
	Priority        string        `json:"priority"`
	WorkflowOutline string        `json:"workflow_outline"`
	ExtraButtons    []ExtraButton `json:"extra_buttons"`
}

type CacheKeySearchWrapper struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string       `json:"_index"`
			Type   string       `json:"_type"`
			ID     string       `json:"_id"`
			Score  float64      `json:"_score"`
			Source CacheKeyData `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type DealSearchWrapper struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string       `json:"_index"`
			Type   string       `json:"_type"`
			ID     string       `json:"_id"`
			Score  float64      `json:"_score"`
			Source ResellerDeal `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type ResellerDeal struct {
	ID          string `json:"id" datastore:"id"`
	Name        string `json:"name" datastore:"name"`
	Type        string `json:"type" datastore:"type"`
	Address     string `json:"address" datastore:"address"`
	Country     string `json:"country" datastore:"country"`
	Currency    string `json:"currency" datastore:"currency"`
	Status      string `json:"status" datastore:"status"`
	Value       string `json:"value" datastore:"value"`
	Discount    string `json:"discount" datastore:"discount"`
	ResellerOrg string `json:"reseller_org" datastore:"reseller_org"`
	Created     int64  `json:"created" datastore:"created"`
	Edited      int64  `json:"edited" datastore:"edited"`
}

type UsecaseLinks []struct {
	Name  string `json:"name"`
	Color string `json:"color"`
	List  []struct {
		Name     string `json:"name" datastore:"name"`
		Priority int    `json:"priority"`
		Type     string `json:"type"`
		Last     string `json:"last"`
		Items    struct {
			Name  string `json:"name"`
			Items struct {
			} `json:"items"`
		} `json:"items,omitempty"`
		Description    string     `json:"description,omitempty" datastore:"description,noindex"`
		Video          string     `json:"video,omitempty"`
		Blogpost       string     `json:"blogpost,omitempty"`
		ReferenceImage string     `json:"reference_image,omitempty"`
		Matches        []Workflow `json:"matches"`
		Keywords       []string   `json:"keywords"`
		KeywordMatches int        `json:"keyword_matches"`
	} `json:"list"`
}

type IdTokenCheck struct {
	Aud   string `json:"aud"`
	Iss   string `json:"iss"`
	Iat   int    `json:"iat"`
	Nbf   int    `json:"nbf"`
	Exp   int    `json:"exp"`
	Aio   string `json:"aio"`
	Nonce string `json:"nonce"`
	Rh    string `json:"rh"`
	Sub   string `json:"sub"`
	Tid   string `json:"tid"`
	Uti   string `json:"uti"`
	Ver   string `json:"ver"`
	Org   Org    `json:"org"`
}

type WidgetMeta struct {
	Color string `json:"color" datastore:"color"`
}

type WidgetPointData struct {
	Key      string     `json:"key" datastore:"key"`
	Data     int64      `json:"data" datastore:"data"`
	MetaData WidgetMeta `json:"metadata" datastore:"metadata"`
}

type WidgetPoint struct {
	Key  string            `json:"key"  datastore:"key"`
	Data []WidgetPointData `json:"data"  datastore:"data"`
}

type Widget struct {
	Success    bool          `json:"success"`
	Id         string        `json:"id"`
	Title      string        `json:"title"`
	Dashboard  string        `json:"dashboard"`
	WidgetType string        `json:"widget_type"`
	Data       []WidgetPoint `json:"data"`
}

type Conversionevents struct {
	Id          string        `json:"id" datastore:"id"`
	Name        string        `json:"name" datastore:"name"`
	Type        string        `json:"type" datastore:"type"`
	Events      []WidgetPoint `json:"events" datastore:"events"`
	Invalid     bool          `json:"invalid" datastore:"invalid"`
	Verified    bool          `json:"verified" datastore:"verified"`
	Orgs        int           `json:"orgs" datastore:"orgs"`
	Searches    int           `json:"searches" datastore:"searches"`
	Clicks      int           `json:"clicks" datastore:"clicks"`
	Conversions int           `json:"conversions" datastore:"conversions"`
	Forks       int           `json:"forks" datastore:"forks"`
	EditedForks int           `json:"edited_forks" datastore:"edited_forks"`
	Success     bool          `json:"success"`
}

type UsecaseStep struct {
	WorkflowId string `json:"workflow_id"`
	AppId      string `json:"app_id"`
	AppName    string `json:"app_name"`
	AppVersion string `json:"app_version"`
	Text       string `json:"text"`
	Image      string `json:"image"`
	Type       string `json:"type"`
	ActionType string `json:"action_type"`
}

type UsecaseMerge struct {
	Name           string        `json:"name"`
	Id             string        `json:"id"`
	Source         UsecaseStep   `json:"source"`
	Middle         []UsecaseStep `json:"middle"`
	Destination    UsecaseStep   `json:"destination"`
	OrgId          string        `json:"org_id"`
	Username       string        `json:"username"`
	UserId         string        `json:"user_id"`
	Timestamp      int64         `json:"timestamp"`
	SourcePlatform string        `json:"source_platform"`
}

type AppStats struct {
	TotalSearches    int           `json:"total_searches" datastore:"total_searches"`
	Events           []WidgetPoint `json:"events" datastore:"events"`
	TotalConversions int           `json:"total_conversions" datastore:"total_conversions"`
	TotalClicks      int           `json:"total_clicks" datastore:"total_clicks"`
	AppName          string        `json:"app_name" datastore:"app_name"`
}

type CreatorStats struct {
	Creator          string     `json:"creator" datastore:"creator"`
	Apps             int        `json:"apps" datastore:"apps"`
	MostClickedApp   string     `json:"most_clicked_app" datastore:"most_clicked_app"`
	MostConversedApp string     `json:"most_conversed_app" datastore:"most_conversed_app"`
	Verified         bool       `json:"verified" datastore:"verified"`
	Workflows        int        `json:"workflows" datastore:"workflows"`
	AppStats         []AppStats `json:"app_stats" datastore:"app_stats"`
}

type Mailcheck struct {
	Targets            []string `json:"targets"`
	Body               string   `json:"body"`
	Subject            string   `json:"subject"`
	Type               string   `json:"type"`
	EmailApp		   bool		`json:"email_app"`
	SenderCompany      string   `json:"sender_company"`
	WorkflowId         string   `json:"workflow_id"`
	ReferenceExecution string   `json:"reference_execution"`
	Authorization      string   `json:"authorization"`
	ExecutionType      string   `json:"execution_type"`
	Start              string   `json:"start"`
}

type SmsBody struct {
	Numbers            []string `json:"numbers" datastore:"numbers"`
	Body               string   `json:"body" datastore:"body"`
	ReferenceExecution string   `json:"reference_execution"`
	Authorization      string   `json:"authorization"`
	WorkflowId         string   `json:"workflow_id"`
	ExecutionType      string   `json:"execution_type"`
	Start              string   `json:"start"`
}

type UserInputResponse struct {
	Success     bool   `json:"success"`
	Source      string `json:"source"`
	Reason      string `json:"reason"`
	Information string `json:"information"`
	ClickInfo   struct {
		Clicked bool   `json:"clicked"`
		Time    int64  `json:"time"`
		IP      string `json:"ip"`
		User    string `json:"user"`
		Note    string `json:"note"`
	} `json:"click_info"`
	Subflow struct {
		Success       bool   `json:"success"`
		ExecutionID   string `json:"execution_id"`
		Authorization string `json:"authorization"`
	} `json:"subflow"`
	SubflowURL string `json:"subflow_url"`
}

type SchemalessOutput struct {
	Success bool        `json:"success"`
	Action  string      `json:"action"`
	Status  int         `json:"status,omitempty"`
	URL	    string      `json:"url,omitempty"`

	// JSON output. What if it's a list?
	//Output map[string]interface{} `json:"output"`
	Output interface{} `json:"output"`

	// Optional
	RawResponse interface{} `json:"raw_response,omitempty"`
}

type CategoryAction struct {
	AppName string         `json:"app_name"`
	Label   string         `json:"label"`
	Fields  []Valuereplace `json:"fields"`

	// Optional~
	AppVersion     string         `json:"app_version"`
	ActionName     string         `json:"action_name"`
	Category       string         `json:"category"`
	OptionalFields []Valuereplace `json:"optional_fields"`

	OrgId            string `json:"org_id"`
	WorkflowId       string `json:"workflow_id"` // Forces it to use a specific workflow ID. This can be used to build multiple steps in the same workflow
	AuthenticationId string `json:"authentication_id"`

	Step                  int64  `json:"step"`                    // The step to use put it in a workflow if generated
	Query                 string `json:"query,omitempty"`         // Due to the API being built around programmatic, and then with LLMs, this was added to make context possible between nodes when using Atomic Actions
	DryRun                bool   `json:"dry_run"`                 // If true, it will not actually execute the action, but instead just build the workflow
	SkipWorkflow          bool   `json:"skip_workflow"`           // If true, it will not put it in a workflow, but instead just execute it
	SkipOutputTranslation bool   `json:"skip_output_translation"` // If true, it will not translate the output to the default format for the label
	Environment           string `json:"environment"`             // The environment to use for the action (Orborus)
}

type LabelStruct struct {
	Category string `json:"category"`
	Label    string `json:"label"`
}

type AppLabel struct {
	AppName    string        `json:"app_name"`
	LargeImage string        `json:"large_image"`
	ID         string        `json:"id"`
	Labels     []LabelStruct `json:"labels"`
}

type AppCategoryLabel struct {
	Label          string        `json:"label"`
	FormattedLabel string        `json:"formatted_label"`
	Apps           []WorkflowApp `json:"apps"`
}

type AppCategory struct {
	Name           string              `json:"name"`
	Color          string              `json:"color"`
	Icon           string              `json:"icon"`
	ActionLabels   []string            `json:"action_labels"`
	AppLabels      []AppLabel          `json:"app_labels"`
	RequiredFields map[string][]string `json:"required_fields"`
	OptionalFields map[string][]string `json:"optional_fields"`
}

type SingleResult struct {
	Success       bool     `json:"success"`
	Id            string   `json:"id"`
	Authorization string   `json:"authorization"`
	Result        string   `json:"result"`
	Errors        []string `json:"errors"`
}

type DockerRequestCheck struct {
	Name string `datastore:"name" json:"name" yaml:"name"`
}

type Recommendations struct {
	AppName    string `json:"app_name"`
	AppVersion string `json:"app_version"`
	AppAction  string `json:"app_action"`
	AppId      string `json:"app_id"`
	LargeImage string `json:"large_image"`
}

type RecommendAction struct {
	AppName         string            `json:"app_name"`
	ActionId        string            `json:"action_id"`
	Recommendations []Recommendations `json:"recommendations"`
}

type RecommendationAction struct {
	Action string `json:"action"`
	Name   string `json:"name"`
}

type ActionRecommendations struct {
	Success bool              `json:"success"`
	Actions []RecommendAction `json:"actions"`
}

type AppLabelData struct {
	AppName    string   `json:"app_name" datastore:"app_name"`
	AppId      string   `json:"app_id" datastore:"app_id"`
	AppVersion string   `json:"app_version" datastore:"app_version"`
	Categories []string `json:"categories" datastore:"categories"`
	ImageURL   string   `json:"image_url" datastore:"image_url"`
	//LabeledActions []LabeledAction `json:"labeled_actions" datastore:"labeled_actions"`

	ActionName string `json:"action_name" datastore:"action_name"`
	Label      string `json:"label" datastore:"label"`
}

type Suggestion struct {
	Creator   string       `json:"creator" datastore:"creator"`
	CreatorId string       `json:"creator_id" datastore:"creator_id"`
	Type      string       `json:"type" datastore:"type"`
	Label     AppLabelData `json:"label" datastore:"label"`
	Created   int64        `json:"created" datastore:"created"`
	Edited    int64        `json:"edited" datastore:"edited"`

	SuggestionID string `json:"suggestion_id" datastore:"suggestion_id"`
	SuggestionBy string `json:"suggestion_by" datastore:"suggestion_by"`

	Status string `json:"status" datastore:"status"`
}

// Parse out CPU, memory and disk. Make struct
type OrborusStats struct {
	Id string `json:"id"`

	OrgId        string `json:"org_id"`
	Environment  string `json:"environment"`
	OrborusLabel string `json:"orborus_label"`
	Timestamp    int64  `json:"timestamp"`
	Swarm        bool   `json:"swarm"`
	Kubernetes   bool   `json:"kubernetes"`

	// Shuffle
	MaxQueue int `json:"max_queue"`
	Queue    int `json:"queue"`
	PollTime int `json:"poll_time"`

	// General
	MaxCPU     int     `json:"max_cpu"`
	CPU        int     `json:"cpu"`
	CPUPercent float64 `json:"cpu_percent"`

	MaxMemory     int     `json:"max_memory"`
	Memory        int     `json:"memory"`
	MemoryPercent float64 `json:"memory_percent"`

	MaxDisk     int     `json:"max_disk"`
	Disk        int     `json:"disk"`
	DiskPercent float64 `json:"disk_percent"`

	// Docker
	AppContainers     int `json:"app_containers"`
	WorkerContainers  int `json:"worker_containers"`
	StoppedContainers int `json:"stopped_containers"`
	TotalContainers   int `json:"total_containers"`
}

// Create struct
type ExecutionReturn struct {
	Success    bool                `json:"success"`
	Executions []WorkflowExecution `json:"executions"`
	Cursor     string              `json:"cursor"`
}

// Create struct
type CacheReturn struct {
	Success bool           `json:"success"`
	Keys    []CacheKeyData `json:"keys"`
	Cursor  string         `json:"cursor"`
}

type GCPIncident struct {
	Incident struct {
		Condition struct {
			ConditionMatchedLog struct {
				Filter             string   `json:"filter"`
				ResourceContainers []string `json:"resourceContainers"`
			} `json:"conditionMatchedLog"`
			DisplayName string `json:"displayName"`
			Name        string `json:"name"`
		} `json:"condition"`
		ConditionName string `json:"condition_name"`
		IncidentID    string `json:"incident_id"`
		Metadata      struct {
			SystemLabels struct {
			} `json:"system_labels"`
			UserLabels struct {
			} `json:"user_labels"`
		} `json:"metadata"`
		Metric struct {
			DisplayName string `json:"displayName"`
			Labels      struct {
			} `json:"labels"`
			Type string `json:"type"`
		} `json:"metric"`
		PolicyName string `json:"policy_name"`
		Resource   struct {
			Labels struct {
				FunctionName string `json:"function_name"`
				ProjectID    string `json:"project_id"`
				Region       string `json:"region"`
			} `json:"labels"`
			Type string `json:"type"`
		} `json:"resource"`
		ResourceID              string `json:"resource_id"`
		ResourceName            string `json:"resource_name"`
		ResourceTypeDisplayName string `json:"resource_type_display_name"`
		ScopingProjectID        string `json:"scoping_project_id"`
		ScopingProjectNumber    int64  `json:"scoping_project_number"`
		StartedAt               int    `json:"started_at"`
		State                   string `json:"state"`
		Summary                 string `json:"summary"`
		URL                     string `json:"url"`
	} `json:"incident"`
	Version string `json:"version"`
}

type AppHealth struct {
	Create      bool   `json:"create"`
	Run         bool   `json:"run"`
	Delete      bool   `json:"delete"`
	Validate    bool   `json:"validate"`
	AppId       string `json:"app_id"`
	Read        bool   `json:"read"`
	Result      string `json:"result"`
	ExecutionID string `json:"execution_id"`
}

type WorkflowHealth struct {
	Create      bool   `json:"create"`
	Run         bool   `json:"run"`
	RunFinished bool   `json:"run_finished"`
	RunStatus   string `json:"run_status"`
	Delete      bool   `json:"delete"`
	ExecutionId string `json:"execution_id"`
	WorkflowId  string `json:"workflow_id"`
}

type HealthCheck struct {
	Success bool  `json:"success"`
	Updated int64 `json:"updated"`
	// Apps AppHealth `json:"apps"`
	Workflows WorkflowHealth `json:"workflows"`
}

type HealthCheckDB struct {
	Success   bool           `json:"success"`
	Updated   int64          `json:"updated"`
	Workflows WorkflowHealth `json:"workflows"`
	ID        string         `json:"id"`
}

type NodeData struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type NodeRelation struct {
	AppCategory string     `json:"app_category"`
	AppNames    []string   `json:"app_names"`
	AppIds      []string   `json:"app_ids"`
	Synonyms    []string   `json:"synonyms"`
	Incoming    []NodeData `json:"incoming"`
	Outgoing    []NodeData `json:"outgoing"`
}

type WorkflowNodeRelations struct {
	Relations map[string]NodeRelation `json:"node_relations"`
}

// Anonymized data that is sent to the cloud
// as backup. Saved in your organization and region
type BackupJob struct {
	Version    string `json:"version"`     // Instance version
	LastSignin int64  `json:"last_signin"` // Last time user signed in

	Stats     ExecutionInfo `json:"stats"`
	Workflows []Workflow    `json:"workflows"`
	Apps      []WorkflowApp `json:"apps"`
}

type WorkflowSearch struct {
	WorkflowId string `json:"workflow_id"`
	Limit      int    `json:"limit"`
	Cursor     string `json:"cursor"`

	Status      string `json:"status"`
	SearchFrom  string `json:"start_time"`
	SearchUntil string `json:"end_time"`

	IgnoreOrg bool `json:"ignore_org"`
}

type WorkflowSearchResult struct {
	Success bool                `json:"success"`
	Runs    []WorkflowExecution `json:"runs"`
	Cursor  string              `json:"cursor"`
}

// Used for the integrations API to work with AI well
type StructuredCategoryAction struct {
	Success     bool          `json:"success"`
	Reason      string        `json:"reason"`
	WorkflowId  string        `json:"workflow_id"`
	ExecutionId string        `json:"execution_id"`
	Action      string        `json:"action"`
	Label 	 	string        `json:"label"`
	Category    string        `json:"category"`
	Apps        []WorkflowApp `json:"apps"`

	Result string `json:"result"`

	AvailableLabels []string `json:"available_labels"`
	ThreadId        string   `json:"thread_id"`
	RunId           string   `json:"run_id"`
	MissingFields  []string `json:"missing_fields"`

	Translated bool `json:"translated"`
}

type ModelLabelParameter struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
}

type UserRequest struct {
	IP        string `json:"ip"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Timestamp int64  `json:"time"`
}

type HTTPOutput struct {
	Success bool                   `json:"success"`
	Status  int                    `json:"status"`
	Url     string                 `json:"url"`
	Body    interface{} 		   `json:"body"`
	Headers map[string]string      `json:"headers"`
	Cookies map[string]string      `json:"cookies"`
	Errors  []string               `json:"errors"`
}

type SnappStep struct {
	Name        string         `json:"name" yaml:"name"`
	Category    string         `json:"category" yaml:"category"`
	AppName     string         `json:"app_name" yaml:"app_name"`
	Environment string         `json:"environment" yaml:"environment"`
	Fields      []Valuereplace `json:"fields" yaml:"fields"`
}

type SnappWf struct {
	Name  string      `json:"name"`
	Steps []SnappStep `json:"steps"`
}

type SSOResponse struct {
	Success bool   `json:"success"`
	Reason  string `json:"reason"`
	URL     string `json:"url"`
}

type Training struct {
	Name              string `json:"Name"`
	Email             string `json:"Email"`
	NumberOfAttendees int    `json:"numberOfAttendees"`
	Message           string `json:"Message"`
	Time              string `json:"Time"`
	Country           string `json:"Country"`

	OrgId string `json:"org_id"`
	UserId string `json:"user_id"`
	Username string `json:"username"`
	ID	  string `json:"id"`
	SignupTime int64 `json:"signupTime"`
}
