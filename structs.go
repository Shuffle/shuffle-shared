package shuffle

import (
	"cloud.google.com/go/datastore"
	"cloud.google.com/go/storage"
	"encoding/xml"
	"github.com/frikky/go-elasticsearch/v8"
	"time"
)

type ShuffleStorage struct {
	GceProject    string
	Dbclient      datastore.Client
	StorageClient storage.Client
	Environment   string
	CacheDb       bool
	Es            elasticsearch.Client
	DbType        string
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
}

type RetStruct struct {
	Success         bool         `json:"success"`
	SyncFeatures    SyncFeatures `json:"sync_features"`
	SessionKey      string       `json:"session_key"`
	IntervalSeconds int64        `json:"interval_seconds"`
}

type WorkflowApp struct {
	Name          string `json:"name" yaml:"name" required:true datastore:"name"`
	IsValid       bool   `json:"is_valid" yaml:"is_valid" required:true datastore:"is_valid"`
	ID            string `json:"id" yaml:"id,omitempty" required:false datastore:"id"`
	Link          string `json:"link" yaml:"link" required:false datastore:"link,noindex"`
	AppVersion    string `json:"app_version" yaml:"app_version" required:true datastore:"app_version"`
	SharingConfig string `json:"sharing_config" yaml:"sharing_config" datastore:"sharing_config"`
	Generated     bool   `json:"generated" yaml:"generated" required:false datastore:"generated"`
	Downloaded    bool   `json:"downloaded" yaml:"downloaded" required:false datastore:"downloaded"`
	Sharing       bool   `json:"sharing" yaml:"sharing" required:false datastore:"sharing"`
	Verified      bool   `json:"verified" yaml:"verified" required:false datastore:"verified"`
	Invalid       bool   `json:"invalid" yaml:"invalid" required:false datastore:"invalid"`
	Activated     bool   `json:"activated" yaml:"activated" required:false datastore:"activated"`
	Tested        bool   `json:"tested" yaml:"tested" required:false datastore:"tested"`
	Hash          string `json:"hash" datastore:"hash" yaml:"hash"` // api.yaml+dockerfile+src/app.py for apps
	PrivateID     string `json:"private_id" yaml:"private_id" required:false datastore:"private_id"`
	Description   string `json:"description" datastore:"description,noindex" required:false yaml:"description"`
	Environment   string `json:"environment" datastore:"environment" required:true yaml:"environment"`
	SmallImage    string `json:"small_image" datastore:"small_image,noindex" required:false yaml:"small_image"`
	LargeImage    string `json:"large_image" datastore:"large_image,noindex" yaml:"large_image" required:false`
	ContactInfo   struct {
		Name string `json:"name" datastore:"name" yaml:"name"`
		Url  string `json:"url" datastore:"url" yaml:"url"`
	} `json:"contact_info" datastore:"contact_info" yaml:"contact_info" required:false`
	ReferenceInfo struct {
		DocumentationUrl string `json:"documentation_url" datastore:"documentation_url"`
		GithubUrl        string `json:"github_url" datastore:"github_url"`
	} `json:"reference_info" datastore:"reference_info"`
	FolderMount struct {
		FolderMount       bool   `json:"folder_mount" datastore:"folder_mount"`
		SourceFolder      string `json:"source_folder" datastore:"source_folder"`
		DestinationFolder string `json:"destination_folder" datastore:"destination_folder"`
	} `json:"folder_mount" datastore:"folder_mount"`
	Actions        []WorkflowAppAction `json:"actions" yaml:"actions" required:true datastore:"actions,noindex"`
	Authentication Authentication      `json:"authentication" yaml:"authentication" required:false datastore:"authentication"`
	Tags           []string            `json:"tags" yaml:"tags" required:false datastore:"activated"`
	Categories     []string            `json:"categories" yaml:"categories" required:false datastore:"categories"`
	Created        int64               `json:"created" datastore:"created"`
	Edited         int64               `json:"edited" datastore:"edited"`
	LastRuntime    int64               `json:"last_runtime" datastore:"last_runtime"`
	Versions       []AppVersion        `json:"versions" datastore:"versions"`
	LoopVersions   []string            `json:"loop_versions" datastore:"loop_versions"`
	Owner          string              `json:"owner" datastore:"owner" yaml:"owner"`
	Public         bool                `json:"public" datastore:"public"`
	ReferenceOrg   string              `json:"reference_org" datastore:"reference_org"`
	ReferenceUrl   string              `json:"reference_url" datastore:"reference_url"`
	ActionFilePath string              `json:"action_file_path" datastore:"action_file_path"`
	Documentation  string              `json:"documentation" datastore:"documentation"`
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
	Value string `json:"value" datastore:"value" yaml:"value"`
}

type WorkflowAppAction struct {
	Description       string                       `json:"description" datastore:"description,noindex"`
	ID                string                       `json:"id" datastore:"id" yaml:"id,omitempty"`
	Name              string                       `json:"name" datastore:"name"`
	Label             string                       `json:"label" datastore:"label"`
	NodeType          string                       `json:"node_type" datastore:"node_type"`
	Environment       string                       `json:"environment" datastore:"environment"`
	Sharing           bool                         `json:"sharing" datastore:"sharing"`
	PrivateID         string                       `json:"private_id" datastore:"private_id"`
	PublicID          string                       `json:"public_id" datastore:"public_id"`
	AppID             string                       `json:"app_id" datastore:"app_id"`
	Tags              []string                     `json:"tags" datastore:"tags" yaml:"tags"`
	Authentication    []AuthenticationStore        `json:"authentication" datastore:"authentication,noindex" yaml:"authentication,omitempty"`
	Tested            bool                         `json:"tested" datastore:"tested" yaml:"tested"`
	Parameters        []WorkflowAppActionParameter `json:"parameters" datastore: "parameters"`
	ExecutionVariable Variable                     `json:"execution_variable" datastore:"execution_variables"`
	Returns           struct {
		Description string           `json:"description" datastore:"returns" yaml:"description,omitempty"`
		Example     string           `json:"example" datastore:"example,noindex" yaml:"example"`
		ID          string           `json:"id" datastore:"id" yaml:"id,omitempty"`
		Schema      SchemaDefinition `json:"schema" datastore:"schema" yaml:"schema"`
	} `json:"returns" datastore:"returns"`
	AuthenticationId string `json:"authentication_id" datastore:"authentication_id"`
	Example          string `json:"example,noindex" datastore:"example" yaml:"example"`
	AuthNotRequired  bool   `json:"auth_not_required" datastore:"auth_not_required" yaml:"auth_not_required"`
	SourceWorkflow   string `json:"source_workflow" yaml:"source_workflow" datastore:"source_workflow"`
}

type Authentication struct {
	Required     bool                   `json:"required" datastore:"required" yaml:"required" `
	Type         string                 `json:"type" datastore:"type" yaml:"type"`
	RedirectUri  string                 `json:"redirect_uri" datastore:"redirect_uri" yaml:"redirect_uri"`
	TokenUri     string                 `json:"token_uri" datastore:"token_uri" yaml:"token_uri"`
	Scope        []string               `json:"scope" datastore:"scope" yaml:"scope"`
	Parameters   []AuthenticationParams `json:"parameters" datastore:"parameters" yaml:"parameters"`
	ClientId     string                 `json:"client_id" datastore:"client_id"`
	ClientSecret string                 `json:"client_secret" datastore:"client_secret"`
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
}

type Userapi struct {
	Username string `datastore:"Username"`
	ApiKey   string `datastore:"apikey"`
}

type ExecutionInfo struct {
	TotalApiUsage           int64 `json:"total_api_usage" datastore:"total_api_usage"`
	TotalWorkflowExecutions int64 `json:"total_workflow_executions" datastore:"total_workflow_executions"`
	TotalAppExecutions      int64 `json:"total_app_executions" datastore:"total_app_executions"`
	TotalCloudExecutions    int64 `json:"total_cloud_executions" datastore:"total_cloud_executions"`
	TotalOnpremExecutions   int64 `json:"total_onprem_executions" datastore:"total_onprem_executions"`
	DailyApiUsage           int64 `json:"daily_api_usage" datastore:"daily_api_usage"`
	DailyWorkflowExecutions int64 `json:"daily_workflow_executions" datastore:"daily_workflow_executions"`
	DailyAppExecutions      int64 `json:"daily_app_executions" datastore:"daily_app_executions"`
	DailyCloudExecutions    int64 `json:"daily_cloud_executions" datastore:"daily_cloud_executions"`
	DailyOnpremExecutions   int64 `json:"daily_onprem_executions" datastore:"daily_onprem_executions"`
}

type ParsedOpenApi struct {
	Body    string `datastore:"body,noindex" json:"body"`
	ID      string `datastore:"id" json:"id"`
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

type Environment struct {
	Name       string `datastore:"name"`
	Type       string `datastore:"type"`
	Registered bool   `datastore:"registered"`
	Default    bool   `datastore:"default" json:"default"`
	Archived   bool   `datastore:"archived" json:"archived"`
	Id         string `datastore:"id" json:"id"`
	OrgId      string `datastore:"org_id" json:"org_id"`
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
	Value string `json:"value" datastore:"value"`
}

// Used to contain users in miniOrg
type UserMini struct {
	Username string `datastore:"Username" json:"username"`
	Id       string `datastore:"id" json:"id"`
	Role     string `datastore:"role" json:"role"`
}

type User struct {
	Username          string        `datastore:"Username" json:"username"`
	Password          string        `datastore:"password,noindex" password:"password,omitempty"`
	Session           string        `datastore:"session,noindex" json:"session"`
	Verified          bool          `datastore:"verified,noindex" json:"verified"`
	PrivateApps       []WorkflowApp `datastore:"privateapps" json:"privateapps":`
	Role              string        `datastore:"role" json:"role"`
	Roles             []string      `datastore:"roles" json:"roles"`
	VerificationToken string        `datastore:"verification_token" json:"verification_token"`
	ApiKey            string        `datastore:"apikey" json:"apikey"`
	ResetReference    string        `datastore:"reset_reference" json:"reset_reference"`
	Executions        ExecutionInfo `datastore:"executions" json:"executions"`
	Limits            UserLimits    `datastore:"limits" json:"limits"`
	Authentication    []UserAuth    `datastore:"authentication,noindex" json:"authentication"`
	ResetTimeout      int64         `datastore:"reset_timeout,noindex" json:"reset_timeout"`
	Id                string        `datastore:"id" json:"id"`
	Orgs              []string      `datastore:"orgs" json:"orgs"`
	CreationTime      int64         `datastore:"creation_time" json:"creation_time"`
	ActiveOrg         OrgMini       `json:"active_org" datastore:"active_org"`
	Active            bool          `datastore:"active" json:"active"`
	FirstSetup        bool          `datastore:"first_setup" json:"first_setup"`
	LoginType         string        `datastore:"login_type" json:"login_type"`
}

type Session struct {
	Username string `datastore:"Username,noindex"`
	Id       string `datastore:"Id,noindex"`
	UserId   string `datastore:"user_id,noindex"`
	Session  string `datastore:"session,noindex"`
}

type Contact struct {
	Firstname   string `json:"firstname"`
	Lastname    string `json:"lastname"`
	Title       string `json:"title"`
	Companyname string `json:"companyname"`
	Phone       string `json:"phone"`
	Email       string `json:"email"`
	Message     string `json:"message"`
}

type Translator struct {
	Src struct {
		Name        string `json:"name" datastore:"name"`
		Value       string `json:"value" datastore:"value"`
		Description string `json:"description" datastore:"description"`
		Required    string `json:"required" datastore:"required"`
		Type        string `json:"type" datastore:"type"`
		Schema      struct {
			Type string `json:"type" datastore:"type"`
		} `json:"schema" datastore:"schema"`
	} `json:"src" datastore:"src"`
	Dst struct {
		Name        string `json:"name" datastore:"name"`
		Value       string `json:"value" datastore:"value"`
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
	Value string `json:"value" datastore:"value"`
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
	Id          string       `json:"id" datastore:"id"`
	Start       string       `json:"start" datastore:"start"`
	Info        Info         `json:"info" datastore:"info"`
	Actions     []HookAction `json:"actions" datastore:"actions,noindex"`
	Type        string       `json:"type" datastore:"type"`
	Owner       string       `json:"owner" datastore:"owner"`
	Status      string       `json:"status" datastore:"status"`
	Workflows   []string     `json:"workflows" datastore:"workflows"`
	Running     bool         `json:"running" datastore:"running"`
	OrgId       string       `json:"org_id" datastore:"org_id"`
	Environment string       `json:"environment" datastore:"environment"`
	Auth        string       `json:"auth" datastore:"auth"`
}

// Used within a user
type OrgMini struct {
	Name       string     `json:"name" datastore:"name"`
	Id         string     `json:"id" datastore:"id"`
	Users      []UserMini `json:"users" datastore:"users"`
	Role       string     `json:"role" datastore:"role"`
	CreatorOrg string     `json:"creator_org" datastore:"creator_org"`
	Image      string     `json:"image" datastore:"image,noindex"`
}

type Org struct {
	Name            string                `json:"name" datastore:"name"`
	Description     string                `json:"description" datastore:"description"`
	Image           string                `json:"image" datastore:"image,noindex"`
	Id              string                `json:"id" datastore:"id"`
	Org             string                `json:"org" datastore:"org"`
	Users           []User                `json:"users" datastore:"users"`
	Role            string                `json:"role" datastore:"role"`
	Roles           []string              `json:"roles" datastore:"roles"`
	ActiveApps      []string              `json:"active_apps" datastore:"active_apps"`
	CloudSync       bool                  `json:"cloud_sync" datastore:"CloudSync"`
	CloudSyncActive bool                  `json:"cloud_sync_active" datastore:"CloudSyncActive"`
	SyncConfig      SyncConfig            `json:"sync_config" datastore:"sync_config"`
	SyncFeatures    SyncFeatures          `json:"sync_features" datastore:"sync_features"`
	Subscriptions   []PaymentSubscription `json:"subscriptions" datastore:"subscriptions"`
	SyncUsage       SyncUsage             `json:"sync_usage" datastore:"sync_usage"`
	Created         int64                 `json:"created" datastore:"created"`
	Edited          int64                 `json:"edited" datastore:"edited"`
	Defaults        Defaults              `json:"defaults" datastore:"defaults"`
	Invites         []string              `json:"invites" datastore:"invites"`
	ChildOrgs       []OrgMini             `json:"child_orgs" datastore:"child_orgs"`
	ManagerOrgs     []OrgMini             `json:"manager_orgs" datastore:"manager_orgs"` // Multi in case more than one org should be able to control another
	CreatorOrg      string                `json:"creator_org" datastore:"creator_org"`
	SSOConfig       SSOConfig             `json:"sso_config" datastore:"sso_config"`
}

type Defaults struct {
	AppDownloadRepo        string `json:"app_download_repo" datastore:"app_download_repo"`
	AppDownloadBranch      string `json:"app_download_branch" datastore:"app_download_branch"`
	WorkflowDownloadRepo   string `json:"workflow_download_repo" datastore:"workflow_download_repo"`
	WorkflowDownloadBranch string `json:"workflow_download_branch" datastore:"workflow_download_branch"`
}

type CacheKeyData struct {
	Success       bool   `json:"success"`
	WorkflowId    string `json:"workflow_id,"`
	ExecutionId   string `json:"execution_id,omityempty"`
	Authorization string `json:"authorization,omitempty"`
	OrgId         string `json:"org_id,omitempty"`
	Key           string `json:"key"`
	Value         string `json:"value"`
	Edited        int64  `json:"edited"`
}

type SyncConfig struct {
	Interval int64  `json:"interval" datastore:"interval"`
	Apikey   string `json:"api_key" datastore:"api_key"`
	Source   string `json:"source" datastore:"source"`
}

type PaymentSubscription struct {
	Active           bool   `json:"active" datastore:"active"`
	Startdate        int64  `json:"startdate" datastore:"startdate"`
	CancellationDate int64  `json:"cancellationdate" datastore:"cancellationdate"`
	Enddate          int64  `json:"enddate" datastore:"enddate"`
	Name             string `json:"name" datastore:"name"`
	Recurrence       string `json:"recurrence" datastore:"recurrence"`
	Reference        string `json:"reference" datastore:"reference"`
	Level            string `json:"level" datastore:"level"`
	Amount           string `json:"amount" datastore:"amount"`
	Currency         string `json:"currency" datastore:"currency"`
}

type SyncUsage struct {
	Webhook            SyncDataUsage `json:"webhook" datastore:"webhook"`
	Schedules          SyncDataUsage `json:"schedules" datastore:"schedules"`
	UserInput          SyncDataUsage `json:"user_input" datastore:"user_input"`
	SendMail           SyncDataUsage `json:"send_mail" datastore:"send_mail"`
	SendSms            SyncDataUsage `json:"send_sms" datastore:"send_sms"`
	EmailTrigger       SyncDataUsage `json:"email_trigger" datastore:"email_trigger"`
	AppExecutions      SyncDataUsage `json:"app_executions" datastore:"app_executions"`
	WorkflowExecutions SyncDataUsage `json:"workflow_executions" datastore:"workflow_executions"`
	Apps               SyncDataUsage `json:"apps" datastore:"apps"`
	Workflows          SyncDataUsage `json:"workflows" datastore:"workflows"`
	Autocomplete       SyncDataUsage `json:"autocomplete" datastore:"autocomplete"`
	Authentication     SyncDataUsage `json:"authentication" datastore:"authentication"`
	Schedule           SyncDataUsage `json:"schedule" datastore:"schedule"`
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
	Value               string `json:"value" datastore:"value"`
	Created             int64  `json:"created" datastore:"created"`
	Id                  string `json:"id" datastore:"id"`
}

type SyncFeatures struct {
	Webhook            SyncData `json:"webhook" datastore:"webhook"`
	Schedules          SyncData `json:"schedules" datastore:"schedules"`
	UserInput          SyncData `json:"user_input" datastore:"user_input"`
	SendMail           SyncData `json:"send_mail" datastore:"send_mail"`
	SendSms            SyncData `json:"send_sms" datastore:"send_sms"`
	Updates            SyncData `json:"updates" datastore:"updates"`
	Notifications      SyncData `json:"notifications" datastore:"notifications"`
	EmailTrigger       SyncData `json:"email_trigger" datastore:"email_trigger"`
	AppExecutions      SyncData `json:"app_executions" datastore:"app_executions"`
	WorkflowExecutions SyncData `json:"workflow_executions" datastore:"workflow_executions"`
	Apps               SyncData `json:"apps" datastore:"apps"`
	Workflows          SyncData `json:"workflows" datastore:"workflows"`
	Autocomplete       SyncData `json:"autocomplete" datastore:"autocomplete"`
	Authentication     SyncData `json:"authentication" datastore:"authentication"`
	Schedule           SyncData `json:"schedule" datastore:"schedule"`
}

type SyncData struct {
	Active         bool   `json:"active" datastore:"active"`
	Type           string `json:"type,omitempty" datastore:"type"`
	Name           string `json:"name,omitempty" datastore:"name"`
	Description    string `json:"description,omitempty" datastore:"description"`
	Limit          int64  `json:"limit,omitempty" datastore:"limit"`
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
	WorkflowId          string         `json:"workflow_id" datastore:"workflow_id"`
	LastNode            string         `json:"last_node" datastore:"last_node"`
	Authorization       string         `json:"authorization" datastore:"authorization"`
	Result              string         `json:"result" datastore:"result,noindex"`
	StartedAt           int64          `json:"started_at" datastore:"started_at"`
	CompletedAt         int64          `json:"completed_at" datastore:"completed_at"`
	ProjectId           string         `json:"project_id" datastore:"project_id"`
	Locations           []string       `json:"locations" datastore:"locations"`
	Workflow            Workflow       `json:"workflow" datastore:"workflow,noindex"`
	Results             []ActionResult `json:"results" datastore:"results,noindex"`
	ExecutionVariables  []Variable     `json:"execution_variables,omitempty" datastore:"execution_variables,omitempty"`
	OrgId               string         `json:"org_id" datastore:"org_id"`
	SubExecutionCount   int64          `json:"sub_execution_count" yaml:"sub_execution_count"`
	ExecutionSource     string         `json:"execution_source" datastore:"execution_source"`
	ExecutionParent     string         `json:"execution_parent" datastore:"execution_parent"`
	ExecutionSourceNode string         `json:"execution_source_node" yaml:"execution_source_node"`
	ExecutionSourceAuth string         `json:"execution_source_auth" yaml:"execution_source_auth"`
}

// This is for the nodes in a workflow, NOT the app action itself.
type Action struct {
	AppName           string                       `json:"app_name" datastore:"app_name"`
	AppVersion        string                       `json:"app_version" datastore:"app_version"`
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
	ExecutionVariable Variable                     `json:"execution_variable,omitempty" datastore:"execution_variable,omitempty"`
	Position          struct {
		X float64 `json:"x,omitempty" datastore:"x"`
		Y float64 `json:"y,omitempty" datastore:"y"`
	} `json:"position,omitempty"`
	Priority         int    `json:"priority,omitempty" datastore:"priority"`
	AuthenticationId string `json:"authentication_id" datastore:"authentication_id"`
	Example          string `json:"example,omitempty" datastore:"example,noindex"`
	AuthNotRequired  bool   `json:"auth_not_required,omitempty" datastore:"auth_not_required" yaml:"auth_not_required"`
	Category         string `json:"category" datastore:"category"`
	ReferenceUrl     string `json:"reference_url" datastore:"reference_url"`
	SubAction        bool   `json:"sub_action" datastore:"sub_action"`
	SourceWorkflow   string `json:"source_workflow" yaml:"source_workflow" datastore:"source_workflow"`
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
	Priority       int    `json:"priority" datastore:"priority"`
	SourceWorkflow string `json:"source_workflow" yaml:"source_workflow" datastore:"source_workflow"`
}

type Branch struct {
	DestinationID string      `json:"destination_id" datastore:"destination_id"`
	ID            string      `json:"id" datastore:"id"`
	SourceID      string      `json:"source_id" datastore:"source_id"`
	Label         string      `json:"label" datastore:"label"`
	HasError      bool        `json:"has_errors" datastore: "has_errors"`
	Conditions    []Condition `json:"conditions" datastore: "conditions"`
	Decorator     bool        `json:"decorator" datastore:"decorator"`
}

// Same format for a lot of stuff
type Condition struct {
	Condition   WorkflowAppActionParameter `json:"condition" datastore:"condition"`
	Source      WorkflowAppActionParameter `json:"source" datastore:"source"`
	Destination WorkflowAppActionParameter `json:"destination" datastore:"destination"`
}

type Schedule struct {
	Name              string `json:"name" datastore:"name"`
	Frequency         string `json:"frequency" datastore:"frequency"`
	ExecutionArgument string `json:"execution_argument" datastore:"execution_argument,noindex"`
	Id                string `json:"id" datastore:"id"`
	OrgId             string `json:"org_id" datastore:"org_id"`
	Environment       string `json:"environment" datastore:"environment"`
}

type Workflow struct {
	Actions        []Action   `json:"actions" datastore:"actions,noindex"`
	Branches       []Branch   `json:"branches" datastore:"branches,noindex"`
	VisualBranches []Branch   `json:"visual_branches" datastore:"visual_branches,noindex"`
	Triggers       []Trigger  `json:"triggers" datastore:"triggers,noindex"`
	Schedules      []Schedule `json:"schedules" datastore:"schedules,noindex"`
	Configuration  struct {
		ExitOnError  bool `json:"exit_on_error" datastore:"exit_on_error"`
		StartFromTop bool `json:"start_from_top" datastore:"start_from_top"`
	} `json:"configuration,omitempty" datastore:"configuration"`
	Created              int64      `json:"created" datastore:"created"`
	Edited               int64      `json:"edited" datastore:"edited"`
	LastRuntime          int64      `json:"last_runtime" datastore:"last_runtime"`
	Errors               []string   `json:"errors,omitempty" datastore:"errors"`
	Tags                 []string   `json:"tags,omitempty" datastore:"tags"`
	ID                   string     `json:"id" datastore:"id"`
	IsValid              bool       `json:"is_valid" datastore:"is_valid"`
	Name                 string     `json:"name" datastore:"name"`
	Description          string     `json:"description" datastore:"description,noindex"`
	Start                string     `json:"start" datastore:"start"`
	Owner                string     `json:"owner" datastore:"owner"`
	Sharing              string     `json:"sharing" datastore:"sharing"`
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
	DefaultReturnValue   string     `json:"default_return_value" datastore:"default_return_value"`
	ContactInfo          struct {
		Name string `json:"name" datastore:"name" yaml:"name"`
		Url  string `json:"url" datastore:"url" yaml:"url"`
	} `json:"contact_info" datastore:"contact_info" yaml:"contact_info" required:false`
	PublishedId string `json:"published_id" yaml:"published_id"`
}

type Category struct {
	Name        string `json:"name" datastore:"name"`
	Description string `json:"description" datastore:"description"`
	Count       int64  `json:"count" datastore:"count"`
}

type Categories struct {
	SIEM          Category `json:"siem" datastore:"siem"`
	Communication Category `json:"communication" datastore:"communication"`
	Assets        Category `json:"assets" datastore:"assets"`
	Cases         Category `json:"cases" datastore:"cases"`
	Network       Category `json:"network" datastore:"network"`
	Intel         Category `json:"intel" datastore:"intel"`
	EDR           Category `json:"edr" datastore:"edr"`
	Other         Category `json:"other" datastore:"other"`
}

type ActionResult struct {
	Action        Action `json:"action" datastore:"action"`
	ExecutionId   string `json:"execution_id" datastore:"execution_id"`
	Authorization string `json:"authorization" datastore:"authorization"`
	Result        string `json:"result" datastore:"result,noindex"`
	StartedAt     int64  `json:"started_at" datastore:"started_at"`
	CompletedAt   int64  `json:"completed_at" datastore:"completed_at"`
	Status        string `json:"status" datastore:"status"`
}

type AuthenticationUsage struct {
	WorkflowId string   `json:"workflow_id" datastore:"workflow_id"`
	Nodes      []string `json:"nodes" datastore:"nodes"`
}

type File struct {
	Id           string   `json:"id" datastore:"id"`
	Type         string   `json:"type" datastore:"type"`
	CreatedAt    int64    `json:"created_at" datastore:"created_at"`
	UpdatedAt    int64    `json:"updated_at" datastore:"updated_at"`
	MetaAccessAt int64    `json:"meta_access_at" datastore:"meta_access_at"`
	DownloadAt   int64    `json:"last_downloaded" datastore:"last_downloaded"`
	Description  string   `json:"description" datastore:"description"`
	ExpiresAt    string   `json:"expires_at" datastore:"expires_at"`
	Status       string   `json:"status" datastore:"status"`
	Filename     string   `json:"filename" datastore:"filename"`
	URL          string   `json:"url" datastore:"org"`
	OrgId        string   `json:"org_id" datastore:"org_id"`
	WorkflowId   string   `json:"workflow_id" datastore:"workflow_id"`
	Workflows    []string `json:"workflows" datastore:"workflows"`
	DownloadPath string   `json:"download_path" datastore:"download_path"`
	Md5sum       string   `json:"md5_sum" datastore:"md5_sum"`
	Sha256sum    string   `json:"sha256_sum" datastore:"sha256_sum"`
	FileSize     int64    `json:"filesize" datastore:"filesize"`
	Duplicate    bool     `json:"duplicate" datastore:"duplicate"`
	Subflows     []string `json:"subflows" datastore:"subflows"`
	StorageArea  string   `json:"storage_area" datastore:"storage_area"`
	Etag         int      `json:"etag" datastore:"etag"`
	ContentType  string   `json:"content_type" datastore:"content_type"`
	UpdatedBy    string   `json:"updated_by" datastore:"updated_by"`
	CreatedBy    string   `json:"created_by" datastore:"created_by"`
	Namespace    string   `json:"namespace" datastore:"namespace"`
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

type AlgoliaSearchWorkflow struct {
	Name          string   `json:"name"`
	ObjectID      string   `json:"objectID"`
	Description   string   `json:"description"`
	Variables     int      `json:"variables"`
	ActionAmount  int      `json:"action_amount"`
	TriggerAmount int      `json:"trigger_amount"`
	Triggers      []string `json:"triggers"`
	Actions       []string `json:"actions"`
	Tags          []string `json:"tags"`
	Categories    []string `json:"categories"`
	AccessibleBy  []string `json:"accessible_by"`
	ImageUrl      string   `json:"image_url"`
	TimeEdited    int64    `json:"time_edited"`
	Invalid       bool     `json:"invalid"`
	Creator       string   `json:"creator"`
	Priority      int      `json:"priority"`
	SourceIP      string   `json:"source_ip`
}

type AlgoliaSearchApp struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	ObjectID     string   `json:"objectID"`
	Actions      int      `json:"actions"`
	Tags         []string `json:"tags"`
	Categories   []string `json:"categories"`
	AccessibleBy []string `json:"accessible_by"`
	ImageUrl     string   `json:"image_url"`
	TimeEdited   int64    `json:"time_edited"`
	Generated    bool     `json:"generated"`
	Invalid      bool     `json:"invalid"`
	Creator      string   `json:"creator"`
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

	Username   string     `json:"username" datastore:"username,noindex"`
	Owner      string     `json:"owner" datastore:"owner"`
	Type       string     `json:"type" datastore:"type"`
	Code       string     `json:"code,omitempty" datastore:"code,noindex"`
	WorkflowId string     `json:"workflow_id" datastore:"workflow_id,noindex"`
	Start      string     `json:"start" datastore:"start"`
	OauthToken OauthToken `json:"oauth_token,omitempty" datastore:"oauth_token"`
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
	}
}

type MailData struct {
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

type FileList struct {
	Success bool     `json:"success"`
	Reason  string   `json:"reason"`
	List    []string `json:"list"`
}

type SessionCookie struct {
	Key        string `json:"key"`
	Value      string `json:"value"`
	Expiration int64  `json:"expiration"`
}

type HandleInfo struct {
	Success    bool            `json:"success"`
	Admin      string          `json:"admin"`
	Username   string          `json:"username"`
	Tutorials  []string        `json:"tutorials"`
	ActiveApps []string        `json:"active_apps"`
	Id         string          `json:"id"`
	Orgs       []OrgMini       `json:"orgs"`
	ActiveOrg  OrgMini         `json:"active_org"`
	Cookies    []SessionCookie `json:"session_cookie"`
}

type BuildLaterStruct struct {
	Tags  []string
	Extra string
	Id    string
}

// Overwriting results fo a subflow trigger
type SubflowData struct {
	Success       bool   `json:"success"`
	ExecutionId   string `json:"execution_id"`
	Authorization string `json:"authorization"`
	Result        string `json:"result"`
}

// AuthenticationStore with oauth2
type Oauth2Resp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	ExtExpiresIn int    `json:"ext_expires_in"`
}

// The data to be parsed
type DataToSend struct {
	Code         string `url:"code" json:"code"`
	GrantType    string `url:"grant_type" json:"grant_type"`
	ClientSecret string `url:"client_secret" json:"client_secret"`
	ClientId     string `url:"client_id" json:"client_id"`
	Scope        string `url:"scope" json:"scope"`
	RedirectUri  string `url:"redirect_uri" json:"redirect_uri"`
}

type FileResponse struct {
	Files      []File   `json:"files" datastore:"files"`
	Namespaces []string `json:"namespaces" datastore:"namespaces"`
}

type SSOConfig struct {
	SSOEntrypoint  string `json:"sso_entrypoint" datastore:"sso_entrypoint"`
	SSOCertificate string `json:"sso_certificate" datastore:"sso_certificate"`
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
