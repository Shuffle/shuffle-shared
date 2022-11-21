org.go

func HandleGetOrgs(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get orgs: %s", err)
        setResponse(resp, request, 401, `{"success": false}`)
		return
	}

	ctx := GetContext(request)
	if user.Role != "global_admin" {
		orgs := []OrgMini{}
		for _, item := range user.Orgs {
			// FIXM: Should return normal orgs, but hidden if the user isn't admin
			org, err := GetOrg(ctx, item)
			if err == nil {
				orgs = append(orgs, OrgMini{
					Id:         org.Id,
					Name:       org.Name,
					CreatorOrg: org.CreatorOrg,
					Image:      org.Image,
				})
				// Role:       "admin",
			}
		}

		newjson, err := json.Marshal(orgs)
		if err != nil {
			log.Printf("[WARNING] Failed marshal in get orgs: %s", err)
            setResponse(resp, request, 401, `{"success": false, "reason": "Failed unpacking"}`)
			return
		}

		//log.Printf("[AUDIT] User %s (%s) isn't global admin and can't list orgs. Returning list of local orgs.", user.Username, user.Id)
        setResponse(resp, request, 200, newjson)
		return
	}

	orgs, err := GetAllOrgs(ctx)
	if err != nil || len(orgs) == 0 {
		log.Printf("[WARNING] Failed getting orgs: %s", err)
        setResponse(resp, request, 401, `{"success": false, "reason": "Can't get orgs"}`)
		return
	}

	newjson, err := json.Marshal(orgs)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshal in get orgs: %s", err)
        setResponse(resp, request, 401, `{"success": false, "reason": "Failed unpacking"}`)
		return
	}

    setResponse(resp, request, 200, newjson)
}

func HandleGetOrg(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	var fileId string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("Path too short: %d", len(location))
            setResponse(resp, request, 401, `{"success": false}`)
			return
		}

		fileId = location[4]
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get org: %s", err)
        setResponse(resp, request, 401, `{"success": false}`)
		return
	}

	ctx := GetContext(request)
	org, err := GetOrg(ctx, fileId)
	if err != nil {
        setResponse(resp, request, 401, `{"success": false, "reason": "Failed getting org details"}`)
		return
	}

	admin := false
	userFound := false
	for _, inneruser := range org.Users {
		if inneruser.Id == user.Id {
			userFound = true

			if inneruser.Role == "admin" {
				admin = true
			}

			break
		}
	}

	if !userFound {
		log.Printf("[ERROR] User %s (%s) isn't a part of org %s (get)", user.Username, user.Id, org.Id)
        setResponse(resp, request, 401, `{"success": false, "reason": "User doesn't have access to org"}`)
		return

	}

	if !admin {
		org.Defaults = Defaults{}
		org.SSOConfig = SSOConfig{}
		org.Subscriptions = []PaymentSubscription{}
		org.ManagerOrgs = []OrgMini{}
		org.ChildOrgs = []OrgMini{}
		org.Invites = []string{}
	} else {
		org.SyncFeatures.AppExecutions.Description = "The amount of Apps within Workflows you can run per month. This limit can be exceeded when running workflows without a trigger (manual execution)."
		org.SyncFeatures.WorkflowExecutions.Description = "N/A. See App Executions"
		org.SyncFeatures.Webhook.Description = "Webhooks are Triggers that take an HTTP input to start a workflow. Read docs for more."
		org.SyncFeatures.Schedules.Description = "Schedules are Triggers that run on an interval defined by you. Read docs for more."
		org.SyncFeatures.MultiEnv.Description = "Multiple Environments are used to run automation in different physical locations. Change from /admin?tab=environments"
		org.SyncFeatures.MultiTenant.Description = "Multiple Tenants can be used to segregate information for each MSSP Customer. Change from /admin?tab=suborgs"
		//org.SyncFeatures.MultiTenant.Description = "Multiple Tenants can be used to segregate information for each MSSP Customer. Change from /admin?tab=suborgs"

		//log.Printf("LIMIT: %#v", org.SyncFeatures.AppExecutions.Limit)
		orgChanged := false
		if org.SyncFeatures.AppExecutions.Limit == 0 || org.SyncFeatures.AppExecutions.Limit == 1500 {
			org.SyncFeatures.AppExecutions.Limit = 5000
			orgChanged = true
		}

		if org.SyncFeatures.SendMail.Limit == 0 {
			org.SyncFeatures.SendMail.Limit = 100
			orgChanged = true
		}

		if org.SyncFeatures.SendSms.Limit == 0 {
			org.SyncFeatures.SendSms.Limit = 30
			orgChanged = true
		}

		org.SyncFeatures.EmailTrigger.Limit = 0
		if org.SyncFeatures.MultiEnv.Limit == 0 {
			org.SyncFeatures.MultiEnv.Limit = 1
			orgChanged = true
		}

		org.SyncFeatures.EmailTrigger.Limit = 0

		if orgChanged {
			log.Printf("[DEBUG] Org features for %s (%s) changed. Updating.", org.Name, org.Id)
			err = SetOrg(ctx, *org, org.Id)
			if err != nil {
				log.Printf("[WARNING] Failed updating org during org loading")
			}
		}

		info, err := GetOrgStatistics(ctx, fileId)
		if err == nil {
			org.SyncFeatures.AppExecutions.Usage = info.MonthlyAppExecutions
		}

		org.SyncFeatures.MultiTenant.Usage = int64(len(org.ChildOrgs) + 1)
		envs, err := GetEnvironments(ctx, fileId)
		if err == nil {
			//log.Printf("Envs: %#v", len(envs))
			org.SyncFeatures.MultiEnv.Usage = int64(len(envs))
		}
	}

	org.Users = []User{}
	org.SyncConfig.Apikey = ""
	org.SyncConfig.Source = ""

	newjson, err := json.Marshal(org)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshal of org %s (%s): %s", org.Name, org.Id, err)
        setResponse(resp, request, 401, `{"success": false, "reason": "Failed unpacking"}`)
		return
	}

    setResponse(resp, request, 200, newjson)
}