package shuffle


func GetBaseDockerfile() []byte {
	return []byte(`FROM frikky/shuffle:app_sdk as base

# We're going to stage away all of the bloat from the build tools so lets create a builder stage
FROM base as builder

# Install all alpine build tools needed for our pip installs
RUN apk --no-cache add --update alpine-sdk libffi libffi-dev musl-dev openssl-dev git

# Install all of our pip packages in a single directory that we can copy to our base image later
RUN mkdir /install
WORKDIR /install
COPY requirements.txt /requirements.txt
RUN pip install --no-cache-dir --prefix="/install" -r /requirements.txt

# Switch back to our base image and copy in all of our built packages and source code
FROM base
COPY --from=builder /install /usr/local
COPY src /app

# Install any binary dependencies needed in our final image
# RUN apk --no-cache add --update my_binary_dependency
RUN apk --no-cache add jq git curl

# Finally, lets run our app!
WORKDIR /app
CMD ["python", "app.py", "--log-level", "DEBUG"]`)
}

func GetWorkflowTest() []byte { 
	return []byte(`{"actions":[{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Set a value to be saved to your organization in Shuffle.","app_id":"b53109ec-2873-4076-9826-4e7f586dc714","errors":[],"id":"c93c2ce0-e42a-4d30-8a2e-e9adb7ee7cc4","is_valid":true,"isStartNode":true,"sharing":true,"label":"Change Me","public":true,"generated":false,"large_image":"","environment":"Shuffle","name":"set_cache_value","parameters":[{"description":"The key to set the value for","id":"","name":"key","example":"timestamp","value":"$onprem_dashboard_testing","multiline":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false},{"description":"The value to set","id":"","name":"value","example":"1621959545","value":"192.168.2.3 https://google.com","multiline":true,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":-142.20343154942202,"y":130.5567750670353},"authentication_id":"","category":"","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Get a value saved to your organization in Shuffle","app_id":"b53109ec-2873-4076-9826-4e7f586dc714","errors":[],"id":"f8a44502-e350-4180-933c-f7c3d7e8460b","is_valid":true,"sharing":true,"label":"Shuffle_Tools_3","public":true,"generated":false,"large_image":"","environment":"Shuffle","name":"get_cache_value","parameters":[{"description":"The key to get","id":"","name":"key","example":"timestamp","value":"$onprem_dashboard_testing","multiline":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":-133.57704208335156,"y":308.69403928684073},"authentication_id":"","category":"Other","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false},{"app_name":"Shuffle Tools","app_version":"1.2.0","description":"Delete a value saved to your organization in Shuffle","app_id":"b53109ec-2873-4076-9826-4e7f586dc714","errors":[],"id":"240b5c73-72eb-4ff0-b177-1dbf5a3cb854","is_valid":true,"sharing":true,"label":"Shuffle_Tools_3_copy","public":true,"generated":false,"large_image":"","environment":"Shuffle","name":"delete_cache_value","parameters":[{"description":"The key to delete","id":"","name":"key","example":"timestamp","value":"$onprem_dashboard_testing","multiline":false,"options":null,"action_field":"","variant":"STATIC_VALUE","required":true,"configuration":false,"tags":null,"schema":{"type":"string"},"skip_multicheck":false,"value_replace":null,"unique_toggled":false}],"execution_variable":{"description":"","id":"","name":"","value":""},"position":{"x":-130.2282403427722,"y":480.74311435295436},"authentication_id":"","category":"Other","reference_url":"","sub_action":false,"source_workflow":"","run_magic_output":false,"run_magic_input":false,"execution_delay":0,"category_label":null,"suggestion":false}],"branches":[{"destination_id":"f8a44502-e350-4180-933c-f7c3d7e8460b","id":"73ed3768-a385-4e8d-a8f5-d7fba4f6ea7e","source_id":"c93c2ce0-e42a-4d30-8a2e-e9adb7ee7cc4","label":"","has_errors":false,"conditions":null,"decorator":false},{"destination_id":"240b5c73-72eb-4ff0-b177-1dbf5a3cb854","id":"34a30674-1325-41fd-90ab-f517cbeb6aa0","source_id":"f8a44502-e350-4180-933c-f7c3d7e8460b","label":"","has_errors":false,"conditions":null,"decorator":false}],"visual_branches":[],"triggers":[],"schedules":[],"comments":[],"configuration":{"exit_on_error":false,"start_from_top":false,"skip_notifications":false},"created":1692126563,"edited":1697725624,"last_runtime":0,"due_date":1697587200,"tags":["test"],"id":"1cd69f13-5f82-462c-b8e1-91a5fbac4746","is_valid":true,"name":"Workflow Testing","description":"Used for workflow testing in Shuffle Onprem","start":"c93c2ce0-e42a-4d30-8a2e-e9adb7ee7cc4","owner":"7cff070a-e888-4e27-a575-39769b6102c2","sharing":"private","image":"","execution_org":{"name":"default","id":"ba4d38b7-db3f-4908-9ccb-47ec03f2963e","users":[],"role":"","creator_org":"","image":"","child_orgs":null,"region_url":""},"org_id":"ba4d38b7-db3f-4908-9ccb-47ec03f2963e","workflow_variables":[{"description":"","id":"7e50be7e-e774-4f4b-ac44-34c5f786eb32","name":"onprem_dashboard_testing","value":"onprem_dashboard_testing"}],"execution_environment":"","previously_saved":true,"categories":{"siem":{"name":"","count":0,"id":"","description":"","large_image":""},"communication":{"name":"","count":0,"id":"","description":"","large_image":""},"assets":{"name":"","count":0,"id":"","description":"","large_image":""},"cases":{"name":"","count":0,"id":"","description":"","large_image":""},"network":{"name":"","count":0,"id":"","description":"","large_image":""},"intel":{"name":"","count":0,"id":"","description":"","large_image":""},"edr":{"name":"","count":0,"id":"","description":"","large_image":""},"iam":{"name":"","count":0,"id":"","description":"","large_image":""},"email":{"name":"","count":0,"id":"","description":"","large_image":""},"other":{"name":"","count":2,"id":"","description":"","large_image":""}},"example_argument":"","public":false,"default_return_value":"","contact_info":{"name":"","url":""},"published_id":"","revision_id":"","usecase_ids":["Email management"],"blogpost":"","video":"","status":"test","workflow_type":"standalone","generated":false,"hidden":false,"updated_by":"admin"}`)
}

func GetOnpremPaidEula() string {
	return (
`Shuffle AS - EULA
The Shuffle End User License Agreement is a legally binding contract between Shuffle and the user of Shuffle's services. By accepting this, you agree to the terms and conditions of this agreement. The Agreement is meant for those intending to buy Shuffle's services, and not when using the Free Open Source or Freemium versions of Shuffle. If you do not agree to these terms, please reach out to support@shuffler.io so we can discuss and create a custom contract.

Any quotation is monthly, and does not reflect any applicable sales tax unless otherwise specified. If you want this contract in PDF form, please contact support@shuffler.io

Shuffle Services
This section describes each part of the previously mentioned services in detail.
About the Shuffle Scale and Support plan
The Shuffle Scale and Support plan is made for anyone that wants to operate Shuffle within their own environment, with the option to scale out easily. It includes an upgraded license for the “Orborus” and “Worker” system, and includes regular, continuous support to help with uptime and maintenance of your Shuffle systems. The Shuffle team will spend time with you at the start of our contract to get your supported instance up and running, and provide a point of contact within Shuffle AS. Also included in the plan is assistance building your first workflows, as well as as many integrations as you want based on OpenAPI. This plan is aimed at growing together, and uses scalable pricing, starting at $75/core. As we grow together, this will be extended as seen below. 

Cost breakdown - Onprem:
- $75/core/month for the first 32 cores
- $60/core/month for the next 32 cores
- After $60/month, custom pricing is advised.		


If the customer has more throughput than what their paid infrastructure can handle, Shuffle can not and will not guarantee high availability of Shuffle and its services, unless more computational resources are made available. In the case Shuffle has helped scope and decide the amount of computational resources necessary to handle the amount of throughput, but these are underestimated or further scale is required because of the underestimation, this does not lead to further costs on the side of the customer until contract renegotiations.

About the Shuffle Cloud plan
The Shuffle Cloud plan is made for anyone that wants to use Shuffle as a Service (SaaS), without worrying about infrastructure or scalability. The Cloud plan includes, but is not limited to access to Multi-Tenancy, Multi-Region and an unlimited amount of Workflows, Users, Apps and Organizations, Workflows as Functions and more. Features such as Multi-Environments and running Workflows and their Actions on-premises are also available. Additional features added over time, will be made immediately available to the customer as it is released to their specific region. The pricing structure is based on the amount of App Runs completed per month. The Shuffle team will spend time with you at the start of the contract to make sure we can fully support your Apps and API’s, and will be available for followup sessions to help with your automation needs, and provide a point of contact within Shuffle AS. 

Cost possibilities - Cloud:	
- Pay As you Go - $0.0042/App Run
- Bulk Pricing  - $180/100k App Runs/month
- After 1m App Runs/month, custom pricing is advised

Support
Support will be provided by our experienced team of customer engineers. We will provide expert guidance and / or support with upgrades, solution configuration, deployment and bug fixes. Support further includes help with deployment, and additionally periodic health checks twice a year. This includes a maximum of 16 hours of support the first month, and 8 hours of support per month the following months. Hours above these times incurs hourly on the consultancy rate. Our initial response time for critical issues like service downtime is 2 hours, with normal inquiries having a response time of 24 hours. 

Hybrid Cloud Access
Shuffle Cloud access is a part of Shuffle Open Source, and gives the customer access to features which aren’t feasible without the cloud integrations. This includes such features as Cloud Triggers, Configuration backups, workflow recommendations, a search engine. It will further be extended by new features as they become available, such as notifications and platform recommendations, New Triggers, App, playbook downloads, a cloud search engine and more. Hybrid Cloud can be enabled by following the Organization management documentation found here: https://shuffler.io/docs/organizations. All future features that are made for our Software-As-A-Service offering will be made accessible from the day they are implemented. All limits are soft limits which can be seen for each individual Organization in their Admin dashboard. Default limits include 10.000 app executions, 1000 emails and 300 SMS for free each month, with the addition of multi-tenant cloud environments to enable hybrid for each on-premises organization. If the limits are exceeded over multiple periods (>=2 months), Shuffle may stop access to either of these features after notifying the customer. 

Training
Training is not included by default. Training for Shuffle happens at a time agreed upon by Shuffle and Customer, and is accessible for up to 5 people. It is a two-day online course with a trainer from Shuffle (2x4 hours), and includes but is not limited to: Workflow Development, App Development and Debugging, Organizational Control, Execution exploration and Information searching. 

The normal cost for this training is $4999.

Consultancy
Consultancy gives you access to Non-recurring engineering (NRE), advice and process improvement by the experienced Shuffle team. NRE is any special development required that is not Integration or Workflow development, but special development of the Shuffle platform itself. Advice and process improvements are part of our goal to help operations teams work more effectively, and in a more standardized manner. 

Custom Shuffle App Development
Custom App Development in Shuffle incurs when the customer requires an integration or extension which Shuffle doesn’t already have a developed version of. We will develop the necessary functions of the App, as well as any Action the Customer sees necessary for future use-cases. This process is typically started based on a use-case, where Shuffle will help identify the needs of the customer. If this is not proprietary software, Shuffle will share the use-cases with the community to further support the community, and if agreed upon, Shuffle will add information about the Customer as the sponsor and/or creator of the App. 

Custom Workflow Development
Custom Workflow Development in Shuffle incurs when the customer requires a process to be automated with the help of Shuffle automation experts. If the workflow requires custom App Creation to fulfill the request, this does not incur extra hours of app development. Workflow development will start with a conversation between Shuffle and Customer to define our goals, before Customer gives access to a demo environment of the required tools if applicable. If this is not proprietary software or processes, Shuffle will share the use-cases with the community to further support the community, and if agreed upon, Shuffle will add information about the Customer as the sponsor and/or creator of the Workflow.

The goals of the Proof of Value are as follows:

Support plan
Roles
The Account Executive (AE)
The Account Executive (AE) at Shuffle is the one who is responsible for prospecting customers and finding out whether or not the customer is a good fit for Shuffles’ services in the first place. Along with prospecting, The Account Executive works with the inside sales team to follow up with meetings for generated leads. The AE also works with the Pre-Sales Engineer to not only uncover pain points, but also strategize to translate current problems to solutions that the Shuffle Console solves.

The Account Executive is further tasked with telling the Shuffle story and explaining to the customer the vision that Shuffle has for our services. The big message that the Account Executive should get across is the economics behind Shuffle’s services. It is a lot cheaper for Shuffle to manage the customers’ Shuffle instance and provide the customer with additional add-ons, rather than trying to get internal staff fully up to speed on the product without training. Additionally, the account executive is the one who must submit the necessary documents such as the Deal Reg, NDA, MSA, SOW, RFP, and any other formal proposal documents to the customer for signature.

Automation Specialist (AS)
The Automation Specialist is the engineer assigned to ensure the customer’s automation needs are fulfilled as per the SLA. They will work with the TAM during the initialization and onboarding phase for default use-case implementations, and be the consultant for any extra service the customer may need. They may further work with the AE, TAM and developers to provide custom resources and training to the customer to ensure they understand the environment they are working with.

The Technical Account Manager (TAM)
The Technical Account Manager (TAM) is essentially the Tier III support engineer for a Shuffle customer. A TAM is assigned to a Shuffle customer as soon as the deal has been executed by the Account Executive, and becomes the primary point of contact for the customer. The Technical Account Manager oversees the initial Shuffle implementation and ongoing management phase after the initial deployment is complete. The Technical Account Manager is the one who will conduct the more difficult work of configuring SAML/OIDC, custom scaling configurations, Integration Management, Security Policy and Network Zone Setup and applicable Lifecycle Management configurations. Additionally, the Technical Account Manager may work with the Helpdesk support and Automation Specialists to not only get them up to speed on some more difficult tasks, but also assist them in some of the easier tasks during the initial Shuffle implementation.

After the implementation is complete, the TAM will be held accountable for the management of the customer. The TAM will oversee maintenance of the Shuffle customer, add/remove applications and other technologies to/from the Instance, work with the Shuffle development team for necessary features for the customer, and answer any highly technical questions the customer may have. For SLA purposes, the TAM will handle any major outages the Shuffle customer may experience or any support issue that the Helpdesk support or ATAM is unable to answer on their own. 
The Associate Technical Account Manager (ATAM)
Similarly, to the TAM, the Associate Technical Account Manager (ATAM) is best compared to the Tier II support engineer in any other scenario. During the implementation phase, the ATAM may take over the more remedial tasks such as Integrating customer applications and building out Shuffle workflows according to what the customer needs, together with our Automation specialists. The ATAM further observes the TAM during the more difficult tasks in hopes that one day the ATAM becomes a TAM. 

During the Management phase of the Shuffle implementation, the ATAM handles the day-to-day operations on behalf of the customer as per the defined SLA. These tasks include updating the instance, providing guidance for the customer, working with Helpdesk support etc. The ATAM also takes points on the Helpdesk during work hours. If any request comes through the helpdesk from the ATAM’s customer, then the ATAM is expected to handle and respond to the request as soon as possible. If a request comes through such as a major outage or another request that the ATAM is not capable of handling on his/her own, it is the ATAM’s responsibility to escalate the request to the TAM for remediation. Along with the helpdesk, it is the ATAM’s duty to work with the AE for any required reporting. The ATAM is responsible for pulling the necessary data from the customer’s systems, and preparing it for analysis in the case of custom updates.

The ATAM may be working as a partner of Shuffle to be able to cover business hours in certain geographical areas. Introduction and building will be discussed with the customer and partner, and be a part of the onboarding phase.
Tier I Helpdesk Support
The General Tier I Helpdesk Support role will serve as the helpdesk Point of Contact during the limited after-hours time window as spelled out in the Shuffle SLA. If any request comes up during this off-hours time, it is the Tier I Helpdesk support’s duty to respond to the customer to meet the SLA and then route the request to the TAM or ATAM support for a proper follow-up response to the customer. If the request is not urgent, the Tier I will pass along the ticket to the TAM or ATAM support so that they may begin work on the request the following morning. If the request is super urgent, it is the Tier I’s duty to get a hold of the TAM for immediate action and remediation.

The ATAM may be working as a partner of Shuffle to be able to cover business hours in certain geographical areas. Introduction and building will be discussed with the customer and partner, and be a part of the onboarding phase.
Support priorities

Shuffle’s support team will provide support via remote assistance. All requests will be performed via email or our support portal. Critical events can be performed by phone, and we will provide you with an alert email to reach us at any time after you have accepted this EULA and paid for Shuffle's services.

Priority
Business Impact


Critical
Trouble conditions where Shuffle is completely out of service, and is causing business impact to the customer.

High
Trouble conditions where Shuffle is not fully functional, and is causing business impact to the customer.

Medium
Trouble conditions where Shuffle is not fully functional, but is not causing business impact to the customer.

Low
Any condition or request that is not causing business impact to the customer. Further used for information exchange.

Standard maintenance and support
We provide technical support Monday through Friday, between 9:00AM - 3:00PM excluding holidays*.

Our team will make commercially reasonable efforts to respond within 8 business hours from the receipt of a trouble notification. Response times will vary depending on the severity of the notification.

Our team will make reasonable efforts to respond within 4 hours to emergency priority one (P1) and priority two (P2) issues.


Offboarding
If the customer stops using Shuffle’s services, all the information provided during onboarding and maintenance will still be available to the customer. The customer will lose access to the extra resources provided by the chosen subscription, but retain access to their organization, users, workflows, apps etc. Shuffle will further want to have a conversation with the customer to ensure Shuffle’s services will improve in all steps.

Disaster recovery & Business continuity
Shuffle’s cloud services run completely on GCP and use GCP serverless functionality all around the world as redundant systems to ensure that customers can reliably access their active utilities. 

In the case of problems with a self-hosted version of Shuffle, the TAM will work with the customer to provide the services necessary to get their instance up and running at full capacity.

In the case of complete failures with GCP, it is likely to be resolved in a number of hours, but the service failure also translates to a complete failure of GCP. This would mean that other services running on GCP have also failed too. If a customer strongly desires to get access to certain information during the outage, the TAM or ATAM will work with the customer’s IT team to access the required information. This may require extra verification of the person asking, as to verify whether they work with the customer or not.

Once GCP and Shuffle come back online, Shuffle will work with the customer to ensure any and all use-cases affected by the outage will be running again at full capacity.

If Shuffle on GCP is completely offline for an extended period of time (2+ days), Shuffle will work with the customer to figure out a contingency plan to ensure the environment works as expected.

In the case of circumstances outside of Shuffle’s control such as sickness or deaths, preventing the contract to be fulfilled by Shuffle directly, Shuffle’s partner Infopercept will take over all operations for the customer. Infopercept has certain access rights, allowing them to take over and host the Shuffle cloud platform by themselves under these circumstances, and have certain extra access due to support fulfillment.



Non-disclosure 
Shuffle will not disclose any information about the customer to any third party, unless the customer has given explicit permission to do so. This includes, but is not limited to, the customer’s name, address, contact information, and any other information that may be considered sensitive.

When information is shared between our entities, the receiving Party acknowledges that the disclosing Party retains proprietary rights and intellectual property rights in the Confidential Information disclosed to the receiving Party, and that the disclosure of such Confidential Information shall not be deemed to confer upon the receiving Party any rights or intellectual property rights whatsoever in respect of any part thereof.



Payment options
The default payment option is by paying through the Shuffle website https://shuffler.io/pricing. We further accept bank transfer if necessary.


Trial or Proof of Value (POV) 
If you have started a Proof-of-Value or Trial with Shuffle, and you want to end the trial, you can do so at any time. When the Trial or POV ends, the customer needs to decide whether to continue by paying Shuffle, or stop the Trial, losing access to any software and support, previously supplied by Shuffle. POV can be extended if needed, but will be discussed with the customer and Shuffle. The maximum length of a Trial or POV is 3 months.

Any payments made will not be refunded. If your license includes special software, the customer will lose access to this software, and has a maximum 30 day limit to remove the software from the time of contract end. The customer will still have access to their organization, users, workflows, apps etc. Shuffle will further want to have a conversation with the customer to ensure Shuffle’s services will improve in all steps.


End of Contract
If the customer wants to end the contract, the customer can do so at any time. The customer will still have access to their data, but will lose access to the extra resources provided by the chosen subscription. Any payments made will not be refunded. If your license includes special software, the customer will lose access to this software, and has a maximum 30 day limit to remove the software from the time of contract end. The customer will still have access to their organization, users, workflows, apps etc. Shuffle will further want to have a conversation with the customer to ensure Shuffle’s services will improve in all steps.


License Auditing
Shuffle may at any time, without warning, audit whether your are overutilizing your license in Shuffle. There are no hard limits when a license is bought, and any overutilization will be discussed with the customer. If the customer is overutilizing their license, the customer will be given a warning and a chance to fix the issue. If the issue is not fixed, Shuffle reserves the right to terminate the contract with the customer.


Misuse
Shuffle may temporarily suspend or limit access to the Platform if usage: (i) exceeds the scope of the license specified in this Agreement, (ii) unduly burdens the Platform, or, (iii) is otherwise inconsistent with normal usage. In any such event, Shuffle will get in contact to review and attempt to resolve the matter. Shuffle may charge, and the Customer will pay any costs associated with any such misuse if Customer fails to respond to and address the matter in a timely manner, not to exceed three (3) business day after Shuffle’s initial contact.

If you want this contract in PDF format to sign instead of as a digital End User License Agreement, please contact us at support@shuffler.io`)
}

// Should become a proper backend thing LOL
func GetUsecaseData() string {
	return (`[
    {
        "name": "1. Collect",
        "color": "#c51152",
        "list": [
            {
                "name": "Email management",
				"priority": 100,
				"type": "communication",
				"last": "cases", 
                "items": {
                    "name": "Release a quarantined message",
                    "items": {}
                }
            },
            {
                "name": "EDR to ticket",
				"priority": 100,
				"type": "edr",
				"last": "cases",
                "items": {
                    "name": "Get host information",
                    "items": {}
                }
            },
            {
                "name": "SIEM to ticket",
				"priority": 100,
				"type": "siem",
				"last": "cases",
				"description": "Ensure tickets are forwarded to the correct destination. Alternatively add enrichment on its way there.",
				"video": "https://www.youtube.com/watch?v=FBISHA7V15c&t=197s&ab_channel=OpenSecure",
				"blogpost": "https://medium.com/shuffle-automation/introducing-shuffle-an-open-source-soar-platform-part-1-58a529de7d12",
				"reference_image": "/images/detectionframework.png",
                "items": {}
            },
            {
				"type": "cases",
				"last": "cases",
                "name": "2-way Ticket synchronization",
				"priority": 20,
                "items": {}
            },
            {
                "name": "ChatOps",
				"priority": 70,
				"type": "communication",
				"last": "cases",
                "items": {}
            },
            {
                "name": "Threat Intel received",
				"priority": 50,
				"type": "intel",
				"last": "cases",
                "items": {}
            }
        ]
    },
    {
        "name": "2. Enrich",
        "color": "#f4c20d",
        "list": [
            {
                "name": "Internal Enrichment",
				"priority": 100,
				"type": "intel",
                "items": {
                    "name": "...",
                    "items": {}
                }
            },
            {
                "name": "External historical Enrichment",
				"priority": 90,
				"type": "intel",
                "items": {
                    "name": "...",
                    "items": {}
                }
            },
            {
                "name": "Sandbox",
				"priority": 60,
				"type": "intel",
                "items": {
                    "name": "Use a sandbox to analyze",
                    "items": {}
                }
            }
        ]
    },
    {
        "name": "3. Detect",
        "color": "#3cba54",
        "list": [
            {
                "name": "Search SIEM (Sigma)",
				"priority": 90,
				"type": "siem",
				"last": "cases",
                "items": {
                    "name": "Endpoint",
                    "items": {}
                }
            },
            {
                "name": "Search EDR (OSQuery)",
				"type": "edr",
				"priority": 90,
				"last": "cases",
                "items": {}
            },
            {
                "name": "Search emails (Sublime)",
				"priority": 90,
				"type": "communication",
				"last": "cases",
                "items": {
                    "name": "Check headers and IOCs",
                    "items": {}
                }
            },
            {
                "name": "Automate Threathunt (Kestrel)",
				"priority": 50,
				"type": "edr",
				"last": "cases",
                "items": {}
            },
            {
                "name": "Search IOCs (ioc-finder)",
				"priority": 50,
				"type": "intel",
				"last": "cases",
                "items": {}
            },
            {
                "name": "Search files (Yara)",
				"priority": 50,
				"type": "intel",
				"last": "cases",
                "items": {}
            },
            {
                "name": "Memory Analysis (Volatility)",
				"priority": 50,
				"type": "intel",
                "items": {}
            },
            {
                "name": "IDS & IPS (Snort/Surricata)",
				"priority": 50,
				"type": "network",
				"last": "cases",
                "items": {}
            },
            {
                "name": "Honeypot access",
				"priority": 50,
				"type": "network",
				"last": "cases",
                "items": {
                    "name": "...",
                    "items": {}
                }
            }
        ]
    },
    {
        "name": "4. Respond",
        "color": "#4885ed",
        "list": [
            {
                "name": "Eradicate malware",
				"priority": 90,
				"type": "intel",
				"last": "edr",
                "items": {}
            },
            {
                "name": "Quarantine host(s)",
				"priority": 90,
				"type": "edr",
                "items": {}
            },
            {
                "name": "Update Outdated Software",
				"priority": 70,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Block IPs, URLs, Domains and Hashes",
				"priority": 90,
				"type": "network",
                "items": {}
            },
            {
                "name": "Trigger scans",
				"priority": 50,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Update indicators (FW, EDR, SIEM...)",
				"priority": 50,
				"type": "intel",
				"last": "siem",
                "items": {}
            },
            {
                "name": "Autoblock activity when threat intel is received",
				"priority": 50,
				"type": "intel",
				"last": "iam",
                "items": {}
            },
            {
                "name": "Lock/Delete/Reset account",
				"priority": 50,
				"type": "iam",
                "items": {}
            },
            {
                "name": "Lock vault",
				"priority": 50,
				"type": "iam",
                "items": {}
            },
            {
                "name": "Increase authentication",
				"priority": 50,
				"type": "iam",
                "items": {}
            },
            {
                "name": "Get policies from assets",
				"priority": 50,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Run ansible scripts",
				"type": "assets",
				"priority": 50,
                "items": {}
            }
        ]
    },
    {
        "name": "5. Verify",
        "color": "#7f00ff",
        "list": [
            {
                "name": "Discover vulnerabilities",
								"priority": 80,
								"type": "assets",
                "items": {}
            },
            {
                "name": "Discover assets",
				"priority": 80,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Ensure policies are followed",
				"priority": 80,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Find Inactive users",
				"priority": 50,
				"type": "iam",
                "items": {}
            },
            {
                "name": "Botnet tracker",
				"priority": 50,
				"type": "network",
                "items": {}
            },
            {
                "name": "Ensure access rights match HR systems",
				"priority": 50,
				"type": "iam",
                "items": {}
            },
            {
                "name": "Ensure onboarding is followed",
				"priority": 50,
				"type": "iam",
                "items": {}
            },
            {
                "name": "Track third party SaaS apps",
				"priority": 50,
				"type": "iam",
                "items": {}
            },
            {
                "name": "Devices used for your cloud account",
				"priority": 50,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Too much access in GCP/Azure/AWS other clouds",
				"priority": 50,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Certificate validation",
				"priority": 50,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Monitor domain creation and expiration",
				"priority": 50,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Monitor new DNS entries for domain with passive DNS",
				"priority": 50,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Monitor and track password dumps",
				"priority": 50,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Monitor for mentions of domain on darknet sites",
				"priority": 50,
				"type": "assets",
                "items": {}
            },
            {
                "name": "Reporting",
				"priority": 50,
				"type": "assets",
				"keywords": ["report", "reporting", "sheets", "excel"],
				"keyword_matches": 1,
                "items": {
                    "name": "Monthly reports",
                    "items": {
                        "name": "...",
                        "items": {}
                    }
                }
            }
        ]
    }
]`)
}
