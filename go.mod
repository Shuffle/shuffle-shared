module github.com/shuffle/shuffle-shared

// Keep on 1.11 until AppEngine supports 1.17 or higher

go 1.11

//replace github.com/frikky/kin-openapi => ../kin-openapi

require (
	cloud.google.com/go/datastore v1.4.0
	cloud.google.com/go/storage v1.12.0
	github.com/Masterminds/semver v1.5.0
	github.com/adrg/strutil v0.2.3
	github.com/algolia/algoliasearch-client-go/v3 v3.18.1
	github.com/bradfitz/gomemcache v0.0.0-20221031212613-62deef7fc822
	github.com/bradfitz/slice v0.0.0-20180809154707-2b758aa73013
	github.com/frikky/kin-openapi v0.41.0
	github.com/go-git/go-billy/v5 v5.5.0
	github.com/go-git/go-git/v5 v5.11.0
	github.com/google/go-github/v28 v28.1.1
	github.com/google/go-querystring v1.0.0
	github.com/opensearch-project/opensearch-go v1.1.0
	github.com/opensearch-project/opensearch-go/v2 v2.3.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/satori/go.uuid v1.2.0
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	go4.org v0.0.0-20201209231011-d4a079459e60 // indirect
	golang.org/x/crypto v0.17.0
	golang.org/x/oauth2 v0.0.0-20210113160501-8b1d76fa0423
	google.golang.org/api v0.36.0
	google.golang.org/appengine v1.6.7
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
)
