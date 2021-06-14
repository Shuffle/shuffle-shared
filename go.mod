module github.com/frikky/shuffle-shared

go 1.11

//replace github.com/frikky/kin-openapi => ../kin-openapi

require (
	cloud.google.com/go/datastore v1.4.0
	cloud.google.com/go/storage v1.12.0
	github.com/Masterminds/semver v1.5.0
	github.com/algolia/algoliasearch-client-go/v3 v3.18.1
	github.com/bradfitz/slice v0.0.0-20180809154707-2b758aa73013
	github.com/elastic/go-elasticsearch/v8 v8.0.0-20210608143047-aa1301e7ba9d // indirect
	github.com/frikky/kin-openapi v0.38.0
	github.com/google/go-github/v28 v28.1.1 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/satori/go.uuid v1.2.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/oauth2 v0.0.0-20210113160501-8b1d76fa0423
	google.golang.org/api v0.36.0
	google.golang.org/appengine v1.6.7
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)
