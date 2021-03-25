module stitcher

go 1.15

replace github.com/frikky/shuffle-shared => ../

require (
	cloud.google.com/go/storage v1.14.0
	github.com/algolia/algoliasearch-client-go/v3 v3.17.0
	github.com/containerd/containerd v1.4.4 // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v20.10.5+incompatible
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/frikky/shuffle-shared v0.0.12
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	google.golang.org/api v0.42.0
	gopkg.in/yaml.v2 v2.4.0
)
