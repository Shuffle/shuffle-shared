module stitcher

go 1.15

//replace github.com/shuffle/shuffle-shared => ../

require (
	cloud.google.com/go/storage v1.30.1
	github.com/containerd/containerd v1.6.26 // indirect
	github.com/docker/docker v20.10.5+incompatible
	github.com/shuffle/shuffle-shared v0.3.60
	google.golang.org/api v0.126.0
	gopkg.in/yaml.v2 v2.4.0
)
