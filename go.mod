module github.com/container-registry/waybill-harbor-adapter

go 1.26

// GO-2026-5856 (crypto/tls) is fixed in 1.26.5; setup-go resolves this via go-version-file.
toolchain go1.26.5

require (
	github.com/alicebob/miniredis/v2 v2.38.0
	github.com/caarlos0/env/v6 v6.10.1
	github.com/google/go-containerregistry v0.21.6
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/schema v1.4.1
	github.com/prometheus/client_golang v1.23.2
	github.com/redis/go-redis/v9 v9.21.0
	github.com/samber/lo v1.53.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/cli v29.4.3+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.9.3 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gotest.tools/v3 v3.5.2 // indirect
)
