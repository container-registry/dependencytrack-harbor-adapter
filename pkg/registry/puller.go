// Package registry pulls an artifact from a Harbor-managed registry with
// go-containerregistry and writes it as a docker-save tarball for mikebom to
// scan (plan D-1). The adapter pulls the artifact itself because mikebom's own
// OCI client hardcodes https:// and trusts only webpki roots (see
// docs/spike-m1.md / upstream-issues); handing mikebom a local tarball sidesteps
// both. Only Basic and anonymous auth are supported (D-2), so vanilla
// go-containerregistry suffices.
package registry

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
)

// ImageRef identifies the artifact to pull. Name is the fully-qualified
// host:port/repository@digest reference (harbor.ScanRequest.GetImageRef).
type ImageRef struct {
	Name      string
	Username  string
	Password  string
	Anonymous bool
	// Insecure is true when registry.url scheme is http (plain-HTTP pull).
	Insecure bool
}

// Puller pulls an artifact and writes it to a docker-save tarball.
type Puller interface {
	PullToTarball(ctx context.Context, ref ImageRef, destTarball string) error
}

type puller struct{}

func NewPuller() Puller {
	return &puller{}
}

func (p *puller) PullToTarball(ctx context.Context, ref ImageRef, destTarball string) error {
	opts := []crane.Option{crane.WithContext(ctx)}
	if ref.Insecure {
		opts = append(opts, crane.Insecure)
	}
	if ref.Anonymous {
		opts = append(opts, crane.WithAuth(authn.Anonymous))
	} else {
		opts = append(opts, crane.WithAuth(&authn.Basic{
			Username: ref.Username,
			Password: ref.Password,
		}))
	}

	img, err := crane.Pull(ref.Name, opts...)
	if err != nil {
		return fmt.Errorf("pulling %s: %w", ref.Name, err)
	}

	// crane.Save writes a docker-save (v1) tarball with a manifest.json, which is
	// exactly what mikebom accepts as --image input (M1 spike confirmed).
	if err := crane.Save(img, ref.Name, destTarball); err != nil {
		return fmt.Errorf("saving %s to tarball: %w", ref.Name, err)
	}
	return nil
}
