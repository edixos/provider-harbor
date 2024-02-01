/*
Copyright 2022 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package project

import (
	"context"
	"fmt"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/goharbor/go-client/pkg/harbor"
	"strings"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	"github.com/crossplane/provider-harbor/apis/project/v1alpha1"
	apisv1alpha1 "github.com/crossplane/provider-harbor/apis/v1alpha1"
	"github.com/crossplane/provider-harbor/internal/features"
	v2client "github.com/goharbor/go-client/pkg/sdk/v2.0/client"
	modelProject "github.com/goharbor/go-client/pkg/sdk/v2.0/client/project"
	"github.com/goharbor/go-client/pkg/sdk/v2.0/models"
)

const (
	errNotProject   = "managed resource is not a Project custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"

	errNewClient = "cannot create new Service"
)

// A HarborService does nothing.
type HarborService struct {
	harborClientSet *v2client.HarborAPI
}

var (
	newHarborClientSetService = func(creds []byte, harborUrl string, insecure *bool) (*HarborService, error) {
		stringCreds := string(creds)
		splitCreds := strings.Split(stringCreds, ":")
		username := splitCreds[0]
		password := splitCreds[1]
		if insecure == nil || *insecure == false {
			fmt.Println(insecure)
		}
		clientSetConfig := &harbor.ClientSetConfig{
			URL:      harborUrl,
			Insecure: false,
			Username: username,
			Password: password,
		}
		clientSet, err := harbor.NewClientSet(clientSetConfig)
		if err != nil {
			return nil, err
		}
		clv2 := clientSet.V2()
		harbourService := HarborService{harborClientSet: clv2}
		return &harbourService, nil
	}
)

// Setup adds a controller that reconciles Project managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.ProjectGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.ProjectGroupVersionKind),
		managed.WithExternalConnecter(&connector{
			kube:         mgr.GetClient(),
			usage:        resource.NewProviderConfigUsageTracker(mgr.GetClient(), &apisv1alpha1.ProviderConfigUsage{}),
			newServiceFn: newHarborClientSetService}),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithPollInterval(o.PollInterval),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithConnectionPublishers(cps...))

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.Project{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

// A connector is expected to produce an ExternalClient when its Connect method
// is called.
type connector struct {
	kube         client.Client
	usage        resource.Tracker
	newServiceFn func(creds []byte, harborUrl string, insecure *bool) (*HarborService, error)
}

// Connect typically produces an ExternalClient by:
// 1. Tracking that the managed resource is using a ProviderConfig.
// 2. Getting the managed resource's ProviderConfig.
// 3. Getting the credentials specified by the ProviderConfig.
// 4. Using the credentials to form a client.
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.Project)
	if !ok {
		return nil, errors.New(errNotProject)
	}

	if err := c.usage.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	pc := &apisv1alpha1.ProviderConfig{}
	if err := c.kube.Get(ctx, types.NamespacedName{Name: cr.GetProviderConfigReference().Name}, pc); err != nil {
		return nil, errors.Wrap(err, errGetPC)
	}

	cd := pc.Spec.Credentials
	data, err := resource.CommonCredentialExtractor(ctx, cd.Source, c.kube, cd.CommonCredentialSelectors)
	if err != nil {
		return nil, errors.Wrap(err, errGetCreds)
	}

	svc, err := c.newServiceFn(data, pc.Spec.HarborUrl, pc.Spec.Insecure)
	if err != nil {
		return nil, errors.Wrap(err, errNewClient)
	}

	return &external{service: svc}, nil
}

// An ExternalClient observes, then either creates, updates, or deletes an
// external resource to ensure it reflects the managed resource's desired state.
type external struct {
	// A 'client' used to connect to the external resource API. In practice this
	// would be something like an AWS SDK client.
	service *HarborService
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.Project)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotProject)
	}

	// These fmt statements should be removed in the real implementation.
	fmt.Printf("Observing: %+v", cr)
	projectParams := &modelProject.GetProjectParams{
		ProjectNameOrID: meta.GetExternalName(cr),
		Context:         context.TODO(),
	}
	getProject, err := c.service.harborClientSet.Project.GetProject(ctx, projectParams)
	if err != nil {
		return managed.ExternalObservation{
			ResourceExists:          false,
			ResourceUpToDate:        false,
			ResourceLateInitialized: false,
			ConnectionDetails:       nil,
			Diff:                    "",
		}, nil
	}
	if !getProject.IsSuccess() {
		return managed.ExternalObservation{
			ResourceExists:          false,
			ResourceUpToDate:        false,
			ResourceLateInitialized: false,
			ConnectionDetails:       nil,
			Diff:                    "",
		}, nil
	}
	return managed.ExternalObservation{
		// Return false when the external resource does not exist. This lets
		// the managed resource reconciler know that it needs to call Create to
		// (re)create the resource, or that it has successfully been deleted.
		ResourceExists: true,

		// Return false when the external resource exists, but it not up to date
		// with the desired managed resource state. This lets the managed
		// resource reconciler know that it needs to call Update.
		ResourceUpToDate: true,

		// Return any details that may be required to connect to the external
		// resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.Project)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotProject)
	}
	metadata := cr.Spec.ForProvider.Metadata
	fmt.Printf("Creating: %+v", cr)
	createProject := &modelProject.CreateProjectParams{
		Project: &models.ProjectReq{
			ProjectName: meta.GetExternalName(cr),
			Metadata: &models.ProjectMetadata{
				AutoScan:                 metadata.AutoScan,
				EnableContentTrust:       metadata.EnableContentTrust,
				EnableContentTrustCosign: metadata.EnableContentTrustCosign,
				PreventVul:               metadata.PreventVul,
				Public:                   metadata.Public,
				RetentionID:              metadata.RetentionID,
				ReuseSysCVEAllowlist:     metadata.ReuseSysCVEAllowlist,
				Severity:                 metadata.Severity,
			},
		},
	}
	projectCreateOutPut, err := c.service.harborClientSet.Project.CreateProject(ctx, createProject)
	if !projectCreateOutPut.IsSuccess() || err != nil {
		return managed.ExternalCreation{}, err
	}
	cr.Status.AtProvider.State = projectCreateOutPut.String()
	return managed.ExternalCreation{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.Project)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotProject)
	}

	fmt.Printf("Updating: %+v", cr)

	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.Project)
	if !ok {
		return errors.New(errNotProject)
	}

	fmt.Printf("Deleting: %+v", cr)

	return nil
}
