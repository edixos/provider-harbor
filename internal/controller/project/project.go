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
	"strings"

	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/google/go-cmp/cmp"
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

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/provider-harbor/apis/project/v1alpha1"
	apisv1alpha1 "github.com/crossplane/provider-harbor/apis/v1alpha1"
	"github.com/crossplane/provider-harbor/internal/features"
	"github.com/crossplane/provider-harbor/utility"
	"github.com/mittwald/goharbor-client/v5/apiv2"
	modelv2 "github.com/mittwald/goharbor-client/v5/apiv2/model"
)

const (
	errNotProject   = "managed resource is not a Project custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"

	errNewClient = "cannot create new Service"
)

// A HarborService is the defaultClient Service
type HarborService struct {
	harborClientSet *apiv2.RESTClient
}

var (
	newHarborClientSetService = func(creds []byte, harborUrl string) (*HarborService, error) {
		stringCreds := string(creds)
		splitCreds := strings.Split(stringCreds, ":")
		username := splitCreds[0]
		password := splitCreds[1]
		password = strings.Trim(password, "\n")

		client, err := apiv2.NewRESTClientForHost(harborUrl, username, password, nil)
		if err != nil {
			return nil, err
		}
		harbourService := HarborService{harborClientSet: client}
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
	newServiceFn func(creds []byte, harborUrl string) (*HarborService, error)
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
	svc, err := c.newServiceFn(data, pc.Spec.HarborUrl)
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

	getProject, err := c.service.harborClientSet.ProjectExists(ctx, meta.GetExternalName(cr))
	if err != nil {
		return managed.ExternalObservation{}, err
	}

	if !getProject {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	getFromServer, err := c.service.harborClientSet.GetProject(ctx, meta.GetExternalName(cr))

	if err != nil {
		return managed.ExternalObservation{}, err
	}

	alphaGetFromServer := utility.CastToLocalType(getFromServer.Metadata)
	if !cmp.Equal(cr.Spec.ForProvider.Metadata, alphaGetFromServer) {
		return managed.ExternalObservation{
			ResourceExists:    true,
			ResourceUpToDate:  false,
			ConnectionDetails: managed.ConnectionDetails{},
			Diff:              cmp.Diff(cr.Spec.ForProvider.Metadata, alphaGetFromServer),
		}, nil
	}
	cr.Status.SetConditions(xpv1.Condition{
		Type:               xpv1.TypeReady,
		Status:             xpv1.Available().Status,
		LastTransitionTime: xpv1.Available().LastTransitionTime,
		Reason:             xpv1.Available().Reason,
		Message:            xpv1.Available().Message,
	})
	return managed.ExternalObservation{
		ResourceExists:    true,
		ResourceUpToDate:  true,
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.Project)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotProject)
	}

	projMeta := &modelv2.ProjectMetadata{
		AutoScan:                 cr.Spec.ForProvider.Metadata.AutoScan,
		EnableContentTrust:       cr.Spec.ForProvider.Metadata.EnableContentTrust,
		EnableContentTrustCosign: cr.Spec.ForProvider.Metadata.EnableContentTrustCosign,
		PreventVul:               cr.Spec.ForProvider.Metadata.PreventVul,
		Public:                   cr.Spec.ForProvider.Metadata.Public,
		ReuseSysCVEAllowlist:     cr.Spec.ForProvider.Metadata.ReuseSysCVEAllowlist,
		Severity:                 cr.Spec.ForProvider.Metadata.Severity,
	}
	err := c.service.harborClientSet.NewProject(ctx, &modelv2.ProjectReq{
		ProjectName: meta.GetExternalName(cr),
		Metadata:    projMeta,
	})
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	cr.Status.SetConditions(xpv1.Creating())
	return managed.ExternalCreation{
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.Project)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotProject)
	}
	getSource, err := GenerateMetadata(mg)

	if err != nil {
		return managed.ExternalUpdate{}, err
	}
	getFromServer, _ := c.service.harborClientSet.GetProject(ctx, meta.GetExternalName(cr))
	*getFromServer.Metadata = getSource
	err = c.service.harborClientSet.UpdateProject(ctx, getFromServer, nil)
	if err != nil {
		return managed.ExternalUpdate{
			ConnectionDetails: managed.ConnectionDetails{},
		}, err

	}
	return managed.ExternalUpdate{
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.Project)
	if !ok {
		return errors.New(errNotProject)
	}

	if !ok {
		return errors.Wrap(nil, "Delete Database failed!")
	}
	err := c.service.harborClientSet.DeleteProject(ctx, cr.GetName())

	if err != nil {
		return err
	}
	return nil
}

func GenerateMetadata(mg resource.Managed) (modelv2.ProjectMetadata, error) {
	cr, ok := mg.(*v1alpha1.Project)
	if !ok {
		return modelv2.ProjectMetadata{}, errors.Wrap(nil, "Genrtaion Failed!")
	}
	return modelv2.ProjectMetadata{
		AutoScan:                 cr.Spec.ForProvider.Metadata.AutoScan,
		EnableContentTrust:       cr.Spec.ForProvider.Metadata.EnableContentTrust,
		EnableContentTrustCosign: cr.Spec.ForProvider.Metadata.EnableContentTrustCosign,
		PreventVul:               cr.Spec.ForProvider.Metadata.PreventVul,
		Public:                   cr.Spec.ForProvider.Metadata.Public,
		ReuseSysCVEAllowlist:     cr.Spec.ForProvider.Metadata.ReuseSysCVEAllowlist,
		Severity:                 cr.Spec.ForProvider.Metadata.Severity,
	}, nil
}
