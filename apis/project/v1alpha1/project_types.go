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

package v1alpha1

import (
	"github.com/goharbor/go-client/pkg/sdk/v2.0/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kube-openapi/pkg/validation/strfmt"
	"reflect"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

// ProjectParameters are the configurable fields of a Project.
type ProjectParameters struct {
	CreationTime strfmt.DateTime `json:"creation_time,omitempty"`
	// The role ID with highest permission of the current user who triggered the API (for UI).  This attribute is deprecated and will be removed in future versions.
	CurrentUserRoleID int64 `json:"current_user_role_id,omitempty"`
	// The list of role ID of the current user who triggered the API (for UI)
	CurrentUserRoleIds []int32 `json:"current_user_role_ids"`
	// The CVE allowlist of this project.
	CVEAllowlist *models.CVEAllowlist `json:"cve_allowlist,omitempty"`
	// A deletion mark of the project.
	Deleted bool `json:"deleted,omitempty"`
	// The metadata of the project.
	Metadata *models.ProjectMetadata `json:"metadata,omitempty"`
	// The name of the project.
	Name string `json:"name,omitempty"`
	// The owner ID of the project always means the creator of the project.
	OwnerID int32 `json:"owner_id,omitempty"`
	// The owner name of the project.
	OwnerName string `json:"owner_name,omitempty"`
	// Project ID
	ProjectID int32 `json:"project_id,omitempty"`
	// The ID of referenced registry when the project is a proxy cache project.
	RegistryID int64 `json:"registry_id,omitempty"`
	// The number of the repositories under this project.
	RepoCount int64 `json:"repo_count"`
	// Correspond to the UI about whether the project's publicity is  updatable (for UI)
	Togglable bool `json:"togglable,omitempty"`
	// The update time of the project.
	// Format: date-time
	UpdateTime strfmt.DateTime `json:"update_time,omitempty"`
}

// ProjectObservation are the observable fields of a Project.
type ProjectObservation struct {
	state string `json:"observableField,omitempty"`
}

// A ProjectSpec defines the desired state of a Project.
type ProjectSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       ProjectParameters `json:"forProvider"`
}

// A ProjectStatus represents the observed state of a Project.
type ProjectStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          ProjectObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A Project is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,harbor}
type Project struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ProjectSpec   `json:"spec"`
	Status ProjectStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ProjectList contains a list of Project
type ProjectList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Project `json:"items"`
}

// Project type metadata.
var (
	ProjectKind             = reflect.TypeOf(Project{}).Name()
	ProjectGroupKind        = schema.GroupKind{Group: Group, Kind: ProjectKind}.String()
	ProjectKindAPIVersion   = ProjectKind + "." + SchemeGroupVersion.String()
	ProjectGroupVersionKind = SchemeGroupVersion.WithKind(ProjectKind)
)

func init() {
	SchemeBuilder.Register(&Project{}, &ProjectList{})
}
