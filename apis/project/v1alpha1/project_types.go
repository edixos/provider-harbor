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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"reflect"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

type ProjectMetadata struct {
	AutoScan                 *string `json:"auto_scan,omitempty"`
	EnableContentTrust       *string `json:"enable_content_trust,omitempty"`
	EnableContentTrustCosign *string `json:"enable_content_trust_cosign,omitempty"`
	PreventVul               *string `json:"prevent_vul,omitempty"`
	Public                   string  `json:"public,omitempty"`
	RetentionID              *string `json:"retention_id,omitempty"`
	ReuseSysCVEAllowlist     *string `json:"reuse_sys_cve_allowlist,omitempty"`
	Severity                 *string `json:"severity,omitempty"`
}

// ProjectParameters are the configurable fields of a Project.
type ProjectParameters struct {
	CurrentUserRoleID  int64            `json:"currentUserRoleID,omitempty"`
	CurrentUserRoleIds []int32          `json:"currentUserRoleIds"`
	Deleted            *bool            `json:"deleted,omitempty"`
	Metadata           *ProjectMetadata `json:"metadata,omitempty"`
	OwnerID            *int32           `json:"ownerID,omitempty"`
	OwnerName          *string          `json:"ownerName,omitempty"`
	ProjectID          *int32           `json:"projectID,omitempty"`
	RegistryID         *int64           `json:"registryID,omitempty"`
	RepoCount          int64            `json:"repoCount"`
	Togglable          *bool            `json:"togglable,omitempty"`
}

// ProjectObservation are the observable fields of a Project.
type ProjectObservation struct {
	State string `json:"state,omitempty"`
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
