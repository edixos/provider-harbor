package utility

import (
	"github.com/crossplane/provider-harbor/apis/project/v1alpha1"
	modelv2 "github.com/mittwald/goharbor-client/v5/apiv2/model"
)

func CastToLocalType(project_metadata *modelv2.ProjectMetadata) v1alpha1.ProjectMetadata {
	projectv2 := v1alpha1.ProjectMetadata{}
	*projectv2.AutoScan = *project_metadata.AutoScan
	*projectv2.EnableContentTrust = *project_metadata.EnableContentTrust
	*projectv2.EnableContentTrustCosign = *project_metadata.EnableContentTrustCosign
	*projectv2.PreventVul = *project_metadata.PreventVul
	projectv2.Public = project_metadata.Public
	*projectv2.RetentionID = *project_metadata.RetentionID
	*projectv2.ReuseSysCVEAllowlist = *project_metadata.ReuseSysCVEAllowlist
	*projectv2.Severity = *project_metadata.Severity
	return projectv2
}
