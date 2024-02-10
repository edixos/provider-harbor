package utility

import (
	"github.com/crossplane/provider-harbor/apis/project/v1alpha1"
	modelv2 "github.com/mittwald/goharbor-client/v5/apiv2/model"
)

func CastToLocalType(project_metadata *modelv2.ProjectMetadata) v1alpha1.ProjectMetadata {
	projectv2 := v1alpha1.ProjectMetadata{}
	projectv2.AutoScan = project_metadata.AutoScan
	projectv2.EnableContentTrust = project_metadata.EnableContentTrust
	projectv2.EnableContentTrustCosign = project_metadata.EnableContentTrustCosign
	projectv2.PreventVul = project_metadata.PreventVul
	projectv2.Public = project_metadata.Public
	projectv2.RetentionID = project_metadata.RetentionID
	projectv2.ReuseSysCVEAllowlist = project_metadata.ReuseSysCVEAllowlist
	projectv2.Severity = project_metadata.Severity
	return projectv2
}

func GetDiff(source, dest v1alpha1.ProjectMetadata) modelv2.ProjectMetadata {
	out := modelv2.ProjectMetadata{}

	if source.Public != dest.Public {
		out.Public = source.Public
	}
	if source.AutoScan != dest.AutoScan {
		out.AutoScan = source.AutoScan
	}
	if source.EnableContentTrust != dest.EnableContentTrust {
		out.EnableContentTrust = source.EnableContentTrust
	}
	if source.EnableContentTrustCosign != dest.EnableContentTrustCosign {
		out.EnableContentTrustCosign = dest.EnableContentTrustCosign
	}
	if source.PreventVul != dest.PreventVul {
		out.PreventVul = source.PreventVul
	}
	if source.RetentionID != dest.RetentionID {
		out.RetentionID = source.RetentionID
	}
	if source.ReuseSysCVEAllowlist != dest.ReuseSysCVEAllowlist {
		out.ReuseSysCVEAllowlist = source.ReuseSysCVEAllowlist
	}
	if source.Severity != dest.Severity {
		out.Severity = source.Severity
	}
	return out

}
