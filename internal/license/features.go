package license

// Feature flags for self-hosted edition licensing.
// Free tier (no LICENSE_KEY) gets access to none of these.
// Paid license keys include the corresponding feature strings in their claims.
const (
	FeatureScheduling     = "scheduling"
	FeaturePolicies       = "policies"
	FeatureCompliance     = "compliance"
	FeatureIntegrations   = "integrations"
	FeatureAIRemediation  = "ai-remediation"
	FeatureReports        = "reports"
	FeatureAuditLog       = "audit-log"
	FeatureRiskAcceptance = "risk-acceptance"
	FeatureTeams          = "teams"
	FeatureComments       = "comments"
	FeatureEmailNotify    = "email-notifications"
)
