package validation

var Roles = map[string]bool{
	"admin":  true,
	"viewer": true,
}

var FindingStatuses = map[string]bool{
	"open":          true,
	"in_review":     true,
	"accepted_risk": true,
	"fixed":         true,
	"verified":      true,
}

var WebhookDeliveryTypes = map[string]bool{
	"generic": true,
	"slack":   true,
	"discord": true,
}

func IsValid(set map[string]bool, value string) bool {
	return set[value]
}

func NormalizeWebhookDeliveryType(raw string) string {
	switch raw {
	case "generic", "Generic", "GENERIC":
		return "generic"
	case "slack", "Slack", "SLACK":
		return "slack"
	case "discord", "Discord", "DISCORD":
		return "discord"
	default:
		return ""
	}
}