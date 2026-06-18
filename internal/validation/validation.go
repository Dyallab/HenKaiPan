package validation

import "strings"

var Roles = map[string]bool{
	"admin":  true,
	"viewer": true,
}

func IsValid(set map[string]bool, value string) bool {
	return set[value]
}

func NormalizeWebhookDeliveryType(raw string) string {
	normalized := strings.ToLower(raw)
	switch normalized {
	case "generic", "slack", "discord":
		return normalized
	default:
		return ""
	}
}