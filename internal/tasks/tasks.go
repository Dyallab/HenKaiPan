package tasks

import "encoding/json"

const (
	TypeScanRun       = "scan:run"
	TypeAgentValidate = "agent:validate"
)

type ScanPayload struct {
	ScanID  string `json:"scan_id"`
	Target  string `json:"target"`
	Scanner string `json:"scanner"`
}

func MarshalPayload(p ScanPayload) ([]byte, error) {
	return json.Marshal(p)
}

func UnmarshalPayload(data []byte) (ScanPayload, error) {
	var p ScanPayload
	return p, json.Unmarshal(data, &p)
}

type AgentValidatePayload struct {
	FindingID string `json:"finding_id"`
}

func MarshalAgentValidatePayload(p AgentValidatePayload) ([]byte, error) {
	return json.Marshal(p)
}

func UnmarshalAgentValidatePayload(data []byte) (AgentValidatePayload, error) {
	var p AgentValidatePayload
	return p, json.Unmarshal(data, &p)
}
