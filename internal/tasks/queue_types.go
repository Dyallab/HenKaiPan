package tasks

import "encoding/json"

const (
	TypeScanRun          = "scan:run"
	TypeFindingValidate  = "agent:validate"
	TypeFindingSummarize = "agent:summarize"
)

type ScanPayload struct {
	ScanID  string `json:"scan_id"`
	Target  string `json:"target"`
	Scanner string `json:"scanner"`
}

func MarshalScanPayload(p ScanPayload) ([]byte, error) {
	return json.Marshal(p)
}

func UnmarshalScanPayload(data []byte) (ScanPayload, error) {
	var p ScanPayload
	return p, json.Unmarshal(data, &p)
}

type FindingValidatePayload struct {
	FindingID string `json:"finding_id"`
}

func MarshalFindingValidatePayload(p FindingValidatePayload) ([]byte, error) {
	return json.Marshal(p)
}

func UnmarshalFindingValidatePayload(data []byte) (FindingValidatePayload, error) {
	var p FindingValidatePayload
	return p, json.Unmarshal(data, &p)
}

type FindingSummarizePayload struct {
	FindingID string `json:"finding_id"`
}

func MarshalFindingSummarizePayload(p FindingSummarizePayload) ([]byte, error) {
	return json.Marshal(p)
}

func UnmarshalFindingSummarizePayload(data []byte) (FindingSummarizePayload, error) {
	var p FindingSummarizePayload
	return p, json.Unmarshal(data, &p)
}
