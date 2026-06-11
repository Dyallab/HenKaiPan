package validation

import (
	"fmt"

	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

type LoginRequest struct {
	Username string `validate:"required,min=1"`
	Email    string `validate:"omitempty,email"`
	Password string `validate:"required"`
}

type CreateProjectRequest struct {
	Name          string   `json:"name" validate:"required,max=255"`
	Description   string   `json:"description" validate:"max=1000"`
	RepoURL       string   `json:"repo_url" validate:"omitempty,url"`
	Provider      string   `json:"provider" validate:"omitempty"`
	DefaultBranch string   `json:"default_branch" validate:"omitempty"`
	Tags          []string `json:"tags" validate:"max=10,dive,max=50"`
}

type UpdateFindingRequest struct {
	Status     string  `json:"status" validate:"required,oneof=open in_review accepted_risk fixed verified"`
	AssignedTo *string `json:"assigned_to" validate:"omitempty,max=255"`
	Notes      string  `json:"notes" validate:"max=5000"`
}

type CreateScanRequest struct {
	ProjectID  string `validate:"required,uuid"`
	ScannerType string `validate:"required"`
}

type BulkUpdateFindingsRequest struct {
	IDs        []string `json:"ids" validate:"required,min=1,dive,uuid"`
	Status     string   `json:"status" validate:"omitempty,oneof=open in_review accepted_risk fixed verified"`
	AssignedTo *string  `json:"assigned_to" validate:"omitempty,max=255"`
	Notes      *string  `json:"notes" validate:"omitempty,max=5000"`
}

type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func ValidateStruct(s interface{}) []ValidationError {
	err := validate.Struct(s)
	if err == nil {
		return nil
	}

	var errors []ValidationError
	for _, err := range err.(validator.ValidationErrors) {
		ve := ValidationError{
			Field:   err.Field(),
			Message: getErrorMessage(err),
		}
		errors = append(errors, ve)
	}
	return errors
}

func getErrorMessage(err validator.FieldError) string {
	switch err.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", err.Field())
	case "email":
		return fmt.Sprintf("%s must be a valid email", err.Field())
	case "min":
		return fmt.Sprintf("%s must be at least %s characters", err.Field(), err.Param())
	case "max":
		return fmt.Sprintf("%s must not exceed %s characters", err.Field(), err.Param())
	case "uuid":
		return fmt.Sprintf("%s must be a valid UUID", err.Field())
	case "url":
		return fmt.Sprintf("%s must be a valid URL", err.Field())
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", err.Field(), err.Param())
	case "dive":
		return fmt.Sprintf("%s contains invalid value", err.Field())
	default:
		return fmt.Sprintf("%s is invalid", err.Field())
	}
}
