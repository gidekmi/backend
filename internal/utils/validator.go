// internal/utils/validator.go
package utils

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

// Validator wraps the go-playground validator
type Validator struct {
	validate *validator.Validate
}

// NewValidator creates a new validator instance
func NewValidator() *Validator {
	v := validator.New()

	// Register custom validators
	v.RegisterValidation("phone", validatePhone)
	v.RegisterValidation("strong_password", validateStrongPassword)

	return &Validator{validate: v}
}

// ValidateStruct validates a struct and returns formatted error messages
func (v *Validator) ValidateStruct(s interface{}) map[string]string {
	err := v.validate.Struct(s)
	if err == nil {
		return nil
	}

	errors := make(map[string]string)

	for _, err := range err.(validator.ValidationErrors) {
		field := strings.ToLower(err.Field())
		errors[field] = v.getErrorMessage(err)
	}

	return errors
}

// getErrorMessage returns a user-friendly error message
func (v *Validator) getErrorMessage(err validator.FieldError) string {
	field := err.Field()
	tag := err.Tag()
	param := err.Param()

	switch tag {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "email":
		return "Please enter a valid email address"
	case "min":
		return fmt.Sprintf("%s must be at least %s characters", field, param)
	case "max":
		return fmt.Sprintf("%s must not exceed %s characters", field, param)
	case "len":
		return fmt.Sprintf("%s must be exactly %s characters", field, param)
	case "phone":
		return "Please enter a valid phone number"
	case "strong_password":
		return "Password must contain at least 8 characters with uppercase, lowercase, number and special character"
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", field, param)
	default:
		return fmt.Sprintf("%s is invalid", field)
	}
}

// Custom validators

// validatePhone validates Turkish phone numbers
func validatePhone(fl validator.FieldLevel) bool {
	phone := fl.Field().String()

	// Remove spaces and common separators
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.ReplaceAll(phone, "-", "")
	phone = strings.ReplaceAll(phone, "(", "")
	phone = strings.ReplaceAll(phone, ")", "")

	// Turkish mobile phone regex patterns
	patterns := []string{
		`^(\+90|0)?5\d{9}$`, // Turkish mobile: +905xxxxxxxxx or 05xxxxxxxxx
		`^(\+90|0)?2\d{9}$`, // Turkish landline: +902xxxxxxxxx or 02xxxxxxxxx
		`^(\+90|0)?3\d{9}$`, // Turkish landline: +903xxxxxxxxx or 03xxxxxxxxx
		`^(\+90|0)?4\d{9}$`, // Turkish landline: +904xxxxxxxxx or 04xxxxxxxxx
		`^\+\d{10,15}$`,     // International format
	}

	for _, pattern := range patterns {
		matched, _ := regexp.MatchString(pattern, phone)
		if matched {
			return true
		}
	}

	return false
}

// validateStrongPassword validates password strength
func validateStrongPassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	if len(password) < 8 {
		return false
	}

	// Check for uppercase letter
	hasUpper, _ := regexp.MatchString(`[A-Z]`, password)
	// Check for lowercase letter
	hasLower, _ := regexp.MatchString(`[a-z]`, password)
	// Check for digit
	hasDigit, _ := regexp.MatchString(`\d`, password)
	// Check for special character
	hasSpecial, _ := regexp.MatchString(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`, password)

	return hasUpper && hasLower && hasDigit && hasSpecial
}

// Additional validation helpers

// IsValidEmail checks if email format is valid
func IsValidEmail(email string) bool {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(pattern, email)
	return matched
}

// IsValidUUID checks if string is valid UUID
func IsValidUUID(uuid string) bool {
	pattern := `^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
	matched, _ := regexp.MatchString(pattern, uuid)
	return matched
}

// NormalizePhone normalizes phone number format
func NormalizePhone(phone string) string {
	// Remove all non-digit characters except +
	re := regexp.MustCompile(`[^\d+]`)
	normalized := re.ReplaceAllString(phone, "")

	// Handle Turkish phone numbers
	if strings.HasPrefix(normalized, "0") && len(normalized) == 11 {
		// Convert 05xxxxxxxxx to +905xxxxxxxxx
		normalized = "+90" + normalized[1:]
	} else if !strings.HasPrefix(normalized, "+") && len(normalized) == 10 {
		// Convert 5xxxxxxxxx to +905xxxxxxxxx
		if strings.HasPrefix(normalized, "5") {
			normalized = "+90" + normalized
		}
	}

	return normalized
}

// SanitizeInput removes potentially harmful characters
func SanitizeInput(input string) string {
	// Remove HTML tags
	re := regexp.MustCompile(`<[^>]*>`)
	sanitized := re.ReplaceAllString(input, "")

	// Remove script tags and content
	re = regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	sanitized = re.ReplaceAllString(sanitized, "")

	// Remove dangerous characters
	dangerous := []string{
		"<script>", "</script>", "<iframe>", "</iframe>",
		"javascript:", "vbscript:", "onload=", "onerror=",
		"onclick=", "onmouseover=", "onfocus=", "onblur=",
	}

	for _, danger := range dangerous {
		sanitized = strings.ReplaceAll(strings.ToLower(sanitized), danger, "")
	}

	// Trim whitespace
	sanitized = strings.TrimSpace(sanitized)

	return sanitized
}

// ValidatePasswordStrength returns password strength score (0-4)
func ValidatePasswordStrength(password string) (int, []string) {
	score := 0
	feedback := []string{}

	if len(password) >= 8 {
		score++
	} else {
		feedback = append(feedback, "Password should be at least 8 characters long")
	}

	if matched, _ := regexp.MatchString(`[a-z]`, password); matched {
		score++
	} else {
		feedback = append(feedback, "Add lowercase letters")
	}

	if matched, _ := regexp.MatchString(`[A-Z]`, password); matched {
		score++
	} else {
		feedback = append(feedback, "Add uppercase letters")
	}

	if matched, _ := regexp.MatchString(`\d`, password); matched {
		score++
	} else {
		feedback = append(feedback, "Add numbers")
	}

	if matched, _ := regexp.MatchString(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`, password); matched {
		score++
	} else {
		feedback = append(feedback, "Add special characters (!@#$%^&*)")
	}

	// Length bonus
	if len(password) >= 12 {
		score++
	}

	// Max score is 5, but we'll cap at 4 for UI purposes
	if score > 4 {
		score = 4
	}

	return score, feedback
}

// ValidateFileUpload validates file upload
func ValidateFileUpload(filename string, maxSizeMB int, allowedTypes []string) error {
	if filename == "" {
		return fmt.Errorf("filename is required")
	}

	// Check file extension
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == "" {
		return fmt.Errorf("file must have an extension")
	}

	// Remove the dot from extension
	ext = ext[1:]

	// Check if extension is allowed
	allowed := false
	for _, allowedType := range allowedTypes {
		if ext == strings.ToLower(allowedType) {
			allowed = true
			break
		}
	}

	if !allowed {
		return fmt.Errorf("file type .%s is not allowed. Allowed types: %s", ext, strings.Join(allowedTypes, ", "))
	}

	return nil
}
