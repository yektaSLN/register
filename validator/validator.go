package validator

import (
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

type Validator struct {
	validate *validator.Validate
}

func New() *Validator {
	return &Validator{
		validate: validator.New(),
	}
}

func (v *Validator) Validate(data interface{}) error {
	return v.validate.Struct(data)
}

func IsValidUsername(username string) bool {
	match, _ := regexp.MatchString(`^[a-zA-Z0-9_]{3,30}$`, username)
	return match
}

func IsValidEmail(email string) bool {
	match, _ := regexp.MatchString(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`, email)
	return match
}

func IsValidPhone(phone string) bool {
	match, _ := regexp.MatchString(`^\+?[0-9]{10,15}$`, phone)
	return match
}

func IsValidPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	hasUpper, _ := regexp.MatchString(`[A-Z]`, password)
	hasLower, _ := regexp.MatchString(`[a-z]`, password)
	hasNumber, _ := regexp.MatchString(`[0-9]`, password)

	return hasUpper && hasLower && hasNumber
}

func IsValidAge(age int) bool {
	return age >= 13 && age <= 120
}
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
func NormalizeUsername(username string) string {
	return strings.TrimSpace(username)
}
func NormalizePhone(phone string) string {
	return strings.TrimSpace(phone)
}
