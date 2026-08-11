package dto

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Age      int    `json:"age"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}
