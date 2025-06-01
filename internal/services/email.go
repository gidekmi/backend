// internal/services/email.go
package services

import (
	"bytes"
	"fmt"
	"html/template"
	"strconv"

	"github.com/gidekmi/backend/internal/config"
	"github.com/gidekmi/backend/internal/models"
	"gopkg.in/gomail.v2"
)

// EmailService handles email sending operations
type EmailService struct {
	config *config.Config
	dialer *gomail.Dialer
}

// EmailTemplate represents email template data
type EmailTemplate struct {
	Subject string
	Body    string
}

// OTPEmailData represents data for OTP email template
type OTPEmailData struct {
	FirstName string
	Code      string
	Type      string
	ExpiresIn int // minutes
	AppName   string
}

// NewEmailService creates a new email service
func NewEmailService(cfg *config.Config) *EmailService {
	port, _ := strconv.Atoi(cfg.Email.SMTPPort)
	dialer := gomail.NewDialer(
		cfg.Email.SMTPHost,
		port,
		cfg.Email.SMTPUser,
		cfg.Email.SMTPPassword,
	)

	return &EmailService{
		config: cfg,
		dialer: dialer,
	}
}

// SendOTPEmail sends OTP verification email
func (e *EmailService) SendOTPEmail(user *models.User, code string, otpType models.OTPType, expiresInMinutes int) error {
	templateData := OTPEmailData{
		FirstName: user.FirstName,
		Code:      code,
		Type:      string(otpType),
		ExpiresIn: expiresInMinutes,
		AppName:   "Gidekmi",
	}

	subject, body, err := e.getOTPEmailTemplate(otpType, templateData)
	if err != nil {
		return fmt.Errorf("failed to get email template: %w", err)
	}

	return e.sendEmail(user.Email, subject, body)
}

// SendWelcomeEmail sends welcome email to new users
func (e *EmailService) SendWelcomeEmail(user *models.User) error {
	subject := "Gidekmi'ye Hoş Geldiniz! 🎉"

	templateData := struct {
		FirstName string
		AppName   string
	}{
		FirstName: user.FirstName,
		AppName:   "Gidekmi",
	}

	body, err := e.renderTemplate(getWelcomeEmailTemplate(), templateData)
	if err != nil {
		return fmt.Errorf("failed to render welcome email template: %w", err)
	}

	return e.sendEmail(user.Email, subject, body)
}

// SendPasswordResetEmail sends password reset email
func (e *EmailService) SendPasswordResetEmail(user *models.User, resetCode string, expiresInMinutes int) error {
	templateData := struct {
		FirstName string
		Code      string
		ExpiresIn int
		AppName   string
	}{
		FirstName: user.FirstName,
		Code:      resetCode,
		ExpiresIn: expiresInMinutes,
		AppName:   "Gidekmi",
	}

	subject := "Şifre Sıfırlama - Gidekmi"
	body, err := e.renderTemplate(getPasswordResetEmailTemplate(), templateData)
	if err != nil {
		return fmt.Errorf("failed to render password reset email template: %w", err)
	}

	return e.sendEmail(user.Email, subject, body)
}

// sendEmail sends an email using SMTP
func (e *EmailService) sendEmail(to, subject, body string) error {
	message := gomail.NewMessage()
	message.SetHeader("From", e.config.Email.SMTPUser)
	message.SetHeader("To", to)
	message.SetHeader("Subject", subject)
	message.SetBody("text/html", body)

	if err := e.dialer.DialAndSend(message); err != nil {
		return fmt.Errorf("failed to send email to %s: %w", to, err)
	}

	return nil
}

// renderTemplate renders email template with data
func (e *EmailService) renderTemplate(templateStr string, data interface{}) (string, error) {
	tmpl, err := template.New("email").Parse(templateStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// getOTPEmailTemplate returns appropriate template based on OTP type
func (e *EmailService) getOTPEmailTemplate(otpType models.OTPType, data OTPEmailData) (string, string, error) {
	var subject, templateStr string

	switch otpType {
	case models.OTPTypeEmailVerification:
		subject = "Email Doğrulama Kodu - Gidekmi"
		templateStr = getEmailVerificationTemplate()
	case models.OTPTypeLogin:
		subject = "Giriş Doğrulama Kodu - Gidekmi"
		templateStr = getLoginOTPTemplate()
	case models.OTPTypePasswordReset:
		subject = "Şifre Sıfırlama Kodu - Gidekmi"
		templateStr = getPasswordResetEmailTemplate()
	default:
		return "", "", fmt.Errorf("unsupported OTP type: %s", otpType)
	}

	body, err := e.renderTemplate(templateStr, data)
	if err != nil {
		return "", "", err
	}

	return subject, body, nil
}

// Email Templates

func getEmailVerificationTemplate() string {
	return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Email Doğrulama</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #4F46E5; color: white; padding: 20px; text-align: center; }
        .content { padding: 30px; background: #f9f9f9; }
        .otp-code { font-size: 32px; font-weight: bold; color: #4F46E5; text-align: center; 
                   background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.AppName}}</h1>
        </div>
        <div class="content">
            <h2>Merhaba {{.FirstName}}!</h2>
            <p>Email adresinizi doğrulamak için aşağıdaki kodu kullanın:</p>
            
            <div class="otp-code">{{.Code}}</div>
            
            <p>Bu kod <strong>{{.ExpiresIn}} dakika</strong> süreyle geçerlidir.</p>
            <p>Eğer bu işlemi siz yapmadıysanız, bu e-postayı görmezden gelebilirsiniz.</p>
        </div>
        <div class="footer">
            <p>© 2025 {{.AppName}}. Tüm hakları saklıdır.</p>
        </div>
    </div>
</body>
</html>`
}

func getLoginOTPTemplate() string {
	return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Giriş Doğrulama</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #10B981; color: white; padding: 20px; text-align: center; }
        .content { padding: 30px; background: #f9f9f9; }
        .otp-code { font-size: 32px; font-weight: bold; color: #10B981; text-align: center; 
                   background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.AppName}}</h1>
        </div>
        <div class="content">
            <h2>Merhaba {{.FirstName}}!</h2>
            <p>Hesabınıza giriş yapmak için aşağıdaki kodu kullanın:</p>
            
            <div class="otp-code">{{.Code}}</div>
            
            <p>Bu kod <strong>{{.ExpiresIn}} dakika</strong> süreyle geçerlidir.</p>
            <p>Eğer bu giriş denemesi size ait değilse, lütfen hesabınızın güvenliğini kontrol edin.</p>
        </div>
        <div class="footer">
            <p>© 2025 {{.AppName}}. Tüm hakları saklıdır.</p>
        </div>
    </div>
</body>
</html>`
}

func getPasswordResetEmailTemplate() string {
	return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Şifre Sıfırlama</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #EF4444; color: white; padding: 20px; text-align: center; }
        .content { padding: 30px; background: #f9f9f9; }
        .otp-code { font-size: 32px; font-weight: bold; color: #EF4444; text-align: center; 
                   background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.AppName}}</h1>
        </div>
        <div class="content">
            <h2>Merhaba {{.FirstName}}!</h2>
            <p>Şifrenizi sıfırlamak için aşağıdaki kodu kullanın:</p>
            
            <div class="otp-code">{{.Code}}</div>
            
            <p>Bu kod <strong>{{.ExpiresIn}} dakika</strong> süreyle geçerlidir.</p>
            <p>Eğer şifre sıfırlama talebinde bulunmadıysanız, bu e-postayı görmezden gelebilirsiniz.</p>
        </div>
        <div class="footer">
            <p>© 2025 {{.AppName}}. Tüm hakları saklıdır.</p>
        </div>
    </div>
</body>
</html>`
}

func getWelcomeEmailTemplate() string {
	return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Hoş Geldiniz</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #8B5CF6; color: white; padding: 20px; text-align: center; }
        .content { padding: 30px; background: #f9f9f9; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 14px; }
        .welcome-text { font-size: 18px; text-align: center; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.AppName}}'ye Hoş Geldiniz! 🎉</h1>
        </div>
        <div class="content">
            <h2>Merhaba {{.FirstName}}!</h2>
            <div class="welcome-text">
                <p>{{.AppName}} ailesine katıldığınız için çok mutluyuz!</p>
                <p>Artık harika özelliklere erişebilir ve deneyiminizi kişiselleştirebilirsiniz.</p>
            </div>
            <p>Herhangi bir sorunuz varsa, bizimle iletişime geçmekten çekinmeyin.</p>
            <p>İyi kullanımlar dileriz!</p>
        </div>
        <div class="footer">
            <p>© 2025 {{.AppName}}. Tüm hakları saklıdır.</p>
        </div>
    </div>
</body>
</html>`
}
