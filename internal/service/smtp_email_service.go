package service

import (
	"context"
	"fmt"
	"log"
	"net/smtp"
	"strings"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	// Assuming your smtp_service.go is in the same package or accessible.
	// If it's in a different package, adjust the import path.
	// For this example, we'll assume it's in the current 'service' package.
)

var _ EmailService = (*SMTPEmailService)(nil)

// SMTPEmailService implements EmailService using the existing smtp.SendMail logic.
type SMTPEmailService struct {
	cfg *config.SmtpConfig // Assuming SmtpConfig is part of your main Config
}

func MergeSlice(s1 []string, s2 []string) []string {
	slice := make([]string, len(s1)+len(s2))
	copy(slice, s1)
	copy(slice[len(s1):], s2)
	return slice
}

func SendToMail(user, password, host, subject, date, body, mailtype, replyToAddress string, to, cc, bcc []string) error {
	hp := strings.Split(host, ":")
	auth := smtp.PlainAuth("", user, password, hp[0])
	var content_type string
	if mailtype == "html" {
		content_type = "Content-Type: text/html" + "; charset=UTF-8"
	} else {
		content_type = "Content-Type: text/plain" + "; charset=UTF-8"
	}

	cc_address := strings.Join(cc, ";")
	bcc_address := strings.Join(bcc, ";")
	to_address := strings.Join(to, ";")
	msg := []byte("To: " + to_address + "\r\nFrom: " + user + "\r\nSubject: " + subject + "\r\nDate: " + date + "\r\nReply-To: " + replyToAddress + "\r\nCc: " + cc_address + "\r\nBcc: " + bcc_address + "\r\n" + content_type + "\r\n\r\n" + body)
	send_to := MergeSlice(to, cc)
	send_to = MergeSlice(send_to, bcc)
	err := smtp.SendMail(host, auth, user, send_to, msg)
	return err
}

// NewSMTPEmailService creates a new SMTPEmailService.
func NewSMTPEmailService(smtpCfg *config.SmtpConfig) *SMTPEmailService {
	if smtpCfg == nil {
		log.Println("[SMTPEmailService] Warning: SMTP configuration is nil. Email sending will likely fail.")
		// Return a service that will log errors but not panic
		return &SMTPEmailService{cfg: &config.SmtpConfig{}}
	}
	return &SMTPEmailService{cfg: smtpCfg}
}

// SendPasswordResetEmail sends a password reset email.
// The `resetCode` is the 6-digit code. `resetContextInfo` can be used for branding or instructions if needed, otherwise can be empty.
func (s *SMTPEmailService) SendPasswordResetEmail(ctx context.Context, toEmail, resetCode, resetContextInfo string) error {
	if s.cfg.Host == "" || s.cfg.User == "" {
		log.Printf("[SMTPEmailService] ERROR: SMTP host or user not configured. Cannot send email to %s.", toEmail)
		return fmt.Errorf("SMTP service not configured")
	}

	subject := "Password Reset Request"
	// resetContextInfo could be your app name or a brief instruction.
	body := fmt.Sprintf("Hello,\n\nYou requested a password reset for %s.\n\nYour 6-digit reset code is: %s\n\nThis code will expire in 15 minutes.\n\nIf you did not request this, please ignore this email.", resetContextInfo, resetCode)
	date := time.Now().Format(time.RFC1123Z)

	err := SendToMail(s.cfg.User, s.cfg.Password, s.cfg.Host, subject, date, body, "text", s.cfg.User, []string{toEmail}, nil, nil)
	if err != nil {
		log.Printf("[SMTPEmailService] ERROR: Failed to send password reset email to %s: %v", toEmail, err)
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Printf("[SMTPEmailService] Password reset email sent to %s", toEmail)
	return nil
}
