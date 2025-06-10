package service

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/config"
	"github.com/rs/zerolog/log"
)

var _ EmailService = (*SMTPEmailService)(nil)

// SMTPEmailService implements EmailService using the existing smtp.SendMail logic.
type SMTPEmailService struct {
	cfg *config.SmtpConfig
}

type unencryptedAuth struct {
	smtp.Auth
}

func (a unencryptedAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	s := *server
	s.TLS = true
	return a.Auth.Start(&s)
}

func MergeSlice(s1 []string, s2 []string) []string {
	slice := make([]string, len(s1)+len(s2))
	copy(slice, s1)
	copy(slice[len(s1):], s2)
	return slice
}

func SendToMail(user, password, smtpAddr, authHostname, subject, date, body, mailtype, replyToAddress string, to, cc, bcc []string) error {
	auth := unencryptedAuth{
		smtp.PlainAuth("", user, password, authHostname),
	}
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
	err := smtp.SendMail(smtpAddr, auth, user, send_to, msg)
	return err
}

// NewSMTPEmailService creates a new SMTPEmailService.
func NewSMTPEmailService(smtpCfg *config.SmtpConfig) *SMTPEmailService {
	if smtpCfg == nil {
		log.Warn().Msg("SMTP configuration is nil. Email sending will likely fail.")
		// Return a service that will log errors but not panic
		return &SMTPEmailService{cfg: &config.SmtpConfig{}}
	}
	return &SMTPEmailService{cfg: smtpCfg}
}

// SendPasswordResetEmail sends a password reset email.
// The `resetCode` is the 6-digit code. `resetContextInfo` can be used for branding or instructions if needed, otherwise can be empty.
func (s *SMTPEmailService) SendPasswordResetEmail(ctx context.Context, toEmail, resetCode, appName string) error {
	if s.cfg.Host == "" || s.cfg.User == "" || s.cfg.Port == "" {
		log.Error().Str("toEmail", toEmail).Msg("SMTP host, user, or port not configured. Cannot send password reset email.")
		return fmt.Errorf("SMTP service not fully configured (host, user, or port missing)")
	}

	subject := fmt.Sprintf("Activate Your Account for %s", appName)
	// resetContextInfo could be your app name or a brief instruction.
	body := fmt.Sprintf("Hello,\n\nYou requested a password reset for %s.\n\nYour 6-digit reset code is: %s\n\nThis code will expire in 5 minutes.\n\nIf you did not request this, please ignore this email.", appName, resetCode)
	date := time.Now().UTC().Format(time.RFC1123Z)
	smtpAddr := s.cfg.Host + ":" + s.cfg.Port

	err := SendToMail(s.cfg.User, s.cfg.Password, smtpAddr, s.cfg.Host, subject, date, body, "text", s.cfg.User, []string{toEmail}, nil, nil)
	if err != nil {
		log.Error().Err(err).Str("toEmail", toEmail).Msg("Failed to send password reset email")
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Info().Str("toEmail", toEmail).Msg("Password reset email sent")
	return nil
}

// SendActivationEmail sends an account activation email.
func (s *SMTPEmailService) SendActivationEmail(ctx context.Context, toEmail, activationCode, appName string) error {
	if s.cfg.Host == "" || s.cfg.User == "" || s.cfg.Port == "" {
		log.Error().Str("toEmail", toEmail).Msg("SMTP host, user, or port not configured. Cannot send activation email.")
		return fmt.Errorf("SMTP service not fully configured (host, user, or port missing)")
	}

	subject := fmt.Sprintf("Activate Your Account for %s", appName)
	body := fmt.Sprintf("Hello,\n\nThank you for registering with %s.\n\nYour account activation code is: %s\n\nThis code will expire in approximately 5 minutes.\n\nPlease use this code to activate your account.\n\nIf you did not request this, please ignore this email.", appName, activationCode)
	date := time.Now().UTC().Format(time.RFC1123Z)
	smtpAddr := s.cfg.Host + ":" + s.cfg.Port

	err := SendToMail(s.cfg.User, s.cfg.Password, smtpAddr, s.cfg.Host, subject, date, body, "text", s.cfg.User, []string{toEmail}, nil, nil)
	if err != nil {
		log.Error().Err(err).Str("toEmail", toEmail).Msg("Failed to send activation email")
		return fmt.Errorf("failed to send activation email: %w", err)
	}

	log.Info().Str("toEmail", toEmail).Msg("Activation email sent")
	return nil
}
