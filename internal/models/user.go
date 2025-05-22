package models

type SRPUser struct {
	Username string `json:"username"`
	Salt     string `json:"-"` // Hex encoded salt 's'
	Verifier string `json:"-"` // Hex encoded verifier 'v'
}

type OAuthUser struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Email       string `json:"mail"`
}
