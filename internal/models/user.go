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
	Audience    string `json:"aud"`
	Subject     string `json:"sub"`
}

type UserInfo struct {
	ID           int64             `json:"id"`
	DisplayName  string            `json:"displayName"`
	State        string            `json:"state"`
	AuthID       string            `json:"authId"`
	AuthProvider string            `json:"authProvider"`
	AuthExtras   map[string]string `json:"authExtras"`
}
