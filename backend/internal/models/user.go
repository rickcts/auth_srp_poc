package models

type User struct {
	Username string `json:"username"`
	Salt     string `json:"-"` // Hex encoded salt 's'
	Verifier string `json:"-"` // Hex encoded verifier 'v'
}
