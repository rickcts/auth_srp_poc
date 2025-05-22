package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// UserAuthEvent holds the schema definition for the UserAuthEvent entity.
type UserAuthEvent struct {
	ent.Schema
}

// Fields of the UserAuth.
func (UserAuthEvent) Fields() []ent.Field {
	return []ent.Field{
		field.Int("user_id"),
		field.Int64("auth_provider"),
		field.String("host"),
		field.Time("timestamp"),
		field.Int64("ns"),
		field.Int("error_code"),
	}
}

// Edges of the UserAuth.
func (UserAuthEvent) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("userAuthEvent").
			Unique().
			Required().
			Field("user_id"),
	}
}
