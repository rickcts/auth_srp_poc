package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// UserMFA holds the schema definition for the UserMFA entity.
type UserMFA struct {
	ent.Schema
}

// Fields of the UserMFA.
func (UserMFA) Fields() []ent.Field {
	return []ent.Field{
		field.Int("user_id").Optional(),
		field.String("method"),
		field.String("params").Optional(),
	}
}

// Edges of the UserMFA.
func (UserMFA) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("userMFA").
			Unique().
			Field("user_id"),
	}
}
