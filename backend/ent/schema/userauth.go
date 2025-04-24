package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// UserAuth holds the schema definition for the UserAuth entity.
type UserAuth struct {
	ent.Schema
}

// Fields of the UserAuth.
func (UserAuth) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("user_id").Unique().Immutable(),
		field.Text("auth_extras"),
		field.String("auth_provider"),
		field.String("auth_id"),
	}
}

// Edges of the UserAuth.
func (UserAuth) Edges() []ent.Edge {
	return nil
}
