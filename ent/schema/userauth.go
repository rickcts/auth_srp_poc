package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// UserAuth holds the schema definition for the UserAuth entity.
type UserAuth struct {
	ent.Schema
}

// Fields of the UserAuth.
func (UserAuth) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("user_id"),
		field.Text("auth_extras"),
		field.String("auth_provider"),
		field.String("auth_id"),
		field.Time("created_at").Default(time.Now().UTC).Immutable(),
		field.Time("updated_at").Default(time.Now().UTC).UpdateDefault(time.Now().UTC),
	}
}

// Edges of the UserAuth.
func (UserAuth) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("userAuth").
			Unique().
			Required().
			Field("user_id"),
	}
}
