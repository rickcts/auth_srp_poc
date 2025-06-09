package schema

import (
	"time"

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
		field.Int64("user_id"),
		field.String("mfa_method").Comment("SMS, EMAIL, NUM_MATCH, etc."),
		field.String("params").Optional(),
		field.Time("created_at").Default(time.Now().UTC).Immutable(),
		field.Time("updated_at").Default(time.Now().UTC).UpdateDefault(time.Now().UTC),
	}
}

// Edges of the UserMFA.
func (UserMFA) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("userMFA").
			Unique().
			Required().
			Field("user_id"),
	}
}
