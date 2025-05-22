package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// UserAccessEvent holds the schema definition for the UserAccessEvent entity.
type UserAccessEvent struct {
	ent.Schema
}

// Fields of the UserAccessEvent.
func (UserAccessEvent) Fields() []ent.Field {
	return []ent.Field{
		field.Int("user_id"),
		field.String("host_from").MaxLen(255).NotEmpty(),
		field.String("api_method").MaxLen(15).NotEmpty(),
		field.String("api_path").MaxLen(255).NotEmpty(),
		field.Text("api_path_extras"),
		field.Int("response_code"),
	}
}

// Edges of the UserAccessEvent.
func (UserAccessEvent) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("userAccessEvent").
			Unique().
			Required().
			Field("user_id"),
	}
}
