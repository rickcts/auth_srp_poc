package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

// Fields of the UserAuth.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").Unique(),
		field.String("state"),
	}
}

// Edges of the UserAuth.
func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("userAuth", UserAuth.Type),
		edge.To("userMFA", UserMFA.Type),
		edge.To("userAuthEvent", UserAuthEvent.Type),
	}
}
