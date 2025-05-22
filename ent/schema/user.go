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
		field.String("display_name").MaxLen(63).Unique(),
		field.String("state").MaxLen(15),
		field.Time("activated_at"),
	}
}

// Edges of the UserAuth.
func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("userAuth", UserAuth.Type),
		edge.To("userMFA", UserMFA.Type),
		edge.To("userAccessEvent", UserAccessEvent.Type),
		edge.To("userAuthEvent", UserAuthEvent.Type),
	}
}
