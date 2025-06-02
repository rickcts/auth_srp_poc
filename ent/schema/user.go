package schema

import (
	"time"

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
		field.Int64("id").Unique().Immutable(),
		field.String("display_name").MaxLen(63),
		field.String("state").MaxLen(15),
		field.Time("activated_at").Optional(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
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
