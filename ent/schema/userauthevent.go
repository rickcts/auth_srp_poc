package schema

import (
	"time"

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
		field.Int64("user_id"),
		field.Int64("auth_provider"),
		field.String("host"),
		field.Time("unix_ts").Default(time.Now().UTC),
		field.Int64("ns").DefaultFunc(
			func() int64 {
				return time.Now().UnixNano() % int64(time.Second)
			},
		),
		field.Int("error_code"),
		field.Time("created_at").Default(time.Now().UTC).Immutable(),
		field.Time("updated_at").Default(time.Now().UTC).UpdateDefault(time.Now().UTC),
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
