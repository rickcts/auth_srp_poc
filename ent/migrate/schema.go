// Code generated by ent, DO NOT EDIT.

package migrate

import (
	"entgo.io/ent/dialect/sql/schema"
	"entgo.io/ent/schema/field"
)

var (
	// UsersColumns holds the columns for the "users" table.
	UsersColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt64, Increment: true},
		{Name: "display_name", Type: field.TypeString, Size: 63},
		{Name: "state", Type: field.TypeString, Size: 15},
		{Name: "activated_at", Type: field.TypeTime, Nullable: true},
		{Name: "created_at", Type: field.TypeTime},
		{Name: "updated_at", Type: field.TypeTime},
	}
	// UsersTable holds the schema information for the "users" table.
	UsersTable = &schema.Table{
		Name:       "users",
		Columns:    UsersColumns,
		PrimaryKey: []*schema.Column{UsersColumns[0]},
	}
	// UserAccessEventsColumns holds the columns for the "user_access_events" table.
	UserAccessEventsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "host_from", Type: field.TypeString, Size: 255},
		{Name: "api_method", Type: field.TypeString, Size: 15},
		{Name: "api_path", Type: field.TypeString, Size: 255},
		{Name: "api_path_extras", Type: field.TypeString, Size: 2147483647},
		{Name: "response_code", Type: field.TypeInt},
		{Name: "created_at", Type: field.TypeTime},
		{Name: "updated_at", Type: field.TypeTime},
		{Name: "user_id", Type: field.TypeInt64},
	}
	// UserAccessEventsTable holds the schema information for the "user_access_events" table.
	UserAccessEventsTable = &schema.Table{
		Name:       "user_access_events",
		Columns:    UserAccessEventsColumns,
		PrimaryKey: []*schema.Column{UserAccessEventsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "user_access_events_users_userAccessEvent",
				Columns:    []*schema.Column{UserAccessEventsColumns[8]},
				RefColumns: []*schema.Column{UsersColumns[0]},
				OnDelete:   schema.NoAction,
			},
		},
	}
	// UserAuthsColumns holds the columns for the "user_auths" table.
	UserAuthsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "auth_extras", Type: field.TypeString, Size: 2147483647},
		{Name: "auth_provider", Type: field.TypeString},
		{Name: "auth_id", Type: field.TypeString},
		{Name: "created_at", Type: field.TypeTime},
		{Name: "updated_at", Type: field.TypeTime},
		{Name: "user_id", Type: field.TypeInt64},
	}
	// UserAuthsTable holds the schema information for the "user_auths" table.
	UserAuthsTable = &schema.Table{
		Name:       "user_auths",
		Columns:    UserAuthsColumns,
		PrimaryKey: []*schema.Column{UserAuthsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "user_auths_users_userAuth",
				Columns:    []*schema.Column{UserAuthsColumns[6]},
				RefColumns: []*schema.Column{UsersColumns[0]},
				OnDelete:   schema.NoAction,
			},
		},
	}
	// UserAuthEventsColumns holds the columns for the "user_auth_events" table.
	UserAuthEventsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "auth_provider", Type: field.TypeInt64},
		{Name: "host", Type: field.TypeString},
		{Name: "unix_ts", Type: field.TypeTime},
		{Name: "ns", Type: field.TypeInt64},
		{Name: "error_code", Type: field.TypeInt},
		{Name: "created_at", Type: field.TypeTime},
		{Name: "updated_at", Type: field.TypeTime},
		{Name: "user_id", Type: field.TypeInt64},
	}
	// UserAuthEventsTable holds the schema information for the "user_auth_events" table.
	UserAuthEventsTable = &schema.Table{
		Name:       "user_auth_events",
		Columns:    UserAuthEventsColumns,
		PrimaryKey: []*schema.Column{UserAuthEventsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "user_auth_events_users_userAuthEvent",
				Columns:    []*schema.Column{UserAuthEventsColumns[8]},
				RefColumns: []*schema.Column{UsersColumns[0]},
				OnDelete:   schema.NoAction,
			},
		},
	}
	// UserMfAsColumns holds the columns for the "user_mf_as" table.
	UserMfAsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "mfa_method", Type: field.TypeString},
		{Name: "params", Type: field.TypeString, Nullable: true},
		{Name: "created_at", Type: field.TypeTime},
		{Name: "updated_at", Type: field.TypeTime},
		{Name: "user_id", Type: field.TypeInt64},
	}
	// UserMfAsTable holds the schema information for the "user_mf_as" table.
	UserMfAsTable = &schema.Table{
		Name:       "user_mf_as",
		Columns:    UserMfAsColumns,
		PrimaryKey: []*schema.Column{UserMfAsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "user_mf_as_users_userMFA",
				Columns:    []*schema.Column{UserMfAsColumns[5]},
				RefColumns: []*schema.Column{UsersColumns[0]},
				OnDelete:   schema.NoAction,
			},
		},
	}
	// Tables holds all the tables in the schema.
	Tables = []*schema.Table{
		UsersTable,
		UserAccessEventsTable,
		UserAuthsTable,
		UserAuthEventsTable,
		UserMfAsTable,
	}
)

func init() {
	UserAccessEventsTable.ForeignKeys[0].RefTable = UsersTable
	UserAuthsTable.ForeignKeys[0].RefTable = UsersTable
	UserAuthEventsTable.ForeignKeys[0].RefTable = UsersTable
	UserMfAsTable.ForeignKeys[0].RefTable = UsersTable
}
