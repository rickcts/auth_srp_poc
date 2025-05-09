// Code generated by ent, DO NOT EDIT.

package userauthevent

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

const (
	// Label holds the string label denoting the userauthevent type in the database.
	Label = "user_auth_event"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldUserID holds the string denoting the user_id field in the database.
	FieldUserID = "user_id"
	// FieldAuthProvider holds the string denoting the auth_provider field in the database.
	FieldAuthProvider = "auth_provider"
	// FieldHost holds the string denoting the host field in the database.
	FieldHost = "host"
	// FieldTimestamp holds the string denoting the timestamp field in the database.
	FieldTimestamp = "timestamp"
	// FieldNs holds the string denoting the ns field in the database.
	FieldNs = "ns"
	// FieldErrorCode holds the string denoting the error_code field in the database.
	FieldErrorCode = "error_code"
	// EdgeUser holds the string denoting the user edge name in mutations.
	EdgeUser = "user"
	// Table holds the table name of the userauthevent in the database.
	Table = "user_auth_events"
	// UserTable is the table that holds the user relation/edge.
	UserTable = "user_auth_events"
	// UserInverseTable is the table name for the User entity.
	// It exists in this package in order to avoid circular dependency with the "user" package.
	UserInverseTable = "users"
	// UserColumn is the table column denoting the user relation/edge.
	UserColumn = "user_id"
)

// Columns holds all SQL columns for userauthevent fields.
var Columns = []string{
	FieldID,
	FieldUserID,
	FieldAuthProvider,
	FieldHost,
	FieldTimestamp,
	FieldNs,
	FieldErrorCode,
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}

// OrderOption defines the ordering options for the UserAuthEvent queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByUserID orders the results by the user_id field.
func ByUserID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldUserID, opts...).ToFunc()
}

// ByAuthProvider orders the results by the auth_provider field.
func ByAuthProvider(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldAuthProvider, opts...).ToFunc()
}

// ByHost orders the results by the host field.
func ByHost(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldHost, opts...).ToFunc()
}

// ByTimestamp orders the results by the timestamp field.
func ByTimestamp(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldTimestamp, opts...).ToFunc()
}

// ByNs orders the results by the ns field.
func ByNs(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldNs, opts...).ToFunc()
}

// ByErrorCode orders the results by the error_code field.
func ByErrorCode(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldErrorCode, opts...).ToFunc()
}

// ByUserField orders the results by user field.
func ByUserField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newUserStep(), sql.OrderByField(field, opts...))
	}
}
func newUserStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(UserInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, UserTable, UserColumn),
	)
}
