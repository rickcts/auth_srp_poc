// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/SimpnicServerTeam/scs-aaa-server/ent/predicate"
	"github.com/SimpnicServerTeam/scs-aaa-server/ent/usermfa"
)

// UserMFADelete is the builder for deleting a UserMFA entity.
type UserMFADelete struct {
	config
	hooks    []Hook
	mutation *UserMFAMutation
}

// Where appends a list predicates to the UserMFADelete builder.
func (umd *UserMFADelete) Where(ps ...predicate.UserMFA) *UserMFADelete {
	umd.mutation.Where(ps...)
	return umd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (umd *UserMFADelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, umd.sqlExec, umd.mutation, umd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (umd *UserMFADelete) ExecX(ctx context.Context) int {
	n, err := umd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (umd *UserMFADelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(usermfa.Table, sqlgraph.NewFieldSpec(usermfa.FieldID, field.TypeInt))
	if ps := umd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, umd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	umd.mutation.done = true
	return affected, err
}

// UserMFADeleteOne is the builder for deleting a single UserMFA entity.
type UserMFADeleteOne struct {
	umd *UserMFADelete
}

// Where appends a list predicates to the UserMFADelete builder.
func (umdo *UserMFADeleteOne) Where(ps ...predicate.UserMFA) *UserMFADeleteOne {
	umdo.umd.mutation.Where(ps...)
	return umdo
}

// Exec executes the deletion query.
func (umdo *UserMFADeleteOne) Exec(ctx context.Context) error {
	n, err := umdo.umd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{usermfa.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (umdo *UserMFADeleteOne) ExecX(ctx context.Context) {
	if err := umdo.Exec(ctx); err != nil {
		panic(err)
	}
}
