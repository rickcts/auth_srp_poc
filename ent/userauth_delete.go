// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/SimpnicServerTeam/scs-aaa-server/ent/predicate"
	"github.com/SimpnicServerTeam/scs-aaa-server/ent/userauth"
)

// UserAuthDelete is the builder for deleting a UserAuth entity.
type UserAuthDelete struct {
	config
	hooks    []Hook
	mutation *UserAuthMutation
}

// Where appends a list predicates to the UserAuthDelete builder.
func (uad *UserAuthDelete) Where(ps ...predicate.UserAuth) *UserAuthDelete {
	uad.mutation.Where(ps...)
	return uad
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (uad *UserAuthDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, uad.sqlExec, uad.mutation, uad.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (uad *UserAuthDelete) ExecX(ctx context.Context) int {
	n, err := uad.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (uad *UserAuthDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(userauth.Table, sqlgraph.NewFieldSpec(userauth.FieldID, field.TypeInt))
	if ps := uad.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, uad.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	uad.mutation.done = true
	return affected, err
}

// UserAuthDeleteOne is the builder for deleting a single UserAuth entity.
type UserAuthDeleteOne struct {
	uad *UserAuthDelete
}

// Where appends a list predicates to the UserAuthDelete builder.
func (uado *UserAuthDeleteOne) Where(ps ...predicate.UserAuth) *UserAuthDeleteOne {
	uado.uad.mutation.Where(ps...)
	return uado
}

// Exec executes the deletion query.
func (uado *UserAuthDeleteOne) Exec(ctx context.Context) error {
	n, err := uado.uad.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{userauth.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (uado *UserAuthDeleteOne) ExecX(ctx context.Context) {
	if err := uado.Exec(ctx); err != nil {
		panic(err)
	}
}
