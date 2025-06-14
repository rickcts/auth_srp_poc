// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/SimpnicServerTeam/scs-aaa-server/ent/predicate"
	"github.com/SimpnicServerTeam/scs-aaa-server/ent/user"
	"github.com/SimpnicServerTeam/scs-aaa-server/ent/usermfa"
)

// UserMFAQuery is the builder for querying UserMFA entities.
type UserMFAQuery struct {
	config
	ctx        *QueryContext
	order      []usermfa.OrderOption
	inters     []Interceptor
	predicates []predicate.UserMFA
	withUser   *UserQuery
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the UserMFAQuery builder.
func (umq *UserMFAQuery) Where(ps ...predicate.UserMFA) *UserMFAQuery {
	umq.predicates = append(umq.predicates, ps...)
	return umq
}

// Limit the number of records to be returned by this query.
func (umq *UserMFAQuery) Limit(limit int) *UserMFAQuery {
	umq.ctx.Limit = &limit
	return umq
}

// Offset to start from.
func (umq *UserMFAQuery) Offset(offset int) *UserMFAQuery {
	umq.ctx.Offset = &offset
	return umq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (umq *UserMFAQuery) Unique(unique bool) *UserMFAQuery {
	umq.ctx.Unique = &unique
	return umq
}

// Order specifies how the records should be ordered.
func (umq *UserMFAQuery) Order(o ...usermfa.OrderOption) *UserMFAQuery {
	umq.order = append(umq.order, o...)
	return umq
}

// QueryUser chains the current query on the "user" edge.
func (umq *UserMFAQuery) QueryUser() *UserQuery {
	query := (&UserClient{config: umq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := umq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := umq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(usermfa.Table, usermfa.FieldID, selector),
			sqlgraph.To(user.Table, user.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, usermfa.UserTable, usermfa.UserColumn),
		)
		fromU = sqlgraph.SetNeighbors(umq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first UserMFA entity from the query.
// Returns a *NotFoundError when no UserMFA was found.
func (umq *UserMFAQuery) First(ctx context.Context) (*UserMFA, error) {
	nodes, err := umq.Limit(1).All(setContextOp(ctx, umq.ctx, ent.OpQueryFirst))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{usermfa.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (umq *UserMFAQuery) FirstX(ctx context.Context) *UserMFA {
	node, err := umq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first UserMFA ID from the query.
// Returns a *NotFoundError when no UserMFA ID was found.
func (umq *UserMFAQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = umq.Limit(1).IDs(setContextOp(ctx, umq.ctx, ent.OpQueryFirstID)); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{usermfa.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (umq *UserMFAQuery) FirstIDX(ctx context.Context) int {
	id, err := umq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single UserMFA entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one UserMFA entity is found.
// Returns a *NotFoundError when no UserMFA entities are found.
func (umq *UserMFAQuery) Only(ctx context.Context) (*UserMFA, error) {
	nodes, err := umq.Limit(2).All(setContextOp(ctx, umq.ctx, ent.OpQueryOnly))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{usermfa.Label}
	default:
		return nil, &NotSingularError{usermfa.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (umq *UserMFAQuery) OnlyX(ctx context.Context) *UserMFA {
	node, err := umq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only UserMFA ID in the query.
// Returns a *NotSingularError when more than one UserMFA ID is found.
// Returns a *NotFoundError when no entities are found.
func (umq *UserMFAQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = umq.Limit(2).IDs(setContextOp(ctx, umq.ctx, ent.OpQueryOnlyID)); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{usermfa.Label}
	default:
		err = &NotSingularError{usermfa.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (umq *UserMFAQuery) OnlyIDX(ctx context.Context) int {
	id, err := umq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of UserMFAs.
func (umq *UserMFAQuery) All(ctx context.Context) ([]*UserMFA, error) {
	ctx = setContextOp(ctx, umq.ctx, ent.OpQueryAll)
	if err := umq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*UserMFA, *UserMFAQuery]()
	return withInterceptors[[]*UserMFA](ctx, umq, qr, umq.inters)
}

// AllX is like All, but panics if an error occurs.
func (umq *UserMFAQuery) AllX(ctx context.Context) []*UserMFA {
	nodes, err := umq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of UserMFA IDs.
func (umq *UserMFAQuery) IDs(ctx context.Context) (ids []int, err error) {
	if umq.ctx.Unique == nil && umq.path != nil {
		umq.Unique(true)
	}
	ctx = setContextOp(ctx, umq.ctx, ent.OpQueryIDs)
	if err = umq.Select(usermfa.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (umq *UserMFAQuery) IDsX(ctx context.Context) []int {
	ids, err := umq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (umq *UserMFAQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, umq.ctx, ent.OpQueryCount)
	if err := umq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, umq, querierCount[*UserMFAQuery](), umq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (umq *UserMFAQuery) CountX(ctx context.Context) int {
	count, err := umq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (umq *UserMFAQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, umq.ctx, ent.OpQueryExist)
	switch _, err := umq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (umq *UserMFAQuery) ExistX(ctx context.Context) bool {
	exist, err := umq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the UserMFAQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (umq *UserMFAQuery) Clone() *UserMFAQuery {
	if umq == nil {
		return nil
	}
	return &UserMFAQuery{
		config:     umq.config,
		ctx:        umq.ctx.Clone(),
		order:      append([]usermfa.OrderOption{}, umq.order...),
		inters:     append([]Interceptor{}, umq.inters...),
		predicates: append([]predicate.UserMFA{}, umq.predicates...),
		withUser:   umq.withUser.Clone(),
		// clone intermediate query.
		sql:  umq.sql.Clone(),
		path: umq.path,
	}
}

// WithUser tells the query-builder to eager-load the nodes that are connected to
// the "user" edge. The optional arguments are used to configure the query builder of the edge.
func (umq *UserMFAQuery) WithUser(opts ...func(*UserQuery)) *UserMFAQuery {
	query := (&UserClient{config: umq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	umq.withUser = query
	return umq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		UserID int64 `json:"user_id,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.UserMFA.Query().
//		GroupBy(usermfa.FieldUserID).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (umq *UserMFAQuery) GroupBy(field string, fields ...string) *UserMFAGroupBy {
	umq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &UserMFAGroupBy{build: umq}
	grbuild.flds = &umq.ctx.Fields
	grbuild.label = usermfa.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		UserID int64 `json:"user_id,omitempty"`
//	}
//
//	client.UserMFA.Query().
//		Select(usermfa.FieldUserID).
//		Scan(ctx, &v)
func (umq *UserMFAQuery) Select(fields ...string) *UserMFASelect {
	umq.ctx.Fields = append(umq.ctx.Fields, fields...)
	sbuild := &UserMFASelect{UserMFAQuery: umq}
	sbuild.label = usermfa.Label
	sbuild.flds, sbuild.scan = &umq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a UserMFASelect configured with the given aggregations.
func (umq *UserMFAQuery) Aggregate(fns ...AggregateFunc) *UserMFASelect {
	return umq.Select().Aggregate(fns...)
}

func (umq *UserMFAQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range umq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, umq); err != nil {
				return err
			}
		}
	}
	for _, f := range umq.ctx.Fields {
		if !usermfa.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if umq.path != nil {
		prev, err := umq.path(ctx)
		if err != nil {
			return err
		}
		umq.sql = prev
	}
	return nil
}

func (umq *UserMFAQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*UserMFA, error) {
	var (
		nodes       = []*UserMFA{}
		_spec       = umq.querySpec()
		loadedTypes = [1]bool{
			umq.withUser != nil,
		}
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*UserMFA).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &UserMFA{config: umq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, umq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := umq.withUser; query != nil {
		if err := umq.loadUser(ctx, query, nodes, nil,
			func(n *UserMFA, e *User) { n.Edges.User = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (umq *UserMFAQuery) loadUser(ctx context.Context, query *UserQuery, nodes []*UserMFA, init func(*UserMFA), assign func(*UserMFA, *User)) error {
	ids := make([]int64, 0, len(nodes))
	nodeids := make(map[int64][]*UserMFA)
	for i := range nodes {
		fk := nodes[i].UserID
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(user.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "user_id" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (umq *UserMFAQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := umq.querySpec()
	_spec.Node.Columns = umq.ctx.Fields
	if len(umq.ctx.Fields) > 0 {
		_spec.Unique = umq.ctx.Unique != nil && *umq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, umq.driver, _spec)
}

func (umq *UserMFAQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(usermfa.Table, usermfa.Columns, sqlgraph.NewFieldSpec(usermfa.FieldID, field.TypeInt))
	_spec.From = umq.sql
	if unique := umq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if umq.path != nil {
		_spec.Unique = true
	}
	if fields := umq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, usermfa.FieldID)
		for i := range fields {
			if fields[i] != usermfa.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
		if umq.withUser != nil {
			_spec.Node.AddColumnOnce(usermfa.FieldUserID)
		}
	}
	if ps := umq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := umq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := umq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := umq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (umq *UserMFAQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(umq.driver.Dialect())
	t1 := builder.Table(usermfa.Table)
	columns := umq.ctx.Fields
	if len(columns) == 0 {
		columns = usermfa.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if umq.sql != nil {
		selector = umq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if umq.ctx.Unique != nil && *umq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range umq.predicates {
		p(selector)
	}
	for _, p := range umq.order {
		p(selector)
	}
	if offset := umq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := umq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// UserMFAGroupBy is the group-by builder for UserMFA entities.
type UserMFAGroupBy struct {
	selector
	build *UserMFAQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (umgb *UserMFAGroupBy) Aggregate(fns ...AggregateFunc) *UserMFAGroupBy {
	umgb.fns = append(umgb.fns, fns...)
	return umgb
}

// Scan applies the selector query and scans the result into the given value.
func (umgb *UserMFAGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, umgb.build.ctx, ent.OpQueryGroupBy)
	if err := umgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*UserMFAQuery, *UserMFAGroupBy](ctx, umgb.build, umgb, umgb.build.inters, v)
}

func (umgb *UserMFAGroupBy) sqlScan(ctx context.Context, root *UserMFAQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(umgb.fns))
	for _, fn := range umgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*umgb.flds)+len(umgb.fns))
		for _, f := range *umgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*umgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := umgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// UserMFASelect is the builder for selecting fields of UserMFA entities.
type UserMFASelect struct {
	*UserMFAQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (ums *UserMFASelect) Aggregate(fns ...AggregateFunc) *UserMFASelect {
	ums.fns = append(ums.fns, fns...)
	return ums
}

// Scan applies the selector query and scans the result into the given value.
func (ums *UserMFASelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, ums.ctx, ent.OpQuerySelect)
	if err := ums.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*UserMFAQuery, *UserMFASelect](ctx, ums.UserMFAQuery, ums, ums.inters, v)
}

func (ums *UserMFASelect) sqlScan(ctx context.Context, root *UserMFAQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(ums.fns))
	for _, fn := range ums.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*ums.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := ums.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
