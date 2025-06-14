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
	"github.com/SimpnicServerTeam/scs-aaa-server/ent/userauthevent"
)

// UserAuthEventQuery is the builder for querying UserAuthEvent entities.
type UserAuthEventQuery struct {
	config
	ctx        *QueryContext
	order      []userauthevent.OrderOption
	inters     []Interceptor
	predicates []predicate.UserAuthEvent
	withUser   *UserQuery
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the UserAuthEventQuery builder.
func (uaeq *UserAuthEventQuery) Where(ps ...predicate.UserAuthEvent) *UserAuthEventQuery {
	uaeq.predicates = append(uaeq.predicates, ps...)
	return uaeq
}

// Limit the number of records to be returned by this query.
func (uaeq *UserAuthEventQuery) Limit(limit int) *UserAuthEventQuery {
	uaeq.ctx.Limit = &limit
	return uaeq
}

// Offset to start from.
func (uaeq *UserAuthEventQuery) Offset(offset int) *UserAuthEventQuery {
	uaeq.ctx.Offset = &offset
	return uaeq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (uaeq *UserAuthEventQuery) Unique(unique bool) *UserAuthEventQuery {
	uaeq.ctx.Unique = &unique
	return uaeq
}

// Order specifies how the records should be ordered.
func (uaeq *UserAuthEventQuery) Order(o ...userauthevent.OrderOption) *UserAuthEventQuery {
	uaeq.order = append(uaeq.order, o...)
	return uaeq
}

// QueryUser chains the current query on the "user" edge.
func (uaeq *UserAuthEventQuery) QueryUser() *UserQuery {
	query := (&UserClient{config: uaeq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := uaeq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := uaeq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(userauthevent.Table, userauthevent.FieldID, selector),
			sqlgraph.To(user.Table, user.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, userauthevent.UserTable, userauthevent.UserColumn),
		)
		fromU = sqlgraph.SetNeighbors(uaeq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first UserAuthEvent entity from the query.
// Returns a *NotFoundError when no UserAuthEvent was found.
func (uaeq *UserAuthEventQuery) First(ctx context.Context) (*UserAuthEvent, error) {
	nodes, err := uaeq.Limit(1).All(setContextOp(ctx, uaeq.ctx, ent.OpQueryFirst))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{userauthevent.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (uaeq *UserAuthEventQuery) FirstX(ctx context.Context) *UserAuthEvent {
	node, err := uaeq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first UserAuthEvent ID from the query.
// Returns a *NotFoundError when no UserAuthEvent ID was found.
func (uaeq *UserAuthEventQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = uaeq.Limit(1).IDs(setContextOp(ctx, uaeq.ctx, ent.OpQueryFirstID)); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{userauthevent.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (uaeq *UserAuthEventQuery) FirstIDX(ctx context.Context) int {
	id, err := uaeq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single UserAuthEvent entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one UserAuthEvent entity is found.
// Returns a *NotFoundError when no UserAuthEvent entities are found.
func (uaeq *UserAuthEventQuery) Only(ctx context.Context) (*UserAuthEvent, error) {
	nodes, err := uaeq.Limit(2).All(setContextOp(ctx, uaeq.ctx, ent.OpQueryOnly))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{userauthevent.Label}
	default:
		return nil, &NotSingularError{userauthevent.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (uaeq *UserAuthEventQuery) OnlyX(ctx context.Context) *UserAuthEvent {
	node, err := uaeq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only UserAuthEvent ID in the query.
// Returns a *NotSingularError when more than one UserAuthEvent ID is found.
// Returns a *NotFoundError when no entities are found.
func (uaeq *UserAuthEventQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = uaeq.Limit(2).IDs(setContextOp(ctx, uaeq.ctx, ent.OpQueryOnlyID)); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{userauthevent.Label}
	default:
		err = &NotSingularError{userauthevent.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (uaeq *UserAuthEventQuery) OnlyIDX(ctx context.Context) int {
	id, err := uaeq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of UserAuthEvents.
func (uaeq *UserAuthEventQuery) All(ctx context.Context) ([]*UserAuthEvent, error) {
	ctx = setContextOp(ctx, uaeq.ctx, ent.OpQueryAll)
	if err := uaeq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*UserAuthEvent, *UserAuthEventQuery]()
	return withInterceptors[[]*UserAuthEvent](ctx, uaeq, qr, uaeq.inters)
}

// AllX is like All, but panics if an error occurs.
func (uaeq *UserAuthEventQuery) AllX(ctx context.Context) []*UserAuthEvent {
	nodes, err := uaeq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of UserAuthEvent IDs.
func (uaeq *UserAuthEventQuery) IDs(ctx context.Context) (ids []int, err error) {
	if uaeq.ctx.Unique == nil && uaeq.path != nil {
		uaeq.Unique(true)
	}
	ctx = setContextOp(ctx, uaeq.ctx, ent.OpQueryIDs)
	if err = uaeq.Select(userauthevent.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (uaeq *UserAuthEventQuery) IDsX(ctx context.Context) []int {
	ids, err := uaeq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (uaeq *UserAuthEventQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, uaeq.ctx, ent.OpQueryCount)
	if err := uaeq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, uaeq, querierCount[*UserAuthEventQuery](), uaeq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (uaeq *UserAuthEventQuery) CountX(ctx context.Context) int {
	count, err := uaeq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (uaeq *UserAuthEventQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, uaeq.ctx, ent.OpQueryExist)
	switch _, err := uaeq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (uaeq *UserAuthEventQuery) ExistX(ctx context.Context) bool {
	exist, err := uaeq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the UserAuthEventQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (uaeq *UserAuthEventQuery) Clone() *UserAuthEventQuery {
	if uaeq == nil {
		return nil
	}
	return &UserAuthEventQuery{
		config:     uaeq.config,
		ctx:        uaeq.ctx.Clone(),
		order:      append([]userauthevent.OrderOption{}, uaeq.order...),
		inters:     append([]Interceptor{}, uaeq.inters...),
		predicates: append([]predicate.UserAuthEvent{}, uaeq.predicates...),
		withUser:   uaeq.withUser.Clone(),
		// clone intermediate query.
		sql:  uaeq.sql.Clone(),
		path: uaeq.path,
	}
}

// WithUser tells the query-builder to eager-load the nodes that are connected to
// the "user" edge. The optional arguments are used to configure the query builder of the edge.
func (uaeq *UserAuthEventQuery) WithUser(opts ...func(*UserQuery)) *UserAuthEventQuery {
	query := (&UserClient{config: uaeq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	uaeq.withUser = query
	return uaeq
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
//	client.UserAuthEvent.Query().
//		GroupBy(userauthevent.FieldUserID).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (uaeq *UserAuthEventQuery) GroupBy(field string, fields ...string) *UserAuthEventGroupBy {
	uaeq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &UserAuthEventGroupBy{build: uaeq}
	grbuild.flds = &uaeq.ctx.Fields
	grbuild.label = userauthevent.Label
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
//	client.UserAuthEvent.Query().
//		Select(userauthevent.FieldUserID).
//		Scan(ctx, &v)
func (uaeq *UserAuthEventQuery) Select(fields ...string) *UserAuthEventSelect {
	uaeq.ctx.Fields = append(uaeq.ctx.Fields, fields...)
	sbuild := &UserAuthEventSelect{UserAuthEventQuery: uaeq}
	sbuild.label = userauthevent.Label
	sbuild.flds, sbuild.scan = &uaeq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a UserAuthEventSelect configured with the given aggregations.
func (uaeq *UserAuthEventQuery) Aggregate(fns ...AggregateFunc) *UserAuthEventSelect {
	return uaeq.Select().Aggregate(fns...)
}

func (uaeq *UserAuthEventQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range uaeq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, uaeq); err != nil {
				return err
			}
		}
	}
	for _, f := range uaeq.ctx.Fields {
		if !userauthevent.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if uaeq.path != nil {
		prev, err := uaeq.path(ctx)
		if err != nil {
			return err
		}
		uaeq.sql = prev
	}
	return nil
}

func (uaeq *UserAuthEventQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*UserAuthEvent, error) {
	var (
		nodes       = []*UserAuthEvent{}
		_spec       = uaeq.querySpec()
		loadedTypes = [1]bool{
			uaeq.withUser != nil,
		}
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*UserAuthEvent).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &UserAuthEvent{config: uaeq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, uaeq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := uaeq.withUser; query != nil {
		if err := uaeq.loadUser(ctx, query, nodes, nil,
			func(n *UserAuthEvent, e *User) { n.Edges.User = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (uaeq *UserAuthEventQuery) loadUser(ctx context.Context, query *UserQuery, nodes []*UserAuthEvent, init func(*UserAuthEvent), assign func(*UserAuthEvent, *User)) error {
	ids := make([]int64, 0, len(nodes))
	nodeids := make(map[int64][]*UserAuthEvent)
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

func (uaeq *UserAuthEventQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := uaeq.querySpec()
	_spec.Node.Columns = uaeq.ctx.Fields
	if len(uaeq.ctx.Fields) > 0 {
		_spec.Unique = uaeq.ctx.Unique != nil && *uaeq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, uaeq.driver, _spec)
}

func (uaeq *UserAuthEventQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(userauthevent.Table, userauthevent.Columns, sqlgraph.NewFieldSpec(userauthevent.FieldID, field.TypeInt))
	_spec.From = uaeq.sql
	if unique := uaeq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if uaeq.path != nil {
		_spec.Unique = true
	}
	if fields := uaeq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, userauthevent.FieldID)
		for i := range fields {
			if fields[i] != userauthevent.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
		if uaeq.withUser != nil {
			_spec.Node.AddColumnOnce(userauthevent.FieldUserID)
		}
	}
	if ps := uaeq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := uaeq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := uaeq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := uaeq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (uaeq *UserAuthEventQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(uaeq.driver.Dialect())
	t1 := builder.Table(userauthevent.Table)
	columns := uaeq.ctx.Fields
	if len(columns) == 0 {
		columns = userauthevent.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if uaeq.sql != nil {
		selector = uaeq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if uaeq.ctx.Unique != nil && *uaeq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range uaeq.predicates {
		p(selector)
	}
	for _, p := range uaeq.order {
		p(selector)
	}
	if offset := uaeq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := uaeq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// UserAuthEventGroupBy is the group-by builder for UserAuthEvent entities.
type UserAuthEventGroupBy struct {
	selector
	build *UserAuthEventQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (uaegb *UserAuthEventGroupBy) Aggregate(fns ...AggregateFunc) *UserAuthEventGroupBy {
	uaegb.fns = append(uaegb.fns, fns...)
	return uaegb
}

// Scan applies the selector query and scans the result into the given value.
func (uaegb *UserAuthEventGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, uaegb.build.ctx, ent.OpQueryGroupBy)
	if err := uaegb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*UserAuthEventQuery, *UserAuthEventGroupBy](ctx, uaegb.build, uaegb, uaegb.build.inters, v)
}

func (uaegb *UserAuthEventGroupBy) sqlScan(ctx context.Context, root *UserAuthEventQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(uaegb.fns))
	for _, fn := range uaegb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*uaegb.flds)+len(uaegb.fns))
		for _, f := range *uaegb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*uaegb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := uaegb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// UserAuthEventSelect is the builder for selecting fields of UserAuthEvent entities.
type UserAuthEventSelect struct {
	*UserAuthEventQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (uaes *UserAuthEventSelect) Aggregate(fns ...AggregateFunc) *UserAuthEventSelect {
	uaes.fns = append(uaes.fns, fns...)
	return uaes
}

// Scan applies the selector query and scans the result into the given value.
func (uaes *UserAuthEventSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, uaes.ctx, ent.OpQuerySelect)
	if err := uaes.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*UserAuthEventQuery, *UserAuthEventSelect](ctx, uaes.UserAuthEventQuery, uaes, uaes.inters, v)
}

func (uaes *UserAuthEventSelect) sqlScan(ctx context.Context, root *UserAuthEventQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(uaes.fns))
	for _, fn := range uaes.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*uaes.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := uaes.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
