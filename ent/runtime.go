// Code generated by ent, DO NOT EDIT.

package ent

import (
	"time"

	"github.com/SimpnicServerTeam/scs-aaa-server/ent/schema"
	"github.com/SimpnicServerTeam/scs-aaa-server/ent/user"
	"github.com/SimpnicServerTeam/scs-aaa-server/ent/useraccessevent"
	"github.com/SimpnicServerTeam/scs-aaa-server/ent/userauth"
	"github.com/SimpnicServerTeam/scs-aaa-server/ent/userauthevent"
	"github.com/SimpnicServerTeam/scs-aaa-server/ent/usermfa"
)

// The init function reads all schema descriptors with runtime code
// (default values, validators, hooks and policies) and stitches it
// to their package variables.
func init() {
	userFields := schema.User{}.Fields()
	_ = userFields
	// userDescDisplayName is the schema descriptor for display_name field.
	userDescDisplayName := userFields[1].Descriptor()
	// user.DisplayNameValidator is a validator for the "display_name" field. It is called by the builders before save.
	user.DisplayNameValidator = userDescDisplayName.Validators[0].(func(string) error)
	// userDescState is the schema descriptor for state field.
	userDescState := userFields[2].Descriptor()
	// user.StateValidator is a validator for the "state" field. It is called by the builders before save.
	user.StateValidator = userDescState.Validators[0].(func(string) error)
	// userDescCreatedAt is the schema descriptor for created_at field.
	userDescCreatedAt := userFields[4].Descriptor()
	// user.DefaultCreatedAt holds the default value on creation for the created_at field.
	user.DefaultCreatedAt = userDescCreatedAt.Default.(func() time.Time)
	// userDescUpdatedAt is the schema descriptor for updated_at field.
	userDescUpdatedAt := userFields[5].Descriptor()
	// user.DefaultUpdatedAt holds the default value on creation for the updated_at field.
	user.DefaultUpdatedAt = userDescUpdatedAt.Default.(func() time.Time)
	// user.UpdateDefaultUpdatedAt holds the default value on update for the updated_at field.
	user.UpdateDefaultUpdatedAt = userDescUpdatedAt.UpdateDefault.(func() time.Time)
	useraccesseventFields := schema.UserAccessEvent{}.Fields()
	_ = useraccesseventFields
	// useraccesseventDescHostFrom is the schema descriptor for host_from field.
	useraccesseventDescHostFrom := useraccesseventFields[1].Descriptor()
	// useraccessevent.HostFromValidator is a validator for the "host_from" field. It is called by the builders before save.
	useraccessevent.HostFromValidator = func() func(string) error {
		validators := useraccesseventDescHostFrom.Validators
		fns := [...]func(string) error{
			validators[0].(func(string) error),
			validators[1].(func(string) error),
		}
		return func(host_from string) error {
			for _, fn := range fns {
				if err := fn(host_from); err != nil {
					return err
				}
			}
			return nil
		}
	}()
	// useraccesseventDescAPIMethod is the schema descriptor for api_method field.
	useraccesseventDescAPIMethod := useraccesseventFields[2].Descriptor()
	// useraccessevent.APIMethodValidator is a validator for the "api_method" field. It is called by the builders before save.
	useraccessevent.APIMethodValidator = func() func(string) error {
		validators := useraccesseventDescAPIMethod.Validators
		fns := [...]func(string) error{
			validators[0].(func(string) error),
			validators[1].(func(string) error),
		}
		return func(api_method string) error {
			for _, fn := range fns {
				if err := fn(api_method); err != nil {
					return err
				}
			}
			return nil
		}
	}()
	// useraccesseventDescAPIPath is the schema descriptor for api_path field.
	useraccesseventDescAPIPath := useraccesseventFields[3].Descriptor()
	// useraccessevent.APIPathValidator is a validator for the "api_path" field. It is called by the builders before save.
	useraccessevent.APIPathValidator = func() func(string) error {
		validators := useraccesseventDescAPIPath.Validators
		fns := [...]func(string) error{
			validators[0].(func(string) error),
			validators[1].(func(string) error),
		}
		return func(api_path string) error {
			for _, fn := range fns {
				if err := fn(api_path); err != nil {
					return err
				}
			}
			return nil
		}
	}()
	// useraccesseventDescCreatedAt is the schema descriptor for created_at field.
	useraccesseventDescCreatedAt := useraccesseventFields[6].Descriptor()
	// useraccessevent.DefaultCreatedAt holds the default value on creation for the created_at field.
	useraccessevent.DefaultCreatedAt = useraccesseventDescCreatedAt.Default.(func() time.Time)
	// useraccesseventDescUpdatedAt is the schema descriptor for updated_at field.
	useraccesseventDescUpdatedAt := useraccesseventFields[7].Descriptor()
	// useraccessevent.DefaultUpdatedAt holds the default value on creation for the updated_at field.
	useraccessevent.DefaultUpdatedAt = useraccesseventDescUpdatedAt.Default.(func() time.Time)
	// useraccessevent.UpdateDefaultUpdatedAt holds the default value on update for the updated_at field.
	useraccessevent.UpdateDefaultUpdatedAt = useraccesseventDescUpdatedAt.UpdateDefault.(func() time.Time)
	userauthFields := schema.UserAuth{}.Fields()
	_ = userauthFields
	// userauthDescCreatedAt is the schema descriptor for created_at field.
	userauthDescCreatedAt := userauthFields[4].Descriptor()
	// userauth.DefaultCreatedAt holds the default value on creation for the created_at field.
	userauth.DefaultCreatedAt = userauthDescCreatedAt.Default.(func() time.Time)
	// userauthDescUpdatedAt is the schema descriptor for updated_at field.
	userauthDescUpdatedAt := userauthFields[5].Descriptor()
	// userauth.DefaultUpdatedAt holds the default value on creation for the updated_at field.
	userauth.DefaultUpdatedAt = userauthDescUpdatedAt.Default.(func() time.Time)
	// userauth.UpdateDefaultUpdatedAt holds the default value on update for the updated_at field.
	userauth.UpdateDefaultUpdatedAt = userauthDescUpdatedAt.UpdateDefault.(func() time.Time)
	userautheventFields := schema.UserAuthEvent{}.Fields()
	_ = userautheventFields
	// userautheventDescUnixTs is the schema descriptor for unix_ts field.
	userautheventDescUnixTs := userautheventFields[3].Descriptor()
	// userauthevent.DefaultUnixTs holds the default value on creation for the unix_ts field.
	userauthevent.DefaultUnixTs = userautheventDescUnixTs.Default.(func() time.Time)
	// userautheventDescNs is the schema descriptor for ns field.
	userautheventDescNs := userautheventFields[4].Descriptor()
	// userauthevent.DefaultNs holds the default value on creation for the ns field.
	userauthevent.DefaultNs = userautheventDescNs.Default.(func() int64)
	// userautheventDescCreatedAt is the schema descriptor for created_at field.
	userautheventDescCreatedAt := userautheventFields[6].Descriptor()
	// userauthevent.DefaultCreatedAt holds the default value on creation for the created_at field.
	userauthevent.DefaultCreatedAt = userautheventDescCreatedAt.Default.(func() time.Time)
	// userautheventDescUpdatedAt is the schema descriptor for updated_at field.
	userautheventDescUpdatedAt := userautheventFields[7].Descriptor()
	// userauthevent.DefaultUpdatedAt holds the default value on creation for the updated_at field.
	userauthevent.DefaultUpdatedAt = userautheventDescUpdatedAt.Default.(func() time.Time)
	// userauthevent.UpdateDefaultUpdatedAt holds the default value on update for the updated_at field.
	userauthevent.UpdateDefaultUpdatedAt = userautheventDescUpdatedAt.UpdateDefault.(func() time.Time)
	usermfaFields := schema.UserMFA{}.Fields()
	_ = usermfaFields
	// usermfaDescCreatedAt is the schema descriptor for created_at field.
	usermfaDescCreatedAt := usermfaFields[3].Descriptor()
	// usermfa.DefaultCreatedAt holds the default value on creation for the created_at field.
	usermfa.DefaultCreatedAt = usermfaDescCreatedAt.Default.(func() time.Time)
	// usermfaDescUpdatedAt is the schema descriptor for updated_at field.
	usermfaDescUpdatedAt := usermfaFields[4].Descriptor()
	// usermfa.DefaultUpdatedAt holds the default value on creation for the updated_at field.
	usermfa.DefaultUpdatedAt = usermfaDescUpdatedAt.Default.(func() time.Time)
	// usermfa.UpdateDefaultUpdatedAt holds the default value on update for the updated_at field.
	usermfa.UpdateDefaultUpdatedAt = usermfaDescUpdatedAt.UpdateDefault.(func() time.Time)
}
