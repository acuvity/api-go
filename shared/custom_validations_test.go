package api

import (
	"testing"
)

func TestValidatePrincipal(t *testing.T) {
	type args struct {
		principal *Principal
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) // use for more precise error evaluation after test
	}{
		{
			"app - valid",
			func(*testing.T) args {
				return args{
					&Principal{
						Type:     PrincipalTypeApp,
						AuthType: PrincipalAuthTypeAppToken,
						App: &PrincipalApp{
							Labels: []string{
								"country=us",
							},
							Tier: "frontend",
						},
					},
				}
			},
			false,
			nil,
		},
		{
			"app - no config",
			func(*testing.T) args {
				return args{
					&Principal{
						Type: PrincipalTypeApp,
					},
				}
			},
			true,
			nil,
		},
		{
			"user - valid",
			func(*testing.T) args {
				return args{
					&Principal{
						Type:     PrincipalTypeUser,
						AuthType: PrincipalAuthTypeCertificate,
						User: &PrincipalUser{
							Name: "some@user.com",
						},
					},
				}
			},
			false,
			nil,
		},
		{
			"user - no config",
			func(*testing.T) args {
				return args{
					&Principal{
						Type: PrincipalTypeUser,
					},
				}
			},
			true,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidatePrincipal(tArgs.principal)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidatePrincipal error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateNonEmptyList(t *testing.T) {
	type args[T any] struct {
		attribute string
		list      []T
	}
	tests := []struct {
		name    string
		args    args[string]
		wantErr bool
	}{
		{
			name: "empty list of strings",
			args: args[string]{
				attribute: "attr",
				list:      []string{},
			},
			wantErr: true,
		},
		{
			name: "non-empty list of strings",
			args: args[string]{
				attribute: "attr",
				list:      []string{"a", "b", "c"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateNonEmptyList(tt.args.attribute, tt.args.list); (err != nil) != tt.wantErr {
				t.Errorf("ValidateNonEmptyList() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
