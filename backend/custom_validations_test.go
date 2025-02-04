package api

import (
	"fmt"
	"testing"
)

func TestValidateURL(t *testing.T) {
	type args struct {
		attribute string
		u         string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"valid url",
			func(t *testing.T) args {
				return args{
					"attr",
					"https://toto.com",
				}
			},
			false,
			nil,
		},
		{
			"invalid url",
			func(t *testing.T) args {
				return args{
					"attr",
					"wesh",
				}
			},
			true,
			nil,
		},
		{
			"empty",
			func(t *testing.T) args {
				return args{
					"attr",
					"",
				}
			},
			false,
			nil,
		},
		{
			"invalid url 3",
			func(t *testing.T) args {
				return args{
					"attr",
					"http##dd%",
				}
			},
			true,
			nil,
		},
		{
			"invalid scheme",
			func(t *testing.T) args {
				return args{
					"attr",
					"ftp://what.com",
				}
			},
			true,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateURL(tArgs.attribute, tArgs.u)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateURL error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateDuration(t *testing.T) {
	type args struct {
		attribute string
		duration  string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"valid",
			args{
				"attr",
				"1m",
			},
			false,
		},
		{
			"invalid",
			args{
				"attr",
				"dog",
			},
			true,
		},
		{
			"empty",
			args{
				"attr",
				"",
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateDuration(tt.args.attribute, tt.args.duration); (err != nil) != tt.wantErr {
				t.Errorf("ValidateDuration() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	type args struct {
		attribute string
		email     string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"valid",
			args{
				"attr",
				"something@somewhere.com",
			},
			false,
		},
		{
			"empty",
			args{
				"attr",
				"",
			},
			false,
		},
		{
			"invalid",
			args{
				"attr",
				"something@.com",
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateEmail(tt.args.attribute, tt.args.email); (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmail() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateEmails(t *testing.T) {
	type args struct {
		attribute string
		emails    []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"valid",
			args{
				"attr",
				[]string{
					"something@somewhere.com",
				},
			},
			false,
		},
		{
			"multiple valid",
			args{
				"attr",
				[]string{
					"something@somewhere.com",
					"this@email.me",
					"that@other.net",
				},
			},
			false,
		},
		{
			"multiple valid with one empty",
			args{
				"attr",
				[]string{
					"something@somewhere.com",
					"this@email.me",
					"",
					"that@other.net",
				},
			},
			true,
		},
		{
			"empty",
			args{
				"attr",
				[]string{},
			},
			false,
		},
		{
			"invalid",
			args{
				"attr",
				[]string{
					"something@.com",
				},
			},
			true,
		},
		{
			"mixed valid w/ invalid",
			args{
				"attr",
				[]string{
					"something@somewhere.com",
					"nope",
					"that@other.net",
				},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateEmails(tt.args.attribute, tt.args.emails); (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmails() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTagsExpression(t *testing.T) {
	type args struct {
		attribute  string
		expression [][]string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"empty tag expression",
			func(*testing.T) args {
				return args{
					"attr",
					[][]string{},
				}
			},
			false,
			nil,
		},
		{
			"half empty tag expression",
			func(*testing.T) args {
				return args{
					"attr",
					[][]string{nil, nil},
				}
			},
			false,
			nil,
		},
		{
			"nil tag expression",
			func(*testing.T) args {
				return args{
					"attr",
					nil,
				}
			},
			false,
			nil,
		},
		{
			"valid tag expression",
			func(*testing.T) args {
				return args{
					"attr",
					[][]string{{"a=a", "b=b"}, {"c=c"}},
				}
			},
			false,
			nil,
		},
		{
			"too long tag expression",
			func(*testing.T) args {
				long := make([]byte, 1025)
				return args{
					"attr",
					[][]string{{string(long), "b=b"}, {"c=c"}},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := fmt.Sprintf("error 422 (a3s): Validation Error: '%s' must be less than 1024 bytes", make([]byte, 1025))
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"invalid tag expression",
			func(*testing.T) args {
				return args{
					"attr",
					[][]string{{"aa", "b=b"}, {"c=c"}},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: 'aa' must contain at least one '=' symbol separating two valid words"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateTagsExpression(tArgs.attribute, tArgs.expression)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateTagsExpression error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateAuthorizationSubject(t *testing.T) {
	type args struct {
		attribute string
		subject   [][]string
	}
	tests := []struct {
		name          string
		args          args
		wantErr       bool
		wantErrString string
	}{
		{
			"valid subject",
			args{
				"subject",
				[][]string{
					{"@auth:realm=certificate", "@auth:claim=a"},
					{"@auth:realm=vince", "@auth:claim=a", "@auth:claim=b"},
				},
			},
			false,
			"",
		},
		// {
		// 	"missing realm claim",
		// 	args{
		// 		"subject",
		// 		[][]string{
		// 			{"@auth:realm=certificate", "@auth:claim=a"},
		// 			{"@auth:claim=a", "@auth:claim=b"},
		// 		},
		// 	},
		// 	true,
		// 	"error 422 (a3s): Validation Error: Subject line 2 must contain the '@auth:realm' key",
		// },
		// {
		// 	"2 realm claims",
		// 	args{
		// 		"subject",
		// 		[][]string{
		// 			{"@auth:realm=certificate", "@auth:claim=a", "@auth:realm=vince"},
		// 			{"@auth:claim=a", "@auth:claim=b"},
		// 		},
		// 	},
		// 	true,
		// 	"error 422 (a3s): Validation Error: Subject line 1 must contain only one '@auth:realm' key",
		// },
		// {
		// 	"single claim line",
		// 	args{
		// 		"subject",
		// 		[][]string{
		// 			{"@auth:realm=certificate", "@auth:claim=a"},
		// 			{"@auth:realm=certificate"},
		// 		},
		// 	},
		// 	true,
		// 	"error 422 (a3s): Validation Error: Subject and line should contain at least 2 claims",
		// },
		// {
		// 	"missing auth prefix claim",
		// 	args{
		// 		"subject",
		// 		[][]string{
		// 			{"@auth:realm=certificate", "@auth:claim=a"},
		// 			{"@auth:claim=a", "@auth:claim=b", "not:good"},
		// 		},
		// 	},
		// 	true,
		// 	"error 422 (a3s): Validation Error: Subject claims 'not:good' on line 2 must be prefixed by '@auth:'",
		// },
		// {
		// 	"oidc correct",
		// 	args{
		// 		"subject",
		// 		[][]string{
		// 			{"@auth:realm=oidc", "@auth:claim=a", "@auth:namespace=/a/b"},
		// 			{"@auth:realm=vince", "@auth:claim=a", "@auth:claim=b"},
		// 		},
		// 	},
		// 	false,
		// 	"",
		// },
		// {
		// 	"oidc missing namespace",
		// 	args{
		// 		"subject",
		// 		[][]string{
		// 			{"@auth:realm=oidc", "@auth:claim=a"},
		// 			{"@auth:realm=vince", "@auth:claim=a", "@auth:claim=b"},
		// 		},
		// 	},
		// 	true,
		// 	"error 422 (a3s): Validation Error: The realm OIDC mandates to add the '@auth:namespace' key to prevent potential security side effects",
		// },
		// {
		// 	"saml correct",
		// 	args{
		// 		"subject",
		// 		[][]string{
		// 			{"@auth:realm=saml", "@auth:claim=a", "@auth:namespace=/a/b"},
		// 			{"@auth:realm=vince", "@auth:claim=a", "@auth:claim=b"},
		// 		},
		// 	},
		// 	false,
		// 	"",
		// },
		// {
		// 	"saml missing namespace",
		// 	args{
		// 		"subject",
		// 		[][]string{
		// 			{"@auth:realm=saml", "@auth:claim=a"},
		// 			{"@auth:realm=vince", "@auth:claim=a", "@auth:claim=b"},
		// 		},
		// 	},
		// 	true,
		// 	"error 422 (a3s): Validation Error: The realm SAML mandates to add the '@auth:namespace' key to prevent potential security side effects",
		// },
		{
			"broken tag with no equal",
			args{
				"subject",
				[][]string{
					{"@auth:realm=saml", "@auth:claim"},
				},
			},
			true,
			"error 422 (a3s): Validation Error: Subject claims '@auth:claim' on line 1 is an invalid tag",
		},
		{
			"broken tag with no value",
			args{
				"subject",
				[][]string{
					{"@auth:realm=saml", "@auth:claim="},
				},
			},
			true,
			"error 422 (a3s): Validation Error: Subject claims '@auth:claim=' on line 1 has no value",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAuthorizationSubject(tt.args.attribute, tt.args.subject)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAPIAuthorizationPolicySubject() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil && err.Error() != tt.wantErrString {
				t.Errorf("ValidateAPIAuthorizationPolicySubject() error = '%v', wantErrString = '%v'", err, tt.wantErrString)
			}
		})
	}
}

func TestValidateRestrictedIP(t *testing.T) {
	type args struct {
		attribute string
		host      string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"ok",
			func(*testing.T) args {
				return args{
					"attr",
					"187.9.3.2",
				}
			},
			false,
			nil,
		},

		{
			"nok",
			func(*testing.T) args {
				return args{
					"attr",
					"localhost",
				}
			},
			true,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateRestrictedIP(tArgs.attribute, tArgs.host)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateRestrictedIP error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateRestrictedIPs(t *testing.T) {
	type args struct {
		attribute string
		hosts     []string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"all ok",
			func(*testing.T) args {
				return args{
					"attr",
					[]string{"187.9.3.2", "86.77.3.4", "google.com"},
				}
			},
			false,
			nil,
		},

		{
			"all nok",
			func(*testing.T) args {
				return args{
					"attr",
					[]string{"localhost", "192.168.0.1"},
				}
			},
			true,
			nil,
		},

		{
			"mixed",
			func(*testing.T) args {
				return args{
					"attr",
					[]string{"67.9.1.2", "192.168.0.1"},
				}
			},
			true,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateRestrictedIPs(tArgs.attribute, tArgs.hosts)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateRestrictedIPs error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateFriendlyName(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) // use for more precise error evaluation after test
	}{
		{
			"valid name",
			func(*testing.T) args {
				return args{
					"something",
				}
			},
			false,
			nil,
		},
		{
			"invalid name - empty",
			func(*testing.T) args {
				return args{}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: provided name ('') must contain as least one alphanumeric character, '-' or '_'."
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"invalid name - white space",
			func(*testing.T) args {
				return args{
					"  ",
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: provided name ('  ') must contain as least one alphanumeric character, '-' or '_'."
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"invalid name - unsupported characters",
			func(*testing.T) args {
				return args{
					"&^%",
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: provided name ('&^%') must contain as least one alphanumeric character, '-' or '_'."
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateFriendlyName("friendlyName", tArgs.name)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateFriendlyName error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateObjectIDs(t *testing.T) {
	type args struct {
		attribute string
		ids       []string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) // use for more precise error evaluation after test
	}{
		{
			"valid - single",
			func(*testing.T) args {
				return args{
					attribute: "attr",
					ids: []string{
						"667bc6832459b79435e32825",
					},
				}
			},
			false,
			nil,
		},
		{
			"valid - multiple",
			func(*testing.T) args {
				return args{
					attribute: "attr",
					ids: []string{
						"667bc6832459b79435e32825",
						"667bc6832459b79435e11125",
						"111bc6832459b79435e32825",
					},
				}
			},
			false,
			nil,
		},
		{
			"valid - empty",
			func(*testing.T) args {
				return args{
					attribute: "attr",
				}
			},
			false,
			nil,
		},
		{
			"invalid - multiple with empty string",
			func(*testing.T) args {
				return args{
					attribute: "attr",
					ids: []string{
						"667bc6832459b79435e32825",
						"",
						"111bc6832459b79435e32825",
					},
				}
			},
			true,
			nil,
		},
		{
			"invalid - bad ID",
			func(*testing.T) args {
				return args{
					attribute: "attr",
					ids: []string{
						"fake-id",
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

			err := ValidateObjectIDs(tArgs.attribute, tArgs.ids)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateObjectIDs error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateObjectID(t *testing.T) {
	type args struct {
		attribute string
		id        string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) // use for more precise error evaluation after test
	}{
		{
			"valid",
			func(*testing.T) args {
				return args{
					attribute: "attr",
					id:        "667bc6832459b79435e32825",
				}
			},
			false,
			nil,
		},
		{
			"empty",
			func(*testing.T) args {
				return args{
					attribute: "attr",
				}
			},
			false,
			nil,
		},
		{
			"invalid",
			func(*testing.T) args {
				return args{
					attribute: "attr",
					id:        "fake-id",
				}
			},
			true,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateObjectID(tArgs.attribute, tArgs.id)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateObjectID error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateContentPolicy(t *testing.T) {
	type args struct {
		contentPolicy *ContentPolicy
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) // use for more precise error evaluation after test
	}{
		{
			"ok",
			func(*testing.T) args {
				return args{
					&ContentPolicy{
						Name:        "something",
						Description: "something",
						Moderations: []*Moderation{
							{
								Action:  ModerationActionWarn,
								Message: "This is a warning",
								Predicates: []*Predicate{
									{
										Key:      PredicateKeyCategories,
										Operator: PredicateOperatorEquals,
										Values:   []any{"image/whiteboard"},
									},
									{
										Key:      PredicateKeySecrets,
										Operator: PredicateOperatorNotEmpty,
									},
									{
										Key:      PredicateKeyPlugin,
										Operator: PredicateOperatorNotEmpty,
									},
								},
							},
							{
								Action:  ModerationActionWarn,
								Message: "This is a warning",
								Redact:  true,
								Predicates: []*Predicate{
									{
										Key:      PredicateKeyModality,
										Operator: PredicateOperatorEquals,
										Values:   []any{"code/go"},
									},
									{
										Key:      PredicateKeyPIIs,
										Operator: PredicateOperatorAny,
										Values:   []any{"us_ssn"},
									},
								},
							},
							{
								Action:          ModerationActionNone,
								AlertDefinition: "something",
								Predicates: []*Predicate{
									{
										Key:      PredicateKeySize,
										Operator: PredicateOperatorEqualsOrGreaterThan,
										Values:   []any{10 * 1024 * 1024},
									},
								},
							},
						},
					},
				}
			},
			false,
			nil,
		},
		{
			"action none with no redaction or alert",
			func(*testing.T) args {
				return args{
					&ContentPolicy{
						Name:        "something",
						Description: "something",
						Moderations: []*Moderation{
							{
								Action: ModerationActionNone,
								Predicates: []*Predicate{
									{
										Key:      PredicateKeyModality,
										Operator: PredicateOperatorEquals,
										Values:   []any{"code/go"},
									},
								},
							},
						},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: You must have at least redaction or alert definition set"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"redaction on gte 2 secrets",
			func(*testing.T) args {
				return args{
					&ContentPolicy{
						Name:        "something",
						Description: "something",
						Moderations: []*Moderation{
							{
								Action:  ModerationActionWarn,
								Message: "This is a warning",
								Redact:  true,
								Predicates: []*Predicate{
									{
										Key:      PredicateKeySecrets,
										Operator: PredicateOperatorEqualsOrGreaterThan,
										Values:   []any{2},
									},
								},
							},
						},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: Cannot pair Secrets 'EqualsOrGreaterThan' with redaction; use 'Any' or 'NotEmpty' instead"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"redaction with no redacted values",
			func(*testing.T) args {
				return args{
					&ContentPolicy{
						Name:        "something",
						Description: "something",
						Moderations: []*Moderation{
							{
								Action:  ModerationActionWarn,
								Message: "This is a warning",
								Redact:  true,
								Predicates: []*Predicate{
									{
										Key:      PredicateKeyModality,
										Operator: PredicateOperatorEquals,
										Values:   []any{"code/go"},
									},
								},
							},
						},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: 'Redact' must have at least one keyword, PII, or secret tied to it"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"action block with no message",
			func(*testing.T) args {
				return args{
					&ContentPolicy{
						Name:        "something",
						Description: "something",
						Moderations: []*Moderation{
							{
								Action: ModerationActionBlock,
								Predicates: []*Predicate{
									{
										Key:      PredicateKeyModality,
										Operator: PredicateOperatorEquals,
										Values:   []any{"code/go"},
									},
								},
							},
						},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: 'Message' must not be empty when 'Action' is 'Block'"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"action warn with no message",
			func(*testing.T) args {
				return args{
					&ContentPolicy{
						Name:        "something",
						Description: "something",
						Moderations: []*Moderation{
							{
								Action: ModerationActionWarn,
								Predicates: []*Predicate{
									{
										Key:      PredicateKeyModality,
										Operator: PredicateOperatorEquals,
										Values:   []any{"code/go"},
									},
								},
							},
						},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: 'Message' must not be empty when 'Action' is 'Warn'"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateContentPolicy(tArgs.contentPolicy)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateContentPolicy error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateAccessPolicy(t *testing.T) {
	type args struct {
		accessPolicy *AccessPolicy
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) // use for more precise error evaluation after test
	}{
		{
			"ok",
			func(*testing.T) args {
				return args{
					&AccessPolicy{
						Name:        "something",
						Description: "something",
						Action:      AccessPolicyActionAllow,
						Match: []*Predicate{
							{
								Key:      PredicateKeyProvider,
								Operator: PredicateOperatorAny,
								Values:   []any{"chatgpt"},
							},
							{
								Key:      PredicateKeyTeam,
								Operator: PredicateOperatorAny,
								Values:   []any{"demo"},
							},
						},
						ContentPolicies: []string{
							"something",
							"something2",
						},
					},
				}
			},
			false,
			nil,
		},
		{
			"allow with alert definition",
			func(*testing.T) args {
				return args{
					&AccessPolicy{
						Name:        "something",
						Description: "something",
						Action:      AccessPolicyActionAllow,
						Match: []*Predicate{
							{
								Key:      PredicateKeyProvider,
								Operator: PredicateOperatorAny,
								Values:   []any{"chatgpt"},
							},
							{
								Key:      PredicateKeyTeam,
								Operator: PredicateOperatorAny,
								Values:   []any{"demo"},
							},
							{
								Key:      PredicateKeyTeam,
								Operator: PredicateOperatorAny,
								Values:   []any{"engineers"},
							},
						},
						AlertDefinition: "something",
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: you cannot set an alert definition if the access decision is 'Allow'"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"deny with content policies",
			func(*testing.T) args {
				return args{
					&AccessPolicy{
						Name:        "something",
						Description: "something",
						Action:      AccessPolicyActionDeny,
						Match: []*Predicate{
							{
								Key:      PredicateKeyProvider,
								Operator: PredicateOperatorAny,
								Values:   []any{"chatgpt"},
							},
							{
								Key:      PredicateKeyTeam,
								Operator: PredicateOperatorAny,
								Values:   []any{"demo"},
							},
							{
								Key:      PredicateKeyTeam,
								Operator: PredicateOperatorAny,
								Values:   []any{"engineers"},
							},
						},
						ContentPolicies: []string{
							"something",
							"something2",
						},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: you cannot set content policies if the access decision is 'Deny'"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"duplicate match criteria",
			func(*testing.T) args {
				return args{
					&AccessPolicy{
						Name:        "something",
						Description: "something",
						Action:      AccessPolicyActionAllow,
						Match: []*Predicate{
							{
								Key:      PredicateKeyProvider,
								Operator: PredicateOperatorAny,
								Values:   []any{"chatgpt"},
							},
							{
								Key:      PredicateKeyTeam,
								Operator: PredicateOperatorAny,
								Values:   []any{"demo"},
							},
							{
								Key:      PredicateKeyTeam,
								Operator: PredicateOperatorAny,
								Values:   []any{"engineers"},
							},
						},
						ContentPolicies: []string{
							"something",
							"something2",
						},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: 'Team' cannot have multiple entries for the same operator 'Any'"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"duplicate content policies",
			func(*testing.T) args {
				return args{
					&AccessPolicy{
						Name:        "something",
						Description: "something",
						Action:      AccessPolicyActionAllow,
						Match: []*Predicate{
							{
								Key:      PredicateKeyProvider,
								Operator: PredicateOperatorAny,
								Values:   []any{"chatgpt"},
							},
							{
								Key:      PredicateKeyTeam,
								Operator: PredicateOperatorAny,
								Values:   []any{"demo"},
							},
						},
						ContentPolicies: []string{
							"something",
							"something",
						},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: you cannot have duplicate content policies applied ('something')"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateAccessPolicy(tArgs.accessPolicy)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateAccessPolicy error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidatePredicate(t *testing.T) {
	type args struct {
		predicate *Predicate
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) // use for more precise error evaluation after test
	}{
		{
			"provider - ok (any)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyProvider,
						Operator: PredicateOperatorAny,
						Values:   []any{"chatgpt"},
					},
				}
			},
			false,
			nil,
		},
		{
			"provider - ok (not any)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyProvider,
						Operator: PredicateOperatorNotAny,
						Values:   []any{"claude"},
					},
				}
			},
			false,
			nil,
		},
		{
			"provider - bad operator",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyProvider,
						Operator: "something",
						Values:   []any{"chatgpt"},
					},
				}
			},
			true,
			nil,
		},
		{
			"provider - no value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyProvider,
						Operator: PredicateOperatorAny,
					},
				}
			},
			true,
			nil,
		},
		{
			"provider - bad value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyProvider,
						Operator: PredicateOperatorAny,
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"provider - value with quote",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyProvider,
						Operator: PredicateOperatorAny,
						Values:   []any{"chat\"gpt"},
					},
				}
			},
			true,
			nil,
		},
		{
			"team - ok",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyTeam,
						Operator: PredicateOperatorAny,
						Values:   []any{"chatgpt"},
					},
				}
			},
			false,
			nil,
		},
		{
			"team - bad operator",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyTeam,
						Operator: "something",
						Values:   []any{"chatgpt"},
					},
				}
			},
			true,
			nil,
		},
		{
			"team - no value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyTeam,
						Operator: PredicateOperatorAny,
					},
				}
			},
			true,
			nil,
		},
		{
			"team - bad value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyTeam,
						Operator: PredicateOperatorAny,
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"team - value with quote",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyTeam,
						Operator: PredicateOperatorAny,
						Values:   []any{"chat\"gpt"},
					},
				}
			},
			true,
			nil,
		},
		{
			"workspace - ok",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyWorkspace,
						Operator: PredicateOperatorAny,
						Values:   []any{"chatgpt"},
					},
				}
			},
			false,
			nil,
		},
		{
			"workspace - bad operator",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyWorkspace,
						Operator: "something",
						Values:   []any{"chatgpt"},
					},
				}
			},
			true,
			nil,
		},
		{
			"workspace - no value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyWorkspace,
						Operator: PredicateOperatorAny,
					},
				}
			},
			true,
			nil,
		},
		{
			"workspace - bad value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyWorkspace,
						Operator: PredicateOperatorAny,
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"workspace - empty with value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyWorkspace,
						Operator: PredicateOperatorEmpty,
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"workspace - value with quote",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyWorkspace,
						Operator: PredicateOperatorAny,
						Values:   []any{"chat\"gpt"},
					},
				}
			},
			true,
			nil,
		},
		{
			"plugin - ok",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyPlugin,
						Operator: PredicateOperatorAny,
						Values:   []any{"chatgpt"},
					},
				}
			},
			false,
			nil,
		},
		{
			"plugin - bad operator",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyPlugin,
						Operator: "something",
						Values:   []any{"chatgpt"},
					},
				}
			},
			true,
			nil,
		},
		{
			"plugin - no value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyPlugin,
						Operator: PredicateOperatorAny,
					},
				}
			},
			true,
			nil,
		},
		{
			"plugin - bad value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyPlugin,
						Operator: PredicateOperatorAny,
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"plugin - empty with value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyPlugin,
						Operator: PredicateOperatorEmpty,
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"plugin - value with quote",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyPlugin,
						Operator: PredicateOperatorAny,
						Values:   []any{"chat\"gpt"},
					},
				}
			},
			true,
			nil,
		},
		{
			"confidentiality - ok",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyConfidentiality,
						Operator: PredicateOperatorEqualsOrLesserThan,
						Values:   []any{1.2},
					},
				}
			},
			false,
			nil,
		},
		{
			"confidentiality - uint64 value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyConfidentiality,
						Operator: PredicateOperatorEqualsOrLesserThan,
						Values:   []any{uint64(50)},
					},
				}
			},
			false,
			nil,
		},
		{
			"confidentiality - int64 value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyConfidentiality,
						Operator: PredicateOperatorEqualsOrLesserThan,
						Values:   []any{int64(50)},
					},
				}
			},
			false,
			nil,
		},
		{
			"confidentiality - bad operator",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyConfidentiality,
						Operator: "something",
						Values:   []any{1.2},
					},
				}
			},
			true,
			nil,
		},
		{
			"confidentiality - no value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyConfidentiality,
						Operator: PredicateOperatorEqualsOrLesserThan,
					},
				}
			},
			true,
			nil,
		},
		{
			"confidentiality - bad value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyConfidentiality,
						Operator: PredicateOperatorEqualsOrLesserThan,
						Values:   []any{"1.2"},
					},
				}
			},
			true,
			nil,
		},
		{
			"relevance - ok",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyRelevance,
						Operator: PredicateOperatorEqualsOrLesserThan,
						Values:   []any{1.2},
					},
				}
			},
			false,
			nil,
		},
		{
			"relevance - uint64 value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyRelevance,
						Operator: PredicateOperatorEqualsOrLesserThan,
						Values:   []any{uint64(50)},
					},
				}
			},
			false,
			nil,
		},
		{
			"relevance - int64 value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyRelevance,
						Operator: PredicateOperatorEqualsOrLesserThan,
						Values:   []any{int64(50)},
					},
				}
			},
			false,
			nil,
		},
		{
			"relevance - bad operator",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyRelevance,
						Operator: "something",
						Values:   []any{1.2},
					},
				}
			},
			true,
			nil,
		},
		{
			"relevance - no value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyRelevance,
						Operator: PredicateOperatorEqualsOrLesserThan,
					},
				}
			},
			true,
			nil,
		},
		{
			"relevance - bad value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyRelevance,
						Operator: PredicateOperatorEqualsOrLesserThan,
						Values:   []any{"1.2"},
					},
				}
			},
			true,
			nil,
		},
		{
			"keywords - ok (any)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyKeywords,
						Operator: PredicateOperatorAny,
						Values:   []any{"k1"},
					},
				}
			},
			false,
			nil,
		},
		{
			"keywords - ok (gte)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyKeywords,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{2},
					},
				}
			},
			false,
			nil,
		},
		{
			"keywords - ok (gte)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyKeywords,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{5.2},
					},
				}
			},
			false,
			nil,
		},
		{
			"keywords - bad operator",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyKeywords,
						Operator: "something",
						Values:   []any{"k1"},
					},
				}
			},
			true,
			nil,
		},
		{
			"keywords - no value (any)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyKeywords,
						Operator: PredicateOperatorAny,
					},
				}
			},
			true,
			nil,
		},
		{
			"keywords - multiple values (gte)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyKeywords,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{1, 2, 3},
					},
				}
			},
			true,
			nil,
		},
		{
			"keywords - bad value (any)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyKeywords,
						Operator: PredicateOperatorAny,
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"keywords - bad value (gte)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyKeywords,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{"k1"},
					},
				}
			},
			true,
			nil,
		},
		{
			"keywords - value with quote",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyKeywords,
						Operator: PredicateOperatorAny,
						Values:   []any{"chat\"gpt"},
					},
				}
			},
			true,
			nil,
		},
		{
			"piis - ok (any)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyPIIs,
						Operator: PredicateOperatorAny,
						Values:   []any{"k1"},
					},
				}
			},
			false,
			nil,
		},
		{
			"piis - ok (gte)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyPIIs,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{2},
					},
				}
			},
			false,
			nil,
		},
		{
			"piis - ok (gte)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyPIIs,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{5.2},
					},
				}
			},
			false,
			nil,
		},
		{
			"piis - bad operator",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyPIIs,
						Operator: "something",
						Values:   []any{"k1"},
					},
				}
			},
			true,
			nil,
		},
		{
			"piis - no value (any)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyPIIs,
						Operator: PredicateOperatorAny,
					},
				}
			},
			true,
			nil,
		},
		{
			"piis - multiple values (gte)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyPIIs,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{1, 2, 3},
					},
				}
			},
			true,
			nil,
		},
		{
			"piis - bad value (any)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyPIIs,
						Operator: PredicateOperatorAny,
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"piis - bad value (gte)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyPIIs,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{"k1"},
					},
				}
			},
			true,
			nil,
		},
		{
			"piis - not empty with value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyPIIs,
						Operator: PredicateOperatorNotEmpty,
						Values:   []any{"k1"},
					},
				}
			},
			true,
			nil,
		},
		{
			"piis - value with quote",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyPIIs,
						Operator: PredicateOperatorAny,
						Values:   []any{"chat\"gpt"},
					},
				}
			},
			true,
			nil,
		},
		{
			"secrets - ok (any)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeySecrets,
						Operator: PredicateOperatorAny,
						Values:   []any{"k1"},
					},
				}
			},
			false,
			nil,
		},
		{
			"secrets - ok (gte)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeySecrets,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{2},
					},
				}
			},
			false,
			nil,
		},
		{
			"secrets - ok (gte)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeySecrets,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{5.2},
					},
				}
			},
			false,
			nil,
		},
		{
			"secrets - bad operator",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeySecrets,
						Operator: "something",
						Values:   []any{"k1"},
					},
				}
			},
			true,
			nil,
		},
		{
			"secrets - no value (any)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeySecrets,
						Operator: PredicateOperatorAny,
					},
				}
			},
			true,
			nil,
		},
		{
			"secrets - multiple values (gte)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeySecrets,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{1, 2, 3},
					},
				}
			},
			true,
			nil,
		},
		{
			"secrets - bad value (any)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeySecrets,
						Operator: PredicateOperatorAny,
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"secrets - bad value (gte)",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeySecrets,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{"k1"},
					},
				}
			},
			true,
			nil,
		},
		{
			"secrets - not empty with value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeySecrets,
						Operator: PredicateOperatorNotEmpty,
						Values:   []any{"k1"},
					},
				}
			},
			true,
			nil,
		},
		{
			"secrets - value with quote",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeySecrets,
						Operator: PredicateOperatorAny,
						Values:   []any{"chat\"gpt"},
					},
				}
			},
			true,
			nil,
		},
		{
			"topics - ok",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyTopics,
						Operator: PredicateOperatorAny,
						Values:   []any{"k1"},
					},
				}
			},
			false,
			nil,
		},
		{
			"topics - bad operator",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyTopics,
						Operator: "something",
						Values:   []any{"k1"},
					},
				}
			},
			true,
			nil,
		},
		{
			"topics - no value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyTopics,
						Operator: PredicateOperatorAny,
					},
				}
			},
			true,
			nil,
		},
		{
			"topics - bad value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyTopics,
						Operator: PredicateOperatorAny,
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"topics - value with quote",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyTopics,
						Operator: PredicateOperatorAny,
						Values:   []any{"chat\"gpt"},
					},
				}
			},
			true,
			nil,
		},

		{
			"languages - ok",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyLanguages,
						Operator: PredicateOperatorAny,
						Values:   []any{"english"},
					},
				}
			},
			false,
			nil,
		},
		{
			"languages - bad operator",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyLanguages,
						Operator: "something",
						Values:   []any{"english"},
					},
				}
			},
			true,
			nil,
		},
		{
			"languages - no value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyLanguages,
						Operator: PredicateOperatorAny,
					},
				}
			},
			true,
			nil,
		},
		{
			"languages - bad value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyLanguages,
						Operator: PredicateOperatorAny,
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"languages - value with quote",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyLanguages,
						Operator: PredicateOperatorAny,
						Values:   []any{"chat\"gpt"},
					},
				}
			},
			true,
			nil,
		},
		{
			"size - ok",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeySize,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{1},
					},
				}
			},
			false,
			nil,
		},
		{
			"size - uint64 value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeySize,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{uint64(50)},
					},
				}
			},
			false,
			nil,
		},
		{
			"size - int64 value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeySize,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{int64(50)},
					},
				}
			},
			false,
			nil,
		},
		{
			"size - float64 value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeySize,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{float64(50)},
					},
				}
			},
			false,
			nil,
		},
		{
			"size - bad operator",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeySize,
						Operator: "something",
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"size - no value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeySize,
						Operator: PredicateOperatorEqualsOrGreaterThan,
					},
				}
			},
			true,
			nil,
		},
		{
			"size - bad value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeySize,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{"1"},
					},
				}
			},
			true,
			nil,
		},
		{
			"categories - ok equals",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyCategories,
						Operator: PredicateOperatorEquals,
						Values:   []any{"k1"},
					},
				}
			},
			false,
			nil,
		},
		{
			"categories - ok not equals",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyCategories,
						Operator: PredicateOperatorNotEquals,
						Values:   []any{"k1"},
					},
				}
			},
			false,
			nil,
		},
		{
			"categories - bad operator",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyCategories,
						Operator: "something",
						Values:   []any{"k1"},
					},
				}
			},
			true,
			nil,
		},
		{
			"categories - no value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyCategories,
						Operator: PredicateOperatorEquals,
					},
				}
			},
			true,
			nil,
		},
		{
			"categories - bad value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyCategories,
						Operator: PredicateOperatorEquals,
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"modality - ok equals",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyModality,
						Operator: PredicateOperatorEquals,
						Values:   []any{"code/go"},
					},
				}
			},
			false,
			nil,
		},
		{
			"modality - ok not equals",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyModality,
						Operator: PredicateOperatorNotEquals,
						Values:   []any{"code/go"},
					},
				}
			},
			false,
			nil,
		},
		{
			"modality - bad operator",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyModality,
						Operator: "something",
						Values:   []any{"k1"},
					},
				}
			},
			true,
			nil,
		},
		{
			"modality - no value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyModality,
						Operator: PredicateOperatorEquals,
					},
				}
			},
			true,
			nil,
		},
		{
			"modality - bad value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyModality,
						Operator: PredicateOperatorEquals,
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"exploit - ok any",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyExploits,
						Operator: PredicateOperatorAny,
						Values:   []any{"coucou"},
					},
				}
			},
			false,
			nil,
		},
		{
			"exploit - ok not empty",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyExploits,
						Operator: PredicateOperatorNotEmpty,
					},
				}
			},
			false,
			nil,
		},
		{
			"exploit - any with no value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyExploits,
						Operator: PredicateOperatorAny,
						Values:   []any{},
					},
				}
			},
			true,
			nil,
		},
		{
			"exploit - any with string with quote",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyExploits,
						Operator: PredicateOperatorAny,
						Values:   []any{`"this is quoted"`},
					},
				}
			},
			true,
			nil,
		},
		{
			"exploit - any with int value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyExploits,
						Operator: PredicateOperatorAny,
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"exploit - not empty with value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyExploits,
						Operator: PredicateOperatorNotEmpty,
						Values:   []any{"coucou"},
					},
				}
			},
			true,
			nil,
		},
		{
			"exploit - bad operator",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyExploits,
						Operator: PredicateOperatorEqualsOrGreaterThan,
						Values:   []any{12},
					},
				}
			},
			true,
			nil,
		},
		{
			"model - ok equals",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyModel,
						Operator: PredicateOperatorEquals,
						Values:   []any{"chatgpt"},
					},
				}
			},
			false,
			nil,
		},
		{
			"model - ok not equals",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyModel,
						Operator: PredicateOperatorNotEquals,
						Values:   []any{"chatgpt"},
					},
				}
			},
			false,
			nil,
		},
		{
			"model - bad operator",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyModel,
						Operator: "something",
						Values:   []any{"chatgpt"},
					},
				}
			},
			true,
			nil,
		},
		{
			"model - no value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyModel,
						Operator: PredicateOperatorEquals,
					},
				}
			},
			true,
			nil,
		},
		{
			"model - bad value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyModel,
						Operator: PredicateOperatorEquals,
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"tools - ok",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyTools,
						Operator: PredicateOperatorAny,
						Values:   []any{"chatgpt"},
					},
				}
			},
			false,
			nil,
		},
		{
			"tools - bad operator",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyTools,
						Operator: "something",
						Values:   []any{"chatgpt"},
					},
				}
			},
			true,
			nil,
		},
		{
			"tools - no value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyTools,
						Operator: PredicateOperatorAny,
					},
				}
			},
			true,
			nil,
		},
		{
			"tools - bad value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyTools,
						Operator: PredicateOperatorAny,
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"tools - empty with value",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyTools,
						Operator: PredicateOperatorEmpty,
						Values:   []any{1},
					},
				}
			},
			true,
			nil,
		},
		{
			"tools - value with quote",
			func(*testing.T) args {
				return args{
					&Predicate{
						Key:      PredicateKeyTools,
						Operator: PredicateOperatorAny,
						Values:   []any{"chat\"gpt"},
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

			err := ValidatePredicate(tArgs.predicate)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidatePredicate error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

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

func TestValidateAlertDefinition(t *testing.T) {
	type args struct {
		alertDefinition *AlertDefinition
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) // use for more precise error evaluation after test
	}{
		{
			"valid",
			func(*testing.T) args {
				return args{
					&AlertDefinition{
						Message:  "something",
						Name:     "testName",
						Severity: AlertDefinitionSeverityWarning,
						Sinks: []string{
							"something",
						},
					},
				}
			},
			false,
			nil,
		},
		{
			"duplicate sinks",
			func(*testing.T) args {
				return args{
					&AlertDefinition{
						Message:  "something",
						Name:     "testName",
						Severity: AlertDefinitionSeverityWarning,
						Sinks: []string{
							"something",
							"something",
						},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: you cannot have duplicate sinks applied ('something')"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"occurrences is too high of a number",
			func(*testing.T) args {
				return args{
					&AlertDefinition{
						Message:  "something",
						Name:     "testName",
						Severity: AlertDefinitionSeverityWarning,
						Trigger: &AlertTrigger{
							Occurrences: 999999999999999,
						},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: you cannot set occurrences ('999999999999999') higher than 25. Please consider setting a cooldown in combination."
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateAlertDefinition(tArgs.alertDefinition)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateAlertDefinition error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateSink(t *testing.T) {
	type args struct {
		sink *Sink
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) // use for more precise error evaluation after test
	}{
		{
			"email - valid",
			func(*testing.T) args {
				return args{
					&Sink{
						Type: SinkTypeEmail,
						Email: &SinkEmail{
							Recipients: []string{"this@email.com"},
						},
					},
				}
			},
			false,
			nil,
		},
		{
			"email - no config",
			func(*testing.T) args {
				return args{
					&Sink{
						Type: SinkTypeEmail,
					},
				}
			},
			true,
			nil,
		},
		{
			"pagerduty - valid",
			func(*testing.T) args {
				return args{
					&Sink{
						Type: SinkTypePagerDuty,
						PagerDuty: &SinkPagerDuty{
							Token: "token",
						},
					},
				}
			},
			false,
			nil,
		},
		{
			"pagerduty - no config",
			func(*testing.T) args {
				return args{
					&Sink{
						Type: SinkTypePagerDuty,
					},
				}
			},
			true,
			nil,
		},
		{
			"slack - valid",
			func(*testing.T) args {
				return args{
					&Sink{
						Type: SinkTypeSlack,
						Slack: &SinkSlack{
							WebhookURL: "webhook-url",
						},
					},
				}
			},
			false,
			nil,
		},
		{
			"slack - no config",
			func(*testing.T) args {
				return args{
					&Sink{
						Type: SinkTypeSlack,
					},
				}
			},
			true,
			nil,
		},
		{
			"splunk - valid",
			func(*testing.T) args {
				return args{
					&Sink{
						Type: SinkTypeSplunk,
						Splunk: &SinkSplunk{
							HECURL: "http-event-collector-url",
							Token:  "GH179AE4-3C99-45F5-A7CC-3284AA91CF90",
						},
					},
				}
			},
			false,
			nil,
		},
		{
			"splunk - no config",
			func(*testing.T) args {
				return args{
					&Sink{
						Type: SinkTypeSplunk,
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

			err := ValidateSink(tArgs.sink)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateSink error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateApp(t *testing.T) {
	type args struct {
		app *App
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"no tiers",
			func(*testing.T) args {
				return args{
					&App{
						Tiers: AppTiersList{},
					},
				}
			},
			false,
			nil,
		},
		{
			"ok tiers",
			func(*testing.T) args {
				return args{
					&App{
						Tiers: AppTiersList{
							&AppTier{
								Name: "a",
							},
							&AppTier{
								Name: "b",
							},
						},
					},
				}
			},
			false,
			nil,
		},
		{
			"using _default",
			func(*testing.T) args {
				return args{
					&App{
						Tiers: AppTiersList{
							&AppTier{
								Name: "_default",
							},
						},
					},
				}
			},
			true,
			nil,
		},
		{
			"duplicate tier",
			func(*testing.T) args {
				return args{
					&App{
						Tiers: AppTiersList{
							&AppTier{
								Name: "tier-a",
							},
							&AppTier{
								Name: "tier-a",
							},
						},
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

			err := ValidateApp(tArgs.app)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateApp error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidatePEM(t *testing.T) {
	type args struct {
		attribute string
		pemdata   string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"nothing set",
			args{
				"pem",
				``,
			},
			false,
		},
		{
			"valid single PEM",
			args{
				"pem",
				`-----BEGIN CERTIFICATE-----
MIIBpDCCAUmgAwIBAgIQDbXKAZzk9RjcNSGMsWke1zAKBggqhkjOPQQDAjBGMRAw
DgYDVQQKEwdBcG9yZXRvMQ8wDQYDVQQLEwZhcG9tdXgxITAfBgNVBAMTGEFwb211
eCBQdWJsaWMgU2lnbmluZyBDQTAeFw0xOTAxMjQyMjQ3MjlaFw0yODEyMDIyMjQ3
MjlaMCoxEjAQBgNVBAoTCXNlcGhpcm90aDEUMBIGA1UEAxMLYXV0b21hdGlvbnMw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASxKA9vbyk7FXXlOCi0kTKLVne/mK8o
ZQDPRcehze0EMwTAR5loNahC19hQtExCi64fmI3QCcrEGH9ycUoITYPgozUwMzAO
BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIw
ADAKBggqhkjOPQQDAgNJADBGAiEAm1u2T1vRooIy3rd0BmBSAa6WR6BtHl9nDbGN
1ZM+SgsCIQDu4R6OziiWbRdn50bneZT5qPO+07ALY5m4DG96VyCaQw==
-----END CERTIFICATE-----`,
			},
			false,
		},
		{
			"valid single PEM",
			args{
				"pem",
				`-----BEGIN CERTIFICATE-----
MIIBpDCCAUmgAwIBAgIQDbXKAZzk9RjcNSGMsWke1zAKBggqhkjOPQQDAjBGMRAw
DgYDVQQKEwdBcG9yZXRvMQ8wDQYDVQQLEwZhcG9tdXgxITAfBgNVBAMTGEFwb211
eCBQdWJsaWMgU2lnbmluZyBDQTAeFw0xOTAxMjQyMjQ3MjlaFw0yODEyMDIyMjQ3
MjlaMCoxEjAQBgNVBAoTCXNlcGhpcm90aDEUMBIGA1UEAxMLYXV0b21hdGlvbnMw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASxKA9vbyk7FXXlOCi0kTKLVne/mK8o
ZQDPRcehze0EMwTAR5loNahC19hQtExCi64fmI3QCcrEGH9ycUoITYPgozUwMzAO
BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIw
ADAKBggqhkjOPQQDAgNJADBGAiEAm1u2T1vRooIy3rd0BmBSAa6WR6BtHl9nDbGN
1ZM+SgsCIQDu4R6OziiWbRdn50bneZT5qPO+07ALY5m4DG96VyCaQw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBpDCCAUmgAwIBAgIQDbXKAZzk9RjcNSGMsWke1zAKBggqhkjOPQQDAjBGMRAw
DgYDVQQKEwdBcG9yZXRvMQ8wDQYDVQQLEwZhcG9tdXgxITAfBgNVBAMTGEFwb211
eCBQdWJsaWMgU2lnbmluZyBDQTAeFw0xOTAxMjQyMjQ3MjlaFw0yODEyMDIyMjQ3
MjlaMCoxEjAQBgNVBAoTCXNlcGhpcm90aDEUMBIGA1UEAxMLYXV0b21hdGlvbnMw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASxKA9vbyk7FXXlOCi0kTKLVne/mK8o
ZQDPRcehze0EMwTAR5loNahC19hQtExCi64fmI3QCcrEGH9ycUoITYPgozUwMzAO
BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIw
ADAKBggqhkjOPQQDAgNJADBGAiEAm1u2T1vRooIy3rd0BmBSAa6WR6BtHl9nDbGN
1ZM+SgsCIQDu4R6OziiWbRdn50bneZT5qPO+07ALY5m4DG96VyCaQw==
-----END CERTIFICATE-----
`,
			},
			false,
		},
		{
			"invalid single PEM",
			args{
				"pem",
				`-----BEGIN CERTIFICATE-----
MIIBpDCCAUmgAwIBAgIQDbXKAZzk9RjcNSGMsWke1zAKBggqhkjOPQQDAjBGMRAw
DgYDVQQKEwdBcG9yZXRvMQ8wDQYDVQQLEwZhcG9tdXgxITAfBgNVBAMTGEFwb211
eCBQdWJsaWMgU2lnbmluZyBDQTAeFw0xOTAxMjQyMjQ3MjlaFw0yODEyMDIyMjQ3
MjlaMCoxEjAQBgNVBAoT ----NOT PEM---- I3QCcrEGH9ycUoITYPgozUwMzAO
BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIw
ADAKBggqhkjOPQQDAgNJADBGAiEAm1u2T1vRooIy3rd0BmBSAa6WR6BtHl9nDbGN
1ZM+SgsCIQDu4R6OziiWbRdn50bneZT5qPO+07ALY5m4DG96VyCaQw==
-----END CERTIFICATE-----`,
			},
			true,
		},
		{
			"valid single PEM",
			args{
				"pem",
				`-----BEGIN CERTIFICATE-----
MIIBpDCCAUmgAwIBAgIQDbXKAZzk9RjcNSGMsWke1zAKBggqhkjOPQQDAjBGMRAw
DgYDVQQKEwdBcG9yZXRvMQ8wDQYDVQQLEwZhcG9tdXgxITAfBgNVBAMTGEFwb211
eCBQdWJsaWMgU2lnbmluZyBDQTAeFw0xOTAxMjQyMjQ3MjlaFw0yODEyMDIyMjQ3
MjlaMCoxEjAQBgNVBAoTCXNlcGhpcm90aDEUMBIGA1UEAxMLYXV0b21hdGlvbnMw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASxKA9vbyk7FXXlOCi0kTKLVne/mK8o
ZQDPRcehze0EMwTAR5loNahC19hQtExCi64fmI3QCcrEGH9ycUoITYPgozUwMzAO
BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIw
ADAKBggqhkjOPQQDAgNJADBGAiEAm1u2T1vRooIy3rd0BmBSAa6WR6BtHl9nDbGN
1ZM+SgsCIQDu4R6OziiWbRdn50bneZT5qPO+07ALY5m4DG96VyCaQw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBpDCCAUmgAwIBAgIQDbXKAZzk9RjcNSGMsWke1zAKBggqhkjOPQQDAjBGMRAw
DgYDVQQKEwdBcG9yZXRvMQ8wDQYDVQQLEwZhcG9tdXgxITAfBgNVBAMTGEFwb211
eCBQdWJsaWMgU2lnbmluZyBDQTAeFw0xOTAxMjQyMjQ3MjlaFw0yODEyMDIyMjQ3
MjlaMCoxEjAQBgNVBAoTCXNlcGhpcm90aDEUMBIGA1UEAxMLYXV0b21hdGlvbnMw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASxKA9vbyk7FXXlOCi0kTKLVne/mK8o
ZQDPRcehze0EMwTAR5     ----NOT PEM----   crEGH9ycUoITYPgozUwMzAO
BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIw
ADAKBggqhkjOPQQDAgNJADBGAiEAm1u2T1vRooIy3rd0BmBSAa6WR6BtHl9nDbGN
1ZM+SgsCIQDu4R6OziiWbRdn50bneZT5qPO+07ALY5m4DG96VyCaQw==
-----END CERTIFICATE-----
`,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidatePEM(tt.args.attribute, tt.args.pemdata); (err != nil) != tt.wantErr {
				t.Errorf("ValidatePEM() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAgentConfig(t *testing.T) {
	type args struct {
		agentConfig *AgentConfig
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) // use for more precise error evaluation after test
	}{
		{
			"valid agent config",
			func(*testing.T) args {
				return args{
					&AgentConfig{
						Name:         "name",
						PingInterval: "10m",
					},
				}
			},
			false,
			nil,
		},
		{
			"ping interval is below 5m",
			func(*testing.T) args {
				return args{
					&AgentConfig{
						Name:         "name",
						PingInterval: "1m",
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

			err := ValidateAgentConfig(tArgs.agentConfig)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateAgentConfig error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}
