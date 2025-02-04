package sanitize

import (
	"reflect"
	"testing"
)

func TestName(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		want string
	}{
		{
			"valid - basic",
			func(*testing.T) args {
				return args{
					"Some Name",
				}
			},
			"some-name",
		},
		{
			"valid - advanced",
			func(*testing.T) args {
				return args{
					"Some Policy with numbers 123 (this is some other info)",
				}
			},
			"some-policy-with-numbers-123-this-is-some-other-info",
		},
		{
			"valid - with special characters",
			func(*testing.T) args {
				return args{
					"*!Some:_Name&%$#@().",
				}
			},
			"some_name",
		},
		{
			"valid - same as expected",
			func(*testing.T) args {
				return args{
					"some-name",
				}
			},
			"some-name",
		},
		{
			"valid - empty",
			func(*testing.T) args {
				return args{}
			},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			got := Name(tArgs.name)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Name \ngot = %v, \nwant: %v", got, tt.want)
			}
		})
	}
}
