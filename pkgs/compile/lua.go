package compile

import (
	"bufio"
	"bytes"
	"fmt"

	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

// Lua compiles the given lua code.
func Lua(code []byte) (*lua.FunctionProto, error) {

	reader := bufio.NewReader(bytes.NewBuffer(code))

	chunk, err := parse.Parse(reader, "code.lua")
	if err != nil {
		return nil, fmt.Errorf("unable to parse code: %w", err)
	}

	proto, err := lua.Compile(chunk, "code.lua")
	if err != nil {
		return nil, fmt.Errorf("unable to compile code: %w", err)
	}

	return proto, nil
}
