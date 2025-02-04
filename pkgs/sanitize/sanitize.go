package sanitize

import "strings"

// Name returns a lowercased version, with white space trimmed
// and replaced by - and special characters removed.
func Name(name string) string {

	if name == "" {
		return ""
	}

	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.ReplaceAll(name, " ", "-")

	sanitizedName := []byte(name)

	var index int
	for _, char := range sanitizedName {
		if ('a' <= char && char <= 'z') || ('0' <= char && char <= '9') ||
			char == '-' || char == '_' {
			sanitizedName[index] = char
			index++
		}
	}

	return string(sanitizedName[:index])
}
