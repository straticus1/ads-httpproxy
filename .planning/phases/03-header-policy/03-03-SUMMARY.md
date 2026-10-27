# Starlark multi-value headers

Status: complete.

Backward-compatible scalar headers plus header_values lists; atomic validation and conflict detection; preserved duplicate Set-Cookie values.

Regression evidence: internal/scripting/starlark/headers_test.go.
Validation: full suite and affected-package race tests passed; go vet and go build passed.
