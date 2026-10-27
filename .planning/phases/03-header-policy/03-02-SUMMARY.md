# CEL header obligations

Status: complete.

Typed request/response header actions, canonical action roundtrip, aggregate validation before publication, last-set/ordered-append/remove-wins semantics.

Regression evidence: internal/policy/headers_test.go.
Validation: full suite and affected-package race tests passed; go vet and go build passed.
