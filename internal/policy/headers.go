package policy

import (
	"strings"

	"ads-httpproxy/internal/headerpolicy"
)

// HeaderActions validates actions and separates request and response mutations.
// Sets use the last value for each name; appends retain action order. Enforcement
// applies sets, then appends, then removals, so a removal always wins.
func HeaderActions(actions []string) (request, response headerpolicy.Operations, err error) {
	obligations, err := parseObligations(actions)
	if err != nil {
		return request, response, err
	}
	request, response = operationsFromObligations(obligations)
	return request, response, nil
}

func operationsFromObligations(obligations []Obligation) (request, response headerpolicy.Operations) {
	request.Set, request.Append = make(map[string][]string), make(map[string][]string)
	response.Set, response.Append = make(map[string][]string), make(map[string][]string)
	for _, o := range obligations {
		ops := &request
		kind := o.Kind
		if strings.HasPrefix(kind, "response_") {
			ops = &response
			kind = strings.TrimPrefix(kind, "response_")
		}
		switch kind {
		case "set_header":
			ops.Set[o.Name] = append([]string(nil), o.Values...)
		case "append_header":
			ops.Append[o.Name] = append(ops.Append[o.Name], o.Values...)
		case "remove_header":
			ops.Remove = append(ops.Remove, o.Name)
		case "redact_headers":
			ops.Remove = append(ops.Remove, o.Headers...)
		}
	}
	return request, response
}
