package policy

import (
	"net/netip"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// CIDREnvOption provides a real IP network match. Invalid inputs are evaluation
// errors, not false: negating a failed parse must never grant access.
func CIDREnvOption() cel.EnvOption {
	return cel.Function("ipInCIDR", cel.Overload("ip_in_cidr_string_string",
		[]*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
		cel.BinaryBinding(func(address, network ref.Val) ref.Val {
			ip, err := netip.ParseAddr(string(address.(types.String)))
			if err != nil || ip.Zone() != "" {
				return types.NewErr("ipInCIDR requires an unscoped IP address")
			}
			prefix, err := netip.ParsePrefix(string(network.(types.String)))
			if err != nil || prefix.Addr().Is4In6() {
				return types.NewErr("ipInCIDR requires an IPv4 or IPv6 CIDR")
			}
			return types.Bool(prefix.Contains(ip.Unmap()))
		})))
}
