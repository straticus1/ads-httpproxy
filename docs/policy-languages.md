# Policy language direction

The proxy already has several complementary mechanisms:

| Mechanism | Current responsibility |
| --- | --- |
| CEL expressions in YAML (`policy_file`) | Request authorization over request, client, verified user and time attributes; allow/block/log and validated actions |
| Starlark (`script_file`, `.star`) and Tengo | Programmable request/response hooks, header transformations and custom blocking |
| Adaptive rules | Versioned host/path/category matching, confidence and expiry, observe/shadow/enforce, preview and rollback |
| WAF, DLP and ICAP | Specialized inspection; a policy expression does not itself classify arbitrary content |

Starlark is useful for extensions, but should not be the only security policy interface. Declarative rules make decisions easier to review and explain. CEL already serves that purpose here. CEL inputs include verified subject, issuer, tenant, groups, scopes and mTLS status. Adaptive category rules consume bounded, fresh tenant-scoped findings; asynchronous sampling cannot guarantee inspection of every request.

## Recommendation

Keep CEL as the built-in policy language and Starlark as the extension mechanism. Before adding another evaluator, define one versioned decision contract (effect, reason, policy/version, obligations), document evaluation order, and add replay tests demonstrating that later hooks cannot bypass earlier security decisions. Body inspection belongs in bounded scanners; evaluators should consume their structured findings.

An optional **OPA/Rego** adapter is the next useful language integration when deployments already manage OPA policies or need richer shared policy/data rules. Rego evaluates structured data and is domain-independent. A future adapter should consume the same verified input, enforce a deadline, reject malformed decisions, fail closed when required, and translate only validated obligations. Bundle distribution, signing, validation and rollback are separate work; installing a language alone does not provide them. [OPA policy language](https://www.openpolicyagent.org/docs/policy-language).

Defer **Cedar** until there is a concrete need for principal/action/resource authorization with an entity model. It is a good candidate for tenant administration and resource permissions, but does not replace content classification, request transformation, or the WAF. Its schemas validate policies against entity types; applications still supply the authorization request and entities. [Cedar authorization](https://docs.cedarpolicy.com/auth/authorization.html), [Cedar schemas](https://docs.cedarpolicy.com/schema/schema.html).

Neither Rego nor Cedar is implemented by this milestone. Avoid enabling multiple independent authorization engines without an explicit composition rule and tests for conflicting decisions.
