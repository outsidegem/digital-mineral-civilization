# M1 — Constitutional Core (initial scope)

## Objective
Create a small deterministic Rust foundation for typed identities, autonomy levels, policy requests, and explicit authorization decisions.

## Non-goals
- No model/LLM makes authorization decisions.
- No network server, wallet, blockchain, token, or production execution.
- No JWT signing or key storage in this milestone.
- No integration or modification of existing Titan repositories.

## Safety properties
- Unknown or unsupported actions are denied.
- Missing policy context is denied.
- E5 reserved-authority actions are denied by this runtime until a separate Founder-approved mechanism exists.
- An ALLOW decision is only a policy result; it does not itself execute an action.
- Every decision indicates that an audit record is required.

## First acceptance cases
1. E2 Research agent creating a sandbox report: ALLOW.
2. E2 Research agent transferring treasury funds: DENY.
3. Missing agent identity: DENY.
4. Reserved authority action: DENY.
5. Unknown action: DENY.
