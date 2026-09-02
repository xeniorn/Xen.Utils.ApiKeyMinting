# Xen.Utils.ApiKeyMinting

Delegated, self-service API keys: a caller asks for a key, and gets one carrying only the permissions someone has
separately been granted the right to hand out.

Carries no framework dependencies. Permissions, policy names and subject claims are plain strings; persistence and
the policy/endpoint catalogs are interfaces the host implements, with whatever it already uses. The ASP.NET
binding lives in `Xen.Utils.AspnetAuthorizationHelper.Minting`.

## The validity rule

A permission on a key is live **only while an active grant still authorises that permission for the subject the
key was minted under**. Everything else follows from that:

- The minter changing role or leaving does not affect the key. Validity follows the rule, never the person — which
  is why keys are required to expire.
- Withdrawing a grant suspends every key that depended on it, immediately and without touching those keys.
- Reinstating the grant revives them. The check matches on `(subject, permission)`, not on the grant id recorded at
  mint time, because reinstating often means re-creating and that yields a new id.

## Pieces

| Type | Does |
| --- | --- |
| `MintingGrant` | One delegation rule: holders of a subject may mint keys carrying one permission, for at most some lifetime. |
| `MintingAuthority` | What a caller may delegate. Returns *every* known permission annotated, so a UI can grey out the rest rather than hide it. |
| `PermissionResolver` | Requested policies and endpoints to the permissions they imply, with notes explaining each step. |
| `MintingService` | Issues and revokes keys, refusing anything the caller is not entitled to delegate. |
| `MintedKeyAuthorizer` | The request path: a presented key hash to the permissions it currently carries. |

## What the host provides

```csharp
IMintingGrantStore          // grants; anything at all - EF, Dapper, a list
IMintedKeyStore             // issued keys
IApiKeyHasher               // must produce exactly what your auth layer will compare against
IPolicyRequirementCatalog   // policy name -> the permission sets that satisfy it
IEndpointPolicyCatalog      // optional: endpoints, so callers can pick those instead
```

`IApiKeyHasher` is the one worth care. If the stored hash is not byte-identical to what the authentication layer
derives from a presented key, keys authenticate perfectly and then match nothing — a failure that looks nothing
like its cause. The ASP.NET binding derives it from the API key standard for exactly that reason.

## Two rules worth deciding out loud

- **Union across grants.** Holding two roles lets a caller combine their permissions onto one key, which is more
  capable than either grant alone. That is the simpler rule and almost certainly what you want, but it should be a
  decision, not an accident.
- **Never-mintable permissions.** Anything that bypasses your policies — an admin-like claim — belongs in
  `MintingOptions.NeverMintablePermissions`, in code, so no grants table can ever hand it out.
