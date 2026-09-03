namespace Util.ApiKeyMinting;

/// <summary>
/// Identifies <em>who</em> a grant applies to, as a plain claim type/value pair - typically a role
/// (<c>roles</c> / <c>SomeAppRole</c>), but nothing here assumes that.
/// </summary>
/// <remarks>
/// Comparison is ordinal and case sensitive, matching how claims are compared everywhere else in the pipeline
/// this feeds. Values come from pick lists rather than free text, so this is not a usability trap.
/// </remarks>
public sealed record SubjectSelector(string ClaimType, string ClaimValue)
{
    /// <summary>Rendered as <c>type=value</c>, which is how it reads in logs and in the UI.</summary>
    public override string ToString() => $"{ClaimType}={ClaimValue}";
}

/// <summary>
/// One delegation rule: holders of <see cref="Subject"/> may mint keys carrying
/// <see cref="GrantablePermission"/>, for at most <see cref="MaxKeyLifetime"/>.
/// <para>
/// One permission per grant, mirroring how claim-to-permission mappings are already stored, so a grant is the
/// smallest revocable unit.
/// </para>
/// </summary>
public sealed record MintingGrant(
    string Id,
    string Scope,
    SubjectSelector Subject,
    string GrantablePermission,
    TimeSpan? MaxKeyLifetime,
    bool IsActive,
    string? Description = null,
    string? CreatedBy = null,
    DateTimeOffset CreatedUtc = default,
    string? LastModifiedBy = null,
    DateTimeOffset? LastModifiedUtc = null,
    string? DeactivatedBy = null,
    DateTimeOffset? DeactivatedUtc = null);

/// <summary>
/// One permission carried by a key.
/// </summary>
/// <param name="Permission">The app-internal permission name.</param>
/// <param name="SourceGrantId">
/// Which grant authorised it at mint time. Provenance only - it is deliberately <em>not</em> what decides whether
/// the permission is still live, because a grant that is removed and re-created gets a new id and must still
/// revive its keys. See <see cref="MintedKeyAuthorizer"/>.
/// </param>
public sealed record MintedKeyPermission(string Permission, string? SourceGrantId);

/// <summary>
/// One digest of the key a caller presented: which algorithm produced it, and the resulting value.
/// </summary>
/// <remarks>
/// A caller sends one key, and the host derives every digest it knows how to. Matching on the pair rather than on
/// the hash alone is what lets keys stored under different algorithms coexist - the algorithm is a property of
/// the stored key, not of the application, so moving the default forward does not invalidate anything.
/// </remarks>
public sealed record PresentedApiKeyDigest(string AlgorithmId, string Hash);

/// <summary>
/// Who is asking to mint, and how far their reach goes.
/// </summary>
/// <param name="Subjects">The subjects the caller actually holds, e.g. their roles.</param>
/// <param name="MayActAsAnySubject">
/// When true the caller may mint under a subject they do not hold - an administrator issuing a key on behalf of a
/// role. It widens <em>whose</em> grants they may draw on, never <em>what</em> a grant allows: a key minted this
/// way still carries only what an active grant gives that subject, and still dies when the grant goes. Someone who
/// can edit grants can already reach the same place in two steps; this only removes the detour.
/// </param>
public sealed record MintingCaller(
    IReadOnlyCollection<SubjectSelector> Subjects,
    bool MayActAsAnySubject = false);

/// <summary>
/// An issued key. Only the hash is ever stored; the plaintext exists once, in the response to the mint call.
/// </summary>
public sealed record MintedKey(
    string Id,
    string Scope,
    string KeyHash,
    string HashAlgorithmId,
    IReadOnlyList<MintedKeyPermission> Permissions,
    SubjectSelector MintedUnderSubject,
    string Label,
    DateTimeOffset CreatedUtc,
    DateTimeOffset ExpiresUtc,
    string? Description = null,
    string? MintedBy = null,
    string? MintedByDisplayName = null,
    DateTimeOffset? LastUsedUtc = null,
    DateTimeOffset? RevokedUtc = null,
    string? RevokedBy = null,
    string? RevocationReason = null)
{
    /// <summary>Revocation is permanent. Unlike a suspended key, a revoked one never comes back.</summary>
    public bool IsRevoked => RevokedUtc is not null;

    /// <summary>Expiry is mandatory, because a key outlives whoever minted it and their role changes.</summary>
    public bool IsExpiredAt(DateTimeOffset nowUtc) => ExpiresUtc <= nowUtc;
}

/// <summary>
/// Why a permission cannot be delegated by a particular caller.
/// </summary>
public enum PermissionBlockReason
{
    /// <summary>Not blocked.</summary>
    None = 0,

    /// <summary>On the never-mintable deny list - no grant can ever unlock it.</summary>
    NeverMintable,

    /// <summary>No active grant covers this permission for any of the caller's subjects.</summary>
    NoActiveGrant
}

/// <summary>
/// The state a key is in, as far as authorization is concerned.
/// </summary>
public enum MintedKeyStatus
{
    /// <summary>No key with that hash in this scope.</summary>
    NotFound = 0,

    /// <summary>Deliberately revoked, permanently.</summary>
    Revoked,

    /// <summary>Past its expiry.</summary>
    Expired,

    /// <summary>The key is intact, but no permission on it is currently backed by an active grant.</summary>
    Suspended,

    /// <summary>At least one permission is live.</summary>
    Active
}
