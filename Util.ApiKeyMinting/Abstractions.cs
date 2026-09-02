namespace Util.ApiKeyMinting;

/// <summary>
/// Persistence for delegation rules. Implement with whatever the host already uses - EF Core, Dapper, a document
/// store, or an in-memory list for tests.
/// </summary>
public interface IMintingGrantStore
{
    /// <summary>All grants in the scope, active and inactive. Callers filter; the UI needs to show both.</summary>
    Task<IReadOnlyList<MintingGrant>> GetAllAsync(string scope, CancellationToken token = default);

    /// <summary>One grant by id, active or not.</summary>
    Task<MintingGrant?> GetAsync(string scope, string grantId, CancellationToken token = default);

    /// <summary>Creates the grant, or replaces it if one with the same id already exists.</summary>
    Task UpsertAsync(MintingGrant grant, CancellationToken token = default);

    /// <summary>
    /// Soft-deactivate. Must not touch any key rows - keys are suspended by the absence of an active grant, and
    /// reactivating has to bring them back.
    /// </summary>
    Task SetActiveAsync(string scope, string grantId, bool isActive, string? actor, CancellationToken token = default);
}

/// <summary>
/// Persistence for issued keys.
/// </summary>
public interface IMintedKeyStore
{
    /// <summary>The key a presented hash belongs to, if any. This is on the authentication path.</summary>
    Task<MintedKey?> FindByHashAsync(string scope, string keyHash, CancellationToken token = default);

    /// <summary>Keys in the scope, for the management view.</summary>
    Task<IReadOnlyList<MintedKey>> ListAsync(string scope, bool includeRevoked, CancellationToken token = default);

    /// <summary>Stores a newly minted key. Only the hash arrives here; the plaintext never does.</summary>
    Task AddAsync(MintedKey key, CancellationToken token = default);

    /// <summary>Permanently revokes a key. Unlike deactivating a grant, this cannot be undone.</summary>
    Task RevokeAsync(string scope, string keyId, string? revokedBy, string? reason, DateTimeOffset revokedUtc,
        CancellationToken token = default);

    /// <summary>
    /// Records that the key was used. Called on the authentication path, so implementations should be cheap and
    /// are free to skip writes - <see cref="MintedKeyAuthorizer"/> already throttles the calls.
    /// </summary>
    Task TouchLastUsedAsync(string scope, string keyId, DateTimeOffset whenUtc, CancellationToken token = default);
}

/// <summary>
/// Turns a plaintext key into the value it is stored and looked up by.
/// </summary>
/// <remarks>
/// In an aspnet host this must produce exactly what the authentication handler will put in the claim, or minted
/// keys will authenticate and then match nothing. The binding package derives it from the api key standard for
/// precisely that reason.
/// </remarks>
public interface IApiKeyHasher
{
    /// <summary>Stored alongside each key, so keys hashed under different algorithms can coexist.</summary>
    string AlgorithmId { get; }

    /// <summary>The stored, comparable form of a plaintext key.</summary>
    string Hash(string apiKey);
}

/// <summary>
/// Produces new plaintext keys.
/// </summary>
public interface IApiKeyGenerator
{
    /// <summary>A fresh, unguessable key, in plaintext.</summary>
    string Generate();
}

/// <summary>
/// What the host's authorization policies require, flattened to plain permission strings.
/// </summary>
public interface IPolicyRequirementCatalog
{
    /// <summary>Every policy name a caller may ask for.</summary>
    IReadOnlyCollection<string> KnownPolicyNames { get; }

    /// <summary>
    /// Every permission the application defines - including ones the caller cannot delegate, so the UI can show
    /// them greyed out rather than hiding their existence.
    /// </summary>
    IReadOnlyCollection<string> KnownPermissions { get; }

    /// <summary>
    /// The alternative permission sets that satisfy a policy. A policy is satisfied if <em>any</em> alternative
    /// is met; an alternative may legitimately be empty (a policy that requires nothing).
    /// </summary>
    bool TryGetRequirementAlternatives(string policyName, out IReadOnlyList<IReadOnlySet<string>> alternatives);
}

/// <summary>
/// An endpoint a key could be minted for.
/// </summary>
public sealed record MintableEndpoint(
    string Id,
    string DisplayName,
    string? HttpMethod,
    string? Route,
    IReadOnlyList<string> PolicyNames);

/// <summary>
/// The endpoints a caller may pick from. Optional - a host may let people choose policies directly instead.
/// </summary>
public interface IEndpointPolicyCatalog
{
    /// <summary>Every endpoint a caller may ask for a key against.</summary>
    IReadOnlyCollection<MintableEndpoint> Endpoints { get; }
}

/// <summary>
/// Knobs for the minting behaviour.
/// </summary>
public sealed class MintingOptions
{
    /// <summary>
    /// Permissions no grant may ever unlock. Belongs in code, not in configuration or the database - the point is
    /// that nobody can add the admin permission to a grants table later.
    /// </summary>
    public IReadOnlyCollection<string> NeverMintablePermissions { get; set; } = [];

    /// <summary>Applied when the caller states no preference.</summary>
    public TimeSpan DefaultKeyLifetime { get; set; } = TimeSpan.FromDays(90);

    /// <summary>Ceiling applied on top of whatever the matching grants allow.</summary>
    public TimeSpan AbsoluteMaxKeyLifetime { get; set; } = TimeSpan.FromDays(365);

    /// <summary>How stale a key's LastUsed timestamp may get before another write is worth it.</summary>
    public TimeSpan LastUsedWriteThrottle { get; set; } = TimeSpan.FromMinutes(1);
}
