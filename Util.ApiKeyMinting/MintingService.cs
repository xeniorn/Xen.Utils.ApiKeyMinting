using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Util.ApiKeyMinting;

/// <param name="Scope">Which application instance the key belongs to.</param>
/// <param name="MintUnderSubject">The caller subject the key hangs off. Its grants decide the key's fate.</param>
/// <param name="Permissions">What the key should carry.</param>
/// <param name="Label">Short name, so the key can be recognised in the list later. Required.</param>
/// <param name="RequestedLifetime">Defaults and caps apply. Ignored when <paramref name="NeverExpires"/> is set.</param>
/// <param name="NeverExpires">
/// Mints a key with no expiry. Allowed only when nothing caps the lifetime of what is being asked for - no grant
/// maximum and no absolute ceiling - so an unlimited key is always a deliberate act by someone who could have
/// been given the ceiling anyway.
/// </param>
/// <param name="HashAlgorithmId">Which digest to store the key under. Defaults to the hasher's default.</param>
/// <param name="Description">What the key is for.</param>
/// <param name="MintedBy">Stable id of the person minting it.</param>
/// <param name="MintedByDisplayName">Their readable name, for the listing.</param>
/// <param name="AdditionalSubjects">
/// Further subjects the caller holds whose grants may back permissions on the same key - one key for someone with
/// several roles. Each permission records the subject backing it, and lives or dies with that subject's grant.
/// </param>
public sealed record MintRequest(
    string Scope,
    SubjectSelector MintUnderSubject,
    IReadOnlyCollection<string> Permissions,
    string Label,
    TimeSpan? RequestedLifetime = null,
    bool NeverExpires = false,
    string? HashAlgorithmId = null,
    string? Description = null,
    string? MintedBy = null,
    string? MintedByDisplayName = null,
    IReadOnlyCollection<SubjectSelector>? AdditionalSubjects = null)
{
    /// <summary>
    /// <see cref="KeyValidity.FollowsMinter"/> for a personal delegation that must lapse with the minter's role;
    /// requires <see cref="MintedBy"/>. An init property, so callers compiled against earlier versions keep working.
    /// </summary>
    public KeyValidity Validity { get; init; } = KeyValidity.FollowsGrant;
}

/// <summary>
/// The plaintext key exists only here, only once. It is never stored and cannot be recovered.
/// </summary>
public sealed record MintResult(MintedKey Key, string PlaintextApiKey);

/// <summary>The request was understood and denied: the caller may not delegate what they asked for.</summary>
public sealed class MintingRefusedException(string reason) : Exception(reason);

/// <summary>
/// Issues and revokes keys, refusing anything the caller is not entitled to delegate.
/// </summary>
public sealed class MintingService(
    IMintedKeyStore keyStore,
    IMintingGrantStore grantStore,
    IApiKeyHasher hasher,
    IApiKeyGenerator generator,
    IPolicyRequirementCatalog policyCatalog,
    MintingAuthority authority,
    MintingOptions options,
    TimeProvider? timeProvider = null,
    ILogger<MintingService>? logger = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly ILogger _logger = logger ?? NullLogger<MintingService>.Instance;

    /// <summary>
    /// What this caller may hand out, with every known permission annotated so the UI can grey out the rest.
    /// </summary>
    public async Task<MintingAuthorityResult> GetAuthorityAsync(
        string scope, MintingCaller caller, CancellationToken token = default)
    {
        var grants = await grantStore.GetAllAsync(scope, token);
        return authority.Evaluate(grants, caller, policyCatalog.KnownPermissions);
    }

    /// <summary>Issues a key, or throws <see cref="MintingRefusedException"/> if the caller may not.</summary>
    public async Task<MintResult> MintAsync(
        MintRequest request, MintingCaller caller, CancellationToken token = default)
    {
        if (string.IsNullOrWhiteSpace(request.Label))
            throw new MintingRefusedException("A label is required, so the key can be recognised later.");

        if (request.Permissions.Count == 0)
            throw new MintingRefusedException("A key with no permissions would do nothing.");

        if (request.Validity == KeyValidity.FollowsMinter && string.IsNullOrWhiteSpace(request.MintedBy))
            throw new MintingRefusedException("A key that follows its minter needs to know who the minter is (MintedBy).");

        SubjectSelector[] subjects = [request.MintUnderSubject, .. (request.AdditionalSubjects ?? []).Where(x => x != request.MintUnderSubject).Distinct()];

        foreach (var subject in subjects)
        {
            if (!caller.MayActAsAnySubject && !caller.Subjects.Contains(subject))
                throw new MintingRefusedException(
                    $"Cannot mint under '{subject}': the caller does not hold it.");
        }

        // Always evaluated against the target subjects alone, unrestricted caller or not: acting for a role means
        // taking that role's grants, not adding one's own to them.
        var grants = await grantStore.GetAllAsync(request.Scope, token);
        var authorityResult = authority.Evaluate(grants, new MintingCaller(subjects), policyCatalog.KnownPermissions);

        var refused = request.Permissions
            .Where(x => !authorityResult.DelegablePermissions.Contains(x))
            .ToArray();

        if (refused.Length > 0)
        {
            var detail = string.Join("; ", refused.Select(x =>
                $"{x} ({Explain(authorityResult.For(x)?.BlockReason ?? PermissionBlockReason.NoActiveGrant)})"));

            throw new MintingRefusedException($"Not permitted to delegate: {detail}.");
        }

        var lifetime = ResolveLifetime(request, authorityResult);
        var nowUtc = _time.GetUtcNow();

        var algorithmId = request.HashAlgorithmId ?? hasher.DefaultAlgorithmId;

        if (!hasher.AlgorithmIds.Contains(algorithmId, StringComparer.Ordinal))
            throw new MintingRefusedException(
                $"Unknown hash algorithm '{algorithmId}'. Known: {string.Join(", ", hasher.AlgorithmIds)}.");

        var plaintext = generator.Generate();

        var key = new MintedKey(
            Id: Guid.NewGuid().ToString("N"),
            Scope: request.Scope,
            KeyHash: hasher.Hash(plaintext, algorithmId),
            HashAlgorithmId: algorithmId,
            Permissions: request.Permissions
                .Distinct(StringComparer.Ordinal)
                .Select(x => Backed(x, grants, subjects))
                .ToArray(),
            MintedUnderSubject: request.MintUnderSubject,
            Label: request.Label.Trim(),
            CreatedUtc: nowUtc,
            ExpiresUtc: lifetime is { } span ? nowUtc + span : null,
            Description: request.Description,
            MintedBy: request.MintedBy,
            MintedByDisplayName: request.MintedByDisplayName)
        {
            Validity = request.Validity,
        };

        await keyStore.AddAsync(key, token);

        _logger.LogInformation(
            "Minted api key {keyId} ({label}) under {subject} by {mintedBy} with {permissionCount} permission(s), expiring {expiresUtc}",
            key.Id, key.Label, request.MintUnderSubject, request.MintedBy ?? "(unknown)", key.Permissions.Count, key.ExpiresUtc);

        return new MintResult(key, plaintext);
    }

    /// <summary>Permanently revokes a key.</summary>
    public async Task RevokeAsync(
        string scope, string keyId, string? revokedBy, string? reason, CancellationToken token = default)
    {
        await keyStore.RevokeAsync(scope, keyId, revokedBy, reason, _time.GetUtcNow(), token);

        _logger.LogInformation("Revoked api key {keyId} by {revokedBy}: {reason}",
            keyId, revokedBy ?? "(unknown)", reason ?? "(no reason given)");
    }

    /// <summary>
    /// The permission with the grant (and so the subject) backing it. Several of the requested subjects may hold a
    /// grant for it; the most generous lifetime wins, as in <see cref="MintingAuthority"/>, then the order the subjects
    /// were given in, so the main subject is preferred.
    /// </summary>
    private static MintedKeyPermission Backed(string permission, IReadOnlyCollection<MintingGrant> grants, SubjectSelector[] subjects)
    {
        var grant = grants
            .Where(x => x.IsActive
                        && string.Equals(x.GrantablePermission, permission, StringComparison.Ordinal)
                        && subjects.Contains(x.Subject))
            .OrderBy(x => x.MaxKeyLifetime is null ? 0 : 1)
            .ThenByDescending(x => x.MaxKeyLifetime)
            .ThenBy(x => Array.IndexOf(subjects, x.Subject))
            .First();

        return new MintedKeyPermission(permission, grant.Id, grant.Subject);
    }

    /// <returns>How long the key lives, or null for a key that never expires.</returns>
    private TimeSpan? ResolveLifetime(MintRequest request, MintingAuthorityResult authorityResult)
    {
        if (request.NeverExpires)
        {
            if (options.AbsoluteMaxKeyLifetime is { } ceiling)
                throw new MintingRefusedException(
                    $"A key with no expiry is not allowed here: keys are capped at {ceiling}.");

            if (!authorityResult.MayMintWithoutExpiry(request.Permissions))
                throw new MintingRefusedException(
                    "A key with no expiry needs every permission on it to be granted without a maximum lifetime.");

            return null;
        }

        var requested = request.RequestedLifetime ?? options.DefaultKeyLifetime;

        if (requested <= TimeSpan.Zero)
            throw new MintingRefusedException("Key lifetime must be positive.");

        var cap = authorityResult.MaxKeyLifetimeFor(request.Permissions) ?? options.AbsoluteMaxKeyLifetime;

        // with no cap at all, any positive lifetime is fine
        if (cap is not { } limit) return requested;

        if (options.AbsoluteMaxKeyLifetime is { } absolute && limit > absolute) limit = absolute;

        if (requested > limit)
            throw new MintingRefusedException(
                $"Requested lifetime {requested} exceeds the maximum {limit} allowed for these permissions.");

        return requested;
    }

    private static string Explain(PermissionBlockReason reason) => reason switch
    {
        PermissionBlockReason.NeverMintable => "never mintable",
        PermissionBlockReason.NoActiveGrant => "no active grant for this subject",
        _ => "not permitted"
    };
}
