using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Util.ApiKeyMinting;

/// <param name="Scope">Which application instance the key belongs to.</param>
/// <param name="MintUnderSubject">The caller subject the key hangs off. Its grants decide the key's fate.</param>
/// <param name="Permissions">What the key should carry.</param>
/// <param name="Label">Short name, so the key can be recognised in the list later. Required.</param>
/// <param name="RequestedLifetime">Defaults and caps apply.</param>
/// <param name="Description">What the key is for.</param>
/// <param name="MintedBy">Stable id of the person minting it.</param>
/// <param name="MintedByDisplayName">Their readable name, for the listing.</param>
public sealed record MintRequest(
    string Scope,
    SubjectSelector MintUnderSubject,
    IReadOnlyCollection<string> Permissions,
    string Label,
    TimeSpan? RequestedLifetime = null,
    string? Description = null,
    string? MintedBy = null,
    string? MintedByDisplayName = null);

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
        string scope, IReadOnlyCollection<SubjectSelector> callerSubjects, CancellationToken token = default)
    {
        var grants = await grantStore.GetAllAsync(scope, token);
        return authority.Evaluate(grants, callerSubjects, policyCatalog.KnownPermissions);
    }

    /// <summary>Issues a key, or throws <see cref="MintingRefusedException"/> if the caller may not.</summary>
    public async Task<MintResult> MintAsync(
        MintRequest request, IReadOnlyCollection<SubjectSelector> callerSubjects, CancellationToken token = default)
    {
        if (string.IsNullOrWhiteSpace(request.Label))
            throw new MintingRefusedException("A label is required, so the key can be recognised later.");

        if (request.Permissions.Count == 0)
            throw new MintingRefusedException("A key with no permissions would do nothing.");

        if (!callerSubjects.Contains(request.MintUnderSubject))
            throw new MintingRefusedException(
                $"Cannot mint under '{request.MintUnderSubject}': the caller does not hold it.");

        var authorityResult = await GetAuthorityAsync(request.Scope, [request.MintUnderSubject], token);

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

        var plaintext = generator.Generate();

        var key = new MintedKey(
            Id: Guid.NewGuid().ToString("N"),
            Scope: request.Scope,
            KeyHash: hasher.Hash(plaintext),
            HashAlgorithmId: hasher.AlgorithmId,
            Permissions: request.Permissions
                .Distinct(StringComparer.Ordinal)
                .Select(x => new MintedKeyPermission(x, authorityResult.For(x)?.BackingGrantIds.FirstOrDefault()))
                .ToArray(),
            MintedUnderSubject: request.MintUnderSubject,
            Label: request.Label.Trim(),
            CreatedUtc: nowUtc,
            ExpiresUtc: nowUtc + lifetime,
            Description: request.Description,
            MintedBy: request.MintedBy,
            MintedByDisplayName: request.MintedByDisplayName);

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

    private TimeSpan ResolveLifetime(MintRequest request, MintingAuthorityResult authorityResult)
    {
        var requested = request.RequestedLifetime ?? options.DefaultKeyLifetime;

        if (requested <= TimeSpan.Zero)
            throw new MintingRefusedException("Key lifetime must be positive.");

        var cap = authorityResult.MaxKeyLifetimeFor(request.Permissions) ?? options.AbsoluteMaxKeyLifetime;

        if (cap > options.AbsoluteMaxKeyLifetime) cap = options.AbsoluteMaxKeyLifetime;

        if (requested > cap)
            throw new MintingRefusedException(
                $"Requested lifetime {requested} exceeds the maximum {cap} allowed for these permissions.");

        return requested;
    }

    private static string Explain(PermissionBlockReason reason) => reason switch
    {
        PermissionBlockReason.NeverMintable => "never mintable",
        PermissionBlockReason.NoActiveGrant => "no active grant for this subject",
        _ => "not permitted"
    };
}
