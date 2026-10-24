using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Util.ApiKeyMinting;

/// <summary>What a presented key is currently worth.</summary>
/// <param name="Status">Why it does or does not work.</param>
/// <param name="Key">The key, when one was found.</param>
/// <param name="LivePermissions">Permissions still backed by an active grant. Empty unless active.</param>
public sealed record MintedKeyAuthorization(
    MintedKeyStatus Status,
    MintedKey? Key,
    IReadOnlySet<string> LivePermissions)
{
    /// <summary>No key matched the presented hash.</summary>
    public static readonly MintedKeyAuthorization NotFound =
        new(MintedKeyStatus.NotFound, null, new HashSet<string>(StringComparer.Ordinal));
}

/// <summary>
/// Answers the only question that matters on the request path: given this key hash, which permissions are live
/// right now?
/// </summary>
/// <remarks>
/// <para>
/// A permission is live only while an active grant still authorises it for the subject it was minted under (the
/// key's subject, or for a key minted under several subjects, the one recorded on the permission).
/// So removing a grant suspends its keys immediately, and reinstating it brings them back - which is why the
/// check matches on <c>(subject, permission)</c> rather than on the grant id recorded at mint time. A grant that
/// is deleted and re-created gets a new id, and the keys must survive that.
/// </para>
/// <para>
/// By default validity follows the rule, never the person. Whoever minted the key may have changed role or left;
/// that has no bearing here, which is why keys are required to expire.
/// </para>
/// <para>
/// A key minted with <see cref="KeyValidity.FollowsMinter"/> additionally needs its minter to still hold the subject
/// backing each permission, as <see cref="IMinterSubjectSource"/> reports it right now. Without a source registered
/// such keys carry nothing: failing closed is the only safe reading of "follows the minter".
/// </para>
/// </remarks>
public sealed class MintedKeyAuthorizer(
    IMintedKeyStore keyStore,
    IMintingGrantStore grantStore,
    MintingOptions options,
    IMinterSubjectSource? minterSubjects,
    TimeProvider? timeProvider = null,
    ILogger<MintedKeyAuthorizer>? logger = null)
{
    /// <summary>The constructor of earlier versions: no minter subject source, so minter-bound keys carry nothing.</summary>
    public MintedKeyAuthorizer(
        IMintedKeyStore keyStore,
        IMintingGrantStore grantStore,
        MintingOptions options,
        TimeProvider? timeProvider = null,
        ILogger<MintedKeyAuthorizer>? logger = null)
        : this(keyStore, grantStore, options, null, timeProvider, logger)
    {
    }

    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly ILogger _logger = logger ?? NullLogger<MintedKeyAuthorizer>.Instance;

    /// <summary>
    /// Resolves the digests of a presented key to the permissions it carries right now.
    /// </summary>
    /// <param name="presented">
    /// One entry per algorithm the host understands, all derived from the same key. The stored key is matched on
    /// algorithm and hash together, so which digest it was written under is its own property.
    /// </param>
    public async Task<MintedKeyAuthorization> AuthorizeAsync(
        string scope, IReadOnlyCollection<PresentedApiKeyDigest> presented, CancellationToken token = default)
    {
        if (presented.Count == 0) return MintedKeyAuthorization.NotFound;

        if (await keyStore.FindByDigestAsync(scope, presented, token) is not { } key)
            return MintedKeyAuthorization.NotFound;

        var nowUtc = _time.GetUtcNow();

        if (key.IsRevoked)
            return new MintedKeyAuthorization(MintedKeyStatus.Revoked, key, Empty);

        if (key.IsExpiredAt(nowUtc))
            return new MintedKeyAuthorization(MintedKeyStatus.Expired, key, Empty);

        var grants = await grantStore.GetAllAsync(scope, token);

        // each permission against the subject it was granted under (a key can span several)
        var stillGranted = grants
            .Where(x => x.IsActive)
            .Select(x => (x.Subject, x.GrantablePermission))
            .ToHashSet();

        var live = key.Permissions
            .Where(x => stillGranted.Contains((key.SubjectOf(x), x.Permission)))
            .Select(x => x.Permission)
            .ToHashSet(StringComparer.Ordinal);

        if (key.Validity == KeyValidity.FollowsMinter && live.Count > 0)
        {
            var minterHolds = await MinterSubjectsAsync(scope, key, token);
            live = key.Permissions
                .Where(x => live.Contains(x.Permission) && minterHolds.Contains(key.SubjectOf(x)))
                .Select(x => x.Permission)
                .ToHashSet(StringComparer.Ordinal);

            if (live.Count == 0)
            {
                _logger.LogInformation(
                    "Api key {keyId} ({label}) follows its minter {mintedBy}, who no longer holds the subjects backing it. " +
                    "It revives if they regain them.",
                    key.Id, key.Label, key.MintedBy);

                return new MintedKeyAuthorization(MintedKeyStatus.Suspended, key, Empty);
            }
        }

        if (live.Count == 0)
        {
            _logger.LogInformation(
                "Api key {keyId} ({label}) carries no live permission: no active grant for {subject}. " +
                "Reinstating the grant restores it.",
                key.Id, key.Label, key.MintedUnderSubject);

            return new MintedKeyAuthorization(MintedKeyStatus.Suspended, key, Empty);
        }

        if (live.Count < key.Permissions.Count)
        {
            _logger.LogInformation(
                "Api key {keyId} ({label}) is partially suspended: {liveCount} of {totalCount} permissions still granted for {subject}",
                key.Id, key.Label, live.Count, key.Permissions.Count, key.MintedUnderSubject);
        }

        await TouchLastUsedAsync(scope, key, nowUtc, token);

        return new MintedKeyAuthorization(MintedKeyStatus.Active, key, live);
    }

    /// <summary>
    /// Throttled, because this sits on the authentication path and every request would otherwise be a write.
    /// Best effort: a failure here must never fail the request the key was presented for.
    /// </summary>
    private async Task TouchLastUsedAsync(string scope, MintedKey key, DateTimeOffset nowUtc, CancellationToken token)
    {
        if (key.LastUsedUtc is { } lastUsed && nowUtc - lastUsed < options.LastUsedWriteThrottle)
            return;

        try
        {
            await keyStore.TouchLastUsedAsync(scope, key.Id, nowUtc, token);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed recording last use of api key {keyId}", key.Id);
        }
    }

    private async Task<IReadOnlySet<SubjectSelector>> MinterSubjectsAsync(string scope, MintedKey key, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(key.MintedBy))
        {
            _logger.LogWarning("Api key {keyId} follows its minter but records none; it carries nothing.", key.Id);
            return new HashSet<SubjectSelector>();
        }

        if (minterSubjects is null)
        {
            _logger.LogWarning(
                "Api key {keyId} follows its minter, but no IMinterSubjectSource is registered; it carries nothing.", key.Id);
            return new HashSet<SubjectSelector>();
        }

        return (await minterSubjects.GetCurrentSubjectsAsync(scope, key.MintedBy, token)).ToHashSet();
    }

    private static IReadOnlySet<string> Empty => new HashSet<string>(StringComparer.Ordinal);
}
