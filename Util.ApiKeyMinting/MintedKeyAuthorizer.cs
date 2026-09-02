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
/// A permission is live only while an active grant still authorises it for the subject the key was minted under.
/// So removing a grant suspends its keys immediately, and reinstating it brings them back - which is why the
/// check matches on <c>(subject, permission)</c> rather than on the grant id recorded at mint time. A grant that
/// is deleted and re-created gets a new id, and the keys must survive that.
/// </para>
/// <para>
/// Validity follows the rule, never the person. Whoever minted the key may have changed role or left; that has no
/// bearing here, which is why keys are required to expire.
/// </para>
/// </remarks>
public sealed class MintedKeyAuthorizer(
    IMintedKeyStore keyStore,
    IMintingGrantStore grantStore,
    MintingOptions options,
    TimeProvider? timeProvider = null,
    ILogger<MintedKeyAuthorizer>? logger = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly ILogger _logger = logger ?? NullLogger<MintedKeyAuthorizer>.Instance;

    /// <summary>Resolves a presented key hash to the permissions it carries right now.</summary>
    public async Task<MintedKeyAuthorization> AuthorizeAsync(
        string scope, string keyHash, CancellationToken token = default)
    {
        if (await keyStore.FindByHashAsync(scope, keyHash, token) is not { } key)
            return MintedKeyAuthorization.NotFound;

        var nowUtc = _time.GetUtcNow();

        if (key.IsRevoked)
            return new MintedKeyAuthorization(MintedKeyStatus.Revoked, key, Empty);

        if (key.IsExpiredAt(nowUtc))
            return new MintedKeyAuthorization(MintedKeyStatus.Expired, key, Empty);

        var grants = await grantStore.GetAllAsync(scope, token);

        var stillGranted = grants
            .Where(x => x.IsActive && x.Subject == key.MintedUnderSubject)
            .Select(x => x.GrantablePermission)
            .ToHashSet(StringComparer.Ordinal);

        var live = key.Permissions
            .Select(x => x.Permission)
            .Where(stillGranted.Contains)
            .ToHashSet(StringComparer.Ordinal);

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

    private static IReadOnlySet<string> Empty => new HashSet<string>(StringComparer.Ordinal);
}
