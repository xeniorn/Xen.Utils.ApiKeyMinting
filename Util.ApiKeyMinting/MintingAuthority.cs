namespace Util.ApiKeyMinting;

/// <summary>
/// One permission, and whether this caller may hand it out.
/// </summary>
/// <param name="Permission">The app-internal permission name.</param>
/// <param name="IsDelegable">Whether this caller may put it on a key.</param>
/// <param name="BlockReason">Why not, when they may not.</param>
/// <param name="BackingGrantIds">Grants that make it delegable; empty when it is not.</param>
/// <param name="MaxKeyLifetime">
/// Shortest lifetime any backing grant allows, already capped by <see cref="MintingOptions.AbsoluteMaxKeyLifetime"/>.
/// </param>
public sealed record PermissionAvailability(
    string Permission,
    bool IsDelegable,
    PermissionBlockReason BlockReason,
    IReadOnlyList<string> BackingGrantIds,
    TimeSpan? MaxKeyLifetime);

/// <summary>
/// Every permission the app knows about, annotated for one caller.
/// </summary>
/// <remarks>
/// Deliberately the full set rather than just the allowed subset: the UI shows everything and greys out what the
/// caller cannot delegate, so people can see what exists and go ask for it instead of wondering.
/// </remarks>
public sealed record MintingAuthorityResult(IReadOnlyList<PermissionAvailability> Permissions)
{
    /// <summary>Just the permissions this caller may hand out.</summary>
    public IReadOnlySet<string> DelegablePermissions { get; } = Permissions
        .Where(x => x.IsDelegable)
        .Select(x => x.Permission)
        .ToHashSet(StringComparer.Ordinal);

    /// <summary>The annotation for one permission, or null if it is not among the known ones.</summary>
    public PermissionAvailability? For(string permission)
        => Permissions.FirstOrDefault(x => string.Equals(x.Permission, permission, StringComparison.Ordinal));

    /// <summary>
    /// The longest lifetime a key carrying all of <paramref name="permissions"/> may have: the tightest cap
    /// across them, since the key is only as delegable as its most restricted permission.
    /// </summary>
    public TimeSpan? MaxKeyLifetimeFor(IEnumerable<string> permissions)
    {
        TimeSpan? tightest = null;

        foreach (var permission in permissions)
        {
            if (For(permission)?.MaxKeyLifetime is not { } lifetime) continue;
            if (tightest is null || lifetime < tightest) tightest = lifetime;
        }

        return tightest;
    }
}

/// <summary>
/// Decides what a caller may delegate, from the grants and the caller's own subjects. Pure function of its
/// inputs - no clock, no storage, no ambient state.
/// </summary>
public sealed class MintingAuthority(MintingOptions options)
{
    /// <summary>Annotates every known permission for a caller holding <paramref name="callerSubjects"/>.</summary>
    public MintingAuthorityResult Evaluate(
        IReadOnlyCollection<MintingGrant> grants,
        IReadOnlyCollection<SubjectSelector> callerSubjects,
        IReadOnlyCollection<string> knownPermissions)
    {
        var neverMintable = options.NeverMintablePermissions.ToHashSet(StringComparer.Ordinal);
        var subjects = callerSubjects.ToHashSet();

        var applicable = grants
            .Where(x => x.IsActive && subjects.Contains(x.Subject))
            .ToArray();

        // a permission the caller can delegate but that the app does not (yet) declare is still worth showing,
        // otherwise a stale grant becomes invisible
        var allPermissions = knownPermissions
            .Concat(applicable.Select(x => x.GrantablePermission))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToArray();

        var availabilities = allPermissions
            .Select(permission =>
            {
                if (neverMintable.Contains(permission))
                {
                    return new PermissionAvailability(permission, false, PermissionBlockReason.NeverMintable, [], null);
                }

                var backing = applicable
                    .Where(x => string.Equals(x.GrantablePermission, permission, StringComparison.Ordinal))
                    .ToArray();

                if (backing.Length == 0)
                {
                    return new PermissionAvailability(permission, false, PermissionBlockReason.NoActiveGrant, [], null);
                }

                return new PermissionAvailability(
                    permission,
                    true,
                    PermissionBlockReason.None,
                    backing.Select(x => x.Id).ToArray(),
                    BestLifetime(backing));
            })
            .ToArray();

        return new MintingAuthorityResult(availabilities);
    }

    /// <summary>
    /// Several grants may cover the same permission; the caller gets the most generous of them, then the global
    /// ceiling. A grant with no stated maximum means "up to the ceiling".
    /// </summary>
    private TimeSpan BestLifetime(IReadOnlyCollection<MintingGrant> backing)
    {
        var mostGenerous = backing.Any(x => x.MaxKeyLifetime is null)
            ? options.AbsoluteMaxKeyLifetime
            : backing.Max(x => x.MaxKeyLifetime!.Value);

        return mostGenerous < options.AbsoluteMaxKeyLifetime
            ? mostGenerous
            : options.AbsoluteMaxKeyLifetime;
    }
}
