namespace Util.ApiKeyMinting.Test;

/// <summary>
/// Keys minted with <see cref="KeyValidity.FollowsMinter"/>: a personal delegation that lives only while its grant is
/// active <em>and</em> its minter still holds the subject behind it.
/// </summary>
public class MinterBoundKeyTests
{
    private const string Scope = "app";
    private const string Hash = "hash";
    private const string Algorithm = "test-reverse";
    private const string Minter = "user-42";

    private static readonly SubjectSelector Maintainer = new("roles", "maintainer@facility:7");
    private static readonly PresentedApiKeyDigest[] Presented = [new(Algorithm, Hash)];

    private readonly FakeGrantStore _grants = new();
    private readonly FakeKeyStore _keys = new();
    private readonly FakeMinterSubjects _minters = new();
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    public MinterBoundKeyTests()
    {
        _grants.Grants.Add(new MintingGrant("grant-1", Scope, Maintainer, "items.edit@facility:7", MaxKeyLifetime: null, IsActive: true));
        _minters.Holds(Minter, Maintainer);
    }

    private MintedKeyAuthorizer Authorizer(IMinterSubjectSource? minters) => new(_keys, _grants, new MintingOptions(), minters, _time);

    private void GivenKey(KeyValidity validity, string? mintedBy = Minter) => _keys.Keys.Add(new MintedKey(
        Id: "key-1",
        Scope: Scope,
        KeyHash: Hash,
        HashAlgorithmId: Algorithm,
        Permissions: [new MintedKeyPermission("items.edit@facility:7", "grant-1")],
        MintedUnderSubject: Maintainer,
        Label: "my script",
        CreatedUtc: _time.GetUtcNow().AddDays(-1),
        ExpiresUtc: _time.GetUtcNow().AddDays(30),
        MintedBy: mintedBy) { Validity = validity });

    [Fact]
    public async Task Lives_while_the_minter_holds_the_subject()
    {
        GivenKey(KeyValidity.FollowsMinter);

        var result = await Authorizer(_minters).AuthorizeAsync(Scope, Presented);

        Assert.Equal(MintedKeyStatus.Active, result.Status);
        Assert.Contains("items.edit@facility:7", result.LivePermissions);
    }

    [Fact]
    public async Task Lapses_when_the_minter_loses_the_subject_and_revives_when_regained()
    {
        GivenKey(KeyValidity.FollowsMinter);
        var authorizer = Authorizer(_minters);

        _minters.Holds(Minter);
        var lost = await authorizer.AuthorizeAsync(Scope, Presented);
        _minters.Holds(Minter, Maintainer);
        var regained = await authorizer.AuthorizeAsync(Scope, Presented);

        Assert.Equal(MintedKeyStatus.Suspended, lost.Status);
        Assert.Empty(lost.LivePermissions);
        Assert.Equal(MintedKeyStatus.Active, regained.Status);
    }

    [Fact]
    public async Task Grant_bound_key_ignores_the_minter()
    {
        GivenKey(KeyValidity.FollowsGrant);
        _minters.Holds(Minter);

        var result = await Authorizer(_minters).AuthorizeAsync(Scope, Presented);

        Assert.Equal(MintedKeyStatus.Active, result.Status);
    }

    [Fact]
    public async Task Still_needs_the_grant()
    {
        GivenKey(KeyValidity.FollowsMinter);
        _grants.Grants.Clear();

        var result = await Authorizer(_minters).AuthorizeAsync(Scope, Presented);

        Assert.Equal(MintedKeyStatus.Suspended, result.Status);
    }

    [Fact]
    public async Task Fails_closed_without_a_minter_subject_source()
    {
        GivenKey(KeyValidity.FollowsMinter);

        var result = await Authorizer(null).AuthorizeAsync(Scope, Presented);

        Assert.Equal(MintedKeyStatus.Suspended, result.Status);
    }

    [Fact]
    public async Task Fails_closed_when_the_key_records_no_minter()
    {
        GivenKey(KeyValidity.FollowsMinter, mintedBy: null);

        var result = await Authorizer(_minters).AuthorizeAsync(Scope, Presented);

        Assert.Equal(MintedKeyStatus.Suspended, result.Status);
    }

    [Fact]
    public async Task Minting_a_minter_bound_key_records_the_mode_and_requires_the_minter()
    {
        var options = new MintingOptions();
        var service = new MintingService(_keys, _grants, new ReversibleHasher(), new FixedKeyGenerator("ptk_personal"),
            new FakePolicyCatalog { KnownPermissions = ["items.edit@facility:7"] }, new MintingAuthority(options), options, _time);
        var caller = new MintingCaller([Maintainer]);
        var request = new MintRequest(Scope, Maintainer, ["items.edit@facility:7"], "my script", MintedBy: Minter) { Validity = KeyValidity.FollowsMinter };

        var minted = await service.MintAsync(request, caller);
        var refused = await Assert.ThrowsAsync<MintingRefusedException>(() => service.MintAsync(request with { MintedBy = null }, caller));

        Assert.Equal(KeyValidity.FollowsMinter, minted.Key.Validity);
        Assert.Contains("MintedBy", refused.Message);
    }

    private sealed class FakeMinterSubjects : IMinterSubjectSource
    {
        private readonly Dictionary<string, SubjectSelector[]> _subjects = [];

        public void Holds(string minter, params SubjectSelector[] subjects) => _subjects[minter] = subjects;

        public Task<IReadOnlyCollection<SubjectSelector>> GetCurrentSubjectsAsync(string scope, string mintedBy, CancellationToken token = default)
            => Task.FromResult<IReadOnlyCollection<SubjectSelector>>(_subjects.GetValueOrDefault(mintedBy) ?? []);
    }
}
