namespace Util.ApiKeyMinting.Test;

/// <summary>
/// The validity rule, which is the whole security contract: a permission is live only while an active grant still
/// authorises it for the subject the key was minted under. Everything else follows from that.
/// </summary>
public class MintedKeyAuthorizerTests
{
    private const string Scope = "app";
    private const string Hash = "hash";

    private static readonly SubjectSelector BillingRole = new("roles", "Billing");

    private readonly FakeGrantStore _grants = new();
    private readonly FakeKeyStore _keys = new();
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private MintedKeyAuthorizer CreateSut() =>
        new(_keys, _grants, new MintingOptions(), _time);

    private void GivenGrant(string id, string permission, bool isActive = true, SubjectSelector? subject = null)
        => _grants.Grants.Add(new MintingGrant(
            id, Scope, subject ?? BillingRole, permission, MaxKeyLifetime: null, IsActive: isActive));

    private void GivenKey(
        string[] permissions,
        DateTimeOffset? expiresUtc = null,
        DateTimeOffset? revokedUtc = null,
        SubjectSelector? subject = null,
        string? sourceGrantId = "grant-1")
        => _keys.Keys.Add(new MintedKey(
            Id: "key-1",
            Scope: Scope,
            KeyHash: Hash,
            HashAlgorithmId: "test",
            Permissions: permissions.Select(x => new MintedKeyPermission(x, sourceGrantId)).ToArray(),
            MintedUnderSubject: subject ?? BillingRole,
            Label: "test key",
            CreatedUtc: _time.GetUtcNow().AddDays(-1),
            ExpiresUtc: expiresUtc ?? _time.GetUtcNow().AddDays(30),
            RevokedUtc: revokedUtc));

    [Fact]
    public async Task UnknownHash_IsNotFound()
    {
        var result = await CreateSut().AuthorizeAsync(Scope, "nothing-like-this");

        Assert.Equal(MintedKeyStatus.NotFound, result.Status);
        Assert.Empty(result.LivePermissions);
    }

    [Fact]
    public async Task ActiveGrant_MakesThePermissionLive()
    {
        GivenGrant("grant-1", "CanViewBillingInfo");
        GivenKey(["CanViewBillingInfo"]);

        var result = await CreateSut().AuthorizeAsync(Scope, Hash);

        Assert.Equal(MintedKeyStatus.Active, result.Status);
        Assert.Equal(["CanViewBillingInfo"], result.LivePermissions);
    }

    [Fact]
    public async Task ExpiredKey_GrantsNothing()
    {
        GivenGrant("grant-1", "CanViewBillingInfo");
        GivenKey(["CanViewBillingInfo"], expiresUtc: _time.GetUtcNow().AddSeconds(-1));

        var result = await CreateSut().AuthorizeAsync(Scope, Hash);

        Assert.Equal(MintedKeyStatus.Expired, result.Status);
        Assert.Empty(result.LivePermissions);
    }

    [Fact]
    public async Task RevokedKey_GrantsNothing()
    {
        GivenGrant("grant-1", "CanViewBillingInfo");
        GivenKey(["CanViewBillingInfo"], revokedUtc: _time.GetUtcNow().AddHours(-1));

        var result = await CreateSut().AuthorizeAsync(Scope, Hash);

        Assert.Equal(MintedKeyStatus.Revoked, result.Status);
        Assert.Empty(result.LivePermissions);
    }

    [Fact]
    public async Task DeactivatingTheGrant_SuspendsTheKeyWithoutTouchingIt()
    {
        GivenGrant("grant-1", "CanViewBillingInfo");
        GivenKey(["CanViewBillingInfo"]);

        var before = _keys.Keys.Single();

        await _grants.SetActiveAsync(Scope, "grant-1", isActive: false, actor: "someone");
        var result = await CreateSut().AuthorizeAsync(Scope, Hash);

        Assert.Equal(MintedKeyStatus.Suspended, result.Status);
        Assert.Empty(result.LivePermissions);

        // suspension must be non-destructive, or reinstating the grant could not bring the key back
        Assert.Equal(before, _keys.Keys.Single());
        Assert.Null(_keys.Keys.Single().RevokedUtc);
    }

    [Fact]
    public async Task ReactivatingTheGrant_RevivesTheKey()
    {
        GivenGrant("grant-1", "CanViewBillingInfo");
        GivenKey(["CanViewBillingInfo"]);

        await _grants.SetActiveAsync(Scope, "grant-1", isActive: false, actor: null);
        Assert.Equal(MintedKeyStatus.Suspended, (await CreateSut().AuthorizeAsync(Scope, Hash)).Status);

        await _grants.SetActiveAsync(Scope, "grant-1", isActive: true, actor: null);

        var result = await CreateSut().AuthorizeAsync(Scope, Hash);

        Assert.Equal(MintedKeyStatus.Active, result.Status);
        Assert.Equal(["CanViewBillingInfo"], result.LivePermissions);
    }

    /// <summary>
    /// Reinstating a grant may well mean re-creating it, which produces a fresh id. Matching on the id recorded at
    /// mint time would leave the key dead forever; matching on subject and permission is what makes it recoverable.
    /// </summary>
    [Fact]
    public async Task GrantDeletedAndRecreatedWithANewId_RevivesTheKey()
    {
        GivenGrant("grant-1", "CanViewBillingInfo");
        GivenKey(["CanViewBillingInfo"], sourceGrantId: "grant-1");

        _grants.Grants.Clear();
        Assert.Equal(MintedKeyStatus.Suspended, (await CreateSut().AuthorizeAsync(Scope, Hash)).Status);

        GivenGrant("a-completely-different-id", "CanViewBillingInfo");

        var result = await CreateSut().AuthorizeAsync(Scope, Hash);

        Assert.Equal(MintedKeyStatus.Active, result.Status);
        Assert.Equal(["CanViewBillingInfo"], result.LivePermissions);
    }

    [Fact]
    public async Task LosingOneOfTwoGrants_KeepsTheOtherPermissionLive()
    {
        GivenGrant("grant-1", "CanViewBillingInfo");
        GivenGrant("grant-2", "CanReportInstrumentInfo");
        GivenKey(["CanViewBillingInfo", "CanReportInstrumentInfo"]);

        await _grants.SetActiveAsync(Scope, "grant-2", isActive: false, actor: null);

        var result = await CreateSut().AuthorizeAsync(Scope, Hash);

        Assert.Equal(MintedKeyStatus.Active, result.Status);
        Assert.Equal(["CanViewBillingInfo"], result.LivePermissions);
    }

    /// <summary>
    /// A grant for a different role must not keep this key alive, or delegation boundaries would be decorative.
    /// </summary>
    [Fact]
    public async Task GrantForADifferentSubject_DoesNotKeepTheKeyAlive()
    {
        GivenGrant("grant-1", "CanViewBillingInfo", subject: new SubjectSelector("roles", "SomeoneElse"));
        GivenKey(["CanViewBillingInfo"], subject: BillingRole);

        var result = await CreateSut().AuthorizeAsync(Scope, Hash);

        Assert.Equal(MintedKeyStatus.Suspended, result.Status);
    }

    [Fact]
    public async Task LastUsed_IsThrottled()
    {
        GivenGrant("grant-1", "CanViewBillingInfo");
        GivenKey(["CanViewBillingInfo"]);

        var sut = CreateSut();

        await sut.AuthorizeAsync(Scope, Hash);
        await sut.AuthorizeAsync(Scope, Hash);
        await sut.AuthorizeAsync(Scope, Hash);

        Assert.Equal(1, _keys.TouchCount);

        _time.Advance(TimeSpan.FromMinutes(5));
        await sut.AuthorizeAsync(Scope, Hash);

        Assert.Equal(2, _keys.TouchCount);
    }
}

/// <summary>Minimal controllable clock; the framework one is not available on every target here.</summary>
public sealed class FakeTimeProvider(DateTimeOffset nowUtc) : TimeProvider
{
    private DateTimeOffset _nowUtc = nowUtc;

    public override DateTimeOffset GetUtcNow() => _nowUtc;

    public void Advance(TimeSpan by) => _nowUtc += by;
}
