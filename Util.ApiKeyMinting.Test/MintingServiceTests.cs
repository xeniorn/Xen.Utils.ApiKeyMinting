namespace Util.ApiKeyMinting.Test;

/// <summary>
/// Issuing keys, and refusing to issue the ones a caller is not entitled to.
/// </summary>
public class MintingServiceTests
{
    private const string Scope = "app";

    private static readonly SubjectSelector Billing = new("roles", "Billing");
    private static readonly SubjectSelector Instruments = new("roles", "Instruments");

    private readonly FakeGrantStore _grants = new();
    private readonly FakeKeyStore _keys = new();
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private readonly FakePolicyCatalog _policies = new()
    {
        KnownPermissions = ["CanViewBillingInfo", "CanEditBillingInfo", "HasAdminLikeAccess"]
    };

    private readonly MintingOptions _options = new()
    {
        NeverMintablePermissions = ["HasAdminLikeAccess"],
        DefaultKeyLifetime = TimeSpan.FromDays(30),
        AbsoluteMaxKeyLifetime = TimeSpan.FromDays(365)
    };

    private MintingService CreateSut() => new(
        _keys, _grants, new ReversibleHasher(), new FixedKeyGenerator("ptk_abc123"),
        _policies, new MintingAuthority(_options), _options, _time);

    private void GivenGrant(string permission, SubjectSelector? subject = null, TimeSpan? maxLifetime = null)
        => _grants.Grants.Add(new MintingGrant(
            $"grant-{_grants.Grants.Count}", Scope, subject ?? Billing, permission, maxLifetime, IsActive: true));

    private static MintRequest Request(
        string[] permissions, TimeSpan? lifetime = null, SubjectSelector? subject = null, string label = "reporting key")
        => new(Scope, subject ?? Billing, permissions, label, lifetime, MintedBy: "someone@example.org");

    [Fact]
    public async Task MintingStoresOnlyTheHash_AndReturnsThePlaintextOnce()
    {
        GivenGrant("CanViewBillingInfo");

        var result = await CreateSut().MintAsync(Request(["CanViewBillingInfo"]), [Billing]);

        Assert.Equal("ptk_abc123", result.PlaintextApiKey);
        Assert.Equal(new string("ptk_abc123".Reverse().ToArray()), result.Key.KeyHash);
        Assert.DoesNotContain(_keys.Keys, x => x.KeyHash == result.PlaintextApiKey);
    }

    [Fact]
    public async Task MintedKeyCarriesItsMetadata()
    {
        GivenGrant("CanViewBillingInfo");

        var result = await CreateSut().MintAsync(Request(["CanViewBillingInfo"], TimeSpan.FromDays(10)), [Billing]);

        Assert.Equal("reporting key", result.Key.Label);
        Assert.Equal("someone@example.org", result.Key.MintedBy);
        Assert.Equal(Billing, result.Key.MintedUnderSubject);
        Assert.Equal(_time.GetUtcNow(), result.Key.CreatedUtc);
        Assert.Equal(_time.GetUtcNow().AddDays(10), result.Key.ExpiresUtc);
        Assert.Equal("test-reverse", result.Key.HashAlgorithmId);
        Assert.Equal("grant-0", result.Key.Permissions.Single().SourceGrantId);
    }

    [Fact]
    public async Task PermissionWithoutAGrant_IsRefused()
    {
        GivenGrant("CanViewBillingInfo");

        var error = await Assert.ThrowsAsync<MintingRefusedException>(
            () => CreateSut().MintAsync(Request(["CanEditBillingInfo"]), [Billing]));

        Assert.Contains("CanEditBillingInfo", error.Message);
        Assert.Empty(_keys.Keys);
    }

    [Fact]
    public async Task NeverMintablePermission_IsRefusedEvenWithAGrant()
    {
        GivenGrant("HasAdminLikeAccess");

        var error = await Assert.ThrowsAsync<MintingRefusedException>(
            () => CreateSut().MintAsync(Request(["HasAdminLikeAccess"]), [Billing]));

        Assert.Contains("never mintable", error.Message);
    }

    /// <summary>
    /// Minting under a subject the caller does not hold would let anyone attach their key to any role's grants.
    /// </summary>
    [Fact]
    public async Task MintingUnderASubjectTheCallerDoesNotHold_IsRefused()
    {
        GivenGrant("CanViewBillingInfo", subject: Instruments);

        var error = await Assert.ThrowsAsync<MintingRefusedException>(
            () => CreateSut().MintAsync(Request(["CanViewBillingInfo"], subject: Instruments), [Billing]));

        Assert.Contains("does not hold", error.Message);
    }

    [Fact]
    public async Task LifetimeBeyondTheGrantMaximum_IsRefused()
    {
        GivenGrant("CanViewBillingInfo", maxLifetime: TimeSpan.FromDays(7));

        var error = await Assert.ThrowsAsync<MintingRefusedException>(
            () => CreateSut().MintAsync(Request(["CanViewBillingInfo"], TimeSpan.FromDays(30)), [Billing]));

        Assert.Contains("exceeds the maximum", error.Message);
    }

    [Fact]
    public async Task DefaultLifetimeApplies_WhenNoneIsRequested()
    {
        GivenGrant("CanViewBillingInfo");

        var result = await CreateSut().MintAsync(Request(["CanViewBillingInfo"]), [Billing]);

        Assert.Equal(_time.GetUtcNow() + _options.DefaultKeyLifetime, result.Key.ExpiresUtc);
    }

    [Fact]
    public async Task KeyWithNoPermissions_IsRefused()
    {
        var error = await Assert.ThrowsAsync<MintingRefusedException>(
            () => CreateSut().MintAsync(Request([]), [Billing]));

        Assert.Contains("no permissions", error.Message);
    }

    [Fact]
    public async Task KeyWithoutALabel_IsRefused()
    {
        GivenGrant("CanViewBillingInfo");

        var error = await Assert.ThrowsAsync<MintingRefusedException>(
            () => CreateSut().MintAsync(Request(["CanViewBillingInfo"], label: "  "), [Billing]));

        Assert.Contains("label is required", error.Message);
    }

    [Fact]
    public async Task RevokingStampsWhoAndWhy()
    {
        GivenGrant("CanViewBillingInfo");
        var sut = CreateSut();
        var minted = await sut.MintAsync(Request(["CanViewBillingInfo"]), [Billing]);

        await sut.RevokeAsync(Scope, minted.Key.Id, "admin@example.org", "leaked in a ticket");

        var stored = _keys.Keys.Single();
        Assert.Equal(_time.GetUtcNow(), stored.RevokedUtc);
        Assert.Equal("admin@example.org", stored.RevokedBy);
        Assert.Equal("leaked in a ticket", stored.RevocationReason);
    }

    [Fact]
    public async Task AuthorityShowsBlockedPermissionsRatherThanHidingThem()
    {
        GivenGrant("CanViewBillingInfo");

        var authority = await CreateSut().GetAuthorityAsync(Scope, [Billing]);

        Assert.Equal(["CanViewBillingInfo"], authority.DelegablePermissions);
        Assert.Equal(PermissionBlockReason.NeverMintable, authority.For("HasAdminLikeAccess")!.BlockReason);
        Assert.Equal(PermissionBlockReason.NoActiveGrant, authority.For("CanEditBillingInfo")!.BlockReason);
    }
}
