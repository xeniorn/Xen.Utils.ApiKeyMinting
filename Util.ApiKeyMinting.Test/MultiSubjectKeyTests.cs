namespace Util.ApiKeyMinting.Test;

/// <summary>
/// One key for someone holding several roles: each permission records the subject whose grant backs it, and lives or
/// dies with that subject's grant alone.
/// </summary>
public class MultiSubjectKeyTests
{
    private const string Scope = "app";

    private static readonly SubjectSelector Billing = new("roles", "Billing");
    private static readonly SubjectSelector Instruments = new("roles", "Instruments");
    private static readonly SubjectSelector Payroll = new("roles", "Payroll");

    private readonly FakeGrantStore _grants = new();
    private readonly FakeKeyStore _keys = new();
    private readonly ReversibleHasher _hasher = new();
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));
    private readonly FakePolicyCatalog _policies = new() { KnownPermissions = ["CanViewBillingInfo", "CanEditInstruments"] };
    private readonly MintingOptions _options = new() { DefaultKeyLifetime = TimeSpan.FromDays(30), AbsoluteMaxKeyLifetime = TimeSpan.FromDays(365) };

    private MintingService Minting() => new(
        _keys, _grants, _hasher, new FixedKeyGenerator("ptk_multi"), _policies, new MintingAuthority(_options), _options, _time);

    private MintedKeyAuthorizer Authorizer() => new(_keys, _grants, _options, _time);

    private void GivenGrant(string id, SubjectSelector subject, string permission, TimeSpan? maxLifetime = null)
        => _grants.Grants.Add(new MintingGrant(id, Scope, subject, permission, maxLifetime, IsActive: true));

    private static MintRequest Request(string[] permissions, params SubjectSelector[] additional)
        => new(Scope, Billing, permissions, "multi key", MintedBy: "someone@example.org", AdditionalSubjects: additional);

    [Fact]
    public async Task SeveralSubjects_CombineOntoOneKey_EachPermissionRememberingItsSubject()
    {
        GivenGrant("billing-view", Billing, "CanViewBillingInfo");
        GivenGrant("instruments-edit", Instruments, "CanEditInstruments");

        var result = await Minting().MintAsync(
            Request(["CanViewBillingInfo", "CanEditInstruments"], Instruments), new MintingCaller([Billing, Instruments]));

        Assert.Equal(Billing, result.Key.MintedUnderSubject);
        Assert.Equal(
            [new MintedKeyPermission("CanViewBillingInfo", "billing-view", Billing), new MintedKeyPermission("CanEditInstruments", "instruments-edit", Instruments)],
            result.Key.Permissions);
    }

    [Fact]
    public async Task AnAdditionalSubjectTheCallerDoesNotHold_IsRefused()
    {
        GivenGrant("billing-view", Billing, "CanViewBillingInfo");
        GivenGrant("instruments-edit", Instruments, "CanEditInstruments");

        var error = await Assert.ThrowsAsync<MintingRefusedException>(() => Minting().MintAsync(
            Request(["CanViewBillingInfo", "CanEditInstruments"], Instruments), new MintingCaller([Billing])));

        Assert.Contains("roles=Instruments", error.Message);
        Assert.Empty(_keys.Keys);
    }

    [Fact]
    public async Task AdditionalSubjects_GiveNothingTheirGrantsDoNot()
    {
        GivenGrant("billing-view", Billing, "CanViewBillingInfo");

        await Assert.ThrowsAsync<MintingRefusedException>(() => Minting().MintAsync(
            Request(["CanEditInstruments"], Instruments), new MintingCaller([Billing, Instruments])));
    }

    [Fact]
    public async Task APermissionSeveralSubjectsCouldBack_IsBackedByTheMostGenerousGrant()
    {
        GivenGrant("billing-short", Billing, "CanViewBillingInfo", TimeSpan.FromDays(7));
        GivenGrant("payroll-long", Payroll, "CanViewBillingInfo", TimeSpan.FromDays(90));

        var result = await Minting().MintAsync(
            Request(["CanViewBillingInfo"], Payroll) with { RequestedLifetime = TimeSpan.FromDays(60) }, new MintingCaller([Billing, Payroll]));

        Assert.Equal(new MintedKeyPermission("CanViewBillingInfo", "payroll-long", Payroll), result.Key.Permissions.Single());
        Assert.Equal(_time.GetUtcNow().AddDays(60), result.Key.ExpiresUtc);
    }

    [Fact]
    public async Task WithdrawingOneSubjectsGrant_SuspendsOnlyThePermissionsItBacked()
    {
        GivenGrant("billing-view", Billing, "CanViewBillingInfo");
        GivenGrant("instruments-edit", Instruments, "CanEditInstruments");
        await Minting().MintAsync(Request(["CanViewBillingInfo", "CanEditInstruments"], Instruments), new MintingCaller([Billing, Instruments]));

        await _grants.SetActiveAsync(Scope, "instruments-edit", isActive: false, actor: "admin");
        var result = await Authorizer().AuthorizeAsync(Scope, _hasher.DigestsOf("ptk_multi"));

        Assert.Equal(MintedKeyStatus.Active, result.Status);
        Assert.Equal(["CanViewBillingInfo"], result.LivePermissions);
    }

    [Fact]
    public async Task AStoreThatDropsThePermissionSubject_FailsSafe()
    {
        // a store written for the single-subject model does not persist MintedKeyPermission.Subject
        GivenGrant("billing-view", Billing, "CanViewBillingInfo");
        GivenGrant("instruments-edit", Instruments, "CanEditInstruments");
        var minted = await Minting().MintAsync(Request(["CanViewBillingInfo", "CanEditInstruments"], Instruments), new MintingCaller([Billing, Instruments]));
        _keys.Keys[0] = minted.Key with { Permissions = [.. minted.Key.Permissions.Select(x => x with { Subject = null })] };

        var result = await Authorizer().AuthorizeAsync(Scope, _hasher.DigestsOf("ptk_multi"));

        // the instruments permission falls back to the key's subject, which never granted it: lost, not widened
        Assert.Equal(["CanViewBillingInfo"], result.LivePermissions);
    }
}
