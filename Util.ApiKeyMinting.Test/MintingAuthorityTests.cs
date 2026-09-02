namespace Util.ApiKeyMinting.Test;

/// <summary>
/// What a caller may hand out. Pure function of grants and the caller's own subjects.
/// </summary>
public class MintingAuthorityTests
{
    private const string Scope = "app";

    private static readonly SubjectSelector Billing = new("roles", "Billing");
    private static readonly SubjectSelector Instruments = new("roles", "Instruments");

    private static readonly string[] KnownPermissions =
        ["CanViewBillingInfo", "CanEditBillingInfo", "CanReportInstrumentInfo", "HasAdminLikeAccess"];

    private static MintingGrant Grant(
        string id, SubjectSelector subject, string permission, TimeSpan? maxLifetime = null, bool isActive = true)
        => new(id, Scope, subject, permission, maxLifetime, isActive);

    private static MintingAuthority CreateSut(MintingOptions? options = null)
        => new(options ?? new MintingOptions { NeverMintablePermissions = ["HasAdminLikeAccess"] });

    [Fact]
    public void EveryKnownPermissionIsReturned_SoTheUiCanGreyOutTheRest()
    {
        var result = CreateSut().Evaluate([Grant("g1", Billing, "CanViewBillingInfo")], [Billing], KnownPermissions);

        Assert.Equal(KnownPermissions.OrderBy(x => x, StringComparer.Ordinal),
            result.Permissions.Select(x => x.Permission));

        Assert.Equal(["CanViewBillingInfo"], result.DelegablePermissions);
    }

    [Fact]
    public void PermissionWithoutAGrant_IsBlockedWithAReason()
    {
        var result = CreateSut().Evaluate([Grant("g1", Billing, "CanViewBillingInfo")], [Billing], KnownPermissions);

        var blocked = result.For("CanEditBillingInfo")!;

        Assert.False(blocked.IsDelegable);
        Assert.Equal(PermissionBlockReason.NoActiveGrant, blocked.BlockReason);
        Assert.Empty(blocked.BackingGrantIds);
    }

    /// <summary>
    /// The deny list is the only thing standing between "may manage grants" and "is permanently admin", so a grant
    /// that names a never-mintable permission must not work.
    /// </summary>
    [Fact]
    public void NeverMintablePermission_StaysBlockedEvenWithAGrant()
    {
        var result = CreateSut().Evaluate([Grant("g1", Billing, "HasAdminLikeAccess")], [Billing], KnownPermissions);

        var admin = result.For("HasAdminLikeAccess")!;

        Assert.False(admin.IsDelegable);
        Assert.Equal(PermissionBlockReason.NeverMintable, admin.BlockReason);
        Assert.DoesNotContain("HasAdminLikeAccess", result.DelegablePermissions);
    }

    [Fact]
    public void InactiveGrant_DoesNotDelegate()
    {
        var result = CreateSut().Evaluate(
            [Grant("g1", Billing, "CanViewBillingInfo", isActive: false)], [Billing], KnownPermissions);

        Assert.Empty(result.DelegablePermissions);
    }

    [Fact]
    public void GrantForAnotherSubject_DoesNotDelegate()
    {
        var result = CreateSut().Evaluate([Grant("g1", Instruments, "CanReportInstrumentInfo")], [Billing], KnownPermissions);

        Assert.Empty(result.DelegablePermissions);
    }

    /// <summary>
    /// Holding two roles lets a caller combine their permissions onto one key. Deliberate, and worth pinning:
    /// the combined key is more capable than either grant alone.
    /// </summary>
    [Fact]
    public void HoldingTwoSubjects_UnionsTheirGrants()
    {
        var result = CreateSut().Evaluate(
            [Grant("g1", Billing, "CanViewBillingInfo"), Grant("g2", Instruments, "CanReportInstrumentInfo")],
            [Billing, Instruments],
            KnownPermissions);

        Assert.Equal(
            new HashSet<string> { "CanViewBillingInfo", "CanReportInstrumentInfo" },
            result.DelegablePermissions);
    }

    [Fact]
    public void PermissionFromAGrantTheAppNoLongerDeclares_IsStillShown()
    {
        var result = CreateSut().Evaluate([Grant("g1", Billing, "SomeRetiredPermission")], [Billing], KnownPermissions);

        Assert.NotNull(result.For("SomeRetiredPermission"));
        Assert.Contains("SomeRetiredPermission", result.DelegablePermissions);
    }

    [Fact]
    public void TwoGrantsForOnePermission_TakeTheMoreGenerousLifetime()
    {
        var result = CreateSut().Evaluate(
            [
                Grant("g1", Billing, "CanViewBillingInfo", TimeSpan.FromDays(7)),
                Grant("g2", Billing, "CanViewBillingInfo", TimeSpan.FromDays(30))
            ],
            [Billing], KnownPermissions);

        Assert.Equal(TimeSpan.FromDays(30), result.For("CanViewBillingInfo")!.MaxKeyLifetime);
    }

    [Fact]
    public void GrantLifetime_IsStillCappedByTheAbsoluteMaximum()
    {
        var options = new MintingOptions
        {
            NeverMintablePermissions = [],
            AbsoluteMaxKeyLifetime = TimeSpan.FromDays(90)
        };

        var result = CreateSut(options).Evaluate(
            [Grant("g1", Billing, "CanViewBillingInfo", TimeSpan.FromDays(3650))], [Billing], KnownPermissions);

        Assert.Equal(TimeSpan.FromDays(90), result.For("CanViewBillingInfo")!.MaxKeyLifetime);
    }

    /// <summary>
    /// A key is only as long-lived as its most restricted permission, otherwise the tighter grant is pointless.
    /// </summary>
    [Fact]
    public void KeyLifetime_IsTheTightestCapAcrossItsPermissions()
    {
        var result = CreateSut().Evaluate(
            [
                Grant("g1", Billing, "CanViewBillingInfo", TimeSpan.FromDays(30)),
                Grant("g2", Billing, "CanEditBillingInfo", TimeSpan.FromDays(7))
            ],
            [Billing], KnownPermissions);

        Assert.Equal(TimeSpan.FromDays(7),
            result.MaxKeyLifetimeFor(["CanViewBillingInfo", "CanEditBillingInfo"]));
    }
}
