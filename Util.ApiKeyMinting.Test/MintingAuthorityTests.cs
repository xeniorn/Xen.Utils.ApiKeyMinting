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

    private static MintingCaller Caller(params SubjectSelector[] subjects) => new(subjects);

    /// <summary>An administrator: holds nothing in particular, may act for any subject.</summary>
    private static MintingCaller Unrestricted => new([], MayActAsAnySubject: true);

    [Fact]
    public void EveryKnownPermissionIsReturned_SoTheUiCanGreyOutTheRest()
    {
        var result = CreateSut().Evaluate([Grant("g1", Billing, "CanViewBillingInfo")], Caller(Billing), KnownPermissions);

        Assert.Equal(KnownPermissions.OrderBy(x => x, StringComparer.Ordinal),
            result.Permissions.Select(x => x.Permission));

        Assert.Equal(["CanViewBillingInfo"], result.DelegablePermissions);
    }

    [Fact]
    public void PermissionWithoutAGrant_IsBlockedWithAReason()
    {
        var result = CreateSut().Evaluate([Grant("g1", Billing, "CanViewBillingInfo")], Caller(Billing), KnownPermissions);

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
        var result = CreateSut().Evaluate([Grant("g1", Billing, "HasAdminLikeAccess")], Caller(Billing), KnownPermissions);

        var admin = result.For("HasAdminLikeAccess")!;

        Assert.False(admin.IsDelegable);
        Assert.Equal(PermissionBlockReason.NeverMintable, admin.BlockReason);
        Assert.DoesNotContain("HasAdminLikeAccess", result.DelegablePermissions);
    }

    [Fact]
    public void InactiveGrant_DoesNotDelegate()
    {
        var result = CreateSut().Evaluate(
            [Grant("g1", Billing, "CanViewBillingInfo", isActive: false)], Caller(Billing), KnownPermissions);

        Assert.Empty(result.DelegablePermissions);
    }

    [Fact]
    public void GrantForAnotherSubject_DoesNotDelegate()
    {
        var result = CreateSut().Evaluate([Grant("g1", Instruments, "CanReportInstrumentInfo")], Caller(Billing), KnownPermissions);

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
            Caller(Billing, Instruments),
            KnownPermissions);

        Assert.Equal(
            new HashSet<string> { "CanViewBillingInfo", "CanReportInstrumentInfo" },
            result.DelegablePermissions);
    }

    [Fact]
    public void PermissionFromAGrantTheAppNoLongerDeclares_IsStillShown()
    {
        var result = CreateSut().Evaluate([Grant("g1", Billing, "SomeRetiredPermission")], Caller(Billing), KnownPermissions);

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
            Caller(Billing), KnownPermissions);

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
            [Grant("g1", Billing, "CanViewBillingInfo", TimeSpan.FromDays(3650))], Caller(Billing), KnownPermissions);

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
            Caller(Billing), KnownPermissions);

        Assert.Equal(TimeSpan.FromDays(7),
            result.MaxKeyLifetimeFor(["CanViewBillingInfo", "CanEditBillingInfo"]));
    }

    [Fact]
    public void UnrestrictedCaller_DrawsOnGrantsNamingSubjectsItDoesNotHold()
    {
        var result = CreateSut().Evaluate(
            [Grant("g1", Billing, "CanViewBillingInfo"), Grant("g2", Instruments, "CanReportInstrumentInfo")],
            Unrestricted,
            KnownPermissions);

        Assert.Equal(
            ["CanReportInstrumentInfo", "CanViewBillingInfo"],
            result.DelegablePermissions.OrderBy(x => x, StringComparer.Ordinal));
    }

    [Fact]
    public void UnrestrictedCaller_IsOfferedEverySubjectSomeActiveGrantNames()
    {
        var result = CreateSut().Evaluate(
            [
                Grant("g1", Billing, "CanViewBillingInfo"),
                Grant("g2", Instruments, "CanReportInstrumentInfo"),
                Grant("g3", Instruments, "CanViewBillingInfo"),
                Grant("g4", Billing, "CanEditBillingInfo", isActive: false)
            ],
            Unrestricted,
            KnownPermissions);

        Assert.Equal([Billing, Instruments], result.AvailableSubjects);
    }

    [Fact]
    public void UnrestrictedCaller_StillCannotDelegateWhatNoGrantGives()
    {
        var result = CreateSut().Evaluate([Grant("g1", Billing, "CanViewBillingInfo")], Unrestricted, KnownPermissions);

        var blocked = result.For("CanEditBillingInfo")!;

        Assert.False(blocked.IsDelegable);
        Assert.Equal(PermissionBlockReason.NoActiveGrant, blocked.BlockReason);
    }

    [Fact]
    public void UnrestrictedCaller_IsStillHeldToTheDenyList()
    {
        var result = CreateSut().Evaluate([Grant("g1", Billing, "HasAdminLikeAccess")], Unrestricted, KnownPermissions);

        var blocked = result.For("HasAdminLikeAccess")!;

        Assert.False(blocked.IsDelegable);
        Assert.Equal(PermissionBlockReason.NeverMintable, blocked.BlockReason);
    }

    [Fact]
    public void OrdinaryCaller_IsOfferedItsOwnSubjects()
    {
        var result = CreateSut().Evaluate(
            [Grant("g1", Instruments, "CanReportInstrumentInfo")], Caller(Billing), KnownPermissions);

        Assert.Equal([Billing], result.AvailableSubjects);
    }
}
