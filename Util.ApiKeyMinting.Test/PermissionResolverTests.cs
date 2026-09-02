namespace Util.ApiKeyMinting.Test;

/// <summary>
/// Turning what a caller asked for into the permissions they actually need.
/// </summary>
public class PermissionResolverTests
{
    private readonly FakePolicyCatalog _policies = new FakePolicyCatalog()
        .WithPolicy("CanViewBillingInfo", ["CanViewBillingInfo"])
        .WithPolicy("CanEditBillingInfo", ["CanEditBillingInfo"])
        // AllowAnonymous as this app models it: one alternative, containing no claims at all
        .WithPolicy("AllowAnonymous", Array.Empty<string>())
        // and the other shape, a policy declaring no alternatives whatsoever
        .WithPolicy("NoRequirementDeclared")
        .WithPolicy("EitherWillDo", ["A", "B", "C"], ["D"]);

    private PermissionResolver CreateSut(IEndpointPolicyCatalog? endpoints = null)
        => new(_policies, endpoints);

    [Fact]
    public void PolicyResolvesToItsPermission()
    {
        var result = CreateSut().Resolve(new PermissionResolutionRequest(PolicyNames: ["CanViewBillingInfo"]));

        Assert.Equal(["CanViewBillingInfo"], result.RequiredPermissions);
    }

    /// <summary>
    /// A policy that requires nothing is satisfied by everyone. Resolving it to the empty set is correct but looks
    /// like a bug from outside, so the resolver has to say why.
    /// </summary>
    [Fact]
    public void PolicyRequiringNothing_ContributesNothingAndSaysSo()
    {
        var result = CreateSut().Resolve(new PermissionResolutionRequest(PolicyNames: ["AllowAnonymous"]));

        Assert.Empty(result.RequiredPermissions);
        Assert.Contains(result.Notes, x => x.Subject == "AllowAnonymous" && x.Message.Contains("without any permission"));
    }

    [Fact]
    public void PolicyDeclaringNoAlternatives_AlsoContributesNothing()
    {
        var result = CreateSut().Resolve(new PermissionResolutionRequest(PolicyNames: ["NoRequirementDeclared"]));

        Assert.Empty(result.RequiredPermissions);
        Assert.DoesNotContain("NoRequirementDeclared", result.UnknownPolicyNames);
        Assert.Contains(result.Notes, x => x.Subject == "NoRequirementDeclared" && x.Message.Contains("no claim requirement"));
    }

    [Fact]
    public void MultipleAlternatives_PickTheSmallestAndReportIt()
    {
        var result = CreateSut().Resolve(new PermissionResolutionRequest(PolicyNames: ["EitherWillDo"]));

        Assert.Equal(["D"], result.RequiredPermissions);
        Assert.Contains(result.Notes, x => x.Message.Contains("2 alternative"));
    }

    [Fact]
    public void ResolutionIsDeterministic()
    {
        var catalog = new FakePolicyCatalog().WithPolicy("TwoOfTheSameSize", ["B"], ["A"]);

        var first = new PermissionResolver(catalog).Resolve(new PermissionResolutionRequest(PolicyNames: ["TwoOfTheSameSize"]));
        var second = new PermissionResolver(catalog).Resolve(new PermissionResolutionRequest(PolicyNames: ["TwoOfTheSameSize"]));

        Assert.Equal(["A"], first.RequiredPermissions);
        Assert.Equal(first.RequiredPermissions, second.RequiredPermissions);
    }

    [Fact]
    public void EndpointsExpandToTheirPolicies()
    {
        var endpoints = new FakeEndpointCatalog(
            new MintableEndpoint("billing", "Billing report", "GET", "/datacube/GetByQueryV2", ["CanViewBillingInfo"]));

        var result = CreateSut(endpoints).Resolve(new PermissionResolutionRequest(EndpointIds: ["billing"]));

        Assert.Equal(["CanViewBillingInfo"], result.RequiredPermissions);
    }

    [Fact]
    public void EndpointWithNoPolicy_NeedsNoPermission()
    {
        var endpoints = new FakeEndpointCatalog(
            new MintableEndpoint("open", "Open endpoint", "GET", "/public", []));

        var result = CreateSut(endpoints).Resolve(new PermissionResolutionRequest(EndpointIds: ["open"]));

        Assert.Empty(result.RequiredPermissions);
        Assert.Contains(result.Notes, x => x.Message.Contains("no authorization policy"));
    }

    [Fact]
    public void EndpointAndPolicyRequestedTogether_DeDuplicate()
    {
        var endpoints = new FakeEndpointCatalog(
            new MintableEndpoint("billing", "Billing report", "GET", "/datacube/GetByQueryV2", ["CanViewBillingInfo"]));

        var result = CreateSut(endpoints).Resolve(new PermissionResolutionRequest(
            PolicyNames: ["CanViewBillingInfo"],
            EndpointIds: ["billing"]));

        Assert.Equal(["CanViewBillingInfo"], result.RequiredPermissions);
    }

    [Fact]
    public void UnknownNames_AreReportedRatherThanThrown()
    {
        var result = CreateSut().Resolve(new PermissionResolutionRequest(
            PolicyNames: ["NoSuchPolicy"],
            EndpointIds: ["NoSuchEndpoint"]));

        Assert.Equal(["NoSuchPolicy"], result.UnknownPolicyNames);
        Assert.Equal(["NoSuchEndpoint"], result.UnknownEndpointIds);
        Assert.Empty(result.RequiredPermissions);
    }

    [Fact]
    public void PermissionsCanBeRequestedDirectly()
    {
        var result = CreateSut().Resolve(new PermissionResolutionRequest(Permissions: ["CanViewBillingInfo"]));

        Assert.Equal(["CanViewBillingInfo"], result.RequiredPermissions);
    }
}
