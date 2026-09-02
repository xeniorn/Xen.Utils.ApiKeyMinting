namespace Util.ApiKeyMinting;

/// <summary>What a caller asked for, in whichever terms suit them.</summary>
public sealed record PermissionResolutionRequest(
    IReadOnlyCollection<string>? PolicyNames = null,
    IReadOnlyCollection<string>? EndpointIds = null,
    IReadOnlyCollection<string>? Permissions = null);

/// <summary>
/// One step of the resolution, kept so the UI can explain the answer rather than just assert it.
/// </summary>
public sealed record ResolutionNote(string Subject, string Message);

/// <param name="RequiredPermissions">Everything the request implies, de-duplicated.</param>
/// <param name="Notes">How each part of the request contributed.</param>
/// <param name="UnknownPolicyNames">Named policies the app does not define. Ignored, not fatal.</param>
/// <param name="UnknownEndpointIds">Named endpoints the app does not expose. Ignored, not fatal.</param>
public sealed record PermissionResolution(
    IReadOnlySet<string> RequiredPermissions,
    IReadOnlyList<ResolutionNote> Notes,
    IReadOnlyList<string> UnknownPolicyNames,
    IReadOnlyList<string> UnknownEndpointIds);

/// <summary>
/// Works out which permissions a caller actually needs, given the endpoints and policies they named.
/// </summary>
public sealed class PermissionResolver(
    IPolicyRequirementCatalog policyCatalog,
    IEndpointPolicyCatalog? endpointCatalog = null)
{
    /// <summary>Expands endpoints to policies, policies to permissions, and unions in anything named directly.</summary>
    public PermissionResolution Resolve(PermissionResolutionRequest request)
    {
        var required = new HashSet<string>(StringComparer.Ordinal);
        var notes = new List<ResolutionNote>();
        var unknownPolicies = new List<string>();
        var unknownEndpoints = new List<string>();

        var policyNames = new HashSet<string>(request.PolicyNames ?? [], StringComparer.Ordinal);

        foreach (var endpointId in request.EndpointIds ?? [])
        {
            var endpoint = endpointCatalog?.Endpoints.FirstOrDefault(x => x.Id == endpointId);

            if (endpoint is null)
            {
                unknownEndpoints.Add(endpointId);
                notes.Add(new ResolutionNote(endpointId, "Unknown endpoint, ignored."));
                continue;
            }

            if (endpoint.PolicyNames.Count == 0)
            {
                notes.Add(new ResolutionNote(endpoint.DisplayName,
                    "Endpoint has no authorization policy attached, so it needs no permission."));
                continue;
            }

            foreach (var policyName in endpoint.PolicyNames)
            {
                policyNames.Add(policyName);
                notes.Add(new ResolutionNote(endpoint.DisplayName, $"Requires policy '{policyName}'."));
            }
        }

        foreach (var policyName in policyNames)
        {
            if (!policyCatalog.TryGetRequirementAlternatives(policyName, out var alternatives))
            {
                unknownPolicies.Add(policyName);
                notes.Add(new ResolutionNote(policyName, "Unknown policy, ignored."));
                continue;
            }

            if (alternatives.Count == 0)
            {
                notes.Add(new ResolutionNote(policyName, "Policy declares no claim requirement, so it needs no permission."));
                continue;
            }

            var chosen = ChooseAlternative(alternatives);

            if (chosen.Count == 0)
            {
                // e.g. an "allow anonymous" policy, modelled as a requirement that requires nothing.
                // Satisfied by everyone, so it contributes nothing - said out loud, because silently
                // resolving to the empty set looks like a bug from the outside.
                notes.Add(new ResolutionNote(policyName, "Policy is satisfied without any permission, so it contributes none."));
                continue;
            }

            required.UnionWith(chosen);

            notes.Add(alternatives.Count == 1
                ? new ResolutionNote(policyName, $"Requires {Join(chosen)}.")
                : new ResolutionNote(policyName,
                    $"Has {alternatives.Count} alternative requirements; picked the smallest, {Join(chosen)}."));
        }

        foreach (var permission in request.Permissions ?? [])
        {
            required.Add(permission);
            notes.Add(new ResolutionNote(permission, "Requested directly."));
        }

        return new PermissionResolution(required, notes, unknownPolicies, unknownEndpoints);
    }

    /// <summary>
    /// Smallest alternative wins; ties are broken by ordinal sort so the same request always resolves the same
    /// way. Deliberately not clever - a caller who wants a different alternative should ask for its permissions
    /// directly rather than have the resolver guess.
    /// </summary>
    private static IReadOnlySet<string> ChooseAlternative(IReadOnlyList<IReadOnlySet<string>> alternatives)
        => alternatives
            .OrderBy(x => x.Count)
            .ThenBy(Join, StringComparer.Ordinal)
            .First();

    private static string Join(IReadOnlySet<string> permissions)
        => string.Join(", ", permissions.OrderBy(x => x, StringComparer.Ordinal));
}
