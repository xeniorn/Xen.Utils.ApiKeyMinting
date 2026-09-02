namespace Util.ApiKeyMinting.Test;

/// <summary>
/// In-memory stores. Their existence is itself a check on the design: if the core needed anything a plain list
/// cannot provide, the persistence seam would be leaking.
/// </summary>
public sealed class FakeGrantStore : IMintingGrantStore
{
    public List<MintingGrant> Grants { get; } = [];

    public Task<IReadOnlyList<MintingGrant>> GetAllAsync(string scope, CancellationToken token = default)
        => Task.FromResult<IReadOnlyList<MintingGrant>>(Grants.Where(x => x.Scope == scope).ToArray());

    public Task<MintingGrant?> GetAsync(string scope, string grantId, CancellationToken token = default)
        => Task.FromResult(Grants.FirstOrDefault(x => x.Scope == scope && x.Id == grantId));

    public Task UpsertAsync(MintingGrant grant, CancellationToken token = default)
    {
        Grants.RemoveAll(x => x.Scope == grant.Scope && x.Id == grant.Id);
        Grants.Add(grant);
        return Task.CompletedTask;
    }

    public Task SetActiveAsync(string scope, string grantId, bool isActive, string? actor, CancellationToken token = default)
    {
        var index = Grants.FindIndex(x => x.Scope == scope && x.Id == grantId);
        if (index >= 0) Grants[index] = Grants[index] with { IsActive = isActive, DeactivatedBy = actor };
        return Task.CompletedTask;
    }
}

public sealed class FakeKeyStore : IMintedKeyStore
{
    public List<MintedKey> Keys { get; } = [];
    public int TouchCount { get; private set; }

    public Task<MintedKey?> FindByHashAsync(string scope, string keyHash, CancellationToken token = default)
        => Task.FromResult(Keys.FirstOrDefault(x => x.Scope == scope && x.KeyHash == keyHash));

    public Task<IReadOnlyList<MintedKey>> ListAsync(string scope, bool includeRevoked, CancellationToken token = default)
        => Task.FromResult<IReadOnlyList<MintedKey>>(
            Keys.Where(x => x.Scope == scope && (includeRevoked || !x.IsRevoked)).ToArray());

    public Task AddAsync(MintedKey key, CancellationToken token = default)
    {
        Keys.Add(key);
        return Task.CompletedTask;
    }

    public Task RevokeAsync(string scope, string keyId, string? revokedBy, string? reason, DateTimeOffset revokedUtc,
        CancellationToken token = default)
    {
        var index = Keys.FindIndex(x => x.Scope == scope && x.Id == keyId);
        if (index >= 0)
        {
            Keys[index] = Keys[index] with
            {
                RevokedUtc = revokedUtc, RevokedBy = revokedBy, RevocationReason = reason
            };
        }
        return Task.CompletedTask;
    }

    public Task TouchLastUsedAsync(string scope, string keyId, DateTimeOffset whenUtc, CancellationToken token = default)
    {
        TouchCount++;
        var index = Keys.FindIndex(x => x.Scope == scope && x.Id == keyId);
        if (index >= 0) Keys[index] = Keys[index] with { LastUsedUtc = whenUtc };
        return Task.CompletedTask;
    }
}

/// <summary>Not a hash at all, just something reversible so tests can read the fixtures.</summary>
public sealed class ReversibleHasher : IApiKeyHasher
{
    public string AlgorithmId => "test-reverse";

    public string Hash(string apiKey) => new(apiKey.Reverse().ToArray());
}

public sealed class FixedKeyGenerator(params string[] keys) : IApiKeyGenerator
{
    private int _index;

    public string Generate() => keys[_index++ % keys.Length];
}

public sealed class FakePolicyCatalog : IPolicyRequirementCatalog
{
    public Dictionary<string, IReadOnlyList<IReadOnlySet<string>>> Policies { get; } = new(StringComparer.Ordinal);

    public IReadOnlyCollection<string> KnownPolicyNames => Policies.Keys;

    public IReadOnlyCollection<string> KnownPermissions { get; set; } = [];

    public bool TryGetRequirementAlternatives(string policyName, out IReadOnlyList<IReadOnlySet<string>> alternatives)
        => Policies.TryGetValue(policyName, out alternatives!);

    public FakePolicyCatalog WithPolicy(string name, params string[][] alternatives)
    {
        Policies[name] = alternatives
            .Select(x => (IReadOnlySet<string>)x.ToHashSet(StringComparer.Ordinal))
            .ToArray();
        return this;
    }
}

public sealed class FakeEndpointCatalog(params MintableEndpoint[] endpoints) : IEndpointPolicyCatalog
{
    public IReadOnlyCollection<MintableEndpoint> Endpoints { get; } = endpoints;
}
