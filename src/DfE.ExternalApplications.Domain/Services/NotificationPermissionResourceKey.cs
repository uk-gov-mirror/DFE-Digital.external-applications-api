using System.Security.Claims;
using GovUK.Dfe.CoreLibs.Contracts.ExternalApplications.Enums;

namespace DfE.ExternalApplications.Domain.Services;

/// <summary>
/// Builds and matches Notifications permission resource keys.
/// Keys are tenant-scoped as <c>{tenantId}:{principalId}</c> (e.g. email or app id),
/// with legacy principalId-only keys still accepted.
/// </summary>
public static class NotificationPermissionResourceKey
{
    public static string Create(Guid tenantId, string principalId) =>
        $"{tenantId}:{principalId}";

    /// <summary>
    /// Candidate resource keys to check against permission claims for Notifications only.
    /// </summary>
    public static IEnumerable<string> CandidateKeys(string principalId, Guid? tenantId)
    {
        if (string.IsNullOrWhiteSpace(principalId))
            yield break;

        yield return principalId;

        if (tenantId is null)
            yield break;

        // Avoid double-prefixing when the caller already passed tenantId:principalId
        if (principalId.StartsWith($"{tenantId.Value}:", StringComparison.OrdinalIgnoreCase))
            yield break;

        yield return Create(tenantId.Value, principalId);
    }

    public static bool HasMatchingClaim(
        ClaimsPrincipal user,
        string principalId,
        AccessType accessType,
        Guid? tenantId)
    {
        foreach (var key in CandidateKeys(principalId, tenantId))
        {
            if (PermissionClaimEvaluator.HasPermissionClaim(user, ResourceType.Notifications, key, accessType))
                return true;
        }

        return false;
    }

    public static bool HasMatchingClaim(
        ClaimsPrincipal user,
        string principalId,
        string action,
        Guid? tenantId)
    {
        if (!Enum.TryParse<AccessType>(action, ignoreCase: true, out var accessType))
            return false;

        return HasMatchingClaim(user, principalId, accessType, tenantId);
    }
}
