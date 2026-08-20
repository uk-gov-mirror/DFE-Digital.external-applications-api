using DfE.ExternalApplications.Domain.Services;
using GovUK.Dfe.CoreLibs.Contracts.ExternalApplications.Enums;
using System.Security.Claims;

namespace DfE.ExternalApplications.Domain.Tests.Services;

public class NotificationPermissionResourceKeyTests
{
    private static readonly Guid TenantId = Guid.Parse("11111111-1111-4111-8111-111111111111");

    [Fact]
    public void Create_FormatsTenantScopedKey()
    {
        var key = NotificationPermissionResourceKey.Create(TenantId, "user@example.com");

        Assert.Equal($"{TenantId}:user@example.com", key);
    }

    [Fact]
    public void CandidateKeys_IncludesLegacyAndTenantScoped()
    {
        var keys = NotificationPermissionResourceKey.CandidateKeys("user@example.com", TenantId).ToList();

        Assert.Equal(["user@example.com", $"{TenantId}:user@example.com"], keys);
    }

    [Fact]
    public void CandidateKeys_DoesNotDoublePrefix()
    {
        var alreadyScoped = $"{TenantId}:user@example.com";
        var keys = NotificationPermissionResourceKey.CandidateKeys(alreadyScoped, TenantId).ToList();

        Assert.Equal([alreadyScoped], keys);
    }

    [Fact]
    public void HasMatchingClaim_MatchesTenantScopedClaimUsingEmail()
    {
        var email = "user@example.com";
        var claim = new Claim(
            PermissionClaimEvaluator.PermissionClaimType,
            $"Notifications:{TenantId}:{email}:Read");
        var user = new ClaimsPrincipal(new ClaimsIdentity([claim]));

        Assert.True(NotificationPermissionResourceKey.HasMatchingClaim(
            user, email, AccessType.Read, TenantId));
    }

    [Fact]
    public void HasMatchingClaim_MatchesLegacyEmailClaim()
    {
        var email = "user@example.com";
        var claim = new Claim(
            PermissionClaimEvaluator.PermissionClaimType,
            $"Notifications:{email}:Read");
        var user = new ClaimsPrincipal(new ClaimsIdentity([claim]));

        Assert.True(NotificationPermissionResourceKey.HasMatchingClaim(
            user, email, AccessType.Read, TenantId));
    }
}
