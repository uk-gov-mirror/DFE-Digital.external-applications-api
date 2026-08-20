using GovUK.Dfe.CoreLibs.Contracts.ExternalApplications.Enums;
using DfE.ExternalApplications.Api.Security.Handlers;
using DfE.ExternalApplications.Application.Services;
using DfE.ExternalApplications.Domain.Common;
using DfE.ExternalApplications.Domain.Factories;
using DfE.ExternalApplications.Domain.Services;
using DfE.ExternalApplications.Domain.Tenancy;
using DfE.ExternalApplications.Domain.ValueObjects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using NSubstitute;
using System.Security.Claims;

namespace DfE.ExternalApplications.Application.Tests.Services;

/// <summary>
/// Verifies that newly provisioned standard users can create applications using template write permissions,
/// without requiring legacy Application:Any grants.
/// </summary>
public class StandardUserApplicationCreationAuthorizationTests
{
    private readonly UserFactory _userFactory = new();

    [Fact]
    public void NewStandardUserClaims_ShouldAllowCreateApplicationPolicy()
    {
        var templateId = new TemplateId(Guid.NewGuid());
        var user = _userFactory.CreateStandardUser(
            new UserId(Guid.NewGuid()),
            "New User",
            "new.user@example.com",
            [templateId],
            new UserId(Guid.NewGuid()));

        var principal = CreateClaimsPrincipal(user);
        var requirement = new AnyTemplatePermissionRequirement(AccessType.Write.ToString());
        var context = new AuthorizationHandlerContext([requirement], principal, null);
        var handler = new AnyTemplatePermissionHandler();

        handler.HandleAsync(context).GetAwaiter().GetResult();

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public void NewStandardUserClaims_ShouldAllowDashboardAccessBeforeFirstApplication()
    {
        var templateId = new TemplateId(Guid.NewGuid());
        var user = _userFactory.CreateStandardUser(
            new UserId(Guid.NewGuid()),
            "New User",
            "new.user@example.com",
            [templateId],
            new UserId(Guid.NewGuid()));

        var principal = CreateClaimsPrincipal(user);
        var requirement = new ApplicationListPermissionRequirement(AccessType.Read.ToString());
        var context = new AuthorizationHandlerContext([requirement], principal, null);
        var handler = new ApplicationListPermissionHandler();

        handler.HandleAsync(context).GetAwaiter().GetResult();

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public void NewStandardUserClaims_ShouldAllowTemplateWriteInCreateHandlerCheck()
    {
        var templateId = new TemplateId(Guid.NewGuid());
        var user = _userFactory.CreateStandardUser(
            new UserId(Guid.NewGuid()),
            "New User",
            "new.user@example.com",
            [templateId],
            new UserId(Guid.NewGuid()));

        var principal = CreateClaimsPrincipal(user);
        var httpContext = Substitute.For<HttpContext>();
        httpContext.User.Returns(principal);
        var httpContextAccessor = Substitute.For<IHttpContextAccessor>();
        httpContextAccessor.HttpContext.Returns(httpContext);

        var tenantContextAccessor = Substitute.For<ITenantContextAccessor>();
        var permissionChecker = new ClaimBasedPermissionCheckerService(httpContextAccessor, tenantContextAccessor);
        var canCreate = permissionChecker.HasTemplatePermission(templateId.Value.ToString(), AccessType.Write);

        Assert.True(canCreate);
    }

    private static ClaimsPrincipal CreateClaimsPrincipal(Domain.Entities.User user)
    {
        var permissionValues = user.Permissions
            .Select(p => $"{p.ResourceType}:{p.ResourceKey}:{p.AccessType}")
            .Concat(user.TemplatePermissions.Select(tp => $"Template:{tp.TemplateId.Value}:{tp.AccessType}"))
            .Select(value => new Claim(PermissionClaimEvaluator.PermissionClaimType, value));

        return new ClaimsPrincipal(new ClaimsIdentity(permissionValues, "Test"));
    }
}
