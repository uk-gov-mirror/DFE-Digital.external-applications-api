using System.Security.Claims;
using DfE.ExternalApplications.Api.Security.Handlers;
using DfE.ExternalApplications.Domain.Services;
using DfE.ExternalApplications.Domain.Tenancy;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using NSubstitute;
using Xunit;

namespace DfE.ExternalApplications.Api.Tests.Security.Handlers;

public class NotificationsPermissionHandlerTests
{
    private static readonly Guid TestTenantId = Guid.Parse("11111111-1111-4111-8111-111111111111");

    private static NotificationsPermissionHandler CreateHandler(
        IHttpContextAccessor accessor,
        Guid? tenantId = null)
    {
        var tenantAccessor = Substitute.For<ITenantContextAccessor>();
        if (tenantId is not null)
        {
            tenantAccessor.CurrentTenant.Returns(new TenantConfiguration(
                tenantId.Value,
                "Test",
                new ConfigurationBuilder().Build(),
                []));
        }

        return new NotificationsPermissionHandler(accessor, tenantAccessor);
    }

    [Fact]
    public async Task Handle_ShouldSucceed_WithNotificationPermissionForCurrentUser()
    {
        var requirement = new NotificationsPermissionRequirement("Read");
        var httpContext = new DefaultHttpContext();
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(httpContext);
        var userEmail = "user@example.com";
        var claims = new[]
        {
            new Claim(ClaimTypes.Email, userEmail),
            new Claim("permission", $"Notifications:{userEmail}:Read")
        };
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims));
        var context = new AuthorizationHandlerContext([requirement], user, null);
        var handler = CreateHandler(accessor);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task Handle_ShouldSucceed_WithTenantScopedNotificationPermission()
    {
        var requirement = new NotificationsPermissionRequirement("Read");
        var httpContext = new DefaultHttpContext();
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(httpContext);
        var userEmail = "farshad.dashti+lsrp5@education.gov.uk";
        var resourceKey = NotificationPermissionResourceKey.Create(TestTenantId, userEmail);
        var claims = new[]
        {
            new Claim(ClaimTypes.Email, userEmail),
            new Claim("permission", $"Notifications:{resourceKey}:Read")
        };
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims));
        var context = new AuthorizationHandlerContext([requirement], user, null);
        var handler = CreateHandler(accessor, TestTenantId);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task Handle_ShouldSucceed_WithAppIdClaim()
    {
        var requirement = new NotificationsPermissionRequirement("Read");
        var httpContext = new DefaultHttpContext();
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(httpContext);
        var appId = "test-app-id";
        var claims = new[]
        {
            new Claim("appid", appId),
            new Claim("permission", $"Notifications:{appId}:Read")
        };
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims));
        var context = new AuthorizationHandlerContext([requirement], user, null);
        var handler = CreateHandler(accessor);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task Handle_ShouldSucceed_WithAzpClaim()
    {
        var requirement = new NotificationsPermissionRequirement("Write");
        var httpContext = new DefaultHttpContext();
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(httpContext);
        var azp = "test-azp-id";
        var claims = new[]
        {
            new Claim("azp", azp),
            new Claim("permission", $"Notifications:{azp}:Write")
        };
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims));
        var context = new AuthorizationHandlerContext([requirement], user, null);
        var handler = CreateHandler(accessor);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task Handle_ShouldNotSucceed_WithoutValidUserClaim()
    {
        var requirement = new NotificationsPermissionRequirement("Read");
        var httpContext = new DefaultHttpContext();
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(httpContext);
        var claims = new[]
        {
            new Claim("permission", "Notifications:other@example.com:Read")
        };
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims));
        var context = new AuthorizationHandlerContext([requirement], user, null);
        var handler = CreateHandler(accessor);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public async Task Handle_ShouldNotSucceed_WithWrongPermissionAction()
    {
        var requirement = new NotificationsPermissionRequirement("Write");
        var httpContext = new DefaultHttpContext();
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(httpContext);
        var userEmail = "user@example.com";
        var claims = new[]
        {
            new Claim(ClaimTypes.Email, userEmail),
            new Claim("permission", $"Notifications:{userEmail}:Read")
        };
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims));
        var context = new AuthorizationHandlerContext([requirement], user, null);
        var handler = CreateHandler(accessor);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public async Task Handle_ShouldNotSucceed_WithoutAnyUserIdentifier()
    {
        var requirement = new NotificationsPermissionRequirement("Read");
        var httpContext = new DefaultHttpContext();
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(httpContext);
        var claims = new[]
        {
            new Claim("permission", "Notifications:user@example.com:Read")
        };
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims));
        var context = new AuthorizationHandlerContext([requirement], user, null);
        var handler = CreateHandler(accessor);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public async Task Handle_ShouldSucceed_WithUserPermissionAsFallback()
    {
        var requirement = new NotificationsPermissionRequirement("Read");
        var httpContext = new DefaultHttpContext();
        var applicationId = Guid.NewGuid().ToString();
        httpContext.Request.RouteValues["applicationId"] = applicationId;
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(httpContext);
        var userEmail = "user@example.com";
        var claims = new[]
        {
            new Claim(ClaimTypes.Email, userEmail),
            new Claim("permission", $"Notifications:{userEmail}:Read")
        };
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims));
        var context = new AuthorizationHandlerContext([requirement], user, null);
        var handler = CreateHandler(accessor);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Theory]
    [InlineData("Read")]
    [InlineData("Write")]
    [InlineData("Delete")]
    public async Task Handle_ShouldSucceed_WithVariousActionTypes(string action)
    {
        var requirement = new NotificationsPermissionRequirement(action);
        var httpContext = new DefaultHttpContext();
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(httpContext);
        var userEmail = "user@example.com";
        var claims = new[]
        {
            new Claim(ClaimTypes.Email, userEmail),
            new Claim("permission", $"Notifications:{userEmail}:{action}")
        };
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims));
        var context = new AuthorizationHandlerContext([requirement], user, null);
        var handler = CreateHandler(accessor);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }
}
