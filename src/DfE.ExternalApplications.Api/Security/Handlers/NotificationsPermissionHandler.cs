using DfE.ExternalApplications.Domain.Services;
using DfE.ExternalApplications.Domain.Tenancy;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Claims;
using GovUK.Dfe.CoreLibs.Contracts.ExternalApplications.Enums;

namespace DfE.ExternalApplications.Api.Security.Handlers
{
    /// <summary>
    /// Authorization handler that checks notifications permission claims for a specific user resource.
    /// Resource keys are tenant-scoped (<c>{tenantId}:{email}</c>) with legacy email-only keys still accepted.
    /// </summary>
    /// <remarks>
    /// Registered as a singleton. Tenant context is resolved from the current request scope
    /// via <see cref="HttpContext.RequestServices"/> (not constructor-injected).
    /// </remarks>
    public sealed class NotificationsPermissionHandler(IHttpContextAccessor accessor)
        : AuthorizationHandler<NotificationsPermissionRequirement>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            NotificationsPermissionRequirement requirement)
        {
            if (PermissionClaimEvaluator.HasFullAdminAccess(context.User))
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            var httpContext = accessor.HttpContext;
            var resourceKey = httpContext?.Request.RouteValues["email"]?.ToString();

            if (string.IsNullOrWhiteSpace(resourceKey))
                resourceKey = context.User.FindFirstValue(ClaimTypes.Email);

            if (string.IsNullOrWhiteSpace(resourceKey))
                resourceKey = context.User.FindFirst("appid")?.Value
                              ?? context.User.FindFirst("azp")?.Value;

            if (string.IsNullOrWhiteSpace(resourceKey))
                return Task.CompletedTask;

            var tenantId = httpContext?.RequestServices?
                .GetService<ITenantContextAccessor>()
                ?.CurrentTenant
                ?.Id;

            if (NotificationPermissionResourceKey.HasMatchingClaim(
                    context.User,
                    resourceKey,
                    requirement.Action,
                    tenantId))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
