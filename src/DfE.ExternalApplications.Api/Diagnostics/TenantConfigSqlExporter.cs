using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;

namespace DfE.ExternalApplications.Api.Diagnostics;

/// <summary>
/// Builds plaintext TenantConfig SQL INSERT scripts from the running API's in-memory Tenants configuration.
/// Does not connect to TenantConfig and does not encrypt secrets.
/// </summary>
public static class TenantConfigSqlExporter
{
    private static readonly HashSet<string> SkipKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "Web", "Hostnames", "Frontend"
    };

    private static readonly HashSet<string> SecretCategories = new(StringComparer.OrdinalIgnoreCase)
    {
        "ConnectionStrings",
        "AzureAd",
        "InternalServiceAuth",
        "Email",
        "DfESignIn",
        "EntraSso",
        "FileStorage",
        "NotificationService",
        "Authorization"
    };

    public static string BuildFromApiConfiguration(IConfiguration configuration)
    {
        var tenantsSection = configuration.GetSection("Tenants");
        if (!tenantsSection.Exists() || !tenantsSection.GetChildren().Any())
        {
            return "-- No Tenants section found in in-memory configuration.";
        }

        var sb = new StringBuilder();
        sb.AppendLine("-- Generated from external-applications-api in-memory configuration");
        sb.AppendLine($"-- GeneratedAtUtc: {DateTime.UtcNow:O}");
        sb.AppendLine("-- Target: Api (plus nested Web sections when present)");
        sb.AppendLine("-- Secrets are PLAINTEXT; encrypt manually before/after import as needed.");
        sb.AppendLine("SET NOCOUNT ON;");
        sb.AppendLine();

        foreach (var tenantSection in tenantsSection.GetChildren())
        {
            AppendTenant(sb, tenantSection, defaultTarget: "Api");
        }

        return sb.ToString();
    }

    private static void AppendTenant(StringBuilder sb, IConfigurationSection tenantSection, string defaultTarget)
    {
        var tenantIdStr = tenantSection["Id"];
        var tenantName = tenantSection["Name"] ?? tenantSection.Key;

        if (string.IsNullOrWhiteSpace(tenantIdStr) || !Guid.TryParse(tenantIdStr, out var tenantId))
        {
            sb.AppendLine($"-- Skipping tenant '{tenantSection.Key}': missing or invalid Id");
            sb.AppendLine();
            return;
        }

        sb.AppendLine($"-- ===== Tenant: {EscapeSqlComment(tenantName)} ({tenantId}) =====");
        sb.AppendLine($"""
            IF NOT EXISTS (SELECT 1 FROM tenantconfig.Tenants WHERE Id = '{tenantId}')
            BEGIN
              INSERT INTO tenantconfig.Tenants (Id, Name, IsActive, CreatedAtUtc, UpdatedAtUtc)
              VALUES ('{tenantId}', N'{EscapeSql(tenantName)}', 1, SYSUTCDATETIME(), SYSUTCDATETIME());
            END
            """);
        sb.AppendLine();

        foreach (var origin in ResolveOrigins(tenantSection))
        {
            sb.AppendLine($"""
                IF NOT EXISTS (
                  SELECT 1 FROM tenantconfig.TenantFrontendOrigins
                  WHERE TenantId = '{tenantId}' AND Origin = N'{EscapeSql(origin)}')
                BEGIN
                  INSERT INTO tenantconfig.TenantFrontendOrigins (Id, TenantId, Origin)
                  VALUES (NEWID(), '{tenantId}', N'{EscapeSql(origin)}');
                END
                """);
            sb.AppendLine();
        }

        foreach (var hostname in ResolveHostnames(tenantSection))
        {
            sb.AppendLine($"""
                IF NOT EXISTS (
                  SELECT 1 FROM tenantconfig.TenantHostnames
                  WHERE TenantId = '{tenantId}' AND Hostname = N'{EscapeSql(hostname)}')
                BEGIN
                  INSERT INTO tenantconfig.TenantHostnames (Id, TenantId, Hostname)
                  VALUES (NEWID(), '{tenantId}', N'{EscapeSql(hostname)}');
                END
                """);
            sb.AppendLine();
        }

        foreach (var categorySection in tenantSection.GetChildren())
        {
            if (SkipKeys.Contains(categorySection.Key))
                continue;

            AppendSetting(sb, tenantId, categorySection.Key, defaultTarget, categorySection);
        }

        var webSection = tenantSection.GetSection("Web");
        if (webSection.Exists())
        {
            foreach (var webCategory in webSection.GetChildren())
            {
                AppendSetting(sb, tenantId, webCategory.Key, "Web", webCategory);
            }
        }

        sb.AppendLine();
    }

    private static void AppendSetting(
        StringBuilder sb,
        Guid tenantId,
        string category,
        string target,
        IConfigurationSection section)
    {
        if (category.Length > 50)
        {
            sb.AppendLine($"-- Skipping category '{EscapeSqlComment(category)}': name longer than 50 chars");
            return;
        }

        var json = SerializeSectionToJson(section);
        if (string.IsNullOrWhiteSpace(json) || json == "{}" || json == "null")
            return;

        var isSecret = SecretCategories.Contains(category) ? 1 : 0;

        sb.AppendLine($"""
            MERGE tenantconfig.TenantSettings AS t
            USING (SELECT
              '{tenantId}' AS TenantId,
              N'{EscapeSql(category)}' AS Category,
              N'{EscapeSql(target)}' AS Target,
              N'{EscapeSql(json)}' AS Settings,
              CAST({isSecret} AS bit) AS IsSecret) AS s
            ON t.TenantId = s.TenantId AND t.Category = s.Category AND t.Target = s.Target
            WHEN MATCHED THEN
              UPDATE SET Settings = s.Settings, IsSecret = s.IsSecret, UpdatedAtUtc = SYSUTCDATETIME()
            WHEN NOT MATCHED THEN
              INSERT (Id, TenantId, Category, Target, Settings, IsSecret, CreatedAtUtc, UpdatedAtUtc)
              VALUES (NEWID(), s.TenantId, s.Category, s.Target, s.Settings, s.IsSecret, SYSUTCDATETIME(), SYSUTCDATETIME());
            """);
        sb.AppendLine();
    }

    private static IEnumerable<string> ResolveOrigins(IConfigurationSection tenantSection)
    {
        var origins = new List<string>();

        var configured = tenantSection.GetSection("Frontend:Origins").Get<string[]>();
        if (configured is { Length: > 0 })
            origins.AddRange(configured.Where(o => !string.IsNullOrWhiteSpace(o)));

        var single = tenantSection["Frontend:Origin"];
        if (!string.IsNullOrWhiteSpace(single))
            origins.Add(single);

        var baseUrl = tenantSection["FrontendSettings:BaseUrl"];
        if (!string.IsNullOrWhiteSpace(baseUrl))
            origins.Add(baseUrl.TrimEnd('/'));

        return origins
            .Select(o => o.Trim().TrimEnd('/'))
            .Where(o => !string.IsNullOrWhiteSpace(o))
            .Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> ResolveHostnames(IConfigurationSection tenantSection)
    {
        var hostnames = tenantSection.GetSection("Hostnames").Get<string[]>() ?? [];
        return hostnames
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Select(h => h.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private static string SerializeSectionToJson(IConfigurationSection section)
    {
        var value = BuildValue(section);
        return JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = false });
    }

    private static object? BuildValue(IConfigurationSection section)
    {
        var children = section.GetChildren().ToList();
        if (children.Count == 0)
            return section.Value;

        if (children.All(c => int.TryParse(c.Key, out _)))
        {
            return children
                .OrderBy(c => int.Parse(c.Key))
                .Select(BuildValue)
                .ToList();
        }

        var dict = new Dictionary<string, object?>();
        foreach (var child in children)
            dict[child.Key] = BuildValue(child);
        return dict;
    }

    private static string EscapeSql(string value) => value.Replace("'", "''", StringComparison.Ordinal);

    private static string EscapeSqlComment(string value) =>
        value.Replace("\r", " ", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);
}
