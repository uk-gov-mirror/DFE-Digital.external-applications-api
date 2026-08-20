using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Text;
using Asp.Versioning;
using DfE.ExternalApplications.Api.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DfE.ExternalApplications.Api.Controllers;

[ApiController]
[ApiVersion("1.0")]
[Route("v{version:apiVersion}/diagnostics")]
[ExcludeFromCodeCoverage]
public class DiagnosticsController(
    IHostEnvironment env,
    IConfiguration configuration,
    ILogger<DiagnosticsController> logger) : ControllerBase
{
    [HttpGet]
    [Authorize]
    public IActionResult Get()
    {
        var asm = typeof(Program).Assembly;

        var informationalVersion =
            asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;

        var version = informationalVersion?.Split('+', 2)[0];
        var buildMetadata = informationalVersion?.Contains('+') == true
            ? informationalVersion.Split('+', 2)[1]
            : null;

        return Ok(new
        {
            service = asm.GetName().Name,
            environment = env.EnvironmentName,
            version = version ?? "unknown",
            informationalVersion,
            buildMetadata
        });
    }

    /// <summary>
    /// Dumps in-memory Tenants configuration as TenantConfig SQL (plaintext, no DB write).
    /// Enable with Diagnostics:ExportTenantConfigSqlEnabled=true (or env Diagnostics__ExportTenantConfigSqlEnabled=true).
    /// SQL is written to the container console and returned as text/plain.
    /// </summary>
    [HttpGet("export-tenant-config-sql")]
    [Authorize(Roles = "Admin")]
    public IActionResult ExportTenantConfigSql()
    {
        if (!configuration.GetValue("Diagnostics:ExportTenantConfigSqlEnabled", false))
        {
            return NotFound(new
            {
                message = "Export disabled. Set Diagnostics:ExportTenantConfigSqlEnabled=true to enable."
            });
        }

        var sql = TenantConfigSqlExporter.BuildFromApiConfiguration(configuration);

        logger.LogWarning(
            "TenantConfig SQL export requested. Script length={Length}. Full script follows in console output.",
            sql.Length);

        Console.WriteLine();
        Console.WriteLine("========== BEGIN TenantConfig SQL (API) ==========");
        Console.WriteLine(sql);
        Console.WriteLine("========== END TenantConfig SQL (API) ==========");
        Console.WriteLine();

        return Content(sql, "text/plain", Encoding.UTF8);
    }
}
