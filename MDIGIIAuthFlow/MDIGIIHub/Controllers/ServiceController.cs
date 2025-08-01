using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MDIGIIHub.Controllers;

[Authorize]
public class ServiceController : Controller
{
	private readonly IConfiguration _configuration;

	public ServiceController(IConfiguration configuration)
	{
		_configuration = configuration;
	}

	public IActionResult LaunchCertificateService()
	{
		var certificateServiceUrl = _configuration["Services:CertificateService:Url"] ?? throw new Exception("Certificate Service Url is missing");

		return Redirect(certificateServiceUrl);
	}
}