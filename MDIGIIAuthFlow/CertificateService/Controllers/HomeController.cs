using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CertificateService.Controllers;

public class HomeController : Controller
{

	public HomeController() { }

	[AllowAnonymous]
	public IActionResult Entry()
	{
		// Entry point for users coming from Hub
		if (User.Identity?.IsAuthenticated ?? false)
		{
			return RedirectToAction("Index");
		}

		// Try silent authentication first
		return RedirectToAction("SilentLogin", "Account", new { returnUrl = "/" });
	}

	[Authorize(Policy = "Users")]
	public IActionResult Index()
	{
		if (!User.Identity?.IsAuthenticated ?? true)
		{
			return Redirect("/Account/AccessDenied");
		}

		ViewBag.Claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList();

		return View();
	}

	[Authorize(Policy = "IssuerOnly")]
	public IActionResult IssuerOnly()
	{
		ViewBag.Roles = string.Join(", ", User.FindAll("roles").Select(c => c.Value));
		return View();
	}

	[Authorize(Policy = "Users")]
	public IActionResult AdminAndIssuer()
	{
		ViewBag.Roles = string.Join(", ", User.FindAll("roles").Select(c => c.Value));
		return View();
	}
	
	[Authorize(Policy = "AdminOnly")]
	public IActionResult AdminOnly()
	{
		ViewBag.Roles = string.Join(", ", User.FindAll("roles").Select(c => c.Value));
		return View();
	}
}