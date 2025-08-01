using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MDIGIIHub.Controllers;

public class HomeController : Controller
{
	[AllowAnonymous]
	// Entry point for public users
	public IActionResult Landing()
	{
		if (User.Identity?.IsAuthenticated ?? false)
		{
			return RedirectToAction("Index");
		}
		return View();
	}

	[Authorize]
	public IActionResult Index()
	{
		// Pass all claims to the view
		ViewBag.Claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList();
		return View();
	}

	[Authorize(Policy = "AdminOnly")]
	public IActionResult AdminOnly()
	{
		ViewBag.Roles = string.Join(", ", User.FindAll("roles").Select(c => c.Value));
		return View();
	}

	[Authorize(Policy = "EditorOnly")]
	public IActionResult EditorOnly()
	{
		ViewBag.Roles = string.Join(", ", User.FindAll("roles").Select(c => c.Value));
		return View();
	}
}