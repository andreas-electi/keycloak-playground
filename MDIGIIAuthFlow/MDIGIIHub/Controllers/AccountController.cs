using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MDIGIIHub.Controllers;

public class AccountController : Controller
{
	private readonly IConfiguration _configuration;

	public AccountController(IConfiguration configuration)
	{
		_configuration = configuration;
	}

	[AllowAnonymous]
	public IActionResult AccessDenied() => View();

	[AllowAnonymous]
	public IActionResult Login(string returnUrl = "/")
	{
		return Challenge(new AuthenticationProperties { RedirectUri = returnUrl },
			OpenIdConnectDefaults.AuthenticationScheme);
	}

	public async Task<IActionResult> Logout()
	{
		var idToken = await HttpContext.GetTokenAsync("id_token");

		// Clear the local session
		await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

		// Sign out from OpenID Connect (which will redirect to Keycloak)
		var authProperties = new AuthenticationProperties
		{
			RedirectUri = Url.Action("LogoutComplete", "Account", null, Request.Scheme)
		};

		// If we have an ID token, pass it to the signout for proper Keycloak logout
		if (!string.IsNullOrEmpty(idToken))
		{
			authProperties.Items["id_token_hint"] = idToken;
		}

		return SignOut(authProperties, OpenIdConnectDefaults.AuthenticationScheme);
	}

	public IActionResult LogoutComplete()
	{
		// This action is called after successful logout from Keycloak
		return View();
	}
}