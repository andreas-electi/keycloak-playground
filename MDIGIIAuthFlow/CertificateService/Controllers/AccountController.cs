using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CertificateService.Controllers
{
	public class AccountController : Controller
	{
		[AllowAnonymous]
		public IActionResult AccessDenied() => View();

		[AllowAnonymous]
		public IActionResult Login(string returnUrl = "/")
		{
			// Always use standard authentication flow
			return Challenge(new AuthenticationProperties { RedirectUri = returnUrl },
				OpenIdConnectDefaults.AuthenticationScheme);
		}

		[AllowAnonymous]
		public IActionResult SilentLogin(string returnUrl = "/")
		{
			// This endpoint is specifically for silent authentication attempts
			var props = new AuthenticationProperties { RedirectUri = returnUrl };
			props.Items["prompt"] = "none";

			return Challenge(props, OpenIdConnectDefaults.AuthenticationScheme);
		}

		[Authorize]
		public async Task<IActionResult> Logout()
		{
			var idToken = await HttpContext.GetTokenAsync("id_token");

			// Clear the local session
			await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

			// Sign out from OpenID Connect (local logout only)
			var authProperties = new AuthenticationProperties
			{
				RedirectUri = "https://localhost:7294/Account/LogoutComplete"
			};

			// If we have an ID token, pass it to the signout for proper Keycloak logout
			if (!string.IsNullOrEmpty(idToken))
			{
				authProperties.Items["id_token_hint"] = idToken;
			}

			return SignOut(authProperties, OpenIdConnectDefaults.AuthenticationScheme);
		}
	}
}
