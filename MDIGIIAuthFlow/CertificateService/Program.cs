using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Claims;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Configure logging
builder.Logging.ClearProviders();
builder.Logging.AddDebug();

// Add services
builder.Services.AddControllersWithViews();

// Configurations
string authority = builder.Configuration["IdentityServer:Authority"] ?? throw new Exception("Identity Authority is missing");
string clientId = builder.Configuration["IdentityServer:ClientId"] ?? throw new Exception("Client Id is missing");
string clientSecret = builder.Configuration["IdentityServer:ClientSecret"] ?? throw new Exception("Client Secret is missing");

// Configure authentication
builder.Services
	.AddAuthentication(options =>
	{
		options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
		options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
	})
	.AddCookie(options =>
	{
		options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
		options.SlidingExpiration = true;
		options.AccessDeniedPath = "/Account/AccessDenied";
		options.Cookie.SameSite = SameSiteMode.Lax; // Allow cross-site navigation
	})
	.AddOpenIdConnect(options =>
	{
		options.Authority = authority;
		options.ClientId = clientId;
		options.ClientSecret = clientSecret;

		options.ResponseType = OpenIdConnectResponseType.Code;
		options.SaveTokens = true;
		options.GetClaimsFromUserInfoEndpoint = true;
		options.RequireHttpsMetadata = false; // Only for development

		options.Scope.Clear();
		options.Scope.Add("openid");
		options.Scope.Add("profile");
		options.Scope.Add("email");

		// Configure logout
		options.SignedOutCallbackPath = "/signout-callback-oidc";
		options.RemoteSignOutPath = "/signout-oidc";

		options.Events = new OpenIdConnectEvents
		{
			OnRedirectToIdentityProviderForSignOut = context =>
			{
				// Ensure we redirect to Keycloak's logout endpoint
				var logoutUri = $"{context.Options.Authority}/protocol/openid-connect/logout";

				var postLogoutUri = context.Properties?.RedirectUri;
				var idToken = context.Properties?.Items["id_token_hint"];
				if (!string.IsNullOrEmpty(idToken))
				{
					logoutUri += $"?id_token_hint={idToken}";
					if (!string.IsNullOrEmpty(postLogoutUri))
						logoutUri += $"&post_logout_redirect_uri={Uri.EscapeDataString(postLogoutUri)}";
				}
				else if (!string.IsNullOrEmpty(postLogoutUri))
				{
					logoutUri += $"?post_logout_redirect_uri={Uri.EscapeDataString(postLogoutUri)}";
				}

				context.Response.Redirect(logoutUri);
				context.HandleResponse();

				return Task.CompletedTask;
			},
			OnRemoteFailure = context =>
			{
				// Check if this was a silent authentication attempt
				var isSilentAuth = context.Properties?.Items?.ContainsKey("prompt") == true &&
								  context.Properties.Items["prompt"] == "none";

				if (isSilentAuth && (
					context.Failure?.Message?.Contains("login_required") == true ||
					context.Failure?.Message?.Contains("interaction_required") == true ||
					context.Failure?.Message?.Contains("consent_required") == true))
				{
					// Silent auth failed - redirect to regular login
					var returnUrl = context.Properties?.RedirectUri ?? "/";
					context.Response.Redirect($"/Account/Login?returnUrl={Uri.EscapeDataString(returnUrl)}");
					context.HandleResponse();
					return Task.CompletedTask;
				}

				// For other failures, let the default error handling take over
				return Task.CompletedTask;
			},
			OnTokenValidated = context =>
			{
				// Map Keycloak roles to claims
				var claims = context.Principal?.Claims.ToList() ?? new List<System.Security.Claims.Claim>();

				// Get the access token to extract roles
				var accessToken = context.TokenEndpointResponse?.AccessToken;
				if (!string.IsNullOrEmpty(accessToken))
				{
					var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
					var jsonToken = handler.ReadJwtToken(accessToken);

					// Extract client-specific roles from resource_access
					var clientRoles = jsonToken.Claims
						.Where(c => c.Type == "resource_access" && !string.IsNullOrEmpty(c.Value))
						.Select(c => c.Value)
						.FirstOrDefault();

					if (!string.IsNullOrEmpty(clientRoles))
					{
						try
						{
							var rolesJson = System.Text.Json.JsonDocument.Parse(clientRoles);
							const string serviceType = "certificate-service";
							if (rolesJson.RootElement.TryGetProperty(serviceType, out var serviceElement) &&
								serviceElement.TryGetProperty("roles", out var rolesElement) &&
								rolesElement.ValueKind == JsonValueKind.Array)
							{
								foreach (var role in rolesElement.EnumerateArray())
								{
									var roleValue = role.GetString();
									if (!string.IsNullOrEmpty(roleValue) && role.ValueKind == JsonValueKind.String)
									{
										claims.Add(new System.Security.Claims.Claim("roles", roleValue));
									}
								}
							}
						}
						catch (Exception ex)
						{
							Console.WriteLine($"Error parsing resource_access: {ex.Message}");
						}
					}
				}

				// Check if we have a comma-separated roles claim
				var commaSeparatedRoles = claims.FirstOrDefault(c => c.Type == ClaimTypes.Role && c.Value.Contains(","));
				if (commaSeparatedRoles != null)
				{
					var roleValues = commaSeparatedRoles.Value.Split(',', StringSplitOptions.RemoveEmptyEntries);
					claims.Remove(commaSeparatedRoles);
					foreach (var role in roleValues)
					{
						claims.Add(new System.Security.Claims.Claim("roles", role.Trim()));
					}
				}

				// Add the sub claim for the session token
				var sub = claims.FirstOrDefault(c => c.Type == "sub");
				if (sub != null && !claims.Any(c => c.Type == System.Security.Claims.ClaimTypes.NameIdentifier))
				{
					claims.Add(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, sub.Value));
				}

				var identity = new System.Security.Claims.ClaimsIdentity(claims, context.Principal?.Identity?.AuthenticationType);
				context.Principal = new System.Security.Claims.ClaimsPrincipal(identity);

				return Task.CompletedTask;
			},
			OnRedirectToIdentityProvider = context =>
			{
				// Ensure we request the roles scope
				context.ProtocolMessage.Scope = "openid profile email certificate-roles";

				// For silent authentication (when navigating from Hub)
				if (context.Properties.Items.TryGetValue("prompt", out var prompt))
				{
					context.ProtocolMessage.Prompt = prompt;
				}

				return Task.CompletedTask;
			}
		};

		options.TokenValidationParameters = new()
		{
			NameClaimType = "preferred_username",
			RoleClaimType = "roles"
		};

		options.ClaimActions.Clear();
		options.ClaimActions.MapJsonKey("sub", "sub");
		options.ClaimActions.MapJsonKey("preferred_username", "preferred_username");
		options.ClaimActions.MapJsonKey("email", "email");
		options.ClaimActions.MapJsonKey("roles", "roles");
		options.ClaimActions.MapJsonKey("resource_access", "resource_access");
	});

builder.Services.AddAuthorizationBuilder()
.AddPolicy("IssuerOnly", policy => policy.RequireClaim("roles", "cert-issuer"))
.AddPolicy("AdminOnly", policy => policy.RequireClaim("roles", "cert-admin"))
.AddPolicy("Users", policy => policy.RequireAssertion(context =>
	context.User.HasClaim("roles", "cert-admin") ||
	context.User.HasClaim("roles", "cert-issuer"))
);

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
	app.UseExceptionHandler("/Home/Error");
	app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
	name: "default",
	pattern: "{controller=Home}/{action=Entry}/{id?}");

app.Run();