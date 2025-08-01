# Keycloak SSO Authentication Playground

A demonstration repository showcasing Single Sign-On (SSO) authentication between multiple ASP.NET Core MVC applications using Keycloak as the identity provider.

## Overview

This project demonstrates:
- SSO authentication flow between two separate applications
- Role-based authorization with client-specific roles
- Silent authentication for seamless navigation between services
- Proper logout handling across applications

## Architecture

The solution consists of two ASP.NET Core MVC applications:

### 1. MDIGI-I Hub (Port: 7294)
The main portal application that serves as the entry point for users. Features:
- Public landing page
- User dashboard showing JWT claims
- Role-based access pages (Admin-only, Editor-only)
- Service launcher for navigating to other applications

### 2. Certificate Service (Port: 7090)
A specialized service for certificate management. Features:
- Silent authentication when accessed from Hub
- Client-specific roles (cert-admin, cert-issuer)
- Role-based access control for different operations

## Prerequisites

- .NET 8.0 SDK
- Keycloak server (tested with Keycloak 26.3.2)
- Visual Studio 2022 or VS Code
- Docker for running Keycloak


## Keycloak Configuration

### Starting Keycloak

You have two options for running Keycloak:

#### Option 1: Development Mode with H2 Database (Quick Start)

This is the simplest way to get started. Keycloak will use an embedded H2 database (data will be lost when container stops).

```bash
docker run -d \
	--name keycloak-dev-h2 \
	-p 127.0.0.1:8080:8080 \
	-e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
	-e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
	quay.io/keycloak/keycloak:26.3.2 start-dev

```

Access Keycloak at: `http://localhost:8080`
Admin credentials: `admin` / `admin`


#### Option 2: Development mode with PostgreSQL
For a more production-like setup with persistent data. Prerequisites are PosgreSQL Server and cli installed

**Step 1: Create Keycloak Database and Keycloak Database User by using a script**
```bash
.\psql -h localhost -p 5432 -U postgres -f .\scripts\setup_db.sql
```

**Step 2: Start Keycloak with PostgreSQL**
```bash
docker run --name keycloak \
  -p 127.0.0.1:8080:8080 \
  -e KC_DB=postgres \
  -e KC_DB_URL_HOST=host.docker.internal \
  -e KC_DB_URL_PORT=5432 \
  -e KC_DB_URL_DATABASE=keycloak \
  -e KC_DB_USERNAME=keycloak_user \
  -e KC_DB_PASSWORD=keycloak_pass \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.3.2 start-dev
```

### Configure Keycloak
1. Go to the (Keycloak Admin Console)[http://localhost:8080/admin].
2. Log in with the username and password you created earlier. 
	- KC_BOOTSTRAP_ADMIN_USERNAME
	- KC_BOOTSTRAP_ADMIN_PASSWORD

#### 1. Create a Realm, Clients (secrets + ids), Users, Client Roles
Go to Realms, and create to add a realm. Upload "\configs\realm-config.json" file
This creates:
1. a Realm `mdigii`
2. two clients
3. roles per client
3. users with roles assigned for both clients

To limit resource roles we specify scopes per client
1. Mdigii-hub client has full scopes allowed
2. xyz-service should have minimal scopes allowed: "openid", "profile", "email", "web-origins", "address", "phone", "offline_access", "microprofile-jwt"

#### 2. Configure Client Scope
Using Admin Console, Navigate to "Client Scopes"
1. Name: `xyz-roles`
2. Description: `OpenID Connect scope for add user xyz roles to the access token`
3. Type: `Default` => Save
4. Go to `Mappers`
5. Click `Add Predefined Mapper`
6. Search/Select `client roles` => Add
7. Click on the added mapper
8. Edit Client ID and select `xyz-service` => Save
9. Go to `Clients`, Click the `xyz-service` => Go to `Client Scopes` => `Add Client Scope`
10. Add `xyz-roles` as `Default` assigned type.

To verify that it works, on `xyz-service` project under `OnRedirectToIdentityProvider` if you add `roles` under scope you should get the following error
```json
OpenIdConnectProtocolException: 
Message contains error: 'invalid_scope', 
error_description: 'Invalid scopes: openid profile email roles', 
error_uri: 'error_uri is null'.
```

Remove `scopes` and add `xyz-roles`. For example
```c#
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
```

## Application Configuration

### 1. User Secrets

Configure user secrets for both applications using `appsettings.Development.json`:

#### MDIGI-I Hub
```bash
set "IdentityServer:Authority" "http://localhost:8080/realms/mdigii"
set "IdentityServer:ClientId" "mdigii-hub"
set "IdentityServer:ClientSecret" "your-client-secret-here" // This can be found on keycload admin console under client/credentials tab
set "Services:CertificateService:Url" "https://localhost:7067"
```

#### Certificate Service
```bash
set "IdentityServer:Authority" "http://localhost:8080/realms/mdigii"
set "IdentityServer:ClientId" "certificate-service"
set "IdentityServer:ClientSecret" "your-client-secret-here"
```

## Running the Applications

1. Start Keycloak server
2. Open the solution in Visual Studio
3. Run both projects (in https) simultaneously use Visual Studio's multiple startup projects feature.
Note: If you want to run it using http instead you should adjust application configurations and realm import file

## Testing the SSO Flow

1. Navigate to `https://localhost:7294` (MDIGI-I Hub)
2. Click "Login" - you'll be redirected to Keycloak
3. Enter credentials for a test user
4. After successful login, you'll see the dashboard with JWT claims
5. Click "Launch Service" to navigate to Certificate Service
6. Notice the silent authentication - no additional login required
7. Test role-based pages in both applications
8. Logout from either application logs out from both