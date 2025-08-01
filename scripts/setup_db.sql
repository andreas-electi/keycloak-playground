-- Create databases
CREATE DATABASE keycloak;

-- Create users
CREATE USER keycloak_user WITH PASSWORD 'keycloak_pass';

-----------------------------------------------------------------
-- Revoke default public permissions
REVOKE ALL ON DATABASE keycloak FROM PUBLIC;

-----------------------------------------------------------------
-- Setup keycloak
\c keycloak
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Database level privileges
GRANT CONNECT, CREATE, TEMPORARY ON DATABASE keycloak TO keycloak_user;

-- Schema level privileges for existing and future schemas
GRANT CREATE ON DATABASE keycloak TO keycloak_user;
GRANT USAGE, CREATE ON SCHEMA public TO keycloak_user;

-- Table privileges
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO keycloak_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO keycloak_user;

-- Future objects privileges (when Administrator creates them)
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public 
    GRANT ALL PRIVILEGES ON TABLES TO keycloak_user;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public 
    GRANT ALL PRIVILEGES ON SEQUENCES TO keycloak_user;