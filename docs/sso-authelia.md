# SSO with Authelia — Setup Guide

This guide walks through configuring [Authelia](https://www.authelia.com/) as the OIDC identity provider for HenKaiPan single sign-on.

## Prerequisites

- HenKaiPan running behind a reverse proxy with HTTPS (Authelia requires HTTPS for OIDC)
- Authelia v4.38+ (OIDC provider support)
- A domain or subdomain for Authelia (e.g., `auth.example.com`)
- HenKaiPan accessible at a domain (e.g., `henkaipan.example.com`)

## Architecture

```
User → HenKaiPan login page → "Sign in with SSO"
  → redirect to Authelia (auth.example.com)
  → user authenticates at Authelia
  → redirect back to HenKaiPan /api/auth/sso/callback
  → HenKaiPan verifies ID token, creates/links user, issues JWT
  → redirect to /dashboard
```

## Step 1 — Add Authelia to Docker Compose

Add this service to your `docker-compose.yml` (alongside HenKaiPan):

```yaml
  authelia:
    image: authelia/authelia:latest
    container_name: authelia
    restart: unless-stopped
    volumes:
      - ./authelia:/config
    ports:
      # Bind to loopback only: the reverse proxy on the host reaches Authelia
      # via 127.0.0.1, while the port stays hidden from the network. If the
      # proxy is also containerized on the same Docker network, remove this
      # ports mapping entirely and reach Authelia by its service name instead.
      - "127.0.0.1:9091:9091"
    environment:
      - AUTHELIA_TELEMETRY_METRICS_ENABLED=false
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:9091/api/health"]
      interval: 10s
      timeout: 5s
      retries: 3
```

Create the config directory:

```bash
mkdir -p authelia
```

## Step 2 — Configure Authelia

Create `authelia/configuration.yml`:

```yaml
server:
  address: 'tcp://0.0.0.0:9091'

log:
  level: info

identity_validation:
  reset_password:
    jwt_lifespan: '5 minutes'
    # Required for signing password-reset JWTs. Use a long random secret.
    jwt_secret: 'replace-with-a-long-random-secret'

authentication:
  file:
    path: '/config/users_database.yml'

access_control:
  default_policy: deny
  rules:
    - domain: 'henkaipan.example.com'
      policy: one_factor  # or two_factor for stricter auth

session:
  # Required for signing session cookies. Use a long random secret.
  secret: 'replace-with-a-long-random-secret'
  cookies:
    - domain: 'example.com'
      authelia_url: 'https://auth.example.com'
      default_redirection_url: 'https://henkaipan.example.com'

storage:
  # Required for encrypting session storage. Use a long random secret.
  encryption_key: 'replace-with-a-long-random-secret'
  local:
    path: '/config/db.sqlite3'

notifier:
  filesystem:
    filename: '/config/notification.txt'

identity_providers:
  oidc:
    # Random alphanumeric secret, at least 64 characters. Generate with:
    #   openssl rand -base64 64
    hmac_secret: 'replace-with-at-least-64-random-characters'
    jwks:
      # RSA private key (PKCS#8 PEM), at least 2048 bits, indented 10 spaces.
      # Generate with:
      #   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
      #     -outform PEM -out authelia-oidc.pem
      - key: |
          -----BEGIN PRIVATE KEY-----
          replace-with-PKCS8-key-content-indented-10-spaces
          -----END PRIVATE KEY-----
    lifespans:
      access_token: '1h'
      id_token: '1h'
      refresh_token: '90d'
    # IMPORTANT: HenKaiPan reads claims ONLY from the signed ID token (no
    # UserInfo fallback). This policy copies email/groups/preferred_username
    # into the ID token for the henkaipan client. Without it, login fails with
    # "SSO provider did not return an email address".
    claims_policies:
      henkaipan:
        id_token:
          - email
          - email_verified
          - groups
          - preferred_username
    clients:
      # ── HenKaiPan OIDC Client ──────────────────────────────────
      - client_id: 'henkaipan'
        client_name: 'HenKaiPan'
        client_secret: '$argon2id$v=19$m=65536,t=3,p=4$...'  # see Step 3
        public: false
        authorization_policy: 'one_factor'
        consent_mode: 'implicit'  # skip consent screen
        claims_policy: 'henkaipan'  # hydrate the ID token with email/groups
        redirect_uris:
          - 'https://henkaipan.example.com/api/auth/sso/callback'
        scopes:
          - 'openid'
          - 'email'
          - 'profile'
          - 'groups'
        response_types:
          - 'code'
        grant_types:
          - 'authorization_code'
```

> **Important:** Replace `example.com` with your actual domain throughout.

## Step 3 — Generate the Client Secret Hash

Authelia stores client secrets as Argon2id hashes. Generate one:

```bash
# Install authelia binary or use the Docker image
docker run --rm authelia/authelia:latest authelia crypto hash generate argon2 --password 'your-secure-client-secret'
```

Copy the full `$argon2id$...` output and paste it as `client_secret` in `configuration.yml`.

## Step 4 — Create Users + Groups in Authelia

Create `authelia/users_database.yml`:

```yaml
users:
  admin:
    displayname: 'Admin User'
    password: '$argon2id$...'  # generate with: authelia crypto hash generate argon2 --password 'password'
    email: admin@example.com
    groups:
      - admins        # ← this maps to HenKaiPan admin role
      - henkaipan-users

  viewer:
    displayname: 'Viewer User'
    password: '$argon2id$...'
    email: viewer@example.com
    groups:
      - henkaipan-users  # ← not in 'admins' → gets viewer role
```

Generate password hashes:

```bash
docker run --rm authelia/authelia:latest authelia crypto hash generate argon2 --password 'user-password'
```

## Step 5 — Configure HenKaiPan

Add these to your HenKaiPan `.env` file:

```bash
# ── SSO / OIDC ──────────────────────────────────────────────────
SSO_ENABLED=true
SSO_ISSUER_URL=https://auth.example.com
SSO_CLIENT_ID=henkaipan
SSO_CLIENT_SECRET=your-secure-client-secret
SSO_REDIRECT_URI=https://henkaipan.example.com/api/auth/sso/callback
SSO_GROUP_CLAIM=groups
SSO_ADMIN_GROUP=admins
```


| Env var             | Value                                                 | Notes                                                   |
| ------------------- | ----------------------------------------------------- | ------------------------------------------------------- |
| `SSO_ENABLED`       | `true`                                                | Enables SSO routes + shows button on login page         |
| `SSO_ISSUER_URL`    | `https://auth.example.com`                            | Must match Authelia's `issuer` config                   |
| `SSO_CLIENT_ID`     | `henkaipan`                                           | Must match `client_id` in Authelia                      |
| `SSO_CLIENT_SECRET` | `your-secure-client-secret`                           | Plaintext secret (not the Argon2 hash)                  |
| `SSO_REDIRECT_URI`  | `https://henkaipan.example.com/api/auth/sso/callback` | Must match `redirect_uris` in Authelia                  |
| `SSO_GROUP_CLAIM`   | `groups`                                              | Authelia sends group membership in the `groups` claim   |
| `SSO_ADMIN_GROUP`   | `admins`                                              | Users in this Authelia group get HenKaiPan `admin` role |


## Step 6 — Reverse Proxy Configuration

Both Authelia and HenKaiPan must be behind HTTPS. Example nginx config:

```nginx
# Authelia
server {
    listen 443 ssl http2;
    server_name auth.example.com;

    location / {
        proxy_pass http://authelia:9091;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}

# HenKaiPan
server {
    listen 443 ssl http2;
    server_name henkaipan.example.com;

    location / {
        proxy_pass http://api:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

Ensure `TRUSTED_PROXIES` is set in HenKaiPan's `.env` if running behind nginx:

```bash
TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

## Step 7 — Restart and Test

```bash
# Restart both services
docker compose restart authelia api

# Verify config status shows SSO enabled
curl -s https://henkaipan.example.com/api/config/status | python3 -m json.tool
# Expected: "features": {"sso": true, "risk_acceptance": true}

# Open the login page — SSO button should appear
open https://henkaipan.example.com/login
```

**Test the flow:**

1. Click "Sign in with SSO"
2. You should be redirected to `auth.example.com`
3. Log in with an Authelia user (e.g., `admin` / password)
4. You should be redirected back to HenKaiPan `/dashboard`
5. Verify the user was created in HenKaiPan with the correct role:
  ```bash
   docker compose exec -T postgres psql -U aspm -d aspm \
     -c "SELECT username, email, role, sso_provider, sso_subject FROM users WHERE sso_subject IS NOT NULL;"
  ```

## How Role Mapping Works

HenKaiPan maps Authelia groups to local roles:

| Authelia group                                     | HenKaiPan role | Behavior               |
| -------------------------------------------------- | -------------- | ---------------------- |
| `admins` (or whatever `SSO_ADMIN_GROUP` is set to) | `admin`        | Full read+write access |
| Any other group, or no group                       | `viewer`       | Read-only access       |

If a user is in BOTH `admins` and `henkaipan-users`, they get `admin` (admin takes priority).

> **Important — the `groups` scope MUST be requested.** HenKaiPan requests `openid`, `email`, `profile`, **and `groups`** scopes from the IdP. With `consent_mode: implicit`, Authelia skips the consent screen, so verify instead that Authelia grants the `groups` scope and that the signed ID token actually contains the `groups` claim (decode the ID token after a login). If `groups` is empty, role mapping won't work. This requires BOTH:
> 1. Authelia client config includes `groups` in `scopes`
> 2. HenKaiPan's OIDC provider requests the `groups` scope (it does by default)

**Role sync**: On every SSO login, HenKaiPan re-evaluates the user's role from the IdP `groups` claim and updates it if it changed. So moving a user into/out of `SSO_ADMIN_GROUP` takes effect on their **next SSO login** — no manual role editing needed.

## User Provisioning Behavior

**First SSO login for an email that already exists in HenKaiPan:**

- The SSO identity (`sso_provider` + `sso_subject`) is linked to the existing user
- Existing team assignments are preserved. The user's role is re-synchronized from the IdP group claim.
- This allows pre-provisioning users before enabling SSO

**First SSO login for a new email:**

- A new user is created automatically
- Username comes from Authelia's `preferred_username` claim (falls back to email)
- Role is determined by group claim mapping (see above)
- Password is empty (SSO-only user — can't log in with password)

## Troubleshooting

### "SSO not configured" on the login page

The API started but the OIDC provider failed to initialize. Check logs:

```bash
docker compose logs api | grep -i sso
```

Common causes:

- `SSO_ISSUER_URL` unreachable from the API container (check DNS/networking)
- `SSO_CLIENT_ID` or `SSO_CLIENT_SECRET` empty
- Authelia OIDC not configured (check Authelia logs)

### "invalid or expired SSO state" on callback

The state cookie expired (5-minute window). This happens if the user takes too long at the Authelia login page. Just try again.

### "sso_failed" redirect after callback

The OIDC token exchange or ID token verification failed. Check API logs:

```bash
docker compose logs api | grep -i "sso.*failed"
```

Common causes:

- Redirect URI mismatch between Authelia and `SSO_REDIRECT_URI` (must match exactly, including trailing slash)
- Client secret mismatch (HenKaiPan uses the plaintext secret, Authelia stores the Argon2 hash — make sure you're not mixing them up)
- Authelia not configured for `authorization_code` grant type

### "SSO provider did not return an email address" (sso_no_email)

HenKaiPan reads claims **only** from the signed ID token (by design — no UserInfo fallback). Authelia by default puts `email`/`groups` in the UserInfo endpoint, NOT the ID token.

**Fix**: add a `claims_policy` that hydrates the ID token for the henkaipan client (see the `claims_policies` section in Step 2). Verify it took effect by decoding an ID token — it must contain `email` and `groups` claims.

If you're using a different IdP (Keycloak, Google), configure the equivalent — the ID token must carry `email` and `groups`.

### SSO button not appearing on login page

Verify the config status endpoint returns `sso: true`:

```bash
curl -s https://henkaipan.example.com/api/config/status
```

If it returns `sso: false`, the API didn't detect SSO config. Check that `SSO_ENABLED=true` is in the `.env` file and the API container was restarted after the change.

### User gets `viewer` instead of `admin`

Check that the Authelia user is in the group specified by `SSO_ADMIN_GROUP`:

```yaml
# authelia/users_database.yml
users:
  myadmin:
    groups:
      - admins  # must match SSO_ADMIN_GROUP exactly
```

### Existing user can't log in after SSO is enabled

If an existing HenKaiPan user's email doesn't match their Authelia email, the SSO identity won't be linked. Fix by either:

1. Updating the user's email in HenKaiPan to match their Authelia email
2. Manually linking the SSO identity in the database:
  ```sql
   UPDATE users
   SET sso_provider = 'https://auth.example.com',
       sso_subject = '[[ORCA_RICH_MD:7ec6aa906dd4d0d751fd592c63c3a34e:inline-html:%3Cauthelia-user-subject%3E]]'
   WHERE email = 'existing@example.com';
  ```

