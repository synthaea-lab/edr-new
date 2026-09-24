# Security Fixes for PR #396

This document describes the security vulnerabilities identified in the review and their fixes.

## Critical Vulnerability: mTLS Header Spoofing

### Problem

The agent authentication flow relied on mTLS headers (`X-Client-Cert-Verified`, `X-Client-Cert-Subject`) without verifying they came from nginx. Since the Next.js port 3000 was exposed directly, attackers could:

1. Bypass nginx entirely by connecting to port 3000
2. Send fake mTLS headers to impersonate any enrolled agent
3. Upload fake detections, heartbeats, or read sensitive data

**Impact:** Complete authentication bypass for agent endpoints.

### Fix

Implemented shared secret authentication between nginx and Next.js:

1. **Environment variable:** `NGINX_PROXY_SECRET` (must be changed in production)
2. **nginx:** Injects `X-Proxy-Secret` header with the shared secret
3. **Next.js:** Validates the secret using constant-time comparison in `verifyProxyAuth()`

### Files Changed

- `.env.example` - Added `NGINX_PROXY_SECRET`
- `docker-compose.yml`:
  - Added `NGINX_PROXY_SECRET` env var to both server and proxy
  - **Commented out port 3000 exposure** (critical for production)
- `nginx.conf` - Added `X-Proxy-Secret` header injection
- `lib/tenant.ts` - Added `verifyProxyAuth()` with constant-time comparison
- `app/api/ingest/detection/route.ts` - Added proxy auth check
- `app/api/ingest/heartbeat/route.ts` - Added proxy auth check

### Defense in Depth

The fix implements multiple layers:

1. **Secret verification:** Requests must include valid `X-Proxy-Secret`
2. **Network isolation:** Port 3000 should NOT be exposed (commented in docker-compose)
3. **Constant-time comparison:** Prevents timing attacks on the secret

### Production Deployment

**CRITICAL:** Before deploying to production:

1. Generate a strong random secret:
   ```bash
   openssl rand -base64 32
   ```

2. Set `NGINX_PROXY_SECRET` in both nginx and Next.js environments

3. **NEVER expose port 3000** - only port 8443 (nginx) should be accessible

4. Consider additional protections:
   - Firewall rules restricting nginx→next.js traffic
   - Network namespaces/VPC isolation
   - mTLS between nginx and Next.js

## Additional Fix: getUserId Implementation

### Problem

The `getUserId()` function was referenced in `enrollment/route.ts` but not implemented in `lib/tenant.ts`.

### Fix

Added `getUserId()` function that extracts user ID from `x-user-id` header (injected by middleware).

### Files Changed

- `lib/tenant.ts` - Added `getUserId()` function
- `app/api/enrollment/route.ts` - Changed from raw header access to `getUserId()`

## Testing

After applying these fixes:

1. TypeScript compilation: ✅ Clean (`npx tsc --noEmit`)
2. Agent requests without `X-Proxy-Secret`: ❌ Rejected with 403
3. Agent requests with valid secret: ✅ Accepted
4. Direct port 3000 access: ❌ Should be blocked (port not exposed)

## Remaining Considerations (Out of Scope)

The review identified additional issues for follow-up:

1. **RBAC on admin endpoints** - Not applicable to PR #396 (no admin endpoints in base scaffold)
2. **Content artifact path validation** - Not applicable to PR #396 (no content endpoints)
3. **Signature verification** - Documented TODO for Phase 2
4. **CRON_SECRET timing** - Minor issue, can be addressed separately

These are tracked in PR #409 review comments.
