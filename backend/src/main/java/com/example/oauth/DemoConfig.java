package com.example.oauth;

/**
 * All the hardcoded values for this demo, kept in one place so they are easy to
 * point at during the oral defense.
 *
 * DELIBERATE DEMO SIMPLIFICATIONS (to be noted in the report):
 *  - A single hardcoded user instead of a user database.
 *  - A single hardcoded public client (client_id + redirect_uri).
 *  - The JWT signing secret is a hardcoded constant. In production this would be
 *    an environment-provided secret (or an asymmetric key pair for RS256).
 */
public final class DemoConfig {

    private DemoConfig() {} // no instances — constants only

    // ---- The one client this server recognizes (a public, native client) ----
    public static final String CLIENT_ID = "ios-demo-client";
    public static final String REDIRECT_URI = "com.example.oauthdemo://callback";

    // ---- The one user this server knows about ----
    public static final String USER_ID = "user-1";
    public static final String USERNAME = "demo_user";

    // ---- Authorization code lifetime (short-lived, single-use) ----
    public static final long AUTH_CODE_TTL_MILLIS = 60_000; // 60 seconds

    // ---- Access token (JWT) settings ----
    public static final long ACCESS_TOKEN_TTL_MILLIS = 5 * 60_000; // 5 minutes
    public static final String JWT_ISSUER = "oauth-pkce-demo";

    /**
     * HS256 signing secret. MUST be >= 32 bytes (256 bits) for HMAC-SHA256.
     * Hardcoded ON PURPOSE for the demo — see class note above.
     */
    public static final String JWT_SECRET =
            "demo-only-super-secret-key-change-me-please-32+bytes";
}
