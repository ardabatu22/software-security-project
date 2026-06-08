package com.example.oauth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The three OAuth endpoints for the demo: /authorize, /token, /me.
 *
 * Flow (RFC 6749 Authorization Code + RFC 7636 PKCE):
 *   1. Client generates code_verifier, derives code_challenge = S256(verifier).
 *   2. GET /authorize?...&code_challenge=...  -> server returns an authorization code.
 *   3. POST /token  (code + code_verifier)    -> server verifies PKCE, returns a JWT.
 *   4. GET /me  with Bearer <jwt>             -> server validates JWT, returns user info.
 */
@RestController
public class AuthController {

    private final CodeStore codeStore;
    private final JwtService jwtService;

    public AuthController(CodeStore codeStore, JwtService jwtService) {
        this.codeStore = codeStore;
        this.jwtService = jwtService;
    }

    // ------------------------------------------------------------------ /authorize

    /**
     * Authorization endpoint. For this demo it auto-approves the single hardcoded user
     * (no login/consent page). It validates the client and PKCE parameters, mints a
     * short-lived single-use code bound to the code_challenge, then issues a standard
     * OAuth 302 redirect back to the registered redirect_uri with `code` and `state`
     * appended as query parameters (RFC 6749 §4.1.2). The iOS app's
     * ASWebAuthenticationSession captures this redirect on its custom URL scheme.
     *
     * On any validation failure we return a clean JSON error instead of redirecting.
     */
    @GetMapping("/authorize")
    public ResponseEntity<?> authorize(
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam("code_challenge") String codeChallenge,
            @RequestParam("code_challenge_method") String codeChallengeMethod) {

        // Validate the client against our one hardcoded client.
        if (!DemoConfig.CLIENT_ID.equals(clientId)) {
            return error(HttpStatus.BAD_REQUEST, "invalid_client", "Unknown client_id.");
        }
        if (!DemoConfig.REDIRECT_URI.equals(redirectUri)) {
            return error(HttpStatus.BAD_REQUEST, "invalid_request",
                    "redirect_uri does not match the registered value.");
        }

        // This demo only supports PKCE S256 (RFC 7636).
        if (!"S256".equals(codeChallengeMethod)) {
            return error(HttpStatus.BAD_REQUEST, "invalid_request",
                    "code_challenge_method must be S256.");
        }
        if (codeChallenge == null || codeChallenge.isBlank()) {
            return error(HttpStatus.BAD_REQUEST, "invalid_request",
                    "code_challenge is required.");
        }

        // Auto-approve: mint a code bound to the PKCE challenge.
        String code = codeStore.createCode(codeChallenge, codeChallengeMethod);

        // Build the redirect: redirect_uri?code=...&state=...  (values URL-encoded).
        StringBuilder location = new StringBuilder(redirectUri)
                .append("?code=").append(urlEncode(code));
        if (state != null && !state.isEmpty()) {
            location.append("&state=").append(urlEncode(state));
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(location.toString()));
        return new ResponseEntity<>(headers, HttpStatus.FOUND); // 302
    }

    /** URL-encodes a query-parameter value (UTF-8). */
    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    // ---------------------------------------------------------------------- /token

    /**
     * Token endpoint. Exchanges an authorization code + PKCE code_verifier for a
     * signed JWT access token. Accepts standard form-encoded parameters.
     */
    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> token(
            @RequestParam("code") String code,
            @RequestParam("code_verifier") String codeVerifier,
            @RequestParam("client_id") String clientId) {

        // Client must match our one hardcoded client.
        if (!DemoConfig.CLIENT_ID.equals(clientId)) {
            return error(HttpStatus.BAD_REQUEST, "invalid_client", "Unknown client_id.");
        }

        // Look up the code.
        AuthorizationCode stored = codeStore.get(code);
        if (stored == null) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant",
                    "Authorization code is invalid or unknown.");
        }
        if (stored.isUsed()) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant",
                    "Authorization code has already been used.");
        }
        if (stored.isExpired()) {
            codeStore.remove(code); // tidy up
            return error(HttpStatus.BAD_REQUEST, "invalid_grant",
                    "Authorization code has expired.");
        }

        // --- PKCE verification (the core security check) ---
        if (!PkceVerifier.verify(codeVerifier, stored.getCodeChallenge())) {
            // Do NOT consume the code on a failed verifier in this demo; the legitimate
            // client could still redeem it. (A stolen code without the verifier dies on expiry.)
            return error(HttpStatus.BAD_REQUEST, "invalid_grant",
                    "PKCE verification failed: code_verifier does not match code_challenge.");
        }

        // Success: enforce single-use, then issue the JWT.
        stored.markUsed();
        codeStore.remove(code);

        String accessToken = jwtService.issueAccessToken(DemoConfig.USER_ID, DemoConfig.USERNAME);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", accessToken);
        body.put("token_type", "Bearer");
        body.put("expires_in", DemoConfig.ACCESS_TOKEN_TTL_MILLIS / 1000);
        return ResponseEntity.ok(body);
    }

    // ----------------------------------------------------- /token-legacy-insecure
    //
    // !!! DEMO-ONLY, INTENTIONALLY VULNERABLE — NEVER SHIP THIS !!!
    //
    // This endpoint SIMULATES a legacy, pre-PKCE OAuth 2.0 token endpoint. It exchanges
    // an authorization code for a JWT *without checking any code_verifier* — i.e. it has
    // no PKCE protection at all. It exists solely so the attack demo can show that on such
    // a server a STOLEN authorization code is enough to obtain a token.
    //
    // The real /token endpoint above (which DOES enforce PKCE) is the secure counterpart.
    // Compare the two side by side: the only meaningful difference is the missing PKCE check.
    //
    // Note: this demo endpoint deliberately does NOT consume the code (no markUsed/remove),
    // so the very same intercepted code can flow through all three demo scenarios. Code
    // single-use is an orthogonal control; the vulnerability being demonstrated here is the
    // absence of the code_verifier check.
    @PostMapping("/token-legacy-insecure")
    public ResponseEntity<?> tokenLegacyInsecure(
            @RequestParam("code") String code,
            @RequestParam(value = "client_id", required = false) String clientId) {

        // A pre-PKCE server still looks the code up and checks it is live...
        AuthorizationCode stored = codeStore.get(code);
        if (stored == null) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant",
                    "Authorization code is invalid or unknown.");
        }
        if (stored.isExpired()) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant",
                    "Authorization code has expired.");
        }

        // ...but it performs NO PKCE verification. Anyone holding the code gets a token.
        String accessToken = jwtService.issueAccessToken(DemoConfig.USER_ID, DemoConfig.USERNAME);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", accessToken);
        body.put("token_type", "Bearer");
        body.put("expires_in", DemoConfig.ACCESS_TOKEN_TTL_MILLIS / 1000);
        return ResponseEntity.ok(body);
    }

    // ------------------------------------------------------------------------- /me

    /**
     * Protected resource. Validates the Bearer JWT (signature + expiry) and returns
     * the hardcoded user's info. Returns 401 on any token problem.
     */
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me(
            @RequestHeader(value = "Authorization", required = false) String authorization) {

        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return error(HttpStatus.UNAUTHORIZED, "invalid_token",
                    "Missing or malformed Authorization header (expected 'Bearer <jwt>').");
        }

        String token = authorization.substring("Bearer ".length()).trim();
        try {
            Claims claims = jwtService.validateAndGetClaims(token);

            Map<String, Object> body = new LinkedHashMap<>();
            body.put("id", claims.getSubject());
            body.put("username", claims.get("username", String.class));
            return ResponseEntity.ok(body);
        } catch (JwtException e) {
            // Covers bad signature, expired token, malformed token, wrong issuer, etc.
            return error(HttpStatus.UNAUTHORIZED, "invalid_token",
                    "Access token is invalid or expired.");
        }
    }

    // --------------------------------------------------------------------- helpers

    /** Builds a consistent OAuth-style JSON error response. */
    private ResponseEntity<Map<String, Object>> error(HttpStatus status, String error, String description) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("error_description", description);
        return ResponseEntity.status(status).body(body);
    }
}
