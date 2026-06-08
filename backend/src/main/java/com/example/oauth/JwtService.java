package com.example.oauth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import io.jsonwebtoken.security.Keys;

/**
 * Issues and validates the HS256-signed JWT access token (RFC 7519).
 *
 * Uses the maintained jjwt library. The signing key is derived from the hardcoded
 * demo secret in {@link DemoConfig}.
 */
@Service
public class JwtService {

    // Symmetric key for HS256, built once from the hardcoded secret.
    private final SecretKey key =
            Keys.hmacShaKeyFor(DemoConfig.JWT_SECRET.getBytes(StandardCharsets.UTF_8));

    /**
     * Issues a signed access token for the given subject (user id), including the
     * username as a custom claim and a 5-minute expiry.
     */
    public String issueAccessToken(String subject, String username) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .issuer(DemoConfig.JWT_ISSUER)
                .subject(subject)                 // "sub" = user id
                .claim("username", username)      // custom claim
                .issuedAt(new Date(now))          // "iat"
                .expiration(new Date(now + DemoConfig.ACCESS_TOKEN_TTL_MILLIS)) // "exp"
                .signWith(key, Jwts.SIG.HS256) // pin HS256 (jjwt would otherwise pick HS384 for a long key)
                .compact();
    }

    /**
     * Validates the token's signature and expiry and returns its claims.
     *
     * @throws io.jsonwebtoken.JwtException if the token is malformed, has a bad
     *         signature, or is expired (the caller maps this to HTTP 401).
     */
    public Claims validateAndGetClaims(String token) {
        Jws<Claims> parsed = Jwts.parser()
                .verifyWith(key)
                .requireIssuer(DemoConfig.JWT_ISSUER)
                .build()
                .parseSignedClaims(token); // throws on bad signature / expiry
        return parsed.getPayload();
    }
}
