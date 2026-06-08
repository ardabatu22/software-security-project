package com.example.oauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the minimal OAuth 2.0 (Authorization Code + PKCE) demo backend.
 *
 * Scope (deliberately minimal — university term project):
 *  - one hardcoded user, one hardcoded client (see {@link DemoConfig})
 *  - in-memory storage only (no database)
 *  - exactly three endpoints: /authorize, /token, /me (see {@link AuthController})
 */
@SpringBootApplication
public class OauthPkceApplication {
    public static void main(String[] args) {
        SpringApplication.run(OauthPkceApplication.class, args);
    }
}
