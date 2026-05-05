package com.venkatasai.auth.authz_service.authentication;

import com.venkatasai.auth.authz_service.exception.AuthenticationException;
import com.venkatasai.auth.authz_service.model.DecodedToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

@Slf4j
@Component
public class TokenValidator {

    private final JwtDecoder jwtDecoder;
    private final String expectedIssuer;
    private final String expectedAudience; // null means audience check is disabled

    public TokenValidator(
            JwtDecoder jwtDecoder,
            @Value("${jwt.issuer}") String expectedIssuer,
            @Value("${jwt.audience:}") String expectedAudience) {
        this.jwtDecoder = jwtDecoder;
        this.expectedIssuer = expectedIssuer;
        // Treat blank config value same as not configured
        this.expectedAudience = (expectedAudience == null || expectedAudience.isBlank()) ? null : expectedAudience;
    }

    public DecodedToken validate(String token) {
        if (token == null || token.isBlank()) {
            throw new AuthenticationException("Access token is missing");
        }

        log.debug("Validating JWT token (length={})", token.length());

        DecodedToken decoded = jwtDecoder.decode(token);

        validateExpiry(decoded);
        validateNotBefore(decoded);
        validateIssuer(decoded);
        if (expectedAudience != null) {
            validateAudience(decoded);
        }

        log.info("Token validated successfully for subject={}", decoded.getSubject());
        return decoded;
    }

    private void validateExpiry(DecodedToken token) {
        Instant exp = token.getExpiry();
        if (exp == null || exp.isBefore(Instant.now())) {
            log.warn("Token expired: exp={}", exp);
            throw new AuthenticationException("Token has expired");
        }
    }

    private void validateNotBefore(DecodedToken token) {
        Instant nbf = token.getNotBefore();
        if (nbf != null && Instant.now().isBefore(nbf)) {
            log.warn("Token not yet valid: nbf={}", nbf);
            throw new AuthenticationException("Token is not yet valid");
        }
    }

    private void validateIssuer(DecodedToken token) {
        String issuer = token.getIssuer();
        if (issuer == null || issuer.isBlank() || !issuer.equals(expectedIssuer)) {
            log.warn("Invalid issuer: expected={} actual={}", expectedIssuer, issuer);
            throw new AuthenticationException("Invalid token issuer");
        }
    }

    private void validateAudience(DecodedToken token) {
        List<String> audience = token.getAudience();
        if (audience == null || !audience.contains(expectedAudience)) {
            log.warn("Invalid audience: expected={} actual={}", expectedAudience, audience);
            throw new AuthenticationException("Invalid token audience");
        }
    }
}