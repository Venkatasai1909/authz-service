package com.venkatasai.auth.authz_service.authentication;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.venkatasai.auth.authz_service.exception.AuthenticationException;
import com.venkatasai.auth.authz_service.model.DecodedToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URL;
import java.util.Map;

@Slf4j
@Component
public class NimbusJwtDecoderImpl implements JwtDecoder {

    private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public NimbusJwtDecoderImpl(
            @Value("${jwt.jwks-uri}") String jwksUrl,
            @Value("${jwt.algorithm:RS256}") String algorithm) {
        try {
            ResourceRetriever resourceRetriever = new DefaultResourceRetriever(2000, 2000);
            JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(new URL(jwksUrl), resourceRetriever);

            this.jwtProcessor = new DefaultJWTProcessor<>();

            JWSKeySelector<SecurityContext> keySelector =
                    new JWSVerificationKeySelector<>(JWSAlgorithm.parse(algorithm), jwkSource);
            jwtProcessor.setJWSKeySelector(keySelector);

        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize JWT decoder: " + e.getMessage(), e);
        }
    }

    @Override
    public DecodedToken decode(String token) {
        try {
            JWTClaimsSet claims = jwtProcessor.process(token, null);
            DecodedToken decoded = mapClaims(claims);
            log.debug("JWT decoded successfully for subject={}", decoded.getSubject());
            return decoded;

        } catch (BadJWTException e) {
            log.warn("JWT claim validation failed: {}", e.getMessage());
            throw new AuthenticationException("Invalid JWT: " + e.getMessage());
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during JWT processing", e);
            throw new AuthenticationException("JWT processing failed");
        }
    }

    private DecodedToken mapClaims(JWTClaimsSet claims) {
        return DecodedToken.builder()
                .subject(claims.getSubject())
                .issuer(claims.getIssuer())
                .expiry(claims.getExpirationTime() != null ? claims.getExpirationTime().toInstant() : null)
                .notBefore(claims.getNotBeforeTime() != null ? claims.getNotBeforeTime().toInstant() : null)
                .audience(claims.getAudience() != null && !claims.getAudience().isEmpty() ? claims.getAudience() : null)
                .claims(Map.copyOf(claims.getClaims()))
                .build();
    }
}