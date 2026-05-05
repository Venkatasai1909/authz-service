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

import java.net.URL;
import java.util.Map;

public class NimbusJwtDecoderImpl implements JwtDecoder{

    private final ConfigurableJWTProcessor<com.nimbusds.jose.proc.SecurityContext> jwtProcessor;

    public NimbusJwtDecoderImpl(String jwksUrl) {
        try {
            ResourceRetriever resourceRetriever = new DefaultResourceRetriever(2000, 2000);
            JWKSource<com.nimbusds.jose.proc.SecurityContext> jwkSource =
                    new RemoteJWKSet<>(new URL(jwksUrl), resourceRetriever);

            this.jwtProcessor = new DefaultJWTProcessor<>();

            JWSKeySelector<com.nimbusds.jose.proc.SecurityContext> keySelector =
                    new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);

            jwtProcessor.setJWSKeySelector(keySelector);

        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize JWT decoder", e);
        }
    }

    @Override
    public DecodedToken decode(String token) {
        try {
            SecurityContext ctx = null;

            JWTClaimsSet claims = jwtProcessor.process(token, ctx);

            return mapClaims(claims);

        } catch (BadJWTException e) {
            e.printStackTrace();
            throw new AuthenticationException("Invalid JWT");
        } catch (Exception e) {
            e.printStackTrace();
            throw new AuthenticationException("JWT processing failed");
        }
    }

    private DecodedToken mapClaims(JWTClaimsSet claims) {
        DecodedToken decoded = new DecodedToken();

        decoded.setSubject(claims.getSubject());
        decoded.setIssuer(claims.getIssuer());

        if (claims.getExpirationTime() != null) {
            decoded.setExpiry(claims.getExpirationTime().toInstant());
        }

        Map<String, Object> claimMap = claims.getClaims();
        decoded.setClaims(claimMap);

        return decoded;
    }
}
