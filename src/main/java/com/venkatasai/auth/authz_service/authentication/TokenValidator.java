package com.venkatasai.auth.authz_service.authentication;

import com.venkatasai.auth.authz_service.exception.AuthenticationException;
import com.venkatasai.auth.authz_service.model.DecodedToken;
import lombok.AllArgsConstructor;

import java.time.Instant;

@AllArgsConstructor
public class TokenValidator {
    private final JwtDecoder jwtDecoder;
    private final String signedIssuer;

    public DecodedToken validate(String token){
        if(token == null || token.isBlank()){
            throw new AuthenticationException("Access token is missing");
        }

        DecodedToken decodedToken = jwtDecoder.decode(token);
        validateExpiry(decodedToken);
        validateIssuer(decodedToken);

        return decodedToken;
    }

    private void validateExpiry(DecodedToken token) {
        Instant exp = token.getExpiry();
        if (exp == null || exp.isBefore(Instant.now())) {
            throw new AuthenticationException("Token expired");
        }
    }

    private void validateIssuer(DecodedToken token) {
        String issuer = token.getIssuer();
        if (issuer == null || issuer.isBlank() || !issuer.equals(signedIssuer)) {
            throw new AuthenticationException("Invalid issuer");
        }
    }

}

