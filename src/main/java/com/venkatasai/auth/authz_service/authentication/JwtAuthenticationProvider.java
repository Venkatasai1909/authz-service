package com.venkatasai.auth.authz_service.authentication;

import com.venkatasai.auth.authz_service.exception.AuthenticationException;
import com.venkatasai.auth.authz_service.model.DecodedToken;
import com.venkatasai.auth.authz_service.model.UserPrincipal;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;

@Slf4j
@Component
@AllArgsConstructor
public class JwtAuthenticationProvider {
    private final TokenValidator tokenValidator;

    public UserPrincipal authenticate(String token) {
        DecodedToken decodedToken = tokenValidator.validate(token);
        return buildPrincipal(decodedToken);
    }

    private UserPrincipal buildPrincipal(DecodedToken token) {
        if (token == null) {
            throw new AuthenticationException("Invalid token provided.");
        }
        if (token.getSubject() == null) {
            throw new AuthenticationException("Token is missing required 'sub' claim.");
        }

        Map<String, Object> claims = token.getClaims();
        String email = (claims != null && claims.get("email") != null) ? claims.get("email").toString() : null;

        UserPrincipal principal = UserPrincipal.builder()
                .userId(token.getSubject())
                .email(email)
                .build();

        log.debug("Principal built: userId={}", principal.getUserId());
        return principal;
    }
}