package com.venkatasai.auth.authz_service.authentication;

import com.venkatasai.auth.authz_service.exception.AuthenticationException;
import com.venkatasai.auth.authz_service.model.DecodedToken;
import com.venkatasai.auth.authz_service.model.UserPrincipal;
import lombok.AllArgsConstructor;

import java.util.Optional;

@AllArgsConstructor
public class JwtAuthenticationProvider {
    private final TokenValidator tokenValidator;

    public Optional<UserPrincipal> authenticate(String token){
        DecodedToken decodedToken = tokenValidator.validate(token);
        return buildPrincipal(decodedToken);

    }

    private Optional<UserPrincipal> buildPrincipal(DecodedToken token) {
        if(token == null){
            throw new AuthenticationException("Invalid token provided.");
        }

        UserPrincipal principal = new UserPrincipal();

        if(token.getSubject() == null){
            throw new AuthenticationException("Invalid subject provided.");
        }

        principal.setUserId(token.getSubject());

        Object email = token.getClaims().get("email");
        if (email != null) {
            principal.setEmail(email.toString());
        }

        return Optional.of(principal);
    }

}
