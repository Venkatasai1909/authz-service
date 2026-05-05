package com.venkatasai.auth.authz_service.authorization.factory;

import com.venkatasai.auth.authz_service.authorization.strategy.AuthorizationStrategy;
import com.venkatasai.auth.authz_service.exception.AuthorizationException;
import com.venkatasai.auth.authz_service.model.AuthorizationType;
import lombok.AllArgsConstructor;

import java.util.Map;

@AllArgsConstructor
public class AuthorizationFactory {
    private final Map<AuthorizationType, AuthorizationStrategy> strategyMap;

    public AuthorizationStrategy getAuthorizationStrategy(AuthorizationType authorizationType){
        AuthorizationStrategy authorizationStrategy =  strategyMap.get(authorizationType);

        if (authorizationStrategy == null) {
            throw new AuthorizationException("Unsupported authorization type: " + authorizationType);
        }

        return authorizationStrategy;

    }
}
