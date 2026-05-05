package com.venkatasai.auth.authz_service.authorization;

import com.venkatasai.auth.authz_service.authorization.factory.AuthorizationFactory;
import com.venkatasai.auth.authz_service.authorization.strategy.AuthorizationStrategy;
import com.venkatasai.auth.authz_service.model.AuthContext;
import com.venkatasai.auth.authz_service.model.AuthorizationResult;
import com.venkatasai.auth.authz_service.model.AuthorizationType;
import com.venkatasai.auth.authz_service.model.Permission;
import lombok.AllArgsConstructor;

import java.util.List;

@AllArgsConstructor
public class AuthorizationManager {
    private final AuthorizationFactory factory;

    public AuthorizationResult evaluate(AuthContext authContext, List<Permission> permissions, AuthorizationType authorizationType){
        AuthorizationStrategy authorizationStrategy = factory.getAuthorizationStrategy(authorizationType);
        return authorizationStrategy.authorize(authContext, permissions);

    }
}
