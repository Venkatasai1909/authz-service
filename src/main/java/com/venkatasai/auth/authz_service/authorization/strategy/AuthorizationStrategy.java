package com.venkatasai.auth.authz_service.authorization.strategy;

import com.venkatasai.auth.authz_service.model.AuthContext;
import com.venkatasai.auth.authz_service.model.AuthorizationResult;
import com.venkatasai.auth.authz_service.model.Permission;

import java.util.List;

public interface AuthorizationStrategy {
    AuthorizationResult authorize(AuthContext context, List<Permission> permissions);
}
