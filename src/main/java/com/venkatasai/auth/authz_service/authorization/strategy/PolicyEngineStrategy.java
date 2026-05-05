package com.venkatasai.auth.authz_service.authorization.strategy;

import com.venkatasai.auth.authz_service.exception.AuthorizationException;
import com.venkatasai.auth.authz_service.model.AuthContext;
import com.venkatasai.auth.authz_service.model.AuthorizationResult;
import com.venkatasai.auth.authz_service.model.Permission;
import com.venkatasai.auth.authz_service.model.PolicyEngineResult;
import com.venkatasai.auth.authz_service.policy.engine.PolicyEngine;
import lombok.AllArgsConstructor;

import java.util.List;

@AllArgsConstructor
public class PolicyEngineStrategy implements AuthorizationStrategy{
    private final PolicyEngine policyEngine;

    @Override
    public AuthorizationResult authorize(AuthContext context, List<Permission> permissions) {
        PolicyEngineResult policyEngineResult = policyEngine.evaluate(context, permissions);

        if(policyEngineResult == null){
            throw new AuthorizationException("Policy Engine failed to validate the permissions");
        }

        return AuthorizationResult.buildAuthorizationResult(policyEngineResult);
    }
}
