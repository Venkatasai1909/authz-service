package com.venkatasai.auth.authz_service.authorization.strategy;

import com.venkatasai.auth.authz_service.exception.AuthorizationException;
import com.venkatasai.auth.authz_service.model.AuthContext;
import com.venkatasai.auth.authz_service.model.AuthorizationResult;
import com.venkatasai.auth.authz_service.model.AuthorizationType;
import com.venkatasai.auth.authz_service.model.Permission;
import com.venkatasai.auth.authz_service.policy.engine.PolicyEngine;
import com.venkatasai.auth.authz_service.policy.model.PolicyEngineResult;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@AllArgsConstructor
public class PolicyEngineStrategy implements AuthorizationStrategy {
    private final PolicyEngine policyEngine;

    @Override
    public AuthorizationResult authorize(AuthContext context, List<Permission> permissions) {
        PolicyEngineResult policyEngineResult = policyEngine.evaluate(context, permissions);

        if (policyEngineResult == null) {
            throw new AuthorizationException("Policy engine returned null result");
        }

        return AuthorizationResult.buildAuthorizationResult(policyEngineResult, context.getUserId());
    }

    @Override
    public AuthorizationType getType() {
        return AuthorizationType.POLICY;
    }
}