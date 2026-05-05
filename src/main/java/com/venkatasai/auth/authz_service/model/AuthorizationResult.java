package com.venkatasai.auth.authz_service.model;

import com.venkatasai.auth.authz_service.policy.model.PolicyEngineResult;
import lombok.Builder;

@Builder
public record AuthorizationResult(String userId, Permission permission, Decision decision, String reason) {
    public static AuthorizationResult buildAuthorizationResult(PolicyEngineResult policyEngineResult, String userId) {
        return AuthorizationResult.builder()
                .userId(userId)
                .permission(policyEngineResult.getPermission())
                .decision(policyEngineResult.getDecision())
                .reason(buildReason(policyEngineResult.getPermission(), policyEngineResult.getDecision()))
                .build();
    }

    private static String buildReason(Permission permission, Decision decision) {
        if (permission == null) {
            return "No matching permission found; default deny applied";
        }
        if (decision == Decision.ALLOW) {
            return String.format("User has %s permission for %s",
                    permission.getAction(), permission.getResource());
        }
        return String.format("Access denied by rule: %s on %s",
                permission.getAction(), permission.getResource());
    }
}