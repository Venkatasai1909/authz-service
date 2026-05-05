package com.venkatasai.auth.authz_service.model;

import com.venkatasai.auth.authz_service.policy.model.PolicyEngineResult;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class AuthorizationResult {
    private final String userId;
    private final Permission permission;
    private final Decision decision;
    private final String reason;

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
            return String.format("Access granted by rule: %s on %s",
                    permission.getAction(), permission.getResource());
        }
        return String.format("Access denied by rule: %s on %s",
                permission.getAction(), permission.getResource());
    }
}