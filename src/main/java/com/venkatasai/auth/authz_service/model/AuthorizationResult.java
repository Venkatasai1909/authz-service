package com.venkatasai.auth.authz_service.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Builder
@AllArgsConstructor
public class AuthorizationResult {
    private Permission permission;
    private Decision decision;
    private String reason;

    public static AuthorizationResult buildAuthorizationResult(PolicyEngineResult policyEngineResult){
        String reason = buildReason(policyEngineResult.getPermission());

        return AuthorizationResult.builder()
                .permission(policyEngineResult.getPermission())
                .decision(policyEngineResult.getDecision())
                .reason(reason)
                .build();

    }

    public static String buildReason(Permission permission){
        return "This User doesn't have ";
    }
}
