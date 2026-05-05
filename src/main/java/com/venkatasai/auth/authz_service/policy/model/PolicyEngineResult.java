package com.venkatasai.auth.authz_service.policy.model;

import com.venkatasai.auth.authz_service.model.Decision;
import com.venkatasai.auth.authz_service.model.Permission;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class PolicyEngineResult {
    private Permission permission;
    private Decision decision;

    public static PolicyEngineResult buildDefaultOutput() {
        return new PolicyEngineResult(null, Decision.DENY);
    }
}