package com.venkatasai.auth.authz_service.policy.resolver;

import com.venkatasai.auth.authz_service.model.Decision;
import com.venkatasai.auth.authz_service.policy.model.ScoredPermission;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class DenyOverridesResolver implements ConflictResolver {

    @Override
    public Decision resolve(List<ScoredPermission> scoredPermissions) {
        if (scoredPermissions == null || scoredPermissions.isEmpty()) {
            return Decision.DENY;
        }

        for (ScoredPermission scoredPermission : scoredPermissions) {
            if (scoredPermission.permission().isDeny()) {
                return Decision.DENY;
            }
        }

        return Decision.ALLOW;
    }
}