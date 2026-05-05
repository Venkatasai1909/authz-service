package com.venkatasai.auth.authz_service.policy.resolver;

import com.venkatasai.auth.authz_service.model.Decision;
import com.venkatasai.auth.authz_service.policy.model.ScoredPermission;

import java.util.List;

public interface ConflictResolver {
    Decision resolve(List<ScoredPermission> scoredPermissions);
}
