package com.venkatasai.auth.authz_service.policy.model;

import com.venkatasai.auth.authz_service.model.Permission;

public record ScoredPermission(Permission permission, int score) {
}
