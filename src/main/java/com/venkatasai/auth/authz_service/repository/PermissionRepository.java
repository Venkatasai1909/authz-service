package com.venkatasai.auth.authz_service.repository;

import com.venkatasai.auth.authz_service.model.Permission;

import java.util.List;

public interface PermissionRepository {
    List<Permission> findByUserIdAndAction(String userId, String action);
}
