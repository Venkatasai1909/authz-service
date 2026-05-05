package com.venkatasai.auth.authz_service.repository.impl;

import com.venkatasai.auth.authz_service.model.Permission;
import com.venkatasai.auth.authz_service.repository.PermissionRepository;

import java.util.List;

public class JdbcPermissionRepository implements PermissionRepository {


    @Override
    public List<Permission> findByUserIdAndAction(String userId, String action) {
        return List.of();
    }
}
