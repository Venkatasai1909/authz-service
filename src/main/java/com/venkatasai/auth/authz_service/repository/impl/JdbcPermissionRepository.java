package com.venkatasai.auth.authz_service.repository.impl;

import com.venkatasai.auth.authz_service.model.Permission;
import com.venkatasai.auth.authz_service.repository.PermissionRepository;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.util.List;

@Slf4j
@Repository
@AllArgsConstructor
public class JdbcPermissionRepository implements PermissionRepository {

    private static final String FIND_BY_USER_AND_ACTION =
            "SELECT id, user_id, action, resource, effect " +
            "FROM user_permissions " +
            "WHERE user_id = ? AND action = ?";

    private final JdbcTemplate jdbcTemplate;

    private final RowMapper<Permission> permissionRowMapper = (rs, rowNum) ->
            Permission.builder()
                    .id(rs.getInt("id"))
                    .userId(rs.getString("user_id"))
                    .action(rs.getString("action"))
                    .resource(rs.getString("resource"))
                    .effect(rs.getString("effect"))
                    .build();

    @Override
    @Cacheable(value = "permissions", key = "#userId + ':' + #action")
    public List<Permission> findByUserIdAndAction(String userId, String action) {
        log.debug("Querying permissions: userId={} action={}", userId, action);
        try {
            List<Permission> results = jdbcTemplate.query(FIND_BY_USER_AND_ACTION, permissionRowMapper, userId, action);
            log.debug("Found {} permission(s) for userId={} action={}", results.size(), userId, action);
            return results;
        } catch (Exception e) {
            log.error("DB error fetching permissions for userId={} action={}", userId, action, e);
            throw e;
        }
    }
}