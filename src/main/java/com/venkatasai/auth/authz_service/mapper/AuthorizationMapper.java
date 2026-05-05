package com.venkatasai.auth.authz_service.mapper;

import com.venkatasai.auth.authz_service.model.AuthContext;
import com.venkatasai.auth.authz_service.model.User;
import com.venkatasai.auth.authz_service.util.PathUtils;
import org.springframework.stereotype.Component;

@Component
public class AuthorizationMapper {

    public AuthContext mapToAuthContext(User user, String method, String path) {
        return AuthContext.builder()
                .userId(user.getUserId())
                .action(PathUtils.mapHttpMethodToAction(method))
                .path(PathUtils.normalizePath(path))
                .build();
    }
}