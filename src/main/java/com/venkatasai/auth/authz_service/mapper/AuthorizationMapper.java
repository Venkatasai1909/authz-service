package com.venkatasai.auth.authz_service.mapper;

import com.venkatasai.auth.authz_service.model.AuthContext;
import com.venkatasai.auth.authz_service.model.UserPrincipal;
import com.venkatasai.auth.authz_service.util.PathUtils;
import org.springframework.stereotype.Component;

@Component
public class AuthorizationMapper {

    public AuthContext mapToAuthContext(UserPrincipal principal, String method, String path) {
        return AuthContext.builder()
                .userId(principal.getUserId())
                .action(PathUtils.mapHttpMethodToAction(method))
                .path(PathUtils.normalizePath(path))
                .build();
    }
}