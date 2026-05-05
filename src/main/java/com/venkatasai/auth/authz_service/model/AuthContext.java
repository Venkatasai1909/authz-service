package com.venkatasai.auth.authz_service.model;

import com.venkatasai.auth.authz_service.dto.request.AuthorizationRequest;
import com.venkatasai.auth.authz_service.util.PathUtils;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthContext {
    private String userId;
    private String action;
    private String path;

    public static AuthContext buildAuthContext(UserPrincipal userPrincipal, AuthorizationRequest request){
        return AuthContext.builder()
                .userId(userPrincipal.getUserId())
                .action(PathUtils.mapHttpMethodToAction(request.getMethod()))
                .path(request.getPath())
                .build();

    }
}
