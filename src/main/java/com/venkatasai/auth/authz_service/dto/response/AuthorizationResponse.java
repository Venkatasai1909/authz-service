package com.venkatasai.auth.authz_service.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.venkatasai.auth.authz_service.model.AuthorizationResult;
import com.venkatasai.auth.authz_service.model.Decision;
import com.venkatasai.auth.authz_service.model.Permission;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Collections;
import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizationResponse {

    private Decision decision;

    @JsonProperty("user_id")
    private String userId;

    private String reason;

    @JsonProperty("matched_permissions")
    private List<MatchedPermission> matchedPermissions;

    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class MatchedPermission {
        private String action;
        private String resource;
        private String effect;
    }

    public static AuthorizationResponse buildAuthorizationResponse(AuthorizationResult result) {
        List<MatchedPermission> permissions = Collections.emptyList();

        Permission matched = result.permission();
        if (matched != null) {
            permissions = List.of(
                    new MatchedPermission(matched.getAction(), matched.getResource(), matched.getEffect()));
        }

        return new AuthorizationResponse(
                result.decision(),
                result.userId(),
                result.reason(),
                permissions
        );
    }
}