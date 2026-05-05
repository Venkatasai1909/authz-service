package com.venkatasai.auth.authz_service.dto.response;

import com.google.gson.annotations.SerializedName;
import com.venkatasai.auth.authz_service.model.AuthorizationResult;
import com.venkatasai.auth.authz_service.model.Decision;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizationResponse {
    private Decision decision;

    @SerializedName(value = "user_id")
    private String userId;

    private String reason;

    @SerializedName(value = "matched_permissions")
    private MatchedPermissions matchedPermissions;

    @NoArgsConstructor
    @AllArgsConstructor
    static class MatchedPermissions{
        private String action;
        private String resource;
        private String effect;
    }

    public static AuthorizationResponse buildAuthorizationResponse(AuthorizationResult authorizationResult){
        AuthorizationResponse authorizationResponse = new AuthorizationResponse();

        if(authorizationResult.getPermission() != null){
            MatchedPermissions permission  = new MatchedPermissions(authorizationResult.getPermission().getAction(),
                    authorizationResult.getPermission().getResource(), authorizationResult.getPermission().getEffect());

            authorizationResponse.setMatchedPermissions(permission);

        }

        authorizationResponse.setDecision(authorizationResult.getDecision());
        authorizationResponse.setUserId(authorizationResponse.getUserId());
        authorizationResponse.setReason(authorizationResponse.getReason());

        return authorizationResponse;

    }
}