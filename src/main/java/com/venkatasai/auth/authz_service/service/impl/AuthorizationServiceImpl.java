package com.venkatasai.auth.authz_service.service.impl;

import com.venkatasai.auth.authz_service.authentication.JwtAuthenticationProvider;
import com.venkatasai.auth.authz_service.authorization.AuthorizationManager;
import com.venkatasai.auth.authz_service.dto.request.AuthorizationRequest;
import com.venkatasai.auth.authz_service.dto.response.AuthorizationResponse;
import com.venkatasai.auth.authz_service.exception.AuthorizationException;
import com.venkatasai.auth.authz_service.model.*;
import com.venkatasai.auth.authz_service.repository.PermissionRepository;
import com.venkatasai.auth.authz_service.service.AuthorizationService;
import lombok.AllArgsConstructor;

import java.util.List;
import java.util.Optional;

@AllArgsConstructor
public class AuthorizationServiceImpl implements AuthorizationService {
    private final JwtAuthenticationProvider jwtAuthenticationProvider;
    private final PermissionRepository permissionRepository;
    private final AuthorizationManager authorizationManager;

    @Override
    public AuthorizationResponse authorize(AuthorizationRequest request) {

        Optional<UserPrincipal> userPrincipalOpt = jwtAuthenticationProvider.authenticate(request.getAccessToken());

        if(userPrincipalOpt.isEmpty()){
            throw new AuthorizationException("Invalid access token provided.");
        }

        UserPrincipal userPrincipal = userPrincipalOpt.get();
        List<Permission> permissions = permissionRepository.findByUserIdAndAction(userPrincipal.getUserId(), request.getMethod());

        AuthContext authContext = AuthContext.buildAuthContext(userPrincipal, request);
        AuthorizationResult authorizationResult = authorizationManager.evaluate(authContext, permissions, AuthorizationType.POLICY);

        if(authorizationResult == null){
            throw new AuthorizationException("Authorization result generation failed.");
        }

        return AuthorizationResponse.buildAuthorizationResponse(authorizationResult);

    }
}
