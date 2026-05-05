package com.venkatasai.auth.authz_service.service.impl;

import com.venkatasai.auth.authz_service.authentication.JwtAuthenticator;
import com.venkatasai.auth.authz_service.authorization.AuthorizationManager;
import com.venkatasai.auth.authz_service.dto.request.AuthorizationRequest;
import com.venkatasai.auth.authz_service.dto.response.AuthorizationResponse;
import com.venkatasai.auth.authz_service.exception.AuthorizationException;
import com.venkatasai.auth.authz_service.mapper.AuthorizationMapper;
import com.venkatasai.auth.authz_service.model.AuthContext;
import com.venkatasai.auth.authz_service.model.AuthorizationResult;
import com.venkatasai.auth.authz_service.model.Permission;
import com.venkatasai.auth.authz_service.model.UserPrincipal;
import com.venkatasai.auth.authz_service.repository.PermissionRepository;
import com.venkatasai.auth.authz_service.service.AuthorizationService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
@AllArgsConstructor
public class AuthorizationServiceImpl implements AuthorizationService {
    private final JwtAuthenticator jwtAuthenticator;
    private final PermissionRepository permissionRepository;
    private final AuthorizationManager authorizationManager;
    private final AuthorizationMapper authorizationMapper;

    @Override
    public AuthorizationResponse authorize(AuthorizationRequest request) {
        log.info("Authorization request: method={} path={}", request.getMethod(), request.getPath());

        // Step 1: Validate token and extract identity
        UserPrincipal userPrincipal = jwtAuthenticator.authenticate(request.getAccessToken());
        log.debug("Authenticated userId={}", userPrincipal.getUserId());

        // Step 2: Build auth context (maps method→action, normalizes path)
        // Must happen before DB query so we query by the correct action ("read"/"write"/"delete")
        AuthContext authContext = authorizationMapper.mapToAuthContext(
                userPrincipal, request.getMethod(), request.getPath());
        log.debug("AuthContext: userId={} action={} path={}",
                authContext.getUserId(), authContext.getAction(), authContext.getPath());

        // Step 3: Load permissions for this user + action
        List<Permission> permissions = permissionRepository.findByUserIdAndAction(
                authContext.getUserId(), authContext.getAction());
        log.debug("Loaded {} permission(s) from DB for userId={} action={}",
                permissions.size(), authContext.getUserId(), authContext.getAction());

        // Step 4: Evaluate policy
        AuthorizationResult authorizationResult = authorizationManager.evaluate(authContext, permissions);

        if (authorizationResult == null) {
            throw new AuthorizationException("Authorization result generation failed.");
        }

        log.info("Authorization decision: userId={} action={} path={} decision={}",
                authContext.getUserId(), authContext.getAction(), authContext.getPath(),
                authorizationResult.decision());

        return AuthorizationResponse.buildAuthorizationResponse(authorizationResult);
    }
}