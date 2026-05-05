package com.venkatasai.auth.authz_service.service.impl;

import com.venkatasai.auth.authz_service.authentication.JwtAuthenticator;
import com.venkatasai.auth.authz_service.authorization.AuthorizationManager;
import com.venkatasai.auth.authz_service.dto.request.AuthorizationRequest;
import com.venkatasai.auth.authz_service.dto.response.AuthorizationResponse;
import com.venkatasai.auth.authz_service.exception.AuthenticationException;
import com.venkatasai.auth.authz_service.exception.AuthorizationException;
import com.venkatasai.auth.authz_service.mapper.AuthorizationMapper;
import com.venkatasai.auth.authz_service.model.*;
import com.venkatasai.auth.authz_service.repository.PermissionRepository;
import com.venkatasai.auth.authz_service.repository.UserRepository;
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
    private final UserRepository userRepository;

    @Override
    public AuthorizationResponse authorize(AuthorizationRequest request) {
        log.info("Authorization request received: method={} path={}", request.getMethod(), request.getPath());

        // Step 1: Validate the JWT — verify signature, expiry, issuer, and extract the external user identity
        log.debug("Step 1: Validating JWT and extracting external user identity from 'sub' claim");
        UserPrincipal userPrincipal = jwtAuthenticator.authenticate(request.getAccessToken());
        log.debug("Step 1 complete: externalUserId={}", userPrincipal.getUserId());

        // Step 2: Resolve external IdP user ID (e.g. Clerk's sub) to the internal user ID used in permissions
        log.debug("Step 2: Resolving externalUserId={} to internal user", userPrincipal.getUserId());
        User user = userRepository.findByExternalUserId(userPrincipal.getUserId())
                .orElseThrow(() -> new AuthenticationException(
                        "User mapping not found for externalUserId=" + userPrincipal.getUserId()
                ));
        log.debug("Step 2 complete: mapped to internalUserId={}", user.getUserId());

        // Step 3: Build the auth context — map HTTP method to semantic action and normalize the request path
        log.debug("Step 3: Building AuthContext — mapping method={} to action and normalizing path={}", request.getMethod(), request.getPath());
        AuthContext authContext = authorizationMapper.mapToAuthContext(
                user, request.getMethod(), request.getPath());
        log.debug("Step 3 complete: AuthContext built — userId={} action={} path={}",
                authContext.getUserId(), authContext.getAction(), authContext.getPath());

        // Step 4: Load all permissions for this user and action from the DB (served from cache if warm)
        log.debug("Step 4: Loading permissions for userId={} action={}", authContext.getUserId(), authContext.getAction());
        List<Permission> permissions = permissionRepository.findByUserIdAndAction(
                authContext.getUserId(), authContext.getAction());
        log.debug("Step 4 complete: loaded {} permission(s)", permissions.size());

        // Step 5: Run the policy engine — match resources, score specificity, resolve conflicts
        log.debug("Step 5: Evaluating policy for userId={} action={} path={}",
                authContext.getUserId(), authContext.getAction(), authContext.getPath());
        AuthorizationResult authorizationResult = authorizationManager.evaluate(authContext, permissions);

        if (authorizationResult == null) {
            throw new AuthorizationException("Authorization result generation failed.");
        }

        log.info("Step 5 complete: decision={} userId={} action={} path={}",
                authorizationResult.decision(), authContext.getUserId(), authContext.getAction(), authContext.getPath());

        return AuthorizationResponse.buildAuthorizationResponse(authorizationResult);
    }
}