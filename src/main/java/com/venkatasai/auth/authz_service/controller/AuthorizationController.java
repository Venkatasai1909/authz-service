package com.venkatasai.auth.authz_service.controller;

import com.venkatasai.auth.authz_service.dto.request.AuthorizationRequest;
import com.venkatasai.auth.authz_service.dto.response.AuthorizationResponse;
import com.venkatasai.auth.authz_service.service.AuthorizationService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;

@AllArgsConstructor
@RequestMapping("/api/authz")
public class AuthorizationController {
    private final AuthorizationService authorizationService;

    public ResponseEntity<AuthorizationResponse> authorize(AuthorizationRequest request){
        AuthorizationResponse authorizationResponse = authorizationService.authorize(request);
        return ResponseEntity.ok(authorizationResponse);

    }
}
