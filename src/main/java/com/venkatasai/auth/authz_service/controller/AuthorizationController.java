package com.venkatasai.auth.authz_service.controller;

import com.venkatasai.auth.authz_service.dto.request.AuthorizationRequest;
import com.venkatasai.auth.authz_service.dto.response.AuthorizationResponse;
import com.venkatasai.auth.authz_service.service.AuthorizationService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("")
@AllArgsConstructor
public class AuthorizationController {
    private final AuthorizationService authorizationService;

    @PostMapping("/authorize")
    public ResponseEntity<AuthorizationResponse> authorize(@Valid @RequestBody AuthorizationRequest request) {
        AuthorizationResponse response = authorizationService.authorize(request);
        return ResponseEntity.ok(response);
    }
}