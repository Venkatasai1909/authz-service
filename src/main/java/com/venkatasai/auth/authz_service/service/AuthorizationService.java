package com.venkatasai.auth.authz_service.service;

import com.venkatasai.auth.authz_service.dto.request.AuthorizationRequest;
import com.venkatasai.auth.authz_service.dto.response.AuthorizationResponse;

public interface AuthorizationService {
    AuthorizationResponse authorize(AuthorizationRequest request);
}
