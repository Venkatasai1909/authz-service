package com.venkatasai.auth.authz_service.authentication;

import com.venkatasai.auth.authz_service.model.DecodedToken;

public interface JwtDecoder {
    DecodedToken decode(String token);
}
