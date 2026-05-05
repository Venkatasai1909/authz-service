package com.venkatasai.auth.authz_service.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizationRequest {

    @NotBlank(message = "access_token is required")
    @JsonProperty("access_token")
    private String accessToken;

    @NotBlank(message = "method is required")
    @Pattern(regexp = "(?i)(GET|POST|PUT|PATCH|DELETE)", message = "method must be one of GET, POST, PUT, PATCH, DELETE")
    private String method;

    @NotBlank(message = "path is required")
    private String path;
}