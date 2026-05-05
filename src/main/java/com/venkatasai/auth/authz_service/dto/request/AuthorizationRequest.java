package com.venkatasai.auth.authz_service.dto.request;


import com.nimbusds.jose.shaded.gson.annotations.SerializedName;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class AuthorizationRequest {
    @NotBlank(message = "Access token is mandatory")
    @SerializedName(value = "access_token")
    private String accessToken;

    @NotBlank(message = "HTTP Method is required")
    private String method;

    @NotBlank(message = "API Path is required")
    private String path;
}