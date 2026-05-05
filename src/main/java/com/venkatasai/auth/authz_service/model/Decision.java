package com.venkatasai.auth.authz_service.model;

import lombok.Getter;

@Getter
public enum Decision {
    ALLOW("allow"),
    DENY("deny");

    private String value;

    Decision(String value){
        this.value = value;
    }
}
