package com.venkatasai.auth.authz_service.model;

import lombok.Getter;

@Getter
public class Permission {
    private Integer id;
    private String userId;
    private String action;
    private String resource;
    private String effect;

    public boolean isAllow(){
        return Decision.ALLOW.getValue().equals(this.effect);
    }

    public boolean isDeny(){
        return Decision.DENY.getValue().equals(this.effect);
    }

    public Decision getDecision(){
        return isAllow() ? Decision.ALLOW : Decision.DENY;
    }
}