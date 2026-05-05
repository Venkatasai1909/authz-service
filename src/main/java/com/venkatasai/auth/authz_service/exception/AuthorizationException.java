package com.venkatasai.auth.authz_service.exception;

public class AuthorizationException extends RuntimeException{
    public AuthorizationException(String messsage){
        super(messsage);
    }
}
