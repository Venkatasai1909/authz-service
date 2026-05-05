package com.venkatasai.auth.authz_service.exception;

public class AuthenticationException extends RuntimeException{
    public AuthenticationException(String messsage){
        super(messsage);
    }
}
