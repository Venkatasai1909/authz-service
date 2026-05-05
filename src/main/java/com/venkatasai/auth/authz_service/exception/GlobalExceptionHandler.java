package com.venkatasai.auth.authz_service.exception;


import com.venkatasai.auth.authz_service.dto.response.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthException(
            AuthenticationException ex,
            HttpServletRequest request) {

        ErrorResponse error = new ErrorResponse(
                "AUTH_001",
                ex.getMessage(),
                Instant.now(),
                request.getRequestURI()
        );

        return new ResponseEntity<>(error, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(AuthorizationException.class)
    public ResponseEntity<ErrorResponse> handleAuthorizationException(
            AuthorizationException ex,
            HttpServletRequest request) {

        ErrorResponse error = new ErrorResponse(
                "AUTHZ_001",
                ex.getMessage(),
                Instant.now(),
                request.getRequestURI()
        );

        return new ResponseEntity<>(error, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleBadRequest(
            IllegalArgumentException ex,
            HttpServletRequest request) {

        ErrorResponse error = new ErrorResponse(
                "REQ_001",
                ex.getMessage(),
                Instant.now(),
                request.getRequestURI()
        );

        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneric(
            Exception ex,
            HttpServletRequest request) {

        ErrorResponse error = new ErrorResponse(
                "GEN_001",
                "Something went wrong",
                Instant.now(),
                request.getRequestURI()
        );

        return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}