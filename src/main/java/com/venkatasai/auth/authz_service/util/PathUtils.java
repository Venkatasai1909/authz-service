package com.venkatasai.auth.authz_service.util;

public class PathUtils {

    public static String mapHttpMethodToAction(String method){
        return switch (method){
            case "GET" -> "read";
            case "PATCH", "PUT", "POST" -> "write";
            case "DELETE" -> "delete";
            default -> throw new IllegalArgumentException("Method to action not found");
        };
    }
}
