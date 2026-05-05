package com.venkatasai.auth.authz_service.util;

public class PathUtils {

    /**
     * Maps an HTTP method to its corresponding authorization action.
     * Case-insensitive: "get", "GET", "Get" all map to "read".
     *
     * @throws IllegalArgumentException for unsupported methods
     */
    public static String mapHttpMethodToAction(String method) {
        if (method == null || method.isBlank()) {
            throw new IllegalArgumentException("HTTP method must not be blank");
        }
        return switch (method.toUpperCase()) {
            case "GET"                    -> "read";
            case "POST", "PUT", "PATCH"   -> "write";
            case "DELETE"                 -> "delete";
            default -> throw new IllegalArgumentException(
                    "Unsupported HTTP method: " + method);
        };
    }

    /**
     * Normalizes a resource path for consistent matching:
     * - Strips leading and trailing slashes
     * - Trims whitespace
     *
     * Examples:
     *   "/wallets/wallet-789/"  → "wallets/wallet-789"
     *   "transactions"          → "transactions"
     */
    public static String normalizePath(String path) {
        if (path == null) {
            return null;
        }
        path = path.trim();
        while (path.startsWith("/")) {
            path = path.substring(1);
        }
        while (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return path;
    }
}