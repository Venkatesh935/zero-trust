package com.zerotrust.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when a URL or resolved address is not an allowed scan destination
 * (wrong scheme, port, internal hostname or blocked IP range).
 */
public class UnsafeTargetException extends ApiException {

    public UnsafeTargetException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }
}
