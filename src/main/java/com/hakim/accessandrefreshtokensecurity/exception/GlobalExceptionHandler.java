package com.hakim.accessandrefreshtokensecurity.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.nio.file.AccessDeniedException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<?> resourceNotFoundException(ResourceNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                Collections.singletonMap("error", ex.getMessage())
        );
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<?> forbiddenException(AccessDeniedException ex) {

        Map<String,String> errorMap = new HashMap<>();
        errorMap.put("message",ex.getMessage());
        errorMap.put("error", "You are not allowed to access this url.");

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(
                errorMap
        );
    }
}
