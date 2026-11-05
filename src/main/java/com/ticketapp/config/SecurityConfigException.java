package com.ticketapp.config;

/** Thrown when required security configuration is missing or invalid (CWE-455). */
public class SecurityConfigException extends Exception {
    public SecurityConfigException(String message) { super(message); }
    public SecurityConfigException(String message, Throwable cause) { super(message, cause); }
}
