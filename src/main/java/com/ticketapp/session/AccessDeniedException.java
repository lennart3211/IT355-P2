package com.ticketapp.session;

/** Thrown for any authentication/authorization failure. Message must be generic. */
public class AccessDeniedException extends RuntimeException {
    public AccessDeniedException(String message) { super(message); }
}
