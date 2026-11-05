package com.ticketapp.auth;

import com.ticketapp.model.User;

import java.time.Clock;
import java.time.Duration;

/**
 * Owner: Kimlay
 *
 * CWE-307 Excessive Authentication Attempts: lock after MAX_FAILED_LOGINS (5).
 * CWE-645 Overly Restrictive Lockout: the lock is TEMPORARY and BOUNDED
 *   (exponential backoff capped at LOCKOUT_MAX), and an admin can unlock.
 *   An attacker must not be able to lock a real user out forever.
 *
 * Clock is injected so tests can fast-forward time.
 */
public class LoginThrottle {

    private final Clock clock;

    public LoginThrottle(Clock clock) {
        this.clock = clock;
    }

    public boolean isLocked(User user) {
        // TODO: lockedUntil != null && now < lockedUntil
        throw new UnsupportedOperationException("TODO");
    }

    /** @return true if this failure caused a new lockout. */
    public boolean recordFailure(User user) {
        // TODO: increment failedLogins; if >= MAX_FAILED_LOGINS, set lockedUntil = now + nextLockDuration
        //       and increment lockoutCount; persist via UserRepository
        throw new UnsupportedOperationException("TODO");
    }

    public void reset(User user) {
        // TODO: failedLogins = 0, lockedUntil = null (consider decaying lockoutCount over time)
        throw new UnsupportedOperationException("TODO");
    }

    /** Recovery path (CWE-645): admin-initiated unlock. Caller must check ADMIN role. */
    public void adminUnlock(User user) {
        // TODO
        throw new UnsupportedOperationException("TODO");
    }

    Duration nextLockDuration(int lockoutCount) {
        // TODO: LOCKOUT_BASE * 2^lockoutCount, capped at LOCKOUT_MAX
        throw new UnsupportedOperationException("TODO");
    }
}
