
package com.ticketapp.auth;

import com.ticketapp.config.AppConfig;
import com.ticketapp.model.User;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Owner: Kimlay
 * CWE-307: Limit failed login attempts.
 * CWE-645: Temporary and bounded account lockouts.
 */
public class LoginThrottle {

    private final Clock clock;

    public LoginThrottle(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    public boolean isLocked(User user) {
        Instant until = user.getLockedUntil();
        return until != null && clock.instant().isBefore(until);
    }

    // Returns true when a new lockout occurs.
    public boolean recordFailure(User user) {

        // Failed attempts during lockout do not extend it.
        if (isLocked(user)) {
            return false;
        }

        int failures = user.getFailedLogins() + 1;

        if (failures < AppConfig.MAX_FAILED_LOGINS) {
            user.setFailedLogins(failures);
            return false;
        }

        Duration duration =
                nextLockDuration(user.getLockoutCount());

        user.setLockedUntil(clock.instant().plus(duration));
        user.setLockoutCount(user.getLockoutCount() + 1);
        user.setFailedLogins(0);

        return true;
    }

    // Reset after successful login.
    public void reset(User user) {
        user.setFailedLogins(0);
        user.setLockedUntil(null);
        user.setLockoutCount(0);
    }

    // Caller must verify ADMIN authorization first.
    public void adminUnlock(User user) {
        reset(user);
    }

    // 1, 2, 4, 8, 15 minutes maximum.
    Duration nextLockDuration(int count) {

        if (count >= 20) {
            return AppConfig.LOCKOUT_MAX;
        }

        long factor = 1L << Math.max(0, count);

        Duration duration =
                AppConfig.LOCKOUT_BASE.multipliedBy(factor);

        return duration.compareTo(AppConfig.LOCKOUT_MAX) > 0
                ? AppConfig.LOCKOUT_MAX
                : duration;
    }
}
