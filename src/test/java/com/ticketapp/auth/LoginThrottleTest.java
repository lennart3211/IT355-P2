
package com.ticketapp.auth;

import com.ticketapp.config.AppConfig;
import com.ticketapp.model.User;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.*;

public class LoginThrottleTest {

    private final Instant start =
            Instant.parse("2026-01-01T12:00:00Z");

    private LoginThrottle throttleAt(Instant time) {
        return new LoginThrottle(
                Clock.fixed(time, ZoneOffset.UTC));
    }

    @Test
    void firstLockoutUsesBaseDuration() {
        assertEquals(
                AppConfig.LOCKOUT_BASE,
                throttleAt(start).nextLockDuration(0)
        );
    }

    @Test
    void repeatedLockoutsIncreaseDuration() {
        LoginThrottle throttle = throttleAt(start);

        assertEquals(
                AppConfig.LOCKOUT_BASE.multipliedBy(2),
                throttle.nextLockDuration(1)
        );

        assertEquals(
                AppConfig.LOCKOUT_BASE.multipliedBy(4),
                throttle.nextLockDuration(2)
        );
    }

    @Test
    void lockoutDurationNeverExceedsMaximum() {
        LoginThrottle throttle = throttleAt(start);

        for (int i = 0; i < 30; i++) {
            Duration duration = throttle.nextLockDuration(i);

            assertTrue(
                    duration.compareTo(AppConfig.LOCKOUT_MAX) <= 0
            );
        }
    }

    @Test
    void largeLockoutCountUsesMaximumDuration() {
        assertEquals(
                AppConfig.LOCKOUT_MAX,
                throttleAt(start).nextLockDuration(20)
        );
    }

    @Test
    void failedAttemptsAreCounted() {
        User user = new User();
        LoginThrottle throttle = throttleAt(start);

        assertFalse(throttle.recordFailure(user));
        assertEquals(1, user.getFailedLogins());
        assertFalse(throttle.isLocked(user));
    }

    @Test
    void accountLocksAfterMaximumFailures() {
        User user = new User();
        LoginThrottle throttle = throttleAt(start);

        for (int i = 0; i < AppConfig.MAX_FAILED_LOGINS - 1; i++) {
            assertFalse(throttle.recordFailure(user));
        }

        assertFalse(throttle.isLocked(user));
        assertTrue(throttle.recordFailure(user));

        assertTrue(throttle.isLocked(user));
        assertEquals(0, user.getFailedLogins());
        assertEquals(1, user.getLockoutCount());
        assertEquals(
                start.plus(AppConfig.LOCKOUT_BASE),
                user.getLockedUntil()
        );
    }

    @Test
    void failuresDuringLockoutDoNotExtendIt() {
        User user = new User();
        LoginThrottle throttle = throttleAt(start);

        for (int i = 0; i < AppConfig.MAX_FAILED_LOGINS; i++) {
            throttle.recordFailure(user);
        }

        Instant originalEnd = user.getLockedUntil();

        assertFalse(throttle.recordFailure(user));
        assertEquals(originalEnd, user.getLockedUntil());
        assertEquals(1, user.getLockoutCount());
    }

    @Test
    void lockoutExpiresAfterDuration() {
        User user = new User();
        LoginThrottle throttle = throttleAt(start);

        for (int i = 0; i < AppConfig.MAX_FAILED_LOGINS; i++) {
            throttle.recordFailure(user);
        }

        assertTrue(throttle.isLocked(user));

        LoginThrottle later = throttleAt(user.getLockedUntil());

        assertFalse(later.isLocked(user));
    }

    @Test
    void resetClearsFailureAndLockoutState() {
        User user = new User();
        LoginThrottle throttle = throttleAt(start);

        for (int i = 0; i < AppConfig.MAX_FAILED_LOGINS; i++) {
            throttle.recordFailure(user);
        }

        throttle.reset(user);

        assertEquals(0, user.getFailedLogins());
        assertEquals(0, user.getLockoutCount());
        assertNull(user.getLockedUntil());
        assertFalse(throttle.isLocked(user));
    }

    @Test
    void adminUnlockClearsLockout() {
        User user = new User();
        LoginThrottle throttle = throttleAt(start);

        for (int i = 0; i < AppConfig.MAX_FAILED_LOGINS; i++) {
            throttle.recordFailure(user);
        }

        assertTrue(throttle.isLocked(user));

        throttle.adminUnlock(user);

        assertFalse(throttle.isLocked(user));
        assertEquals(0, user.getFailedLogins());
        assertEquals(0, user.getLockoutCount());
        assertNull(user.getLockedUntil());
    }
}
