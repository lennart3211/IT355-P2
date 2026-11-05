package com.ticketapp.auth;

import com.ticketapp.audit.AuditLog;
import com.ticketapp.session.Session;
import com.ticketapp.session.SessionManager;
import com.ticketapp.user.PasswordHasher;
import com.ticketapp.user.UserRepository;

import java.util.Optional;

/**
 * Login / logout.  Owner: Kimlay
 *
 * CWE-204 Observable Response Discrepancy: every failure returns the SAME
 *   message, GENERIC_FAILURE, whether the user is missing, locked, or the
 *   password is wrong.
 * CWE-208 Observable Timing Discrepancy: for unknown usernames, still run a
 *   full PBKDF2 hash against DUMMY salt; compare with MessageDigest.isEqual().
 * CWE-307 / CWE-645: delegates throttling to LoginThrottle.
 * CWE-778: logs LOGIN_SUCCESS / LOGIN_FAILURE / ACCOUNT_LOCKED.
 */
public class AuthService {

    public static final String GENERIC_FAILURE = "Invalid username or password";

    private final UserRepository users;
    private final PasswordHasher hasher;
    private final LoginThrottle throttle;
    private final SessionManager sessions;
    private final AuditLog audit;

    public AuthService(UserRepository users, PasswordHasher hasher, LoginThrottle throttle,
                       SessionManager sessions, AuditLog audit) {
        this.users = users;
        this.hasher = hasher;
        this.throttle = throttle;
        this.sessions = sessions;
        this.audit = audit;
    }

    /**
     * @return a session on success; empty on ANY failure (caller prints GENERIC_FAILURE).
     */
    public Optional<Session> login(String username, char[] password) {
        // TODO:
        //  1. look up user (may be absent)
        //  2. if absent -> hasher.dummyVerify(password) for equal timing (CWE-208), return empty
        //  3. if throttle.isLocked(user) -> still do dummy work, return empty (CWE-204: same message)
        //  4. hasher.verify(password, user) -> uses MessageDigest.isEqual
        //  5. on failure: throttle.recordFailure(user); audit LOGIN_FAILURE (+ ACCOUNT_LOCKED if it locked)
        //  6. on success: throttle.reset(user); sessions.create(user); audit LOGIN_SUCCESS
        //  7. always zero out the password array in finally
        throw new UnsupportedOperationException("TODO");
    }

    public void logout(Session session) {
        // TODO: sessions.invalidate(session.token()) (CWE-1465); audit LOGOUT
        throw new UnsupportedOperationException("TODO");
    }
}
