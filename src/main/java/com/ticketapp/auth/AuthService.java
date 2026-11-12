
package com.ticketapp.auth;

import com.ticketapp.audit.AuditLog;
import com.ticketapp.model.User;
import com.ticketapp.session.Session;
import com.ticketapp.session.SessionManager;
import com.ticketapp.user.PasswordHasher;
import com.ticketapp.user.UserRepository;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * Owner: Kimlay
 * CWE-204: Generic authentication failure responses.
 * CWE-208: Similar password verification work.
 * CWE-307 / CWE-645: Login throttling.
 */
public class AuthService {

    public static final String GENERIC_FAILURE =
            "Invalid username or password";

    private final UserRepository users;
    private final PasswordHasher hasher;
    private final LoginThrottle throttle;
    private final SessionManager sessions;
    private final AuditLog audit;

    public AuthService(
            UserRepository users,
            PasswordHasher hasher,
            LoginThrottle throttle,
            SessionManager sessions,
            AuditLog audit) {

        this.users = Objects.requireNonNull(users);
        this.hasher = Objects.requireNonNull(hasher);
        this.throttle = Objects.requireNonNull(throttle);
        this.sessions = Objects.requireNonNull(sessions);
        this.audit = Objects.requireNonNull(audit);
    }

    public Optional<Session> login(
            String username, char[] password) {

                if (password == null) {
                    password = new char[0];
                }

        try {
            Optional<User> found = username == null
                    ? Optional.empty()
                    : users.findByUsername(username);

            // Unknown username.
            if (found.isEmpty()) {
                hasher.dummyVerify(password);

                audit.record(
                    AuditLog.Event.LOGIN_FAILURE,
                    username == null ? "anonymous" : username,
                    "Login rejected");

                return Optional.empty();
            }

            User user = found.get();

            // Account is temporarily locked.
            if (throttle.isLocked(user)) {
                hasher.dummyVerify(password);

                audit.record(
                        AuditLog.Event.LOGIN_FAILURE,
                        user.getUsername(),
                        "Login rejected");

                return Optional.empty();
            }

            // Incorrect password.
            if (!hasher.verify(password, user)) {

                boolean locked =
                        throttle.recordFailure(user);

                users.updateLockState(user);

                audit.record(
                        AuditLog.Event.LOGIN_FAILURE,
                        user.getUsername(),
                        "Login rejected");

                if (locked) {
                    audit.record(
                            AuditLog.Event.ACCOUNT_LOCKED,
                            user.getUsername(),
                            "Temporary lockout");
                }

                return Optional.empty();
            }

            // Successful authentication.
            throttle.reset(user);
            users.updateLockState(user);

            Session session = sessions.create(user);

            audit.record(
                    AuditLog.Event.LOGIN_SUCCESS,
                    user.getUsername(),
                    "Login succeeded");

            return Optional.of(session);

        } finally {
            Arrays.fill(password, '\0');
        }
    }

    public void logout(Session session) {
        if (session == null) {
            return;
        }

        sessions.invalidate(session.token());

        audit.record(
                AuditLog.Event.LOGOUT,
                session.username(),
                "Logout");
    }
}
