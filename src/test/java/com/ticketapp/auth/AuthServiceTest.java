
package com.ticketapp.auth;

import com.ticketapp.audit.AuditLog;
import com.ticketapp.model.User;
import com.ticketapp.session.Session;
import com.ticketapp.session.SessionManager;
import com.ticketapp.user.PasswordHasher;
import com.ticketapp.user.UserRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class AuthServiceTest {

    private UserRepository users;
    private PasswordHasher hasher;
    private LoginThrottle throttle;
    private SessionManager sessions;
    private AuditLog audit;
    private AuthService auth;

    @BeforeEach
    void setUp() {
        users = mock(UserRepository.class);
        hasher = mock(PasswordHasher.class);
        throttle = new LoginThrottle(Clock.systemUTC());
        sessions = mock(SessionManager.class);
        audit = mock(AuditLog.class);

        auth = new AuthService(
                users, hasher, throttle, sessions, audit);
    }

    private User testUser() {
        User user = new User();
        user.setId(1);
        user.setUsername("kimlay");
        return user;
    }

    @Test
    void unknownUsernameIsRejected() {
        when(users.findByUsername("unknown"))
                .thenReturn(Optional.empty());

        assertTrue(auth.login(
                "unknown", "wrongPassword".toCharArray()).isEmpty());

        verify(hasher).dummyVerify(any(char[].class));
        verify(audit).record(
                eq(AuditLog.Event.LOGIN_FAILURE),
                eq("unknown"),
                eq("Login rejected"));
    }

    @Test
    void incorrectPasswordIsRejected() {
        User user = testUser();

        when(users.findByUsername("kimlay"))
                .thenReturn(Optional.of(user));

        when(hasher.verify(any(char[].class), eq(user)))
                .thenReturn(false);

        assertTrue(auth.login(
                "kimlay", "wrongPassword".toCharArray()).isEmpty());

        assertEquals(1, user.getFailedLogins());
        verify(users).updateLockState(user);
    }

    @Test
    void lockedAccountIsRejected() {
        User user = testUser();
        user.setLockedUntil(
                Clock.systemUTC().instant().plusSeconds(600));

        when(users.findByUsername("kimlay"))
                .thenReturn(Optional.of(user));

        assertTrue(auth.login(
                "kimlay", "password".toCharArray()).isEmpty());

        verify(hasher).dummyVerify(any(char[].class));
        verify(hasher, never()).verify(any(), any());
    }

    @Test
    void successfulLoginResetsFailures() {
        User user = testUser();
        user.setFailedLogins(3);

        when(users.findByUsername("kimlay"))
                .thenReturn(Optional.of(user));

        when(hasher.verify(any(char[].class), eq(user)))
                .thenReturn(true);

        Session session = mock(Session.class);
        when(sessions.create(user)).thenReturn(session);

        Optional<Session> result =
                auth.login("kimlay", "correctPassword".toCharArray());

        assertTrue(result.isPresent());
        assertEquals(0, user.getFailedLogins());
        verify(sessions).create(user);
        verify(users).updateLockState(user);
    }

    @Test
    void nullUsernameIsRejected() {
        assertTrue(auth.login(
                null, "password".toCharArray()).isEmpty());

        verify(hasher).dummyVerify(any(char[].class));
    }

    @Test
    void passwordArrayIsClearedAfterLogin() {
        char[] password = "secretPassword".toCharArray();

        when(users.findByUsername("unknown"))
                .thenReturn(Optional.empty());

        auth.login("unknown", password);

        for (char c : password) {
            assertEquals('\0', c);
        }
    }

    @Test
    void genericFailureMessageIsDefined() {
        assertEquals(
                "Invalid username or password",
                AuthService.GENERIC_FAILURE);
    }
}
