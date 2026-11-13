
package com.ticketapp.cli;

import com.ticketapp.auth.AuthService;
import com.ticketapp.session.AccessControl;
import com.ticketapp.session.AccessDeniedException;

import org.junit.jupiter.api.Test;
import com.ticketapp.model.Role;
import com.ticketapp.session.Session;
import java.time.Instant;
import java.util.Optional;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class CommandDispatcherTest {

    @Test
    void menuShowsLoginBeforeAuthentication() {
        AuthService auth = mock(AuthService.class);
        AccessControl access = mock(AccessControl.class);

        CommandDispatcher dispatcher =
                new CommandDispatcher(auth, access);

        String output = run(dispatcher, "4\n");

        assertTrue(output.contains("1. Login"));
        assertTrue(output.contains("2. Register"));
        assertTrue(output.contains("Goodbye!"));
    }

    @Test
    void helpWorksWithoutLogin() {
        AuthService auth = mock(AuthService.class);
        AccessControl access = mock(AccessControl.class);

        CommandDispatcher dispatcher =
                new CommandDispatcher(auth, access);

        String output = run(dispatcher, "3\n4\n");

        assertTrue(output.contains("Login to manage support tickets."));
        verifyNoInteractions(access);
    }

    @Test
    void invalidOptionDoesNotBypassAuthentication() {
        AuthService auth = mock(AuthService.class);
        AccessControl access = mock(AccessControl.class);

        CommandDispatcher dispatcher =
                new CommandDispatcher(auth, access);

        String output = run(dispatcher, "9\n4\n");

        assertTrue(output.contains("Invalid option."));
        verifyNoInteractions(access);
    }

    @Test
    void exitWithoutLoginDoesNotCrash() {
        AuthService auth = mock(AuthService.class);
        AccessControl access = mock(AccessControl.class);

        CommandDispatcher dispatcher =
                new CommandDispatcher(auth, access);

        String output = run(dispatcher, "4\n");

        assertTrue(output.contains("Goodbye!"));
        verify(auth, never()).logout(any());
    }

    private String run(CommandDispatcher dispatcher, String commands) {
        ByteArrayInputStream input = new ByteArrayInputStream(
                commands.getBytes(StandardCharsets.UTF_8));

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        dispatcher.runRepl(input, new PrintStream(output));

        return output.toString(StandardCharsets.UTF_8);
    }

@Test
void successfulLoginAndLogout() {
    AuthService auth = mock(AuthService.class);
    AccessControl access = mock(AccessControl.class);

    Session session = new Session(
            "test-token", 1L, "kimlay",
            Role.USER, Instant.now()
    );

    when(auth.login(eq("kimlay"), any(char[].class)))
            .thenReturn(Optional.of(session));

    CommandDispatcher dispatcher = new CommandDispatcher(
            auth, access,
            () -> "TestPassword123!".toCharArray()
    );

    String output = run(dispatcher, "1\nkimlay\n6\n4\n");

    assertTrue(output.contains("Login successful!"));
    assertTrue(output.contains("Logged in as: kimlay"));
    assertTrue(output.contains("Logged out successfully."));

    verify(auth).logout(session);
}

@Test
void failedLoginShowsGenericMessage() {
    AuthService auth = mock(AuthService.class);
    AccessControl access = mock(AccessControl.class);

    when(auth.login(eq("unknown"), any(char[].class)))
            .thenReturn(Optional.empty());

    CommandDispatcher dispatcher = new CommandDispatcher(
            auth, access,
            () -> "WrongPassword123!".toCharArray()
    );

    String output = run(dispatcher, "1\nunknown\n4\n");

    assertTrue(output.contains(AuthService.GENERIC_FAILURE));
    assertFalse(output.contains("Login successful!"));
}

@Test
void protectedCommandRequiresValidSession() {
    AuthService auth = mock(AuthService.class);
    AccessControl access = mock(AccessControl.class);

    Session session = new Session(
            "test-token", 1L, "kimlay",
            Role.USER, Instant.now()
    );

    when(auth.login(eq("kimlay"), any(char[].class)))
            .thenReturn(Optional.of(session));

    when(access.requireValid(session)).thenReturn(session);

    CommandDispatcher dispatcher = new CommandDispatcher(
            auth, access,
            () -> "TestPassword123!".toCharArray()
    );

    String output = run(dispatcher, "1\nkimlay\n1\n6\n4\n");

    assertTrue(output.contains("Login successful!"));
    assertTrue(output.contains(
            "Create Ticket is not implemented yet."));

    verify(access).requireValid(session);
    verify(auth).logout(session);
}

@Test
void logoutReturnsUserToPublicMenu() {
    AuthService auth = mock(AuthService.class);
    AccessControl access = mock(AccessControl.class);

    Session session = new Session(
            "test-token", 1L, "kimlay",
            Role.USER, Instant.now()
    );

    when(auth.login(eq("kimlay"), any(char[].class)))
            .thenReturn(Optional.of(session));

    CommandDispatcher dispatcher = new CommandDispatcher(
            auth, access,
            () -> "TestPassword123!".toCharArray()
    );

    String output = run(dispatcher, "1\nkimlay\n6\n4\n");

    assertTrue(output.contains("Logged out successfully."));
    assertTrue(output.contains("1. Login"));

    verify(auth).logout(session);
}

@Test
void expiredSessionCannotAccessProtectedCommands() {
    AuthService auth = mock(AuthService.class);
    AccessControl access = mock(AccessControl.class);

    Session session = new Session(
            "test-token",
            1L,
            "kimlay",
            Role.USER,
            Instant.now()
    );

    // Simulate a successful login.
    when(auth.login(eq("kimlay"), any(char[].class)))
            .thenReturn(Optional.of(session));

    // Simulate an expired or invalid session.
    when(access.requireValid(session))
            .thenThrow(
                    new AccessDeniedException("Access denied"));

    CommandDispatcher dispatcher = new CommandDispatcher(
            auth,
            access,
            () -> "TestPassword123!".toCharArray()
    );

    // Login, try to create a ticket, then exit.
    String output = run(dispatcher, "1\nkimlay\n1\n4\n");

    assertTrue(output.contains("Login successful!"));

    assertTrue(output.contains(
            "Session invalid or expired. Please log in."));

    // The protected ticket command must not execute.
    assertFalse(output.contains(
            "Create Ticket is not implemented yet."));

    // The user should return to the public menu.
    assertTrue(output.contains("1. Login"));

    verify(access).requireValid(session);
}

}
