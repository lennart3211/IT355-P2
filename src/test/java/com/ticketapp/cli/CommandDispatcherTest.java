
package com.ticketapp.cli;

import com.ticketapp.session.AccessControl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class CommandDispatcherTest {

    private CommandDispatcher dispatcher;
    private AccessControl access;
    private Method authMethod;

    @BeforeEach
    void setUp() throws Exception {
        dispatcher = new CommandDispatcher();
        access = mock(AccessControl.class);

        Field field = CommandDispatcher.class.getDeclaredField("access");
        field.setAccessible(true);
        field.set(dispatcher, access);

        authMethod = CommandDispatcher.class.getDeclaredMethod(
                "requireAuthentication", String.class);
        authMethod.setAccessible(true);
    }

    private void check(String command) throws Exception {
        try {
            authMethod.invoke(dispatcher, command);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception exception) {
                throw exception;
            }
            throw e;
        }
    }

    @Test
    void publicCommandsDoNotRequireLogin() throws Exception {
        for (String command :
                new String[]{"login", "register", "help", "quit"}) {
            check(command);
        }

        verifyNoInteractions(access);
    }

    @Test
    void protectedCommandsRequireSessionValidation() throws Exception {
        for (String command :
                new String[]{"create-ticket", "delete-ticket",
                        "set-role", "logout"}) {
            check(command);
        }

        verify(access, times(4)).requireValid(null);
    }

    @Test
    void missingAuthenticationServiceIsRejected() throws Exception {
        Field field = CommandDispatcher.class.getDeclaredField("access");
        field.setAccessible(true);
        field.set(dispatcher, null);

        assertThrows(IllegalStateException.class,
                () -> check("delete-ticket"));
    }

    @Test
    void nullCommandIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> check(null));
    }

    @Test
    void blankCommandIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> check(" "));
    }

    @Test
    void accessDenialIsPropagated() {
        when(access.requireValid(null))
                .thenThrow(new SecurityException("Access denied"));

        assertThrows(SecurityException.class,
                () -> check("set-role"));
    }
}
