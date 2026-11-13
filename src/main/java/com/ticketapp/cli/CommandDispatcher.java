
package com.ticketapp.cli;

import com.ticketapp.auth.AuthService;
import com.ticketapp.config.AppConfig;
import com.ticketapp.session.AccessControl;
import com.ticketapp.session.AccessDeniedException;
import com.ticketapp.session.Session;

import java.io.Console;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.Scanner;

public class CommandDispatcher {

    @FunctionalInterface
    public interface PasswordReader {
        char[] readPassword();
    }

    private final AuthService auth;
    private final AccessControl access;
    private final PasswordReader passwordReader;
    private Session currentSession;

    // Normal application constructor
    public CommandDispatcher(AuthService auth, AccessControl access) {
        this(auth, access, () -> {
            Console console = System.console();

            if (console == null) {
                throw new IllegalStateException(
                        "Secure password input unavailable");
            }

            return console.readPassword("Password: ");
        });
    }

    // Constructor for testing with a simulated password
    public CommandDispatcher(
            AuthService auth,
            AccessControl access,
            PasswordReader passwordReader) {

        this.auth = Objects.requireNonNull(auth);
        this.access = Objects.requireNonNull(access);
        this.passwordReader = Objects.requireNonNull(passwordReader);
    }

    /**
     * CWE-306: Validate the current session before
     * allowing protected operations.
     */
    private void requireAuthentication() {
        currentSession = access.requireValid(currentSession);
    }

    /**
     * Application wiring is pending database
     * and repository implementation.
     */
    public static CommandDispatcher wire(AppConfig config) {
        throw new UnsupportedOperationException(
                "Application wiring is not implemented yet");
    }

    /**
     * Display numbered menu based on login status.
     */
    private void showMenu(PrintStream out) {
        out.println();
        out.println("===== TICKET MANAGEMENT SYSTEM =====");

        if (currentSession == null) {
            out.println("1. Login");
            out.println("2. Register");
            out.println("3. Help");
            out.println("4. Exit");
        } else {
            out.println("Logged in as: " + currentSession.username());
            out.println("1. Create Ticket");
            out.println("2. View Ticket");
            out.println("3. List My Tickets");
            out.println("4. Search Tickets");
            out.println("5. Change Password");
            out.println("6. Logout");
            out.println("7. Exit");
        }

        out.print("Select option: ");
        out.flush();
    }

    /**
     * Login using AuthService.
     * CWE-204: Use generic failure messages.
     */
    private void handleLogin(Scanner scanner, PrintStream out) {
        out.print("Username: ");
        out.flush();

        if (!scanner.hasNextLine()) {
            return;
        }

        String username = scanner.nextLine().trim();

        if (username.isEmpty()) {
            out.println("Username is required.");
            return;
        }

        char[] password;

        try {
            password = passwordReader.readPassword();
        } catch (IllegalStateException e) {
            out.println("Secure password input unavailable.");
            return;
        }

        if (password == null) {
            out.println("Login cancelled.");
            return;
        }

        try {
            Optional<Session> result =
                    auth.login(username, password);

            if (result.isPresent()) {
                currentSession = result.get();
                out.println("Login successful!");
            } else {
                out.println(AuthService.GENERIC_FAILURE);
            }

        } finally {
            Arrays.fill(password, '\0');
        }
    }

    /**
     * Logout and invalidate the current session.
     */
    private void handleLogout(PrintStream out) {
        if (currentSession != null) {
            auth.logout(currentSession);
            currentSession = null;
        }

        out.println("Logged out successfully.");
    }

    /**
     * Main numbered-menu loop.
     */
    public void runRepl(InputStream in, PrintStream out) {
        Scanner scanner = new Scanner(in);

        while (true) {
            showMenu(out);

            if (!scanner.hasNextLine()) {
                if (currentSession != null) {
                    auth.logout(currentSession);
                    currentSession = null;
                }
                return;
            }

            String choice = scanner.nextLine().trim();

            try {
                if (currentSession == null) {
                    switch (choice) {
                        case "1" -> handleLogin(scanner, out);

                        case "2" -> out.println(
                                "Registration is not implemented yet.");

                        case "3" -> {
                            out.println(
                                    "Login to manage support tickets.");
                            out.println(
                                    "Choose a number from the menu.");
                        }

                        case "4" -> {
                            out.println("Goodbye!");
                            return;
                        }

                        default -> out.println("Invalid option.");
                    }

                } else {

                    // Logout and exit remain available
                    // even when the session expires.
                    if (choice.equals("6")) {
                        handleLogout(out);
                        continue;
                    }

                    if (choice.equals("7")) {
                        handleLogout(out);
                        out.println("Goodbye!");
                        return;
                    }

                    // CWE-306: Authentication required
                    // before protected commands.
                    requireAuthentication();

                    switch (choice) {
                        case "1" -> out.println(
                                "Create Ticket is not implemented yet.");

                        case "2" -> out.println(
                                "View Ticket is not implemented yet.");

                        case "3" -> out.println(
                                "List Tickets is not implemented yet.");

                        case "4" -> out.println(
                                "Search Tickets is not implemented yet.");

                        case "5" -> out.println(
                                "Change Password is not implemented yet.");

                        default -> out.println("Invalid option.");
                    }
                }

            } catch (AccessDeniedException e) {
                currentSession = null;
                out.println(
                        "Session invalid or expired. Please log in.");
            }
        }
    }
}
