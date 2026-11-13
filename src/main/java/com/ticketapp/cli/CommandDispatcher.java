package com.ticketapp.cli;

import com.ticketapp.audit.AuditLog;
import com.ticketapp.auth.AuthService;
import com.ticketapp.auth.LoginThrottle;
import com.ticketapp.config.AppConfig;
import com.ticketapp.db.Database;
import com.ticketapp.files.AttachmentStore;
import com.ticketapp.files.ExportService;
import com.ticketapp.files.TicketImporter;
import com.ticketapp.model.Role;
import com.ticketapp.model.Ticket;
import com.ticketapp.model.User;
import com.ticketapp.session.AccessControl;
import com.ticketapp.session.AccessDeniedException;
import com.ticketapp.session.Session;
import com.ticketapp.session.SessionManager;
import com.ticketapp.ticket.FieldEncryptor;
import com.ticketapp.ticket.TicketRepository;
import com.ticketapp.ticket.TicketService;
import com.ticketapp.ticket.TicketView;
import com.ticketapp.user.AccountService;
import com.ticketapp.user.PasswordHasher;
import com.ticketapp.user.PasswordPolicy;
import com.ticketapp.user.UserRepository;

import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Scanner;

/**
 * Owner: Kimlay
 * CWE-306: every protected command validates the session first.
 * CWE-204: login failures always show the same generic message.
 */
public class CommandDispatcher {

    @FunctionalInterface
    public interface PasswordReader {
        char[] readPassword();
    }

    private final AuthService auth;
    private final AccessControl access;
    private final PasswordReader passwordReader;
    private final AppServices services;   // null in unit tests that only test login/logout
    private Session currentSession;

    // Login/logout only (used by older unit tests)
    public CommandDispatcher(AuthService auth, AccessControl access) {
        this(auth, access, consolePasswordReader());
    }

    // Login/logout only, with a simulated password (used by unit tests)
    public CommandDispatcher(
            AuthService auth,
            AccessControl access,
            PasswordReader passwordReader) {
        this(auth, access, passwordReader, null);
    }

    // Full application
    public CommandDispatcher(
            AuthService auth,
            AccessControl access,
            PasswordReader passwordReader,
            AppServices services) {

        this.auth = Objects.requireNonNull(auth);
        this.access = Objects.requireNonNull(access);
        this.passwordReader = Objects.requireNonNull(passwordReader);
        this.services = services;
    }

    private static PasswordReader consolePasswordReader() {
        return () -> {
            Console console = System.console();

            if (console == null) {
                throw new IllegalStateException(
                        "Secure password input unavailable");
            }

            return console.readPassword("Password: ");
        };
    }

    /**
     * CWE-306: Validate the current session before
     * allowing protected operations.
     */
    private void requireAuthentication() {
        currentSession = access.requireValid(currentSession);
    }

    /**
     * Builds every service the CLI needs.
     * CWE-455: any failure here propagates to Main, which exits.
     */
    public static CommandDispatcher wire(AppConfig config)
            throws java.sql.SQLException, IOException {
        Objects.requireNonNull(config, "config");

        Database db = new Database(config);
        db.initSchema();

        // CWE-552: protected folders, owner-only where the OS supports it.
        createPrivateDir(config.dataDir());
        createPrivateDir(config.attachmentsDir());
        createPrivateDir(config.exportsDir());

        java.time.Clock clock = java.time.Clock.systemUTC();
        AuditLog audit = new AuditLog();
        FieldEncryptor encryptor = new FieldEncryptor(config.fieldKey());

        UserRepository users = new UserRepository(db, encryptor);
        TicketRepository ticketRepo = new TicketRepository(db, encryptor);
        PasswordHasher hasher = new PasswordHasher();
        LoginThrottle throttle = new LoginThrottle(clock);
        SessionManager sessions = new SessionManager(db, clock);
        AccessControl access = new AccessControl(sessions, audit);

        // CWE-1392: create the admin account on first run (needs TICKETAPP_ADMIN_PASSWORD).
        AccountService accounts = new AccountService(
                users, hasher, new PasswordPolicy(), access, audit);
        accounts.seedAdminIfMissing();

        AppServices services = new AppServices(
                accounts,
                new TicketService(ticketRepo, access, audit),
                ticketRepo,
                users,
                throttle,
                new ExportService(config.exportsDir(), access, audit, ticketRepo),
                new TicketImporter(),
                new AttachmentStore(config.attachmentsDir(), access, ticketRepo),
                audit);

        AuthService auth = new AuthService(users, hasher, throttle, sessions, audit);
        return new CommandDispatcher(auth, access, consolePasswordReader(), services);
    }

    private static void createPrivateDir(Path dir) throws IOException {
        Files.createDirectories(dir);
        if (Files.getFileStore(dir).supportsFileAttributeView("posix")) {
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        }
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
            out.println("Logged in as: " + currentSession.username()
                    + " (" + currentSession.role() + ")");
            out.println("1. Create Ticket");
            out.println("2. View Ticket");
            out.println("3. List My Tickets");
            out.println("4. Search Tickets");
            out.println("5. Change Password");
            out.println("6. Logout");
            out.println("7. Exit");

            if (services != null) {
                out.println("8. Import Tickets (CSV/XML)");
                out.println("9. Attach File to Ticket");

                if (hasRole(Role.TECHNICIAN)) {
                    out.println("--- Technician ---");
                    out.println("10. Claim Ticket");
                    out.println("11. Export All Tickets (CSV)");
                }

                if (hasRole(Role.ADMIN)) {
                    out.println("--- Admin ---");
                    out.println("12. Delete Ticket");
                    out.println("13. Change User Role");
                    out.println("14. Unlock User Account");
                }
            }
        }

        out.print("Select option: ");
        out.flush();
    }

    private boolean hasRole(Role role) {
        return currentSession != null
                && currentSession.role() != null
                && currentSession.role().atLeast(role);
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
     * Register a new USER account (CWE-842: role is never chosen by the user).
     */
    private void handleRegister(Scanner scanner, PrintStream out) {
        if (services == null) {
            out.println("Registration is not implemented yet.");
            return;
        }

        String username = ask(scanner, out, "Choose a username: ");
        if (username == null) {
            return;
        }

        out.println("Choose a password (12+ chars, 3 of: upper, lower, digit, symbol).");
        char[] password = readPassword(out);
        if (password == null) {
            return;
        }

        out.println("Type the password again.");
        char[] confirm = readPassword(out);
        if (confirm == null) {
            Arrays.fill(password, '\0');
            return;
        }

        try {
            if (!Arrays.equals(password, confirm)) {
                out.println("Passwords do not match.");
                return;
            }

            String email = blankToNull(ask(scanner, out, "Email (optional, press Enter to skip): "));
            String phone = blankToNull(ask(scanner, out, "Phone (optional, press Enter to skip): "));

            // register() clears the password array itself.
            User user = services.accounts().register(username, password, email, phone);
            out.println("Account created for " + user.getUsername()
                    + " (role " + user.getRole() + "). You can log in now.");
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(confirm, '\0');
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

    // ---------- logged-in actions ----------

    private void createTicket(Scanner scanner, PrintStream out) {
        String title = ask(scanner, out, "Title: ");
        String description = ask(scanner, out, "Description: ");
        String contact = blankToNull(ask(scanner, out, "Contact info (optional, private): "));
        if (title == null || description == null) {
            return;
        }

        TicketView view = services.tickets().create(currentSession, title, description, contact);
        out.println("Ticket #" + view.id() + " created.");
    }

    private void viewTicket(Scanner scanner, PrintStream out) {
        Long id = askId(scanner, out, "Ticket ID: ");
        if (id == null) {
            return;
        }
        printTicketDetail(out, services.tickets().view(currentSession, id));
    }

    private void listTickets(PrintStream out) {
        printTicketList(out, services.tickets().list(currentSession));
    }

    private void searchTickets(Scanner scanner, PrintStream out) {
        String keyword = ask(scanner, out, "Search title for: ");
        if (keyword == null) {
            return;
        }
        printTicketList(out, services.tickets().search(currentSession, keyword));
    }

    private void changePassword(PrintStream out) {
        out.println("Enter your CURRENT password.");
        char[] oldPassword = readPassword(out);
        if (oldPassword == null) {
            return;
        }

        out.println("Enter your NEW password.");
        char[] newPassword = readPassword(out);
        if (newPassword == null) {
            Arrays.fill(oldPassword, '\0');
            return;
        }

        // changePassword() clears both arrays and ends every session for this user.
        services.accounts().changePassword(currentSession, oldPassword, newPassword);
        currentSession = null;
        out.println("Password changed. Please log in again with your new password.");
    }

    private void importTickets(Scanner scanner, PrintStream out) {
        String file = ask(scanner, out, "Path to .csv or .xml file: ");
        if (file == null) {
            return;
        }

        Path path = Path.of(file);
        List<Ticket> parsed = file.toLowerCase(Locale.ROOT).endsWith(".xml")
                ? services.importer().importXml(currentSession, path)
                : services.importer().importCsv(currentSession, path);

        // Save through TicketService so the normal limits and checks still apply.
        int saved = 0;
        for (Ticket t : parsed) {
            services.tickets().create(currentSession,
                    t.getTitle(), t.getDescription(), blankToNull(t.getContactInfo()));
            saved++;
        }

        services.audit().record(AuditLog.Event.IMPORT_COMPLETED,
                currentSession.username(), "Imported " + saved + " tickets");
        out.println("Imported " + saved + " ticket(s).");
    }

    private void attachFile(Scanner scanner, PrintStream out) {
        Long id = askId(scanner, out, "Ticket ID: ");
        if (id == null) {
            return;
        }
        String file = ask(scanner, out, "Path to file: ");
        if (file == null) {
            return;
        }

        Path stored = services.attachments().attach(currentSession, id, Path.of(file));
        out.println("File attached to ticket #" + id + " as " + stored.getFileName() + ".");
    }

    private void claimTicket(Scanner scanner, PrintStream out) {
        Session tech = access.requireRole(currentSession, Role.TECHNICIAN);
        Long id = askId(scanner, out, "Ticket ID to claim: ");
        if (id == null) {
            return;
        }

        // CWE-367: assignIfUnassigned is a single atomic UPDATE ... WHERE assignee_id IS NULL.
        if (services.ticketRepo().assignIfUnassigned(id, tech.userId())) {
            services.audit().record(AuditLog.Event.TICKET_ASSIGNED,
                    tech.username(), "Ticket " + id + " claimed");
            out.println("Ticket #" + id + " is now assigned to you.");
        } else {
            out.println("Ticket not found or already assigned.");
        }
    }

    private void exportTickets(PrintStream out) {
        Path file = services.exports().export(currentSession);
        out.println("Export saved to: " + file);
    }

    private void deleteTicket(Scanner scanner, PrintStream out) {
        access.requireRole(currentSession, Role.ADMIN);
        Long id = askId(scanner, out, "Ticket ID to delete: ");
        if (id == null) {
            return;
        }
        services.tickets().delete(currentSession, id);
        out.println("Delete request completed for ticket #" + id + ".");
    }

    private void changeRole(Scanner scanner, PrintStream out) {
        access.requireRole(currentSession, Role.ADMIN);
        String username = ask(scanner, out, "Username: ");
        if (username == null) {
            return;
        }
        String roleText = ask(scanner, out, "New role (USER, TECHNICIAN, ADMIN): ");
        if (roleText == null) {
            return;
        }

        Role role;
        try {
            role = Role.valueOf(roleText.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            out.println("Unknown role.");
            return;
        }

        User target = services.users().findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        boolean self = target.getId() == currentSession.userId();
        services.accounts().changeRole(currentSession, target.getId(), role);
        out.println(username + " is now " + role + ". They must log in again.");

        if (self) {
            currentSession = null;   // our own session was revoked
        }
    }

    private void unlockAccount(Scanner scanner, PrintStream out) {
        Session admin = access.requireRole(currentSession, Role.ADMIN);
        String username = ask(scanner, out, "Username to unlock: ");
        if (username == null) {
            return;
        }

        User target = services.users().findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // CWE-645: admins can always lift a lockout.
        services.throttle().adminUnlock(target);
        services.users().updateLockState(target);
        services.audit().record(AuditLog.Event.ACCOUNT_LOCKED,
            admin.username(), "Lockout cleared for " + username);
        out.println(username + " has been unlocked.");
    }

    // ---------- input / output helpers ----------

    private static String ask(Scanner scanner, PrintStream out, String prompt) {
        out.print(prompt);
        out.flush();
        if (!scanner.hasNextLine()) {
            return null;
        }
        return scanner.nextLine().trim();
    }

    private static Long askId(Scanner scanner, PrintStream out, String prompt) {
        String text = ask(scanner, out, prompt);
        if (text == null) {
            return null;
        }
        try {
            return Long.parseLong(text);
        } catch (NumberFormatException e) {
            out.println("Please enter a number.");
            return null;
        }
    }

    private char[] readPassword(PrintStream out) {
        try {
            char[] password = passwordReader.readPassword();
            if (password == null) {
                out.println("Cancelled.");
            }
            return password;
        } catch (IllegalStateException e) {
            out.println("Secure password input unavailable.");
            return null;
        }
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s;
    }

    private static void printTicketList(PrintStream out, List<TicketView> tickets) {
        if (tickets.isEmpty()) {
            out.println("No tickets found.");
            return;
        }
        out.println("ID   | STATUS      | TITLE");
        for (TicketView t : tickets) {
            out.printf("%-4d | %-11s | %s%n", t.id(), t.status(), t.title());
        }
    }

    private static void printTicketDetail(PrintStream out, TicketView t) {
        out.println("Ticket #" + t.id());
        out.println("  Title:       " + t.title());
        out.println("  Status:      " + t.status());
        out.println("  Description: " + t.description());
        out.println("  Assigned to: " + (t.assigneeId() == null ? "nobody" : "user " + t.assigneeId()));
        // CWE-359: TicketView hides contact info from people who shouldn't see it.
        out.println("  Contact:     " + (t.contactInfo() == null ? "(hidden)" : t.contactInfo()));
    }

    /**
     * Run one logged-in command. Returns false if the user chose Exit.
     */
    private boolean handleLoggedIn(String choice, Scanner scanner, PrintStream out) {
        // Logout and exit remain available even when the session expires.
        if (choice.equals("6")) {
            handleLogout(out);
            return true;
        }

        if (choice.equals("7")) {
            handleLogout(out);
            out.println("Goodbye!");
            return false;
        }

        // CWE-306: Authentication required before protected commands.
        // If this throws, runRepl() treats the session as expired.
        requireAuthentication();

        if (services == null) {
            switch (choice) {
                case "1" -> out.println("Create Ticket is not implemented yet.");
                case "2" -> out.println("View Ticket is not implemented yet.");
                case "3" -> out.println("List Tickets is not implemented yet.");
                case "4" -> out.println("Search Tickets is not implemented yet.");
                case "5" -> out.println("Change Password is not implemented yet.");
                default -> out.println("Invalid option.");
            }
            return true;
        }

        try {
            switch (choice) {
                case "1" -> createTicket(scanner, out);
                case "2" -> viewTicket(scanner, out);
                case "3" -> listTickets(out);
                case "4" -> searchTickets(scanner, out);
                case "5" -> changePassword(out);
                case "8" -> importTickets(scanner, out);
                case "9" -> attachFile(scanner, out);
                case "10" -> { if (hasRole(Role.TECHNICIAN)) claimTicket(scanner, out); else out.println("Invalid option."); }
                case "11" -> { if (hasRole(Role.TECHNICIAN)) exportTickets(out); else out.println("Invalid option."); }
                case "12" -> { if (hasRole(Role.ADMIN)) deleteTicket(scanner, out); else out.println("Invalid option."); }
                case "13" -> { if (hasRole(Role.ADMIN)) changeRole(scanner, out); else out.println("Invalid option."); }
                case "14" -> { if (hasRole(Role.ADMIN)) unlockAccount(scanner, out); else out.println("Invalid option."); }
                default -> out.println("Invalid option.");
            }
        } catch (AccessDeniedException e) {
            // Generic message only ("Access denied" / "Ticket not found").
            out.println(e.getMessage());
        } catch (IllegalArgumentException | IllegalStateException
                 | UncheckedIOException | SecurityException e) {
            out.println("Error: " + e.getMessage());
        }
        return true;
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

                        case "2" -> {
                            try {
                                handleRegister(scanner, out);
                            } catch (IllegalArgumentException | IllegalStateException e) {
                                out.println("Error: " + e.getMessage());
                            }
                        }

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

                } else if (!handleLoggedIn(choice, scanner, out)) {
                    return;
                }

            } catch (AccessDeniedException e) {
                currentSession = null;
                out.println(
                        "Session invalid or expired. Please log in.");
            }
        }
    }
}