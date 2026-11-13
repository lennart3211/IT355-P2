package com.ticketapp.user;

import com.ticketapp.config.AppConfig;
import com.ticketapp.db.Database;
import com.ticketapp.model.Role;
import com.ticketapp.model.User;
import com.ticketapp.ticket.FieldEncryptor;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

public class UserRepositoryTest {

    private Database db;
    private UserRepository repo;

    @BeforeEach
    void setUp() throws Exception {
        Path dataDir = Files.createTempDirectory("ticketapp-user-test");

        Constructor<AppConfig> constructor = AppConfig.class.getDeclaredConstructor(
                String.class, String.class, char[].class, byte[].class, Path.class);
        constructor.setAccessible(true);

        AppConfig config = constructor.newInstance(
                "jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1",
                "sa", new char[0], new byte[32], dataDir);

        db = new Database(config);
        db.initSchema();
        repo = new UserRepository(db, new FieldEncryptor(new byte[32]));
    }

    private User newUser(String username) {
        User user = new User();
        user.setUsername(username);
        user.setPasswordHash(new byte[32]);
        user.setSalt(new byte[16]);
        user.setIterations(1000);
        return user;
    }

    @Test
    void insertAndFindByUsername() {
        User saved = repo.insert(newUser("alice"));
        assertTrue(saved.getId() > 0);

        Optional<User> found = repo.findByUsername("alice");
        assertTrue(found.isPresent());
        assertEquals("alice", found.get().getUsername());
        assertEquals(Role.USER, found.get().getRole());
    }

    @Test
    void findByIdReturnsSameUser() {
        User saved = repo.insert(newUser("bob"));
        assertEquals("bob", repo.findById(saved.getId()).orElseThrow().getUsername());
    }

    @Test
    void unknownUserIsEmpty() {
        assertTrue(repo.findByUsername("nobody").isEmpty());
        assertTrue(repo.findByUsername(null).isEmpty());
    }

    @Test
    void sqlInjectionInUsernameIsTreatedAsData() {
        repo.insert(newUser("carol"));
        assertTrue(repo.findByUsername("' OR '1'='1").isEmpty());
    }

    @Test
    void lockStateIsPersisted() {
        User user = repo.insert(newUser("dave"));
        Instant lockedUntil = Instant.ofEpochMilli(Instant.now().toEpochMilli() + 60_000);

        user.setFailedLogins(5);
        user.setLockedUntil(lockedUntil);
        user.setLockoutCount(2);
        repo.updateLockState(user);

        User reloaded = repo.findById(user.getId()).orElseThrow();
        assertEquals(5, reloaded.getFailedLogins());
        assertEquals(lockedUntil, reloaded.getLockedUntil());
        assertEquals(2, reloaded.getLockoutCount());
    }

    @Test
    void roleAndPasswordUpdatesArePersisted() {
        User user = repo.insert(newUser("erin"));

        repo.updateRole(user.getId(), Role.TECHNICIAN);
        repo.updatePassword(user.getId(), new byte[]{1, 2, 3}, new byte[]{4, 5}, 7, true);

        User reloaded = repo.findById(user.getId()).orElseThrow();
        assertEquals(Role.TECHNICIAN, reloaded.getRole());
        assertEquals(7, reloaded.getIterations());
        assertTrue(reloaded.isMustChangePassword());
    }

    @Test
    void emailIsEncryptedAtRest() throws Exception {
        User user = newUser("frank");
        user.setEmail("frank@example.com");
        repo.insert(user);

        try (Connection conn = db.connect();
             PreparedStatement ps = conn.prepareStatement(
                "SELECT email_enc FROM users WHERE username = ?")) {
            ps.setString(1, "frank");
            try (ResultSet rs = ps.executeQuery()) {
                assertTrue(rs.next());
                assertNotEquals("frank@example.com", rs.getString(1));
            }
        }

        assertEquals("frank@example.com",
                repo.findByUsername("frank").orElseThrow().getEmail());
    }
}