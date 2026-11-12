
package com.ticketapp.user;

import com.ticketapp.audit.AuditLog;
import com.ticketapp.model.Role;
import com.ticketapp.model.User;
import com.ticketapp.session.AccessControl;
import com.ticketapp.session.Session;

/**
 * Registration, password change, role change. Owner: Caleb (roles: Luke)
 *
 * CWE-521: PasswordPolicy on register and change.
 * CWE-620 Unverified Password Change: changePassword requires the OLD password.
 * CWE-1392 Default Credentials: seedAdminIfMissing() sets mustChangePassword=true;
 *   CommandDispatcher blocks every command except change-password until it's cleared.
 * CWE-842 Incorrect Group: register() always assigns Role.DEFAULT (USER),
 *   regardless of any input.
 * CWE-749 / CWE-306: changeRole() checks ADMIN inside the service, not just in the CLI.
 * CWE-778: PASSWORD_CHANGED, ROLE_CHANGED logged.
 */
public class AccountService {

    private final UserRepository users;
    private final PasswordHasher hasher;
    private final PasswordPolicy policy;
    private final AccessControl access;
    private final AuditLog audit;

    public AccountService(UserRepository users, PasswordHasher hasher,
                          PasswordPolicy policy, AccessControl access,
                          AuditLog audit) {
        this.users = users;
        this.hasher = hasher;
        this.policy = policy;
        this.access = access;
        this.audit = audit;
    }

    public User register(String username, char[] password,
                         String email, String phone) {

        if (username == null || !username.matches("[A-Za-z0-9._-]{3,32}")) {
            if (password != null) {
                java.util.Arrays.fill(password, '\0');
            }

            throw new IllegalArgumentException(
                    "Username must be 3-32 characters using letters, numbers, '.', '_' or '-'");
        }

        if (password == null) {
            throw new IllegalArgumentException("Password is required");
        }

        try {
            if (users.findByUsername(username).isPresent()) {
                throw new IllegalArgumentException("Username is unavailable");
            }

            java.util.List<String> problems =
                    policy.validate(password, username);

            if (!problems.isEmpty()) {
                throw new IllegalArgumentException(
                        String.join("; ", problems));
            }

            PasswordHasher.HashResult result = hasher.hash(password);

            User user = new User();
            user.setUsername(username);
            user.setPasswordHash(result.hash());
            user.setSalt(result.salt());
            user.setIterations(result.iterations());
            user.setEmail(email);
            user.setPhone(phone);

            // Never accept a role from registration input.
            // Every new account starts least-privileged.
            user.setRole(Role.DEFAULT);

            user.setMustChangePassword(false);

            return users.insert(user);

        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    public void changePassword(Session session, char[] oldPassword, char[] newPassword) {
        try {
            Session validSession = access.requireValid(session);
            User user = users.findById(validSession.userId())
                    .orElseThrow(() -> new IllegalArgumentException("User not found"));

            if (oldPassword == null || !hasher.verify(oldPassword, user)) {
                throw new IllegalArgumentException("Current password is incorrect");
            }

            var problems = policy.validate(newPassword, user.getUsername());
            if (!problems.isEmpty()) {
                throw new IllegalArgumentException(String.join("; ", problems));
            }

            if (java.util.Arrays.equals(oldPassword, newPassword)) {
                throw new IllegalArgumentException("Choose a different password");
            }

            var result = hasher.hash(newPassword);
            users.updatePassword(user.getId(), result.hash(), result.salt(),
                    result.iterations(), false);

            access.invalidateAllForUser(user.getId());
            audit.record(AuditLog.Event.PASSWORD_CHANGED,
                    user.getUsername(), "Password changed");
        } finally {
            if (oldPassword != null) {
                java.util.Arrays.fill(oldPassword, '\0');
            }
            if (newPassword != null) {
                java.util.Arrays.fill(newPassword, '\0');
            }
        }
    }
    
    public void changeRole(Session session, long targetUserId,
                           Role newRole) {

        Session actor = access.requireRole(session, Role.ADMIN);

        if (newRole == null) {
            throw new IllegalArgumentException("A valid role is required");
        }

        User target = users.findById(targetUserId)
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found"));

        Role oldRole = target.getRole();

        if (oldRole == newRole) {
            return;
        }

        // Revoke old role snapshots before persisting the new role.
        // If persistence fails, the user is merely required to log in again;
        // stale privileges are never retained.
        access.invalidateAllForUser(targetUserId);

        users.updateRole(targetUserId, newRole);

        audit.record(
                AuditLog.Event.ROLE_CHANGED,
                actor.username(),
                "User " + targetUserId
                        + " role changed from " + oldRole
                        + " to " + newRole
        );
    }

    /**
     * Creates the initial admin on first run. The initial password comes from an env var
     * or is randomly generated and printed ONCE; mustChangePassword = true (CWE-1392, CWE-798).
     */
    public void seedAdminIfMissing() {
        throw new UnsupportedOperationException("TODO");
    }
}