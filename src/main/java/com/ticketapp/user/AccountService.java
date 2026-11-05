package com.ticketapp.user;

import com.ticketapp.audit.AuditLog;
import com.ticketapp.model.Role;
import com.ticketapp.model.User;
import com.ticketapp.session.AccessControl;
import com.ticketapp.session.Session;

/**
 * Registration, password change, role change.  Owner: Caleb (roles: Luke)
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

    public AccountService(UserRepository users, PasswordHasher hasher, PasswordPolicy policy,
                          AccessControl access, AuditLog audit) {
        this.users = users;
        this.hasher = hasher;
        this.policy = policy;
        this.access = access;
        this.audit = audit;
    }

    public User register(String username, char[] password, String email, String phone) {
        // TODO: validate username format; policy.validate(); hasher.hash();
        //       user.setRole(Role.DEFAULT)  <-- never from input (CWE-842)
        throw new UnsupportedOperationException("TODO");
    }

    public void changePassword(Session session, char[] oldPassword, char[] newPassword) {
        // TODO: access.requireValid(session); verify oldPassword (CWE-620);
        //       policy.validate(newPassword); hash; save with mustChange=false; audit PASSWORD_CHANGED
        throw new UnsupportedOperationException("TODO");
    }

    public void changeRole(Session session, long targetUserId, Role newRole) {
        // TODO: access.requireRole(session, Role.ADMIN)  (CWE-749 / CWE-306)
        //       users.updateRole(); audit ROLE_CHANGED with old -> new
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Creates the initial admin on first run. The initial password comes from an env var
     * or is randomly generated and printed ONCE; mustChangePassword = true (CWE-1392, CWE-798).
     */
    public void seedAdminIfMissing() {
        throw new UnsupportedOperationException("TODO");
    }
}
