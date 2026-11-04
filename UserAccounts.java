/*
 * FEATURE 2: User accounts and passwords
 * Initial owner: Caleb Clauson
 *
 * WHAT TO CREATE:
 * - Account registration and a documented password policy.
 * - Password hashing with a unique salt and sufficient computational effort.
 * - Password verification without storing plaintext passwords.
 * - Password changes that first verify the current password.
 * - External loading of any required database/service credentials.
 * - First-admin setup without a shared default password.
 *
 * SIX CWEs:
 * 916   Use of Password Hash With Insufficient Computational Effort
 * 256   Plaintext Storage of a Password
 * 521   Weak Password Requirements
 * 620   Unverified Password Change
 * 798   Use of Hard-coded Credentials
 * 1392  Use of Default Credentials
 *
 * COORDINATE WITH: Login for verification; SessionsAndRoles for default user roles
 * and revoking sessions after password changes; AssignmentAndAudit for events.
 */
public class UserAccounts {
    // Add your own fields and methods here.
}
