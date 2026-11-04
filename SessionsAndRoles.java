/*
 * FEATURE 3: Sessions and roles
 * Owner: To be claimed
 *
 * WHAT TO CREATE:
 * - A way to track the current logged-in user and their role.
 * - Secure random session tokens after successful authentication.
 * - Session expiry checks and logout that revokes the old token.
 * - Ticket ownership/permission checks before viewing or changing records.
 * - USER as the ordinary registration role, with controlled privilege changes.
 * - Role checks for dangerous operations even when called outside the menu.
 *
 * SIX CWEs:
 * 338   Use of Cryptographically Weak Pseudo-Random Number Generator
 * 1463  Insufficient Session Timeout Value
 * 1465  Improper Session Invalidation after User Logout
 * 639   Authorization Bypass Through User-Controlled Key
 * 842   Placement of User into Incorrect Group
 * 749   Exposed Dangerous Method or Function
 *
 * COORDINATE WITH: Login, UserAccounts and every protected feature.
 */
public class SessionsAndRoles {
    // Add your own fields and methods here.
}
