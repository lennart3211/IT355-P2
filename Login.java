/*
 * FEATURE 1: Login and authentication
 * Initial owner: Kimlay
 *
 * WHAT TO CREATE:
 * - A way to accept and verify login details using UserAccounts.
 * - A way to limit failed attempts while allowing legitimate users to recover.
 * - The same public failure response for unknown users and wrong passwords.
 * - A login process that avoids revealing whether a username exists through timing.
 * - Startup checks that stop normal use if required security setup fails.
 *
 * SIX CWEs:
 * 306  Missing Authentication for Critical Functionality
 * 307  Improper Restriction of Excessive Authentication Attempts
 * 645  Overly Restrictive Account Lockout Mechanism
 * 204  Observable Response Discrepancy
 * 208  Observable Timing Discrepancy
 * 455  Non-exit on Failed Initialization
 *
 * COORDINATE WITH: UserAccounts for password verification; SessionsAndRoles for
 * successful login sessions; AssignmentAndAudit for login outcome records.
 */
public class Login {
    // Add your own fields and methods here.
}
