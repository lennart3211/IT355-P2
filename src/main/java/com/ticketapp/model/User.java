package com.ticketapp.model;

/**
 * A user account as stored in the DB.
 *
 * CWE-256 Plaintext Storage of a Password (Caleb): there is NO password field,
 *   only passwordHash + salt + iterations.
 * CWE-1392 Default Credentials (Caleb): mustChangePassword is true for the
 *   seeded admin until they set a new password.
 * CWE-307 / CWE-645 (Kimlay): failedLogins + lockedUntil drive throttling.
 */
public class User {
    private long id;
    private String username;
    private byte[] passwordHash;
    private byte[] salt;
    private int iterations;
    private Role role = Role.DEFAULT;          // CWE-842
    private String email;                      // CWE-312/359: sensitive, encrypted at rest
    private String phone;                      // CWE-312/359
    private boolean mustChangePassword;        // CWE-1392
    private int failedLogins;                  // CWE-307
    private java.time.Instant lockedUntil;     // CWE-307/645
    private int lockoutCount;                  // CWE-645 bounded backoff


    public long getId() { return id; }
    public void setId(long id) { this.id = id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public byte[] getPasswordHash() { return passwordHash; }
    public void setPasswordHash(byte[] passwordHash) { this.passwordHash = passwordHash; }
    public byte[] getSalt() { return salt; }
    public void setSalt(byte[] salt) { this.salt = salt; }
    public int getIterations() { return iterations; }
    public void setIterations(int iterations) { this.iterations = iterations; }
    public Role getRole() { return role; }
    public void setRole(Role role) { this.role = role; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getPhone() { return phone; }
    public void setPhone(String phone) { this.phone = phone; }
    public boolean isMustChangePassword() { return mustChangePassword; }
    public void setMustChangePassword(boolean v) { this.mustChangePassword = v; }
    public int getFailedLogins() { return failedLogins; }
    public void setFailedLogins(int failedLogins) { this.failedLogins = failedLogins; }
    public java.time.Instant getLockedUntil() { return lockedUntil; }
    public void setLockedUntil(java.time.Instant lockedUntil) { this.lockedUntil = lockedUntil; }
    public int getLockoutCount() { return lockoutCount; }
    public void setLockoutCount(int lockoutCount) { this.lockoutCount = lockoutCount; }
}
