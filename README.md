# IT Ticket CLI App — skeleton

Java 17 / Maven. Every method that still needs work throws `UnsupportedOperationException("TODO")`
and has a `// TODO` describing what to do. Each class's Javadoc lists the CWEs it covers.

## Setup
```
export TICKETAPP_DB_URL=jdbc:h2:./data/tickets
export TICKETAPP_DB_USER=app
export TICKETAPP_DB_PASSWORD=...        # CWE-798: never in source
export TICKETAPP_FIELD_KEY=...          # Base64 32-byte AES key (CWE-312)
export TICKETAPP_DATA_DIR=./data
mvn compile
```

## CWE → class map

| # | CWE | Owner | Class |
|---|-----|-------|-------|
| 1 | 306 Missing Authentication | Kimlay | `session/AccessControl`, `cli/CommandDispatcher` |
| 2 | 307 Excessive Auth Attempts | Kimlay | `auth/LoginThrottle` |
| 3 | 645 Overly Restrictive Lockout | Kimlay | `auth/LoginThrottle` (bounded backoff + `adminUnlock`) |
| 4 | 204 Response Discrepancy | Kimlay | `auth/AuthService.GENERIC_FAILURE` |
| 5 | 208 Timing Discrepancy | Kimlay | `auth/AuthService`, `user/PasswordHasher.dummyVerify` |
| 6 | 455 Non-exit on Failed Init | Kimlay | `Main`, `config/AppConfig.load` |
| 7 | 916 Weak Password Hash | Caleb | `user/PasswordHasher` |
| 8 | 256 Plaintext Password | Caleb | `model/User`, `user/PasswordHasher` |
| 9 | 521 Weak Password Requirements | Caleb | `user/PasswordPolicy` |
| 10 | 620 Unverified Password Change | Caleb | `user/AccountService.changePassword` |
| 11 | 798 Hard-coded Credentials | Caleb | `config/AppConfig`, `db/Database` |
| 12 | 1392 Default Credentials | Caleb | `user/AccountService.seedAdminIfMissing`, `cli/CommandDispatcher` |
| 13 | 338 Weak PRNG | Luke | `session/SessionManager.newToken` |
| 14 | 1463 Session Timeout | Luke | `session/SessionManager.validate` |
| 15 | 1465 Invalidation after Logout | Luke | `session/SessionManager.invalidate` |
| 16 | 639 User-Controlled Key | Luke | `session/AccessControl.requireCanView` |
| 17 | 842 Incorrect Group | Luke | `model/Role.DEFAULT`, `user/AccountService.register` |
| 18 | 749 Exposed Dangerous Method | Luke | `session/AccessControl.requireRole` (called inside services) |
| 19 | 89 SQL Injection | Jocelyn | `ticket/TicketRepository`, `user/UserRepository` |
| 20 | 770 Resource Limits | Jocelyn | `ticket/TicketService`, `config/AppConfig` limits |
| 21 | 1333 ReDoS | Jocelyn | `ticket/TicketService.search` |
| 22 | 772 Resource Release | Jocelyn | `db/Database`, all repositories |
| 23 | 312 Cleartext Storage | Jocelyn | `ticket/FieldEncryptor` |
| 24 | 359 Private Info Exposure | Jocelyn | `ticket/TicketView.forViewer` |
| 25 | 22 Path Traversal | Lennart | `files/AttachmentStore.safeResolve` |
| 26 | 502 Deserialization | Lennart | `files/TicketImporter` |
| 27 | 611 XXE | Lennart | `files/TicketImporter.secureDocumentBuilderFactory` |
| 28 | 378 Insecure Temp File | Lennart | `files/ExportService.createOwnerOnlyTempFile` |
| 29 | 459 Incomplete Cleanup | Lennart | `files/ExportService.export` (finally) |
| 30 | 552 Externally Accessible Files | Lennart | `files/ExportService`, `config/AppConfig.exportsDir` |
| 31 | 820 Missing Synchronization | — | `assign/TicketLockManager` |
| 32 | 821 Incorrect Synchronization | — | `assign/TicketLockManager`, version column in `TicketRepository` |
| 33 | 367 TOCTOU | — | `ticket/TicketRepository.assignIfUnassigned`, `assign/AssignmentService.claim` |
| 34 | 833 Deadlock | — | `assign/TicketLockManager.withLocks` |
| 35 | 117 Log Injection | — | `audit/LogSanitizer` |
| 36 | 778 Insufficient Logging | — | `audit/AuditLog` (+ calls from every service) |
