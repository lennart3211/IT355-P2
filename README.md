# IT Ticket CLI App

A Java help-desk application for IT355 Project 2. The numbered menu supports account management, ticket management, attachments, CSV/XML imports, and CSV exports. H2 stores application data locally.

## Build and run

The app targets Java 17. Use a Java 17 or later JDK and Maven 3.9+. On Apple Silicon, use an ARM64 (AArch64) JDK. These macOS and Linux commands run from the repository root in an interactive terminal so the CLI can read passwords without echoing them.

```sh
mvn compile
mkdir -p ./data
```

Set these environment variables before starting the app. Replace the password and key placeholders with your own values. The field key must be a Base64-encoded 32-byte key. You can generate one with `openssl rand -base64 32`. Keep the same database credentials and field key for subsequent runs against the same database.

```sh
export TICKETAPP_DB_URL='jdbc:h2:./data/tickets'
export TICKETAPP_DB_USER='app'
export TICKETAPP_DB_PASSWORD='<your database password>'
export TICKETAPP_FIELD_KEY='<your Base64-encoded 32-byte key>'
export TICKETAPP_DATA_DIR='./data'
```

To create the initial admin account on a fresh database, also set `TICKETAPP_ADMIN_PASSWORD`. Use 12–128 characters and at least three character types (uppercase, lowercase, digit, symbol). Avoid including the username `admin`. Keep credential and key values out of version control.

```sh
export TICKETAPP_ADMIN_PASSWORD='<your initial admin password>'
```

Launch the app:

```sh
java -cp "target/classes:$HOME/.m2/repository/com/h2database/h2/2.2.224/h2-2.2.224.jar" com.ticketapp.Main
```

The launch command assumes Maven’s default local repository path.

## First login

1. Select **1. Login** and sign in as `admin` with the initial password.
2. Select **5. Change Password**. Protected actions are blocked until you complete this step.
3. Sign in again with the new password. Subsequent starts can omit `TICKETAPP_ADMIN_PASSWORD` once the `admin` account exists with the `ADMIN` role.

## CWE coverage

The table lists the 30 CWEs selected in the report and their assigned owners. Java references are relative to `src/main/java/com/ticketapp/`. The names link to the corresponding MITRE entries.

| # | CWE | Assigned owner | Java reference |
|---|-----|-------|-------|
| 1 | [CWE-306 Missing Authentication for Critical Functionality](https://cwe.mitre.org/data/definitions/306.html) | Kimlay Neng | `session/AccessControl.requireValid()`, `cli/CommandDispatcher.requireAuthentication()` |
| 2 | [CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html) | Kimlay Neng | `auth/AuthService.login()`, `auth/LoginThrottle.recordFailure()` |
| 3 | [CWE-645 Overly Restrictive Account Lockout Mechanism](https://cwe.mitre.org/data/definitions/645.html) | Kimlay Neng | `auth/LoginThrottle`, `cli/CommandDispatcher.unlockAccount()` |
| 4 | [CWE-204 Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html) | Kimlay Neng | `auth/AuthService.GENERIC_FAILURE`, `cli/CommandDispatcher.handleLogin()` |
| 5 | [CWE-208 Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html) | Kimlay Neng | `auth/AuthService.login()`, `user/PasswordHasher.dummyVerify()` |
| 6 | [CWE-455 Non-exit on Failed Initialization](https://cwe.mitre.org/data/definitions/455.html) | Kimlay Neng | `Main.main()`, `config/AppConfig.load()`, `cli/CommandDispatcher.wire()` |
| 7 | [CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html) | Caleb Clauson | `user/PasswordHasher.hash()`, `config/AppConfig.PBKDF2_ITERATIONS` |
| 8 | [CWE-256 Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html) | Caleb Clauson | `user/PasswordHasher.hash()`, `user/UserRepository.insert()`, `user/UserRepository.updatePassword()` |
| 9 | [CWE-521 Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html) | Caleb Clauson | `user/PasswordPolicy.validate()`, `user/AccountService.register()`, `user/AccountService.changePassword()` |
| 10 | [CWE-620 Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html) | Caleb Clauson | `user/AccountService.changePassword()` |
| 11 | [CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) | Caleb Clauson | `config/AppConfig.load()`, `db/Database.connect()`, `user/AccountService.seedAdminIfMissing()` |
| 12 | [CWE-1392 Use of Default Credentials](https://cwe.mitre.org/data/definitions/1392.html) | Caleb Clauson | `user/AccountService.seedAdminIfMissing()`, `cli/CommandDispatcher.handleLoggedIn()` |
| 13 | [CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html) | Luke Gibson | `session/SessionManager.newToken()` |
| 14 | [CWE-1463 Insufficient Session Timeout Value](https://cwe.mitre.org/data/definitions/1463.html) | Luke Gibson | `session/SessionManager.validate()` |
| 15 | [CWE-1465 Improper Session Invalidation after User Logout](https://cwe.mitre.org/data/definitions/1465.html) | Luke Gibson | `auth/AuthService.logout()`, `session/SessionManager.invalidate()` |
| 16 | [CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) | Luke Gibson | `ticket/TicketService.view()`, `session/AccessControl.requireCanView()` |
| 17 | [CWE-842 Placement of User into Incorrect Group](https://cwe.mitre.org/data/definitions/842.html) | Luke Gibson | `model/Role.DEFAULT`, `user/AccountService.register()` |
| 18 | [CWE-749 Exposed Dangerous Method or Function](https://cwe.mitre.org/data/definitions/749.html) | Luke Gibson | `session/AccessControl.requireRole()`, `ticket/TicketService.delete()`, `files/ExportService.export()` |
| 19 | [CWE-89 Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) | Jocelyn Jude | `ticket/TicketRepository`, `user/UserRepository` |
| 20 | [CWE-770 Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html) | Jocelyn Jude | `ticket/TicketService.create()`, `config/AppConfig` |
| 21 | [CWE-1333 Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html) | Jocelyn Jude | `ticket/TicketService.search()` |
| 22 | [CWE-772 Missing Release of Resource after Effective Lifetime](https://cwe.mitre.org/data/definitions/772.html) | Jocelyn Jude | `db/Database.initSchema()`, `ticket/TicketRepository`, `user/UserRepository`, `session/SessionManager` |
| 23 | [CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html) | Jocelyn Jude | `ticket/FieldEncryptor`, `ticket/TicketRepository`, `user/UserRepository` |
| 24 | [CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html) | Jocelyn Jude | `ticket/TicketView.forViewer()`, `session/AccessControl.requireCanView()` |
| 25 | [CWE-22 Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html) | Lennart Strempfer | `files/AttachmentStore.attach()`, `files/AttachmentStore.safeResolve()` (stored attachment paths) |
| 26 | [CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html) | Lennart Strempfer | `files/TicketImporter.importCsv()`, `files/TicketImporter.importXml()` |
| 27 | [CWE-611 Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html) | Lennart Strempfer | `files/TicketImporter.secureDocumentBuilderFactory()` |
| 28 | [CWE-378 Creation of Temporary File With Insecure Permissions](https://cwe.mitre.org/data/definitions/378.html) | Lennart Strempfer | `files/ExportService.createOwnerOnlyTempFile()` |
| 29 | [CWE-459 Incomplete Cleanup](https://cwe.mitre.org/data/definitions/459.html) | Lennart Strempfer | `files/ExportService.export()` |
| 30 | [CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html) | Lennart Strempfer | `cli/CommandDispatcher.createPrivateDir()`, `files/ExportService.export()` |
