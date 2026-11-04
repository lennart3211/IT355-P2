/*
 * FEATURE 4: Ticket management
 * Owner: To be claimed
 *
 * WHAT TO CREATE:
 * - Ticket creation, viewing, searching, status updates and deletion.
 * - The shared ticket data model and database access, agreed with the team.
 * - Parameterized database queries and reliable closing of database resources.
 * - Limits on description size, ticket counts and search results.
 * - Search that cannot trigger expensive attacker-controlled regex processing.
 * - Protection of sensitive stored fields and private details in displayed results.
 *
 * SIX CWEs:
 * 89    SQL Injection
 * 770   Allocation of Resources Without Limits or Throttling
 * 1333  Inefficient Regular Expression Complexity
 * 772   Missing Release of Resource after Effective Lifetime
 * 312   Cleartext Storage of Sensitive Information
 * 359   Exposure of Private Personal Information
 *
 * COORDINATE WITH: SessionsAndRoles for access checks; Attachments for linked
 * files/imported records; AssignmentAndAudit for shared ticket updates and events.
 * Display masking alone does not protect plaintext data stored in a database.
 */
public class Tickets {
    // Add your own fields and methods here.
}
