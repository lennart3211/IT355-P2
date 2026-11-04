/*
 * FEATURE 5: Attachments and export/import
 * Initial owner: Lennart
 *
 * WHAT TO CREATE:
 * - Adding and retrieving ticket attachments within a protected storage folder.
 * - File access that prevents traversal, absolute-path and symbolic-link escapes.
 * - Bounded ticket imports using an explicit data format, not arbitrary Java objects.
 * - XML import with DTDs, external entities and external resource access disabled.
 * - Report export with protected temporary files and reliable cleanup.
 * - Directory/file permissions that prevent unintended access.
 *
 * SIX CWEs:
 * 22   Path Traversal
 * 502  Deserialization of Untrusted Data
 * 611  Improper Restriction of XML External Entity Reference
 * 378  Creation of Temporary File With Insecure Permissions
 * 459  Incomplete Cleanup
 * 552  Files or Directories Accessible to External Parties
 *
 * COORDINATE WITH: Tickets for imported records and linked files; SessionsAndRoles
 * for access checks; AssignmentAndAudit for events. Agree on supported file formats.
 */
public class Attachments {
    // Add your own fields and methods here.
}
