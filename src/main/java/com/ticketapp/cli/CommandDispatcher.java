package com.ticketapp.cli;

import com.ticketapp.config.AppConfig;

import java.io.InputStream;
import java.io.PrintStream;

/**
 * Parses CLI input and routes to services.
 *
 * Every command except login/register/help/quit:
 *   1. AccessControl.requireValid(currentSession)       (CWE-306, CWE-1463)
 *   2. if user.mustChangePassword -> only allow change-password   (CWE-1392)
 *   3. call the service — which does its OWN role check (CWE-749)
 *
 * Read passwords with System.console().readPassword() into char[] (no echo).
 * Print AuthService.GENERIC_FAILURE for any login failure (CWE-204).
 * Never print stack traces to the user; log internally instead.
 *
 * Commands (suggested):
 *   register | login | logout | change-password
 *   create-ticket | view-ticket <id> | list-tickets | search <keyword>
 *   claim <id> | reassign <id> <techId> | merge <fromId> <intoId>
 *   delete-ticket <id> | set-role <userId> <role> | unlock <userId>
 *   attach <id> <path> | import <path> | export
 *   help | quit
 */
public class CommandDispatcher {

    // TODO: fields for each service + current Session

    public static CommandDispatcher wire(AppConfig config) {
        // TODO: construct Database, repositories, services; db.initSchema();
        //       accountService.seedAdminIfMissing()
        //       Any failure here must abort startup (CWE-455)
        throw new UnsupportedOperationException("TODO");
    }

    public void runRepl(InputStream in, PrintStream out) {
        // TODO: read line, split, switch on command, catch AccessDeniedException -> print generic message
        throw new UnsupportedOperationException("TODO");
    }
}
