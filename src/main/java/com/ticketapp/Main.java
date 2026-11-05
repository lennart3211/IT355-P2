package com.ticketapp;

import com.ticketapp.cli.CommandDispatcher;
import com.ticketapp.config.AppConfig;
import com.ticketapp.config.SecurityConfigException;

/**
 * CLI entry point.
 *
 * CWE-455 Non-exit on Failed Initialization (Kimlay):
 *   if any required security configuration fails to load, print a generic
 *   error and exit with a non-zero status. Never fall back to "insecure defaults".
 */
public final class Main {

    private Main() { }

    public static void main(String[] args) {
        AppConfig config;
        try {
            config = AppConfig.load();          // throws if anything required is missing
        } catch (SecurityConfigException e) {
            System.err.println("Startup failed: security configuration invalid.");
            System.exit(1);                     // CWE-455: do NOT continue
            return;
        }

        CommandDispatcher dispatcher = CommandDispatcher.wire(config);
        dispatcher.runRepl(System.in, System.out);
    }
}
