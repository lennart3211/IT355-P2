
package com.ticketapp;

import com.ticketapp.cli.CommandDispatcher;
import com.ticketapp.config.AppConfig;

/**
 * CWE-455: Non-exit on Failed Initialization
 *
 * The application must stop if required security
 * configuration or service initialization fails.
 */
public final class Main {

    private Main() { }

    public static void main(String[] args) {

        try {
            // Load required security configuration.
            AppConfig config = AppConfig.load();

            // Initialize application services.
            CommandDispatcher dispatcher =
                    CommandDispatcher.wire(config);

            // Start only after successful initialization.
            dispatcher.runRepl(System.in, System.out);

        } catch (Exception e) {

            // Do not expose sensitive configuration details.
            System.err.println(
                    "Startup or application initialization failed.");

            // CWE-455: Stop instead of continuing insecurely.
            System.exit(1);
        }
    }
}
