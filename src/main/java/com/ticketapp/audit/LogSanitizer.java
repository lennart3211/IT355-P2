package com.ticketapp.audit;

/**
 * CWE-117 Improper Output Neutralization for Logs.
 * Strip CR/LF (and other control chars) so a ticket title like
 * "Printer broken\n2026-11-05 LOGIN_SUCCESS admin" can't forge a log line.
 */
public final class LogSanitizer {

    private LogSanitizer() { }

    public static String clean(String input) {
    if (input == null) {
        return "";
    }

    StringBuilder result = new StringBuilder();

    for (char c : input.toCharArray()) {
        if (Character.isISOControl(c) || c == '|') {
            result.append('_');
        } else {
            result.append(c);
        }
    }

    return result.length() > 500
            ? result.substring(0, 500)
            : result.toString();
}
}
