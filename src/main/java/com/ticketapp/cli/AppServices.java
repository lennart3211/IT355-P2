package com.ticketapp.cli;

import com.ticketapp.audit.AuditLog;
import com.ticketapp.auth.LoginThrottle;
import com.ticketapp.files.AttachmentStore;
import com.ticketapp.files.ExportService;
import com.ticketapp.files.TicketImporter;
import com.ticketapp.ticket.TicketRepository;
import com.ticketapp.ticket.TicketService;
import com.ticketapp.user.AccountService;
import com.ticketapp.user.UserRepository;

/**
 * Everything the logged-in menu needs, built once by CommandDispatcher.wire().
 * Keeping them together keeps the CommandDispatcher constructor short.
 */
public record AppServices(
        AccountService accounts,
        TicketService tickets,
        TicketRepository ticketRepo,
        UserRepository users,
        LoginThrottle throttle,
        ExportService exports,
        TicketImporter importer,
        AttachmentStore attachments,
        AuditLog audit) {
}