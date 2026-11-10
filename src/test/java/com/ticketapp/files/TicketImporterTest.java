package com.ticketapp.files;

import com.ticketapp.model.Role;
import com.ticketapp.model.Ticket;
import com.ticketapp.session.Session;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

public class TicketImporterTest {
    
    @Test
    public void testImportCsv(@TempDir Path dir) throws Exception {
        Session session = new Session("token", 1L, "user", Role.USER, Instant.now());
        Path csv = dir.resolve("t.csv");
        Files.writeString(csv, "Printer jam,Paper stuck,a@example.com\n");
        TicketImporter ti = new TicketImporter();
        List<Ticket> tickets = ti.importCsv(session, csv);
        assertEquals(1, tickets.size());
        assertEquals(1L, tickets.get(0).getOwnerId());
    }

    @Test 
    public void testImportEmptyCsv(@TempDir Path dir) throws Exception {
        Session session = new Session("token", 1L, "user", Role.USER, Instant.now());
        Path csv = dir.resolve("empty.csv");
        Files.writeString(csv, "");
        TicketImporter ti = new TicketImporter();
        List<Ticket> tickets = ti.importCsv(session, csv);
        assertEquals(0, tickets.size());
    }

    @Test 
    public void testImportXml(@TempDir Path dir) throws Exception {
        Session session = new Session("token", 1L, "user", Role.USER, Instant.now());
        Path xml = dir.resolve("t.xml");
        Files.writeString(xml, "<tickets><ticket><title>Printer jam</title><description>Paper stuck</description><contactInfo>a@example.com</contactInfo></ticket></tickets>");
        TicketImporter ti = new TicketImporter();
        List<Ticket> tickets = ti.importXml(session, xml);
        assertEquals(1, tickets.size());
        assertEquals(1L, tickets.get(0).getOwnerId());
    }

    @Test 
    public void testImportEmptyXml(@TempDir Path dir) throws Exception {
        Session session = new Session("token", 1L, "user", Role.USER, Instant.now());
        Path xml = dir.resolve("empty.xml");
        Files.writeString(xml, "<tickets></tickets>");
        TicketImporter ti = new TicketImporter();
        List<Ticket> tickets = ti.importXml(session, xml);
        assertEquals(0, tickets.size());
    }
}


