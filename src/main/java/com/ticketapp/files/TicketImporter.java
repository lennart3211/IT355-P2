package com.ticketapp.files;

import com.ticketapp.config.AppConfig;
import com.ticketapp.model.Ticket;
import com.ticketapp.session.Session;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Owner: Lennart
 *
 * CWE-502 Deserialization of Untrusted Data: import ONLY CSV or XML/JSON text.
 *   Never ObjectInputStream.
 * CWE-611 XXE: XML parser built by secureDocumentBuilderFactory() with DTDs and
 *   external entities disabled.
 * CWE-770: cap file size and row count.
 */
public class TicketImporter {

    private static final long MAX_FILE_BYTES = 256 * 1024;
    private static final int MAX_ROWS = AppConfig.MAX_OPEN_TICKETS_PER_USER;
    private static final int MAX_TITLE_LENGTH = 200;
    private static final int MAX_CONTACT_LENGTH = 200;

    /** Plain-text CSV, one ticket per line: title,description,contactInfo (no quoting). */
    public List<Ticket> importCsv(Session session, Path file) {
        try {
            if (Files.size(file) > MAX_FILE_BYTES) {
                throw new IllegalArgumentException("CSV file too large");
            }
            List<Ticket> tickets = new ArrayList<>();
            try (BufferedReader in = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                String line;
                while ((line = in.readLine()) != null) {
                    if (line.isBlank()) continue;
                    if (tickets.size() >= MAX_ROWS) {
                        throw new IllegalArgumentException("Too many rows (max " + MAX_ROWS + ")");
                    }
                    String[] f = line.split(",", 3);
                    if (f.length != 3) {
                        throw new IllegalArgumentException("Row " + (tickets.size() + 1) + ": expected 3 fields");
                    }
                    Ticket t = newTicket(session, tickets.size() + 1, f[0], f[1], f[2]);
                    tickets.add(t);
                }
            }
            return tickets;
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read CSV file", e);
        }
    }

    /** XML: <tickets><ticket><title/><description/><contactInfo/></ticket>...</tickets> */
    public List<Ticket> importXml(Session session, Path file) {
        try {
            if (Files.size(file) > MAX_FILE_BYTES) {
                throw new IllegalArgumentException("XML file too large");
            }
            Document doc = secureDocumentBuilderFactory().newDocumentBuilder().parse(file.toFile());
            NodeList nodes = doc.getElementsByTagName("ticket");
            if (nodes.getLength() > MAX_ROWS) {
                throw new IllegalArgumentException("Too many tickets (max " + MAX_ROWS + ")");
            }
            List<Ticket> tickets = new ArrayList<>();
            for (int i = 0; i < nodes.getLength(); i++) {
                Element e = (Element) nodes.item(i);
                tickets.add(newTicket(session, i + 1,
                        text(e, "title"), text(e, "description"), text(e, "contactInfo")));
            }
            return tickets;
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read XML file", e);
        } catch (ParserConfigurationException | SAXException e) {
            throw new IllegalArgumentException("Invalid XML file", e);
        }
    }

    private static String text(Element parent, String tag) {
        NodeList n = parent.getElementsByTagName(tag);
        return n.getLength() == 0 ? "" : n.item(0).getTextContent();
    }

    private static Ticket newTicket(Session session, int row, String title, String description, String contact) {
        title = title.trim();
        description = description.trim();
        contact = contact.trim();
        if (title.isEmpty() || title.length() > MAX_TITLE_LENGTH
                || description.isEmpty() || description.length() > AppConfig.MAX_DESCRIPTION_LENGTH
                || contact.length() > MAX_CONTACT_LENGTH) {
            throw new IllegalArgumentException("Row " + row + ": invalid field length");
        }
        Ticket t = new Ticket();
        t.setOwnerId(session.userId());
        t.setTitle(title);
        t.setDescription(description);
        t.setContactInfo(contact);
        t.setCreatedAt(Instant.now());
        return t;
    }

    static DocumentBuilderFactory secureDocumentBuilderFactory() {
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setFeature("http://xml.org/sax/features/external-general-entities", false);
            f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            f.setXIncludeAware(false);
            f.setExpandEntityReferences(false);
            f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            return f;
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException("Cannot configure secure XML parser", e);
        }
    }
}
