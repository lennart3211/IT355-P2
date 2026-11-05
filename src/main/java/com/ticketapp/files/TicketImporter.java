package com.ticketapp.files;

import com.ticketapp.model.Ticket;
import com.ticketapp.session.Session;

import java.nio.file.Path;
import java.util.List;

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

    public List<Ticket> importCsv(Session session, Path file) {
        // TODO: parse rows; validate each field same as TicketService.create
        throw new UnsupportedOperationException("TODO");
    }

    public List<Ticket> importXml(Session session, Path file) {
        // TODO: use secureDocumentBuilderFactory()
        throw new UnsupportedOperationException("TODO");
    }

    static javax.xml.parsers.DocumentBuilderFactory secureDocumentBuilderFactory() {
        // TODO:
        //  f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        //  f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        //  f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        //  f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        //  f.setXIncludeAware(false); f.setExpandEntityReferences(false);
        //  f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, ""); ACCESS_EXTERNAL_SCHEMA, "")
        throw new UnsupportedOperationException("TODO");
    }
}
