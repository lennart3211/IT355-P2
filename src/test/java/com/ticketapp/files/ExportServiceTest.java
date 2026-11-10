package com.ticketapp.files;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ExportServiceTest {

    @Test
    public void testOwnerOnlyFile(@TempDir Path dir) throws IOException {
        ExportService es = new ExportService(dir, null, null, null);

        Path temp = es.createOwnerOnlyTempFile();

        assertTrue(Files.exists(temp));
        assertEquals(dir, temp.getParent());
        if (Files.getFileStore(temp).supportsFileAttributeView("posix")) {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(temp)));
        }
    }
}
