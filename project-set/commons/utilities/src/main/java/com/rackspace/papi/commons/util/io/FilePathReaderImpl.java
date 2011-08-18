package com.rackspace.papi.commons.util.io;

import java.io.*;

/**
 * Created by IntelliJ IDEA.
 * User: joshualockwood
 * Date: 6/27/11
 * Time: 9:28 AM
 */
public class FilePathReaderImpl extends FileReader {
    private final String filePath;

    public FilePathReaderImpl(String filePath) {
        this.filePath = filePath;
    }

    @Override
    protected void checkPreconditions() throws IOException {
        if (!(getResourceAsStream().available() > 0)) {
            throw new FileNotFoundException("filePath [" + filePath + "] not found");
        }
    }

    @Override
    protected BufferedReader getReader() throws IOException {
        return new BufferedReader(new InputStreamReader(
                    FileReaderImpl.class.getResource(filePath).openStream()));
    }

    public InputStream getResourceAsStream() {
        return FileReaderImpl.class.getResourceAsStream(filePath);
    }

}
