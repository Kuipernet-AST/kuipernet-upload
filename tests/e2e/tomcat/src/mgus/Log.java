package mgus;

import java.io.FileWriter;
import java.io.IOException;

final class Log {
    private Log() { }

    static synchronized void write(String line) throws IOException {
        try (FileWriter w = new FileWriter(System.getProperty("mgus.log"), true)) {
            w.write(line + "\n");
        }
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }

    static String safe(String s) {
        return s == null ? "" : s.replaceAll("[^A-Za-z0-9_.-]", "_");
    }
}
