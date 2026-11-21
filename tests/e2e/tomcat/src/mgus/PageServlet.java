package mgus;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;

/** A servlet without multipart support: it counts the raw body it receives. */
@WebServlet(urlPatterns = {"/page"})
public class PageServlet extends HttpServlet {

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        long n = 0;
        try (InputStream in = req.getInputStream()) {
            byte[] buf = new byte[65536];
            int r;
            while ((r = in.read(buf)) > 0) {
                n += r;
            }
        }
        String line = "{\"backend\":\"tomcat\",\"servlet\":\"page\",\"test_id\":\""
            + Log.safe(req.getHeader("X-Test-Id")) + "\",\"content_length\":"
            + req.getContentLengthLong() + ",\"body_bytes_read\":" + n + "}";
        Log.write(line);
        resp.setContentType("application/json");
        resp.getWriter().println(line);
    }
}
