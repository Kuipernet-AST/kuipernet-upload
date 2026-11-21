package mgus;

import jakarta.servlet.annotation.MultipartConfig;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;

/** Test backend only: records what Tomcat made of a multipart request. */
@WebServlet(urlPatterns = {"/upload"})
@MultipartConfig
public class UploadServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        int files = 0, fields = 0;
        long maxFile = 0, maxField = 0;
        String error = null;
        StringBuilder list = new StringBuilder("[");

        try {
            for (Part p : req.getParts()) {
                boolean isFile = p.getSubmittedFileName() != null;
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                long n = 0;
                try (InputStream in = p.getInputStream()) {
                    byte[] buf = new byte[65536];
                    int r;
                    while ((r = in.read(buf)) > 0) {
                        md.update(buf, 0, r);
                        n += r;
                    }
                }
                if (isFile) {
                    files++;
                    maxFile = Math.max(maxFile, n);
                    if (list.length() > 1) {
                        list.append(',');
                    }
                    list.append("{\"size\":").append(n).append(",\"sha256\":\"")
                        .append(Log.hex(md.digest())).append("\"}");
                } else {
                    fields++;
                    maxField = Math.max(maxField, n);
                }
            }
        } catch (Exception e) {
            error = e.getClass().getName();
        }
        list.append(']');

        String line = "{\"backend\":\"tomcat\",\"servlet\":\"upload\",\"test_id\":\""
            + Log.safe(req.getHeader("X-Test-Id")) + "\",\"content_length\":"
            + req.getContentLengthLong() + ",\"files\":" + files + ",\"fields\":"
            + fields + ",\"max_file_bytes\":" + maxFile + ",\"max_field_bytes\":"
            + maxField + ",\"file_list\":" + list + ",\"error\":"
            + (error == null ? "null" : "\"" + error + "\"") + "}";
        Log.write(line);

        resp.setStatus(error == null ? 200 : 400);
        resp.setContentType("application/json");
        resp.getWriter().println(line);
    }
}
