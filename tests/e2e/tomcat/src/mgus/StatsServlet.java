package mgus;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import javax.management.MBeanServer;
import javax.management.ObjectName;

/** Exposes Tomcat's own connector counters (requests, body bytes received). */
@WebServlet(urlPatterns = {"/stats"})
public class StatsServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        long requests = 0, bytes = 0;
        try {
            MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
            for (ObjectName n : mbs.queryNames(
                    new ObjectName("Catalina:type=GlobalRequestProcessor,*"), null)) {
                requests += ((Number) mbs.getAttribute(n, "requestCount")).longValue();
                bytes += ((Number) mbs.getAttribute(n, "bytesReceived")).longValue();
            }
        } catch (Exception e) {
            resp.sendError(500, e.toString());
            return;
        }
        resp.setContentType("application/json");
        resp.getWriter().println("{\"requestCount\":" + requests
            + ",\"bytesReceived\":" + bytes + "}");
    }
}
