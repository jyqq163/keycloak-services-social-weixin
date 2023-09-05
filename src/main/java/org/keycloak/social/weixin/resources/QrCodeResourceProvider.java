package org.keycloak.social.weixin.resources;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import java.util.Map;

@RequiredArgsConstructor
public class QrCodeResourceProvider implements RealmResourceProvider {
    private final KeycloakSession session;
    protected static final Logger logger = Logger.getLogger(QrCodeResourceProvider.class);

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {

    }

    @GET
    @Path("hello")
    @Produces(MediaType.APPLICATION_JSON)
    public Response helloAnonymous() {
        logger.info("hello");
        return Response.ok(Map.of("hello", session.getContext().getRealm().getName())).build();
    }

    @GET
    @Path("mp-qr-url")
    @Produces(MediaType.TEXT_HTML)
    public Response mpQrUrl() {
        logger.info("展示一个 HTML 页面，该页面使用 React 展示一个组件，它调用一个后端 API，得到一个带参二维码 URL，并将该 URL 作为 img 的 src 属性值");

        String htmlContent = "<!DOCTYPE html>\n" +
                "<html>\n" +
                "<head>\n" +
                "    <title>QR Code Page</title>\n" +
                "</head>\n" +
                "<body>\n" +
                "    <div id=\"qrCodeContainer\">\n" +
                "        Loading QR Code...\n" +
                "    </div>\n" +
                "    <script>\n" +
                "        // 使用JavaScript获取后端API返回的二维码URL\n" +
                "        fetch('/api/get-qr-code-url')\n" +
                "            .then(response => response.json())\n" +
                "            .then(data => {\n" +
                "                const qrCodeUrl = data.qrCodeUrl;\n" +
                "                const qrCodeContainer = document.getElementById('qrCodeContainer');\n" +
                "                qrCodeContainer.innerHTML = `<img src=\"${qrCodeUrl}\" alt=\"QR Code\">`;\n" +
                "            })\n" +
                "            .catch(error => {\n" +
                "                console.error('Error fetching QR code URL:', error);\n" +
                "            });\n" +
                "    </script>\n" +
                "</body>\n" +
                "</html>";

        // 返回包含HTML内容的响应
        return Response.ok(htmlContent, MediaType.TEXT_HTML_TYPE).build();
    }
}
