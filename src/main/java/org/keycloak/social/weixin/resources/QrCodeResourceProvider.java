package org.keycloak.social.weixin.resources;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.SneakyThrows;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.social.weixin.cache.TicketStatusProvider;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.Map;
import java.util.Objects;

public class QrCodeResourceProvider implements RealmResourceProvider {
    private final KeycloakSession session;
    protected static final Logger logger = Logger.getLogger(QrCodeResourceProvider.class);
    private final TicketStatusProvider ticketStatusProvider;

    public QrCodeResourceProvider(KeycloakSession session) {
        this.session = session;
        this.ticketStatusProvider = new TicketStatusProvider(session, null);
    }

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
    @Path("mp-qr")
    @Produces(MediaType.TEXT_HTML)
    public Response mpQrUrl(@QueryParam("ticket") String ticket, @QueryParam("qr-code-url") String qrCodeUrl) {
        logger.info("展示一个 HTML 页面，该页面使用 React 展示一个组件，它调用一个后端 API，得到一个带参二维码 URL，并将该 URL 作为 img 的 src 属性值");

        String htmlContent = "<!DOCTYPE html>\n" +
                "<html>\n" +
                "<head>\n" +
                "    <title>QR Code Page</title>\n" +
                "</head>\n" +
                "<body>\n" +
                "    <div id=\"qrCodeContainer\">\n" +
                "        <img src=\"" + qrCodeUrl + "\" alt=\"" + ticket + "\">\n" +
                "    </div>\n" +
                "</body>\n" +
                "</html>";

        // 返回包含HTML内容的响应
        return Response.ok(htmlContent, MediaType.TEXT_HTML_TYPE).build();
    }

    @GET
    @Path("mp-qr-scan-status")
    @Produces(MediaType.APPLICATION_JSON)
    public Response mpQrScanStatus(@QueryParam("ticket") String ticket) {
        logger.info("查询二维码扫描状态");

        var ticketEntity = this.ticketStatusProvider.getTicketStatus(ticket);
        if (ticketEntity == null) {
            logger.warn(String.format("ticket is not found or expired, {%s}", ticket));

            return Response.ok(Map.of("status", "not_found")).build();
        }

        var expireSeconds = ticketEntity.getExpireSeconds();
        var ticketCreatedAt = ticketEntity.getTicketCreatedAt();
        var status = ticketEntity.getStatus();

        if ((Long) expireSeconds < System.currentTimeMillis() / 1000 - (Long) ticketCreatedAt) {
            status = "expired";

            ticketEntity.setStatus(status);
            this.ticketStatusProvider.saveTicketStatus(ticketEntity);
        }

        logger.info(String.format("ticket is %s%n, status is %s%n", ticket, status));
        return Response.ok(Map.of("ticket", ticket, "expireSeconds", expireSeconds, "ticketCreatedAt", ticketCreatedAt, "status", status)).build();
    }

    @SneakyThrows
    @POST
    @Path("mp-qr-scan-status")
    @Consumes(MediaType.APPLICATION_XML)
    @Produces(MediaType.APPLICATION_JSON)
    public Response mpQrScanStatusScanned(String xmlData) {
        logger.info("接收到微信服务器发来的事件： " + xmlData);

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xmlData)));
        var root = document.getDocumentElement();
        var xmlEvent = root.getElementsByTagName("Event").item(0).getTextContent();

        if (!Objects.equals(xmlEvent, "SCAN")) {
            logger.info(String.format("ignoring not scanning event: {%s} != {%s}", xmlEvent, "SCAN"));
            return Response.ok(Map.of("status", "not_scanned")).build();
        }

        var xmlTicket = root.getElementsByTagName("Ticket").item(0).getTextContent();
        var xmlFromUserName = root.getElementsByTagName("FromUserName").item(0).getTextContent();

        var ticketSaved = this.ticketStatusProvider.getTicketStatus(xmlTicket);
        if (ticketSaved == null) {
            logger.warn(String.format("ticket is not found, {%s}", xmlTicket));
            return Response.ok(Map.of("status", "not_scanned")).build();
        }

        ticketSaved.setStatus("scanned");
        ticketSaved.setScannedAt(System.currentTimeMillis() / 1000L);
        ticketSaved.setOpenid(xmlFromUserName);

        this.ticketStatusProvider.saveTicketStatus(ticketSaved);

        return Response.ok(Map.of("status", "scanned")).build();
    }
}
