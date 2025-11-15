package org.keycloak.social.weixin.resources;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.SneakyThrows;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.social.weixin.cache.TicketStatusProvider;
import org.keycloak.social.weixin.helpers.WechatMpHelper;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Map;
import java.util.Objects;

public class WechatCallbackResourceProvider implements RealmResourceProvider {
    protected static final Logger logger = Logger.getLogger(WechatCallbackResourceProvider.class);
    private final TicketStatusProvider ticketStatusProvider;
    private final KeycloakSession session;

    public WechatCallbackResourceProvider(KeycloakSession session) {
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
    @Path("wechat-callback")
    @Produces(MediaType.TEXT_PLAIN)
    public Response wechatCallback(@QueryParam("signature") String signature,
                                   @QueryParam("timestamp") String timestamp,
                                   @QueryParam("nonce") String nonce,
                                   @QueryParam("echostr") String echostr) {
        logger.info("received wechat callback: %s, %s, %s, %s".formatted(signature, timestamp, nonce, echostr));

        if (WechatMpHelper.isWechatMpMessage(signature, timestamp, nonce)) {
            logger.info("wechat-callback: %s verified.".formatted(echostr));

            return Response.ok(echostr).build();
        }

        return Response.notAcceptable(new ArrayList<>()).build();
    }

    @SneakyThrows
    @POST
    @Path("wechat-callback")
    @Consumes(MediaType.APPLICATION_XML)
    @Produces(MediaType.APPLICATION_JSON)
    public Response wechatCallback(String xmlData) {
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
