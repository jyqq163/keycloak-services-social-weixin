package org.keycloak.social.weixin.resources;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.SneakyThrows;
import org.apache.commons.collections4.map.HashedMap;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderStorageProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.social.weixin.WeiXinIdentityProvider;
import org.keycloak.social.weixin.cache.TicketStatusProvider;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.Map;
import java.util.Objects;

import static org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_REDIRECT_URI;
import static org.keycloak.social.weixin.helpers.WechatMpHelper.isWechatMpMessage;

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
    @Produces(MediaType.TEXT_HTML + ";charset=UTF-8")
    public Response mpQrUrl(@QueryParam("ticket") String ticket, @QueryParam("qr-code-url") String qrCodeUrl, @QueryParam("state") String state, @QueryParam(OAUTH2_PARAMETER_REDIRECT_URI) String redirectUri) {
        logger.info("展示一个 HTML 页面，该页面使用 React 展示一个组件，它调用一个后端 API，得到一个带参二维码 URL，并将该 URL 作为 img 的 src 属性值");

        var host = session.getContext().getUri().getBaseUri().toString();
        var realmName = session.getContext().getRealm().getName();
        var accountRedirectUri = host + "/realms/" + realmName + "/account";

        logger.info(String.format("host is %s, realmName is %s", host, realmName));

        var template = """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>QR Code Page</title>
                    <style>
                        body {
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            min-height: 100vh;
                            margin: 0;
                            font-family: Arial, sans-serif;
                        }
                        #qrCodeContainer {
                            text-align: center;
                        }
                        img {
                            max-width: 300px;
                            height: auto;
                        }
                        .status-text {
                            margin-top: 20px;
                            font-size: 16px;
                            color: #666;
                        }
                        .status-text.scanned {
                            color: #4CAF50;
                        }
                    </style>
                </head>
                <body>
                    <div id="qrCodeContainer">
                        <p>请使用微信扫描下方二维码</p>
                        <img src="%s" alt="%s">
                        <p id="statusText" class="status-text">等待扫码...</p>
                    </div>
                    <script type="text/javascript">
                        async function fetchQrScanStatus() {
                            const res = await fetch(`mp-qr-scan-status?ticket=%s`, {
                                headers: {
                                    'Content-Type': 'application/json'
                                }
                            })
                
                            const {status, openid} = await res.json()
                            const statusText = document.getElementById('statusText')
                
                            if (status === 'scanned') {
                                statusText.textContent = '已扫码，正在登录...'
                                statusText.classList.add('scanned')
                                window.location.href = `%s?openid=${openid}&state=%s`
                            } else if (status === 'not_scanned') {
                                statusText.textContent = '等待扫码...'
                                setTimeout(fetchQrScanStatus, 1000)
                            } else if (status === 'expired') {
                                statusText.textContent = '二维码已过期，请重新扫码二维码'
                            } else {
                                statusText.textContent = '未知错误，请重新扫码二维码'
                            }
                        }
                
                        fetchQrScanStatus()
                    </script>
                
                    <script src="/js/keycloak.js" type="text/javascript"></script>
                    <script type="text/javascript">
                        const keycloak = new Keycloak({
                            url: '%s',
                            realm: '%s',
                            clientId: 'account-console',
                            redirectUri: '%s'
                        });
                        keycloak.init({onLoad: 'check-sso', pkceMethod: 'S256', promiseType: 'native'});
                    </script>
                </body>
                </html>
                """;

        String htmlContent = String.format(template, qrCodeUrl, ticket, ticket, redirectUri, state, host, realmName, accountRedirectUri);

        // 返回包含HTML内容的响应
        return Response.ok(htmlContent, MediaType.TEXT_HTML_TYPE).build();
    }

    @SneakyThrows
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
        var openid = ticketEntity.getOpenid();
        var scannedAt = ticketEntity.getScannedAt();

        if (expireSeconds.longValue() < (System.currentTimeMillis() / 1000 - ticketCreatedAt.longValue())) {
            status = "expired";

            ticketEntity.setStatus(status);
            this.ticketStatusProvider.saveTicketStatus(ticketEntity);
        }

        logger.info(String.format("ticket is %s%n, status is %s%n, openid is %s", ticket, status, openid));
        Map<String, String> data = new HashedMap<>();
        data.put("ticket", ticket);
        data.put("expireSeconds", expireSeconds.toString());
        data.put("ticketCreatedAt", ticketCreatedAt.toString());
        data.put("status", status);
        data.put("openid", openid);
        data.put("scannedAt", Objects.toString(scannedAt, null));

        var objectMapper = new ObjectMapper();
        var json = objectMapper.writeValueAsString(data);
        return Response.ok(json, MediaType.APPLICATION_JSON).build();
    }

    @SneakyThrows
    @POST
    @Path("mp-qr-scan-status")
    @Consumes(MediaType.APPLICATION_XML)
    @Produces(MediaType.APPLICATION_JSON)
    public Response mpQrScanStatusScanned(String xmlData) {
        logger.info("查询二维码状态： " + xmlData);

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

        return Response.ok("success").build();
    }

    @SneakyThrows
    @POST
    @Path("message")
    @Consumes(MediaType.WILDCARD)
    @Produces(MediaType.APPLICATION_JSON)
    public Response message(
            @QueryParam("signature") String signature,
            @QueryParam("timestamp") String timestamp,
            @QueryParam("nonce") String nonce,
            String xmlData
    ) {
        logger.info("接收微信消息和事件" + xmlData);
        logger.info("查询参数: signature=" + signature + ", timestamp=" + timestamp + ", nonce=" + nonce);

        // 获取配置的WECHAT_MP_APP_TOKEN
        IdentityProviderStorageProvider idpStorage = session.getProvider(IdentityProviderStorageProvider.class);
        IdentityProviderModel idpModel = idpStorage.getByAlias("weixin");
        if (idpModel == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("Identity Provider not found")
                    .build();
        }
        OAuth2IdentityProviderConfig config = new OAuth2IdentityProviderConfig(idpModel);
        String token = config.getConfig().get(WeiXinIdentityProvider.WECHAT_MP_APP_TOKEN);

        if (token != null && !token.isEmpty()) {
            // 使用配置的token进行验证
            if (!isWechatMpMessage(token, signature, timestamp, nonce)) {
                logger.warn("签名验证失败");
                return Response.status(Response.Status.UNAUTHORIZED).entity("Invalid signature").build();
            }
        } else {
            // 如果没有配置token，使用默认的验证方式
            if (!isWechatMpMessage(signature, timestamp, nonce)) {
                logger.warn("签名验证失败");
                return Response.status(Response.Status.UNAUTHORIZED).entity("Invalid signature").build();
            }
        }

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xmlData)));
        var root = document.getDocumentElement();
        var xmlEvent = root.getElementsByTagName("Event").item(0).getTextContent();

        if (!Objects.equals(xmlEvent, "SCAN") && !Objects.equals(xmlEvent, "subscribe")) {
            logger.info(String.format("ignoring not scanning event: {%s} != {%s}", xmlEvent, "SCAN"));

            return Response.ok("success").build();
//            return Response.ok(Map.of("status", "not_scanned")).build();
        }

        var xmlTicket = root.getElementsByTagName("Ticket").item(0).getTextContent();
        var xmlFromUserName = root.getElementsByTagName("FromUserName").item(0).getTextContent();

        var ticketSaved = this.ticketStatusProvider.getTicketStatus(xmlTicket);
        if (ticketSaved == null) {
            logger.warn(String.format("ticket is not found, {%s}", xmlTicket));
//            return Response.ok("success").build();
            return Response.ok(Map.of("status", "ticket_not_found")).build();
        }

        ticketSaved.setStatus("scanned");
        ticketSaved.setScannedAt(System.currentTimeMillis() / 1000L);
        ticketSaved.setOpenid(xmlFromUserName);

        this.ticketStatusProvider.saveTicketStatus(ticketSaved);

        return Response.ok("success").build();
    }

    @SneakyThrows
    @GET
    @Path("message")
    @Produces(MediaType.APPLICATION_JSON)
    public Response message(
            @QueryParam("echostr") String echostr, @QueryParam("signature") String signature,
            @QueryParam("timestamp") String timestamp,
            @QueryParam("nonce") String nonce,
            String xmlData) {

        logger.info("接收到微信服务器发来的事件： " + xmlData);
        logger.info("查询参数: signature=" + signature + ", timestamp=" + timestamp + ", nonce=" + nonce);

        // 获取配置的WECHAT_MP_APP_TOKEN
        IdentityProviderStorageProvider idpStorage = session.getProvider(IdentityProviderStorageProvider.class);
        IdentityProviderModel idpModel = idpStorage.getByAlias("weixin");
        if (idpModel == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("Identity Provider not found")
                    .build();
        }
        OAuth2IdentityProviderConfig config = new OAuth2IdentityProviderConfig(idpModel);
        String token = config.getConfig().get(WeiXinIdentityProvider.WECHAT_MP_APP_TOKEN);

        if (token != null && !token.isEmpty()) {
            // 使用配置的token进行验证
            if (!isWechatMpMessage(token, signature, timestamp, nonce)) {
                logger.warn("签名验证失败");
                return Response.status(Response.Status.UNAUTHORIZED).entity("Invalid signature").build();
            }
        } else {
            // 如果没有配置token，使用默认的验证方式
            if (!isWechatMpMessage(signature, timestamp, nonce)) {
                logger.warn("签名验证失败");
                return Response.status(Response.Status.UNAUTHORIZED).entity("Invalid signature").build();
            }
        }

        return Response.ok(echostr).build();
    }
}
