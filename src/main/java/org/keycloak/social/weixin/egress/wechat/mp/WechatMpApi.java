package org.keycloak.social.weixin.egress.wechat.mp;

import lombok.SneakyThrows;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.social.weixin.cache.TicketStatusProvider;
import org.keycloak.social.weixin.egress.wechat.mp.models.AccessTokenResponse;
import org.keycloak.social.weixin.egress.wechat.mp.models.TicketRequest;
import org.keycloak.social.weixin.egress.wechat.mp.models.TicketResponse;


public class WechatMpApi {
    private static final Logger logger = Logger.getLogger(WechatMpApi.class);
    private final String appSecret;
    private final String appId;
    protected final KeycloakSession session;
    protected final AuthenticationSessionModel authenticationSession;

    public WechatMpApi(String appId, String appSecret, KeycloakSession session, AuthenticationSessionModel authenticationSession) {
        this.appId = appId;
        this.appSecret = appSecret;
        this.session = session;
        this.authenticationSession = authenticationSession;
    }

    @SneakyThrows
    public AccessTokenResponse getAccessToken(String appId, String appSecret) {
        logger.info(String.format("getAccessToken by %s%n%s%n", appId, appSecret));
        var res =
                SimpleHttp.doGet(String.format("https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential" +
                                "&appid=%s&secret=%s", appId, appSecret),
                        session).asJson(AccessTokenResponse.class);

        logger.info(String.format("res is %s%n", res));

        return res;
    }

    @SneakyThrows
    public TicketResponse createTmpQrCode(TicketRequest ticketRequest) {
        logger.info(String.format("createTmpQrCode by %s%n", ticketRequest));

        var res = SimpleHttp.doPost("https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token=" + this.getAccessToken(appId, appSecret).access_token,
                session).json(ticketRequest).asJson(TicketResponse.class);

        logger.info(String.format("res is %s%n", res));

        this.saveTicketStatus(res.ticket, res.expire_seconds);

        return res;
    }

    private void saveTicketStatus(String ticket, Number expireSeconds) {
        logger.info(String.format("saveTicketStatus by %s%n%s%n", ticket, expireSeconds));

        var ticketStatusProvider = new TicketStatusProvider(session, null);

        ticketStatusProvider.saveTicketStatus(ticket, expireSeconds, "not_scanned");
    }
}
