package org.keycloak.social.weixin.helpers;

import static org.keycloak.social.weixin.WeiXinIdentityProvider.WECHATFLAG;

public class UserAgentHelper {
    public static boolean isWechatBrowser(String ua) {
        return ua.indexOf(WECHATFLAG) > 0;
    }
}
