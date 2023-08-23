package org.keycloak.social.weixin;

import static org.keycloak.social.weixin.WeiXinIdentityProvider.WECHATFLAG;

public class UserAgentHelper {
    public static boolean isWechatBrowser(String ua) {
        return ua.contains(WECHATFLAG);
    }
}
