package org.keycloak.social.weixin.egress.wechat.mp.models;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class TicketRequest {
    public Number expire_seconds;
    public String action_name;
    public ActionInfo action_info;
}
