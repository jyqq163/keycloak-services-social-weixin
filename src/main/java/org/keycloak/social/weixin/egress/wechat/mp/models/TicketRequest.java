package org.keycloak.social.weixin.egress.wechat.mp.models;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class TicketRequest {
    public Number expire_seconds;
    public String action_name;
    public ActionInfo action_info;

    // public TicketRequest(Number expire_seconds, String action_name, ActionInfo action_info) {
    //     this.expire_seconds = expire_seconds;
    //     this.action_name = action_name;
    //     this.action_info = action_info;
    // }
}
