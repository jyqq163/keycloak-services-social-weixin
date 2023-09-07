package org.keycloak.social.weixin.cache;

import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import lombok.Getter;
import lombok.Setter;
import jakarta.persistence.Entity;

@NamedQueries({
        @NamedQuery(name = "TicketEntity.findById", query = "select t from TicketEntity t where t.id = :id"),
        @NamedQuery(name = "TicketEntity.findByTicket", query = "select t from TicketEntity t where t.ticket = :ticket"),
})
@Getter
@Entity
public class TicketEntity {
    @Setter
    @Id
    private String id;
    @Setter
    private String ticket;
    @Setter
    private String status;
    @Setter
    private Number expireSeconds;
    @Setter
    private Number ticketCreatedAt;
    @Setter
    private Number scannedAt;
    @Setter
    private String openid;
}
