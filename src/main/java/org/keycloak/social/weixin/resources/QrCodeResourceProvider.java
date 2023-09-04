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
}
