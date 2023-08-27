package org.keycloak.social.weixin;

import jakarta.ws.rs.core.*;
import org.jboss.logging.Logger;
import org.jboss.resteasy.plugins.server.BaseHttpRequest;
import org.jboss.resteasy.specimpl.ResteasyUriInfo;
import org.jboss.resteasy.spi.ResteasyAsynchronousContext;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.PostBrokerLoginConstants;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.ObjectUtil;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.HttpRequestImpl;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.SessionCodeChecks;
import org.keycloak.services.util.BrowserHistoryHelper;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.social.weixin.helpers.JsonHelper;
import org.keycloak.social.weixin.helpers.WMPHelper;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.*;
import java.util.concurrent.CancellationException;
import java.util.stream.Stream;

public class WeiXinIdentityBrokerService implements IdentityProvider.AuthenticationCallback {
    public final RealmModel realmModel;
    private static final Logger logger = Logger.getLogger(IdentityBrokerService.class);
    public static final String LINKING_IDENTITY_PROVIDER = "LINKING_IDENTITY_PROVIDER";

    @Context
    private KeycloakSession session;

    @Context
    private org.keycloak.http.HttpRequest request;

    @Context
    private ClientConnection clientConnection;

    private EventBuilder event;


    @Context
    private HttpHeaders headers;

    public void init(KeycloakSession session, ClientConnection clientConnection, EventBuilder event, org.keycloak.http.HttpRequest request) {
        if (session != null) {
            this.session = session;
        }

        this.clientConnection = Objects.requireNonNullElseGet(clientConnection, () -> new ClientConnection() {
            @Override
            public String getRemoteAddr() {
                return null;
            }

            @Override
            public String getRemoteHost() {
                return null;
            }

            @Override
            public int getRemotePort() {
                return 0;
            }

            @Override
            public String getLocalAddr() {
                return null;
            }

            @Override
            public int getLocalPort() {
                return 0;
            }
        });

        this.request = Objects.requireNonNullElseGet(request, () -> new HttpRequestImpl(new BaseHttpRequest(new ResteasyUriInfo("/", "/")) {
            @Override
            public HttpHeaders getHttpHeaders() {
                return Objects.requireNonNull(session).getContext().getRequestHeaders();
            }

            @Override
            public MultivaluedMap<String, String> getMutableHeaders() {
                return null;
            }

            @Override
            public InputStream getInputStream() {
                return null;
            }

            @Override
            public void setInputStream(InputStream stream) {

            }

            @Override
            public String getHttpMethod() {
                return null;
            }

            @Override
            public void setHttpMethod(String method) {

            }

            @Override
            public Object getAttribute(String attribute) {
                return null;
            }

            @Override
            public void setAttribute(String name, Object value) {

            }

            @Override
            public void removeAttribute(String name) {

            }

            @Override
            public Enumeration<String> getAttributeNames() {
                return null;
            }

            @Override
            public ResteasyAsynchronousContext getAsyncContext() {
                return null;
            }

            @Override
            public void forward(String path) {

            }

            @Override
            public boolean wasForwarded() {
                return false;
            }

            @Override
            public String getRemoteAddress() {
                return null;
            }

            @Override
            public String getRemoteHost() {
                return null;
            }
        }));

        this.event = Objects.requireNonNullElseGet(event, () -> new EventBuilder(this.realmModel, this.session, this.clientConnection)).event(EventType.IDENTITY_PROVIDER_LOGIN);
    }

    public WeiXinIdentityBrokerService(RealmModel realmModel) {
        if (realmModel == null) {
            throw new IllegalArgumentException("Realm can not be null.");
        }
        this.realmModel = realmModel;
    }

    private Response redirectToErrorPage(Response.Status status, String message, Object... parameters) {
        return redirectToErrorPage(null, status, message, null, parameters);
    }

    private Response redirectToErrorPage(AuthenticationSessionModel authSession, Response.Status status, String message, Object... parameters) {
        return redirectToErrorPage(authSession, status, message, null, parameters);
    }

    private void fireErrorEvent(String message) {
        fireErrorEvent(message, null);
    }

    private void rollback() {
        if (this.session.getTransactionManager().isActive()) {
            this.session.getTransactionManager().rollback();
        }
    }

    private void fireErrorEvent(String message, Throwable throwable) {
        if (!this.event.getEvent().getType().toString().endsWith("_ERROR")) {
            boolean newTransaction = !this.session.getTransactionManager().isActive();

            try {
                if (newTransaction) {
                    this.session.getTransactionManager().begin();
                }

                this.event.error(message);

                if (newTransaction) {
                    this.session.getTransactionManager().commit();
                }
            } catch (Exception e) {
                ServicesLogger.LOGGER.couldNotFireEvent(e);
                rollback();
            }
        }

        if (throwable != null) {
            logger.error(message, throwable);
        } else {
            logger.error(message);
        }
    }

    private Response redirectToAccountErrorPage(AuthenticationSessionModel authSession, String message, Object... parameters) {
        fireErrorEvent(message);

        FormMessage errorMessage = new FormMessage(message, parameters);
        try {
            String serializedError = JsonSerialization.writeValueAsString(errorMessage);
            authSession.setAuthNote("accountMgmtForwardedError", serializedError);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        URI accountServiceUri = UriBuilder.fromUri(authSession.getRedirectUri()).queryParam(Constants.TAB_ID, authSession.getTabId()).build();
        return Response.status(302).location(accountServiceUri).build();
    }

    private Response checkAccountManagementFailedLinking(AuthenticationSessionModel authSession, String error, Object... parameters) {
        UserSessionModel userSession = new AuthenticationSessionManager(session).getUserSession(authSession);
        if (userSession != null && authSession.getClient() != null && authSession.getClient().getClientId().equals(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID)) {

            this.event.event(EventType.FEDERATED_IDENTITY_LINK);
            UserModel user = userSession.getUser();
            this.event.user(user);
            this.event.detail(Details.USERNAME, user.getUsername());

            return redirectToAccountErrorPage(authSession, error, parameters);
        } else {
            return null;
        }
    }

    private ParsedCodeContext parseSessionCode(String code, String clientId, String tabId, BrokeredIdentityContext context) {
        logger.info("parsing with code = " + code + ", clientId = " + clientId + ", tabId = " + tabId);

        if (code == null || clientId == null || tabId == null) {
            System.out.printf("Invalid request. Authorization code, clientId or tabId was null. Code=%s, " +
                            "clientId=%s, tabID=%s", code
                    , clientId, tabId);
            Response staleCodeError = redirectToErrorPage(Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
            return ParsedCodeContext.response(staleCodeError);
        }

        if (code.equals("wmp")) {
            return ParsedCodeContext.clientSessionCode(WMPHelper.getClientSessionCode(this, realmModel, session, context));
        }

        SessionCodeChecks checks = new SessionCodeChecks(realmModel, session.getContext().getUri(), request, clientConnection, session, event, null, code, null, clientId, tabId, LoginActionsService.AUTHENTICATE_PATH);

        checks.initialVerify();
        if (!checks.verifyActiveAndValidAction(AuthenticationSessionModel.Action.AUTHENTICATE.name(), ClientSessionCode.ActionType.LOGIN)) {
            AuthenticationSessionModel authSession = checks.getAuthenticationSession();

            if (authSession != null) {
                if (code.equals("wmp")) {
                    return ParsedCodeContext.response(checks.getResponse());
                }

                // Check if error happened during login or during linking from account management
                Response accountManagementFailedLinking = checkAccountManagementFailedLinking(authSession, Messages.STALE_CODE_ACCOUNT);
                if (accountManagementFailedLinking != null) {
                    return ParsedCodeContext.response(accountManagementFailedLinking);
                } else {
                    Response errorResponse = checks.getResponse();

                    // Remove "code" from browser history
                    errorResponse = BrowserHistoryHelper.getInstance().saveResponseAndRedirect(session, authSession, errorResponse, true, request);
                    return ParsedCodeContext.response(errorResponse);
                }
            } else {
                return ParsedCodeContext.response(checks.getResponse());
            }
        } else {
            logger.debugf("Authorization code is valid.");

            return ParsedCodeContext.clientSessionCode(checks.getClientCode());
        }
    }

    private ParsedCodeContext parseEncodedSessionCode(String encodedCode, BrokeredIdentityContext context) {
        IdentityBrokerState state = IdentityBrokerState.encoded(encodedCode, realmModel);
        String code = state.getDecodedState();
        String clientId = state.getClientId();
        String tabId = state.getTabId();

        logger.info("decoded session code = " + code + ", clientid = " + clientId + ", tabId = " + tabId);

        return parseSessionCode(code, clientId, tabId, context);
    }

    private boolean shouldPerformAccountLinking(AuthenticationSessionModel authSession, UserSessionModel userSession, String providerId) {
        String noteFromSession = authSession.getAuthNote(LINKING_IDENTITY_PROVIDER);

        if (noteFromSession == null) {
            return false;
        }

        boolean linkingValid;
        if (userSession == null) {
            linkingValid = false;
        } else {
            String expectedNote = userSession.getId() + authSession.getClient().getClientId() + providerId;
            logger.info("expecting note = " + expectedNote);
            linkingValid = expectedNote.equals(noteFromSession);
        }

        if (linkingValid) {
            authSession.removeAuthNote(LINKING_IDENTITY_PROVIDER);
            return true;
        } else {
            throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.BROKER_LINKING_SESSION_EXPIRED);
        }
    }


    private Response redirectToErrorWhenLinkingFailed(AuthenticationSessionModel authSession, String message, Object... parameters) {
        if (authSession.getClient() != null && authSession.getClient().getClientId().equals(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID)) {
            return redirectToAccountErrorPage(authSession, message, parameters);
        } else {
            return redirectToErrorPage(authSession, Response.Status.BAD_REQUEST, message, parameters); // Should rather redirect to app instead and display error here?
        }
    }


    private Response performAccountLinking(AuthenticationSessionModel authSession, UserSessionModel userSession, BrokeredIdentityContext context, FederatedIdentityModel newModel, UserModel federatedUser) {
        logger.debugf("Will try to link identity provider [%s] to user [%s]", context.getIdpConfig().getAlias(), userSession.getUser().getUsername());

        this.event.event(EventType.FEDERATED_IDENTITY_LINK);


        UserModel authenticatedUser = userSession.getUser();
        authSession.setAuthenticatedUser(authenticatedUser);

        if (federatedUser != null && !authenticatedUser.getId().equals(federatedUser.getId())) {
            return redirectToErrorWhenLinkingFailed(authSession, Messages.IDENTITY_PROVIDER_ALREADY_LINKED, context.getIdpConfig().getAlias());
        }

        if (!authenticatedUser.hasRole(this.realmModel.getClientByClientId(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID).getRole(AccountRoles.MANAGE_ACCOUNT))) {
            return redirectToErrorPage(authSession, Response.Status.FORBIDDEN, Messages.INSUFFICIENT_PERMISSION);
        }

        if (!authenticatedUser.isEnabled()) {
            return redirectToErrorWhenLinkingFailed(authSession, Messages.ACCOUNT_DISABLED);
        }


        if (federatedUser != null) {
            if (context.getIdpConfig().isStoreToken()) {
                FederatedIdentityModel oldModel = this.session.users().getFederatedIdentity(this.realmModel, federatedUser, context.getIdpConfig().getAlias());
                if (!ObjectUtil.isEqualOrBothNull(context.getToken(), oldModel.getToken())) {
                    this.session.users().updateFederatedIdentity(this.realmModel, federatedUser, newModel);
                    logger.debugf("Identity [%s] update with response from identity provider [%s].", federatedUser, context.getIdpConfig().getAlias());
                }
            }
        } else {
            this.session.users().addFederatedIdentity(this.realmModel, authenticatedUser, newModel);
        }
        context.getIdp().authenticationFinished(authSession, context);

        AuthenticationManager.setClientScopesInSession(authSession);
        TokenManager.attachAuthenticationSession(session, userSession, authSession);

        logger.debugf("Linking account [%s] from identity provider [%s] to user [%s].", newModel, context.getIdpConfig().getAlias(), authenticatedUser);

        this.event.user(authenticatedUser)
                .detail(Details.USERNAME, authenticatedUser.getUsername())
                .detail(Details.IDENTITY_PROVIDER, newModel.getIdentityProvider())
                .detail(Details.IDENTITY_PROVIDER_USERNAME, newModel.getUserName())
                .success();

        // we do this to make sure that the parent IDP is logged out when this user session is complete.
        // But for the case when userSession was previously authenticated with broker1 and now is linked to another broker2, we shouldn't override broker1 notes with the broker2 for sure.
        // Maybe broker logout should be rather always skiped in case of broker-linking
        if (userSession.getNote(Details.IDENTITY_PROVIDER) == null) {
            userSession.setNote(Details.IDENTITY_PROVIDER, context.getIdpConfig().getAlias());
            userSession.setNote(Details.IDENTITY_PROVIDER_USERNAME, context.getUsername());
        }

        return Response.status(302).location(UriBuilder.fromUri(authSession.getRedirectUri()).build()).build();
    }


    public Response validateUser(AuthenticationSessionModel authSession, UserModel user, RealmModel realm) {
        if (!user.isEnabled()) {
            event.error(Errors.USER_DISABLED);
            return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, Messages.ACCOUNT_DISABLED);
        }
        if (realm.isBruteForceProtected()) {
            if (session.getProvider(BruteForceProtector.class).isTemporarilyDisabled(session, realm, user)) {
                event.error(Errors.USER_TEMPORARILY_DISABLED);
                return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, Messages.ACCOUNT_DISABLED);
            }
        }
        return null;
    }

    private void updateToken(BrokeredIdentityContext context, UserModel federatedUser, FederatedIdentityModel federatedIdentityModel) {
        if (context.getIdpConfig().isStoreToken() && !ObjectUtil.isEqualOrBothNull(context.getToken(), federatedIdentityModel.getToken())) {
            federatedIdentityModel.setToken(context.getToken());

            this.session.users().updateFederatedIdentity(this.realmModel, federatedUser, federatedIdentityModel);

            logger.debugf("Identity [%s] update with response from identity provider [%s].", federatedUser, context.getIdpConfig().getAlias());
        }
    }

    private void updateFederatedIdentity(BrokeredIdentityContext context, UserModel federatedUser) {
        FederatedIdentityModel federatedIdentityModel = this.session.users().getFederatedIdentity(this.realmModel, federatedUser, context.getIdpConfig().getAlias());

        // Skip DB write if tokens are null or equal
        updateToken(context, federatedUser, federatedIdentityModel);
        context.getIdp().updateBrokeredUser(session, realmModel, federatedUser, context);
        Stream<IdentityProviderMapperModel> mappers = realmModel.getIdentityProviderMappersByAliasStream(context.getIdpConfig().getAlias());
        if (mappers != null) {
            KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
            mappers.forEachOrdered(mapper -> {
                IdentityProviderMapper target = (IdentityProviderMapper) sessionFactory.getProviderFactory(IdentityProviderMapper.class, mapper.getIdentityProviderMapper());
                target.updateBrokeredUser(session, realmModel, federatedUser, mapper, context);
            });
        }

    }

    private Response checkPassiveLoginError(AuthenticationSessionModel authSession, String message) {
        LoginProtocol.Error error = OAuthErrorException.LOGIN_REQUIRED.equals(message) ? LoginProtocol.Error.PASSIVE_LOGIN_REQUIRED :
                (OAuthErrorException.INTERACTION_REQUIRED.equals(message) ? LoginProtocol.Error.PASSIVE_INTERACTION_REQUIRED : null);
        if (error != null) {
            LoginProtocol protocol = session.getProvider(LoginProtocol.class, authSession.getProtocol());
            protocol.setRealm(realmModel)
                    .setHttpHeaders(headers)
                    .setUriInfo(session.getContext().getUri())
                    .setEventBuilder(event);
            return protocol.sendError(authSession, error);
        }
        return null;
    }

    private Response finishBrokerAuthentication(BrokeredIdentityContext context, UserModel federatedUser, AuthenticationSessionModel authSession, String providerId) {
        authSession.setAuthNote(AuthenticationProcessor.BROKER_SESSION_ID, context.getBrokerSessionId());
        authSession.setAuthNote(AuthenticationProcessor.BROKER_USER_ID, context.getBrokerUserId());

        this.event.user(federatedUser);

        context.getIdp().authenticationFinished(authSession, context);
        authSession.setUserSessionNote(Details.IDENTITY_PROVIDER, providerId);
        authSession.setUserSessionNote(Details.IDENTITY_PROVIDER_USERNAME, context.getUsername());

        event.detail(Details.IDENTITY_PROVIDER, providerId)
                .detail(Details.IDENTITY_PROVIDER_USERNAME, context.getUsername());

        logger.debugf("Performing local authentication for user [%s].", federatedUser);

        AuthenticationManager.setClientScopesInSession(authSession);

        String nextRequiredAction = AuthenticationManager.nextRequiredAction(session, authSession, request, event);

        logger.info("nextRequiredAction = " + nextRequiredAction);

        if (nextRequiredAction != null) {
            if ("true".equals(authSession.getAuthNote(AuthenticationProcessor.FORWARDED_PASSIVE_LOGIN))) {
                logger.errorf("Required action %s found. Auth requests using prompt=none are incompatible with required actions", nextRequiredAction);
                return checkPassiveLoginError(authSession, OAuthErrorException.INTERACTION_REQUIRED);
            }
            return AuthenticationManager.redirectToRequiredActions(session, realmModel, authSession, session.getContext().getUri(), nextRequiredAction);
        } else {
            event.detail(Details.CODE_ID, authSession.getParentSession().getId());  // todo This should be set elsewhere.  find out why tests fail.  Don't know where this is supposed to be set

            var contextData = context.getContextData();
            var state = contextData.get("state");
            logger.info("Login success!");

            if (state.toString().startsWith("wmp")) {
                final AuthenticationSessionManager authenticationSessionManager = new AuthenticationSessionManager(session);
                UserSessionModel userSession = authenticationSessionManager.getUserSession(authSession);

                if (userSession == null) {
                    userSession = WMPHelper.getUserSessionModel(context, federatedUser, authSession);
                }

                AuthenticationManager.createLoginCookie(this.session, realmModel, userSession.getUser(), userSession, session.getContext().getUri(), this.clientConnection);

                return JsonResponse.fromJson(JsonHelper.stringify(userSession));
            }

            return AuthenticationManager.finishedRequiredActions(session, authSession, null, clientConnection, request, session.getContext().getUri(), event);
        }
    }

    private Response afterFirstBrokerLogin(ClientSessionCode<AuthenticationSessionModel> clientSessionCode) {
        AuthenticationSessionModel authSession = clientSessionCode.getClientSession();
        try {
            this.event.detail(Details.CODE_ID, authSession.getParentSession().getId())
                    .removeDetail("auth_method");

            SerializedBrokeredIdentityContext serializedCtx = SerializedBrokeredIdentityContext.readFromAuthenticationSession(authSession, AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
            if (serializedCtx == null) {
                throw new IdentityBrokerException("Not found serialized context in clientSession");
            }
            BrokeredIdentityContext context = serializedCtx.deserialize(session, authSession);
            String providerId = context.getIdpConfig().getAlias();

            event.detail(Details.IDENTITY_PROVIDER, providerId);
            event.detail(Details.IDENTITY_PROVIDER_USERNAME, context.getUsername());

            // Ensure the first-broker-login flow was successfully finished
            String authProvider = authSession.getAuthNote(AbstractIdpAuthenticator.FIRST_BROKER_LOGIN_SUCCESS);
            if (authProvider == null || !authProvider.equals(providerId)) {
                throw new IdentityBrokerException("Invalid request. Not found the flag that first-broker-login flow was finished");
            }

            // firstBrokerLogin workflow finished. Removing note now
            authSession.removeAuthNote(AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);

            UserModel federatedUser = authSession.getAuthenticatedUser();
            if (federatedUser == null) {
                throw new IdentityBrokerException("Couldn't found authenticated federatedUser in authentication session");
            }

            event.user(federatedUser);
            event.detail(Details.USERNAME, federatedUser.getUsername());

            if (context.getIdpConfig().isAddReadTokenRoleOnCreate()) {
                ClientModel brokerClient = realmModel.getClientByClientId(Constants.BROKER_SERVICE_CLIENT_ID);
                if (brokerClient == null) {
                    throw new IdentityBrokerException("Client 'broker' not available. Maybe realm has not migrated to support the broker token exchange service");
                }
                RoleModel readTokenRole = brokerClient.getRole(Constants.READ_TOKEN_ROLE);
                federatedUser.grantRole(readTokenRole);
            }

            // Add federated identity link here
            FederatedIdentityModel federatedIdentityModel = new FederatedIdentityModel(context.getIdpConfig().getAlias(), context.getId(),
                    context.getUsername(), context.getToken());
            session.users().addFederatedIdentity(realmModel, federatedUser, federatedIdentityModel);


            String isRegisteredNewUser = authSession.getAuthNote(AbstractIdpAuthenticator.BROKER_REGISTERED_NEW_USER);
            if (Boolean.parseBoolean(isRegisteredNewUser)) {

                logger.debugf("Registered new user '%s' after first login with identity provider '%s'. Identity provider username is '%s' . ", federatedUser.getUsername(), providerId, context.getUsername());

                context.getIdp().importNewUser(session, realmModel, federatedUser, context);
                Stream<IdentityProviderMapperModel> mappers = realmModel.getIdentityProviderMappersByAliasStream(providerId);
                if (mappers != null) {
                    KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
                    mappers.forEachOrdered(mapper -> {
                        IdentityProviderMapper target = (IdentityProviderMapper) sessionFactory.getProviderFactory(IdentityProviderMapper.class, mapper.getIdentityProviderMapper());
                        target.importNewUser(session, realmModel, federatedUser, mapper, context);
                    });
                }

                if (context.getIdpConfig().isTrustEmail() && !Validation.isBlank(federatedUser.getEmail()) && !Boolean.parseBoolean(authSession.getAuthNote(AbstractIdpAuthenticator.UPDATE_PROFILE_EMAIL_CHANGED))) {
                    logger.debugf("Email verified automatically after registration of user '%s' through Identity provider '%s' ", federatedUser.getUsername(), context.getIdpConfig().getAlias());
                    federatedUser.setEmailVerified(true);
                }

                event.event(EventType.REGISTER)
                        .detail(Details.REGISTER_METHOD, "broker")
                        .detail(Details.EMAIL, federatedUser.getEmail())
                        .success();

            } else {
                logger.debugf("Linked existing keycloak user '%s' with identity provider '%s' . Identity provider username is '%s' .", federatedUser.getUsername(), providerId, context.getUsername());

                event.event(EventType.FEDERATED_IDENTITY_LINK)
                        .success();

                updateFederatedIdentity(context, federatedUser);
            }

            return finishOrRedirectToPostBrokerLogin(authSession, context, true, clientSessionCode);

        } catch (Exception e) {
            return redirectToErrorPage(authSession, Response.Status.INTERNAL_SERVER_ERROR, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR, e);
        }
    }

    private Response afterPostBrokerLoginFlowSuccess(AuthenticationSessionModel authSession, BrokeredIdentityContext context, boolean wasFirstBrokerLogin, ClientSessionCode<AuthenticationSessionModel> clientSessionCode) {
        String providerId = context.getIdpConfig().getAlias();
        UserModel federatedUser = authSession.getAuthenticatedUser();

        if (wasFirstBrokerLogin) {
            return finishBrokerAuthentication(context, federatedUser, authSession, providerId);
        } else {

            boolean firstBrokerLoginInProgress = (authSession.getAuthNote(AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE) != null);
            if (firstBrokerLoginInProgress) {
                logger.debugf("Reauthenticated with broker '%s' when linking user '%s' with other broker", context.getIdpConfig().getAlias(), federatedUser.getUsername());

                UserModel linkingUser = AbstractIdpAuthenticator.getExistingUser(session, realmModel, authSession);
                if (!linkingUser.getId().equals(federatedUser.getId())) {
                    return redirectToErrorPage(authSession, Response.Status.BAD_REQUEST, "identityProviderDifferentUserMessage", federatedUser.getUsername(), linkingUser.getUsername());
                }

                SerializedBrokeredIdentityContext serializedCtx = SerializedBrokeredIdentityContext.readFromAuthenticationSession(authSession, AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
                authSession.setAuthNote(AbstractIdpAuthenticator.FIRST_BROKER_LOGIN_SUCCESS, serializedCtx.getIdentityProviderId());

                return afterFirstBrokerLogin(clientSessionCode);
            } else {
                return finishBrokerAuthentication(context, federatedUser, authSession, providerId);
            }
        }
    }

    private Response finishOrRedirectToPostBrokerLogin(AuthenticationSessionModel authSession, BrokeredIdentityContext context, boolean wasFirstBrokerLogin, ClientSessionCode<AuthenticationSessionModel> clientSessionCode) {
        String postBrokerLoginFlowId = context.getIdpConfig().getPostBrokerLoginFlowId();
        if (postBrokerLoginFlowId == null) {

            logger.debugf("Skip redirect to postBrokerLogin flow. PostBrokerLogin flow not set for identityProvider '%s'.", context.getIdpConfig().getAlias());
            return afterPostBrokerLoginFlowSuccess(authSession, context, wasFirstBrokerLogin, clientSessionCode);
        } else {

            logger.debugf("Redirect to postBrokerLogin flow after authentication with identityProvider '%s'.", context.getIdpConfig().getAlias());

            authSession.getParentSession().setTimestamp(Time.currentTime());

            SerializedBrokeredIdentityContext ctx = SerializedBrokeredIdentityContext.serialize(context);
            ctx.saveToAuthenticationSession(authSession, PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT);

            authSession.setAuthNote(PostBrokerLoginConstants.PBL_AFTER_FIRST_BROKER_LOGIN, String.valueOf(wasFirstBrokerLogin));

            URI redirect = LoginActionsService.postBrokerLoginProcessor(session.getContext().getUri())
                    .queryParam(Constants.CLIENT_ID, authSession.getClient().getClientId())
                    .queryParam(Constants.TAB_ID, authSession.getTabId())
                    .build(realmModel.getName());
            return Response.status(302).location(redirect).build();
        }
    }


    @Override
    public AuthenticationSessionModel getAndVerifyAuthenticationSession(String s) {
        return null;
    }

    @Override
    public Response authenticated(BrokeredIdentityContext context) {
        IdentityProviderModel identityProviderConfig = context.getIdpConfig();

        final Object state = context.getContextData().get("state");
        final ParsedCodeContext parsedCode = parseEncodedSessionCode(state.toString(), context);

        if (parsedCode.response != null) {
            logger.info("response = " + parsedCode.response);

            return parsedCode.response;
        }
        ClientSessionCode<AuthenticationSessionModel> clientCode = parsedCode.clientSessionCode;

        String providerId = identityProviderConfig.getAlias();

        if (!identityProviderConfig.isStoreToken()) {
            logger.debugf("Token will not be stored for identity provider [%s].", providerId);
            context.setToken(null);
        }

        AuthenticationSessionModel authenticationSession = clientCode.getClientSession();
        context.setAuthenticationSession(authenticationSession);

        session.getContext().setClient(authenticationSession.getClient());

        context.getIdp().preprocessFederatedIdentity(session, realmModel, context);
        Stream<IdentityProviderMapperModel> mappers = realmModel.getIdentityProviderMappersByAliasStream(context.getIdpConfig().getAlias());

        if (mappers != null) {
            KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();

            mappers.forEachOrdered(mapper -> {
                IdentityProviderMapper target = (IdentityProviderMapper) sessionFactory.getProviderFactory(IdentityProviderMapper.class, mapper.getIdentityProviderMapper());
                target.preprocessFederatedIdentity(session, realmModel, mapper, context);
            });
        }

        FederatedIdentityModel federatedIdentityModel = new FederatedIdentityModel(providerId, context.getId(),
                context.getUsername(), context.getToken());

        this.event.event(EventType.IDENTITY_PROVIDER_LOGIN)
                .detail(Details.REDIRECT_URI, authenticationSession.getRedirectUri())
                .detail(Details.IDENTITY_PROVIDER, providerId)
                .detail(Details.IDENTITY_PROVIDER_USERNAME, context.getUsername());

        final UserProvider users = this.session.users();

        // Check if federatedUser is already authenticated (this means linking social into existing federatedUser account)
        final AuthenticationSessionManager authenticationSessionManager = new AuthenticationSessionManager(session);

        UserSessionModel userSession = authenticationSessionManager.getUserSession(authenticationSession);

        UserModel federatedUser = users.getUserByFederatedIdentity(this.realmModel, federatedIdentityModel);

        if (shouldPerformAccountLinking(authenticationSession, userSession, providerId)) {
            logger.info("linking");
            return performAccountLinking(authenticationSession, userSession, context, federatedIdentityModel, federatedUser);
        }

        if (federatedUser == null) {
            IdentityBrokerState theState = IdentityBrokerState.encoded(state.toString(), realmModel);

            if (theState.getDecodedState().equals("wmp")) {
                return finishOrRedirectToPostBrokerLogin(authenticationSession, context, false, parsedCode.clientSessionCode);
            }

            logger.debugf("Federated user not found for provider '%s' and broker username '%s' . Redirecting to flow for firstBrokerLogin", providerId, context.getUsername());

            String username = context.getModelUsername();
            if (username == null) {
                if (this.realmModel.isRegistrationEmailAsUsername() && !Validation.isBlank(context.getEmail())) {
                    username = context.getEmail();
                } else if (context.getUsername() == null) {
                    username = context.getIdpConfig().getAlias() + "." + context.getId();
                } else {
                    username = context.getUsername();
                }
            }
            username = username.trim();
            context.setModelUsername(username);

            boolean forwardedPassiveLogin = "true".equals(authenticationSession.getAuthNote(AuthenticationProcessor.FORWARDED_PASSIVE_LOGIN));
            // Redirect to firstBrokerLogin after successful login and ensure that previous authentication state removed
            AuthenticationProcessor.resetFlow(authenticationSession, LoginActionsService.FIRST_BROKER_LOGIN_PATH);

            // Set the FORWARDED_PASSIVE_LOGIN note (if needed) after resetting the session so it is not lost.
            if (forwardedPassiveLogin) {
                authenticationSession.setAuthNote(AuthenticationProcessor.FORWARDED_PASSIVE_LOGIN, "true");
            }

            SerializedBrokeredIdentityContext ctx = SerializedBrokeredIdentityContext.serialize(context);
            ctx.saveToAuthenticationSession(authenticationSession, AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);

            URI redirect = LoginActionsService.firstBrokerLoginProcessor(session.getContext().getUri())
                    .queryParam(Constants.CLIENT_ID, authenticationSession.getClient().getClientId())
                    .queryParam(Constants.TAB_ID, authenticationSession.getTabId())
                    .build(realmModel.getName());
            return Response.status(302).location(redirect).build();

        } else {
            Response response = validateUser(authenticationSession, federatedUser, realmModel);
            if (response != null) {
                return response;
            }

            updateFederatedIdentity(context, federatedUser);
            authenticationSession.setAuthenticatedUser(federatedUser);

            return finishOrRedirectToPostBrokerLogin(authenticationSession, context, false, parsedCode.clientSessionCode);
        }
    }

    @Override
    public Response cancelled(IdentityProviderModel idpConfig) {
        throw new CancellationException("Cancelled!");
    }

    @Override
    public Response error(String s) {
        return null;
    }

}
