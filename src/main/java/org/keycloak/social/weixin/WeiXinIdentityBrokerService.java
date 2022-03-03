package org.keycloak.social.weixin;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.PostBrokerLoginConstants;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.*;
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
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.SessionCodeChecks;
import org.keycloak.services.resources.account.AccountFormService;
import org.keycloak.services.util.BrowserHistoryHelper;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.concurrent.CancellationException;

public class WeiXinIdentityBrokerService implements IdentityProvider.AuthenticationCallback {
    private final RealmModel realmModel;
    private static final Logger logger = Logger.getLogger(IdentityBrokerService.class);
    private static final String LINKING_IDENTITY_PROVIDER = "LINKING_IDENTITY_PROVIDER";
    @Context
    private KeycloakSession session;

    @Context
    private HttpRequest request;

    @Context
    private ClientConnection clientConnection;

    private EventBuilder event;


    @Context
    private HttpHeaders headers;

    public void init(KeycloakSession session, ClientConnection clientConnection, HttpHeaders headers, EventBuilder event, HttpRequest request) {
        if (session != null) {
            this.session = session;
        }

        if (clientConnection != null) {
            this.clientConnection = clientConnection;
        }

        if (headers != null) {
            this.headers = headers;
        }

        if (request != null) {
            this.request = request;
        }

        logger.info("initializing ... realModel = " + Util.inspect("realmModel", realmModel));
        Util.inspect("session", this.session);
        Util.inspect("clientConnection", this.clientConnection);

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
            authSession.setAuthNote(AccountFormService.ACCOUNT_MGMT_FORWARDED_ERROR_NOTE, serializedError);
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

        logger.info("check with session = " + Util.inspect("session", session));

        if (code.equals("wmp")) {
            return ParsedCodeContext.clientSessionCode(new ClientSessionCode(session, realmModel, new WechatMiniProgramSession(session, this.realmModel, new UserModel() {
                @Override
                public String getId() {
                    return context.getId();
                }

                @Override
                public String getUsername() {
                    return context.getUsername();
                }

                @Override
                public void setUsername(String s) {

                }

                @Override
                public Long getCreatedTimestamp() {
                    return null;
                }

                @Override
                public void setCreatedTimestamp(Long aLong) {

                }

                @Override
                public boolean isEnabled() {
                    return true;
                }

                @Override
                public void setEnabled(boolean b) {

                }

                @Override
                public void setSingleAttribute(String s, String s1) {

                }

                @Override
                public void setAttribute(String s, List<String> list) {

                }

                @Override
                public void removeAttribute(String s) {

                }

                @Override
                public String getFirstAttribute(String s) {
                    return null;
                }

                @Override
                public List<String> getAttribute(String s) {
                    return Collections.singletonList(context.getUserAttribute(s));
                }

                @Override
                public Map<String, List<String>> getAttributes() {
                    return null;
                }

                @Override
                public Set<String> getRequiredActions() {
                    return null;
                }

                @Override
                public void addRequiredAction(String s) {

                }

                @Override
                public void removeRequiredAction(String s) {

                }

                @Override
                public String getFirstName() {
                    return context.getFirstName();
                }

                @Override
                public void setFirstName(String s) {

                }

                @Override
                public String getLastName() {
                    return context.getLastName();
                }

                @Override
                public void setLastName(String s) {

                }

                @Override
                public String getEmail() {
                    return context.getEmail();
                }

                @Override
                public void setEmail(String s) {

                }

                @Override
                public boolean isEmailVerified() {
                    return true;
                }

                @Override
                public void setEmailVerified(boolean b) {

                }

                @Override
                public Set<GroupModel> getGroups() {
                    return null;
                }

                @Override
                public void joinGroup(GroupModel groupModel) {

                }

                @Override
                public void leaveGroup(GroupModel groupModel) {

                }

                @Override
                public boolean isMemberOf(GroupModel groupModel) {
                    return false;
                }

                @Override
                public String getFederationLink() {
                    return null;
                }

                @Override
                public void setFederationLink(String s) {

                }

                @Override
                public String getServiceAccountClientLink() {
                    return null;
                }

                @Override
                public void setServiceAccountClientLink(String s) {

                }

                @Override
                public Set<RoleModel> getRealmRoleMappings() {
                    return null;
                }

                @Override
                public Set<RoleModel> getClientRoleMappings(ClientModel clientModel) {
                    return null;
                }

                @Override
                public boolean hasRole(RoleModel roleModel) {
                    return false;
                }

                @Override
                public void grantRole(RoleModel roleModel) {

                }

                @Override
                public Set<RoleModel> getRoleMappings() {
                    return null;
                }

                @Override
                public void deleteRoleMapping(RoleModel roleModel) {

                }
            })));
        }

        SessionCodeChecks checks = new SessionCodeChecks(realmModel, session.getContext().getUri(), request, clientConnection, session, event, null, code, null, clientId, tabId, LoginActionsService.AUTHENTICATE_PATH);

        logger.info(Util.inspect("checks = ", checks));

        checks.initialVerify();
        if (!checks.verifyActiveAndValidAction(AuthenticationSessionModel.Action.AUTHENTICATE.name(), ClientSessionCode.ActionType.LOGIN)) {
            AuthenticationSessionModel authSession = checks.getAuthenticationSession();

            if (authSession != null) {
                logger.info(Util.inspect("authSession = ", authSession));

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
        IdentityBrokerState state = IdentityBrokerState.encoded(encodedCode);
        String code = state.getDecodedState();
        String clientId = state.getClientId();
        String tabId = state.getTabId();

        logger.info("decoded session code = " + code + ", clientid = " + clientId + ", tabId = " + tabId);

        var res = parseSessionCode(code, clientId, tabId, context);
        logger.info("context = " + Util.inspect("context = ", res));

        return res;
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
                FederatedIdentityModel oldModel = this.session.users().getFederatedIdentity(federatedUser, context.getIdpConfig().getAlias(), this.realmModel);
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
        FederatedIdentityModel federatedIdentityModel = this.session.users().getFederatedIdentity(federatedUser, context.getIdpConfig().getAlias(), this.realmModel);

        // Skip DB write if tokens are null or equal
        updateToken(context, federatedUser, federatedIdentityModel);
        context.getIdp().updateBrokeredUser(session, realmModel, federatedUser, context);
        Set<IdentityProviderMapperModel> mappers = realmModel.getIdentityProviderMappersByAlias(context.getIdpConfig().getAlias());
        if (mappers != null) {
            KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
            for (IdentityProviderMapperModel mapper : mappers) {
                IdentityProviderMapper target = (IdentityProviderMapper) sessionFactory.getProviderFactory(IdentityProviderMapper.class, mapper.getIdentityProviderMapper());
                target.updateBrokeredUser(session, realmModel, federatedUser, mapper, context);
            }
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
            logger.info("login success state =  " + Util.inspect("state = ", state));

            if(state.toString().startsWith("wmp")) {
                return JsonResponse.fromJson("{\"success\": true}");
            }


            logger.info("Login success!");
            logger.info(Util.inspect("session", session));
            logger.info(Util.inspect("request", request));
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
                Set<IdentityProviderMapperModel> mappers = realmModel.getIdentityProviderMappersByAlias(providerId);
                if (mappers != null) {
                    KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
                    for (IdentityProviderMapperModel mapper : mappers) {
                        IdentityProviderMapper target = (IdentityProviderMapper) sessionFactory.getProviderFactory(IdentityProviderMapper.class, mapper.getIdentityProviderMapper());
                        target.importNewUser(session, realmModel, federatedUser, mapper, context);
                    }
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
        logger.info("BrokeredIdentityContext = " + Util.inspect("BrokeredIdentityContext", context));
        IdentityProviderModel identityProviderConfig = context.getIdpConfig();
        logger.info(Util.inspect("identityProviderConfig = ", identityProviderConfig));

        final Object state = context.getContextData().get("state");
        final ParsedCodeContext parsedCode = parseEncodedSessionCode(state.toString(), context);

        logger.info(Util.inspect("parsedCode", parsedCode));

        if (parsedCode.response != null) {
            logger.info("response = " + parsedCode.response);

            return parsedCode.response;
        }
        ClientSessionCode<AuthenticationSessionModel> clientCode = parsedCode.clientSessionCode;

        logger.info("client code = " + Util.inspect("client code = ", clientCode));

        String providerId = identityProviderConfig.getAlias();

        logger.info(Util.inspect("identityProviderConfig = ", identityProviderConfig));

        if (!identityProviderConfig.isStoreToken()) {
            logger.debugf("Token will not be stored for identity provider [%s].", providerId);
            context.setToken(null);
        }

        AuthenticationSessionModel authenticationSession = clientCode.getClientSession();
        logger.info(Util.inspect("authentication session = ", authenticationSession));
        context.setAuthenticationSession(authenticationSession);

        session.getContext().setClient(authenticationSession.getClient());

        context.getIdp().preprocessFederatedIdentity(session, realmModel, context);
        Set<IdentityProviderMapperModel> mappers = realmModel.getIdentityProviderMappersByAlias(context.getIdpConfig().getAlias());
        if (mappers != null) {
            KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
            for (IdentityProviderMapperModel mapper : mappers) {
                IdentityProviderMapper target = (IdentityProviderMapper) sessionFactory.getProviderFactory(IdentityProviderMapper.class, mapper.getIdentityProviderMapper());
                target.preprocessFederatedIdentity(session, realmModel, mapper, context);
            }
        }

        FederatedIdentityModel federatedIdentityModel = new FederatedIdentityModel(providerId, context.getId(),
                context.getUsername(), context.getToken());
        logger.info(Util.inspect("model = ", federatedIdentityModel));

        this.event.event(EventType.IDENTITY_PROVIDER_LOGIN)
                .detail(Details.REDIRECT_URI, authenticationSession.getRedirectUri())
                .detail(Details.IDENTITY_PROVIDER, providerId)
                .detail(Details.IDENTITY_PROVIDER_USERNAME, context.getUsername());

        logger.info(Util.inspect("realmModel = ", realmModel));
        UserModel federatedUser = this.session.users().getUserByFederatedIdentity(federatedIdentityModel, this.realmModel);

        logger.info("Federated = " + Util.inspect("federated = ", federatedUser));

        // Check if federatedUser is already authenticated (this means linking social into existing federatedUser account)
        final AuthenticationSessionManager authenticationSessionManager = new AuthenticationSessionManager(session);
        logger.info(Util.inspect("authSessionManager = ", authenticationSessionManager));

        UserSessionModel userSession = authenticationSessionManager.getUserSession(authenticationSession);

        logger.info("user session = " + Util.inspect("userSession = ", userSession));

        IdentityBrokerState theState = IdentityBrokerState.encoded(state.toString());

        if (theState.getDecodedState().equals("wmp")) {
            logger.info("it's wmp, let's return directly early. " + Util.inspect("theState", theState.getDecodedState()));
            return finishOrRedirectToPostBrokerLogin(authenticationSession, context, true, parsedCode.clientSessionCode);
        }

        if (shouldPerformAccountLinking(authenticationSession, userSession, providerId)) {
            logger.info("linking");
            return performAccountLinking(authenticationSession, userSession, context, federatedIdentityModel, federatedUser);
        }

        if (federatedUser == null) {
            if (theState.getDecodedState().equals("wmp")) {
                logger.info("it's wmp, let's return directly. " + Util.inspect("theState", theState.getDecodedState()));
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
    public Response cancelled() {
        throw new CancellationException("Cancelled!");
    }

    @Override
    public Response error(String s) {
        return null;
    }

    public static class ParsedCodeContext {
        private ClientSessionCode<AuthenticationSessionModel> clientSessionCode;
        private Response response;

        public static ParsedCodeContext clientSessionCode(ClientSessionCode<AuthenticationSessionModel> clientSessionCode) {
            ParsedCodeContext ctx = new ParsedCodeContext();
            ctx.clientSessionCode = clientSessionCode;
            return ctx;
        }

        public static ParsedCodeContext response(Response response) {
            ParsedCodeContext ctx = new ParsedCodeContext();
            ctx.response = response;
            return ctx;
        }
    }
}
