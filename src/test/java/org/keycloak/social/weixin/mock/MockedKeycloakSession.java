package org.keycloak.social.weixin.mock;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.models.cache.UserCache;
import org.keycloak.provider.Provider;
import org.keycloak.services.clientpolicy.ClientPolicyManager;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.storage.federated.UserFederatedStorageProvider;
import org.keycloak.vault.VaultTranscriber;

import java.util.Set;
import java.util.function.Function;

public class MockedKeycloakSession implements KeycloakSession {
    @Override
    public KeycloakContext getContext() {
        return null;
    }

    @Override
    public KeycloakTransactionManager getTransactionManager() {
        return null;
    }

    @Override
    public <T extends Provider> T getProvider(Class<T> aClass) {
        return null;
    }

    @Override
    public <T extends Provider> T getProvider(Class<T> aClass, String s) {
        return null;
    }

    @Override
    public <T extends Provider> T getComponentProvider(Class<T> aClass, String s) {
        return null;
    }

    @Override
    public <T extends Provider> T getComponentProvider(Class<T> aClass, String s, Function<KeycloakSessionFactory, ComponentModel> function) {
        return null;
    }

    @Override
    public <T extends Provider> T getProvider(Class<T> aClass, ComponentModel componentModel) {
        return null;
    }

    @Override
    public <T extends Provider> Set<String> listProviderIds(Class<T> aClass) {
        return null;
    }

    @Override
    public <T extends Provider> Set<T> getAllProviders(Class<T> aClass) {
        return null;
    }

    @Override
    public Class<? extends Provider> getProviderClass(String s) {
        return null;
    }

    @Override
    public Object getAttribute(String s) {
        return null;
    }

    @Override
    public <T> T getAttribute(String s, Class<T> aClass) {
        return null;
    }

    @Override
    public Object removeAttribute(String s) {
        return null;
    }

    @Override
    public void setAttribute(String s, Object o) {

    }

    @Override
    public void invalidate(InvalidableObjectType invalidableObjectType, Object... objects) {

    }

    @Override
    public void enlistForClose(Provider provider) {

    }

    @Override
    public KeycloakSessionFactory getKeycloakSessionFactory() {
        return null;
    }

    @Override
    public RealmProvider realms() {
        return null;
    }

    @Override
    public ClientProvider clients() {
        return null;
    }

    @Override
    public ClientScopeProvider clientScopes() {
        return null;
    }

    @Override
    public GroupProvider groups() {
        return null;
    }

    @Override
    public RoleProvider roles() {
        return null;
    }

    @Override
    public UserSessionProvider sessions() {
        return null;
    }

    @Override
    public UserLoginFailureProvider loginFailures() {
        return null;
    }

    @Override
    public AuthenticationSessionProvider authenticationSessions() {
        return null;
    }

    @Override
    public void close() {

    }

    @Override
    public UserCache userCache() {
        return null;
    }

    @Override
    public UserProvider users() {
        return null;
    }

    @Override
    public ClientProvider clientStorageManager() {
        return null;
    }

    @Override
    public ClientScopeProvider clientScopeStorageManager() {
        return null;
    }

    @Override
    public RoleProvider roleStorageManager() {
        return null;
    }

    @Override
    public GroupProvider groupStorageManager() {
        return null;
    }

    @Override
    public UserProvider userStorageManager() {
        return null;
    }

    @Override
    public UserCredentialManager userCredentialManager() {
        return null;
    }

    @Override
    public UserProvider userLocalStorage() {
        return null;
    }

    @Override
    public RealmProvider realmLocalStorage() {
        return null;
    }

    @Override
    public ClientProvider clientLocalStorage() {
        return null;
    }

    @Override
    public ClientScopeProvider clientScopeLocalStorage() {
        return null;
    }

    @Override
    public GroupProvider groupLocalStorage() {
        return null;
    }

    @Override
    public RoleProvider roleLocalStorage() {
        return null;
    }

    @Override
    public UserFederatedStorageProvider userFederatedStorage() {
        return null;
    }

    @Override
    public KeyManager keys() {
        return null;
    }

    @Override
    public ThemeManager theme() {
        return null;
    }

    @Override
    public TokenManager tokens() {
        return null;
    }

    @Override
    public VaultTranscriber vault() {
        return null;
    }

    @Override
    public ClientPolicyManager clientPolicy() {
        return null;
    }
}
