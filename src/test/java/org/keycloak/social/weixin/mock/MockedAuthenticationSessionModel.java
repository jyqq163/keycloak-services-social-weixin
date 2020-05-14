package org.keycloak.social.weixin.mock;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import java.util.Map;
import java.util.Set;

public class MockedAuthenticationSessionModel implements AuthenticationSessionModel {
    @Override
    public String getTabId() {
        return null;
    }

    @Override
    public RootAuthenticationSessionModel getParentSession() {
        return null;
    }

    @Override
    public Map<String, ExecutionStatus> getExecutionStatus() {
        return null;
    }

    @Override
    public void setExecutionStatus(String s, ExecutionStatus executionStatus) {

    }

    @Override
    public void clearExecutionStatus() {

    }

    @Override
    public UserModel getAuthenticatedUser() {
        return null;
    }

    @Override
    public void setAuthenticatedUser(UserModel userModel) {

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
    public void addRequiredAction(UserModel.RequiredAction requiredAction) {

    }

    @Override
    public void removeRequiredAction(UserModel.RequiredAction requiredAction) {

    }

    @Override
    public void setUserSessionNote(String s, String s1) {

    }

    @Override
    public Map<String, String> getUserSessionNotes() {
        return null;
    }

    @Override
    public void clearUserSessionNotes() {

    }

    @Override
    public String getAuthNote(String s) {
        return null;
    }

    @Override
    public void setAuthNote(String s, String s1) {

    }

    @Override
    public void removeAuthNote(String s) {

    }

    @Override
    public void clearAuthNotes() {

    }

    @Override
    public String getClientNote(String s) {
        return null;
    }

    @Override
    public void setClientNote(String s, String s1) {

    }

    @Override
    public void removeClientNote(String s) {

    }

    @Override
    public Map<String, String> getClientNotes() {
        return null;
    }

    @Override
    public void clearClientNotes() {

    }

    @Override
    public Set<String> getClientScopes() {
        return null;
    }

    @Override
    public void setClientScopes(Set<String> set) {

    }

    @Override
    public String getRedirectUri() {
        return null;
    }

    @Override
    public void setRedirectUri(String s) {

    }

    @Override
    public RealmModel getRealm() {
        return null;
    }

    @Override
    public ClientModel getClient() {
        return null;
    }

    @Override
    public String getAction() {
        return null;
    }

    @Override
    public void setAction(String s) {

    }

    @Override
    public String getProtocol() {
        return null;
    }

    @Override
    public void setProtocol(String s) {

    }
}
