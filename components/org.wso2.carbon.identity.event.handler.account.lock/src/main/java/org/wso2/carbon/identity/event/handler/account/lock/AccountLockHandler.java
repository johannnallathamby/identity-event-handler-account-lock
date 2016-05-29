/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations und
 */

package org.wso2.carbon.identity.event.handler.account.lock;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.event.handler.account.lock.exception.AccountLockException;
import org.wso2.carbon.identity.event.handler.account.lock.internal.IdentityAccountLockServiceDataHolder;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.EventMgtConstants;
import org.wso2.carbon.identity.event.EventMgtException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.handler.account.lock.util.AccountLockUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityGovernanceConnector;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class AccountLockHandler extends AbstractEventHandler implements IdentityGovernanceConnector {

    private static final Log log = LogFactory.getLog(AccountLockHandler.class);

    private static ThreadLocal<String> lockedState = new ThreadLocal<>();

    private enum lockedStates {LOCKED_MODIFIED, UNLOCKED_MODIFIED, LOCKED_UNMODIFIED, UNLOCKED_UNMODIFIED}

    public String getName() {
        return "account.lock.handler";
    }

    public String getFriendlyName() {
        return "Account Locking Connector";
    }

    @Override
    public void init(InitConfig initConfig) {
        super.init(initConfig);
        IdentityAccountLockServiceDataHolder.getInstance().getBundleContext().registerService
                (IdentityGovernanceConnector.class.getName(), this, null);
    }

    @Override
    public boolean handleEvent(Event event) throws EventMgtException {

        IdentityUtil.clearIdentityErrorMsg();

        Map<String, Object> eventProperties = event.getEventProperties();
        String userName = (String) eventProperties.get(EventMgtConstants.EventProperty.USER_NAME);
        UserStoreManager userStoreManager = (UserStoreManager) eventProperties.get(EventMgtConstants.EventProperty.USER_STORE_MANAGER);
        String userStoreDomainName = AccountLockUtil.getUserStoreDomainName(userStoreManager);
        String tenantDomain = (String) eventProperties.get(EventMgtConstants.EventProperty.TENANT_DOMAIN);

        Map<String, String> idpProperties = null;
        try {
            idpProperties = IdentityAccountLockServiceDataHolder.getInstance()
                    .getIdentityGovernanceService().getConfiguration(getPropertyNames(), tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw new EventMgtException("Error while retrieving Account Locking Handler properties.", e);
        }

        if (!Boolean.parseBoolean(idpProperties.get(AccountLockConstants.ACCOUNT_LOCKED_PROPERTY))) {
            return true;
        }

        String usernameWithDomain = UserCoreUtil.addDomainToName(userName, userStoreDomainName);
        boolean userExists;
        try {
            userExists = userStoreManager.isExistingUser(usernameWithDomain);
        } catch (UserStoreException e) {
            throw new EventMgtException("Error in accessing user store");
        }
        if(!userExists) {
            return true;
        }

        if (EventMgtConstants.Event.PRE_AUTHENTICATION.equals(event.getEventName())) {
            handlePreAuthentication(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                                    idpProperties);
        } else if (EventMgtConstants.Event.POST_AUTHENTICATION.equals(event.getEventName())) {
            handlePostAuthentication(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                                     idpProperties);
        } else if (EventMgtConstants.Event.PRE_SET_USER_CLAIMS.equals(event.getEventName())) {
            handlePreSetUserClaimValues(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                                        idpProperties);
        } else if (EventMgtConstants.Event.POST_SET_USER_CLAIMS.equals(event.getEventName())) {
            handlePostSetUserClaimValues(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                                         idpProperties);
        }
        return true;
    }

    protected boolean handlePreAuthentication(Event event, String userName, UserStoreManager userStoreManager,
                                              String userStoreDomainName, String tenantDomain,
                                              Map<String,String> idpProperties) throws AccountLockException {

        String accountLockedClaim = null;
        try {
            accountLockedClaim = userStoreManager.getUserClaimValue(userName,
                                                                    AccountLockConstants.ACCOUNT_LOCKED_CLAIM, null);
        } catch (UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving " + AccountLockConstants
                    .ACCOUNT_LOCKED_CLAIM + " claim value");
        }
        if (Boolean.parseBoolean(accountLockedClaim)) {
            long unlockTime = 0;
            try {
                unlockTime = Long.parseLong(userStoreManager.getUserClaimValue(userName,
                                                                                    AccountLockConstants.ACCOUNT_UNLOCK_TIME_CLAIM, null));
            } catch (UserStoreException e) {
                throw new AccountLockException("Error occurred while retrieving " + AccountLockConstants
                        .ACCOUNT_UNLOCK_TIME_CLAIM + " claim value");
            }
            if (unlockTime != 0 && System.currentTimeMillis() >= unlockTime) {
                Map<String, String> newClaims = new HashMap<>();
                newClaims.put(AccountLockConstants.ACCOUNT_LOCKED_CLAIM, Boolean.FALSE.toString());
                newClaims.put(AccountLockConstants.ACCOUNT_UNLOCK_TIME_CLAIM, "0");
                try {
                    userStoreManager.setUserClaimValues(userName, newClaims, null);
                } catch (UserStoreException e) {
                    throw new AccountLockException("Error occurred while storing " + AccountLockConstants
                            .ACCOUNT_LOCKED_CLAIM + " and " + AccountLockConstants.ACCOUNT_UNLOCK_TIME_CLAIM +
                                                   "claim values");
                }
            } else {
                String message = null;
                if(StringUtils.isNotBlank(userStoreDomainName)) {
                    message = "Account is locked for user " + userName + " in user store "
                              + userStoreDomainName + " in tenant " + tenantDomain + ". Cannot login until the " +
                              "account is unlocked.";
                } else {
                    message = "Account is locked for user " + userName + " in tenant " + tenantDomain + ". Cannot" +
                              " login until the account is unlocked.";
                }
                throw new AccountLockException(UserCoreConstants.ErrorCode.USER_IS_LOCKED + " " + message);
            }
        }
        return true;
    }

    protected boolean handlePostAuthentication(Event event, String userName, UserStoreManager userStoreManager,
                                               String userStoreDomainName, String tenantDomain,
                                               Map<String,String> idpProperties) throws AccountLockException {

        if ((Boolean)event.getEventProperties().get(EventMgtConstants.EventProperty.OPERATION_STATUS)) {
            Map<String, String> newClaims = new HashMap<>();
            newClaims.put(AccountLockConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, "0");
            newClaims.put(AccountLockConstants.ACCOUNT_UNLOCK_TIME_CLAIM, "0");
            newClaims.put(AccountLockConstants.ACCOUNT_LOCKED_CLAIM, Boolean.FALSE.toString());
            try {
                userStoreManager.setUserClaimValues(userName, newClaims, null);
            } catch (UserStoreException e) {
                throw new AccountLockException("Error occurred while storing " + AccountLockConstants
                        .FAILED_LOGIN_ATTEMPTS_CLAIM + ", " + AccountLockConstants.ACCOUNT_UNLOCK_TIME_CLAIM + " and " +
                                               "" + AccountLockConstants.ACCOUNT_LOCKED_CLAIM, e);
            }
        } else {
            int currentFailedAttempts;
            try {
                currentFailedAttempts = Integer.parseInt(userStoreManager.getUserClaimValue(userName,
                                                                                            AccountLockConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, null));
            } catch (UserStoreException e) {
                throw new AccountLockException("Error occurred while retrieving " + AccountLockConstants
                        .FAILED_LOGIN_ATTEMPTS_CLAIM + " claim value");
            }
            currentFailedAttempts += 1;
            Map<String, String> newClaims = new HashMap<>();
            newClaims.put(AccountLockConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, currentFailedAttempts + "");
            if (currentFailedAttempts >= Integer.parseInt(idpProperties.get(AccountLockConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY))) {
                newClaims.put(AccountLockConstants.ACCOUNT_LOCKED_CLAIM, "true");
                String unlockTimeProperty = idpProperties.get(AccountLockConstants.ACCOUNT_UNLOCK_TIME_PROPERTY);
                if (StringUtils.isNotBlank(unlockTimeProperty) && !"0".equals(unlockTimeProperty)) {
                    long unlockTime = System.currentTimeMillis() + Integer.parseInt(unlockTimeProperty) * 60 * 1000L;
                    newClaims.put(AccountLockConstants.ACCOUNT_UNLOCK_TIME_CLAIM, unlockTime + "");
                }
            }
            try {
                userStoreManager.setUserClaimValues(userName, newClaims, null);
            } catch (UserStoreException e) {
                throw new AccountLockException("Error occurred while storing " + AccountLockConstants
                        .ACCOUNT_LOCKED_CLAIM + " and " + AccountLockConstants.ACCOUNT_UNLOCK_TIME_CLAIM + " claim " +
                                               "value");
            }
        }
        return true;
    }

    protected boolean handlePreSetUserClaimValues(Event event, String userName, UserStoreManager userStoreManager,
                                                  String userStoreDomainName, String tenantDomain,
                                                  Map<String,String> idpProperties) throws AccountLockException {

        if (lockedState.get() != null) {
            return true;
        }
        boolean existingAccountLockedValue;
        try {
            existingAccountLockedValue = Boolean.parseBoolean(userStoreManager.getUserClaimValue(userName,
                                                                                                 AccountLockConstants.ACCOUNT_LOCKED_CLAIM, null));
        } catch (UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving " + AccountLockConstants
                    .ACCOUNT_LOCKED_CLAIM + " claim value");
        }
        Boolean newAccountLockedValue = Boolean.parseBoolean(
                ((Map<String, String>)event.getEventProperties().get("USER_CLAIMS"))
                        .get(AccountLockConstants.ACCOUNT_LOCKED_CLAIM));
        if (existingAccountLockedValue != newAccountLockedValue){
            if (existingAccountLockedValue) {
                lockedState.set(lockedStates.UNLOCKED_MODIFIED.toString());
            } else {
                lockedState.set(lockedStates.LOCKED_MODIFIED.toString());
            }
        } else {
            if (existingAccountLockedValue) {
                lockedState.set(lockedStates.LOCKED_UNMODIFIED.toString());
            } else {
                lockedState.set(lockedStates.UNLOCKED_UNMODIFIED.toString());
            }
        }
        return true;
    }

    protected boolean handlePostSetUserClaimValues(Event event, String userName, UserStoreManager userStoreManager,
                                                   String userStoreDomainName, String tenantDomain,
                                                   Map<String,String> idpProperties) throws AccountLockException {

        try {
            if (lockedStates.UNLOCKED_MODIFIED.toString().equals(lockedState.get())) {
                triggerNotification(event, userName, userStoreManager, userStoreDomainName, tenantDomain, idpProperties,
                                    AccountLockConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED);
            } else if (lockedStates.LOCKED_MODIFIED.toString().equals(lockedState.get())) {
                triggerNotification(event, userName, userStoreManager, userStoreDomainName, tenantDomain, idpProperties,
                                    AccountLockConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED);
            }
        } finally {
            lockedState.remove();
        }
        return true;
    }

    public String[] getPropertyNames(){

        String[] arr = this.properties.keySet().toArray(new String[this.properties.keySet().size()]);
        return arr;
    }

    public Properties getDefaultPropertyValues (String tenantDomain) throws IdentityGovernanceException{
       return properties;
    }

    public Map<String, String> getDefaultPropertyValues (String[] propertyNames, String tenantDomain) throws IdentityGovernanceException{
        return null;
    }

    protected void triggerNotification (Event event, String userName, UserStoreManager userStoreManager,
                                        String userStoreDomainName, String tenantDomain,
                                        Map<String,String> idpProperties,
                                        String notificationEvent) throws AccountLockException {

        String eventName = EventMgtConstants.Event.TRIGGER_NOTIFICATION;

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(EventMgtConstants.EventProperty.USER_NAME, userName);
        properties.put(EventMgtConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        properties.put(EventMgtConstants.EventProperty.USER_STORE_DOMAIN, userStoreDomainName);
        properties.put(EventMgtConstants.EventProperty.TENANT_DOMAIN, tenantDomain);
        properties.put("TEMPLATE_TYPE", notificationEvent);
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            IdentityAccountLockServiceDataHolder.getInstance().getEventMgtService().handleEvent(identityMgtEvent);
        } catch (EventMgtException e) {
            throw new AccountLockException("Error occurred while sending notification", e);
        }
    }

}
