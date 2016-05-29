package org.wso2.carbon.identity.event.handler.account.lock.exception;

import org.wso2.carbon.identity.event.EventMgtException;

public class AccountLockException extends EventMgtException {

    public AccountLockException(String message) {
        super(message);
    }

    public AccountLockException(String message, Throwable cause) {
        super(message, cause);
    }

    public AccountLockException(Throwable cause) {
        super(cause);
    }

    public AccountLockException(int errorCode) {
        super(errorCode);
    }

    public AccountLockException(int errorCode, Object[] args) {
        super(errorCode, args);
    }
}
