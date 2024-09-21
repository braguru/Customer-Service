package api.springsecurity.customerservice.exceptions;

import org.springframework.security.core.AuthenticationException;

public class CustomExceptions {

    private CustomExceptions() {
        super();
    }

    /**
     * Exception thrown when a user attempts to register with an email, username,
     * or phone number that already exists in the system.
     */
    public static class UserAlreadyExistsException extends RuntimeException {
        public UserAlreadyExistsException(String message) {
            super(message);
        }
    }

    /**
     * Exception thrown when there is an issue sending the verification email.
     */
    public static class EmailNotSentException extends RuntimeException {
        public EmailNotSentException(String message) {
            super(message);
        }
    }

    /**
     * Exception thrown when there is an issue sending the OTP to the user's phone.
     */
    public static class OtpNotSentException extends RuntimeException {
        public OtpNotSentException(String message) {
            super(message);
        }
    }

    /**
     * Exception thrown when a provided verification token does not exist in the system.
     */
    public static class TokenNotFoundException extends RuntimeException {
        public TokenNotFoundException(String message) {
            super(message);
        }
    }

    /**
     * Exception thrown when an attempt is made to confirm an email that has
     * already been confirmed.
     */
    public static class EmailAlreadyConfirmedException extends RuntimeException {
        public EmailAlreadyConfirmedException(String message) {
            super(message);
        }
    }

    /**
     * Exception thrown when a provided verification token has expired.
     */
    public static class TokenExpiredException extends RuntimeException {
        public TokenExpiredException(String message) {
            super(message);
        }
    }

    /**
     * Exception thrown when the format of a token is invalid.
     */
    public static class InvalidTokenFormatException extends RuntimeException {
        public InvalidTokenFormatException(String message) {
            super(message);
        }
    }

    /**
     * Exception thrown when an email address is not found in the system.
     */
    public static class EmailNotFoundException extends RuntimeException {
        public EmailNotFoundException(String message) {
            super(message);
        }
    }

    public static class EmailAlreadyExistException extends RuntimeException {
        public EmailAlreadyExistException(String message) {
            super(message);
        }
    }

    /**
     * Exception thrown when there is an error processing JSON data.
     */
    public static class JsonProcessException extends RuntimeException {
        public JsonProcessException(String message) {
            super(message);
        }
    }

    /**
     * Exception thrown when the payload of a token is invalid.
     */
    public static class InvalidTokenPayloadException extends RuntimeException {
        public InvalidTokenPayloadException(String message) {
            super(message);
        }
    }

    public static class UserNotFoundException extends RuntimeException {
        public UserNotFoundException(String message) {
            super(message);
        }
    }

    public static class InvalidOTPException extends RuntimeException {
        public InvalidOTPException(String message) {
            super(message);
        }
    }

    public static class MessageNotSentException extends RuntimeException {
        public MessageNotSentException(String message) {
            super(message);
        }
    }

    public static class UserProfileNotFoundException extends RuntimeException {
        public UserProfileNotFoundException(String message) {
            super(message);
        }
    }

    public static class UsernameOrEmailOrPhoneNotException extends RuntimeException {
        public UsernameOrEmailOrPhoneNotException(String message) {
            super(message);
        }
    }

    public static class PhoneNumberAlreadyExistsException extends RuntimeException {
        public PhoneNumberAlreadyExistsException(String message) {
            super(message);
        }
    }

    public static class NoEmailORPhoneNumberException extends RuntimeException {
        public NoEmailORPhoneNumberException(String message) {
            super(message);
        }
    }

    public static class PasswordValidationException extends RuntimeException {
        public PasswordValidationException(String message) {
            super(message);
        }
    }

    public static class LoginException extends RuntimeException {
        public LoginException(String message) {
            super(message);
        }
    }

    public static class UnActivatedAccountException extends RuntimeException {
        public UnActivatedAccountException(String message) {
            super(message);
        }
    }

    public static class ProfileDataException extends RuntimeException{
        public ProfileDataException(String message){
            super(message);
        }
    }

    public static class ProfileNotFoundException extends RuntimeException{
        public ProfileNotFoundException(String message){
            super(message);
        }
    }

    public static class AuthenticationException extends org.springframework.security.core.AuthenticationException {
        public AuthenticationException(String msg) {
            super(msg);
        }
    }
}
