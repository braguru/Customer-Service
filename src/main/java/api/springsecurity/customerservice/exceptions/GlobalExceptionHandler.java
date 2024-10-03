package api.springsecurity.customerservice.exceptions;

import api.springsecurity.customerservice.dto.ErrorResponse;
import com.twilio.exception.ApiException;
import jakarta.mail.MessagingException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.InvalidPropertiesFormatException;

import static api.springsecurity.customerservice.exceptions.CustomExceptions.*;

@RestControllerAdvice
public class GlobalExceptionHandler {


    @ExceptionHandler({Exception.class})
    public ResponseEntity<ErrorResponse> handleException(Exception ex) {
        ErrorResponse errorResponse = new ErrorResponse(ex.getMessage());
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Handles {@link InvalidTokenPayloadException} exceptions.
     * <p>
     * This method catches exceptions thrown when the payload of a token is invalid.
     * It creates an {@link ErrorResponse} containing the error message and HTTP
     * status code 400 Bad Request, which is then returned to the client.
     * </p>
     *
     * @param ex the {@link InvalidTokenPayloadException} exception to handle
     * @return a {@link ResponseEntity} containing an {@link ErrorResponse} with an error message and
     *         HTTP status code 400 Bad Request
     */
    @ExceptionHandler(value = {InvalidTokenPayloadException.class, EmailAlreadyConfirmedException.class,
            InvalidTokenFormatException.class, NoEmailORPhoneNumberException.class, PasswordValidationException.class,
            JsonProcessException.class, ProfileDataException.class, LoginException.class, BadCredentialsException.class,
            InvalidPropertiesFormatException.class})
    public ResponseEntity<ErrorResponse> handleInvalidTokenPayloadException(Exception ex) {
        ErrorResponse errorResponse = new ErrorResponse(ex.getMessage());
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    /**
     * Handles {@link ApiException} exceptions.
     *
     * <p>Returns a response entity with the appropriate status code and error message for Twilio-related errors.</p>
     *
     * @param e the {@link ApiException} instance
     * @return a {@link ResponseEntity} with the error message and status code from the exception
     */
    @ExceptionHandler(ApiException.class)
    public ResponseEntity<String> handleApiException(ApiException e) {
        return ResponseEntity.status(e.getStatusCode())
                .body("Twilio error: " + e.getMessage());
    }

    /**
     * Handles {@link InvalidOTPException}.
     *
     * <p>Returns a response entity with the UNAUTHORIZED status and a detailed error response for invalid OTP scenarios.</p>
     *
     * @param ex the {@link InvalidOTPException} instance
     * @return a {@link ResponseEntity} with an {@link ErrorResponse} and UNAUTHORIZED status
     */
    @ExceptionHandler(value = {InvalidOTPException.class, TokenExpiredException.class})
    public ResponseEntity<ErrorResponse> handleUnauthorizedException(Exception ex) {
        ErrorResponse errorResponse = new ErrorResponse(ex.getMessage());
        return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(value = {UserProfileNotFoundException.class, UsernameOrEmailOrPhoneNotException.class,
            UserNotFoundException.class, EmailNotFoundException.class, TokenNotFoundException.class,
            ProfileNotFoundException.class
    })
    public ResponseEntity<ErrorResponse> handleNotFoundException(Exception ex) {
        ErrorResponse errorResponse = new ErrorResponse(ex.getMessage());
        return new ResponseEntity<>(errorResponse, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(value = {EmailAlreadyExistException.class, UserAlreadyExistsException.class,
            PhoneNumberAlreadyExistsException.class, DataIntegrityViolationException.class})
    public ResponseEntity<ErrorResponse> handleConflictException(Exception ex) {
        ErrorResponse errorResponse = new ErrorResponse(ex.getMessage());
        return new ResponseEntity<>(errorResponse, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(value = {MessageNotSentException.class, EmailNotSentException.class,
            OtpNotSentException.class})
    public ResponseEntity<ErrorResponse> handleNotSentException(Exception ex) {
        ErrorResponse errorResponse = new ErrorResponse(ex.getMessage());
        return new ResponseEntity<>(errorResponse, HttpStatus.ACCEPTED);
    }

    @ExceptionHandler(value = {UnActivatedAccountException.class , DisabledException.class})
    public ResponseEntity<ErrorResponse> handleForbiddenException(Exception ex) {
        ErrorResponse errorResponse = new ErrorResponse(ex.getMessage());
        return new ResponseEntity<>(errorResponse, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(value = {MessagingException.class})
    public ResponseEntity<ErrorResponse> handleMessagingException(Exception ex) {
        ErrorResponse errorResponse = new ErrorResponse(ex.getMessage());
        return new ResponseEntity<>(errorResponse, HttpStatus.SERVICE_UNAVAILABLE);
    }
}
