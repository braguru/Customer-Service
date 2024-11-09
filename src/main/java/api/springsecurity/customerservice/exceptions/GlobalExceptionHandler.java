package api.springsecurity.customerservice.exceptions;

import api.springsecurity.customerservice.dto.ErrorResponse;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.mail.MessagingException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.security.SignatureException;
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
            NoEmailORPhoneNumberException.class, PasswordValidationException.class,
            JsonProcessException.class, ProfileDataException.class, LoginException.class,
            InvalidPropertiesFormatException.class, S3Exception.class, InvalidFileTypeException.class})
    public ResponseEntity<ErrorResponse> handleInvalidTokenPayloadException(Exception ex) {
        ErrorResponse errorResponse = new ErrorResponse(ex.getMessage());
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleMethodArgumentNotValidException(MethodArgumentNotValidException ex) {
        StringBuilder errorMessage = new StringBuilder("Validation failed: ");
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            errorMessage.append(error.getField())
                    .append(" - ")
                    .append(error.getDefaultMessage())
                    .append("; ");
        }

        ErrorResponse errorResponse = new ErrorResponse("Invalid file type. Only images are allowed.");

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
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

    @ExceptionHandler(value = {MalformedJwtException.class, SignatureException.class, InsufficientAuthenticationException.class,
            BadCredentialsException.class, InvalidOTPException.class, TokenExpiredException.class, InvalidTokenFormatException.class})
    public ResponseEntity<ErrorResponse> handleSecurityException(Exception ex) {
        ErrorResponse errorResponse = new ErrorResponse(ex.getMessage());
        return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
    }
}
