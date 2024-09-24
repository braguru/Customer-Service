package api.springsecurity.customerservice.service.emailservice;

import jakarta.mail.MessagingException;

public interface EmailService {

    /**
     * Sends a generic email with the provided subject and body.
     * <p>
     * This method constructs and sends an email to the specified recipient with the given
     * subject and content. It can send plain text or HTML-formatted emails.
     *
     * @param toEmail the recipient's email address
     * @param subject the subject of the email
     * @param body the body of the email, which can be plain text or HTML
     * @throws MessagingException if an error occurs while sending the email
     */
    void sendEmail(String toEmail, String subject, String body) throws MessagingException;

    /**
     * Sends an account verification email to the user with a verification token.
     * <p>
     * This method sends an email to the specified recipient containing a verification link
     * that includes a token. The recipient can click the link to verify their account.
     * The token is used to validate the user's email.
     *
     * @param toEmail the recipient's email address
     * @param token the verification token generated for the user
     * @throws MessagingException if an error occurs while sending the email
     */
    void sendVerificationEmail(String toEmail, String token) throws MessagingException;
}
