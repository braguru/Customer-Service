package api.springsecurity.customerservice.service.emailservice;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

@Service
@AllArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {

    private final SpringTemplateEngine templateEngine;
    private final JavaMailSender mailSender;

    /**
     * Sends an email with the specified recipient, subject, and body content.
     * <p>
     * This method creates a MIME message and uses the provided email details
     * to send an email. The email content supports HTML formatting.
     *
     * @param toEmail the recipient's email address
     * @param subject the subject of the email
     * @param body the body of the email, which can contain HTML content
     *
     * @throws MessagingException if there is an error while creating or sending the email
     */
    @Override
    @Async
    public void sendEmail(String toEmail, String subject, String body) throws MessagingException {
        try{
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, "utf-8");
        helper.setText(body, true);
        helper.setTo(toEmail);
        helper.setSubject(subject);
        mailSender.send(message);
        log.info("Email sent successfully to: {}", toEmail);
        } catch (MessagingException e) {
            log.error("Failed to send email: {}", e.getMessage());
            throw new MessagingException("Failed to send email: " + e.getMessage());
        }
    }

    /**
     * Sends an account verification email to the specified recipient.
     * <p>
     * This method generates an email with a verification token and other
     * relevant details, such as the verification link and registration link,
     * and uses a predefined HTML template to format the email content.
     * <p>
     * The email is sent using the {@link #sendEmail(String, String, String)} method.
     *
     * @param toEmail the recipient's email address
     * @param token the verification token to be included in the email
     *
     * @throws MessagingException if there is an error while creating or sending the email
     */
    @Override
    @Async
    public void sendVerificationEmail(String toEmail, String token) throws MessagingException {
        try {
            Context context = new Context();
            context.setVariable("token", token);
            context.setVariable("subject", "Account Verification");
            context.setVariable("link", System.getenv("VERIFICATION_LINK"));
            context.setVariable("registerLink", System.getenv("REGISTRATION_LINK"));
            String htmlContent = templateEngine.process("verification_template", context);
            sendEmail(toEmail, "Account Verification", htmlContent);
            log.info("Verification email sent successfully to: {}", toEmail);
        } catch (MessagingException e) {
            log.error("Failed to send verification email: {}", e.getMessage());
            throw new MessagingException("Failed to send verification email: " + e.getMessage());
        }
    }
}
