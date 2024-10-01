package api.springsecurity.customerservice.service.emailservice;

import jakarta.mail.MessagingException;

public interface EmailService {

    void sendEmail(String toEmail, String subject, String body) throws MessagingException;

    void sendVerificationEmail(String toEmail, String token) throws MessagingException;
}
