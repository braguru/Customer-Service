package api.springsecurity.customerservice.utils;

import api.springsecurity.customerservice.exceptions.CustomExceptions;

public class PasswordUtil {

    private PasswordUtil() {

    }

    public static boolean encodePassword(String password) {
        if (password == null || password.isEmpty()) {
            throw new CustomExceptions.NoEmailORPhoneNumberException("Password is required for registration.");
        } else {
            // Validate the password
            String passwordPattern = "^(?=.*\\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]).{8,}$";

            if (!password.matches(passwordPattern)) {
                throw new CustomExceptions.PasswordValidationException("Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character.");
            }
        }
        return true;
    }
}
