package api.springsecurity.customerservice.utils.userutil;

import api.springsecurity.customerservice.dto.RegisterResponse;
import api.springsecurity.customerservice.payload.OTPRequest;
import api.springsecurity.customerservice.repositories.UserRepository;
import api.springsecurity.customerservice.service.otpservice.OTPService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OTPAuthenticationProvider implements AuthenticationProvider {

    private final UserRepository userRepository;
    private final OTPService otpService;

    /**
     * Authenticates the user based on the provided phone number and OTP.
     *
     * <p>This method verifies the OTP using the {@link OTPService}. If the OTP is valid, it retrieves the user details
     * from the {@link UserRepository} and returns an authenticated {@link OTPAuthenticationToken}. If the OTP or phone
     * number is invalid, a {@link BadCredentialsException} is thrown.</p>
     *
     * @param authentication the authentication request object containing phone number and OTP
     * @return a fully authenticated object including credentials
     * @throws AuthenticationException if authentication fails due to invalid OTP or phone number
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String phone = ((OTPAuthenticationToken) authentication).getPhoneNumber();
        String otp = (String) authentication.getCredentials();

        OTPRequest otpRequest = new OTPRequest(phone, otp);
        RegisterResponse otpResponse = otpService.verifyOTP(otpRequest);
        if (!"OK".equals(otpResponse.getMessage())) {
            throw new BadCredentialsException("Invalid OTP");
        }

        UserDetails user = userRepository.findByPhone(phone)
                .orElseThrow(() -> new BadCredentialsException("Invalid phone number"));

        OTPAuthenticationToken otpAuthenticationToken = new OTPAuthenticationToken(phone, otp);
        otpAuthenticationToken.setDetails(user);
        return otpAuthenticationToken;
    }


    /**
     * Indicates whether this provider supports the indicated authentication object.
     *
     * @param authentication the authentication class to check
     * @return true if the authentication object is assignable from {@link OTPAuthenticationToken}; false otherwise
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return OTPAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

