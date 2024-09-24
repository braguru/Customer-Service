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

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String phone = ((OTPAuthenticationToken) authentication).getPhoneNumber();
        String otp = (String) authentication.getCredentials();

        // Verify OTP with third-party service
        OTPRequest otpRequest = new OTPRequest(phone, otp);
        RegisterResponse otpResponse = otpService.verifyOTP(otpRequest);
        if (!"OK".equals(otpResponse.getMessage())) {
            throw new BadCredentialsException("Invalid OTP");
        }

        UserDetails userDetails = userRepository.findByPhoneAndLockedIsFalse(phone)
                .orElseThrow(() -> new BadCredentialsException("Invalid phone number or OTP"));

        return new OTPAuthenticationToken(userDetails, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OTPAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

