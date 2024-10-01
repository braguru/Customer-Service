package api.springsecurity.customerservice.utils.userutil;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;

@EqualsAndHashCode(callSuper = true)
public class OTPAuthenticationToken extends AbstractAuthenticationToken {

    @Getter
    private final String phoneNumber;
    private final String otp;

    public OTPAuthenticationToken(String phoneNumber, String otp) {
        super(null);
        this.phoneNumber = phoneNumber;
        this.otp = otp;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.otp;
    }

    @Override
    public Object getPrincipal() {
        return this.phoneNumber;
    }

}
