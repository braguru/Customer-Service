package api.springsecurity.customerservice.utils.userutil;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Objects;


public class OTPAuthenticationToken extends AbstractAuthenticationToken {

    @Getter
    private final String phoneNumber;
    private final transient Object principal;
    private final transient Object credentials;

    public OTPAuthenticationToken(String phoneNumber, Object credentials) {
        super(null);
        this.phoneNumber = phoneNumber;
        this.credentials = credentials;
        this.principal = null;  // Principal can be null initially
        setAuthenticated(false);
    }

    public OTPAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.phoneNumber = null;
        this.credentials = null;
        this.principal = principal;
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal != null ? this.principal : this.phoneNumber;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        OTPAuthenticationToken that = (OTPAuthenticationToken) obj;
        return Objects.equals(phoneNumber, that.phoneNumber) &&
                Objects.equals(principal, that.principal) &&
                Objects.equals(credentials, that.credentials);
    }

    @Override
    public int hashCode() {
        return Objects.hash(phoneNumber, principal, credentials);
    }

}
