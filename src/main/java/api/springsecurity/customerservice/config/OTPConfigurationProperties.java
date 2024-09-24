package api.springsecurity.customerservice.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "arkesel")
@Data
public class OTPConfigurationProperties {

    private String apiKey;
    private String otpUrl;
    private String verifyOtpUrl;

}
