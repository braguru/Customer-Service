package api.springsecurity.customerservice.payload;

import lombok.Builder;

@Builder
public record OTPRequest(String number, String code) {
}
