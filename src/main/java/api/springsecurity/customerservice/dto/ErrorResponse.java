package api.springsecurity.customerservice.dto;

import lombok.*;

@AllArgsConstructor
@Getter
@Setter
@Builder
public class ErrorResponse {
    private String message;
}
