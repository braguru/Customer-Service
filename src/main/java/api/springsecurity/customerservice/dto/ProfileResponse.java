package api.springsecurity.customerservice.dto;

import api.springsecurity.customerservice.entity.enums.ID;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDate;

@Builder
@Getter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProfileResponse {
    private Long id;
    private String firstname;
    private String lastname;
    private String username;
    private String email;
    private String profilePicture;
    private String phoneNumber;
    private String message;
    private String bio;
    private LocalDate dateOfBirth;
    private ID idType;
    private String idNumber;
}
