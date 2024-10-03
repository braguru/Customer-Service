package api.springsecurity.customerservice.entity;

import api.springsecurity.customerservice.entity.enums.ID;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserProfile {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = "user_id")
    private User user;

    private String profilePicture;

    @Column(length = 100000000)
    private String bio;

    private LocalDate dateOfBirth;

    @Enumerated(EnumType.STRING)
    private ID idType;

    @DateTimeFormat(pattern = "dd-MM-yyyy")
    private String idNumber;
}
