package api.springsecurity.customerservice.repositories;

import api.springsecurity.customerservice.entity.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {

    Optional<VerificationToken> findByConfirmationToken(String token);
}
