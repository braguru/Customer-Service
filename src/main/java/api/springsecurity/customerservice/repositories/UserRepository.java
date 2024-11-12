package api.springsecurity.customerservice.repositories;

import api.springsecurity.customerservice.entity.User;
import api.springsecurity.customerservice.entity.enums.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);
    Optional<User> findByUsername(String username);
    Optional<User> findByPhone(String phone);
    Optional<User> findByUsernameOrEmailOrPhone(String username, String email, String phone);
    Optional<User> findByUsernameAndLockedIsFalse(String username);
    Optional<User> findByPhoneAndLockedIsFalse(String phone);
    Optional<User> findByEmailAndLockedIsFalse(String email);
    boolean existsByRole(Role role);
    boolean existsByEmail(String email);
}