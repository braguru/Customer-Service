package api.springsecurity.customerservice.utils;

import api.springsecurity.customerservice.entity.User;
import api.springsecurity.customerservice.entity.UserProfile;
import api.springsecurity.customerservice.entity.enums.Role;
import api.springsecurity.customerservice.repositories.UserProfileRepository;
import api.springsecurity.customerservice.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.time.LocalDate;

@Component
@RequiredArgsConstructor
@Slf4j
public class AdminSeeder implements CommandLineRunner {

    private final UserRepository userRepository;
    private final UserProfileRepository userProfileRepository;

    @Override
    public void run(String... args) {
        if (!userRepository.existsByRole(Role.ADMIN) && !userRepository.existsByEmail("michaelattoh@protonmail.com")){
            log.info("Admin user does not exist. Creating new admin user.");
            User user = userRepository.save(User.builder()
                    .firstname("ADMIN")
                    .lastname("ADMIN")
                    .email("sabastainofori@gmail.com")
                    .phone("0596053602")
                    .role(Role.ADMIN)
                    .date(LocalDate.now())
                    .enabled(true)
                    .build());
            userProfileRepository.save(UserProfile.builder()
                    .user(user)
                    .build());
            log.info("Admin user created successfully.");
        }else {
            log.info("Admin user already exists.");
        }
    }
}
