package api.springsecurity.customerservice.utils.userutil;

import api.springsecurity.customerservice.entity.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class UserUtil {

    public String getUserName() {
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }

    public UUID getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof User user) {
            return user.getId();
        } else {
            throw new IllegalStateException("User not authenticated or principal is not an instance of User");
        }
    }
}
