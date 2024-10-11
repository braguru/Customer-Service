package api.springsecurity.customerservice.controller;

import api.springsecurity.customerservice.dto.ProfileResponse;
import api.springsecurity.customerservice.payload.ProfileRequest;
import api.springsecurity.customerservice.service.userprofile.UserProfileService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/profile")
public class UserProfileController {

    private final UserProfileService userProfileService;

    @GetMapping
    public ResponseEntity<ProfileResponse> getProfile() {
        ProfileResponse profileResponse = userProfileService.getProfile();
        return ResponseEntity.ok(profileResponse);
    }

    @PutMapping(consumes = "multipart/form-data")
    public ResponseEntity<ProfileResponse> updateProfile(@ModelAttribute ProfileRequest profileData) throws IOException {
        ProfileResponse profileResponse = userProfileService.updateProfile(profileData);
        return ResponseEntity.ok(profileResponse);
    }

    @DeleteMapping("/picture")
    public ResponseEntity<String> deleteProfilePicture(@RequestParam String pictureLink) {
        String response = userProfileService.deleteProfilePicture(pictureLink);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping
    public ResponseEntity<ProfileResponse> deleteAccount() {
        ProfileResponse profileResponse = userProfileService.deleteAccount();
        return ResponseEntity.ok(profileResponse);
    }

}
