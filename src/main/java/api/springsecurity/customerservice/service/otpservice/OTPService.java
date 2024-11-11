package api.springsecurity.customerservice.service.otpservice;

import api.springsecurity.customerservice.config.OTPConfigurationProperties;
import api.springsecurity.customerservice.dto.RegisterResponse;
import api.springsecurity.customerservice.entity.User;
import api.springsecurity.customerservice.payload.OTPRequest;
import api.springsecurity.customerservice.repositories.UserRepository;
import api.springsecurity.customerservice.utils.jwtutil.JwtUtil;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.*;

import static api.springsecurity.customerservice.exceptions.CustomExceptions.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class OTPService {

    public static final String MESSAGE = "message";
    private final UserRepository userRepository;
    private final OkHttpClient client = new OkHttpClient();
    private final OTPConfigurationProperties otpConfig;  // Externalized configuration
    private final JwtUtil jwtUtil;

    private static final Gson gson = new Gson();

    /**
     * Sends an OTP (One-Time Password) to the user's phone number using the Arkesel API.
     * <p>
     * This method constructs a request to the Arkesel API with the user's phone information and sends it.
     * If the OTP is sent successfully, a success message is returned. If an error occurs, an exception is thrown.
     * </p>
     *
     * @param user The user object containing necessary phone information.
     * @return A {@link String} containing a message indicating whether the OTP was sent successfully.
     * @throws OtpNotSentException if there is an error while sending the OTP.
     */
    public String sendOtp(User user) {
        Map<String, String> requestBody = buildRequestBody(user);
        RequestBody jsonRequestBody = buildJsonRequestBody(requestBody);

        Request request = new Request.Builder()
                .url(otpConfig.getOtpUrl())
                .addHeader("Content-Type", "application/json")
                .addHeader("api-key", otpConfig.getApiKey())
                .post(jsonRequestBody)
                .build();

        try {
            return executeRequestWithRetry(request);
        } catch (IOException e) {
            log.error("Failed to send OTP due to an exception: {}", e.getMessage());
            throw new OtpNotSentException("Failed to send OTP due to an exception: " + e.getMessage());
        }
    }

    /**
     * Verifies the provided OTP using the Arkesel API.
     * <p>
     * This method constructs a request to verify the OTP by sending the code and phone number to the Arkesel API.
     * It checks the response to determine if the OTP is valid. If valid, it enables the user if they were previously disabled.
     * If the OTP is invalid, an exception is thrown.
     * </p>
     *
     * @param otpRequest The {@link OTPRequest} object containing the OTP code and phone number.
     * @return A {@link RegisterResponse} object containing the outcome of the OTP verification, including a message.
     * @throws InvalidOTPException if the provided OTP is invalid.
     * @throws InvalidTokenFormatException if there is an error during the OTP verification process.
     */
    public RegisterResponse verifyOTP(OTPRequest otpRequest) {
        Map<String, String> requestBody = new LinkedHashMap<>();
        requestBody.put("code", otpRequest.code());
        requestBody.put("number", otpRequest.number());

        RequestBody jsonRequestBody = buildJsonRequestBody(requestBody);
        Request request = new Request.Builder()
                .url(otpConfig.getVerifyOtpUrl())
                .addHeader("api-key", otpConfig.getApiKey())
                .post(jsonRequestBody)
                .build();

        try (Response response = client.newCall(request).execute()) {
            assert response.body() != null;
            String responseBody = response.body().string();

            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readTree(responseBody);

            // Extract "message" field from the JSON
            String message = jsonNode.has(MESSAGE) ? jsonNode.get(MESSAGE).asText() : "No message provided";

            if(message.equals("Invalid phone number")){
                throw new InvalidOTPException("Invalid phone number");
            }

            if(message.equals("Code has expired")){
                throw new InvalidOTPException("Code has expired");
            }

            if (!response.isSuccessful()) {
                throw new InvalidOTPException("Invalid OTP. Please try again.");
            }

            Optional<User> user = userRepository.findByPhone(otpRequest.number());
            user.ifPresent(this::enableUserIfDisabled);
            String jwtToken = jwtUtil.generateToken(user.orElseThrow(() -> new UserNotFoundException("User not found")));

            return RegisterResponse.builder()
                    .token(jwtToken)
                    .message("OTP verified successfully and account enabled. You can now log in.")
                    .build();
        } catch (IOException e) {
            throw new InvalidTokenFormatException("Failed to verify OTP due to an exception: " + e.getMessage());
        }
    }


    /**
     * Retries an HTTP request up to a specified number of times if it fails.
     * <p>
     * This method executes the provided HTTP request and checks for a successful response.
     * If the response is unsuccessful, it logs the failure and retries the request up to three times
     * with exponential backoff between attempts. If all attempts fail, an IOException is thrown.
     * </p>
     *
     * @param request The HTTP request to execute.
     * @return The response body as a {@link String} if the request is successful.
     * @throws IOException If the request fails after the maximum number of retries.
     */
    private String executeRequestWithRetry(Request request) throws IOException {
        int attempt = 0;
        while (attempt < 3) {
            try (Response response = client.newCall(request).execute()) {
                if (response.isSuccessful()) {
                    return "OTP sent successfully. Please enter this code within 5 minutes to complete your authentication.";
                }
                log.error("Attempt {} failed: {}", attempt + 1, response.message());
            }
            attempt++;
            if (attempt < 3) {
                try {
                    Thread.sleep(2000L * attempt);  // Exponential backoff
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        throw new IOException("Failed to execute request after " + 3 + " attempts.");
    }

    /**
     * Constructs the request body for sending an OTP to the user's phone number.
     * <p>
     * This method creates a map containing the necessary parameters for the OTP request,
     * including expiry time, length, medium, message template, user's phone number, sender ID, and type.
     * </p>
     *
     * @param user The {@link User} object containing the user's phone number.
     * @return A {@link Map<String,String>} representing the request body for the OTP request.
     */
    private Map<String, String> buildRequestBody(User user) {
        Map<String, String> requestBody = new LinkedHashMap<>();
        requestBody.put("expiry", "5");
        requestBody.put("length", "6");
        requestBody.put("medium", "sms");
        requestBody.put(MESSAGE, "Your verification code for SALON SPOT is %otp_code%. Please enter this code within 5 minutes to complete your authentication.");
        requestBody.put("number", user.getPhone());
        requestBody.put("sender_id", "SALON SPOT");
        requestBody.put("type", "numeric");
        return requestBody;
    }

    /**
     * Builds a JSON request body from the provided map.
     * <p>
     * This method serializes the given map into a JSON string using Gson and creates a
     * {@link RequestBody} suitable for sending as part of an HTTP request.
     * </p>
     *
     * @param requestBody The {@link Map<String, String>} containing the parameters for the request.
     * @return A {@link RequestBody} containing the serialized JSON representation of the request body.
     */
    private RequestBody buildJsonRequestBody(Map<String, String> requestBody) {
        return RequestBody.create(
                gson.toJson(requestBody),
                MediaType.parse("application/json; charset=utf-8")
        );
    }

    /**
     * Enables a user account if it is currently disabled.
     * <p>
     * This method checks the user's status and, if the user is not enabled,
     * sets the user's status to enabled and saves the changes to the user repository.
     * </p>
     *
     * @param user The {@link User} object to be enabled.
     */
    private void enableUserIfDisabled(User user) {
        if (!user.isEnabled()) {
            user.setEnabled(true);
            userRepository.save(user);
        }
    }
}
