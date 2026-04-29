package com.fsad.studentachievement.service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class MailService {

    @Value("${mail.enabled:true}")
    private boolean mailEnabled;

    @Value("${vercel.email.api.url:https://student-achievement-blush.vercel.app/api/send-email}")
    private String vercelApiUrl;

    @Value("${vercel.email.secret:SecretVercelKey123!}")
    private String vercelApiSecret;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newHttpClient();

    public boolean sendMail(String to, String subject, String text) {
        if (!mailEnabled) {
            log.info("Mail disabled. To: {} Subject: {} Body: {}", to, subject, text);
            return false;
        }
        try {
            Map<String, Object> payload = new HashMap<>();
            payload.put("secretKey", vercelApiSecret);
            payload.put("to", to);
            payload.put("subject", subject);
            payload.put("text", text);

            String jsonPayload = objectMapper.writeValueAsString(payload);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(vercelApiUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                return true;
            } else {
                log.error("Failed to send mail via Vercel. Status: {} Response: {}", response.statusCode(), response.body());
                return false;
            }
        } catch (Exception exception) {
            log.error("Unable to send mail to {}", to, exception);
            return false;
        }
    }

    public boolean sendMailWithAttachment(String to, String subject, String text, byte[] attachment, String filename, String contentType) {
        if (!mailEnabled) {
            log.info("Mail disabled. To: {} Subject: {} Attachment: {}", to, subject, filename);
            return false;
        }
        try {
            Map<String, Object> payload = new HashMap<>();
            payload.put("secretKey", vercelApiSecret);
            payload.put("to", to);
            payload.put("subject", subject);
            payload.put("text", text);
            payload.put("attachmentBase64", Base64.getEncoder().encodeToString(attachment));
            payload.put("filename", filename);
            payload.put("contentType", contentType);

            String jsonPayload = objectMapper.writeValueAsString(payload);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(vercelApiUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                return true;
            } else {
                log.error("Failed to send mail with attachment via Vercel. Status: {} Response: {}", response.statusCode(), response.body());
                return false;
            }
        } catch (Exception exception) {
            log.error("Unable to send mail with attachment to {}", to, exception);
            return false;
        }
    }
}
