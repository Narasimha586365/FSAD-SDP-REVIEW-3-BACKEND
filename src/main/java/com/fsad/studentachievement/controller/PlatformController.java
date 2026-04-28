package com.fsad.studentachievement.controller;

import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fsad.studentachievement.dto.AchievementRequest;
import com.fsad.studentachievement.dto.ActivityRequest;
import com.fsad.studentachievement.dto.ActivitySlotUpdateRequest;
import com.fsad.studentachievement.dto.AuthRequest;
import com.fsad.studentachievement.dto.CertificateRequest;
import com.fsad.studentachievement.dto.CoAdminApprovalRequest;
import com.fsad.studentachievement.dto.DeleteUserRequest;
import com.fsad.studentachievement.dto.EnrollmentRequest;
import com.fsad.studentachievement.dto.IssueAchievementRequest;
import com.fsad.studentachievement.dto.PasswordResetConfirmRequest;
import com.fsad.studentachievement.dto.PasswordResetRequest;
import com.fsad.studentachievement.dto.PlatformLimitsRequest;
import com.fsad.studentachievement.dto.RegistrationOtpRequest;
import com.fsad.studentachievement.dto.SubmitTestRequest;
import com.fsad.studentachievement.dto.TestAccessRequest;
import com.fsad.studentachievement.dto.VerifyRegistrationOtpRequest;
import com.fsad.studentachievement.service.PlatformService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class PlatformController {

    private final PlatformService platformService;

    @PostMapping({"/login", "/auth/login"})
    public Map<String, Object> login(@Valid @RequestBody AuthRequest request) {
        return platformService.login(request);
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        platformService.logout(request.getHeader(HttpHeaders.AUTHORIZATION));
        return ResponseEntity.ok("Logged out successfully");
    }

    @PostMapping("/auth/request-registration-otp")
    public ResponseEntity<Map<String, Object>> requestRegistrationOtp(@Valid @RequestBody RegistrationOtpRequest request) {
        return ResponseEntity.ok(platformService.requestRegistrationOtp(request));
    }

    @PostMapping("/auth/verify-registration-otp")
    public ResponseEntity<Map<String, Object>> verifyRegistrationOtp(@Valid @RequestBody VerifyRegistrationOtpRequest request) {
        return ResponseEntity.ok(platformService.verifyRegistrationOtp(request));
    }

    @PostMapping("/auth/request-password-reset")
    public ResponseEntity<Map<String, Object>> requestPasswordReset(@Valid @RequestBody PasswordResetRequest request) {
        return ResponseEntity.ok(platformService.requestPasswordReset(request));
    }

    @PostMapping("/auth/reset-password")
    public ResponseEntity<String> resetPassword(@Valid @RequestBody PasswordResetConfirmRequest request) {
        return ResponseEntity.ok(platformService.resetPassword(request));
    }

    @GetMapping("/students")
    public List<Map<String, Object>> getStudents(HttpServletRequest request) {
        return platformService.getStudents(request.getHeader(HttpHeaders.AUTHORIZATION));
    }

    @GetMapping("/achievements")
    public List<Map<String, Object>> getAchievements(HttpServletRequest request) {
        return platformService.getAchievements(request.getHeader(HttpHeaders.AUTHORIZATION));
    }

    @GetMapping("/achievements/user/{userId}")
    public List<Map<String, Object>> getAchievementsByUser(HttpServletRequest request, @PathVariable Integer userId) {
        return platformService.getAchievementsByUser(request.getHeader(HttpHeaders.AUTHORIZATION), userId);
    }

    @PostMapping("/achievements")
    public ResponseEntity<String> createAchievement(HttpServletRequest httpRequest, @Valid @RequestBody AchievementRequest request) {
        platformService.createAchievement(httpRequest.getHeader(HttpHeaders.AUTHORIZATION), request);
        return ResponseEntity.ok("Achievement added successfully");
    }

    @GetMapping("/activities")
    public List<Map<String, Object>> getActivities(HttpServletRequest request) {
        return platformService.getActivities(request.getHeader(HttpHeaders.AUTHORIZATION));
    }

    @PostMapping("/activities")
    public ResponseEntity<String> createActivity(HttpServletRequest httpRequest, @Valid @RequestBody ActivityRequest request) {
        platformService.createActivity(httpRequest.getHeader(HttpHeaders.AUTHORIZATION), request);
        return ResponseEntity.ok("Activity added successfully");
    }

    @PostMapping("/admin/activity-slots")
    public ResponseEntity<String> updateActivitySlots(HttpServletRequest request, @Valid @RequestBody ActivitySlotUpdateRequest body) {
        platformService.updateActivitySlots(request.getHeader(HttpHeaders.AUTHORIZATION), body);
        return ResponseEntity.ok("Activity slots updated successfully");
    }

    @PostMapping("/admin/enrollments/grant-test-access")
    public ResponseEntity<String> grantTestAccess(HttpServletRequest request, @Valid @RequestBody TestAccessRequest body) {
        platformService.grantTestAccess(request.getHeader(HttpHeaders.AUTHORIZATION), body.enrollmentId());
        return ResponseEntity.ok("Test access granted successfully");
    }

    @GetMapping("/enrollments")
    public List<Map<String, Object>> getEnrollments(HttpServletRequest request) {
        return platformService.getEnrollments(request.getHeader(HttpHeaders.AUTHORIZATION));
    }

    @PostMapping("/enrollments")
    public ResponseEntity<String> createEnrollment(HttpServletRequest httpRequest, @Valid @RequestBody EnrollmentRequest request) {
        platformService.createEnrollment(httpRequest.getHeader(HttpHeaders.AUTHORIZATION), request);
        return ResponseEntity.ok("Enrollment saved");
    }

    @GetMapping("/participations")
    public List<Map<String, Object>> getParticipations(HttpServletRequest request) {
        return platformService.getParticipations(request.getHeader(HttpHeaders.AUTHORIZATION));
    }

    @GetMapping("/participations/me")
    public List<Map<String, Object>> getMyParticipations(HttpServletRequest request) {
        return platformService.getMyParticipations(request.getHeader(HttpHeaders.AUTHORIZATION));
    }

    @GetMapping("/admin/access-summary")
    public ResponseEntity<Map<String, Object>> getAdminAccessSummary(HttpServletRequest request) {
        return ResponseEntity.ok(platformService.getAdminAccessSummary(request.getHeader(HttpHeaders.AUTHORIZATION)));
    }

    @PostMapping("/admin/limits")
    public ResponseEntity<String> updatePlatformLimits(HttpServletRequest request, @Valid @RequestBody PlatformLimitsRequest body) {
        platformService.updatePlatformLimits(request.getHeader(HttpHeaders.AUTHORIZATION), body);
        return ResponseEntity.ok("Platform limits updated successfully");
    }

    @GetMapping("/admin/debug")
    public ResponseEntity<List<Map<String, Object>>> debugDb(HttpServletRequest request) {
        return ResponseEntity.ok(platformService.debugDb());
    }

    @PostMapping("/admin/approve-coadmin")
    public ResponseEntity<String> approveCoAdmin(HttpServletRequest request, @Valid @RequestBody CoAdminApprovalRequest body) {
        platformService.approveCoAdmin(request.getHeader(HttpHeaders.AUTHORIZATION), body);
        return ResponseEntity.ok("Co-admin approved successfully");
    }

    @PostMapping("/admin/remove-user")
    public ResponseEntity<String> removeUser(HttpServletRequest request, @Valid @RequestBody DeleteUserRequest body) {
        platformService.removeUser(request.getHeader(HttpHeaders.AUTHORIZATION), body);
        return ResponseEntity.ok("User removed successfully");
    }

    @GetMapping("/categories")
    public List<Map<String, Object>> getCategories(HttpServletRequest request) {
        return platformService.getCategories(request.getHeader(HttpHeaders.AUTHORIZATION));
    }

    @GetMapping("/domains/{categoryId}")
    public List<Map<String, Object>> getDomains(HttpServletRequest request, @PathVariable Integer categoryId) {
        return platformService.getDomains(request.getHeader(HttpHeaders.AUTHORIZATION), categoryId);
    }

    @GetMapping("/modules/{domainId}")
    public List<Map<String, Object>> getModules(HttpServletRequest request, @PathVariable Integer domainId) {
        return platformService.getModules(request.getHeader(HttpHeaders.AUTHORIZATION), domainId);
    }

    @GetMapping("/module-study/{moduleId}")
    public ResponseEntity<Map<String, Object>> getModuleStudy(HttpServletRequest request, @PathVariable Integer moduleId) {
        return ResponseEntity.ok(platformService.getModuleStudy(request.getHeader(HttpHeaders.AUTHORIZATION), moduleId));
    }

    @GetMapping("/tests/{moduleId}")
    public ResponseEntity<Map<String, Object>> getTests(HttpServletRequest request, @PathVariable Integer moduleId) {
        return ResponseEntity.ok(platformService.getTests(request.getHeader(HttpHeaders.AUTHORIZATION), moduleId));
    }

    @PostMapping("/submit-test")
    public ResponseEntity<Map<String, Object>> submitTest(HttpServletRequest httpRequest, @Valid @RequestBody SubmitTestRequest request) {
        return ResponseEntity.ok(platformService.submitTest(httpRequest.getHeader(HttpHeaders.AUTHORIZATION), request));
    }

    @GetMapping("/test-attempts/me")
    public ResponseEntity<List<Map<String, Object>>> getMyTestAttempts(HttpServletRequest request) {
        return ResponseEntity.ok(platformService.getMyTestAttempts(request.getHeader(HttpHeaders.AUTHORIZATION)));
    }

    @GetMapping("/test-attempts/{attemptId}/review")
    public ResponseEntity<Map<String, Object>> getTestAttemptReview(HttpServletRequest request, @PathVariable Integer attemptId) {
        return ResponseEntity.ok(platformService.getTestAttemptReview(request.getHeader(HttpHeaders.AUTHORIZATION), attemptId));
    }

    @GetMapping("/admin/test-attempts")
    public ResponseEntity<List<Map<String, Object>>> getTestAttemptsForAdmin(HttpServletRequest request) {
        return ResponseEntity.ok(platformService.getTestAttemptsForAdmin(request.getHeader(HttpHeaders.AUTHORIZATION)));
    }

    @PostMapping("/admin/test-attempts/issue-achievement")
    public ResponseEntity<String> issueAchievementForAttempt(HttpServletRequest request, @Valid @RequestBody IssueAchievementRequest body) {
        platformService.issueAchievementForAttempt(request.getHeader(HttpHeaders.AUTHORIZATION), body);
        return ResponseEntity.ok("Achievement and certificate issued successfully");
    }

    @PostMapping("/certificate")
    public ResponseEntity<String> createCertificate(HttpServletRequest httpRequest, @Valid @RequestBody CertificateRequest request) {
        platformService.createCertificate(httpRequest.getHeader(HttpHeaders.AUTHORIZATION), request);
        return ResponseEntity.ok("Certificate created");
    }

    @GetMapping("/certificates/me")
    public ResponseEntity<List<Map<String, Object>>> getMyCertificates(HttpServletRequest request) {
        return ResponseEntity.ok(platformService.getMyCertificates(request.getHeader(HttpHeaders.AUTHORIZATION)));
    }

    @GetMapping("/certificate/resolve")
    public ResponseEntity<Map<String, Object>> resolveCertificate(HttpServletRequest request, @RequestParam Integer moduleId) {
        return ResponseEntity.ok(platformService.resolveCertificate(request.getHeader(HttpHeaders.AUTHORIZATION), moduleId));
    }

    @GetMapping("/certificate/download")
    public ResponseEntity<byte[]> downloadCertificate(HttpServletRequest request, @RequestParam Integer certificateId) {
        byte[] content = platformService.downloadCertificate(request.getHeader(HttpHeaders.AUTHORIZATION), certificateId);
        return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=certificate.pdf")
            .contentType(MediaType.APPLICATION_PDF)
            .body(content);
    }
}
