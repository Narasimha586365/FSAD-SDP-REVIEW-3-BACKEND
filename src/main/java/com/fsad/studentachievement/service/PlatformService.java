package com.fsad.studentachievement.service;

import java.io.ByteArrayOutputStream;
import java.sql.Date;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.fsad.studentachievement.config.PlatformBootstrap;
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
import com.fsad.studentachievement.dto.TestAnswerRequest;
import com.fsad.studentachievement.dto.VerifyRegistrationOtpRequest;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class PlatformService {

    private static final String ROLE_ADMIN = "ADMIN";
    private static final String ROLE_CO_ADMIN = "CO_ADMIN";
    private static final String ROLE_STUDENT = "STUDENT";
    private static final String STATUS_ACTIVE = "ACTIVE";
    private static final String STATUS_PENDING = "PENDING";

    private final JdbcTemplate jdbcTemplate;
    private final PasswordEncoder passwordEncoder;
    private final MailService mailService;
    private final Random random = new Random();

    public Map<String, Object> login(AuthRequest request) {
        try {
            Map<String, Object> user = jdbcTemplate.queryForObject(
                "SELECT id, name, email, password, role, roll_number AS rollNumber, department, cohort, phone, password_changed AS passwordChanged, access_status AS accessStatus FROM users WHERE email = ?",
                (rs, rowNum) -> {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("id", rs.getInt("id"));
                    item.put("name", rs.getString("name"));
                    item.put("email", rs.getString("email"));
                    item.put("storedPassword", rs.getString("password"));
                    item.put("role", rs.getString("role"));
                    item.put("rollNumber", rs.getString("rollNumber"));
                    item.put("department", rs.getString("department"));
                    item.put("cohort", rs.getString("cohort"));
                    item.put("phone", rs.getString("phone"));
                    item.put("passwordChanged", rs.getBoolean("passwordChanged"));
                    item.put("accessStatus", rs.getString("accessStatus"));
                    return item;
                },
                request.email()
            );
            String storedPassword = String.valueOf(user.remove("storedPassword"));
            boolean matches = storedPassword.startsWith("$2")
                ? passwordEncoder.matches(request.password(), storedPassword)
                : storedPassword.equals(request.password());
            if (!matches) {
                return Map.of();
            }
            if (!storedPassword.startsWith("$2")) {
                jdbcTemplate.update("UPDATE users SET password = ? WHERE email = ?", passwordEncoder.encode(request.password()), request.email());
            }
            if (!STATUS_ACTIVE.equalsIgnoreCase(String.valueOf(user.get("accessStatus")))) {
                throw new IllegalArgumentException("Your co-admin request is pending main admin approval.");
            }
            String token = UUID.randomUUID().toString() + UUID.randomUUID();
            jdbcTemplate.update("DELETE FROM auth_sessions WHERE user_id = ?", user.get("id"));
            jdbcTemplate.update(
                "INSERT INTO auth_sessions (user_id, token, expires_at) VALUES (?, ?, ?)",
                user.get("id"),
                token,
                Timestamp.valueOf(LocalDateTime.now().plusHours(12))
            );
            user.put("token", token);
            user.put("role", normalizeRole(String.valueOf(user.get("role"))));
            user.put("accessStatus", String.valueOf(user.get("accessStatus")).toLowerCase());
            return user;
        } catch (EmptyResultDataAccessException exception) {
            return Map.of();
        }
    }

    public void logout(String authHeader) {
        jdbcTemplate.update("DELETE FROM auth_sessions WHERE token = ?", extractToken(authHeader));
    }

    public Map<String, Object> requestRegistrationOtp(RegistrationOtpRequest request) {
        Integer userCount = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM users WHERE email = ?", Integer.class, request.email());
        if (userCount != null && userCount > 0) {
            throw new IllegalArgumentException("Email already registered");
        }
        Integer rollNumberCount = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM users WHERE roll_number = ?", Integer.class, request.rollNumber());
        if (rollNumberCount != null && rollNumberCount > 0) {
            throw new IllegalArgumentException("Roll number already registered. Please use a different roll number.");
        }
        String normalizedRole = request.role().toUpperCase();
        if (!ROLE_STUDENT.equals(normalizedRole) && !"ADMIN".equals(normalizedRole)) {
            throw new IllegalArgumentException("Invalid role selected");
        }
        if (ROLE_STUDENT.equals(normalizedRole) && getSettingInt("student_limit") <= getRoleCount(ROLE_STUDENT, STATUS_ACTIVE)) {
            throw new IllegalArgumentException("Student registration limit has been reached. Please contact the admin.");
        }
        String otp = generateOtp();
        jdbcTemplate.update("DELETE FROM registration_otps WHERE email = ?", request.email());
        jdbcTemplate.update(
            "INSERT INTO registration_otps (name, email, phone, role, roll_number, department, cohort, otp, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            request.name(), request.email(), request.phone(), normalizedRole, request.rollNumber(), request.department(), request.cohort(), otp, Timestamp.valueOf(LocalDateTime.now().plusMinutes(10))
        );

        String subject = "Student Achievement Platform OTP Verification";
        String body = "Hello " + request.name() + ",\n\nYour 6-digit OTP for registration is: " + otp + "\nIt is valid for 10 minutes.\n\nRole selected: " + normalizedRole + "\nPhone: " + request.phone() + "\n\nStudent Achievement Platform";
        boolean sent = mailService.sendMail(request.email(), subject, body);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("message", sent ? "OTP sent to your email" : "OTP generated. Mail is not configured, using development mode.");
        if (!sent) {
            response.put("developmentOtp", otp);
        }
        return response;
    }

    public Map<String, Object> verifyRegistrationOtp(VerifyRegistrationOtpRequest request) {
        try {
            Map<String, Object> pending = jdbcTemplate.queryForObject(
                "SELECT * FROM registration_otps WHERE email = ? AND phone = ? AND role = ? ORDER BY id DESC LIMIT 1",
                (rs, rowNum) -> {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("id", rs.getInt("id"));
                    item.put("name", rs.getString("name"));
                    item.put("email", rs.getString("email"));
                    item.put("phone", rs.getString("phone"));
                    item.put("role", rs.getString("role"));
                    item.put("rollNumber", rs.getString("roll_number"));
                    item.put("department", rs.getString("department"));
                    item.put("cohort", rs.getString("cohort"));
                    item.put("otp", rs.getString("otp"));
                    item.put("expiresAt", rs.getTimestamp("expires_at").toLocalDateTime());
                    return item;
                },
                request.email(), request.phone(), request.role().toUpperCase()
            );
            if (!String.valueOf(pending.get("otp")).equals(request.otp())) {
                throw new IllegalArgumentException("Invalid OTP");
            }
            if (((LocalDateTime) pending.get("expiresAt")).isBefore(LocalDateTime.now())) {
                throw new IllegalArgumentException("OTP expired. Please request again.");
            }
            Integer emailCount = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM users WHERE email = ?", Integer.class, pending.get("email"));
            if (emailCount != null && emailCount > 0) {
                throw new IllegalArgumentException("Email already registered. Please log in instead.");
            }
            Integer rollNumberCount = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM users WHERE roll_number = ?", Integer.class, pending.get("rollNumber"));
            if (rollNumberCount != null && rollNumberCount > 0) {
                throw new IllegalArgumentException("Roll number already registered. Please use a different roll number.");
            }

            String requestedRole = String.valueOf(pending.get("role"));
            String assignedRole = ROLE_STUDENT;
            String accessStatus = STATUS_ACTIVE;
            String defaultPassword = generateTemporaryPassword(requestedRole);
            if ("ADMIN".equalsIgnoreCase(requestedRole)) {
                assignedRole = ROLE_CO_ADMIN;
                accessStatus = STATUS_PENDING;
            }
            jdbcTemplate.update(
                "INSERT INTO users (name, email, password, role, roll_number, department, cohort, phone, password_changed, access_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, FALSE, ?)",
                pending.get("name"), pending.get("email"), passwordEncoder.encode(defaultPassword), assignedRole, pending.get("rollNumber"), pending.get("department"), pending.get("cohort"), pending.get("phone"), accessStatus
            );
            jdbcTemplate.update("DELETE FROM registration_otps WHERE id = ?", pending.get("id"));

            boolean userMailSent = true;
            if (STATUS_ACTIVE.equals(accessStatus)) {
                String userMailText = "Hello " + pending.get("name") + ",\n\nYour account has been created successfully.\nDefault password: " + defaultPassword + "\nPlease log in and use Forgot Password to set your own secure password.\n\nEmail: " + pending.get("email") + "\nRole: Student\nPhone: " + pending.get("phone") + "\n\nStudent Achievement Platform";
                userMailSent = mailService.sendMail(String.valueOf(pending.get("email")), "Your Student Achievement Platform Account", userMailText);
            } else {
                String pendingMailText = "Hello " + pending.get("name") + ",\n\nYour admin registration request has been received by the main admin.\nYour request is currently under review for co-admin access.\nYou will receive another email with your default password once the main admin approves your request.\n\nEmail: " + pending.get("email") + "\nRequested Role: Admin\nPhone: " + pending.get("phone") + "\n\nStudent Achievement Platform";
                userMailSent = mailService.sendMail(String.valueOf(pending.get("email")), "Admin Registration Request Received", pendingMailText);
            }

            String adminMailText = "New user registered on Student Achievement Platform.\n\nName: " + pending.get("name") + "\nEmail: " + pending.get("email") + "\nRequested role: " + requestedRole + "\nPhone: " + pending.get("phone");
            mailService.sendMail(PlatformBootstrap.MAIN_ADMIN_EMAIL, "New Registration Alert", adminMailText);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("message", STATUS_PENDING.equals(accessStatus)
                ? "Registration request submitted. Main admin will review your co-admin request."
                : (userMailSent ? "Registration completed. Default password sent to your email." : "Registration completed in development mode."));
            if (STATUS_ACTIVE.equals(accessStatus) && !userMailSent) {
                response.put("developmentPassword", defaultPassword);
            }
            return response;
        } catch (EmptyResultDataAccessException exception) {
            throw new IllegalArgumentException("Please request OTP before verifying.");
        }
    }

    public Map<String, Object> requestPasswordReset(PasswordResetRequest request) {
        Map<String, Object> user = findUserByEmail(request.email());
        if (user == null || !String.valueOf(user.get("role")).equalsIgnoreCase(request.role().replace('-', '_'))) {
            throw new IllegalArgumentException("No account found for the selected role.");
        }
        if (!STATUS_ACTIVE.equals(String.valueOf(user.get("accessStatus")))) {
            throw new IllegalArgumentException("This account is pending admin approval.");
        }
        String otp = generateOtp();
        jdbcTemplate.update("DELETE FROM password_reset_otps WHERE email = ?", request.email());
        jdbcTemplate.update(
            "INSERT INTO password_reset_otps (email, role, otp, expires_at) VALUES (?, ?, ?, ?)",
            request.email(), request.role().toUpperCase().replace('-', '_'), otp, Timestamp.valueOf(LocalDateTime.now().plusMinutes(10))
        );
        boolean sent = mailService.sendMail(request.email(), "Password Reset OTP", "Your password reset OTP is: " + otp + "\nValid for 10 minutes.");
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("message", sent ? "Password reset OTP sent to your email" : "Password reset OTP generated in development mode.");
        if (!sent) {
            response.put("developmentOtp", otp);
        }
        return response;
    }

    public String resetPassword(PasswordResetConfirmRequest request) {
        if (!request.newPassword().contains("@")) {
            throw new IllegalArgumentException("Password must contain @ symbol");
        }
        try {
            Map<String, Object> otpRow = jdbcTemplate.queryForObject(
                "SELECT id, otp, expires_at FROM password_reset_otps WHERE email = ? AND role = ? ORDER BY id DESC LIMIT 1",
                (rs, rowNum) -> Map.of(
                    "id", rs.getInt("id"),
                    "otp", rs.getString("otp"),
                    "expiresAt", rs.getTimestamp("expires_at").toLocalDateTime()
                ),
                request.email(), request.role().toUpperCase().replace('-', '_')
            );
            if (!String.valueOf(otpRow.get("otp")).equals(request.otp())) {
                throw new IllegalArgumentException("Invalid OTP");
            }
            if (((LocalDateTime) otpRow.get("expiresAt")).isBefore(LocalDateTime.now())) {
                throw new IllegalArgumentException("OTP expired. Please request again.");
            }
            jdbcTemplate.update("UPDATE users SET password = ?, password_changed = TRUE WHERE email = ?", passwordEncoder.encode(request.newPassword()), request.email());
            jdbcTemplate.update("DELETE FROM password_reset_otps WHERE id = ?", otpRow.get("id"));
            mailService.sendMail(request.email(), "Password Changed Successfully", "Your password has been updated successfully for Student Achievement Platform.");
            return "Password updated successfully";
        } catch (EmptyResultDataAccessException exception) {
            throw new IllegalArgumentException("No password reset OTP found.");
        }
    }

    public List<Map<String, Object>> getStudents(String authHeader) {
        requireRole(authHeader, ROLE_ADMIN, ROLE_CO_ADMIN);
        return jdbcTemplate.query(
            "SELECT id, name, email, role, roll_number AS rollNumber, department, cohort, phone, access_status AS accessStatus FROM users WHERE role = 'STUDENT' ORDER BY id DESC",
            (rs, rowNum) -> mapUser(rs.getInt("id"), rs.getString("name"), rs.getString("email"), rs.getString("role"), rs.getString("rollNumber"), rs.getString("department"), rs.getString("cohort"), rs.getString("phone"), rs.getString("accessStatus"))
        );
    }

    public List<Map<String, Object>> getAchievements(String authHeader) {
        requireRole(authHeader, ROLE_ADMIN, ROLE_CO_ADMIN);
        return jdbcTemplate.query(
            "SELECT a.id, a.user_id AS studentId, u.name AS studentName, u.roll_number AS rollNumber, a.title, a.category, a.activity_category AS activityCategory, a.description, a.date FROM achievements a JOIN users u ON u.id = a.user_id ORDER BY a.date DESC",
            (rs, rowNum) -> {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("id", rs.getInt("id"));
                item.put("studentId", rs.getInt("studentId"));
                item.put("studentName", rs.getString("studentName"));
                item.put("rollNumber", rs.getString("rollNumber"));
                item.put("title", rs.getString("title"));
                item.put("category", rs.getString("category"));
                item.put("activityCategory", rs.getString("activityCategory"));
                item.put("description", rs.getString("description"));
                item.put("date", rs.getString("date"));
                return item;
            }
        );
    }

    public List<Map<String, Object>> getAchievementsByUser(String authHeader, Integer userId) {
        Map<String, Object> actor = requireAuthenticated(authHeader);
        if (((Number) actor.get("id")).intValue() != userId && !hasRole(actor, ROLE_ADMIN, ROLE_CO_ADMIN)) {
            throw new IllegalArgumentException("You are not allowed to view this student's achievements.");
        }
        return jdbcTemplate.query(
            "SELECT a.id, a.user_id AS studentId, u.name AS studentName, u.roll_number AS rollNumber, a.title, a.category, a.activity_category AS activityCategory, a.description, a.date FROM achievements a JOIN users u ON u.id = a.user_id WHERE a.user_id = ? ORDER BY a.date DESC",
            (rs, rowNum) -> {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("id", rs.getInt("id"));
                item.put("studentId", rs.getInt("studentId"));
                item.put("studentName", rs.getString("studentName"));
                item.put("rollNumber", rs.getString("rollNumber"));
                item.put("title", rs.getString("title"));
                item.put("category", rs.getString("category"));
                item.put("activityCategory", rs.getString("activityCategory"));
                item.put("description", rs.getString("description"));
                item.put("date", rs.getString("date"));
                return item;
            },
            userId
        );
    }

    public void createAchievement(String authHeader, AchievementRequest request) {
        requireRole(authHeader, ROLE_ADMIN, ROLE_CO_ADMIN);
        jdbcTemplate.update(
            "INSERT INTO achievements (user_id, title, category, activity_category, description, date) VALUES (?, ?, ?, ?, ?, ?)",
            request.studentId(), request.title(), request.category(), request.activityCategory(), request.description(), Date.valueOf(request.date())
        );
    }

    public List<Map<String, Object>> getActivities(String authHeader) {
        requireAuthenticated(authHeader);
        return jdbcTemplate.query(
            "SELECT a.id AS activityId, a.name AS activityName, a.type AS activityCategory, a.domain_id AS domainId, d.name AS domainName, a.role, a.duration, a.skills, a.start_date AS startDate, a.end_date AS endDate, a.slots, COUNT(e.id) AS enrolledCount FROM activities a LEFT JOIN domains d ON d.id = a.domain_id LEFT JOIN enrollments e ON e.activity_id = a.id GROUP BY a.id, a.name, a.type, a.domain_id, d.name, a.role, a.duration, a.skills, a.start_date, a.end_date, a.slots ORDER BY a.start_date DESC, a.id DESC",
            (rs, rowNum) -> mapActivity(rs)
        );
    }

    public void createActivity(String authHeader, ActivityRequest request) {
        requireRole(authHeader, ROLE_ADMIN, ROLE_CO_ADMIN);
        jdbcTemplate.update(
            "INSERT INTO activities (name, type, domain_id, role, duration, skills, start_date, end_date, slots) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            request.activityName(), request.activityCategory(), request.domainId(), request.role(), request.duration(), request.skills(), Date.valueOf(request.startDate()), Date.valueOf(request.endDate()), request.slots()
        );
    }

    public void updateActivitySlots(String authHeader, ActivitySlotUpdateRequest request) {
        requireRole(authHeader, ROLE_ADMIN);
        Integer enrolledCount = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM enrollments WHERE activity_id = ?", Integer.class, request.activityId());
        if (enrolledCount != null && request.slots() < enrolledCount) {
            throw new IllegalArgumentException("Slots cannot be less than current enrollments.");
        }
        jdbcTemplate.update("UPDATE activities SET slots = ? WHERE id = ?", request.slots(), request.activityId());
    }

    public void grantTestAccess(String authHeader, Integer enrollmentId) {
        requireRole(authHeader, ROLE_ADMIN);
        Integer updated = jdbcTemplate.update("UPDATE enrollments SET test_access = TRUE WHERE id = ?", enrollmentId);
        if (updated == 0) {
            throw new IllegalArgumentException("Enrollment not found.");
        }
    }

    public List<Map<String, Object>> getEnrollments(String authHeader) {
        requireRole(authHeader, ROLE_ADMIN, ROLE_CO_ADMIN);
        return jdbcTemplate.query(
            "SELECT e.id, e.user_id AS studentId, u.name AS studentName, u.roll_number AS rollNumber, e.activity_id AS activityId, a.name AS activityName, a.type AS activityCategory, a.domain_id AS domainId, d.name AS domainName, e.test_access AS testAccessGranted, a.slots, (SELECT COUNT(*) FROM enrollments en WHERE en.activity_id = a.id) AS enrolledCount, e.status, e.enrolled_date AS enrolledDate FROM enrollments e JOIN users u ON u.id = e.user_id JOIN activities a ON a.id = e.activity_id LEFT JOIN domains d ON d.id = a.domain_id ORDER BY e.enrolled_date DESC",
            (rs, rowNum) -> {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("id", rs.getInt("id"));
                item.put("studentId", rs.getInt("studentId"));
                item.put("studentName", rs.getString("studentName"));
                item.put("rollNumber", rs.getString("rollNumber"));
                item.put("activityId", rs.getInt("activityId"));
                item.put("activityName", rs.getString("activityName"));
                item.put("activityCategory", rs.getString("activityCategory"));
                item.put("domainId", rs.getObject("domainId"));
                item.put("domainName", rs.getString("domainName"));
                item.put("slots", rs.getInt("slots"));
                item.put("enrolledCount", rs.getInt("enrolledCount"));
                item.put("status", rs.getString("status"));
                item.put("enrolledDate", rs.getString("enrolledDate"));
                item.put("testAccessGranted", rs.getBoolean("testAccessGranted"));
                return item;
            }
        );
    }

    public void createEnrollment(String authHeader, EnrollmentRequest request) {
        Map<String, Object> actor = requireAuthenticated(authHeader);
        boolean selfEnrollment = hasRole(actor, ROLE_STUDENT) && ((Number) actor.get("id")).intValue() == request.studentId();
        if (!selfEnrollment && !hasRole(actor, ROLE_ADMIN, ROLE_CO_ADMIN)) {
            throw new IllegalArgumentException("You are not authorized to enroll this student.");
        }
        Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM enrollments WHERE user_id = ? AND activity_id = ?", Integer.class, request.studentId(), request.activityId());
        if (count != null && count > 0) {
            return;
        }
        Integer slots = jdbcTemplate.queryForObject("SELECT slots FROM activities WHERE id = ?", Integer.class, request.activityId());
        Integer enrolledCount = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM enrollments WHERE activity_id = ?", Integer.class, request.activityId());
        if (slots != null && enrolledCount != null && enrolledCount >= slots) {
            throw new IllegalArgumentException("Enrollment limit reached for this activity.");
        }
        jdbcTemplate.update("INSERT INTO enrollments (user_id, activity_id, status, enrolled_date, test_access) VALUES (?, ?, 'ENROLLED', ?, TRUE)", request.studentId(), request.activityId(), Date.valueOf(LocalDate.now()));
    }

    public List<Map<String, Object>> getParticipations(String authHeader) {
        requireRole(authHeader, ROLE_ADMIN, ROLE_CO_ADMIN);
        return jdbcTemplate.query(
            "SELECT e.id, e.user_id AS studentId, u.name AS studentName, a.id AS activityId, a.name AS activityName, a.type AS activityCategory, a.domain_id AS domainId, d.name AS domainName, e.test_access AS testAccessGranted, a.role, a.duration, a.skills, a.start_date AS startDate, a.end_date AS endDate, a.slots, (SELECT COUNT(*) FROM enrollments en WHERE en.activity_id = a.id) AS enrolledCount, e.status FROM enrollments e JOIN users u ON u.id = e.user_id JOIN activities a ON a.id = e.activity_id LEFT JOIN domains d ON d.id = a.domain_id ORDER BY a.start_date DESC",
            (rs, rowNum) -> {
                Map<String, Object> item = mapActivity(rs);
                item.put("id", rs.getInt("id"));
                item.put("studentId", rs.getInt("studentId"));
                item.put("studentName", rs.getString("studentName"));
                item.put("status", rs.getString("status"));
                item.put("testAccessGranted", rs.getBoolean("testAccessGranted"));
                return item;
            }
        );
    }

    public List<Map<String, Object>> getMyParticipations(String authHeader) {
        Map<String, Object> actor = requireRole(authHeader, ROLE_STUDENT);
        return jdbcTemplate.query(
            "SELECT e.id, e.user_id AS studentId, u.name AS studentName, a.id AS activityId, a.name AS activityName, a.type AS activityCategory, a.domain_id AS domainId, d.name AS domainName, e.test_access AS testAccessGranted, a.role, a.duration, a.skills, a.start_date AS startDate, a.end_date AS endDate, a.slots, (SELECT COUNT(*) FROM enrollments en WHERE en.activity_id = a.id) AS enrolledCount, e.status FROM enrollments e JOIN users u ON u.id = e.user_id JOIN activities a ON a.id = e.activity_id LEFT JOIN domains d ON d.id = a.domain_id WHERE e.user_id = ? ORDER BY a.start_date DESC",
            (rs, rowNum) -> {
                Map<String, Object> item = mapActivity(rs);
                item.put("id", rs.getInt("id"));
                item.put("studentId", rs.getInt("studentId"));
                item.put("studentName", rs.getString("studentName"));
                item.put("status", rs.getString("status"));
                item.put("testAccessGranted", rs.getBoolean("testAccessGranted"));
                return item;
            },
            actor.get("id")
        );
    }

    public Map<String, Object> getAdminAccessSummary(String authHeader) {
        requireRole(authHeader, ROLE_ADMIN);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("studentLimit", getSettingInt("student_limit"));
        response.put("studentCount", getRoleCount(ROLE_STUDENT, STATUS_ACTIVE));
        response.put("coAdminLimit", getSettingInt("co_admin_limit"));
        response.put("coAdminCount", getRoleCount(ROLE_CO_ADMIN, STATUS_ACTIVE));
        response.put("pendingCoAdminCount", getRoleCount(ROLE_CO_ADMIN, STATUS_PENDING));
        response.put("pendingCoAdmins", jdbcTemplate.query(
            "SELECT id, name, email, role, roll_number AS rollNumber, department, cohort, phone, access_status AS accessStatus FROM users WHERE role = 'CO_ADMIN' AND access_status = 'PENDING' ORDER BY id DESC",
            (rs, rowNum) -> mapUser(rs.getInt("id"), rs.getString("name"), rs.getString("email"), rs.getString("role"), rs.getString("rollNumber"), rs.getString("department"), rs.getString("cohort"), rs.getString("phone"), rs.getString("accessStatus"))
        ));
        response.put("activeCoAdmins", jdbcTemplate.query(
            "SELECT id, name, email, role, roll_number AS rollNumber, department, cohort, phone, access_status AS accessStatus FROM users WHERE role = 'CO_ADMIN' AND access_status = 'ACTIVE' ORDER BY id DESC",
            (rs, rowNum) -> mapUser(rs.getInt("id"), rs.getString("name"), rs.getString("email"), rs.getString("role"), rs.getString("rollNumber"), rs.getString("department"), rs.getString("cohort"), rs.getString("phone"), rs.getString("accessStatus"))
        ));
        return response;
    }

    public void updatePlatformLimits(String authHeader, PlatformLimitsRequest request) {
        requireRole(authHeader, ROLE_ADMIN);
        if (request.studentLimit() < getRoleCount(ROLE_STUDENT, STATUS_ACTIVE)) {
            throw new IllegalArgumentException("Student limit cannot be lower than current active students.");
        }
        if (request.coAdminLimit() < getRoleCount(ROLE_CO_ADMIN, STATUS_ACTIVE)) {
            throw new IllegalArgumentException("Co-admin limit cannot be lower than current active co-admins.");
        }
        jdbcTemplate.update("UPDATE platform_settings SET setting_value = ? WHERE setting_key = 'student_limit'", String.valueOf(request.studentLimit()));
        jdbcTemplate.update("UPDATE platform_settings SET setting_value = ? WHERE setting_key = 'co_admin_limit'", String.valueOf(request.coAdminLimit()));
    }

    public List<Map<String, Object>> debugDb() {
        return jdbcTemplate.queryForList("SELECT * FROM test_attempts");
    }

    public void approveCoAdmin(String authHeader, CoAdminApprovalRequest request) {
        requireRole(authHeader, ROLE_ADMIN);
        if (getRoleCount(ROLE_CO_ADMIN, STATUS_ACTIVE) >= getSettingInt("co_admin_limit")) {
            throw new IllegalArgumentException("Co-admin limit reached. Increase the limit before approving.");
        }
        Map<String, Object> user = jdbcTemplate.queryForObject(
            "SELECT id, name, email, role, access_status AS accessStatus FROM users WHERE id = ?",
            (rs, rowNum) -> Map.of(
                "id", rs.getInt("id"),
                "name", rs.getString("name"),
                "email", rs.getString("email"),
                "role", rs.getString("role"),
                "accessStatus", rs.getString("accessStatus")
            ),
            request.userId()
        );
        if (!ROLE_CO_ADMIN.equals(String.valueOf(user.get("role"))) || !STATUS_PENDING.equals(String.valueOf(user.get("accessStatus")))) {
            throw new IllegalArgumentException("Selected user is not a pending co-admin request.");
        }
        String defaultPassword = generateTemporaryPassword("ADMIN");
        jdbcTemplate.update("UPDATE users SET access_status = 'ACTIVE', password = ?, password_changed = FALSE WHERE id = ?", passwordEncoder.encode(defaultPassword), request.userId());
        mailService.sendMail(
            String.valueOf(user.get("email")),
            "Co-Admin Access Approved",
            "Hello " + user.get("name") + ",\n\nYour co-admin access has been approved.\nDefault password: " + defaultPassword + "\nPlease log in and change your password using Forgot Password.\n\nStudent Achievement Platform"
        );
    }

    public void removeUser(String authHeader, DeleteUserRequest request) {
        Map<String, Object> actor = requireRole(authHeader, ROLE_ADMIN);
        Map<String, Object> user = jdbcTemplate.queryForObject(
            "SELECT id, name, email, role, roll_number AS rollNumber, department, cohort, phone, access_status AS accessStatus FROM users WHERE id = ?",
            (rs, rowNum) -> {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("id", rs.getInt("id"));
                item.put("name", rs.getString("name"));
                item.put("email", rs.getString("email"));
                item.put("role", rs.getString("role"));
                item.put("rollNumber", rs.getString("rollNumber"));
                item.put("department", rs.getString("department"));
                item.put("cohort", rs.getString("cohort"));
                item.put("phone", rs.getString("phone"));
                item.put("accessStatus", rs.getString("accessStatus"));
                return item;
            },
            request.userId()
        );
        int userId = ((Number) user.get("id")).intValue();
        if (userId == ((Number) actor.get("id")).intValue()) {
            throw new IllegalArgumentException("Main admin cannot remove the current account.");
        }
        String role = String.valueOf(user.get("role"));
        if (!ROLE_STUDENT.equals(role) && !ROLE_CO_ADMIN.equals(role)) {
            throw new IllegalArgumentException("Only student and co-admin accounts can be removed.");
        }
        if (PlatformBootstrap.MAIN_ADMIN_EMAIL.equalsIgnoreCase(String.valueOf(user.get("email")))) {
            throw new IllegalArgumentException("Main admin account cannot be removed.");
        }

        jdbcTemplate.update(
            "INSERT INTO removed_users (original_user_id, name, email, role, roll_number, department, cohort, phone, access_status, removed_by, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            userId,
            user.get("name"),
            user.get("email"),
            user.get("role"),
            user.get("rollNumber"),
            user.get("department"),
            user.get("cohort"),
            user.get("phone"),
            user.get("accessStatus"),
            actor.get("id"),
            "Removed from admin access management"
        );

        String removedRoleLabel = ROLE_CO_ADMIN.equals(role) ? "co-admin" : "student";
        String removalMailText = "Hello " + user.get("name") + ",\n\n"
            + "Your " + removedRoleLabel + " account has been removed from the Student Achievement Platform by the main admin.\n"
            + "You no longer have access to the portal with this account.\n\n"
            + "Email: " + user.get("email") + "\n"
            + "Role: " + removedRoleLabel + "\n\n"
            + "If you believe this was done by mistake, please contact the main admin.\n\n"
            + "Student Achievement Platform";
        mailService.sendMail(String.valueOf(user.get("email")), "Account Removed From Student Achievement Platform", removalMailText);

        jdbcTemplate.update("DELETE FROM auth_sessions WHERE user_id = ?", userId);
        jdbcTemplate.update("DELETE FROM password_reset_otps WHERE email = ?", user.get("email"));
        jdbcTemplate.update("DELETE FROM registration_otps WHERE email = ?", user.get("email"));
        jdbcTemplate.update("DELETE taa FROM test_attempt_answers taa JOIN test_attempts ta ON ta.id = taa.attempt_id WHERE ta.user_id = ?", userId);
        jdbcTemplate.update("DELETE FROM test_attempts WHERE user_id = ?", userId);
        jdbcTemplate.update("DELETE FROM certificates WHERE user_id = ?", userId);
        jdbcTemplate.update("DELETE FROM achievements WHERE user_id = ?", userId);
        jdbcTemplate.update("DELETE FROM enrollments WHERE user_id = ?", userId);
        jdbcTemplate.update("DELETE FROM student_progress WHERE user_id = ?", userId);
        jdbcTemplate.update("DELETE FROM users WHERE id = ?", userId);
    }

    public List<Map<String, Object>> getCategories(String authHeader) {
        requireAuthenticated(authHeader);
        return jdbcTemplate.query(
            "SELECT id, name FROM categories ORDER BY id",
            (rs, rowNum) -> Map.of("id", rs.getInt("id"), "name", rs.getString("name"), "activityCategory", categoryToActivityType(rs.getString("name")))
        );
    }

    public List<Map<String, Object>> getDomains(String authHeader, Integer categoryId) {
        requireAuthenticated(authHeader);
        return jdbcTemplate.query(
            "SELECT d.id, d.name, m.id AS moduleId FROM domains d JOIN categories c ON c.id = d.category_id LEFT JOIN modules m ON m.domain_id = d.id WHERE d.category_id = ? AND NOT (c.name = 'Sports Competitions' AND d.name = 'Competitive Sports') ORDER BY d.id",
            (rs, rowNum) -> Map.of("id", rs.getInt("id"), "name", rs.getString("name"), "moduleId", rs.getInt("moduleId")),
            categoryId
        );
    }

    public List<Map<String, Object>> getModules(String authHeader, Integer domainId) {
        requireAuthenticated(authHeader);
        return jdbcTemplate.query(
            "SELECT id, COALESCE(name, title) AS name, question_count AS questionCount FROM modules WHERE domain_id = ? ORDER BY id",
            (rs, rowNum) -> Map.of("id", rs.getInt("id"), "name", rs.getString("name"), "questionCount", rs.getInt("questionCount")),
            domainId
        );
    }

    public Map<String, Object> getModuleStudy(String authHeader, Integer moduleId) {
        requireRole(authHeader, ROLE_STUDENT);
        Map<String, Object> module = jdbcTemplate.queryForObject(
            "SELECT m.id, COALESCE(m.name, m.title) AS moduleName, m.content, d.id AS domainId, d.name AS domainName, c.id AS categoryId, c.name AS categoryName FROM modules m JOIN domains d ON d.id = m.domain_id JOIN categories c ON c.id = d.category_id WHERE m.id = ?",
            (rs, rowNum) -> {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("moduleId", rs.getInt("id"));
                item.put("moduleName", rs.getString("moduleName"));
                item.put("domainId", rs.getInt("domainId"));
                item.put("domainName", rs.getString("domainName"));
                item.put("categoryId", rs.getInt("categoryId"));
                item.put("categoryName", rs.getString("categoryName"));
                item.put("content", rs.getString("content"));
                return item;
            },
            moduleId
        );
        String existingContent = String.valueOf(module.getOrDefault("content", ""));
        String studyContent = existingContent;
        if (shouldRegenerateStudyContent(existingContent)) {
            studyContent = buildStudyContent(
                String.valueOf(module.get("categoryName")),
                String.valueOf(module.get("domainName")),
                String.valueOf(module.get("moduleName"))
            );
            jdbcTemplate.update("UPDATE modules SET content = ? WHERE id = ?", studyContent, moduleId);
        }
        module.put("content", studyContent);
        return module;
    }

    public Map<String, Object> getTests(String authHeader, Integer moduleId) {
        Map<String, Object> actor = requireRole(authHeader, ROLE_STUDENT);
        Map<String, Object> module = jdbcTemplate.queryForObject(
            "SELECT m.id, COALESCE(m.name, m.title) AS moduleName, m.question_count AS questionCount, d.id AS domainId, d.name AS domainName, c.name AS categoryName FROM modules m JOIN domains d ON d.id = m.domain_id JOIN categories c ON c.id = d.category_id WHERE m.id = ?",
            (rs, rowNum) -> Map.of(
                "moduleId", rs.getInt("id"),
                "moduleName", rs.getString("moduleName"),
                "domainId", rs.getInt("domainId"),
                "questionCount", rs.getInt("questionCount"),
                "domainName", rs.getString("domainName"),
                "categoryName", rs.getString("categoryName")
            ),
            moduleId
        );
        ensureStudentEnrolledForDomain(
            ((Number) actor.get("id")).intValue(),
            ((Number) module.get("domainId")).intValue(),
            String.valueOf(module.get("domainName")),
            String.valueOf(module.get("categoryName"))
        );

        Integer completedAttempts = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM test_attempts WHERE user_id = ? AND module_id = ? AND status = 'COMPLETED'",
            Integer.class,
            actor.get("id"),
            moduleId
        );
        Integer passedAttempts = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM test_attempts WHERE user_id = ? AND module_id = ? AND status = 'COMPLETED' AND score >= 50",
            Integer.class,
            actor.get("id"),
            moduleId
        );
        if ((passedAttempts != null && passedAttempts > 0) || (completedAttempts != null && completedAttempts >= 2)) {
            throw new IllegalArgumentException("You have already completed both test chances for this domain.");
        }

        Integer attemptId = jdbcTemplate.query(
            "SELECT id FROM test_attempts WHERE user_id = ? AND module_id = ? AND status = 'IN_PROGRESS' ORDER BY id DESC LIMIT 1",
            rs -> rs.next() ? rs.getInt("id") : null,
            actor.get("id"),
            moduleId
        );
        int questionCount = ((Number) module.get("questionCount")).intValue();
        if (attemptId == null) {
            jdbcTemplate.update(
                "INSERT INTO test_attempts (user_id, module_id, status, total_questions, correct_answers, score, certificate_issued) VALUES (?, ?, 'IN_PROGRESS', ?, 0, 0, FALSE)",
                actor.get("id"),
                moduleId,
                questionCount
            );
            attemptId = jdbcTemplate.queryForObject("SELECT LAST_INSERT_ID()", Integer.class);
            List<Integer> questionIds = jdbcTemplate.queryForList("SELECT id FROM tests WHERE module_id = ? ORDER BY RAND() LIMIT ?", Integer.class, moduleId, questionCount);
            if (questionIds.size() < questionCount) {
                throw new IllegalArgumentException("Question bank is not ready for this domain yet.");
            }
            for (Integer questionId : questionIds) {
                jdbcTemplate.update("INSERT INTO test_attempt_answers (attempt_id, test_id) VALUES (?, ?)", attemptId, questionId);
            }
        }

        List<Map<String, Object>> questions = jdbcTemplate.query(
            "SELECT t.id, t.question, t.option_a AS optionA, t.option_b AS optionB, t.option_c AS optionC, t.option_d AS optionD FROM test_attempt_answers a JOIN tests t ON t.id = a.test_id WHERE a.attempt_id = ? ORDER BY a.id",
            (rs, rowNum) -> {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("id", rs.getInt("id"));
                item.put("question", rs.getString("question"));
                item.put("optionA", rs.getString("optionA"));
                item.put("optionB", rs.getString("optionB"));
                item.put("optionC", rs.getString("optionC"));
                item.put("optionD", rs.getString("optionD"));
                return item;
            },
            attemptId
        );

        return Map.of(
            "attemptId", attemptId,
            "moduleId", module.get("moduleId"),
            "moduleName", module.get("moduleName"),
            "domainName", module.get("domainName"),
            "categoryName", module.get("categoryName"),
            "questions", questions
        );
    }

    public Map<String, Object> submitTest(String authHeader, SubmitTestRequest request) {
        Map<String, Object> actor = requireRole(authHeader, ROLE_STUDENT);
        if (((Number) actor.get("id")).intValue() != request.userId()) {
            throw new IllegalArgumentException("You are not allowed to submit this test.");
        }
        Map<String, Object> attempt = jdbcTemplate.queryForObject(
            "SELECT id, user_id AS userId, module_id AS moduleId, status FROM test_attempts WHERE id = ?",
            (rs, rowNum) -> Map.of("id", rs.getInt("id"), "userId", rs.getInt("userId"), "moduleId", rs.getInt("moduleId"), "status", rs.getString("status")),
            request.attemptId()
        );
        if (((Number) attempt.get("userId")).intValue() != request.userId() || ((Number) attempt.get("moduleId")).intValue() != request.moduleId()) {
            throw new IllegalArgumentException("Test attempt does not belong to this student.");
        }
        if (!"IN_PROGRESS".equals(String.valueOf(attempt.get("status")))) {
            throw new IllegalArgumentException("This test attempt has already been submitted.");
        }
        Integer totalQuestions = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM test_attempt_answers WHERE attempt_id = ?", Integer.class, request.attemptId());
        if (totalQuestions == null || request.answers().size() != totalQuestions) {
            throw new IllegalArgumentException("Please answer all 20 questions before submitting.");
        }

        for (TestAnswerRequest answer : request.answers()) {
            String correctAnswer = jdbcTemplate.queryForObject(
                "SELECT t.correct_answer FROM test_attempt_answers a JOIN tests t ON t.id = a.test_id WHERE a.attempt_id = ? AND a.test_id = ?",
                String.class,
                request.attemptId(),
                answer.questionId()
            );
            if (correctAnswer == null) {
                throw new IllegalArgumentException("Invalid question in test submission.");
            }
            jdbcTemplate.update(
                "UPDATE test_attempt_answers SET selected_answer = ?, is_correct = ? WHERE attempt_id = ? AND test_id = ?",
                answer.selectedAnswer(),
                correctAnswer.equals(answer.selectedAnswer()),
                request.attemptId(),
                answer.questionId()
            );
        }

        Integer correctAnswers = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM test_attempt_answers WHERE attempt_id = ? AND is_correct = TRUE", Integer.class, request.attemptId());
        int score = totalQuestions == null || totalQuestions == 0 ? 0 : (int) Math.round((correctAnswers == null ? 0 : correctAnswers) * 100.0 / totalQuestions);
        jdbcTemplate.update("UPDATE test_attempts SET status = 'COMPLETED', total_questions = ?, correct_answers = ?, score = ?, submitted_at = NOW() WHERE id = ?", totalQuestions, correctAnswers == null ? 0 : correctAnswers, score, request.attemptId());
        Integer completedAttempts = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM test_attempts WHERE user_id = ? AND module_id = ? AND status = 'COMPLETED'",
            Integer.class,
            request.userId(),
            request.moduleId()
        );
        int attemptsUsed = completedAttempts == null ? 1 : completedAttempts;
        int attemptsLeft = Math.max(0, 2 - attemptsUsed);
        boolean passed = score >= 50;
        issueAutomaticCertificateForAttempt(request.attemptId(), passed);

        return Map.of(
            "message", passed
                ? "Submitted test successfully. Certificate issued to the student."
                : attemptsLeft > 0
                    ? "Submitted test successfully. You can use your second chance."
                    : "Submitted test successfully. Final not-passed certificate issued to the student.",
            "score", score,
            "passed", passed,
            "attemptsLeft", attemptsLeft,
            "certificateIssued", true
        );
    }

    public List<Map<String, Object>> getMyTestAttempts(String authHeader) {
        Map<String, Object> actor = requireRole(authHeader, ROLE_STUDENT);
        return jdbcTemplate.query(
            "SELECT ta.id, ta.module_id AS moduleId, ta.status, ta.total_questions AS totalQuestions, ta.correct_answers AS correctAnswers, ta.score, ta.submitted_at AS submittedAt, ta.certificate_issued AS certificateIssued, cert.id AS certificateId, cert.file_name AS certificateFileName, COALESCE(m.name, m.title) AS moduleName, d.name AS domainName, c.name AS categoryName FROM test_attempts ta JOIN modules m ON m.id = ta.module_id JOIN domains d ON d.id = m.domain_id JOIN categories c ON c.id = d.category_id LEFT JOIN certificates cert ON cert.attempt_id = ta.id WHERE ta.user_id = ? ORDER BY ta.id DESC",
            (rs, rowNum) -> mapAttempt(rs),
            actor.get("id")
        );
    }

    public Map<String, Object> getTestAttemptReview(String authHeader, Integer attemptId) {
        Map<String, Object> actor = requireAuthenticated(authHeader);
        Map<String, Object> summary = jdbcTemplate.queryForObject(
            "SELECT ta.id, ta.user_id AS userId, u.name AS studentName, ta.score, ta.correct_answers AS correctAnswers, ta.total_questions AS totalQuestions, ta.certificate_issued AS certificateIssued, ta.submitted_at AS submittedAt, COALESCE(m.name, m.title) AS moduleName, d.name AS domainName, c.name AS categoryName FROM test_attempts ta JOIN users u ON u.id = ta.user_id JOIN modules m ON m.id = ta.module_id JOIN domains d ON d.id = m.domain_id JOIN categories c ON c.id = d.category_id WHERE ta.id = ? AND ta.status = 'COMPLETED'",
            (rs, rowNum) -> {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("id", rs.getInt("id"));
                item.put("userId", rs.getInt("userId"));
                item.put("studentName", rs.getString("studentName"));
                item.put("score", rs.getInt("score"));
                item.put("correctAnswers", rs.getInt("correctAnswers"));
                item.put("totalQuestions", rs.getInt("totalQuestions"));
                item.put("certificateIssued", rs.getBoolean("certificateIssued"));
                item.put("submittedAt", rs.getString("submittedAt"));
                item.put("moduleName", rs.getString("moduleName"));
                item.put("domainName", rs.getString("domainName"));
                item.put("categoryName", rs.getString("categoryName"));
                item.put("resultLabel", rs.getInt("score") >= 50 ? "Passed" : "Not Passed");
                return item;
            },
            attemptId
        );
        if (((Number) actor.get("id")).intValue() != ((Number) summary.get("userId")).intValue() && !hasRole(actor, ROLE_ADMIN, ROLE_CO_ADMIN)) {
            throw new IllegalArgumentException("You are not allowed to review this test.");
        }
        List<Map<String, Object>> answers = jdbcTemplate.query(
            "SELECT t.id, t.question, t.option_a AS optionA, t.option_b AS optionB, t.option_c AS optionC, t.option_d AS optionD, t.correct_answer AS correctAnswer, taa.selected_answer AS selectedAnswer, taa.is_correct AS isCorrect FROM test_attempt_answers taa JOIN tests t ON t.id = taa.test_id WHERE taa.attempt_id = ? ORDER BY taa.id",
            (rs, rowNum) -> {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("questionId", rs.getInt("id"));
                item.put("question", rs.getString("question"));
                item.put("optionA", rs.getString("optionA"));
                item.put("optionB", rs.getString("optionB"));
                item.put("optionC", rs.getString("optionC"));
                item.put("optionD", rs.getString("optionD"));
                item.put("correctAnswer", rs.getString("correctAnswer"));
                item.put("selectedAnswer", rs.getString("selectedAnswer"));
                item.put("isCorrect", rs.getBoolean("isCorrect"));
                return item;
            },
            attemptId
        );
        summary.put("answers", answers);
        return summary;
    }

    public List<Map<String, Object>> getTestAttemptsForAdmin(String authHeader) {
        requireRole(authHeader, ROLE_ADMIN, ROLE_CO_ADMIN);
        return jdbcTemplate.query(
            "SELECT ta.id, ta.user_id AS userId, u.name AS studentName, u.email AS studentEmail, u.roll_number AS rollNumber, ta.module_id AS moduleId, ta.status, ta.total_questions AS totalQuestions, ta.correct_answers AS correctAnswers, ta.score, ta.submitted_at AS submittedAt, ta.certificate_issued AS certificateIssued, cert.id AS certificateId, cert.file_name AS certificateFileName, COALESCE(m.name, m.title) AS moduleName, d.name AS domainName, c.name AS categoryName FROM test_attempts ta JOIN users u ON u.id = ta.user_id JOIN modules m ON m.id = ta.module_id JOIN domains d ON d.id = m.domain_id JOIN categories c ON c.id = d.category_id LEFT JOIN certificates cert ON cert.attempt_id = ta.id WHERE ta.status = 'COMPLETED' ORDER BY ta.id DESC",
            (rs, rowNum) -> {
                Map<String, Object> item = mapAttempt(rs);
                item.put("userId", rs.getInt("userId"));
                item.put("studentName", rs.getString("studentName"));
                item.put("studentEmail", rs.getString("studentEmail"));
                item.put("rollNumber", rs.getString("rollNumber"));
                return item;
            }
        );
    }

    public void issueAchievementForAttempt(String authHeader, IssueAchievementRequest request) {
        requireRole(authHeader, ROLE_ADMIN, ROLE_CO_ADMIN);
        Map<String, Object> attempt = jdbcTemplate.queryForObject(
            "SELECT ta.id, ta.user_id AS userId, ta.module_id AS moduleId, ta.score, ta.certificate_issued AS certificateIssued, u.name AS studentName, u.email AS studentEmail, u.roll_number AS rollNumber, COALESCE(m.name, m.title) AS moduleName, d.name AS domainName, c.name AS categoryName FROM test_attempts ta JOIN users u ON u.id = ta.user_id JOIN modules m ON m.id = ta.module_id JOIN domains d ON d.id = m.domain_id JOIN categories c ON c.id = d.category_id WHERE ta.id = ?",
            (rs, rowNum) -> {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("attemptId", rs.getInt("id"));
                item.put("userId", rs.getInt("userId"));
                item.put("moduleId", rs.getInt("moduleId"));
                item.put("score", rs.getInt("score"));
                item.put("certificateIssued", rs.getBoolean("certificateIssued"));
                item.put("studentName", rs.getString("studentName"));
                item.put("studentEmail", rs.getString("studentEmail"));
                item.put("rollNumber", rs.getString("rollNumber"));
                item.put("moduleName", rs.getString("moduleName"));
                item.put("domainName", rs.getString("domainName"));
                item.put("categoryName", rs.getString("categoryName"));
                return item;
            },
            request.attemptId()
        );
        if ((Boolean) attempt.get("certificateIssued")) {
            throw new IllegalArgumentException("Certificate already issued for this test attempt.");
        }
        boolean passed = ((Number) attempt.get("score")).intValue() >= 50;
        Integer achievementId = null;
        if (passed) {
            Integer achievementCount = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM achievements WHERE user_id = ? AND module_id = ?", Integer.class, attempt.get("userId"), attempt.get("moduleId"));
            if (achievementCount == null || achievementCount == 0) {
                jdbcTemplate.update(
                    "INSERT INTO achievements (user_id, title, category, activity_category, description, date, module_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    attempt.get("userId"),
                    request.title(),
                    request.category(),
                    categoryToActivityType(String.valueOf(attempt.get("categoryName"))),
                    request.description(),
                    Date.valueOf(LocalDate.now()),
                    attempt.get("moduleId")
                );
            }
            achievementId = jdbcTemplate.queryForObject("SELECT id FROM achievements WHERE user_id = ? AND module_id = ? ORDER BY id DESC LIMIT 1", Integer.class, attempt.get("userId"), attempt.get("moduleId"));
        }
        byte[] pdf = generateCertificatePdf(attempt, passed);
        String suffix = passed ? "passed" : "not-passed";
        String filename = sanitizeFileName(attempt.get("studentName") + "-" + attempt.get("moduleName") + "-" + suffix + "-certificate.pdf");
        jdbcTemplate.update("INSERT INTO certificates (user_id, module_id, attempt_id, achievement_id, issued_date, score, file_name) VALUES (?, ?, ?, ?, ?, ?, ?)", attempt.get("userId"), attempt.get("moduleId"), request.attemptId(), achievementId, Date.valueOf(LocalDate.now()), attempt.get("score"), filename);
        jdbcTemplate.update("UPDATE test_attempts SET certificate_issued = TRUE WHERE id = ?", request.attemptId());
        mailService.sendMailWithAttachment(
            String.valueOf(attempt.get("studentEmail")),
            passed ? "Achievement Certificate - " + attempt.get("moduleName") : "Assessment Result Certificate - " + attempt.get("moduleName"),
            passed
                ? "Hello " + attempt.get("studentName") + ",\n\nYour result status is PASS.\nDomain: " + attempt.get("domainName") + "\nCategory: " + attempt.get("categoryName") + "\nScore: " + attempt.get("score") + "%\n\nYour certificate PDF is attached.\n\nStudent Achievement Platform"
                : "Hello " + attempt.get("studentName") + ",\n\nYour result status is NOT PASSED.\nDomain: " + attempt.get("domainName") + "\nCategory: " + attempt.get("categoryName") + "\nScore: " + attempt.get("score") + "%\n\nYour result certificate PDF is attached.\n\nStudent Achievement Platform",
            pdf,
            filename,
            "application/pdf"
        );
    }

    public void createCertificate(String authHeader, CertificateRequest request) {
        requireRole(authHeader, ROLE_ADMIN, ROLE_CO_ADMIN);
        issueAchievementForAttempt(authHeader, new IssueAchievementRequest(findLatestAttemptId(request.userId(), request.moduleId()), "Achievement in " + findModuleName(request.moduleId()), "recognition", "Certificate issued after successful completion of domain assessment."));
    }

    public List<Map<String, Object>> getMyCertificates(String authHeader) {
        Map<String, Object> actor = requireRole(authHeader, ROLE_STUDENT);
        return jdbcTemplate.query(
            "SELECT c.id, c.module_id AS moduleId, c.issued_date AS issuedDate, c.score, c.file_name AS fileName, COALESCE(m.name, m.title) AS moduleName, d.name AS domainName, cat.name AS categoryName, a.title AS achievementTitle FROM certificates c JOIN modules m ON m.id = c.module_id JOIN domains d ON d.id = m.domain_id JOIN categories cat ON cat.id = d.category_id LEFT JOIN achievements a ON a.id = c.achievement_id WHERE c.user_id = ? ORDER BY c.id DESC",
            (rs, rowNum) -> {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("id", rs.getInt("id"));
                item.put("moduleId", rs.getInt("moduleId"));
                item.put("issuedDate", rs.getString("issuedDate"));
                item.put("score", rs.getInt("score"));
                item.put("fileName", rs.getString("fileName"));
                item.put("moduleName", rs.getString("moduleName"));
                item.put("domainName", rs.getString("domainName"));
                item.put("categoryName", rs.getString("categoryName"));
                item.put("achievementTitle", rs.getString("achievementTitle"));
                item.put("resultLabel", rs.getInt("score") >= 50 ? "PASSED" : "NOT PASSED");
                return item;
            },
            actor.get("id")
        );
    }

    public Map<String, Object> resolveCertificate(String authHeader, Integer moduleId) {
        Map<String, Object> actor = requireRole(authHeader, ROLE_STUDENT);
        try {
            return jdbcTemplate.queryForObject(
                "SELECT c.id, c.module_id AS moduleId, c.issued_date AS issuedDate, c.score, c.file_name AS fileName, COALESCE(m.name, m.title) AS moduleName, d.name AS domainName, cat.name AS categoryName, a.title AS achievementTitle FROM certificates c JOIN modules m ON m.id = c.module_id JOIN domains d ON d.id = m.domain_id JOIN categories cat ON cat.id = d.category_id LEFT JOIN achievements a ON a.id = c.achievement_id WHERE c.user_id = ? AND c.module_id = ? ORDER BY c.id DESC LIMIT 1",
                (rs, rowNum) -> {
                    Map<String, Object> item = new LinkedHashMap<>();
                    int score = rs.getInt("score");
                    item.put("id", rs.getInt("id"));
                    item.put("moduleId", rs.getInt("moduleId"));
                    item.put("issuedDate", rs.getString("issuedDate"));
                    item.put("score", score);
                    item.put("fileName", rs.getString("fileName"));
                    item.put("moduleName", rs.getString("moduleName"));
                    item.put("domainName", rs.getString("domainName"));
                    item.put("categoryName", rs.getString("categoryName"));
                    item.put("achievementTitle", rs.getString("achievementTitle"));
                    item.put("resultLabel", score >= 50 ? "PASSED" : "NOT PASSED");
                    return item;
                },
                actor.get("id"),
                moduleId
            );
        } catch (EmptyResultDataAccessException exception) {
            throw new IllegalArgumentException("Certificate is not ready yet. Please refresh and try again.");
        }
    }

    public byte[] downloadCertificate(String authHeader, Integer certificateId) {
        Map<String, Object> actor = requireAuthenticated(authHeader);
        Map<String, Object> info = jdbcTemplate.queryForObject(
            "SELECT c.id, c.user_id AS userId, c.score, c.issued_date AS issuedDate, u.name AS studentName, u.roll_number AS rollNumber, COALESCE(m.name, m.title) AS moduleName, d.name AS domainName, cat.name AS categoryName FROM certificates c JOIN users u ON u.id = c.user_id JOIN modules m ON m.id = c.module_id JOIN domains d ON d.id = m.domain_id JOIN categories cat ON cat.id = d.category_id WHERE c.id = ?",
            (rs, rowNum) -> {
                Map<String, Object> item = new LinkedHashMap<>();
                int score = rs.getInt("score");
                item.put("certificateId", rs.getInt("id"));
                item.put("userId", rs.getInt("userId"));
                item.put("score", score);
                item.put("issuedDate", rs.getString("issuedDate"));
                item.put("studentName", rs.getString("studentName"));
                item.put("rollNumber", rs.getString("rollNumber"));
                item.put("moduleName", rs.getString("moduleName"));
                item.put("domainName", rs.getString("domainName"));
                item.put("categoryName", rs.getString("categoryName"));
                item.put("resultLabel", score >= 50 ? "PASSED" : "NOT PASSED");
                item.put("certificateTitle", score >= 50 ? "Certificate of Achievement" : "Assessment Completion Certificate");
                return item;
            },
            certificateId
        );
        if (((Number) actor.get("id")).intValue() != ((Number) info.get("userId")).intValue() && !hasRole(actor, ROLE_ADMIN, ROLE_CO_ADMIN)) {
            throw new IllegalArgumentException("You are not allowed to download this certificate.");
        }
        return generateCertificatePdf(info);
    }

    private Map<String, Object> findUserByEmail(String email) {
        try {
            return jdbcTemplate.queryForObject(
                "SELECT id, email, role, access_status AS accessStatus FROM users WHERE email = ?",
                (rs, rowNum) -> Map.of(
                    "id", rs.getInt("id"),
                    "email", rs.getString("email"),
                    "role", rs.getString("role"),
                    "accessStatus", rs.getString("accessStatus")
                ),
                email
            );
        } catch (EmptyResultDataAccessException exception) {
            return null;
        }
    }

    private Map<String, Object> requireAuthenticated(String authHeader) {
        String token = extractToken(authHeader);
        try {
            return jdbcTemplate.queryForObject(
                "SELECT u.id, u.role, u.access_status AS accessStatus FROM auth_sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > NOW()",
                (rs, rowNum) -> Map.of(
                    "id", rs.getInt("id"),
                    "role", rs.getString("role"),
                    "accessStatus", rs.getString("accessStatus")
                ),
                token
            );
        } catch (EmptyResultDataAccessException exception) {
            throw new IllegalArgumentException("Your session has expired. Please log in again.");
        }
    }

    private Map<String, Object> requireRole(String authHeader, String... roles) {
        Map<String, Object> actor = requireAuthenticated(authHeader);
        if (!STATUS_ACTIVE.equals(String.valueOf(actor.get("accessStatus")))) {
            throw new IllegalArgumentException("Your account is pending approval.");
        }
        if (!hasRole(actor, roles)) {
            throw new IllegalArgumentException("You are not authorized to perform this action.");
        }
        return actor;
    }

    private boolean hasRole(Map<String, Object> actor, String... roles) {
        String role = String.valueOf(actor.get("role"));
        return Arrays.stream(roles).anyMatch(allowed -> allowed.equalsIgnoreCase(role));
    }

    private String extractToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Please log in to continue.");
        }
        return authHeader.substring(7).trim();
    }

    private int getSettingInt(String key) {
        Integer value = jdbcTemplate.queryForObject("SELECT CAST(setting_value AS SIGNED) FROM platform_settings WHERE setting_key = ?", Integer.class, key);
        return value == null ? 0 : value;
    }

    private int getRoleCount(String role, String status) {
        Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM users WHERE role = ? AND access_status = ?", Integer.class, role, status);
        return count == null ? 0 : count;
    }

    private String generateOtp() {
        return String.format("%06d", random.nextInt(1_000_000));
    }

    private String generateTemporaryPassword(String role) {
        String prefix = "ADMIN".equalsIgnoreCase(role) ? "Adm" : "Stu";
        return prefix + "@" + String.format("%04d", random.nextInt(10_000));
    }

    private Map<String, Object> mapUser(int id, String name, String email, String role, String rollNumber, String department, String cohort, String phone, String accessStatus) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("id", id);
        item.put("name", name);
        item.put("email", email);
        item.put("role", normalizeRole(role));
        item.put("rollNumber", rollNumber);
        item.put("department", department);
        item.put("cohort", cohort);
        item.put("phone", phone);
        item.put("accessStatus", accessStatus == null ? "active" : accessStatus.toLowerCase());
        return item;
    }

    private Map<String, Object> mapActivity(ResultSet rs) throws java.sql.SQLException {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("activityId", rs.getInt("activityId"));
        item.put("activityName", rs.getString("activityName"));
        item.put("activityCategory", rs.getString("activityCategory"));
        item.put("domainId", rs.getObject("domainId"));
        item.put("domainName", rs.getString("domainName"));
        item.put("role", rs.getString("role"));
        item.put("duration", rs.getString("duration"));
        String skills = rs.getString("skills");
        item.put("skills", skills == null || skills.isBlank() ? List.of() : Arrays.stream(skills.split(",")).map(String::trim).toList());
        item.put("startDate", rs.getString("startDate"));
        item.put("endDate", rs.getString("endDate"));
        item.put("slots", rs.getInt("slots"));
        item.put("enrolledCount", rs.getInt("enrolledCount"));
        return item;
    }

    private Map<String, Object> mapAttempt(ResultSet rs) throws java.sql.SQLException {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("id", rs.getInt("id"));
        item.put("moduleId", rs.getInt("moduleId"));
        item.put("moduleName", rs.getString("moduleName"));
        item.put("domainName", rs.getString("domainName"));
        item.put("categoryName", rs.getString("categoryName"));
        item.put("status", rs.getString("status"));
        item.put("totalQuestions", rs.getInt("totalQuestions"));
        item.put("correctAnswers", rs.getInt("correctAnswers"));
        item.put("score", rs.getInt("score"));
        item.put("submittedAt", rs.getString("submittedAt"));
        item.put("certificateIssued", rs.getBoolean("certificateIssued"));
        Object certificateId = rs.getObject("certificateId");
        item.put("certificateId", certificateId == null ? null : ((Number) certificateId).intValue());
        item.put("certificateFileName", rs.getString("certificateFileName"));
        item.put("resultLabel", rs.getInt("score") >= 50 ? "Passed" : "Not Passed");
        return item;
    }

    private void ensureStudentEnrolledForDomain(Integer userId, Integer domainId, String domainName, String categoryName) {
        Integer directCount = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM enrollments e JOIN activities a ON a.id = e.activity_id WHERE e.user_id = ? AND a.domain_id = ?",
            Integer.class, userId, domainId
        );
        if (directCount != null && directCount > 0) {
            return;
        }
        throw new IllegalArgumentException("You must enroll in the same domain activity before taking this test.");
    }

    private void issueAutomaticCertificateForAttempt(Integer attemptId, boolean passed) {
        Map<String, Object> attempt = jdbcTemplate.queryForObject(
            "SELECT ta.id, ta.user_id AS userId, ta.module_id AS moduleId, ta.score, ta.certificate_issued AS certificateIssued, u.name AS studentName, u.email AS studentEmail, u.roll_number AS rollNumber, COALESCE(m.name, m.title) AS moduleName, d.name AS domainName, c.name AS categoryName FROM test_attempts ta JOIN users u ON u.id = ta.user_id JOIN modules m ON m.id = ta.module_id JOIN domains d ON d.id = m.domain_id JOIN categories c ON c.id = d.category_id WHERE ta.id = ?",
            (rs, rowNum) -> {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("attemptId", rs.getInt("id"));
                item.put("userId", rs.getInt("userId"));
                item.put("moduleId", rs.getInt("moduleId"));
                item.put("score", rs.getInt("score"));
                item.put("certificateIssued", rs.getBoolean("certificateIssued"));
                item.put("studentName", rs.getString("studentName"));
                item.put("studentEmail", rs.getString("studentEmail"));
                item.put("rollNumber", rs.getString("rollNumber"));
                item.put("moduleName", rs.getString("moduleName"));
                item.put("domainName", rs.getString("domainName"));
                item.put("categoryName", rs.getString("categoryName"));
                return item;
            },
            attemptId
        );
        if ((Boolean) attempt.get("certificateIssued")) {
            return;
        }
        Integer achievementId = null;
        if (passed) {
            Integer achievementCount = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM achievements WHERE user_id = ? AND module_id = ?", Integer.class, attempt.get("userId"), attempt.get("moduleId"));
            if (achievementCount == null || achievementCount == 0) {
                jdbcTemplate.update(
                    "INSERT INTO achievements (user_id, title, category, activity_category, description, date, module_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    attempt.get("userId"),
                    attempt.get("domainName") + " Excellence",
                    "recognition",
                    categoryToActivityType(String.valueOf(attempt.get("categoryName"))),
                    "Completed " + attempt.get("domainName") + " assessment with " + attempt.get("score") + "% score.",
                    Date.valueOf(LocalDate.now()),
                    attempt.get("moduleId")
                );
            }
            achievementId = jdbcTemplate.queryForObject("SELECT id FROM achievements WHERE user_id = ? AND module_id = ? ORDER BY id DESC LIMIT 1", Integer.class, attempt.get("userId"), attempt.get("moduleId"));
        }
        byte[] pdf = generateCertificatePdf(attempt, passed);
        String resultText = passed ? "passed" : "not-passed";
        String filename = sanitizeFileName(attempt.get("studentName") + "-" + attempt.get("moduleName") + "-" + resultText + "-certificate.pdf");
        jdbcTemplate.update(
            "INSERT INTO certificates (user_id, module_id, attempt_id, achievement_id, issued_date, score, file_name) VALUES (?, ?, ?, ?, ?, ?, ?)",
            attempt.get("userId"),
            attempt.get("moduleId"),
            attemptId,
            achievementId,
            Date.valueOf(LocalDate.now()),
            attempt.get("score"),
            filename
        );
        jdbcTemplate.update("UPDATE test_attempts SET certificate_issued = TRUE WHERE id = ?", attemptId);
        try {
            mailService.sendMailWithAttachment(
                String.valueOf(attempt.get("studentEmail")),
                passed ? "Achievement Certificate - " + attempt.get("moduleName") : "Assessment Result Certificate - " + attempt.get("moduleName"),
                passed
                    ? "Hello " + attempt.get("studentName") + ",\n\nCongratulations. You passed the " + attempt.get("domainName") + " test with " + attempt.get("score") + "%.\nYour certificate PDF is attached.\n\nStudent Achievement Platform"
                    : "Hello " + attempt.get("studentName") + ",\n\nYou completed the " + attempt.get("domainName") + " test with " + attempt.get("score") + "%.\nYour result certificate PDF is attached.\n\nStudent Achievement Platform",
                pdf,
                filename,
                "application/pdf"
            );
        } catch (Exception e) {
            System.err.println("Failed to send certificate email: " + e.getMessage());
        }
    }

    private byte[] generateCertificatePdf(Map<String, Object> info, boolean passed) {
        Map<String, Object> enhancedInfo = new LinkedHashMap<>(info);
        enhancedInfo.put("resultLabel", passed ? "PASSED" : "NOT PASSED");
        enhancedInfo.put("certificateTitle", passed ? "Certificate of Achievement" : "Assessment Completion Certificate");
        return generateCertificatePdf(enhancedInfo);
    }

    private byte[] generateCertificatePdf(Map<String, Object> info) {
        try (PDDocument document = new PDDocument(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            PDPage page = new PDPage(new PDRectangle(PDRectangle.A4.getHeight(), PDRectangle.A4.getWidth()));
            document.addPage(page);
            try (PDPageContentStream contentStream = new PDPageContentStream(document, page)) {
                float pageWidth = page.getMediaBox().getWidth();
                float pageHeight = page.getMediaBox().getHeight();
                float margin = 24f;
                String resultLabel = String.valueOf(info.getOrDefault("resultLabel", "PASSED"));
                String certificateTitle = String.valueOf(info.getOrDefault("certificateTitle", "Certificate of Achievement"));

                contentStream.setNonStrokingColor(249, 250, 251);
                contentStream.addRect(0, 0, pageWidth, pageHeight);
                contentStream.fill();

                contentStream.setNonStrokingColor(30, 64, 175);
                contentStream.addRect(margin, pageHeight - 96, pageWidth - (margin * 2), 54);
                contentStream.fill();

                contentStream.setStrokingColor(212, 175, 55);
                contentStream.setLineWidth(4f);
                contentStream.addRect(margin, margin, pageWidth - (margin * 2), pageHeight - (margin * 2));
                contentStream.stroke();

                contentStream.setLineWidth(1.6f);
                contentStream.addRect(margin + 12, margin + 12, pageWidth - ((margin + 12) * 2), pageHeight - ((margin + 12) * 2));
                contentStream.stroke();

                drawCenteredText(contentStream, PDType1Font.HELVETICA_BOLD, 22, pageWidth / 2, pageHeight - 74, "Student Achievement Platform", 255, 255, 255);
                drawCenteredText(contentStream, PDType1Font.HELVETICA_BOLD, 13, pageWidth / 2, pageHeight - 126, "Certificate of Completion and Performance", 212, 175, 55);
                drawCenteredText(contentStream, PDType1Font.HELVETICA_BOLD, 26, pageWidth / 2, pageHeight - 170, certificateTitle, 15, 23, 42);
                drawCenteredText(contentStream, PDType1Font.HELVETICA_OBLIQUE, 13, pageWidth / 2, pageHeight - 205, "This certificate is proudly presented to", 71, 85, 105);
                drawCenteredText(contentStream, PDType1Font.HELVETICA_BOLD, 24, pageWidth / 2, pageHeight - 245, String.valueOf(info.get("studentName")), 30, 64, 175);

                contentStream.setStrokingColor(212, 175, 55);
                contentStream.setLineWidth(2f);
                contentStream.moveTo(210, pageHeight - 265);
                contentStream.lineTo(pageWidth - 210, pageHeight - 265);
                contentStream.stroke();

                drawCenteredText(
                    contentStream,
                    PDType1Font.HELVETICA,
                    13,
                    pageWidth / 2,
                    pageHeight - 298,
                    "For completing the " + info.get("domainName") + " assessment in " + info.get("categoryName"),
                    51,
                    65,
                    85
                );
                drawCenteredText(
                    contentStream,
                    PDType1Font.HELVETICA,
                    12,
                    pageWidth / 2,
                    pageHeight - 320,
                    "Module: " + info.get("moduleName"),
                    71,
                    85,
                    105
                );

                contentStream.setNonStrokingColor(241, 245, 249);
                contentStream.addRect(120, pageHeight - 400, pageWidth - 240, 76);
                contentStream.fill();
                contentStream.setStrokingColor(191, 219, 254);
                contentStream.setLineWidth(1.4f);
                contentStream.addRect(120, pageHeight - 400, pageWidth - 240, 76);
                contentStream.stroke();

                float leftCol = 230f;
                float centerCol = pageWidth / 2;
                float rightCol = pageWidth - 230f;
                drawCenteredText(contentStream, PDType1Font.HELVETICA_BOLD, 14, leftCol, pageHeight - 362, "Roll Number", 100, 116, 139);
                drawCenteredText(contentStream, PDType1Font.HELVETICA_BOLD, 14, centerCol, pageHeight - 362, "Score", 100, 116, 139);
                drawCenteredText(contentStream, PDType1Font.HELVETICA_BOLD, 14, rightCol, pageHeight - 362, "Issued Date", 100, 116, 139);

                drawCenteredText(contentStream, PDType1Font.HELVETICA_BOLD, 16, leftCol, pageHeight - 386, String.valueOf(info.get("rollNumber")), 15, 23, 42);
                drawCenteredText(contentStream, PDType1Font.HELVETICA_BOLD, 16, centerCol, pageHeight - 386, info.get("score") + "%", 15, 23, 42);
                drawCenteredText(contentStream, PDType1Font.HELVETICA_BOLD, 16, rightCol, pageHeight - 386, String.valueOf(info.getOrDefault("issuedDate", LocalDate.now().toString())), 15, 23, 42);

                int[] badgeColor = "PASSED".equals(resultLabel) ? new int[] { 5, 150, 105 } : new int[] { 185, 28, 28 };
                contentStream.setNonStrokingColor(badgeColor[0], badgeColor[1], badgeColor[2]);
                contentStream.addRect((pageWidth / 2) - 88, 102, 176, 38);
                contentStream.fill();
                drawCenteredText(contentStream, PDType1Font.HELVETICA_BOLD, 16, pageWidth / 2, 116, resultLabel, 255, 255, 255);

                drawCenteredText(contentStream, PDType1Font.HELVETICA_OBLIQUE, 12, pageWidth / 2, 70, "Generated digitally by Student Achievement Platform", 100, 116, 139);
            }
            document.save(output);
            return output.toByteArray();
        } catch (Exception exception) {
            throw new IllegalArgumentException("Unable to generate certificate PDF.");
        }
    }

    private void drawCenteredText(
        PDPageContentStream contentStream,
        PDType1Font font,
        int fontSize,
        float centerX,
        float y,
        String text,
        int red,
        int green,
        int blue
    ) throws Exception {
        float textWidth = font.getStringWidth(text) / 1000 * fontSize;
        contentStream.beginText();
        contentStream.setNonStrokingColor(red, green, blue);
        contentStream.setFont(font, fontSize);
        contentStream.newLineAtOffset(centerX - (textWidth / 2), y);
        contentStream.showText(text);
        contentStream.endText();
    }

    private Integer findLatestAttemptId(Integer userId, Integer moduleId) {
        Integer attemptId = jdbcTemplate.query("SELECT id FROM test_attempts WHERE user_id = ? AND module_id = ? AND status = 'COMPLETED' ORDER BY id DESC LIMIT 1", rs -> rs.next() ? rs.getInt("id") : null, userId, moduleId);
        if (attemptId == null) {
            throw new IllegalArgumentException("No completed test found for this module.");
        }
        return attemptId;
    }

    private String findModuleName(Integer moduleId) {
        String name = jdbcTemplate.queryForObject("SELECT COALESCE(name, title) FROM modules WHERE id = ?", String.class, moduleId);
        return name == null ? "Domain Assessment" : name;
    }

    private String categoryToActivityType(String categoryName) {
        return switch (categoryName) {
            case "Sports Competitions" -> "sports";
            case "Cultural Events" -> "cultural";
            case "NCC / NSS Participation", "NCC/NSS Participation" -> "ncc";
            case "Club Activities" -> "club";
            case "Entrepreneurship" -> "entrepreneurship";
            default -> "others";
        };
    }

    private String buildStudyContent(String categoryName, String domainName, String moduleName) {
        String context = switch (categoryName) {
            case "Sports Competitions" -> "fitness routines, pressure situations, team drills, and disciplined match preparation";
            case "Cultural Events" -> "creative preparation, performance confidence, stage communication, and event coordination";
            case "NCC / NSS Participation", "NCC/NSS Participation" -> "community responsibility, leadership in service, and structured social impact work";
            case "Club Activities" -> "project collaboration, technical execution, club operations, and peer coordination";
            case "Entrepreneurship" -> "idea validation, business planning, communication, and market-oriented decision making";
            default -> "self-development, practical discipline, and continuous improvement across activities";
        };
        String examHint = switch (categoryName) {
            case "Sports Competitions" -> "In tests, prefer options that show disciplined preparation, teamwork, and ethical participation over impulsive or shortcut behavior.";
            case "Cultural Events" -> "In tests, prefer options that reflect communication clarity, creativity with structure, and collaborative rehearsal habits.";
            case "NCC / NSS Participation", "NCC/NSS Participation" -> "In tests, prefer options that show service mindset, coordinated action, responsibility, and leadership through discipline.";
            case "Club Activities" -> "In tests, prefer options that show planning, problem solving, collaboration, and steady execution with review.";
            case "Entrepreneurship" -> "In tests, prefer options that balance innovation with validation, risk awareness, market understanding, and decision discipline.";
            default -> "In tests, prefer options that show structured practice, responsible participation, reflection, and long-term growth.";
        };
        return """
            Page 1: Understanding {domain} in {category}
            {module} is not only an assessment module; it is a guided preparation journey for students who want real capability in {context}. In this domain, the focus is on how you think, how you prepare, how you respond under challenge, and how you convert learning into repeatable performance. The test is only a final checkpoint. The deeper objective is that every student should leave this module with a method they can use in real activity contexts without dependency on guesswork.
            
            Students usually struggle when they treat domain preparation as memorization. In this module, the expected approach is different. You should read each topic as a practical instruction for action. Whenever you learn a concept, link it with one real example from your participation history. This habit creates stronger retention and better test performance because your answers come from understanding, not from temporary memory.
            
            Page 2: Core Concepts and Mental Model
            The mental model for this domain is built on clarity, consistency, and reflection. Clarity means you understand what success looks like before starting work. Consistency means you repeat the right actions even when motivation changes. Reflection means you examine outcomes honestly and improve specific weak areas instead of repeating the same pattern. This three-part model supports both high scoring and long-term growth.
            
            In {domain}, students are expected to identify context before action. That includes understanding constraints, timeline, team role, quality expectations, and impact of mistakes. If context is ignored, execution quality drops quickly. If context is understood well, even a simple plan produces strong outcomes. During test preparation, use this same model by reading questions slowly, identifying what the question is really asking, and then selecting the most contextually correct answer.
            
            Page 3: Application in Real Student Scenarios
            A common scenario in {domain} is that a student must perform under limited time with shared responsibility. In such conditions, students who rely on impulse often make avoidable errors. Students who use structured thinking first usually perform better. Before action, define objective. During action, monitor progress. After action, review decisions. This cycle creates stable improvement regardless of category.
            
            Another scenario appears when students face peer comparison and pressure. The right response is not speed alone; the right response is controlled execution. In this domain, controlled execution includes preparing essentials in advance, avoiding distractions during activity, and documenting learnings immediately after completion. If you adopt this process in your activity life, your domain answers become naturally stronger because they reflect practiced behavior.
            
            {examHint}
            
            Page 4: Frequent Errors and Strong Corrections
            The biggest error pattern is superficial preparation. Students read topics once and assume readiness, then lose marks on applied questions. Correct preparation demands revisiting content with deeper intention: explain each concept in your own words, map it to one practical case, and identify one mistake you previously made in similar contexts. This converts passive reading into active understanding.
            
            Another major error is emotional decision making under pressure. In {domain}, stress may push students toward rushed judgments. To correct this, train with deliberate pacing. Read question, identify key phrase, reject weak options, then choose the most principled answer. This method improves accuracy and reduces panic. Consistent use of this method in mock review sessions is usually enough to improve outcome quality significantly.
            
            Page 5: Advanced Preparation Strategy
            At this stage of preparation, your focus should shift from finishing syllabus to demonstrating mastery. Mastery in {domain} means you can explain why one approach is stronger than another, not just identify definitions. Build this by comparing scenarios, discussing choices with peers, and revising mistakes from previous attempts. If a concept feels unclear, return to fundamentals instead of moving ahead with confusion.
            
            Use short daily study cycles with clear targets. A practical structure is concept review, scenario analysis, and self-test reflection. Repeat this cycle until your reasoning becomes stable. By the time you attempt the test, you should feel that questions are familiar decision patterns, not surprises. When this readiness level is achieved, performance becomes predictable and confidence becomes natural.
            
            A reliable approach for this module is to build one-page daily revision notes. Every note should include concept meaning, one practical campus scenario, one common mistake, and one corrected action. This note-based cycle helps you remember test-relevant logic and improves decision quality while answering MCQs.
            
            Page 6: Test Attempt Method and Post-Test Learning
            During the test, keep decision quality higher than speed. Read each question fully, detect the central idea, and compare options against domain principles from this module. Avoid option selection based on keywords alone. Choose the answer that best aligns with practical correctness. After submission, use the review section to analyze wrong answers carefully. Each wrong answer is feedback for improvement, not failure.
            
            This module is complete only when learning continues after the attempt. Whether the result is pass or not passed, the student should carry forward the method learned here into future categories and domains. That continuity is the real value of {module} under {category}.

            Page 7: Deepening Mastery Through Reflection
            Students who improve quickly in {domain} usually follow a reflective cycle after every learning session. They record what they understood, what remained unclear, and where they made weak decisions. This self-observation improves attention in future study rounds. Reflection should be practical and specific, not generic. Instead of writing I need to improve, identify exactly which concept or situation needs rework and why.
            
            In {domain}, reflection becomes powerful when paired with action. If you identify one weakness, immediately connect it with one corrective behavior for the next practice session. Over time, this produces visible improvement in confidence, judgment, and answer quality. The test then becomes an outcome of preparation discipline rather than luck.

            Page 8: Long-Term Domain Readiness
            Long-term readiness in {domain} is built when students repeatedly apply this module's ideas in their real activities. Concept understanding must move into behavior: how you plan, how you communicate, how you respond under uncertainty, and how you recover from mistakes. These habits are useful beyond this test and create stronger outcomes in future domains as well.
            
            Treat this material as a reusable handbook. Revisit it whenever you prepare for a new attempt or when performance drops. Consistent return to fundamentals, followed by guided practice, keeps your growth stable. With this method, every attempt becomes meaningful, and every result contributes to your next improvement cycle.
            
            Final readiness checkpoint for {module}: if you can explain the domain process in your own words, apply it in one realistic scenario, and justify why one option is stronger than three alternatives, you are prepared for test-level questions in this domain.
            """
            .replace("{domain}", domainName)
            .replace("{category}", categoryName)
            .replace("{module}", moduleName)
            .replace("{context}", context)
            .replace("{examHint}", examHint);
    }

    private boolean shouldRegenerateStudyContent(String content) {
        if (content == null || content.isBlank()) {
            return true;
        }
        String normalized = content.toLowerCase();
        if (normalized.startsWith("assessment module for ")) {
            return true;
        }
        if (normalized.contains("http://") || normalized.contains("https://") || normalized.contains("source.unsplash.com")) {
            return true;
        }
        return content.length() < 4500;
    }

    private String sanitizeFileName(Object raw) {
        return String.valueOf(raw).replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    private String normalizeRole(String role) {
        return role == null ? "" : role.toLowerCase().replace('_', '-');
    }
}
