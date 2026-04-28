package com.fsad.studentachievement.config;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class PlatformBootstrap implements CommandLineRunner {

    public static final String MAIN_ADMIN_EMAIL = "2400030764@kluniversity.in";
    public static final String MAIN_ADMIN_PHONE = "7207106954";
    public static final String PRIMARY_STUDENT_EMAIL = "ghost586365@gmail.com";

    private final JdbcTemplate jdbcTemplate;
    private final PasswordEncoder passwordEncoder;

    @Value("${default.admin.password:}")
    private String defaultAdminPassword;

    @Value("${default.student.password:}")
    private String defaultStudentPassword;

    @Override
    public void run(String... args) {
        createTables();
        addColumnIfMissing("users", "roll_number", "ALTER TABLE users ADD COLUMN roll_number VARCHAR(50) UNIQUE");
        addColumnIfMissing("users", "department", "ALTER TABLE users ADD COLUMN department VARCHAR(100)");
        addColumnIfMissing("users", "cohort", "ALTER TABLE users ADD COLUMN cohort VARCHAR(50)");
        addColumnIfMissing("users", "phone", "ALTER TABLE users ADD COLUMN phone VARCHAR(20)");
        addColumnIfMissing("users", "password_changed", "ALTER TABLE users ADD COLUMN password_changed BOOLEAN DEFAULT FALSE");
        addColumnIfMissing("users", "access_status", "ALTER TABLE users ADD COLUMN access_status VARCHAR(20) DEFAULT 'ACTIVE'");
        addColumnIfMissing("achievements", "activity_category", "ALTER TABLE achievements ADD COLUMN activity_category VARCHAR(50)");
        addColumnIfMissing("achievements", "description", "ALTER TABLE achievements ADD COLUMN description TEXT");
        addColumnIfMissing("achievements", "module_id", "ALTER TABLE achievements ADD COLUMN module_id INT");
        addColumnIfMissing("activities", "slots", "ALTER TABLE activities ADD COLUMN slots INT DEFAULT 0");
        addColumnIfMissing("activities", "domain_id", "ALTER TABLE activities ADD COLUMN domain_id INT NULL");
        addColumnIfMissing("enrollments", "test_access", "ALTER TABLE enrollments ADD COLUMN test_access BOOLEAN DEFAULT FALSE");
        addColumnIfMissing("modules", "title", "ALTER TABLE modules ADD COLUMN title VARCHAR(200)");
        addColumnIfMissing("modules", "name", "ALTER TABLE modules ADD COLUMN name VARCHAR(200)");
        addColumnIfMissing("modules", "question_count", "ALTER TABLE modules ADD COLUMN question_count INT DEFAULT 20");
        addColumnIfMissing("tests", "option_a", "ALTER TABLE tests ADD COLUMN option_a VARCHAR(255)");
        addColumnIfMissing("tests", "option_b", "ALTER TABLE tests ADD COLUMN option_b VARCHAR(255)");
        addColumnIfMissing("tests", "option_c", "ALTER TABLE tests ADD COLUMN option_c VARCHAR(255)");
        addColumnIfMissing("tests", "option_d", "ALTER TABLE tests ADD COLUMN option_d VARCHAR(255)");
        addColumnIfMissing("tests", "correct_answer", "ALTER TABLE tests ADD COLUMN correct_answer VARCHAR(20) DEFAULT 'optionA'");
        addColumnIfMissing("certificates", "module_id", "ALTER TABLE certificates ADD COLUMN module_id INT");
        addColumnIfMissing("certificates", "attempt_id", "ALTER TABLE certificates ADD COLUMN attempt_id INT");
        addColumnIfMissing("certificates", "achievement_id", "ALTER TABLE certificates ADD COLUMN achievement_id INT");
        addColumnIfMissing("certificates", "score", "ALTER TABLE certificates ADD COLUMN score INT DEFAULT 0");
        addColumnIfMissing("certificates", "file_name", "ALTER TABLE certificates ADD COLUMN file_name VARCHAR(255)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS auth_sessions (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, token VARCHAR(200) NOT NULL UNIQUE, expires_at TIMESTAMP NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS platform_settings (setting_key VARCHAR(100) PRIMARY KEY, setting_value VARCHAR(100) NOT NULL)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS test_attempts (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, module_id INT NOT NULL, status VARCHAR(20) DEFAULT 'IN_PROGRESS', total_questions INT DEFAULT 20, correct_answers INT DEFAULT 0, score INT DEFAULT 0, submitted_at TIMESTAMP NULL, certificate_issued BOOLEAN DEFAULT FALSE, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS test_attempt_answers (id INT AUTO_INCREMENT PRIMARY KEY, attempt_id INT NOT NULL, test_id INT NOT NULL, selected_answer VARCHAR(20) NULL, is_correct BOOLEAN NULL, UNIQUE KEY uk_attempt_question (attempt_id, test_id), FOREIGN KEY (attempt_id) REFERENCES test_attempts(id) ON DELETE CASCADE, FOREIGN KEY (test_id) REFERENCES tests(id) ON DELETE CASCADE)");
        addActivityDomainForeignKeyIfMissing();
        seedSettings();

        if (columnExists("modules", "title")) {
            jdbcTemplate.update("UPDATE modules SET name = title WHERE (name IS NULL OR name = '') AND title IS NOT NULL");
        }
        migratePlainTextPasswords();
        seedUsers();
        seedActivitiesAndLearning();
        mapExistingDomainActivities();
    }

    private void createTables() {
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(100) NOT NULL UNIQUE, password VARCHAR(255) NOT NULL, role ENUM('ADMIN','CO_ADMIN','STUDENT') DEFAULT 'STUDENT', roll_number VARCHAR(50) UNIQUE, department VARCHAR(100), cohort VARCHAR(50), phone VARCHAR(20), password_changed BOOLEAN DEFAULT FALSE, access_status VARCHAR(20) DEFAULT 'ACTIVE')");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS activities (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, type VARCHAR(50) NOT NULL, domain_id INT NULL, role VARCHAR(50) NOT NULL, duration VARCHAR(50), skills TEXT, start_date DATE, end_date DATE, slots INT DEFAULT 0)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS achievements (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, title VARCHAR(100) NOT NULL, category VARCHAR(50) NOT NULL, activity_category VARCHAR(50), description TEXT, date DATE, certificate VARCHAR(255), module_id INT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS enrollments (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, activity_id INT NOT NULL, status VARCHAR(20) DEFAULT 'ENROLLED', enrolled_date DATE DEFAULT (CURRENT_DATE()), test_access BOOLEAN DEFAULT FALSE, UNIQUE KEY uk_enrollment (user_id, activity_id), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (activity_id) REFERENCES activities(id) ON DELETE CASCADE)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS categories (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS domains (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, category_id INT NOT NULL, FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS modules (id INT AUTO_INCREMENT PRIMARY KEY, title VARCHAR(200), name VARCHAR(200), domain_id INT NOT NULL, content TEXT, question_count INT DEFAULT 20, FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS tests (id INT AUTO_INCREMENT PRIMARY KEY, module_id INT NOT NULL, question TEXT NOT NULL, option_a VARCHAR(255), option_b VARCHAR(255), option_c VARCHAR(255), option_d VARCHAR(255), correct_answer VARCHAR(20) DEFAULT 'optionA', FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS student_progress (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, module_id INT NOT NULL, completed BOOLEAN DEFAULT FALSE, score INT DEFAULT 0, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS certificates (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, domain_id INT NULL, module_id INT NULL, attempt_id INT NULL, achievement_id INT NULL, issued_date DATE, score INT DEFAULT 0, file_name VARCHAR(255), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS registration_otps (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(100) NOT NULL, phone VARCHAR(20) NOT NULL, role VARCHAR(20) NOT NULL, roll_number VARCHAR(50) NOT NULL, department VARCHAR(100) NOT NULL, cohort VARCHAR(50) NOT NULL, otp VARCHAR(6) NOT NULL, expires_at TIMESTAMP NOT NULL)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS password_reset_otps (id INT AUTO_INCREMENT PRIMARY KEY, email VARCHAR(100) NOT NULL, role VARCHAR(20) NOT NULL, otp VARCHAR(6) NOT NULL, expires_at TIMESTAMP NOT NULL)");
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS removed_users (id INT AUTO_INCREMENT PRIMARY KEY, original_user_id INT NOT NULL, name VARCHAR(100), email VARCHAR(100), role VARCHAR(20), roll_number VARCHAR(50), department VARCHAR(100), cohort VARCHAR(50), phone VARCHAR(20), access_status VARCHAR(20), removed_by INT NOT NULL, removed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, reason VARCHAR(255))");
    }

    private void addActivityDomainForeignKeyIfMissing() {
        Integer count = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'activities' AND COLUMN_NAME = 'domain_id' AND REFERENCED_TABLE_NAME = 'domains'",
            Integer.class
        );
        if (count == null || count == 0) {
            try {
                jdbcTemplate.execute("ALTER TABLE activities ADD CONSTRAINT fk_activities_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE SET NULL");
            } catch (Exception ignored) {
            }
        }
    }

    private void seedUsers() {
        Integer adminId = jdbcTemplate.query(
            "SELECT id FROM users WHERE email = ? OR roll_number = ? ORDER BY id LIMIT 1",
            rs -> rs.next() ? rs.getInt("id") : null,
            MAIN_ADMIN_EMAIL,
            "ADMIN001"
        );
        if (adminId == null) {
            if (defaultAdminPassword == null || defaultAdminPassword.isBlank()) {
                throw new IllegalStateException("Set DEFAULT_ADMIN_PASSWORD before first startup to create the admin account safely.");
            }
            jdbcTemplate.update("INSERT INTO users (name, email, password, role, roll_number, department, cohort, phone, password_changed, access_status) VALUES (?, ?, ?, 'ADMIN', ?, ?, ?, ?, TRUE, 'ACTIVE')",
                "Main Admin", MAIN_ADMIN_EMAIL, passwordEncoder.encode(defaultAdminPassword), "ADMIN001", "Administration", "2020-2030", MAIN_ADMIN_PHONE);
        } else {
            jdbcTemplate.update("UPDATE users SET name=?, email=?, role='ADMIN', roll_number=?, department=?, cohort=?, phone=?, access_status='ACTIVE' WHERE id=?",
                "Main Admin", MAIN_ADMIN_EMAIL, "ADMIN001", "Administration", "2020-2030", MAIN_ADMIN_PHONE, adminId);
        }

        seedUserIfMissing("manu", PRIMARY_STUDENT_EMAIL, defaultStudentPassword, "STUDENT", "2400037764", "CSE", "2024-2028", "9876543210", true);
    }

    private void seedActivitiesAndLearning() {
        // Remove hardcoded activities and achievements
        jdbcTemplate.update("DELETE FROM achievements WHERE title IN ('Cricket Tournament Winner', 'Ui/Ux Workshop Recognition')");
        jdbcTemplate.update("DELETE FROM activities WHERE name IN ('Cricket Tournament', 'Coding Club', 'Cultural Fest', 'NSS Community Drive', 'Startup Bootcamp')");

        Map<String, List<String>> categoryDomains = new LinkedHashMap<>();
        categoryDomains.put("Sports Competitions", List.of("Physical Fitness", "Team Collaboration", "Leadership", "Strategy & Decision Making", "Discipline & Time Management", "Sportsmanship"));
        categoryDomains.put("Cultural Events", List.of("Creativity & Expression", "Performing Arts (Dance, Music, Drama)", "Communication Skills", "Cultural Awareness", "Confidence Building", "Event Coordination"));
        categoryDomains.put("NCC / NSS Participation", List.of("Social Responsibility", "Leadership & Discipline", "Community Service", "Disaster Management", "National Awareness", "Teamwork & Coordination"));
        categoryDomains.put("Club Activities", List.of("Technical Skills (for tech clubs)", "Management & Organization", "Collaboration", "Problem Solving", "Networking", "Innovation"));
        categoryDomains.put("Entrepreneurship", List.of("Business Strategy", "Innovation & Ideation", "Financial Literacy", "Marketing & Branding", "Risk Management", "Leadership & Initiative"));
        categoryDomains.put("Others", List.of("Personal Development", "Volunteering", "Research & Projects", "Certifications & Workshops", "Soft Skills (Communication, Adaptability)", "Miscellaneous Achievements"));

        for (Map.Entry<String, List<String>> entry : categoryDomains.entrySet()) {
            insertIfMissing("INSERT INTO categories (name) VALUES ('" + escapeSql(entry.getKey()) + "')", "SELECT COUNT(*) FROM categories WHERE name='" + escapeSql(entry.getKey()) + "'");
            Integer categoryId = jdbcTemplate.queryForObject("SELECT id FROM categories WHERE name = ?", Integer.class, entry.getKey());
            if (categoryId == null) {
                continue;
            }
            for (String domainName : entry.getValue()) {
                insertIfMissing(
                    "INSERT INTO domains (name, category_id) VALUES ('" + escapeSql(domainName) + "', " + categoryId + ")",
                    "SELECT COUNT(*) FROM domains WHERE name='" + escapeSql(domainName) + "' AND category_id=" + categoryId
                );
                Integer domainId = jdbcTemplate.queryForObject("SELECT id FROM domains WHERE name = ? AND category_id = ?", Integer.class, domainName, categoryId);
                if (domainId == null) {
                    continue;
                }
                String moduleName = domainName + " Assessment";
                insertIfMissing(
                    "INSERT INTO modules (name, domain_id, content, question_count) VALUES ('" + escapeSql(moduleName) + "', " + domainId + ", '" + escapeSql("Assessment module for " + domainName + " under " + entry.getKey()) + "', 20)",
                    "SELECT COUNT(*) FROM modules WHERE name='" + escapeSql(moduleName) + "' AND domain_id=" + domainId
                );
                Integer moduleId = jdbcTemplate.queryForObject("SELECT id FROM modules WHERE name = ? AND domain_id = ?", Integer.class, moduleName, domainId);
                if (moduleId != null) {
                    seedQuestionBank(moduleId, entry.getKey(), domainName);
                }
            }
        }
    }

    private void mapExistingDomainActivities() {
        // Map sports activities to Physical Fitness domain
        jdbcTemplate.update(
            "UPDATE activities SET domain_id = (SELECT d.id FROM domains d JOIN categories c ON c.id = d.category_id WHERE c.name = 'Sports Competitions' AND d.name = 'Physical Fitness' LIMIT 1) WHERE LOWER(type) = 'sports' AND domain_id IS NULL"
        );
        // Map club activities to Technical Skills domain
        jdbcTemplate.update(
            "UPDATE activities SET domain_id = (SELECT d.id FROM domains d JOIN categories c ON c.id = d.category_id WHERE c.name = 'Club Activities' AND d.name = 'Technical Skills (for tech clubs)' LIMIT 1) WHERE LOWER(type) = 'club' AND domain_id IS NULL"
        );
        // Map cultural activities
        jdbcTemplate.update(
            "UPDATE activities SET domain_id = (SELECT d.id FROM domains d JOIN categories c ON c.id = d.category_id WHERE c.name = 'Cultural Events' LIMIT 1) WHERE LOWER(type) = 'cultural' AND domain_id IS NULL"
        );
        // Map ncc/nss activities
        jdbcTemplate.update(
            "UPDATE activities SET domain_id = (SELECT d.id FROM domains d JOIN categories c ON c.id = d.category_id WHERE c.name = 'NCC / NSS Participation' LIMIT 1) WHERE LOWER(type) = 'ncc' AND domain_id IS NULL"
        );
        // Map entrepreneurship activities
        jdbcTemplate.update(
            "UPDATE activities SET domain_id = (SELECT d.id FROM domains d JOIN categories c ON c.id = d.category_id WHERE c.name = 'Entrepreneurship' LIMIT 1) WHERE LOWER(type) = 'entrepreneurship' AND domain_id IS NULL"
        );
    }

    private void seedQuestionBank(Integer moduleId, String categoryName, String domainName) {
        Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM tests WHERE module_id = ?", Integer.class, moduleId);
        if (count != null && count >= 24) {
            return;
        }
        for (QuestionSeed question : buildQuestions(categoryName, domainName)) {
            Integer exists = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM tests WHERE module_id = ? AND question = ?", Integer.class, moduleId, question.question());
            if (exists == null || exists == 0) {
                jdbcTemplate.update(
                    "INSERT INTO tests (module_id, question, option_a, option_b, option_c, option_d, correct_answer) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    moduleId,
                    question.question(),
                    question.optionA(),
                    question.optionB(),
                    question.optionC(),
                    question.optionD(),
                    question.correctAnswer()
                );
            }
        }
    }

    private List<QuestionSeed> buildQuestions(String categoryName, String domainName) {
        List<String> prompts = List.of(
            "Which action best strengthens %s in %s?",
            "What is the most effective way to demonstrate %s during %s activities?",
            "Which habit supports long-term growth in %s?",
            "What should a student focus on first to improve %s?",
            "Which choice reflects strong %s in a practical setting?",
            "What is the safest strategy to build %s steadily?",
            "Which response shows maturity in %s?",
            "What is a key indicator that %s is improving?",
            "Which approach helps a team apply %s successfully?",
            "How can a student prepare for assessment in %s?",
            "Which decision most directly supports %s?",
            "What role does reflection play in %s?",
            "Which action weakens %s the most?",
            "Which behavior aligns with high standards in %s?",
            "What is the best way to sustain %s under pressure?",
            "Which planning step improves %s outcomes?",
            "What should students avoid while developing %s?",
            "Which example best represents %s in action?",
            "How does feedback contribute to %s?",
            "Which result shows successful learning in %s?",
            "What is the best checkpoint for measuring %s?",
            "Which practice helps convert theory into %s performance?",
            "How should a student respond after a setback in %s?",
            "Which statement correctly describes %s?"
        );

        List<QuestionSeed> seeds = new ArrayList<>();
        for (int index = 0; index < prompts.size(); index++) {
            String question = String.format(prompts.get(index), domainName, categoryName);
            String correct = domainName + " through structured practice and responsible participation";
            List<String> options = new ArrayList<>();
            options.add(correct);
            options.add("Ignoring preparation and depending on luck alone");
            options.add("Avoiding teamwork, feedback, and reflection");
            options.add("Rushing decisions without goals or discipline");
            int correctIndex = index % 4;
            if (correctIndex != 0) {
                String option = options.remove(0);
                options.add(correctIndex, option);
            }
            seeds.add(new QuestionSeed(question, options.get(0), options.get(1), options.get(2), options.get(3), "option" + "ABCD".charAt(correctIndex)));
        }
        return seeds;
    }

    private void seedUserIfMissing(String name, String email, String rawPassword, String role, String rollNumber, String department, String cohort, String phone, boolean changed) {
        Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM users WHERE email = ?", Integer.class, email);
        if (count == null || count == 0) {
            if (rawPassword == null || rawPassword.isBlank()) {
                throw new IllegalStateException("Set DEFAULT_STUDENT_PASSWORD before first startup to create the seeded student account safely.");
            }
            jdbcTemplate.update("INSERT INTO users (name, email, password, role, roll_number, department, cohort, phone, password_changed, access_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')",
                name, email, passwordEncoder.encode(rawPassword), role, rollNumber, department, cohort, phone, changed);
        } else {
            jdbcTemplate.update(
                "UPDATE users SET name = ?, role = ?, roll_number = ?, department = ?, cohort = ?, phone = ?, password_changed = ?, access_status = 'ACTIVE' WHERE email = ?",
                name, role, rollNumber, department, cohort, phone, changed, email
            );
        }
    }

    private void migratePlainTextPasswords() {
        List<Map<String, Object>> users = jdbcTemplate.query(
            "SELECT id, password FROM users",
            (rs, rowNum) -> Map.of("id", rs.getInt("id"), "password", rs.getString("password"))
        );
        for (Map<String, Object> user : users) {
            String password = String.valueOf(user.get("password"));
            if (password != null && !password.startsWith("$2")) {
                jdbcTemplate.update(
                    "UPDATE users SET password = ? WHERE id = ?",
                    passwordEncoder.encode(password),
                    user.get("id")
                );
            }
        }
    }

    private void seedSettings() {
        insertSettingIfMissing("student_limit", "500");
        insertSettingIfMissing("co_admin_limit", "5");
    }

    private void addColumnIfMissing(String tableName, String columnName, String sql) {
        if (!columnExists(tableName, columnName)) {
            jdbcTemplate.execute(sql);
        }
    }

    private boolean columnExists(String tableName, String columnName) {
        Integer count = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?",
            Integer.class,
            tableName,
            columnName
        );
        return count != null && count > 0;
    }

    private void insertIfMissing(String insertSql, String existsSql) {
        Integer count = jdbcTemplate.queryForObject(existsSql, Integer.class);
        if (count == null || count == 0) {
            jdbcTemplate.execute(insertSql);
        }
    }

    private void insertSettingIfMissing(String key, String value) {
        Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM platform_settings WHERE setting_key = ?", Integer.class, key);
        if (count == null || count == 0) {
            jdbcTemplate.update("INSERT INTO platform_settings (setting_key, setting_value) VALUES (?, ?)", key, value);
        }
    }

    private String escapeSql(String value) {
        return value.replace("'", "''");
    }

    private record QuestionSeed(String question, String optionA, String optionB, String optionC, String optionD, String correctAnswer) {
    }
}
