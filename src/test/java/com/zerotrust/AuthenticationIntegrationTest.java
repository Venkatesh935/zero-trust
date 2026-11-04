package com.zerotrust;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;

import com.zerotrust.entity.AppUser;
import com.zerotrust.entity.Role;

class AuthenticationIntegrationTest extends IntegrationTestSupport {

    private static final String JSON = MediaType.APPLICATION_JSON_VALUE;

    @Test
    void protectedApiRequiresAuthentication() throws Exception {
        mvc.perform(get("/api/websites")).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false));
        mvc.perform(get("/api/dashboard/summary")).andExpect(status().isUnauthorized());
    }

    @Test
    void protectedPagesRedirectToLogin() throws Exception {
        mvc.perform(get("/")).andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/login.html"));
        mvc.perform(get("/login.html")).andExpect(status().isOk());
    }

    @Test
    void loginRequiresCsrfToken() throws Exception {
        mvc.perform(post("/api/auth/login").contentType(JSON).content("{\"username\":\"admin\",\"password\":\"x\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void successfulLoginCreatesSessionAndPasswordIsHashed() throws Exception {
        MockHttpSession session = loginAdmin();
        mvc.perform(get("/api/auth/me").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value("admin"))
                .andExpect(jsonPath("$.data.role").value("ADMIN"));
        AppUser admin = users.findByUsernameIgnoreCase("admin").orElseThrow();
        assertThat(admin.getPasswordHash()).startsWith("$2").doesNotContain(ADMIN_PASSWORD);
        assertThat(admin.getLastLoginAt()).isNotNull();
    }

    @Test
    void wrongPasswordIsRejectedWithGenericMessage() throws Exception {
        mvc.perform(post("/api/auth/login").with(xsrf()).contentType(JSON)
                        .content("{\"username\":\"admin\",\"password\":\"wrong-password\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid username or password."));
        mvc.perform(post("/api/auth/login").with(xsrf()).contentType(JSON)
                        .content("{\"username\":\"nobody\",\"password\":\"wrong-password\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid username or password."));
    }

    @Test
    void blankCredentialsFailValidation() throws Exception {
        mvc.perform(post("/api/auth/login").with(xsrf()).contentType(JSON)
                        .content("{\"username\":\"\",\"password\":\"\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void accountLocksAfterRepeatedFailures() throws Exception {
        createUser("lockme", "Correct#Pass1", Role.ANALYST, true);
        for (int i = 0; i < 5; i++) {
            mvc.perform(post("/api/auth/login").with(xsrf()).contentType(JSON)
                    .content("{\"username\":\"lockme\",\"password\":\"bad\"}")).andExpect(status().isUnauthorized());
        }
        mvc.perform(post("/api/auth/login").with(xsrf()).contentType(JSON)
                        .content("{\"username\":\"lockme\",\"password\":\"Correct#Pass1\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message", containsString("locked")));
        assertThat(users.findByUsernameIgnoreCase("lockme").orElseThrow().isLocked()).isTrue();
    }

    @Test
    void disabledAccountCannotLogIn() throws Exception {
        createUser("pending1", "Pending#Pass1", Role.ANALYST, false);
        mvc.perform(post("/api/auth/login").with(xsrf()).contentType(JSON)
                        .content("{\"username\":\"pending1\",\"password\":\"Pending#Pass1\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message", containsString("disabled")));
    }

    @Test
    void logoutInvalidatesSession() throws Exception {
        MockHttpSession session = loginAdmin();
        mvc.perform(post("/api/auth/logout").session(session).with(xsrf())).andExpect(status().isOk());
        assertThat(session.isInvalid()).isTrue();
    }

    @Test
    void registrationIsEnabledByDefaultCreatesPendingAnalystAndCanBeDisabled() throws Exception {
        String body = "{\"username\":\"newcomer\",\"password\":\"Join#Team2026\"}";
        mvc.perform(post("/api/auth/register").with(xsrf()).contentType(JSON).content(body))
                .andExpect(status().isCreated());
        MockHttpSession admin = loginAdmin();
        AppUser created = users.findByUsernameIgnoreCase("newcomer").orElseThrow();
        assertThat(created.getRole()).isEqualTo(Role.ANALYST);
        assertThat(created.isEnabled()).isFalse();

        mvc.perform(put("/api/settings").session(admin).with(xsrf()).contentType(JSON)
                .content("{\"registrationEnabled\":false}")).andExpect(status().isOk());
        mvc.perform(post("/api/auth/register").with(xsrf()).contentType(JSON)
                .content("{\"username\":\"latecomer\",\"password\":\"Join#Team2026\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void userCanChangeOwnPasswordOnlyWithCurrentPassword() throws Exception {
        createUser("pw-changer", "Original#Pass1", Role.ANALYST, true);
        MockHttpSession session = login("pw-changer", "Original#Pass1");
        mvc.perform(put("/api/auth/password").session(session).with(xsrf()).contentType(JSON)
                        .content("{\"currentPassword\":\"wrong\",\"newPassword\":\"Changed#Pass2\"}"))
                .andExpect(status().isBadRequest());
        mvc.perform(put("/api/auth/password").session(session).with(xsrf()).contentType(JSON)
                        .content("{\"currentPassword\":\"Original#Pass1\",\"newPassword\":\"Changed#Pass2\"}"))
                .andExpect(status().isOk());
        login("pw-changer", "Changed#Pass2");
    }

    @Test
    void weakPasswordsAreRejected() throws Exception {
        MockHttpSession admin = loginAdmin();
        mvc.perform(post("/api/users").session(admin).with(xsrf()).contentType(JSON)
                        .content("{\"username\":\"weakling\",\"password\":\"password\",\"role\":\"ANALYST\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", containsString("Password must")));
    }

    @Test
    void responsesCarrySecurityHeaders() throws Exception {
        mvc.perform(get("/login.html"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Content-Security-Policy", containsString("script-src 'self'")))
                .andExpect(header().string("Referrer-Policy", "strict-origin-when-cross-origin"))
                .andExpect(header().exists("Permissions-Policy"));
    }
}
