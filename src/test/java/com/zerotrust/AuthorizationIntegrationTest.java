package com.zerotrust;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;

import com.zerotrust.entity.AppUser;
import com.zerotrust.entity.AuditAction;
import com.zerotrust.entity.Role;
import com.zerotrust.repository.AuditLogRepository;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Role-based access control and per-website authorization for analysts.
 */
class AuthorizationIntegrationTest extends IntegrationTestSupport {

    private static final String JSON = MediaType.APPLICATION_JSON_VALUE;

    @Autowired
    private AuditLogRepository auditLogs;

    private long createWebsite(MockHttpSession admin, String name, String url, Long analystId) throws Exception {
        String analysts = analystId == null ? "[]" : "[" + analystId + "]";
        String response = mvc.perform(post("/api/websites").session(admin).with(xsrf()).contentType(JSON)
                        .content("{\"name\":\"" + name + "\",\"url\":\"" + url + "\",\"authorizationConfirmed\":true,\"analystIds\":" + analysts + "}"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        JsonNode node = JsonMapper.builder().build().readTree(response);
        return node.get("data").get("id").asLong();
    }

    @Test
    void analystCannotUseAdministrativeEndpoints() throws Exception {
        createUser("rbac-analyst", "Analyst#Pass1", Role.ANALYST, true);
        MockHttpSession analyst = login("rbac-analyst", "Analyst#Pass1");

        mvc.perform(get("/api/users").session(analyst)).andExpect(status().isForbidden());
        mvc.perform(get("/api/audit-logs").session(analyst)).andExpect(status().isForbidden());
        mvc.perform(post("/api/websites").session(analyst).with(xsrf()).contentType(JSON)
                        .content("{\"name\":\"x\",\"url\":\"https://rbac.example.com\",\"authorizationConfirmed\":true}"))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/monitoring").session(analyst).with(xsrf()).contentType(JSON)
                .content("{\"websiteId\":1,\"intervalMinutes\":60}")).andExpect(status().isForbidden());
        mvc.perform(put("/api/settings").session(analyst).with(xsrf()).contentType(JSON)
                .content("{\"registrationEnabled\":true}")).andExpect(status().isForbidden());
        assertThat(auditLogs.findAll()).anyMatch(a -> a.getAction() == AuditAction.ACCESS_DENIED
                && "rbac-analyst".equals(a.getUsername()));
    }

    @Test
    void analystOnlySeesAssignedWebsites() throws Exception {
        AppUser analystUser = createUser("scoped-analyst", "Scoped#Pass1", Role.ANALYST, true);
        MockHttpSession admin = loginAdmin();
        long assigned = createWebsite(admin, "Assigned", "https://assigned.example.com", analystUser.getId());
        long other = createWebsite(admin, "Other", "https://other.example.com", null);

        MockHttpSession analyst = login("scoped-analyst", "Scoped#Pass1");
        mvc.perform(get("/api/websites").session(analyst))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(1))
                .andExpect(jsonPath("$.data[0].id").value(assigned));
        mvc.perform(get("/api/websites/" + assigned).session(analyst)).andExpect(status().isOk());
        mvc.perform(get("/api/websites/" + other).session(analyst)).andExpect(status().isForbidden());
        mvc.perform(post("/api/scans").session(analyst).with(xsrf()).contentType(JSON)
                .content("{\"websiteId\":" + other + "}")).andExpect(status().isForbidden());
        mvc.perform(delete("/api/websites/" + assigned).session(analyst).with(xsrf()))
                .andExpect(status().isForbidden());
    }

    @Test
    void disablingUserRevokesActiveSession() throws Exception {
        AppUser target = createUser("revoke-me", "Revoke#Pass1", Role.ANALYST, true);
        MockHttpSession analyst = login("revoke-me", "Revoke#Pass1");
        mvc.perform(get("/api/websites").session(analyst)).andExpect(status().isOk());

        MockHttpSession admin = loginAdmin();
        mvc.perform(put("/api/users/" + target.getId()).session(admin).with(xsrf()).contentType(JSON)
                .content("{\"enabled\":false}")).andExpect(status().isOk());

        mvc.perform(get("/api/websites").session(analyst)).andExpect(status().isUnauthorized());
        assertThat(auditLogs.findAll()).anyMatch(a -> a.getAction() == AuditAction.SESSION_REVOKED
                && "revoke-me".equals(a.getUsername()));
    }

    @Test
    void adminCannotRemoveOwnAccessOrTheLastAdmin() throws Exception {
        MockHttpSession admin = loginAdmin();
        Long adminId = users.findByUsernameIgnoreCase("admin").orElseThrow().getId();
        mvc.perform(delete("/api/users/" + adminId).session(admin).with(xsrf())).andExpect(status().isBadRequest());
        mvc.perform(put("/api/users/" + adminId).session(admin).with(xsrf()).contentType(JSON)
                .content("{\"enabled\":false}")).andExpect(status().isBadRequest());
        mvc.perform(put("/api/users/" + adminId).session(admin).with(xsrf()).contentType(JSON)
                .content("{\"role\":\"ANALYST\"}")).andExpect(status().isBadRequest());
    }

    @Test
    void websiteRegistrationValidatesUrlAndAuthorization() throws Exception {
        MockHttpSession admin = loginAdmin();
        String[] unsafe = {"http://localhost/", "http://127.0.0.1/", "http://169.254.169.254/", "https://db.internal-test.com/",
                "ftp://files.example.com/", "https://example.com:22/"};
        for (String url : unsafe) {
            mvc.perform(post("/api/websites").session(admin).with(xsrf()).contentType(JSON)
                            .content("{\"name\":\"bad\",\"url\":\"" + url + "\",\"authorizationConfirmed\":true}"))
                    .andExpect(status().isBadRequest());
        }
        mvc.perform(post("/api/websites").session(admin).with(xsrf()).contentType(JSON)
                        .content("{\"name\":\"no-auth\",\"url\":\"https://noauth.example.com\",\"authorizationConfirmed\":false}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.authorizationConfirmed").exists());
        createWebsite(admin, "Dup", "https://dup.example.com", null);
        mvc.perform(post("/api/websites").session(admin).with(xsrf()).contentType(JSON)
                        .content("{\"name\":\"Dup2\",\"url\":\"HTTPS://DUP.example.com:443/\",\"authorizationConfirmed\":true}"))
                .andExpect(status().isConflict());
    }
}
