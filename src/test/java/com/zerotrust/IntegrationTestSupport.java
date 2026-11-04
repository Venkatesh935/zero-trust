package com.zerotrust;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import com.zerotrust.entity.AppUser;
import com.zerotrust.entity.Role;
import com.zerotrust.repository.AppUserRepository;
import com.zerotrust.security.TargetUrlValidator;
import com.zerotrust.service.scanner.HttpFetcher;

import jakarta.servlet.http.Cookie;

/**
 * Base class for integration tests: full Spring context on a throw-away local
 * MongoDB database (emptied at start-up), MockMvc, a fake DNS resolver and a mocked HTTP fetcher, so tests
 * never touch the network.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(IntegrationTestSupport.FakeDnsConfig.class)
public abstract class IntegrationTestSupport {

    public static final String ADMIN_PASSWORD = "Adm1n!Passw0rd#";

    @Autowired
    protected MockMvc mvc;

    @Autowired
    protected AppUserRepository users;

    @Autowired
    protected PasswordEncoder passwordEncoder;

    @MockitoBean
    protected HttpFetcher httpFetcher;

    @TestConfiguration
    static class FakeDnsConfig {
        /** Empties the test database before the initial administrator is created. */
        @Bean
        @Order(Ordered.HIGHEST_PRECEDENCE)
        ApplicationRunner emptyTestDatabase(MongoTemplate mongo) {
            return args -> mongo.getDb().drop();
        }

        /** Every hostname resolves to a public documentation-free address; "*.internal-test.com" resolves to 10.x. */
        @Bean
        @Primary
        TargetUrlValidator testTargetUrlValidator() {
            return new TargetUrlValidator(FakeDnsConfig::resolve, Set.of(80, 443, 8080, 8443));
        }

        static InetAddress[] resolve(String host) throws UnknownHostException {
            if (host.matches("[0-9.]+") || host.contains(":")) {
                return new InetAddress[] {InetAddress.getByName(host)};
            }
            if (host.endsWith("internal-test.com")) {
                return new InetAddress[] {InetAddress.getByName("10.20.30.40")};
            }
            return new InetAddress[] {InetAddress.getByName("93.184.216.34")};
        }
    }

    /**
     * Double-submit CSRF token exactly as the browser client sends it: the
     * XSRF-TOKEN cookie plus the same value in the X-XSRF-TOKEN header.
     */
    protected static RequestPostProcessor xsrf() {
        return request -> {
            request.setCookies(new Cookie("XSRF-TOKEN", TEST_CSRF_TOKEN));
            request.addHeader("X-XSRF-TOKEN", TEST_CSRF_TOKEN);
            return request;
        };
    }

    private static final String TEST_CSRF_TOKEN = "3f1c7a52-test-csrf-token";

    protected MockHttpSession login(String username, String password) throws Exception {
        MvcResult result = mvc.perform(post("/api/auth/login").with(xsrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }

    protected MockHttpSession loginAdmin() throws Exception {
        return login("admin", ADMIN_PASSWORD);
    }

    protected AppUser createUser(String username, String password, Role role, boolean enabled) {
        AppUser user = new AppUser();
        user.setUsername(username);
        user.setPasswordHash(passwordEncoder.encode(password));
        user.setRole(role);
        user.setEnabled(enabled);
        return users.save(user);
    }
}
