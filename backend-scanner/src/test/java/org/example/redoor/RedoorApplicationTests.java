package org.example.redoor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.redoor.scan.ScanJobRepository;
import org.example.redoor.scan.ScannerEngineService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
class RedoorApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ScanJobRepository scanJobRepository;

    @MockBean
    private ScannerEngineService scannerEngineService;

    @AfterEach
    void cleanup() {
        scanJobRepository.deleteAll();
    }

    @Test
    void contextLoads() {
        assertThat(scanJobRepository).isNotNull();
    }

    @Test
    void loginReturnsBearerTokenForDemoUser() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "admin",
                                  "password": "admin123"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("admin"))
                .andExpect(jsonPath("$.role").value("ADMIN"))
                .andExpect(jsonPath("$.token").isString());
    }

    @Test
    void scansEndpointRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/scans"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void createScanStoresQueuedJob() throws Exception {
        String token = login("user", "user123");

        doAnswer(invocation -> {
            java.util.UUID scanId = invocation.getArgument(0);
            assertThat(scanJobRepository.existsById(scanId)).isTrue();
            return null;
        }).when(scannerEngineService).executeScan(any(java.util.UUID.class));

        MvcResult result = mockMvc.perform(post("/api/scans")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "targetUrl": "http://localhost:3000",
                                  "scanType": "FULL",
                                  "checks": ["XSS", "SQLI", "CSRF"]
                                }
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("QUEUED"))
                .andExpect(jsonPath("$.progress").value(0))
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        java.util.UUID scanId = java.util.UUID.fromString(body.get("id").asText());
        assertThat(scanJobRepository.existsById(scanId)).isTrue();
        verify(scannerEngineService).executeScan(scanId);
    }

    private String login(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "%s",
                                  "password": "%s"
                                }
                                """.formatted(username, password)))
                .andExpect(status().isOk())
                .andReturn();

        return objectMapper.readTree(result.getResponse().getContentAsString()).get("token").asText();
    }
}
