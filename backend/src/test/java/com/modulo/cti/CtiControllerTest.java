package com.modulo.cti;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.modulo.security.AuthenticatedUserService;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.server.ResponseStatusException;

class CtiControllerTest {
  private final CtiService cti = mock(CtiService.class);
  private final CtiExportService exports = mock(CtiExportService.class);
  private final AuthenticatedUserService users = mock(AuthenticatedUserService.class);
  private MockMvc mvc;

  @BeforeEach
  void setUp() {
    when(users.requireUserId()).thenReturn(7L);
    mvc = MockMvcBuilders.standaloneSetup(new CtiController(cti, exports, mock(CtiCsvImport.class),
            mock(CtiEnrichmentService.class), mock(CtiTaxiiService.class), users))
        .defaultRequest(get("/").accept(MediaType.APPLICATION_JSON)).build();
  }

  @Test
  void ingestBindsRefsAndNaturalKeyLookupsForTheSignedInOwner() throws Exception {
    when(cti.ingest(eq(7L), any())).thenReturn(Map.of("created", 1));
    mvc.perform(post("/api/cti/ingest").contentType(MediaType.APPLICATION_JSON).content(
            "{\"source\":\"cron:wallet-watch\",\"objects\":[{\"ref\":\"w\",\"kind\":\"identity\",\"attributes\":"
                + "{\"identityType\":\"wallet\",\"value\":\"T123\"}}],\"relationships\":[{\"source\":\"w\","
                + "\"target\":{\"kind\":\"actor\",\"key\":\"tronzitveca\"},\"type\":\"attributed-to\"}],"
                + "\"watch\":{\"watchType\":\"wallet\",\"target\":\"T123\",\"result\":\"ok\"}}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.created").value(1));
    ArgumentCaptor<CtiService.IngestBatch> batch = ArgumentCaptor.forClass(CtiService.IngestBatch.class);
    verify(cti).ingest(eq(7L), batch.capture());
    assertThat(batch.getValue().objects().get(0).attributes().get("value").asText()).isEqualTo("T123");
    assertThat(batch.getValue().relationships().get(0).source().asText()).isEqualTo("w");
    assertThat(batch.getValue().relationships().get(0).target().get("key").asText()).isEqualTo("tronzitveca");
    assertThat(batch.getValue().watch().watchType()).isEqualTo("wallet");
  }

  @Test
  void failuresAreClassifiedCodes() throws Exception {
    when(cti.list(eq(7L), any(), eq("bogus"), any(), any(), any(), any(), anyInt(), anyInt()))
        .thenThrow(new ResponseStatusException(HttpStatus.BAD_REQUEST, "CTI_UNKNOWN_VIEW"));
    mvc.perform(get("/api/cti/objects").param("view", "bogus"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("CTI_UNKNOWN_VIEW"));
  }
}
