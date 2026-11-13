package com.modulo.cti;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Through the real security chains: TAXII requests reach {@link TaxiiController} with partner
 * tokens (Basic or Bearer), never the Keycloak JWT chain or the browser login, while the rest of
 * {@code /api} stays protected.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-test.properties",
    properties = "modulo.security.keycloak.jwk-set-uri=http://127.0.0.1:9/jwks")
class TaxiiSecurityTest {
  @Autowired MockMvc mvc;
  @MockBean CtiTaxiiService taxii;

  static final CtiTaxiiService.Principal PARTNER =
      new CtiTaxiiService.Principal(1, UUID.fromString("00000000-0000-4000-8000-000000000001"), "green", false, true, true);

  @Test
  void anonymousTaxiiRequestsGetATaxiiChallengeNotALoginRedirect() throws Exception {
    when(taxii.authenticate(any())).thenReturn(Optional.empty());
    mvc.perform(get("/api/taxii2/root/collections/"))
        .andExpect(status().isUnauthorized())
        .andExpect(header().string("WWW-Authenticate", "Basic realm=\"Modulo TAXII\""));
    mvc.perform(get("/api/taxii2/")).andExpect(status().isOk()).andExpect(jsonPath("$.api_roots[0]").exists());
  }

  @Test
  void bearerPartnerTokensBypassTheKeycloakChainOnlyForTaxii() throws Exception {
    when(taxii.authenticate("Bearer token.secret")).thenReturn(Optional.of(PARTNER));
    when(taxii.collectionResource(PARTNER)).thenReturn(Map.of("id", PARTNER.collection().toString(), "title", "Partners"));
    mvc.perform(get("/api/taxii2/root/collections/").header("Authorization", "Bearer token.secret"))
        .andExpect(status().isOk()).andExpect(jsonPath("$.collections[0].title").value("Partners"));
    // The same header anywhere else in /api is a (bad) Keycloak token and is rejected.
    mvc.perform(get("/api/cti/summary").header("Authorization", "Bearer token.secret")).andExpect(status().isUnauthorized());
  }

  @Test
  void partnersCanPostWithoutABrowserSessionOrCsrfToken() throws Exception {
    when(taxii.authenticate(any())).thenReturn(Optional.of(PARTNER));
    when(taxii.importObjects(any(), any())).thenReturn(Map.of("created", 0));
    mvc.perform(post("/api/taxii2/root/collections/" + PARTNER.collection() + "/objects/")
            .header("Authorization", "Basic dG9rZW46c2VjcmV0").contentType(CtiTaxiiService.MEDIA_TYPE).content("{\"objects\":[]}"))
        .andExpect(status().isAccepted()).andExpect(jsonPath("$.status").value("complete"));
  }
}
