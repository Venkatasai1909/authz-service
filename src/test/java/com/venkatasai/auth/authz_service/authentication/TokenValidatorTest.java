package com.venkatasai.auth.authz_service.authentication;

import com.venkatasai.auth.authz_service.exception.AuthenticationException;
import com.venkatasai.auth.authz_service.model.DecodedToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenValidatorTest {

    @Mock
    private JwtDecoder jwtDecoder;

    private TokenValidator validator;

    private static final String ISSUER = "https://auth.example.com";
    private static final String AUDIENCE = "authz-service";
    private static final String TOKEN = "dummy.jwt.token";

    @BeforeEach
    void setUp() {
        validator = new TokenValidator(jwtDecoder, ISSUER, AUDIENCE);
    }

    private DecodedToken.DecodedTokenBuilder validTokenBuilder() {
        return DecodedToken.builder()
                .subject("user123")
                .issuer(ISSUER)
                .expiry(Instant.now().plusSeconds(300))
                .audience(List.of(AUDIENCE))
                .claims(Map.of("sub", "user123"));
    }

    private DecodedToken validToken() {
        return validTokenBuilder().build();
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Valid token → decoded token returned")
    void validToken_returnsDecodedToken() {
        when(jwtDecoder.decode(TOKEN)).thenReturn(validToken());

        DecodedToken result = validator.validate(TOKEN);

        assertThat(result).isNotNull();
        assertThat(result.getSubject()).isEqualTo("user123");
    }

    // ── Token format ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("Null token → AuthenticationException")
    void nullToken_throws() {
        assertThatThrownBy(() -> validator.validate(null))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("missing");
    }

    @Test
    @DisplayName("Blank token → AuthenticationException")
    void blankToken_throws() {
        assertThatThrownBy(() -> validator.validate("   "))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("missing");
    }

    // ── Expiry ────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Expired token → AuthenticationException")
    void expiredToken_throws() {
        when(jwtDecoder.decode(TOKEN)).thenReturn(
                validTokenBuilder().expiry(Instant.now().minusSeconds(60)).build());

        assertThatThrownBy(() -> validator.validate(TOKEN))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("expired");
    }

    @Test
    @DisplayName("Missing expiry → AuthenticationException")
    void missingExpiry_throws() {
        when(jwtDecoder.decode(TOKEN)).thenReturn(
                validTokenBuilder().expiry(null).build());

        assertThatThrownBy(() -> validator.validate(TOKEN))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("expired");
    }

    // ── Not-before ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("nbf in future → AuthenticationException")
    void notYetValid_throws() {
        when(jwtDecoder.decode(TOKEN)).thenReturn(
                validTokenBuilder().notBefore(Instant.now().plusSeconds(300)).build());

        assertThatThrownBy(() -> validator.validate(TOKEN))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("not yet valid");
    }

    @Test
    @DisplayName("nbf in past → accepted")
    void pastNotBefore_accepted() {
        when(jwtDecoder.decode(TOKEN)).thenReturn(
                validTokenBuilder().notBefore(Instant.now().minusSeconds(60)).build());

        assertThat(validator.validate(TOKEN)).isNotNull();
    }

    @Test
    @DisplayName("Missing nbf → accepted (optional claim)")
    void missingNotBefore_accepted() {
        when(jwtDecoder.decode(TOKEN)).thenReturn(
                validTokenBuilder().notBefore(null).build());

        assertThat(validator.validate(TOKEN)).isNotNull();
    }

    // ── Issuer ────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Wrong issuer → AuthenticationException")
    void wrongIssuer_throws() {
        when(jwtDecoder.decode(TOKEN)).thenReturn(
                validTokenBuilder().issuer("https://evil.example.com").build());

        assertThatThrownBy(() -> validator.validate(TOKEN))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("issuer");
    }

    @Test
    @DisplayName("Missing issuer → AuthenticationException")
    void missingIssuer_throws() {
        when(jwtDecoder.decode(TOKEN)).thenReturn(
                validTokenBuilder().issuer(null).build());

        assertThatThrownBy(() -> validator.validate(TOKEN))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("issuer");
    }

    // ── Audience ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Wrong audience → AuthenticationException")
    void wrongAudience_throws() {
        when(jwtDecoder.decode(TOKEN)).thenReturn(
                validTokenBuilder().audience(List.of("other-service")).build());

        assertThatThrownBy(() -> validator.validate(TOKEN))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("audience");
    }

    @Test
    @DisplayName("Missing audience claim → AuthenticationException")
    void missingAudience_throws() {
        when(jwtDecoder.decode(TOKEN)).thenReturn(
                validTokenBuilder().audience(null).build());

        assertThatThrownBy(() -> validator.validate(TOKEN))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("audience");
    }

    @Test
    @DisplayName("Audience check skipped when not configured")
    void noAudienceConfig_skipCheck() {
        TokenValidator noAudValidator = new TokenValidator(jwtDecoder, ISSUER, null);
        when(jwtDecoder.decode(TOKEN)).thenReturn(
                validTokenBuilder().audience(null).build());

        assertThat(noAudValidator.validate(TOKEN)).isNotNull();
    }

    @Test
    @DisplayName("Multiple audiences — token accepted if expected audience is included")
    void multipleAudiences_accepted() {
        when(jwtDecoder.decode(TOKEN)).thenReturn(
                validTokenBuilder().audience(List.of("other-service", AUDIENCE, "another-service")).build());

        assertThat(validator.validate(TOKEN)).isNotNull();
    }
}