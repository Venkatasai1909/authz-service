package com.venkatasai.auth.authz_service.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PathUtilsTest {

    // ── mapHttpMethodToAction ─────────────────────────────────────────────────

    @Nested
    @DisplayName("mapHttpMethodToAction")
    class MethodMapping {

        @Test
        void GET_mapsTo_read() {
            assertThat(PathUtils.mapHttpMethodToAction("GET")).isEqualTo("read");
        }

        @Test
        void POST_mapsTo_write() {
            assertThat(PathUtils.mapHttpMethodToAction("POST")).isEqualTo("write");
        }

        @Test
        void PUT_mapsTo_write() {
            assertThat(PathUtils.mapHttpMethodToAction("PUT")).isEqualTo("write");
        }

        @Test
        void PATCH_mapsTo_write() {
            assertThat(PathUtils.mapHttpMethodToAction("PATCH")).isEqualTo("write");
        }

        @Test
        void DELETE_mapsTo_delete() {
            assertThat(PathUtils.mapHttpMethodToAction("DELETE")).isEqualTo("delete");
        }

        @Test
        void lowercase_get_mapsTo_read() {
            assertThat(PathUtils.mapHttpMethodToAction("get")).isEqualTo("read");
        }

        @Test
        void mixedCase_Post_mapsTo_write() {
            assertThat(PathUtils.mapHttpMethodToAction("Post")).isEqualTo("write");
        }

        @Test
        void unknownMethod_throwsException() {
            assertThatThrownBy(() -> PathUtils.mapHttpMethodToAction("HEAD"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("HEAD");
        }

        @Test
        void nullMethod_throwsException() {
            assertThatThrownBy(() -> PathUtils.mapHttpMethodToAction(null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void blankMethod_throwsException() {
            assertThatThrownBy(() -> PathUtils.mapHttpMethodToAction("  "))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    // ── normalizePath ─────────────────────────────────────────────────────────

    @Nested
    @DisplayName("normalizePath")
    class PathNormalization {

        @Test
        void leadingSlash_stripped() {
            assertThat(PathUtils.normalizePath("/transactions")).isEqualTo("transactions");
        }

        @Test
        void trailingSlash_stripped() {
            assertThat(PathUtils.normalizePath("transactions/")).isEqualTo("transactions");
        }

        @Test
        void bothSlashes_stripped() {
            assertThat(PathUtils.normalizePath("/wallets/wallet-789/")).isEqualTo("wallets/wallet-789");
        }

        @Test
        void noSlashes_unchanged() {
            assertThat(PathUtils.normalizePath("wallets/wallet-789")).isEqualTo("wallets/wallet-789");
        }

        @Test
        void nullPath_returnsNull() {
            assertThat(PathUtils.normalizePath(null)).isNull();
        }

        @Test
        void whitespace_stripped() {
            assertThat(PathUtils.normalizePath("  /transactions  ")).isEqualTo("transactions");
        }

        @Test
        void deepPath_normalized() {
            assertThat(PathUtils.normalizePath("/wallets/w-1/transactions/t-1"))
                    .isEqualTo("wallets/w-1/transactions/t-1");
        }
    }
}