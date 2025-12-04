/*
 * GAR Bootstrap Token Helper for window.name handoff
 * Mints short-lived JWTs for client-side SSE authentication
 */
package org.keycloak.protocol.saml;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.JsonWebToken;

import java.util.UUID;

/**
 * Helper for minting bootstrap tokens used in window.name handoff.
 * Tokens are short-lived, bound to client origin and Keycloak session.
 */
public class BootstrapTokenHelper {

    private static final Logger logger = Logger.getLogger(BootstrapTokenHelper.class);
    private static final int TOKEN_LIFETIME_SECONDS = 300; // 5 minutes
    private static final String AUDIENCE = "gar-bootstrap";
    private static final ObjectMapper objectMapper = new ObjectMapper();

    /** Client attribute to enable bootstrap token injection */
    public static final String BOOTSTRAP_ENABLED_ATTR = "gar.bootstrap.enabled";
    /** Client attribute for explicit origin override */
    public static final String BOOTSTRAP_ORIGIN_ATTR = "gar.bootstrap.origin";

    /**
     * Check if bootstrap token injection is enabled for this client.
     */
    public static boolean isBootstrapEnabled(ClientModel client) {
        String enabled = client.getAttribute(BOOTSTRAP_ENABLED_ATTR);
        return "true".equalsIgnoreCase(enabled);
    }

    /**
     * Get the client origin for bootstrap token binding.
     * Priority: 1) explicit attribute, 2) first web origin, 3) root URL
     */
    public static String getClientOrigin(ClientModel client) {
        // Check explicit bootstrap origin attribute
        String origin = client.getAttribute(BOOTSTRAP_ORIGIN_ATTR);
        if (origin != null && !origin.isEmpty()) {
            return origin;
        }

        // Fallback to first web origin
        if (client.getWebOrigins() != null) {
            for (String webOrigin : client.getWebOrigins()) {
                if (webOrigin != null && !webOrigin.equals("*") && !webOrigin.isEmpty()) {
                    return webOrigin;
                }
            }
        }

        // Check root URL as last resort
        String rootUrl = client.getRootUrl();
        if (rootUrl != null && !rootUrl.isEmpty()) {
            return rootUrl;
        }

        return null;
    }

    /**
     * Mint a bootstrap token for the given session and client.
     *
     * @param session Keycloak session
     * @param realm Current realm
     * @param userSession User's session
     * @param client Target client
     * @param spEntityId SP Entity ID for SAML
     * @return Serialized bootstrap token for window.name, or null if disabled/error
     */
    public static String mintToken(KeycloakSession session, RealmModel realm,
                                    UserSessionModel userSession, ClientModel client,
                                    String spEntityId) {
        if (!isBootstrapEnabled(client)) {
            return null;
        }

        String clientOrigin = getClientOrigin(client);
        if (clientOrigin == null) {
            logger.warnf("Bootstrap enabled but no origin found for client %s", client.getClientId());
            return null;
        }

        try {
            long now = Time.currentTime();
            long exp = now + TOKEN_LIFETIME_SECONDS;

            // Create JWT with minimal claims
            JsonWebToken jwt = new JsonWebToken();
            jwt.id(UUID.randomUUID().toString());
            jwt.issuer(realm.getName());
            jwt.subject(userSession.getId()); // Keycloak session ID
            jwt.audience(AUDIENCE);
            jwt.iat(now);
            jwt.nbf(now);
            jwt.exp(exp);

            // Custom claims
            jwt.setOtherClaims("origin", clientOrigin);
            jwt.setOtherClaims("sid", userSession.getId());
            if (spEntityId != null) {
                jwt.setOtherClaims("sp", spEntityId);
            }
            jwt.setOtherClaims("purpose", "channel");

            // Sign token with realm's RSA key
            String tokenString = new JWSBuilder()
                    .jsonContent(jwt)
                    .rsa256(session.keys().getActiveRsaKey(realm).getPrivateKey());

            // Create payload for window.name
            BootstrapPayload payload = new BootstrapPayload(tokenString, exp, clientOrigin, spEntityId);
            String json = objectMapper.writeValueAsString(payload);
            String serialized = "__GAR_BOOTSTRAP__" + json;

            logger.debugf("Minted bootstrap token for session %s, client %s, origin %s",
                    userSession.getId(), client.getClientId(), clientOrigin);

            return serialized;

        } catch (Exception e) {
            logger.error("Failed to mint bootstrap token", e);
            return null;
        }
    }

    /**
     * Payload structure for window.name injection
     */
    public static class BootstrapPayload {
        public String token;
        public long exp;
        public String origin;
        public String sp;

        public BootstrapPayload() {}

        public BootstrapPayload(String token, long exp, String origin, String sp) {
            this.token = token;
            this.exp = exp;
            this.origin = origin;
            this.sp = sp;
        }
    }
}
