/**
 * Java Text-to-Speech Starter - Backend Server
 *
 * This is a simple Javalin HTTP server that provides a text-to-speech API endpoint
 * powered by Deepgram's Text-to-Speech service. It's designed to be easily
 * modified and extended for your own projects.
 *
 * Key Features:
 * - Contract-compliant API endpoint: POST /api/text-to-speech
 * - Accepts text in body and model as query parameter
 * - Returns binary audio data (audio/mpeg)
 * - JWT session auth for API protection
 * - CORS enabled for frontend communication
 * - Direct HTTP to Deepgram (no SDK)
 */

package com.deepgram.starter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;
import io.github.cdimascio.dotenv.Dotenv;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

// ============================================================================
// MAIN APPLICATION
// ============================================================================

public class App {

    // ========================================================================
    // CONFIGURATION - Customize these values for your needs
    // ========================================================================

    /**
     * Default text-to-speech model to use when none is specified.
     * Options: "aura-2-thalia-en", "aura-2-theia-en", "aura-2-andromeda-en", etc.
     * See: https://developers.deepgram.com/docs/text-to-speech-models
     */
    private static final String DEFAULT_MODEL = "aura-2-thalia-en";

    /** JWT token expiry duration in seconds (1 hour). */
    private static final long JWT_EXPIRY_SECONDS = 3600;

    // ========================================================================
    // STATE - Application-level state
    // ========================================================================

    private static String sessionSecret;
    private static Algorithm jwtAlgorithm;
    private static JWTVerifier jwtVerifier;
    private static String apiKey;
    private static final ObjectMapper jsonMapper = new ObjectMapper();

    // ========================================================================
    // SESSION AUTH - JWT tokens for API protection
    // ========================================================================

    /**
     * Generates a random hex string of the given byte length.
     * Used for session secret generation in development mode.
     */
    private static String generateRandomHex(int byteLength) {
        byte[] bytes = new byte[byteLength];
        new SecureRandom().nextBytes(bytes);
        StringBuilder sb = new StringBuilder(byteLength * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Initializes the session secret from environment or generates a random one.
     * Also sets up the JWT algorithm and verifier.
     */
    private static void initSessionSecret(Dotenv dotenv) {
        sessionSecret = dotenv.get("SESSION_SECRET");
        if (sessionSecret == null || sessionSecret.isEmpty()) {
            sessionSecret = generateRandomHex(32);
        }
        jwtAlgorithm = Algorithm.HMAC256(sessionSecret);
        jwtVerifier = JWT.require(jwtAlgorithm).build();
    }

    /**
     * Creates a signed JWT with the configured session secret.
     * Token includes issued-at and expiry claims.
     */
    private static String createJWT() {
        Instant now = Instant.now();
        return JWT.create()
                .withIssuedAt(now)
                .withExpiresAt(now.plusSeconds(JWT_EXPIRY_SECONDS))
                .sign(jwtAlgorithm);
    }

    /**
     * Verifies a JWT token string and throws on failure.
     */
    private static void verifyJWT(String token) {
        jwtVerifier.verify(token);
    }

    // ========================================================================
    // API KEY LOADING - Load Deepgram API key from environment
    // ========================================================================

    /**
     * Loads the Deepgram API key from environment variables.
     * Exits with a helpful error message if not found.
     */
    private static String loadApiKey(Dotenv dotenv) {
        String key = dotenv.get("DEEPGRAM_API_KEY");
        if (key == null || key.isEmpty()) {
            System.err.println();
            System.err.println("ERROR: Deepgram API key not found!");
            System.err.println();
            System.err.println("Please set your API key using one of these methods:");
            System.err.println();
            System.err.println("1. Create a .env file (recommended):");
            System.err.println("   DEEPGRAM_API_KEY=your_api_key_here");
            System.err.println();
            System.err.println("2. Environment variable:");
            System.err.println("   export DEEPGRAM_API_KEY=your_api_key_here");
            System.err.println();
            System.err.println("Get your API key at: https://console.deepgram.com");
            System.err.println();
            System.exit(1);
        }
        return key;
    }

    // ========================================================================
    // HELPER FUNCTIONS - Modular logic for easier understanding and testing
    // ========================================================================

    /**
     * Writes a JSON error response to the Javalin context.
     * Builds a contract-compliant error structure.
     *
     * @param ctx        Javalin request context
     * @param statusCode HTTP status code
     * @param type       Error type (ValidationError, GenerationError, AuthenticationError)
     * @param code       Error code (EMPTY_TEXT, INVALID_TEXT, etc.)
     * @param message    Human-readable error message
     */
    private static void writeErrorResponse(Context ctx, int statusCode, String type,
                                           String code, String message) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("originalError", message);

        Map<String, Object> error = new LinkedHashMap<>();
        error.put("type", type);
        error.put("code", code);
        error.put("message", message);
        error.put("details", details);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);

        ctx.status(statusCode);
        ctx.contentType("application/json");
        ctx.json(body);
    }

    /**
     * Auto-detects an error code from the error message when not explicitly provided.
     * Used for mapping Deepgram API errors to contract error codes.
     */
    private static String detectErrorCode(String message, int statusCode) {
        String msgLower = message.toLowerCase();
        if (statusCode == 400) {
            if (msgLower.contains("empty")) return "EMPTY_TEXT";
            if (msgLower.contains("model") || msgLower.contains("not found")) return "MODEL_NOT_FOUND";
            if (msgLower.contains("long") || msgLower.contains("limit") || msgLower.contains("exceed")) {
                return "TEXT_TOO_LONG";
            }
            return "INVALID_TEXT";
        }
        return "INVALID_TEXT";
    }

    // ========================================================================
    // DEEPGRAM API - Direct HTTP calls to the Deepgram TTS endpoint
    // ========================================================================

    /**
     * Calls the Deepgram TTS API directly and returns the audio bytes.
     * Sends a JSON body with the text and passes the model as a query parameter.
     *
     * @param text  The text to convert to speech
     * @param model The TTS model to use
     * @return Binary audio data as byte array
     * @throws Exception on network or API errors
     */
    private static byte[] generateAudio(String text, String model) throws Exception {
        // Build the JSON payload
        Map<String, String> payload = new LinkedHashMap<>();
        payload.put("text", text);
        byte[] payloadBytes = jsonMapper.writeValueAsBytes(payload);

        // Build the request to Deepgram TTS API
        URI uri = new URI("https://api.deepgram.com/v1/speak?model=" + model);
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "Token " + apiKey);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(30000);
        conn.setReadTimeout(30000);

        // Write the request body
        conn.getOutputStream().write(payloadBytes);
        conn.getOutputStream().flush();

        // Check for API errors (non-2xx status)
        int responseCode = conn.getResponseCode();
        if (responseCode < 200 || responseCode >= 300) {
            InputStream errorStream = conn.getErrorStream();
            String errorBody = "";
            if (errorStream != null) {
                errorBody = new String(errorStream.readAllBytes());
                errorStream.close();
            }
            throw new RuntimeException(
                    "Deepgram API error (status " + responseCode + "): " + errorBody);
        }

        // Read all bytes from the response (binary audio data)
        byte[] audioData;
        try (InputStream in = conn.getInputStream()) {
            audioData = in.readAllBytes();
        }
        conn.disconnect();

        return audioData;
    }

    // ========================================================================
    // AUTH MIDDLEWARE - JWT Bearer token validation
    // ========================================================================

    /**
     * Validates the JWT Bearer token from the Authorization header.
     * Returns true if the request should proceed, false if an error was sent.
     */
    private static boolean requireSession(Context ctx) {
        String authHeader = ctx.header("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            writeErrorResponse(ctx, 401, "AuthenticationError", "MISSING_TOKEN",
                    "Authorization header with Bearer token is required");
            return false;
        }

        String token = authHeader.substring(7);
        try {
            verifyJWT(token);
            return true;
        } catch (TokenExpiredException e) {
            writeErrorResponse(ctx, 401, "AuthenticationError", "INVALID_TOKEN",
                    "Session expired, please refresh the page");
            return false;
        } catch (JWTVerificationException e) {
            writeErrorResponse(ctx, 401, "AuthenticationError", "INVALID_TOKEN",
                    "Invalid session token");
            return false;
        }
    }

    // ========================================================================
    // ROUTE HANDLERS - API endpoint implementations
    // ========================================================================

    /**
     * GET /api/session
     * Issues a signed JWT for session authentication.
     */
    private static void handleSession(Context ctx) {
        String token = createJWT();
        Map<String, String> response = new LinkedHashMap<>();
        response.put("token", token);
        ctx.json(response);
    }

    /**
     * POST /api/text-to-speech
     *
     * Contract-compliant text-to-speech endpoint per starter-contracts specification.
     * Accepts:
     * - Query parameter: model (optional, default "aura-2-thalia-en")
     * - Body: JSON with text field (required)
     *
     * Returns:
     * - Success (200): Binary audio data (audio/mpeg)
     * - Error (4XX/5XX): JSON error response matching contract format
     */
    private static void handleTextToSpeech(Context ctx) {
        // Check auth first
        if (!requireSession(ctx)) {
            return;
        }

        try {
            // Parse the model from query parameter
            String model = ctx.queryParam("model");
            if (model == null || model.isEmpty()) {
                model = DEFAULT_MODEL;
            }

            // Parse the JSON body
            Map<String, Object> body;
            try {
                body = jsonMapper.readValue(ctx.body(), Map.class);
            } catch (Exception e) {
                writeErrorResponse(ctx, 400, "ValidationError", "INVALID_TEXT",
                        "Invalid request body");
                return;
            }

            Object textObj = body.get("text");
            String text = textObj != null ? textObj.toString() : null;

            // Validate input - text is required
            if (text == null) {
                writeErrorResponse(ctx, 400, "ValidationError", "EMPTY_TEXT",
                        "Text parameter is required");
                return;
            }

            if (text.trim().isEmpty()) {
                writeErrorResponse(ctx, 400, "ValidationError", "EMPTY_TEXT",
                        "Text must be a non-empty string");
                return;
            }

            // Generate audio from text via Deepgram API
            byte[] audioData = generateAudio(text, model);

            // Return binary audio data with proper content type
            ctx.contentType("audio/mpeg");
            ctx.result(audioData);

        } catch (Exception e) {
            System.err.println("Text-to-speech error: " + e.getMessage());
            String errMsg = e.getMessage() != null ? e.getMessage() : "Unknown error";
            String errMsgLower = errMsg.toLowerCase();

            // Determine error type and status code based on error message
            int statusCode = 500;
            String errorCode = null;

            if (errMsgLower.contains("model") || errMsgLower.contains("not found")) {
                statusCode = 400;
                errorCode = "MODEL_NOT_FOUND";
            } else if (errMsgLower.contains("too long") || errMsgLower.contains("length")
                    || errMsgLower.contains("limit") || errMsgLower.contains("exceed")) {
                statusCode = 400;
                errorCode = "TEXT_TOO_LONG";
            } else if (errMsgLower.contains("invalid") || errMsgLower.contains("malformed")) {
                statusCode = 400;
                errorCode = "INVALID_TEXT";
            }

            String errorType = (statusCode == 400) ? "ValidationError" : "GenerationError";
            if (errorCode == null) {
                errorCode = detectErrorCode(errMsg, statusCode);
            }

            writeErrorResponse(ctx, statusCode, errorType, errorCode, errMsg);
        }
    }

    /**
     * GET /api/metadata
     * Returns project metadata from deepgram.toml [meta] section.
     */
    @SuppressWarnings("unchecked")
    private static void handleMetadata(Context ctx) {
        try {
            TomlMapper tomlMapper = new TomlMapper();
            Map<String, Object> config = tomlMapper.readValue(
                    new java.io.File("deepgram.toml"), Map.class);

            Object meta = config.get("meta");
            if (meta == null) {
                ctx.status(500);
                Map<String, String> error = new LinkedHashMap<>();
                error.put("error", "INTERNAL_SERVER_ERROR");
                error.put("message", "Missing [meta] section in deepgram.toml");
                ctx.json(error);
                return;
            }

            ctx.json(meta);
        } catch (Exception e) {
            System.err.println("Error reading deepgram.toml: " + e.getMessage());
            ctx.status(500);
            Map<String, String> error = new LinkedHashMap<>();
            error.put("error", "INTERNAL_SERVER_ERROR");
            error.put("message", "Failed to read metadata from deepgram.toml");
            ctx.json(error);
        }
    }

    /**
     * GET /health
     * Simple health check endpoint for monitoring.
     */
    private static void handleHealth(Context ctx) {
        Map<String, String> response = new LinkedHashMap<>();
        response.put("status", "ok");
        ctx.json(response);
    }

    // ========================================================================
    // SERVER START
    // ========================================================================

    public static void main(String[] args) {
        // Load .env file (ignore if not present)
        Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();

        // Load API key and initialize session
        apiKey = loadApiKey(dotenv);
        initSessionSecret(dotenv);

        // Read port and host from environment
        String portStr = dotenv.get("PORT", "8081");
        int port = Integer.parseInt(portStr);
        String host = dotenv.get("HOST", "0.0.0.0");

        // Create Javalin app with CORS
        Javalin app = Javalin.create(config -> {
            config.bundledPlugins.enableCors(cors -> {
                cors.addRule(rule -> {
                    rule.anyHost();
                });
            });
        });

        // Register routes
        // Unprotected routes
        app.get("/api/session", App::handleSession);
        app.get("/api/metadata", App::handleMetadata);
        app.get("/health", App::handleHealth);

        // Protected routes (auth checked inside handler)
        app.post("/api/text-to-speech", App::handleTextToSpeech);

        // Start the server
        app.start(host, port);

        System.out.println();
        System.out.println("=".repeat(70));
        System.out.println("Backend API running at http://localhost:" + port);
        System.out.println("GET  /api/session");
        System.out.println("POST /api/text-to-speech (auth required)");
        System.out.println("GET  /api/metadata");
        System.out.println("GET  /health");
        System.out.println("=".repeat(70));
        System.out.println();
    }
}
