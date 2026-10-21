import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import java.awt.Desktop;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

public final class SalesforceNoPkceApp {
    private static final String DEFAULT_LOGIN_URL = "https://login.salesforce.com";
    private static final String REDIRECT_URI = "https://localhost:3000/atlas/callback";
    private static final String API_VERSION = "v66.0";
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(30);
    private static final String KEYSTORE_PATH_ENV = "SALESFORCE_KEYSTORE_PATH";
    private static final String KEYSTORE_PASSWORD_ENV = "SALESFORCE_KEYSTORE_PASSWORD";
    private static final String CLIENT_SECRET_ENV = "SALESFORCE_CLIENT_SECRET";

    private SalesforceNoPkceApp() {
    }

    public static void main(String[] args) {
        try {
            Map<String, String> options = parseArguments(args);
            if (options.containsKey("help")) {
                printUsage();
                return;
            }

            String clientId = options.get("client-id");
            if (clientId == null || clientId.isBlank()) {
                throw new IllegalArgumentException("Missing required --client-id.");
            }

            URI loginUri = validateLoginUrl(options.getOrDefault("login-url", DEFAULT_LOGIN_URL));
            authenticateAndVerify(clientId, loginUri);
        } catch (Exception e) {
            System.err.println("Salesforce connection failed: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void authenticateAndVerify(String clientId, URI loginUri) throws Exception {
        String state = randomUrlSafe(32);
        URI authorizationUri = URI.create(loginUri + "/services/oauth2/authorize"
                + "?response_type=code"
                + "&client_id=" + encode(clientId)
                + "&redirect_uri=" + encode(REDIRECT_URI)
                + "&scope=" + encode("api")
                + "&state=" + encode(state));

        CountDownLatch callbackLatch = new CountDownLatch(1);
        AtomicReference<Map<String, String>> callbackResult = new AtomicReference<>();
        AtomicBoolean callbackReceived = new AtomicBoolean();

        HttpsServer server = HttpsServer.create(new InetSocketAddress("localhost", 3000), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(loadSslContext()));
        server.createContext("/atlas/callback", exchange ->
                handleCallback(exchange, state, callbackResult, callbackReceived, callbackLatch));

        try {
            server.start();
            System.out.println("Opening Salesforce sign-in in your browser...");
            System.out.println("If it does not open, visit this URL:\n" + authorizationUri);
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                try {
                    Desktop.getDesktop().browse(authorizationUri);
                } catch (IOException e) {
                    System.err.println("Could not open the browser automatically: " + e.getMessage());
                }
            }

            if (!callbackLatch.await(5, TimeUnit.MINUTES)) {
                throw new IOException("Timed out waiting for the Salesforce sign-in callback.");
            }
        } finally {
            server.stop(0);
        }

        Map<String, String> callback = callbackResult.get();
        if (callback == null) {
            throw new IOException("The sign-in callback did not include a result.");
        }
        if (callback.containsKey("error")) {
            String description = callback.getOrDefault("error_description", callback.get("error"));
            throw new IOException("Salesforce authorization failed: " + description);
        }

        String code = callback.get("code");
        if (code == null || code.isBlank()) {
            throw new IOException("Salesforce did not return an authorization code.");
        }

        Token token = exchangeCode(loginUri, clientId, code);
        verifyApiAccess(token);
    }

    private static SSLContext loadSslContext() throws Exception {
        String keystorePath = System.getenv(KEYSTORE_PATH_ENV);
        String password = System.getenv(KEYSTORE_PASSWORD_ENV);
        if (keystorePath == null || keystorePath.isBlank()
                || password == null || password.isBlank()) {
            throw new IllegalStateException("Set " + KEYSTORE_PATH_ENV
                    + " and " + KEYSTORE_PASSWORD_ENV
                    + " to the path and password of a PKCS#12 keystore containing a localhost certificate.");
        }

        char[] passwordChars = password.toCharArray();
        KeyManagerFactory keyManagers;
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream input = Files.newInputStream(Path.of(keystorePath))) {
                keyStore.load(input, passwordChars);
            }
            keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagers.init(keyStore, passwordChars);
        } finally {
            java.util.Arrays.fill(passwordChars, '\0');
        }

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers.getKeyManagers(), null, new SecureRandom());
        return sslContext;
    }

    private static void handleCallback(
            HttpExchange exchange,
            String expectedState,
            AtomicReference<Map<String, String>> callbackResult,
            AtomicBoolean callbackReceived,
            CountDownLatch callbackLatch) throws IOException {
        Map<String, String> parameters = parseQuery(exchange.getRequestURI().getRawQuery());
        if (!expectedState.equals(parameters.get("state"))) {
            respond(exchange, 400, "Sign-in rejected: state did not match. You may close this window.");
            return;
        }
        if (!callbackReceived.compareAndSet(false, true)) {
            respond(exchange, 409, "This sign-in response was already received. You may close this window.");
            return;
        }

        callbackResult.set(parameters);
        boolean failed = parameters.containsKey("error") || !parameters.containsKey("code");
        respond(exchange, failed ? 400 : 200,
                failed
                        ? "Salesforce sign-in failed. Return to the Java application for details."
                        : "Salesforce sign-in succeeded. You may close this window and return to the Java application.");
        callbackLatch.countDown();
    }

    private static Token exchangeCode(URI loginUri, String clientId, String code)
            throws IOException, InterruptedException {
        String form = "grant_type=authorization_code"
                + "&client_id=" + encode(clientId)
                + "&redirect_uri=" + encode(REDIRECT_URI)
                + "&code=" + encode(code);
        String clientSecret = System.getenv(CLIENT_SECRET_ENV);
        if (clientSecret != null && !clientSecret.isBlank()) {
            form += "&client_secret=" + encode(clientSecret);
        }

        HttpRequest request = HttpRequest.newBuilder(loginUri.resolve("/services/oauth2/token"))
                .timeout(HTTP_TIMEOUT)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();
        HttpResponse<String> response = httpClient().send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw httpFailure("OAuth token exchange", response);
        }

        String accessToken = jsonStringField(response.body(), "access_token");
        String instanceUrl = jsonStringField(response.body(), "instance_url");
        if (accessToken == null || instanceUrl == null) {
            throw new IOException("Salesforce token response was missing access_token or instance_url.");
        }
        URI instance = validateInstanceUrl(instanceUrl);
        return new Token(accessToken, instance);
    }

    private static void verifyApiAccess(Token token) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(token.instanceUrl().resolve("/services/data/"))
                .timeout(HTTP_TIMEOUT)
                .header("Authorization", "Bearer " + token.accessToken())
                .GET()
                .build();
        HttpResponse<String> response = httpClient().send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw httpFailure("Salesforce REST API verification", response);
        }
        getAccountRecords(token);
        System.out.println("Connected successfully to Salesforce.");
        System.out.println("Org instance: " + token.instanceUrl());
        System.out.println("The authenticated user can access the REST API.");
    }

    private static void getAccountRecords(Token token) throws IOException, InterruptedException {
        String soql = "SELECT Id, Name FROM Account LIMIT 5";
        URI queryUri = token.instanceUrl().resolve("/services/data/" + API_VERSION
                + "/query/?q=" + encode(soql));
        HttpRequest request = HttpRequest.newBuilder(queryUri)
                .timeout(HTTP_TIMEOUT)
                .header("Authorization", "Bearer " + token.accessToken())
                .GET()
                .build();
        HttpResponse<String> response = httpClient().send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw httpFailure("Salesforce REST API query", response);
        }
        System.out.println("Salesforce REST API query succeeded; account records are accessible.");
        System.out.println("Salesforce account query response:");
        System.out.println(response.body());
    }

    private static HttpClient httpClient() {
        return HttpClient.newBuilder()
                .connectTimeout(HTTP_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    private static IOException httpFailure(String operation, HttpResponse<String> response) {
        String body = response.body();
        if (body.length() > 2000) {
            body = body.substring(0, 2000) + "...";
        }
        return new IOException(operation + " returned HTTP " + response.statusCode() + ": " + body);
    }

    private static URI validateLoginUrl(String value) {
        URI uri = URI.create(value.endsWith("/") ? value.substring(0, value.length() - 1) : value);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getRawPath() != null && !uri.getRawPath().isEmpty()
                || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new IllegalArgumentException(
                    "--login-url must be an HTTPS origin, such as https://login.salesforce.com "
                            + "or https://your-domain.my.salesforce.com.");
        }
        return uri;
    }

    private static URI validateInstanceUrl(String value) throws IOException {
        URI uri = URI.create(value);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new IOException("Salesforce returned an invalid instance_url.");
        }
        return uri;
    }

    private static Map<String, String> parseArguments(String[] args) {
        Map<String, String> options = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--help".equals(arg) || "-h".equals(arg)) {
                options.put("help", "");
            } else if ("--client-id".equals(arg) || "--login-url".equals(arg)) {
                if (i + 1 >= args.length || args[i + 1].startsWith("--")) {
                    throw new IllegalArgumentException("Missing value for " + arg + ".");
                }
                options.put(arg.substring(2), args[++i]);
            } else {
                throw new IllegalArgumentException("Unknown option: " + arg);
            }
        }
        return options;
    }

    private static String randomUrlSafe(int byteCount) {
        byte[] bytes = new byte[byteCount];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static Map<String, String> parseQuery(String query) {
        Map<String, String> values = new HashMap<>();
        if (query == null || query.isEmpty()) {
            return values;
        }
        for (String pair : query.split("&")) {
            int separator = pair.indexOf('=');
            String key = separator < 0 ? pair : pair.substring(0, separator);
            String value = separator < 0 ? "" : pair.substring(separator + 1);
            values.put(URLDecoder.decode(key, StandardCharsets.UTF_8),
                    URLDecoder.decode(value, StandardCharsets.UTF_8));
        }
        return values;
    }

    private static String jsonStringField(String json, String field) throws IOException {
        int cursor = skipWhitespace(json, 0);
        if (cursor >= json.length() || json.charAt(cursor++) != '{') {
            throw new IOException("Malformed Salesforce token response.");
        }

        while (true) {
            cursor = skipWhitespace(json, cursor);
            if (cursor >= json.length() || json.charAt(cursor) == '}') {
                return null;
            }
            if (json.charAt(cursor) != '"') {
                throw new IOException("Malformed Salesforce token response.");
            }
            ParsedString key = readJsonString(json, cursor);
            cursor = skipWhitespace(json, key.end());
            if (cursor >= json.length() || json.charAt(cursor++) != ':') {
                throw new IOException("Malformed Salesforce token response.");
            }
            cursor = skipWhitespace(json, cursor);
            if (field.equals(key.value()) && cursor < json.length() && json.charAt(cursor) == '"') {
                return readJsonString(json, cursor).value();
            }

            cursor = skipJsonValue(json, cursor);
            cursor = skipWhitespace(json, cursor);
            if (cursor < json.length() && json.charAt(cursor) == ',') {
                cursor++;
            } else if (cursor >= json.length() || json.charAt(cursor) != '}') {
                throw new IOException("Malformed Salesforce token response.");
            }
        }
    }

    private static int skipJsonValue(String json, int cursor) throws IOException {
        if (cursor >= json.length()) {
            throw new IOException("Malformed Salesforce token response.");
        }
        char first = json.charAt(cursor);
        if (first == '"') {
            return readJsonString(json, cursor).end();
        }
        if (first == '{' || first == '[') {
            int depth = 0;
            boolean inString = false;
            boolean escaped = false;
            for (int i = cursor; i < json.length(); i++) {
                char c = json.charAt(i);
                if (inString) {
                    if (escaped) {
                        escaped = false;
                    } else if (c == '\\') {
                        escaped = true;
                    } else if (c == '"') {
                        inString = false;
                    }
                } else if (c == '"') {
                    inString = true;
                } else if (c == '{' || c == '[') {
                    depth++;
                } else if (c == '}' || c == ']') {
                    if (--depth == 0) {
                        return i + 1;
                    }
                }
            }
            throw new IOException("Malformed Salesforce token response.");
        }
        int end = cursor;
        while (end < json.length() && json.charAt(end) != ',' && json.charAt(end) != '}'
                && !Character.isWhitespace(json.charAt(end))) {
            end++;
        }
        if (end == cursor) {
            throw new IOException("Malformed Salesforce token response.");
        }
        return end;
    }

    private static int skipWhitespace(String value, int cursor) {
        while (cursor < value.length() && Character.isWhitespace(value.charAt(cursor))) {
            cursor++;
        }
        return cursor;
    }

    private static ParsedString readJsonString(String json, int start) throws IOException {
        StringBuilder value = new StringBuilder();
        for (int i = start + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"') {
                return new ParsedString(value.toString(), i + 1);
            }
            if (c != '\\') {
                value.append(c);
                continue;
            }
            if (++i >= json.length()) {
                break;
            }
            char escaped = json.charAt(i);
            switch (escaped) {
                case '"', '\\', '/' -> value.append(escaped);
                case 'b' -> value.append('\b');
                case 'f' -> value.append('\f');
                case 'n' -> value.append('\n');
                case 'r' -> value.append('\r');
                case 't' -> value.append('\t');
                case 'u' -> {
                    if (i + 4 >= json.length()) {
                        throw new IOException("Malformed JSON escape in Salesforce token response.");
                    }
                    try {
                        value.append((char) Integer.parseInt(json.substring(i + 1, i + 5), 16));
                    } catch (NumberFormatException e) {
                        throw new IOException("Malformed JSON escape in Salesforce token response.", e);
                    }
                    i += 4;
                }
                default -> throw new IOException("Malformed JSON escape in Salesforce token response.");
            }
        }
        throw new IOException("Malformed JSON string in Salesforce token response.");
    }

    private static void respond(HttpExchange exchange, int status, String message) throws IOException {
        byte[] body = message.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, body.length);
        try (var output = exchange.getResponseBody()) {
            output.write(body);
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java --add-modules jdk.httpserver SalesforceNoPkceApp"
                + " --client-id <connected-app-consumer-key>"
                + " [--login-url <https://login.salesforce.com>]");
        System.out.println("Also set " + KEYSTORE_PATH_ENV + " and " + KEYSTORE_PASSWORD_ENV
                + " for the local HTTPS callback.");
        System.out.println("If required by the Connected App, set " + CLIENT_SECRET_ENV
                + " for token exchange.");
    }

    private record Token(String accessToken, URI instanceUrl) {
    }

    private record ParsedString(String value, int end) {
    }
}
