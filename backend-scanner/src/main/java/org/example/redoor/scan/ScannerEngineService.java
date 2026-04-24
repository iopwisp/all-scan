package org.example.redoor.scan;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ScannerEngineService {

    private static final int MAX_CRAWL_DEPTH = 3;
    private static final String USER_AGENT = "AllScan/1.0 (Vulnerability Scanner)";

    // Merged SQLi payloads from Hackathon engine + existing
    private static final List<String> SQLI_PAYLOADS = List.of(
            "'", "' OR 1=1--", "') OR ('1'='1", "admin'--"
    );

    // Extended XSS payloads: direct injection + attribute-breaking (from Hackathon)
    private static final List<String> XSS_PAYLOADS = List.of(
            "<script>alert(1)</script>",
            "\"><script>console.log('XSS')</script>"
    );

    private static final List<String> DIRECTORY_PATHS = List.of(
            "/backup/", "/admin/", "/uploads/", "/config/"
    );

    private static final List<String> LEAKAGE_PATHS = List.of(
            "/.env", "/.git/config", "/backup.zip", "/phpinfo.php"
    );

    // AI remediation advice from Hackathon ReportBuilder
    private static final Map<String, String> AI_REMEDIATION_MAP = Map.of(
            "SQLI", "Use parameterized queries (Prepared Statements) and filter all user input.",
            "XSS", "Implement Content Security Policy (CSP) and escape special characters in HTML output.",
            "LEAKAGE", "Restrict access to system files (.env, .git) at the web server configuration level.",
            "OPEN_DIRECTORIES", "Disable directory listing and restrict access to administrative and backup folders.",
            "CSRF", "Add an anti-CSRF token to all state-changing forms and ensure session cookies use SameSite protection."
    );

    private final ScanJobRepository scanJobRepository;
    private final FindingRepository findingRepository;
    private final HttpClient httpClient;
    private final Duration requestTimeout;

    public ScannerEngineService(
            ScanJobRepository scanJobRepository,
            FindingRepository findingRepository,
            @Value("${app.scanner.connect-timeout:PT5S}") Duration connectTimeout,
            @Value("${app.scanner.read-timeout:PT10S}") Duration readTimeout
    ) {
        this.scanJobRepository = scanJobRepository;
        this.findingRepository = findingRepository;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        this.requestTimeout = readTimeout;
    }

    @Async("scannerTaskExecutor")
    @Transactional
    public void executeScan(UUID scanId) {
        ScanJob scanJob = scanJobRepository.findById(scanId).orElseThrow();
        try {
            runScan(scanJob);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            fail(scanJob, "Scan interrupted.");
        } catch (IOException | IllegalArgumentException exception) {
            fail(scanJob, "Scan failed: " + exception.getMessage());
        }
    }

    private void runScan(ScanJob scanJob) throws IOException, InterruptedException {
        List<CheckType> checks = scanJob.requestedChecksAsList();
        Set<String> seenFindings = new LinkedHashSet<>();

        updateState(scanJob, ScanStatus.RUNNING, 5, "Crawling target");
        FetchResponse baseResponse = fetchGet(scanJob.getTargetUrl());

        // Crawl the site to discover all endpoints (Hackathon Crawler integration)
        CrawlResult crawlResult = crawlSite(scanJob.getTargetUrl(), baseResponse);

        for (int index = 0; index < checks.size(); index++) {
            CheckType check = checks.get(index);
            int progress = 10 + ((index + 1) * 80 / checks.size());

            switch (check) {
                case XSS -> {
                    updateState(scanJob, ScanStatus.RUNNING, progress, "Testing reflected XSS");
                    runXssCheck(scanJob, crawlResult.forms(), crawlResult.getEndpoints(), seenFindings);
                }
                case SQLI -> {
                    updateState(scanJob, ScanStatus.RUNNING, progress, "Testing SQL injection");
                    runSqliCheck(scanJob, crawlResult.forms(), crawlResult.getEndpoints(), seenFindings);
                }
                case CSRF -> {
                    updateState(scanJob, ScanStatus.RUNNING, progress, "Testing forms");
                    runCsrfCheck(scanJob, crawlResult.forms(), baseResponse, seenFindings);
                }
                case OPEN_DIRECTORIES -> {
                    updateState(scanJob, ScanStatus.RUNNING, progress, "Checking open directories");
                    runOpenDirectoriesCheck(scanJob, seenFindings);
                }
                case LEAKAGE -> {
                    updateState(scanJob, ScanStatus.RUNNING, progress, "Checking exposed files");
                    runLeakageCheck(scanJob, seenFindings);
                }
            }
        }

        scanJob.setRiskScore(calculateRiskScore(scanJob.getFindings()));
        updateState(scanJob, ScanStatus.COMPLETED, 100, "Scan completed");
    }

    // ── Crawler (ported from Hackathon engine.py Crawler class) ──────────────

    private CrawlResult crawlSite(String baseUrl, FetchResponse baseResponse) {
        String host;
        try {
            host = URI.create(baseUrl).getHost();
        } catch (Exception e) {
            return new CrawlResult(List.of(), parseForms(baseUrl, baseResponse.body()));
        }

        Set<String> visited = new LinkedHashSet<>();
        List<GetEndpoint> getEndpoints = new ArrayList<>();
        List<FormDescriptor> forms = new ArrayList<>();
        Set<String> seenSigs = new LinkedHashSet<>();

        visited.add(normalizeUrl(baseUrl));
        extractGetEndpointFromUrl(baseUrl, getEndpoints, seenSigs);

        Document baseDoc = Jsoup.parse(baseResponse.body(), baseUrl);
        collectFormsFromDocument(baseUrl, baseDoc, forms, seenSigs);

        for (Element link : baseDoc.select("a[href]")) {
            crawlRecursive(link.attr("abs:href"), host, 1, visited, getEndpoints, forms, seenSigs);
        }

        return new CrawlResult(getEndpoints, forms);
    }

    private void crawlRecursive(String url, String host, int depth,
            Set<String> visited, List<GetEndpoint> getEndpoints,
            List<FormDescriptor> forms, Set<String> seenSigs) {
        if (depth > MAX_CRAWL_DEPTH || url == null || url.isBlank()) return;

        String cleanUrl;
        try {
            URI uri = URI.create(url);
            if (!host.equals(uri.getHost())) return;
            cleanUrl = normalizeUrl(url);
        } catch (Exception e) {
            return;
        }

        if (!visited.add(cleanUrl)) return;

        extractGetEndpointFromUrl(url, getEndpoints, seenSigs);

        FetchResponse response;
        try {
            response = fetchGet(cleanUrl);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
        } catch (Exception e) {
            return;
        }

        String contentType = response.headerValues("content-type").stream().findFirst().orElse("");
        if (!contentType.contains("text/html")) return;

        Document doc = Jsoup.parse(response.body(), cleanUrl);
        collectFormsFromDocument(cleanUrl, doc, forms, seenSigs);

        for (Element link : doc.select("a[href]")) {
            crawlRecursive(link.attr("abs:href"), host, depth + 1, visited, getEndpoints, forms, seenSigs);
        }
    }

    private void extractGetEndpointFromUrl(String url, List<GetEndpoint> endpoints, Set<String> seenSigs) {
        if (!url.contains("?")) return;
        try {
            URI uri = URI.create(url);
            String query = uri.getRawQuery();
            if (query == null || query.isBlank()) return;

            List<String> params = Arrays.stream(query.split("&"))
                    .map(pair -> pair.contains("=") ? pair.substring(0, pair.indexOf('=')) : pair)
                    .filter(p -> !p.isBlank())
                    .distinct()
                    .toList();
            if (params.isEmpty()) return;

            String base = uri.getScheme() + "://" + uri.getHost()
                    + (uri.getPort() > 0 ? ":" + uri.getPort() : "")
                    + (uri.getPath() == null ? "" : uri.getPath());

            String sig = "get:" + base + "|" + params.stream().sorted().collect(Collectors.joining(","));
            if (seenSigs.add(sig)) {
                endpoints.add(new GetEndpoint(base, params));
            }
        } catch (Exception e) {
            // skip malformed URLs
        }
    }

    private void collectFormsFromDocument(String pageUrl, Document doc,
            List<FormDescriptor> forms, Set<String> seenSigs) {
        for (FormDescriptor form : parseFormsFromDocument(pageUrl, doc)) {
            String sig = "form:" + form.method() + "|" + form.actionUrl() + "|"
                    + form.fieldNames().stream().sorted().collect(Collectors.joining(","));
            if (seenSigs.add(sig)) {
                forms.add(form);
            }
        }
    }

    private String normalizeUrl(String url) {
        try {
            URI uri = URI.create(url);
            String path = uri.getPath();
            return uri.getScheme() + "://" + uri.getHost()
                    + (uri.getPort() > 0 ? ":" + uri.getPort() : "")
                    + (path == null || path.isBlank() ? "/" : path);
        } catch (Exception e) {
            return url;
        }
    }

    // ── XSS Check ────────────────────────────────────────────────────────────

    private void runXssCheck(ScanJob scanJob, List<FormDescriptor> forms,
            List<GetEndpoint> getEndpoints, Set<String> seenFindings)
            throws IOException, InterruptedException {

        // Test all crawled GET endpoints with URL params
        for (GetEndpoint endpoint : getEndpoints) {
            for (String param : endpoint.params()) {
                for (String payload : XSS_PAYLOADS) {
                    FetchResponse response = fetchGet(buildUrlWithParams(endpoint.url(), Map.of(param, payload)));
                    if (response.body().contains(payload)) {
                        saveFinding(scanJob, seenFindings, "XSS", Severity.HIGH,
                                endpoint.url(), param,
                                "Reflected XSS payload was returned in the response body.",
                                "Escape user-controlled content and add output encoding on reflected values.",
                                "A03:2021 - Injection", payload, AI_REMEDIATION_MAP.get("XSS"));
                        break;
                    }
                }
            }
        }

        // Fallback: probe base URL when no forms found
        if (forms.isEmpty()) {
            for (String payload : XSS_PAYLOADS) {
                FetchResponse response = fetchGet(buildUrlWithParams(scanJob.getTargetUrl(), Map.of("q", payload)));
                if (response.body().contains(payload)) {
                    saveFinding(scanJob, seenFindings, "XSS", Severity.HIGH,
                            scanJob.getTargetUrl(), "q",
                            "Reflected XSS payload was returned in the response body.",
                            "Escape user-controlled content and add output encoding on reflected values.",
                            "A03:2021 - Injection", payload, AI_REMEDIATION_MAP.get("XSS"));
                    break;
                }
            }
            return;
        }

        for (FormDescriptor form : forms) {
            String parameter = resolveInjectionParameter(form);
            for (String payload : XSS_PAYLOADS) {
                Map<String, String> parameters = new LinkedHashMap<>(form.hiddenInputs());
                parameters.put(parameter, payload);
                FetchResponse response = submitForm(form, parameters);
                if (response.body().contains(payload)) {
                    saveFinding(scanJob, seenFindings, "XSS", Severity.HIGH,
                            form.actionUrl(), parameter,
                            "Reflected XSS payload was returned after form submission.",
                            "Sanitize and encode form inputs before rendering them back to the browser.",
                            "A03:2021 - Injection", payload, AI_REMEDIATION_MAP.get("XSS"));
                    break;
                }
            }
        }
    }

    // ── SQLi Check ───────────────────────────────────────────────────────────

    private void runSqliCheck(ScanJob scanJob, List<FormDescriptor> forms,
            List<GetEndpoint> getEndpoints, Set<String> seenFindings)
            throws IOException, InterruptedException {

        // Test all crawled GET endpoints
        for (GetEndpoint endpoint : getEndpoints) {
            for (String param : endpoint.params()) {
                for (String payload : SQLI_PAYLOADS) {
                    FetchResponse response = fetchGet(buildUrlWithParams(endpoint.url(), Map.of(param, payload)));
                    if (isAbnormalSqlResponse(response)) {
                        saveFinding(scanJob, seenFindings, "SQLI", Severity.CRITICAL,
                                endpoint.url(), param,
                                "The application produced a database-related abnormal response for a SQL injection payload.",
                                "Use parameterized queries and avoid building SQL strings from raw request parameters.",
                                "A03:2021 - Injection", payload, AI_REMEDIATION_MAP.get("SQLI"));
                        break;
                    }
                }
            }
        }

        // Fallback: probe base URL when no forms found
        if (forms.isEmpty()) {
            for (String payload : SQLI_PAYLOADS) {
                FetchResponse response = fetchGet(buildUrlWithParams(scanJob.getTargetUrl(), Map.of("id", payload)));
                if (isAbnormalSqlResponse(response)) {
                    saveFinding(scanJob, seenFindings, "SQLI", Severity.CRITICAL,
                            scanJob.getTargetUrl(), "id",
                            "The application produced a database-like abnormal response for a SQL injection payload.",
                            "Use parameterized queries and avoid building SQL strings from raw request parameters.",
                            "A03:2021 - Injection", payload, AI_REMEDIATION_MAP.get("SQLI"));
                    break;
                }
            }
            return;
        }

        for (FormDescriptor form : forms) {
            String parameter = resolveInjectionParameter(form);
            for (String payload : SQLI_PAYLOADS) {
                Map<String, String> parameters = new LinkedHashMap<>(form.hiddenInputs());
                parameters.put(parameter, payload);

                boolean found = false;
                FetchResponse formResponse = submitForm(form, parameters);
                if (isAbnormalSqlResponse(formResponse)) {
                    found = true;
                } else if ("POST".equals(form.method())) {
                    // Also try JSON POST for REST APIs (from Hackathon sqli.py)
                    FetchResponse jsonResponse = fetchPostJson(form.actionUrl(), parameters);
                    if (isAbnormalSqlResponse(jsonResponse)) {
                        found = true;
                    }
                }

                if (found) {
                    saveFinding(scanJob, seenFindings, "SQLI", Severity.CRITICAL,
                            form.actionUrl(), parameter,
                            "The application produced an abnormal database-related response for a SQL injection payload.",
                            "Use prepared statements, typed validation, and strict server-side query parameter handling.",
                            "A03:2021 - Injection", payload, AI_REMEDIATION_MAP.get("SQLI"));
                    break;
                }
            }
        }
    }

    // ── CSRF Check ───────────────────────────────────────────────────────────

    private void runCsrfCheck(
            ScanJob scanJob,
            List<FormDescriptor> forms,
            FetchResponse baseResponse,
            Set<String> seenFindings
    ) {
        boolean hasSameSiteCookie = baseResponse.headerValues("set-cookie")
                .stream()
                .anyMatch(value -> value.toLowerCase(Locale.ROOT).contains("samesite"));

        for (FormDescriptor form : forms) {
            if ("GET".equals(form.method())) continue;
            boolean hasCsrfToken = form.hiddenInputs().keySet().stream().anyMatch(this::looksLikeCsrfToken);
            if (!hasCsrfToken || !hasSameSiteCookie) {
                saveFinding(scanJob, seenFindings, "CSRF", Severity.MEDIUM, form.actionUrl(), null,
                        buildCsrfDescription(hasCsrfToken, hasSameSiteCookie),
                        "Add an anti-CSRF token to state-changing forms and ensure session cookies use SameSite protection.",
                        "A01:2021 - Broken Access Control", null, AI_REMEDIATION_MAP.get("CSRF"));
            }
        }
    }

    // ── Directory + Leakage Checks ───────────────────────────────────────────

    private void runOpenDirectoriesCheck(ScanJob scanJob, Set<String> seenFindings)
            throws IOException, InterruptedException {
        for (String path : DIRECTORY_PATHS) {
            String target = resolvePath(scanJob.getTargetUrl(), path);
            FetchResponse response = fetchGet(target);
            if (looksLikeOpenDirectory(response)) {
                saveFinding(scanJob, seenFindings, "OPEN_DIRECTORIES", Severity.MEDIUM, target, null,
                        "A potentially exposed directory is reachable and appears to list or expose content.",
                        "Disable directory listing and restrict public access to administrative and backup folders.",
                        "A05:2021 - Security Misconfiguration", path, AI_REMEDIATION_MAP.get("OPEN_DIRECTORIES"));
            }
        }
    }

    private void runLeakageCheck(ScanJob scanJob, Set<String> seenFindings)
            throws IOException, InterruptedException {
        for (String path : LEAKAGE_PATHS) {
            String target = resolvePath(scanJob.getTargetUrl(), path);
            FetchResponse response = fetchGet(target);
            if (looksSensitive(path, response)) {
                Severity severity = "/phpinfo.php".equals(path) ? Severity.MEDIUM : Severity.HIGH;
                saveFinding(scanJob, seenFindings, "LEAKAGE", severity, target, null,
                        "Sensitive file exposure was detected on a well-known path.",
                        "Remove exposed files from the web root and block direct access to configuration and backup assets.",
                        "A05:2021 - Security Misconfiguration", path, AI_REMEDIATION_MAP.get("LEAKAGE"));
            }
        }
    }

    // ── Persistence ──────────────────────────────────────────────────────────

    private void saveFinding(
            ScanJob scanJob,
            Set<String> seenFindings,
            String type,
            Severity severity,
            String url,
            String parameter,
            String description,
            String recommendation,
            String owaspCategory,
            String payload,
            String aiRemediation
    ) {
        String fingerprint = type + "|" + url + "|" + (parameter == null ? "" : parameter);
        if (!seenFindings.add(fingerprint)) return;

        Finding finding = new Finding();
        finding.setScanJob(scanJob);
        finding.setType(type);
        finding.setSeverity(severity);
        finding.setUrl(url);
        finding.setParameter(parameter);
        finding.setDescription(description);
        finding.setRecommendation(recommendation);
        finding.setOwaspCategory(owaspCategory);
        finding.setPayload(payload);
        finding.setAiRemediation(aiRemediation != null ? aiRemediation : recommendation);
        findingRepository.save(finding);
        scanJob.getFindings().add(finding);
    }

    private void updateState(ScanJob scanJob, ScanStatus status, int progress, String stage) {
        scanJob.setStatus(status);
        scanJob.setProgress(progress);
        scanJob.setStage(stage);
        scanJobRepository.save(scanJob);
    }

    private void fail(ScanJob scanJob, String message) {
        scanJob.setStatus(ScanStatus.FAILED);
        scanJob.setStage(message);
        scanJobRepository.save(scanJob);
    }

    private int calculateRiskScore(List<Finding> findings) {
        return Math.min(100, findings.stream().map(Finding::getSeverity).mapToInt(Severity::getScoreWeight).sum());
    }

    // ── HTTP helpers ─────────────────────────────────────────────────────────

    private FetchResponse fetchGet(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .GET()
                .timeout(requestTimeout)
                .header("User-Agent", USER_AGENT)
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return new FetchResponse(response.statusCode(), response.body(), response.headers().map());
    }

    private FetchResponse submitForm(FormDescriptor form, Map<String, String> parameters)
            throws IOException, InterruptedException {
        if ("POST".equals(form.method())) {
            String formBody = encodeParameters(parameters);
            HttpRequest request = HttpRequest.newBuilder(URI.create(form.actionUrl()))
                    .timeout(requestTimeout)
                    .header("User-Agent", USER_AGENT)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(formBody))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return new FetchResponse(response.statusCode(), response.body(), response.headers().map());
        }
        return fetchGet(buildUrlWithParams(form.actionUrl(), parameters));
    }

    // JSON POST for REST API testing (from Hackathon sqli.py / xss.py)
    private FetchResponse fetchPostJson(String url, Map<String, String> params) {
        try {
            String jsonBody = buildJsonBody(params);
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(requestTimeout)
                    .header("User-Agent", USER_AGENT)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return new FetchResponse(response.statusCode(), response.body(), response.headers().map());
        } catch (Exception e) {
            return new FetchResponse(0, "", Map.of());
        }
    }

    private String buildJsonBody(Map<String, String> params) {
        String entries = params.entrySet().stream()
                .map(e -> "\"" + escapeJson(e.getKey()) + "\":\"" + escapeJson(e.getValue()) + "\"")
                .collect(Collectors.joining(","));
        return "{" + entries + "}";
    }

    private String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    // ── HTML parsing ─────────────────────────────────────────────────────────

    private List<FormDescriptor> parseForms(String targetUrl, String html) {
        return parseFormsFromDocument(targetUrl, Jsoup.parse(html, targetUrl));
    }

    private List<FormDescriptor> parseFormsFromDocument(String pageUrl, Document doc) {
        List<FormDescriptor> forms = new ArrayList<>();
        for (Element form : doc.select("form")) {
            String actionAttribute = form.attr("action");
            String actionUrl = actionAttribute.isBlank()
                    ? pageUrl
                    : URI.create(pageUrl).resolve(actionAttribute).toString();
            String method = form.attr("method").isBlank()
                    ? "GET"
                    : form.attr("method").toUpperCase(Locale.ROOT);

            List<String> fieldNames = new ArrayList<>();
            Map<String, String> hiddenInputs = new LinkedHashMap<>();
            for (Element input : form.select("input[name], textarea[name], select[name]")) {
                String name = input.attr("name").trim();
                if (name.isEmpty()) continue;
                fieldNames.add(name);
                if ("input".equals(input.tagName()) && "hidden".equalsIgnoreCase(input.attr("type"))) {
                    hiddenInputs.put(name, input.val());
                }
            }
            forms.add(new FormDescriptor(actionUrl, method, fieldNames, hiddenInputs));
        }
        return forms;
    }

    private String resolveInjectionParameter(FormDescriptor form) {
        return form.fieldNames().stream()
                .filter(name -> !form.hiddenInputs().containsKey(name))
                .filter(name -> !looksLikeCsrfToken(name))
                .findFirst()
                .orElse("q");
    }

    private boolean looksLikeCsrfToken(String name) {
        String normalized = name.toLowerCase(Locale.ROOT);
        return normalized.contains("csrf") || normalized.contains("xsrf")
                || normalized.contains("authenticity") || normalized.contains("token");
    }

    private boolean isAbnormalSqlResponse(FetchResponse response) {
        String body = response.body().toLowerCase(Locale.ROOT);
        return response.statusCode() >= 500
                || body.contains("sql syntax")
                || body.contains("syntax error")
                || body.contains("database error")
                || body.contains("unclosed quotation")
                || body.contains("jdbc")
                || body.contains("sqliteexception")
                || body.contains("mysql")
                || body.contains("postgres");
    }

    private String buildCsrfDescription(boolean hasCsrfToken, boolean hasSameSiteCookie) {
        if (!hasCsrfToken && !hasSameSiteCookie) {
            return "State-changing form is missing a hidden CSRF token and the application does not advertise SameSite cookies.";
        }
        if (!hasCsrfToken) {
            return "State-changing form is missing a hidden CSRF token.";
        }
        return "Session cookies do not advertise SameSite protection for a state-changing form.";
    }

    private boolean looksLikeOpenDirectory(FetchResponse response) {
        if (response.statusCode() != 200 || isProbablyMissingPage(response.body())) return false;
        String body = response.body().toLowerCase(Locale.ROOT);
        return body.contains("index of")
                || body.contains("parent directory")
                || body.contains("directory listing")
                || body.contains("<title>admin")
                || body.contains("uploads")
                || body.contains("backup");
    }

    private boolean looksSensitive(String path, FetchResponse response) {
        if (response.statusCode() != 200) return false;
        String body = response.body().toLowerCase(Locale.ROOT);
        return switch (path) {
            case "/.env" -> body.contains("app_") || body.contains("db_") || body.contains("secret") || body.contains("token=");
            case "/.git/config" -> body.contains("[core]") || body.contains("[remote");
            case "/backup.zip" -> response.headerValues("content-type").stream().anyMatch(v -> v.contains("zip"))
                    || !response.body().isBlank();
            case "/phpinfo.php" -> body.contains("phpinfo") || body.contains("php version");
            default -> false;
        };
    }

    private boolean isProbablyMissingPage(String body) {
        String normalized = body.toLowerCase(Locale.ROOT);
        return normalized.contains("404")
                || normalized.contains("not found")
                || normalized.contains("page not found");
    }

    private String resolvePath(String targetUrl, String path) {
        return URI.create(targetUrl).resolve(path).toString();
    }

    private String buildUrlWithParams(String baseUrl, Map<String, String> parameters) {
        if (parameters.isEmpty()) return baseUrl;
        String delimiter = baseUrl.contains("?") ? "&" : "?";
        return baseUrl + delimiter + encodeParameters(parameters);
    }

    private String encodeParameters(Map<String, String> parameters) {
        return parameters.entrySet().stream()
                .map(entry -> URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8)
                        + "=" + URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8))
                .reduce((left, right) -> left + "&" + right)
                .orElse("");
    }

    // ── Inner records ─────────────────────────────────────────────────────────

    private record GetEndpoint(String url, List<String> params) {}

    private record CrawlResult(List<GetEndpoint> getEndpoints, List<FormDescriptor> forms) {}

    private record FormDescriptor(
            String actionUrl,
            String method,
            List<String> fieldNames,
            Map<String, String> hiddenInputs
    ) {}

    private record FetchResponse(
            int statusCode,
            String body,
            Map<String, List<String>> headers
    ) {
        List<String> headerValues(String headerName) {
            return headers.entrySet().stream()
                    .filter(entry -> entry.getKey() != null && entry.getKey().equalsIgnoreCase(headerName))
                    .findFirst()
                    .map(Map.Entry::getValue)
                    .orElse(List.of());
        }
    }
}

