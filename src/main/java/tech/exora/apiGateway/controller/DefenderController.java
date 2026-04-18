package tech.exora.apiGateway.controller;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/defender")
public class DefenderController {

    private static final String ARM_BASE = "https://management.azure.com";
    private static final String LOGIN_BASE = "https://login.microsoftonline.com";
    private static final int HARD_CAP = 1000;

    public record Creds(
            String tenantId,
            String clientId,
            String clientSecret,
            String subscriptionId,
            Integer maxResults
    ) {}

    @PostMapping("/alerts")
    public Mono<ResponseEntity<Map<String, Object>>> alerts(@RequestBody Creds req) {
        if (req == null
                || isBlank(req.tenantId())
                || isBlank(req.clientId())
                || isBlank(req.clientSecret())
                || isBlank(req.subscriptionId())) {
            return Mono.just(ResponseEntity.badRequest().body(err(
                    "tenantId, clientId, clientSecret and subscriptionId are required.")));
        }

        int cap = req.maxResults() != null
                ? Math.min(Math.max(req.maxResults(), 1), HARD_CAP)
                : 200;

        return getToken(req.tenantId().trim(), req.clientId().trim(), req.clientSecret().trim())
                .flatMap(token -> fetchAllAlerts(token, req.subscriptionId().trim(), cap))
                .map(pair -> buildResponse(req.subscriptionId().trim(), pair.alerts(), pair.pages(), pair.truncated()))
                .map(ResponseEntity::ok)
                .onErrorResume(WebClientResponseException.class, ex -> Mono.just(
                        ResponseEntity.status(ex.getStatusCode()).body(err(
                                "Azure: HTTP " + ex.getStatusCode().value() + " — " + ex.getResponseBodyAsString()))))
                .onErrorResume(ex -> Mono.just(ResponseEntity.status(500).body(err(
                        ex.getMessage() != null ? ex.getMessage() : ex.getClass().getSimpleName()))));
    }

    private Mono<String> getToken(String tenantId, String clientId, String clientSecret) {
        WebClient client = WebClient.builder().baseUrl(LOGIN_BASE).build();

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("scope", "https://management.azure.com/.default");

        return client.post()
                .uri("/{tid}/oauth2/v2.0/token", tenantId)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(form)
                .retrieve()
                .bodyToMono(Map.class)
                .flatMap(body -> {
                    Object at = body.get("access_token");
                    if (at == null) return Mono.error(new RuntimeException("No access_token in token response"));
                    return Mono.just(String.valueOf(at));
                });
    }

    private record FetchResult(List<Map<String, Object>> alerts, int pages, boolean truncated) {}

    @SuppressWarnings("unchecked")
    private Mono<FetchResult> fetchAllAlerts(String token, String subscriptionId, int cap) {
        WebClient arm = WebClient.builder()
                .baseUrl(ARM_BASE)
                .defaultHeader("Authorization", "Bearer " + token)
                .build();

        String startUri = "/subscriptions/" + subscriptionId
                + "/providers/Microsoft.Security/alerts?api-version=2022-01-01";

        List<Map<String, Object>> acc = new ArrayList<>();
        return fetchPage(arm, startUri, acc, cap, 0)
                .map(pagesAndTrunc -> new FetchResult(acc, pagesAndTrunc[0], pagesAndTrunc[1] == 1));
    }

    @SuppressWarnings("unchecked")
    private Mono<int[]> fetchPage(WebClient arm, String uri, List<Map<String, Object>> acc, int cap, int pages) {
        if (acc.size() >= cap) {
            return Mono.just(new int[]{pages, 1}); // truncated
        }
        if (pages >= 20) {
            return Mono.just(new int[]{pages, 1}); // safety cap
        }
        return arm.get().uri(uri).retrieve().bodyToMono(Map.class)
                .flatMap(resp -> {
                    List<Map<String, Object>> values =
                            (List<Map<String, Object>>) resp.getOrDefault("value", List.of());
                    for (Map<String, Object> v : values) {
                        if (acc.size() >= cap) break;
                        acc.add(v);
                    }
                    String next = (String) resp.get("nextLink");
                    int newPages = pages + 1;
                    if (next == null || next.isBlank() || acc.size() >= cap) {
                        return Mono.just(new int[]{newPages, (next != null && !next.isBlank() && acc.size() >= cap) ? 1 : 0});
                    }
                    String nextUri = next.startsWith(ARM_BASE) ? next.substring(ARM_BASE.length()) : next;
                    return fetchPage(arm, nextUri, acc, cap, newPages);
                });
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> buildResponse(String subscriptionId,
                                              List<Map<String, Object>> raw,
                                              int pages,
                                              boolean truncated) {
        List<Map<String, Object>> findings = raw.stream()
                .map(this::mapAlert)
                .collect(Collectors.toList());

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("source", "azure-defender");
        out.put("subscriptionId", subscriptionId);
        out.put("region", "azure");
        out.put("count", findings.size());
        out.put("truncated", truncated);
        out.put("pages", pages);
        out.put("severityCounts", countBy(findings, "severity"));
        out.put("workflowStatusCounts", countBy(findings, "workflowStatus"));
        out.put("complianceStatusCounts", Map.of());
        out.put("recordStateCounts", countBy(findings, "recordState"));
        out.put("productCounts", countBy(findings, "productName"));
        out.put("resourceTypeCounts", resourceTypeCounts(findings));
        out.put("topResources", topResources(findings, 10));
        out.put("ageBuckets", ageBuckets(findings));
        out.put("findings", findings);
        return out;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> mapAlert(Map<String, Object> alert) {
        Map<String, Object> props = alert.get("properties") instanceof Map
                ? (Map<String, Object>) alert.get("properties") : Map.of();

        String severity = normalizeSeverity(str(props.get("severity")));
        String status = normalizeStatus(str(props.get("status")));

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", str(alert.get("name")));
        m.put("generatorId", str(props.get("alertType")));
        m.put("title", firstNonBlank(str(props.get("alertDisplayName")), str(props.get("alertType"))));
        m.put("description", str(props.get("description")));
        m.put("severity", severity);
        m.put("severityNormalized", severityScore(severity));
        m.put("productName", firstNonBlank(
                str(props.get("productName")),
                str(props.get("productComponentName")),
                "Microsoft Defender for Cloud"));
        m.put("companyName", firstNonBlank(str(props.get("vendorName")), "Microsoft"));
        m.put("awsAccountId", null);
        m.put("subscriptionId", extractSubscriptionId(str(alert.get("id"))));
        m.put("region", extractLocation(str(alert.get("id"))));
        m.put("createdAt", parseInstant(str(props.get("startTimeUtc"))));
        m.put("updatedAt", parseInstant(firstNonBlank(
                str(props.get("timeGeneratedUtc")),
                str(props.get("processingEndTimeUtc")),
                str(props.get("endTimeUtc")))));
        m.put("firstObservedAt", parseInstant(str(props.get("startTimeUtc"))));
        m.put("lastObservedAt", parseInstant(str(props.get("endTimeUtc"))));
        m.put("workflowStatus", status);
        m.put("recordState", "Dismissed".equalsIgnoreCase(str(props.get("status"))) ? "ARCHIVED" : "ACTIVE");
        m.put("complianceStatus", null);
        m.put("resources", mapResources(props));
        m.put("types", intentToTypes(str(props.get("intent"))));

        List<Map<String, Object>> remSteps = props.get("remediationSteps") instanceof List
                ? (List<Map<String, Object>>) props.get("remediationSteps") : null;
        if (remSteps != null && !remSteps.isEmpty()) {
            String text = remSteps.stream()
                    .map(o -> o == null ? "" : String.valueOf(o))
                    .filter(s -> !s.isBlank())
                    .collect(Collectors.joining("; "));
            Map<String, Object> rec = new LinkedHashMap<>();
            rec.put("text", text);
            rec.put("url", null);
            m.put("remediation", rec);
        } else if (props.get("remediationSteps") instanceof List<?> list && !list.isEmpty()) {
            String text = list.stream().map(String::valueOf).collect(Collectors.joining("; "));
            Map<String, Object> rec = new LinkedHashMap<>();
            rec.put("text", text);
            rec.put("url", null);
            m.put("remediation", rec);
        }
        return m;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> mapResources(Map<String, Object> props) {
        List<Map<String, Object>> out = new ArrayList<>();
        Object ids = props.get("resourceIdentifiers");
        if (ids instanceof List<?> list) {
            for (Object o : list) {
                if (o instanceof Map<?, ?> map) {
                    Map<String, Object> r = new LinkedHashMap<>();
                    r.put("id", firstNonBlank(
                            str(map.get("azureResourceId")),
                            str(map.get("aadTenantId")),
                            str(map.get("workspaceSubscriptionId")),
                            str(map.get("type"))));
                    r.put("type", firstNonBlank(str(map.get("type")), "Azure.Resource"));
                    r.put("region", null);
                    r.put("partition", "azure");
                    out.add(r);
                }
            }
        }
        String compromised = str(props.get("compromisedEntity"));
        if (!compromised.isBlank() && out.isEmpty()) {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("id", compromised);
            r.put("type", "Azure.Entity");
            r.put("region", null);
            r.put("partition", "azure");
            out.add(r);
        }
        return out;
    }

    private static String extractSubscriptionId(String resourceId) {
        if (resourceId == null) return null;
        String marker = "/subscriptions/";
        int i = resourceId.indexOf(marker);
        if (i < 0) return null;
        int start = i + marker.length();
        int end = resourceId.indexOf('/', start);
        return end < 0 ? resourceId.substring(start) : resourceId.substring(start, end);
    }

    private static String extractLocation(String resourceId) {
        if (resourceId == null) return null;
        String marker = "/locations/";
        int i = resourceId.indexOf(marker);
        if (i < 0) return null;
        int start = i + marker.length();
        int end = resourceId.indexOf('/', start);
        return end < 0 ? resourceId.substring(start) : resourceId.substring(start, end);
    }

    private static String normalizeSeverity(String s) {
        if (s == null || s.isBlank()) return "INFORMATIONAL";
        return switch (s.trim().toUpperCase()) {
            case "CRITICAL"      -> "CRITICAL";
            case "HIGH"          -> "HIGH";
            case "MEDIUM"        -> "MEDIUM";
            case "LOW"           -> "LOW";
            case "INFORMATIONAL", "INFO" -> "INFORMATIONAL";
            default              -> "INFORMATIONAL";
        };
    }

    private static int severityScore(String s) {
        return switch (s) {
            case "CRITICAL" -> 90;
            case "HIGH"     -> 70;
            case "MEDIUM"   -> 50;
            case "LOW"      -> 30;
            default          -> 10;
        };
    }

    private static String normalizeStatus(String s) {
        if (s == null || s.isBlank()) return "NEW";
        return switch (s.trim().toUpperCase()) {
            case "ACTIVE"    -> "NEW";
            case "RESOLVED"  -> "RESOLVED";
            case "DISMISSED" -> "SUPPRESSED";
            default           -> s.trim().toUpperCase();
        };
    }

    private static List<String> intentToTypes(String intent) {
        if (intent == null || intent.isBlank()) return List.of();
        return Arrays.stream(intent.split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .map(s -> "TTPs/" + s)
                .collect(Collectors.toList());
    }

    // ----- aggregations (mirror SecurityHubController) -----

    private static Map<String, Long> countBy(List<Map<String, Object>> findings, String key) {
        return findings.stream().collect(Collectors.groupingBy(
                f -> {
                    Object v = f.get(key);
                    return v == null || String.valueOf(v).isBlank() ? "UNKNOWN" : String.valueOf(v);
                },
                Collectors.counting()
        ));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Long> resourceTypeCounts(List<Map<String, Object>> findings) {
        Map<String, Long> out = new LinkedHashMap<>();
        for (Map<String, Object> f : findings) {
            List<Map<String, Object>> resources =
                    (List<Map<String, Object>>) f.getOrDefault("resources", List.of());
            for (Map<String, Object> r : resources) {
                String t = r.get("type") == null ? "Unknown" : String.valueOf(r.get("type"));
                out.merge(t, 1L, Long::sum);
            }
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> topResources(List<Map<String, Object>> findings, int limit) {
        record Key(String id, String type) {}
        Map<Key, long[]> agg = new LinkedHashMap<>();
        Map<Key, Map<String, Long>> perSev = new LinkedHashMap<>();

        for (Map<String, Object> f : findings) {
            String sev = String.valueOf(f.getOrDefault("severity", "INFORMATIONAL"));
            List<Map<String, Object>> resources =
                    (List<Map<String, Object>>) f.getOrDefault("resources", List.of());
            for (Map<String, Object> r : resources) {
                String id = r.get("id") == null ? "—" : String.valueOf(r.get("id"));
                String type = r.get("type") == null ? "—" : String.valueOf(r.get("type"));
                Key k = new Key(id, type);
                agg.computeIfAbsent(k, x -> new long[1])[0]++;
                perSev.computeIfAbsent(k, x -> new LinkedHashMap<>()).merge(sev, 1L, Long::sum);
            }
        }

        return agg.entrySet().stream()
                .sorted(Comparator.<Map.Entry<Key, long[]>>comparingLong(e -> e.getValue()[0]).reversed())
                .limit(limit)
                .map(e -> {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("id", e.getKey().id());
                    row.put("type", e.getKey().type());
                    row.put("count", e.getValue()[0]);
                    row.put("bySeverity", perSev.get(e.getKey()));
                    return row;
                })
                .collect(Collectors.toList());
    }

    private static Map<String, Long> ageBuckets(List<Map<String, Object>> findings) {
        Map<String, Long> out = new LinkedHashMap<>();
        out.put("lt_7d", 0L);
        out.put("7_30d", 0L);
        out.put("30_90d", 0L);
        out.put("gt_90d", 0L);
        Instant now = Instant.now();
        for (Map<String, Object> f : findings) {
            Object ts = f.getOrDefault("updatedAt", f.get("createdAt"));
            if (!(ts instanceof Instant when)) continue;
            long days = ChronoUnit.DAYS.between(when, now);
            if (days < 7)       out.merge("lt_7d",  1L, Long::sum);
            else if (days < 30) out.merge("7_30d",  1L, Long::sum);
            else if (days < 90) out.merge("30_90d", 1L, Long::sum);
            else                out.merge("gt_90d", 1L, Long::sum);
        }
        return out;
    }

    // ----- small helpers -----

    private static boolean isBlank(String s) { return s == null || s.isBlank(); }

    private static String str(Object o) { return o == null ? "" : String.valueOf(o); }

    private static String firstNonBlank(String... values) {
        for (String v : values) if (v != null && !v.isBlank()) return v;
        return "";
    }

    private static Instant parseInstant(String iso) {
        if (iso == null || iso.isBlank()) return null;
        try { return Instant.parse(iso); } catch (Exception e) { return null; }
    }

    private static Map<String, Object> err(String message) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("error", message);
        return m;
    }
}
