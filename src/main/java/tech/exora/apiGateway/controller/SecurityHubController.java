package tech.exora.apiGateway.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.securityhub.SecurityHubClient;
import software.amazon.awssdk.services.securityhub.model.AwsSecurityFinding;
import software.amazon.awssdk.services.securityhub.model.GetFindingsRequest;
import software.amazon.awssdk.services.securityhub.model.GetFindingsResponse;
import software.amazon.awssdk.services.securityhub.model.Resource;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/securityhub")
public class SecurityHubController {

    private static final int PAGE_SIZE = 100;
    private static final int HARD_CAP = 1000;

    public record CredsRequest(
            String accessKey,
            String secretKey,
            String sessionToken,
            String region,
            Integer maxResults
    ) {}

    @PostMapping("/findings")
    public Mono<ResponseEntity<Map<String, Object>>> findings(@RequestBody CredsRequest req) {
        return Mono.fromCallable(() -> fetchFindings(req))
                .subscribeOn(Schedulers.boundedElastic());
    }

    private ResponseEntity<Map<String, Object>> fetchFindings(CredsRequest req) {
        if (req == null || isBlank(req.accessKey()) || isBlank(req.secretKey())) {
            return ResponseEntity.badRequest().body(err("Access key and secret key are required."));
        }

        String region = isBlank(req.region()) ? "us-east-1" : req.region().trim();
        int totalCap = req.maxResults() != null
                ? Math.min(Math.max(req.maxResults(), 1), HARD_CAP)
                : 200;

        StaticCredentialsProvider creds = isBlank(req.sessionToken())
                ? StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(req.accessKey().trim(), req.secretKey().trim()))
                : StaticCredentialsProvider.create(
                        AwsSessionCredentials.create(
                                req.accessKey().trim(),
                                req.secretKey().trim(),
                                req.sessionToken().trim()));

        try (SecurityHubClient hub = SecurityHubClient.builder()
                .region(Region.of(region))
                .credentialsProvider(creds)
                .build()) {

            List<AwsSecurityFinding> all = new ArrayList<>();
            String nextToken = null;
            int pages = 0;
            do {
                int remaining = totalCap - all.size();
                if (remaining <= 0) break;
                int pageSize = Math.min(PAGE_SIZE, remaining);
                GetFindingsRequest.Builder rb = GetFindingsRequest.builder().maxResults(pageSize);
                if (nextToken != null) rb.nextToken(nextToken);
                GetFindingsResponse resp = hub.getFindings(rb.build());
                all.addAll(resp.findings());
                nextToken = resp.nextToken();
                pages++;
                if (pages > 20) break; // safety
            } while (nextToken != null && !nextToken.isBlank() && all.size() < totalCap);

            List<Map<String, Object>> findings = all.stream()
                    .map(this::mapFinding)
                    .collect(Collectors.toList());

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("region", region);
            out.put("count", findings.size());
            out.put("truncated", nextToken != null && !nextToken.isBlank());
            out.put("pages", pages);
            out.put("severityCounts", countBy(findings, "severity"));
            out.put("workflowStatusCounts", countBy(findings, "workflowStatus"));
            out.put("complianceStatusCounts", countBy(findings, "complianceStatus"));
            out.put("recordStateCounts", countBy(findings, "recordState"));
            out.put("productCounts", countBy(findings, "productName"));
            out.put("resourceTypeCounts", resourceTypeCounts(findings));
            out.put("topResources", topResources(findings, 10));
            out.put("ageBuckets", ageBuckets(findings));
            out.put("findings", findings);
            return ResponseEntity.ok(out);

        } catch (AwsServiceException ase) {
            int code = ase.statusCode() == 0 ? 502 : ase.statusCode();
            String detail = ase.awsErrorDetails() != null
                    ? ase.awsErrorDetails().errorCode() + " — " + ase.awsErrorDetails().errorMessage()
                    : ase.getMessage();
            return ResponseEntity.status(code).body(err("AWS: " + detail));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(err(
                    e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()));
        }
    }

    private Map<String, Object> mapFinding(AwsSecurityFinding f) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", f.id());
        m.put("generatorId", f.generatorId());
        m.put("title", f.title());
        m.put("description", f.description());
        m.put("severity", f.severity() != null && f.severity().label() != null
                ? f.severity().label().toString() : "INFORMATIONAL");
        m.put("severityNormalized", f.severity() != null ? f.severity().normalized() : 0);
        m.put("productName", nullIfBlank(f.productName()));
        m.put("companyName", nullIfBlank(f.companyName()));
        m.put("awsAccountId", f.awsAccountId());
        m.put("region", f.region());
        m.put("createdAt", f.createdAt());
        m.put("updatedAt", f.updatedAt());
        m.put("firstObservedAt", f.firstObservedAt());
        m.put("lastObservedAt", f.lastObservedAt());
        m.put("workflowStatus", f.workflow() != null && f.workflow().status() != null
                ? f.workflow().status().toString() : null);
        m.put("recordState", f.recordState() != null ? f.recordState().toString() : null);
        m.put("complianceStatus", f.compliance() != null && f.compliance().status() != null
                ? f.compliance().status().toString() : null);
        m.put("resources", f.resources() == null ? List.of()
                : f.resources().stream().map(this::mapResource).collect(Collectors.toList()));
        m.put("types", f.types() != null ? f.types() : List.of());
        if (f.remediation() != null && f.remediation().recommendation() != null) {
            Map<String, Object> rec = new LinkedHashMap<>();
            rec.put("text", f.remediation().recommendation().text());
            rec.put("url", f.remediation().recommendation().url());
            m.put("remediation", rec);
        }
        return m;
    }

    private Map<String, Object> mapResource(Resource r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", r.id());
        m.put("type", r.type());
        m.put("region", r.region());
        m.put("partition", r.partition() != null ? r.partition().toString() : null);
        return m;
    }

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
            List<Map<String, Object>> resources = (List<Map<String, Object>>) f.getOrDefault("resources", List.of());
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
            List<Map<String, Object>> resources = (List<Map<String, Object>>) f.getOrDefault("resources", List.of());
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
            if (days < 7)      out.merge("lt_7d",  1L, Long::sum);
            else if (days < 30) out.merge("7_30d",  1L, Long::sum);
            else if (days < 90) out.merge("30_90d", 1L, Long::sum);
            else                out.merge("gt_90d", 1L, Long::sum);
        }
        return out;
    }

    private static boolean isBlank(String s) { return s == null || s.isBlank(); }
    private static String nullIfBlank(String s) { return (s == null || s.isBlank()) ? null : s; }

    private static Map<String, Object> err(String message) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("error", message);
        return m;
    }
}