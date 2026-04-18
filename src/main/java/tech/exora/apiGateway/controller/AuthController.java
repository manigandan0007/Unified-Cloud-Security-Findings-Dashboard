package tech.exora.apiGateway.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class AuthController {

    @GetMapping("/auth/status")
    public Mono<Map<String, Object>> status(ServerWebExchange exchange) {
        return exchange.getPrincipal()
                .cast(OAuth2AuthenticationToken.class)
                .map(auth -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("authenticated", true);
                    m.put("user", auth.getName());
                    return m;
                })
                .defaultIfEmpty(buildAnonymousStatus());
    }

    private Map<String, Object> buildAnonymousStatus() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("authenticated", false);
        m.put("loginUrl", "/oauth2/authorization/azure");
        return m;
    }

    @GetMapping("/auth/me")
    public Mono<Map<String, Object>> me(ServerWebExchange exchange) {
        return exchange.getPrincipal()
                .cast(OAuth2AuthenticationToken.class)
                .map(auth -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("authenticated", true);
                    if (auth.getPrincipal() instanceof OidcUser oidc) {
                        out.put("name", oidc.getFullName());
                        out.put("preferredUsername", oidc.getPreferredUsername());
                        out.put("email", oidc.getEmail());
                        out.put("subject", oidc.getSubject());
                        out.put("claims", oidc.getClaims());
                    } else {
                        out.put("name", auth.getName());
                        out.put("attributes", auth.getPrincipal().getAttributes());
                    }
                    return out;
                });
    }

    @GetMapping("/groups")
    public Mono<Object> getGroups(@AuthenticationPrincipal Mono<OAuth2AuthenticationToken> authMono) {
        return authMono.map(auth -> {
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = (Map<String, Object>) auth.getPrincipal().getAttributes();
            Map<String, Object> result = new HashMap<>();
            result.put("user", auth.getPrincipal().getName());
            result.put("groups", claims.get("groups"));
            return result;
        });
    }

    @GetMapping("/group-names")
    public Mono<Map> getGroupNames(
            @RegisteredOAuth2AuthorizedClient("azure") OAuth2AuthorizedClient client) {

        String accessToken = client.getAccessToken().getTokenValue();

        WebClient graphClient = WebClient.builder()
                .baseUrl("https://graph.microsoft.com/v1.0")
                .defaultHeader("Authorization", "Bearer " + accessToken)
                .build();

        return graphClient
                .get()
                .uri("/me/memberOf")
                .retrieve()
                .bodyToMono(Map.class);
    }

    @GetMapping("/roles")
    public Mono<Object> getRoles(ServerWebExchange exchange) {
        return exchange.getPrincipal()
                .cast(OAuth2AuthenticationToken.class)
                .map(auth -> {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> claims = (Map<String, Object>) auth.getPrincipal().getAttributes();
                    Map<String, Object> result = new HashMap<>();
                    result.put("user", auth.getPrincipal().getName());
                    result.put("roles", claims.get("roles"));
                    return result;
                });
    }
}