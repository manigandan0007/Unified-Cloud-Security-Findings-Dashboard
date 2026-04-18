package tech.exora.apiGateway.controller;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Controller
public class HomeController {

    @GetMapping("/")
    public Mono<String> root(ServerWebExchange exchange) {
        return isAuthenticated(exchange)
                .map(authed -> authed ? "redirect:/dashboard" : "redirect:/login");
    }

    @GetMapping("/login")
    public Mono<String> login(
            @RequestParam(value = "logout", required = false) String logout,
            Model model,
            ServerWebExchange exchange) {

        model.addAttribute("logoutSuccess", "success".equals(logout));

        return isAuthenticated(exchange)
                .map(authed -> authed ? "redirect:/dashboard" : "login");
    }

    @GetMapping("/dashboard")
    public Mono<String> dashboard(Model model, ServerWebExchange exchange) {
        return exchange.getPrincipal()
                .cast(OAuth2AuthenticationToken.class)
                .map(auth -> {
                    Object principal = auth.getPrincipal();
                    String displayName = auth.getName();
                    String email = "";

                    if (principal instanceof OidcUser oidc) {
                        if (oidc.getFullName() != null && !oidc.getFullName().isBlank()) {
                            displayName = oidc.getFullName();
                        } else if (oidc.getPreferredUsername() != null) {
                            displayName = oidc.getPreferredUsername();
                        }
                        email = oidc.getEmail() != null ? oidc.getEmail()
                                : (oidc.getPreferredUsername() != null ? oidc.getPreferredUsername() : "");
                    }

                    model.addAttribute("name", displayName);
                    model.addAttribute("email", email);
                    return "dashboard";
                })
                .switchIfEmpty(Mono.just("redirect:/login"));
    }

    private Mono<Boolean> isAuthenticated(ServerWebExchange exchange) {
        return exchange.getPrincipal()
                .cast(OAuth2AuthenticationToken.class)
                .map(a -> Boolean.TRUE)
                .defaultIfEmpty(Boolean.FALSE);
    }
}