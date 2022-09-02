package oauth.demo.client.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.URI;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@RestController
@RequestMapping("/person-flow")
@RequiredArgsConstructor
public class PersonFlowController {
    private final WebClient webClient;

    @GetMapping("/address")
    public Mono<String> callPersonAddress(@RegisteredOAuth2AuthorizedClient("address-client") OAuth2AuthorizedClient authorizedClient,
                                          OAuth2AuthenticationToken oauth2Authentication) {
        return this.webClient
                .get()
                .uri(URI.create("http://localhost:8090/person-service/address"))
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String.class);
    }
}
