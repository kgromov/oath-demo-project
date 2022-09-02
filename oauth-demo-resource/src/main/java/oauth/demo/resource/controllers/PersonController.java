package oauth.demo.resource.controllers;

import com.github.javafaker.Address;
import com.github.javafaker.Demographic;
import com.github.javafaker.Faker;
import lombok.extern.slf4j.Slf4j;
import oauth.demo.resource.model.PersonAddress;
import oauth.demo.resource.model.PersonMetrics;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/person-service")
public class PersonController {

    @GetMapping("/address")
    @PreAuthorize("hasAnyAuthority('person:search', 'SCOPE_person:search')")
    public PersonAddress getPersonAddress(JwtAuthenticationToken authenticationToken) {
        Faker faker = new Faker();
        Address address = faker.address();
        log.info("Address = {}", address.fullAddress());
        return new PersonAddress(address);
    }

    @GetMapping("/metrics")
    @PreAuthorize("hasAuthority('SCOPE_person:metrics')")
    public PersonMetrics getPersonMetrics(JwtAuthenticationToken authenticationToken) {
        Faker faker = new Faker();
        Demographic demographic = faker.demographic();
        PersonMetrics personMetrics = new PersonMetrics(demographic);
        log.info("PersonMetrics = {}", personMetrics);
        return personMetrics;
    }
}
