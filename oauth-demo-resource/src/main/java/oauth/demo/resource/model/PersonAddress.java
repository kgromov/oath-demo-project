package oauth.demo.resource.model;

import com.github.javafaker.Address;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Delegate;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PersonAddress {
    private String country;
    private String state;
    private String city;
    private String secondaryAddress;
    private String streetName;
    private String zipCode;
    private String fullAddress;
    private String firstName;
    private String lastName;
    private String latitude;
    private String longitude;

    public PersonAddress(Address address) {
        this.country = address.country();
        this.state = address.state();
        this.city = address.city();
        this.zipCode = address.zipCode();
        this.streetName = address.streetName();
        this.secondaryAddress = address.secondaryAddress();
        this.fullAddress = address.fullAddress();
        this.latitude = address.latitude();
        this.longitude = address.longitude();
        this.firstName = address.firstName();
        this.lastName = address.lastName();
    }

    /*@Delegate(types = Address.class)
    private Address address;*/
}
