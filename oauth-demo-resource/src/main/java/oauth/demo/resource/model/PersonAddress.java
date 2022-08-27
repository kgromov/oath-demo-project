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
    /*private String country;
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
*/
    @Delegate(types = Address.class)
    private Address address;
}
