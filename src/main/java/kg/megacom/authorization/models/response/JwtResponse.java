package kg.megacom.authorization.models.response;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class JwtResponse {

    private String jwt;
    private Long userId;
    private String name;
    private String email;
    private List<String> roles;
}
