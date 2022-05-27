package kg.megacom.authorization.services;

import kg.megacom.authorization.models.dtos.UserDto;
import org.springframework.security.core.userdetails.UserDetails;

public interface UserService {

    UserDto save(UserDto userDto);
    UserDto findById(Long id);
    UserDto findByEmail(String email);

}
