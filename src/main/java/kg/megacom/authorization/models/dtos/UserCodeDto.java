package kg.megacom.authorization.models.dtos;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Builder;
import lombok.Data;

import java.util.Date;
@Data
@Builder
public class UserCodeDto {

    private Long id;
    private UserDto user;
    private String code;
    @JsonFormat(pattern = "dd.MM.yyyy HH:mm:ss")
    private Date sentDate;
    @JsonFormat(pattern = "dd.MM.yyyy HH:mm:ss")
    private Date expirationDate;
    private boolean confirm;
}
