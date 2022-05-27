package kg.megacom.authorization.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin
@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/all")
    public String access(){
        return "All access";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('ADMIN') or hasRole('USER') or hasRole('MODERATOR')")
    public String userAccess(){
        return "User access";
    }

    @GetMapping("/moderator")
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderatorAccess(){
        return "Moderator access";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess(){
        return "Admin access";
    }
}
