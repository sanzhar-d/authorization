package kg.megacom.authorization.controllers;

import kg.megacom.authorization.models.request.LoginRequest;
import kg.megacom.authorization.models.request.SignInRequest;
import kg.megacom.authorization.models.response.JwtResponse;
import kg.megacom.authorization.services.AuthService;
import kg.megacom.authorization.utils.JwtUtils;
import kg.megacom.authorization.utils.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.Email;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping(value = "/api/auth")
@CrossOrigin
public class AuthController {

    @Autowired private AuthService authService;
    private AuthenticationManager authenticationManager;
    private PasswordEncoder passwordEncoder;
    @Autowired private JwtUtils jwtUtils;

    @PostMapping("/signIn")
    public ResponseEntity<?> signIn(@RequestBody SignInRequest signInRequest){
        return authService.signIn(signInRequest);
    }

    @PostMapping("/logIn")
    public ResponseEntity<?> logIn(@RequestBody LoginRequest loginRequest){
       System.out.println(loginRequest.getLogin());
        System.out.println(loginRequest.getPassword());
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getLogin(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateToken(authentication);
        System.out.println(jwt);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());
        return new ResponseEntity<>(JwtResponse.builder().jwt(jwt)
                                                          .name(userDetails.getUsername())
                                                          .email(userDetails.getUsername())
                                                          .roles(roles).build(), HttpStatus.OK);

        //return authService.logIn(login, password);
    }

    @GetMapping("/confirm")
    public ResponseEntity<?> confirm(@RequestParam  String email, @RequestParam String code){
        return authService.confirmation(email, code);
    }
}
