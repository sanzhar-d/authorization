package kg.megacom.authorization.config;

import kg.megacom.authorization.services.impl.UserDetailsServiceImpl;
import kg.megacom.authorization.utils.AuthEntryPointJwt;
import kg.megacom.authorization.utils.UserDetailsImpl;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@FieldDefaults(level = AccessLevel.PRIVATE)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired UserDetailsServiceImpl userDetailsService;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired CustomAuthorizationFilter filter;
    @Autowired AuthEntryPointJwt unauthorizedHandler;

//    @Bean
//    public CustomAuthorizationFilter filter(){
//        return  new CustomAuthorizationFilter();
//    }

    @Bean
    @Override
    public AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManagerBean();
    }

    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .cors()
                .and()
                .csrf().disable()
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler)
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
//                .antMatchers(
//                        "/v2/api-docs",
//                        "/configuration/ui",
//                        "/swagger-resources",
//                        "/configuration/security",
//                        "/swagger-ui.html",
//                        "/webjars/**",
//                        "/swagger-resources/configuration/ui",
//                        "/swagger-ui.html").permitAll()
                .antMatchers("/api/auth/**").permitAll()
                .antMatchers("/api/test/**").permitAll()
                .anyRequest().authenticated();

                http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);

    }
//    @Bean
//    public CorsConfigurationSource corsConfigurationSource(){
//        CorsConfiguration corsConfiguration = new CorsConfiguration();
//        corsConfiguration.setAllowedOrigins(Arrays.asList("http://localhost:8082"));
//        corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT"));
//        corsConfiguration.setAllowedHeaders(Arrays.asList("Content-Type", "Access-Control-Allow-Origin", "Access-Control-Allow-Headers", "Authorization", "X-Requested-With", "X-XSRF-TOKEN"));
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", corsConfiguration);
//        return source;
//    }


//    @Bean
//    public DaoAuthenticationProvider daoAuthenticationProvider(){
//        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
//        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
//        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
//        return daoAuthenticationProvider;
//    }
}
