package com.products.UserMicroService.configs;

import com.products.UserMicroService.jwt.AuthEntryPointJwt;
import com.products.UserMicroService.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final DataSource dataSource;
    private final BCryptPasswordEncoder passwordEncoder;

    @Autowired
    AuthEntryPointJwt authEntryPointJwt;

    @Autowired
    public SecurityConfig(DataSource dataSource, BCryptPasswordEncoder passwordEncoder) {
        this.dataSource = dataSource;
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public SecurityFilterChain customSecurityFilterChainConfig(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests((requests) -> requests.requestMatchers("/api/signin","/h2-console/**").permitAll().anyRequest().authenticated()); //Permit hello endpoint without authentication.
        http.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); //Make APIs as stateless. without this our basic http filter maintaining session by cookies.
        http.exceptionHandling(exception-> exception.authenticationEntryPoint(authEntryPointJwt));
        //http.formLogin(Customizer.withDefaults()); //fault form login filter ignored.
        http.httpBasic(Customizer.withDefaults());   // popup login and postman kind of REST client basic filter enabled.
        http.csrf(AbstractHttpConfigurer::disable);    //cross site request forgery protection not needed,because now APIs are stateless,no cookies no session to share info to third party site.
        http.headers(headers->headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
        http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        return (SecurityFilterChain)http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new JdbcUserDetailsManager(dataSource);  //JDBCUserDetailsManager impl UserDetailsService indirectly.
        //return new InMemoryUserDetailsManager(user1, admin);
    }

    //CommandLiner is the Functional Interface with a function : run();
    // here we use that for just execute h2 initialization code while app starting.
    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService) {

        return (args)->  {
            JdbcUserDetailsManager userDetailsManager = (JdbcUserDetailsManager) userDetailsService;
            UserDetails user1 = User.withUsername("user1").password(passwordEncoder.encode("password")).roles("USER").build();
            UserDetails admin = User.withUsername("admin").password(passwordEncoder.encode("password")).roles("ADMIN").build();
            if(!userDetailsManager.userExists("user1"))
                userDetailsManager.createUser(user1);
            if(!userDetailsManager.userExists("admin"))
                userDetailsManager.createUser(admin);
        };
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public AuthTokenFilter authTokenFilter() {
        return new AuthTokenFilter();
    }
}
