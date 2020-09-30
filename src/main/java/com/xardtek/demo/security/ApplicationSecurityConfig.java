package com.xardtek.demo.security;

import com.xardtek.demo.Auth.ApplicationUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.xardtek.demo.security.ApplicationUserRole.ADMIN;
import static com.xardtek.demo.security.ApplicationUserRole.ADMINTRAINEE;
import static com.xardtek.demo.security.ApplicationUserRole.STUDENT;

@Configuration
@EnableWebSecurity
//TODO -6 Remove this line if you choose to implement code level roles/authorizations
@EnableGlobalMethodSecurity(prePostEnabled = true)
//Add above line of code if you want to use code level annotation !
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //TODO -9 USE CSRF BY UNCOMMENTING BELOW
                //.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())  //Enable this line when usig with front-end framework(Angular,React etc) for form posting

                //TODO -1 REMOVE BELOW AND USE CODE ABOVE - FOR DEMO PURPOSES

                .csrf().disable() //Disable for Testing purposes
               // .and()
                .authorizeRequests() // Authorize Request
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll() // Permit all antMatchers above

                //TODO -5 Remove this line if you choose to implement code level roles/authorizations
                //  Commented out to enable code level annotation with PreAuthorize
                // .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission()) //COURSE_WRITE PERMISSIONS FOR USERS WITH AUTHORITY/PERMISSION
                // .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())//COURSE_WRITE PERMISSIONS FOR USERS WITH AUTHORITY/PERMISSION
                // .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())//COURSE_WRITE PERMISSIONS FOR USERS WITH AUTHORITY/PERMISSION
                // .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())//ADMINTRAINEE PERMISSIONS FOR USERS WITH ROLE

                .anyRequest()        //ALL ANY REQUEST THAT REACH THIS POINT
                .authenticated()    //USER MUST BE Authenticated
                .and()
                .formLogin() // FORM BASED AUTH NB: Requires HTTPS -> You can log out!!!!
                .loginPage("/login").permitAll() // Redirect to custom Login page!!
                .defaultSuccessUrl("/courses", true) //Redirect Page after Login
                //TODO -11, Feel free to modify if you want to have your own custom id for username txtbox & password txtbox
                .passwordParameter("password") //can be deleted, use here only for demo purposes
                .usernameParameter("username") // can be deleted, use here only for demo purposes

                .and()

                //TODO -2 Configure remember Me Token to Ideal Time, use either below or TO-DO 3
              //  .rememberMe() // Add Remember Me , Defaults to 2 Weeks!!!

                //TODO -3 A modified rememberMe Custom Wait Time, Use below line if you intend to use a custom duration
                .rememberMe().tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))  // Add Remember Me , Defaults to 2 Weeks, A modified rememberMe Wait Time!!!

                //TODO -4 A modified rememberMe Custom Wait Time, Use below line if you intend to use a custom duration
                .key("Uniquely-Generated-Key") //Generate Your Unique Key HERE instead of using spring-security-key
                .rememberMeParameter("remember-me") // can be deleted, use here only for demo purposes
                .and()
                .logout()
                .logoutUrl("/logout")

                //TODO -10 USE POST METHOD, ONCE YOU ENABLE CSRF IN TODO -9, YOU SHOULD DELETE LINE BELOW
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET"))
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID","remember-me")
                .logoutSuccessUrl("/login");
    }

    /* This part handles In-memory, JDBC, UserDetails Caching overriding httpBasic with
    autogenerated user =='user' and password =='auto generated encoded-password' !!!
    */

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

}
