package com.example.springsecurity;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.filter.CommonsRequestLoggingFilter;

@Configuration

public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public CommonsRequestLoggingFilter logFilter() {
        CommonsRequestLoggingFilter filter
                = new CommonsRequestLoggingFilter();
        filter.setIncludeQueryString(true);
        filter.setIncludePayload(true);
        filter.setMaxPayloadLength(10000);
        filter.setIncludeHeaders(false);
        filter.setAfterMessagePrefix("REQUEST DATA : ");
        return filter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .antMatchers(HttpMethod.GET, "/api/cars").hasAnyRole("ADMIN", "CARS")
                .antMatchers(HttpMethod.POST, "/api/cars").authenticated()
                .antMatchers("/api/users/**").hasAuthority("ROLE_USER_ADMIN")
                .anyRequest().permitAll()
                .and()
                .httpBasic()
                .and()
                .formLogin()
                .and()
                .logout()
                .and()
                .csrf().ignoringAntMatchers("/api/**","/h2/**")
                .and()
                .headers().frameOptions().disable()
        ;


    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin").roles("ADMIN", "CARS").password("{noop}Secret_123")
                .and()
                .withUser("admin2").authorities("ROLE_USER_ADMIN").password("{noop}Secret_123")
                .and()
                .withUser("admin3").roles("CARS").password("{noop}Secret_123")
        ;

    }
}
