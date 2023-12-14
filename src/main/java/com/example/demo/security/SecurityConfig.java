package com.example.demo.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.example.demo.Model.Authority;
import com.example.demo.Model.User;
import com.example.demo.Repository.UserRepo;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter implements AuthenticationFailureHandler,AuthenticationSuccessHandler{

	
	   @Autowired
	    private UserRepo userRepository;


   
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/public/**","/**").permitAll()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard").usernameParameter("username")
    	        .successHandler(this)  
    	        .failureHandler(this).permitAll()
                .and()
            .logout()
                .logoutSuccessUrl("/login?logout")
                .permitAll();
    }

	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		
		auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
	}
	  
	
	
	@Bean
	public UserDetailsService userDetailsService() {
	    return username -> {
	        User user = userRepository.findFirstByUsername(username);
	  
	        if (user != null) {
	        	 System.out.println(user.getUsername()+"=="+user.getPassword());
	        	
	            List<GrantedAuthority> authorities = new ArrayList<>();

	            // Extract and add authorities (roles) to the authorities list
	            for (Authority authority : user.getAuthorities1()) {
	                authorities.add(new SimpleGrantedAuthority(authority.getAuthority()));
	            }

	            System.out.println(user.getUsername()+"=="+user.getPassword()+authorities);
	            // Create UserDetails object with username, password, and authorities
	            UserDetails userDetails = new org.springframework.security.core.userdetails.User(
	                user.getUsername(), user.getPassword(), authorities
	            );

                return userDetails;
	            
	        } else {
	            throw new UsernameNotFoundException("User not found: " + username);
	        }
	    };
	}

 
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		
		System.out.println("hello on success"+authentication.getAuthorities());
		String targetUrl = determineTargetUrl(authentication);
		System.out.println("Target url :"+targetUrl+"");
		
		
		  RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
//		    redirectStrategy.sendRedirect(request, response, "/dashboard");		
			redirectStrategy.sendRedirect(request, response, targetUrl);
		
	}

	protected String determineTargetUrl(final Authentication authentication) {
	    Map<String, String> roleTargetUrlMap = new HashMap<>();
	    roleTargetUrlMap.put("superadmin", "/superadminlanding"); 
	    roleTargetUrlMap.put("subadmin", "/subadminlanding");
	    
	    final Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
	    String defaultTargetUrl = roleTargetUrlMap.get("both"); // Default value

	    for (final GrantedAuthority grantedAuthority : authorities) {
	        String authorityName = grantedAuthority.getAuthority();
	        if (roleTargetUrlMap.containsKey(authorityName)) {
	            // If the authority name is a key in the map, return the corresponding value
	            return roleTargetUrlMap.get(authorityName);
	        }
	    }

	    // If none of the authorities matched a key in the map, return the default value
	    return defaultTargetUrl;
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		System.out.println("hello on failure");
		System.out.println(exception.getLocalizedMessage());
		  RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
		    redirectStrategy.sendRedirect(request, response, "/home");
		
	}
}