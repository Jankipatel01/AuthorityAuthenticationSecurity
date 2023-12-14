package com.example.demo.controller;



import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import com.example.demo.Model.Authority;
import com.example.demo.Model.User;
import com.example.demo.Repository.AuthorityRepo;
import com.example.demo.Repository.UserRepo;

@Controller
public class UserController {
	@Autowired
	PasswordEncoder bcript;
	
	@Autowired
	public UserRepo urepo;
	
	
	@GetMapping("/home")
	public String home(Model model) {
		model.addAttribute("registrationForm", new User());
		model.addAttribute("loginForm", new User());
		return "home";
	}

	@GetMapping("/dashboard")
	public String dashboard(Model model) {

		return "dashboard";
	}
	
	@GetMapping("/superadminlanding")
	public String superadminlanding(Model model) {

		return "dashboard";
	}
	@GetMapping("/subadminlanding")
	public String subadminlanding(Model model) {

		return "dashboard";
	}
	

	@PostMapping("/login")
	public String login(Model model, @ModelAttribute("loginForm") User userForm) {
		System.out.println("in login post============");
		
		return	"redirect:/dashboard";
		//return "dashboard";
	}
	
	@Autowired
	AuthorityRepo aurepo;
	
	
	@PostMapping("/registration")
	public String registersave(Model model, @ModelAttribute("registrationForm") User userForm) {	
		
		Authority authority = new Authority();
		authority.setAuthority(userForm.getAuthority());
		authority.setUsername(userForm.getUsername());
		
		
		List<Authority> userAuthorities = new ArrayList<>();
	    userAuthorities.add(authority);

	    // Set the user's authorities
	    userForm.setAuthorities1(userAuthorities);
		
		
		userForm.setPassword(bcript.encode(userForm.getPassword()));
		urepo.save(userForm);				
		return "home";
	}
	
}
