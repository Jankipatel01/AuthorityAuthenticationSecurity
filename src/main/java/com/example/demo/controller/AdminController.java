package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class AdminController {
	
	
	@GetMapping("/")
	String home() {		
		System.out.println("hello");
		return "home";
	}
	
	

	
}
