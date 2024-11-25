package com.ahmed.users.restControllers;

import java.util.List;

import com.ahmed.users.repos.UserRepository;
import com.ahmed.users.service.register.RegistrationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import com.ahmed.users.entities.User;
import com.ahmed.users.service.UserService;

@RestController
public class UserRestController {

	@Autowired
	UserRepository userRep;

	@Autowired
	UserService userService;

	@RequestMapping(path = "all",method = RequestMethod.GET)
	public List<User> getAllUsers() {
		return userRep.findAll();
	}


	@PostMapping("/register")
	public User register(@RequestBody RegistrationRequest request) {
		return userService.registerUser(request);

	}


	@GetMapping("/verifyEmail/{token}")
	public User verifyEmail(@PathVariable("token") String token){
		return userService.validateToken(token);
	}


}