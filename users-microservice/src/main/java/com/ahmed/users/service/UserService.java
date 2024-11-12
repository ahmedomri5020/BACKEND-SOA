package com.ahmed.users.service;

import com.ahmed.users.entities.Role;
import com.ahmed.users.entities.User;
import com.ahmed.users.service.register.RegistrationRequest;

public interface UserService {
	User saveUser(User user);
	User findUserByUsername (String username);
	Role addRole(Role role);
	User addRoleToUser(String username, String rolename);

	User registerUser(RegistrationRequest request);

	public void sendEmailUser(User u, String code);
	public User validateToken(String code);


}
