package com.salesforce.se.msl;

public class BasicAuthCredential {
	
	private String username;
	private String password;
	
	
	protected BasicAuthCredential() {
		
	}
	
	protected BasicAuthCredential(String username, String password) {
		this.username = username;
		this.password = password;
	}
	
	protected String getUsername() {
		return this.username;
	}
	
	protected String getPassword() {
		return this.password;
	}
	
	protected void setUsername(String username) {
		this.username = username;
	}
	
	protected void setPassword(String password) {
		this.password = password;
	}

}
