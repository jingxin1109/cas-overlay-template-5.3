package com.jingxin.cas;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.login.FailedLoginException;

import org.apache.http.auth.AuthenticationException;
import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.MessageDescriptor;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;

public class MyAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler{

	public MyAuthenticationHandler(String name, ServicesManager servicesManager, PrincipalFactory principalFactory,
			Integer order) {
		super(name, servicesManager, principalFactory, order);
		// TODO Auto-generated constructor stub
	}

	@Override
	protected AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal(
			UsernamePasswordCredential credential, String originalPassword)
			throws GeneralSecurityException, PreventedException {
		String username = credential.getUsername();
		String password = credential.getPassword();
		
		if("123456".equals(password)) {
			List<MessageDescriptor> messages = new ArrayList<>();
			
			Map<String, Object> propMap = new HashMap<>();
			propMap.put("username", username);
			propMap.put("id", 123);
			
			return createHandlerResult(credential,
					this.principalFactory.createPrincipal(username,propMap),
					messages);
		} else {
			throw new FailedLoginException("密码错误");
		}
	}

}
