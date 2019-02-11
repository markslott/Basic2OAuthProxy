package com.salesforce.se.msl;


import org.junit.jupiter.api.Test;

import com.salesforce.se.msl.Basic2OAuthProxy;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class TestBasic2OAuthProxy {
	
	
	/**
	 * test for proper response if no HTTP Basic Authorization header is provided to the servlet.
	 * Proper response is HTTP 401 with a standard error message
	 * @throws IOException
	 * @throws ServletException
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void testNoBasicAuthCreds() throws IOException, ServletException {
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);

        //set mock request headers
        Map<String, String> headers = new HashMap<String,String>();
        headers.put(null, "HTTP/1.1 200 OK");
        headers.put("Content-Type", "application/json");
        Iterator<String> iterator = headers.keySet().iterator();
        @SuppressWarnings("rawtypes")
		Enumeration headerNames = new Enumeration<String>() {
            @Override
            public boolean hasMoreElements() {
                return iterator.hasNext();
            }

            @Override
            public String nextElement() {
                return iterator.next();
            }
        };
        
        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(mockResponse.getWriter()).thenReturn(writer);
        when(mockRequest.getHeaderNames()).thenReturn(headerNames);
        
        new Basic2OAuthProxy().doGet(mockRequest, mockResponse);
        
        verify(mockResponse).addHeader("Content-Type","application/json;charset=UTF-8");
        verify(mockResponse).setStatus(401);
        assertTrue(stringWriter.toString().contains("[{\"error\":\"Must provide HTTP Basic Authentication header\"}]"));

	}
	
	
	/*
	 * To-dos - make test methods for the following:
	 * test Salesforce authorization flow - happy path
	 * test Salesforce authorixation flow - invalud credentials.
	 * test access token deletion if basic auth creds changed while access token is still alive
	 * 
	 */
	
}
