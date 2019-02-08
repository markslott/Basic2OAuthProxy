package com.salesforce.se.msl;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Abstract servlet class to extend the default HttpServlet to handle PATCH and HEAD verbs
 * @author Mark Lott
 */
public abstract class EnhancedHttpServlet extends HttpServlet {


	private static final long serialVersionUID = -5328512181188509050L;

	public void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		if (request.getMethod().equalsIgnoreCase("PATCH")) {
			doPatch(request, response);
		} else if (request.getMethod().equalsIgnoreCase("HEAD")) {
			doHead(request, response);
		} else {
			super.service(request, response);
		}
	}

	protected abstract void doPatch(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException;

	protected abstract void doHead(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException;

}
