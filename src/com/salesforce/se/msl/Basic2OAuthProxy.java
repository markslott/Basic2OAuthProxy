
// Copyright 2018, Mark Lott - Sales Engineering, Salesforce.com Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// - Redistributions of source code must retain the above copyright notice,
//   this list of conditions and the following disclaimer. 
// - Redistributions in binary form must reproduce the above copyright notice, 
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
// - Neither the name of the salesforce.com nor the names of its contributors
//   may be used to endorse or promote products derived from this software
//   without specific prior written permission. 
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package com.salesforce.se.msl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.oauth2.PasswordTokenRequest;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;

/**
 * *
 * 
 * Basic2OAuthProxy servlet
 * <p>
 * Simple HTTPS proxy for GET, POST, PUT, PATCH, and HEAD requests to the
 * Salesforce REST API. Allows access to the Salesforce REST API using a Basic
 * Auth header Useful for integrating apps that can not deal with an OAuth flow,
 * but can send credentials via HTTP Basic Auth.
 * 
 * Keep in mind that using this is not a good idea from a security practice
 * since passwords will flow on every API request and will be stored in the Java
 * heap on the application server. Use at your own risk! And be sure to disable
 * HTTP! Only use HTTPS!!!
 * </p>
 * 
 * @author Mark Lott
 */

@WebServlet("/Basic2OAuthProxy")
public class Basic2OAuthProxy extends EnhancedHttpServlet {

	private static final long serialVersionUID = -2022642324141260825L;
	private static final String TOKEN_SERVER_URL = "https://login.salesforce.com/services/oauth2/token";
	private static final String CLIENT_ID = System.getenv("CLIENT_ID");
	private static final String CLIENT_SECRET = System.getenv("CLIENT_SECRET");
	private static int TOKEN_LIFESPAN_MILLISECS;

	private static Header PRETTY_PRINT_HEADER = new BasicHeader("X-PrettyPrint", "1");

	private static final Logger logger = LogManager.getLogger(Basic2OAuthProxy.class);

	/**
	 * Contains a mapping of user id to Salesforce OAuth tokens
	 */
	protected static Hashtable<String, String> tokenMap = new Hashtable<String, String>();

	/**
	 * Contains a mapping of user id to SHA1 hashed passwords
	 * <p>
	 * Used to keep track if the basic auth password has changed since the access
	 * token was issued
	 * </p>
	 */
	protected static Hashtable<String, String> basicAuthHashMap = new Hashtable<String, String>();

	/**
	 * Default constructor.
	 */
	public Basic2OAuthProxy() {

		try {
			TOKEN_LIFESPAN_MILLISECS = Integer.parseInt(System.getenv("TOKEN_EXPIRATION_TIME_MILLISECONDS"));
		} catch (NumberFormatException e) {
			TOKEN_LIFESPAN_MILLISECS = 10000;
			logger.warn("TOKEN_EXPIRATION_TIME_MILLISECONDS is set to an invalid value: "
					+ System.getenv("TOKEN_EXPIRATION_TIME_MILLISECONDS") + ". Defaulting to "
					+ TOKEN_LIFESPAN_MILLISECS);
		}
		if (CLIENT_ID == null) {
			logger.error("CLIENT_ID is not set");
		}
		if (CLIENT_SECRET == null) {
			logger.error("CLIENT_SECRET is not set");
		}

	}

	/**
	 * Returns the access token for the user in the basic auth credential
	 * 
	 * @param cred Basic auth credentials
	 * @return
	 */
	private static synchronized String getAccessToken(BasicAuthCredential cred) {
		String token = tokenMap.get(cred.getUsername());
		if (token == null) {
			return null;
		} else {
			JSONObject jsonToken = new JSONObject(token);
			return jsonToken.getString("access_token");
		}
	}

	/**
	 * Returns the instance url from the Salesforce OAuth response object
	 * 
	 * @param cred Basic auth credentials
	 * @return
	 */
	private static synchronized String getInstanceURL(BasicAuthCredential cred) {
		String token = tokenMap.get(cred.getUsername());
		if (token == null) {
			return null;
		} else {
			JSONObject jsonToken = new JSONObject(token);
			return jsonToken.getString("instance_url");
		}
	}

	/**
	 * Uses Google OAuth library to make a token request to the Salesforce API
	 * <p>
	 * Uses the Salesforce Username/Password OAuth flow to request an access token
	 * Username/Password credentials are supplied via basic auth. If successful, the
	 * token is stored in the tokenMap for the user The token contains the access
	 * token and instance url returned from Salesforce in JSON format
	 * </p>
	 * 
	 * @param cred Basic auth credentials
	 * @throws IOException
	 * @throws TokenResponseException
	 */
	private static synchronized void requestAccessToken(BasicAuthCredential cred)
			throws IOException, TokenResponseException {

		TokenResponse response = new PasswordTokenRequest(new NetHttpTransport(), new JacksonFactory(),
				new GenericUrl(TOKEN_SERVER_URL), cred.getUsername(), cred.getPassword())
						.setClientAuthentication(new ClientParametersAuthentication(CLIENT_ID, CLIENT_SECRET))
						.execute();
		tokenMap.put(cred.getUsername(), response.toString());
		basicAuthHashMap.put(cred.getUsername(), DigestUtils.sha1Hex(cred.getPassword()));
		JSONObject j = new JSONObject(response.toString());
		logger.debug("Token : " + j.toString());

	}

	/**
	 * Check for a token in the tokenMap and sees if it has expired or not.
	 * <p>
	 * This method is called on every interaction to make sure the credentials are
	 * still valid. Since the access token is paired to a set of basic auth
	 * credentials, If the basic auth credentials have changed, then the access
	 * token needs to be deleted
	 * </p>
	 * 
	 * @param cred Basic auth credentials
	 * @return boolean True if the token for the user is valid, False if not
	 */
	private static synchronized boolean checkAccessToken(BasicAuthCredential cred)
			throws NoBasicAuthCredentialsException {
		if (cred == null) {
			throw new NoBasicAuthCredentialsException("Must provide HTTP Basic Authentication header");

		}
		String token = tokenMap.get(cred.getUsername());
		if (token == null) {
			return false;
		}
		if (!basicAuthHashMap.get(cred.getUsername()).equals(DigestUtils.sha1Hex(cred.getPassword()))) {
			// check to see if the password value for the user has changed. If it has,
			// delete the token
			// this is not a great design, but it works...
			tokenMap.remove(cred.getUsername());
			return false;
		} else {
			JSONObject jsonToken = new JSONObject(token);
			long timestamp = jsonToken.getLong("issued_at");
			long currenttime = System.currentTimeMillis();
			logger.debug("Comparing token vs current time: " + currenttime + " - " + timestamp + " = "
					+ (currenttime - timestamp));
			if (currenttime - timestamp > TOKEN_LIFESPAN_MILLISECS) {
				logger.debug("Reauthenticating");
				return false;
			}

		}
		return true;
	}

	/**
	 * Converts the basic authorization header to a BasicAuthCredential object
	 * 
	 * @param req Servlet request object
	 * @return BasicAuthCredential
	 */
	private BasicAuthCredential getBasicAuthCreds(HttpServletRequest req) {
		String authHeader = req.getHeader("Authorization");
		if (authHeader != null) {
			StringTokenizer st = new StringTokenizer(authHeader);
			if (st.hasMoreTokens()) {
				String basic = st.nextToken();
				if (basic.equalsIgnoreCase("Basic")) {
					try {
						String credentials = new String(Base64.getDecoder().decode(st.nextToken()), "UTF-8");
						int p = credentials.indexOf(":");
						if (p != -1) {
							String login = credentials.substring(0, p).trim();
							String password = credentials.substring(p + 1).trim();

							return new BasicAuthCredential(login, password);
						} else {
							logger.error("Invalid authentication token");
						}
					} catch (UnsupportedEncodingException e) {
						logger.error("Couldn't retrieve authentication" + e.getMessage());
						e.printStackTrace();
					}
				}
			}
		}
		return null;
	}

	/**
	 * Prints a standard HTTP log to logger
	 * 
	 * @param remoteAddress
	 * @param user
	 * @param verb
	 * @param uri
	 * @param statusCode
	 * @param contentLength
	 */
	private void printLogEntry(String remoteAddress, String user, String verb, String uri, int statusCode,
			int contentLength) {
		Date today = Calendar.getInstance().getTime();
		DateFormat df = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss z");
		String timestamp = df.format(today);
		logger.info(remoteAddress + " " + user + " [" + timestamp + "] " + "'" + verb + " " + uri + " HTTP/1.1' "
				+ statusCode + " " + contentLength);
	}

	/**
	 * Called by each doXXX method to authorize the user
	 * <p>
	 * Two step process- check the tokenMap object to see if the user already has an
	 * access token If there is no token, or it has expired, use the basic auth
	 * credentials to request a new access token.
	 * </p>
	 * 
	 * @param request  Servlet request object
	 * @param response Servlet response object. Used if there is an exception to the
	 *                 auth process so error can be presented to requestor
	 * @param cred     Basic auth credentials
	 * @return boolean True if there is a valid token available, False if not
	 * @throws IOException
	 */
	private boolean authorize(HttpServletRequest request, HttpServletResponse response, BasicAuthCredential cred)
			throws IOException {

		try {
			if (!checkAccessToken(cred)) {
				requestAccessToken(cred);
			}
		} catch (TokenResponseException e) {
			response.setStatus(401);
			response.addHeader("Content-Type", "application/json;charset=UTF-8");
			JSONArray jsonArray = new JSONArray();
			JSONObject jsonError = new JSONObject();

			logger.error("Auth error for " + cred.getUsername());
			logger.error(e.getDetails().getError());
			jsonError.put("error", e.getDetails().getError());

			if (e.getDetails().getErrorDescription() != null) {
				logger.error(e.getDetails().getErrorDescription());
				jsonError.put("description", e.getDetails().getErrorDescription());
			}
			if (e.getDetails().getErrorUri() != null) {
				logger.error(e.getDetails().getErrorUri());
				jsonError.put("uri", e.getDetails().getErrorUri());
			}
			jsonArray.put(jsonError);
			response.getWriter().append(jsonArray.toString());
			logger.error(jsonArray.toString());

			printLogEntry(request.getRemoteAddr(), cred.getUsername(), "POST", TOKEN_SERVER_URL, 401,
					jsonArray.toString().length());
			return false;

		} catch (NoBasicAuthCredentialsException e) {
			response.setStatus(401);
			response.addHeader("Content-Type", "application/json;charset=UTF-8");
			JSONArray jsonArray = new JSONArray();
			JSONObject jsonError = new JSONObject();
			jsonError.put("error", e.getMessage());
			jsonArray.put(jsonError);
			response.getWriter().append(jsonArray.toString());
			return false;
		}
		return true;
	}

	/**
	 * Copies the headers returned from the Salesforce API call to the response
	 * object
	 * 
	 * @param response        the HTTP response object that will go back to the
	 *                        requestor
	 * @param proxiedResponse the response object returned from the Salesforce API
	 *                        call
	 */
	private void setResponseHeaders(HttpServletResponse response, HttpResponse proxiedResponse) {
		Header[] headers = proxiedResponse.getAllHeaders();
		for (Header h : headers) {
			logger.debug(h.toString());
			if (!h.getName().contentEquals("Transfer-Encoding"))
				response.addHeader(h.getName(), h.getValue());

		}
	}

	/**
	 * Copies and relevant headers from the received request to the proxy request
	 * <p>
	 * Specifically copies over the content-type and accept headers from the
	 * incoming request and discards all others. It also sets the authorization
	 * header with the Salesforce access token
	 * </p>
	 * 
	 * @param request
	 * @param proxyRequest
	 * @param accessToken
	 */
	private void setProxiedRequestHeaders(HttpServletRequest request, HttpRequestBase proxyRequest,
			String accessToken) {
		@SuppressWarnings("rawtypes")
		Enumeration headerNames = request.getHeaderNames();
		while (headerNames.hasMoreElements()) {
			String name = (String) headerNames.nextElement();
			String value = request.getHeader(name);
			logger.debug(name + ":" + value);
			switch (name.toLowerCase()) {
			case "content-type":
			case "accept":
				proxyRequest.addHeader(new BasicHeader(name, value));
				break;
			}
		}
		BasicHeader oauthHeader = new BasicHeader("Authorization", "OAuth " + accessToken);
		proxyRequest.addHeader(oauthHeader);
		proxyRequest.addHeader(PRETTY_PRINT_HEADER);
	}

	/**
	 * Copies the request body received by the servlet to the proxied request call
	 * 
	 * @param request      servlet request that contains the incoming request
	 * @param proxyRequest outbound HTTP request (POST,PUT, or PATCH) that can have
	 *                     an entity associated with it
	 * @throws IOException
	 */
	private void setProxiedEntity(HttpServletRequest request, HttpEntityEnclosingRequestBase proxyRequest)
			throws IOException {
		StringBuilder buffer = new StringBuilder();
		BufferedReader reader = request.getReader();
		String line;
		while ((line = reader.readLine()) != null) {
			buffer.append(line);
		}
		proxyRequest.setEntity(new StringEntity(buffer.toString()));
	}

	/**
	 * Generates a URI to call the Salesforce REST API based on the URI passed into
	 * the servlet
	 * 
	 * @param cred    Basic Auth Credentials
	 * @param request Servlet HTTP request object
	 * @return URI for accessing the Salesforce REST API
	 */
	private String generateSalesforceRestURI(BasicAuthCredential cred, HttpServletRequest request) {
		String instanceURL = getInstanceURL(cred);
		String uri = request.getRequestURI().substring(request.getContextPath().length());
		String queryString = "";
		if (request.getQueryString() != null) {
			queryString = "?" + request.getQueryString();
		}
		return instanceURL + uri + queryString;
	}

	/**
	 * Proxy handler for HTTP GET
	 * <p>
	 * This method will retrieve or generate an access token based on the basic
	 * authentication credentials supplied, and proxy a GET request to the
	 * Salesforce REST API.
	 * </p>
	 * 
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		BasicAuthCredential cred = getBasicAuthCreds(request);
		boolean haveToken = authorize(request, response, cred);

		if (haveToken) {
			String sfdcURI = generateSalesforceRestURI(cred, request);
			HttpClient httpClient = HttpClientBuilder.create().build();
			HttpGet httpGet = new HttpGet(sfdcURI);

			setProxiedRequestHeaders(request, httpGet, getAccessToken(cred));

			HttpResponse proxiedResponse = httpClient.execute(httpGet);
			int statusCode = proxiedResponse.getStatusLine().getStatusCode();
			response.setStatus(statusCode);

			String response_string = proxiedResponse.getEntity() == null ? ""
					: EntityUtils.toString(proxiedResponse.getEntity());

			setResponseHeaders(response, proxiedResponse);
			printLogEntry(request.getRemoteAddr(), cred.getUsername(), "GET", sfdcURI, statusCode,
					response_string.length());
			response.getWriter().append(response_string);
		}
	}

	/**
	 * Proxy handler for HTTP HEAD
	 * <p>
	 * This method will retrieve or generate an access token based on the basic
	 * authentication credentials supplied, and proxy a HEAD request to the
	 * Salesforce REST API.
	 * </p>
	 * 
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	@Override
	protected void doHead(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		BasicAuthCredential cred = getBasicAuthCreds(request);
		boolean haveToken = authorize(request, response, cred);

		if (haveToken) {

			String sfdcURI = generateSalesforceRestURI(cred, request);
			HttpClient httpClient = HttpClientBuilder.create().build();
			HttpHead httpHead = new HttpHead(sfdcURI);

			setProxiedRequestHeaders(request, httpHead, getAccessToken(cred));

			HttpResponse proxiedResponse = httpClient.execute(httpHead);
			int statusCode = proxiedResponse.getStatusLine().getStatusCode();
			response.setStatus(statusCode);

			String response_string = proxiedResponse.getEntity() == null ? ""
					: EntityUtils.toString(proxiedResponse.getEntity());

			setResponseHeaders(response, proxiedResponse);
			printLogEntry(request.getRemoteAddr(), cred.getUsername(), "HEAD", sfdcURI, statusCode,
					response_string.length());
			response.getWriter().append(response_string);
		}
	}

	/**
	 * Proxy handler for HTTP POST
	 * <p>
	 * This method will retrieve or generate an access token based on the basic
	 * authentication credentials supplied, and proxy a POST request to the
	 * Salesforce REST API.
	 * </p>
	 * 
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		BasicAuthCredential cred = getBasicAuthCreds(request);
		boolean haveToken = authorize(request, response, cred);

		if (haveToken) {
			String sfdcURI = generateSalesforceRestURI(cred, request);
			HttpClient httpClient = HttpClientBuilder.create().build();
			HttpPost httpPost = new HttpPost(sfdcURI);

			setProxiedRequestHeaders(request, httpPost, getAccessToken(cred));
			setProxiedEntity(request, httpPost);

			HttpResponse proxiedResponse = httpClient.execute(httpPost);
			int statusCode = proxiedResponse.getStatusLine().getStatusCode();
			response.setStatus(statusCode);

			String response_string = proxiedResponse.getEntity() == null ? ""
					: EntityUtils.toString(proxiedResponse.getEntity());

			setResponseHeaders(response, proxiedResponse);
			printLogEntry(request.getRemoteAddr(), cred.getUsername(), "POST", sfdcURI, statusCode,
					response_string.length());
			response.getWriter().append(response_string);
		}
	}

	/**
	 * Proxy handler for HTTP DELETE
	 * <p>
	 * This method will retrieve or generate an access token based on the basic
	 * authentication credentials supplied, and proxy a DELETE request to the
	 * Salesforce REST API.
	 * </p>
	 * 
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	@Override
	protected void doDelete(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		BasicAuthCredential cred = getBasicAuthCreds(request);
		boolean haveToken = authorize(request, response, cred);

		if (haveToken) {
			String sfdcURI = generateSalesforceRestURI(cred, request);

			HttpClient httpClient = HttpClientBuilder.create().build();
			HttpDelete httpDelete = new HttpDelete(sfdcURI);
			setProxiedRequestHeaders(request, httpDelete, getAccessToken(cred));

			HttpResponse proxiedResponse = httpClient.execute(httpDelete);
			int statusCode = proxiedResponse.getStatusLine().getStatusCode();
			response.setStatus(statusCode);

			String response_string = proxiedResponse.getEntity() != null ? ""
					: EntityUtils.toString(proxiedResponse.getEntity());

			setResponseHeaders(response, proxiedResponse);
			printLogEntry(request.getRemoteAddr(), cred.getUsername(), "DELETE", sfdcURI, statusCode,
					response_string.length());
			response.getWriter().append(response_string);
		}
	}

	@Override
	/**
	 * Proxy handler for HTTP PUT
	 * <p>
	 * This method will retrieve or generate an access token based on the basic
	 * authentication credentials supplied, and proxy a PUT request to the
	 * Salesforce REST API.
	 * </p>
	 * 
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doPut(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		BasicAuthCredential cred = getBasicAuthCreds(request);
		boolean haveToken = authorize(request, response, cred);

		if (haveToken) {
			String sfdcURI = generateSalesforceRestURI(cred, request);

			HttpClient httpClient = HttpClientBuilder.create().build();
			HttpPut httpPut = new HttpPut(sfdcURI);

			setProxiedRequestHeaders(request, httpPut, getAccessToken(cred));
			setProxiedEntity(request, httpPut);

			HttpResponse proxiedResponse = httpClient.execute(httpPut);
			int statusCode = proxiedResponse.getStatusLine().getStatusCode();
			response.setStatus(statusCode);

			String response_string = proxiedResponse.getEntity() == null ? ""
					: EntityUtils.toString(proxiedResponse.getEntity());

			setResponseHeaders(response, proxiedResponse);
			printLogEntry(request.getRemoteAddr(), cred.getUsername(), "PUT", sfdcURI, statusCode,
					response_string.length());
			response.getWriter().append(response_string);
		}
	}

	/**
	 * Proxy handler for HTTP PATCH
	 * <p>
	 * This method will retrieve or generate an access token based on the basic
	 * authentication credentials supplied, and proxy a PATCH request to the
	 * Salesforce REST API.
	 * </p>
	 * 
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	@Override
	protected void doPatch(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		BasicAuthCredential cred = getBasicAuthCreds(request);
		boolean haveToken = authorize(request, response, cred);

		if (haveToken) {
			String sfdcURI = generateSalesforceRestURI(cred, request);

			HttpClient httpClient = HttpClientBuilder.create().build();
			HttpPatch httpPatch = new HttpPatch(sfdcURI);

			setProxiedRequestHeaders(request, httpPatch, getAccessToken(cred));
			setProxiedEntity(request, httpPatch);

			HttpResponse proxiedResponse = httpClient.execute(httpPatch);
			int statusCode = proxiedResponse.getStatusLine().getStatusCode();
			response.setStatus(statusCode);

			String response_string = proxiedResponse.getEntity() == null ? ""
					: EntityUtils.toString(proxiedResponse.getEntity());

			setResponseHeaders(response, proxiedResponse);
			printLogEntry(request.getRemoteAddr(), cred.getUsername(), "PATCH", sfdcURI, statusCode,
					response_string.length());
			response.getWriter().append(response_string);
		}
	}

}
