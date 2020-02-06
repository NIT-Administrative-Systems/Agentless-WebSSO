package edu.northwestern.websso;

import java.io.IOException;
import java.net.URLEncoder;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * This class has dependencies on javax.servlet and org.apache.http We could store the users OpenAM session in our servers session. We can check that
 * and save on API calls.
 * 
 * @author bab4379
 *
 */
public class AuthenticationFilter implements Filter {

	// Configurable Properties

	// Value of the domain, this is likely environment specific. WebSSO supports DEV/QA/PROD
	private static String DOMAIN = "dev-websso.it.northwestern.edu";

	// Name of the openam realm you are logging into
	private static String REALM = "northwestern";

	// Name of the authentication tree used for LDAP authentication without MFA
	private static String LDAP_ONLY_TREE = "ldap-registry";

	// Name of the authentication tree used for LDAP AND MFA authentication
	private static String LDAP_AND_DUO_TREE = "ldap-and-duo";

	// Whether or not your application requires MFA (Duo)
	private static boolean MFA_REQUIRED = true;

	// Session recheck duration
	private static int SESSION_RECHECK_INTERVAL = 300000;

	// Name of the cookie that stores the OpenAM SSO Token
	private static String OPENAM_SSO_TOKEN = "nusso";

	// Name of the session key for storing the {@code SessionInfo} object that represents an authenticated user
	public static String SESSION_INFO_SESSION_KEY = "sessionKey";

	// Location of error page. In the case where an exception is thrown send the user here. If not specified they will
	// be sent to the Login page
	private static String ERROR_PAGE;

	// Non-Configurable properties, because adding these just seems like overkill
	// The WebSSO login page
	private static final String WEBSSO_LOGIN_URL = "https://%s/nusso/XUI/?realm=%s#login&authIndexType=service&authIndexValue=%s&goto=%s";

	// The URL for querying the OpenAM server.
	private static final String WEBSSO_IDENTITY_CONFIRMATION_URL = "https://%s/nusso/json/realms/root/realms/%s/sessions?_action=getSessionInfo";

	// Session Property returned by OpenAM that tells whether a person went through MFA or not
	private static final String DUO_SESSION_PROPERTY_NAME = "isDuoAuthenticated";

	private static final Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class.getName());

	private static final int OPENAM_REST_TIMEOUT_SECONDS = 6;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
		logger.trace("Entering {}.doFilter().", getClass().getName());

		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		SessionInfo sessionInfo = (SessionInfo) httpRequest.getSession().getAttribute(SESSION_INFO_SESSION_KEY);
		String netID = null;
		boolean isDuoAuthenticated = false;

		// Grab the cookies and look for the OpenAM SSO Token
		Cookie[] cookies = httpRequest.getCookies();
		String openAMssoToken = null;

		// Loop through the cookies until you find the cookie holding OpenAM SSO Token
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals(OPENAM_SSO_TOKEN)) {
					openAMssoToken = cookie.getValue();
					break;
				}
			}
		}

		// If the token exists they were validated by OpenAM at some point. If the session object doesn't exist or if it requires a recheck
		// We will want to call OpenAM to see if the token is still valid.
		if (openAMssoToken != null && (sessionInfo == null || !sessionInfo.isValid() || sessionInfo.requiresRecheck())) {
			logger.debug("Unable to find WebSSO token in the '{}' cookie.", OPENAM_SSO_TOKEN);

			// Validate the token and get the user details
			try {
				RequestConfig.Builder requestBuilder = RequestConfig.custom();

				// Set the timeout for this request in milliseconds
				requestBuilder = requestBuilder.setConnectTimeout(OPENAM_REST_TIMEOUT_SECONDS * 1000).setConnectionRequestTimeout(OPENAM_REST_TIMEOUT_SECONDS * 1000);
				HttpClient client = HttpClientBuilder.create().build();

				// This URL will call the getSessionInfo endpoint in OpenAM. If the token is invalid a 401
				// unauthorized will be returned
				String url = String.format(WEBSSO_IDENTITY_CONFIRMATION_URL, DOMAIN, REALM);

				HttpPost postRequest = new HttpPost(url);

				// You could import org.json libraries to do this
				JSONObject json = new JSONObject();
				json.put("tokenId", openAMssoToken);

				StringEntity input = new StringEntity(json.toString());
				postRequest.setEntity(input);

				// Apigee API key used for authentication on Apigee
				postRequest.addHeader("Accept-API-Version", "resource=3.1");
				postRequest.addHeader("Content-Type", MediaType.APPLICATION_JSON);

				HttpResponse webSSOResponse = client.execute(postRequest);

				String responseString = EntityUtils.toString(webSSOResponse.getEntity());

				// If this token is invalid or their session has expired this should return a 401
				if (webSSOResponse.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
					ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
					sessionInfo = mapper.readValue(responseString, SessionInfo.class);
					sessionInfo.setNextCheckTime(System.currentTimeMillis() + SESSION_RECHECK_INTERVAL);

					isDuoAuthenticated = sessionInfo.getBooleanProperty(DUO_SESSION_PROPERTY_NAME);
				}
			}
			catch (Exception e) {
				//This will redirect to the login page.  If they have a token, but for some reason an error occurred
				//while attempting to validate it this could cause infinite redirect loop of erroring/sending to OpenAm which
				//sends them back here.  Might need to add something to the session to keep track of this and break out of the cycle and send to ERROR_PAGE
				logger.error("An exception occured while trying to verify the WebSSO token.", e);
			}
		}

		// If we did not get the NetID or we require Duo and Duo was not performed then redirect the user to the WebSSO login page
		if (sessionInfo == null || !sessionInfo.isValid() || (MFA_REQUIRED && !isDuoAuthenticated)) {

			logger.debug("Requested URL = {}", httpRequest.getRequestURL());
			logger.debug("Query String = {}", httpRequest.getQueryString());

			String successURL = httpRequest.getRequestURL().toString();

			String queryParams = httpRequest.getQueryString();
			if (queryParams != null) {
				successURL = successURL + queryParams;
			}
			successURL = URLEncoder.encode(successURL, "UTF-8");

			String redirectURL = String.format(WEBSSO_LOGIN_URL, DOMAIN, REALM, (MFA_REQUIRED ? LDAP_AND_DUO_TREE : LDAP_ONLY_TREE), successURL);

			logger.debug("Login URL = {}", redirectURL);

			httpResponse.sendRedirect(redirectURL);
		}
		else {
			httpRequest.getSession().setAttribute(SESSION_INFO_SESSION_KEY, sessionInfo);

			try {
				// Success - return control
				logger.debug("{} successfully valid by OpenAM , allowing access to protected resources.", netID);
				filterChain.doFilter(request, response);
			}
			catch (Exception e) {
				if (ERROR_PAGE != null && !ERROR_PAGE.isEmpty()) {
					httpResponse.sendRedirect(ERROR_PAGE);
				}
				else {
					throw new ServletException("Unable to process at this time.");
				}
			}
		}
	}

	@Override
	public void destroy() {
		// Nothing to destroy
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {

		String domain = filterConfig.getInitParameter("domain");
		logger.debug("domain = {}", domain);
		if (domain != null && !domain.isEmpty()) {
			DOMAIN = domain;
		}

		String realm = filterConfig.getInitParameter("realm");
		logger.debug("realm = {}", realm);
		if (realm != null && !realm.isEmpty()) {
			REALM = realm;
		}

		String ldap_only_tree = filterConfig.getInitParameter("ldap_only_tree");
		logger.debug("ldap_only_tree = {}", ldap_only_tree);
		if (ldap_only_tree != null && !ldap_only_tree.isEmpty()) {
			LDAP_ONLY_TREE = ldap_only_tree;
		}

		String ldap_and_duo_tree = filterConfig.getInitParameter("ldap_and_duo_tree");
		logger.debug("ldap_and_duo_tree = {}", ldap_and_duo_tree);
		if (ldap_and_duo_tree != null && !ldap_and_duo_tree.isEmpty()) {
			LDAP_AND_DUO_TREE = ldap_and_duo_tree;
		}

		String mfa_required = filterConfig.getInitParameter("mfa_required");
		logger.debug("mfa_required = {}", mfa_required);
		if (mfa_required != null && !mfa_required.isEmpty()) {
			MFA_REQUIRED = Boolean.parseBoolean(mfa_required);
		}

		String session_info_key = filterConfig.getInitParameter("session_info_key");
		logger.debug("session_info_key = {}", session_info_key);
		if (session_info_key != null && !session_info_key.isEmpty()) {
			SESSION_INFO_SESSION_KEY = session_info_key;
		}

		String error_page = filterConfig.getInitParameter("error_page");
		logger.debug("error_page = {}", error_page);
		if (error_page != null && !error_page.isEmpty()) {
			ERROR_PAGE = error_page;
		}

		logger.debug("session_recheck_duration = {}", filterConfig.getInitParameter("session_recheck_duration"));
		try {
			int sessionRecheckInterval = Integer.parseInt(filterConfig.getInitParameter("session_recheck_duration"));
			SESSION_RECHECK_INTERVAL = sessionRecheckInterval * 1000;
		}
		catch (Exception e) {
			// Caught exception you default value
			logger.warn("session_recheck_duration of {} is not a valid int using default value of {}", filterConfig.getInitParameter("session_recheck_duration"), SESSION_RECHECK_INTERVAL);
		}
	}
}