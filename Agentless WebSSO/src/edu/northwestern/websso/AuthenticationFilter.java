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

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;


/**
 * This class has dependencies on javax.servlet and org.apache.http
 * @author bab4379
 *
 */
public class AuthenticationFilter implements Filter {


	private static final String DOMAIN = "dev-websso.it.northwestern.edu";
	
	private static final String REALM = "northwestern";
	
	private static final String LDAP_TREE = "ldap-registry";
	
	private static final String LDAP_AND_DUO_TREE = "ldap-and-duo";

	//The WebSSO login page
	private static final String WEBSSO_LOGIN_URL = "https://%s/nusso/XUI/?realm=%s#login&authIndexType=service&authIndexValue=%s&goto=%s";

	//The URL for querying the OpenAM server.   
	private static final String WEBSSO_IDENTITY_CONFIRMATION_URL = "https://%s/nusso/json/realms/root/realms/%s/sessions?_action=getSessionInfo";

	//Name of the session key for storing the authenticated user
	public static final String IDS_PERSON_SESSION_KEY = "IDSPerson";

	//Name of the cookie that stores the OpenAM SSO Token 
	private static final String OPENAM_SSO_TOKEN = "nusso";
	
	public static final String DUO_SESSION_PROPERTY_NAME = "isDuoAuthenticated";

	public static boolean needsDuo = true;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		//Grab the cookies and look for the OpenAM SSO Token
		Cookie[] cookies = httpRequest.getCookies();
		String openAMssoToken = null;

		//Loop through the cookies until you find the cookie holding OpenAM SSO Token 
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals(OPENAM_SSO_TOKEN)) {
					openAMssoToken = cookie.getValue();
					break;
				}
			}
		}

		String netID = null;
		boolean isDuoAuthenticated = false;

		//If the token exists they were validated by OpenAM at some point.  We will want to see if the token is still valid.
		if (openAMssoToken != null) {

			// Validate the token and get the user details
			try {
				RequestConfig.Builder requestBuilder = RequestConfig.custom();

				//Set the timeout for this request in milliseconds
				requestBuilder = requestBuilder.setConnectTimeout(6 * 1000).setConnectionRequestTimeout(6 * 1000);
				HttpClient client = HttpClientBuilder.create().build();

				//This URL will call the getSessionInfo endpoint in OpenAM.  If the token is invalid a 401 unauthorized will be returned
				String url = String.format(WEBSSO_IDENTITY_CONFIRMATION_URL, DOMAIN, REALM);

				HttpPost postRequest = new HttpPost(url);
				StringEntity input = new StringEntity("{ \"tokenId\" : \"" + openAMssoToken + "\" }");
				postRequest.setEntity(input);
		
				// Apigee API key used for authentication on Apigee
				postRequest.addHeader("Accept-API-Version", "resource=3.1");
				postRequest.addHeader("Content-Type", MediaType.APPLICATION_JSON);

				HttpResponse webSSOResponse = client.execute(postRequest);

				String responseString = EntityUtils.toString(webSSOResponse.getEntity());

				//If this token is invalid or their session has expired this should return a 401
				if (webSSOResponse.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
					ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
					SessionInfo sessionInfo = mapper.readValue(responseString, SessionInfo.class);

					netID = sessionInfo.getUsername();
					isDuoAuthenticated = sessionInfo.getBooleanProperty(DUO_SESSION_PROPERTY_NAME);
				}
			}
			catch (Exception e) {
				//We could just direct them to websso again.  Or we could send them to an application specific error page?
				System.out.println("Error getting ID");
			}
		}



		//If we did not get the NetID or we require Duo and Duo was not performed then redirect the user to the WebSSO login page
		//Determining that we were successfully authenticated based on the presence of the Net ID, this could be cleaner maybe?
		if (netID == null || (needsDuo && !isDuoAuthenticated)) {
			//redirect to websso login
			System.out.println("URL = " + httpRequest.getRequestURL());
			System.out.println("Query String = " + httpRequest.getQueryString());

			String successURL = httpRequest.getRequestURL().toString();
			
			String queryParams = httpRequest.getQueryString();
			if(queryParams != null) {
				successURL = successURL + queryParams;
			}
			successURL = URLEncoder.encode(successURL, "UTF-8" );

			String redirectURL = String.format(WEBSSO_LOGIN_URL, DOMAIN, REALM, (needsDuo ? LDAP_AND_DUO_TREE : LDAP_TREE), successURL);

			System.out.println("Login URL = " + redirectURL);

			httpResponse.sendRedirect(redirectURL);
		}
		else {
			httpRequest.getSession().setAttribute(IDS_PERSON_SESSION_KEY, netID);

			//Success - return control
			filterChain.doFilter(request, response);
		}
	}

	@Override
	public void destroy() {
		// TODO Auto-generated method stub
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		// TODO Auto-generated method stub
	}
}