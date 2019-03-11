package edu.northwestern.websso;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Properties;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;

/**
 * This class has dependancies on javax.servlet and org.apache.http
 * @author bab4379
 *
 */
public class AuthenticationFilter implements Filter {

	//The WebSSO login page
	private static final String WEBSSO_URL = "https://websso.it.northwestern.edu/amserver/UI/Login?goto=";

	//The key of the netid in the response body
	private static final String WEBSSO_NETID_KEY = "userdetails.attribute.value";

	//The URL for querying the OpenAM server.  Note the attributenames=uid  this limits or return results (since all we care about is netid) and allows for easier parsing 
	private static final String WEBSSO_IDENTITY_CONFIRMATION_URL = "https://websso.it.northwestern.edu/amserver/identity/attributes?attributenames=uid&subjectid=";

	//Name of the session key for storing the authenticated user
	public static final String IDS_PERSON_SESSION_KEY = "IDSPerson";

	//Name of the cookie that stores the OpenAM SSO Token 
	private static final String OPENAM_SSO_TOKEN = "openAMssoToken";

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		//Grab the cookies and look for the OpenAM SSO Token
		Cookie[] cookies = httpRequest.getCookies();
		String openAMssoToken = null;

		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals(OPENAM_SSO_TOKEN)) {
					openAMssoToken = cookie.getValue();
					break;
				}
			}
		}

		String netID = null;
		//If the token exists they were validated by OpenAM at some point
		if (openAMssoToken != null) {
			// Validate the token and get the user details
			try {
				RequestConfig.Builder requestBuilder = RequestConfig.custom();

				//Set the timeout for this request in milliseconds
				requestBuilder = requestBuilder.setConnectTimeout(6 * 1000).setConnectionRequestTimeout(6 * 1000);
				HttpClient client = HttpClientBuilder.create().build();
				HttpGet postReq = new HttpGet(WEBSSO_IDENTITY_CONFIRMATION_URL + openAMssoToken);

				HttpResponse resp = client.execute(postReq);

				//If this token is invalid or their session has expired this should return a 401
				if (resp.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
					Properties props = new Properties();
					props.load(new InputStreamReader((resp.getEntity().getContent())));
					netID = String.valueOf(props.get(WEBSSO_NETID_KEY));
				}
			}
			catch (Exception e) {
				//We could just direct them to websso again.  Or we could send them to an application specific error page?
				System.out.println("Error getting ID");
			}
		}

		//If we did not get the NetID redirect the user to the WebSSO login page
		if (netID == null) {
			// redirect to websso login
			System.out.println("URL = " + httpRequest.getRequestURL());

			String redirectURL = WEBSSO_URL + httpRequest.getRequestURL();
			String queryParams = httpRequest.getQueryString();
			if(queryParams != null) {
				redirectURL = redirectURL + queryParams;
			}

			httpResponse.sendRedirect(redirectURL);
		}
		else {
			httpRequest.getSession().setAttribute(IDS_PERSON_SESSION_KEY, netID);

			//Success - return control
			filterChain.doFilter(request, response);
		}
	}
}