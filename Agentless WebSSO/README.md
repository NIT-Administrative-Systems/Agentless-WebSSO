# Agentless WebSSO Examples
This repository contains an example implementations of Northwestern's webSSO authentication for OpenAM 6.5. It can also be "plugged-in" as is to provide WebSSO authentication to your java application.

We are happy to accept pull requests!

## Agentless?
This code implements a Servlet Filter which can be plugged into an application server like Tomcat.  It will intercept incoming
calls (based on the url pattern specified) and ensure the user making the call has a valid WebSSO session.  Additionaly, it also
optionally supports MFA via Duo.  

## Setup
To authenticate a webSSO session your app must be served from a `northwestern.edu` domain. This is because the webSSO cookie 
is only accessible to `*.northwestern.edu` and `northwestern.edu` itself.  To start enforcing WebSSO on your application add 
the following to you web.xml
```
	<filter>
		<filter-name>AuthenticationFilter</filter-name>
		<filter-class>edu.northwestern.websso.AuthenticationFilter</filter-class>
		<init-param>
			<param-name>mfa_required</param-name>
			<param-value>false</param-value>
		</init-param>
	</filter>
	<filter-mapping>
		<filter-name>AuthenticationFilter</filter-name>
		<url-pattern>/*</url-pattern>
	</filter-mapping>
```

### Configuration
There are several properties that can be configured.  Each property has a general purpose default that can be overridden via <init-param>'s on the filter.  m
The configurable properties are:
* domain - The instance of WebSSO to authenticate against.  Default: uat-websso.it.northwestern.edu
*	realm - The OpenAM authentication realm.  Default: northwestern
* ldap_only_tree - The name of the OpenAM authentication tree that only authenticates against LDAP.  Default: ldap-registry
* ldap_and_duo_tree - The name of the OpenAM authentication tree that uses LDAP and MFA (Duo)  Default: ldap-and-duo
* mfa_required - True or False indicating whether or not MFA (Duo) should be enforced.  Default: true
* session_info_key - Key name where the user's session information will be stored.  Default: sessionKey
* error_page - The fully qualified URL to redirect a user to in the case of an error (unrelated to access denied/credentials).  Default: WebSSO login page for the specified domain
* session_recheck_duration - Intervsl in minutes to re-validate a users OpenAM token.  Default: 5 minutes
		

## Beyond Authentication
WebSSO only gives you a netID. If you need directory information (e.g. name, email, staff/student/faculty status), you will 
need to use the [DirectorySearch service](https://apiserviceregistry.northwestern.edu). This beyond the scope of our humble 
demo repository.
