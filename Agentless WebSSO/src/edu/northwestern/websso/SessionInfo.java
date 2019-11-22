package edu.northwestern.websso;

import java.util.Properties;

public class SessionInfo {

	private String username;
	private String universalId;
	private String realm;
	private String latestAccessTime;
	private String maxIdleExpirationTime;
	private String maxSessionExpirationTime;
	private Properties properties;
	private boolean valid = true;

	public boolean isValid() {
		return valid;
	}

	public void setValid(boolean valid) {
		this.valid = valid;
	}

	public SessionInfo() {

	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getUniversalId() {
		return universalId;
	}

	public void setUniversalId(String universalId) {
		this.universalId = universalId;
	}

	public String getRealm() {
		return realm;
	}

	public void setRealm(String realm) {
		this.realm = realm;
	}

	public String getLatestAccessTime() {
		return latestAccessTime;
	}

	public void setLatestAccessTime(String latestAccessTime) {
		this.latestAccessTime = latestAccessTime;
	}

	public String getMaxIdleExpirationTime() {
		return maxIdleExpirationTime;
	}

	public void setMaxIdleExpirationTime(String maxIdleExpirationTime) {
		this.maxIdleExpirationTime = maxIdleExpirationTime;
	}

	public String getMaxSessionExpirationTime() {
		return maxSessionExpirationTime;
	}

	public void setMaxSessionExpirationTime(String maxSessionExpirationTime) {
		this.maxSessionExpirationTime = maxSessionExpirationTime;
	}

	public Properties getProperties() {
		return properties;
	}

	public void setProperties(Properties properties) {
		this.properties = properties;
	}

	public String getProperty(String propertyName) {
		return properties.getProperty(propertyName);
	}

	public boolean getBooleanProperty(String propertyName) {
		String value = getProperty(propertyName);

		if ("true".equalsIgnoreCase(value) || "1".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value)) {
			return true;
		}
		else {
			return false;
		}
	}
}