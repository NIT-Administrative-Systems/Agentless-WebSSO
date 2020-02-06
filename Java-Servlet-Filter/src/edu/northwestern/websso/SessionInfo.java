package edu.northwestern.websso;

import java.time.Clock;
import java.time.ZonedDateTime;
import java.util.Properties;

public class SessionInfo {

	private String username;
	private String universalId;
	private String realm;

	// Last time session was accessed in GMT
	private String latestAccessTime;

	// Idle timeout
	private String maxIdleExpirationTime;

	// When the session expires
	private String maxSessionExpirationTime;
	private Properties properties;
	private boolean valid = true;
	private long nextCheckTime = 0L;

	public SessionInfo() {

	}

	/**
	 * If the maxSessionExpirationTime has passed, or the maxIdleExpirationTime has passed, or
	 * 
	 * @return
	 */
	public boolean requiresRecheck() {
		long currentTime = System.currentTimeMillis();
		if (nextCheckTime > currentTime) {
			return false;
		}
		else {
			return true;
		}
	}

	public boolean isExpired() {
		// Check to see maxIdleExpirationTime has passed
		// LocalDateTime nowUTC = LocalDateTime.now();
		ZonedDateTime nowUTC = ZonedDateTime.now(Clock.systemUTC());
		ZonedDateTime maxSessionExpirationTimeUTC = ZonedDateTime.parse(maxSessionExpirationTime);
		if (nowUTC.isAfter(maxSessionExpirationTimeUTC)) {
			return true;
		}
		else {
			return false;
		}
	}

	public boolean isValid() {
		if (!valid || isExpired() || username == null) {
			return false;
		}
		else {
			return true;
		}
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

	public long getNextCheckTime() {
		return nextCheckTime;
	}

	public void setNextCheckTime(long nextCheckTime) {
		this.nextCheckTime = nextCheckTime;
	}

	public void invalidate() {
		valid = false;
		username = null;
	}
}