/*
 * Copyright (C) 2013 Pavel Stastny
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package cz.ceskaexpedice.k5.k5jaas.basic;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.Principal;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.json.JSONException;
import org.json.JSONObject;

import biz.sourcecode.base64Coder.Base64Coder;



public class K5LoginModule implements LoginModule {

	//public static final String KEY = "lname";
	
	public static final Logger LOGGER = Logger.getLogger(K5LoginModule.class.getName()); 
	
    private Subject subject;
    private CallbackHandler callbackhandler;

    private String loginAddress;

	private boolean logged;
	
	private String remoteLoginName;
	private String remotePassword;
	
	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String, ?> sharedState, Map<String, ?> options) {
		this.loginAddress = (String) options.get("loginPoint");
        this.subject = subject;
        this.callbackhandler = callbackHandler;

	}

	public static URLConnection openConnection(String urlString, String user,
			String pass) throws MalformedURLException, IOException {
		URL url = new URL(urlString);
		String userPassword = user + ":" + pass;
		String encoded = new String(Base64Coder.encode(userPassword.getBytes())); 
		URLConnection uc = url.openConnection();
		uc.setReadTimeout(1000);
		uc.setConnectTimeout(1000);
		uc.setRequestProperty ("Authorization", "Basic " + encoded);
		return uc;
	}

	public static void copyStreams(InputStream is, OutputStream os) throws IOException {
		byte[] buffer = new byte[8192];
		int read = -1;
		while((read = is.read(buffer)) > 0) {
			os.write(buffer, 0, read);
		}
	}

	
	@Override
	public boolean login() throws LoginException {
        try {
			NameCallback nmCallback = new NameCallback("Name");
			PasswordCallback pswdCallback = new PasswordCallback("Password", false);
			this.callbackhandler.handle(new Callback[] { nmCallback, pswdCallback });

			String loginName = nmCallback.getName();
			this.remoteLoginName = loginName;
			char[] pswd = pswdCallback.getPassword();
			this.remotePassword = new String(pswd); 
			URLConnection connection = openConnection(this.loginAddress, loginName, new String(pswd));
			InputStream is = connection.getInputStream();
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			copyStreams(is, bos);
			String str = new String(bos.toByteArray(), "UTF-8");
			JSONObject obj = new JSONObject(str);
			this.logged =  testLogged(obj);

			
        } catch (IOException e) {
			LOGGER.log(Level.SEVERE,e.getMessage(),e);
		} catch (UnsupportedCallbackException e) {
			LOGGER.log(Level.SEVERE,e.getMessage(),e);
		} catch (JSONException e) {
			LOGGER.log(Level.SEVERE,e.getMessage(),e);
		}

		return this.logged;
	}

	private boolean testLogged(JSONObject jsonRes) {
		boolean res = false;
		try {
			String lname = jsonRes.getString("lname");
			res = !lname.equals("not_logged");
		} catch (JSONException e) {
			LOGGER.log(Level.SEVERE,e.getMessage(),e);
		}
		return res;
	}

	@Override
	public boolean commit() throws LoginException {
		if (!this.logged)
            return false;
        associateUserPrincipal(this.subject, this.remoteLoginName, this.remotePassword);
        assignPrincipal(this.subject, new WebRole());

        return true;	
    }

	@Override
	public boolean abort() throws LoginException {
        return true;
	}

    public static void assignPrincipal(Subject subject, Principal principal) {
        if (!subject.getPrincipals().contains(principal)) {
            subject.getPrincipals().add(principal);
        }
    }
    

    public static void associateUserPrincipal(Subject subject, String remoteUser, String remotePass) {
        K5User user = new K5User();
        user.setRemoteName(remoteUser);
        user.setRemotePass(remotePass);
        assignPrincipal(subject, user);
    }


	@Override
	public boolean logout() throws LoginException {
        this.subject.getPrincipals().clear();
		return true;
	}

}
