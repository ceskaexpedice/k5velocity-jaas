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

import java.io.Serializable;
import java.security.Principal;

public class K5User implements Principal, Serializable {
	
	private static final String ROLE_NAME ="k5";
	
	private String remoteName;
	private String remotePass;
	public String getRemoteName() {
		return remoteName;
	}
	public void setRemoteName(String remoteName) {
		this.remoteName = remoteName;
	}
	public String getRemotePass() {
		return remotePass;
	}
	public void setRemotePass(String remotePass) {
		this.remotePass = remotePass;
	}
	@Override
	public String getName() {
		return ROLE_NAME;
	}
	
	

}
