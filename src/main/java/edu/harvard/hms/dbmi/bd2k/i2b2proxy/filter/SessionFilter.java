/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package edu.harvard.hms.dbmi.bd2k.i2b2proxy.filter;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Map;
import java.util.regex.Pattern;

import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.JWTVerifyException;

/**
 * Creates a session filter for ensuring secure access
 * 
 * @author Jeremy R. Easton-Marks
 *
 */
@WebFilter(filterName = "session-filter", urlPatterns = { "/*" })
public class SessionFilter implements Filter {
	private String clientId;
	private String clientSecret;
	private String userField;

	@Inject
	private ServletContext context;

	@Override
	public void init(FilterConfig fliterConfig) throws ServletException {
		this.clientSecret = context.getInitParameter("client_secret");
		this.clientId = context.getInitParameter("client_id");
		this.userField = context.getInitParameter("userField");
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain fc)
			throws IOException, ServletException {

		String user = validateAuthorizationHeader((HttpServletRequest) req);

		if (user == null) {
			((HttpServletResponse) res)
					.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			res.getOutputStream().write(
					"{\"message\":\"Session is not authorized\"}".getBytes());
			res.getOutputStream().close();
			return;
		}

		HttpSession session = ((HttpServletRequest) req).getSession();
		session.setAttribute("user", user);

		fc.doFilter(req, res);
	}

	private String validateAuthorizationHeader(HttpServletRequest req) {
		String authorizationHeader = ((HttpServletRequest) req)
				.getHeader("Authorization");
		if (authorizationHeader != null) {
			try {

				String[] parts = authorizationHeader.split(" ");
				if (parts.length != 2) {
					return null;
				}

				String scheme = parts[0];
				String credentials = parts[1];
				String token = "";

				Pattern pattern = Pattern.compile("^Bearer$",
						Pattern.CASE_INSENSITIVE);
				if (pattern.matcher(scheme).matches()) {
					token = credentials;
				}

				byte[] secret = Base64.decodeBase64(this.clientSecret);
				Map<String, Object> decodedPayload = new JWTVerifier(secret,
						this.clientId).verify(token);

				return (String) decodedPayload.get(this.userField);

			} catch (InvalidKeyException | NoSuchAlgorithmException
					| IllegalStateException | SignatureException | IOException
					| JWTVerifyException e) {
				e.printStackTrace();
			}
		}
		return null;
	}

	@Override
	public void destroy() {

	}

}
