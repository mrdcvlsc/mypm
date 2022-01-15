/*
 * The MIT License
 *
 * Copyright 2022 mrdcvlsc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package mypm;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class javahash{
	
	public static String SHA512Hash(String password)
	{
		return sha512(password);
	}

	public static String SHA512Hash(String password, int level){
		String hash = SHA512Hash(password);
		for(int i=0; i<level; ++i){
			hash = SHA512Hash(hash);
		}
		return hash;
	}
	private static String sha512(String password){
		MessageDigest sha = null;
		byte[] hash = null;

		try{
			sha = MessageDigest.getInstance("SHA-512");
			hash = sha.digest(password.getBytes("UTF-8"));
		}
		catch(NoSuchAlgorithmException | UnsupportedEncodingException e){
			System.err.println(e);
		}
		return convertToHex(hash);
	}

	private static String convertToHex(byte[] raw){
		StringBuffer sb = new StringBuffer();
		for(int i=0; i<raw.length; ++i){
			sb.append(Integer.toString((raw[i] & 0xff) + 0x100, 16).substring(1));
		}
		return sb.toString();
	}
}