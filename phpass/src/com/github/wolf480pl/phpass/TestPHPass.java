package com.github.wolf480pl.phpass;


import org.junit.Test;

import junit.framework.TestCase;

public class TestPHPass extends TestCase {
	static String correct = "test12345";
	static String wrong = "test12346";
	static String hash = "$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0";
	static PHPass phpass = new PHPass(8, false);
	String hashed = phpass.HashPassword(correct);
	
	public static void main(String args[]){
		junit.textui.TestRunner.run(TestPHPass.class);
	}
	@Test
	public final void testCheckPassword_correct() {
//		String hashed = phpass.HashPassword(correct);
		boolean check = phpass.CheckPassword(correct, hashed);
		this.assertTrue(check);
	}
	@Test
	public final void testCheckPassword_wrong() {
//		String hashed = phpass.HashPassword(correct);
		boolean check = phpass.CheckPassword(wrong, hashed);
		this.assertFalse(check);
	}
	@Test
	public final void testCheckPassword_givenhash_correct() {
		boolean check = phpass.CheckPassword(correct, hash);
		this.assertTrue(check);
	}
	@Test
	public final void testCheckPassword_givenhash_wrong() {
		boolean check = phpass.CheckPassword(wrong, hash);
		this.assertFalse(check);
	}

}
