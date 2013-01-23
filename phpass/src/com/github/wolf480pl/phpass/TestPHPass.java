package com.github.wolf480pl.phpass;

import junit.framework.Assert;
import junit.framework.TestCase;

import org.junit.Test;

public class TestPHPass extends TestCase {
    static final String correct = "test12345";
    static final String wrong = "test12346";
    static final String hash = "$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0";
    static final String correctpl = "ąćęłóńśźż";
    static final String wrongpl = "acelonszz";
    static final String hashpl = "$P$ByXWbzDvVAJ0jxvNp5sv4xYPIRXJJ1.";
    static final PHPass phpass = new PHPass(8);
    String hashed = phpass.HashPassword(correct);

    public static void main(String args[]) {
        junit.textui.TestRunner.run(TestPHPass.class);
    }

    @Test
    public final void testCheckPassword_correct() {
        boolean check = phpass.CheckPassword(correct, this.hashed);
        Assert.assertTrue(check);
    }

    @Test
    public final void testCheckPassword_wrong() {
        boolean check = phpass.CheckPassword(wrong, this.hashed);
        Assert.assertFalse(check);
    }

    @Test
    public final void testCheckPassword_givenhash_correct() {
        boolean check = phpass.CheckPassword(correct, hash);
        Assert.assertTrue(check);
    }

    @Test
    public final void testCheckPassword_givenhash_wrong() {
        boolean check = phpass.CheckPassword(wrong, hash);
        Assert.assertFalse(check);
    }

    @Test
    public final void testCheckPassword_nationalCharacters_correct() {
        boolean check = phpass.CheckPassword(correctpl, hashpl);
        assertTrue(check);
    }

    @Test
    public final void testCheckPassword_nationalCharacters_wrong() {
        boolean check = phpass.CheckPassword(wrongpl, hashpl);
        assertFalse(check);
    }

}
