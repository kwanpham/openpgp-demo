package didisoft;

import com.didisoft.pgp.PGPLib;

public class EncryptFile {
    public static void main(String[] args) throws Exception{
        // create an instance of the library
        PGPLib pgp = new PGPLib();

        // is output ASCII or binary
        boolean asciiArmor = false;
        // should integrity check information be added
        // set to true for compatibility with GnuPG 2.2.8+
        boolean withIntegrityCheck = false;

        pgp.encryptFile("INPUT.txt",
                "DCC1BD015C9C4A78086B10D3171008177430C9B9.asc",
                "OUTPUT.pgp",
                asciiArmor,
                withIntegrityCheck);
    }
}