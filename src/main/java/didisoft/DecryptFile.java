package didisoft;

import com.didisoft.pgp.PGPLib;

public class DecryptFile {
    public static void main(String[] args) throws Exception{
        // initialize the library instance
        PGPLib pgp = new PGPLib();

        String privateKeyFile = "private-key.asc";
        String privateKeyPass = "12345678";

        // The decrypt method returns the original name of the file
        // that was encrypted. We can use it afterwards,
        // to rename OUTPUT.txt.
        String originalFileName = pgp.decryptFile("OUTPUT.pgp",
                privateKeyFile,
                privateKeyPass,
                "OUTPUT.txt");
    }
}