package net.capitalist;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.*;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.io.StringReader;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;



public class SignatureCreator {
    private static PrivateKey loadPrivate(String keyPemString, String cryptoProviderName ) throws GeneralSecurityException, IOException {
        PEMReader r = new PEMReader(new StringReader(keyPemString), null, cryptoProviderName);
        KeyPair caKeyPair = (KeyPair) r.readObject();
        if (caKeyPair == null) {
            throw new GeneralSecurityException("Reading CA private key failed");
        }
        return caKeyPair.getPrivate();
    }

    public static String getSignature(String keyPemString, String dataToSign,  String cryptoProviderName) throws Exception {
        RSAPrivateKey privateKey = (RSAPrivateKey) loadPrivate(keyPemString, cryptoProviderName);
        Signature engine = Signature.getInstance("SHA1WithRSA");
        engine.initSign(privateKey);

        engine.update(dataToSign.getBytes());
        byte[] signatureBytes = engine.sign();

        return new String(Base64.encode(signatureBytes));
    }

    public static void main(String[] args) throws Exception {

        String privKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIICXQIBAAKBgQCM2+ONZRzb9L7PawxTPQj1OMAFSQlDhxqjPqr5mGtsF8H1NOE8\n" +
                "oIRNQETM5VQDMPZVoJZG2sLLM/frFDb/9dlmRIbeHllhfjB+sc48sEzBbIRMnp0d\n" +
                "27sgaRixZOI0T15ZBqsIVFU8av1a05QsC/d8ikRIYO6yob0TIthut9sG9QIDAQAB\n" +
                "AoGBAIlD6v8qLrJmUd+dSPiAvQ8DC5Ta9K0apqm4czMiBmTizf9fVbMYFXWWkLU/\n" +
                "MdyeRR9yi59mpXcSIKG0JFjQwtX2Y4iHER1zx/x3EXZYeakT+U2goavCxBMZ1voz\n" +
                "UZA0wAixZaJrg7CkCQBRdRhBUsTIemJilrhSFEZhcX4wFiMBAkEA+2SDOVUuHXMf\n" +
                "0g82YVOkkwHtM5dAMg9NbUZbyy+zE5n/1XpGEuRGbJiA4cgqXbLDdiNzKUhX1LHk\n" +
                "KJTj69pCNQJBAI9wxdZ4nb4fef+++IswJowtNvYCyjEkQC6vQZfOZcY304MvpStw\n" +
                "OxKR56vwnOkWoyfH8iiV656F7r5ECmt2ScECQAyY2MqCrjDjl/Cauord+h0zt4Mi\n" +
                "TSE1Cxgysl7YIQ0WZm94FRLVRYIjkjG+KgFP9+Nvm1GyQlRyJZCzBUjIQxECQE2/\n" +
                "v8yPllkOcK9aERhI4iwK+gaA3p2iW5OydShWvL2jVud9tNaFv89B/MQq6LJDDe6r\n" +
                "Jywujwde61iAQvGarUECQQDh20IrxD9pJjd+03hf46H/dqSWMr2MZrdyxFlhRg8C\n" +
                "+sFf0zEdsZyU/IhDoNubFMaxdvfte8tMoIp0iDBpJWvd\n" +
                "-----END RSA PRIVATE KEY-----\n";

        //Default java crypto provider - SunRsaSign
        System.out.println(
                getSignature(privKey, "some:date:to:sign:123456", "SunRsaSign"));

        //Bouncy Castle Provider
        Security.addProvider(new BouncyCastleProvider());
        System.out.println(
                getSignature(privKey, "some:date:to:sign:123456", "BC"));

        //Encode password with given exponent and modulus
        System.out.println(net.capitalist.PasswordEncoder.encryptPassword("myPassword123",
                "10001",
                "ed6ba604e155bd1dd53079997ecb7580a6e4469d6b1100613a668d23209ab69db105c49422afb9ae5e8c7f59043222e5c483020fa714c38b08876eab8fbc71b753626dff58abc6212a707fc37a493a1e7104efdee0ce43c4e683da845def94218e68a7febf8972e4e609415ae179c60649c0ae9bc38457ae3db5d627b2d28789"));
    }
}
