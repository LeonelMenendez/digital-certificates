import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 * This class contains static methods that allow the management of
 * digital certificates under a public key infrastructure (PKI).
 *
 * @author Leonel Menendez
 */
public class CertificateService {

    public static final int KEY_SIZE_1024 = 1024;
    public static final int KEY_SIZE_2048 = 2048;
    public static final int KEY_SIZE_3072 = 3072;

    public static final String GENERATOR_ALGORITHM_DIFFIE_HELLMAN = "DiffieHellman";
    public static final String GENERATOR_ALGORITHM_DSA = "DSA";
    public static final String GENERATOR_ALGORITHM_RSA = "RSA";
    public static final String GENERATOR_ALGORITHM_EC = "EC";

    public static final String SIGNATURE_ALGORITHM_RSA = "NONEwithRSA";
    public static final String SIGNATURE_ALGORITHM_MD2_RSA = "MD2withRSA";
    public static final String SIGNATURE_ALGORITHM_MD5_RSA = "MD5withRSA";
    public static final String SIGNATURE_ALGORITHM_SHA1_RSA = "SHA1withRSA";
    public static final String SIGNATURE_ALGORITHM_SHA256_RSA = "SHA256withRSA";
    public static final String SIGNATURE_ALGORITHM_SHA384_RSA = "SHA384withRSA";
    public static final String SIGNATURE_ALGORITHM_SHA512_RSA = "SHA512withRSA";
    public static final String SIGNATURE_ALGORITHM_DSA = "NONEwithDSA";
    public static final String SIGNATURE_ALGORITHM_SHA1_DSA = "SHA1withDSA";
    public static final String SIGNATURE_ALGORITHM_ECDSA = "NONEwithECDSA";
    public static final String SIGNATURE_ALGORITHM_SHA1_ECDSA = "SHA1withECDSA";
    public static final String SIGNATURE_ALGORITHM_SHA256_ECDSA = "SHA256withECDSA";
    public static final String SIGNATURE_ALGORITHM_SHA384_ECDSA = "SHA384withECDSA";
    public static final String SIGNATURE_ALGORITHM_SHA512_ECDSA = "SHA512withECDSA";

    private static final String STANDARD_PKCS12 = "PKCS12";

    private static final String EXTENSION_PEM = ".pem";

    /**
     * Generate a <code>KeyPair</code> object that acts as a container for a private and public key.
     *
     * <p>The private key is generated in PKCS#8 format.
     * <p>The public key is generated in X.509 format.
     *
     * @param algorithm the algorithm with which the public and private key will be generated.
     * @param keySize   the key size with which the public and private key will be generated.
     * @return the <code>KeyPair</code> object generated with the generation algorithm and the key size.
     * @throws NoSuchAlgorithmException if the generation algorithm does not exist.
     */
    public static KeyPair generateKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    /**
     * Generate a file that stores the private key in PKCS#8 format.
     *
     * <p>PKCS#8 is a standard syntax for storing private key information.
     *
     * @param privateKey  the key to be stored in PKCS#8 format.
     * @param keyFilePath the path of the file where the private key will be stored in PKCS#8 format.
     * @throws IOException if an input or output exception occurred.
     */
    public static void generatePKCS8(PrivateKey privateKey, String keyFilePath) throws IOException {
        FileWriter fw = new FileWriter(new File(keyFilePath + EXTENSION_PEM));

        PKCS8Generator pkcs8 = new JcaPKCS8Generator(privateKey, null);
        JcaPEMWriter pemWriter = new JcaPEMWriter(fw);
        pemWriter.writeObject(pkcs8);
        pemWriter.flush();

        fw.close();
    }

    /**
     * Retrieve a private key stored in PKCS#8 format.
     *
     * @param keyFilePath the path of the file that stores the private key in PKCS#8 format.
     * @return the private key obtained from the file.
     * @throws IOException if an input or output exception occurred.
     * @see CertificateService#generatePKCS8
     */
    public static PrivateKey getPrivateKeyFromFile(String keyFilePath) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(keyFilePath));
        PEMParser pemParser = new PEMParser(br);
        PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
        KeyPair keyPair = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
        return keyPair.getPrivate();
    }

    /**
     * Generate the CSR (Certificate Signing Request) in PKCS#10 format.
     *
     * <p>A certificate signing request (also CSR or certification request) is a message sent from an
     * applicant to a certificate authority in order to apply for a digital identity certificate.
     *
     * <p>The CSR contains information (e.g. common name, organization, country) the Certificate
     * Authority (CA) will use to create your certificate. It also contains the public key that will be
     * included in your certificate and is signed with the corresponding private key.
     *
     * <p>PKCS#10 is a standard format for requesting X.509 certificates from the certification
     * authorities.
     *
     * @param certFilePath       the path of the file where the CSR will be stored in PKCS#10 format.
     * @param keyPair            the <code>KeyPair</code> object that contains the public and private
     *                           keys to use.
     * @param signatureAlgorithm the algorithm used to sign the content, using the private key.
     * @param C                  the two letters in ISO code of the country where the company or
     *                           organization is located.
     * @param O                  the legal name of the company or organization. This information must
     *                           match the full name of it.
     * @param CN                 the domain (or subdomain) name of the website. This information must
     *                           match the domain that visitors will enter when accessing the web.
     * @param CUIT               the CUIT, <i>without hyphens</i>, of the company or organization.
     * @return the certificate signing request (CSR) generated.
     * @throws OperatorCreationException if an error occurred while creating the <code>ContentSigner</code>.
     * @throws IOException               if an input or output exception occurred.
     */
    public static PKCS10CertificationRequest generatePKCS10(String certFilePath, KeyPair keyPair, String signatureAlgorithm, String C, String O, String CN, String CUIT) throws OperatorCreationException, IOException {
        String subject = "C=" + C + ",O=" + O + ",CN=" + CN + ",serialNumber=CUIT" + CUIT;

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(subject), keyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        FileWriter fw = new FileWriter(new File(certFilePath));

        JcaPEMWriter pemWriter = new JcaPEMWriter(fw);
        pemWriter.writeObject(csr);
        pemWriter.flush();

        fw.close();
        return csr;
    }

    /**
     * Retrieves a certificate signing request (CSR) stored in PKCS#10 format.
     *
     * @param CSRFilePath the path of the file that stores the CSR in PKCS#10 format.
     * @return the CSR obtained from the file.
     * @throws IOException if an input or output exception occurred.
     * @see CertificateService#generatePKCS10
     */
    public static PKCS10CertificationRequest getCSRFromFile(String CSRFilePath) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(CSRFilePath));
        PEMParser pp = new PEMParser(br);
        return (PKCS10CertificationRequest) pp.readObject();
    }

    /**
     * Retrieve an X.509 certificate stored in PEM format.
     *
     * <p>X.509 is a standard defining the format of public key certificates. It is defined by the
     * International Telecommunications Union's Standardization sector (ITU-T), and is based on ASN.1,
     * another ITU-T standard.
     *
     * @param certFilePath the path of the file that stores the X.509 certificate in PEM format.
     * @return the X.509 certificate obtained from the file.
     * @throws CertificateException if an exception occurred while trying to convert.
     * @throws IOException          if an input or output exception occurred.
     */
    public static Certificate getX509CertificateFromFile(String certFilePath) throws CertificateException, IOException {
        FileReader reader = new FileReader(certFilePath);
        PEMParser pem = new PEMParser(reader);

        X509CertificateHolder certHolder = (X509CertificateHolder) pem.readObject();
        Certificate X509Certificate = new JcaX509CertificateConverter().getCertificate(certHolder);

        pem.close();
        reader.close();

        return X509Certificate;
    }

    /**
     * Stores an X.509 certificate in PEM format and a private key in PKCS#8 format in a file in
     * PKCS#12 format.
     *
     * <p>PKCS #12 defines an archive file format for storing many cryptography objects as a single file.
     * It is commonly used to bundle a private key with its X.509 certificate or to bundle all the members
     * of a chain of trust.
     *
     * @param PKCS12Path   the path of the file where the X.509 certificate and the private key will be
     *                     stored in PKCS#12 format.
     * @param keyFilePath  the path of the file that stores the private key in PKCS#8 format. It must be
     *                     the one that was used to sign the CSR that was sent to the certification
     *                     authority to obtain the X.509 certificate.
     * @param certFilePath the path of the file that stores the X.509 certificate in PEM format.
     * @param alias        the alias to be used.
     * @param password     the password to be used.
     * @throws KeyStoreException        if there is no <code>Provider</code> that supports the implementation
     *                                  of <code>KeyStoreSpi</code> for the specified type, if the <code>KeyStore</code>
     *                                  was not initialized (loaded), if the indicated key cannot be protected or if the
     *                                  operation of the key to the indicated alias protecting it with the indicated
     *                                  password failed due to some other reason.
     * @throws CertificateException     if an exception occurred while trying to convert.
     * @throws NoSuchAlgorithmException if the algorithm used to verify the integrity of the keystore could not be found.
     * @throws IOException              if an input or output exception occurred.
     * @see CertificateService#generatePKCS8
     * @see CertificateService#generatePKCS10
     */
    public static void generatePKCS12(String PKCS12Path, String keyFilePath, String certFilePath, String alias, String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        PrivateKey privateKey = getPrivateKeyFromFile(keyFilePath);
        Certificate X509Certificate = getX509CertificateFromFile(certFilePath);

        KeyStore keyStore = KeyStore.getInstance(STANDARD_PKCS12);
        keyStore.load(null, null);
        keyStore.setKeyEntry(alias, privateKey, password.toCharArray(), new java.security.cert.Certificate[]{X509Certificate});

        keyStore.store(new FileOutputStream(PKCS12Path), password.toCharArray());
    }
}
