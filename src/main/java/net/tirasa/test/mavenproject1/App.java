package net.tirasa.test.mavenproject1;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.okta.sdk.authc.credentials.TokenClientCredentials;
import com.okta.sdk.client.Client;
import com.okta.sdk.client.Clients;
import com.okta.sdk.impl.resource.DefaultUserBuilder;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.cxf.ext.logging.LoggingFeature;
import org.apache.cxf.jaxrs.client.JAXRSClientFactoryBean;
import org.apache.cxf.jaxrs.client.WebClient;

public class App {

    private static final String BASE_URL = "https://dev-800826.okta.com/";

    private static final String TOKEN = "003cjlaIP04zw_upWrm0zsKKRjBWMnx33pyDh2xFbt";

    private enum Algorithm {
        SHA256("SHA-256", 256 / 8),
        SHA512("SHA-512", 512 / 8);

        private final String name;

        private final int length;

        Algorithm(final String name, final int length) {
            this.name = name;
            this.length = length;
        }

        public String getName() {
            return name;
        }

        public int getLength() {
            return length;
        }
    }

    private static boolean passwordMatches(
            final Algorithm algorithm,
            final String plaintextPassword,
            final String storedPassword) throws Exception {
        // Base64-decode the stored value and take the first 256 bits
        // (SHA256_LENGTH) as the digest.
        byte[] saltBytes;
        byte[] digestBytes = new byte[algorithm.getLength()];
        int saltLength = 0;

        try {
            byte[] decodedBytes = Base64.getMimeDecoder().decode(storedPassword);

            saltLength = decodedBytes.length - algorithm.getLength();
            if (saltLength <= 0) {
                throw new Exception("Salt length: " + saltLength);
            }
            saltBytes = new byte[saltLength];
            System.arraycopy(decodedBytes, 0, digestBytes, 0, algorithm.getLength());
            System.arraycopy(decodedBytes, algorithm.getLength(), saltBytes, 0,
                    saltLength);
        } catch (Exception e) {
            throw e;
        }

        // Use the salt to generate a digest based on the provided plain-text value.
        int plainBytesLength = plaintextPassword.length();
        byte[] plainPlusSalt = new byte[plainBytesLength + saltLength];
        System.arraycopy(plaintextPassword.getBytes(), 0, plainPlusSalt, 0, plainBytesLength);
        System.arraycopy(saltBytes, 0, plainPlusSalt, plainBytesLength, saltLength);

        byte[] userDigestBytes;

        try {
            userDigestBytes = MessageDigest.getInstance(algorithm.getName()).digest(plainPlusSalt);
        } catch (Exception e) {
            e.printStackTrace();

            return false;
        } finally {
            Arrays.fill(plainPlusSalt, (byte) 0);
        }

        System.out.println("DIGEST:\t\t" + Hex.encodeHexString(digestBytes));
        System.out.println("USER:\t\t" + Hex.encodeHexString(userDigestBytes));

        return Arrays.equals(digestBytes, userDigestBytes);
    }

    private static void createUserViaREST(
            final String email,
            final String base64Salt,
            final String base64HashPlusSalt)
            throws JsonProcessingException {

        ObjectMapper mapper = new ObjectMapper();

        ObjectNode req = mapper.createObjectNode();

        ObjectNode profile = mapper.createObjectNode();
        profile.put("firstName", "Joe");
        profile.put("lastName", "Coder");
        profile.put("email", email);
        profile.put("login", email);
        req.set("profile", profile);

        ObjectNode hashNode = mapper.createObjectNode();
        hashNode.put("algorithm", "SHA-256");
        hashNode.put("salt", base64Salt);
        hashNode.put("saltOrder", "POSTFIX");
        hashNode.put("value", base64HashPlusSalt);

        ObjectNode password = mapper.createObjectNode();
        password.set("hash", hashNode);

        ObjectNode credentials = mapper.createObjectNode();
        credentials.set("password", password);
        req.set("credentials", credentials);

        JAXRSClientFactoryBean bean = new JAXRSClientFactoryBean();
        bean.setAddress(BASE_URL + "/api/v1/users?activate=false");
        bean.setFeatures(Arrays.asList(new LoggingFeature()));
        WebClient webClient = bean.createWebClient();

        Response response = webClient.
                header(HttpHeaders.AUTHORIZATION, "SSWS " + TOKEN).
                accept(MediaType.APPLICATION_JSON_TYPE).
                type(MediaType.APPLICATION_JSON_TYPE).
                post(mapper.writeValueAsString(req));
        System.out.println("RESPONSE:\t" + response.getStatus());
    }

    private static void createUserViaSDK(
            final String email,
            final String base64Salt,
            final String base64HashPlusSalt) {

        Client client = Clients.builder().
                setOrgUrl(BASE_URL).
                setClientCredentials(new TokenClientCredentials(TOKEN)).
                build();

        new DefaultUserBuilder().
                setFirstName("Joe").
                setLastName("Coder").
                setEmail(email).
                setSha512PasswordHash(
                        base64HashPlusSalt,
                        base64Salt, "POSTFIX").
                buildAndCreate(client);
    }

    public static void main(String[] args) throws DecoderException, Exception {
        String hashed =
                "e1NTSEE1MTJ9VkhjNnVrSXNUWkowNmFWd1dDOW5KR1ZORi9XeU0zRVJJYlYxelRTY205dnY0MFIrS1gvL0phOUxuVU5nbHZnQ2ludkZQMERpNmZRaVo2YWM1RHluYnhyaWNjb1k0VFhS";
//        String hashed = Base64.getMimeEncoder().encodeToString(
//                "{SSHA256}Zn4FC1Jvm5eZpBxkvlNwhSCl53plV9tH4Gvw2Jo5jZbaVabBSWT1dw==".getBytes());

        String input = "Welcome123";
//        String input = "Password1";

        String decoded = new String(Base64.getMimeDecoder().decode(hashed));
        System.out.println("DECODED:\t" + decoded);

        String base64HashPlusSalt = decoded.substring(decoded.indexOf('}') + 1);
        System.out.println("HASH + SALT:\t" + base64HashPlusSalt);

        String hexHashPlusSalt = Hex.encodeHexString(Base64.getMimeDecoder().decode(base64HashPlusSalt));
        System.out.println("HASH + SALT:\t" + hexHashPlusSalt);

        String hexHash = hexHashPlusSalt.substring(0, hexHashPlusSalt.length() - 16);
        System.out.println("HASH:\t\t" + hexHash);

        String base64Hash = Base64.getMimeEncoder().encodeToString(Hex.decodeHex(hexHash));
        System.out.println("HASH:\t\t" + base64Hash);

        String hexSalt = hexHashPlusSalt.substring(hexHashPlusSalt.length() - 16);
        System.out.println("SALT:\t\t" + hexSalt);

        String base64Salt = Base64.getMimeEncoder().encodeToString(Hex.decodeHex(hexSalt));
        System.out.println("SALT:\t\t" + base64Salt);

        System.out.println("MATCH?\t\t" + passwordMatches(Algorithm.SHA512, input, base64HashPlusSalt));

        //createUserViaREST("joe.coder32@example.com", base64Salt, base64HashPlusSalt);
        //createUserViaSDK("joe.coder32@example.com", base64Salt, base64HashPlusSalt);
    }
}
