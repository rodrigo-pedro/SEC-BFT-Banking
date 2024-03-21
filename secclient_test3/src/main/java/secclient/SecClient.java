package secclient;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import secserver.grpc.SecServerServiceGrpc;
import secserver.grpc.Secserver.CheckAccountRequest;
import secserver.grpc.Secserver.CheckAccountResponse;
import secserver.grpc.Secserver.OpenAccountRequest;
import secserver.grpc.Secserver.OpenAccountResponse;
import secserver.grpc.Secserver.Payload;
import secserver.grpc.Secserver.ReceiveAmountRequest;
import secserver.grpc.Secserver.ReceiveAmountResponse;
import secserver.grpc.Secserver.SendAmountRequest;
import secserver.grpc.Secserver.SendAmountResponse;
import secserver.grpc.Secserver.SequenceNumberRequest;
import secserver.grpc.Secserver.SequenceNumberResponse;
import secserver.grpc.Secserver.AuditRequest;
import secserver.grpc.Secserver.AuditResponse;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

public class SecClient {
    private final PublicKey publicKey;
    private final PublicKey serverPublicKey;
    private final PrivateKey privateKey;
    private final ManagedChannel channel;
    private final SecServerServiceGrpc.SecServerServiceBlockingStub stub;
    private String password;

    private long sequenceNumber = 0;

    private int MAX_RETRIES = 3;

    public SecClient(String publicKeyPath, String keyStorePath, String password) throws InvalidKeySpecException,
            NoSuchAlgorithmException, IOException, UnrecoverableKeyException, KeyStoreException, CertificateException {
        this.password = password;
        publicKey = readPublicKey(publicKeyPath);
        privateKey = readPrivateKey(keyStorePath);
        serverPublicKey = readPublicKey("server_public.pem");
        this.channel = ManagedChannelBuilder.forTarget("localhost:8888").usePlaintext().build();
        this.stub = SecServerServiceGrpc.newBlockingStub(channel);
        sequenceNumber();
    }

    private boolean verifySignature(ByteString signatureBytes, Any data) throws Exception {
        Signature dsaForVerify = Signature.getInstance("SHA256withRSA");

        dsaForVerify.initVerify(serverPublicKey);
        dsaForVerify.update(data.toByteArray());
        return dsaForVerify.verify(signatureBytes.toByteArray());
    }

    private ByteString generateSignature(byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        Signature dsaForSign = Signature.getInstance("SHA256withRSA");
        dsaForSign.initSign(privateKey);
        dsaForSign.update(data);
        return ByteString.copyFrom(dsaForSign.sign());
    }

    private PublicKey readPublicKey(String publicKeyPath)
            throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        File file = new File(publicKeyPath);

        String key = Files.readString(file.toPath(), Charset.defaultCharset());

        String publicKeyPEM = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return keyFactory.generatePublic(keySpec);
    }

    private PrivateKey readPrivateKey(String keyStorePath) throws KeyStoreException, UnrecoverableKeyException,
            NoSuchAlgorithmException, IOException, CertificateException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keyStorePath), password.toCharArray());
        return (PrivateKey) ks.getKey("private", password.toCharArray());
    }

    public void sequenceNumber() {
        while (true) {
            try {
                SequenceNumberRequest seqRequest = SequenceNumberRequest.newBuilder()
                        .setPublicKey(ByteString.copyFrom(publicKey.getEncoded())).build();
                Any request = Any.pack(seqRequest);

                Payload payload = Payload.newBuilder()
                        .setMessage(request)
                        .setDigitalSignature(generateSignature(request.toByteArray()))
                        .build();

                Payload responsePayload = stub.withDeadlineAfter(5, TimeUnit.SECONDS).sequenceNumber(payload);

                boolean result = verifySignature(responsePayload.getDigitalSignature(), responsePayload.getMessage());

                if (result) {
                    this.sequenceNumber = responsePayload.getMessage().unpack(SequenceNumberResponse.class).getSeqNum()
                            + 1L;
                    return;
                }

            } catch (Exception e) {

            }
        }
    }

    public void openAccount() throws Exception {
        for (int i = 0; i < MAX_RETRIES; i++) {
            try {
                Any request = Any.pack(OpenAccountRequest.newBuilder().setSeqNum(this.sequenceNumber)
                        .setPublicKey(ByteString.copyFrom(publicKey.getEncoded())).build());

                Payload requestPayload = Payload.newBuilder()
                        .setMessage(request)
                        .setDigitalSignature(generateSignature(request.toByteArray()))
                        .build();
                Payload response = stub.withDeadlineAfter(5, TimeUnit.SECONDS).openAccount(requestPayload);
                boolean result = verifySignature(response.getDigitalSignature(), response.getMessage());
                if (result) {

                    OpenAccountResponse parsedResponse = response.getMessage().unpack(OpenAccountResponse.class);

                    if (this.sequenceNumber == parsedResponse.getSeqNum()) {
                        this.sequenceNumber++;
                        if (!parsedResponse.getSuccess())
                            System.out.println(parsedResponse.getErrorMessage());
                        else
                            System.out.println("Account opened");

                        return;
                    }
                }
            } catch (StatusRuntimeException e) {
                if (e.getStatus().getCode() != Status.Code.DEADLINE_EXCEEDED) {
                    System.out.println(e.getMessage());
                    return;
                }

            } catch (Exception e) {
                System.out.println(e.getMessage());
                return;
            }
        }
        System.out.println("Server is not responding");
    }

    public void sendAmount(String destinationPublicKeyPath, int amount) {

        for (int i = 0; i < MAX_RETRIES; i++) {
            try {

                Any request = Any.pack(SendAmountRequest.newBuilder()
                        .setSeqNum(this.sequenceNumber)
                        .setPublicKeyDestination(
                                ByteString.copyFrom(readPublicKey(destinationPublicKeyPath).getEncoded()))
                        .setPublicKeySource(ByteString.copyFrom(publicKey.getEncoded())).setAmount(amount).build());

                Payload requestPayload = Payload.newBuilder()
                        .setMessage(request)
                        .setDigitalSignature(generateSignature(request.toByteArray())).build();
                Payload response = stub.withDeadlineAfter(5, TimeUnit.SECONDS).sendAmount(requestPayload);
                boolean result = verifySignature(response.getDigitalSignature(), response.getMessage());

                if (result) {

                    SendAmountResponse parsedResponse = response.getMessage().unpack(SendAmountResponse.class);

                    if (this.sequenceNumber == parsedResponse.getSeqNum()) {
                        if (!parsedResponse.getSuccess())
                            System.out.println(parsedResponse.getErrorMessage());
                        else
                            System.out.println("Money sent successfully");

                        return;
                    }
                }
            } catch (StatusRuntimeException e) {
                if (e.getStatus().getCode() != Status.Code.DEADLINE_EXCEEDED) {
                    System.out.println(e.getMessage());
                    return;
                }

            } catch (Exception e) {
                System.out.println(e.getMessage());
                return;
            }

        }
        System.out.println("Server is not responding");
    }
        
    

    public void checkAccount() throws Exception {
        for (int i = 0; i < MAX_RETRIES; i++) {
            try {
                Any request = Any.pack(CheckAccountRequest.newBuilder().setSeqNum(this.sequenceNumber)
                        .setPublicKey(ByteString.copyFrom(publicKey.getEncoded())).build());

                Any request2 = Any.pack(CheckAccountRequest.newBuilder().setSeqNum(this.sequenceNumber + 1)
                    .setPublicKey(ByteString.copyFrom(publicKey.getEncoded())).build());

                Payload requestPayload = Payload.newBuilder()
                        .setMessage(request2)
                        .setDigitalSignature(generateSignature(request.toByteArray()))
                        .build();


                        
                Payload response = stub.withDeadlineAfter(5, TimeUnit.SECONDS).checkAccount(requestPayload);
                boolean result = verifySignature(response.getDigitalSignature(), response.getMessage());
                if (result) {
                    CheckAccountResponse parsedResponse = response.getMessage().unpack(CheckAccountResponse.class);

                    if (this.sequenceNumber == parsedResponse.getSeqNum()) {
                        this.sequenceNumber++;
                        if (!parsedResponse.getSuccess())
                            System.out.println(parsedResponse.getErrorMessage());
                        else {
                            System.out.println("Current balance: " + parsedResponse.getBalance());
                            System.out.println("Transaction list:");
                            for (var entry : parsedResponse.getIncomingList()) {
                                System.out.println(
                                        "From: " + Base64.getEncoder().encodeToString(entry.getPublicKeySource().toByteArray())
                                                + "\nAmount: " + entry.getAmount());
                            }
                        }
        
                        return;
                    }
                }
            } catch (StatusRuntimeException e) {
                if (e.getStatus().getCode() != Status.Code.DEADLINE_EXCEEDED) {
                    System.out.println(e.getMessage());
                    return;
                }

            } catch (Exception e) {
                System.out.println(e.getMessage());
                return;
            }
        }

        System.out.println("Server is not responding");

    }

    public void receiveAmount() {
        for (int i = 0; i < MAX_RETRIES; i++) {
            try {
                Any request = Any.pack(ReceiveAmountRequest.newBuilder().setSeqNum(this.sequenceNumber)
                        .setPublicKey(ByteString.copyFrom(publicKey.getEncoded())).build());
                Payload requestPayload = Payload.newBuilder()
                        .setMessage(request)
                        .setDigitalSignature(generateSignature(request.toByteArray()))
                        .build();

                Payload response = stub.withDeadlineAfter(5, TimeUnit.SECONDS).receiveAmount(requestPayload);
                boolean result = verifySignature(response.getDigitalSignature(), response.getMessage());
                if (result) {
                    ReceiveAmountResponse parsedResponse = response.getMessage().unpack(ReceiveAmountResponse.class);
    
                    if (this.sequenceNumber == parsedResponse.getSeqNum()) {
                        this.sequenceNumber++;
                        if (!parsedResponse.getSuccess())
                            System.out.println(parsedResponse.getErrorMessage());
                        else
                            System.out.println("Received all the incoming money from pending transactions.");
                        return;
                    }
                }
            } catch (StatusRuntimeException e) {
                if (e.getStatus().getCode() != Status.Code.DEADLINE_EXCEEDED) {
                    System.out.println(e.getMessage());
                    return;
                }

            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }
        System.out.println("Server is not responding");

    }

    public void audit() {
        for (int i = 0; i < MAX_RETRIES; i++) {
            try {
                Any request = Any.pack(AuditRequest.newBuilder().setSeqNum(this.sequenceNumber)
                        .setPublicKey(ByteString.copyFrom(publicKey.getEncoded())).build());
                Payload requestPayload = Payload.newBuilder()
                        .setMessage(request)
                        .setDigitalSignature(generateSignature(request.toByteArray()))
                        .build();

                Payload response = stub.withDeadlineAfter(5, TimeUnit.SECONDS).audit(requestPayload);
                boolean result = verifySignature(response.getDigitalSignature(), response.getMessage());

                if (result) {

                    AuditResponse parsedResponse = response.getMessage().unpack(AuditResponse.class);

                    if (this.sequenceNumber == parsedResponse.getSeqNum()) {
                        this.sequenceNumber++;
                        if (!parsedResponse.getSuccess()) 
                            System.out.println(parsedResponse.getErrorMessage());
                        else
                            parsedResponse.getAuditsList().forEach(x -> System.out.println(x));
                        return;
                    }
                }
            } catch (StatusRuntimeException e) {
                if (e.getStatus().getCode() != Status.Code.DEADLINE_EXCEEDED) {
                    System.out.println(e.getMessage());
                    return;
                }

            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }
        System.out.println("Server is not responding");
    }
}