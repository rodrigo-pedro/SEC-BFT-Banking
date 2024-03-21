package secserver;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;

import io.grpc.Status;
import io.grpc.stub.StreamObserver;

import secserver.grpc.SecServerServiceGrpc;
import secserver.grpc.Secserver.*;

import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;

public class SecServerImpl extends SecServerServiceGrpc.SecServerServiceImplBase {
	private final SecServerBackend backend;
	private final KeyStore keyStore;
	

	public SecServerImpl(FileWriter log, KeyStore ks) throws Exception {
		backend = new SecServerBackend(log);
		keyStore = ks;
	}

	
	private boolean verifySignature(ByteString signatureBytes, ByteString publicKey, Any data) throws Exception {
		Signature dsaForVerify = Signature.getInstance("SHA256withRSA");
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey key = keyFactory.generatePublic(new X509EncodedKeySpec(publicKey.toByteArray()));
		
	
		dsaForVerify.initVerify(key);
		dsaForVerify.update(data.toByteArray());
		return dsaForVerify.verify(signatureBytes.toByteArray());
	}

	private ByteString generateSignature(byte[] data, PublicKey key) throws UnrecoverableKeyException, KeyStoreException,
			NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
		Signature dsaForSign = Signature.getInstance("SHA256withRSA");
		
		dsaForSign.initSign((PrivateKey) keyStore.getKey("private", "alentejanomau12".toCharArray()));
		dsaForSign.update(data);
		return ByteString.copyFrom(dsaForSign.sign());
	}

	private PublicKey decodePublicKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
	}

	@Override
	public void sequenceNumber(Payload request, StreamObserver<Payload> responseObserver) {
		try {
			SequenceNumberRequest snRequest = request.getMessage().unpack(SequenceNumberRequest.class);
			boolean result = verifySignature(request.getDigitalSignature(), snRequest.getPublicKey(), request.getMessage());

			if (!result)
				return;

			PublicKey publicKey = decodePublicKey(snRequest.getPublicKey().toByteArray());
			byte[] nonce = snRequest.getNonce().toByteArray();

			SequenceNumberResponse snResponse = backend.sequenceNumber(publicKey, nonce);
			Any response = Any.pack(snResponse);

			ByteString responseSignature = generateSignature(response.toByteArray(), publicKey);
			Payload payload =  Payload.newBuilder()
						.setMessage(response)
						.setDigitalSignature(responseSignature).build();

			responseObserver.onNext(payload);
			responseObserver.onCompleted();
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}

	@Override
	public void openAccount(Payload request, StreamObserver<Payload> responseObserver) {
		try {
			OpenAccountRequest oar = request.getMessage().unpack(OpenAccountRequest.class);
			boolean result = verifySignature(request.getDigitalSignature(), oar.getPublicKey(), request.getMessage());
			PublicKey publicKey = decodePublicKey(oar.getPublicKey().toByteArray());

			if (result) {
				OpenAccountResponse oaResponse = backend.openAccount(publicKey, oar.getSeqNum(), false);

				if (oaResponse == null)
					return;

				Any response = Any.pack(oaResponse);

				ByteString responseSignature = generateSignature(response.toByteArray(), publicKey);
				Payload payload =  Payload.newBuilder()
							.setMessage(response)
							.setDigitalSignature(responseSignature).build();	
				responseObserver.onNext(payload);
				responseObserver.onCompleted();

			}
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}

	@Override
	public void sendAmount(Payload request, StreamObserver<Payload> responseObserver) {
		
		try {
			SendAmountRequest sar = request.getMessage().unpack(SendAmountRequest.class);
			boolean result = verifySignature(request.getDigitalSignature(), sar.getPublicKeySource(), request.getMessage());
			PublicKey sendPublicKeyDestination = decodePublicKey(sar.getPublicKeyDestination().toByteArray());
			PublicKey publicKey = decodePublicKey(sar.getPublicKeySource().toByteArray());
			
			if (result) {
				SendAmountResponse saResponse = backend.sendAmount(publicKey, sendPublicKeyDestination, sar.getAmount(), sar.getSeqNum(), false);
				if (saResponse == null)
					return;
					
				Any response = Any.pack(saResponse);
				
				ByteString responseSignature = generateSignature(response.toByteArray(), publicKey);
				Payload payload = Payload.newBuilder()
							.setMessage(response)
							.setDigitalSignature(responseSignature).build();
				responseObserver.onNext(payload);
				responseObserver.onCompleted();
			}
		}
		catch(Exception e) {
			System.out.println(e.getMessage());
		}
	}

	@Override
	public void checkAccount(Payload request, StreamObserver<Payload> responseObserver) {
		try {
			CheckAccountRequest car = request.getMessage().unpack(CheckAccountRequest.class);
			boolean result = verifySignature(request.getDigitalSignature(), car.getPublicKey(), request.getMessage());
			PublicKey publicKey = decodePublicKey(car.getPublicKey().toByteArray());
			
			if (result) {
				CheckAccountResponse caResponse = backend.checkAccount(publicKey, car.getSeqNum());
				if (caResponse == null)
					return;
					
				Any response = Any.pack(caResponse);
				
				ByteString responseSignature = generateSignature(response.toByteArray(), publicKey);
				Payload payload = Payload.newBuilder()
							.setMessage(response)
							.setDigitalSignature(responseSignature).build();
				responseObserver.onNext(payload);
				responseObserver.onCompleted();
			}
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}
	
	@Override
	public void receiveAmount(Payload request, StreamObserver<Payload> responseObserver) {
	
		try {
			ReceiveAmountRequest rar = request.getMessage().unpack(ReceiveAmountRequest.class);
			boolean result = verifySignature(request.getDigitalSignature(), rar.getPublicKey(), request.getMessage());
			PublicKey publicKey = decodePublicKey(rar.getPublicKey().toByteArray());
			
			if (result) {
				ReceiveAmountResponse raResponse = backend.receiveAmount(publicKey, rar.getSeqNum(), false);
				if (raResponse == null)
					return;
					
				Any response = Any.pack(raResponse);

				ByteString responseSignature = generateSignature(response.toByteArray(), publicKey);
				
				Payload payload = Payload.newBuilder()
							.setMessage(response)
							.setDigitalSignature(responseSignature).build();
	
				
				responseObserver.onNext(payload);
				responseObserver.onCompleted();	
			}
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}

	@Override
	public void audit(Payload request, StreamObserver<Payload> responseObserver) {
		try {
			AuditRequest ar = request.getMessage().unpack(AuditRequest.class);		
			boolean result = verifySignature(request.getDigitalSignature(), ar.getPublicKey(), request.getMessage());

			if (result) {
				PublicKey publicKey = decodePublicKey(ar.getPublicKey().toByteArray());
				AuditResponse aResponse = backend.audit(publicKey, ar.getSeqNum());

				if (aResponse == null)
					return;
					
				Any response = Any.pack(aResponse);
	
				ByteString responseSignature = generateSignature(response.toByteArray(), publicKey);
				Payload payload = Payload.newBuilder()
						.setMessage(response)
						.setDigitalSignature(responseSignature).build();
				
				responseObserver.onNext(payload);
				responseObserver.onCompleted();			
			}
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}
}