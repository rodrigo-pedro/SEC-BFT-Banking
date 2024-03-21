package secserver;

import io.grpc.BindableService;
import io.grpc.Server;
import io.grpc.ServerBuilder;

import java.io.FileInputStream;
import java.io.FileWriter;
import java.security.KeyStore;

public class SecServerMain {

	public static void main(String[] args) throws Exception {
		System.out.println(SecServerMain.class.getSimpleName());

		FileWriter fos = new FileWriter("log.txt", true);

		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream("server.jks"), "alentejanomau12".toCharArray());

		final BindableService impl = new SecServerImpl(fos, ks);

		Server secserver = ServerBuilder.forPort(8888).addService(impl).build();

		secserver.start();

		System.out.println("secserver started");

		secserver.awaitTermination();

		fos.close();

	}


}
