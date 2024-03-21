package secclient;

import java.util.Scanner;

public class SecClientMain {

	// arg1 - jks, arg2 - public
	public static void main(String[] args) throws Exception {
		System.out.println(SecClientMain.class.getSimpleName());

		Scanner scanner = new Scanner(System.in);

		SecClient secClient = new SecClient(args[0], args[1], args[2]);



		while (true) {
			System.out.print("> ");

			// clause that breaks the while loop
			if (!scanner.hasNextLine()) {
				System.out.print("\b\b");
				scanner.close();
				System.exit(0);
			}

			String line = scanner.nextLine();
			String[] splitLine = line.split("\\s+");
			try {
				switch (splitLine[0]) {
					case "open":
						secClient.openAccount();
						break;
					case "send":
						secClient.sendAmount(splitLine[1], Integer.parseInt(splitLine[2]));
						break;
					case "check":
						secClient.checkAccount();
						break;
					case "receive":
						secClient.receiveAmount();
						break;
					case "audit":
						secClient.audit();
						break;
					case "exit":
						System.exit(0);
					default:
						System.out.println("Invalid operation");
						break;
				}
			} catch (IndexOutOfBoundsException ioobe) {
				System.out.println("Invalid command");
			}
		}
	
	}
}
