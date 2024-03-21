package secserver;

import com.google.protobuf.ByteString;
import secserver.grpc.Secserver;
import secserver.grpc.Secserver.*;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class SecServerBackend {
    private ConcurrentHashMap<PublicKey, Account> accounts = new ConcurrentHashMap<>();
    private ConcurrentHashMap<PublicKey, Long> sequenceNumbers = new ConcurrentHashMap<>();
    

    private final FileWriter log;

    private int DEFAULT_BALANCE = 50;

    public SecServerBackend(FileWriter log) throws Exception {
        this.log = log;
        restoreState();
    }

    private List<Secserver.Transaction> convertTransactionToGrpc(List<Transaction> transactions) {
        List<Secserver.Transaction> out = new ArrayList<>();

        for (Transaction i : transactions) {
            out.add(Secserver.Transaction.newBuilder()
                    .setAmount(i.getAmount())
                    .setPublicKeySource(ByteString.copyFrom(i.getPublicKeySource().getEncoded())).build());
        }

        return out;
    }


    public PublicKey decodePublicKey(byte[] encodedKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
	}

    public OpenAccountResponse openAccount(PublicKey publicKey, long incomingSequenceNumber, boolean fromLog) throws IOException {
        if (!sequenceNumbers.containsKey(publicKey) && fromLog) {
            sequenceNumbers.put(publicKey, 0L);
        }
        long serverSequenceNumber = sequenceNumbers.get(publicKey);

        
        if(serverSequenceNumber == incomingSequenceNumber)  {
            if (accounts.containsKey(publicKey))
                return OpenAccountResponse.newBuilder().setSuccess(false).setErrorMessage("Account already opened").setSeqNum(serverSequenceNumber).build();

            return OpenAccountResponse.newBuilder().setSuccess(true).setSeqNum(serverSequenceNumber).build();
        }
        else if (serverSequenceNumber == incomingSequenceNumber -1) {
            sequenceNumbers.put(publicKey, incomingSequenceNumber);
            if (accounts.containsKey(publicKey)) {
                writeToLog(fromLog, "open reject " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + DEFAULT_BALANCE + " " + incomingSequenceNumber + " .\n");
                sequenceNumbers.put(publicKey, incomingSequenceNumber);
                return OpenAccountResponse.newBuilder().setSuccess(false).setErrorMessage("Account already opened").setSeqNum(incomingSequenceNumber).build();
            }

            Account account = new Account(publicKey, DEFAULT_BALANCE);
            accounts.put(publicKey, account);
            writeToLog(fromLog, "open accept " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + DEFAULT_BALANCE + " " + incomingSequenceNumber + " .\n");
            
            return OpenAccountResponse.newBuilder().setSuccess(true).setSeqNum(incomingSequenceNumber).build();
        }

        return null;
    }

    public SendAmountResponse sendAmount(PublicKey publicKeySource, PublicKey publicKeyDestination, int amount, long incomingSequenceNumber, boolean fromLog) throws IOException {
        if (!sequenceNumbers.containsKey(publicKeySource) && fromLog) {
            sequenceNumbers.put(publicKeySource, 0L);
        }
        long serverSequenceNumber = sequenceNumbers.get(publicKeySource);

        if(serverSequenceNumber == incomingSequenceNumber)  {
            if (!accounts.containsKey(publicKeySource) || !accounts.containsKey(publicKeyDestination))
                return SendAmountResponse.newBuilder().setSuccess(false).setSeqNum(serverSequenceNumber).setErrorMessage("sender or receiver does not have an account").build();
            
            if (amount <= 0)
                return SendAmountResponse.newBuilder().setSuccess(false).setSeqNum(serverSequenceNumber).setErrorMessage("amount needs to be positive").build();

            if (publicKeyDestination.equals(publicKeySource)) 
                return SendAmountResponse.newBuilder().setSuccess(false).setSeqNum(serverSequenceNumber).setErrorMessage("can't send money to yourself").build();
            

            return SendAmountResponse.newBuilder().setSuccess(true).setSeqNum(serverSequenceNumber).build();
        }
        else if (serverSequenceNumber + 1 == incomingSequenceNumber) {
            sequenceNumbers.put(publicKeySource, incomingSequenceNumber);

            if (!accounts.containsKey(publicKeySource) || !accounts.containsKey(publicKeyDestination)){
                writeToLog(fromLog, "send reject " + Base64.getEncoder().encodeToString(publicKeySource.getEncoded()) + " " + 
                    Base64.getEncoder().encodeToString(publicKeyDestination.getEncoded()) + " " + amount + " " + incomingSequenceNumber + " .\n");
                 return SendAmountResponse.newBuilder().setSuccess(false).setSeqNum(incomingSequenceNumber).setErrorMessage("sender or receiver does not have an account").build();
            }

            if (amount <= 0) {
                writeToLog(fromLog, "send reject " + Base64.getEncoder().encodeToString(publicKeySource.getEncoded()) + " " + 
                    Base64.getEncoder().encodeToString(publicKeyDestination.getEncoded()) + " " + amount + " " + incomingSequenceNumber + " .\n");
                return SendAmountResponse.newBuilder().setSuccess(false).setSeqNum(incomingSequenceNumber).setErrorMessage("amount needs to be positive").build();
            }

            if (publicKeyDestination.equals(publicKeySource)) {
                writeToLog(fromLog, "send reject " + Base64.getEncoder().encodeToString(publicKeySource.getEncoded()) + " " + 
                    Base64.getEncoder().encodeToString(publicKeyDestination.getEncoded()) + " " + amount + " " + incomingSequenceNumber + " .\n");
                return SendAmountResponse.newBuilder().setSuccess(false).setSeqNum(incomingSequenceNumber).setErrorMessage("can't send money to yourself").build();     
            }

            boolean operation;
            synchronized (accounts.get(publicKeySource)) {
                operation = accounts.get(publicKeySource).subtractFromBalance(amount);
            }

            if (operation == false) {
                writeToLog(fromLog, "send reject " + Base64.getEncoder().encodeToString(publicKeySource.getEncoded()) + " " + 
                    Base64.getEncoder().encodeToString(publicKeyDestination.getEncoded()) + " " + amount + " " + incomingSequenceNumber + " .\n");
                return SendAmountResponse.newBuilder().setSuccess(false).setSeqNum(incomingSequenceNumber).setErrorMessage("balance cannot be negative").build();
            }

            synchronized (accounts.get(publicKeyDestination)) {
                accounts.get(publicKeyDestination).addTransaction(new Transaction(publicKeySource, amount));
            }

            writeToLog(fromLog, "send accept " + Base64.getEncoder().encodeToString(publicKeySource.getEncoded()) + " " + 
                Base64.getEncoder().encodeToString(publicKeyDestination.getEncoded()) + " " + amount + " " + incomingSequenceNumber + " .\n");
            return SendAmountResponse.newBuilder().setSuccess(true).setSeqNum(incomingSequenceNumber).build();
        }

        return null;
    }


    public CheckAccountResponse checkAccount(PublicKey publicKey, long incomingSequenceNumber) {
        Account account = accounts.get(publicKey);
        long serverSequenceNumber = sequenceNumbers.get(publicKey);
        
        if (serverSequenceNumber == incomingSequenceNumber)  {
            if (account == null) {
                return CheckAccountResponse.newBuilder().setErrorMessage("Account does not exist").setSeqNum(serverSequenceNumber).setSuccess(false).build();
            }

            return CheckAccountResponse.newBuilder()
                .setSuccess(true)
                .setBalance(account.getCurrentBalance())
                .addAllIncoming(convertTransactionToGrpc(account.getPendingTransactions())).setSeqNum(serverSequenceNumber).build();
        } else if (serverSequenceNumber == incomingSequenceNumber -1) {
            
            sequenceNumbers.put(publicKey, incomingSequenceNumber);
            if (account == null) {
                writeToLog(false, "check reject " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + incomingSequenceNumber + " .\n");
                return CheckAccountResponse.newBuilder().setErrorMessage("Account does not exist").setSeqNum(incomingSequenceNumber).setSuccess(false).build();
            }
            
            writeToLog(false, "check accept " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + incomingSequenceNumber + " .\n");
            return CheckAccountResponse.newBuilder()
                .setSuccess(true)
                .setBalance(account.getCurrentBalance())
                .addAllIncoming(convertTransactionToGrpc(account.getPendingTransactions())).setSeqNum(incomingSequenceNumber).build();
            
        }
        return null;
    }

    public ReceiveAmountResponse receiveAmount(PublicKey publicKey, long incomingSequenceNumber, boolean fromLog) throws IOException {
        if (!sequenceNumbers.containsKey(publicKey)) {
            sequenceNumbers.put(publicKey, 0L);
        }
        long serverSequenceNumber = sequenceNumbers.get(publicKey);
        Account account = accounts.get(publicKey);

        if (serverSequenceNumber == incomingSequenceNumber)  {
            if (account == null) {
                return ReceiveAmountResponse.newBuilder().setErrorMessage("Account does not exist").setSuccess(false).setSeqNum(serverSequenceNumber).build();
            }
            
            return ReceiveAmountResponse.newBuilder().setSuccess(true).setSeqNum(serverSequenceNumber).build();
        } else if (serverSequenceNumber == incomingSequenceNumber - 1) { 

            sequenceNumbers.put(publicKey, incomingSequenceNumber);
            if (account == null) {
                writeToLog(fromLog, "receive reject " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + incomingSequenceNumber + " .\n");
                return ReceiveAmountResponse.newBuilder().setErrorMessage("Account does not exist").setSuccess(false).setSeqNum(incomingSequenceNumber).build();
            }


            synchronized (accounts.get(publicKey)) {
                account.acceptTransactions();
            }
            
            writeToLog(fromLog, "receive accept " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + incomingSequenceNumber + " .\n");
            return ReceiveAmountResponse.newBuilder().setSuccess(true).setSeqNum(incomingSequenceNumber).build();
        }
        return null;  
    }

    public AuditResponse audit(PublicKey publicKey, long incomingSequenceNumber) throws IOException {
        long serverSequenceNumber = sequenceNumbers.get(publicKey);

        if (serverSequenceNumber == incomingSequenceNumber)  { 
            if (!accounts.containsKey(publicKey))
                return AuditResponse.newBuilder().setErrorMessage("Account does not exist").setSuccess(false).setSeqNum(serverSequenceNumber).build();
            
            List<String> lines;
            synchronized (log) {
                lines = Files.readAllLines(Path.of("log.txt"));
            }
            List<String> participantLines = new ArrayList<>();

            for (String line : lines) {
                if (line.contains(Base64.getEncoder().encodeToString(publicKey.getEncoded()))) {
                    participantLines.add(line);
                }
            }

            return AuditResponse.newBuilder().addAllAudits(participantLines).setSeqNum(serverSequenceNumber).build();
        } else if (serverSequenceNumber == incomingSequenceNumber - 1) { 
            sequenceNumbers.put(publicKey, incomingSequenceNumber);

            if (!accounts.containsKey(publicKey)) {
                writeToLog(false, "audit reject " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + incomingSequenceNumber + " .\n");
                return AuditResponse.newBuilder().setErrorMessage("Account does not exist").setSeqNum(incomingSequenceNumber).setSuccess(false).build();
            }
           
            List<String> lines;
            synchronized (log) {
                lines = Files.readAllLines(Path.of("log.txt"));
            }
            List<String> participantLines = new ArrayList<>();
            
            for (String line : lines) {
                if (line.contains(Base64.getEncoder().encodeToString(publicKey.getEncoded())) && 
                    (line.startsWith("open accept") || line.startsWith("receive accept") || line.startsWith("send accept"))) {
                    participantLines.add(line);
                }
            }
            
            
            writeToLog(false, "audit accept " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + incomingSequenceNumber + " .\n");
            return AuditResponse.newBuilder().setSuccess(true).addAllAudits(participantLines).setSeqNum(incomingSequenceNumber).build();
        }
        return null;
    }

    public void fixLogFileIntegrity() throws IOException {
        File file = new File(String.valueOf(Path.of("log.txt")));
        if (file.length() > 0) {
            RandomAccessFile raf = new RandomAccessFile(file, "r");

            raf.seek(file.length() - 1);
            byte[] byteArray = new byte[1];
            raf.read(byteArray, 0, 1);
            if (!Arrays.equals(byteArray, "\n".getBytes())) {
                log.write("\n");
                log.flush();
            }
            raf.close();
        }
    }

    public void restoreState() throws Exception {
        List<String> lines = Files.readAllLines(Path.of("log.txt"));
        for (String line : lines) {
            String[] splitLine = line.split(" ");
            switch (splitLine[0]) {
                case "open":
                    if (splitLine.length == 6 && Objects.equals(splitLine[5], ".")) {
                        if (splitLine[1].equals("accept"))
                            openAccount(decodePublicKey(Base64.getDecoder().decode(splitLine[2])), Long.parseLong(splitLine[4]), true);
                        else
                            sequenceNumbers.put(decodePublicKey(Base64.getDecoder().decode(splitLine[2])), Long.parseLong(splitLine[4]));
                    }
                    break;
                case "send":
                    if (splitLine.length == 7 && Objects.equals(splitLine[6], ".")) {
                        if (splitLine[1].equals("accept"))
                            sendAmount(decodePublicKey(Base64.getDecoder().decode(splitLine[2])), decodePublicKey(Base64.getDecoder().decode(splitLine[3])), 
                            Integer.parseInt(splitLine[4]), Long.parseLong(splitLine[5]), true);
                        else
                            sequenceNumbers.put(decodePublicKey(Base64.getDecoder().decode(splitLine[2])), Long.parseLong(splitLine[5]));
                    }
                    break;
                
                case "receive":
                    if (splitLine.length == 5 && Objects.equals(splitLine[4], ".")) {
                        if (splitLine[1].equals("accept"))
                            receiveAmount(decodePublicKey(Base64.getDecoder().decode(splitLine[2])), Long.parseLong(splitLine[3]), true);
                        else
                            sequenceNumbers.put(decodePublicKey(Base64.getDecoder().decode(splitLine[2])), Long.parseLong(splitLine[3]));
                    }
                    break;

                case "audit":
                case "check":
                    if (splitLine.length == 5 && Objects.equals(splitLine[4], ".")) {
                        sequenceNumbers.put(decodePublicKey(Base64.getDecoder().decode(splitLine[2])), Long.parseLong(splitLine[3]));
                    }
                    break;
            }
        }

        fixLogFileIntegrity();
    }

	public SequenceNumberResponse sequenceNumber(PublicKey publicKey, byte[] nonce) {
		if (!sequenceNumbers.containsKey(publicKey)) {
            sequenceNumbers.put(publicKey, 0L);
        }

        return SequenceNumberResponse.newBuilder().setSeqNum(sequenceNumbers.get(publicKey)).setNonce(ByteString.copyFrom(nonce)).build();
	}

    public void writeToLog(boolean fromLog, String line) {
        if (!fromLog) {
            try {
                synchronized(log) {
                    log.write(line);
                    log.flush();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
