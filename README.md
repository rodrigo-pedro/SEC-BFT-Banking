# SEC - Project Demo

University project for Highly Dependable Systems course at Instituto Superior Técnico (2022).

See project statement [Part 1](SEC-2122_project-stage1_v2.pdf) and [Part 2](SEC-2122_project-stage2.pdf) for more information.

## 1. Preparation of the environment

Java 11 version and Maven are needed.

### 1.1 Compiling the Java project using Maven

In the *root* folder of the project, run the following command:

```sh
mvn clean install
```

### 1.2 Launching a server

The server will be hosted on `localhost:8888`. Access the *secserver* folder of the project and run the following command:

```sh
mvn compile exec:java
```

### 1.3 Launching a client

To launch a client, run the following command in the *secclient* directory:

```sh
mvn compile exec:java -Dexec.args="client2_public.pem client2.jks alentejanomau12"
```

The first argument represents the path of the public key, the second the path of the KeyStore where the private key is stored, and the third is the keystore password. Two pairs of public/private keys and two Keystores are found in the *secclient* directory (`client1_public.pem` and `client1.jks`, `client2_public.pem` and `client2.jks`). For each of the KeyStores, password is "alentejanomau12".

### 1.4 Generating Key Pairs

To generate a private key:

```sh
openssl genrsa -out key.pem
```

To convert the key to DER formatting:

```sh
openssl pkcs8 -topk8 -inform PEM -outform DER -in key.pem -out key.der -nocrypt
```

To generate a public key from the previously generated private key:

```sh
openssl rsa -in key.pem -pubout -out public.pem
```

To generate the request for the certificate and self sign the certificate:

```sh
openssl req -new -key key.pem -out key.csr
```

```sh
openssl x509 -req -days 365 -in key.csr -signkey key.pem -out key.crt
```

To generate a keystore with the private key, access the *root* folder of the project and run the following commands:

```sh
javac CreateKeyStore.java
```

```sh
java CreateKeyStore desiredPassword pathToCrt pathToPrivateKeyInDERFormat
```

## 2. Possible Operations

The following commands are allowed in the client's API.

### 2.1 Open Account

To open the account associated with the public key with an initial balance of 50:

```sh
> open
```

### 2.2 Send Amount

To send a certain amount of money to an existing client:

```sh
> send publickeypath amount
```

Where publickeypath is the path to a file containing the public key of the client who's receiving the money's.

A valid example would be:

```sh
mvn compile exec:java -Dexec.args="client1_public.pem client1.jks"
```

```sh
> send client2_public.pem 20
```

Assuming client1's balance is more than 20 and its account is prevously opened.

### 2.3 Check Account

To check the client's account status:

```sh
> check
```

This command retrieves the client's current balance, along with the pending transactions assigned.

### 2.4 Receive Amount

To receive all the incoming pending transactions:

```sh
> receive
```

This command will add to the client's balance all the pending transactions associated to it.

### 2.5 Audit

To check the audit log of the operations where the client is present:

```sh
> audit
```

All the history of the client's movements will be shown.

## 3. Demo

### 3.1 - Test 1 - Replay Attack Protection

Instead of incrementing the sequence number, the send function decreases the number by 2. This tests the server's capability of rejecting replay attacks.

Clear the log and insert the following commands:

```sh
> open
```

```sh
> check
```

```sh
> send client1_public.pem 20
```

```sh
> check
```

As you can observe, the client tried contacting the server for a while (15 seconds), and then gave up on the action. This means that the server dropped the requests from the client.

### 3.2 - Test 2 - Send repeated message (Server response dropped)

This tests the server's capability of not repeating requests, by sending the same sequence number on 2 equal send operations. This is useful because if an attacker drops the server's response, and the client retries the same request, there won't be a repeated operation.

Clear the server log, start two client sessions and run the following commands:

In client1_public.pem:

```sh
> open
```

In client2_public.pem:

```sh
> open
```

```sh
> check
```

```sh
> send client1_public.pem 20
```

```sh
> send client1_public.pem 20
```

```sh
> check
```

### 3.3 - Test 3 - Integrity checking message-wise

This test's objective is to simulate the tampering with the message. The server will attempt to check the message's integrity and if it realizes that something has been tampered with, the client will receive no response.
The open call won't be tampered with, but the check one will.

Clear the server log and run the commands:

```sh
> open
```

```sh
> check
```

### 3.4 - Test 4 - Server recovering from crash

The purpose of this test is to demonstrate the recovery of the system state after a crash. All operations for which the client has received a response will be applied to the system.

Launch the client on secclient_test2 and run the following commands:

In client1_public.pem:

```sh
> open
```

In client2_public.pem:

```sh
> open
```

```sh
> send client1_public.pem 20
```

In client1_public.pem:

```sh
> send client2_public.pem 20
```

```sh
> receive
```

Crash the server
Relaunch the server

Run in both clients:

```sh
> check
```

This proves that since the receive operation wasn't confirmed as completed to the client, it also doesn't show up in the log, thus not applied to the system's state.
