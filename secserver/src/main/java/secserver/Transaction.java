package secserver;

import java.security.PublicKey;

public class Transaction {
    private PublicKey publicKeySource;
    private int amount;

    public Transaction(PublicKey publicKeySource, int amount) {
        this.publicKeySource = publicKeySource;
        this.amount = amount;
    }

    public PublicKey getPublicKeySource() {
        return publicKeySource;
    }

    public void setPublicKeySource(PublicKey publicKeySource) {
        this.publicKeySource = publicKeySource;
    }

    public int getAmount() {
        return amount;
    }

    public void setAmount(int amount) {
        this.amount = amount;
    }

}
