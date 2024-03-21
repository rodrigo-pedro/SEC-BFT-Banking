package secserver;

import java.security.PublicKey;
import java.util.ArrayList;

public class Account {
    private PublicKey publicKey;
    private int currentBalance;
    private ArrayList<Transaction> pendingTransactions;

    public Account(PublicKey publicKey, int currentBalance) {
        this.publicKey = publicKey;
        this.currentBalance = currentBalance;
        this.pendingTransactions = new ArrayList<Transaction>();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public int getCurrentBalance() {
        return currentBalance;
    }

    public void setCurrentBalance(int currentBalance) {
        this.currentBalance = currentBalance;
    }

    public void addToBalance(int amount) {
        this.currentBalance += amount;
    }

    public boolean subtractFromBalance(int amount) {
        if (this.currentBalance - amount <= 0) {
            return false;
        }

        this.currentBalance -= amount;
        return true;
    }

    public void addTransaction(Transaction transaction) {
        this.pendingTransactions.add(transaction);
    }

    public ArrayList<Transaction> getPendingTransactions() {
        return pendingTransactions;
    }

    public void acceptTransactions() {
        for (Transaction transaction : this.pendingTransactions) {
            this.addToBalance(transaction.getAmount());
        }

        this.pendingTransactions.clear();
    }
}
