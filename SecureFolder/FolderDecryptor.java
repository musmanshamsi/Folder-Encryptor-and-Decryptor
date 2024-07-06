package SecureFolder;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.zip.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class FolderDecryptor {
    private JFrame frame;
    private JTextField inputFileTextField;
    private JTextField outputFolderTextField;
    private JTextField keyTextField;

    public FolderDecryptor() {
        createGUI();
    }

    private void createGUI() {
        frame = new JFrame("Folder Decryptor");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());
        frame.setSize(700, 250); // Set the JFrame size to 800x600
        frame.setLocation(100, 100); // Set the JFrame location to (100, 100)
        frame.getContentPane().setBackground(Color.BLACK);

        // Top Panel
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new GridLayout(3, 2));
        topPanel.setBackground(Color.BLACK);

        JButton selectInputButton = new JButton("Select Input File");
        selectInputButton.setForeground(Color.WHITE);
        selectInputButton.setBackground(Color.BLACK);
        selectInputButton.setBorder(BorderFactory.createLineBorder(Color.WHITE, 3));
        selectInputButton.setFocusPainted(false);
        selectInputButton.setHorizontalAlignment(SwingConstants.CENTER);
        selectInputButton.setVerticalAlignment(SwingConstants.CENTER);
        selectInputButton.setPreferredSize(new Dimension(120, 30));
        selectInputButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                selectInputButton.setBackground(Color.WHITE);
                selectInputButton.setForeground(Color.BLACK);
            }

            @Override
            public void mouseExited(MouseEvent e) {
                selectInputButton.setBackground(Color.BLACK);
                selectInputButton.setForeground(Color.WHITE);
            }
        });
        selectInputButton.addActionListener(new SelectInputButtonListener());
        topPanel.add(selectInputButton);

        inputFileTextField = new JTextField(30);
        inputFileTextField.setEditable(false);
        inputFileTextField.setBackground(Color.BLACK);
        inputFileTextField.setForeground(Color.WHITE);
        topPanel.add(inputFileTextField);

        JButton selectOutputButton = new JButton("Select Output Folder");
        selectOutputButton.setForeground(Color.WHITE);
        selectOutputButton.setBackground(Color.BLACK);
        selectOutputButton.setBorder(BorderFactory.createLineBorder(Color.WHITE, 3));
        selectOutputButton.setFocusPainted(false);
        selectOutputButton.setHorizontalAlignment(SwingConstants.CENTER);
        selectOutputButton.setVerticalAlignment(SwingConstants.CENTER);
        selectOutputButton.setPreferredSize(new Dimension(120, 30));
        selectOutputButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                selectOutputButton.setBackground(Color.WHITE);
                selectOutputButton.setForeground(Color.BLACK);
            }

            @Override
            public void mouseExited(MouseEvent e) {
                selectOutputButton.setBackground(Color.BLACK);
                selectOutputButton.setForeground(Color.WHITE);
            }
        });
        selectOutputButton.addActionListener(new SelectOutputButtonListener());
        topPanel.add(selectOutputButton);

        outputFolderTextField = new JTextField(30);
        outputFolderTextField.setEditable(false);
        outputFolderTextField.setBackground(Color.BLACK);
        outputFolderTextField.setForeground(Color.WHITE);
        topPanel.add(outputFolderTextField);

        JLabel keyLabel = new JLabel("Key:");
        keyLabel.setForeground(Color.WHITE);
        topPanel.add(keyLabel);

        keyTextField = new JTextField(30);
        keyTextField.setEditable(true);
        keyTextField.setBackground(Color.BLACK);
        keyTextField.setForeground(Color.WHITE);
        topPanel.add(keyTextField);

        frame.add(topPanel, BorderLayout.NORTH);

        // Bottom Panel
        JPanel bottomPanel = new JPanel();
        bottomPanel.setLayout(new FlowLayout());
        bottomPanel.setBackground(Color.BLACK);

        JButton decryptButton = new JButton("Decrypt Folder");
        decryptButton.setForeground(Color.WHITE);
        decryptButton.setBackground(Color.BLACK);
        decryptButton.setBorder(BorderFactory.createLineBorder(Color.WHITE, 3));
        decryptButton.setFocusPainted(false);
        decryptButton.setHorizontalAlignment(SwingConstants.CENTER);
        decryptButton.setVerticalAlignment(SwingConstants.CENTER);
        decryptButton.setPreferredSize(new Dimension(120, 30));
        decryptButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                decryptButton.setBackground(Color.WHITE);
                decryptButton.setForeground(Color.BLACK);
            }

            @Override
            public void mouseExited(MouseEvent e) {
                decryptButton.setBackground(Color.BLACK);
                decryptButton.setForeground(Color.WHITE);
            }
        });
        decryptButton.addActionListener(new DecryptButtonListener());
        bottomPanel.add(decryptButton);

        JButton endProgramButton = new JButton("End Program");
        endProgramButton.setForeground(Color.WHITE);
        endProgramButton.setBackground(Color.BLACK);
        endProgramButton.setBorder(BorderFactory.createLineBorder(Color.WHITE, 3));
        endProgramButton.setFocusPainted(false);
        endProgramButton.setHorizontalAlignment(SwingConstants.CENTER);
        endProgramButton.setVerticalAlignment(SwingConstants.CENTER);
        endProgramButton.setPreferredSize(new Dimension(120, 30));
        endProgramButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                endProgramButton.setBackground(Color.WHITE);
                endProgramButton.setForeground(Color.BLACK);
            }

            @Override
            public void mouseExited(MouseEvent e){
                endProgramButton.setBackground(Color.BLACK);
                endProgramButton.setForeground(Color.WHITE);
            }
        });
        endProgramButton.addActionListener(new EndProgramButtonListener());
        bottomPanel.add(endProgramButton);

        frame.add(bottomPanel, BorderLayout.SOUTH);

        // Center the frame
        frame.setLocationRelativeTo(null);

        frame.pack();
        frame.setVisible(true);
    }

    private class SelectInputButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            int returnValue = fileChooser.showOpenDialog(frame);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                inputFileTextField.setText(selectedFile.getAbsolutePath());
            } else {
                inputFileTextField.setText("No file selected");
            }
        }
    }

    private class SelectOutputButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            int returnValue = fileChooser.showOpenDialog(frame);
            if (returnValue == JFileChooser.APPROVE_OPTION){
                File selectedFile = fileChooser.getSelectedFile();
                outputFolderTextField.setText(selectedFile.getAbsolutePath());
            } else {
                outputFolderTextField.setText("No folder selected");
            }
        }
    }

    private class DecryptButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String inputFile = inputFileTextField.getText();
            String outputFolder = outputFolderTextField.getText();
            String key = keyTextField.getText();
            if (inputFile.isEmpty() || outputFolder.isEmpty() || key.isEmpty()) {
                JOptionPane.showMessageDialog(frame, "Please select both input file and output folder, and enter a key");
                return;
            }
            try {
                decryptFolder(inputFile, outputFolder, key);
                JOptionPane.showMessageDialog(frame, "Folder decrypted successfully");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(frame, "Error decrypting folder: " + ex.getMessage());
            }
        }
    }

    private class EndProgramButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            System.exit(0);
        }
    }

    private static void decryptFolder(String inputFile, String outputFolder, String key) throws Exception {
        byte[] keyBytes = hexToBytes(key);
        System.out.println("Using key: " + bytesToHex(keyBytes));

        File encryptedFile = new File(inputFile);
        File decryptedFile = new File("temp.zip");
        decryptFile(encryptedFile, decryptedFile, keyBytes);

        unzipFolder(decryptedFile, new File(outputFolder));

        decryptedFile.delete();
    }

    private static void decryptFile(File inputFile, File outputFile, byte[] key) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile);
             CipherInputStream cis = new CipherInputStream(fis, cipher)) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = cis.read(buffer)) > 0) {
                fos.write(buffer, 0, len);
            }
        }
    }

    private static void unzipFolder(File zipFile, File outputFolder) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry())!= null) {
                File file = new File(outputFolder, entry.getName());
                file.getParentFile().mkdirs();
                if (!entry.isDirectory()) {
                    try (FileOutputStream fos = new FileOutputStream(file)) {
                        byte[] buffer = new byte[1024];
                        int len;
                        while ((len = zis.read(buffer)) > 0) {
                            fos.write(buffer, 0, len);
                        }
                    }
                }
            }
        }
    }

    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new FolderDecryptor();
            }
        });
    }
}