package SecureFolder;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.zip.*;

public class FolderEncrypter {
    private JFrame frame;
    private JTextField inputFileTextField;
    private JTextField outputFolderTextField;
    private JTextField keyTextField;

    public FolderEncrypter() {
        createGUI();
    }

    private void createGUI() {
        frame = new JFrame("Folder Encrypter");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());
        frame.setSize(800, 600);
        frame.setLocation(100, 100);
        frame.getContentPane().setBackground(Color.BLACK);

        // Top Panel
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new GridLayout(3, 2));
        topPanel.setBackground(Color.BLACK);

        JButton selectInputButton = new JButton("Select Input Folder");
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

        JLabel keyLabel =new JLabel("Generated Key:");
        keyLabel.setForeground(Color.WHITE);
        topPanel.add(keyLabel);

        keyTextField = new JTextField(30);
        keyTextField.setEditable(false);
        keyTextField.setBackground(Color.BLACK);
        keyTextField.setForeground(Color.WHITE);
        topPanel.add(keyTextField);

        frame.add(topPanel, BorderLayout.NORTH);

        // Bottom Panel
        JPanel bottomPanel = new JPanel();
        bottomPanel.setLayout(new FlowLayout());
        bottomPanel.setBackground(Color.BLACK);

        JButton encryptButton = new JButton("Encrypt Folder");
        encryptButton.setForeground(Color.WHITE);
        encryptButton.setBackground(Color.BLACK);
        encryptButton.setBorder(BorderFactory.createLineBorder(Color.WHITE, 3));
        encryptButton.setFocusPainted(false);
        encryptButton.setHorizontalAlignment(SwingConstants.CENTER);
        encryptButton.setVerticalAlignment(SwingConstants.CENTER);
        encryptButton.setPreferredSize(new Dimension(120, 30));
        encryptButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                encryptButton.setBackground(Color.WHITE);
                encryptButton.setForeground(Color.BLACK);
            }

            @Override
            public void mouseExited(MouseEvent e) {
                encryptButton.setBackground(Color.BLACK);
                encryptButton.setForeground(Color.WHITE);
            }
        });
        encryptButton.addActionListener(new EncryptButtonListener());
        bottomPanel.add(encryptButton);

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
            public void mouseExited(MouseEvent e) {
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
            fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            int returnValue = fileChooser.showOpenDialog(frame);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                inputFileTextField.setText(selectedFile.getAbsolutePath());
            } else {
                inputFileTextField.setText("No folder selected");
            }
        }
    }

    private class SelectOutputButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            int returnValue = fileChooser.showOpenDialog(frame);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                outputFolderTextField.setText(selectedFile.getAbsolutePath());
            } else {
                outputFolderTextField.setText("No folder selected");
            }
        }
    }

    private class EncryptButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String inputFile = inputFileTextField.getText();
            String outputFolder = outputFolderTextField.getText();
            if (inputFile.isEmpty() || outputFolder.isEmpty()) {
                JOptionPane.showMessageDialog(frame, "Please select both input and output folders");
                return;
            }
            try {
                String key = generateKey();
                keyTextField.setText(key);
                encryptFolder(inputFile, outputFolder, key);
                JOptionPane.showMessageDialog(frame, "Folder encrypted successfully");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(frame, "Error encrypting folder: " + ex.getMessage());
            }
        }
    }

    private class EndProgramButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            System.exit(0);
        }
    }

    private static String generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        byte[] keyBytes = secretKey.getEncoded();
        StringBuilder sb = new StringBuilder();
        for (byte b : keyBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static void encryptFolder(String inputPath, String outputPath, String hexKey) throws Exception {
        byte[] keyBytes = new byte[hexKey.length() / 2];
        for (int i = 0; i < keyBytes.length; i++) {
            keyBytes[i] = (byte) Integer.parseInt(hexKey.substring(2 * i, 2 * i + 2), 16);
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        // Zip the folder first
        File inputFile = new File(inputPath);
        File tempZip = new File(outputPath + File.separator + "temp.zip");
        zipFolder(inputFile, tempZip);

        // Encrypt the zipped file
        File encryptedFile = new File(outputPath + File.separator + "encrypted.exe"); // Change the extension to .exe
        encryptFile(tempZip, encryptedFile, secretKeySpec);

        // Delete the temporary zip file
        tempZip.delete();
    }

    private static void zipFolder(File sourceFolder, File zipFile) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(zipFile);
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            zipFile(sourceFolder, sourceFolder.getName(), zos);
        }
    }

    private static void zipFile(File fileToZip, String fileName, ZipOutputStream zos) throws IOException {
        if (fileToZip.isHidden()) {
            return;
        }
        if (fileToZip.isDirectory()) {
            if (fileName.endsWith("/")) {
                zos.putNextEntry(new ZipEntry(fileName));
                zos.closeEntry();
            } else {
                zos.putNextEntry(new ZipEntry(fileName + "/"));
                zos.closeEntry();
            }
            File[] children = fileToZip.listFiles();
            for (File childFile : children) {
                zipFile(childFile, fileName + "/" + childFile.getName(), zos);
            }
            return;
        }
        try (FileInputStream fis = new FileInputStream(fileToZip)) {
            ZipEntry zipEntry = new ZipEntry(fileName);
            zos.putNextEntry(zipEntry);
            byte[] bytes = new byte[1024];
            int length;
            while ((length = fis.read(bytes)) >= 0) {
                zos.write(bytes, 0, length);
            }
        }
    }

    private static void encryptFile(File inputFile, File outputFile, SecretKeySpec secretKeySpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile);
             CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = fis.read(buffer)) > 0) {
                cos.write(buffer, 0, len);
            }
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new FolderEncrypter();
            }
        });
    }
}