/*
 * The MIT License
 *
 * Copyright 2022 mrdcvlsc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package mypm;

import java.sql.*;
import java.util.ArrayList;
import javax.swing.table.DefaultTableModel;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class mypmdisp extends javax.swing.JFrame {

    private SecretKey AES128KEY;
    private byte[] byteIV;
    private String algorithm = "AES/CBC/PKCS5Padding";
    
    private int selected_table_index = -1;
  
    private void updateTable()
    {
        DefaultTableModel tableModel = new DefaultTableModel(){
            @Override // makes the table unedditable by user
            public boolean  isCellEditable(int row, int column){
                return false;
            }
        };
        
        tableModel.addColumn("Platform");
        tableModel.addColumn("User ID");
        tableModel.addColumn("Password");
        
        try{
            platformList.clear();
            userList.clear();
            passList.clear();
            
            platformIV.clear();
            userIV.clear();
            passIV.clear();
            
            Class.forName("org.sqlite.JDBC");
            Connection conn = DriverManager.getConnection("jdbc:sqlite:d/dt.db");
            Statement st = conn.createStatement();
            ResultSet rs = st.executeQuery("SELECT * FROM `srstbl`");
            
            String readIvPltfrm;
            String readIvSrs;
            String readIvPsswrd;
            
            int items_read = 0;
            
            while(rs.next())
            {
                items_read++;
                
                String dbPltfrm = rs.getString("pltfrm");
                String dbSrs = rs.getString("srs");
                String dbPsswrd = rs.getString("psswrd");
                
                readIvPltfrm = dbPltfrm.substring(0,24);
                dbPltfrm = dbPltfrm.substring(24,dbPltfrm.length());
                
                readIvSrs = dbSrs.substring(0,24);
                dbSrs = dbSrs.substring(24,dbSrs.length());
                
                readIvPsswrd = dbPsswrd.substring(0,24);
                dbPsswrd = dbPsswrd.substring(24,dbPsswrd.length());
                
                byteIV = new byte[16];
                
                byteIV = Base64.getDecoder().decode(readIvPltfrm);
                String pltforms = AES128.decrypt(algorithm, dbPltfrm, AES128KEY, new IvParameterSpec(byteIV));
                
                byteIV = Base64.getDecoder().decode(readIvSrs);
                String usersl = AES128.decrypt(algorithm, dbSrs, AES128KEY, new IvParameterSpec(byteIV));
                
                byteIV = Base64.getDecoder().decode(readIvPsswrd);
                String passwds = AES128.decrypt(algorithm, dbPsswrd, AES128KEY, new IvParameterSpec(byteIV));
                
                tableModel.addRow(new Object[]{
                    pltforms,
                    usersl,
                    passwds
                });
                
                platformList.add(pltforms);
                userList.add(usersl);
                passList.add(passwds);
                
                platformIV.add(readIvPltfrm);
                userIV.add(readIvSrs);
                passIV.add(readIvPsswrd);
            }
            System.out.println("--------------------------------------------");
            System.out.println(""+items_read+" items read from the database");
            st.close();
        }
        catch(Exception e){
            System.out.println(e);
            System.exit(8);
        }
        recordstbl.setModel(tableModel);
    }
    
    private boolean patternMatch(String left, String right){
        int min = (left.length() < right.length()) ? left.length() : right.length();
        for(int i=0; i<min; ++i){
            if(left.charAt(i) != right.charAt(i))
                return false;
        }
        return true;
    }
    
    private ArrayList<String> platformIV = new ArrayList<>();
    private ArrayList<String> userIV = new ArrayList<>();
    private ArrayList<String> passIV = new ArrayList<>();
    
    private ArrayList<String> platformList = new ArrayList<>();
    private ArrayList<String> userList = new ArrayList<>();
    private ArrayList<String> passList = new ArrayList<>();
    
    private void updateTableFilter(String filter)
    {
        updateTable();
        if(filter.equals(""))
        {
            return;
        }
        
        DefaultTableModel recordstblmodel = new DefaultTableModel(){
            @Override // makes the table unedditable by user
            public boolean  isCellEditable(int row, int column){
                return false;
            }
        };
        
        recordstblmodel.addColumn("Platform");
        recordstblmodel.addColumn("User ID");
        recordstblmodel.addColumn("Password");
        
        ArrayList<String> newPlatformIV = new ArrayList<>();
        ArrayList<String> newUserIV = new ArrayList<>();
        ArrayList<String> newPassIV = new ArrayList<>();
        
        int item_counts = 0;
        int rowlen = platformList.size();
        for(int i=0; i<rowlen; ++i)
        {
            if(patternMatch(platformList.get(i),filter))
            {
                item_counts++;
                recordstblmodel.addRow(new Object[]{
                    platformList.get(i),
                    userList.get(i),
                    passList.get(i)
                });
                
                newPlatformIV.add(platformIV.get(i));
                newUserIV.add(userIV.get(i));
                newPassIV.add(passIV.get(i));
            }
        }
        
        platformIV = newPlatformIV;
        userIV = newUserIV;
        passIV = newPassIV;
        
        System.out.println(""+item_counts+" items match from platform filter");
        recordstbl.setModel(recordstblmodel);
    }
    
    private void databaseRemove(String plt, String usr, String psw){
        try{
            Class.forName("org.sqlite.JDBC");
            Connection conn = DriverManager.getConnection("jdbc:sqlite:d/dt.db");
            
            String query = "DELETE FROM `srstbl` WHERE pltfrm=? AND srs=? AND psswrd=?";
            PreparedStatement pst = conn.prepareStatement(query);
                        
            byteIV = Base64.getDecoder().decode(platformIV.get(selected_table_index));
            pst.setString(1, platformIV.get(selected_table_index) + AES128.encrypt(algorithm, plt, AES128KEY, new IvParameterSpec(byteIV)));
            
            byteIV = Base64.getDecoder().decode(userIV.get(selected_table_index));
            pst.setString(2, userIV.get(selected_table_index) + AES128.encrypt(algorithm, usr, AES128KEY, new IvParameterSpec(byteIV)));
            
            byteIV = Base64.getDecoder().decode(passIV.get(selected_table_index));
            pst.setString(3, passIV.get(selected_table_index) + AES128.encrypt(algorithm, psw, AES128KEY, new IvParameterSpec(byteIV)));
          
            int deleted = pst.executeUpdate();
            
            if(deleted!=0)
            {
                platformIV.remove(selected_table_index);
                userIV.remove(selected_table_index);
                passIV.remove(selected_table_index);
            }
            
            System.out.println(""+deleted+" item deleted from the database");
            pst.close();
        }
        catch(Exception e){
            System.out.println("An Error occur when deleting an item");
            System.out.println(e);
        }
    }
    
    public mypmdisp() {
        try{
            AES128KEY = AES128.generateKey(login.CurrentKey, login.CurrentSalt);
        } catch(Exception cryptoError)
        {
            cryptoError.printStackTrace();
            System.exit(1);
        }
        
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Windows".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(mypmdisp.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(mypmdisp.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(mypmdisp.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(mypmdisp.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        initComponents();
        this.setLocationRelativeTo(null);
        
        updateTable();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        adddialog = new javax.swing.JDialog();
        adduserid = new javax.swing.JTextField();
        savebtnadd = new javax.swing.JButton();
        discardbtnadd = new javax.swing.JButton();
        addplatform = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        passerr = new javax.swing.JLabel();
        addpassword = new javax.swing.JTextField();
        addreenterpassword = new javax.swing.JTextField();
        jLabel7 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        recordstbl = new javax.swing.JTable();
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        filterfield = new javax.swing.JTextField();
        jLabel1 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();

        adddialog.setTitle("Add a Record");
        adddialog.setAlwaysOnTop(true);
        adddialog.setMinimumSize(new java.awt.Dimension(353, 351));
        adddialog.setPreferredSize(new java.awt.Dimension(353, 351));
        adddialog.setResizable(false);
        adddialog.setSize(new java.awt.Dimension(353, 351));

        savebtnadd.setText("Save");
        savebtnadd.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                savebtnaddActionPerformed(evt);
            }
        });

        discardbtnadd.setText("Discard");
        discardbtnadd.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                discardbtnaddActionPerformed(evt);
            }
        });

        jLabel2.setText("Platform");

        jLabel3.setText("UserID");

        jLabel4.setText("Enter Password");

        jLabel5.setText("Re-Enter Password");

        passerr.setText("-");

        jLabel7.setText("    ");

        javax.swing.GroupLayout adddialogLayout = new javax.swing.GroupLayout(adddialog.getContentPane());
        adddialog.getContentPane().setLayout(adddialogLayout);
        adddialogLayout.setHorizontalGroup(
            adddialogLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(adddialogLayout.createSequentialGroup()
                .addGap(33, 33, 33)
                .addGroup(adddialogLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, adddialogLayout.createSequentialGroup()
                        .addComponent(savebtnadd, javax.swing.GroupLayout.PREFERRED_SIZE, 137, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(discardbtnadd, javax.swing.GroupLayout.PREFERRED_SIZE, 133, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(adduserid, javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(addplatform, javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(addpassword, javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel2, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(addreenterpassword, javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(passerr, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel3, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel4, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel5, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel7, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addGap(32, 32, 32))
        );
        adddialogLayout.setVerticalGroup(
            adddialogLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(adddialogLayout.createSequentialGroup()
                .addGap(23, 23, 23)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(addplatform, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel3)
                .addGap(3, 3, 3)
                .addComponent(adduserid, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel4)
                .addGap(4, 4, 4)
                .addComponent(addpassword, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(10, 10, 10)
                .addComponent(jLabel5)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(addreenterpassword, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(passerr)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(adddialogLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(savebtnadd)
                    .addComponent(discardbtnadd))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel7)
                .addGap(24, 24, 24))
        );

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        recordstbl.setFont(new java.awt.Font("Segoe UI", 1, 11)); // NOI18N
        recordstbl.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Platform", "User ID", "Password"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.String.class, java.lang.String.class, java.lang.String.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        recordstbl.setCellSelectionEnabled(true);
        recordstbl.setGridColor(new java.awt.Color(204, 204, 204));
        recordstbl.setRowMargin(2);
        recordstbl.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                recordstblMouseClicked(evt);
            }
        });
        jScrollPane1.setViewportView(recordstbl);

        jButton1.setFont(new java.awt.Font("Segoe UI", 1, 11)); // NOI18N
        jButton1.setText("Add");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jButton2.setFont(new java.awt.Font("Segoe UI", 1, 11)); // NOI18N
        jButton2.setText("Remove");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        filterfield.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                filterfieldKeyReleased(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Segoe UI", 3, 14)); // NOI18N
        jLabel1.setText("Password Manager");

        jLabel6.setText("Platform Filter :");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel1)
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jButton1)
                                .addGap(28, 28, 28)
                                .addComponent(jButton2)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(jLabel6)
                                .addGap(18, 18, 18)
                                .addComponent(filterfield, javax.swing.GroupLayout.PREFERRED_SIZE, 162, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addGap(20, 20, 20))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(19, 19, 19)
                .addComponent(jLabel1)
                .addGap(18, 18, 18)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 348, Short.MAX_VALUE)
                .addGap(27, 27, 27)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton1)
                    .addComponent(jButton2)
                    .addComponent(filterfield, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel6))
                .addGap(24, 24, 24))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        adddialog.setLocationRelativeTo(null);
        adddialog.setVisible(true);
    }//GEN-LAST:event_jButton1ActionPerformed

    private void savebtnaddActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_savebtnaddActionPerformed

        if(addplatform.getText().length()<1){
            passerr.setText(" - Platform should have at least 1 characters");
            return;
        }else if(adduserid.getText().length()<=2){
            passerr.setText(" - User ID should have at least 3 characters");
            return;
        }
        else if(addpassword.getText().length()<=5){
            passerr.setText(" - Password require 5 characters (recommended:8)");
            return;
        }
        else
        if(addpassword.getText().equals(addreenterpassword.getText())){
            passerr.setText("-");
            try{
                Class.forName("org.sqlite.JDBC");
                Connection conn = DriverManager.getConnection("jdbc:sqlite:d/dt.db");

                String query = "INSERT INTO `srstbl` VALUES(?,?,?)";
                PreparedStatement pst = conn.prepareStatement(query);
                
                byteIV = new byte[16];
                
                new SecureRandom().nextBytes(byteIV);
                platformIV.add(AES128.ByteToString(byteIV));
                pst.setString(1, AES128.ByteToString(byteIV) + AES128.encrypt(algorithm, addplatform.getText(), AES128KEY, new IvParameterSpec(byteIV)));
                
                new SecureRandom().nextBytes(byteIV);
                userIV.add(AES128.ByteToString(byteIV));
                pst.setString(2, AES128.ByteToString(byteIV) + AES128.encrypt(algorithm, adduserid.getText(), AES128KEY, new IvParameterSpec(byteIV)));
                
                new SecureRandom().nextBytes(byteIV);
                passIV.add(AES128.ByteToString(byteIV));
                pst.setString(3, AES128.ByteToString(byteIV) + AES128.encrypt(algorithm, addpassword.getText(), AES128KEY, new IvParameterSpec(byteIV)));
                
                System.out.println(""+pst.executeUpdate()+" item added to the database");
                pst.close();
                updateTable();
                
                adddialog.setVisible(false);
                addplatform.setText("");
                adduserid.setText("");
                addpassword.setText("");
                addreenterpassword.setText("");
            }
            catch(Exception e){
                System.out.println(e);
                System.exit(7);
            }
        }
        else{
            passerr.setText(" - Password Did not match");
        }
        
    }//GEN-LAST:event_savebtnaddActionPerformed

    private void discardbtnaddActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_discardbtnaddActionPerformed
        addplatform.setText("");
        addpassword.setText("");
        adduserid.setText("");
        addpassword.setText("");
        addreenterpassword.setText("");
        adddialog.setVisible(false);
    }//GEN-LAST:event_discardbtnaddActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        if(selected_table_index == -1)
            return;
        databaseRemove(
                recordstbl.getValueAt(selected_table_index, 0).toString(),
                recordstbl.getValueAt(selected_table_index, 1).toString(),
                recordstbl.getValueAt(selected_table_index, 2).toString()
        );
        updateTable();
        selected_table_index = -1;
    }//GEN-LAST:event_jButton2ActionPerformed

    private void recordstblMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_recordstblMouseClicked
        selected_table_index = recordstbl.getSelectedRow();
    }//GEN-LAST:event_recordstblMouseClicked

    private void filterfieldKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_filterfieldKeyReleased
        selected_table_index = -1;
        updateTableFilter(filterfield.getText());
        selected_table_index = -1;
    }//GEN-LAST:event_filterfieldKeyReleased

 

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JDialog adddialog;
    private javax.swing.JTextField addpassword;
    private javax.swing.JTextField addplatform;
    private javax.swing.JTextField addreenterpassword;
    private javax.swing.JTextField adduserid;
    private javax.swing.JButton discardbtnadd;
    private javax.swing.JTextField filterfield;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JLabel passerr;
    private javax.swing.JTable recordstbl;
    private javax.swing.JButton savebtnadd;
    // End of variables declaration//GEN-END:variables
}
