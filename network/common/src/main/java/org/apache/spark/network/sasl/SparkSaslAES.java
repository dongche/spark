/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.spark.network.sasl;

import com.intel.chimera.cipher.Cipher;
import com.intel.chimera.cipher.CipherTransformation;
import com.intel.chimera.utils.Utils;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.sasl.SaslException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * AES encryption and decryption.
 */
public class SparkSaslAES {
  private final Logger logger = LoggerFactory.getLogger(SparkSaslAES.class);

  private final Cipher encryptor;
  private final Cipher decryptor;

  private final Integrity integrity;

  public SparkSaslAES(CipherTransformation cipherTransformation, Properties properties, byte[] inKey,
      byte[] outKey, byte[] inIv, byte[] outIv) throws IOException {
    checkTransformation(cipherTransformation);
    // encryptor
    encryptor = Utils.getCipherInstance(cipherTransformation, properties);
    try {
      encryptor.init(Cipher.ENCRYPT_MODE, outKey, outIv);
    } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
      throw new IOException("Failed to initialize encryptor", e);
    }

    // decryptor
    decryptor = Utils.getCipherInstance(cipherTransformation, properties);
    try {
      decryptor.init(Cipher.DECRYPT_MODE, inKey, inIv);
    } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
      throw new IOException("Failed to initialize decryptor", e);
    }

    integrity = new Integrity(outKey, inKey);
    logger.info("xxxxxx : cipher class: {}", encryptor.getClass().getName());
  }

  /**
   * Encrypts input data. The result composes of (msg, padding if needed, mac) and sequence num.
   * @param data the input byte array
   * @param offset the offset in input where the input starts
   * @param len the input length
   * @return the new encrypted byte array.
   * @throws SaslException if error happens
   */
  public byte[] wrap(byte[] data, int offset, int len) throws SaslException {
    // mac
    byte[] mac = integrity.getHMAC(data, offset, len);

    // padding based on cipher
    byte[] padding;
    if (encryptor.getTransformation() == CipherTransformation.AES_CBC_NOPADDING) {
      int bs = encryptor.getTransformation().getAlgorithmBlockSize();
      int pad = bs - (len + 10) % bs;
      padding = new byte[pad];
      for (int i = 0; i < pad; i ++) {
        padding[i] = (byte) pad;
      }
    } else {
      padding = new byte[0];
    }

    // encrypt
    byte[] toBeEncrypted = new byte[len + 10 + padding.length];
    System.arraycopy(data, offset, toBeEncrypted, 0, len);
    System.arraycopy(padding, 0, toBeEncrypted, len, padding.length);
    System.arraycopy(mac, 0, toBeEncrypted, len + padding.length, 10);
    byte[] encrypted = encryptor.update(toBeEncrypted, 0, toBeEncrypted.length);

    // append seqNum used for mac
    byte[] wrapped = new byte[encrypted.length + 4];
    System.arraycopy(encrypted, 0, wrapped, 0, encrypted.length);
    System.arraycopy(integrity.getSeqNum(), 0, wrapped, encrypted.length, 4);

    //logger.info("xxxxxx: wrap msg - " + count.incrementAndGet());
    return wrapped;
  }

  /**
   * Decrypts input data. The input composes of (msg, padding if needed, mac) and sequence num.
   * The result is msg.
   * @param data the input byte array
   * @param offset the offset in input where the input starts
   * @param len the input length
   * @return the new decrypted byte array.
   * @throws SaslException if error happens
   */
  public byte[] unwrap(byte[] data, int offset, int len) throws SaslException {
    // get plaintext and seqNum
    byte[] encrypted = new byte[len - 4];
    byte[] peerSeqNum = new byte[4];
    System.arraycopy(data, offset, encrypted, 0, encrypted.length);
    System.arraycopy(data, offset + encrypted.length, peerSeqNum, 0, 4);
    byte[] decrypted = decryptor.update(encrypted, 0, encrypted.length);

    // get msg and mac
    byte[] msg = new byte[decrypted.length - 10];
    byte[] mac = new byte[10];
    System.arraycopy(decrypted, 0, msg, 0, msg.length);
    System.arraycopy(decrypted, msg.length, mac, 0, 10);

    // modify msg length if padding
    int msgLength = msg.length;
    if (decryptor.getTransformation() == CipherTransformation.AES_CBC_NOPADDING) {
      msgLength -= (int) msg[msgLength - 1];
    }

    // check mac integrity and msg sequence
    if (!integrity.compareHMAC(mac, peerSeqNum, msg, 0, msgLength)) {
      throw new SaslException("Unmatched MAC");
    }
    if (!integrity.comparePeerSeqNum(peerSeqNum)) {
      throw new SaslException("Out of order sequencing of messages. Got: " + integrity.byteToInt
          (peerSeqNum) + " Expected: " + integrity.peerSeqNum);
    }

    //logger.info("xxxxxx: unwrap msg - " + count.incrementAndGet());
    // return msg considering padding
    if (msgLength == msg.length) {
      return msg;
    } else {
      byte[] clearMsg = new byte[msgLength];
      System.arraycopy(msg, 0, clearMsg, 0, msgLength);
      return clearMsg;
    }
  }

  private void checkTransformation(CipherTransformation transformation) throws IOException {
    if (transformation == CipherTransformation.AES_CBC_NOPADDING
        || transformation == CipherTransformation.AES_CTR_NOPADDING) {
      return;
    }
    throw new IOException("AES cipher transformation is not supported: "
        + transformation.getName());
  }

  /**
   * Helper class for providing integrity protection.
   */
  private static class Integrity {

    private int mySeqNum = 0;
    private int peerSeqNum = 0;
    private byte[] seqNum = new byte[4];

    private byte[] myKey;
    private byte[] peerKey;

    Integrity(byte[] outKey, byte[] inKey) throws IOException {
      myKey = outKey;
      peerKey = inKey;
    }

    byte[] getHMAC(byte[] msg, int start, int len) throws SaslException {
      seqNum = intToByte(mySeqNum ++);
      return calculateHMAC(myKey, seqNum, msg, start, len);
    }

    boolean compareHMAC(byte[] expectedHMAC, byte[] peerSeqNum, byte[] msg, int start,
        int len) throws SaslException {
      byte[] mac = calculateHMAC(peerKey, peerSeqNum, msg, start, len);
      return Arrays.equals(mac, expectedHMAC);
    }

    boolean comparePeerSeqNum(byte[] peerSeqNum) {
      return this.peerSeqNum ++ == byteToInt(peerSeqNum);
    }

    byte[] getSeqNum() {
      return seqNum;
    }

    private byte[] calculateHMAC(byte[] key, byte[] seqNum, byte[] msg, int start,
        int len) throws SaslException {
      byte[] seqAndMsg = new byte[4+len];
      System.arraycopy(seqNum, 0, seqAndMsg, 0, 4);
      System.arraycopy(msg, start, seqAndMsg, 4, len);

      try {
        SecretKey keyKi = new SecretKeySpec(key, "HmacMD5");
        Mac m = Mac.getInstance("HmacMD5");
        m.init(keyKi);
        m.update(seqAndMsg);
        byte[] hMAC_MD5 = m.doFinal();

        /* First 10 bytes of HMAC_MD5 digest */
        byte macBuffer[] = new byte[10];
        System.arraycopy(hMAC_MD5, 0, macBuffer, 0, 10);

        return macBuffer;
      } catch (InvalidKeyException e) {
        throw new SaslException("Invalid bytes used for key of HMAC-MD5 hash.", e);
      } catch (NoSuchAlgorithmException e) {
        throw new SaslException("Error creating instance of MD5 MAC algorithm", e);
      }
    }

    private byte[] intToByte(int seqNum) {
      byte[] answer = new byte[4];
      for(int i = 3; i >= 0; i --) {
        answer[i] = (byte)(seqNum & 0xff);
        seqNum >>>= 8;
      }
      return answer;
    }

    private int byteToInt(byte[] seqNum) {
      int answer = 0;
      for (int i = 0; i < 4; i ++) {
        answer <<= 8;
        answer |= ((int)seqNum[i] & 0xff);
      }
      return answer;
    }
  }
}
