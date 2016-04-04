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

import java.io.IOException;
import java.nio.ByteBuffer;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;

import com.intel.chimera.cipher.CipherTransformation;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.spark.network.client.TransportClient;
import org.apache.spark.network.client.TransportClientBootstrap;
import org.apache.spark.network.util.JavaUtils;
import org.apache.spark.network.util.TransportConf;

import java.util.Properties;

/**
 * Bootstraps a {@link TransportClient} by performing SASL authentication on the connection. The
 * server should be setup with a {@link SaslRpcHandler} with matching keys for the given appId.
 */
public class SaslClientBootstrap implements TransportClientBootstrap {
  private final Logger logger = LoggerFactory.getLogger(SaslClientBootstrap.class);

  private final boolean encrypt;
  private final TransportConf conf;
  private final String appId;
  private final SecretKeyHolder secretKeyHolder;

  public SaslClientBootstrap(TransportConf conf, String appId, SecretKeyHolder secretKeyHolder) {
    this(conf, appId, secretKeyHolder, false);
  }

  public SaslClientBootstrap(
      TransportConf conf,
      String appId,
      SecretKeyHolder secretKeyHolder,
      boolean encrypt) {
    logger.info("************* construct client bootstrap {} ********", encrypt);
    this.conf = conf;
    this.appId = appId;
    this.secretKeyHolder = secretKeyHolder;
    this.encrypt = encrypt;
  }

  /**
   * Performs SASL authentication by sending a token, and then proceeding with the SASL
   * challenge-response tokens until we either successfully authenticate or throw an exception
   * due to mismatch.
   */
  @Override
  public void doBootstrap(TransportClient client, Channel channel) {
    logger.info("************** start client ***********");
    SparkSaslClient saslClient = new SparkSaslClient(appId, secretKeyHolder, encrypt);
    try {
      byte[] payload = saslClient.firstToken();

      while (!saslClient.isComplete()) {
        SaslMessage msg = new SaslMessage(appId, payload);
        ByteBuf buf = Unpooled.buffer(msg.encodedLength() + (int) msg.body().size());
        msg.encode(buf);
        buf.writeBytes(msg.body().nioByteBuffer());

        ByteBuffer response = client.sendRpcSync(buf.nioBuffer(), conf.saslRTTimeoutMs());
        payload = saslClient.response(JavaUtils.bufferToArray(response));
      }

      client.setClientId(appId);
      logger.info("xxxxxx: client1");
      if (encrypt) {
        if (!SparkSaslServer.QOP_AUTH_CONF.equals(saslClient.getNegotiatedProperty(Sasl.QOP))) {
          throw new RuntimeException(
            new SaslException("Encryption requests by negotiated non-encrypted connection."));
        }

        logger.info("xxxxxx: client2");
        if (conf.saslEncryptionAesEnabled()) {
          logger.info("xxxxxx: start aes negotiate on client");
          negotiateAes(client, saslClient);
        }

        SaslEncryption.addToChannel(channel, saslClient, conf.maxSaslEncryptedBlockSize());
        saslClient = null;

        logger.info("xxxxxx: Channel {} configured for SASL encryption.", client);
      }
    } catch (IOException ioe) {
      throw new RuntimeException(ioe);
    } finally {
      if (saslClient != null) {
        try {
          // Once authentication is complete, the server will trust all remaining communication.
          saslClient.dispose();
        } catch (RuntimeException e) {
          logger.error("Error while disposing SASL client", e);
        }
      }
    }
  }

  /**
   * Negotiates AES cipher based on complete {@link SparkSaslClient}. The keys need to be
   * decrypted by sasl client.
   */
  private void negotiateAes(TransportClient client, SparkSaslClient saslClient) throws IOException {
    // create option for negotiation
    CipherOption cipherOption = new CipherOption(conf.saslEncryptionAesCipherTransformation());
    ByteBuf buf = Unpooled.buffer(cipherOption.encodedLength());
    cipherOption.encode(buf);

    // send option to server and decode received negotiated option
    logger.info("xxxxxx: AES on client. before send");
    ByteBuffer response = client.sendRpcSync(buf.nioBuffer(), conf.saslRTTimeoutMs());
    logger.info("xxxxxx: AES on client. after send");
    cipherOption = CipherOption.decode(Unpooled.wrappedBuffer(response));

    // decrypt key from option. Server's outKey is client's inKey, and vice versa.
    byte[] outKey = saslClient.unwrap(cipherOption.inKey, 0, cipherOption.inKey.length);
    byte[] inKey = saslClient.unwrap(cipherOption.outKey, 0, cipherOption.outKey.length);

    // enable AES on saslClient
    Properties properties = new Properties();
    saslClient.enableAes(CipherTransformation.fromName(cipherOption.cipherSuite), properties,
        inKey, outKey, cipherOption.outIv, cipherOption.inIv);

    logger.info("xxxxxx: AES enabled for SASL encryption on client.");
  }
}
