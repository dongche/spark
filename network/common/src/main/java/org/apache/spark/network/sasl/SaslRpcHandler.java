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
import javax.crypto.KeyGenerator;
import javax.security.sasl.Sasl;

import com.google.common.base.Throwables;
import com.intel.chimera.cipher.CipherTransformation;
import com.intel.chimera.conf.ConfigurationKeys;
import com.intel.chimera.random.JavaSecureRandom;
import com.intel.chimera.random.SecureRandom;
import com.intel.chimera.random.SecureRandomFactory;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.spark.network.client.RpcResponseCallback;
import org.apache.spark.network.client.TransportClient;
import org.apache.spark.network.server.RpcHandler;
import org.apache.spark.network.server.StreamManager;
import org.apache.spark.network.util.JavaUtils;
import org.apache.spark.network.util.TransportConf;

import java.util.Properties;

/**
 * RPC Handler which performs SASL authentication before delegating to a child RPC handler.
 * The delegate will only receive messages if the given connection has been successfully
 * authenticated. A connection may be authenticated at most once.
 *
 * Note that the authentication process consists of multiple challenge-response pairs, each of
 * which are individual RPCs.
 */
class SaslRpcHandler extends RpcHandler {
  private static final Logger logger = LoggerFactory.getLogger(SaslRpcHandler.class);

  /** Transport configuration. */
  private final TransportConf conf;

  /** The client channel. */
  private final Channel channel;

  /** RpcHandler we will delegate to for authenticated connections. */
  private final RpcHandler delegate;

  /** Class which provides secret keys which are shared by server and client on a per-app basis. */
  private final SecretKeyHolder secretKeyHolder;

  private SparkSaslServer saslServer;
  private boolean isComplete;
  private boolean isNegotiatingAes;

  SaslRpcHandler(
      TransportConf conf,
      Channel channel,
      RpcHandler delegate,
      SecretKeyHolder secretKeyHolder) {
    this.conf = conf;
    this.channel = channel;
    this.delegate = delegate;
    this.secretKeyHolder = secretKeyHolder;
    this.saslServer = null;
    this.isComplete = false;
    this.isNegotiatingAes = false;
  }

  @Override
  public void receive(TransportClient client, ByteBuffer message, RpcResponseCallback callback) {
    if (isComplete) {
      // Authentication complete, delegate to base handler.
      delegate.receive(client, message, callback);
      return;
    }

    if (saslServer == null || !saslServer.isComplete()) {
      // Sasl authentication procedure
      ByteBuf nettyBuf = Unpooled.wrappedBuffer(message);
      SaslMessage saslMessage;
      try {
        saslMessage = SaslMessage.decode(nettyBuf);
      } finally {
        nettyBuf.release();
      }

      if (saslServer == null) {
        // First message in the handshake, setup the necessary state.
        client.setClientId(saslMessage.appId);
        saslServer = new SparkSaslServer(saslMessage.appId, secretKeyHolder,
            conf.saslServerAlwaysEncrypt());
      }

      byte[] response;
      try {
        response = saslServer.response(JavaUtils.bufferToArray(
            saslMessage.body().nioByteBuffer()));
      } catch (IOException ioe) {
        throw new RuntimeException(ioe);
      }
      callback.onSuccess(ByteBuffer.wrap(response));
    }

    // Setup encryption after the SASL response is sent, otherwise the client can't parse the
    // response. It's ok to change the channel pipeline here since we are processing an incoming
    // message, so the pipeline is busy and no new incoming messages will be fed to it before this
    // method returns. This assumes that the code ensures, through other means, that no outbound
    // messages are being written to the channel while negotiation is still going on.
    if (saslServer.isComplete()) {
      if (SparkSaslServer.QOP_AUTH_CONF.equals(saslServer.getNegotiatedProperty(Sasl.QOP))) {
        if (conf.saslEncryptionAesEnabled()) {
          // negotiate AES if configured
          if (isNegotiatingAes) {
            negotiateAes(message, callback);
          } else {
            isNegotiatingAes = true;
            // return from here to wait for next RPC from client
            return;
          }
        }
        logger.info("xxxxxx: SASL authentication successful for channel {}", client);
        logger.info("xxxxxx: Enabling encryption for channel {}", client);
        SaslEncryption.addToChannel(channel, saslServer, conf.maxSaslEncryptedBlockSize());
        saslServer = null;
      } else {
        logger.info("xxxxxx: SASL authentication successful for channel {}", client);
        saslServer.dispose();
        saslServer = null;
      }
      isComplete = true;
    }
  }

  @Override
  public void receive(TransportClient client, ByteBuffer message) {
    delegate.receive(client, message);
  }

  @Override
  public StreamManager getStreamManager() {
    return delegate.getStreamManager();
  }

  @Override
  public void connectionTerminated(TransportClient client) {
    try {
      delegate.connectionTerminated(client);
    } finally {
      if (saslServer != null) {
        saslServer.dispose();
      }
    }
  }

  @Override
  public void exceptionCaught(Throwable cause, TransportClient client) {
    delegate.exceptionCaught(cause, client);
  }

  /**
   * Negotiates AES based on complete {@link SparkSaslServer}. The keys need to be encrypted by
   * sasl server.
   */
  private void negotiateAes(ByteBuffer message, RpcResponseCallback callback) {
    // receive initial option from client
    CipherOption cipherOption = CipherOption.decode(Unpooled.wrappedBuffer(message));
    logger.info("xxxxxx: cipher in server: {}", cipherOption.cipherSuite);
    CipherTransformation transformation = CipherTransformation.fromName(cipherOption.cipherSuite);
    Properties properties = new Properties();
    properties.setProperty(ConfigurationKeys.CHIMERA_CRYPTO_SECURE_RANDOM_CLASSES_KEY,
        JavaSecureRandom.class.getName());

    try {
      // generate key and iv
      int keyLen = conf.saslEncryptionAesCipherKeySizeBits();
      KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA1");
      keyGenerator.init(keyLen);

      byte[] inKey = keyGenerator.generateKey().getEncoded();
      byte[] outKey = keyGenerator.generateKey().getEncoded();

      byte[] inIv = new byte[transformation.getAlgorithmBlockSize()];
      byte[] outIv = new byte[transformation.getAlgorithmBlockSize()];
      SecureRandom secureRandom = SecureRandomFactory.getSecureRandom(properties);
      secureRandom.nextBytes(inIv);
      secureRandom.nextBytes(outIv);

      // create new option for client. The key is encrypted
      cipherOption = new CipherOption(cipherOption.cipherSuite,
          saslServer.wrap(inKey, 0, inKey.length), inIv,
          saslServer.wrap(outKey, 0, outKey.length), outIv);

      // enable AES on saslServer
      saslServer.enableAes(transformation, properties, inKey, outKey, inIv, outIv);

      // send cipher option to client
      ByteBuf buf = Unpooled.buffer(cipherOption.encodedLength());
      cipherOption.encode(buf);
      callback.onSuccess(buf.nioBuffer());
      logger.info("xxxxxx: AES enabled on server : {}", transformation.getName());
    } catch (Exception e) {
      logger.error("AES negotiation exception: ", e);
      throw Throwables.propagate(e);
    }
  }
}
