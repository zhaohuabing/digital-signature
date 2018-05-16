/**
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 * 
 */
package com.zhaohuabing.signature;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

/**
 * @author Huabing Zhao
 *
 */
class DigitalSignature {

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(1024, random);
        KeyPair pair = keyGen.generateKeyPair();
        return pair;
    }

    public byte[] signMessage(PrivateKey sk, String message)
                    throws NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeyException {
        Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
        sig.initSign(sk);
        sig.update(message.getBytes());
        return sig.sign();
    }


    public boolean verify(PublicKey pk, String message, byte[] signatrue)
                    throws NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeyException {
        Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
        sig.initVerify(pk);
        sig.update(message.getBytes());
        return sig.verify(signatrue);
    }
}
