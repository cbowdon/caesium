(ns caesium.crypto.box-test
  (:require [caesium.crypto.box :refer :all]
            [caesium.util :refer :all]
            [clojure.test :refer :all]))

(deftest box-keypair-generation
  (testing "Simply generates new keypairs"
    (is (let [kp1 (generate-keypair)
              kp2 (generate-keypair)]
          (and (not (array-eq (:public kp1) (:public kp2)))
               (not (array-eq (:secret kp1) (:secret kp2)))))))
  (testing "Can generate the public-key from a secret-key"
    (is (let [kp1 (generate-keypair)
              kp2 (generate-keypair (:secret kp1))]
          (array-eq (:public kp1)
                    (:public kp2))))))

;; These values taken from Kalium's test suite
(def nonce
  (unhexify "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37"))
(def plaintext
  (unhexify "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705"))
(def ciphertext 
  (unhexify "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5"))

(def bob-secret-key 
  (unhexify "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
(def bob-public-key 
  (unhexify "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))

(def alice-secret-key 
  (unhexify "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
(def alice-public-key 
  (unhexify "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))

(deftest box-encrypt-decrypt-test
  (testing "Bob can encrypt a message for Alice"
    (is (array-eq ciphertext
                  (encrypt alice-public-key bob-secret-key nonce plaintext))))
  (testing "Alice can decrypt the message from Bob"
    (is (array-eq plaintext
                  (decrypt bob-public-key alice-secret-key nonce ciphertext))))
  (testing "No hex please"
    (is (thrown? java.lang.ClassCastException
                 (encrypt (hexify alice-public-key)
                          (hexify bob-secret-key)
                          nonce
                          plaintext)))))
