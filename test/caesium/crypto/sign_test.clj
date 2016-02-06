(ns caesium.crypto.sign-test
  (:require [caesium.crypto.sign :refer :all]
            [caesium.util :refer :all]
            [clojure.test :refer :all]))

;; Test values taken from Kalium's suite
(def secret
  (unhexify "b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd"))
(def message
  (unhexify "916c7d1d268fc0e77c1bef238432573c39be577bbea0998936add2b50a653171ce18a542b0b7f96c1691a3be6031522894a8634183eda38798a0c5d5d79fbd01dd04a8646d71873b77b221998a81922d8105f892316369d5224c9983372d2313c6b1f4556ea26ba49d46e8b561e0fc76633ac9766e68e21fba7edca93c4c7460376d7f3ac22ff372c18f613f2ae2e856af40"))
(def signature
  (unhexify "6bd710a368c1249923fc7a1610747403040f0cc30815a00f9ff548a896bbda0b4eb2ca19ebcf917f0f34200a9edbad3901b64ab09cc5ef7b9bcc3c40c0ff7509"))
(def public
  (unhexify "77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb"))

(deftest generate-signing-keys-test
  (testing "Simply generates new keypairs"
    (is (let [kp1 (generate-signing-keys)
              kp2 (generate-signing-keys)]
          (and (not (array-eq (:public kp1) (:public kp2)))
               (not (array-eq (:secret kp1) (:secret kp2)))))))
  (testing "Can generate expected public-key from secret seed"
    (is (array-eq public
                  (:public (generate-signing-keys secret))))))

(deftest sign-test
  (testing "Can sign a message"
    (is (array-eq signature
                  (sign secret message)))))

(deftest verify-test
  (testing "Verifying correct signature works"
    (is (verify public message signature))
    (is (let [{pk :public ss :secret} (generate-signing-keys)]
          (verify pk message
                  (sign ss message)))))
  (testing "Will not verify arbitrary signature"
    (is (thrown-with-msg? java.lang.RuntimeException #"^signature was forged or corrupted$"
                          (let [{pk :public ss :secret} (generate-signing-keys)
                                other-sig (sign ss message)]
                            (verify public message other-sig))))))
