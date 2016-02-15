(ns caesium.crypto.pwhash-test
  (:require [clojure.test :refer :all]
            [caesium.randombytes :refer :all]
            [caesium.crypto.pwhash :refer :all]))

(deftest pwhash-derive-key
  (testing "Can derive key of the specified length"
    (are [pwlen len] (= len (count (derive-key len
                                         (randombytes pwlen)
                                         (randombytes (salt-length)))))
      25 32
      11 24
      55 64))
  (testing "Throws if salt not valid"
    (is (thrown? java.lang.IllegalArgumentException
                 (derive-key 32 (randombytes 16) (randombytes 9))))))
