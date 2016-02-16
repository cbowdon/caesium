(ns caesium.crypto.pwhash
  (:import org.abstractj.kalium.crypto.Password
           org.abstractj.kalium.NaCl
           org.abstractj.kalium.NaCl$Sodium))

;; This is a function rather than a constant because they might change and
;; libsodium provides lookup functions. Although kalium doesn't use these yet,
;; if they do switch in future then this prevents a breaking change.
(defn opslimit-interactive
  "The suggested opslimit for interactive applications."
  []
  NaCl$Sodium/PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE)

(defn memlimit-interactive
  "The suggested memlimit for interactive applications."
  []
  NaCl$Sodium/PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE)

(defn salt-length
  "The expected length of a salt byte array."
  []
  32) ;; This is hard-coded until kalium exposes it

(defn derive-key
  "Derive a key with the given length using `crypto_pwhash_scryptsalsa208sha256`,
  with optional operations limit and memory limit parameters."
  ([length password salt]
   (derive-key length password salt {:opslimit (opslimit-interactive)
                                     :memlimit (memlimit-interactive)}))
  ([length password salt {ops :opslimit mem :memlimit}]
   (if (= (count salt) (salt-length))
     (.deriveKey (Password.) length password salt ops mem)
     (throw (java.lang.IllegalArgumentException. "Invalid salt length")))))
