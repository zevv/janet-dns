#!/usr/bin/env janet

(import ./resolver)

# Main code: create resolver and resolve a bit

(def res (resolver/new "8.8.4.4"))

(defn test[]
  (ev/sleep 1.0)
  (pp (:resolve res "nyt.com"))
  (ev/sleep 0.1)
  (pp (:resolve res "google.com" :AAAA)))


(ev/call test)

