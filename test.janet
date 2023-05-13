#!/usr/bin/env janet

(import ./resolver)

# Main code: create resolver and resolve a bit

(def res (resolver/new "8.8.4.4"))

(defn test[]
  (pp (:resolve res "nyt.com"))
  (pp (:resolve res "google.com" :AAAA))
  (:stop res))


(ev/call test)

