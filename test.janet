#!/usr/bin/env janet

(import ./resolver)

# Main code: create resolver and resolve a bit

(def res (resolver/new "8.8.4.3"))

(defn test[]
  (pp (:resolve res "nyt.com"))
  (pp (:resolve res "google.com" :AAAA))
  (pp (:resolve res "zevv.nl" :TXT))
  (:stop res))


(ev/call test)

