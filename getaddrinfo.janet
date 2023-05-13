
(defn hexdump [buf]
  (for i 0 (length buf)
    (if (= 0 (band i 0xf))
      (prinf "\n%04x: " i))
    (prinf "%02x " (get buf i)))
  (print ""))

(def qtype {
    :A 1 :NS 2 :CNAME 5 :SOA 6 :PTR 12 :MX 15 :TXT 16 :AAAA 28 :SRV 33 :OPT 41 :AXFR 252 :ANY 255 
    1 :A 2 :NS 5 :CNAME 6 :SOA 12 :PTR 15 :MX 16 :TXT 28 :AAAA 33 :SRV 41 :OPT 252 :AXFR 255 :ANY})

(def qclass { :IN 1 :CS 2 :CH 3 :HS 4 :ANY 255 1 :IN 2 :CS 3 :CH 4 :HS 255 :ANY})

(varfn decode-name [buf off] 0)

(defn unpack [buf off & ks]
  (var off off)
  (def result @[])
  (each k ks
    (def [off-next v]
      (case k
        :name (decode-name buf off)
        :u8 [(+ off 1) (get buf off)]
        :u16 (do (def [off v1 v2] (unpack buf off :u8 :u8))
                 [off (+ (blshift v1 8) v2)])
        :u32 (do (def [off v1 v2] (unpack buf off :u16 :u16))
                 [off (+ (blshift v1 16) v2)])
        :A (do (def [off & vs] (unpack buf off :u8 :u8 :u8 :u8))
               [off (string/format "%d.%d.%d.%d" ;vs)])
        :AAAA (do (def [off & vs] (unpack buf off :u16 :u16 :u16 :u16 :u16 :u16 :u16 :u16))
                  [off (string/format "%x:%x:%x:%x:%x:%x:%x:%x" ;vs)])
        :MX (do (def [off pref name] (unpack buf off :u16 :name))
                [off { :preference pref :name name} ])
        :NS (unpack buf off :name)
        :PTR (unpack buf off :name)
        ))
    (set off off-next)
    (array/push result v))
  [off ;result])

(defn push-name [buf name]
  (def parts (string/split "." name))
  (each part parts
    (def len (length part))
    (buffer/push-byte buf len)
    (buffer/push buf part))
  (buffer/push-byte buf 0))

(defn push-u16 [buffer v]
  (buffer/push-byte buffer (band (brshift v 8) 0xff))
  (buffer/push-byte buffer (band (brshift v 0) 0xff)))

(defn dns-encode [pkt]
  (def questions (get pkt :questions))
  (def answers (get pkt :answers))
  (def buf @"")
  (push-u16 buf (get pkt :id))
  (push-u16 buf 0x0100)
  (push-u16 buf (length questions))
  (push-u16 buf (length answers))
  (push-u16 buf 0)
  (push-u16 buf 0)
  (each q questions
    (push-name buf (get q :name))
    (push-u16 buf (qtype (q :type)))
    (push-u16 buf (qclass (q :class))))
  buf)

(defn is-compressed? [len]
  (= 0xc0 (band 0xc0 len)))

(varfn decode-name-aux [buf off parts] 0)

# Decode label part; length prefixed followed by data
(defn decode-part-label [buf off len parts]
  (def off-next (+ off len))
  (array/push parts (slice buf off off-next))
  (decode-name-aux buf off-next parts))

# Decode compressed part; 0x0c followed by a pointer to the name
(defn decode-part-compressed [buf off len parts]
  (def [off ptr] (unpack buf off :u8))
  (decode-name-aux buf ptr parts)
  off)

(varfn decode-name-aux [buf off parts]
  (def [off len] (unpack buf off :u8))
  (if (> len 0)
    (if (is-compressed? len)
      (decode-part-compressed buf off len parts)
      (decode-part-label buf off len parts))
    off))
                      
(varfn decode-name [buf off]
  (def parts @[])
  (def off (decode-name-aux buf off parts))
  [off (string/join parts ".")])

(defn decode-data [buf off len type]
  (unpack buf off type))

(defn decode-question [buf off]
  (def [off name type class] (unpack buf off :name :u16 :u16))
  [off {:name name :type (qtype type) :class (qclass class)}])

(defn decode-answer [buf off]
  (def [off name type class ttl len] (unpack buf off :name :u16 :u16 :u32 :u16))
  (def [off data] (decode-data buf off len (qtype type)))
  [off {:name name :type (qtype type) :class (qclass class) :ttl ttl :data data}])

(defn decode-questions [buf off nquestions questions]
  (if (> nquestions 0)
    (do (def [off question] (decode-question buf off))
        (decode-questions buf off (dec nquestions) [question; questions]))
    [off questions]))

(defn decode-answers [buf off nanswers answers]
  (if (> nanswers 0)
    (do (def [off answer] (decode-answer buf off))
        (decode-answers buf off (dec nanswers) [answer; answers]))
    [off answers]))


(defn dns-decode [buf]
  (hexdump buf)
  (def [off id flags nquestions nanswers] (unpack buf 0 :u16 :u16 :u16 :u16 :u16 :u16))
  (def [off questions] (decode-questions buf off nquestions @[]))
  (def [off answers] (decode-answers buf off nanswers @[]))
  {:id id :flags flags :questions questions :answers answers})

(defn resolve [type name]
  (def sock (net/connect "8.8.4.4" "53" :datagram))
  (def query-pkt {
            :id 0x1234 
            :questions [ { :name name :type type :class :IN } ] 
            :answers []
          })
  (net/write sock (dns-encode query-pkt))
  (dns-decode (net/read sock 4096)))


(def resp (resolve :A "nu"))
(print "")
(each q (get resp :questions) (pp q))
(print "")
(each a (get resp :answers) (pp a))
