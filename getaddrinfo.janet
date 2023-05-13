
(def qtype {
    :A 1 :NS 2 :CNAME 5 :SOA 6 :PTR 12 :MX 15 :TXT 16 :AAAA 28 :SRV 33 :OPT 41 :AXFR 252 :ANY 255
    1 :A 2 :NS 5 :CNAME 6 :SOA 12 :PTR 15 :MX 16 :TXT 28 :AAAA 33 :SRV 41 :OPT 252 :AXFR 255 :ANY})

(def qclass { :IN 1 :CS 2 :CH 3 :HS 4 :ANY 255 1 :IN 2 :CS 3 :CH 4 :HS 255 :ANY})

(varfn decode-name [buf off parts] 0)

(defn push-name [buf name]
  (each part (string/split "." name)
    (buffer/push-byte buf (length part))
    (buffer/push buf part))
  (buffer/push-byte buf 0))

(defn push-u16 [buffer v]
  (buffer/push-byte buffer (band (brshift v 8) 0xff))
  (buffer/push-byte buffer (band (brshift v 0) 0xff)))

(defn pack [buf & kvs]
  (each [k v] (partition 2 kvs)
    (case k
      :name (push-name buf v)
      :u16 (push-u16 buf v)
      )))

(defn dns-encode [pkt]
  (def buf @"")
  (pack buf
        :u16 (pkt :id)
        :u16 0x0100 # flags
        :u16 (length (pkt :questions))
        :u16 (length (pkt :answers))
        :u16 0  # authority RRs
        :u16 0) # additional RRs
  (each q (pkt :questions)
    (pack buf
          :name (q :name)
          :u16 (qtype (q :type))
          :u16 (qclass (q :class))))
  buf)

(defn unpack [buf off & ks]
  (var off off)
  (def result @[])
  (each k ks
    (def [off-next v]
      (case k
        :name (do (def parts @[])
                  (def off (decode-name buf off parts))
                  [off (string/join parts ".")])
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
                [off { :preference pref :name name}])
        :NS (unpack buf off :name)
        :PTR (unpack buf off :name)
        :TXT (do (def [off len] (unpack buf off :u8))
                 [(+ off len) (slice buf off (+ off len))])
        ))
    (set off off-next)
    (array/push result v))
  [off ;result])

(defn decode-part-label [buf off len parts]
  (def off-next (+ off len))
  (array/push parts (slice buf off off-next))
  (decode-name buf off-next parts))

(defn decode-part-compressed [buf off len parts]
  (def [off ptr] (unpack buf off :u8))
  (decode-name buf ptr parts)
  off)

(defn is-compressed? [len]
  (= 0xc0 (band 0xc0 len)))

(varfn decode-name [buf off parts]
  (def [off len] (unpack buf off :u8))
  (if (> len 0)
    (if (is-compressed? len)
      (decode-part-compressed buf off len parts)
      (decode-part-label buf off len parts))
    off))

(defn decode-data [buf off len type]
  (unpack buf off type))

(defn decode-question [buf off]
  (def [off name type class] (unpack buf off :name :u16 :u16))
  [off {:name name :type (qtype type) :class (qclass class)}])

(defn decode-answer [buf off]
  (def [off name type class ttl len] (unpack buf off :name :u16 :u16 :u32 :u16))
  (def [off data] (decode-data buf off len (qtype type)))
  [off {:name name :type (qtype type) :class (qclass class) :ttl ttl :data data}])

(defn decode-list [buf off decoder count vs]
  (if (> count 0)
    (do (def [off v] (decoder buf off))
        (decode-list buf off decoder (dec count) [v; vs]))
    [off vs]))

(defn dns-decode [buf]
  (def [off id flags nquestions nanswers] (unpack buf 0 :u16 :u16 :u16 :u16 :u16 :u16))
  (def [off questions] (decode-list buf off decode-question nquestions @[]))
  (def [off answers] (decode-list buf off decode-answer nanswers @[]))
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

(each type [:A :AAAA :MX :TXT] (do
  (def resp (resolve type "nyt.com"))
  (each a (resp :answers) 
    (printf "%s %q" (a :type) (a :data)))))
